"""Integration tests for patatt sign/verify within b4.

Uses ephemeral ed25519 keys so no external key material is needed.
"""
import base64
import email.message
import os
import tempfile
from collections.abc import Generator
from typing import Tuple, Union

import pytest
from nacl.signing import SigningKey

import b4
import patatt


@pytest.fixture()
def ed25519_keypair() -> Generator[Tuple[str, str, str, str], None, None]:
    """Generate an ephemeral ed25519 keypair written to temp files.

    Returns (privkey_path, verify_key_b64, identity, selector).
    The private key file is written so patatt can find it via
    signingkey = ed25519:/path/to/key.
    """
    sk = SigningKey.generate()
    sk_b64 = base64.b64encode(sk.encode()).decode()
    vk_b64 = base64.b64encode(sk.verify_key.encode()).decode()
    with tempfile.NamedTemporaryFile(mode='w', suffix='.key',
                                     delete=False) as fh:
        fh.write(sk_b64)
        privkey_path = fh.name
    yield privkey_path, vk_b64, 'test@example.com', 'default'
    os.unlink(privkey_path)


@pytest.fixture()
def keyring_dir(ed25519_keypair: Tuple[str, str, str, str]) -> Generator[str, None, None]:
    """Create a temporary keyring directory with the ephemeral public key.

    The directory layout follows patatt's expected structure:
    <keyring>/<identity>/ed25519/<selector>
    """
    _privkey, vk_b64, identity, selector = ed25519_keypair
    # patatt looks up keys as: ed25519/<domain>/<localpart>/<selector>
    local, domain = identity.split('@', 1)
    with tempfile.TemporaryDirectory() as tmpdir:
        key_dir = os.path.join(tmpdir, 'ed25519', domain, local)
        os.makedirs(key_dir)
        key_file = os.path.join(key_dir, selector)
        with open(key_file, 'w') as fh:
            fh.write(vk_b64)
        yield tmpdir


def _make_test_message(from_addr: str = 'test@example.com',
                       subject: str = 'Test patch',
                       body: str = 'This is a test.\n') -> bytes:
    """Build a minimal RFC2822 message as bytes."""
    msg = email.message.EmailMessage()
    msg['From'] = from_addr
    msg['To'] = 'list@example.com'
    msg['Subject'] = subject
    msg['Message-ID'] = '<test-001@example.com>'
    msg.set_payload(body, charset='utf-8')
    return msg.as_bytes(policy=b4.emlpolicy)


class TestPatattSignVerify:
    """Round-trip sign and verify using ephemeral ed25519 keys."""

    def test_sign_and_verify(self, ed25519_keypair: Tuple[str, str, str, str],
                             keyring_dir: str) -> None:
        """A signed message should validate with the matching public key."""
        privkey_path, _vk_b64, identity, selector = ed25519_keypair
        msg_bytes = _make_test_message(from_addr=identity)

        config: dict[str, Union[str, list[str]]] = {
            'identity': identity,
            'selector': selector,
            'signingkey': f'ed25519:{privkey_path}',
        }
        signed = patatt.rfc2822_sign(msg_bytes, config=config)
        assert b'X-Developer-Signature' in signed

        results = patatt.validate_message(signed, [keyring_dir])
        assert len(results) > 0
        assert results[0][0] == patatt.RES_VALID

    def test_tampered_body_fails(self, ed25519_keypair: Tuple[str, str, str, str],
                                 keyring_dir: str) -> None:
        """Modifying the body after signing should fail validation."""
        privkey_path, _vk_b64, identity, selector = ed25519_keypair
        msg_bytes = _make_test_message(from_addr=identity)

        config: dict[str, Union[str, list[str]]] = {
            'identity': identity,
            'selector': selector,
            'signingkey': f'ed25519:{privkey_path}',
        }
        signed = patatt.rfc2822_sign(msg_bytes, config=config)

        # Tamper with the body
        tampered = signed.replace(b'This is a test.', b'This is TAMPERED.')
        results = patatt.validate_message(tampered, [keyring_dir])
        assert len(results) > 0
        assert results[0][0] == patatt.RES_BADSIG

    def test_wrong_key_fails(self, ed25519_keypair: Tuple[str, str, str, str]) -> None:
        """Validating against a different public key should fail."""
        privkey_path, _vk_b64, identity, selector = ed25519_keypair
        msg_bytes = _make_test_message(from_addr=identity)

        config: dict[str, Union[str, list[str]]] = {
            'identity': identity,
            'selector': selector,
            'signingkey': f'ed25519:{privkey_path}',
        }
        signed = patatt.rfc2822_sign(msg_bytes, config=config)

        # Create a keyring with a different key
        other_sk = SigningKey.generate()
        other_vk_b64 = base64.b64encode(other_sk.verify_key.encode()).decode()
        local, domain = identity.split('@', 1)
        with tempfile.TemporaryDirectory() as tmpdir:
            key_dir = os.path.join(tmpdir, 'ed25519', domain, local)
            os.makedirs(key_dir)
            with open(os.path.join(key_dir, selector), 'w') as fh:
                fh.write(other_vk_b64)
            results = patatt.validate_message(signed, [tmpdir])
            assert len(results) > 0
            assert results[0][0] == patatt.RES_BADSIG

    def test_no_key_available(self, ed25519_keypair: Tuple[str, str, str, str]) -> None:
        """Validating with an empty keyring should return RES_NOKEY."""
        privkey_path, _vk_b64, identity, selector = ed25519_keypair
        msg_bytes = _make_test_message(from_addr=identity)

        config: dict[str, Union[str, list[str]]] = {
            'identity': identity,
            'selector': selector,
            'signingkey': f'ed25519:{privkey_path}',
        }
        signed = patatt.rfc2822_sign(msg_bytes, config=config)

        with tempfile.TemporaryDirectory() as empty_keyring:
            results = patatt.validate_message(signed, [empty_keyring])
            assert len(results) > 0
            assert results[0][0] == patatt.RES_NOKEY

    def test_unsigned_message(self, keyring_dir: str) -> None:
        """An unsigned message should return RES_NOSIG."""
        msg_bytes = _make_test_message()
        results = patatt.validate_message(msg_bytes, [keyring_dir])
        assert len(results) == 1
        assert results[0][0] == patatt.RES_NOSIG

    def test_sign_adds_developer_key_header(self, ed25519_keypair: Tuple[str, str, str, str]) -> None:
        """Signing adds both X-Developer-Signature and X-Developer-Key."""
        privkey_path, _vk_b64, identity, selector = ed25519_keypair
        msg_bytes = _make_test_message(from_addr=identity)

        config: dict[str, Union[str, list[str]]] = {
            'identity': identity,
            'selector': selector,
            'signingkey': f'ed25519:{privkey_path}',
        }
        signed = patatt.rfc2822_sign(msg_bytes, config=config)
        assert b'X-Developer-Signature' in signed
        assert b'X-Developer-Key' in signed
        assert b'a=ed25519' in signed
        assert identity.encode() in signed
