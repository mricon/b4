"""Integration tests for patatt sign/verify within b4.

Uses ephemeral ed25519 keys so no external key material is needed.
"""

import base64
import email.message
import email.parser
import os
import pathlib
import sqlite3
import tempfile
import time
from collections.abc import Generator
from typing import Any, List, Tuple, Union

import pytest

pytest.importorskip('nacl')

from nacl.signing import SigningKey

import b4
import patatt


@pytest.fixture(autouse=True)
def empty_keycache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start each test with an empty patatt key cache.

    patatt caches the signing key by identity, and every test here signs
    as the same identity with its own new key.  Without this, a test can
    sign with the key of a test that ran before it.
    """
    monkeypatch.setattr(patatt, 'KEYCACHE', {})


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
    with tempfile.NamedTemporaryFile(mode='w', suffix='.key', delete=False) as fh:
        fh.write(sk_b64)
        privkey_path = fh.name
    yield privkey_path, vk_b64, 'test@example.com', 'default'
    os.unlink(privkey_path)


@pytest.fixture()
def keyring_dir(
    ed25519_keypair: Tuple[str, str, str, str],
) -> Generator[str, None, None]:
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


def _signing_config(
    keypair: Tuple[str, str, str, str],
) -> dict[str, Union[str, list[str]]]:
    """Build the patatt signing config for an ed25519_keypair fixture value."""
    privkey_path, _vk_b64, identity, selector = keypair
    return {
        'identity': identity,
        'selector': selector,
        'signingkey': f'ed25519:{privkey_path}',
    }


def _make_test_message(
    from_addr: str = 'test@example.com',
    subject: str = 'Test patch',
    body: str = 'This is a test.\n',
) -> bytes:
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

    def test_sign_and_verify(
        self, ed25519_keypair: Tuple[str, str, str, str], keyring_dir: str
    ) -> None:
        """A signed message validates; signing adds both signature and key headers."""
        identity = ed25519_keypair[2]
        msg_bytes = _make_test_message(from_addr=identity)

        config = _signing_config(ed25519_keypair)
        signed = patatt.rfc2822_sign(msg_bytes, config=config)
        assert b'X-Developer-Signature' in signed
        assert b'X-Developer-Key' in signed
        assert b'a=ed25519' in signed
        assert identity.encode() in signed

        results = patatt.validate_message(signed, [keyring_dir])
        assert len(results) > 0
        assert results[0][0] == patatt.RES_VALID

    def test_tampered_body_fails(
        self, ed25519_keypair: Tuple[str, str, str, str], keyring_dir: str
    ) -> None:
        """Modifying the body after signing should fail validation."""
        identity = ed25519_keypair[2]
        msg_bytes = _make_test_message(from_addr=identity)

        config = _signing_config(ed25519_keypair)
        signed = patatt.rfc2822_sign(msg_bytes, config=config)

        # Tamper with the body
        tampered = signed.replace(b'This is a test.', b'This is TAMPERED.')
        results = patatt.validate_message(tampered, [keyring_dir])
        assert len(results) > 0
        assert results[0][0] == patatt.RES_BADSIG

    def test_wrong_key_fails(self, ed25519_keypair: Tuple[str, str, str, str]) -> None:
        """Validating against a different public key should fail."""
        _privkey, _vk_b64, identity, selector = ed25519_keypair
        msg_bytes = _make_test_message(from_addr=identity)

        config = _signing_config(ed25519_keypair)
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
        identity = ed25519_keypair[2]
        msg_bytes = _make_test_message(from_addr=identity)

        config = _signing_config(ed25519_keypair)
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


class _Clock:
    """Stands in for the time module inside b4, on a clock the test sets."""

    def __init__(self) -> None:
        self.now = 1_790_000_000.0

    def time(self) -> float:
        return self.now

    def __getattr__(self, name: str) -> Any:
        return getattr(time, name)


class TestPatattStore:
    """A patatt result is remembered for a day, unless the key is missing."""

    HOUR = 3600
    DAY = 86400
    MSG = (
        b'From: Test Sender <test@example.com>\r\n'
        b'To: list@example.com\r\n'
        b'Subject: [PATCH] foo: fix the bar\r\n'
        b'Date: Sat, 03 Oct 2026 12:00:00 +0000\r\n'
        b'Message-ID: <patatt-store@example.com>\r\n'
        b'\r\n'
        b'Just a test.\r\n'
    )

    @pytest.fixture(autouse=True)
    def setup(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: pathlib.Path,
        ed25519_keypair: Tuple[str, str, str, str],
    ) -> None:
        self.pubkey = ed25519_keypair[1]
        selector = ed25519_keypair[3]
        self.signcfg = _signing_config(ed25519_keypair)
        self.keyring = tmp_path / 'keyring-src'
        self.keyfile = self.keyring / 'ed25519' / 'example.com' / 'test' / selector
        self.keyfile.parent.mkdir(parents=True)
        monkeypatch.setitem(b4.MAIN_CONFIG, 'attestation-policy', 'softfail')
        monkeypatch.setitem(b4.MAIN_CONFIG, 'keyringsrc', [str(self.keyring)])
        monkeypatch.setitem(b4.MAIN_CONFIG, 'gpgbin', 'gpg')
        self.clock = _Clock()
        monkeypatch.setattr(b4, 'time', self.clock)
        self.validations = 0
        real_validate = patatt.validate_message

        def counting_validate(*args: Any, **kwargs: Any) -> Any:
            self.validations += 1
            return real_validate(*args, **kwargs)

        monkeypatch.setattr(patatt, 'validate_message', counting_validate)

    def _install_key(self, pubkey: str = '') -> None:
        self.keyfile.write_text(pubkey or self.pubkey)

    def _sign(self) -> bytes:
        return patatt.rfc2822_sign(self.MSG, config=self.signcfg)

    @staticmethod
    def _load(raw: bytes) -> b4.LoreMessage:
        msg = email.parser.BytesParser(
            policy=b4.emlpolicy, _class=email.message.EmailMessage
        ).parsebytes(raw)
        return b4.LoreMessage(msg)

    def _check(self, raw: bytes) -> List[Any]:
        """The patatt attestors of a freshly parsed copy of *raw*."""
        return [a for a in self._load(raw).attestors if a.mode == 'patatt']

    def _status(self, raw: bytes) -> str:
        atts = self._check(raw)
        assert len(atts) == 1
        if atts[0].passing:
            return 'pass'
        return 'badsig' if atts[0].have_key else 'nokey'

    def test_pass_is_not_checked_again(self) -> None:
        """The second look at a verified message doesn't run patatt."""
        self._install_key()
        raw = self._sign()
        assert self._status(raw) == 'pass'
        assert self.validations == 1
        assert self._status(raw) == 'pass'
        assert self.validations == 1

    def test_pass_is_trusted_for_less_than_a_day(self) -> None:
        """A key removed from the keyring stops passing within a day."""
        self._install_key()
        raw = self._sign()
        assert self._status(raw) == 'pass'
        self.keyfile.unlink()
        # The earliest an entry may expire
        self.clock.now += 20 * self.HOUR - 1
        assert self._status(raw) == 'pass'
        # The latest an entry may expire
        self.clock.now += 4 * self.HOUR + 1
        assert self._status(raw) == 'nokey'

    def test_badsig_is_remembered(self) -> None:
        """A signature that fails with a key we have is not checked again."""
        self._install_key(
            base64.b64encode(SigningKey.generate().verify_key.encode()).decode()
        )
        raw = self._sign()
        assert self._status(raw) == 'badsig'
        checked = self.validations
        assert self._status(raw) == 'badsig'
        assert self.validations == checked

    def test_nokey_is_not_remembered(self) -> None:
        """A key imported after a check makes the very next check pass."""
        raw = self._sign()
        assert self._status(raw) == 'nokey'
        self._install_key()
        assert self._status(raw) == 'pass'

    def test_nokey_is_checked_once(self) -> None:
        """Trimming the body can't find a missing key, so it isn't tried."""
        assert self._status(self._sign()) == 'nokey'
        assert self.validations == 1

    def test_trimmed_pass_trims_body_when_recalled(self) -> None:
        """Text added after the signed length is cut off, from the store too."""
        self._install_key()
        raw = self._sign() + b'Unsigned extra text.\r\n'
        first = self._load(raw)
        assert [a.passing for a in first.attestors] == [True]
        assert 'Unsigned extra text' not in first.body
        checked = self.validations
        again = self._load(raw)
        assert [a.passing for a in again.attestors] == [True]
        assert self.validations == checked
        assert 'Unsigned extra text' not in again.body

    def test_changed_message_is_checked_again(self) -> None:
        """A result is for the exact bytes, so an edited copy is not trusted."""
        self._install_key()
        raw = self._sign()
        assert self._status(raw) == 'pass'
        tampered = raw.replace(b'[PATCH] foo', b'[PATCH] f00')
        assert self._status(tampered) == 'badsig'

    def test_changed_keyring_setting_is_checked_again(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
    ) -> None:
        """A pass from one keyring doesn't carry over to another."""
        self._install_key()
        raw = self._sign()
        assert self._status(raw) == 'pass'
        empty = tmp_path / 'empty-keyring'
        empty.mkdir()
        monkeypatch.setitem(b4.MAIN_CONFIG, 'keyringsrc', [str(empty)])
        assert self._status(raw) == 'nokey'

    def test_expired_entries_are_pruned(self) -> None:
        """Entries older than a day are deleted, so the store doesn't grow."""
        self._install_key()
        assert self._status(self._sign()) == 'pass'
        self.clock.now += self.DAY + 1
        other = patatt.rfc2822_sign(
            self.MSG.replace(b'fix the bar', b'fix the baz'), config=self.signcfg
        )
        assert self._status(other) == 'pass'
        conn = sqlite3.connect(b4._patatt_store_path())
        try:
            (count,) = conn.execute('SELECT COUNT(*) FROM patatt_checked').fetchone()
        finally:
            conn.close()
        assert count == 1

    def test_unusable_store_still_verifies(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
    ) -> None:
        """If the store can't be opened, b4 checks every time, as before."""
        blocker = tmp_path / 'not-a-dir'
        blocker.write_text('')
        monkeypatch.setattr(
            b4, '_patatt_store_path', lambda: str(blocker / 'patatt.sqlite3')
        )
        self._install_key()
        raw = self._sign()
        assert self._status(raw) == 'pass'
        assert self._status(raw) == 'pass'
        assert self.validations == 2
