"""Tests for trust on first use (TOFU) of patatt ed25519 keys.

Every message is signed during the test run with a throwaway ed25519
key, so no private keys are shipped with the test samples.
"""

import base64
import email.message
import email.parser
import logging
import pathlib
import sqlite3
import threading
from collections.abc import Generator
from typing import Any, Dict, List, Optional, Sequence

import pytest

pytest.importorskip('nacl')

from nacl.signing import SigningKey

import b4
import patatt
from b4 import tofu

from .helpers.mail import MINIMAL_DIFF, make_msg


class Dev:
    """A developer with a throwaway ed25519 key."""

    def __init__(self, tmp_path: pathlib.Path, email_addr: str, name: str) -> None:
        self.email = email_addr
        self.name = name
        sk = SigningKey.generate()
        self.pk = base64.b64encode(sk.verify_key.encode()).decode()
        self.keyfile = tmp_path / f'{name}-{self.pk[:8].replace("/", "_")}.key'
        self.keyfile.write_text(base64.b64encode(sk.encode()).decode())

    @property
    def from_addr(self) -> str:
        return f'{self.name.capitalize()} <{self.email}>'

    def sign(
        self,
        msg: email.message.EmailMessage,
        identity: Optional[str] = None,
        selector: str = 'default',
    ) -> email.message.EmailMessage:
        config: Dict[str, Any] = {
            'identity': identity or self.email,
            'selector': selector,
            'signingkey': f'ed25519:{self.keyfile}',
        }
        # patatt caches the signing key per identity, but in these tests
        # one address can have more than one key
        patatt.KEYCACHE.pop(config['identity'], None)
        signed = patatt.rfc2822_sign(msg.as_bytes(policy=b4.emlpolicy), config=config)
        return parse(signed)


def parse(raw: bytes) -> email.message.EmailMessage:
    return email.parser.BytesParser(
        policy=b4.emlpolicy, _class=email.message.EmailMessage
    ).parsebytes(raw)


def series_msgs(
    dev: Dev,
    tag: str,
    count: int = 2,
    cover: bool = True,
    revision: int = 1,
    unsigned: Sequence[int] = (),
    signers: Optional[Dict[int, Dev]] = None,
    skip: Sequence[int] = (),
) -> List[email.message.EmailMessage]:
    """Build one revision of a series sent by *dev*.

    Message 0 is the cover letter.  *unsigned* lists the messages left
    unsigned, *signers* maps messages to a different signing key (same
    address), and *skip* lists messages left out of the result.
    """
    signers = signers or dict()
    vtag = f' v{revision}' if revision > 1 else ''
    cover_id = f'{tag}-0@example.com'
    msgs: List[email.message.EmailMessage] = list()
    first = 0 if cover else 1
    for num in range(first, count + 1):
        if num == 0:
            subject = f'[PATCH{vtag} 0/{count}] foo: a series'
            body = 'This is the cover letter.\n'
            irt = None
        else:
            subject = f'[PATCH{vtag} {num}/{count}] foo: change {num}'
            body = MINIMAL_DIFF.replace(
                'bar();', f'bar{num}_{tag.replace("-", "_")}();'
            )
            irt = cover_id if cover else (f'{tag}-1@example.com' if num > 1 else None)
        msg = make_msg(
            f'{tag}-{num}@example.com',
            subject,
            from_addr=dev.from_addr,
            body=body,
            in_reply_to=irt,
            references=f'<{irt}>' if irt else None,
        )
        if num not in unsigned:
            msg = signers.get(num, dev).sign(msg)
        if num not in skip:
            msgs.append(msg)
    return msgs


def followup_msg(
    dev: Dev, tag: str, parent: str, trailer: str = ''
) -> email.message.EmailMessage:
    msg = make_msg(
        f'{tag}@example.com',
        'Re: [PATCH 1/2] foo: change 1',
        from_addr=dev.from_addr,
        body=(trailer or f'Reviewed-by: {dev.from_addr}') + '\n',
        in_reply_to=parent,
        references=f'<{parent}>',
    )
    return dev.sign(msg)


def get_series(msgs: Sequence[email.message.EmailMessage]) -> b4.LoreSeries:
    lmbx = b4.LoreMailbox()
    for msg in msgs:
        lmbx.add_message(msg)
    lser = lmbx.get_series()
    assert lser is not None
    return lser


def load(msg: email.message.EmailMessage) -> b4.LoreMessage:
    return b4.LoreMessage(parse(msg.as_bytes(policy=b4.emlpolicy)))


def statuses(lmsg: b4.LoreMessage, policy: str = 'softfail') -> List[str]:
    atts, _passing, _critical = lmsg.get_attestation_status(policy, tofu=True)
    return [att['status'] for att in atts]


def series_statuses(lser: b4.LoreSeries) -> List[str]:
    """Record the series, then return the status of every patch we have."""
    tofu.record_series(lser)
    out: List[str] = list()
    for lmsg in lser.patches[1:]:
        if lmsg is not None:
            out += statuses(lmsg)
    return out


def tofu_info(lmsg: b4.LoreMessage) -> Dict[str, Any]:
    atts, _passing, _critical = lmsg.get_attestation_status('softfail', tofu=True)
    assert len(atts) == 1
    return atts[0]


def db() -> sqlite3.Connection:
    return tofu.connect()


def key_rows(identity: str) -> Dict[str, str]:
    conn = db()
    try:
        rows = conn.execute(
            'SELECT pk, status FROM keys WHERE identity = ?', (identity,)
        ).fetchall()
    finally:
        conn.close()
    return {pk: status for pk, status in rows}


def set_key_status(identity: str, pk: str, status: str) -> None:
    conn = db()
    try:
        conn.execute(
            'UPDATE keys SET status = ?, '
            'changed_at = (SELECT MAX(seen_at) FROM sightings) + 1 '
            'WHERE identity = ? AND pk = ?',
            (status, identity, pk),
        )
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def tofu_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> Generator[pathlib.Path, None, None]:
    """Attestation on, an empty keyring, and fresh TOFU caches."""
    # patatt caches signing keys; start every test with an empty cache
    monkeypatch.setattr(patatt, 'KEYCACHE', {})
    keyring = tmp_path / 'keyring-src'
    keyring.mkdir()
    monkeypatch.setitem(b4.MAIN_CONFIG, 'attestation-policy', 'softfail')
    monkeypatch.setitem(b4.MAIN_CONFIG, 'attestation-checkmarks', 'plain')
    monkeypatch.setitem(b4.MAIN_CONFIG, 'attestation-staleness-days', '0')
    monkeypatch.setitem(b4.MAIN_CONFIG, 'keyringsrc', [str(keyring)])
    monkeypatch.setitem(b4.MAIN_CONFIG, 'gpgbin', 'gpg')
    tofu.reset_caches()
    yield keyring
    tofu.reset_caches()


@pytest.fixture()
def alice(tmp_path: pathlib.Path) -> Dev:
    return Dev(tmp_path, 'alice@example.org', 'alice')


@pytest.fixture()
def alice2(tmp_path: pathlib.Path) -> Dev:
    """Alice's second key."""
    return Dev(tmp_path, 'alice@example.org', 'alice')


@pytest.fixture()
def mallory(tmp_path: pathlib.Path) -> Dev:
    return Dev(tmp_path, 'mallory@example.net', 'mallory')


def install_key(keyring: pathlib.Path, dev: Dev, selector: str = 'default') -> None:
    local, domain = dev.email.split('@')
    keyfile = keyring / 'ed25519' / domain / local / selector
    keyfile.parent.mkdir(parents=True, exist_ok=True)
    keyfile.write_text(dev.pk + '\n')


class TestEmbeddedKey:
    """A "no key" ed25519 signature is checked with the key the message carries."""

    def test_valid_signature_sets_tofu_pk(self, alice: Dev) -> None:
        lmsg = load(series_msgs(alice, 'emb', count=1, cover=False)[0])
        (att,) = lmsg.attestors
        assert att.tofu_pk == alice.pk
        # Code that does not know about TOFU still sees "no key"
        assert not att.passing
        assert not att.have_key

    def test_tampered_body_is_badsig(self, alice: Dev) -> None:
        msg = series_msgs(alice, 'emb', count=1, cover=False)[0]
        raw = msg.as_bytes(policy=b4.emlpolicy).replace(b'bar1_emb', b'evil_emb')
        (att,) = b4.LoreMessage(parse(raw)).attestors
        assert att.tofu_pk is None
        assert att.have_key and not att.passing

    def test_wrong_embedded_key_is_badsig(self, alice: Dev, alice2: Dev) -> None:
        msg = series_msgs(alice, 'emb', count=1, cover=False)[0]
        raw = msg.as_bytes(policy=b4.emlpolicy).replace(
            alice.pk.encode(), alice2.pk.encode()
        )
        (att,) = b4.LoreMessage(parse(raw)).attestors
        assert att.tofu_pk is None
        assert att.have_key and not att.passing

    def test_missing_key_header_stays_nokey(self, alice: Dev) -> None:
        msg = series_msgs(alice, 'emb', count=1, cover=False)[0]
        del msg['X-Developer-Key']
        lmsg = load(msg)
        (att,) = lmsg.attestors
        assert att.tofu_pk is None
        assert statuses(lmsg) == ['nokey']

    def test_identity_not_matching_sender_never_pins(
        self, alice: Dev, mallory: Dev
    ) -> None:
        # Mallory signs as Alice, but sends from her own address
        msgs = series_msgs(mallory, 'mis', count=1, cover=False, unsigned=[1])
        msgs = [mallory.sign(msgs[0], identity=alice.email)]
        lser = get_series(msgs)
        assert series_statuses(lser) == ['nokey']
        assert key_rows(alice.email) == {}

    def test_disabled_tofu_is_plain_nokey(
        self, monkeypatch: pytest.MonkeyPatch, alice: Dev
    ) -> None:
        monkeypatch.setitem(b4.MAIN_CONFIG, 'attestation-tofu', 'no')
        lser = get_series(series_msgs(alice, 'off'))
        assert series_statuses(lser) == ['nokey', 'nokey']
        assert key_rows(alice.email) == {}

    def test_status_without_tofu_flag_is_nokey(self, alice: Dev) -> None:
        """Readers that did not ask for TOFU, like the review TUI, see "no key"."""
        lser = get_series(series_msgs(alice, 'flag'))
        tofu.record_series(lser)
        lmsg = lser.patches[1]
        assert lmsg is not None
        atts, _passing, _critical = lmsg.get_attestation_status('softfail')
        assert [att['status'] for att in atts] == ['nokey']

    def test_trimmed_signature_trims_body(self, alice: Dev) -> None:
        msg = series_msgs(alice, 'trim', count=1, cover=False)[0]
        raw = msg.as_bytes(policy=b4.emlpolicy) + b'\nAppended junk\n'
        lmsg = b4.LoreMessage(parse(raw))
        (att,) = lmsg.attestors
        assert att.tofu_pk == alice.pk
        assert 'Appended junk' not in lmsg.body

    def test_embedded_check_is_remembered(
        self, monkeypatch: pytest.MonkeyPatch, alice: Dev
    ) -> None:
        calls = 0
        real_validate = patatt.PatattMessage.validate

        def counting(self: patatt.PatattMessage, *args: Any, **kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            return real_validate(self, *args, **kwargs)

        monkeypatch.setattr(patatt.PatattMessage, 'validate', counting)
        msg = series_msgs(alice, 'mem', count=1, cover=False)[0]
        assert load(msg).attestors[0].tofu_pk == alice.pk
        first = calls
        assert load(msg).attestors[0].tofu_pk == alice.pk
        assert first > 0
        assert calls == first


class TestPinAndCount:
    def test_first_series_pins(self, alice: Dev) -> None:
        lser = get_series(series_msgs(alice, 's1'))
        assert series_statuses(lser) == ['tofu-new', 'tofu-new']
        assert key_rows(alice.email) == {alice.pk: 'trusted'}

    def test_second_revision_counts(self, alice: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        lser = get_series(series_msgs(alice, 's2', revision=2))
        assert series_statuses(lser) == ['tofu', 'tofu']
        lmsg = lser.patches[1]
        assert lmsg is not None
        assert tofu_info(lmsg)['tofu']['count'] == 1

    def test_same_revision_twice_counts_once(self, alice: Dev) -> None:
        for _ in range(3):
            lser = get_series(series_msgs(alice, 's1'))
            assert series_statuses(lser) == ['tofu-new', 'tofu-new']
        lser = get_series(series_msgs(alice, 's2', revision=2))
        series_statuses(lser)
        lmsg = lser.patches[1]
        assert lmsg is not None
        assert tofu_info(lmsg)['tofu']['count'] == 1

    def test_series_without_cover_letter(self, alice: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1', cover=False)))
        lser = get_series(series_msgs(alice, 's2', cover=False, revision=2))
        assert series_statuses(lser) == ['tofu', 'tofu']

    @pytest.mark.parametrize(
        'kwargs',
        [
            pytest.param({'skip': [2]}, id='incomplete'),
            pytest.param({'unsigned': [2]}, id='unsigned-patch'),
        ],
    )
    def test_series_pins_but_does_not_count(
        self, alice: Dev, kwargs: Dict[str, Any]
    ) -> None:
        series_statuses(get_series(series_msgs(alice, 's1', **kwargs)))
        assert key_rows(alice.email) == {alice.pk: 'trusted'}
        lser = get_series(series_msgs(alice, 's2', revision=2))
        # The first series added no trust
        assert series_statuses(lser) == ['tofu-new', 'tofu-new']

    def test_unsigned_cover_letter_still_counts(self, alice: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1', unsigned=[0])))
        lser = get_series(series_msgs(alice, 's2', revision=2))
        assert series_statuses(lser) == ['tofu', 'tofu']

    def test_cover_letter_with_other_key_does_not_count(
        self, alice: Dev, alice2: Dev
    ) -> None:
        lser = get_series(series_msgs(alice, 's1', signers={0: alice2}))
        tofu.record_series(lser)
        # The cover letter came first, so its key was pinned
        assert key_rows(alice.email) == {alice2.pk: 'trusted', alice.pk: 'pending'}
        assert series_statuses(lser) == ['tofu-changed', 'tofu-changed']
        lser = get_series(series_msgs(alice2, 's2', revision=2))
        assert series_statuses(lser) == ['tofu-new', 'tofu-new']

    def test_same_key_new_address_is_new_identity(
        self, tmp_path: pathlib.Path, alice: Dev
    ) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        work = Dev(tmp_path, 'alice@corp.example.com', 'alice')
        work.keyfile = alice.keyfile
        work.pk = alice.pk
        lser = get_series(series_msgs(work, 's2'))
        assert series_statuses(lser) == ['tofu-new', 'tofu-new']
        assert tofu.print_warnings([m for m in lser.patches if m]) == []


class TestKeyChange:
    def test_new_key_is_changed_and_pending(self, alice: Dev, alice2: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        lser = get_series(series_msgs(alice2, 's2', revision=2))
        assert series_statuses(lser) == ['tofu-changed', 'tofu-changed']
        assert key_rows(alice.email) == {alice.pk: 'trusted', alice2.pk: 'pending'}
        # The pending key keeps collecting evidence, but no trust
        lser = get_series(series_msgs(alice2, 's3', revision=3))
        assert series_statuses(lser) == ['tofu-changed', 'tofu-changed']

    def test_two_keys_in_one_series(self, alice: Dev, alice2: Dev) -> None:
        lser = get_series(series_msgs(alice, 's1', signers={2: alice2}))
        assert series_statuses(lser) == ['tofu-new', 'tofu-changed']
        lser = get_series(series_msgs(alice, 's2', revision=2))
        # The mixed series did not count
        assert series_statuses(lser) == ['tofu-new', 'tofu-new']

    def test_warning_is_printed_once(
        self, caplog: pytest.LogCaptureFixture, alice: Dev, alice2: Dev
    ) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        lser = get_series(series_msgs(alice2, 's2', revision=2))
        tofu.record_series(lser)
        members = [m for m in lser.patches if m]
        with caplog.at_level(logging.CRITICAL, logger='b4'):
            printed = tofu.print_warnings(members)
            assert tofu.print_warnings(members) == []
        assert [(w['identity'], w['pk']) for w in printed] == [(alice.email, alice2.pk)]
        text = caplog.text
        assert f'KEY CHANGED: {alice.email}' in text
        assert alice.pk in text and alice2.pk in text
        assert 'Trusted key:' in text

    def test_concurrent_writers_pin_exactly_one_key(
        self, alice: Dev, alice2: Dev
    ) -> None:
        sers = [
            get_series(series_msgs(alice, 's1')),
            get_series(series_msgs(alice2, 's2')),
        ]
        # Check the signatures first, so the threads only race on the store
        for lser in sers:
            for lmsg in lser.patches:
                if lmsg is not None:
                    assert lmsg.attestors
        barrier = threading.Barrier(len(sers))

        def worker(lser: b4.LoreSeries) -> None:
            barrier.wait()
            tofu.record_series(lser)

        threads = [threading.Thread(target=worker, args=(s,)) for s in sers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sorted(key_rows(alice.email).values()) == ['pending', 'trusted']


class TestFollowups:
    def test_followup_never_pins(self, alice: Dev) -> None:
        lmsg = load(followup_msg(alice, 'fu', 'elsewhere@example.com'))
        assert lmsg.reply
        assert statuses(lmsg) == ['nokey']
        # Even next to an unsigned series, a follow-up is not a series member
        msgs = series_msgs(alice, 's1', unsigned=[0, 1, 2])
        msgs.append(followup_msg(alice, 'fu2', 's1-1@example.com'))
        tofu.record_series(get_series(msgs))
        assert key_rows(alice.email) == {}

    def test_followup_with_trusted_key(self, alice: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        lmsg = load(followup_msg(alice, 'fu', 's1-1@example.com'))
        assert statuses(lmsg) == ['tofu']
        assert tofu_info(lmsg)['tofu']['count'] == 1

    def test_followups_do_not_count(self, alice: Dev) -> None:
        msgs = series_msgs(alice, 's1')
        msgs.append(followup_msg(alice, 'fu', 's1-1@example.com'))
        lser = get_series(msgs)
        series_statuses(lser)
        conn = db()
        try:
            rows = conn.execute('SELECT msgid FROM sightings ORDER BY msgid').fetchall()
        finally:
            conn.close()
        assert [r[0] for r in rows] == [
            's1-0@example.com',
            's1-1@example.com',
            's1-2@example.com',
        ]

    def test_followup_with_other_key_is_changed(self, alice: Dev, alice2: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        lmsg = load(followup_msg(alice2, 'fu', 's1-1@example.com'))
        assert statuses(lmsg) == ['tofu-changed']
        # Checking it changed nothing
        assert key_rows(alice.email) == {alice.pk: 'trusted'}


class TestKeyring:
    def test_keyring_key_is_never_tofu(
        self, tofu_env: pathlib.Path, alice: Dev
    ) -> None:
        install_key(tofu_env, alice)
        lser = get_series(series_msgs(alice, 's1'))
        assert series_statuses(lser) == ['signed', 'signed']
        assert key_rows(alice.email) == {}

    def test_same_key_under_other_selector_is_signed(
        self, tofu_env: pathlib.Path, alice: Dev
    ) -> None:
        install_key(tofu_env, alice, selector='20211009')
        lser = get_series(series_msgs(alice, 's1'))
        assert series_statuses(lser) == ['signed', 'signed']
        assert key_rows(alice.email) == {}

    def test_selector_gap_is_a_key_change(
        self,
        caplog: pytest.LogCaptureFixture,
        tofu_env: pathlib.Path,
        alice: Dev,
        alice2: Dev,
    ) -> None:
        install_key(tofu_env, alice, selector='20211009')
        lser = get_series(series_msgs(alice2, 's1'))
        assert series_statuses(lser) == ['tofu-changed', 'tofu-changed']
        # Nothing is pinned for an identity the keyring covers
        assert key_rows(alice.email) == {}
        with caplog.at_level(logging.CRITICAL, logger='b4'):
            tofu.print_warnings([m for m in lser.patches if m])
        assert 'the one in your keyring' in caplog.text
        assert f'Keyring key:  {alice.pk}' in caplog.text

    def test_selector_gap_in_git_ref_keyring(
        self,
        monkeypatch: pytest.MonkeyPatch,
        gitdir: str,
        alice: Dev,
        alice2: Dev,
    ) -> None:
        keyring = pathlib.Path(gitdir) / '.keys'
        install_key(keyring, alice, selector='20211009')
        ecode, _ = b4.git_run_command(gitdir, ['add', '.keys'])
        assert ecode == 0
        ecode, _ = b4.git_run_command(gitdir, ['commit', '-m', 'add keys'])
        assert ecode == 0
        # Keep only the committed copy
        (keyring / 'ed25519' / 'example.org' / 'alice' / '20211009').unlink()
        monkeypatch.setitem(b4.MAIN_CONFIG, 'keyringsrc', [f'ref:{gitdir}::.keys'])
        lser = get_series(series_msgs(alice2, 's1'))
        assert series_statuses(lser) == ['tofu-changed', 'tofu-changed']
        assert tofu.keyring_keys(alice.email, [f'ref:{gitdir}::.keys']) == [alice.pk]


class TestStatusesAndPolicies:
    @pytest.mark.parametrize(
        ('policy', 'critical'), [('softfail', False), ('hardfail', True)]
    )
    def test_changed_key(
        self, alice: Dev, alice2: Dev, policy: str, critical: bool
    ) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        lmsg = load(series_msgs(alice2, 's2', count=1, cover=False)[0])
        atts, passing, crit = lmsg.get_attestation_status(policy, tofu=True)
        assert [a['status'] for a in atts] == ['tofu-changed']
        assert not passing
        assert crit is critical

    @pytest.mark.parametrize('policy', ['softfail', 'hardfail'])
    def test_new_key_is_never_critical(self, alice: Dev, policy: str) -> None:
        lmsg = load(series_msgs(alice, 's1', count=1, cover=False)[0])
        atts, passing, crit = lmsg.get_attestation_status(policy, tofu=True)
        assert [a['status'] for a in atts] == ['tofu-new']
        assert passing and not crit

    @pytest.mark.parametrize(
        ('policy', 'critical'), [('softfail', False), ('hardfail', True)]
    )
    def test_rejected_key_takes_effect_at_once(
        self, alice: Dev, policy: str, critical: bool
    ) -> None:
        lser = get_series(series_msgs(alice, 's1'))
        assert series_statuses(lser) == ['tofu-new', 'tofu-new']
        set_key_status(alice.email, alice.pk, 'rejected')
        lmsg = lser.patches[1]
        assert lmsg is not None
        atts, _passing, crit = lmsg.get_attestation_status(policy, tofu=True)
        assert [a['status'] for a in atts] == ['tofu-rejected']
        assert crit is critical

    def test_retired_key_history(
        self, monkeypatch: pytest.MonkeyPatch, alice: Dev
    ) -> None:
        old = get_series(series_msgs(alice, 's1'))
        series_statuses(old)
        set_key_status(alice.email, alice.pk, 'retired')
        # A message we saw before the key was retired is known history
        lmsg = old.patches[1]
        assert lmsg is not None
        att = tofu_info(lmsg)
        assert att['status'] == 'tofu' and att['tofu']['retired']
        # A new message with the old key is not, even when its t= says
        # it was signed long ago
        monkeypatch.setattr(patatt.time, 'time', lambda: 1_000_000_000.0)
        new = load(series_msgs(alice, 's2', count=1, cover=False)[0])
        atts, passing, crit = new.get_attestation_status('hardfail', tofu=True)
        assert [a['status'] for a in atts] == ['tofu-retired']
        assert not passing and not crit

    def test_time_drift_is_badsig(
        self, monkeypatch: pytest.MonkeyPatch, alice: Dev
    ) -> None:
        # Signed a year after the Date: header
        monkeypatch.setattr(patatt.time, 'time', lambda: 1_806_000_000.0)
        lmsg = load(series_msgs(alice, 's1', count=1, cover=False)[0])
        atts, _passing, _crit = lmsg.get_attestation_status(
            'softfail', maxdays=30, tofu=True
        )
        assert [a['status'] for a in atts] == ['badsig']

    def test_trailers(self, alice: Dev, alice2: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        lmsg = load(series_msgs(alice, 's1', count=1, cover=False)[0])
        _mark, trailers, _crit = lmsg.get_attestation_trailers('softfail')
        assert trailers == [f'? Signed: ed25519/{alice.email} (TOFU, first seen)']
        series_statuses(get_series(series_msgs(alice, 's2', revision=2)))
        series_statuses(get_series(series_msgs(alice, 's3', revision=3)))
        lmsg = load(series_msgs(alice, 's4', count=1, cover=False)[0])
        mark, trailers, _crit = lmsg.get_attestation_trailers('softfail')
        assert mark == 'v'
        assert trailers == [f'v Signed: ed25519/{alice.email} (TOFU, 3 other series)']
        lmsg = load(series_msgs(alice2, 's5', count=1, cover=False)[0])
        mark, trailers, _crit = lmsg.get_attestation_trailers('softfail')
        assert mark == 'x'
        assert trailers == [f'x KEY CHANGED: ed25519/{alice.email}']


class TestAmReady:
    """b4 am / b4 shazam: record, warn, and stop under hardfail."""

    def test_first_series(self, caplog: pytest.LogCaptureFixture, alice: Dev) -> None:
        lser = get_series(series_msgs(alice, 's1'))
        with caplog.at_level(logging.INFO, logger='b4'):
            assert len(lser.get_am_ready()) == 2
        assert f'? Signed: ed25519/{alice.email} (TOFU, first seen)' in caplog.text
        assert key_rows(alice.email) == {alice.pk: 'trusted'}

    def test_changed_key_softfail_warns(
        self, caplog: pytest.LogCaptureFixture, alice: Dev, alice2: Dev
    ) -> None:
        get_series(series_msgs(alice, 's1')).get_am_ready()
        lser = get_series(series_msgs(alice2, 's2', revision=2))
        with caplog.at_level(logging.INFO, logger='b4'):
            assert len(lser.get_am_ready()) == 2
        assert f'KEY CHANGED: {alice.email}' in caplog.text
        assert f'x KEY CHANGED: ed25519/{alice.email}' in caplog.text

    def test_changed_key_hardfail_exits(
        self, monkeypatch: pytest.MonkeyPatch, alice: Dev, alice2: Dev
    ) -> None:
        get_series(series_msgs(alice, 's1')).get_am_ready()
        monkeypatch.setitem(b4.MAIN_CONFIG, 'attestation-policy', 'hardfail')
        lser = get_series(series_msgs(alice2, 's2', revision=2))
        with pytest.raises(SystemExit):
            lser.get_am_ready()

    def test_followup_with_changed_key_hardfail_exits(
        self, monkeypatch: pytest.MonkeyPatch, alice: Dev, alice2: Dev, mallory: Dev
    ) -> None:
        get_series(series_msgs(alice, 's0')).get_am_ready()
        monkeypatch.setitem(b4.MAIN_CONFIG, 'attestation-policy', 'hardfail')
        msgs = series_msgs(mallory, 's1', unsigned=[0, 1, 2])
        msgs.append(followup_msg(alice2, 'fu', 's1-1@example.com'))
        with pytest.raises(SystemExit):
            get_series(msgs).get_am_ready()

    def test_followup_with_trusted_key_hardfail_passes(
        self, monkeypatch: pytest.MonkeyPatch, alice: Dev, mallory: Dev
    ) -> None:
        get_series(series_msgs(alice, 's0')).get_am_ready()
        monkeypatch.setitem(b4.MAIN_CONFIG, 'attestation-policy', 'hardfail')
        msgs = series_msgs(mallory, 's1', unsigned=[0, 1, 2])
        msgs.append(followup_msg(alice, 'fu', 's1-1@example.com'))
        lser = get_series(msgs)
        # Unsigned patches are "no key", which hardfail tolerates
        am_msgs = lser.get_am_ready()
        assert f'Reviewed-by: {alice.from_addr}' in am_msgs[0].as_string()
