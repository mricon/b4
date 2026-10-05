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
from typing import Any, Dict, List, Optional, Sequence, Tuple

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


def latest_status(dev: Dev, tag: str) -> str:
    """The status of a new single patch from *dev*, not recorded."""
    (status,) = statuses(load(series_msgs(dev, tag, count=1, cover=False)[0]))
    return status


class TestReconcile:
    """The tofu.py helpers behind the b4 kr subcommands."""

    def test_accept_add_trusts_both(self, alice: Dev, alice2: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        series_statuses(get_series(series_msgs(alice2, 's2', revision=2)))
        assert key_rows(alice.email) == {alice.pk: 'trusted', alice2.pk: 'pending'}
        assert tofu.accept_key(alice.email, alice2.pk, replace=False) == []
        assert key_rows(alice.email) == {alice.pk: 'trusted', alice2.pk: 'trusted'}
        assert latest_status(alice, 's3') == 'tofu'
        # The series signed while the key was pending counts now
        info = tofu_info(load(series_msgs(alice2, 's4', count=1, cover=False)[0]))
        assert info['status'] == 'tofu' and info['tofu']['count'] == 1

    def test_accept_replace_retires_old_key(self, alice: Dev, alice2: Dev) -> None:
        old = get_series(series_msgs(alice, 's1'))
        series_statuses(old)
        series_statuses(get_series(series_msgs(alice2, 's2', revision=2)))
        assert tofu.accept_key(alice.email, alice2.pk, replace=True) == [alice.pk]
        assert key_rows(alice.email) == {alice.pk: 'retired', alice2.pk: 'trusted'}
        # What we saw before the change is still history
        lmsg = old.patches[1]
        assert lmsg is not None
        att = tofu_info(lmsg)
        assert att['status'] == 'tofu' and att['tofu']['retired']
        assert latest_status(alice, 's3') == 'tofu-retired'

    def test_reject_pending_key(self, alice: Dev, alice2: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        series_statuses(get_series(series_msgs(alice2, 's2', revision=2)))
        tofu.reject_key(alice.email, alice2.pk)
        assert key_rows(alice.email) == {alice.pk: 'trusted', alice2.pk: 'rejected'}
        assert latest_status(alice2, 's3') == 'tofu-rejected'
        assert latest_status(alice, 's4') == 'tofu'

    def test_accept_key_never_seen_pins_by_hand(self, alice: Dev) -> None:
        tofu.accept_key(alice.email.upper(), alice.pk, replace=False)
        assert tofu.key_history(alice.email)[0]['origin'] == 'manual'
        lser = get_series(series_msgs(alice, 's1'))
        assert series_statuses(lser) == ['tofu-new', 'tofu-new']
        assert key_rows(alice.email) == {alice.pk: 'trusted'}

    def test_reject_key_never_seen(self, alice: Dev) -> None:
        tofu.reject_key(alice.email, alice.pk)
        assert latest_status(alice, 's1') == 'tofu-rejected'

    def test_forget_pins_again(self, alice: Dev, alice2: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        assert tofu.forget_identity(alice.email) == (1, 3)
        assert tofu.identities() == []
        series_statuses(get_series(series_msgs(alice2, 's2')))
        assert key_rows(alice.email) == {alice2.pk: 'trusted'}

    def test_forget_leaves_other_identities(self, alice: Dev, mallory: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        series_statuses(get_series(series_msgs(mallory, 's2')))
        tofu.forget_identity(alice.email)
        assert tofu.identities() == [mallory.email]

    def test_promote_moves_key_to_keyring(self, alice: Dev, alice2: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        path = tofu.promote_key(alice.email, alice.pk)
        assert path == tofu.promote_path(alice.email)
        assert path.read_text() == alice.pk + '\n'
        # patatt finds the key now, so TOFU is out of the picture, and
        # another key under the same selector is a bad signature
        assert latest_status(alice, 's2') == 'signed'
        assert latest_status(alice2, 's3') == 'badsig'

    def test_promote_refuses_to_overwrite(self, alice: Dev, alice2: Dev) -> None:
        tofu.promote_key(alice.email, alice.pk)
        # Writing the same key again is fine
        tofu.promote_key(alice.email, alice.pk)
        with pytest.raises(tofu.TofuError, match='already has a different key'):
            tofu.promote_key(alice.email, alice2.pk)
        tofu.promote_key(alice.email, alice2.pk, force=True)
        assert tofu.promote_path(alice.email).read_text() == alice2.pk + '\n'

    def test_promote_with_selector(self, alice: Dev) -> None:
        path = tofu.promote_key(alice.email, alice.pk, selector='laptop')
        assert path.parts[-4:] == ('ed25519', 'example.org', 'alice', 'laptop')

    @pytest.mark.parametrize('pk', ['', 'not-base64!', 'c2hvcnQ='])
    def test_invalid_key_is_refused(self, alice: Dev, pk: str) -> None:
        with pytest.raises(tofu.TofuError, match='Not a valid'):
            tofu.accept_key(alice.email, pk, replace=False)
        with pytest.raises(tofu.TofuError, match='Not a valid'):
            tofu.promote_key(alice.email, pk)
        assert key_rows(alice.email) == {}

    def test_resolve_pk(self, alice: Dev, alice2: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        assert tofu.resolve_pk(alice.email, alice.pk[:10]) == alice.pk
        assert tofu.resolve_pk(alice.email, tofu.short_key(alice.pk)[:13]) == alice.pk
        # A full key we have never seen is taken as it is
        assert tofu.resolve_pk(alice.email, alice2.pk) == alice2.pk
        with pytest.raises(tofu.TofuError, match='No key'):
            tofu.resolve_pk(alice.email, '!!!')
        with pytest.raises(tofu.TofuError, match='No key'):
            tofu.resolve_pk('nobody@example.org', alice.pk[:10])

    def test_resolve_pk_ambiguous(self, alice: Dev) -> None:
        for pk in ('AAAAone', 'AAAAtwo'):
            conn = db()
            conn.execute(
                'INSERT INTO keys VALUES (?, ?, ?, ?, ?, 1, 1, 1)',
                (alice.email, 'ed25519', pk, 'pending', 'tofu'),
            )
            conn.close()
        with pytest.raises(tofu.TofuError, match='More than one'):
            tofu.resolve_pk(alice.email, 'AAAA')

    def test_recent_series(self, alice: Dev) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        series_statuses(get_series(series_msgs(alice, 's2', revision=2)))
        series_statuses(get_series(series_msgs(alice, 's3', cover=False)))
        recent = tofu.recent_series(alice.email, limit=2)
        assert list(recent) == [alice.pk]
        assert [s['series_key'] for s in recent[alice.pk]] == [
            's3-1@example.com',
            's2-0@example.com',
        ]
        # The cover letter subject names the series
        assert recent[alice.pk][1]['subject'] == '[PATCH v2 0/2] foo: a series'
        assert recent[alice.pk][0]['subject'] == '[PATCH 1/2] foo: change 1'


def kr(*args: str) -> int:
    """Run ``b4 kr`` with *args* and return its exit code."""
    import b4.command
    import b4.kr

    parser = b4.command.setup_parser()
    cmdargs = parser.parse_args(b4.command._legacy_kr_argv(['kr', *args]))
    try:
        b4.kr.main(cmdargs)
    except SystemExit as ex:
        return int(ex.code or 0)
    return 0


class TestKrCli:
    @pytest.fixture(autouse=True)
    def _log(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO, logger='b4')

    @pytest.mark.parametrize(
        ('argv', 'expected'),
        [
            (
                ['kr', '--show-keys', 'id@x'],
                ['kr', 'show-keys', '--show-keys', 'id@x'],
            ),
            (
                ['-d', '-c', 'b4.x=y', 'kr', 'id@x', '--show-keys'],
                ['-d', '-c', 'b4.x=y', 'kr', 'show-keys', 'id@x', '--show-keys'],
            ),
            (['kr', 'list'], ['kr', 'list']),
            (['kr', 'show-keys', 'id@x'], ['kr', 'show-keys', 'id@x']),
            (
                ['kr', 'show-keys', '--show-keys', 'id@x'],
                ['kr', 'show-keys', '--show-keys', 'id@x'],
            ),
            (['am', 'kr', '--show-keys'], ['am', 'kr', '--show-keys']),
            (['-c', 'kr', 'am', '--show-keys'], ['-c', 'kr', 'am', '--show-keys']),
        ],
    )
    def test_legacy_argv(self, argv: List[str], expected: List[str]) -> None:
        import b4.command

        assert b4.command._legacy_kr_argv(argv) == expected

    def test_legacy_show_keys_parses(self) -> None:
        import b4.command

        parser = b4.command.setup_parser()
        argv = b4.command._legacy_kr_argv(['kr', '--show-keys', 'id@x'])
        cmdargs = parser.parse_args(argv)
        assert cmdargs.kr_subcmd == 'show-keys'
        assert cmdargs.showkeys is True
        assert cmdargs.msgid == 'id@x'

    def test_no_subcommand(self, caplog: pytest.LogCaptureFixture) -> None:
        assert kr() == 1
        assert 'Please specify a kr sub-command' in caplog.text

    def test_list(
        self, caplog: pytest.LogCaptureFixture, alice: Dev, alice2: Dev
    ) -> None:
        assert kr('list') == 0
        assert 'No keys trusted on first use yet.' in caplog.text
        series_statuses(get_series(series_msgs(alice, 's1')))
        series_statuses(get_series(series_msgs(alice2, 's2', revision=2)))
        caplog.clear()
        assert kr('list') == 0
        assert alice.email in caplog.text
        assert f'trusted   {tofu.short_key(alice.pk)}    1 series' in caplog.text
        assert f'pending   {tofu.short_key(alice2.pk)}    1 series' in caplog.text

    def test_list_mentions_keyring(
        self, caplog: pytest.LogCaptureFixture, tofu_env: pathlib.Path, alice: Dev
    ) -> None:
        tofu.accept_key(alice.email, alice.pk, replace=False)
        install_key(tofu_env, alice, selector='other')
        assert kr('list') == 0
        assert 'Your keyring has a key for this address' in caplog.text

    def test_show(
        self, caplog: pytest.LogCaptureFixture, alice: Dev, alice2: Dev
    ) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        # Patch 2/2 is missing, so this revision does not count
        series_statuses(get_series(series_msgs(alice2, 's2', revision=2, skip=[2])))
        assert kr('show', alice.email.upper()) == 0
        assert f'Key: {alice.pk}' in caplog.text
        assert 'Status: pending (tofu)' in caplog.text
        assert '[PATCH 0/2] foo: a series' in caplog.text
        assert f'{b4.LINKADDR}/s1-0@example.com' in caplog.text
        assert '(not counted)' in caplog.text
        assert f'b4 kr accept {alice.email} {alice2.pk[:10]} --replace' in caplog.text

    def test_show_unknown(self, caplog: pytest.LogCaptureFixture) -> None:
        assert kr('show', 'nobody@example.org') == 0
        assert 'Nothing known about nobody@example.org.' in caplog.text

    def test_accept_needs_mode(
        self, caplog: pytest.LogCaptureFixture, alice: Dev, alice2: Dev
    ) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        series_statuses(get_series(series_msgs(alice2, 's2', revision=2)))
        assert kr('accept', alice.email, alice2.pk[:10]) == 1
        assert 'Use --add to trust both' in caplog.text
        assert key_rows(alice.email)[alice2.pk] == 'pending'
        assert kr('accept', alice.email, alice2.pk[:10], '--replace') == 0
        assert f'Retired: {alice.pk}' in caplog.text
        assert key_rows(alice.email) == {alice.pk: 'retired', alice2.pk: 'trusted'}

    def test_accept_add_and_replace_conflict(self, alice: Dev) -> None:
        with pytest.raises(SystemExit):
            kr('accept', alice.email, alice.pk, '--add', '--replace')

    def test_accept_first_key_needs_no_mode(
        self, caplog: pytest.LogCaptureFixture, alice: Dev
    ) -> None:
        assert kr('accept', alice.email, alice.pk) == 0
        assert 'never seen in a message' in caplog.text
        assert key_rows(alice.email) == {alice.pk: 'trusted'}
        assert kr('list') == 0
        assert '0 series  added by hand' in caplog.text
        assert kr('show', alice.email) == 0
        assert 'Added by hand:' in caplog.text

    def test_accept_unknown_prefix(
        self, caplog: pytest.LogCaptureFixture, alice: Dev
    ) -> None:
        assert kr('accept', alice.email, 'nope') == 1
        assert f'No key of {alice.email} matches nope' in caplog.text

    def test_reject_last_trusted_key(
        self, caplog: pytest.LogCaptureFixture, alice: Dev
    ) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        assert kr('reject', alice.email, alice.pk[:10]) == 0
        assert 'No trusted key is left' in caplog.text
        assert key_rows(alice.email) == {alice.pk: 'rejected'}

    @pytest.mark.parametrize(('answer', 'forgotten'), [('y', True), ('', False)])
    def test_forget(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        alice: Dev,
        answer: str,
        forgotten: bool,
    ) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        monkeypatch.setattr('builtins.input', lambda _prompt: answer)
        assert kr('forget', alice.email) == 0
        assert (key_rows(alice.email) == {}) is forgotten
        if not forgotten:
            assert 'Aborted, nothing forgotten.' in caplog.text

    def test_promote_default_key(
        self, caplog: pytest.LogCaptureFixture, alice: Dev, alice2: Dev
    ) -> None:
        series_statuses(get_series(series_msgs(alice, 's1')))
        assert kr('promote', alice.email) == 0
        assert tofu.promote_path(alice.email).read_text() == alice.pk + '\n'
        tofu.accept_key(alice.email, alice2.pk, replace=False)
        assert kr('promote', alice.email, '-s', 'laptop') == 1
        assert 'has 2 trusted keys' in caplog.text

    def test_promote_conflict(
        self, caplog: pytest.LogCaptureFixture, alice: Dev, alice2: Dev
    ) -> None:
        tofu.promote_key(alice.email, alice.pk)
        assert kr('promote', alice.email, alice2.pk) == 1
        assert 'Use --force' in caplog.text
        assert kr('promote', alice.email, alice2.pk, '--force') == 0

    @pytest.mark.parametrize('legacy', [False, True])
    def test_show_keys(
        self,
        caplog: pytest.LogCaptureFixture,
        tmp_path: pathlib.Path,
        alice: Dev,
        mallory: Dev,
        legacy: bool,
    ) -> None:
        series_statuses(get_series(series_msgs(alice, 's0')))
        msgs = series_msgs(alice, 's1', count=1)
        msgs.append(followup_msg(mallory, 'fu', 's1-1@example.com'))
        mbox = tmp_path / 'thread.mbox'
        mbox.write_bytes(
            b''.join(
                b'From x@y Thu Jan  1 00:00:00 1970\n' + m.as_bytes(policy=b4.emlpolicy)
                for m in msgs
            )
        )
        args = ['-m', str(mbox), 's1-0@example.com']
        args = ['--show-keys', *args] if legacy else ['show-keys', *args]
        assert kr(*args) == 0
        assert ('is deprecated' in caplog.text) is legacy
        assert f'{alice.email}: (trusted on first use, 1 series)' in caplog.text
        assert f'{mallory.email}: (unknown)' in caplog.text
        assert f'b4 kr promote {mallory.email} {mallory.pk}' in caplog.text
        assert 'recv-key' not in caplog.text
        # Looking at keys must not create keyring directories
        assert not (tmp_path / 'b4' / 'keyring').exists()


# --- Stored attestation results (b4 review) ----------------------------------

ALICE = 'ed25519/alice@example.org'


def stored(lser: b4.LoreSeries) -> Tuple[Optional[str], List[str]]:
    """Check *lser* the way b4 review does, and return a resolve_stored() row."""
    from b4.review import check_series_attestation

    msgids = [lmsg.msgid for lmsg in lser.patches if lmsg is not None]
    return check_series_attestation(lser), msgids


def live(row: Tuple[Optional[str], List[str]]) -> Tuple[Optional[str], Dict[str, Any]]:
    ((att, details),) = tofu.resolve_stored([row])
    return att, details


class TestStoredResults:
    """The review database keeps "nokey", the TOFU status is worked out live."""

    def test_check_records_and_stores_nokey(self, alice: Dev) -> None:
        row = stored(get_series(series_msgs(alice, 's1')))
        assert row[0] == f'nokey:{ALICE}'
        # Checking a series records it, there is no separate step
        assert key_rows(alice.email) == {alice.pk: 'trusted'}
        att, details = live(row)
        assert att == f'tofu-new:{ALICE}'
        assert details[ALICE]['pk'] == alice.pk

    def test_next_revision_makes_both_trusted(self, alice: Dev) -> None:
        v1 = stored(get_series(series_msgs(alice, 's1')))
        v2 = stored(get_series(series_msgs(alice, 's2', revision=2)))
        # Each revision counts the other one
        assert [live(row)[0] for row in (v1, v2)] == [f'tofu:{ALICE}'] * 2
        assert live(v1)[1][ALICE]['count'] == 1

    @pytest.mark.parametrize(
        ('decision', 'expected'),
        [
            # The new key signed only this series, so it is new
            pytest.param('add', 'tofu-new', id='add'),
            pytest.param('replace', 'tofu-new', id='replace'),
            pytest.param('reject', 'tofu-rejected', id='reject'),
        ],
    )
    def test_decision_takes_effect_without_a_check(
        self, alice: Dev, alice2: Dev, decision: str, expected: str
    ) -> None:
        stored(get_series(series_msgs(alice, 's1')))
        row = stored(get_series(series_msgs(alice2, 's2', revision=2)))
        assert row[0] == f'nokey:{ALICE}'
        att, details = live(row)
        assert att == f'tofu-changed:{ALICE}'
        assert details[ALICE]['pk'] == alice2.pk
        if decision == 'reject':
            tofu.reject_key(alice.email, alice2.pk)
        else:
            tofu.accept_key(alice.email, alice2.pk, replace=decision == 'replace')
        assert live(row)[0] == f'{expected}:{ALICE}'

    def test_replaced_key_keeps_its_history(self, alice: Dev, alice2: Dev) -> None:
        old = stored(get_series(series_msgs(alice, 's1')))
        stored(get_series(series_msgs(alice2, 's2', revision=2)))
        tofu.accept_key(alice.email, alice2.pk, replace=True)
        att, details = live(old)
        assert att == f'tofu:{ALICE}'
        assert details[ALICE]['retired']

    def test_worst_key_wins(self, alice: Dev, alice2: Dev) -> None:
        stored(get_series(series_msgs(alice, 's0')))
        row = stored(get_series(series_msgs(alice, 's1', signers={2: alice2})))
        assert live(row)[0] == f'tofu-changed:{ALICE}'

    def test_other_entries_are_kept(self, alice: Dev) -> None:
        att, msgids = stored(get_series(series_msgs(alice, 's1')))
        row = (f'{att};signed:DKIM/example.org;nokey:openpgp/bob@example.com', msgids)
        assert live(row)[0] == (
            f'nokey:openpgp/bob@example.com;signed:DKIM/example.org;tofu-new:{ALICE}'
        )

    def test_keyring_gap_is_stored(
        self, tofu_env: pathlib.Path, alice: Dev, alice2: Dev
    ) -> None:
        install_key(tofu_env, alice, selector='20211009')
        row = stored(get_series(series_msgs(alice2, 's1')))
        assert row[0] == f'tofu-changed:{ALICE}'
        assert live(row) == (row[0], {})

    @pytest.mark.parametrize(
        'case', ['unknown-messages', 'disabled', 'no-messages', 'pending']
    )
    def test_stays_nokey(
        self, monkeypatch: pytest.MonkeyPatch, alice: Dev, case: str
    ) -> None:
        att, msgids = stored(get_series(series_msgs(alice, 's1')))
        if case == 'unknown-messages':
            msgids = ['other@example.com']
        elif case == 'disabled':
            monkeypatch.setitem(b4.MAIN_CONFIG, 'attestation-tofu', 'no')
        elif case == 'no-messages':
            msgids = []
        else:
            att = 'pending'
        assert live((att, msgids)) == (att, {})

    def test_many_series_one_connection(
        self, monkeypatch: pytest.MonkeyPatch, alice: Dev
    ) -> None:
        rows = [
            stored(get_series(series_msgs(alice, f's{num}', revision=num)))
            for num in range(1, 4)
        ]
        calls: List[int] = list()
        connect = tofu.connect

        def counting_connect() -> sqlite3.Connection:
            calls.append(1)
            return connect()

        monkeypatch.setattr(tofu, 'connect', counting_connect)
        monkeypatch.setattr(tofu, '_CHUNK', 2)
        results = tofu.resolve_stored(rows * 10)
        assert len(calls) == 1
        assert [att for att, _details in results] == [f'tofu:{ALICE}'] * 30


def track(identifier: str, change_id: str, lser: b4.LoreSeries) -> None:
    """Track *lser* and store its attestation, as b4 review update does."""
    from b4.review import tracking

    from .helpers.tracking import seed_series

    att, _msgids = stored(lser)
    cover = lser.patches[0] or lser.patches[1]
    assert cover is not None
    seed_series(
        identifier,
        change_id,
        sender_email='alice@example.org',
        message_id=cover.msgid,
        num_patches=lser.expected,
    )
    conn = tracking.get_db(identifier)
    try:
        tracking.add_series_patches(conn, change_id, 1, lser)
    finally:
        conn.close()
    tracking.update_attestation(identifier, change_id, 1, att)


class TestTrackedSeries:
    """Every reader of the tracking database sees the live status."""

    def test_get_all_tracked_series(self, alice: Dev, alice2: Dev) -> None:
        from b4.review import tracking

        track('proj', 'old', get_series(series_msgs(alice, 's1')))
        track('proj', 'new', get_series(series_msgs(alice2, 's2', revision=2)))
        rows = {s['change_id']: s for s in tracking.get_all_tracked_series('proj')}
        assert rows['old']['attestation'] == f'tofu-new:{ALICE}'
        assert rows['new']['attestation'] == f'tofu-changed:{ALICE}'
        assert rows['new']['tofu'][ALICE]['pk'] == alice2.pk
        tofu.reject_key(alice.email, alice2.pk)
        rows = {s['change_id']: s for s in tracking.get_all_tracked_series('proj')}
        assert rows['new']['attestation'] == f'tofu-rejected:{ALICE}'

    def test_untouched_without_tofu_signatures(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without a signature TOFU may know, nothing extra is read."""
        from b4.review import tracking

        from .helpers.tracking import seed_series

        seed_series('proj', 'dkim')
        tracking.update_attestation('proj', 'dkim', 1, 'signed:DKIM/example.org')
        monkeypatch.setattr(tofu, 'resolve_stored', None)
        (row,) = tracking.get_all_tracked_series('proj')
        assert row['attestation'] == 'signed:DKIM/example.org'
        assert row['tofu'] == {}

    def test_tofu_failure_keeps_the_list(
        self, monkeypatch: pytest.MonkeyPatch, alice: Dev
    ) -> None:
        from b4.review import tracking

        track('proj', 'old', get_series(series_msgs(alice, 's1')))

        def broken(rows: Any) -> Any:
            raise RuntimeError('boom')

        monkeypatch.setattr(tofu, 'resolve_stored', broken)
        (row,) = tracking.get_all_tracked_series('proj')
        assert row['attestation'] == f'nokey:{ALICE}'
        assert row['tofu'] == {}

    @pytest.mark.asyncio
    async def test_tui_badge_and_decision(self, alice: Dev, alice2: Dev) -> None:
        from textual.widgets import ListView

        from b4.review_tui._modals import KeyDecisionScreen
        from b4.review_tui._tracking_app import TrackedSeriesItem, TrackingApp

        track('proj', 'old', get_series(series_msgs(alice, 's1')))
        track('proj', 'v2', get_series(series_msgs(alice, 's2', revision=2)))
        track('proj', 'new', get_series(series_msgs(alice2, 's3', revision=3)))

        def marks(app: TrackingApp) -> Dict[str, str]:
            lv = app.query_one('#tracking-list', ListView)
            return {
                item.series['change_id']: item.render_label().plain[20]
                for item in lv.children
                if isinstance(item, TrackedSeriesItem)
            }

        app = TrackingApp('proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            assert marks(app) == {'old': '✔', 'v2': '✔', 'new': '!'}
            lv = app.query_one('#tracking-list', ListView)
            lv.index = next(
                idx
                for idx, item in enumerate(lv.children)
                if isinstance(item, TrackedSeriesItem)
                and item.series['change_id'] == 'new'
            )
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            await pilot.press('K')
            await pilot.pause()
            assert isinstance(app.screen, KeyDecisionScreen)
            await pilot.press('r')
            await pilot.pause()
            # The old series are history now, the new one is a fresh key
            assert marks(app) == {'old': '✔', 'v2': '✔', 'new': ' '}
        assert key_rows(alice.email) == {alice.pk: 'retired', alice2.pk: 'trusted'}
