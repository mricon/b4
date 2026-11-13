"""Interrupted submissions use frozen mail and never repeat accepted recipients.

SMTP connections use mocks or a loopback-only server.
"""

import base64
import dataclasses
import email.policy
import json
import smtplib
import socketserver
import threading
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Tuple, cast
from unittest.mock import Mock

import pytest

import b4
import patatt
from b4._send import (
    RetryableSendError,
    SendSession,
    State,
)

COVER = '20261113-an-intentionally-long-change-id-for-testing-wire-headers-v4-0-0123456789ab@example.org'


class FakeSMTP:
    def __init__(self, *outcomes: Any) -> None:
        self.outcomes = list(outcomes)
        self.calls: List[Tuple[str, List[str], bytes]] = []
        self.closed = False

    def sendmail(
        self, sender: str, recipients: List[str], data: bytes
    ) -> Dict[str, Tuple[int, bytes]]:
        self.calls.append((sender, recipients[:], data))
        result = self.outcomes.pop(0) if self.outcomes else {}
        if isinstance(result, BaseException):
            raise result
        return cast(Dict[str, Tuple[int, bytes]], result)

    def quit(self) -> None:
        self.closed = True

    def connector(self) -> b4.SMTPConnector:
        return b4.SMTPConnector(lambda: cast(smtplib.SMTP, self))


def messages(count: int = 3) -> List[EmailMessage]:
    result = []
    for n in range(count):
        msg = EmailMessage()
        msg['From'] = 'Alice <alice@example.org>'
        msg['To'] = 'Bob <bob@example.org>'
        msg['Cc'] = 'List <list@example.org>'
        msg['Subject'] = f'[PATCH v4 {n}/{count - 1}] message {n}'
        msg['Message-ID'] = '<' + COVER.replace('-0-', f'-{n}-') + '>'
        msg['Date'] = 'Fri, 13 Nov 2026 11:14:16 -0700'
        if n:
            msg['References'] = f'<{COVER}>'
            msg['In-Reply-To'] = f'<{COVER}>'
        msg.set_content(f'Message {n} with non-ASCII text: café.\n')
        result.append(msg)
    return result


@pytest.fixture
def session(tmp_path: Path) -> SendSession:
    state = State(
        change_id='test-change',
        revision=4,
        branch='b4/test',
        head='a' * 40,
        tree='b' * 40,
        cover_hash='c' * 64,
        tag_message='The cover letter',
        cover_message_id=COVER,
        fromaddr='alice@example.org',
        messages=[],
    )
    return SendSession.prepare(
        tmp_path / 'send' / 'series' / 'v4', state, b4.prepare_mail(messages())
    )


@pytest.mark.parametrize('code', [421, 450, 550])
def test_explicit_rejection_resumes_without_duplicates(
    session: SendSession, code: int
) -> None:
    first = FakeSMTP({}, smtplib.SMTPDataError(code, b'rejected'))
    with pytest.raises(RetryableSendError, match='SMTP rejected DATA'):
        session.send(first.connector())
    assert first.closed
    saved = SendSession.load(session.directory)
    assert saved.state.in_flight is None
    assert not saved.state.messages[0].pending()
    assert saved.state.messages[1].pending()
    second = FakeSMTP()
    saved.send(second.connector())
    assert len(first.calls) == len(second.calls) == 2
    assert first.calls[1] == second.calls[0]
    assert second.calls[1][2] == saved.message_bytes(2)
    assert SendSession.load(session.directory).delivered()
    unused = Mock(spec=b4.SMTPConnector)
    saved.send(unused)
    unused.assert_not_called()


def test_partial_recipient_acceptance(session: SendSession) -> None:
    """A temporary refusal leaves that recipient pending, but the rest of
    the series still goes out: stopping there would hold every later
    message back because of one address."""
    first = FakeSMTP({'bob@example.org': (450, b'later')})
    with pytest.raises(RetryableSendError, match='refused recipients'):
        session.send(first.connector())
    assert len(first.calls) == 3
    saved = SendSession.load(session.directory)
    assert saved.state.messages[0].accepted == ['list@example.org']
    second = FakeSMTP()
    saved.send(second.connector())
    assert [call[1] for call in second.calls] == [['bob@example.org']]
    assert second.calls[0][2] == first.calls[0][2]


@pytest.mark.parametrize('when', ['first-attempt', 'on-retry'])
def test_permanent_refusal_does_not_stall_the_series(
    session: SendSession, when: str
) -> None:
    """A 5xx answer for one address is final. Asking again cannot change
    it, so such a recipient must not keep the other messages from going
    out or the submission from finishing. The refusal can come with the
    other recipients, or alone on a retry after a temporary one."""
    gone = {'list@example.org': (550, b'user unknown')}
    if when == 'first-attempt':
        smtp = FakeSMTP(gone, gone, gone)
        session.send(smtp.connector())
        assert [call[1] for call in smtp.calls] == [
            ['bob@example.org', 'list@example.org']
        ] * 3
    else:
        later = {'list@example.org': (450, b'later')}
        with pytest.raises(RetryableSendError):
            session.send(FakeSMTP(later, later, later).connector())
        refusal = smtplib.SMTPRecipientsRefused(gone)
        smtp = FakeSMTP(refusal, refusal, refusal)
        session.send(smtp.connector())
        assert [call[1] for call in smtp.calls] == [['list@example.org']] * 3
    saved = SendSession.load(session.directory)
    assert saved.delivered()
    for message in saved.state.messages:
        assert message.accepted == ['bob@example.org']
        assert message.refused == ['list@example.org']


@pytest.mark.parametrize(
    'error',
    [
        smtplib.SMTPRecipientsRefused({'bob@example.org': (550, b'no')}),
        smtplib.SMTPSenderRefused(550, b'no', 'alice@example.org'),
        # Raised before MAIL FROM, so no recipient was even named
        smtplib.SMTPHeloError(500, b'no'),
    ],
)
def test_envelope_rejection_is_safe_to_retry(
    session: SendSession, error: Exception
) -> None:
    with pytest.raises(RetryableSendError, match='rejected'):
        session.send(FakeSMTP(error).connector())
    saved = SendSession.load(session.directory)
    assert saved.state.in_flight is None
    assert not any(message.accepted for message in saved.state.messages)


@pytest.mark.parametrize(
    'error',
    [smtplib.SMTPServerDisconnected('lost'), TimeoutError('late'), KeyboardInterrupt()],
)
def test_uncertain_delivery_requires_reconciliation(
    session: SendSession, error: BaseException
) -> None:
    with pytest.raises((RuntimeError, KeyboardInterrupt)) as exc:
        session.send(FakeSMTP({}, error).connector())
    assert not isinstance(exc.value, RetryableSendError)
    saved = SendSession.load(session.directory)
    assert saved.state.in_flight == 1
    unused = Mock(spec=b4.SMTPConnector)
    with pytest.raises(RuntimeError, match='uncertain'):
        saved.send(unused)
    unused.assert_not_called()


@pytest.mark.parametrize('outcome,count', [('sent', 1), ('unsent', 2)])
def test_reconcile_only_the_interrupted_transaction(
    session: SendSession, outcome: str, count: int
) -> None:
    with pytest.raises(RuntimeError):
        session.send(FakeSMTP({}, TimeoutError()).connector())
    saved = SendSession.load(session.directory)
    saved.resolve(outcome)
    resumed = FakeSMTP()
    SendSession.load(session.directory).send(resumed.connector())
    assert len(resumed.calls) == count
    assert resumed.calls[0][2] == saved.message_bytes(3 - count)
    with pytest.raises(RuntimeError, match='no uncertain'):
        saved.resolve(outcome)


def test_connection_failure_does_not_create_uncertainty(session: SendSession) -> None:
    connect = Mock(side_effect=OSError('offline'))
    with pytest.raises(RetryableSendError, match='connect'):
        session.send(b4.SMTPConnector(connect))
    assert SendSession.load(session.directory).state.in_flight is None


def test_acceptance_record_failure_blocks_retries(
    session: SendSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = session.save
    count = 0

    def fail_after_acceptance() -> None:
        nonlocal count
        count += 1
        if count == 2:
            raise OSError('disk full')
        original()

    monkeypatch.setattr(session, 'save', fail_after_acceptance)
    first = FakeSMTP()
    with pytest.raises(OSError, match='disk full'):
        session.send(first.connector())
    assert len(first.calls) == 1
    saved = SendSession.load(session.directory)
    assert saved.state.in_flight == 0
    unused = Mock(spec=b4.SMTPConnector)
    with pytest.raises(RuntimeError, match='uncertain'):
        saved.send(unused)
    unused.assert_not_called()


def test_attempt_record_failure_prevents_smtp_data(
    session: SendSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session, 'save', Mock(side_effect=OSError('disk full')))
    smtp = FakeSMTP()
    with pytest.raises(OSError):
        session.send(smtp.connector())
    assert not smtp.calls
    assert SendSession.load(session.directory).state.in_flight is None


def test_changed_payload_is_rejected_before_connect(session: SendSession) -> None:
    session.message_path(2).write_bytes(b'corrupt')
    unused = Mock(spec=b4.SMTPConnector)
    with pytest.raises(ValueError, match='changed'):
        session.send(unused)
    unused.assert_not_called()
    with pytest.raises(RuntimeError, match='changed'):
        SendSession.load(session.directory)


@pytest.mark.parametrize(
    'mutation',
    [
        {'schema': 2},
        {'in_flight': 3},
        {'in_flight': -1},
        {'in_flight': True},
        {'finished': True},
        {'messages': []},
        {'revision': '4'},
    ],
)
def test_corrupt_snapshot_rejected(
    session: SendSession, mutation: Dict[str, Any]
) -> None:
    path = session.directory / 'state.json'
    state = json.loads(path.read_text())
    state.update(mutation)
    path.write_text(json.dumps(state))
    with pytest.raises(RuntimeError):
        SendSession.load(session.directory)


def test_private_permissions_and_exact_wire_headers(session: SendSession) -> None:
    assert session.directory.stat().st_mode & 0o077 == 0
    for path in session.directory.iterdir():
        assert path.stat().st_mode & 0o077 == 0
    wire = session.message_bytes(1)
    msg = BytesParser(policy=email.policy.compat32).parsebytes(wire)
    for header in ('References', 'In-Reply-To'):
        assert str(msg[header]).strip() == f'<{COVER}>'
        assert '=?' not in str(msg[header])
    assert b'\n' not in wire.replace(b'\r\n', b'')
    with pytest.raises(RuntimeError, match='already recorded'):
        SendSession.prepare(
            session.directory,
            dataclasses.replace(session.state, messages=[]),
            b4.prepare_mail(messages()),
        )


def test_unknown_refusal_address_is_not_treated_as_success(
    session: SendSession,
) -> None:
    with pytest.raises(RuntimeError, match='unexpected recipient'):
        session.send(FakeSMTP({'foreign@example.org': (450, b'later')}).connector())
    assert SendSession.load(session.directory).state.in_flight == 0


def test_large_series_recovers_original_suffix(tmp_path: Path) -> None:
    state = State(
        'large', 4, 'b4/test', 'a', 'b', 'c', 'cover', COVER, 'alice@example.org', []
    )
    session = SendSession.prepare(
        tmp_path / 'send' / 'large' / 'v4', state, b4.prepare_mail(messages(59))
    )
    first = FakeSMTP(*([{}] * 48), smtplib.SMTPDataError(421, b'later'))
    with pytest.raises(RuntimeError):
        session.send(first.connector())
    second = FakeSMTP()
    SendSession.load(session.directory).send(second.connector())
    assert len(first.calls) == 49
    assert len(second.calls) == 11
    assert first.calls[48] == second.calls[0]
    assert [call[2] for call in second.calls] == [
        session.message_bytes(n) for n in range(48, 59)
    ]


@pytest.mark.parametrize('failure', ['data', 'recipient'])
def test_real_smtplib_against_local_server(session: SendSession, failure: str) -> None:
    """Exercise actual SMTP responses without delivering or relaying any mail."""
    transactions: List[Tuple[List[str], bytes, bool]] = []
    errors: List[BaseException] = []
    quits: List[bytes] = []
    refused_once = False

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            nonlocal refused_once
            self.connection.settimeout(5)
            accepted: List[str] = []
            try:
                self.wfile.write(b'220 localhost test-only SMTP\r\n')
                while line := self.rfile.readline():
                    command, _, rest = line.partition(b' ')
                    command = command.strip().upper()
                    if command in (b'EHLO', b'HELO'):
                        self.wfile.write(b'250 localhost\r\n')
                    elif command == b'MAIL':
                        accepted = []
                        self.wfile.write(b'250 sender ok\r\n')
                    elif command == b'RCPT':
                        address = (
                            rest.decode().strip().split('<', 1)[1].split('>', 1)[0]
                        )
                        if (
                            failure == 'recipient'
                            and not refused_once
                            and address == 'bob@example.org'
                        ):
                            refused_once = True
                            self.wfile.write(b'450 try again later\r\n')
                        else:
                            accepted.append(address)
                            self.wfile.write(b'250 recipient ok\r\n')
                    elif command == b'DATA':
                        self.wfile.write(b'354 send data\r\n')
                        body = bytearray()
                        while data := self.rfile.readline():
                            if data == b'.\r\n':
                                break
                            body.extend(data[1:] if data.startswith(b'..') else data)
                        rejected = failure == 'data' and len(transactions) == 1
                        transactions.append((accepted[:], bytes(body), not rejected))
                        if rejected:
                            self.wfile.write(b'421 temporary problem\r\n')
                            return
                        self.wfile.write(b'250 accepted\r\n')
                    elif command == b'RSET':
                        accepted = []
                        self.wfile.write(b'250 reset\r\n')
                    elif command == b'QUIT':
                        quits.append(command)
                        self.wfile.write(b'221 bye\r\n')
                        return
                    else:
                        raise AssertionError(
                            f'Unexpected test-server command: {command!r}'
                        )
            except BaseException as exc:
                errors.append(exc)
                raise

    with socketserver.TCPServer(('127.0.0.1', 0), Handler) as server:
        worker = threading.Thread(
            target=server.serve_forever, kwargs={'poll_interval': 0.01}
        )
        worker.start()
        port = server.server_address[1]

        def connector() -> b4.SMTPConnector:
            return b4.SMTPConnector(lambda: smtplib.SMTP('127.0.0.1', port, timeout=5))

        try:
            with pytest.raises(RuntimeError, match='SMTP'):
                session.send(connector())
            saved = SendSession.load(session.directory)
            saved.send(connector())
        finally:
            server.shutdown()
            worker.join(timeout=5)
        assert not worker.is_alive()
    assert not errors
    # Connections end with QUIT, except the one the server closed with 421
    assert len(quits) == (1 if failure == 'data' else 2)
    assert SendSession.load(session.directory).delivered()
    delivered = [
        (address, data)
        for recipients, data, ok in transactions
        if ok
        for address in recipients
    ]
    expected = [
        (address, session.message_bytes(index))
        for index, message in enumerate(session.state.messages)
        for address in message.recipients
    ]
    assert sorted(delivered) == sorted(expected)


def test_finished_record_does_not_block_a_new_submission(
    session: SendSession,
) -> None:
    """A finished record can outlive its send when removing it fails, and
    --force-revision can make b4 send that revision again. Neither may
    leave the user unable to send."""
    session.send(FakeSMTP().connector())
    session.state.finished = True
    session.save()
    fresh = SendSession.prepare(
        session.directory,
        dataclasses.replace(session.state, messages=[], finished=False),
        b4.prepare_mail(messages(2)),
    )
    assert len(fresh.state.messages) == 2
    assert sorted(p.name for p in session.directory.glob('*.eml')) == [
        '0000.eml',
        '0001.eml',
    ]
    fresh.discard()
    assert not session.directory.exists()


def test_changed_message_id_metadata_is_rejected(session: SendSession) -> None:
    session.state.messages[1].message_id = 'other@example.org'
    session.save()
    with pytest.raises(RuntimeError, match='wire message'):
        SendSession.load(session.directory)


def test_resumed_signatures_verify_without_private_key(
    session: SendSession, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signing = pytest.importorskip('nacl.signing')
    key = signing.SigningKey.generate()
    private = tmp_path / 'private.key'
    private.write_bytes(base64.b64encode(key.encode()))
    public = tmp_path / 'keys' / 'ed25519' / 'example.org' / 'alice' / 'default'
    public.parent.mkdir(parents=True)
    public.write_bytes(base64.b64encode(key.verify_key.encode()))
    monkeypatch.setattr(patatt, 'KEYCACHE', {})
    monkeypatch.setattr(
        patatt,
        'get_main_config',
        lambda: {
            'identity': 'alice@example.org',
            'selector': 'default',
            'signingkey': f'ed25519:{private}',
        },
    )
    saved = SendSession.prepare(
        session.directory.parent / 'signed',
        dataclasses.replace(session.state, messages=[]),
        b4.prepare_mail(messages(), patatt_sign=True),
    )
    first = FakeSMTP({}, smtplib.SMTPDataError(421, b'later'))
    with pytest.raises(RuntimeError):
        saved.send(first.connector())
    private.unlink()
    monkeypatch.setattr(patatt, 'KEYCACHE', {})
    monkeypatch.setattr(
        patatt, 'rfc2822_sign', Mock(side_effect=AssertionError('must not resign'))
    )
    second = FakeSMTP()
    SendSession.load(saved.directory).send(second.connector())
    assert second.calls[0] == first.calls[1]
    for _sender, _recipients, data in first.calls[:1] + second.calls:
        assert b'X-Developer-Signature:' in data
        results = patatt.validate_message(data, [str(tmp_path / 'keys')])
        assert len(results) == 1
        assert results[0][0] == patatt.RES_VALID
