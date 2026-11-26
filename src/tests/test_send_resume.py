"""Interrupted submissions use frozen mail and never repeat accepted recipients.

SMTP connections use mocks or a loopback-only server. Integration tests use
disposable Git repos and exercise formatting, signing, state and rerolling.
"""

import base64
import dataclasses
import email.policy
import json
import smtplib
import socketserver
import sys
import threading
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Tuple, cast
from unittest.mock import Mock

import pytest

import b4
import b4.command
import b4.ez
import patatt
from b4._send import (
    RetryableSendError,
    SendSession,
    State,
    pending_session,
    series_directory,
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


def run_send(*args: str, no_interactive: bool = False) -> None:
    options = ['--no-interactive'] if no_interactive else []
    parsed = b4.command.setup_parser().parse_args(
        ['--no-stdin', *options, 'send', *args]
    )
    b4.ez.cmd_send(parsed)


@pytest.fixture(params=['branch-description', 'commit', 'tip-commit'])
def send_repo(
    gitdir: str, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> Path:
    b4.MAIN_CONFIG.update(
        {
            'prep-cover-strategy': request.param,
            'prep-pre-flight-checks': 'disable-all',
        }
    )
    prep_args = ['--no-stdin', 'prep', '-n', 'smtp-resume']
    if request.param == 'tip-commit':
        base = b4.git_get_current_branch()
        assert base is not None
        prep_args = ['--no-stdin', 'prep', '-e', base]
        assert b4.git_run_command(None, ['checkout', '-b', 'b4/smtp-resume'])[0] == 0
    else:
        b4.ez.cmd_prep(b4.command.setup_parser().parse_args(prep_args))
    for n in range(2):
        Path(gitdir, f'send-{n}.txt').write_text(f'Change {n}\n')
        assert b4.git_run_command(None, ['add', f'send-{n}.txt'])[0] == 0
        assert b4.git_run_command(None, ['commit', '-m', f'Change {n}'])[0] == 0
    if request.param == 'tip-commit':
        b4.ez.cmd_prep(b4.command.setup_parser().parse_args(prep_args))
    _cover, tracking = b4.ez.load_cover()
    b4.ez.store_cover(
        'Two changes\n\nA cover letter.\n\nTo: list@example.org\n', tracking
    )
    monkeypatch.setattr(b4, 'SENDEMAIL_CONFIG', {'smtpserver': 'smtp.example.org'})
    monkeypatch.setattr('builtins.input', lambda _prompt: '')
    return series_directory(tracking['series']['change-id'])


def configure_smtp(monkeypatch: pytest.MonkeyPatch, smtp: FakeSMTP) -> None:
    def get_smtp(dryrun: bool = False) -> Tuple[Any, str]:
        return (None if dryrun else smtp.connector()), str(b4.USER_CONFIG['email'])

    monkeypatch.setattr(b4, 'get_smtp', get_smtp)


def interrupt_send(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> Tuple[SendSession, FakeSMTP]:
    smtp = FakeSMTP({}, smtplib.SMTPDataError(421, b'temporary'))
    configure_smtp(monkeypatch, smtp)
    with pytest.raises(SystemExit) as exc:
        run_send('--no-sign')
    assert exc.value.code == 1
    session = pending_session(send_repo)
    assert session is not None
    return session, smtp


def test_cli_resume_and_reroll(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    saved, first = interrupt_send(send_repo, monkeypatch)
    assert 'run: b4 send --resume' in caplog.text
    _cover, tracking = b4.ez.load_cover()
    assert tracking['series']['revision'] == 1
    second = FakeSMTP()
    configure_smtp(monkeypatch, second)
    monkeypatch.setattr(
        b4.ez,
        'get_prep_branch_as_patches',
        Mock(side_effect=AssertionError('must not regenerate')),
    )
    run_send('--resume')
    assert second.calls[0] == first.calls[1]
    assert len(second.calls) == 2
    _cover, tracking = b4.ez.load_cover()
    assert tracking['series']['revision'] == 2
    assert tracking['series']['history']['v1'] == [saved.state.cover_message_id]
    # Signed mail and recipient lists are not kept once nothing needs them
    assert not saved.directory.exists()
    run_send('--resume')
    assert len(second.calls) == 2


def retry_prompt(monkeypatch: pytest.MonkeyPatch, *answers: Any) -> Mock:
    retry = Mock(side_effect=answers)

    def respond(prompt: str) -> str:
        if prompt.startswith('Retry sending'):
            return cast(str, retry(prompt))
        return ''

    monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
    monkeypatch.setattr('builtins.input', respond)
    return retry


@pytest.mark.parametrize(
    'error',
    [
        smtplib.SMTPDataError(421, b'temporary'),
        smtplib.SMTPDataError(550, b'quota'),
        smtplib.SMTPSenderRefused(550, b'no', 'test-override@example.com'),
        smtplib.SMTPRecipientsRefused({'list@example.org': (450, b'later')}),
    ],
)
def test_interactive_retry_reconnects_without_regenerating_mail(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    first = FakeSMTP({}, error)
    second = FakeSMTP()
    get_smtp = Mock(
        side_effect=[
            (first.connector(), b4.USER_CONFIG['email']),
            (second.connector(), b4.USER_CONFIG['email']),
        ]
    )
    monkeypatch.setattr(b4, 'get_smtp', get_smtp)
    signer = Mock(side_effect=lambda data: b'X-Developer-Signature: frozen\n' + data)
    monkeypatch.setattr(patatt, 'rfc2822_sign', signer)
    retry = retry_prompt(monkeypatch, 'y')
    run_send()
    retry.assert_called_once_with(
        'Retry sending to the remaining recipients now? [y/N] '
    )
    assert get_smtp.call_count == 2
    assert signer.call_count == 3
    assert first.closed and second.closed
    assert len(first.calls) == len(second.calls) == 2
    assert first.calls[1] == second.calls[0]
    assert pending_session(send_repo) is None
    assert b4.ez.load_cover()[1]['series']['revision'] == 2


def test_interactive_retry_after_connection_failure(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connect = Mock(side_effect=OSError('offline'))
    smtp = FakeSMTP()
    monkeypatch.setattr(
        b4,
        'get_smtp',
        Mock(
            side_effect=[
                (b4.SMTPConnector(connect), b4.USER_CONFIG['email']),
                (smtp.connector(), b4.USER_CONFIG['email']),
            ]
        ),
    )
    retry = retry_prompt(monkeypatch, 'YES')
    run_send('--no-sign')
    retry.assert_called_once()
    connect.assert_called_once()
    assert len(smtp.calls) == 3
    assert pending_session(send_repo) is None


def test_interactive_retry_only_resends_refused_recipients(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = FakeSMTP({}, {'test-override@example.com': (450, b'later')})
    second = FakeSMTP()
    monkeypatch.setattr(
        b4,
        'get_smtp',
        Mock(
            side_effect=[
                (first.connector(), b4.USER_CONFIG['email']),
                (second.connector(), b4.USER_CONFIG['email']),
            ]
        ),
    )
    retry_prompt(monkeypatch, 'yes')
    run_send('--no-sign', '--cc', 'test-override@example.com')
    assert second.calls[0][1] == ['test-override@example.com']
    assert second.calls[0][2] == first.calls[1][2]
    assert pending_session(send_repo) is None


def test_resume_also_offers_immediate_retry(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _saved, first = interrupt_send(send_repo, monkeypatch)
    failed = FakeSMTP(smtplib.SMTPDataError(421, b'later'))
    final = FakeSMTP()
    monkeypatch.setattr(
        b4,
        'get_smtp',
        Mock(
            side_effect=[
                (failed.connector(), b4.USER_CONFIG['email']),
                (final.connector(), b4.USER_CONFIG['email']),
            ]
        ),
    )
    retry = retry_prompt(monkeypatch, 'y')
    run_send('--resume')
    retry.assert_called_once()
    assert len(failed.calls) == 1 and len(final.calls) == 2
    assert failed.calls[0] == final.calls[0]
    assert final.calls[0] == first.calls[1]
    assert pending_session(send_repo) is None


@pytest.mark.parametrize(
    'answer', ['', 'n', 'No', 'later', EOFError(), KeyboardInterrupt()]
)
def test_declining_retry_preserves_progress(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, answer: Any
) -> None:
    first = FakeSMTP({}, smtplib.SMTPDataError(421, b'later'))
    configure_smtp(monkeypatch, first)
    retry = retry_prompt(monkeypatch, answer)
    with pytest.raises(SystemExit) as exc:
        run_send('--no-sign')
    assert exc.value.code == (130 if isinstance(answer, KeyboardInterrupt) else 1)
    retry.assert_called_once()
    assert len(first.calls) == 2
    saved = pending_session(send_repo)
    assert saved is not None and saved.state.in_flight is None
    assert not saved.state.messages[0].pending()
    assert saved.state.messages[1].pending()
    assert b4.ez.load_cover()[1]['series']['revision'] == 1
    second = FakeSMTP()
    configure_smtp(monkeypatch, second)
    run_send('--resume')
    assert second.calls[0] == first.calls[1]
    assert pending_session(send_repo) is None


def test_each_retry_requires_confirmation(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = FakeSMTP({}, smtplib.SMTPDataError(421, b'later'))
    second = FakeSMTP(smtplib.SMTPDataError(421, b'still unavailable'))
    get_smtp = Mock(
        side_effect=[
            (first.connector(), b4.USER_CONFIG['email']),
            (second.connector(), b4.USER_CONFIG['email']),
        ]
    )
    monkeypatch.setattr(b4, 'get_smtp', get_smtp)
    retry = retry_prompt(monkeypatch, 'y', 'n')
    with pytest.raises(SystemExit):
        run_send('--no-sign')
    assert retry.call_count == 2
    assert get_smtp.call_count == 2
    assert first.calls[1] == second.calls[0]
    assert len(second.calls) == 1
    assert pending_session(send_repo) is not None


@pytest.mark.parametrize('no_interactive', [False, True])
def test_noninteractive_failure_does_not_prompt_for_retry(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, no_interactive: bool
) -> None:
    first = FakeSMTP({}, smtplib.SMTPDataError(421, b'later'))
    configure_smtp(monkeypatch, first)
    retry = retry_prompt(monkeypatch)
    monkeypatch.setattr(sys.stdin, 'isatty', lambda: no_interactive)
    with pytest.raises(SystemExit):
        run_send('--no-sign', no_interactive=no_interactive)
    retry.assert_not_called()
    assert len(first.calls) == 2
    assert pending_session(send_repo) is not None


@pytest.mark.parametrize(
    'error',
    [
        TimeoutError('late'),
        smtplib.SMTPServerDisconnected('lost'),
        smtplib.SMTPDataError(-1, b'bad reply'),
    ],
)
def test_uncertain_delivery_never_offers_immediate_retry(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    first = FakeSMTP({}, error)
    configure_smtp(monkeypatch, first)
    retry = retry_prompt(monkeypatch)
    with pytest.raises(SystemExit):
        run_send('--no-sign')
    retry.assert_not_called()
    saved = pending_session(send_repo)
    assert saved is not None and saved.state.in_flight == 1
    assert len(first.calls) == 2


@pytest.mark.parametrize('outcome', [{}, smtplib.SMTPDataError(421, b'later')])
def test_journal_failure_never_offers_immediate_retry(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, outcome: Any
) -> None:
    first = FakeSMTP({}, outcome)
    configure_smtp(monkeypatch, first)
    retry = retry_prompt(monkeypatch)
    original = SendSession.save

    def fail_recording_result(self: SendSession) -> None:
        if len(first.calls) == 2 and self.state.in_flight is None:
            raise OSError('disk full')
        original(self)

    monkeypatch.setattr(SendSession, 'save', fail_recording_result)
    with pytest.raises(SystemExit):
        run_send('--no-sign')
    retry.assert_not_called()
    saved = pending_session(send_repo)
    assert saved is not None and saved.state.in_flight == 1


@pytest.mark.parametrize(
    'what', ['dirty', 'cover', 'branch', 'sender', 'excluded', 'transport', 'message']
)
def test_retry_uses_saved_submission_after_prompt(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, what: str
) -> None:
    first = FakeSMTP({}, smtplib.SMTPDataError(421, b'later'))
    second = FakeSMTP()
    configure_smtp(monkeypatch, first)
    retry = retry_prompt(monkeypatch)

    def change_submission(_prompt: str) -> str:
        configure_smtp(monkeypatch, second)
        if what == 'dirty':
            Path('send-0.txt').write_text('uncommitted')
        elif what == 'cover':
            cover, tracking = b4.ez.load_cover()
            b4.ez.store_cover(cover + '\nChanged during prompt.\n', tracking)
        elif what == 'branch':
            assert b4.git_run_command(None, ['checkout', '-b', 'elsewhere'])[0] == 0
        elif what == 'sender':
            monkeypatch.setattr(
                b4, 'get_smtp', lambda: (second.connector(), 'other@example.org')
            )
        elif what == 'excluded':
            b4.MAIN_CONFIG['email-exclude'] = 'list@example.org'
        elif what == 'transport':
            monkeypatch.setattr(
                b4, 'get_smtp', lambda: (['sendmail'], b4.USER_CONFIG['email'])
            )
        else:
            (send_repo / 'v1' / '0001.eml').write_bytes(b'changed')
        return 'y'

    retry.side_effect = change_submission
    if what == 'sender':
        run_send('--no-sign')
        assert all(call[0] == first.calls[0][0] for call in second.calls)
        assert pending_session(send_repo) is None
    else:
        with pytest.raises(SystemExit):
            run_send('--no-sign')
    retry.assert_called_once()
    if what in {'dirty', 'cover', 'branch', 'sender'}:
        assert len(second.calls) == 2
        assert second.calls[0] == first.calls[1]
        if what != 'sender':
            saved = pending_session(send_repo)
            assert saved is not None and saved.delivered()
    else:
        assert not second.calls


def test_fresh_send_is_blocked_while_pending(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _saved, smtp = interrupt_send(send_repo, monkeypatch)
    generate = Mock(side_effect=AssertionError('must not regenerate'))
    monkeypatch.setattr(b4.ez, 'get_prep_branch_as_patches', generate)
    with pytest.raises(SystemExit):
        run_send('--no-sign')
    generate.assert_not_called()
    assert len(smtp.calls) == 2


@pytest.mark.parametrize('what', ['head', 'cover', 'dirty', 'sender', 'excluded'])
def test_resume_uses_saved_submission_after_changes(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, what: str
) -> None:
    saved, first = interrupt_send(send_repo, monkeypatch)
    original_cover, original_tracking = b4.ez.load_cover(strip_comments=False)
    second = FakeSMTP()
    configure_smtp(monkeypatch, second)
    if what == 'head':
        assert (
            b4.git_run_command(None, ['commit', '--allow-empty', '-m', 'Changed'])[0]
            == 0
        )
    elif what == 'cover':
        cover, tracking = b4.ez.load_cover()
        b4.ez.store_cover(cover + '\nAnother paragraph.\n', tracking)
    elif what == 'dirty':
        Path('send-0.txt').write_text('uncommitted')
    elif what == 'sender':
        monkeypatch.setattr(
            b4, 'get_smtp', lambda: (second.connector(), 'other@example.org')
        )
    else:
        b4.MAIN_CONFIG['email-exclude'] = 'list@example.org'
    changed_head = b4.git_revparse_obj('HEAD')
    changed_cover = b4.ez.load_cover(strip_comments=False)
    if what == 'sender':
        run_send('--resume')
        assert pending_session(send_repo) is None
    else:
        with pytest.raises(SystemExit) as exc:
            run_send('--resume')
        assert exc.value.code == 1
        assert b4.git_revparse_obj('HEAD') == changed_head
        assert b4.ez.load_cover(strip_comments=False) == changed_cover
    if what == 'excluded':
        assert not second.calls
    else:
        assert len(second.calls) == 2
        assert second.calls[0] == first.calls[1]
        assert all(call[0] == saved.state.fromaddr for call in second.calls)
        if what != 'sender':
            assert SendSession.load(saved.directory).delivered()
    if what in {'head', 'cover', 'dirty'}:
        monkeypatch.setattr(
            b4, 'get_smtp', Mock(side_effect=AssertionError('all accepted'))
        )
        with pytest.raises(SystemExit):
            run_send('--resume')
        assert b4.ez.load_cover(strip_comments=False) == changed_cover
        assert b4.git_run_command(None, ['reset', '--hard', saved.state.head])[0] == 0
        if b4.ez.get_cover_strategy() == 'branch-description':
            b4.ez.store_cover(original_cover, original_tracking)
        run_send('--resume')
        assert pending_session(send_repo) is None
        assert b4.ez.load_cover()[1]['series']['revision'] == 2


def test_resume_export_never_connects_or_updates_progress(
    send_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The export is for reading, so it uses the same line endings as
    b4 send -o and --dry-run, not the CRLF of the saved wire messages."""
    saved, _first = interrupt_send(send_repo, monkeypatch)
    before = (saved.directory / 'state.json').read_bytes()
    monkeypatch.setattr(
        b4, 'get_smtp', Mock(side_effect=AssertionError('must not connect'))
    )
    out = tmp_path / 'outgoing'
    run_send('--resume', '-o', str(out))
    assert sorted(path.read_bytes() for path in out.glob('*.eml')) == sorted(
        saved.message_bytes(n).replace(b'\r\n', b'\n') for n in (1, 2)
    )
    assert (saved.directory / 'state.json').read_bytes() == before
    run_send('--resume', '--dry-run')
    assert 'Change 1' in caplog.text
    assert '\r' not in caplog.text
    assert (saved.directory / 'state.json').read_bytes() == before


@pytest.mark.parametrize(
    'option',
    [
        ('--to', 'other@example.org'),
        ('--cc', 'other@example.org'),
        ('--bcc', 'other@example.org'),
        ('--no-sign',),
        ('--reflect',),
        ('--resend',),
        ('--use-web-endpoint',),
        ('--force-cover-letter',),
    ],
)
def test_resume_disallows_message_changes(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, option: Tuple[str, ...]
) -> None:
    _saved, smtp = interrupt_send(send_repo, monkeypatch)
    with pytest.raises(SystemExit):
        run_send('--resume', *option)
    assert len(smtp.calls) == 2


def test_series_lock_prevents_parallel_senders(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _saved, smtp = interrupt_send(send_repo, monkeypatch)
    with b4.lockfile_nb(str(send_repo / 'send.lock')), pytest.raises(SystemExit):
        run_send('--resume')
    assert len(smtp.calls) == 2


@pytest.mark.parametrize(
    'failure,revision',
    [
        ('before-reroll', 1),
        ('after-reroll', 2),
        ('finish-record', 2),
    ],
)
def test_bookkeeping_failure_is_completed_without_mail(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, failure: str, revision: int
) -> None:
    """Once every recipient has accepted, --resume only finishes the
    reroll, whichever step was interrupted."""
    smtp = FakeSMTP()
    configure_smtp(monkeypatch, smtp)
    retry = retry_prompt(monkeypatch)
    with monkeypatch.context() as patched:
        if failure.endswith('reroll'):
            original_reroll = b4.ez.reroll

            def interrupted(*args: Any, **kwargs: Any) -> None:
                if failure == 'after-reroll':
                    original_reroll(*args, **kwargs)
                raise RuntimeError('interrupted bookkeeping')

            patched.setattr(b4.ez, 'reroll', interrupted)
        else:
            original_save = SendSession.save

            def fail_if_finished(self: SendSession) -> None:
                if self.state.finished:
                    raise OSError('disk full after reroll')
                original_save(self)

            patched.setattr(SendSession, 'save', fail_if_finished)
        with pytest.raises(SystemExit):
            run_send('--no-sign')
    retry.assert_not_called()
    assert len(smtp.calls) == 3
    assert b4.ez.load_cover()[1]['series']['revision'] == revision
    saved = pending_session(send_repo)
    assert saved is not None and saved.delivered()
    monkeypatch.setattr(
        b4, 'get_smtp', Mock(side_effect=AssertionError('all accepted'))
    )
    run_send('--resume')
    assert pending_session(send_repo) is None
    assert b4.ez.load_cover()[1]['series']['revision'] == 2


def test_interrupted_cover_tracking_update_is_completed_once(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    smtp = FakeSMTP()
    configure_smtp(monkeypatch, smtp)
    original = b4.ez.store_cover
    intermediate_cover = None

    def interrupted(cover: str, tracking: Dict[str, Any], new: bool = False) -> None:
        nonlocal intermediate_cover
        intermediate_cover = cover
        if b4.ez.get_cover_strategy() == 'branch-description':
            branch = b4.git_get_current_branch()
            b4.git_set_config(None, f'branch.{branch}.description', cover)
        raise OSError('interrupted while saving cover/tracking')

    monkeypatch.setattr(b4.ez, 'store_cover', interrupted)
    with pytest.raises(SystemExit):
        run_send('--no-sign')
    assert len(smtp.calls) == 3
    assert b4.ez.load_cover()[1]['series']['revision'] == 1
    monkeypatch.setattr(b4.ez, 'store_cover', original)
    monkeypatch.setattr(
        b4, 'get_smtp', Mock(side_effect=AssertionError('all accepted'))
    )
    run_send('--resume')
    cover, tracking = b4.ez.load_cover(strip_comments=False)
    assert intermediate_cover is not None
    assert cover == intermediate_cover.strip()
    assert cover.count('Changes in v2:') == 1
    assert tracking['series']['revision'] == 2
    assert len(tracking['series']['history']['v1']) == 1
    assert pending_session(send_repo) is None


def test_signed_bytes_are_not_resigned(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def sign(data: bytes) -> bytes:
        return b'X-Developer-Signature: frozen-test-signature\n' + data

    signer = Mock(side_effect=sign)
    monkeypatch.setattr(patatt, 'rfc2822_sign', signer)
    first = FakeSMTP({}, smtplib.SMTPDataError(550, b'limit'))
    configure_smtp(monkeypatch, first)
    with pytest.raises(SystemExit):
        run_send()
    assert signer.call_count == 3
    saved = pending_session(send_repo)
    assert saved is not None
    second = FakeSMTP()
    configure_smtp(monkeypatch, second)
    signer.side_effect = AssertionError('must not sign again')
    run_send('--resume')
    assert second.calls[0][2] == first.calls[1][2]
    assert b'X-Developer-Signature: frozen-test-signature\r\n' in second.calls[0][2]


@pytest.mark.parametrize('outcome,count', [('sent', 1), ('unsent', 2)])
def test_cli_reconciles_uncertain_delivery(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, outcome: str, count: int
) -> None:
    first = FakeSMTP({}, TimeoutError('no final response'))
    configure_smtp(monkeypatch, first)
    with pytest.raises(SystemExit):
        run_send('--no-sign')
    saved = pending_session(send_repo)
    assert saved is not None and saved.state.in_flight == 1
    second = FakeSMTP()
    configure_smtp(monkeypatch, second)
    with pytest.raises(SystemExit):
        run_send('--resume')
    assert not second.calls
    before = (saved.directory / 'state.json').read_bytes()
    with pytest.raises(SystemExit):
        run_send('--resume', '--resolve-uncertain', outcome, '--dry-run')
    assert (saved.directory / 'state.json').read_bytes() == before
    run_send('--resume', '--resolve-uncertain', outcome)
    assert len(second.calls) == count
    assert pending_session(send_repo) is None


def test_resume_uses_same_state_from_subdirectory(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    saved, _first = interrupt_send(send_repo, monkeypatch)
    child = Path('nested') / 'directory'
    child.mkdir(parents=True)
    monkeypatch.chdir(child)
    assert series_directory(saved.state.change_id) == send_repo
    second = FakeSMTP()
    configure_smtp(monkeypatch, second)
    run_send('--resume')
    assert len(second.calls) == 2


def test_no_snapshot_is_published_when_signing_fails(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    signer = Mock(side_effect=patatt.SigningError('test failure'))
    monkeypatch.setattr(patatt, 'rfc2822_sign', signer)
    smtp = FakeSMTP()
    configure_smtp(monkeypatch, smtp)
    with pytest.raises(SystemExit):
        run_send()
    assert not smtp.calls
    assert pending_session(send_repo) is None
    assert '--resume' not in caplog.text


@pytest.mark.parametrize(
    'args,sent',
    [
        (['--dry-run'], 0),
        (['-o', 'outgoing'], 0),
        (['--reflect'], 3),
        (['--preview-to', 'preview@example.org'], 3),
    ],
)
def test_non_submission_modes_do_not_create_resume_state(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, args: List[str], sent: int
) -> None:
    smtp = FakeSMTP()
    configure_smtp(monkeypatch, smtp)
    run_send('--no-sign', *args)
    assert len(smtp.calls) == sent
    assert not send_repo.exists()
    assert b4.ez.load_cover()[1]['series']['revision'] == 1


def test_completed_sends_leave_no_record(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sending the same revision again after --force-revision must work."""
    smtp = FakeSMTP()
    configure_smtp(monkeypatch, smtp)
    run_send('--no-sign')
    b4.ez.force_revision(1)
    run_send('--no-sign')
    assert len(smtp.calls) == 6
    assert b4.ez.load_cover()[1]['series']['revision'] == 2
    assert not list(send_repo.glob('v*'))


def test_source_change_at_resume_confirmation_only_defers_bookkeeping(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _saved, _first = interrupt_send(send_repo, monkeypatch)
    second = FakeSMTP()
    configure_smtp(monkeypatch, second)

    def change_branch(_prompt: str) -> str:
        b4.git_run_command(
            None, ['commit', '--allow-empty', '-m', 'Changed during prompt']
        )
        return ''

    monkeypatch.setattr('builtins.input', change_branch)
    with pytest.raises(SystemExit):
        run_send('--resume')
    assert len(second.calls) == 2
    saved = pending_session(send_repo)
    assert saved is not None and saved.delivered()


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


@pytest.mark.parametrize('exclude', ['list@example.org', '*@Example.org'])
def test_resume_respects_exclusions_in_frozen_headers(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, exclude: str
) -> None:
    """email-exclude takes shell-style patterns everywhere else in b4, so
    a pattern must keep a saved submission from going out as well."""
    first = FakeSMTP({}, {'test-override@example.com': (450, b'later')})
    configure_smtp(monkeypatch, first)
    with pytest.raises(SystemExit):
        run_send('--no-sign', '--cc', 'test-override@example.com')
    saved = pending_session(send_repo)
    assert saved is not None
    assert 'list@example.org' in saved.state.messages[1].accepted
    b4.MAIN_CONFIG['email-exclude'] = exclude
    second = FakeSMTP()
    configure_smtp(monkeypatch, second)
    with pytest.raises(SystemExit):
        run_send('--resume')
    assert not second.calls


def test_source_change_at_send_confirmation_saves_nothing(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The messages were made from the old HEAD, so they must not be saved
    as a submission that --resume would later send unchecked."""
    smtp = FakeSMTP()
    configure_smtp(monkeypatch, smtp)

    def change_branch(_prompt: str) -> str:
        b4.git_run_command(
            None, ['commit', '--allow-empty', '-m', 'Changed during prompt']
        )
        return ''

    monkeypatch.setattr('builtins.input', change_branch)
    with pytest.raises(SystemExit):
        run_send('--no-sign')
    assert not smtp.calls
    assert pending_session(send_repo) is None


@pytest.mark.parametrize('source', ['option', 'config'])
def test_bcc_survives_resume(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    bcc = 'secret@example.org'
    if source == 'config':
        b4.MAIN_CONFIG['send-series-bcc'] = bcc
        args = ['--no-sign']
    else:
        args = ['--no-sign', '--bcc', bcc]
    first = FakeSMTP({}, smtplib.SMTPDataError(421, b'temporary'))
    configure_smtp(monkeypatch, first)
    with pytest.raises(SystemExit):
        run_send(*args)
    second = FakeSMTP()
    configure_smtp(monkeypatch, second)
    run_send('--resume')
    calls = first.calls + second.calls
    assert len(calls) == 4
    assert all(bcc in recipients for _sender, recipients, _data in calls)
    assert not any(bcc.encode() in data for _sender, _recipients, data in calls)


def test_cli_permanent_refusal_finishes_with_a_warning(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Everyone else has the series, so it counts as sent and is rerolled.
    The user still has to learn who did not get it."""
    gone = {'test-override@example.com': (550, b'user unknown')}
    smtp = FakeSMTP(gone, gone, gone)
    configure_smtp(monkeypatch, smtp)
    run_send('--no-sign', '--cc', 'test-override@example.com')
    assert len(smtp.calls) == 3
    assert pending_session(send_repo) is None
    assert b4.ez.load_cover()[1]['series']['revision'] == 2
    assert 'permanently refused' in caplog.text
    assert 'test-override@example.com' in caplog.text


@pytest.mark.parametrize(
    'failure,transport',
    [('connect', 'smtp'), ('sender', 'smtp'), ('sender', 'local'), ('sender', 'web')],
)
def test_submission_that_reached_nobody_does_not_block_a_fresh_send(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch, failure: str, transport: str
) -> None:
    """Nothing went out, so there is nothing to protect from duplicates.
    The user must be free to fix the series and send it again, through
    any transport, instead of being held to the saved messages. Once the
    replacement goes out, --resume must not deliver the old messages."""
    if failure == 'connect':
        connector = b4.SMTPConnector(Mock(side_effect=OSError('bad password')))
    else:
        connector = FakeSMTP(
            smtplib.SMTPSenderRefused(550, b'no', 'alice@example.org')
        ).connector()
    monkeypatch.setattr(
        b4, 'get_smtp', lambda dryrun=False: (connector, str(b4.USER_CONFIG['email']))
    )
    with pytest.raises(SystemExit):
        run_send('--no-sign')
    stale = pending_session(send_repo)
    assert stale is not None and stale.untouched()
    _cover, tracking = b4.ez.load_cover()
    b4.ez.store_cover('Two fixed changes\n\nTo: list@example.org\n', tracking)

    smtp = FakeSMTP()
    configure_smtp(monkeypatch, smtp)
    args = ['--no-sign']
    if transport == 'web':
        b4.MAIN_CONFIG['send-endpoint-web'] = 'https://example.org/send'
        args = ['--use-web-endpoint']
    elif transport == 'local':
        monkeypatch.setattr(
            b4, 'get_smtp', lambda dryrun=False: (['sendmail'], 'alice@example.org')
        )
    # Stopping at the prompt must leave the original available for resume.
    with monkeypatch.context() as mp:
        mp.setattr('builtins.input', Mock(side_effect=KeyboardInterrupt))
        with pytest.raises(SystemExit) as exc:
            run_send(*args)
        assert exc.value.code == 130
    assert pending_session(send_repo) is not None

    delivered: List[bytes] = []

    def deliver(smtp: Any, msgs: List[EmailMessage], **kwargs: Any) -> int:
        if transport == 'web':
            assert kwargs['web_endpoint'] == 'https://example.org/send'
        else:
            assert smtp == ['sendmail']
        assert pending_session(send_repo) is None
        with (
            pytest.raises(b4.LockHeldError),
            b4.lockfile_nb(str(send_repo / 'send.lock')),
        ):
            pass
        delivered.extend(msg.as_bytes() for msg in msgs)
        return len(msgs)

    monkeypatch.setattr(b4, 'send_mail', deliver)
    run_send(*args)
    if transport == 'smtp':
        delivered = [data for _sender, _recipients, data in smtp.calls]
    assert len(delivered) == 3
    assert b'Two fixed changes' in delivered[0]
    assert pending_session(send_repo) is None
    assert b4.ez.load_cover()[1]['series']['revision'] == 2

    resumed = FakeSMTP()
    configure_smtp(monkeypatch, resumed)
    run_send('--resume')
    assert not resumed.calls


@pytest.mark.parametrize('failure', ['cannot-tag', 'tag-exists'])
def test_sent_tag_trouble_does_not_block_the_reroll(
    send_repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failure: str,
) -> None:
    """The sent tag is a convenience for --resend. The mail is out either
    way, so a tag that cannot be made, or one left by an earlier send of
    the same revision, must not leave a record that no --resume can ever
    finish."""
    smtp = FakeSMTP()
    configure_smtp(monkeypatch, smtp)
    if failure == 'cannot-tag':
        original_git = b4.git_run_command

        def fail_tag(topdir: Any, args: List[str], **kwargs: Any) -> Tuple[int, str]:
            if args[0] == 'tag':
                return 1, 'cannot create tag'
            return original_git(topdir, args, **kwargs)

        monkeypatch.setattr(b4, 'git_run_command', fail_tag)
    else:
        change_id = b4.ez.load_cover()[1]['series']['change-id']
        tagname, _rev = b4.ez.get_sent_tagname(change_id, b4.ez.SENT_TAG_PREFIX, 1)
        # Two commits back has a different tree with every cover strategy
        gitargs = ['tag', '-a', '-m', 'earlier send', tagname, 'HEAD~2']
        assert b4.git_run_command(None, gitargs)[0] == 0
    run_send('--no-sign')
    assert len(smtp.calls) == 3
    assert pending_session(send_repo) is None
    assert b4.ez.load_cover()[1]['series']['revision'] == 2
    expected = 'Could not tag' if failure == 'cannot-tag' else 'already exists'
    assert expected in caplog.text


def test_resend_is_not_blocked_by_an_unfinished_submission(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--resend sends an older revision from its tag and keeps no record
    of its own, so the unfinished submission of the current revision has
    nothing to say about it."""
    configure_smtp(monkeypatch, FakeSMTP())
    run_send('--no-sign')
    saved, _smtp = interrupt_send(send_repo, monkeypatch)
    assert saved.state.revision == 2
    smtp = FakeSMTP()
    configure_smtp(monkeypatch, smtp)
    run_send('--no-sign', '--resend', 'v1')
    assert len(smtp.calls) == 3
    assert all(b'RESEND' in call[2] for call in smtp.calls)
    still = pending_session(send_repo)
    assert still is not None
    assert (still.directory / 'state.json').read_bytes() == (
        saved.directory / 'state.json'
    ).read_bytes()


def test_unreadable_record_does_not_block_a_dry_run(
    send_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dry run sends nothing, so it needs no answer from the record and
    must keep working when the record cannot be read."""
    saved, _smtp = interrupt_send(send_repo, monkeypatch)
    (saved.directory / 'state.json').write_text('{')
    run_send('--no-sign', '--dry-run')
    with pytest.raises(SystemExit):
        run_send('--no-sign')
