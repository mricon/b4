"""Tests for the shared TUI helpers in b4.tui._common, and for the
contracts every top-level b4 TUI app is expected to honour."""

import ast
import contextlib
import importlib
import pathlib
import signal
import subprocess
from typing import Any, Dict, Iterator, List, Tuple, Type
from unittest import mock

import pytest

pytest.importorskip('textual')

from textual.app import App
from textual.binding import Binding

import b4
import b4.bugs
from b4.tui._common import (
    QUIT_BINDINGS,
    LoreNodeShutdownMixin,
    limit_substring_matcher,
    matches_limit,
    notify_quit_hint,
    pw_key_suspended,
    send_suspended,
    suspended,
)

# A representative item for engine tests; per-app field semantics are
# pinned by the _matches_limit tests in test_tui_tracking.py and
# test_tui_bugs.py.
ITEM: Dict[str, Any] = {
    'subject': 'net: fix widget frobnication',
    'author': 'Alice Author',
    'status': 'reviewing',
    'empty': '',
    'missing_value': None,
}

PREFIXED = {
    's:': limit_substring_matcher('status'),
    'has:': lambda item, needle: bool(item.get(needle)),
}
BARE = limit_substring_matcher('subject', 'author')


class TestMatchesLimit:
    """Tests for the generic matches_limit() engine."""

    @pytest.mark.parametrize(
        'pattern, expected',
        [
            pytest.param('', True, id='empty-pattern-matches-all'),
            pytest.param('   ', True, id='whitespace-only-matches-all'),
            pytest.param('widget', True, id='bare-first-field'),
            pytest.param('alice', True, id='bare-second-field'),
            pytest.param('WIDGET', True, id='bare-case-insensitive'),
            pytest.param('gadget', False, id='bare-no-match'),
            pytest.param('s:review', True, id='prefixed-match'),
            pytest.param('S:REVIEW', True, id='prefixed-case-insensitive'),
            pytest.param('s:done', False, id='prefixed-no-match'),
            pytest.param('s:', True, id='empty-needle-matches'),
            pytest.param('widget alice s:review', True, id='and-all-match'),
            pytest.param('widget s:done', False, id='and-one-fails'),
            pytest.param('has:status', True, id='custom-matcher-true'),
            pytest.param('has:empty', False, id='custom-matcher-false'),
        ],
    )
    def test_engine(self, pattern: str, expected: bool) -> None:
        assert matches_limit(ITEM, pattern, PREFIXED, BARE) is expected

    def test_unknown_prefix_falls_through_to_bare(self) -> None:
        """A token with an unregistered prefix is just a bare token."""
        assert matches_limit(ITEM, 'x:widget', PREFIXED, BARE) is False
        item = dict(ITEM, subject='see x:widget marker')
        assert matches_limit(item, 'x:widget', PREFIXED, BARE) is True


class TestLimitSubstringMatcher:
    """Tests for the dict-field substring matcher factory."""

    def test_any_of_fields(self) -> None:
        match = limit_substring_matcher('subject', 'author')
        assert match(ITEM, 'frobnication') is True
        assert match(ITEM, 'author') is True
        assert match(ITEM, 'reviewing') is False

    def test_missing_and_none_fields_count_as_empty(self) -> None:
        match = limit_substring_matcher('nonexistent', 'missing_value')
        assert match(ITEM, 'anything') is False
        # ...but the empty needle is a substring of the empty string.
        assert match(ITEM, '') is True

    def test_field_values_matched_case_insensitively(self) -> None:
        match = limit_substring_matcher('author')
        # matches_limit lowercases the needle; the matcher must lowercase
        # the field value to meet it.
        assert match(ITEM, 'alice') is True


# ---------------------------------------------------------------------------
# Contracts shared by every top-level app
# ---------------------------------------------------------------------------

TOP_LEVEL_APPS = [
    'b4.review_tui._pw_app.PwApp',
    'b4.review_tui._review_app.ReviewApp',
    'b4.review_tui._tracking_app.TrackingApp',
    pytest.param(
        'b4.bugs._tui.BugListApp',
        marks=pytest.mark.skipif(
            not b4.bugs.has_ezgb(), reason='needs the optional [bugs] extra'
        ),
    ),
]


def _load(path: str) -> Any:
    modpath, clsname = path.rsplit('.', 1)
    return getattr(importlib.import_module(modpath), clsname)


class TestTopLevelAppContracts:
    """Every app quits on capital Q, only hints on bare q, and shuts the
    shared lore node down on exit."""

    @pytest.mark.parametrize('app_path', TOP_LEVEL_APPS)
    def test_quit_takes_capital_q(self, app_path: str) -> None:
        cls = _load(app_path)
        bmap = {b.key: b for b in cls.BINDINGS if isinstance(b, Binding)}
        assert bmap['Q'].action == 'quit'
        assert bmap['q'].action == 'quit_hint'
        assert bmap['q'].show is False
        assert callable(getattr(cls, 'action_quit_hint', None))

    @pytest.mark.parametrize('app_path', TOP_LEVEL_APPS)
    def test_shuts_down_lore_node_on_exit(self, app_path: str) -> None:
        cls = _load(app_path)
        assert issubclass(cls, LoreNodeShutdownMixin)
        # Nothing in the class hierarchy overrides the hook away.
        assert cls.on_unmount is LoreNodeShutdownMixin.on_unmount


class _QuitHost(LoreNodeShutdownMixin, App[None]):
    """The smallest app wearing the shared quit bindings and the mixin."""

    BINDINGS = list(QUIT_BINDINGS)

    def action_quit_hint(self) -> None:
        notify_quit_hint(self)


class TestQuitBehaviour:
    """The live behaviour behind the bindings the apps above share.  The
    per-app wiring is pinned structurally by TestTopLevelAppContracts;
    TestTrackingQuit in test_tui_tracking.py drives it end-to-end once."""

    @pytest.mark.asyncio
    async def test_q_hints_capital_q_quits_and_shuts_down(self) -> None:
        node = mock.Mock()
        app = _QuitHost()
        with mock.patch('b4.get_lore_node', return_value=node):
            async with app.run_test() as pilot:
                await pilot.press('q')
                await pilot.pause()
                exited_on_q = app._exit
                assert any("'Q'" in n.message for n in app._notifications)

                await pilot.press('Q')
                await pilot.pause()
                exited_on_capital_q = app._exit

        assert (exited_on_q, exited_on_capital_q) == (False, True)

        # on_unmount fired during app teardown and shut the node down.
        assert node.shutdown.called


class _FakeDriver:
    """Just enough driver for the real App.suspend() to run against."""

    can_suspend = True

    def __init__(self) -> None:
        self.calls: List[str] = []

    def suspend_application_mode(self) -> None:
        self.calls.append('suspend')

    def resume_application_mode(self) -> None:
        self.calls.append('resume')

    def no_automatic_restart(self) -> 'contextlib.nullcontext[None]':
        return contextlib.nullcontext()


@pytest.fixture
def suspendable() -> Iterator[Tuple[App[None], _FakeDriver]]:
    """An app that is not running, but whose suspend() works for real."""
    app: App[None] = App()
    driver = _FakeDriver()
    with mock.patch.object(app, '_driver', driver):
        yield app, driver


@pytest.fixture
def apps_sigint() -> Iterator[List[int]]:
    """Stand in for the SIGINT handler asyncio installs for a running app.

    Yields the signals it saw: any entry means the app's main task would
    have been cancelled, and the TUI would quit.
    """
    seen: List[int] = []

    def _handler(signum: int, frame: Any) -> None:
        seen.append(signum)

    prev = signal.signal(signal.SIGINT, _handler)
    try:
        yield seen
    finally:
        signal.signal(signal.SIGINT, prev)


class TestPwKeySuspended:
    """A credential helper may ask for a passphrase on the terminal.  While
    the TUI owns the terminal that prompt is hidden and cannot be answered,
    so the TUI must step aside for the lookup -- but only for a lookup that
    really runs a helper, because stepping aside makes the screen flicker."""

    PW_USER_CONFIG = {'pw-user': 'me', 'pw-url': 'https://pw.example.org/'}

    @pytest.fixture(autouse=True)
    def _clear_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(b4, '_PW_KEY_CACHE', {})

    def test_helper_runs_with_the_tui_out_of_the_way(
        self, suspendable: Tuple[App[None], _FakeDriver]
    ) -> None:
        app, driver = suspendable
        b4.MAIN_CONFIG.update(self.PW_USER_CONFIG)
        during: List[str] = []

        def _fill(*args: Any, **kwargs: Any) -> str:
            during.extend(driver.calls)
            return 'fromhelper'

        with mock.patch.object(b4, 'git_credential_fill', _fill):
            assert pw_key_suspended(app) == 'fromhelper'
        assert during == ['suspend']
        assert driver.calls == ['suspend', 'resume']

    @pytest.mark.parametrize('cached', [False, True])
    def test_no_flicker_when_no_helper_runs(
        self, suspendable: Tuple[App[None], _FakeDriver], cached: bool
    ) -> None:
        app, driver = suspendable
        if cached:
            b4.MAIN_CONFIG.update(self.PW_USER_CONFIG)
            with mock.patch.object(b4, 'git_credential_fill', return_value='key'):
                b4.get_pw_key()
        else:
            b4.MAIN_CONFIG.update({'pw-key': 'key'})
        assert pw_key_suspended(app) == 'key'
        assert driver.calls == []


class TestSuspended:
    """Textual's App.suspend() only resumes the app when its block exits
    normally.  Anything raised inside -- a failed signature, or the Ctrl-C a
    user presses to give up on a hung gpg -- left the app deaf, with its
    writer thread stopped, and the next write to the screen blocked b4."""

    @pytest.mark.parametrize('exc', [RuntimeError, KeyboardInterrupt, SystemExit])
    def test_resumes_the_app_when_the_block_raises(
        self, suspendable: Tuple[App[None], _FakeDriver], exc: Type[BaseException]
    ) -> None:
        app, driver = suspendable
        with pytest.raises(exc):
            with suspended(app):
                raise exc()
        assert driver.calls == ['suspend', 'resume']

    def test_ctrl_c_ends_the_child_but_spares_the_app(
        self, suspendable: Tuple[App[None], _FakeDriver], apps_sigint: List[int]
    ) -> None:
        """Most suspended blocks run a child, and have Python code after it
        that must still run, such as going back to the user's branch.  Ctrl-C
        must end the child, but must not reach the block or the app: the
        app's handler would cancel its main task and quit the TUI."""
        app, _ = suspendable
        child_rc: Any = None
        with pytest.raises(RuntimeError):
            with suspended(app):
                # The child sends itself the SIGINT a terminal would send it.
                child = subprocess.run(['sh', '-c', 'kill -INT $$; exit 0'])
                child_rc = child.returncode
                signal.raise_signal(signal.SIGINT)
                raise RuntimeError('the block went on after Ctrl-C')
        assert child_rc == -signal.SIGINT
        assert apps_sigint == []
        # The app's own handler is back, also after an error.
        signal.raise_signal(signal.SIGINT)
        assert apps_sigint == [signal.SIGINT]

    def test_an_interruptible_block_hears_ctrl_c(
        self, suspendable: Tuple[App[None], _FakeDriver], apps_sigint: List[int]
    ) -> None:
        """A caller that can handle Ctrl-C, such as a send, gets
        KeyboardInterrupt raised in the block, like any CLI code."""
        app, driver = suspendable
        with pytest.raises(KeyboardInterrupt):
            with suspended(app, interruptible=True):
                signal.raise_signal(signal.SIGINT)
        assert driver.calls == ['suspend', 'resume']
        assert apps_sigint == []

    def test_nothing_else_calls_textual_suspend_directly(self) -> None:
        """Every suspend must go through suspended(), or the bug above comes
        back at whichever call site skipped it."""
        srcdir = pathlib.Path(b4.__file__).parent
        helper = srcdir / 'tui' / '_common.py'
        offenders = []
        for path in sorted(srcdir.rglob('*.py')):
            for node in ast.walk(ast.parse(path.read_text(), str(path))):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == 'suspend'
                    and not node.args
                    and path != helper
                ):
                    offenders.append(f'{path.relative_to(srcdir)}:{node.lineno}')
        assert offenders == []


def _connector(connected: bool) -> b4.SMTPConnector:
    conn = b4.SMTPConnector(mock.Mock)
    if connected:
        conn()
    return conn


class TestSendSuspended:
    """A send that fails or is interrupted is reported, not raised, and the
    app is back on screen to report it."""

    @pytest.mark.parametrize(
        ('smtp', 'dies', 'notice', 'severity'),
        [
            pytest.param(
                _connector(False),
                RuntimeError('bad PIN'),
                'Send failed: bad PIN',
                'error',
                id='error',
            ),
            pytest.param(
                _connector(False),
                KeyboardInterrupt(),
                'Send interrupted',
                'warning',
                id='ctrl-c-while-signing',
            ),
            # Once the server was dialled, a retry may send duplicates, and
            # the user has to know that before they press send again.
            pytest.param(
                _connector(True),
                KeyboardInterrupt(),
                'Send interrupted, some messages may have gone out',
                'warning',
                id='ctrl-c-after-connecting',
            ),
            # A local sendmail command leaves no trace of having been run.
            pytest.param(
                ['/usr/sbin/sendmail', '-i'],
                KeyboardInterrupt(),
                'Send interrupted, some messages may have gone out',
                'warning',
                id='ctrl-c-with-local-command',
            ),
        ],
    )
    def test_reports_and_returns_none(
        self,
        suspendable: Tuple[App[None], _FakeDriver],
        apps_sigint: None,
        smtp: Any,
        dies: BaseException,
        notice: str,
        severity: str,
    ) -> None:
        app, driver = suspendable
        handlers: List[Any] = []

        def _send_mail(*args: Any, **kwargs: Any) -> int:
            handlers.append(signal.getsignal(signal.SIGINT))
            raise dies

        with (
            mock.patch.object(app, 'notify') as notify,
            mock.patch('b4.get_smtp', return_value=(smtp, 'me@ex.com')),
            mock.patch('b4.send_mail', side_effect=_send_mail),
        ):
            sent = send_suspended(app, [mock.Mock()], patatt_sign=True, dryrun=False)
        assert sent is None
        assert driver.calls == ['suspend', 'resume']
        notify.assert_called_once_with(notice, severity=severity)
        # The send is the one block where Ctrl-C has to raise in our code.
        assert handlers == [signal.default_int_handler]

    def test_returns_the_count_without_a_notice(
        self, suspendable: Tuple[App[None], _FakeDriver]
    ) -> None:
        """Success is the caller's to report: each one words it differently."""
        app, _ = suspendable
        with (
            mock.patch.object(app, 'notify') as notify,
            mock.patch('b4.get_smtp', return_value=(None, 'me@ex.com')),
            mock.patch('b4.send_mail', return_value=0),
        ):
            sent = send_suspended(app, [mock.Mock()], patatt_sign=False, dryrun=True)
        assert sent == 0
        notify.assert_not_called()
