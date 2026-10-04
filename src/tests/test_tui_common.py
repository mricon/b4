"""Tests for the shared TUI helpers in b4.tui._common, and for the
contracts every top-level b4 TUI app is expected to honour."""

import importlib
from typing import Any, Dict
from unittest import mock

import pytest

pytest.importorskip('textual')

from textual.app import App
from textual.binding import Binding

import b4.bugs
from b4.tui._common import (
    QUIT_BINDINGS,
    LoreNodeShutdownMixin,
    limit_substring_matcher,
    matches_limit,
    notify_quit_hint,
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
