#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Integration tests for the PwApp (Patchwork) TUI.

Uses real SQLite databases (via b4.review.tracking) but no network access:
the Patchwork REST calls and lore retrieval are mocked.
"""

import datetime
from typing import Any, Dict, List
from unittest import mock

import pytest

pytest.importorskip('textual')

from textual.widgets import Label, ListView, ProgressBar

import b4
import b4.review
import b4.review.tracking as tracking
import liblore
from b4.review._review import PwFetchResult
from b4.review_tui._modals import SetStateScreen
from b4.review_tui._pw_app import PwApp, PwFetchProgress

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeLoreNode:
    """Stand-in for the shared lore node with a real sticky cancel flag.

    Mirrors the contract that matters here: once cancelled, the node stays
    cancelled (and callers raise OperationCancelledError) until reset_cancel().
    """

    def __init__(self, cancelled: bool = False) -> None:
        self.cancelled = cancelled

    def cancel(self) -> None:
        self.cancelled = True

    def reset_cancel(self) -> None:
        self.cancelled = False


def _make_lore_series() -> Any:
    """Build a minimal LoreSeries-like object for tracking metadata."""
    lser = mock.Mock()
    lser.revision = 1
    lser.fromname = 'Test Author'
    lser.fromemail = 'author@example.com'
    lser.expected = 1
    lser.subject = '[PATCH] test series'
    lser.change_id = 'test-change-id-123'
    lser.fingerprint = 'abcdef0123456789'

    ref_msg = mock.Mock()
    ref_msg.msgid = 'cover@example.com'
    ref_msg.date = datetime.datetime(2026, 1, 15, 10, 0, tzinfo=datetime.timezone.utc)
    return lser, ref_msg


# ---------------------------------------------------------------------------
# action_track_series
# ---------------------------------------------------------------------------


class TestPwTrackSeries:
    """Tracking a Patchwork series fetches the thread from lore.

    Regression coverage for the bug where starting to track a series in the
    Patchwork app aborted immediately with "Request cancelled": another app
    (e.g. TrackingApp) cancels the shared lore node on exit, leaving its
    sticky cancel flag set, and action_track_series fetched without first
    calling reset_cancel().
    """

    @pytest.mark.asyncio
    async def test_track_series_resets_stale_cancel_flag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        identifier = 'pw-test-project'
        tracking.init_db(identifier)

        series: Dict[str, Any] = {
            'id': 42,
            'name': 'Test series',
            'msgid': 'cover@example.com',
            'state': 'new',
        }

        # The series list loads via the Patchwork REST API (not the lore node).
        monkeypatch.setattr(
            b4.review,
            'pw_fetch_series',
            lambda *a, **k: PwFetchResult([series], 1, None),
        )
        monkeypatch.setattr(b4.review, 'pw_fetch_states', lambda *a, **k: [])
        # Resolve the tracking identifier from the patchwork project name.
        monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)

        # A previous app left the shared node cancelled.
        node = _FakeLoreNode(cancelled=True)
        monkeypatch.setattr(b4, 'get_lore_node', lambda: node)

        def _fake_retrieve(msgid: str) -> List[Any]:
            # Honour the sticky flag exactly like liblore does.
            if node.cancelled:
                raise liblore.OperationCancelledError('Request cancelled')
            return [object()]

        lser, ref_msg = _make_lore_series()
        monkeypatch.setattr(b4.review, '_retrieve_messages', _fake_retrieve)
        monkeypatch.setattr(b4.review, '_get_lore_series', lambda msgs: lser)
        monkeypatch.setattr(b4.review, 'get_reference_message', lambda lser: ref_msg)

        app = PwApp('fakekey', 'https://pw.example.org', identifier)
        assert app._tracking_enabled is True

        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # The series list is populated and the first item highlighted.
            item = app._get_highlighted_item()
            assert item is not None
            assert item.series['id'] == 42

            app.action_track_series()
            await app.workers.wait_for_complete()
            await pilot.pause()

            # The stale flag was cleared before the fetch, so the retrieve
            # succeeded and the series is now tracked both in memory and in the
            # database.  (Asserted inside the context: on_unmount cancels the
            # node again on app shutdown.)
            assert node.cancelled is False
            assert 42 in app._tracked_ids
            assert 42 in tracking.get_tracked_pw_series_ids(identifier)

    @pytest.mark.asyncio
    async def test_track_series_does_not_suspend(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The fetch runs in a worker, not by suspending the TUI.

        Suspending dropped out of the alternate screen and back, which the user
        saw as a flicker.  We now fetch in a worker thread (quietly), so suspend
        must not be touched -- this guards against regressing to the old path.
        """
        identifier = 'pwflicker'
        tracking.init_db(identifier)

        series = {
            'id': 7,
            'name': 'flicker series',
            'msgid': 'flick@example.com',
            'state': 'new',
            'submitter': 'Someone',
            'date': '2026-01-15T10:00:00',
        }
        monkeypatch.setattr(
            b4.review,
            'pw_fetch_series',
            lambda *a, **k: PwFetchResult([series], 1, None),
        )
        monkeypatch.setattr(b4.review, 'pw_fetch_states', lambda *a, **k: [])
        monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)

        node = _FakeLoreNode()
        monkeypatch.setattr(b4, 'get_lore_node', lambda: node)
        lser, ref_msg = _make_lore_series()
        monkeypatch.setattr(b4.review, '_retrieve_messages', lambda msgid: [object()])
        monkeypatch.setattr(b4.review, '_get_lore_series', lambda msgs: lser)
        monkeypatch.setattr(b4.review, 'get_reference_message', lambda lser: ref_msg)

        # Any call to suspend() means we regressed to the flickering path.
        def _boom(self: PwApp) -> Any:
            raise AssertionError('action_track_series must not suspend the TUI')

        monkeypatch.setattr(PwApp, 'suspend', _boom, raising=False)

        app = PwApp('fakekey', 'https://pw.example.org', identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_track_series()
            await app.workers.wait_for_complete()
            await pilot.pause()

            # Tracked successfully, and suspend() was never invoked.
            assert 7 in app._tracked_ids
            assert 7 in tracking.get_tracked_pw_series_ids(identifier)

    @pytest.mark.asyncio
    async def test_track_series_surfaces_fetch_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A fetch failure notifies and leaves the series untracked.

        With the worker running exit_on_error=False, a raised error flows to
        on_worker_state_changed instead of crashing the app.
        """
        identifier = 'pwerr'
        tracking.init_db(identifier)

        series = {
            'id': 9,
            'name': 'doomed series',
            'msgid': 'doom@example.com',
            'state': 'new',
            'submitter': 'Someone',
            'date': '2026-01-15T10:00:00',
        }
        monkeypatch.setattr(
            b4.review,
            'pw_fetch_series',
            lambda *a, **k: PwFetchResult([series], 1, None),
        )
        monkeypatch.setattr(b4.review, 'pw_fetch_states', lambda *a, **k: [])
        monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)

        node = _FakeLoreNode()
        monkeypatch.setattr(b4, 'get_lore_node', lambda: node)

        def _boom_fetch(msgid: str) -> List[Any]:
            raise RuntimeError('network is down')

        monkeypatch.setattr(b4.review, '_retrieve_messages', _boom_fetch)

        app = PwApp('fakekey', 'https://pw.example.org', identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_track_series()
            # The worker drains during this pause and is removed from the
            # manager (errored workers re-raise via wait_for_complete()).
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            # App stayed alive; nothing got tracked and the context was cleared.
            assert 9 not in app._tracked_ids
            assert 9 not in tracking.get_tracked_pw_series_ids(identifier)
            assert app._track_ctx is None


# ---------------------------------------------------------------------------
# Large-backlog notice
# ---------------------------------------------------------------------------


def _backlog_series() -> Dict[str, Any]:
    return {
        'id': 1,
        'name': 'a series',
        'msgid': 'a@example.com',
        'state': 'new',
        'submitter': 'Someone',
        'date': '2026-06-01T00:00:00',
    }


def _backlog_toasts(app: PwApp) -> List[Any]:
    """The active large-backlog notifications, if any."""
    return [n for n in app._notifications if n.title == 'Large Patchwork backlog']


def _static_text(widget: Any) -> str:
    """Return a Static/Label's text across Textual versions.

    Textual >= 1.0 (pip) exposes ``content``; older builds (Fedora package)
    still use ``renderable``.
    """
    if hasattr(widget, 'content'):
        return str(widget.content)
    return str(widget.renderable)


class TestPwBacklogNotice:
    """When the fetch is windowed, the user gets a one-shot, self-dismissing
    notification (not a blocking modal)."""

    @pytest.mark.asyncio
    async def test_windowed_fetch_notifies(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            b4.review,
            'pw_fetch_series',
            lambda *a, **k: PwFetchResult([_backlog_series()], 28180, 30),
        )
        monkeypatch.setattr(b4.review, 'pw_fetch_states', lambda *a, **k: [])
        monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)

        app = PwApp('fakekey', 'https://pw.example.org', 'linux-kselftest')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            # A toast was posted (not a modal screen), carrying the count/window.
            toasts = _backlog_toasts(app)
            assert len(toasts) == 1
            assert toasts[0].severity == 'warning'
            assert '28,180' in toasts[0].message
            assert '30 days' in toasts[0].message
            assert app._backlog_count == 28180
            assert app._window_days == 30

    @pytest.mark.asyncio
    async def test_full_fetch_does_not_notify(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            b4.review,
            'pw_fetch_series',
            lambda *a, **k: PwFetchResult([_backlog_series()], 42, None),
        )
        monkeypatch.setattr(b4.review, 'pw_fetch_states', lambda *a, **k: [])
        monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)

        app = PwApp('fakekey', 'https://pw.example.org', 'proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert _backlog_toasts(app) == []

    @pytest.mark.asyncio
    async def test_notifies_once_across_refresh(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A manual refresh must not re-post the notice once shown."""
        monkeypatch.setattr(
            b4.review,
            'pw_fetch_series',
            lambda *a, **k: PwFetchResult([_backlog_series()], 28180, 30),
        )
        monkeypatch.setattr(b4.review, 'pw_fetch_states', lambda *a, **k: [])
        monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)

        app = PwApp('fakekey', 'https://pw.example.org', 'linux-kselftest')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert len(_backlog_toasts(app)) == 1
            # Clear toasts and refresh: the flag keeps it from posting again.
            app._notifications.clear()
            await app.action_refresh()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert _backlog_toasts(app) == []


# ---------------------------------------------------------------------------
# Loading progress bar
# ---------------------------------------------------------------------------


class TestPwLoadingProgress:
    """While fetching, the loading widget is a determinate progress bar driven
    by the fetch worker (rather than an indeterminate spinner)."""

    @pytest.mark.asyncio
    async def test_fetch_passes_progress_callback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The worker hands pw_fetch_series a callable that posts progress."""
        captured: Dict[str, Any] = {}

        def _fake_fetch(
            pwkey: str, pwurl: str, pwproj: str, progress_cb: Any = None
        ) -> PwFetchResult:
            captured['cb'] = progress_cb
            # Exercise the callback the way the real fetch does.
            if progress_cb is not None:
                progress_cb(0, 5)
                progress_cb(5, 5)
            return PwFetchResult([_backlog_series()], 5, None)

        monkeypatch.setattr(b4.review, 'pw_fetch_series', _fake_fetch)
        monkeypatch.setattr(b4.review, 'pw_fetch_states', lambda *a, **k: [])
        monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)

        app = PwApp('fakekey', 'https://pw.example.org', 'proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert callable(captured['cb'])

    @pytest.mark.asyncio
    async def test_multi_page_progress_drives_determinate_bar(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When the result spans several pages, the bar tracks total/progress."""
        monkeypatch.setattr(
            b4.review,
            'pw_fetch_series',
            lambda *a, **k: PwFetchResult([_backlog_series()], 1, None),
        )
        monkeypatch.setattr(b4.review, 'pw_fetch_states', lambda *a, **k: [])
        monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)

        app = PwApp('fakekey', 'https://pw.example.org', 'proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            # The initial dialog is gone once the list is populated; mount a
            # fresh loading panel to exercise the handler deterministically.
            await app.mount(app._make_loading())
            total = b4.review.PW_PER_PAGE * 3
            app.on_pw_fetch_progress(
                PwFetchProgress(fetched=b4.review.PW_PER_PAGE, total=total)
            )
            await pilot.pause()
            bar = app.query_one('#pw-loading-bar', ProgressBar)
            assert bar.total == total
            assert bar.progress == b4.review.PW_PER_PAGE
            status = app.query_one('#pw-loading-status', Label)
            assert 'of' in _static_text(status)

    @pytest.mark.asyncio
    async def test_single_page_progress_stays_indeterminate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A single page of patches can't advance a determinate bar, so it
        keeps pulsing while the status line shows the count."""
        monkeypatch.setattr(
            b4.review,
            'pw_fetch_series',
            lambda *a, **k: PwFetchResult([_backlog_series()], 1, None),
        )
        monkeypatch.setattr(b4.review, 'pw_fetch_states', lambda *a, **k: [])
        monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)

        app = PwApp('fakekey', 'https://pw.example.org', 'proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            await app.mount(app._make_loading())
            app.on_pw_fetch_progress(PwFetchProgress(fetched=0, total=204))
            await pilot.pause()
            # No total set -> the bar is still in its indeterminate (pulsing)
            # state, not stuck at 0% of a known total.
            bar = app.query_one('#pw-loading-bar', ProgressBar)
            assert bar.total is None
            status = app.query_one('#pw-loading-status', Label)
            assert 'Loading 204 patches' in _static_text(status)


# ---------------------------------------------------------------------------
# Multi-select marking and bulk state changes
# ---------------------------------------------------------------------------


def _mk_series(sid: int, state: str = 'new') -> Dict[str, Any]:
    """A Patchwork series row carrying two patches."""
    return {
        'id': sid,
        'name': f'series {sid}',
        'msgid': f's{sid}@example.com',
        'state': state,
        'submitter': 'Someone',
        'date': '2026-06-01T00:00:00',
        'check': 'pending',
        'patch_ids': [sid * 10, sid * 10 + 1],
    }


def _pw_states() -> List[Dict[str, Any]]:
    return [
        {'slug': 'new', 'name': 'New'},
        {'slug': 'reviewing', 'name': 'Reviewing'},
        {'slug': 'accepted', 'name': 'Accepted'},
    ]


class _FakeResp:
    def raise_for_status(self) -> None:
        return None


class _FakePwSession:
    """Records PATCH calls so a test can assert which patches were updated."""

    def __init__(self) -> None:
        self.patched: List[str] = []

    def patch(self, url: str, data: Any = None, stream: bool = False) -> _FakeResp:
        self.patched.append(url)
        return _FakeResp()


def _install_series(
    monkeypatch: pytest.MonkeyPatch, series: List[Dict[str, Any]]
) -> None:
    monkeypatch.setattr(
        b4.review,
        'pw_fetch_series',
        lambda *a, **k: PwFetchResult(series, len(series), None),
    )
    monkeypatch.setattr(b4.review, 'pw_fetch_states', lambda *a, **k: _pw_states())
    monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)


class TestPwMarkSelection:
    """Marking series with space/a/Esc tracks ids and renders a leading '*'."""

    @pytest.mark.asyncio
    async def test_space_marks_and_advances(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_series(monkeypatch, [_mk_series(1), _mk_series(2), _mk_series(3)])
        app = PwApp('k', 'https://pw.example.org', 'proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            lv = app.query_one('#pw-list', ListView)
            assert lv.index == 0

            await pilot.press('space')
            await pilot.pause()
            # First series marked and the cursor stepped to the second row.
            assert app._selected_ids == {1}
            assert lv.index == 1
            assert '1 selected' in _static_text(app.query_one('#pw-title'))

            await pilot.press('space')
            await pilot.pause()
            assert app._selected_ids == {1, 2}

            # Toggling a marked row clears just that mark.
            lv.index = 0
            app.action_toggle_mark()
            await pilot.pause()
            assert app._selected_ids == {2}

    @pytest.mark.asyncio
    async def test_marker_glyph_rendered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_series(monkeypatch, [_mk_series(1), _mk_series(2)])
        app = PwApp('k', 'https://pw.example.org', 'proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            item = app._get_highlighted_item()
            assert item is not None
            assert not _static_text(item.query_one(Label)).startswith('*')
            app.action_toggle_mark()
            await pilot.pause()
            assert _static_text(item.query_one(Label)).startswith('*')

    @pytest.mark.asyncio
    async def test_mark_all_then_unmark_all(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_series(monkeypatch, [_mk_series(1), _mk_series(2), _mk_series(3)])
        app = PwApp('k', 'https://pw.example.org', 'proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            app.action_mark_all()
            await pilot.pause()
            assert app._selected_ids == {1, 2, 3}
            # A second mark-all, with everything already marked, clears them.
            app.action_mark_all()
            await pilot.pause()
            assert app._selected_ids == set()

    @pytest.mark.asyncio
    async def test_escape_clears_marks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_series(monkeypatch, [_mk_series(1), _mk_series(2)])
        app = PwApp('k', 'https://pw.example.org', 'proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            app.action_mark_all()
            await pilot.pause()
            assert app._selected_ids == {1, 2}
            await pilot.press('escape')
            await pilot.pause()
            assert app._selected_ids == set()
            assert all(not it.selected for it in app._visible_items())

    @pytest.mark.asyncio
    async def test_marks_pruned_on_refetch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A re-fetch keeps marks for surviving series and drops vanished ones."""
        _install_series(monkeypatch, [_mk_series(1), _mk_series(2), _mk_series(3)])
        app = PwApp('k', 'https://pw.example.org', 'proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            app.action_mark_all()
            await pilot.pause()
            assert app._selected_ids == {1, 2, 3}
            # Series 3 is gone on the next fetch.
            monkeypatch.setattr(
                b4.review,
                'pw_fetch_series',
                lambda *a, **k: PwFetchResult([_mk_series(1), _mk_series(2)], 2, None),
            )
            await app.action_refresh()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app._selected_ids == {1, 2}


class TestPwBulkSetState:
    """`s` applies the chosen state to every marked series, else the current."""

    @pytest.mark.asyncio
    async def test_set_state_applies_to_all_marked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _FakePwSession()
        monkeypatch.setattr(
            b4, 'get_patchwork_session', lambda key, url: (fake, 'https://pw/api')
        )
        _install_series(monkeypatch, [_mk_series(1), _mk_series(2), _mk_series(3)])
        app = PwApp('k', 'https://pw.example.org', 'proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            # Mark the first two series (each toggle advances the cursor).
            app.action_toggle_mark()
            await pilot.pause()
            app.action_toggle_mark()
            await pilot.pause()
            assert app._selected_ids == {1, 2}

            app.action_set_state()
            await pilot.pause()
            assert isinstance(app.screen, SetStateScreen)
            await app.screen.dismiss(('reviewing', False))
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            by_id = {s['id']: s for s in app._all_series}
            assert by_id[1]['state'] == 'reviewing'
            assert by_id[2]['state'] == 'reviewing'
            # The unmarked third series is untouched.
            assert by_id[3]['state'] == 'new'
            # One PATCH per patch across the two marked series.
            assert len(fake.patched) == 4
            # Marks are consumed once applied.
            assert app._selected_ids == set()

    @pytest.mark.asyncio
    async def test_set_state_falls_back_to_highlighted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _FakePwSession()
        monkeypatch.setattr(
            b4, 'get_patchwork_session', lambda key, url: (fake, 'https://pw/api')
        )
        _install_series(monkeypatch, [_mk_series(1), _mk_series(2)])
        app = PwApp('k', 'https://pw.example.org', 'proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            # No marks: act on the highlighted (second) row only.
            app.query_one('#pw-list', ListView).index = 1
            app.action_set_state()
            await pilot.pause()
            await app.screen.dismiss(('accepted', False))
            await pilot.pause()
            await app.workers.wait_for_complete()
            await pilot.pause()

            by_id = {s['id']: s for s in app._all_series}
            assert by_id[1]['state'] == 'new'
            assert by_id[2]['state'] == 'accepted'
            assert len(fake.patched) == 2

    @pytest.mark.asyncio
    async def test_set_state_needs_states_loaded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_series(monkeypatch, [_mk_series(1)])
        app = PwApp('k', 'https://pw.example.org', 'proj')
        async with app.run_test(size=(120, 30)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            # States never arrived: the action warns and opens nothing.
            app._states = []
            app.action_set_state()
            await pilot.pause()
            assert not isinstance(app.screen, SetStateScreen)
