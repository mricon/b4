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

import b4
import b4.review
import b4.review.tracking as tracking
import liblore
from b4.review_tui._pw_app import PwApp

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
        monkeypatch.setattr(b4.review, 'pw_fetch_series', lambda *a, **k: [series])
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
        monkeypatch.setattr(b4.review, 'pw_fetch_series', lambda *a, **k: [series])
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
        monkeypatch.setattr(b4.review, 'pw_fetch_series', lambda *a, **k: [series])
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
