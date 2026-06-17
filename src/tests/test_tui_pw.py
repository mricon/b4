#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Integration tests for the PwApp (Patchwork) TUI.

Uses real SQLite databases (via b4.review.tracking) but no network access:
the Patchwork REST calls and lore retrieval are mocked.
"""

import contextlib
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

        # suspend() drops to the console for logging output; there is no real
        # terminal under the headless test driver, so make it a no-op.
        monkeypatch.setattr(
            PwApp, 'suspend', lambda self: contextlib.nullcontext(), raising=False
        )

        app = PwApp('fakekey', 'https://pw.example.org', identifier)
        assert app._tracking_enabled is True

        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # The series list is populated and the first item highlighted.
            item = app._get_highlighted_item()
            assert item is not None
            assert item.series['id'] == 42

            app.action_track_series()
            await pilot.pause()

            # The stale flag was cleared before the fetch, so the retrieve
            # succeeded and the series is now tracked both in memory and in the
            # database.  (Asserted inside the context: on_unmount cancels the
            # node again on app shutdown.)
            assert node.cancelled is False
            assert 42 in app._tracked_ids
            assert 42 in tracking.get_tracked_pw_series_ids(identifier)
