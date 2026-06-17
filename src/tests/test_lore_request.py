#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Unit tests for the lore-fetch chokepoint helpers.

``lore_request()`` and ``run_lore_worker()`` are the single sanctioned ways
to begin a lore fetch: they clear the shared node's sticky cancel flag so a
fetch can't inherit a stale cancel left by a prior aborted operation or a
sibling app's shutdown.  Because every threaded fetch site now routes through
``run_lore_worker()``, proving it resets the flag and launches with
crash-safe options structurally covers all of them.
"""

from typing import Any, Callable, Dict, List, Optional, cast

import pytest

import b4
import liblore
from b4.review_tui._common import lore_request, run_lore_worker

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

    def fetch(self) -> str:
        """A fetch that honours the sticky flag exactly like liblore does."""
        if self.cancelled:
            raise liblore.OperationCancelledError('Request cancelled')
        return 'ok'


class _RecordingHost:
    """A worker host that records run_worker() arguments instead of running.

    The signature mirrors the _WorkerHost protocol exactly so this conforms
    structurally; the Any return avoids constructing a real Textual worker.
    """

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    def run_worker(
        self,
        work: Callable[[], Any],
        name: Optional[str] = None,
        group: str = 'default',
        description: str = '',
        exit_on_error: bool = True,
        start: bool = True,
        exclusive: bool = False,
        thread: bool = False,
    ) -> Any:
        self.calls.append(
            {
                'work': work,
                'name': name,
                'group': group,
                'description': description,
                'exit_on_error': exit_on_error,
                'start': start,
                'exclusive': exclusive,
                'thread': thread,
            }
        )
        return 'worker-handle'


# ---------------------------------------------------------------------------
# lore_request()
# ---------------------------------------------------------------------------


class TestLoreRequest:
    def test_clears_stale_cancel_flag_on_enter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A prior cancel must not leak into the next fetch."""
        node = _FakeLoreNode(cancelled=True)
        monkeypatch.setattr(b4, 'get_lore_node', lambda: node)

        with lore_request():
            # The flag is cleared before the body runs, so the fetch succeeds
            # rather than raising the sticky "Request cancelled".
            assert node.cancelled is False
            assert node.fetch() == 'ok'

    def test_resets_before_body_even_if_body_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The reset happens on enter, so an exception in the body is fine."""
        node = _FakeLoreNode(cancelled=True)
        monkeypatch.setattr(b4, 'get_lore_node', lambda: node)

        with pytest.raises(ValueError):
            with lore_request():
                assert node.cancelled is False
                raise ValueError('boom')

    def test_reproduces_stale_flag_bug_without_the_reset(self) -> None:
        """Sanity check: a fetch on a cancelled node aborts immediately.

        This is the failure the chokepoint prevents -- without the reset,
        a stale flag makes every request raise "Request cancelled".
        """
        node = _FakeLoreNode(cancelled=True)
        with pytest.raises(liblore.OperationCancelledError):
            node.fetch()


# ---------------------------------------------------------------------------
# run_lore_worker()
# ---------------------------------------------------------------------------


class TestRunLoreWorker:
    def test_resets_flag_and_uses_crash_safe_defaults(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        node = _FakeLoreNode(cancelled=True)
        monkeypatch.setattr(b4, 'get_lore_node', lambda: node)
        host = _RecordingHost()

        def _work() -> str:
            return 'done'

        handle = run_lore_worker(host, _work, name='_my_worker')

        # The stale flag was cleared before the worker launched.
        assert node.cancelled is False
        # The handle from run_worker() is passed straight back to the caller.
        # (cast: the static return type is Worker[...], but our fake returns a
        # sentinel string so we can assert the value is threaded through.)
        assert cast(Any, handle) == 'worker-handle'
        assert len(host.calls) == 1
        call = host.calls[0]
        assert call['work'] is _work
        assert call['name'] == '_my_worker'
        # thread=True so the blocking fetch runs off the UI thread; and
        # exit_on_error=False so a fetch failure surfaces through the host's
        # on_worker_state_changed handler instead of crashing the whole TUI.
        assert call['thread'] is True
        assert call['exit_on_error'] is False

    def test_exit_on_error_override_is_honored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        node = _FakeLoreNode()
        monkeypatch.setattr(b4, 'get_lore_node', lambda: node)
        host = _RecordingHost()

        run_lore_worker(host, lambda: None, name='_w', exit_on_error=True)

        assert host.calls[0]['exit_on_error'] is True

    def test_extra_kwargs_pass_through(self, monkeypatch: pytest.MonkeyPatch) -> None:
        node = _FakeLoreNode()
        monkeypatch.setattr(b4, 'get_lore_node', lambda: node)
        host = _RecordingHost()

        run_lore_worker(host, lambda: None, name='_w', exclusive=True)

        assert host.calls[0]['exclusive'] is True
