#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Unit tests for the lore-fetch chokepoint helper.

``run_lore_worker()`` is the single sanctioned way to begin a threaded lore
fetch: it bundles ``thread=True`` with ``exit_on_error=False`` so a new fetch
site cannot block the UI thread or tear down the whole TUI on a fetch
failure.  Because every threaded fetch site routes through it, proving it
launches with crash-safe options structurally covers all of them.

(Cancellation hygiene needs no chokepoint anymore: liblore 0.9 scopes
cancellation to the operations in flight, so a fetch cannot inherit a stale
cancel from a previously aborted one.)
"""

from typing import Any, Callable, Dict, List, Optional, cast

import pytest

pytest.importorskip('textual')

from b4.tui._common import run_lore_worker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
# run_lore_worker()
# ---------------------------------------------------------------------------


class TestRunLoreWorker:
    def test_uses_crash_safe_defaults(self) -> None:
        host = _RecordingHost()

        def _work() -> str:
            return 'done'

        handle = run_lore_worker(host, _work, name='_my_worker')

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

    def test_exit_on_error_override_is_honored(self) -> None:
        host = _RecordingHost()

        run_lore_worker(host, lambda: None, name='_w', exit_on_error=True)

        assert host.calls[0]['exit_on_error'] is True

    def test_extra_kwargs_pass_through(self) -> None:
        host = _RecordingHost()

        run_lore_worker(host, lambda: None, name='_w', exclusive=True)

        assert host.calls[0]['exclusive'] is True
