# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Helpers for the Textual-based suites.

This module deliberately does not import textual itself, so it is safe
to import before the ``pytest.importorskip('textual')`` guard.
"""

from typing import Any


def static_text(widget: Any) -> str:
    """Return the text of a Static widget across Textual versions.

    Textual >= 1.0 exposes ``Static.content``; older builds (such as the
    Fedora 43 package) still use ``Static.renderable``.
    """
    if hasattr(widget, 'content'):
        return str(widget.content)
    return str(widget.renderable)


def current_screen(app: Any) -> Any:
    """Return the app's active screen, read fresh.

    After ``assert isinstance(app.screen, X)`` mypy narrows ``app.screen``
    for the rest of the test and does not know that a key press can swap
    the screen. A later ``assert not isinstance(app.screen, X)`` then makes
    every following line "unreachable". Reading the screen through a
    function call avoids that narrowing.
    """
    return app.screen


async def settle_tracking_app(app: Any, pilot: Any) -> None:
    """Wait for TrackingApp to finish its startup work.

    on_mount() starts a ``_startup_rescan`` worker thread. When that worker
    finds a changed branch, it replaces ``#tracking-list`` with a rebuilt
    one. A plain ``pilot.pause()`` decides the app is idle by watching CPU
    time, and a thread blocked on ``git`` uses none, so the test can see
    the old list or no list at all. This waits for the worker itself.
    """
    await app.workers.wait_for_complete()
    # The first pause runs the worker's StateChanged handler. That handler
    # only queues _refresh_list with call_later(), so the second pause is
    # what makes sure the rebuild has run, without relying on the idle
    # heuristic.
    await pilot.pause()
    await pilot.pause()


# A reply buffer exercising every trim rule the send paths share: the
# instruction header is dropped, everything quoted above the >--cut--
# marker collapses into a "lines skipped" note, and a trailing quoted run
# after the reply text is removed.
CUT_INSTRUCTION = '# Put ">--cut--" alone on a line to trim quoted context.\n'
CUT_BUFFER = (
    'On today, Reviewer wrote:\n'
    '> old context one\n'
    '> old context two\n'
    '>--cut--\n'
    '> context kept below the marker\n'
    'My reply.\n'
    '> trailing untouched quote\n'
)
CUT_TRIMMED = (
    'On today, Reviewer wrote:\n'
    '> [ ... 2 lines skipped ... ]\n'
    '> context kept below the marker\n'
    'My reply.'
)
