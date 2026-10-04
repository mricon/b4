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
