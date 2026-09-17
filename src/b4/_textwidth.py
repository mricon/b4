#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Terminal column arithmetic for aligned text output.

Kept free of any optional dependency so that plain CLI commands can
align their columns too -- the TUI modules re-export these, but a
listing printed by ``b4 review list`` must not need ``textual``
installed to line its columns up.
"""

__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import unicodedata
from typing import List


def display_width(s: str) -> int:
    """Return the terminal display width of *s*, accounting for full-width chars."""
    w = 0
    for ch in s:
        w += 2 if unicodedata.east_asian_width(ch) in ('F', 'W') else 1
    return w


def pad_display(s: str, width: int) -> str:
    """Pad or truncate *s* to *width* terminal columns, accounting for full-width chars."""
    dw = display_width(s)
    if dw > width:
        # Truncate with ellipsis
        truncated: List[str] = []
        tw = 0
        for ch in s:
            cw = 2 if unicodedata.east_asian_width(ch) in ('F', 'W') else 1
            if tw + cw > width - 1:
                break
            truncated.append(ch)
            tw += cw
        return ''.join(truncated) + '…' + ' ' * (width - tw - 1)
    if dw < width:
        return s + ' ' * (width - dw)
    return s
