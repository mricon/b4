#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Shared TUI utilities for b4 Textual apps."""

__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import email.utils
import unicodedata
from collections import defaultdict
from typing import Any, Dict, List, Optional, Protocol

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, ListView
from textual.widgets._footer import FooterKey
from textual.worker import NoActiveWorker, get_current_worker

import b4

# _suspend_to_shell now lives in b4 itself (textual-free, so the non-TUI shazam
# conflict flow can reuse it). Re-export it so this stays the import home for the
# TUI callers (and b4.review_tui._common's re-export of it).
from b4 import _suspend_to_shell as _suspend_to_shell

logger = b4.logger


def worker_cancelled() -> bool:
    """Return ``True`` if the active Textual thread worker was cancelled.

    Thread workers cannot be force-stopped: Textual sets a flag and the
    thread keeps running until it returns on its own.  For a worker that
    walks a long list (patches, series, follow-up threads) -- each step a
    slow git or network call -- poll this at the top of every iteration and
    break out when it returns ``True``.  That turns "run all remaining
    items to completion" into "finish the one in flight, then stop".

    The flag is raised both when the user cancels (``Worker.cancel()``, e.g.
    an Esc/q binding) and when the app quits, since Textual calls
    ``workers.cancel_all()`` during shutdown.  So polling this keeps the app
    from blocking on a half-finished background job on exit.

    Safe to call from anywhere: outside a worker thread there is no active
    worker, and this returns ``False`` rather than raising, so helpers that
    are shared with the synchronous CLI keep working unchanged.
    """
    try:
        return get_current_worker().is_cancelled
    except NoActiveWorker:
        return False


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
        return ''.join(truncated) + '\u2026' + ' ' * (width - tw - 1)
    if dw < width:
        return s + ' ' * (width - dw)
    return s


def _fix_ansi_theme(app: Any) -> None:
    """Work around Textual theme-watcher bug.

    The ``theme`` reactive in Textual's ``App`` uses ``init=False``,
    so ``_watch_theme()`` never fires for the initial theme set via
    ``TEXTUAL_THEME`` env-var.  This leaves ``ansi_color`` as False
    and all ``:ansi`` CSS pseudo-class overrides dead.  Call this
    from ``on_mount()`` to force the watcher when needed.
    """
    if app.current_theme.name == 'textual-ansi' and not app.ansi_color:
        app._watch_theme(app.theme)


def _to_rich_color(textual_color: str) -> str:
    """Convert a Textual CSS colour value to a Rich-compatible name.

    Textual uses ``ansi_green``, ``ansi_bright_blue``, etc. in its CSS
    variable system.  Rich expects ``green``, ``bright_blue``, etc.
    Non-ansi values (hex codes, named CSS colours) pass through unchanged.
    ``ansi_default`` maps to ``default``.
    """
    if textual_color.startswith('ansi_'):
        return textual_color[5:]  # strip 'ansi_' prefix
    return textual_color


def resolve_styles(app: Any) -> Dict[str, str]:
    """Resolve Textual CSS variables into Rich-compatible colour strings.

    Call this once per render cycle and pass the resulting dict to
    helper functions like ``ci_styles()`` and ``reviewer_colours()``.

    The dict maps semantic names to colour strings that Rich ``Text``
    objects can use directly in *style* parameters.
    """
    v = app.get_css_variables()
    return {
        'success': _to_rich_color(v.get('success', 'green')),
        'error': _to_rich_color(v.get('error', 'red')),
        'warning': _to_rich_color(v.get('warning', 'dark_orange')),
        'accent': _to_rich_color(v.get('accent', 'cyan')),
        'secondary': _to_rich_color(v.get('secondary-lighten-3', 'magenta')),
        'foreground': _to_rich_color(v.get('foreground', 'bright_white')),
        'panel': _to_rich_color(v.get('panel', 'grey11')),
        'surface': _to_rich_color(v.get('surface', '#1e1e1e')),
        'primary': _to_rich_color(v.get('primary', 'dark_blue')),
        'text-muted': _to_rich_color(v.get('text-muted', 'grey70')),
        'syntax_theme': 'ansi_dark' if app.current_theme.dark else 'ansi_light',
    }


def ci_styles(ts: Dict[str, str]) -> Dict[str, str]:
    """Return CI indicator styles from a resolved theme dict."""
    return {
        'pending': 'dim',
        'success': ts['success'],
        'warning': ts['warning'],
        'fail': f'bold {ts["error"]}',
    }


def ci_markup(ts: Dict[str, str]) -> Dict[str, str]:
    """Return CI dot markup strings from a resolved theme dict."""
    return {
        state: f'[{style}]\u25cf[/{style}]' for state, style in ci_styles(ts).items()
    }


def ci_check_styles(ts: Dict[str, str]) -> Dict[str, str]:
    """Return CI check detail styles from a resolved theme dict."""
    return {
        'pending': 'dim',
        'success': ts['success'],
        'warning': ts['warning'],
        'fail': f'bold {ts["error"]}',
    }


def reviewer_colours(ts: Dict[str, str]) -> List[str]:
    """Return the reviewer colour palette from a resolved theme dict.

    Index 0 is always the current user; the rest cycle for others.
    """
    return [
        ts['warning'],  # index 0: current user (warm/distinct)
        ts['accent'],
        ts['secondary'],
        ts['error'],
        ts['primary'],
    ]


class _quiet_worker:
    """Context manager that silences b4 logger output from the current thread.

    Worker threads in Textual run while the TUI owns the terminal, so any
    logger output would overwrite the screen.  This installs a thread-aware
    filter on the b4 logger's handlers for the duration of the block.
    """

    def __enter__(self) -> '_quiet_worker':
        import logging
        import threading

        tid = threading.current_thread().ident

        class _Filter(logging.Filter):
            def filter(self, record: logging.LogRecord) -> bool:
                return record.thread != tid

        self._filt = _Filter()
        self._logger = logging.getLogger('b4')
        for h in self._logger.handlers:
            h.addFilter(self._filt)
        return self

    def __exit__(self, *exc: object) -> None:
        for h in self._logger.handlers:
            h.removeFilter(self._filt)


def _wait_for_enter() -> None:
    try:
        input('Press Enter to continue...')
    except (KeyboardInterrupt, EOFError):
        pass


def _addrs_to_lines(header_str: str) -> str:
    """Parse a comma-separated address header into one-per-line display."""
    if not header_str:
        return ''
    pairs = email.utils.getaddresses([header_str])
    lines = []
    for name, addr in pairs:
        if not addr:
            continue
        if name and name != addr:
            lines.append(f'{name} <{addr}>')
        else:
            lines.append(addr)
    return '\n'.join(lines)


def _lines_to_header(text: str) -> str:
    """Parse one-per-line addresses back to a comma-separated header string."""
    text = text.strip()
    if not text:
        return ''
    # getaddresses expects a list of header strings; join lines with commas
    pairs = email.utils.getaddresses(text.splitlines())
    pairs = [(n, a) for n, a in pairs if a]
    return b4.format_addrs(pairs, clean=False)


def _validate_addrs(text: str) -> Optional[str]:
    """Return an error message if any line has an invalid address, or None."""
    text = text.strip()
    if not text:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        pairs = email.utils.getaddresses([line])
        if not pairs:
            return f'Cannot parse: {line}'
        for _name, addr in pairs:
            if not addr or '@' not in addr:
                return f'Invalid address: {line}'
    return None


class _ListViewHost(Protocol):
    _list_id: str

    def query_one(self, selector: str, expect_type: type[ListView]) -> ListView: ...


class JKListNavMixin:
    """Mixin providing j/k cursor navigation for a named ListView.

    Classes using this mixin must set ``_list_id`` to the DOM id of the
    target :class:`ListView` (e.g. ``'#action-list'``).
    """

    def action_cursor_down(self: _ListViewHost) -> None:
        lv = self.query_one(self._list_id, ListView)
        if lv.index is not None and lv.index < len(lv.children) - 1:
            lv.index += 1

    def action_cursor_up(self: _ListViewHost) -> None:
        lv = self.query_one(self._list_id, ListView)
        if lv.index is not None and lv.index > 0:
            lv.index -= 1


_SENTINEL = object()


class SeparatedFooter(Footer):
    """Footer that shows full descriptions and a vertical separator between groups."""

    DEFAULT_CSS = """
    SeparatedFooter FooterKey.-group-first {
        border-left: vkey $foreground 20%;
    }
    SeparatedFooter:ansi {
        background: ansi_bright_black;
        .footer-key--key {
            background: ansi_bright_black;
        }
        .footer-key--description {
            background: ansi_bright_black;
        }
    }
    SeparatedFooter:ansi FooterKey.-group-first {
        border-left: vkey ansi_default;
    }
    """

    def compose(self) -> ComposeResult:
        if not self._bindings_ready:
            return
        active_bindings = self.screen.active_bindings
        bindings = [
            (binding, enabled, tooltip)
            for (_, binding, enabled, tooltip) in active_bindings.values()
            if binding.show
        ]
        action_to_bindings: defaultdict[str, list[tuple[Binding, bool, str]]]
        action_to_bindings = defaultdict(list)
        for binding, enabled, tooltip in bindings:
            action_to_bindings[binding.action].append((binding, enabled, tooltip))

        self.styles.grid_size_columns = len(action_to_bindings)

        group_map = getattr(self.app, 'BINDING_GROUPS', {})
        prev_group: object = _SENTINEL
        for multi_bindings_list in action_to_bindings.values():
            binding, enabled, tooltip = multi_bindings_list[0]
            cur_group = group_map.get(binding.action)
            is_first = prev_group is not _SENTINEL and cur_group != prev_group
            prev_group = cur_group
            classes = '-group-first' if is_first else ''
            yield FooterKey(
                binding.key,
                self.app.get_key_display(binding),
                binding.description,
                binding.action,
                disabled=not enabled,
                tooltip=tooltip,
                classes=classes,
            ).data_bind(compact=Footer.compact)

        if self.show_command_palette and self.app.ENABLE_COMMAND_PALETTE:
            try:
                _node, binding, enabled, tooltip = active_bindings[
                    self.app.COMMAND_PALETTE_BINDING
                ]
            except KeyError:
                pass
            else:
                yield FooterKey(
                    binding.key,
                    self.app.get_key_display(binding),
                    binding.description,
                    binding.action,
                    classes='-command-palette',
                    disabled=not enabled,
                    tooltip=binding.tooltip or binding.description,
                )
