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
from contextlib import contextmanager
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    List,
    Mapping,
    Optional,
    Protocol,
    TypeVar,
)

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.css.query import NoMatches
from textual.dom import DOMNode
from textual.widgets import Footer, ListItem, ListView
from textual.widgets._footer import FooterKey
from textual.worker import NoActiveWorker, Worker, get_current_worker

import b4

# _suspend_to_shell now lives in b4 itself (textual-free, so the non-TUI shazam
# conflict flow can reuse it). Re-export it so this stays the import home for the
# TUI callers (and b4.review_tui._common's re-export of it).
from b4 import _suspend_to_shell as _suspend_to_shell

logger = b4.logger

# Bare 'q' shares the key namespace with the heavily used navigation keys
# (j/k/n/p/h/l, space), so a single stray keypress used to quit an app
# outright. All b4 TUI apps quit on capital 'Q' instead; bare 'q' lands on
# quit_hint, which shows a warning pointing at 'Q'.
QUIT_BINDINGS: List[Binding] = [
    Binding('Q', 'quit', 'quit', key_display='Q'),
    Binding('q', 'quit_hint', 'quit', show=False),
]


def notify_quit_hint(app: 'App[Any]') -> None:
    """Tell the user that quitting takes a capital Q."""
    app.notify("Press 'Q' (capital) to quit", severity='warning')


def suspend_and_edit(
    app: 'App[Any]',
    bdata: bytes,
    filehint: str,
    *,
    topdir: Optional[str] = None,
) -> Optional[bytes]:
    """Drop out of the TUI and run the user's editor on *bdata*.

    Returns what they saved, or ``None`` if the editor could not be run --
    it has already been reported through a notification by then.  Letting
    that escape instead would unwind out of the key handler and tear the app
    down, taking every other unsaved change in the session with it, over an
    editor that would not start.

    *topdir* is the working tree the edit belongs to; pass the one the app
    operates on, since it need not be the tree b4 was started in.
    """
    try:
        with app.suspend():
            return b4.edit_in_editor(bdata, filehint=filehint, topdir=topdir)
    except Exception as ex:
        logger.debug('Editor failed: %s', ex, exc_info=True)
        app.notify(f'Editor error: {ex}', severity='error')
        return None


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


_WorkerResult = TypeVar('_WorkerResult')


class _WorkerHost(Protocol):
    """Anything (App or Screen) able to launch a Textual worker."""

    def run_worker(
        self,
        work: Callable[[], _WorkerResult],
        name: Optional[str] = ...,
        group: str = ...,
        description: str = ...,
        exit_on_error: bool = ...,
        start: bool = ...,
        exclusive: bool = ...,
        thread: bool = ...,
    ) -> Worker[_WorkerResult]: ...


@contextmanager
def lore_request() -> Generator[None, None, None]:
    """Clear the shared lore node's sticky cancel flag before a fetch.

    ``b4.get_lore_node()`` returns a process-wide singleton whose cancel
    flag is *sticky*: once ``.cancel()`` runs -- ``UpdateAllSeriesScreen``
    Esc, app shutdown via :class:`LoreNodeShutdownMixin`, a sibling app
    switching away, or SIGINT -- every subsequent request raises
    ``OperationCancelledError`` until ``.reset_cancel()`` is called.

    Wrap any lore fetch in this context manager.  It is the one sanctioned
    way to begin a fetch, so a new fetch site cannot inherit a stale cancel
    left behind by a prior aborted operation.  Use it directly around a
    synchronous fetch, or via :func:`run_lore_worker` for a threaded one.
    """
    b4.get_lore_node().reset_cancel()
    yield


def run_lore_worker(
    host: _WorkerHost,
    work: Callable[[], _WorkerResult],
    *,
    name: str,
    exit_on_error: bool = False,
    **kwargs: Any,
) -> Worker[_WorkerResult]:
    """Reset the sticky cancel flag, then launch a threaded lore fetch.

    The single sanctioned way to start a lore fetch in a worker thread.  It
    bundles the three things every such fetch needs, so a new site cannot
    forget any of them:

    * clears the sticky cancel flag (via :func:`lore_request`) on the
      *calling* thread, before the worker starts -- preserving the existing
      ordering, since resetting inside the worker could race with
      :meth:`LoreNodeShutdownMixin.on_unmount` cancelling the node on
      shutdown and re-enable a fetch the app is trying to abort;
    * runs the work in a thread (``thread=True``);
    * keeps a fetch failure from tearing down the whole TUI via
      ``WorkerFailed`` (``exit_on_error=False``), so it surfaces through the
      host's ``on_worker_state_changed`` handler instead.
    """
    with lore_request():
        return host.run_worker(
            work, name=name, thread=True, exit_on_error=exit_on_error, **kwargs
        )


class LoreNodeShutdownMixin:
    """App mixin that cancels in-flight lore fetches on shutdown.

    A worker blocked inside a single liblore network fetch cannot be
    stopped by polling :func:`worker_cancelled` -- there is no loop to
    poll, just one long-running request.  When the app quits, Textual
    flips the worker's cancellation flag but the fetch keeps blocking, so
    the interpreter stalls at shutdown joining the worker thread until the
    request returns on its own.

    Textual dispatches an ``Unmount`` event to the app itself during
    shutdown (on every exit path: ``q``, Ctrl-C, programmatic exit, or an
    error), and that runs on the main thread while the worker is still
    parked in its fetch.  Cancelling the shared lore node here makes the
    in-flight request raise ``OperationCancelledError`` promptly, so the
    worker unwinds and the app exits without waiting on the network.

    This complements :func:`worker_cancelled`, which already covers the
    workers that loop over many smaller fetches.
    """

    def on_unmount(self) -> None:
        # Textual's internal teardown uses _on_unmount(), so overriding the
        # public on_unmount() hook does not skip any framework cleanup.
        try:
            b4.get_lore_node().cancel()
        except Exception:
            logger.debug('lore node cancel on shutdown failed', exc_info=True)


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


def limit_substring_matcher(*fields: str) -> Callable[[Dict[str, Any], str], bool]:
    """Return a limit-token matcher over dict *fields*.

    The returned matcher reports whether the needle is a case-insensitive
    substring of any of the named fields (missing or None fields count as
    empty).  For use with :func:`matches_limit`.
    """

    def _match(item: Dict[str, Any], needle: str) -> bool:
        return any(needle in (item.get(f, '') or '').lower() for f in fields)

    return _match


def matches_limit(
    item: Any,
    pattern: str,
    prefixed: Mapping[str, Callable[[Any, str], bool]],
    bare: Callable[[Any, str], bool],
) -> bool:
    """Test whether *item* matches the limit *pattern*.

    The pattern is lowercased and split on whitespace; every token must
    match (AND logic).  A token starting with a key of *prefixed* is
    handled by that key's matcher, called with the token minus the
    prefix; any other token is handled by the *bare* matcher.  Each app
    supplies its own field semantics through the matchers.
    """
    for token in pattern.lower().split():
        for prefix, matcher in prefixed.items():
            if token.startswith(prefix):
                if not matcher(item, token[len(prefix) :]):
                    return False
                break
        else:
            if not bare(item, token):
                return False
    return True


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


class ReplacementListView(ListView):
    """A ListView that replaces a predecessor without moving the viewport.

    The tracker-style screens rebuild their ListView wholesale on every
    refresh, so the scroll position dies with the old widget.  Restoring
    the cursor index alone only scrolls the minimum needed to reveal
    that row, which made the viewport visibly jump towards the top on
    every refresh.  Capture the predecessor's offset with
    :meth:`capture_scroll` before removing it, pass it as *scroll_y*,
    and the replacement seeds its scroll state on mount, before the
    first paint.

    There is deliberately no ``initial_index``: ListView's default of 0
    schedules a scroll-into-view for row 0 on mount, which would fire
    after the restore and undo it.  Assign ``index`` explicitly after
    mounting instead — that schedules a minimal scroll-into-view which
    is a no-op when the restored offset already shows the row, and
    otherwise keeps the cursor visible (e.g. after a re-sort moved it).
    """

    def __init__(
        self, *children: ListItem, scroll_y: float = 0.0, id: Optional[str] = None
    ) -> None:
        super().__init__(*children, initial_index=None, id=id)
        self._replaced_scroll_y = scroll_y

    @staticmethod
    def capture_scroll(node: DOMNode, selector: str) -> float:
        """Return the scroll offset of *selector*'s ListView, or 0.0."""
        try:
            return node.query_one(selector, ListView).scroll_y
        except NoMatches:
            return 0.0

    def on_mount(self) -> None:
        if not self._replaced_scroll_y:
            return
        # scroll_to() cannot seed the position here: layout hasn't run
        # yet, so it would clamp against a zero virtual size.  The first
        # reflow re-validates these values against the real size, which
        # clamps them if the new list is shorter.  scroll_target_y feeds
        # wheel/page scrolling, and nothing syncs the scrollbar thumb
        # when that re-validation is a no-op, so seed both as well.
        self.set_scroll(None, self._replaced_scroll_y)
        self.set_reactive(
            ListView.scroll_target_y,  # pyright: ignore[reportArgumentType] # cannot pick Reactive's class-access __get__ overload
            float(round(self._replaced_scroll_y)),
        )
        self.vertical_scrollbar.position = round(self._replaced_scroll_y)


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
