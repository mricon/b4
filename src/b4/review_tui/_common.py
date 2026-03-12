#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import email.message
import email.parser
import email.policy
import email.utils
import json
import os
import subprocess
import tempfile
import unicodedata

from typing import Any, Dict, List, Optional, Set, Tuple

import b4
import b4.mbox
import b4.review
import b4.review.tracking

from collections import defaultdict

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, ListView, RichLog
from textual.widgets._footer import FooterKey
from rich import box
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

logger = b4.logger


# Per-patch state indicators — same glyphs as _tracking_app._STATUS_SYMBOLS
PATCH_STATE_MARKERS: Dict[str, str] = {
    '':      ' ',
    'draft': '\u270e',  # ✎ lower right pencil  (= reviewing)
    'done':  '\u2713',  # ✓ check mark           (= thanked)
    'skip':  '\u2715',  # ✕ multiplication x      (= gone)
}

# CI check label text (colour-free constant — used with ci_check_styles())
CI_CHECK_LABELS = {
    'pending': '\u25cf pending',
    'success': '\u25cf pass',
    'warning': '\u25cf warning',
    'fail': '\u25cf FAIL',
}


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
    helper functions like ``_write_diff_line()`` and ``ci_styles()``.

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
        'fail': f"bold {ts['error']}",
    }


def ci_markup(ts: Dict[str, str]) -> Dict[str, str]:
    """Return CI dot markup strings from a resolved theme dict."""
    return {
        state: f'[{style}]\u25cf[/{style}]'
        for state, style in ci_styles(ts).items()
    }


def ci_check_styles(ts: Dict[str, str]) -> Dict[str, str]:
    """Return CI check detail styles from a resolved theme dict."""
    return {
        'pending': 'dim',
        'success': ts['success'],
        'warning': ts['warning'],
        'fail': f"bold {ts['error']}",
    }


def reviewer_colours(ts: Dict[str, str]) -> List[str]:
    """Return the reviewer colour palette from a resolved theme dict.

    Index 0 is always the current user; the rest cycle for others.
    """
    return [
        ts['warning'],      # index 0: current user (warm/distinct)
        ts['success'],
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


class CheckRunnerMixin:
    """Mixin providing CI check execution for Textual App subclasses.

    Subclasses must implement :meth:`_get_check_context` to supply the
    message-id, subject, and change-id for the series to check.  All UI
    interaction (loading overlay, results modal) is handled here.
    """

    _check_loading: Optional[Any] = None

    # -- interface for subclasses ------------------------------------------

    def _get_check_context(self) -> Optional[Tuple[str, str, str]]:
        """Return ``(message_id, series_subject, change_id)`` or *None*.

        Return *None* when no series is selected or checks cannot run.
        """
        raise NotImplementedError

    # -- public action -----------------------------------------------------

    def action_check(self) -> None:
        """Run CI checks on the current series."""
        self._run_checks(force=False)

    # -- helpers -----------------------------------------------------------

    def _run_checks(self, force: bool = False) -> None:
        """Show loading overlay and launch the check worker thread."""
        ctx = self._get_check_context()
        if ctx is None:
            return
        message_id, series_subject, change_id = ctx
        if not message_id:
            self.notify('No message-id for this series', severity='error')  # type: ignore[attr-defined]
            return
        from b4.review_tui._modals import CheckLoadingScreen
        self._check_loading = CheckLoadingScreen()
        self.push_screen(self._check_loading)  # type: ignore[attr-defined]
        self.run_worker(  # type: ignore[attr-defined]
            lambda: self._fetch_and_check(message_id, series_subject,
                                          change_id=change_id, force=force),
            name='_check_worker', thread=True)

    def _dismiss_loading(self, msg: str = '', severity: str = '') -> None:
        """Dismiss the check loading screen and optionally notify."""
        def _do() -> None:
            if self._check_loading is not None and self._check_loading.is_attached:
                self._check_loading.dismiss(None)
            if msg:
                self.notify(msg, severity=severity)  # type: ignore[attr-defined]
        self.app.call_from_thread(_do)  # type: ignore[attr-defined]

    def _update_loading(self, text: str) -> None:
        """Update the loading screen status text."""
        def _do() -> None:
            if self._check_loading is not None and self._check_loading.is_attached:
                self._check_loading.update_status(text)
        self.app.call_from_thread(_do)  # type: ignore[attr-defined]

    def _fetch_and_check(self, message_id: str, series_subject: str,
                         change_id: str = '', force: bool = False) -> None:
        """Fetch thread, run checks, and push results modal (worker thread)."""
        import b4.review.checks as checks
        from b4.review_tui._modals import TrackingCheckResultsScreen

        perpatch_cmds, series_cmds = checks.load_check_cmds()
        if not perpatch_cmds and not series_cmds:
            self._dismiss_loading('No check commands configured', 'warning')
            return

        topdir = b4.git_get_toplevel()
        if not topdir:
            self._dismiss_loading('Not in a git repository', 'error')
            return

        # Patchwork config for _builtin_patchwork
        config = b4.get_main_config()
        pwkey = str(config.get('pw-key', ''))
        pwurl = str(config.get('pw-url', ''))

        # Dump tracking data to a temp file for external scripts
        extra_env: Dict[str, str] = {}
        tracking_file: Optional[str] = None
        if change_id:
            review_branch = f'b4/review/{change_id}'
            try:
                _cover, tracking = b4.review.load_tracking(topdir, review_branch)
                fd, tracking_file = tempfile.mkstemp(prefix='b4-tracking-', suffix='.json')
                with os.fdopen(fd, 'w') as fp:
                    json.dump(tracking, fp, indent=2)
                extra_env['B4_TRACKING_FILE'] = tracking_file
            except SystemExit:
                pass

        # Fetch the thread
        self._update_loading('Fetching thread\u2026')
        with _quiet_worker():
            msgs = b4.get_pi_thread_by_msgid(message_id, quiet=True)
        if not msgs:
            self._dismiss_loading('Could not fetch thread from lore', 'error')
            return

        # Separate patches from non-patches using LoreSubject
        cover_msg: Optional[Tuple[str, email.message.EmailMessage]] = None
        patches: List[Tuple[str, email.message.EmailMessage]] = []
        for msg in msgs:
            subject = msg.get('subject', '')
            if not subject:
                continue
            lsubj = b4.LoreSubject(subject)
            msgid = msg.get('message-id', '').strip('<> ')
            if not msgid:
                continue
            if lsubj.counter == 0 and lsubj.expected > 0:
                cover_msg = (msgid, msg)
            elif lsubj.patch and not lsubj.reply:
                patches.append((msgid, msg))

        if not patches and not cover_msg:
            self._dismiss_loading('No patches found in thread', 'error')
            return

        # Sort patches by counter
        patches.sort(key=lambda p: b4.LoreSubject(p[1].get('subject', '')).counter)

        # Open or create cache DB
        conn = checks.get_db()
        checks.cleanup_old(conn)

        expected = patches[0][1].get('subject', '') if patches else ''
        lsubj0 = b4.LoreSubject(expected)
        num_patches = lsubj0.expected if lsubj0.expected > 0 else len(patches)

        # Build patch labels and subjects
        patch_labels: List[str] = []
        patch_subjects: List[str] = []
        ordered_msgs: List[Tuple[str, email.message.EmailMessage]] = []
        if cover_msg:
            patch_labels.append(f'0/{num_patches}')
            patch_subjects.append(b4.LoreSubject(cover_msg[1].get('subject', '')).subject)
            ordered_msgs.append(cover_msg)
        for idx, (mid, msg) in enumerate(patches, 1):
            patch_labels.append(f'{idx}/{num_patches}')
            patch_subjects.append(b4.LoreSubject(msg.get('subject', '')).subject)
            ordered_msgs.append((mid, msg))

        # Check cache first (clear and skip when force-rerunning)
        all_msgids = [mid for mid, _ in ordered_msgs]
        cached: Dict[str, List[Dict[str, str]]] = {}
        if force:
            checks.delete_results(conn, all_msgids)
        else:
            cached = checks.get_cached_results(conn, all_msgids)

        all_tools: set[str] = set()
        matrix: Dict[Tuple[int, str], Dict[str, str]] = {}

        # Populate matrix from cache
        for pidx, (mid, _msg) in enumerate(ordered_msgs):
            for result in cached.get(mid, []):
                tool = result['tool']
                all_tools.add(tool)
                matrix[(pidx, tool)] = result

        # Collect new results for batch DB storage
        new_results: Dict[str, List[Dict[str, str]]] = {}

        # Determine which patches still need checking
        if perpatch_cmds:
            start_idx = 1 if cover_msg else 0
            unchecked: List[Tuple[int, str, email.message.EmailMessage]] = []
            for pidx_offset, (mid, _msg) in enumerate(ordered_msgs[start_idx:]):
                pidx = pidx_offset + start_idx
                if mid not in cached:
                    unchecked.append((pidx, mid, _msg))

            for pidx, mid, _msg in unchecked:
                label = patch_labels[pidx]
                self._update_loading(f'Running checks\u2026 {label}')
                single_results = checks.run_perpatch_checks(
                    [(mid, _msg)], perpatch_cmds, topdir, pwkey, pwurl,
                    extra_env=extra_env)
                for result in single_results.get(mid, []):
                    tool = result['tool']
                    all_tools.add(tool)
                    matrix[(pidx, tool)] = result
                    new_results.setdefault(mid, []).append(result)

        # Run per-series checks (only if not cached)
        if series_cmds:
            target = cover_msg if cover_msg else (ordered_msgs[0] if ordered_msgs else None)
            if target and target[0] not in cached:
                self._update_loading('Running series checks\u2026')
                series_results = checks.run_series_checks(
                    target, series_cmds, topdir, pwkey, pwurl,
                    extra_env=extra_env)
                cover_idx = 0
                for result in series_results:
                    tool = result['tool']
                    all_tools.add(tool)
                    matrix[(cover_idx, tool)] = result
                    new_results.setdefault(target[0], []).append(result)

        # Batch-store all new results
        for mid, results in new_results.items():
            checks.store_results(conn, mid, results)
        conn.close()

        # Clean up the tracking data temp file
        if tracking_file:
            try:
                os.unlink(tracking_file)
            except OSError:
                pass

        # Build title and swap loading screen for results
        title = f'CI Check Results: {series_subject}'
        tools_sorted = sorted(all_tools)

        def _on_result(result: Optional[str]) -> None:
            if result == 'rerun':
                self._run_checks(force=True)

        def _push_modal() -> None:
            if self._check_loading is not None and self._check_loading.is_attached:
                self._check_loading.dismiss(None)
            self.push_screen(TrackingCheckResultsScreen(  # type: ignore[attr-defined]
                title, patch_labels, patch_subjects, tools_sorted, matrix),
                callback=_on_result)

        self.app.call_from_thread(_push_modal)  # type: ignore[attr-defined]


def _wait_for_enter() -> None:
    try:
        input('Press Enter to continue...')
    except (KeyboardInterrupt, EOFError):
        pass


def _make_initials(name: str) -> str:
    """Derive initials from a maintainer name.

    - "Konstantin Ryabitsev" -> "KR"
    - "Foo Bar Barski"       -> "FBB"
    - "FooBarski"            -> "FB"  (CamelCase single word)
    - ""                     -> "?"
    """
    name = name.strip()
    if not name:
        return 'me'
    parts = name.split()
    if len(parts) > 1:
        return ''.join(p[0].upper() for p in parts if p)
    # Single word: extract uppercase letters for CamelCase
    uppers = [c for c in parts[0] if c.isupper()]
    if len(uppers) >= 2:
        return ''.join(uppers)
    # Fallback: first two characters
    return parts[0][:2].upper()


def _has_review_data(reviews: Dict[str, Dict[str, Any]]) -> bool:
    """Return True if any reviewer has trailers, reply, comments, or a note."""
    return any(
        r.get('trailers') or r.get('reply', '') or r.get('comments') or r.get('note', '')
        for r in reviews.values()
    )


def _strip_attribution(body: str) -> str:
    """Strip a leading attribution line if present.

    An attribution line is the first non-blank line (possibly wrapped
    across consecutive non-blank lines) that ends with ':' and is
    followed (after optional blank lines) by a quoted line ('> ').
    """
    lines = body.splitlines()
    # Find the first non-blank line
    first_idx = None
    for i, ln in enumerate(lines):
        if ln.strip():
            first_idx = i
            break
    if first_idx is None:
        return body
    # Walk consecutive non-blank lines looking for one ending with ':'
    attr_end = None
    for i in range(first_idx, len(lines)):
        if not lines[i].strip():
            break
        if lines[i].strip().endswith(':'):
            attr_end = i
            break
    if attr_end is None:
        return body
    # Check that the next non-blank line starts with '>'
    for ln in lines[attr_end + 1:]:
        if ln.strip():
            if ln.startswith('> ') or ln.strip() == '>':
                remaining = lines[attr_end + 1:]
                while remaining and (not remaining[0].strip() or remaining[0].strip() == '>'):
                    remaining.pop(0)
                return '\n'.join(remaining)
            break
    return body


def _write_followup_comments(
    viewer: 'RichLog',
    fc_list: List[Dict[str, Any]],
    comment_positions: List[int],
    fc_author_positions: Optional[Dict[str, int]] = None,
    header_position_map: Optional[Dict[int, Dict[str, Any]]] = None,
    ts: Optional[Dict[str, str]] = None,
) -> None:
    """Render follow-up comments at the bottom of the viewer.

    Each entry has 'body', 'fromname', 'fromemail', 'date', and optionally
    'depth' (0 = direct reply to patch, N = N hops through follow-up replies).
    Entries with depth > 0 are indented to visually show threading.
    If *fc_author_positions* is provided, it is populated with the
    first viewer line position for each unique fromemail.
    If *header_position_map* is provided, it is populated with
    {viewer_line: entry} for each panel header row, enabling click-to-reply.
    *ts* is a resolved theme styles dict from :func:`resolve_styles`.
    """
    if not fc_list:
        return
    rev_palette = reviewer_colours(ts) if ts else [
        'dark_goldenrod', 'dark_green', 'dark_cyan',
        'dark_magenta', 'dark_red', 'dark_blue',
    ]
    fc_emails = sorted({e['fromemail'] for e in fc_list})
    colour_map: Dict[str, str] = {}
    for ci, em in enumerate(fc_emails):
        colour_map[em] = rev_palette[1 + (ci % (len(rev_palette) - 1))]
    viewer.write(Text(''))
    viewer.write(Rule(title='follow-ups', style='dim'))
    viewer.write(Text(''))
    for e in sorted(fc_list, key=lambda x: x['date']):
        initials = _make_initials(e['fromname'])
        colour = colour_map.get(e['fromemail'], rev_palette[1])
        line_pos = len(viewer.lines)
        comment_positions.append(line_pos)
        if header_position_map is not None:
            header_position_map[line_pos] = e
        if fc_author_positions is not None and e['fromemail'] not in fc_author_positions:
            fc_author_positions[e['fromemail']] = line_pos
        body = _strip_attribution(e['body'])
        body_text = Text()
        body_text.append(f'From:  {e["fromname"]} <{e["fromemail"]}>\n', style='bold')
        body_text.append(f'Date:  {e["date"].strftime("%Y-%m-%d %H:%M %z")}\n', style='bold')
        if msgid := e.get('msgid', ''):
            body_text.append(f'Msgid: <{msgid}>\n', style='bold')
        body_text.append('\n')
        for line in body.splitlines():
            if line.startswith('>'):
                body_text.append(line, style='dim')
            else:
                body_text.append(line)
            body_text.append('\n')
        depth = e.get('depth', 0)
        title_text = Text()
        title_text.append(initials)
        title_text.append('  ↩', style='dim')
        panel = Panel(
            body_text,
            box=box.ROUNDED,
            border_style=colour,
            title=title_text,
            title_align='left',
            expand=True,
            padding=(0, 1),
        )
        if depth > 0:
            viewer.write(Padding(panel, pad=(0, 0, 0, depth * 2)))
        else:
            viewer.write(panel)


_FOLLOWUP_MAX_DEPTH = 5


def _get_followup_depth(
    in_reply_to: Optional[str],
    patch_msgids: Dict[str, int],
    msgid_map: Dict[str, 'b4.LoreMessage'],
) -> int:
    """Return the threading depth of a follow-up relative to its patch.

    Depth 0 = direct reply to a patch; depth N = N hops through follow-up
    replies. Capped at _FOLLOWUP_MAX_DEPTH to prevent runaway indentation.
    """
    depth = 0
    seen: Set[str] = set()
    current = in_reply_to
    while current and current not in seen:
        if current in patch_msgids:
            break
        seen.add(current)
        lmsg = msgid_map.get(current)
        if lmsg is None:
            break
        depth += 1
        current = lmsg.in_reply_to
    return min(depth, _FOLLOWUP_MAX_DEPTH)


def _resolve_patch_for_followup(
    in_reply_to: Optional[str],
    patch_msgids: Dict[str, int],
    msgid_map: Dict[str, 'b4.LoreMessage'],
) -> Optional[int]:
    """Walk the in_reply_to chain to find which patch a follow-up belongs to.

    Returns the display index (0=cover, 1..N=patches) or None.
    """
    seen: Set[str] = set()
    current = in_reply_to
    while current and current not in seen:
        if current in patch_msgids:
            return patch_msgids[current]
        seen.add(current)
        lmsg = msgid_map.get(current)
        if lmsg is None:
            break
        current = lmsg.in_reply_to
    return None


def _write_comments(
    viewer: 'RichLog',
    entries: List[Tuple[str, str, str]],
    ts: Optional[Dict[str, str]] = None,
) -> None:
    """Write review comment entries to *viewer* as bordered panels.

    Each entry is an (initials, colour, text) tuple.  Comments from
    the same diff line are rendered as separate panels.
    *ts* is a resolved theme styles dict from :func:`resolve_styles`.
    """
    bg = f"on {ts['panel']}" if ts else 'on grey11'
    for initials, colour, text in entries:
        panel = Panel(
            Text(text),
            box=box.ROUNDED,
            border_style=colour,
            title=initials,
            title_align='left',
            expand=False,
            padding=(0, 1),
            style=bg,
        )
        viewer.write(panel)


def _write_followup_trailers(
    viewer: 'RichLog',
    followups: List[Dict[str, Any]],
    existing: Optional[Set[str]] = None,
    ts: Optional[Dict[str, str]] = None,
) -> None:
    """Write follow-up trailers as a panel in the diff viewer.

    Each followup dict has 'link', 'fromname', 'fromemail', and 'trailers'.
    Trailers already present in *existing* (lowercased) are skipped.
    *ts* is a resolved theme styles dict from :func:`resolve_styles`.
    """
    if existing is None:
        existing = set()
    trailer_color = ts['success'] if ts else 'green'
    lines = Text()
    for followup in followups:
        link = followup.get('link', '')
        for tstr in followup.get('trailers', []):
            if tstr.lower() in existing:
                continue
            existing.add(tstr.lower())
            if lines.plain:
                lines.append('\n')
            lines.append(tstr, style=f'bold {trailer_color}')
            if link:
                lines.append(f'\n  {link}', style=f'dim {trailer_color} link {link}')
    if not lines.plain:
        return
    viewer.write(Text(''))
    panel = Panel(
        lines,
        box=box.ROUNDED,
        title='+++',
        title_align='left',
        border_style=trailer_color,
        expand=False,
        padding=(0, 1),
    )
    viewer.write(panel)


def _write_diff_line(
    viewer: 'RichLog', line: str,
    ts: Optional[Dict[str, str]] = None,
) -> None:
    """Write a single diff line to a RichLog with appropriate colouring.

    *ts* is a resolved theme styles dict from :func:`resolve_styles`.
    """
    if line.startswith('diff --git ') or line.startswith('--- ') or line.startswith('+++ '):
        viewer.write(Text(line, style='bold'))
    elif line.startswith('@@'):
        viewer.write(Text(line, style=f"bold {ts['accent']}" if ts else 'bold cyan'))
    elif line.startswith('+'):
        viewer.write(Text(line, style=ts['success'] if ts else 'green'))
    elif line.startswith('-'):
        viewer.write(Text(line, style=ts['error'] if ts else 'red'))
    else:
        viewer.write(Text(line))


def _render_email_to_viewer(
    viewer: 'RichLog', msg: email.message.EmailMessage,
    ts: Optional[Dict[str, str]] = None,
) -> None:
    """Render an EmailMessage into a RichLog, headers first then body.

    Subject, To and Cc labels are bold.  Address headers are word-wrapped
    using LoreMessage.wrap_header.  Quoted body lines (>) are dim cyan,
    separator lines (---) are dim.
    *ts* is a resolved theme styles dict from :func:`resolve_styles`.
    """
    for hdr in ('From', 'Subject', 'To', 'Cc'):
        val = msg[hdr]
        if not val:
            continue
        val = str(val)
        if hdr.lower() in ('to', 'cc'):
            wrapped = b4.LoreMessage.wrap_header(
                (hdr, val), transform='decode').decode(errors='replace')
            first_line, *rest = wrapped.splitlines()
            colon = first_line.find(':')
            hdr_text = Text()
            if colon >= 0:
                hdr_text.append(first_line[:colon + 1], style='bold')
                hdr_text.append(first_line[colon + 1:])
            else:
                hdr_text.append(first_line)
            for r in rest:
                hdr_text.append('\n')
                hdr_text.append(r)
            viewer.write(hdr_text)
        else:
            hdr_text = Text()
            hdr_text.append(f'{hdr}:', style='bold')
            hdr_text.append(f' {val}')
            viewer.write(hdr_text)
    viewer.write('')
    payload = msg.get_payload(decode=True)
    body = payload.decode(errors='replace') if isinstance(payload, bytes) else str(payload or '')
    for line in body.splitlines():
        if line.startswith('>'):
            viewer.write(Text(line, style=f"dim {ts['accent']}" if ts else 'dim cyan'))
        elif line.startswith('---'):
            viewer.write(Text(line, style='dim'))
        else:
            viewer.write(Text(line))


def _suspend_to_shell(hint: str = 'b4 review') -> None:
    """Spawn an interactive sub-shell with a PS1 hint.

    For bash and zsh, a temporary rc file is used so the user's normal
    configuration is loaded first and then the prompt is prefixed with
    a short marker.  For other shells the B4_REVIEW environment variable
    is set so the user can incorporate it into their own prompt.
    """
    logger.info('---')
    logger.info('You are now in shell mode. You can execute git commands or run checks.')
    logger.info('DO NOT rebase or modify commits, as b4 will get confused.')
    logger.info('When done, Ctrl-d to return to review UI.')
    logger.info('---')

    shell = os.environ.get('SHELL', '/bin/sh')
    shellname = os.path.basename(shell)
    env = os.environ.copy()
    env['B4_REVIEW'] = hint

    if shellname == 'bash':
        bashrc = os.path.expanduser('~/.bashrc')
        source = f'[ -f {bashrc} ] && . {bashrc}\n'
        source += f'PS1="({hint}) $PS1"\n'
        with tempfile.NamedTemporaryFile(mode='w', prefix='b4-shell-',
                                         suffix='.sh', delete=False) as rcf:
            rcf.write(source)
            rcfile = rcf.name
        try:
            subprocess.run([shell, '--rcfile', rcfile], env=env)
        finally:
            os.unlink(rcfile)
    elif shellname == 'zsh':
        real_zdotdir = os.environ.get('ZDOTDIR', os.path.expanduser('~'))
        with tempfile.TemporaryDirectory(prefix='b4-shell-') as tmpdir:
            zshrc = os.path.join(tmpdir, '.zshrc')
            with open(zshrc, 'w') as f:
                f.write(f'ZDOTDIR="{real_zdotdir}"\n')
                f.write('[ -f "$ZDOTDIR/.zshrc" ] && . "$ZDOTDIR/.zshrc"\n')
                f.write(f'PS1="({hint}) $PS1"\n')
            env['ZDOTDIR'] = tmpdir
            subprocess.run([shell], env=env)
    else:
        subprocess.run([shell], env=env)


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


def gather_attestation_info(lser: b4.LoreSeries) -> Dict[str, Any]:
    """Gather attestation and applicability information for a series.

    Args:
        lser: The LoreSeries to check

    Returns:
        Dict with keys:
            - total: Total number of patches
            - passing: Number of passing patches
            - critical: If True, hardfail policy triggered
            - same_attestation: If True, all patches have same attestations
            - attestations: Common attestations (if same_attestation) or None
            - per_patch: List of per-patch info (if not same_attestation)
            - base_commit: The base commit (or None)
            - base_exists: Whether the base commit exists in the repo
            - applies_clean: Whether the series applies cleanly (None if not checked)
            - apply_checked: Number of blobs checked
            - apply_mismatches: Number of mismatched blobs
    """
    config = b4.get_main_config()
    attpolicy = str(config.get('attestation-policy', 'softfail'))

    # Check base commit and applicability
    topdir = b4.git_get_toplevel()
    base_commit = lser.base_commit
    base_exists = False
    applies_clean = None
    apply_checked = 0
    apply_mismatches = 0

    if topdir:
        # Ensure indexes are populated for applicability check
        if lser.indexes is None:
            lser.populate_indexes()

        if base_commit:
            base_exists = b4.git_commit_exists(topdir, base_commit)

        # Check applicability
        if lser.indexes:
            check_at = None
            if base_commit and base_exists:
                check_at = base_commit
            else:
                # No base commit or base doesn't exist - check against HEAD
                check_at = 'HEAD'

            try:
                apply_checked, mismatches = lser.check_applies_clean(topdir, at=check_at)
                apply_mismatches = len(mismatches)
                applies_clean = (apply_mismatches == 0)
            except Exception:
                pass

    if attpolicy == 'off':
        return {
            'total': 0,
            'passing': 0,
            'critical': False,
            'same_attestation': True,
            'attestations': [],
            'per_patch': [],
            'base_commit': base_commit,
            'base_exists': base_exists,
            'applies_clean': applies_clean,
            'apply_checked': apply_checked,
            'apply_mismatches': apply_mismatches,
        }

    try:
        maxdays = int(str(config.get('attestation-staleness-days', '0')))
    except ValueError:
        maxdays = 0

    per_patch = []
    any_critical = False
    total_passing = 0
    ref_attestations: Optional[List[Dict[str, Any]]] = None
    same_attestation = True

    total = lser.expected
    width = len(str(total))
    for idx, lmsg in enumerate(lser.patches[1:], start=1):
        patch_idx = f'{idx:0{width}d}/{total:0{width}d}'

        if lmsg is None:
            per_patch.append({
                'index': patch_idx,
                'passing': False,
                'attestations': [{'status': 'missing', 'identity': 'Patch not available', 'passing': False}],
            })
            same_attestation = False
            continue

        attestations, overall_passing, critical = lmsg.get_attestation_status(attpolicy, maxdays)
        if critical:
            any_critical = True

        if overall_passing:
            total_passing += 1

        # Check if attestation is the same as previous patches (compare by identity set)
        if ref_attestations is None:
            ref_attestations = attestations
        else:
            ref_ids = {a['identity'] for a in ref_attestations}
            cur_ids = {a['identity'] for a in attestations}
            if ref_ids != cur_ids:
                same_attestation = False

        per_patch.append({
            'index': patch_idx,
            'passing': overall_passing,
            'attestations': attestations,
        })

    return {
        'total': len(per_patch),
        'passing': total_passing,
        'critical': any_critical,
        'same_attestation': same_attestation,
        'attestations': ref_attestations or [],
        'per_patch': per_patch,
        'base_commit': base_commit,
        'base_exists': base_exists,
        'applies_clean': applies_clean,
        'apply_checked': apply_checked,
        'apply_mismatches': apply_mismatches,
    }


class JKListNavMixin:
    """Mixin providing j/k cursor navigation for a named ListView.

    Classes using this mixin must set ``_list_id`` to the DOM id of the
    target :class:`ListView` (e.g. ``'#action-list'``).
    """

    _list_id: str = ''

    def action_cursor_down(self) -> None:
        lv = self.query_one(self._list_id, ListView)  # type: ignore[attr-defined]
        if lv.index is not None and lv.index < len(lv.children) - 1:
            lv.index += 1

    def action_cursor_up(self) -> None:
        lv = self.query_one(self._list_id, ListView)  # type: ignore[attr-defined]
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
