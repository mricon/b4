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
