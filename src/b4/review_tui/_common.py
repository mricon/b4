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
from rich.panel import Panel
from rich.markup import escape as _escape_markup
from rich.rule import Rule
from rich.text import Text

logger = b4.logger

# Unicode marker for patches that have review data
REVIEW_MARKER = '\u2714'  # ✔

# Rich markup for CI check indicators (● = \u25cf)
CI_COLOURS = {
    'pending': 'dim',
    'success': 'green',
    'warning': 'red',
    'fail': 'bold red',
}

# Short dot indicator for series listings
CI_MARKUP = {
    state: f'[{style}]\u25cf[/{style}]'
    for state, style in CI_COLOURS.items()
}

# Verbose label for CI check detail views
CI_CHECK_MARKUP = {
    'pending': '[dim]\u25cf pending[/dim]',
    'success': '[green]\u25cf pass[/green]',
    'warning': '[dark_orange]\u25cf warning[/dark_orange]',
    'fail': '[bold red]\u25cf FAIL[/bold red]',
}

_REVIEWER_COLOURS = [
    'dark_goldenrod',   # index 0: always the current user
    'dark_green',
    'dark_cyan',
    'dark_magenta',
    'dark_red',
    'dark_blue',
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
) -> None:
    """Render follow-up comments at the bottom of the viewer.

    Each entry has 'body', 'fromname', 'fromemail', and 'date'.
    If *fc_author_positions* is provided, it is populated with the
    first viewer line position for each unique fromemail.
    """
    if not fc_list:
        return
    fc_emails = sorted({e['fromemail'] for e in fc_list})
    colour_map: Dict[str, str] = {}
    for ci, em in enumerate(fc_emails):
        colour_map[em] = _REVIEWER_COLOURS[1 + (ci % (len(_REVIEWER_COLOURS) - 1))]
    viewer.write(Text(''))
    viewer.write(Rule(title='follow-ups', style='dim'))
    viewer.write(Text(''))
    for e in sorted(fc_list, key=lambda x: x['date']):
        initials = _make_initials(e['fromname'])
        colour = colour_map.get(e['fromemail'], _REVIEWER_COLOURS[1])
        line_pos = len(viewer.lines)
        comment_positions.append(line_pos)
        if fc_author_positions is not None and e['fromemail'] not in fc_author_positions:
            fc_author_positions[e['fromemail']] = line_pos
        body = _strip_attribution(e['body'])
        body_text = Text()
        body_text.append(f'From: {e["fromname"]} <{e["fromemail"]}>\n', style='bold')
        body_text.append(f'Date: {e["date"].strftime("%Y-%m-%d %H:%M %z")}\n', style='bold')
        body_text.append('\n')
        for line in body.splitlines():
            if line.startswith('> ') or line == '>':
                body_text.append(line, style='dim')
            else:
                body_text.append(line)
            body_text.append('\n')
        panel = Panel(
            body_text,
            box=box.ROUNDED,
            border_style=colour,
            title=initials,
            title_align='left',
            expand=True,
            padding=(0, 1),
        )
        viewer.write(panel)


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
) -> None:
    """Write review comment entries to *viewer* as bordered panels.

    Each entry is an (initials, colour, text) tuple.  Comments from
    the same diff line are rendered as separate panels.
    """
    for initials, colour, text in entries:
        panel = Panel(
            Text(text),
            box=box.ROUNDED,
            border_style=colour,
            title=initials,
            title_align='left',
            expand=False,
            padding=(0, 1),
            style='on grey11',
        )
        viewer.write(panel)


def _write_followup_trailers(
    viewer: 'RichLog',
    followups: List[Dict[str, Any]],
    existing: Optional[Set[str]] = None,
) -> None:
    """Write follow-up trailers as a panel in the diff viewer.

    Each followup dict has 'link', 'fromname', 'fromemail', and 'trailers'.
    Trailers already present in *existing* (lowercased) are skipped.
    """
    if existing is None:
        existing = set()
    lines = Text()
    for followup in followups:
        link = followup.get('link', '')
        for tstr in followup.get('trailers', []):
            if tstr.lower() in existing:
                continue
            existing.add(tstr.lower())
            if lines.plain:
                lines.append('\n')
            lines.append(tstr, style='bold green')
            if link:
                lines.append(f'\n  {link}', style=f'dim green link {link}')
    if not lines.plain:
        return
    viewer.write(Text(''))
    panel = Panel(
        lines,
        box=box.ROUNDED,
        title='+++',
        title_align='left',
        border_style='green',
        expand=False,
        padding=(0, 1),
    )
    viewer.write(panel)


def _write_diff_line(viewer: 'RichLog', line: str) -> None:
    """Write a single diff line to a RichLog with appropriate colouring."""
    escaped = _escape_markup(line)
    if line.startswith('diff --git ') or line.startswith('--- ') or line.startswith('+++ '):
        viewer.write(f'[bold]{escaped}[/bold]')
    elif line.startswith('@@'):
        viewer.write(f'[bold cyan]{escaped}[/bold cyan]')
    elif line.startswith('+'):
        viewer.write(f'[green]{escaped}[/green]')
    elif line.startswith('-'):
        viewer.write(f'[red]{escaped}[/red]')
    else:
        viewer.write(escaped)


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
    SeparatedFooter:ansi FooterKey.-group-first {
        border-left: vkey ansi_black;
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
