#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import email.message
import json
import os
import tempfile
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    ParamSpec,
    Protocol,
    Set,
    Tuple,
    TypeVar,
)

import liblore.utils
from rich import box
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from textual.widgets import RichLog
from textual.worker import Worker

import b4
import b4.review
import b4.review.tracking

# -- Re-exported from b4.tui (canonical home for shared TUI utilities) --------
from b4.tui._common import (
    JKListNavMixin as JKListNavMixin,
)
from b4.tui._common import (
    SeparatedFooter as SeparatedFooter,
)
from b4.tui._common import (
    _addrs_to_lines as _addrs_to_lines,
)
from b4.tui._common import (
    _fix_ansi_theme as _fix_ansi_theme,
)
from b4.tui._common import (
    _lines_to_header as _lines_to_header,
)
from b4.tui._common import (
    _quiet_worker as _quiet_worker,
)
from b4.tui._common import (
    _suspend_to_shell as _suspend_to_shell,
)
from b4.tui._common import (
    _to_rich_color as _to_rich_color,
)
from b4.tui._common import (
    _validate_addrs as _validate_addrs,
)
from b4.tui._common import (
    _wait_for_enter as _wait_for_enter,
)
from b4.tui._common import (
    ci_check_styles as ci_check_styles,
)
from b4.tui._common import (
    ci_markup as ci_markup,
)
from b4.tui._common import (
    ci_styles as ci_styles,
)
from b4.tui._common import (
    display_width as display_width,
)
from b4.tui._common import (
    pad_display as pad_display,
)
from b4.tui._common import (
    resolve_styles as resolve_styles,
)
from b4.tui._common import (
    reviewer_colours as reviewer_colours,
)

logger = b4.logger

if TYPE_CHECKING:
    from b4.review_tui._modals import CheckLoadingScreen

_CallFromThreadParams = ParamSpec('_CallFromThreadParams')
_CallFromThreadReturn = TypeVar('_CallFromThreadReturn')
_WorkerResult = TypeVar('_WorkerResult')


def get_thread_msgs(
    topdir: str,
    message_id: str,
    blob_sha: str = '',
    quiet: bool = False,
) -> Optional[List[email.message.EmailMessage]]:
    """Retrieve thread messages, trying the local git blob first.

    If *blob_sha* points to a valid mbox blob in the repository, the
    thread is loaded from there without network access.  Otherwise
    falls back to fetching from lore via ``b4.get_pi_thread_by_msgid``.

    Returns a list of ``EmailMessage`` objects, or *None* on failure.
    """
    if blob_sha:
        mbox_bytes = b4.review.tracking.get_thread_mbox(topdir, blob_sha)
        if mbox_bytes:
            msgs = liblore.utils.split_mbox(mbox_bytes)
            if msgs:
                return msgs

    return b4.get_pi_thread_by_msgid(message_id, quiet=quiet) or None


# Per-patch state indicators — same glyphs as _tracking_app._STATUS_SYMBOLS
PATCH_STATE_MARKERS: Dict[str, str] = {
    '': ' ',
    'external': '\u00b1',  # ± plus-minus    (= external comments available)
    'draft': '\u270e',  # ✎ pencil        (= maintainer reviewing)
    'done': '\u2713',  # ✓ check         (= done)
    'skip': '\u2715',  # ✕ cross         (= skipped)
    'unchanged': '\u2261',  # ≡ identical-to  (= patch unchanged from prior revision)
}

# CI check label text (colour-free constant — used with ci_check_styles())
CI_CHECK_LABELS = {
    'pending': '\u25cf pending',
    'success': '\u25cf pass',
    'warning': '\u25cf warning',
    'fail': '\u25cf FAIL',
}


class _CallFromThreadHost(Protocol):
    def call_from_thread(
        self,
        callback: Callable[
            _CallFromThreadParams,
            _CallFromThreadReturn | Awaitable[_CallFromThreadReturn],
        ],
        *args: _CallFromThreadParams.args,
        **kwargs: _CallFromThreadParams.kwargs,
    ) -> _CallFromThreadReturn: ...


class _CheckRunnerHost(Protocol):
    _check_loading: Optional['CheckLoadingScreen']

    @property
    def app(self) -> _CallFromThreadHost: ...

    def _get_check_context(self) -> Optional[Tuple[str, str, str]]: ...

    def _run_checks(self, force: bool = ...) -> None: ...

    def _dismiss_loading(self, msg: str = ..., severity: str = ...) -> None: ...

    def _update_loading(self, text: str) -> None: ...

    def _fetch_and_check(
        self,
        message_id: str,
        series_subject: str,
        change_id: str = '',
        force: bool = ...,
    ) -> None: ...

    def notify(self, message: str, *, severity: str = ...) -> None: ...

    def push_screen(
        self,
        screen: object,
        callback: Optional[Callable[[Optional[str]], None]] = ...,
    ) -> object: ...

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


class CheckRunnerMixin:
    """Mixin providing CI check execution for Textual App subclasses.

    Subclasses must implement :meth:`_get_check_context` to supply the
    message-id, subject, and change-id for the series to check.  All UI
    interaction (loading overlay, results modal) is handled here.
    """

    _check_loading: Optional['CheckLoadingScreen']

    # -- interface for subclasses ------------------------------------------

    def _get_check_context(self) -> Optional[Tuple[str, str, str]]:
        """Return ``(message_id, series_subject, change_id)`` or *None*.

        Return *None* when no series is selected or checks cannot run.
        """
        raise NotImplementedError

    # -- public action -----------------------------------------------------

    def action_check(self: _CheckRunnerHost) -> None:
        """Run CI checks on the current series."""
        self._run_checks(force=False)

    # -- helpers -----------------------------------------------------------

    def _run_checks(self: _CheckRunnerHost, force: bool = False) -> None:
        """Show loading overlay and launch the check worker thread."""
        ctx = self._get_check_context()
        if ctx is None:
            return
        message_id, series_subject, change_id = ctx
        if not message_id:
            self.notify('No message-id for this series', severity='error')
            return
        from b4.review_tui._modals import CheckLoadingScreen

        self._check_loading = CheckLoadingScreen()
        self.push_screen(self._check_loading)
        self.run_worker(
            lambda: self._fetch_and_check(
                message_id, series_subject, change_id=change_id, force=force
            ),
            name='_check_worker',
            thread=True,
        )

    def _dismiss_loading(
        self: _CheckRunnerHost, msg: str = '', severity: str = ''
    ) -> None:
        """Dismiss the check loading screen and optionally notify."""

        def _do() -> None:
            if self._check_loading is not None and self._check_loading.is_attached:
                self._check_loading.dismiss(None)
            if msg:
                self.notify(msg, severity=severity)

        self.app.call_from_thread(_do)

    def _update_loading(self: _CheckRunnerHost, text: str) -> None:
        """Update the loading screen status text."""

        def _do() -> None:
            if self._check_loading is not None and self._check_loading.is_attached:
                self._check_loading.update_status(text)

        self.app.call_from_thread(_do)

    def _fetch_and_check(
        self: _CheckRunnerHost,
        message_id: str,
        series_subject: str,
        change_id: str = '',
        force: bool = False,
    ) -> None:
        """Fetch thread, run checks, and push results modal (worker thread)."""
        import b4.review.checks as checks
        from b4.review_tui._modals import TrackingCheckResultsScreen

        checks.clear_sashiko_cache()
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
        blob_sha = ''
        if change_id:
            review_branch = f'b4/review/{change_id}'
            try:
                _cover, tracking = b4.review.load_tracking(topdir, review_branch)
                blob_sha = tracking.get('series', {}).get('thread-blob', '')
                fd, tracking_file = tempfile.mkstemp(
                    prefix='b4-tracking-', suffix='.json'
                )
                with os.fdopen(fd, 'w') as fp:
                    json.dump(tracking, fp, indent=2)
                extra_env['B4_TRACKING_FILE'] = tracking_file
            except SystemExit:
                pass

        # Fetch the thread (local blob first, then lore)
        self._update_loading('Loading thread\u2026')
        with _quiet_worker():
            msgs = get_thread_msgs(topdir, message_id, blob_sha=blob_sha, quiet=True)
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
            patch_subjects.append(
                b4.LoreSubject(cover_msg[1].get('subject', '')).subject
            )
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
                    [(mid, _msg)],
                    perpatch_cmds,
                    topdir,
                    pwkey,
                    pwurl,
                    extra_env=extra_env,
                )
                for result in single_results.get(mid, []):
                    tool = result['tool']
                    all_tools.add(tool)
                    matrix[(pidx, tool)] = result
                    new_results.setdefault(mid, []).append(result)

        # Run per-series checks (only if not cached)
        if series_cmds:
            target = (
                cover_msg if cover_msg else (ordered_msgs[0] if ordered_msgs else None)
            )
            if target and target[0] not in cached:
                self._update_loading('Running series checks\u2026')
                series_results = checks.run_series_checks(
                    target, series_cmds, topdir, pwkey, pwurl, extra_env=extra_env
                )
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
            self.push_screen(
                TrackingCheckResultsScreen(
                    title, patch_labels, patch_subjects, tools_sorted, matrix
                ),
                callback=_on_result,
            )

        self.app.call_from_thread(_push_modal)


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
        r.get('trailers')
        or r.get('reply', '')
        or r.get('comments')
        or r.get('note', '')
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
    for ln in lines[attr_end + 1 :]:
        if ln.strip():
            if ln.startswith('> ') or ln.strip() == '>':
                remaining = lines[attr_end + 1 :]
                while remaining and (
                    not remaining[0].strip() or remaining[0].strip() == '>'
                ):
                    remaining.pop(0)
                return '\n'.join(remaining)
            break
    return body


def _write_followup_comments(
    viewer: 'RichLog',
    fc_list: List[Dict[str, Any]],
    comment_positions: List[int],
    header_position_map: Optional[Dict[int, Dict[str, Any]]] = None,
    ts: Optional[Dict[str, str]] = None,
) -> None:
    """Render follow-up comments at the bottom of the viewer.

    Each entry has 'body', 'fromname', 'fromemail', 'date', and optionally
    'depth' (0 = direct reply to patch, N = N hops through follow-up replies).
    Entries with depth > 0 are indented to visually show threading.
    If *header_position_map* is provided, it is populated with
    {viewer_line: entry} for each panel header row, enabling click-to-reply.
    *ts* is a resolved theme styles dict from :func:`resolve_styles`.
    """
    if not fc_list:
        return
    rev_palette = (
        reviewer_colours(ts)
        if ts
        else [
            'dark_goldenrod',
            'dark_cyan',
            'dark_magenta',
            'dark_red',
            'dark_blue',
        ]
    )
    fc_emails = sorted({e['fromemail'] for e in fc_list})
    colour_map: Dict[str, str] = {}
    for ci, em in enumerate(fc_emails):
        colour_map[em] = rev_palette[1 + (ci % (len(rev_palette) - 1))]
    viewer.write(Text(''))
    viewer.write(Rule(title='follow-ups', style='dim'))
    viewer.write(Text(''))
    for e in sorted(fc_list, key=lambda x: x['date']):
        fromname = e['fromname']
        colour = colour_map.get(e['fromemail'], rev_palette[1])
        line_pos = len(viewer.lines)
        comment_positions.append(line_pos)
        if header_position_map is not None:
            header_position_map[line_pos] = e
        body = _strip_attribution(e['body'])
        body_text = Text()
        body_text.append(f'From:  {fromname} <{e["fromemail"]}>\n', style='bold')
        body_text.append(
            f'Date:  {e["date"].strftime("%Y-%m-%d %H:%M %z")}\n', style='bold'
        )
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
        title_text.append(fromname)
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


def _chain_has_additional_patch(
    in_reply_to: Optional[str],
    patch_msgids: Dict[str, int],
    msgid_map: Dict[str, 'b4.LoreMessage'],
) -> bool:
    """Check whether the in-reply-to chain passes through a message that
    contains its own diff before reaching a known series patch.

    Such a message is an additional patch posted as a follow-up.
    Replies to it discuss that new code, so their quoted diffs should not
    be treated as inline reviews of the original series patch.
    """
    seen: Set[str] = set()
    current = in_reply_to
    while current and current not in seen:
        if current in patch_msgids:
            return False
        seen.add(current)
        lmsg = msgid_map.get(current)
        if lmsg is None:
            break
        if lmsg.has_diff:
            return True
        current = lmsg.in_reply_to
    return False


def _write_comments(
    viewer: 'RichLog',
    entries: List[Tuple[str, str, str]],
    ts: Optional[Dict[str, str]] = None,
) -> None:
    """Write review comment entries to *viewer* as bordered panels.

    Each entry is a (name, colour, text) tuple.  Comments from
    the same diff line are rendered as separate panels.
    *ts* is a resolved theme styles dict from :func:`resolve_styles`.
    """
    bg = f'on {ts["panel"]}' if ts else 'on grey11'
    for name, colour, text in entries:
        panel = Panel(
            Text(text),
            box=box.ROUNDED,
            border_style=colour,
            subtitle=name,
            subtitle_align='right',
            expand=False,
            padding=(1, 1),
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
    viewer: 'RichLog',
    line: str,
    ts: Optional[Dict[str, str]] = None,
) -> None:
    """Write a single diff line to a RichLog with appropriate colouring.

    *ts* is a resolved theme styles dict from :func:`resolve_styles`.
    """
    if line.startswith(('diff --git ', '--- ', '+++ ')):
        viewer.write(Text(line, style='bold'))
    elif line.startswith('@@'):
        viewer.write(Text(line, style=f'bold {ts["accent"]}' if ts else 'bold cyan'))
    elif line.startswith('+'):
        viewer.write(Text(line, style=ts['success'] if ts else 'green'))
    elif line.startswith('-'):
        viewer.write(Text(line, style=ts['error'] if ts else 'red'))
    else:
        viewer.write(Text(line))


def _render_email_to_viewer(
    viewer: 'RichLog',
    msg: email.message.EmailMessage,
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
            wrapped = b4.LoreMessage.wrap_header((hdr, val), transform='decode').decode(
                errors='replace'
            )
            first_line, *rest = wrapped.splitlines()
            colon = first_line.find(':')
            hdr_text = Text()
            if colon >= 0:
                hdr_text.append(first_line[: colon + 1], style='bold')
                hdr_text.append(first_line[colon + 1 :])
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
    body = (
        payload.decode(errors='replace')
        if isinstance(payload, bytes)
        else str(payload or '')
    )
    for line in body.splitlines():
        if line.startswith('>'):
            viewer.write(Text(line, style=f'dim {ts["accent"]}' if ts else 'dim cyan'))
        elif line.startswith('---'):
            viewer.write(Text(line, style='dim'))
        else:
            viewer.write(Text(line))


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
                apply_checked, mismatches = lser.check_applies_clean(
                    topdir, at=check_at
                )
                apply_mismatches = len(mismatches)
                applies_clean = apply_mismatches == 0
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
            per_patch.append(
                {
                    'index': patch_idx,
                    'passing': False,
                    'attestations': [
                        {
                            'status': 'missing',
                            'identity': 'Patch not available',
                            'passing': False,
                        }
                    ],
                }
            )
            same_attestation = False
            continue

        attestations, overall_passing, critical = lmsg.get_attestation_status(
            attpolicy, maxdays
        )
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

        per_patch.append(
            {
                'index': patch_idx,
                'passing': overall_passing,
                'attestations': attestations,
            }
        )

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
