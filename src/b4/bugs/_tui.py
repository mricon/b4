#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
"""Textual TUI for b4 bugs."""
import email.message
import email.utils
import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional, Union

if TYPE_CHECKING:
    from textual.events import Key

from textual.events import Click, MouseScrollDown, MouseScrollUp

from rich import box
from rich.panel import Panel
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.suggester import SuggestFromList
from textual.widgets import (
    Checkbox,
    Input,
    ListItem,
    ListView,
    RichLog,
    Static,
)
from textual.worker import Worker, WorkerState

from b4.tui import (
    ActionScreen,
    ConfirmScreen,
    JKListNavMixin,
    LimitScreen,
    SeparatedFooter,
    _quiet_worker,
    _wait_for_enter,
    display_width,
    pad_display,
    resolve_styles,
    reviewer_colours,
)
import b4
from b4.bugs._import import is_comment_removed, make_tombstone, parse_comment_header
from ezgb import Bug, BugSummary, Comment, GitBugRepo, Status

# Union type for items that can appear in the bug list.
# BugSummary is used for the fast initial load; full Bug on demand.
BugLike = Union[Bug, BugSummary]

logger = logging.getLogger('b4')

# Material UI colors used by git-bug for deterministic label coloring.
# See entities/common/label.go in git-bug.
_LABEL_COLORS = [
    (244, 67, 54),    # red
    (233, 30, 99),    # pink
    (156, 39, 176),   # purple
    (103, 58, 183),   # deepPurple
    (63, 81, 181),    # indigo
    (33, 150, 243),   # blue
    (3, 169, 244),    # lightBlue
    (0, 188, 212),    # cyan
    (0, 150, 136),    # teal
    (76, 175, 80),    # green
    (139, 195, 74),   # lightGreen
    (205, 220, 57),   # lime
    (255, 235, 59),   # yellow
    (255, 193, 7),    # amber
    (255, 152, 0),    # orange
    (255, 87, 34),    # deepOrange
    (121, 85, 72),    # brown
    (158, 158, 158),  # grey
    (96, 125, 139),   # blueGrey
]


def label_color(label: str) -> str:
    """Compute a deterministic Rich color string for a label.

    Matches git-bug's Label.Color() algorithm: SHA-256 the label
    name, sum all bytes mod len(palette), pick that color.
    """
    digest = hashlib.sha256(label.encode()).digest()
    idx = sum(digest) % len(_LABEL_COLORS)
    r, g, b = _LABEL_COLORS[idx]
    return f'#{r:02x}{g:02x}{b:02x}'


_LIFECYCLE_SYMBOLS: dict[str, str] = {
    'new':        '\u2605',  # ★ black star
    'confirmed':  '\u00a4',  # ¤ currency sign (bug-like)
    'worksforme': '\u00f8',  # ø latin small letter o with stroke
    'needinfo':   '\u203d',  # ‽ interrobang
    'wontfix':    '\u2260',  # ≠ not equal to
    'fixed':      '\u2713',  # ✓ check mark
    'duplicate':  '\u2261',  # ≡ identical to
}


# Sort tier for each lifecycle state. Lower tier sorts higher in the list.
#   0 = active (needs triage or work)
#   1 = waiting (pending external input)
#   2 = resolved (no action needed)
_LIFECYCLE_TIER: dict[str, int] = {
    'new':        0,
    'confirmed':  0,
    'needinfo':   1,
    'worksforme': 2,
    'wontfix':    2,
    'fixed':      2,
    'duplicate':  2,
}


def _bug_tier(bug: BugLike) -> int:
    """Return the sort tier for a bug (0=active, 1=waiting, 2=resolved)."""
    if bug.status == Status.CLOSED:
        return 2
    for lb in bug.labels:
        if lb.startswith('lifecycle:'):
            state = lb[len('lifecycle:'):]
            return _LIFECYCLE_TIER.get(state, 0)
    return 0


def _bug_last_activity(bug: BugLike) -> datetime:
    """Return the last activity date."""
    if isinstance(bug, BugSummary):
        return bug.edited_at
    if bug.comments:
        return bug.comments[-1].created_at
    return bug.created_at


def _bug_lifecycle(bug: BugLike) -> str:
    """Extract the lifecycle status from a bug's labels.

    Looks for a ``lifecycle:<value>`` label and returns the
    corresponding symbol, or ★ (new) if none is set.
    For closed bugs without a lifecycle label, returns × (closed).
    """
    for lb in bug.labels:
        if lb.startswith('lifecycle:'):
            state = lb[len('lifecycle:'):]
            return _LIFECYCLE_SYMBOLS.get(state, '?')
    if bug.status == Status.CLOSED:
        return '\u00d7'  # × multiplication sign
    return _LIFECYCLE_SYMBOLS['new']


def label_dots(labels: set[str]) -> Text:
    """Render labels as colored ■ dots, matching git-bug's style.

    Excludes ``lifecycle:`` labels since those have their own column.
    """
    text = Text()
    for lb in sorted(labels):
        if lb.startswith('lifecycle:'):
            continue
        if text.plain:
            text.append(' ')
        text.append('\u25a0', style=label_color(lb))
    return text


def _relative_time(dt: datetime) -> str:
    """Format a datetime as a human-readable relative time string."""
    now = datetime.now(tz=timezone.utc)
    delta = now - dt
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return 'just now'
    minutes = seconds // 60
    if minutes < 60:
        return f'{minutes}m ago'
    hours = minutes // 60
    if hours < 24:
        return f'{hours}h ago'
    days = hours // 24
    if days < 30:
        return f'{days}d ago'
    months = days // 30
    if months < 12:
        return f'{months}mo ago'
    years = days // 365
    return f'{years}y ago'


def _render_comment(viewer: RichLog, text: str,
                    ts: dict[str, str]) -> None:
    """Render an RFC 2822 formatted comment into a RichLog."""
    if '\n\n' in text:
        header_block, body = text.split('\n\n', 1)
    else:
        header_block, body = text, ''

    # Render headers with bold names
    for line in header_block.splitlines():
        colon = line.find(':')
        if colon > 0:
            hdr_text = Text()
            hdr_text.append(line[:colon + 1], style='bold')
            hdr_text.append(line[colon + 1:])
            viewer.write(hdr_text)
        else:
            viewer.write(Text(line))

    viewer.write(Text(''))

    # Render body with quote highlighting
    accent = ts.get('accent', 'cyan')
    for line in body.splitlines():
        if line.startswith('>'):
            viewer.write(Text(line, style=f'dim {accent}'))
        else:
            viewer.write(Text(line))


# -- List item widget --------------------------------------------------------

def _bug_submitter(bug: Bug) -> str:
    """Get the submitter name from the first comment's From header."""
    if bug.comments:
        from_hdr = parse_comment_header(bug.comments[0].text, 'From')
        if from_hdr:
            # Extract just the name part from "Name <email>"
            name, _addr = email.utils.parseaddr(from_hdr)
            if name:
                return name
    return bug.creator.name


class BugListItem(ListItem):
    """A single bug row in the bug list."""

    def __init__(self, bug: BugLike) -> None:
        super().__init__()
        self.bug = bug

    def compose(self) -> ComposeResult:
        bug = self.bug
        style = 'dim' if _bug_tier(bug) >= 2 else ''
        if isinstance(bug, BugSummary):
            submitter = bug.author_name or '\u2014'
            msgs = str(bug.comment_count).rjust(4)
        else:
            submitter = _bug_submitter(bug)
            visible = sum(1 for c in bug.comments
                          if not is_comment_removed(c.text))
            msgs = str(visible).rjust(4)
        if display_width(submitter) > 20:
            while display_width(submitter) > 19:
                submitter = submitter[:-1]
            submitter += '\u2026'
        submitter = pad_display(submitter, 20)
        status_sym = _bug_lifecycle(bug)
        label = Text(no_wrap=True, overflow='ellipsis', style=style)
        label.append(f'{bug.id[:7]}  ')
        label.append(submitter)
        label.append(f'  {msgs}')
        label.append(f'  {status_sym}')
        label.append(f'  {bug.title}')
        yield Static(label)


# -- Modal screens -----------------------------------------------------------

class ImportScreen(ModalScreen[Optional[str]]):
    """Modal for importing a lore thread by message-id."""

    DEFAULT_CSS = '''
    ImportScreen {
        align: center middle;
    }
    #import-dialog {
        width: 72;
        height: auto;
        max-height: 12;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #import-status {
        height: auto;
        margin-top: 1;
    }
    '''

    BINDINGS = [
        Binding('escape', 'cancel', 'cancel'),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id='import-dialog') as dialog:
            dialog.border_title = 'Import thread from lore'
            yield Input(placeholder='Message-ID or lore URL', id='import-msgid')
            yield Checkbox('Ignore parent messages in thread',
                           id='import-noparent')
            yield Static('', id='import-status')

    def on_input_submitted(self, event: Input.Submitted) -> None:
        raw = event.value.strip()
        if not raw:
            return
        status = self.query_one('#import-status', Static)
        try:
            msgid = b4.parse_msgid(raw)
        except Exception:
            msgid = ''
        if not msgid or '@' not in msgid:
            status.update('Not a valid message-id or lore URL')
            return
        noparent = self.query_one('#import-noparent', Checkbox).value
        status.update('Importing...')
        self.run_worker(
            lambda: self._do_import(msgid, noparent),
            name='import', thread=True,
        )

    def _do_import(self, msgid: str, noparent: bool) -> str:
        from b4.bugs._import import import_thread
        app = self.app
        if not isinstance(app, BugListApp):
            raise RuntimeError('ImportScreen must be used with BugListApp')
        with _quiet_worker():
            bug = import_thread(app.repo, msgid, noparent=noparent)
        return bug.id

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != 'import':
            return
        if event.state == WorkerState.SUCCESS:
            result: str = str(event.worker.result)
            self.dismiss(result)
        elif event.state == WorkerState.ERROR:
            status = self.query_one('#import-status', Static)
            status.update(f'Error: {event.worker.error}')

    def action_cancel(self) -> None:
        self.dismiss(None)


class CommentItem(ListItem):
    """A commenter entry in the left pane of the bug detail view."""

    def __init__(self, name: str, comment_idx: int) -> None:
        super().__init__()
        self.comment_idx = comment_idx
        self._display_name = name

    def compose(self) -> ComposeResult:
        from textual.widgets import Label
        st = Label(f'  {self._display_name}', markup=False)
        st.styles.text_style = 'dim'
        yield st


class BugDetailScreen(ModalScreen[None]):
    """Full-screen bug detail view with left pane navigation."""

    DEFAULT_CSS = '''
    BugDetailScreen {
        background: $surface;
    }
    #detail-header {
        height: auto;
        padding: 0 1;
        background: $primary-darken-2;
        color: $text;
    }
    BugDetailScreen:ansi #detail-header {
        background: ansi_bright_black;
        color: ansi_default;
        text-style: bold;
    }
    #detail-subheader {
        height: 1;
    }
    #detail-commenters-label {
        width: 1fr;
        min-width: 20;
        max-width: 30;
        padding: 0 1;
        color: $text-muted;
    }
    #detail-labels {
        width: 3fr;
        padding: 0 1;
        content-align: right middle;
    }
    #detail-body {
        height: 1fr;
    }
    #comment-list-pane {
        width: 1fr;
        min-width: 20;
        max-width: 30;
        border-right: solid $primary;
    }
    #comment-list {
        height: 1fr;
    }
    #detail-log {
        width: 3fr;
    }
    '''

    BINDINGS = [
        Binding('a', 'bug_action', 'action'),
        Binding('r', 'reply', 'reply'),
        Binding('c', 'comment', 'comment'),
        Binding('T', 'edit_title', 'edit title'),
        Binding('X', 'remove_comment', 'remove comment'),
        Binding('space', 'page_down', 'pgdn', show=False),
        Binding('backspace', 'page_up', 'pgup', show=False),
        Binding('pagedown', 'page_down', 'pgdn', show=False),
        Binding('pageup', 'page_up', 'pgup', show=False),
        Binding('escape', 'back', 'back'),
        Binding('q', 'back', 'back', show=False),
    ]

    _MAX_DEPTH = 5

    def __init__(self, bug: Bug) -> None:
        super().__init__()
        self.bug = bug
        self._comment_positions: dict[int, int] = {}
        self._comment_depths: dict[int, int] = {}
        self._header_line_map: dict[int, int] = {}
        self._visible_indices: list[int] = []
        self._ts: dict[str, str] = {}
        self._colour_map: dict[str, str] = {}

    def compose(self) -> ComposeResult:
        bug = self.bug
        header = Text()
        header.append(f'{bug.id[:7]} ', style='bold')
        header.append(bug.title, style='bold')
        yield Static(header, id='detail-header')
        with Horizontal(id='detail-subheader'):
            yield Static('Commenters', id='detail-commenters-label')
            if bug.labels:
                meta = Text()
                for lb in sorted(bug.labels):
                    if lb.startswith('lifecycle:'):
                        continue
                    meta.append('\u25a0 ', style=label_color(lb))
                    meta.append(f'{lb}  ')
                yield Static(meta, id='detail-labels')
            else:
                yield Static('', id='detail-labels')
        with Horizontal(id='detail-body'):
            with Vertical(id='comment-list-pane'):
                yield ListView(id='comment-list')
            yield RichLog(id='detail-log', wrap=True, markup=False,
                          auto_scroll=False)
        yield SeparatedFooter()

    def on_mount(self) -> None:
        app = self.app
        if isinstance(app, BugListApp):
            self._ts = app._ts

        # Build colour map for commenters
        palette = reviewer_colours(self._ts) if self._ts else [
            'dark_goldenrod', 'dark_cyan', 'dark_magenta',
            'dark_red', 'dark_blue',
        ]
        emails: list[str] = []
        for comment in self.bug.comments:
            addr = ''
            from_hdr = parse_comment_header(comment.text, 'From')
            if from_hdr:
                _name, addr = email.utils.parseaddr(from_hdr)
            if not addr:
                addr = comment.author.email
            if addr and addr not in emails:
                emails.append(addr)
        for ci, em in enumerate(emails):
            self._colour_map[em] = palette[ci % len(palette)]

        # Build depth map from In-Reply-To chains
        msgid_to_idx: dict[str, int] = {}
        for i, comment in enumerate(self.bug.comments):
            mid = parse_comment_header(comment.text, 'Message-ID')
            if mid:
                msgid_to_idx[mid.strip('<>')] = i
        for i, comment in enumerate(self.bug.comments):
            irt = parse_comment_header(comment.text, 'In-Reply-To')
            if irt:
                parent_idx = msgid_to_idx.get(irt.strip('<>'))
                if parent_idx is not None:
                    parent_depth = self._comment_depths.get(parent_idx, 0)
                    self._comment_depths[i] = min(
                        parent_depth + 1, self._MAX_DEPTH,
                    )
                    continue
            self._comment_depths[i] = 0

        # Build visible comment indices (skip removed)
        self._visible_indices = [
            i for i, c in enumerate(self.bug.comments)
            if not is_comment_removed(c.text)
        ]

        # Populate left pane
        lv = self.query_one('#comment-list', ListView)
        for item in self._build_comment_items():
            lv.append(item)
        lv.index = 0

        # Populate right pane after mount so RichLog tracks lines correctly
        def _initial_populate() -> None:
            self._populate_richlog()
            self.query_one('#comment-list', ListView).focus()
        self.call_after_refresh(_initial_populate)

    def _build_comment_items(self) -> list[CommentItem]:
        """Build CommentItem widgets for the left pane."""
        items: list[CommentItem] = []
        for i in self._visible_indices:
            comment = self.bug.comments[i]
            from_hdr = parse_comment_header(comment.text, 'From')
            if from_hdr:
                name, _addr = email.utils.parseaddr(from_hdr)
                if not name:
                    name = from_hdr
            else:
                name = comment.author.name
            depth = self._comment_depths.get(i, 0)
            indent = '  ' * depth
            items.append(CommentItem(f'{indent}{name}', i))
        return items

    def _populate_richlog(self) -> None:
        """Fill the RichLog with comment panels and record positions."""
        viewer = self.query_one('#detail-log', RichLog)
        viewer.clear()
        self._comment_positions.clear()
        self._header_line_map.clear()
        for i in self._visible_indices:
            comment = self.bug.comments[i]
            line_pos = len(viewer.lines)
            self._comment_positions[i] = line_pos
            self._header_line_map[line_pos] = i
            depth = self._comment_depths.get(i, 0)
            self._render_comment_panel(viewer, comment, i, depth)

    async def _rebuild_panes(self, scroll_to_end: bool = False) -> None:
        """Rebuild both panes from the current bug state.

        Replaces the ListView widget entirely (rather than clear +
        append) because ListView.clear() is async and races with
        subsequent appends, causing stale child counts.
        """
        self._visible_indices = [
            i for i, c in enumerate(self.bug.comments)
            if not is_comment_removed(c.text)
        ]
        # Replace the ListView widget and rebuild the RichLog in a
        # single batch so the screen doesn't flicker mid-rebuild.
        items = self._build_comment_items()
        initial = len(items) - 1 if scroll_to_end and items else 0
        new_lv = ListView(*items, id='comment-list', initial_index=initial)
        pane = self.query_one('#comment-list-pane', Vertical)
        old_lv = self.query_one('#comment-list', ListView)
        with self.app.batch_update():
            await old_lv.remove()
            await pane.mount(new_lv)
            self._populate_richlog()
            new_lv.focus()

    def _get_comment_colour(self, comment: Comment) -> str:
        """Get the colour for a comment based on sender."""
        from_hdr = parse_comment_header(comment.text, 'From')
        if from_hdr:
            _name, addr = email.utils.parseaddr(from_hdr)
            if addr and addr in self._colour_map:
                return self._colour_map[addr]
        # Fall back to git-bug identity email
        if comment.author.email in self._colour_map:
            return self._colour_map[comment.author.email]
        return self._ts.get('accent', 'cyan')

    def _render_comment_panel(
        self, viewer: RichLog, comment: Comment, idx: int,
        depth: int = 0,
    ) -> None:
        """Render a comment as a bordered panel in the review app style."""
        text = comment.text
        if '\n\n' in text:
            header_block, body = text.split('\n\n', 1)
        else:
            header_block, body = text, ''

        colour = self._get_comment_colour(comment)
        bg = f"on {self._ts['panel']}" if self._ts.get('panel') else 'on grey11'

        # Extract sender name for panel title
        from_hdr = parse_comment_header(text, 'From')
        if from_hdr:
            sender_name, _addr = email.utils.parseaddr(from_hdr)
            if not sender_name:
                sender_name = from_hdr
        else:
            sender_name = comment.author.name

        title_text = Text()
        title_text.append(sender_name)
        title_text.append('  \u21a9', style='dim')  # ↩ reply arrow

        # Build body content
        body_text = Text()
        # Headers inside the panel (skip In-Reply-To, shorten Message-ID)
        for line in header_block.splitlines():
            colon = line.find(':')
            if colon > 0:
                hdr_name = line[:colon]
                hdr_val = line[colon + 1:].strip()
                if hdr_name == 'In-Reply-To':
                    continue
                if hdr_name == 'Message-ID':
                    hdr_name = 'Msgid'
                    if not hdr_val.startswith('<'):
                        hdr_val = f'<{hdr_val}>'
                body_text.append(f'{hdr_name}:', style='bold')
                body_text.append(f' {hdr_val}')
            else:
                body_text.append(line)
            body_text.append('\n')
        if body.strip():
            body_text.append('\n')

        # Body with quote highlighting
        accent = self._ts.get('accent', 'cyan')
        for line in body.splitlines():
            if line.startswith('>'):
                body_text.append(line, style=f'dim {accent}')
            else:
                body_text.append(line)
            body_text.append('\n')

        # Trim trailing whitespace to avoid a blank line at the bottom
        body_text.rstrip()

        panel = Panel(
            body_text,
            box=box.ROUNDED,
            border_style=colour,
            title=title_text,
            title_align='left',
            expand=True,
            padding=(0, 1),
            style=bg,
        )
        if depth > 0:
            from rich.padding import Padding
            viewer.write(Padding(panel, pad=(0, 0, 0, depth * 2)))
        else:
            viewer.write(panel)

    def on_click(self, event: Click) -> None:
        """Detect clicks on comment headers (↩ arrow) to trigger a reply."""
        try:
            viewer = self.query_one('#detail-log', RichLog)
        except Exception:
            return
        region = viewer.content_region
        if not region.contains(event.screen_x, event.screen_y):
            return
        content_line = int(viewer.scroll_y) + (event.screen_y - region.y)
        if not self._header_line_map:
            return
        comment_idx = self._header_line_map.get(content_line)
        if comment_idx is not None:
            lv = self.query_one('#comment-list', ListView)
            lv.index = comment_idx
            self.action_reply()
            event.stop()

    def on_mouse_scroll_down(self, event: MouseScrollDown) -> None:
        self.call_after_refresh(self._sync_highlight_from_scroll)

    def on_mouse_scroll_up(self, event: MouseScrollUp) -> None:
        self.call_after_refresh(self._sync_highlight_from_scroll)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if isinstance(event.item, CommentItem):
            self._scroll_to_comment(event.item.comment_idx)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        # Same as highlighted — scroll to the comment
        if isinstance(event.item, CommentItem):
            pos = self._comment_positions.get(event.item.comment_idx)
            if pos is not None:
                viewer = self.query_one('#detail-log', RichLog)
                viewer.scroll_to(y=pos, animate=False)

    def action_page_down(self) -> None:
        viewer = self.query_one('#detail-log', RichLog)
        viewer.scroll_page_down()
        self.call_after_refresh(self._sync_highlight_from_scroll)

    def action_page_up(self) -> None:
        viewer = self.query_one('#detail-log', RichLog)
        viewer.scroll_page_up()
        self.call_after_refresh(self._sync_highlight_from_scroll)

    def _is_viewer_focused(self) -> bool:
        viewer = self.query_one('#detail-log', RichLog)
        return viewer.has_focus

    def _move_comment(self, delta: int) -> None:
        lv = self.query_one('#comment-list', ListView)
        if lv.index is None:
            return
        new_idx = lv.index + delta
        if 0 <= new_idx < len(lv.children):
            lv.index = new_idx

    def on_key(self, event: 'Key') -> None:
        if event.character in ('j', 'k'):
            event.stop()
            event.prevent_default()
            if self._is_viewer_focused():
                # Viewer focused: scroll the viewer line-by-line
                viewer = self.query_one('#detail-log', RichLog)
                if event.character == 'j':
                    viewer.scroll_down()
                else:
                    viewer.scroll_up()
                self.call_after_refresh(self._sync_highlight_from_scroll)
            else:
                # Default: move comment cursor and scroll right pane
                self._move_comment(1 if event.character == 'j' else -1)
        elif event.character == '.':
            event.stop()
            event.prevent_default()
            self._move_comment(1)
        elif event.character == ',':
            event.stop()
            event.prevent_default()
            self._move_comment(-1)

    def _scroll_to_comment(self, idx: int) -> None:
        pos = self._comment_positions.get(idx)
        if pos is not None:
            viewer = self.query_one('#detail-log', RichLog)
            viewer.scroll_to(y=pos, animate=False)

    def _sync_highlight_from_scroll(self) -> None:
        """Update left pane selection to match the right pane scroll position."""
        viewer = self.query_one('#detail-log', RichLog)
        scroll_pos = int(viewer.scroll_y)
        # Select the comment whose panel header is in the upper third
        # of the viewport. This feels natural: once a comment's header
        # is well into view, it becomes the active comment.
        threshold = scroll_pos + viewer.content_region.height // 3
        best_real_idx: Optional[int] = None
        for real_idx in self._visible_indices:
            pos = self._comment_positions.get(real_idx)
            if pos is not None and pos <= threshold:
                best_real_idx = real_idx
        if best_real_idx is None:
            return
        # Map real comment index to ListView position
        lv = self.query_one('#comment-list', ListView)
        for lv_idx, child in enumerate(lv.children):
            if isinstance(child, CommentItem) and child.comment_idx == best_real_idx:
                if lv.index != lv_idx:
                    lv.index = lv_idx
                break

    def action_comment(self) -> None:
        """Open editor for an internal comment on this bug."""
        template = (
            '<!-- Add a comment to bug %s\n'
            '     This comment will be stored in the git-bug database and\n'
            '     visible to anyone with access to this repository.\n'
            '     It will NOT be sent to the reporter via email.\n'
            '     Use "reply" to communicate with the reporter.\n'
            '     Everything between these markers will be removed. -->\n'
            '\n'
        ) % self.bug.id[:7]
        with self.app.suspend():
            try:
                result = b4.edit_in_editor(
                    template.encode(), filehint='bug-comment.md',
                )
            except Exception as exc:
                logger.critical('Editor error: %s', exc)
                return
        # Strip HTML comments and check if anything remains
        import re
        text = result.decode(errors='replace')
        text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL).strip()
        if not text:
            self.notify('No comment added (empty or unchanged)')
            return
        app = self.app
        if not isinstance(app, BugListApp):
            return
        app.repo.add_comment(self.bug.id, text)
        app.repo.invalidate(self.bug.id)
        self._refresh_bug_view(scroll_to_end=True)

    def _get_selected_comment(self) -> Optional[Comment]:
        """Return the currently selected comment, or None."""
        lv = self.query_one('#comment-list', ListView)
        if lv.highlighted_child is not None and isinstance(
            lv.highlighted_child, CommentItem,
        ):
            idx = lv.highlighted_child.comment_idx
            if idx < len(self.bug.comments):
                return self.bug.comments[idx]
        return None

    def action_reply(self) -> None:
        """Reply to the selected comment via email."""
        comment = self._get_selected_comment()
        if comment is None:
            return

        # Get message-id from comment — required for reply
        msgid = parse_comment_header(comment.text, 'Message-ID')
        if not msgid:
            self.notify('No Message-ID in this comment, cannot reply',
                        severity='warning')
            return

        # Fetch the original message from lore
        self.notify('Fetching original message from lore...')

        def _fetch_and_reply() -> None:
            self._do_reply(comment, msgid.strip('<>'))

        self.run_worker(_fetch_and_reply, name='reply_fetch', thread=True)

    def _do_reply(self, comment: Comment, msgid: str) -> None:
        """Fetch the original message and compose a reply."""
        # Determine if this bug uses --no-parent scope
        scope = parse_comment_header(
            self.bug.comments[0].text, 'X-B4-Bug-Scope',
        )
        root_msgid = parse_comment_header(
            self.bug.comments[0].text, 'Message-ID',
        )
        if not root_msgid:
            root_msgid = msgid

        # Fetch thread from lore
        fetch_id = root_msgid.strip('<>')
        with _quiet_worker():
            msgs = b4.get_pi_thread_by_msgid(fetch_id)
        if not msgs:
            self.app.call_from_thread(
                self.notify, 'Could not retrieve thread from lore',
                severity='error',
            )
            return

        # Apply --no-parent filter if applicable
        if scope == 'no-parent':
            filtered = b4.get_strict_thread(
                msgs, fetch_id, noparent=True,
            )
            if filtered:
                msgs = filtered

        # Find the specific message we're replying to
        target_msg = None
        clean_msgid = msgid.strip('<>')
        for msg in msgs:
            raw_mid = msg.get('Message-ID', '')
            mid = b4.LoreMessage.clean_header(raw_mid).strip('<>')
            if mid == clean_msgid:
                target_msg = msg
                break

        if target_msg is None:
            self.app.call_from_thread(
                self.notify, f'Message {msgid} not found in thread',
                severity='error',
            )
            return

        # Build the reply
        lmsg = b4.LoreMessage(target_msg)
        # Build quoted body
        body, _charset = b4.LoreMessage.get_payload(target_msg)
        date_hdr = parse_comment_header(comment.text, 'Date') or ''
        from_hdr = parse_comment_header(comment.text, 'From') or ''
        name, _addr = email.utils.parseaddr(from_hdr)
        if not name:
            name = from_hdr

        attribution = f'On {date_hdr}, {name} wrote:\n'
        quoted = '\n'.join(f'> {line}' for line in body.splitlines())
        reply_text = f'{attribution}{quoted}\n\n'

        # Add signature
        sig = b4.get_email_signature()
        if sig:
            reply_text = reply_text.rstrip('\n') + '\n\n-- \n' + sig

        # Schedule the editor open on the main thread
        self.app.call_from_thread(
            self._open_reply_editor, lmsg, reply_text,
        )

    def _open_reply_editor(self, lmsg: 'b4.LoreMessage',
                           reply_text: str) -> None:
        """Open editor and show preview (runs on main thread)."""
        self._reply_edit_loop(lmsg, reply_text)

    def _reply_edit_loop(self, lmsg: 'b4.LoreMessage',
                         reply_text: str,
                         is_reedit: bool = False) -> None:
        with self.app.suspend():
            try:
                result = b4.edit_in_editor(
                    reply_text.encode(), filehint='reply.eml',
                )
            except Exception as exc:
                logger.critical('Editor error: %s', exc)
                return

        edited = result.decode(errors='replace')
        if edited.strip() == reply_text.strip() and not is_reedit:
            self.notify('Reply unchanged, not sent')
            return

        # Use the edited text (or unchanged on re-edit)
        final_text = edited

        # Build the full email message
        reply_msg = lmsg.make_reply(final_text)

        def _on_preview(action: Optional[str]) -> None:
            if action == 'send':
                self._send_reply(reply_msg)
            elif action == 'edit':
                self._reply_edit_loop(lmsg, final_text, is_reedit=True)

        self.app.push_screen(
            ReplyPreviewScreen(reply_msg), callback=_on_preview,
        )

    def _send_reply(self, msg: 'email.message.EmailMessage') -> None:
        app = self.app
        if not isinstance(app, BugListApp):
            return
        dryrun = app.email_dryrun
        patatt_sign = app.patatt_sign
        with app.suspend():
            try:
                smtp, fromaddr = b4.get_smtp(dryrun=dryrun)
                sent = b4.send_mail(
                    smtp, [msg],
                    fromaddr=fromaddr,
                    patatt_sign=patatt_sign,
                    dryrun=dryrun,
                )
            except Exception as exc:
                self.notify(f'Send failed: {exc}', severity='error')
                return
        if sent is None:
            self.notify('Failed to send reply', severity='error')
            return
        if dryrun:
            self.notify('Dry-run: reply logged, not sent')
        else:
            self.notify('Reply sent')
        # Record the reply as a comment on the bug
        from b4.bugs._import import format_comment
        comment_text = format_comment(msg)
        app.repo.add_comment(self.bug.id, comment_text)
        app.repo.invalidate(self.bug.id)
        self._refresh_bug_view(scroll_to_end=True)

    def _refresh_bug_view(self, scroll_to_end: bool = False) -> None:
        """Reload the bug from the repo and rebuild both panes."""
        app = self.app
        if isinstance(app, BugListApp):
            app.repo.invalidate(self.bug.id)
            self.bug = app.repo.get_bug(self.bug.id)
        # Run the async rebuild so the ListView replacement (which
        # requires await) happens cleanly in the event loop.
        self.run_worker(
            self._rebuild_panes(scroll_to_end=scroll_to_end),
            name='rebuild_panes',
        )

    def action_remove_comment(self) -> None:
        """Tombstone the selected comment."""
        comment = self._get_selected_comment()
        if comment is None:
            return

        def _on_confirm(confirmed: bool | None) -> None:
            if not confirmed:
                return
            app = self.app
            if not isinstance(app, BugListApp):
                return
            usercfg = b4.get_user_config()
            identity = (f'{usercfg.get("name", "Unknown")} '
                        f'<{usercfg.get("email", "unknown")}>')
            tombstone = make_tombstone(comment.text, identity)
            app.repo.edit_comment(self.bug.id, comment.id, tombstone)
            self._refresh_bug_view()

        from_hdr = parse_comment_header(comment.text, 'From')
        sender = from_hdr or comment.author.name
        self.app.push_screen(
            ConfirmScreen(
                title='Remove comment?',
                body=[f'From: {sender}',
                      'The comment body will be permanently removed.'],
                border='$warning',
            ),
            callback=_on_confirm,
        )

    def action_edit_title(self) -> None:
        """Edit the bug title."""
        def _on_result(new_title: Optional[str]) -> None:
            if not new_title:
                return
            app = self.app
            if not isinstance(app, BugListApp):
                return
            app.repo.set_title(self.bug.id, new_title)
            app.repo.invalidate(self.bug.id)
            self.bug = app.repo.get_bug(self.bug.id)
            # Update the header
            header = Text()
            header.append(f'{self.bug.id[:7]} ', style='bold')
            header.append(self.bug.title, style='bold')
            self.query_one('#detail-header', Static).update(header)

        self.app.push_screen(
            EditTitleScreen(self.bug.title), callback=_on_result,
        )

    def action_bug_action(self) -> None:
        """Show lifecycle action menu for the current bug."""
        actions = BugListApp._build_actions(self.bug)

        def _on_result(action: Optional[str]) -> None:
            if action is None:
                return
            app = self.app
            if not isinstance(app, BugListApp):
                return
            bid = self.bug.id
            if action == 'delete':
                def _on_delete(confirmed: bool | None) -> None:
                    if not confirmed:
                        return
                    app.repo.remove_bug(bid)
                    app.repo.invalidate()
                    self.dismiss(None)
                self.app.push_screen(
                    ConfirmScreen(
                        title='Delete bug?',
                        subject=f'{bid[:7]}: {self.bug.title}',
                        body=[],
                        border='$error',
                    ),
                    callback=_on_delete,
                )
                return
            if action == 'duplicate':
                def _on_dup(target_id: Optional[str]) -> None:
                    if not target_id:
                        return
                    target = app.repo.get_bug(target_id)
                    app.repo.add_comment(
                        bid,
                        f'Closing as duplicate of {target.id[:7]}: '
                        f'{target.title}',
                    )
                    for lb in self.bug.labels:
                        if lb.startswith('lifecycle:'):
                            app.repo.remove_label(bid, lb)
                    app.repo.add_label(bid, 'lifecycle:duplicate')
                    app.repo.set_status(bid, Status.CLOSED)
                    app.repo.invalidate()
                    self.dismiss(None)
                self.app.push_screen(
                    DuplicateScreen(app.repo, self.bug),
                    callback=_on_dup,
                )
                return
            if action == 'reopen':
                app.repo.set_status(bid, Status.OPEN)
                for lb in self.bug.labels:
                    if lb.startswith('lifecycle:'):
                        app.repo.remove_label(bid, lb)
            elif action in _LIFECYCLE_SYMBOLS:
                for lb in self.bug.labels:
                    if lb.startswith('lifecycle:'):
                        app.repo.remove_label(bid, lb)
                app.repo.add_label(bid, f'lifecycle:{action}')
                if action in BugListApp._CLOSING_STATES:
                    app.repo.set_status(bid, Status.CLOSED)
            app.repo.invalidate()
            # Closing/deleting: return to list. Otherwise refresh detail.
            if action in BugListApp._CLOSING_STATES or action == 'reopen':
                self.dismiss(None)
            else:
                self._refresh_bug_view()

        self.app.push_screen(
            ActionScreen(actions, shortcuts=_ACTION_SHORTCUTS),
            callback=_on_result)

    def action_back(self) -> None:
        self.dismiss(None)


class ReplyPreviewScreen(ModalScreen[Optional[str]]):
    """Preview a reply email before sending.

    Returns 'send' to send, 'edit' to re-edit, or None to abandon.
    """

    DEFAULT_CSS = '''
    ReplyPreviewScreen {
        background: $surface;
    }
    #reply-preview-header {
        height: auto;
        padding: 0 1;
        background: $primary-darken-2;
        color: $text;
    }
    #reply-preview-log {
        height: 1fr;
        padding: 0 1;
    }
    #reply-preview-hint {
        height: 1;
        padding: 0 1;
        color: $text-muted;
    }
    '''

    BINDINGS = [
        Binding('S', 'send', 'Send'),
        Binding('e', 'edit', 'edit'),
        Binding('t', 'edit_tocc', 'To/Cc'),
        Binding('j', 'scroll_down', 'down', show=False),
        Binding('k', 'scroll_up', 'up', show=False),
        Binding('space', 'page_down', 'pgdn', show=False),
        Binding('backspace', 'page_up', 'pgup', show=False),
        Binding('escape', 'cancel', 'cancel'),
        Binding('q', 'cancel', 'cancel', show=False),
    ]

    def __init__(self, msg: 'email.message.EmailMessage') -> None:
        super().__init__()
        self._msg = msg

    def compose(self) -> ComposeResult:
        yield Static('Reply preview', id='reply-preview-header')
        yield RichLog(id='reply-preview-log', wrap=True, markup=False)
        yield Static(
            Text('S send  |  e edit body  |  t To/Cc  |  Escape abandon'),
            id='reply-preview-hint',
        )
        yield SeparatedFooter()

    def on_mount(self) -> None:
        viewer = self.query_one('#reply-preview-log', RichLog)
        app = self.app
        ts: dict[str, str] = {}
        if isinstance(app, BugListApp):
            ts = app._ts
        # Render email headers
        for hdr in ('From', 'To', 'Cc', 'Subject', 'In-Reply-To'):
            val = self._msg.get(hdr)
            if val:
                hdr_text = Text()
                hdr_text.append(f'{hdr}:', style='bold')
                hdr_text.append(f' {b4.LoreMessage.clean_header(val)}')
                viewer.write(hdr_text)
        viewer.write(Text(''))
        # Render body
        body, _charset = b4.LoreMessage.get_payload(self._msg)
        accent = ts.get('accent', 'cyan')
        for line in body.splitlines():
            if line.startswith('>'):
                viewer.write(Text(line, style=f'dim {accent}'))
            else:
                viewer.write(Text(line))

    def _rerender(self) -> None:
        """Re-render the preview after header changes."""
        viewer = self.query_one('#reply-preview-log', RichLog)
        viewer.clear()
        self.on_mount()

    def action_edit_tocc(self) -> None:
        from b4.tui import ToCcScreen
        to_val = b4.LoreMessage.clean_header(self._msg.get('To', ''))
        cc_val = b4.LoreMessage.clean_header(self._msg.get('Cc', ''))
        screen = ToCcScreen(to_val, cc_val, '', show_apply_all=False)

        def _on_result(saved: bool | None) -> None:
            if not saved:
                return
            del self._msg['To']
            del self._msg['Cc']
            if screen.to_result:
                self._msg['To'] = screen.to_result
            if screen.cc_result:
                self._msg['Cc'] = screen.cc_result
            self._rerender()

        self.app.push_screen(screen, callback=_on_result)

    def action_send(self) -> None:
        self.dismiss('send')

    def action_edit(self) -> None:
        self.dismiss('edit')

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_scroll_down(self) -> None:
        self.query_one('#reply-preview-log', RichLog).scroll_down()

    def action_scroll_up(self) -> None:
        self.query_one('#reply-preview-log', RichLog).scroll_up()

    def action_page_down(self) -> None:
        self.query_one('#reply-preview-log', RichLog).scroll_page_down()

    def action_page_up(self) -> None:
        self.query_one('#reply-preview-log', RichLog).scroll_page_up()



class LabelOption(ListItem):
    """A toggleable label option in the label selection dialog."""

    def __init__(self, label_name: str, initially_selected: bool = False) -> None:
        super().__init__()
        self.label_name = label_name
        self.selected = initially_selected

    def compose(self) -> ComposeResult:
        from textual.widgets import Label
        mark = 'x' if self.selected else ' '
        text = Text()
        text.append(f'[{mark}] ')
        text.append('\u25a0 ', style=label_color(self.label_name))
        text.append(self.label_name)
        yield Label(text)

    def toggle(self) -> None:
        self.selected = not self.selected
        from textual.widgets import Label
        mark = 'x' if self.selected else ' '
        text = Text()
        text.append(f'[{mark}] ')
        text.append('\u25a0 ', style=label_color(self.label_name))
        text.append(self.label_name)
        self.query_one(Label).update(text)


class LabelScreen(JKListNavMixin, ModalScreen[Optional[dict[str, list[str]]]]):
    """Toggle labels on/off, like the trailer selector.

    Shows all known labels in the project. Labels already on the bug
    are pre-checked. Press ``a`` to add a brand-new label.

    Returns ``{'add': [...], 'remove': [...]}`` on confirm, or
    None on cancel.
    """

    _list_id = '#label-list'

    DEFAULT_CSS = '''
    LabelScreen {
        align: center middle;
    }
    #label-dialog {
        width: 50;
        height: auto;
        max-height: 70%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #label-list {
        height: auto;
        max-height: 20;
    }
    #label-hint {
        margin-top: 1;
        color: $text-muted;
    }
    '''

    BINDINGS = [
        Binding('space', 'toggle_item', 'Toggle', show=False),
        Binding('j', 'cursor_down', 'Down', show=False),
        Binding('k', 'cursor_up', 'Up', show=False),
        Binding('a', 'add_new', 'add new'),
        Binding('enter', 'confirm', 'Save'),
        Binding('escape', 'cancel', 'Cancel'),
        Binding('q', 'cancel', 'Cancel', show=False),
    ]

    def __init__(
        self, current_labels: set[str] | frozenset[str],
        suggestions: list[str],
    ) -> None:
        super().__init__()
        self._current = sorted(
            lb for lb in current_labels if not lb.startswith('lifecycle:')
        )
        self._suggestions = suggestions

    def compose(self) -> ComposeResult:
        items = [
            LabelOption(lb, initially_selected=True)
            for lb in self._current
        ]
        with Vertical(id='label-dialog') as dialog:
            dialog.border_title = 'Select labels'
            if not items:
                yield Static('(no labels)', id='label-empty')
                yield ListView(*items, id='label-list')
                yield Static(
                    Text('[a] add new  |  Escape cancel'),
                    id='label-hint',
                )
            else:
                yield ListView(*items, id='label-list')
                yield Static(
                    Text('space toggle  |  [a] add new  |  Enter save  |  Escape cancel'),
                    id='label-hint',
                )

    def on_mount(self) -> None:
        self.query_one('#label-list', ListView).focus()

    def action_toggle_item(self) -> None:
        lv = self.query_one('#label-list', ListView)
        if lv.highlighted_child is not None and isinstance(
            lv.highlighted_child, LabelOption,
        ):
            lv.highlighted_child.toggle()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Enter on ListView fires Selected — use it to confirm."""
        event.stop()
        self._do_confirm()

    def _update_hint(self) -> None:
        lv = self.query_one('#label-list', ListView)
        has_items = len(lv.children) > 0
        hint = self.query_one('#label-hint', Static)
        if has_items:
            hint.update(Text('space toggle  |  [a] add new  |  Enter save  |  Escape cancel'))
        else:
            hint.update(Text('[a] add new  |  Escape cancel'))

    def action_add_new(self) -> None:
        def _on_added(label: Optional[str]) -> None:
            if label:
                lv = self.query_one('#label-list', ListView)
                # Don't add duplicates
                for child in lv.children:
                    if isinstance(child, LabelOption) and child.label_name == label:
                        child.selected = True
                        child.toggle()  # Force visual refresh
                        child.toggle()
                        return
                opt = LabelOption(label, initially_selected=True)
                lv.append(opt)
                lv.index = len(lv.children) - 1
                lv.focus()
                self._update_hint()
        self.app.push_screen(
            AddLabelScreen(self._suggestions),
            callback=_on_added,
        )

    def action_confirm(self) -> None:
        self._do_confirm()

    def _do_confirm(self) -> None:
        add: list[str] = []
        remove: list[str] = []
        current_set = set(self._current)
        lv = self.query_one('#label-list', ListView)
        for child in lv.children:
            if not isinstance(child, LabelOption):
                continue
            if child.selected and child.label_name not in current_set:
                add.append(child.label_name)
            elif not child.selected and child.label_name in current_set:
                remove.append(child.label_name)
        if add or remove:
            self.dismiss({'add': add, 'remove': remove})
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class AddLabelScreen(ModalScreen[Optional[str]]):
    """Text input for adding a brand-new label, with suggestions."""

    DEFAULT_CSS = '''
    AddLabelScreen {
        align: center middle;
    }
    #addlabel-dialog {
        width: 50;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    '''

    BINDINGS = [
        Binding('escape', 'cancel', 'cancel'),
    ]

    def __init__(self, suggestions: list[str]) -> None:
        super().__init__()
        self._suggestions = suggestions

    def compose(self) -> ComposeResult:
        suggester = (
            SuggestFromList(self._suggestions, case_sensitive=False)
            if self._suggestions else None
        )
        with Vertical(id='addlabel-dialog') as dialog:
            dialog.border_title = 'Add label'
            yield Input(
                placeholder='Label name',
                id='addlabel-input',
                suggester=suggester,
            )

    def on_mount(self) -> None:
        self.query_one('#addlabel-input', Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        if value:
            self.dismiss(value)

    def action_cancel(self) -> None:
        self.dismiss(None)


# Shortcut keys for the bug action selector.
_ACTION_SHORTCUTS: dict[str, str] = {
    'confirmed':  'c',
    'needinfo':   'n',
    'worksforme': 'w',
    'wontfix':    'x',
    'fixed':      'f',
    'duplicate':  'd',
    'reopen':     'r',
    'delete':     'D',
}


class UpdateBugsScreen(ModalScreen[Optional[dict[str, int]]]):
    """Modal showing progress while updating bugs from lore."""

    DEFAULT_CSS = '''
    UpdateBugsScreen {
        align: center middle;
    }
    #update-dialog {
        width: 70;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #update-status {
        margin-top: 1;
    }
    #update-bug {
        margin-top: 1;
        color: $text-muted;
    }
    '''

    BINDINGS = [
        Binding('escape', 'cancel', 'cancel'),
        Binding('q', 'cancel', 'cancel', show=False),
    ]

    def __init__(self, bugs: list[BugLike], repo: GitBugRepo) -> None:
        super().__init__()
        self._bugs = bugs
        self._repo = repo
        self._cancelled = False
        self._result: dict[str, int] = {
            'checked': 0, 'updated': 0, 'new_comments': 0,
        }

    def compose(self) -> ComposeResult:
        from textual.widgets import Label, ProgressBar
        count = len(self._bugs)
        title = f'Updating {count} bug(s)' if count > 1 else 'Updating bug'
        with Vertical(id='update-dialog') as dialog:
            dialog.border_title = title
            yield Label(
                f'Checking 0/{count} bugs...',
                id='update-status',
            )
            yield Label('', id='update-bug', markup=False)
            yield ProgressBar(
                total=count, show_eta=False, id='update-progress',
            )

    def on_mount(self) -> None:
        self.run_worker(
            self._do_updates, name='_do_updates', thread=True,
        )

    def _update_progress(self, completed: int, title: str) -> None:
        from textual.widgets import Label, ProgressBar
        count = len(self._bugs)
        self.query_one('#update-status', Label).update(
            f'Checking {completed}/{count} bugs...',
        )
        self.query_one('#update-bug', Label).update(title)
        self.query_one('#update-progress', ProgressBar).progress = completed

    def _do_updates(self) -> dict[str, int]:
        from b4.bugs._import import refresh_bug
        with _quiet_worker():
            for i, bug in enumerate(self._bugs):
                if self._cancelled:
                    break
                self.app.call_from_thread(
                    self._update_progress, i, bug.title,
                )
                try:
                    count = refresh_bug(self._repo, bug.id)
                except Exception:
                    count = 0
                self._result['checked'] += 1
                if count > 0:
                    self._result['updated'] += 1
                    self._result['new_comments'] += count
                self.app.call_from_thread(
                    self._update_progress, i + 1, bug.title,
                )
        return self._result

    async def on_worker_state_changed(
        self, event: Worker.StateChanged,
    ) -> None:
        if event.worker.name != '_do_updates':
            return
        if event.state == WorkerState.SUCCESS:
            self.dismiss(event.worker.result)
        elif event.state == WorkerState.ERROR:
            self.dismiss(self._result)

    def action_cancel(self) -> None:
        self._cancelled = True


class DuplicateScreen(ModalScreen[Optional[str]]):
    """Prompt for the bug ID that this bug duplicates.

    Returns the resolved bug ID on confirm, or None on cancel.
    """

    DEFAULT_CSS = '''
    DuplicateScreen {
        align: center middle;
    }
    #dup-dialog {
        width: 60;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #dup-status {
        height: auto;
        margin-top: 1;
        color: $text-muted;
    }
    '''

    BINDINGS = [
        Binding('escape', 'cancel', 'cancel'),
    ]

    def __init__(self, repo: GitBugRepo, this_bug: BugLike) -> None:
        super().__init__()
        self._repo = repo
        self._this_bug = this_bug

    def compose(self) -> ComposeResult:
        with Vertical(id='dup-dialog') as dialog:
            dialog.border_title = 'Close as duplicate of'
            yield Input(placeholder='Bug ID', id='dup-input')
            yield Static('Enter confirm  |  Escape cancel',
                         id='dup-status')

    def on_mount(self) -> None:
        self.query_one('#dup-input', Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        if not value:
            return
        status = self.query_one('#dup-status', Static)
        try:
            bid = self._repo.resolve_bug_id(value)
        except Exception:
            status.update(f'Bug not found: {value}')
            return
        if bid == self._this_bug.id:
            status.update('A bug cannot be a duplicate of itself')
            return
        target = self._repo.get_bug(bid)
        status.update(f'{target.id[:7]}: {target.title}')
        self.dismiss(bid)

    def action_cancel(self) -> None:
        self.dismiss(None)


class EditTitleScreen(ModalScreen[Optional[str]]):
    """Edit a bug's title."""

    DEFAULT_CSS = '''
    EditTitleScreen {
        align: center middle;
    }
    #edit-title-dialog {
        width: 72;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #edit-title-hint {
        margin-top: 1;
        color: $text-muted;
    }
    '''

    BINDINGS = [
        Binding('escape', 'cancel', 'cancel'),
    ]

    def __init__(self, current_title: str) -> None:
        super().__init__()
        self._current_title = current_title

    def compose(self) -> ComposeResult:
        with Vertical(id='edit-title-dialog') as dialog:
            dialog.border_title = 'Edit title'
            yield Input(value=self._current_title, id='edit-title-input')
            yield Static('Enter save  |  Escape cancel',
                         id='edit-title-hint')

    def on_mount(self) -> None:
        self.query_one('#edit-title-input', Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        value = event.value.strip()
        if value and value != self._current_title:
            self.dismiss(value)
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


# -- Main app ----------------------------------------------------------------

class BugListApp(JKListNavMixin, App[None]):
    """Bug management TUI backed by git-bug via ezgb."""

    TITLE = 'b4 bugs'

    _list_id = '#bug-list'

    DEFAULT_CSS = '''
    BugListApp {
        layout: vertical;
    }
    #title-bar {
        dock: top;
        width: 100%;
        height: 1;
        background: $primary-darken-2;
        color: $text;
        padding: 0 1;
    }
    BugListApp:ansi #title-bar {
        background: ansi_bright_black;
        color: ansi_default;
        text-style: bold;
    }
    #column-header {
        height: 1;
        color: $text-muted;
    }
    #bug-list {
        height: 1fr;
        min-height: 5;
    }
    #details-panel {
        dock: bottom;
        width: 100%;
        height: 0;
        background: $surface;
        border-top: solid $primary;
        padding: 0 1;
    }
    .details-row {
        height: 1;
    }
    .details-label {
        width: 14;
        text-style: bold;
    }
    '''

    BINDINGS = [
        Binding('j', 'cursor_down', 'down', show=False),
        Binding('k', 'cursor_up', 'up', show=False),
        # Bug-specific actions (left side)
        Binding('N', 'import_thread', 'New'),
        Binding('L', 'add_label', 'Label'),
        Binding('a', 'bug_action', 'action'),
        Binding('u', 'update_one', 'update'),
        # Global actions (right side, after divider)
        Binding('U', 'update_all', 'Update all'),
        Binding('p', 'pull', 'pull'),
        Binding('P', 'push', 'push'),
        Binding('l', 'limit', 'limit'),
        Binding('s', 'toggle_closed', 'show closed'),
        Binding('q', 'quit', 'quit'),
    ]

    BINDING_GROUPS = {
        'action_import_thread': 'bug',
        'action_add_label': 'bug',
        'action_bug_action': 'bug',
        'action_update_one': 'bug',
        'action_update_all': 'global',
        'action_pull': 'global',
        'action_push': 'global',
        'action_limit': 'global',
        'action_toggle_closed': 'global',
        'action_quit': 'global',
    }

    def __init__(self, repo: GitBugRepo, *,
                 email_dryrun: bool = False,
                 no_sign: bool = False) -> None:
        super().__init__()
        self.repo = repo
        self.email_dryrun = email_dryrun
        self.patatt_sign = not no_sign
        self._ts: dict[str, str] = {}
        self._all_bugs: list[BugLike] = []
        self._known_labels: list[str] = []
        self._limit_pattern: str = ''
        self._show_closed: bool = False
        self._focus_bug_id: str | None = None
        self._cache_mtime: float = 0.0

    def compose(self) -> ComposeResult:
        yield Static('b4 bugs', id='title-bar')
        header_text = f'{"ID":<7s}  {"Submitter":<20s}  {"Msgs":>4s}  {"S"}  {"Subject"}'
        yield Static(header_text, id='column-header')
        yield ListView(id='bug-list')
        with Vertical(id='details-panel'):
            with Horizontal(classes='details-row'):
                yield Static('Title:', classes='details-label')
                yield Static('', id='detail-title', markup=False)
            with Horizontal(classes='details-row'):
                yield Static('Status:', classes='details-label')
                yield Static('', id='detail-status', markup=False)
            with Horizontal(classes='details-row'):
                yield Static('Labels:', classes='details-label')
                yield Static('', id='detail-labels')
            with Horizontal(classes='details-row'):
                yield Static('Created:', classes='details-label')
                yield Static('', id='detail-created', markup=False)
            with Horizontal(classes='details-row'):
                yield Static('Last changed:', classes='details-label')
                yield Static('', id='detail-last-activity', markup=False)
            with Horizontal(classes='details-row'):
                yield Static('Comments:', classes='details-label')
                yield Static('', id='detail-comments', markup=False)
        yield SeparatedFooter()

    def _get_cache_path(self) -> str:
        """Return the path to git-bug's excerpt cache file."""
        topdir = self.repo._repo
        gitdir = topdir
        if os.path.isdir(os.path.join(topdir, '.git')):
            gitdir = os.path.join(topdir, '.git')
        return os.path.join(gitdir, 'git-bug', 'cache', 'bugs')

    def _snapshot_cache_mtime(self) -> None:
        """Record the current mtime of the git-bug cache file."""
        cache_path = self._get_cache_path()
        try:
            self._cache_mtime = os.path.getmtime(cache_path)
        except OSError:
            self._cache_mtime = 0.0

    def _check_cache_changed(self) -> None:
        """Poll the git-bug cache file for external changes."""
        cache_path = self._get_cache_path()
        try:
            current_mtime = os.path.getmtime(cache_path)
        except OSError:
            return
        if current_mtime != self._cache_mtime:
            self._cache_mtime = current_mtime
            self._save_focus()
            self.run_worker(self._load_bugs, name='load_bugs',
                            thread=True)

    def on_mount(self) -> None:
        self._ts = resolve_styles(self)
        self._snapshot_cache_mtime()
        self.run_worker(self._load_bugs, name='load_bugs', thread=True)
        self.set_interval(5.0, self._check_cache_changed)

    def _load_bugs(self) -> list[BugLike]:
        return list(self.repo.list_bug_summaries())

    @staticmethod
    def _matches_limit(bug: BugLike, pattern: str) -> bool:
        """Test whether *bug* matches the limit *pattern*.

        Tokens starting with ``s:`` filter by status (open/closed),
        ``l:`` by label substring. Bare tokens match the bug title.
        All tokens must match (AND logic).

        Note: ``s:`` in a limit pattern is an explicit status override
        that takes precedence over the show-closed toggle. The caller
        handles the default open-only filtering separately.
        """
        for token in pattern.lower().split():
            if token.startswith('s:'):
                needle = token[2:]
                status_str = 'open' if bug.status == Status.OPEN else 'closed'
                if needle not in status_str:
                    return False
            elif token.startswith('l:'):
                needle = token[2:]
                if not any(needle in lb.lower() for lb in bug.labels):
                    return False
            else:
                if token not in bug.title.lower():
                    return False
        return True

    @staticmethod
    def _has_status_token(pattern: str) -> bool:
        """Check if the limit pattern contains an explicit s: token."""
        return any(t.startswith('s:') for t in pattern.lower().split())

    def _update_title(self, count: int = 0) -> None:
        topdir = self.repo._repo
        name = os.path.basename(topdir.rstrip('/'))
        if self._show_closed:
            status = 'all'
        else:
            status = 'open'
        parts = [f'{name} \u2014 {count} bugs ({status})']
        if self._limit_pattern:
            parts.append(f'limit: {self._limit_pattern}')
        title_bar = self.query_one('#title-bar', Static)
        title_bar.update(Text(' '.join(parts)))
        title_bar.refresh()

    async def _refresh_list(self) -> None:
        display_bugs = self._all_bugs

        # Default: only open bugs, unless show_closed is on
        # or the limit pattern has an explicit s: token
        has_explicit_status = self._has_status_token(self._limit_pattern)
        if not self._show_closed and not has_explicit_status:
            display_bugs = [
                b for b in display_bugs if b.status == Status.OPEN
            ]

        if self._limit_pattern:
            display_bugs = [
                b for b in display_bugs
                if self._matches_limit(b, self._limit_pattern)
            ]

        # Sort: by last activity (newest first) within each tier,
        # then by tier (active → waiting → resolved).
        display_bugs.sort(
            key=_bug_last_activity, reverse=True,
        )
        display_bugs.sort(key=_bug_tier)

        self._update_title(len(display_bugs))

        items: list[BugListItem] = [BugListItem(bug) for bug in display_bugs]
        lv = ListView(*items, id='bug-list')

        with self.app.batch_update():
            old_lv = self.query_one('#bug-list', ListView)
            await old_lv.remove()
            await self.mount(lv, before=self.query_one('#details-panel', Vertical))

        # Restore cursor to previously focused bug
        if self._focus_bug_id:
            for idx, item in enumerate(items):
                if item.bug.id == self._focus_bug_id:
                    lv.index = idx
                    self._focus_bug_id = None
                    break
        lv.focus()

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.state != WorkerState.SUCCESS:
            return
        if event.worker.name == 'load_bugs':
            result = event.worker.result
            self._all_bugs = result if isinstance(result, list) else []
            # Collect all known labels across all bugs
            all_labels: set[str] = set()
            for bug in self._all_bugs:
                for lb in bug.labels:
                    if not lb.startswith('lifecycle:'):
                        all_labels.add(lb)
            self._known_labels = sorted(all_labels)
            self._snapshot_cache_mtime()
            await self._refresh_list()

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item is not None and isinstance(event.item, BugListItem):
            self._show_details(event.item.bug)

    def _show_details(self, bug: BugLike) -> None:
        panel = self.query_one('#details-panel', Vertical)

        self.query_one('#detail-title', Static).update(bug.title)

        lifecycle = ''
        for lb in bug.labels:
            if lb.startswith('lifecycle:'):
                lifecycle = lb[len('lifecycle:'):]
                break
        git_status = 'open' if bug.status == Status.OPEN else 'closed'
        if lifecycle:
            sym = _LIFECYCLE_SYMBOLS.get(lifecycle, '?')
            self.query_one('#detail-status', Static).update(
                f'{sym}  {lifecycle} ({git_status})',
            )
        else:
            sym = _bug_lifecycle(bug)
            self.query_one('#detail-status', Static).update(
                f'{sym}  {git_status}',
            )

        visible_labels = sorted(
            lb for lb in bug.labels if not lb.startswith('lifecycle:')
        )
        if visible_labels:
            label_text = Text()
            for lb in visible_labels:
                label_text.append('\u25a0 ', style=label_color(lb))
                label_text.append(f'{lb}  ')
            self.query_one('#detail-labels', Static).update(label_text)
        else:
            self.query_one('#detail-labels', Static).update('none')

        created_str = (
            f'{bug.created_at:%Y-%m-%d %H:%M} '
            f'({_relative_time(bug.created_at)})'
        )
        self.query_one('#detail-created', Static).update(created_str)

        if isinstance(bug, BugSummary):
            edited_str = (
                f'{bug.edited_at:%Y-%m-%d %H:%M} '
                f'({_relative_time(bug.edited_at)})'
            )
            self.query_one('#detail-last-activity', Static).update(edited_str)
            self.query_one('#detail-comments', Static).update(
                str(bug.comment_count),
            )
        elif bug.comments:
            last = bug.comments[-1]
            last_str = (
                f'{last.created_at:%Y-%m-%d %H:%M} '
                f'({_relative_time(last.created_at)}) '
                f'by {last.author.name}'
            )
            self.query_one('#detail-last-activity', Static).update(last_str)
            visible = sum(1 for c in bug.comments
                          if not is_comment_removed(c.text))
            self.query_one('#detail-comments', Static).update(
                str(visible),
            )
        else:
            self.query_one('#detail-last-activity', Static).update('none')
            self.query_one('#detail-comments', Static).update('0')

        # Expand panel if not already visible
        panel.styles.height = 'auto'

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, BugListItem):
            self._focus_bug_id = event.item.bug.id
            # Load full Bug on demand (CachedBug doesn't have comments)
            bug = self.repo.get_bug(event.item.bug.id)

            def _on_dismiss(_result: None) -> None:
                self.repo.invalidate()
                self._save_focus()
                self.run_worker(self._load_bugs, name='load_bugs',
                                thread=True)

            self.push_screen(BugDetailScreen(bug),
                             callback=_on_dismiss)

    # -- Actions -------------------------------------------------------------

    def _get_selected_bug(self) -> Optional[BugLike]:
        lv = self.query_one('#bug-list', ListView)
        if lv.highlighted_child is not None and isinstance(lv.highlighted_child, BugListItem):
            return lv.highlighted_child.bug
        return None

    def _save_focus(self) -> None:
        """Remember the currently selected bug for cursor restore."""
        bug = self._get_selected_bug()
        if bug:
            self._focus_bug_id = bug.id

    async def action_toggle_closed(self) -> None:
        self._save_focus()
        self._show_closed = not self._show_closed
        await self._refresh_list()

    def action_limit(self) -> None:
        self.push_screen(
            LimitScreen(self._limit_pattern,
                        hint='Prefixes: s:<status>  l:<label>',
                        title='Limit bugs'),
            callback=self._on_limit,
        )

    async def _on_limit(self, result: Optional[str]) -> None:
        if result is None:
            return
        self._save_focus()
        self._limit_pattern = result
        await self._refresh_list()

    def action_import_thread(self) -> None:
        self._save_focus()
        actions = [
            ('import', 'Import from lore thread'),
            ('create', 'Create new bug'),
        ]

        def _on_choice(choice: Optional[str]) -> None:
            if choice == 'import':
                self._do_import_from_lore()
            elif choice == 'create':
                self._do_create_new_bug()

        self.push_screen(
            ActionScreen(actions, shortcuts={'import': 'i', 'create': 'c'}),
            callback=_on_choice,
        )

    def _do_import_from_lore(self) -> None:
        def _on_result(result: Optional[str]) -> None:
            if result:
                self._focus_bug_id = result
                self.repo.invalidate()
                self.run_worker(self._load_bugs, name='load_bugs',
                                thread=True)
        self.push_screen(ImportScreen(), callback=_on_result)

    def _do_create_new_bug(self) -> None:
        template = (
            '<!-- Enter a new bug report.\n'
            '     First line = title, rest = description.\n'
            '     Everything between these markers will be removed. -->\n'
            '\n'
        )
        with self.suspend():
            try:
                result = b4.edit_in_editor(
                    template.encode(), filehint='new-bug.md',
                )
            except Exception as exc:
                logger.critical('Editor error: %s', exc)
                return
        import re
        text = result.decode(errors='replace')
        text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL).strip()
        if not text:
            self.notify('No bug created (empty or unchanged)')
            return
        lines = text.split('\n', 1)
        title = lines[0].strip()
        body = lines[1].strip() if len(lines) > 1 else ''
        if not title:
            self.notify('No bug created (empty title)')
            return
        bug = self.repo.create_bug(title, body)
        self._focus_bug_id = bug.id
        self.repo.invalidate()
        self.run_worker(self._load_bugs, name='load_bugs',
                        thread=True)

    def _on_update_complete(
        self, result: Optional[dict[str, int]],
    ) -> None:
        if result:
            updated = result.get('updated', 0)
            new_comments = result.get('new_comments', 0)
            checked = result.get('checked', 0)
            self.notify(
                f'Checked {checked} bug(s): {updated} updated, '
                f'{new_comments} new comment(s)',
            )
        self.repo.invalidate()
        self.run_worker(self._load_bugs, name='load_bugs', thread=True)

    def action_update_one(self) -> None:
        """Update the selected bug with new messages from lore."""
        bug = self._get_selected_bug()
        if not bug:
            return
        self._focus_bug_id = bug.id
        self.push_screen(
            UpdateBugsScreen([bug], self.repo),
            callback=self._on_update_complete,
        )

    def action_update_all(self) -> None:
        """Update all displayed bugs with new messages from lore."""
        self._save_focus()
        bugs = list(self._all_bugs)
        if not bugs:
            self.notify('No bugs to update')
            return
        self.push_screen(
            UpdateBugsScreen(bugs, self.repo),
            callback=self._on_update_complete,
        )

    def action_pull(self) -> None:
        """Pull bugs and identities from the remote."""
        self._save_focus()
        with self.suspend():
            print('Pulling bugs from remote...')
            rc, out, err = self.repo.pull()
            if out.strip():
                print(out)
            if err.strip():
                print(err)
            if rc != 0:
                print(f'Pull failed (exit code {rc})')
            else:
                print('Pull complete')
            _wait_for_enter()
        self.run_worker(self._load_bugs, name='load_bugs', thread=True)

    def action_push(self) -> None:
        """Push bugs and identities to the remote."""
        with self.suspend():
            print('Pushing bugs to remote...')
            rc, out, err = self.repo.push()
            if out.strip():
                print(out)
            if err.strip():
                print(err)
            if rc != 0:
                print(f'Push failed (exit code {rc})')
            else:
                print('Push complete')
            _wait_for_enter()

    def action_add_label(self) -> None:
        bug = self._get_selected_bug()
        if not bug:
            return

        def _on_result(result: Optional[dict[str, list[str]]]) -> None:
            if not result or not bug:
                return
            self._focus_bug_id = bug.id
            for lb in result.get('remove', []):
                self.repo.remove_label(bug.id, lb)
            for lb in result.get('add', []):
                self.repo.add_label(bug.id, lb)
            self.repo.invalidate()
            self.run_worker(self._load_bugs, name='load_bugs',
                            thread=True)

        self.push_screen(
            LabelScreen(bug.labels, self._known_labels),
            callback=_on_result,
        )

    @staticmethod
    def _build_actions(bug: BugLike) -> list[tuple[str, str]]:
        """Build context-sensitive action list for a bug.

        Actions are lifecycle-dependent. Closing a bug always
        requires a reason (worksforme, wontfix, fixed), shown
        under a "Close as:" heading.
        """
        if bug.status == Status.CLOSED:
            return [
                ('reopen', 'Reopen'),
                ('delete', 'Delete bug'),
            ]

        lifecycle = 'new'
        for lb in bug.labels:
            if lb.startswith('lifecycle:'):
                lifecycle = lb[len('lifecycle:'):]
                break

        actions: list[tuple[str, str]] = []
        if lifecycle == 'new':
            actions = [
                ('confirmed', 'Confirm'),
                ('needinfo', 'Need info'),
            ]
        elif lifecycle == 'confirmed':
            actions = [
                ('needinfo', 'Need info'),
            ]
        elif lifecycle == 'needinfo':
            actions = [
                ('confirmed', 'Confirm'),
            ]
        else:
            actions = [
                ('confirmed', 'Confirm'),
                ('needinfo', 'Need info'),
            ]
        # Close reasons are always available regardless of lifecycle
        actions.extend([
            ('fixed', 'Close: fixed'),
            ('worksforme', 'Close: works for me'),
            ('wontfix', "Close: won't fix"),
            ('duplicate', 'Close: duplicate of\u2026'),
        ])
        actions.append(('delete', 'Delete bug'))
        return actions

    def action_bug_action(self) -> None:
        bug = self._get_selected_bug()
        if not bug:
            return
        actions = self._build_actions(bug)

        def _on_result(action: Optional[str]) -> None:
            self._apply_action(bug, action)

        self.push_screen(ActionScreen(actions, shortcuts=_ACTION_SHORTCUTS),
                         callback=_on_result)

    # Lifecycle states that close the bug
    _CLOSING_STATES = {'worksforme', 'wontfix', 'fixed', 'duplicate'}

    def _apply_action(self, bug: BugLike, action: Optional[str]) -> None:
        if action is None:
            return

        if action == 'delete':
            self._confirm_delete(bug)
            return

        if action == 'duplicate':
            self._close_as_duplicate(bug)
            return

        self._focus_bug_id = bug.id
        bid = bug.id
        if action == 'reopen':
            self.repo.set_status(bid, Status.OPEN)
            for lb in bug.labels:
                if lb.startswith('lifecycle:'):
                    self.repo.remove_label(bid, lb)
        elif action in _LIFECYCLE_SYMBOLS:
            # Remove old lifecycle label, add new one
            for lb in bug.labels:
                if lb.startswith('lifecycle:'):
                    self.repo.remove_label(bid, lb)
            self.repo.add_label(bid, f'lifecycle:{action}')
            # Closing actions also close the bug
            if action in self._CLOSING_STATES:
                self.repo.set_status(bid, Status.CLOSED)

        self.repo.invalidate()
        self.run_worker(self._load_bugs, name='load_bugs', thread=True)

    def _confirm_delete(self, bug: BugLike) -> None:
        def _on_confirm(confirmed: bool | None) -> None:
            if confirmed and bug:
                self.repo.remove_bug(bug.id)
                self.repo.invalidate()
                self.run_worker(self._load_bugs, name='load_bugs',
                                thread=True)
        self.push_screen(
            ConfirmScreen(
                title='Delete bug?',
                subject=f'{bug.id[:7]}: {bug.title}',
                body=[],
                border='$error',
            ),
            callback=_on_confirm,
        )

    def _close_as_duplicate(self, bug: BugLike) -> None:
        def _on_result(target_id: Optional[str]) -> None:
            if not target_id:
                return
            self._focus_bug_id = bug.id
            bid = bug.id
            target = self.repo.get_bug(target_id)
            self.repo.add_comment(
                bid,
                f'Closing as duplicate of {target.id[:7]}: {target.title}',
            )
            for lb in bug.labels:
                if lb.startswith('lifecycle:'):
                    self.repo.remove_label(bid, lb)
            self.repo.add_label(bid, 'lifecycle:duplicate')
            self.repo.set_status(bid, Status.CLOSED)
            self.repo.invalidate()
            self.run_worker(self._load_bugs, name='load_bugs',
                            thread=True)

        self.push_screen(
            DuplicateScreen(self.repo, bug), callback=_on_result,
        )


