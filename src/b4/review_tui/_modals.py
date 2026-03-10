#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import email.message
import email.utils
import json
import re

from typing import Any, Dict, List, Optional, TYPE_CHECKING, Tuple

if TYPE_CHECKING:
    from textual.events import Key

import b4

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Checkbox, Input, Label, ListItem, ListView, LoadingIndicator, ProgressBar, RichLog, Select, Static, TextArea
from textual.screen import ModalScreen
from textual.suggester import SuggestFromList
from textual.worker import Worker, WorkerState
from rich import box
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from b4.review_tui._common import (
    CI_CHECK_LABELS, resolve_styles, ci_check_styles,
    JKListNavMixin, logger,
    _addrs_to_lines, _lines_to_header, _validate_addrs,
    _write_diff_line, _quiet_worker, _render_email_to_viewer,
)


class TrailerOption(ListItem):
    """A toggleable trailer option in the trailer selection dialog."""

    def __init__(self, trailer_name: str, initially_selected: bool = False) -> None:
        super().__init__()
        self.trailer_name = trailer_name
        self.selected = initially_selected

    def compose(self) -> ComposeResult:
        mark = 'x' if self.selected else ' '
        yield Label(f'[{mark}] {self.trailer_name}', markup=False)

    def toggle(self) -> None:
        self.selected = not self.selected
        mark = 'x' if self.selected else ' '
        lbl = self.query_one(Label)
        lbl.update(f'[{mark}] {self.trailer_name}')


class TrailerScreen(JKListNavMixin, ModalScreen[Optional[List[str]]]):
    """Modal screen to select trailer types with arrow navigation.

    Pre-toggles options that already have a matching trailer.
    Returns the full list of selected trailer names on confirm,
    or None on cancel (no changes).
    """

    _list_id = '#trailer-list'

    BINDINGS = [
        Binding('space', 'toggle_item', 'Toggle', show=False),
        Binding('j', 'cursor_down', 'Down', show=False),
        Binding('k', 'cursor_up', 'Up', show=False),
        Binding('q', 'confirm', 'Save'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    TrailerScreen {
        align: center middle;
    }
    #trailer-dialog {
        width: 44;
        height: 12;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #trailer-list {
        height: auto;
    }
    #trailer-hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

    TRAILER_NAMES = ['Acked-by', 'Reviewed-by', 'Tested-by', 'NACKed-by']

    def __init__(self, existing_trailers: List[str]) -> None:
        super().__init__()
        # Build a set of trailer name prefixes that are already present
        self._existing: set[str] = set()
        for t in existing_trailers:
            name = t.split(':', 1)[0].strip()
            for known in self.TRAILER_NAMES:
                if name.lower() == known.lower():
                    self._existing.add(known)

    def compose(self) -> ComposeResult:
        with Vertical(id='trailer-dialog'):
            yield Label('Select trailers:')
            yield ListView(
                *[TrailerOption(name, name in self._existing) for name in self.TRAILER_NAMES],
                id='trailer-list',
            )
            yield Static('Space toggle  |  Enter save', id='trailer-hint')

    def on_mount(self) -> None:
        self.query_one('#trailer-list', ListView).focus()

    def action_confirm(self) -> None:
        self._confirm()

    def action_toggle_item(self) -> None:
        lv = self.query_one('#trailer-list', ListView)
        if lv.highlighted_child is not None and isinstance(lv.highlighted_child, TrailerOption):
            lv.highlighted_child.toggle()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Enter key on ListView triggers Selected — use it to confirm."""
        self._confirm()

    def _confirm(self) -> None:
        lv = self.query_one('#trailer-list', ListView)
        selected = [
            child.trailer_name
            for child in lv.children
            if isinstance(child, TrailerOption) and child.selected
        ]
        self.dismiss(selected)

    def action_cancel(self) -> None:
        self.dismiss(None)


class HelpScreen(ModalScreen[None]):
    """Parametric modal showing keybinding help.

    Pass pre-built *lines* (Rich markup strings, each ending with
    ``\\n``) to display.  All three TUI apps share this single class.
    """

    BINDINGS = [
        Binding('escape', 'close', 'Close'),
        Binding('question_mark', 'close', 'Close'),
    ]

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    #help-dialog {
        width: 64;
        height: auto;
        max-height: 80%;
        border: solid $primary;
        background: $surface;
        padding: 1 2;
        overflow-y: auto;
    }
    """

    def __init__(self, lines: List[str]) -> None:
        super().__init__()
        self._lines = lines

    def compose(self) -> ComposeResult:
        with Vertical(id='help-dialog'):
            yield Static(''.join(self._lines))

    def action_close(self) -> None:
        self.dismiss(None)


def _review_help_lines(has_agent: bool = False) -> List[str]:
    """Build help text for the review TUI."""
    lines = [
        '[bold]b4 review TUI — Keybindings[/bold]\n',
        '\n',
        '[bold]Navigation[/bold]\n',
        '  [bold]j[/bold] / [bold]↓[/bold]     Next patch / scroll down (right pane)\n',
        '  [bold]k[/bold] / [bold]↑[/bold]     Previous patch / scroll up (right pane)\n',
        '  [bold]\\[[/bold] / [bold]][/bold]     Previous / next patch (any pane)\n',
        '  [bold]h[/bold] / [bold]l[/bold]     Scroll left / right (right pane)\n',
        '  [bold]Space[/bold]     Page down (right pane)\n',
        '  [bold]Backspace[/bold] Page up (right pane)\n',
        '  [bold].[/bold]         Jump to next review comment\n',
        '  [bold],[/bold]         Jump to previous review comment\n',
        '  [bold]Tab[/bold]       Switch focus between panels\n',
        '\n',
        '[bold]Review mode[/bold]\n',
        '  [bold]t[/bold]         Trailers (↑↓ navigate, Space toggle, Enter save)\n',
        '  [bold]c[/bold]         Open $EDITOR for inline comments\n',
        '  [bold]n[/bold]         View/edit notes\n',
        '  [bold]r[/bold]         Open $EDITOR for reply\n',
        '  [bold]f[/bold]         Toggle follow-up comments from lore\n',
        '  [bold]d[/bold]         Toggle patch done state\n',
        '  [bold]x[/bold]         Toggle patch skip state\n',
    ]
    if has_agent:
        lines.append('  [bold]a[/bold]         Run review agent\n')
    lines += [
        '  [bold]e[/bold]         Toggle email mode\n',
        '\n',
        '[bold]Email mode[/bold]\n',
        '  [bold]t[/bold]         Trailers (↑↓ navigate, Space toggle, Enter save)\n',
        '  [bold]r[/bold]         Open $EDITOR for reply\n',
        '  [bold]T[/bold]         Edit To/Cc recipients\n',
        '  [bold]S[/bold]         Send review emails\n',
        '  [bold]e[/bold]         Toggle email mode\n',
        '\n',
        '  [bold]s[/bold]         Suspend to shell\n',
        '  [bold]q[/bold]         Quit\n',
        '  [bold]?[/bold]         Show this help\n',
    ]
    return lines


TRACKING_HELP_LINES = [
    '[bold]b4 review tracking — Keybindings[/bold]\n',
    '\n',
    '[bold]Status symbols[/bold]\n',
    '  ★  new          Series not yet reviewed\n',
    '  ✎  reviewing    Review branch checked out\n',
    '  ↩  replied      Review reply sent\n',
    '  ↻  waiting      Waiting for a new revision\n',
    '  ∈  accepted     Series accepted\n',
    '  ⏸  snoozed      Deferred until a date\n',
    '  ✓  thanked      Thank-you sent\n',
    '  ∅  gone         Branch no longer present\n',
    '  *  (suffix)     Tracking data needs refresh (press u)\n',
    '\n',
    '[bold]Columns[/bold]\n',
    '  Submitter     Patch author name\n',
    '  A·R·T         Acked-by · Reviewed-by · Tested-by trailer counts\n',
    '  Msgs          Thread message count (total, unseen in yellow)\n',
    '  S             Status symbol (see above) + update flag\n',
    '  Subject       Series subject line\n',
    '\n',
    '[bold]Navigation[/bold]\n',
    '  [bold]j[/bold] / [bold]↓[/bold]     Move cursor down\n',
    '  [bold]k[/bold] / [bold]↑[/bold]     Move cursor up\n',
    '  [bold]Escape[/bold]   Close details panel\n',
    '\n',
    '[bold]Series[/bold]\n',
    '  [bold]r[/bold]         Review selected series\n',
    '  [bold]v[/bold]         View series in modal\n',
    '  [bold]d[/bold]         Range-diff between revisions\n',
    '  [bold]a[/bold]         Open action menu (take, rebase, etc.)\n',
    '  [bold]u[/bold]         Update selected series\n',
    '\n',
    '[bold]App[/bold]\n',
    '  [bold]U[/bold]         Update all tracked series\n',
    '  [bold]l[/bold]         Filter series by pattern\n',
    '  [bold]s[/bold]         Suspend to shell\n',
    '  [bold]p[/bold]         Switch to Patchwork TUI\n',
    '  [bold]q[/bold]         Quit\n',
    '  [bold]?[/bold]         Show this help\n',
]

PW_HELP_LINES = [
    '[bold]b4 patchwork — Keybindings[/bold]\n',
    '\n',
    '[bold]Navigation[/bold]\n',
    '  [bold]j[/bold] / [bold]↓[/bold]     Move cursor down\n',
    '  [bold]k[/bold] / [bold]↑[/bold]     Move cursor up\n',
    '  [bold]Enter[/bold]     Select series\n',
    '\n',
    '[bold]Series[/bold]\n',
    '  [bold]v[/bold]         View series in modal\n',
    '  [bold]c[/bold]         View CI check details\n',
    '  [bold]t[/bold]         Track series for review\n',
    '  [bold]s[/bold]         Set Patchwork state\n',
    '  [bold]h[/bold]         Hide series\n',
    '  [bold]u[/bold]         Unhide series (when showing hidden)\n',
    '\n',
    '[bold]App[/bold]\n',
    '  [bold]r[/bold]         Refresh series list\n',
    '  [bold]l[/bold]         Filter series by pattern\n',
    '  [bold]H[/bold]         Toggle showing hidden series\n',
    '  [bold]q[/bold]         Quit\n',
    '  [bold]?[/bold]         Show this help\n',
]


class NoteScreen(ModalScreen[Optional[str]]):
    """Read-only modal showing all reviewers' notes.

    Dismisses with:
    - None on escape (no action)
    - "__EDIT__" when the user presses 'e' (edit in external editor)
    - "__DELETE__" when the user presses 'd' (delete all notes)
    """

    BINDINGS = [
        Binding('escape', 'cancel', 'Cancel'),
        Binding('e', 'edit', 'Edit'),
        Binding('d', 'delete', 'Delete all'),
    ]

    DEFAULT_CSS = """
    NoteScreen {
        align: center middle;
    }
    #note-dialog {
        width: 90%;
        height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #note-viewer {
        height: 1fr;
    }
    #note-hint {
        height: 1;
        dock: bottom;
        color: $text-muted;
    }
    """

    def __init__(self, note_entries: List[Tuple[str, str, str]]) -> None:
        super().__init__()
        self._note_entries = note_entries

    def compose(self) -> ComposeResult:
        with Vertical(id='note-dialog'):
            yield RichLog(id='note-viewer', highlight=False, wrap=True,
                          markup=True, auto_scroll=False)
            yield Static('Escape close  |  e edit  |  d delete all', id='note-hint')

    def on_mount(self) -> None:
        viewer = self.query_one('#note-viewer', RichLog)
        for header, colour, note in self._note_entries:
            header_text = Text(header, style=f'bold {colour}')
            viewer.write(header_text)
            for line in note.splitlines():
                viewer.write(Text(line))
            viewer.write('')

    def action_edit(self) -> None:
        self.dismiss('__EDIT__')

    def action_delete(self) -> None:
        self.dismiss('__DELETE__')

    def action_cancel(self) -> None:
        self.dismiss(None)


class PriorReviewScreen(ModalScreen[None]):
    """Read-only modal showing prior revision review context."""

    BINDINGS = [
        Binding('escape', 'cancel', 'Close'),
    ]

    DEFAULT_CSS = """
    PriorReviewScreen {
        align: center middle;
    }
    #prior-review-dialog {
        width: 90%;
        height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #prior-review-viewer {
        height: 1fr;
    }
    #prior-review-hint {
        height: 1;
        dock: bottom;
        color: $text-muted;
    }
    """

    def __init__(self, context_text: str) -> None:
        super().__init__()
        self._context_text = context_text

    def compose(self) -> ComposeResult:
        with Vertical(id='prior-review-dialog'):
            yield RichLog(id='prior-review-viewer', highlight=False, wrap=True,
                          markup=False, auto_scroll=False)
            yield Static('Escape close', id='prior-review-hint')

    def on_mount(self) -> None:
        ts = resolve_styles(self)
        viewer = self.query_one('#prior-review-viewer', RichLog)
        for line in self._context_text.splitlines():
            if line.startswith('== ') and line.endswith(' =='):
                viewer.write(Text(line, style=f"bold {ts['accent']}"))
            else:
                viewer.write(Text(line))

    def action_cancel(self) -> None:
        self.dismiss(None)


class FollowupReplyPreviewScreen(ModalScreen[Optional[str]]):
    """Preview a composed follow-up reply before sending.

    Builds the real EmailMessage (including signature) via
    lmsg.make_reply() and renders it identically to the patch email
    preview — headers and body in a single scrollable RichLog.

    Dismisses with:
    - 'send'  on S — caller should send the reply immediately
    - 'edit'  on E — caller should re-open the editor with the current text
    - None    on Escape — abandon (no action)
    """

    BINDINGS = [
        Binding('S', 'send', 'Send'),
        Binding('e', 'edit', 'Edit'),
        Binding('escape', 'abandon', 'Abandon'),
    ]

    DEFAULT_CSS = """
    FollowupReplyPreviewScreen {
        align: center middle;
    }
    #followup-preview-dialog {
        width: 80%;
        height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #followup-preview-viewer {
        height: 1fr;
        border: solid $panel;
        margin-bottom: 1;
    }
    #followup-preview-hint {
        height: 1;
        color: $text-muted;
    }
    """

    def __init__(self, entry: Dict[str, Any], reply_text: str) -> None:
        super().__init__()
        self._entry = entry
        self._reply_text = reply_text

    def compose(self) -> ComposeResult:
        with Vertical(id='followup-preview-dialog'):
            yield RichLog(id='followup-preview-viewer', highlight=False,
                          wrap=True, markup=False, auto_scroll=False)
            yield Static('S  send  |  e  edit  |  Escape  abandon',
                         id='followup-preview-hint')

    def on_mount(self) -> None:
        body = self._reply_text
        if '\n-- \n' not in body:
            sig = b4.get_email_signature()
            body = body.rstrip('\n') + '\n\n-- \n' + sig
        msg = self._entry['lmsg'].make_reply(body)
        viewer = self.query_one('#followup-preview-viewer', RichLog)
        _render_email_to_viewer(viewer, msg, ts=resolve_styles(self.app))

    def action_send(self) -> None:
        self.dismiss('send')

    def action_edit(self) -> None:
        self.dismiss('edit')

    def action_abandon(self) -> None:
        self.dismiss(None)


class ToCcScreen(ModalScreen[bool]):
    """Modal screen to edit To, Cc, and Bcc addresses."""

    BINDINGS = [
        Binding('ctrl+s', 'save', 'Save'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    ToCcScreen {
        align: center middle;
    }
    #tocc-dialog {
        width: 80;
        max-height: 90%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    .tocc-label {
        margin-top: 1;
        text-style: bold;
    }
    .tocc-area {
        height: 6;
    }
    #tocc-hint {
        height: 1;
        dock: bottom;
        color: $text-muted;
    }
    """

    def __init__(
        self,
        to_addrs: str,
        cc_addrs: str,
        bcc_addrs: str,
        show_apply_all: bool,
    ) -> None:
        super().__init__()
        self._to_text = _addrs_to_lines(to_addrs)
        self._cc_text = _addrs_to_lines(cc_addrs)
        self._bcc_text = _addrs_to_lines(bcc_addrs)
        self._show_apply_all = show_apply_all
        # Set after save
        self.to_result: str = ''
        self.cc_result: str = ''
        self.bcc_result: str = ''
        self.apply_all: bool = False

    def compose(self) -> ComposeResult:
        with Vertical(id='tocc-dialog'):
            yield Label('To:', classes='tocc-label')
            yield TextArea(self._to_text, id='to-area', classes='tocc-area')
            yield Label('Cc:', classes='tocc-label')
            yield TextArea(self._cc_text, id='cc-area', classes='tocc-area')
            yield Label('Bcc:', classes='tocc-label')
            yield TextArea(self._bcc_text, id='bcc-area', classes='tocc-area')
            if self._show_apply_all:
                yield Checkbox('Apply to all patches', id='apply-all')
            yield Static('Ctrl+S save  |  Escape cancel  |  Tab next field', id='tocc-hint')

    def on_mount(self) -> None:
        self.query_one('#to-area', TextArea).focus()

    def action_save(self) -> None:
        to_text = self.query_one('#to-area', TextArea).text
        cc_text = self.query_one('#cc-area', TextArea).text
        bcc_text = self.query_one('#bcc-area', TextArea).text

        for label, text in [('To', to_text), ('Cc', cc_text), ('Bcc', bcc_text)]:
            err = _validate_addrs(text)
            if err:
                self.notify(f'{label}: {err}', severity='error')
                return

        self.to_result = _lines_to_header(to_text)
        self.cc_result = _lines_to_header(cc_text)
        self.bcc_result = _lines_to_header(bcc_text)
        if self._show_apply_all:
            self.apply_all = self.query_one('#apply-all', Checkbox).value
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class SendScreen(ModalScreen[bool]):
    """Modal confirmation screen showing a summary of emails to send."""

    BINDINGS = [
        Binding('y', 'confirm', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
        Binding('q', 'cancel', 'Cancel', show=False),
    ]

    DEFAULT_CSS = """
    SendScreen {
        align: center middle;
    }
    #send-dialog {
        width: 72;
        max-height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
        overflow-y: auto;
    }
    #send-hint {
        height: 1;
        dock: bottom;
        color: $text-muted;
    }
    """

    def __init__(self, msgs: List[email.message.EmailMessage]) -> None:
        super().__init__()
        self._msgs = msgs

    def compose(self) -> ComposeResult:
        text = Text()
        text.append(f'Send {len(self._msgs)} review email(s)?', style='bold')
        text.append('\n')
        for msg in self._msgs:
            subj = str(msg['Subject']) if msg['Subject'] else '(no subject)'
            text.append('\n  ')
            text.append('Subject:', style='bold')
            text.append(f' {subj}')
            to_count = len(email.utils.getaddresses([msg['To']])) if msg['To'] else 0
            cc_count = len(email.utils.getaddresses([msg['Cc']])) if msg['Cc'] else 0
            recip_parts: List[str] = []
            if to_count:
                recip_parts.append(f'{to_count} To')
            if cc_count:
                recip_parts.append(f'{cc_count} Cc')
            if recip_parts:
                text.append(f'\n          {", ".join(recip_parts)}')
            text.append('\n')
        with Vertical(id='send-dialog'):
            yield Static(text, markup=False)
            yield Static('y confirm  |  Escape cancel', id='send-hint')

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class TakeScreen(ModalScreen[bool]):
    """Modal screen for take (merge/fast-forward) options."""

    BINDINGS = [
        Binding('ctrl+y', 'continue_take', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    TakeScreen {
        align: center middle;
    }
    #take-dialog {
        width: 70;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #take-title {
        text-style: bold;
        margin-bottom: 1;
    }
    .take-label {
        margin-top: 1;
    }
    .take-value {
        color: $text;
    }
    #take-target {
        margin-bottom: 1;
    }
    #take-method {
        margin-bottom: 1;
    }
    .take-checkbox {
        margin-top: 0;
    }
    #take-hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

    def __init__(self, target_branch: str, review_branch: str,
                 num_patches: int = 0,
                 default_method: Optional[str] = None,
                 recent_branches: Optional[List[str]] = None) -> None:
        """Initialize take screen.

        Args:
            target_branch: Pre-populated target branch name
            review_branch: The review branch to take
            num_patches: Number of patches in the series
            default_method: Override the default take method selection
            recent_branches: Recently used branch names for auto-suggest
        """
        super().__init__()
        self._target_branch = target_branch
        self._review_branch = review_branch
        self._default_method = default_method or ('linear' if num_patches == 1 else 'merge')
        self._recent_branches = recent_branches
        # Results set after continue
        self.target_result: str = ''
        self.method_result: str = self._default_method
        self.add_link: bool = True
        self.add_signoff: bool = True

    def compose(self) -> ComposeResult:
        method_options = [
            ('merge', 'merge'),
            ('linear', 'linear'),
            ('cherry-pick', 'cherry-pick'),
        ]
        with Vertical(id='take-dialog'):
            yield Static('Take Series', id='take-title')
            yield Static(f'Review branch: {self._review_branch}', classes='take-value')
            yield Static('Target branch:', classes='take-label')
            suggester = SuggestFromList(self._recent_branches, case_sensitive=True) if self._recent_branches else None
            yield Input(value=self._target_branch, id='take-target', suggester=suggester)
            yield Static('Method:', classes='take-label')
            yield Select(method_options, value=self._default_method, id='take-method', allow_blank=False)
            yield Checkbox('add Link:', value=True, id='take-add-link', classes='take-checkbox')
            yield Checkbox('add Signed-off-by:', value=True, id='take-add-signoff', classes='take-checkbox')
            yield Static('Ctrl-y continue  |  Escape cancel', id='take-hint')

    def on_mount(self) -> None:
        self.query_one('#take-target', Input).focus()

    def action_continue_take(self) -> None:
        self.target_result = self.query_one('#take-target', Input).value.strip()
        if not self.target_result:
            self.notify('Target branch is required', severity='error')
            return
        if not b4.git_branch_exists(None, self.target_result):
            self.notify(f'Branch does not exist: {self.target_result}', severity='error')
            return
        self.method_result = str(self.query_one('#take-method', Select).value)
        self.add_link = self.query_one('#take-add-link', Checkbox).value
        self.add_signoff = self.query_one('#take-add-signoff', Checkbox).value
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class CherryPickScreen(ModalScreen[bool]):
    """Modal screen for selecting individual patches to cherry-pick."""

    BINDINGS = [
        Binding('ctrl+y', 'continue_pick', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    CherryPickScreen {
        align: center middle;
    }
    #cherrypick-dialog {
        width: 80;
        max-height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #cherrypick-title {
        text-style: bold;
        margin-bottom: 1;
    }
    #cherrypick-list {
        height: auto;
        max-height: 20;
        overflow-y: auto;
    }
    .cherrypick-checkbox {
        margin: 0;
    }
    #cherrypick-skip-note {
        color: $warning;
        margin-bottom: 1;
    }
    #cherrypick-hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

    def __init__(self, patches: List[Dict[str, Any]],
                 preselected: Optional[List[int]] = None) -> None:
        super().__init__()
        self._patches = patches
        self._preselected: List[int] = preselected if preselected is not None else []
        self.selected_indices: List[int] = []

    def compose(self) -> ComposeResult:
        has_preselected = bool(self._preselected)
        with Vertical(id='cherrypick-dialog'):
            yield Static('Select patches to apply', id='cherrypick-title')
            if has_preselected:
                yield Static('Skipped patches are pre-deselected.',
                             id='cherrypick-skip-note')
            with Vertical(id='cherrypick-list'):
                for i, patch in enumerate(self._patches):
                    title = patch.get('title', f'Patch {i + 1}')
                    checked = (i + 1) in self._preselected if has_preselected else False
                    yield Checkbox(Text(f' {i + 1:3d}. {title}'), value=checked,
                                   id=f'cherrypick-{i}', classes='cherrypick-checkbox')
            yield Static('Ctrl-y continue  |  Escape cancel', id='cherrypick-hint')

    def action_continue_pick(self) -> None:
        self.selected_indices = []
        for i in range(len(self._patches)):
            cb = self.query_one(f'#cherrypick-{i}', Checkbox)
            if cb.value:
                self.selected_indices.append(i + 1)  # 1-based for get_am_ready
        if not self.selected_indices:
            self.notify('No patches selected', severity='error')
            return
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class TakeConfirmScreen(ModalScreen[bool]):
    """Final confirmation screen before executing a take.

    Runs a test apply in a background worker and shows the result.
    The maintainer can confirm (proceed) or back out (cancel).
    """

    BINDINGS = [
        Binding('ctrl+y', 'confirm_take', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    TakeConfirmScreen {
        align: center middle;
    }
    #takeconfirm-dialog {
        width: 70;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #takeconfirm-title {
        text-style: bold;
        margin-bottom: 1;
    }
    .takeconfirm-pass {
        color: $success;
    }
    .takeconfirm-fail {
        color: $error;
    }
    .takeconfirm-warn {
        color: $warning;
    }
    #takeconfirm-status {
        margin-top: 1;
    }
    #takeconfirm-accept {
        margin-top: 1;
    }
    #takeconfirm-hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

    def __init__(self, method: str, target_branch: str,
                 review_branch: str, subject: str = '',
                 cherrypick: Optional[List[int]] = None) -> None:
        super().__init__()
        self._method = method
        self._target_branch = target_branch
        self._review_branch = review_branch
        self._subject = subject
        self._cherrypick = cherrypick
        self.accept_series: bool = True

    def compose(self) -> ComposeResult:
        with Vertical(id='takeconfirm-dialog'):
            yield Static('Confirm Take', id='takeconfirm-title')
            if self._subject:
                yield Static(f'Series:  {self._subject}', markup=False)
            yield Static(f'Method:  {self._method}', markup=False)
            yield Static(f'Target:  {self._target_branch}', markup=False)
            if self._cherrypick:
                yield Static(
                    f'Patches: {", ".join(str(i) for i in self._cherrypick)}',
                    markup=False)
            yield Static('Testing apply\u2026', id='takeconfirm-status')
            yield LoadingIndicator(id='takeconfirm-loading')
            yield Checkbox('mark as accepted', value=True,
                           id='takeconfirm-accept')
            yield Static(
                'Ctrl-y confirm  |  Escape cancel',
                id='takeconfirm-hint')

    def on_mount(self) -> None:
        self.run_worker(self._test_take, name='_test_take', thread=True)

    def _test_take(self) -> Tuple[bool, str]:
        """Test-apply review branch patches at the target base."""
        import b4.review

        with _quiet_worker():
            topdir = b4.git_get_toplevel()
            if not topdir:
                return False, 'not in a git repository'

            # Load tracking to find base-commit and patch count
            try:
                _cover, tracking = b4.review.load_tracking(
                    topdir, self._review_branch)
            except SystemExit:
                return False, 'could not load tracking data'

            num_patches = len(tracking.get('patches', []))
            if num_patches == 0:
                return False, 'no patches in tracking data'

            # The review branch structure is:
            #   base -> patch1 -> ... -> patchN -> tracking_commit
            patch_base = f'{self._review_branch}~{num_patches + 1}'
            patch_tip = f'{self._review_branch}~1'

            # For merge, test at the series base-commit (or target branch);
            # for linear/cherry-pick, test at target branch HEAD.
            if self._method == 'merge':
                t_series = tracking.get('series', {})
                test_base = t_series.get('base-commit', '')
                if not test_base:
                    test_base = self._target_branch
            else:
                test_base = self._target_branch

            # Resolve the test base
            ecode, out = b4.git_run_command(
                topdir, ['rev-parse', '--verify', test_base])
            if ecode != 0:
                return False, f'cannot resolve base: {test_base}'
            resolved_base = out.strip()

            # Get patch commits
            commits = b4.git_get_command_lines(
                topdir, ['rev-list', '--reverse',
                         f'{patch_base}..{patch_tip}'])
            if not commits:
                return False, 'no commits found on review branch'

            # For cherry-pick, select only the chosen patches
            if self._cherrypick:
                selected = []
                for idx in self._cherrypick:
                    if 0 < idx <= len(commits):
                        selected.append(commits[idx - 1])
                commits = selected
                if not commits:
                    return False, 'no matching commits for selection'

            # Build mbox from selected commits
            mbox_parts = []
            for commit in commits:
                ecode, out = b4.git_run_command(
                    topdir,
                    ['format-patch', '--stdout', '-1', commit],
                    decode=False)
                if ecode != 0:
                    return False, f'format-patch failed for {commit[:12]}'
                mbox_parts.append(out)
            ambytes = b''.join(mbox_parts)

            # Test apply in a temporary sparse worktree
            try:
                with b4.git_temp_worktree(topdir, resolved_base) as gwt:
                    ecode, out = b4.git_run_command(
                        gwt, ['sparse-checkout', 'set'])
                    if ecode > 0:
                        return False, 'failed to set up worktree'
                    ecode, out = b4.git_run_command(
                        gwt, ['checkout', '-f'])
                    if ecode > 0:
                        return False, 'failed to checkout base'
                    ecode, out = b4.git_run_command(
                        gwt, ['am'], stdin=ambytes)
                    if ecode > 0:
                        for line in out.splitlines():
                            if line.startswith('Patch failed at '):
                                return False, line
                        return False, 'apply failed'
                    return True, f'clean ({resolved_base[:12]})'
            except Exception as ex:
                return False, str(ex)

    def _update_status(self, text: str, level: str) -> None:
        widget = self.query_one('#takeconfirm-status', Static)
        widget.update(text)
        widget.remove_class('takeconfirm-pass', 'takeconfirm-warn',
                            'takeconfirm-fail')
        widget.add_class(f'takeconfirm-{level}')

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != '_test_take':
            return
        if event.state == WorkerState.SUCCESS and event.worker.result:
            await self.query_one('#takeconfirm-loading', LoadingIndicator
                                 ).remove()
            ok, detail = event.worker.result
            if ok:
                self._update_status(f'Test apply: {detail}', 'pass')
            else:
                self._update_status(f'Test apply: {detail}', 'fail')
        elif event.state == WorkerState.ERROR:
            await self.query_one('#takeconfirm-loading', LoadingIndicator
                                 ).remove()
            self._update_status('test apply error', 'fail')

    def action_confirm_take(self) -> None:
        self.accept_series = self.query_one(
            '#takeconfirm-accept', Checkbox).value
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class SnoozeScreen(ModalScreen[Optional[Dict[str, str]]]):
    """Modal dialog for snoozing a series until a future date/time or tag.

    Returns ``{'until': '<value>'}`` on confirm, or ``None`` on cancel.
    The *until* value is either an ISO datetime string (for duration/date
    snoozes) or ``tag:<tagname>`` (for tag-based snoozes).
    """

    BINDINGS = [
        Binding('ctrl+y', 'continue_snooze', 'Confirm', show=False),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    SnoozeScreen {
        align: center middle;
    }
    #snooze-dialog {
        width: 60;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #snooze-title {
        text-style: bold;
        margin-bottom: 1;
    }
    .snooze-label {
        margin-top: 1;
    }
    #snooze-hint {
        margin-top: 1;
        color: $text-muted;
    }
    #snooze-error {
        color: $error;
        margin-top: 1;
    }
    """

    def __init__(self, last_source: str = '', last_input: str = '') -> None:
        super().__init__()
        self._last_source = last_source
        self._last_input = last_input

    def compose(self) -> ComposeResult:
        with Vertical(id='snooze-dialog'):
            yield Static('Snooze Series', id='snooze-title')
            yield Static('Snooze for duration:', classes='snooze-label')
            yield Input(placeholder='e.g. 30m, 3h, 1d, 2w', id='snooze-duration')
            yield Static('— or until date (YYYY-MM-DD):', classes='snooze-label')
            yield Input(placeholder='e.g. 2026-04-01', id='snooze-date')
            yield Static('— or until tag appears:', classes='snooze-label')
            yield Input(placeholder='e.g. v6.15-rc3', id='snooze-tag')
            yield Static('', id='snooze-error')
            yield Static('Ctrl-y confirm  |  Escape cancel', id='snooze-hint')

    def on_mount(self) -> None:
        # Pre-populate the field that was used last time
        field_map = {
            'duration': '#snooze-duration',
            'date': '#snooze-date',
            'tag': '#snooze-tag',
        }
        target_id = field_map.get(self._last_source, '')
        if target_id and self._last_input:
            widget = self.query_one(target_id, Input)
            widget.value = self._last_input
            widget.focus()
        else:
            self.query_one('#snooze-duration', Input).focus()

    # Regex for duration shorthand: number + optional unit (m/h/d/w)
    _DURATION_RE = re.compile(r'^(\d+)\s*([mhdw]?)$', re.IGNORECASE)

    def action_continue_snooze(self) -> None:
        import datetime

        dur_str = self.query_one('#snooze-duration', Input).value.strip()
        date_str = self.query_one('#snooze-date', Input).value.strip()
        tag_str = self.query_one('#snooze-tag', Input).value.strip()
        error_widget = self.query_one('#snooze-error', Static)

        has_dur = bool(dur_str)
        has_date = bool(date_str)
        has_tag = bool(tag_str)

        filled = sum([has_dur, has_date, has_tag])
        if filled == 0:
            error_widget.update('Please enter a duration, date, or tag')
            return
        if filled > 1:
            error_widget.update('Please fill in only one field')
            return

        until_value: str = ''
        source: str = ''
        raw_input: str = ''
        if has_tag:
            until_value = f'tag:{tag_str}'
            source = 'tag'
            raw_input = tag_str
        elif has_dur:
            m = self._DURATION_RE.match(dur_str)
            if not m:
                error_widget.update('Invalid duration (use e.g. 30m, 3h, 1d, 2w)')
                return
            value = int(m.group(1))
            unit = m.group(2).lower() if m.group(2) else 'd'
            if value < 1:
                error_widget.update('Duration must be positive')
                return
            unit_map = {'m': 'minutes', 'h': 'hours', 'd': 'days', 'w': 'weeks'}
            delta = datetime.timedelta(**{unit_map[unit]: value})
            target = datetime.datetime.now(datetime.timezone.utc) + delta
            # Store as YYYY-MM-DDTHH:MM:SS (no tz suffix) for SQLite compat
            until_value = target.strftime('%Y-%m-%dT%H:%M:%S')
            source = 'duration'
            raw_input = dur_str
        else:
            try:
                target_date = datetime.date.fromisoformat(date_str)
            except ValueError:
                error_widget.update('Invalid date format (use YYYY-MM-DD)')
                return
            if target_date <= datetime.date.today():
                error_widget.update('Date must be in the future')
                return
            # Convert date to midnight UTC datetime
            target = datetime.datetime(
                target_date.year, target_date.month, target_date.day,
                tzinfo=datetime.timezone.utc,
            )
            until_value = target.strftime('%Y-%m-%dT%H:%M:%S')
            source = 'date'
            raw_input = date_str

        self.dismiss({'until': until_value, 'source': source, 'input': raw_input})

    def action_cancel(self) -> None:
        self.dismiss(None)


class ThankScreen(ModalScreen[Optional[str]]):
    """Modal preview of a thank-you email.  Dismisses with '__EDIT__',
    '__SEND__', or None (cancelled)."""

    BINDINGS = [
        Binding('e', 'edit', '[e]dit'),
        Binding('S', 'send', '[S]end', key_display='S'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    ThankScreen {
        align: center middle;
    }
    #thank-dialog {
        width: 90%;
        height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #thank-viewer {
        height: 1fr;
    }
    #thank-hint {
        height: 1;
        dock: bottom;
        color: $text-muted;
    }
    """

    def __init__(self, msg: email.message.EmailMessage) -> None:
        super().__init__()
        self._msg = msg

    def compose(self) -> ComposeResult:
        with Vertical(id='thank-dialog'):
            yield RichLog(id='thank-viewer', highlight=False, wrap=True,
                          markup=False, auto_scroll=False)
            yield Static('e edit  |  S send  |  Escape cancel', id='thank-hint')

    def on_mount(self) -> None:
        viewer = self.query_one('#thank-viewer', RichLog)
        for hdr in ('From', 'To', 'Cc', 'Subject', 'In-Reply-To'):
            val = self._msg.get(hdr)
            if val:
                viewer.write(f'{hdr}: {val}')
        viewer.write('')
        body = self._msg.get_payload(decode=True)
        if isinstance(body, bytes):
            body = body.decode(errors='replace')
        elif not isinstance(body, str):
            body = str(body) if body else ''
        for line in body.splitlines():
            viewer.write(line)

    def action_edit(self) -> None:
        self.dismiss('__EDIT__')

    def action_send(self) -> None:
        self.dismiss('__SEND__')

    def action_cancel(self) -> None:
        self.dismiss(None)


class WorkerScreen(ModalScreen[Any]):
    """Generic modal that runs a callable in a worker thread.

    Shows a loading indicator while the callable runs.  Dismisses with
    the return value on success or None on error.

    Usage::

        def _do_work():
            ...
            return result

        self.push_screen(
            WorkerScreen('Fetching series\u2026', _do_work),
            callback=self._on_result,
        )
    """

    BINDINGS = [
        Binding('escape', 'cancel', 'Cancel', show=False),
    ]

    DEFAULT_CSS = """
    WorkerScreen {
        align: center middle;
    }
    #ws-dialog {
        width: 50;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #ws-title {
        text-style: bold;
        margin-bottom: 1;
    }
    """

    def __init__(self, title: str, fn: Any) -> None:
        super().__init__()
        self._title = title
        self._fn = fn

    def compose(self) -> ComposeResult:
        with Vertical(id='ws-dialog'):
            yield Static(self._title, id='ws-title', markup=False)
            yield LoadingIndicator()

    def on_mount(self) -> None:
        self.run_worker(self._fn, name='_ws_work', thread=True)

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != '_ws_work':
            return
        if event.state == WorkerState.SUCCESS:
            self.dismiss(event.worker.result)
        elif event.state == WorkerState.ERROR:
            self.app.notify(str(event.worker.error), severity='error')
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class _FetchViewerScreen(ModalScreen[None]):
    """Base class for modals that fetch data in a worker and display in a RichLog.

    Subclasses must implement :meth:`_fetch` (runs in a thread) and
    :meth:`_show_result` (populates the viewer on success).  Set
    ``_loading_text`` to customise the title while loading.
    """

    _loading_text: str = 'Loading\u2026'

    BINDINGS = [
        Binding('escape', 'dismiss', 'Close'),
        Binding('q', 'dismiss', 'Close', show=False),
        Binding('space', 'page_down', 'Page down', show=False),
        Binding('backspace', 'page_up', 'Page up', show=False),
    ]

    DEFAULT_CSS = """
    _FetchViewerScreen {
        align: center middle;
    }
    #fv-dialog {
        width: 90%;
        height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #fv-title {
        text-style: bold;
        margin-bottom: 1;
    }
    #fv-viewer {
        height: 1fr;
    }
    #fv-hint {
        height: 1;
        dock: bottom;
        color: $text-muted;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id='fv-dialog'):
            yield Static(self._loading_text, id='fv-title', markup=False)
            yield LoadingIndicator(id='fv-loading')
            yield RichLog(id='fv-viewer', highlight=False, wrap=True,
                          markup=True, auto_scroll=False)
            yield Static('Escape close', id='fv-hint')

    def on_mount(self) -> None:
        self.query_one('#fv-viewer', RichLog).display = False
        self.query_one('#fv-hint', Static).display = False
        self.run_worker(self._fetch, name='_fv_fetch', thread=True)

    def _fetch(self) -> Any:
        raise NotImplementedError

    def _show_result(self, result: Any) -> None:
        raise NotImplementedError

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != '_fv_fetch':
            return
        if event.state == WorkerState.SUCCESS:
            await self.query_one('#fv-loading', LoadingIndicator).remove()
            if event.worker.result is not None:
                title = self.query_one('#fv-title', Static)
                viewer = self.query_one('#fv-viewer', RichLog)
                hint = self.query_one('#fv-hint', Static)
                viewer.display = True
                hint.display = True
                self._show_result(event.worker.result)
        elif event.state == WorkerState.ERROR:
            await self.query_one('#fv-loading', LoadingIndicator).remove()
            self.query_one('#fv-title', Static).update('Error')
            viewer = self.query_one('#fv-viewer', RichLog)
            viewer.display = True
            viewer.write(str(event.worker.error))
            self.query_one('#fv-hint', Static).display = True

    def action_page_down(self) -> None:
        self.query_one('#fv-viewer', RichLog).scroll_page_down()

    def action_page_up(self) -> None:
        self.query_one('#fv-viewer', RichLog).scroll_page_up()


class ViewSeriesScreen(_FetchViewerScreen):
    """Modal screen for previewing a series fetched from lore."""

    _loading_text = 'Fetching series\u2026'

    def __init__(self, message_id: str) -> None:
        super().__init__()
        self._message_id = message_id

    def _fetch(self) -> 'b4.LoreSeries':
        with _quiet_worker():
            msgs = b4.review._retrieve_messages(self._message_id)
            return b4.review._get_lore_series(msgs)

    def _show_result(self, lser: 'b4.LoreSeries') -> None:
        subject = lser.subject or '(no subject)'
        self.query_one('#fv-title', Static).update(subject)
        viewer = self.query_one('#fv-viewer', RichLog)
        ts = resolve_styles(self.app)

        first = True
        for idx, lmsg in enumerate(lser.patches):
            if lmsg is None:
                continue
            if idx == 0 and not lser.has_cover:
                continue
            if not first:
                viewer.write(Rule())
            first = False
            viewer.write(Text(f'From: {lmsg.fromname} <{lmsg.fromemail}>', style='bold'))
            if lmsg.date:
                viewer.write(Text(f'Date: {lmsg.date}', style='bold'))
            viewer.write(Text(f'Subject: {lmsg.full_subject}', style='bold'))
            viewer.write('')
            if lmsg.body:
                in_diff = False
                for line in lmsg.body.splitlines():
                    if line.startswith('diff --git '):
                        in_diff = True
                    if in_diff:
                        _write_diff_line(viewer, line, ts=ts)
                    else:
                        viewer.write(Text(line))


class CIChecksScreen(_FetchViewerScreen):
    """Modal screen for viewing CI check details for a Patchwork series."""

    _loading_text = 'Fetching CI checks\u2026'

    def __init__(self, pwkey: str, pwurl: str,
                 series: Dict[str, Any]) -> None:
        super().__init__()
        self._pwkey = pwkey
        self._pwurl = pwurl
        self._series = series

    def _fetch(self) -> List[Dict[str, Any]]:
        import b4.review
        with _quiet_worker():
            patch_ids = self._series.get('patch_ids', [])
            return b4.review.pw_fetch_checks(
                self._pwkey, self._pwurl, patch_ids)

    def _show_result(self, checks: List[Dict[str, Any]]) -> None:
        series_name = self._series.get('name') or '(no subject)'
        self.query_one('#fv-title', Static).update(
            f'CI checks \u2014 {series_name}')
        viewer = self.query_one('#fv-viewer', RichLog)

        if not checks:
            viewer.write(Text('No CI checks reported for this series.', style='dim'))
            return

        ts = resolve_styles(self.app)
        ci_map = ci_check_styles(ts)

        # Group checks by patch
        patch_names: Dict[int, str] = self._series.get('patch_names', {})
        by_patch: Dict[int, List[Dict[str, Any]]] = {}
        for check in checks:
            pid = check.get('patch_id', 0)
            by_patch.setdefault(pid, []).append(check)

        patch_ids = self._series.get('patch_ids', [])
        first = True
        for pid in patch_ids:
            if pid not in by_patch:
                continue
            if not first:
                viewer.write(Rule())
            first = False
            pname = patch_names.get(pid, '')
            if pname:
                viewer.write(Text(pname, style='bold'))
            else:
                viewer.write(Text(f'Patch ID {pid}', style='bold'))
            viewer.write('')
            for check in by_patch[pid]:
                state = check.get('state', 'pending')
                ci_style = ci_map.get(state, ci_map['pending'])
                ci_label = CI_CHECK_LABELS.get(state, CI_CHECK_LABELS['pending'])
                context = check.get('context') or 'default'
                line_text = Text()
                line_text.append('  ')
                line_text.append(ci_label, style=ci_style)
                line_text.append(f'  {context}')
                desc = check.get('description')
                if desc:
                    desc_lines = desc.splitlines()
                    line_text.append(f' \u2014 {desc_lines[0]}')
                    viewer.write(line_text)
                    for dline in desc_lines[1:]:
                        viewer.write(Text(f'    {dline}'))
                else:
                    viewer.write(line_text)
                target_url = check.get('target_url')
                if target_url:
                    viewer.write(Text(f'    \u2192 {target_url}', style='dim'))


class ConfirmScreen(ModalScreen[bool]):
    """Generic y/escape confirmation modal.

    *title*: bold heading text.
    *body*: list of plain strings rendered as ``Static`` widgets.
    *border*: Textual CSS border-colour token (e.g. ``'$warning'``).
    *title_colour*: optional CSS colour for the title (defaults to *border*).
    """

    BINDINGS = [
        Binding('y', 'confirm', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    ConfirmScreen {
        align: center middle;
    }
    #confirm-dialog {
        width: 65;
        height: auto;
        background: $surface;
        padding: 1 2;
        border: solid $accent;
    }
    #confirm-dialog.--border-warning {
        border: solid $warning;
    }
    #confirm-dialog.--border-error {
        border: solid $error;
    }
    #confirm-title {
        text-style: bold;
        margin-bottom: 1;
    }
    #confirm-title.--color-warning {
        color: $warning;
    }
    #confirm-title.--color-error {
        color: $error;
    }
    #confirm-hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

    # Map CSS variable names to CSS class suffixes for border/title colours.
    _COLOUR_CLASSES = {'$warning': 'warning', '$error': 'error'}

    def __init__(self, title: str, body: List[str],
                 border: str = '$accent',
                 title_colour: Optional[str] = None) -> None:
        super().__init__()
        self._title = title
        self._body = body
        self._border = border
        self._title_colour = title_colour

    def compose(self) -> ComposeResult:
        dialog = Vertical(id='confirm-dialog')
        border_cls = self._COLOUR_CLASSES.get(self._border)
        if border_cls:
            dialog.add_class(f'--border-{border_cls}')
        with dialog:
            title = Static(self._title, id='confirm-title', markup=False)
            colour_cls = self._COLOUR_CLASSES.get(self._title_colour or '')
            if colour_cls:
                title.add_class(f'--color-{colour_cls}')
            yield title
            for line in self._body:
                yield Static(line, markup=False)
            yield Static('y confirm  |  Escape cancel', id='confirm-hint')

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


def NewerRevisionWarningScreen(current_rev: int, newer_versions: List[int]) -> ConfirmScreen:
    """Build a confirmation screen warning about newer revisions."""
    versions = ', '.join(f'v{v}' for v in newer_versions)
    return ConfirmScreen(
        title='Newer revision available',
        body=[
            f'You are about to take v{current_rev}, but '
            f'newer version(s) exist: {versions}',
            '',
            'Are you sure you want to proceed?',
        ],
        border='$warning',
        title_colour='$warning',
    )


class RevisionChoiceScreen(ModalScreen[Optional[int]]):
    """Modal offering a choice between reviewing the tracked or a newer revision."""

    DEFAULT_CSS = """
    RevisionChoiceScreen {
        align: center middle;
    }
    #rev-choice-dialog {
        width: 65;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #rev-choice-title {
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }
    #rev-choice-hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding('n', 'newer', 'Newer'),
        Binding('o', 'older', 'Older'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    def __init__(self, current_rev: int, newest_rev: int) -> None:
        super().__init__()
        self._current_rev = current_rev
        self._newest_rev = newest_rev

    def compose(self) -> ComposeResult:
        with Vertical(id='rev-choice-dialog'):
            yield Static('Newer revision available', id='rev-choice-title')
            yield Static(
                f'This series was tracked as v{self._current_rev}, but '
                f'v{self._newest_rev} is now available.')
            yield Static('')
            yield Static('Which version would you like to review?')
            yield Static(
                f'n review v{self._newest_rev} (newer)  |  '
                f'o review v{self._current_rev} (older)  |  '
                f'Escape cancel',
                id='rev-choice-hint')

    def action_newer(self) -> None:
        self.dismiss(self._newest_rev)

    def action_older(self) -> None:
        self.dismiss(self._current_rev)

    def action_cancel(self) -> None:
        self.dismiss(None)


class RebaseScreen(ModalScreen[bool]):
    """Modal screen for rebasing a review branch onto a target branch."""

    BINDINGS = [
        Binding('ctrl+y', 'continue_rebase', 'Confirm', show=False),
        Binding('escape', 'cancel', 'Cancel', show=False),
    ]

    DEFAULT_CSS = """
    RebaseScreen {
        align: center middle;
    }
    #rebase-dialog {
        width: 60;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #rebase-title {
        text-style: bold;
        margin-bottom: 1;
    }
    .rebase-label {
        margin-top: 1;
        color: $text-muted;
    }
    .rebase-value {
        color: $text;
    }
    #rebase-target {
        margin-bottom: 1;
    }
    #rebase-hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

    def __init__(self, current_branch: str, review_branch: str,
                 recent_branches: Optional[List[str]] = None) -> None:
        """Initialize rebase screen.

        Args:
            current_branch: Pre-populated target branch name
            review_branch: The review branch to rebase
            recent_branches: Recently used branch names for auto-suggest
        """
        super().__init__()
        self._current_branch = current_branch
        self._review_branch = review_branch
        self._recent_branches = recent_branches
        self.target_result: str = ''

    def compose(self) -> ComposeResult:
        with Vertical(id='rebase-dialog'):
            yield Static('Rebase Series', id='rebase-title')
            yield Static(f'Review branch: {self._review_branch}', classes='rebase-value')
            yield Static('Rebase on top of:', classes='rebase-label')
            suggester = SuggestFromList(self._recent_branches, case_sensitive=True) if self._recent_branches else None
            yield Input(value=self._current_branch, id='rebase-target', suggester=suggester)
            yield Static('Ctrl-y confirm  |  Escape cancel', id='rebase-hint')

    def on_mount(self) -> None:
        self.query_one('#rebase-target', Input).focus()

    def action_continue_rebase(self) -> None:
        self.target_result = self.query_one('#rebase-target', Input).value.strip()
        if not self.target_result:
            self.notify('Target branch is required', severity='error')
            return
        if not b4.git_branch_exists(None, self.target_result):
            self.notify(f'Branch does not exist: {self.target_result}', severity='error')
            return
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


def AbandonConfirmScreen(change_id: str, review_branch: str,
                         has_branch: bool) -> ConfirmScreen:
    """Build a confirmation screen for abandon operation."""
    body = [f'Change-ID: {change_id}']
    if has_branch:
        body.append(f'Review branch {review_branch} will be DELETED')
    body += [
        'Tracking data will be removed from the database.',
        '',
        'Are you sure?',
    ]
    return ConfirmScreen(
        title='Abandon Series',
        body=body,
        border='$error',
        title_colour='$error',
    )


def ArchiveConfirmScreen(change_id: str, review_branch: str,
                         has_branch: bool) -> ConfirmScreen:
    """Build a confirmation screen for archive operation."""
    body = [f'Change-ID: {change_id}']
    if has_branch:
        body.append(f'Review branch {review_branch} will be archived and DELETED')
    body += [
        'Series will be archived to the b4 data directory.',
        '',
        'Are you sure?',
    ]
    return ConfirmScreen(
        title='Archive Series',
        body=body,
        border='$warning',
        title_colour='$warning',
    )


class RangeDiffScreen(JKListNavMixin, ModalScreen[Optional[int]]):
    """Modal to select a revision for range-diff comparison.

    Returns the chosen revision number, or None on cancel.
    """

    _list_id = '#rangediff-list'

    BINDINGS = [
        Binding('j', 'cursor_down', 'Down', show=False),
        Binding('k', 'cursor_up', 'Up', show=False),
        Binding('enter', 'confirm', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    RangeDiffScreen {
        align: center middle;
    }
    #rangediff-dialog {
        width: 60;
        height: auto;
        max-height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #rangediff-list {
        height: auto;
        max-height: 20;
    }
    """

    def __init__(self, current_revision: int, revisions: List[Dict[str, Any]]) -> None:
        super().__init__()
        self._current_revision = current_revision
        self._revisions = sorted(
            [r for r in revisions if r['revision'] != current_revision],
            key=lambda r: r['revision'], reverse=True)

    def compose(self) -> ComposeResult:
        with Vertical(id='rangediff-dialog'):
            yield Label(f'Range-diff against v{self._current_revision} \u2014 select version:')
            items = []
            for r in self._revisions:
                subject = r.get('subject', '(no subject)')
                label = f'v{r["revision"]}  {subject}'
                items.append(ListItem(Label(label, markup=False)))
            yield ListView(*items, id='rangediff-list')

    def on_mount(self) -> None:
        self.query_one('#rangediff-list', ListView).focus()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self._do_confirm()

    def action_confirm(self) -> None:
        self._do_confirm()

    def _do_confirm(self) -> None:
        lv = self.query_one('#rangediff-list', ListView)
        if lv.index is not None and 0 <= lv.index < len(self._revisions):
            self.dismiss(self._revisions[lv.index]['revision'])
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class StateOption(ListItem):
    """A selectable state entry in the set-state dialog."""

    def __init__(self, slug: str, name: str, highlighted: bool = False) -> None:
        super().__init__()
        self.slug = slug
        self.state_name = name
        self._highlighted = highlighted

    def compose(self) -> ComposeResult:
        marker = '> ' if self._highlighted else '  '
        yield Label(f'{marker}{self.state_name}', markup=False)


class SetStateScreen(JKListNavMixin, ModalScreen[Optional[Tuple[str, bool]]]):
    """Modal to select a new state for a series.

    Returns (state_slug, archived) on confirm, or None on cancel.
    """

    _list_id = '#state-list'

    BINDINGS = [
        Binding('j', 'cursor_down', 'Down', show=False),
        Binding('k', 'cursor_up', 'Up', show=False),
        Binding('a', 'toggle_archived', 'Archive'),
        Binding('enter', 'confirm', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    SetStateScreen {
        align: center middle;
    }
    #state-dialog {
        width: 50;
        height: auto;
        max-height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #state-list {
        height: auto;
        max-height: 20;
    }
    #state-archived {
        margin-top: 1;
    }
    """

    def __init__(self, states: List[Dict[str, Any]], current_state: str) -> None:
        super().__init__()
        self._states = states
        self._current_state = current_state

    def compose(self) -> ComposeResult:
        with Vertical(id='state-dialog'):
            yield Label('Set state (Enter=confirm, Esc=cancel):')
            yield ListView(
                *[StateOption(s['slug'], s['name'], s['slug'] == self._current_state)
                  for s in self._states],
                id='state-list',
            )
            yield Checkbox('Archived', False, id='state-archived')

    def on_mount(self) -> None:
        lv = self.query_one('#state-list', ListView)
        lv.focus()
        # Pre-select the current state
        for i, child in enumerate(lv.children):
            if isinstance(child, StateOption) and child.slug == self._current_state:
                lv.index = i
                break

    def action_toggle_archived(self) -> None:
        cb = self.query_one('#state-archived', Checkbox)
        cb.value = not cb.value

    def action_confirm(self) -> None:
        self._do_confirm()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self._do_confirm()

    def _do_confirm(self) -> None:
        lv = self.query_one('#state-list', ListView)
        if lv.highlighted_child is not None and isinstance(lv.highlighted_child, StateOption):
            slug = lv.highlighted_child.slug
        else:
            self.dismiss(None)
            return
        archived = self.query_one('#state-archived', Checkbox).value
        self.dismiss((slug, archived))

    def action_cancel(self) -> None:
        self.dismiss(None)


class ApplyStateModal(ModalScreen[Tuple[int, int, str]]):
    """Modal showing progress while applying state changes to patches.

    Returns (success_count, failure_count, new_state) when complete.
    """

    DEFAULT_CSS = """
    ApplyStateModal {
        align: center middle;
    }
    #apply-dialog {
        width: 60;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #apply-title {
        text-style: bold;
        margin-bottom: 1;
    }
    #apply-status {
        margin-bottom: 1;
    }
    #apply-progress {
        width: 100%;
        height: 1;
    }
    """

    def __init__(self, pwkey: str, pwurl: str, patch_ids: List[int],
                 new_state: str, archived: bool, series_name: str) -> None:
        super().__init__()
        self._pwkey = pwkey
        self._pwurl = pwurl
        self._patch_ids = patch_ids
        self._new_state = new_state
        self._archived = archived
        self._series_name = series_name
        self._ok = 0
        self._fail = 0

    def compose(self) -> ComposeResult:
        with Vertical(id='apply-dialog'):
            yield Label(f'Setting state to: {self._new_state}', id='apply-title')
            yield Label(self._series_name, id='apply-series', markup=False)
            yield Label(f'Processing 0/{len(self._patch_ids)} patches...', id='apply-status')
            yield ProgressBar(total=len(self._patch_ids), show_eta=False, id='apply-progress')

    def on_mount(self) -> None:
        self.run_worker(self._apply_states, thread=True)

    def _apply_states(self) -> Tuple[int, int, str]:
        import b4

        with _quiet_worker():
            pses, api_url = b4.get_patchwork_session(self._pwkey, self._pwurl)
            patches_url = '/'.join((api_url, 'patches'))

            for i, patch_id in enumerate(self._patch_ids):
                patchid_url = '/'.join((patches_url, str(patch_id), ''))
                data = {
                    'state': self._new_state,
                    'archived': self._archived,
                }
                try:
                    rsp = pses.patch(patchid_url, data=data, stream=False)
                    rsp.raise_for_status()
                    self._ok += 1
                except Exception:
                    self._fail += 1

                # Update progress from worker thread
                self.app.call_from_thread(self._update_progress, i + 1)

        return self._ok, self._fail, self._new_state

    def _update_progress(self, completed: int) -> None:
        self.query_one('#apply-status', Label).update(
            f'Processing {completed}/{len(self._patch_ids)} patches...'
        )
        self.query_one('#apply-progress', ProgressBar).progress = completed

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.state == WorkerState.SUCCESS:
            self.dismiss(event.worker.result)
        elif event.state == WorkerState.ERROR:
            # Return what we have so far
            self.dismiss((self._ok, self._fail, self._new_state))


class UpdateAllScreen(ModalScreen[Dict[str, int]]):
    """Modal showing progress while updating all tracked series.

    Iterates every non-archived series, fetching threads and updating
    revisions/trailers.  Returns a summary dict on completion.
    """

    DEFAULT_CSS = """
    UpdateAllScreen {
        align: center middle;
    }
    #updateall-dialog {
        width: 70;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #updateall-title {
        text-style: bold;
        margin-bottom: 1;
    }
    #updateall-series {
        margin-bottom: 1;
    }
    #updateall-progress {
        width: 100%;
        height: 1;
    }
    """

    BINDINGS = [
        Binding('escape', 'cancel', 'Cancel'),
    ]

    def __init__(self, series_list: List[Dict[str, Any]],
                 identifier: str, linkmask: str,
                 topdir: Optional[str] = None) -> None:
        super().__init__()
        self._series_list = series_list
        self._identifier = identifier
        self._linkmask = linkmask
        self._topdir = topdir
        self._cancelled = False
        self._result: Dict[str, int] = {
            'series_checked': 0,
            'series_updated': 0,
            'promoted': 0,
            'errors': 0,
            'gone': 0,
        }

    def compose(self) -> ComposeResult:
        with Vertical(id='updateall-dialog'):
            count = len(self._series_list)
            title = 'Updating series' if count == 1 else 'Updating all tracked series'
            yield Label(title, id='updateall-title')
            yield Label(f'Checking 0/{len(self._series_list)} series...', id='updateall-status')
            yield Label('', id='updateall-series', markup=False)
            yield ProgressBar(total=len(self._series_list), show_eta=False, id='updateall-progress')

    def on_mount(self) -> None:
        self.run_worker(self._do_updates, thread=True)

    def action_cancel(self) -> None:
        self._cancelled = True

    def _do_updates(self) -> Dict[str, int]:
        import b4.review

        with _quiet_worker():
            # Rescan local review branches first so the DB reflects current
            # on-disk state before the network update runs.
            if self._topdir:
                try:
                    rescan = b4.review.tracking.rescan_branches(
                        self._identifier, self._topdir)
                    self._result['gone'] = rescan.get('gone', 0)
                except Exception as ex:
                    logger.warning('Pre-update rescan failed: %s', ex)

            for i, series in enumerate(self._series_list):
                if self._cancelled:
                    break

                subject = series.get('subject', '(no subject)')
                self.app.call_from_thread(self._update_progress, i, subject)

                r = b4.review.update_series_tracking(
                    series, self._identifier, self._linkmask,
                    topdir=self._topdir,
                )
                self._result['series_checked'] += 1
                if r.get('new_revisions') or r.get('new_trailers'):
                    self._result['series_updated'] += 1
                if r.get('promoted'):
                    self._result['promoted'] += 1
                if r.get('error'):
                    self._result['errors'] += 1

                self.app.call_from_thread(self._update_progress, i + 1, subject)

            if not self._cancelled:
                self.app.call_from_thread(
                    self._update_status_text, 'Fetching message counts...')
                msg_result = b4.review.tracking.update_message_counts(
                    self._identifier, self._series_list, topdir=self._topdir)
                self._result['followup_updated'] = msg_result.get('updated', 0)

        return self._result

    def _update_progress(self, completed: int, subject: str) -> None:
        self.query_one('#updateall-status', Label).update(
            f'Checking {completed}/{len(self._series_list)} series...'
        )
        self.query_one('#updateall-series', Label).update(subject)
        self.query_one('#updateall-progress', ProgressBar).progress = completed

    def _update_status_text(self, msg: str) -> None:
        self.query_one('#updateall-status', Label).update(msg)
        self.query_one('#updateall-series', Label).update('')

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.state == WorkerState.SUCCESS:
            self.dismiss(event.worker.result)
        elif event.state == WorkerState.ERROR:
            self.dismiss(self._result)


class BaseSelectionScreen(ModalScreen[Optional[str]]):
    """Modal for selecting the base commit before checking out a series.

    Lets the maintainer pick a base, checks whether a/b blobs match,
    and optionally runs a test apply when they don't.

    Returns None if cancelled, or the resolved base commit SHA.
    """

    BINDINGS = [
        Binding('ctrl+y', 'continue', 'Confirm', show=False),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    BaseSelectionScreen {
        align: center middle;
    }
    #base-dialog {
        width: 60;
        height: auto;
        max-height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
        overflow: hidden;
    }
    #base-title {
        text-style: bold;
        margin-bottom: 1;
    }
    .base-pass {
        color: $success;
    }
    .base-fail {
        color: $error;
    }
    .base-warn {
        color: $warning;
    }
    #base-hint {
        margin-bottom: 1;
    }
    #base-status {
        margin-top: 1;
    }
    #base-footer {
        color: $text-muted;
        margin-top: 1;
    }
    """

    def __init__(self, initial_base: str,
                 lser: 'b4.LoreSeries',
                 ambytes: bytes,
                 base_suggestions: Optional[List[str]] = None,
                 base_hint: str = '') -> None:
        """Initialize the base selection screen.

        Args:
            initial_base: Pre-filled base ref (short SHA, branch, or "HEAD")
            lser: The LoreSeries, used for check_applies_clean()
            ambytes: Pre-built mbox bytes for test apply
            base_suggestions: Branch/ref names for the input suggester
            base_hint: Informational line about the guessed/specified base
        """
        super().__init__()
        self._initial_base = initial_base
        self._lser = lser
        self._ambytes = ambytes
        self._base_suggestions = base_suggestions
        self._base_hint = base_hint
        self._resolved_base: Optional[str] = None

    def compose(self) -> ComposeResult:
        with Vertical(id='base-dialog'):
            yield Static('Select Base Commit', id='base-title', markup=False)
            if self._base_hint:
                yield Static(self._base_hint, id='base-hint',
                             classes='base-warn', markup=False)
            yield Static('Base:', markup=False)
            suggester = SuggestFromList(
                self._base_suggestions, case_sensitive=True,
            ) if self._base_suggestions else None
            yield Input(value=self._initial_base, id='base-input',
                        suggester=suggester)
            yield Static('', id='base-status', markup=False)
            yield Static(
                'Enter check  |  Ctrl-y confirm  |  Escape cancel',
                id='base-footer', markup=False,
            )

    def on_mount(self) -> None:
        self.query_one('#base-input', Input).focus()
        # Run initial applicability check for the pre-filled value
        self._check_base(self._initial_base)

    def _update_status(self, text: str, level: str) -> None:
        """Update the status line below the input."""
        widget = self.query_one('#base-status', Static)
        widget.update(text)
        widget.remove_class('base-pass', 'base-warn', 'base-fail')
        widget.add_class(f'base-{level}')

    def _check_base(self, value: str) -> None:
        """Resolve a ref and run check_applies_clean against it."""
        topdir = b4.git_get_toplevel()
        if not topdir:
            self._update_status('not in a git repository', 'fail')
            return

        ecode, out = b4.git_run_command(
            topdir, ['rev-parse', '--verify', value])
        if ecode != 0:
            self._update_status(f'not a valid ref: {value}', 'fail')
            self._resolved_base = None
            return

        self._resolved_base = out.strip()

        if self._lser.indexes:
            try:
                checked, mismatches = self._lser.check_applies_clean(
                    topdir, at=self._resolved_base)
                if len(mismatches) == 0:
                    self._update_status(
                        f'Apply results: clean ({self._resolved_base[:12]})',
                        'pass')
                else:
                    matched = checked - len(mismatches)
                    self._update_status(
                        f'Apply results: {matched}/{checked} a/b blobs match'
                        f' — testing\u2026', 'warn')
                    self._run_test_apply()
            except Exception:
                self._update_status('could not check applicability', 'warn')
        else:
            self._update_status(
                f'will use {self._resolved_base[:12]}', 'pass')

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Validate the entered base ref."""
        if event.input.id != 'base-input':
            return
        value = event.value.strip()
        if not value:
            self.notify('Base commit is required', severity='error')
            return
        self._check_base(value)

    def _run_test_apply(self) -> None:
        """Test-apply patches in a temp worktree (worker thread)."""
        base = self._resolved_base
        if not base:
            return
        self.run_worker(
            lambda: self._test_apply_at(self._ambytes, base),
            name='_test_apply', thread=True,
        )

    @staticmethod
    def _test_apply_at(ambytes: bytes,
                       base: str) -> Tuple[bool, str]:
        """Run git-am in a throwaway sparse worktree. Returns (ok, detail)."""
        topdir = b4.git_get_toplevel()
        if not topdir:
            return False, 'not in a git repository'
        with _quiet_worker():
            try:
                with b4.git_temp_worktree(topdir, base) as gwt:
                    ecode, out = b4.git_run_command(
                        gwt, ['sparse-checkout', 'set'])
                    if ecode > 0:
                        return False, 'failed to set up worktree'
                    ecode, out = b4.git_run_command(
                        gwt, ['checkout', '-f'])
                    if ecode > 0:
                        return False, 'failed to checkout base'
                    ecode, out = b4.git_run_command(
                        gwt, ['am'], stdin=ambytes)
                    if ecode > 0:
                        # Extract just the "Patch failed" line
                        for line in out.splitlines():
                            if line.startswith('Patch failed at '):
                                return False, line
                        return False, 'apply failed'
                    return True, 'success'
            except Exception as ex:
                return False, str(ex)

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != '_test_apply':
            return
        if event.state == WorkerState.SUCCESS and event.worker.result:
            ok, detail = event.worker.result
            if ok:
                self._update_status('Apply results: success', 'pass')
            else:
                self._update_status(f'Apply results: {detail}', 'fail')
        elif event.state == WorkerState.ERROR:
            self._update_status('test apply error', 'fail')

    def action_continue(self) -> None:
        if self._resolved_base:
            self.dismiss(self._resolved_base)
            return
        # Try to resolve whatever is in the input
        value = self.query_one('#base-input', Input).value.strip()
        if not value:
            self.notify('Base commit is required', severity='error')
            return
        topdir = b4.git_get_toplevel()
        if not topdir:
            return
        ecode, out = b4.git_run_command(
            topdir, ['rev-parse', '--verify', value])
        if ecode != 0:
            self.notify(f'Not a valid ref: {value}', severity='error')
            return
        self.dismiss(out.strip())

    def action_cancel(self) -> None:
        self.dismiss(None)


class LimitScreen(ModalScreen[Optional[str]]):
    """Modal screen for mutt-style limit (filter) by author/subject."""

    BINDINGS = [
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    LimitScreen {
        align: center middle;
    }
    #limit-dialog {
        width: 60;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #limit-title {
        text-style: bold;
        margin-bottom: 1;
    }
    #limit-hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

    def __init__(self, current_pattern: str = '') -> None:
        super().__init__()
        self._current_pattern = current_pattern

    def compose(self) -> ComposeResult:
        with Vertical(id='limit-dialog'):
            yield Static('Limit by author/subject:', id='limit-title')
            yield Input(value=self._current_pattern, id='limit-input',
                        placeholder='substring to match (empty to clear)')
            yield Static('Enter apply  |  Escape cancel', id='limit-hint')

    def on_mount(self) -> None:
        self.query_one('#limit-input', Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class UpdateRevisionScreen(JKListNavMixin, ModalScreen[Optional[int]]):
    """Modal to select a newer revision to upgrade to.

    Shows available newer revisions and a confirmation message.
    Returns the chosen revision number, or None on cancel.
    """

    _list_id = '#update-rev-list'

    BINDINGS = [
        Binding('j', 'cursor_down', 'Down', show=False),
        Binding('k', 'cursor_up', 'Up', show=False),
        Binding('enter', 'confirm', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    UpdateRevisionScreen {
        align: center middle;
    }
    #update-rev-dialog {
        width: 65;
        height: auto;
        max-height: 80%;
        border: solid $warning;
        background: $surface;
        padding: 1 2;
    }
    #update-rev-title {
        text-style: bold;
        color: $warning;
        margin-bottom: 1;
    }
    #update-rev-list {
        height: auto;
        max-height: 20;
    }
    #update-rev-hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

    def __init__(self, current_revision: int,
                 revisions: List[Dict[str, Any]]) -> None:
        super().__init__()
        self._current_revision = current_revision
        self._revisions = [
            r for r in revisions
            if r['revision'] > current_revision
        ]

    def compose(self) -> ComposeResult:
        with Vertical(id='update-rev-dialog'):
            yield Static('Upgrade review branch', id='update-rev-title')
            yield Static(
                f'Current revision: v{self._current_revision}\n'
                'The current review branch will be archived.\n'
                'Reviews on unchanged patches will be preserved.')
            items = []
            for r in self._revisions:
                subject = r.get('subject', '(no subject)')
                label = f'v{r["revision"]}  {subject}'
                items.append(ListItem(Label(label, markup=False)))
            yield ListView(*items, id='update-rev-list')
            yield Static('Enter confirm  |  Escape cancel',
                         id='update-rev-hint')

    def on_mount(self) -> None:
        self.query_one('#update-rev-list', ListView).focus()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self._do_confirm()

    def action_confirm(self) -> None:
        self._do_confirm()

    def _do_confirm(self) -> None:
        lv = self.query_one('#update-rev-list', ListView)
        if lv.index is not None and 0 <= lv.index < len(self._revisions):
            self.dismiss(self._revisions[lv.index]['revision'])
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class ActionItem(ListItem):
    """A single action entry in the action selector."""

    def __init__(self, key: str, label: str) -> None:
        super().__init__()
        self.key = key
        self._label = label

    def compose(self) -> ComposeResult:
        yield Label(self._label, markup=False)


class ActionScreen(JKListNavMixin, ModalScreen[Optional[str]]):
    """Modal presenting context-sensitive actions for a tracked series.

    Returns the action key string (e.g. 'take', 'archive') or None on cancel.
    Shortcut keys allow single-keypress selection without navigating.
    """

    _list_id = '#action-list'

    BINDINGS = [
        Binding('j', 'cursor_down', 'Down', show=False),
        Binding('k', 'cursor_up', 'Up', show=False),
        Binding('enter', 'confirm', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    _SHORTCUT_MAP = {
        'review': 'r',
        'take': 'T',
        'rebase': 'R',
        'waiting': 'w',
        'snooze': 's',
        'unsnooze': 'u',
        'upgrade': 'U',
        'thank': 't',
        'abandon': 'A',
        'archive': 'x',
    }

    DEFAULT_CSS = """
    ActionScreen {
        align: center middle;
    }
    #action-dialog {
        width: 45;
        height: auto;
        max-height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #action-list {
        height: auto;
        max-height: 20;
    }
    """

    def __init__(self, actions: List[Tuple[str, str]]) -> None:
        super().__init__()
        self._actions = actions          # [(key, label), ...]
        # Reverse map: shortcut char -> action key (for current actions only)
        self._shortcut_to_action = {
            self._SHORTCUT_MAP[key]: key
            for key, _label in actions
            if key in self._SHORTCUT_MAP
        }

    def compose(self) -> ComposeResult:
        with Vertical(id='action-dialog'):
            yield Label('Select action:')
            items = []
            for key, label in self._actions:
                shortcut = self._SHORTCUT_MAP.get(key, '')
                if shortcut:
                    label = f'[{shortcut}] {label}'
                items.append(ActionItem(key, label))
            yield ListView(*items, id='action-list')

    def on_mount(self) -> None:
        self.query_one('#action-list', ListView).focus()

    def on_key(self, event: "Key") -> None:
        ch = event.character
        if not ch:
            return
        action_key = self._shortcut_to_action.get(ch)
        if action_key:
            event.stop()
            event.prevent_default()
            self.dismiss(action_key)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        self._do_confirm()

    def action_confirm(self) -> None:
        self._do_confirm()

    def _do_confirm(self) -> None:
        lv = self.query_one('#action-list', ListView)
        if lv.index is not None and 0 <= lv.index < len(self._actions):
            self.dismiss(self._actions[lv.index][0])
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class CheckLoadingScreen(ModalScreen[None]):
    """Lightweight loading overlay shown while CI checks are running."""

    BINDINGS = [
        Binding('escape', 'dismiss', 'Cancel', show=False),
    ]

    DEFAULT_CSS = """
    CheckLoadingScreen {
        align: center middle;
    }
    #cl-dialog {
        width: 50;
        height: auto;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #cl-title {
        text-style: bold;
        margin-bottom: 1;
    }
    """

    def __init__(self, title: str = 'Running checks\u2026') -> None:
        super().__init__()
        self._title = title

    def compose(self) -> ComposeResult:
        with Vertical(id='cl-dialog'):
            yield Static(self._title, id='cl-title', markup=False)
            yield LoadingIndicator()

    def update_status(self, text: str) -> None:
        """Update the title text from outside the modal."""
        self.query_one('#cl-title', Static).update(text)


class TrackingCheckResultsScreen(ModalScreen[str]):
    """Modal for displaying CI check results in a matrix view.

    The matrix shows patches as rows and check tools as columns, with
    colour-coded status indicators.  Press Enter on a row to see
    detailed results in a scrollable view.

    Dismiss result: ``'close'`` for normal close, ``'rerun'`` to re-run
    all checks ignoring the cache.
    """

    BINDINGS = [
        Binding('escape', 'close_or_back', 'Close'),
        Binding('q', 'close_or_back', 'Close', show=False),
        Binding('enter', 'details', 'Details'),
        Binding('R', 'rerun', 'Rerun', key_display='R'),
        Binding('j', 'cursor_down', 'Down', show=False),
        Binding('k', 'cursor_up', 'Up', show=False),
        Binding('space', 'page_down', 'Page down', show=False),
        Binding('backspace', 'page_up', 'Page up', show=False),
    ]

    DEFAULT_CSS = """
    TrackingCheckResultsScreen {
        align: center middle;
    }
    #tcr-dialog {
        width: 90%;
        height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
    }
    #tcr-title {
        text-style: bold;
        margin-bottom: 1;
    }
    #tcr-matrix {
        height: 1fr;
    }
    #tcr-detail {
        height: 1fr;
    }
    #tcr-hint {
        height: 1;
        dock: bottom;
        color: $text;
        background: $panel;
    }
    """

    _STATUS_DOTS = {
        'pass': ('\u25cf', 'green'),
        'warn': ('\u25cf', 'yellow'),
        'fail': ('\u25cf', 'red'),
    }

    def __init__(
            self,
            title: str,
            patch_labels: List[str],
            patch_subjects: List[str],
            tools: List[str],
            matrix: Dict[Tuple[int, str], Dict[str, str]],
    ) -> None:
        """Create a check results modal.

        *patch_labels*: display labels like ``['0/3', '1/3', '2/3', '3/3']``.
        *patch_subjects*: clean subject for each patch (same order as labels).
        *tools*: column headers (tool names).
        *matrix*: ``{(patch_idx, tool): {status, summary, url, details}}``.
        """
        super().__init__()
        self._title = title
        self._patch_labels = patch_labels
        self._patch_subjects = patch_subjects
        self._tools = tools
        self._matrix = matrix
        self._in_detail = False
        self._cursor_row = 0

    def compose(self) -> ComposeResult:
        with Vertical(id='tcr-dialog'):
            yield Static(self._title, id='tcr-title', markup=False)
            yield RichLog(id='tcr-matrix', highlight=False, wrap=False,
                          markup=True, auto_scroll=False)
            yield RichLog(id='tcr-detail', highlight=False, wrap=True,
                          markup=True, auto_scroll=False)
            yield Static(Text('[j/k] navigate  [Enter] details  [R] rerun  [q] close'),
                         id='tcr-hint')

    def on_mount(self) -> None:
        self.query_one('#tcr-detail', RichLog).display = False
        self.call_after_refresh(self._render_matrix)

    def _render_matrix(self) -> None:
        viewer = self.query_one('#tcr-matrix', RichLog)
        viewer.clear()
        viewer.scroll_home(animate=False)

        if not self._tools:
            viewer.write(Text('No check results to display.', style='dim'))
            return

        # Compute column widths
        label_w = max(len(lbl) for lbl in self._patch_labels) if self._patch_labels else 5
        col_w = max(max(len(t) for t in self._tools), 8)
        ci_total = (col_w + 2) * len(self._tools)
        # pointer(2) + label + gap(2) + subject + gap(2) + ci_columns
        fixed_w = 2 + label_w + 2 + 2 + ci_total
        avail_w = viewer.size.width - 2 if viewer.size.width else 80
        subj_w = max(avail_w - fixed_w, 10)

        # Header row
        header = Text()
        header.append(' ' * (2 + label_w + 2))
        header.append(f'{"Subject":<{subj_w}s}  ', style='bold')
        for tool in self._tools:
            header.append(f'{tool:^{col_w}s}  ', style='bold')
        viewer.write(header)
        viewer.write(Text('\u2500' * (fixed_w + subj_w)))

        # Data rows with cursor highlight
        for pidx, label in enumerate(self._patch_labels):
            is_selected = (pidx == self._cursor_row)
            row = Text(style='on grey27' if is_selected else '')
            pointer = '\u25b6 ' if is_selected else '  '
            row.append(pointer)
            row.append(f'{label:>{label_w}s}', style='bold' if is_selected else '')
            row.append('  ')
            # Truncated subject
            subj = self._patch_subjects[pidx] if pidx < len(self._patch_subjects) else ''
            if len(subj) > subj_w:
                subj = subj[:subj_w - 1] + '\u2026'
            row.append(f'{subj:<{subj_w}s}  ', style='' if is_selected else 'dim')
            for tool in self._tools:
                cell = self._matrix.get((pidx, tool))
                if cell:
                    status = cell.get('status', '')
                    dot, colour = self._STATUS_DOTS.get(status, ('\u2013', 'dim'))
                    cell_text = f'{dot} {status:<{col_w - 2}s}'
                    row.append(cell_text, style=colour)
                    row.append('  ')
                else:
                    dash = '\u2013'
                    row.append(f'{dash:^{col_w}s}  ', style='dim')
            viewer.write(row)

    def _render_detail(self, pidx: int) -> None:
        detail = self.query_one('#tcr-detail', RichLog)
        detail.clear()
        detail.scroll_home(animate=False)

        label = self._patch_labels[pidx] if pidx < len(self._patch_labels) else '?'
        detail.write(Text(f'Details for {label}', style='bold'))
        detail.write('')

        found_any = False
        for tool in self._tools:
            cell = self._matrix.get((pidx, tool))
            if not cell:
                continue
            found_any = True
            status = cell.get('status', '')
            dot, colour = self._STATUS_DOTS.get(status, ('\u2022', 'dim'))
            # Build panel body
            body = Text()
            summary = cell.get('summary', '')
            if summary:
                body.append(f'{summary}\n')
            details_text = cell.get('details', '')
            if details_text:
                body.append('\n')
                self._render_detail_lines(body, details_text)
            url = cell.get('url', '')
            if url:
                body.append(f'\n\u2192 {url}', style='dim')
            # Title: "● tool — STATUS"
            title = Text()
            title.append(f'{dot} ', style=colour)
            title.append(f'{tool}', style='bold')
            title.append(f' \u2014 {status.upper()}', style=colour)
            panel = Panel(
                body,
                box=box.ROUNDED,
                border_style=colour,
                title=title,
                title_align='left',
                expand=True,
                padding=(0, 1),
            )
            detail.write(panel)

        if not found_any:
            detail.write(Text('No results for this patch.', style='dim'))

    def _render_detail_lines(self, body: Text, details: str) -> None:
        """Append detail lines to *body*, handling JSON check lists specially."""
        try:
            check_list = json.loads(details)
            if not isinstance(check_list, list):
                raise ValueError
        except (json.JSONDecodeError, ValueError):
            # Plain text fallback
            for line in details.splitlines():
                body.append(f'{line}\n')
            return
        # Structured check list (from patchwork or checkpatch)
        for entry in check_list:
            if not isinstance(entry, dict):
                continue
            status = entry.get('status', '')
            dot, colour = self._STATUS_DOTS.get(status, ('\u2022', 'dim'))
            context = entry.get('context', '')
            state = entry.get('state', status)
            desc = entry.get('description', '')
            url = entry.get('url', '')
            body.append(f'{dot} ', style=colour)
            if context:
                # Patchwork-style: state + context + description
                body.append(f'{state}  ', style=colour)
                parts = [context]
                if desc:
                    parts.append(desc)
                body.append(' \u2014 '.join(parts))
            else:
                # Checkpatch-style: just the finding text
                body.append(desc)
            body.append('\n')
            if url:
                body.append(f'  \u2192 {url}\n', style='dim')

    def action_details(self) -> None:
        if self._in_detail:
            return
        pidx = self._cursor_row
        self._in_detail = True
        self.query_one('#tcr-matrix', RichLog).display = False
        self.query_one('#tcr-detail', RichLog).display = True
        self.query_one('#tcr-hint', Static).update(Text('[q] back to matrix'))
        self._render_detail(pidx)

    def action_close_or_back(self) -> None:
        if self._in_detail:
            self._in_detail = False
            self.query_one('#tcr-detail', RichLog).display = False
            self.query_one('#tcr-matrix', RichLog).display = True
            self.query_one('#tcr-hint', Static).update(
                Text('[j/k] navigate  [Enter] details  [R] rerun  [q] close'))
            return
        self.dismiss('close')

    def action_rerun(self) -> None:
        self.dismiss('rerun')

    def action_cursor_down(self) -> None:
        if self._in_detail:
            self.query_one('#tcr-detail', RichLog).scroll_down()
            return
        if self._cursor_row < len(self._patch_labels) - 1:
            self._cursor_row += 1
            self._render_matrix()

    def action_cursor_up(self) -> None:
        if self._in_detail:
            self.query_one('#tcr-detail', RichLog).scroll_up()
            return
        if self._cursor_row > 0:
            self._cursor_row -= 1
            self._render_matrix()

    def action_page_down(self) -> None:
        if self._in_detail:
            self.query_one('#tcr-detail', RichLog).scroll_page_down()
            return
        self._cursor_row = len(self._patch_labels) - 1
        self._render_matrix()

    def action_page_up(self) -> None:
        if self._in_detail:
            self.query_one('#tcr-detail', RichLog).scroll_page_up()
            return
        self._cursor_row = 0
        self._render_matrix()
