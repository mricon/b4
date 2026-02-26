#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import email.message
import email.utils

from typing import Any, Dict, List, Optional, Tuple

import b4

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import Checkbox, Input, Label, ListItem, ListView, LoadingIndicator, ProgressBar, RichLog, Select, Static, TextArea
from textual.screen import ModalScreen
from textual.worker import Worker, WorkerState
from rich.markup import escape as _escape_markup
from rich.rule import Rule
from rich.text import Text

from b4.review_tui._common import (
    CI_CHECK_MARKUP,
    JKListNavMixin,
    _addrs_to_lines, _lines_to_header, _validate_addrs,
    _write_diff_line, _quiet_worker,
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


def _review_help_lines(has_agent: bool = False, has_check: bool = False) -> List[str]:
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
        '  [bold]f[/bold]         Load follow-up comments from lore\n',
    ]
    if has_agent:
        lines.append('  [bold]a[/bold]         Run review agent\n')
    if has_check:
        lines.append('  [bold]x[/bold]         Run check command\n')
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
    '\n',
    '[bold]App[/bold]\n',
    '  [bold]u[/bold]         Update all tracked series\n',
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
                viewer.write(line)
            viewer.write('')

    def action_edit(self) -> None:
        self.dismiss('__EDIT__')

    def action_delete(self) -> None:
        self.dismiss('__DELETE__')

    def action_cancel(self) -> None:
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
        lines: List[str] = []
        lines.append(f'[bold]Send {len(self._msgs)} review email(s)?[/bold]\n')
        for msg in self._msgs:
            subj = str(msg['Subject']) if msg['Subject'] else '(no subject)'
            lines.append(f'  [bold]Subject:[/bold] {_escape_markup(subj)}')
            to_count = len(email.utils.getaddresses([msg['To']])) if msg['To'] else 0
            cc_count = len(email.utils.getaddresses([msg['Cc']])) if msg['Cc'] else 0
            recip_parts: List[str] = []
            if to_count:
                recip_parts.append(f'{to_count} To')
            if cc_count:
                recip_parts.append(f'{cc_count} Cc')
            if recip_parts:
                lines.append(f'          {", ".join(recip_parts)}')
            lines.append('')
        with Vertical(id='send-dialog'):
            yield Static('\n'.join(lines))
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
                 num_patches: int = 0) -> None:
        """Initialize take screen.

        Args:
            target_branch: Pre-populated target branch name
            review_branch: The review branch to take
            num_patches: Number of patches in the series
        """
        super().__init__()
        self._target_branch = target_branch
        self._review_branch = review_branch
        self._default_method = 'linear' if num_patches == 1 else 'merge'
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
            yield Input(value=self._target_branch, id='take-target')
            yield Static('Method:', classes='take-label')
            yield Select(method_options, value=self._default_method, id='take-method', allow_blank=False)
            yield Checkbox('add Link:', value=True, id='take-add-link', classes='take-checkbox')
            yield Checkbox('add Signed-off-by:', value=True, id='take-add-signoff', classes='take-checkbox')
            yield Static('Ctrl-y confirm  |  Escape cancel', id='take-hint')

    def on_mount(self) -> None:
        self.query_one('#take-target', Input).focus()

    def action_continue_take(self) -> None:
        self.target_result = self.query_one('#take-target', Input).value.strip()
        if not self.target_result:
            self.notify('Target branch is required', severity='error')
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
        Binding('y', 'continue_pick', 'Confirm'),
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
    #cherrypick-hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

    def __init__(self, patches: List[Dict[str, Any]]) -> None:
        super().__init__()
        self._patches = patches
        self.selected_indices: List[int] = []

    def compose(self) -> ComposeResult:
        with Vertical(id='cherrypick-dialog'):
            yield Static('Select patches to apply', id='cherrypick-title')
            with Vertical(id='cherrypick-list'):
                for i, patch in enumerate(self._patches):
                    title = patch.get('title', f'Patch {i + 1}')
                    yield Checkbox(f' {i + 1:3d}. {title}', value=False,
                                   id=f'cherrypick-{i}', classes='cherrypick-checkbox')
            yield Static('y confirm  |  Escape cancel', id='cherrypick-hint')

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
            yield Static(self._loading_text, id='fv-title')
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
                        _write_diff_line(viewer, line)
                    else:
                        viewer.write(_escape_markup(line))


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
            _escape_markup(f'CI checks \u2014 {series_name}'))
        viewer = self.query_one('#fv-viewer', RichLog)

        if not checks:
            viewer.write(Text('No CI checks reported for this series.', style='dim'))
            return

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
                indicator = CI_CHECK_MARKUP.get(state, CI_CHECK_MARKUP['pending'])
                context = _escape_markup(check.get('context') or 'default')
                line = f'  {indicator}  {context}'
                desc = check.get('description')
                if desc:
                    desc_lines = desc.splitlines()
                    line += f' \u2014 {_escape_markup(desc_lines[0])}'
                    viewer.write(line)
                    # Indent continuation lines to align with first
                    for dline in desc_lines[1:]:
                        viewer.write(f'    {_escape_markup(dline)}')
                else:
                    viewer.write(line)
                target_url = check.get('target_url')
                if target_url:
                    viewer.write(f'    [dim]\u2192 {_escape_markup(target_url)}[/dim]')


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
    }
    #confirm-title {
        text-style: bold;
        margin-bottom: 1;
    }
    #confirm-hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

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
        dialog.styles.border = ('solid', self._border)
        with dialog:
            title = Static(self._title, id='confirm-title', markup=False)
            if self._title_colour:
                title.styles.color = self._title_colour
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


def RebaseConfirmScreen(current_branch: str, review_branch: str) -> ConfirmScreen:
    """Build a confirmation screen for rebase operation."""
    return ConfirmScreen(
        title='Rebase Series',
        body=[
            f'Review branch: {review_branch}',
            f'Rebase on top of: {current_branch}',
            '',
            'Proceed with rebase?',
        ],
    )


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
            yield Label(self._series_name, id='apply-series')
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
        }

    def compose(self) -> ComposeResult:
        with Vertical(id='updateall-dialog'):
            yield Label('Updating all tracked series', id='updateall-title')
            yield Label(f'Checking 0/{len(self._series_list)} series...', id='updateall-status')
            yield Label('', id='updateall-series')
            yield ProgressBar(total=len(self._series_list), show_eta=False, id='updateall-progress')

    def on_mount(self) -> None:
        self.run_worker(self._do_updates, thread=True)

    def action_cancel(self) -> None:
        self._cancelled = True

    def _do_updates(self) -> Dict[str, int]:
        import b4.review

        with _quiet_worker():
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

        return self._result

    def _update_progress(self, completed: int, subject: str) -> None:
        self.query_one('#updateall-status', Label).update(
            f'Checking {completed}/{len(self._series_list)} series...'
        )
        self.query_one('#updateall-series', Label).update(subject)
        self.query_one('#updateall-progress', ProgressBar).progress = completed

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.state == WorkerState.SUCCESS:
            self.dismiss(event.worker.result)
        elif event.state == WorkerState.ERROR:
            self.dismiss(self._result)


class AttestationScreen(ModalScreen[bool]):
    """Modal showing attestation status before checking out a series.

    Displays attestation status and asks the user to confirm
    before proceeding. Returns True to continue, False to cancel.
    """

    BINDINGS = [
        Binding('y', 'continue', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

    DEFAULT_CSS = """
    AttestationScreen {
        align: center middle;
    }
    #att-dialog {
        width: 60;
        height: auto;
        max-height: 80%;
        border: solid $accent;
        background: $surface;
        padding: 1 2;
        overflow: hidden;
    }
    #att-title {
        text-style: bold;
        margin-bottom: 1;
    }
    .att-line {
        overflow: hidden;
        width: 100%;
    }
    .att-pass {
        color: $success;
    }
    .att-fail {
        color: $error;
    }
    .att-warn {
        color: $warning;
    }
    #att-critical {
        color: $error;
        text-style: bold;
        margin-top: 1;
    }
    #att-footer {
        color: $text-muted;
        margin-top: 1;
    }
    """

    def __init__(self, attestation_result: Dict[str, Any]) -> None:
        """Initialize the attestation screen.

        Args:
            attestation_result: Dict with keys:
                - total: Total number of patches
                - passing: Number of passing patches
                - critical: If True, hardfail policy triggered
                - same_attestation: If True, all patches have same trailers
                - trailers: Common trailers (if same_attestation) or None
                - per_patch: List of per-patch info (if not same_attestation)
        """
        super().__init__()
        self._result = attestation_result

    def compose(self) -> ComposeResult:
        total = self._result.get('total', 0)
        passing = self._result.get('passing', 0)
        failing = total - passing
        critical = self._result.get('critical', False)
        same_att = self._result.get('same_attestation', False)
        attestations = self._result.get('attestations', [])
        per_patch = self._result.get('per_patch', [])

        with Vertical(id='att-dialog'):
            yield Static('Attestation Check', id='att-title', markup=False)

            # Summary line and details
            if total == 0:
                yield Static('No patches to check', classes='att-warn', markup=False)
            elif same_att:
                # All patches have the same attestation - show summary with details
                if not attestations:
                    yield Static(f'{total} patches, no attestations found', classes='att-warn', markup=False)
                elif failing == 0:
                    yield Static(f'All {total} patches have valid attestations', classes='att-pass', markup=False)
                else:
                    yield Static(f'All {total} patches have attestation issues', classes='att-fail', markup=False)
                # Show each attestation with its own status colour
                for att in attestations:
                    text = self._format_attestation(att)
                    if att.get('passing', False):
                        yield Static(f'  {text}', classes='att-line att-pass', markup=False)
                    else:
                        yield Static(f'  {text}', classes='att-line att-fail', markup=False)
            else:
                # Different attestation per patch - show summary and per-patch breakdown
                if failing == 0:
                    yield Static(f'All {total} patches have valid attestations', classes='att-pass', markup=False)
                else:
                    yield Static(f'{failing}/{total} patches have attestation issues', classes='att-fail', markup=False)
                # Only show patches with issues (limit to avoid overflow)
                shown = 0
                for pinfo in per_patch:
                    if pinfo.get('passing', True):
                        continue
                    if shown >= 5:
                        remaining = failing - shown
                        yield Static(f'  ... and {remaining} more', classes='att-fail', markup=False)
                        break
                    idx = pinfo.get('index', '??/??')
                    yield Static(f'  patch {idx}:', classes='att-fail', markup=False)
                    for att in pinfo.get('attestations', []):
                        if not att.get('passing', False):
                            text = self._format_attestation(att)
                            yield Static(f'    {text}', classes='att-line att-fail', markup=False)
                    shown += 1

            # Show applicability information
            base_commit = self._result.get('base_commit')
            base_exists = self._result.get('base_exists', False)
            applies_clean = self._result.get('applies_clean')
            apply_checked = self._result.get('apply_checked', 0)
            apply_mismatches = self._result.get('apply_mismatches', 0)

            yield Static('', markup=False)  # Blank line separator

            if base_commit:
                short_base = base_commit[:12] if len(base_commit) > 12 else base_commit
                if base_exists:
                    if applies_clean is True:
                        yield Static(f'Base: {short_base} (applies clean)', classes='att-pass', markup=False)
                    elif applies_clean is False:
                        yield Static(f'Base: {short_base} ({apply_checked - apply_mismatches}/{apply_checked} blobs match)',
                                     classes='att-warn', markup=False)
                    else:
                        yield Static(f'Base: {short_base}', markup=False)
                else:
                    # Base commit not in repo - show HEAD applicability
                    if applies_clean is True:
                        yield Static(f'Base: {short_base} (not in repo, applies clean to HEAD)',
                                     classes='att-warn', markup=False)
                    elif applies_clean is False:
                        yield Static(f'Base: {short_base} (not in repo, {apply_checked - apply_mismatches}/{apply_checked} blobs match HEAD)',
                                     classes='att-warn', markup=False)
                    else:
                        yield Static(f'Base: {short_base} (not in repo)', classes='att-warn', markup=False)
            else:
                if applies_clean is True:
                    yield Static('Base: not specified (applies clean to HEAD)', classes='att-pass', markup=False)
                elif applies_clean is False:
                    yield Static(f'Base: not specified ({apply_checked - apply_mismatches}/{apply_checked} blobs match HEAD)',
                                 classes='att-warn', markup=False)
                else:
                    yield Static('Base: not specified', classes='att-warn', markup=False)

            if critical:
                yield Static('Cannot continue: attestation-policy is hardfail', id='att-critical', markup=False)
                yield Static('Escape cancel', id='att-footer', markup=False)
            else:
                yield Static('y confirm  |  Escape cancel', id='att-footer', markup=False)

    def _format_attestation(self, att: Dict[str, Any]) -> str:
        """Format an attestation dict for display."""
        status = att.get('status', 'unknown')
        identity = att.get('identity', 'unknown')

        if status == 'signed':
            if 'mismatch' in att:
                return f'Signed: {identity} (From: {att["mismatch"]})'
            return f'Signed: {identity}'
        elif status == 'badsig':
            return f'BADSIG: {identity}'
        elif status == 'nokey':
            return f'No key: {identity}'
        elif status == 'missing':
            return str(identity)
        return f'{status}: {identity}'

    def action_continue(self) -> None:
        if self._result.get('critical', False):
            self.notify('Cannot continue due to hardfail policy', severity='error')
            return
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


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
    """

    _list_id = '#action-list'

    BINDINGS = [
        Binding('j', 'cursor_down', 'Down', show=False),
        Binding('k', 'cursor_up', 'Up', show=False),
        Binding('enter', 'confirm', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
    ]

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

    def compose(self) -> ComposeResult:
        with Vertical(id='action-dialog'):
            yield Label('Select action:')
            yield ListView(
                *[ActionItem(key, label) for key, label in self._actions],
                id='action-list',
            )

    def on_mount(self) -> None:
        self.query_one('#action-list', ListView).focus()

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
