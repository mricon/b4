#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Shared modal screens for b4 Textual apps."""
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from textual.events import Key

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Checkbox, Input, Label, ListItem, ListView, Static, TextArea

from b4.tui._common import (
    JKListNavMixin,
    _addrs_to_lines,
    _lines_to_header,
    _validate_addrs,
)


class ToCcScreen(ModalScreen[bool]):
    """Modal screen to edit To, Cc, and Bcc addresses."""

    BINDINGS = [
        Binding('ctrl+s', 'save', 'Save'),
        Binding('escape', 'cancel', 'Cancel'),
        Binding('q', 'cancel', 'Cancel', show=False),
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


class ConfirmScreen(ModalScreen[bool]):
    """Generic y/escape confirmation modal.

    *title*: border title text.
    *body*: list of plain strings rendered as ``Static`` widgets.
    *border*: Textual CSS border-colour token (e.g. ``'$warning'``).
    *subject*: optional bold subject line inside the dialog.
    """

    BINDINGS = [
        Binding('y', 'confirm', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
        Binding('q', 'cancel', 'Cancel', show=False),
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
                 title_colour: Optional[str] = None,
                 subject: str = '') -> None:
        super().__init__()
        self._title = title
        self._body = body
        self._border = border
        self._title_colour = title_colour
        self._subject = subject

    def compose(self) -> ComposeResult:
        dialog = Vertical(id='confirm-dialog')
        border_cls = self._COLOUR_CLASSES.get(self._border)
        if border_cls:
            dialog.add_class(f'--border-{border_cls}')
        with dialog:
            dialog.border_title = self._title
            if self._subject:
                yield Static(self._subject, id='confirm-title', markup=False)
            for line in self._body:
                yield Static(line, markup=False)
            yield Static('y confirm  |  Escape cancel', id='confirm-hint')

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_cancel(self) -> None:
        self.dismiss(False)


class LimitScreen(ModalScreen[Optional[str]]):
    """Modal for mutt-style limit (filter) by substring.

    Returns the entered string on submit, or None on cancel.
    The *title* sets the dialog border title, and *hint* adds
    extra help text above the standard key hints.
    """

    BINDINGS = [
        Binding('escape', 'cancel', 'Cancel'),
        Binding('q', 'cancel', 'Cancel', show=False),
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
    #limit-hint {
        margin-top: 1;
        color: $text-muted;
    }
    """

    def __init__(self, current_pattern: str = '',
                 hint: Optional[str] = None,
                 title: str = 'Limit') -> None:
        super().__init__()
        self._current_pattern = current_pattern
        self._hint = hint
        self._title = title

    def compose(self) -> ComposeResult:
        with Vertical(id='limit-dialog') as dialog:
            dialog.border_title = self._title
            yield Input(value=self._current_pattern, id='limit-input',
                        placeholder='substring to match (empty to clear)')
            hint_lines = ''
            if self._hint:
                hint_lines = self._hint + '\n'
            hint_lines += 'Enter apply  |  Escape cancel'
            yield Static(hint_lines, id='limit-hint')

    def on_mount(self) -> None:
        self.query_one('#limit-input', Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

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
    """Context-sensitive action selector with optional shortcut keys.

    *actions*: list of ``(key, label)`` tuples.
    *shortcuts*: optional ``{key: char}`` map for single-keypress selection.
    Returns the action key string or None on cancel.
    """

    _list_id = '#action-list'

    BINDINGS = [
        Binding('j', 'cursor_down', 'Down', show=False),
        Binding('k', 'cursor_up', 'Up', show=False),
        Binding('enter', 'confirm_action', 'Confirm'),
        Binding('escape', 'cancel', 'Cancel'),
        Binding('q', 'cancel', 'Cancel', show=False),
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

    def __init__(self, actions: List[Tuple[str, str]],
                 shortcuts: Optional[Dict[str, str]] = None) -> None:
        super().__init__()
        self._actions = actions
        self._shortcuts = shortcuts or {}
        self._shortcut_to_action = {
            self._shortcuts[key]: key
            for key, _label in actions
            if key in self._shortcuts
        }

    def compose(self) -> ComposeResult:
        with Vertical(id='action-dialog') as dialog:
            dialog.border_title = 'Select action'
            items = []
            for key, label in self._actions:
                shortcut = self._shortcuts.get(key, '')
                if shortcut:
                    label = f'[{shortcut}] {label}'
                items.append(ActionItem(key, label))
            yield ListView(*items, id='action-list')

    def on_mount(self) -> None:
        self.query_one('#action-list', ListView).focus()

    def on_key(self, event: 'Key') -> None:
        ch = event.character
        if not ch:
            return
        action_key = self._shortcut_to_action.get(ch)
        if action_key:
            event.stop()
            event.prevent_default()
            self.dismiss(action_key)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        event.stop()
        self._do_confirm()

    def action_confirm_action(self) -> None:
        self._do_confirm()

    def _do_confirm(self) -> None:
        lv = self.query_one('#action-list', ListView)
        if lv.index is not None and 0 <= lv.index < len(self._actions):
            self.dismiss(self._actions[lv.index][0])
        else:
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)
