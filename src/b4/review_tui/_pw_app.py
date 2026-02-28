#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import json
import pathlib

from typing import Any, Dict, List, Optional, Set, Tuple

from rich.markup import escape as _escape_markup

import b4
import b4.review
import b4.review.tracking

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Label, ListItem, ListView, LoadingIndicator, Static
from textual.worker import Worker, WorkerState

from b4.review_tui._common import CI_MARKUP, logger, SeparatedFooter
from b4.review_tui._modals import (
    ViewSeriesScreen, CIChecksScreen, SetStateScreen, ApplyStateModal,
    LimitScreen, HelpScreen, PW_HELP_LINES,
)


def _format_series_label(series: Dict[str, Any], tracked: bool) -> str:
    """Build a Rich-markup label string for a series row."""
    track_mark = 'T' if tracked else ' '
    ci = CI_MARKUP.get(series.get('check') or 'pending', CI_MARKUP['pending'])
    date = _escape_markup((series.get('date') or '')[:10])
    state = _escape_markup(f"{(series.get('state') or 'new'):<15s}")
    submitter = _escape_markup(f"{(series.get('submitter') or 'Unknown'):<30s}")
    name = _escape_markup(series.get('name') or '(no subject)')
    return f'{track_mark}{ci} {date}  {state} {submitter} {name}'


class PwSeriesItem(ListItem):
    """A single Patchwork series entry in the listing."""

    ACTION_REQUIRED_STATES = ('new', 'under-review')

    def __init__(self, series: Dict[str, Any], tracked: bool = False) -> None:
        super().__init__()
        self.series = series
        self.tracked = tracked
        state = series.get('state', 'new')
        if state not in self.ACTION_REQUIRED_STATES:
            self.add_class('--dimmed')
        if tracked:
            self.add_class('--tracked')

    def compose(self) -> ComposeResult:
        yield Label(_format_series_label(self.series, self.tracked))


class PwApp(App[None]):
    """Textual app for browsing Patchwork series."""

    TITLE = 'b4 review pw'

    DEFAULT_CSS = """
    PwApp {
        layout: vertical;
    }
    #pw-title {
        dock: top;
        width: 100%;
        height: 1;
        background: $accent;
        color: $text;
        text-style: bold;
        content-align: center middle;
    }
    #pw-header {
        dock: top;
        width: 100%;
        height: 1;
        background: $surface;
        color: $text-muted;
    }
    #pw-list {
        height: 1fr;
    }
    PwSeriesItem.--dimmed Label {
        color: $text-disabled;
    }
    PwSeriesItem.--hidden Label {
        color: $text-disabled;
        text-style: dim italic;
    }
    PwSeriesItem.--tracked Label {
        color: $success-lighten-2;
        text-style: bold;
    }
    PwSeriesItem.--tracked.--dimmed Label {
        color: $success;
    }
    #pw-loading {
        height: 1fr;
        content-align: center middle;
    }
    """

    BINDING_GROUPS = {
        'view': 'Series', 'ci_checks': 'Series', 'track_series': 'Series',
        'set_state': 'Series', 'hide_series': 'Series',
        'limit': 'App', 'toggle_show_hidden': 'App', 'quit': 'App', 'help': 'App',
    }

    BINDINGS = [
        # Hidden navigation bindings
        Binding('j', 'cursor_down', 'Down', show=False),
        Binding('k', 'cursor_up', 'Up', show=False),
        Binding('enter', 'select_series', 'Select', show=False),
        Binding('u', 'unhide_series', 'unhide', show=False),
        # Series-specific actions
        Binding('v', 'view', 'view'),
        Binding('c', 'ci_checks', 'ci checks'),
        Binding('t', 'track_series', 'track'),
        Binding('s', 'set_state', 'set state'),
        Binding('h', 'hide_series', 'hide'),
        # App-global actions
        Binding('l', 'limit', 'limit'),
        Binding('H', 'toggle_show_hidden', 'show hidden', key_display='H'),
        Binding('q', 'quit', 'quit'),
        Binding('question_mark', 'help', 'help', key_display='?'),
    ]

    def __init__(self, pwkey: str, pwurl: str, pwproj: str) -> None:
        super().__init__()
        self._pwkey = pwkey
        self._pwurl = pwurl
        self._pwproj = pwproj
        self._states: List[Dict[str, Any]] = []
        self._hidden_ids: Set[int] = set()
        self._tracked_ids: Set[int] = set()
        self._show_hidden: bool = False
        self._limit_pattern: str = ''
        self._all_series: List[Dict[str, Any]] = []
        self._tracking_identifier: Optional[str] = None
        self._tracking_enabled: bool = False
        self._load_local_data()
        self._load_tracking_data()

    def _get_local_data_path(self) -> pathlib.Path:
        datadir = b4.get_data_dir('patchwork')
        return pathlib.Path(datadir) / f'{self._pwproj}.json'

    def _load_local_data(self) -> None:
        path = self._get_local_data_path()
        if not path.exists():
            return
        try:
            with open(path, 'r', encoding='utf-8') as fp:
                data = json.load(fp)
            for sid, sdata in data.get('series', {}).items():
                if sdata.get('hidden'):
                    self._hidden_ids.add(int(sid))
        except (json.JSONDecodeError, OSError):
            pass

    def _load_tracking_data(self) -> None:
        # Try to resolve tracking identifier from current repo or use pwproj
        topdir = b4.git_get_toplevel()
        if topdir:
            self._tracking_identifier = b4.review.tracking.get_repo_identifier(topdir)
        if not self._tracking_identifier:
            # Fall back to patchwork project name
            self._tracking_identifier = self._pwproj
        if self._tracking_identifier and b4.review.tracking.db_exists(self._tracking_identifier):
            self._tracking_enabled = True
            self._tracked_ids = b4.review.tracking.get_tracked_pw_series_ids(self._tracking_identifier)

    def _save_local_data(self) -> None:
        path = self._get_local_data_path()
        data: Dict[str, Any] = {'series': {}}
        for sid in self._hidden_ids:
            data['series'][str(sid)] = {'hidden': True}
        try:
            with open(path, 'w', encoding='utf-8') as fp:
                json.dump(data, fp, indent=2)
        except OSError:
            pass

    def compose(self) -> ComposeResult:
        yield Static(' Patchwork — loading\u2026', id='pw-title')
        yield LoadingIndicator(id='pw-loading')
        yield SeparatedFooter()

    def on_mount(self) -> None:
        self.run_worker(self._fetch_initial, name='_fetch_initial', thread=True)

    def _fetch_initial(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        import b4.review
        from b4.review_tui._common import _quiet_worker

        with _quiet_worker():
            series = b4.review.pw_fetch_series(self._pwkey, self._pwurl, self._pwproj)
            states = b4.review.pw_fetch_states(self._pwkey, self._pwurl, self._pwproj)
            return series, states

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name == '_fetch_initial':
            if event.state == WorkerState.SUCCESS:
                if event.worker.result is None:
                    return
                series_list, states = event.worker.result
                self._states = states
                await self._populate(series_list)
            elif event.state == WorkerState.ERROR:
                await self.query_one('#pw-loading', LoadingIndicator).remove()
                self.query_one('#pw-title', Static).update(' Patchwork — error fetching series')
                self.notify(str(event.worker.error), severity='error')

    async def _populate(self, series_list: List[Dict[str, Any]]) -> None:
        await self.query_one('#pw-loading', LoadingIndicator).remove()
        self._all_series = series_list
        await self._refresh_list()

    async def _refresh_list(self) -> None:
        title = self.query_one('#pw-title', Static)
        widgets = list(self.query('#pw-header, #pw-list'))
        for widget in widgets:
            await widget.remove()
        visible = []
        hidden_count = 0
        for s in self._all_series:
            sid = s.get('id')
            is_hidden = sid in self._hidden_ids
            if is_hidden:
                hidden_count += 1
                if self._show_hidden:
                    visible.append((s, True))
            else:
                visible.append((s, False))
        if self._limit_pattern:
            pat = self._limit_pattern.lower()
            visible = [
                (s, h) for s, h in visible
                if pat in (s.get('name', '') or '').lower()
                or pat in (s.get('submitter', '') or '').lower()
            ]
        limit_suffix = f', limit: {_escape_markup(self._limit_pattern)}' if self._limit_pattern else ''
        if hidden_count and not self._show_hidden:
            title.update(f' Patchwork — {len(visible)} series ({hidden_count} hidden{limit_suffix})')
        elif hidden_count and self._show_hidden:
            title.update(f' Patchwork — {len(visible)} series (showing {hidden_count} hidden{limit_suffix})')
        elif self._limit_pattern:
            title.update(f' Patchwork — {len(visible)} action-required series{limit_suffix}')
        else:
            title.update(f' Patchwork — {len(visible)} action-required series')
        if not visible:
            return
        header_text = f'   {"Date":<12s}{"State":<15s} {"Submitter":<30s} {"Series"}'
        header = Static(header_text, id='pw-header')
        items = []
        for s, is_hidden in visible:
            sid = s.get('id')
            is_tracked = sid in self._tracked_ids if sid else False
            item = PwSeriesItem(s, tracked=is_tracked)
            if is_hidden:
                item.add_class('--hidden')
            items.append(item)
        lv = ListView(*items, id='pw-list')
        await self.mount(header, before=self.query_one(Footer))
        await self.mount(lv, before=self.query_one(Footer))
        lv.focus()

    def action_limit(self) -> None:
        self.push_screen(LimitScreen(self._limit_pattern), callback=self._on_limit)

    async def _on_limit(self, result: Optional[str]) -> None:
        if result is None:
            return
        self._limit_pattern = result
        await self._refresh_list()

    def action_cursor_down(self) -> None:
        try:
            self.query_one('#pw-list', ListView).action_cursor_down()
        except Exception:
            pass

    def action_cursor_up(self) -> None:
        try:
            self.query_one('#pw-list', ListView).action_cursor_up()
        except Exception:
            pass

    def action_select_series(self) -> None:
        self.notify('Not implemented', severity='information')

    def action_view(self) -> None:
        """Preview a Patchwork series in a modal dialog."""
        item = self._get_highlighted_item()
        if item is None:
            return
        msgid = item.series.get('msgid', '')
        if not msgid:
            self.notify('No message-id available for this series', severity='error')
            return
        self.push_screen(ViewSeriesScreen(msgid))

    def action_ci_checks(self) -> None:
        """View CI check details for the highlighted series."""
        item = self._get_highlighted_item()
        if item is None:
            return
        check = item.series.get('check') or 'pending'
        if check == 'pending':
            self.notify('No CI checks available for this series', severity='information')
            return
        self.push_screen(CIChecksScreen(self._pwkey, self._pwurl, item.series))

    def _get_highlighted_item(self) -> Optional['PwSeriesItem']:
        try:
            lv = self.query_one('#pw-list', ListView)
        except Exception:
            return None
        child = lv.highlighted_child
        if isinstance(child, PwSeriesItem):
            return child
        return None

    def action_set_state(self) -> None:
        if not self._states:
            self.notify('States not loaded yet', severity='warning')
            return
        item = self._get_highlighted_item()
        if item is None:
            return
        current_state = item.series.get('state', 'new')
        self.push_screen(
            SetStateScreen(self._states, current_state),
            callback=lambda result: self._on_set_state(result, item),
        )

    def _on_set_state(self, result: Optional[Tuple[str, bool]], item: 'PwSeriesItem') -> None:
        if result is None:
            return
        new_state, archived = result
        patch_ids = item.series.get('patch_ids', [])
        if not patch_ids:
            self.notify('No patch IDs for this series', severity='warning')
            return

        series_name = item.series.get('name', '(no subject)')
        self.push_screen(
            ApplyStateModal(
                self._pwkey, self._pwurl, patch_ids,
                new_state, archived, series_name
            ),
            callback=lambda res: self._on_apply_complete(res, item),
        )

    def _on_apply_complete(self, result: Tuple[int, int, str], item: 'PwSeriesItem') -> None:
        ok, fail, new_state = result
        if fail:
            self.notify(f'{ok} updated, {fail} failed', severity='warning')
        else:
            self.notify(f'{ok} patch(es) set to {new_state}', severity='information')
        item.series['state'] = new_state
        if new_state in PwSeriesItem.ACTION_REQUIRED_STATES:
            item.remove_class('--dimmed')
        else:
            item.add_class('--dimmed')
        item.query_one(Label).update(_format_series_label(item.series, item.tracked))

    def action_track_series(self) -> None:
        import uuid

        if not self._tracking_enabled:
            self.notify('Repository not enrolled. Enroll with: b4 review enroll', severity='warning')
            return
        item = self._get_highlighted_item()
        if item is None:
            return
        sid = item.series.get('id')
        if sid is None:
            return
        if sid in self._tracked_ids:
            self.notify('Series already tracked', severity='information')
            return

        series_name = item.series.get('name', '(no subject)')
        msgid = item.series.get('msgid', '')
        if not msgid:
            self.notify('No message-id available for this series', severity='error')
            return

        s = item.series
        pw_series_id: int = sid

        # Suspend UI while retrieving from lore (produces logging output)
        with self.suspend():
            logger.info('Retrieving series: %s', msgid)
            try:
                msgs = b4.review._retrieve_messages(msgid)
            except Exception as ex:
                logger.critical('Error retrieving series: %s', ex)
                return

        try:
            lser = b4.review._get_lore_series(msgs)
        except LookupError as ex:
            self.notify(str(ex), severity='error')
            return

        # Extract series metadata
        if lser.change_id:
            change_id = lser.change_id
        else:
            change_id = str(uuid.uuid4())

        revision = lser.revision
        sender_name = lser.fromname
        sender_email = lser.fromemail
        num_patches = lser.expected
        subject = lser.subject

        # Get message-id from cover letter or first patch
        try:
            ref_msg = b4.review.get_reference_message(lser)
        except LookupError:
            self.notify('Could not find cover letter or first patch', severity='error')
            return

        message_id = ref_msg.msgid
        sent_at: Optional[str] = None
        if ref_msg.date:
            sent_at = ref_msg.date.isoformat()

        # Add to database
        assert self._tracking_identifier is not None
        conn = b4.review.tracking.get_db(self._tracking_identifier)
        b4.review.tracking.add_series_to_db(
            conn, change_id, revision, subject, sender_name, sender_email,
            sent_at, message_id, num_patches, pw_series_id
        )
        conn.close()

        # Update UI
        self._tracked_ids.add(pw_series_id)
        item.tracked = True
        item.add_class('--tracked')
        item.query_one(Label).update(_format_series_label(item.series, True))
        self.notify(f'Started tracking: {series_name}', severity='information', timeout=3)

    async def action_hide_series(self) -> None:
        item = self._get_highlighted_item()
        if item is None:
            return
        sid = item.series.get('id')
        if sid is None:
            return
        if sid in self._hidden_ids:
            self.notify('Series already hidden', severity='information')
            return
        self._hidden_ids.add(sid)
        self._save_local_data()
        title = item.series.get('name', '(no subject)')
        self.notify(f'Hidden: {title}', timeout=3)
        await self._refresh_list()

    async def action_toggle_show_hidden(self) -> None:
        if not self._hidden_ids:
            self.notify('No hidden series', severity='information')
            return
        self._show_hidden = not self._show_hidden
        await self._refresh_list()

    async def action_unhide_series(self) -> None:
        item = self._get_highlighted_item()
        if item is None:
            return
        sid = item.series.get('id')
        if sid is None:
            return
        if sid not in self._hidden_ids:
            self.notify('Series not hidden', severity='information')
            return
        self._hidden_ids.discard(sid)
        self._save_local_data()
        title = item.series.get('name', '(no subject)')
        self.notify(f'Restored: {title}', timeout=3)
        await self._refresh_list()

    def check_action(self, action: str, parameters: Tuple[Any, ...]) -> Optional[bool]:
        if action == 'ci_checks':
            item = self._get_highlighted_item()
            if item is None:
                return False
            return (item.series.get('check') or 'pending') != 'pending'
        if action == 'track_series':
            if not self._tracking_enabled:
                return True  # Allow action so user sees the helpful error message
            item = self._get_highlighted_item()
            if item is None:
                return False
            sid = item.series.get('id')
            return sid not in self._tracked_ids
        if action == 'toggle_show_hidden':
            return bool(self._hidden_ids)
        if action == 'unhide_series':
            item = self._get_highlighted_item()
            if item is None:
                return False
            sid = item.series.get('id')
            return sid in self._hidden_ids
        if action == 'hide_series':
            item = self._get_highlighted_item()
            if item is None:
                return False
            sid = item.series.get('id')
            return sid not in self._hidden_ids
        return True

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        self.refresh_bindings()

    def action_help(self) -> None:
        """Show keybinding help."""
        self.push_screen(HelpScreen(PW_HELP_LINES))

    async def action_quit(self) -> None:
        self.exit()

