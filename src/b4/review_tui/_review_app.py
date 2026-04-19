#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import email.message
import email.utils
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

from rich.rule import Rule
from rich.syntax import Syntax
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Click
from textual.widgets import Label, ListItem, ListView, RichLog, Static

import b4
import b4.mbox
import b4.review
import b4.review.tracking
from b4.review._review import COMMIT_MESSAGE_PATH
from b4.review_tui._common import (
    PATCH_STATE_MARKERS,
    CheckRunnerMixin,
    SeparatedFooter,
    _chain_has_additional_patch,
    _fix_ansi_theme,
    _get_followup_depth,
    _has_review_data,
    _make_initials,
    _quiet_worker,
    _render_email_to_viewer,
    _resolve_patch_for_followup,
    _suspend_to_shell,
    _wait_for_enter,
    _write_comments,
    _write_followup_comments,
    _write_followup_trailers,
    get_thread_msgs,
    logger,
    resolve_styles,
    reviewer_colours,
)
from b4.review_tui._modals import (
    CheckLoadingScreen,
    FollowupReplyPreviewScreen,
    HelpScreen,
    NoteScreen,
    PriorReviewScreen,
    SendScreen,
    ToCcScreen,
    TrailerScreen,
    _review_help_lines,
)


class PatchListItem(ListItem):
    """A single entry in the patch list."""

    def __init__(self, label: str, patch_idx: int, state: str = '') -> None:
        super().__init__()
        self.patch_idx = patch_idx
        self._label_text = label
        self._state = state

    def compose(self) -> ComposeResult:
        yield Label(self._label_text, markup=False)

    def on_mount(self) -> None:
        self._apply_state_style()

    def _apply_state_style(self) -> None:
        lbl = self.query_one(Label)
        if self._state in ('skip', 'unchanged'):
            lbl.styles.text_style = 'dim'
        elif self._state == 'done':
            lbl.styles.text_style = 'bold'
        else:
            lbl.styles.text_style = 'none'

    def update_label(self, label: str, state: str = '') -> None:
        self._label_text = label
        self._state = state
        lbl = self.query_one(Label)
        lbl.update(label)
        self._apply_state_style()


class FollowupItem(ListItem):
    """A follow-up entry in the patch list sidebar."""

    def __init__(self, name: str, display_idx: int, msgid: str) -> None:
        super().__init__()
        self.display_idx = display_idx
        self.msgid = msgid
        self._display_name = name

    def compose(self) -> ComposeResult:
        st = Static(f'\u00a0\u00a0\u00a0\u00a0{self._display_name}', markup=False)
        st.styles.text_style = 'dim'
        yield st


class ReviewApp(CheckRunnerMixin, App[None]):
    """Textual app for b4 review TUI."""

    TITLE = 'b4 review'

    DEFAULT_CSS = """
    ReviewApp {
        layout: horizontal;
    }
    #left-pane {
        width: 1fr;
        min-width: 30;
        max-width: 50;
        border-right: solid $primary;
    }
    #patch-list {
        height: 1fr;
    }
    #diff-viewer {
        width: 3fr;
    }
    .diff-add {
        color: $success;
    }
    .diff-remove {
        color: $error;
    }
    .diff-hunk {
        color: $secondary;
        text-style: bold;
    }
    .comment-block {
        background: $surface;
        border: solid $warning;
        padding: 0 1;
    }
    #trailer-overlay {
        height: auto;
        max-height: 24;
        border-top: solid $accent;
        padding: 0 1;
        display: none;
    }
    #newer-warning {
        dock: top;
        width: 100%;
        height: 1;
        background: $warning;
        color: $text;
        text-style: bold;
        padding: 0 1;
        display: none;
    }
    #title-bar {
        dock: top;
        width: 100%;
        height: 1;
        background: $primary-darken-2;
        color: $text;
        text-style: bold;
        padding: 0 1;
    }
    ReviewApp:ansi #title-bar {
        background: ansi_bright_black;
        color: ansi_default;
        text-style: bold;
    }
    ReviewApp:ansi #newer-warning {
        background: ansi_bright_black;
        color: ansi_default;
        text-style: bold;
    }
    ReviewApp:ansi #left-pane {
        border-right: solid ansi_default;
    }
    ReviewApp:ansi #trailer-overlay {
        border-top: solid ansi_default;
    }
    ReviewApp:ansi .comment-block {
        background: ansi_default;
        border: solid ansi_default;
    }
    """

    # Actions visible only in review mode
    _REVIEW_ACTIONS = frozenset({'followups', 'agent'})
    # Actions visible only in email mode
    _EMAIL_ACTIONS = frozenset({'edit_tocc', 'send'})

    BINDING_GROUPS = {
        'trailer': 'Review',
        'edit_note': 'Review',
        'edit_reply': 'Review',
        'followups': 'Review',
        'agent': 'Review',
        'prior_review': 'Review',
        'patch_done': 'Review',
        'patch_skip': 'Review',
        'check': 'Review',
        'edit_tocc': 'Review',
        'send': 'Review',
        'toggle_preview': 'App',
        'suspend': 'App',
        'quit': 'App',
        'help': 'App',
    }

    BINDINGS = [
        # Hidden navigation bindings
        Binding('j', 'j_key', 'Next/Scroll down', show=False),
        Binding('k', 'k_key', 'Prev/Scroll up', show=False),
        Binding('down', 'j_key', 'Next/Scroll down', show=False),
        Binding('up', 'k_key', 'Prev/Scroll up', show=False),
        # Review mode bindings
        Binding('t', 'trailer', 'trailers'),
        Binding('N', 'edit_note', 'note', key_display='N'),
        Binding('r', 'edit_reply', 'reply'),
        Binding('f', 'followups', 'followups'),
        Binding('a', 'agent', 'agent'),
        Binding('d', 'patch_done', 'done'),
        Binding('x', 'patch_skip', 'skip'),
        Binding('H', 'hide_skipped', 'hide skipped', key_display='H', show=False),
        Binding('P', 'prior_review', 'prior', key_display='P'),
        Binding('c', 'check', 'checks'),
        Binding('full_stop', 'next_comment', 'Next comment', show=False),
        Binding('comma', 'prev_comment', 'Prev comment', show=False),
        # Email mode bindings
        Binding('T', 'edit_tocc', 'edit to/cc', key_display='T'),
        Binding('S', 'send', 'send', key_display='S'),
        # App bindings
        Binding('e', 'toggle_preview', 'email mode'),
        Binding('s', 'suspend', 'shell'),
        Binding('q', 'quit', 'quit'),
        Binding('question_mark', 'help', 'help', key_display='?'),
        Binding('tab', 'focus_next', 'Tab', show=False),
        Binding('space', 'page_down', 'Page down', show=False),
        Binding('backspace', 'page_up', 'Page up', show=False),
        Binding('pagedown', 'page_down', 'Page down', show=False),
        Binding('pageup', 'page_up', 'Page up', show=False),
        Binding('n', 'next_patch', 'Next patch', show=False),
        Binding('p', 'prev_patch', 'Prev patch', show=False),
        Binding('left_square_bracket', 'prev_patch', 'Prev patch', show=False),
        Binding('right_square_bracket', 'next_patch', 'Next patch', show=False),
        Binding('h', 'scroll_left', 'Scroll left', show=False),
        Binding('l', 'scroll_right', 'Scroll right', show=False),
    ]

    def __init__(self, session: Dict[str, Any]) -> None:
        super().__init__()
        self._session = session
        self._topdir: str = session['topdir']
        self._cover_text: str = session['cover_text']
        self._tracking: Dict[str, Any] = session['tracking']
        self._series: Dict[str, Any] = session['series']
        self._patches: List[Dict[str, Any]] = session['patches']
        self._base_commit: str = session['base_commit']
        self._commit_shas: List[str] = session['commit_shas']
        self._commit_subjects: List[str] = session['commit_subjects']
        self._sha_map: Dict[str, Tuple[str, int]] = session['sha_map']
        self._abbrev_len: int = session['abbrev_len']
        self._default_identity: str = session['default_identity']
        self._usercfg: b4.ConfigDictT = session['usercfg']
        self._reviewer_initials: str = _make_initials(
            session['usercfg'].get('name', '')
        )
        self._cover_subject_clean: str = session['cover_subject_clean']
        self._email_dryrun: bool = session.get('email_dryrun', False)
        self._patatt_sign: bool = session.get('patatt_sign', True)
        self._branch: str = session['branch']
        self._original_branch: Optional[str] = session.get('original_branch')
        self.branch_checked_out: bool = False
        self._has_cover: bool = (
            'NOTE: No cover letter provided by the author.' not in self._cover_text
        )
        self._selected_idx: int = (
            0 if self._has_cover else 1
        )  # 0 = cover, 1..N = patches
        self._preview_mode: bool = False
        self._comment_positions: List[int] = []
        self._followup_positions: Dict[str, int] = {}
        self._followup_comments: Dict[int, List[Dict[str, Any]]] = {}
        self._followup_header_map: Dict[int, Dict[str, Any]] = {}
        self._selected_followup_msgid: Optional[str] = None
        self._show_external_comments: bool = False
        self._collapsed_comment_lines: Dict[int, Tuple[str, int]] = {}
        self._reply_sent: bool = False
        self._hide_skipped: bool = False
        self._check_loading: Optional[CheckLoadingScreen] = None

    def _get_check_context(self) -> Optional[Tuple[str, str, str]]:
        message_id = self._series.get('header-info', {}).get('msgid', '')
        subject = self._cover_subject_clean
        change_id = self._series.get('change-id', '')
        return (message_id, subject, change_id)

    def compose(self) -> ComposeResult:
        yield Static(id='newer-warning', markup=False)
        yield Static(id='title-bar', markup=False)
        with Horizontal():
            with Vertical(id='left-pane'):
                yield ListView(id='patch-list')
                yield Static(id='trailer-overlay', markup=False)
            yield RichLog(
                id='diff-viewer',
                highlight=False,
                wrap=False,
                markup=True,
                auto_scroll=False,
            )
        yield SeparatedFooter()

    def on_mount(self) -> None:
        _fix_ansi_theme(self)
        self._refresh_newer_warning()
        self._refresh_title_bar()
        self._populate_patch_list()
        self._show_content(self._selected_idx)
        switch_hint = self._session.get('_switch_hint')
        if switch_hint:
            self.notify(
                f"You're in a review branch. To see all tracked series, switch to {switch_hint}.",
                timeout=10,
            )

    def _refresh_title_bar(self) -> None:
        """Update the title bar to reflect current mode."""
        bar = self.query_one('#title-bar', Static)
        subject = self._series.get('subject', self._cover_subject_clean)
        if self._preview_mode:
            label = f' \u2709 {subject}'
            if self._email_dryrun:
                label += ' (dry-run)'
            bar.styles.background = self.get_css_variables()['accent']
        else:
            label = f' \u270e {subject}'
            bar.styles.background = self.get_css_variables()['primary-darken-2']
        bar.update(label)

    def _refresh_newer_warning(self) -> None:
        """Show or hide the newer-version warning bar based on tracking data."""
        widget = self.query_one('#newer-warning', Static)
        newer = self._series.get('newer-versions', [])
        if newer:
            versions = ', '.join(f'v{v}' for v in newer)
            widget.update(f' WARNING: newer version(s) available: {versions}')
            widget.styles.display = 'block'
        else:
            # Textual infers StringEnumProperty from the default ("block"),
            # so ty treats the valid "none" value as an invalid assignment.
            widget.styles.display = 'none'

    def _populate_patch_list(self) -> None:
        """Populate or refresh the patch list widget."""
        lv = self.query_one('#patch-list', ListView)
        lv.clear()

        total = len(self._commit_shas)
        # Track new-item count ourselves: lv.children may still
        # contain old items pending async removal after clear().
        new_count = 0
        restore_index = 0

        # Cover letter entry (skip if no actual cover letter)
        if self._has_cover:
            state = b4.review._get_patch_state(self._series, self._usercfg)
            mark = PATCH_STATE_MARKERS[state]
            cover_label = f'{mark} 0/{total} {self._cover_subject_clean[:40]}'
            lv.append(PatchListItem(cover_label, 0, state))
            if 0 == self._selected_idx:
                restore_index = new_count
            new_count += 1
            self._append_followup_items(lv, 0)
            new_count += len(self._followup_comments.get(0, []))

        # Patch entries
        for idx, _sha in enumerate(self._commit_shas):
            patch_num = idx + 1
            subject = (
                self._commit_subjects[idx]
                if idx < len(self._commit_subjects)
                else '(unknown)'
            )
            patch_meta = self._patches[idx] if idx < len(self._patches) else {}
            state = b4.review._get_patch_state(patch_meta, self._usercfg)
            if self._hide_skipped and state == 'skip':
                continue
            mark = PATCH_STATE_MARKERS[state]
            label = f'{mark} {patch_num}/{total} {subject[:40]}'
            lv.append(PatchListItem(label, patch_num, state))
            if patch_num == self._selected_idx:
                restore_index = new_count
            new_count += 1
            self._append_followup_items(lv, patch_num)
            new_count += len(self._followup_comments.get(patch_num, []))

        if new_count > 0:
            # Defer index restoration: clear() only schedules DOM
            # removal, so lv._nodes still contains old items right
            # now.  Setting the index immediately would highlight a
            # stale item that disappears once pruning completes.
            def _restore() -> None:
                lv.index = restore_index
                lv.scroll_visible()

            self.call_after_refresh(_restore)

    def _append_followup_items(self, lv: ListView, display_idx: int) -> None:
        """Append FollowupItem entries to *lv* for each follow-up message."""
        fc_list = self._followup_comments.get(display_idx, [])
        if not fc_list:
            return
        for e in fc_list:
            name = str(e.get('fromname') or e.get('fromemail') or '(unknown)')
            msgid = str(e.get('msgid', ''))
            lv.append(FollowupItem(name, display_idx, msgid))

    def _refresh_patch_item(self, display_idx: int) -> None:
        """Refresh a single patch list item's label."""
        lv = self.query_one('#patch-list', ListView)
        item = None
        for child in lv.children:
            if isinstance(child, PatchListItem) and child.patch_idx == display_idx:
                item = child
                break
        if item is None:
            return
        total = len(self._commit_shas)
        if display_idx == 0:
            target = self._series
            subject = self._cover_subject_clean[:40]
            label_num = f'0/{total}'
        else:
            patch_idx = display_idx - 1
            subject = (
                self._commit_subjects[patch_idx]
                if patch_idx < len(self._commit_subjects)
                else '(unknown)'
            )
            target = self._patches[patch_idx] if patch_idx < len(self._patches) else {}
            label_num = f'{display_idx}/{total}'
            subject = subject[:40]
        state = b4.review._get_patch_state(target, self._usercfg)
        mark = PATCH_STATE_MARKERS[state]
        item.update_label(f'{mark} {label_num} {subject}', state)

    def _show_content(self, display_idx: int) -> None:
        """Show the diff/cover or email preview for the given index."""
        total = len(self._commit_shas)
        if display_idx < 0 or display_idx > total:
            return
        viewer = self.query_one('#diff-viewer', RichLog)
        viewer.clear()
        self._comment_positions = []
        self._followup_positions = {}
        self._followup_header_map = {}
        self._collapsed_comment_lines = {}
        self._selected_followup_msgid = None

        self._selected_idx = display_idx

        if self._preview_mode:
            self._show_email_preview(viewer, display_idx)
        elif display_idx == 0:
            self._show_cover(viewer)
        else:
            patch_idx = display_idx - 1
            self._show_diff(viewer, patch_idx)

        viewer.scroll_home()
        self._refresh_trailer_overlay()

    def _build_msg_comment_map(
        self,
        target: Dict[str, Any],
        ts: Dict[str, str],
    ) -> Dict[int, List[Tuple[str, str, str]]]:
        """Build a comment map for COMMIT_MESSAGE_PATH comments.

        Returns a dict mapping line number to list of
        ``(author, colour, text)`` tuples for the current user's comments.
        """
        all_reviews = target.get('reviews', {})
        my_email = str(self._usercfg.get('email', ''))
        result: Dict[int, List[Tuple[str, str, str]]] = {}
        my_review = all_reviews.get(my_email, {})
        colour = self._reviewer_colour(my_email, target, ts)
        for c in my_review.get('comments', []):
            if c['path'] == COMMIT_MESSAGE_PATH:
                result.setdefault(c['line'], []).append(('You', colour, c['text']))
        return result

    def _show_cover(self, viewer: RichLog) -> None:
        """Render the cover letter in the diff viewer."""
        ts = resolve_styles(self)
        cover_lines = self._cover_text.strip().splitlines()
        # Render subject in accent colour, same as patches
        if cover_lines:
            viewer.write(Text(cover_lines[0], style=f'bold {ts["accent"]}'))
            viewer.write(Text(''))
        body_lines = b4.review._strip_subject(self._cover_text)
        body = '\n'.join(body_lines)
        if body:
            # Build cover comment map
            cv_comment_map = self._build_msg_comment_map(self._series, ts)

            # Render preamble comments (line 0)
            preamble_entries = cv_comment_map.pop(0, [])
            if preamble_entries:
                self._comment_positions.append(len(viewer.lines))
                _write_comments(viewer, preamble_entries, ts=ts)

            if cv_comment_map:
                # Render body line-by-line with inline comments
                body_lines = body.splitlines()
                for lineno, bline in enumerate(body_lines, start=1):
                    viewer.write(Text(bline))
                    entries = cv_comment_map.pop(lineno, [])
                    if entries:
                        self._comment_positions.append(len(viewer.lines))
                        _write_comments(viewer, entries, ts=ts)
            else:
                viewer.write(Syntax(body, 'markdown', theme=ts['syntax_theme']))
        # Show cover-level follow-up trailers
        _write_followup_trailers(viewer, self._tracking.get('followups', []), ts=ts)
        # Show cover-level follow-up comments
        _write_followup_comments(
            viewer,
            self._followup_comments.get(0, []),
            self._comment_positions,
            header_position_map=self._followup_header_map,
            ts=ts,
        )
        for line_pos, entry in self._followup_header_map.items():
            msgid = str(entry.get('msgid', ''))
            if msgid:
                self._followup_positions[msgid] = line_pos

    def _show_diff(self, viewer: RichLog, patch_idx: int) -> None:
        """Render a patch diff in the diff viewer with syntax colouring."""
        ts = resolve_styles(self)
        if patch_idx >= len(self._commit_shas):
            viewer.write(Text('Patch index out of range', style=ts['error']))
            return
        sha = self._commit_shas[patch_idx]

        # Show commit message with subject as a bright heading
        ecode, commit_msg = b4.git_run_command(
            self._topdir, ['show', '--format=%B', '--no-patch', sha]
        )
        if ecode == 0 and commit_msg.strip():
            all_lines = commit_msg.strip().splitlines()
            # Render subject in accent colour
            if all_lines:
                viewer.write(Text(all_lines[0], style=f'bold {ts["accent"]}'))
                viewer.write(Text(''))
            body = '\n'.join(b4.review._strip_subject(commit_msg))
            if body:
                # Build commit message comment map
                patch_target_cm = (
                    self._patches[patch_idx] if patch_idx < len(self._patches) else {}
                )
                msg_comment_map = self._build_msg_comment_map(patch_target_cm, ts)

                # Render preamble comments (line 0 = before commit message)
                preamble_entries = msg_comment_map.pop(0, [])
                if preamble_entries:
                    self._comment_positions.append(len(viewer.lines))
                    _write_comments(viewer, preamble_entries, ts=ts)

                bheaders, message, btrailers, _basement, _signature = (
                    b4.LoreMessage.get_body_parts(body)
                )
                has_content = bool(preamble_entries)
                # Track line number through the body (1-based, after
                # subject and leading blanks — same as _build_annotated_diff)
                body_lines = body.splitlines()
                body_lineno = 0

                def _write_msg_line(text_obj: Text) -> None:
                    nonlocal body_lineno, has_content
                    body_lineno += 1
                    viewer.write(text_obj)
                    has_content = True
                    entries = msg_comment_map.pop(body_lineno, [])
                    if entries:
                        self._comment_positions.append(len(viewer.lines))
                        _write_comments(viewer, entries, ts=ts)

                if bheaders:
                    for lt in bheaders:
                        _write_msg_line(Text(lt.as_string(), style='dim'))
                if message:
                    if has_content:
                        viewer.write('')
                    for mline in message.rstrip('\n').splitlines():
                        _write_msg_line(Text(mline))
                if btrailers:
                    if has_content:
                        viewer.write('')
                    for lt in btrailers:
                        _write_msg_line(Text(lt.as_string(), style=ts['accent']))

                # Account for blank lines between parts that get_body_parts
                # consumed but we didn't render — advance the counter
                while body_lineno < len(body_lines):
                    body_lineno += 1
                    entries = msg_comment_map.pop(body_lineno, [])
                    if entries:
                        self._comment_positions.append(len(viewer.lines))
                        _write_comments(viewer, entries, ts=ts)

                # Show follow-up trailers not already in the commit,
                # including cover-letter trailers that apply to all patches
                patch_meta = (
                    self._patches[patch_idx] if patch_idx < len(self._patches) else {}
                )
                existing = set()
                if btrailers:
                    existing = {lt.as_string().lower() for lt in btrailers}
                all_followups = self._tracking.get('followups', []) + patch_meta.get(
                    'followups', []
                )
                _write_followup_trailers(viewer, all_followups, existing, ts=ts)
                if all_followups:
                    has_content = True
                # Show basement (content below ---) from the original email
                email_basement = patch_meta.get('basement', '')
                if email_basement.strip():
                    if has_content:
                        viewer.write(Text(''))
                    viewer.write(Text('---', style='dim'))
                    for bline in email_basement.strip('\n').splitlines():
                        viewer.write(Text(bline, style='dim'))
                    has_content = True

                if has_content:
                    viewer.write(Text(''))
                    viewer.write(Rule(style='dim'))
                    viewer.write(Text(''))

        ecode, diff_out = b4.git_run_command(self._topdir, ['diff', f'{sha}~1', sha])
        if ecode > 0:
            viewer.write(Text('Could not generate diff', style=ts['error']))
            return

        # Get review comments — own comments always, external only on "f"
        patch_target = (
            self._patches[patch_idx] if patch_idx < len(self._patches) else {}
        )
        all_reviews = patch_target.get('reviews', {})
        my_email = str(self._usercfg.get('email', ''))
        comment_map: Dict[Tuple[str, int], List[Tuple[str, str, str]]] = {}
        # Track lines with hidden external comments — map to (name, line_count)
        external_hints: Dict[Tuple[str, int], List[Tuple[str, int]]] = {}
        for rev_email, rev_data in all_reviews.items():
            if rev_email == my_email:
                colour = self._reviewer_colour(rev_email, patch_target, ts)
                for c in rev_data.get('comments', []):
                    key = (c['path'], c['line'])
                    comment_map.setdefault(key, []).append(('You', colour, c['text']))
            elif self._show_external_comments:
                rev_name = rev_data.get('name', '')
                colour = self._reviewer_colour(rev_email, patch_target, ts)
                for c in rev_data.get('comments', []):
                    key = (c['path'], c['line'])
                    comment_map.setdefault(key, []).append(
                        (rev_name, colour, c['text'])
                    )
            else:
                rev_name = rev_data.get('name', rev_email)
                for c in rev_data.get('comments', []):
                    key = (c['path'], c['line'])
                    nlines = len(c.get('text', '').splitlines())
                    external_hints.setdefault(key, []).append((rev_name, nlines))

        # Parse and render diff with line tracking
        hunk_re = re.compile(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@')
        current_a_file = ''
        current_b_file = ''
        a_line = 0
        b_line = 0
        hint_style = f'bold {ts["warning"]}'
        self._collapsed_comment_lines = {}

        def _write_hints(key: Tuple[str, int]) -> None:
            entries = external_hints.get(key, [])
            if not entries:
                return
            # Aggregate line counts per reviewer (deduplicate)
            counts: Dict[str, int] = {}
            for name, nlines in entries:
                counts[name] = counts.get(name, 0) + nlines
            parts: List[str] = []
            for name, total in counts.items():
                parts.append(f'{name} ({total}L)')
            label = ', '.join(parts)
            self._collapsed_comment_lines[len(viewer.lines)] = key
            ruler = Text(f' \u2500\u2500 {label} \u2500\u2500', style=hint_style)
            viewer.write(ruler)

        for line in diff_out.splitlines():
            if line.startswith('diff --git '):
                viewer.write(Text(line, style='bold'))
                continue
            if line.startswith('--- '):
                if line.startswith(('--- a/', '--- /dev/null')):
                    current_a_file = line[4:]
                viewer.write(Text(line, style='bold'))
                continue
            if line.startswith('+++ '):
                if line.startswith(('+++ b/', '+++ /dev/null')):
                    current_b_file = line[4:]
                viewer.write(Text(line, style='bold'))
                continue

            hm = hunk_re.match(line)
            if hm:
                a_line = int(hm.group(1))
                b_line = int(hm.group(2))
                # Colour only the @@...@@ marker, leave context in default
                end = line.index(' @@', 3) + 3
                hunk_text = Text()
                hunk_text.append(line[:end], style=f'bold {ts["secondary"]}')
                if len(line) > end:
                    hunk_text.append(line[end:])
                viewer.write(hunk_text)
                continue

            if line.startswith('+'):
                key = (current_b_file, b_line)
                viewer.write(Text(line, style=ts['success']))
                entries = comment_map.pop(key, [])
                if entries:
                    self._comment_positions.append(len(viewer.lines))
                    _write_comments(viewer, entries, ts=ts)
                _write_hints(key)
                b_line += 1
            elif line.startswith('-'):
                key = (current_a_file, a_line)
                viewer.write(Text(line, style=ts['error']))
                entries = comment_map.pop(key, [])
                if entries:
                    self._comment_positions.append(len(viewer.lines))
                    _write_comments(viewer, entries, ts=ts)
                _write_hints(key)
                a_line += 1
            elif line.startswith(' '):
                key = (current_b_file, b_line)
                viewer.write(Text(line))
                entries = comment_map.pop(key, [])
                if entries:
                    self._comment_positions.append(len(viewer.lines))
                    _write_comments(viewer, entries, ts=ts)
                _write_hints(key)
                a_line += 1
                b_line += 1
            else:
                viewer.write(Text(line))

        # Render follow-up comments at the bottom
        _write_followup_comments(
            viewer,
            self._followup_comments.get(patch_idx + 1, []),
            self._comment_positions,
            header_position_map=self._followup_header_map,
            ts=ts,
        )
        for line_pos, entry in self._followup_header_map.items():
            msgid = str(entry.get('msgid', ''))
            if msgid:
                self._followup_positions[msgid] = line_pos

    def _show_email_preview(self, viewer: RichLog, display_idx: int) -> None:
        """Render the email that would be sent for the selected patch/cover."""
        if display_idx == 0:
            review = b4.review._get_my_review(self._series, self._usercfg)
            patch_meta = None
            commit_sha = None
        else:
            patch_idx = display_idx - 1
            if patch_idx < len(self._patches):
                patch_meta = self._patches[patch_idx]
                review = b4.review._get_my_review(patch_meta, self._usercfg)
            else:
                review = {}
                patch_meta = None
            commit_sha = (
                self._commit_shas[patch_idx]
                if patch_idx < len(self._commit_shas)
                else None
            )

        target = self._series if display_idx == 0 else patch_meta
        if target and b4.review._get_patch_state(target, self._usercfg) == 'skip':
            total = len(self._commit_shas)
            label = 'cover' if display_idx == 0 else f'{display_idx}/{total}'
            my_review = b4.review._get_my_review(target, self._usercfg)
            skip_reason = str(my_review.get('skip-reason', ''))
            if skip_reason:
                viewer.write(
                    f'[dim]Patch {label} is marked as skipped: {skip_reason}[/dim]'
                )
            else:
                viewer.write(
                    f'[dim]Patch {label} is marked as skipped — no email will be sent.[/dim]'
                )
            return

        if not review or not (
            review.get('trailers')
            or review.get('reply', '')
            or review.get('comments')
            or review.get('note', '')
        ):
            viewer.write('[dim]No reply will be sent for this patch.[/dim]')
            return

        msg = b4.review._build_review_email(
            self._series, patch_meta, review, self._cover_text, self._topdir, commit_sha
        )
        if msg is None:
            viewer.write('[dim]No email to preview (missing message-id?).[/dim]')
            return

        _render_email_to_viewer(viewer, msg, ts=resolve_styles(self))

    def _refresh_trailer_overlay(self) -> None:
        """Update the review status overlay in the left pane."""
        overlay = self.query_one('#trailer-overlay', Static)
        target = self._get_current_review_target()
        if not target:
            overlay.display = False
            return

        all_reviews = target.get('reviews', {})
        if not all_reviews or not _has_review_data(all_reviews):
            overlay.display = False
            return

        ts = resolve_styles(self)
        my_email = str(self._usercfg.get('email', ''))
        # Build ordered list: current user first, then others sorted by email
        ordered: List[Tuple[str, Dict[str, Any]]] = []
        if my_email in all_reviews:
            ordered.append((my_email, all_reviews[my_email]))
        for addr in sorted(all_reviews):
            if addr != my_email:
                ordered.append((addr, all_reviews[addr]))

        text = Text()
        has_content = False
        for rev_email, review in ordered:
            if not (
                review.get('trailers')
                or review.get('reply', '')
                or review.get('comments')
                or review.get('note', '')
            ):
                continue

            colour = self._reviewer_colour(rev_email, target, ts)
            if rev_email == my_email:
                header = 'Your review'
            else:
                header = review.get('name', rev_email)

            if has_content:
                text.append('\n')
            if self.app.ansi_color:
                text.append(f' {header} ', style=f'bold reverse {colour}')
            else:
                text.append(f' {header} ', style=f'bold {ts["surface"]} on {colour}')
            has_content = True

            comments = review.get('comments', [])
            if comments:
                files: set[str] = set(c.get('path', '') for c in comments)
                text.append(
                    f'\n    {len(comments)} comments across {len(files)} files',
                    style=ts['warning'],
                )
            reply = review.get('reply', '')
            if reply:
                non_quoted = sum(
                    1
                    for ln in reply.splitlines()
                    if ln.strip() and not ln.startswith('>')
                )
                text.append(
                    f'\n    {non_quoted} non-quoted reply lines', style=ts['accent']
                )
            trailers = review.get('trailers', [])
            if trailers:
                for t in trailers:
                    ttype = t.split(':', 1)[0] if ':' in t else t
                    text.append(f'\n    {ttype}', style=ts['success'])
            note = review.get('note', '')
            if note:
                lines = note.splitlines()
                summary = lines[0] if lines else ''
                text.append(f'\n    {summary}', style=ts['secondary'])
                # Find body after blank-line separator
                body_start = None
                for i, ln in enumerate(lines[1:], 1):
                    if not ln.strip():
                        body_start = i + 1
                        break
                if body_start is not None and body_start < len(lines):
                    body_words = ' '.join(lines[body_start:]).split()
                    if body_words:
                        text.append(
                            '\n    (view full note with N)', style=ts['secondary']
                        )

        if not has_content:
            overlay.display = False
            return

        overlay.update(text)
        overlay.display = True

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle patch selection in the list view."""
        item = event.item
        if isinstance(item, PatchListItem):
            self._show_content(item.patch_idx)
        elif isinstance(item, FollowupItem):
            self._show_followup_item(item)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        """Handle patch highlight change in the list view."""
        item = event.item
        if isinstance(item, PatchListItem):
            self._show_content(item.patch_idx)
        elif isinstance(item, FollowupItem):
            self._show_followup_item(item)

    def _show_followup_item(self, item: 'FollowupItem') -> None:
        """Show the parent patch for a follow-up item and scroll to its comment."""
        if self._selected_idx != item.display_idx:
            self._show_content(item.display_idx)
        self._selected_followup_msgid = item.msgid
        pos = self._followup_positions.get(item.msgid)
        if pos is not None:
            viewer = self.query_one('#diff-viewer', RichLog)
            viewer.scroll_to(y=pos)

    def _get_current_review_target(self) -> Dict[str, Any]:
        """Return the tracking dict (series or patch) for the currently selected item."""
        if self._selected_idx == 0:
            return self._series
        patch_idx = self._selected_idx - 1
        if patch_idx < len(self._patches):
            return self._patches[patch_idx]
        return {}

    def _ensure_review(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Return the current user's review sub-dict, creating it if needed."""
        return b4.review._ensure_my_review(target, self._usercfg)

    def _reviewer_colour(
        self, email: str, target: Dict[str, Any], ts: Optional[Dict[str, str]] = None
    ) -> str:
        """Return a stable colour for a reviewer email.

        Current user always gets index 0; others are sorted by email
        and assigned cyclically from the rest of the palette.
        *ts* is a resolved theme styles dict from :func:`resolve_styles`.
        """
        palette = (
            reviewer_colours(ts)
            if ts
            else [
                'dark_goldenrod',
                'dark_green',
                'dark_cyan',
                'dark_magenta',
                'dark_red',
                'dark_blue',
            ]
        )
        my_email = self._usercfg.get('email', '')
        if email == my_email:
            return palette[0]
        reviews = target.get('reviews', {})
        others = sorted(e for e in reviews if e != my_email)
        idx = others.index(email) if email in others else 0
        return palette[1 + (idx % (len(palette) - 1))]

    def _is_diff_focused(self) -> bool:
        """Check if the diff viewer (right pane) has focus."""
        viewer = self.query_one('#diff-viewer', RichLog)
        return self.focused is viewer

    def action_j_key(self) -> None:
        if self._is_diff_focused():
            self.query_one('#diff-viewer', RichLog).scroll_down()
        else:
            self.action_next_patch()

    def action_k_key(self) -> None:
        if self._is_diff_focused():
            self.query_one('#diff-viewer', RichLog).scroll_up()
        else:
            self.action_prev_patch()

    def action_prev_patch(self) -> None:
        lv = self.query_one('#patch-list', ListView)
        if lv.index is not None and lv.index > 0:
            lv.index -= 1
            lv.scroll_visible()

    def action_next_patch(self) -> None:
        lv = self.query_one('#patch-list', ListView)
        if lv.index is not None and lv.index < len(lv.children) - 1:
            lv.index += 1
            lv.scroll_visible()

    def action_page_down(self) -> None:
        self.query_one('#diff-viewer', RichLog).scroll_page_down()

    def action_page_up(self) -> None:
        self.query_one('#diff-viewer', RichLog).scroll_page_up()

    def action_scroll_left(self) -> None:
        self.query_one('#diff-viewer', RichLog).scroll_left()

    def action_scroll_right(self) -> None:
        self.query_one('#diff-viewer', RichLog).scroll_right()

    def _get_navigable_comment_positions(self) -> List[int]:
        """Return comment positions to navigate, including collapsed hints."""
        if self._comment_positions:
            return self._comment_positions
        if self._collapsed_comment_lines:
            return sorted(self._collapsed_comment_lines.keys())
        return []

    def action_next_comment(self) -> None:
        """Scroll to the next review comment in the diff view."""
        positions = self._get_navigable_comment_positions()
        if not positions:
            self.notify('No comments in this patch', severity='warning')
            return
        viewer = self.query_one('#diff-viewer', RichLog)
        current_y = int(viewer.scroll_y)
        # Show a few lines of diff context above the comment
        context = 5
        # Account for the context offset when determining current position
        viewed_pos = current_y + context
        for pos in positions:
            if pos > viewed_pos:
                viewer.scroll_to(y=max(0, pos - context))
                return
        self.notify('No more comments below', severity='information')

    def action_prev_comment(self) -> None:
        """Scroll to the previous review comment in the diff view."""
        positions = self._get_navigable_comment_positions()
        if not positions:
            self.notify('No comments in this patch', severity='warning')
            return
        viewer = self.query_one('#diff-viewer', RichLog)
        current_y = int(viewer.scroll_y)
        # Show a few lines of diff context above the comment
        context = 5
        # Account for the context offset when determining current position
        viewed_pos = current_y + context
        for pos in reversed(positions):
            if pos < viewed_pos:
                viewer.scroll_to(y=max(0, pos - context))
                return
        self.notify('No more comments above', severity='information')

    def check_action(self, action: str, parameters: Tuple[Any, ...]) -> Optional[bool]:
        """Show/hide mode-specific bindings in the footer."""
        if action == 'edit_reply' and self._selected_followup_msgid is not None:
            return True
        if action == 'agent':
            config = b4.get_main_config()
            if not config.get('review-agent-command') or not config.get(
                'review-agent-prompt-path'
            ):
                return False
            return not self._preview_mode
        if action == 'prior_review':
            if not self._series.get('prior-review-context'):
                return False
            return not self._preview_mode
        if action == 'check':
            return not self._preview_mode
        if action in self._REVIEW_ACTIONS:
            return not self._preview_mode
        if action in self._EMAIL_ACTIONS:
            return self._preview_mode
        return True

    def action_toggle_preview(self) -> None:
        """Toggle between review mode and email mode."""
        self._preview_mode = not self._preview_mode
        self._show_content(self._selected_idx)
        self._refresh_title_bar()
        self.refresh_bindings()

    def action_trailer(self) -> None:
        """Open the trailer selection popup with current state pre-populated."""
        target = self._get_current_review_target()
        if not target:
            return
        existing_trailers = b4.review._get_my_review(target, self._usercfg).get(
            'trailers', []
        )

        def _on_trailer(result: Optional[List[str]]) -> None:
            if result is None:
                return
            review = self._ensure_review(target)
            # Build the new trailer list from the selected names
            if 'NACKed-by' in result:
                # NACKed-by replaces all others
                new_trailers = [f'NACKed-by: {self._default_identity}']
            else:
                new_trailers = [f'{name}: {self._default_identity}' for name in result]
            # If adding to a patch, filter out trailers already on the cover letter
            if self._selected_idx > 0 and new_trailers:
                cover_trailers = b4.review._get_my_review(
                    self._series, self._usercfg
                ).get('trailers', [])
                cover_names = {
                    t.split(':', 1)[0].strip().lower() for t in cover_trailers
                }
                overlap = [r for r in result if r.lower() in cover_names]
                if overlap:
                    self.notify(
                        f'{", ".join(overlap)} already on cover letter',
                        severity='warning',
                    )
                    new_trailers = [
                        t
                        for t in new_trailers
                        if t.split(':', 1)[0].strip().lower() not in cover_names
                    ]
            old_trailers: List[str] = review.get('trailers', [])
            if new_trailers == old_trailers:
                return
            if new_trailers:
                review['trailers'] = new_trailers
            else:
                review.pop('trailers', None)
                b4.review._cleanup_review(target, self._usercfg)
            # Consolidate trailers between cover and patches
            promoted = False
            if self._selected_idx == 0 and new_trailers:
                # Cover letter trailer applies to all patches —
                # remove matching per-patch trailers
                new_names = {t.split(':', 1)[0].strip().lower() for t in new_trailers}
                for pidx, patch in enumerate(self._patches):
                    preview = b4.review._get_my_review(patch, self._usercfg)
                    pt = preview.get('trailers', [])
                    if not pt:
                        continue
                    remaining = [
                        t
                        for t in pt
                        if t.split(':', 1)[0].strip().lower() not in new_names
                    ]
                    if remaining != pt:
                        if remaining:
                            preview['trailers'] = remaining
                        else:
                            preview.pop('trailers', None)
                            b4.review._cleanup_review(patch, self._usercfg)
                        self._refresh_patch_item(pidx + 1)
            elif self._selected_idx > 0 and new_trailers and self._patches:
                # Check if all patches now have the same trailer set —
                # if so, promote to cover letter
                new_names = {t.split(':', 1)[0].strip().lower() for t in new_trailers}
                all_match = True
                for patch in self._patches:
                    preview = b4.review._get_my_review(patch, self._usercfg)
                    pt = preview.get('trailers', [])
                    patch_names = {t.split(':', 1)[0].strip().lower() for t in pt}
                    if patch_names != new_names:
                        all_match = False
                        break
                if all_match:
                    cover_review = self._ensure_review(self._series)
                    cover_review['trailers'] = new_trailers
                    for pidx, patch in enumerate(self._patches):
                        preview = b4.review._get_my_review(patch, self._usercfg)
                        preview.pop('trailers', None)
                        b4.review._cleanup_review(patch, self._usercfg)
                        self._refresh_patch_item(pidx + 1)
                    self._refresh_patch_item(0)
                    promoted = True
            self._save_tracking()
            self._refresh_patch_item(self._selected_idx)
            self._show_content(self._selected_idx)
            if promoted:
                self.notify(f'Trailers promoted to cover letter ({len(new_trailers)})')
            elif new_trailers:
                self.notify(f'Trailers updated ({len(new_trailers)})')
            else:
                self.notify('Trailers removed')

        self.push_screen(TrailerScreen(existing_trailers), _on_trailer)

    def action_edit_reply(self) -> None:
        """Open $EDITOR for reply editing."""
        if self._selected_followup_msgid is not None:
            for entry in self._followup_comments.get(self._selected_idx, []):
                if entry.get('msgid') == self._selected_followup_msgid:
                    self._compose_followup_reply(entry)
                    return
        target = self._get_current_review_target()
        if not target:
            return
        review = self._ensure_review(target)
        existing_reply = review.get('reply', '')

        # Get the real diff for position resolution when parsing back
        if self._selected_idx > 0:
            patch_idx = self._selected_idx - 1
            if patch_idx >= len(self._commit_shas):
                return
            sha = self._commit_shas[patch_idx]
            ecode, real_diff = b4.git_run_command(
                self._topdir, ['diff', f'{sha}~1', sha]
            )
            if ecode > 0:
                self.notify('Could not get diff', severity='error')
                return
            if existing_reply:
                editor_text = existing_reply
            else:
                all_reviews = target.get('reviews', {})
                my_email = str(self._usercfg.get('email', ''))
                ecode, commit_msg = b4.git_run_command(
                    self._topdir, ['show', '--format=%B', '--no-patch', sha]
                )
                if ecode > 0:
                    self.notify('Could not get commit message', severity='error')
                    return
                editor_text = b4.review._render_quoted_diff_with_comments(
                    real_diff, all_reviews, my_email, commit_msg=commit_msg.strip()
                )
        else:
            real_diff = ''
            if existing_reply:
                editor_text = existing_reply
            else:
                all_reviews = target.get('reviews', {})
                my_email = str(self._usercfg.get('email', ''))
                editor_text = b4.review._render_quoted_diff_with_comments(
                    '', all_reviews, my_email, commit_msg=self._cover_text
                )

        with self.suspend():
            result = b4.edit_in_editor(
                editor_text.encode(), filehint='reply.b4-review.eml'
            )

        if not result:
            self.notify('Editor returned no content')
            return
        reply_text = result.decode(errors='replace')
        if reply_text == editor_text:
            self.notify('No changes made')
            return
        # Extract trailers from the unquoted portion of the reply
        # (skip > quoted lines and | external comment lines)
        unquoted_lines: List[str] = []
        for line in reply_text.splitlines():
            if not line.startswith('>') and not line.startswith('|'):
                unquoted_lines.append(line)
        unquoted_text = '\n'.join(unquoted_lines)
        found_trailers, _others = b4.LoreMessage.find_trailers(unquoted_text)
        if found_trailers:
            trailer_strs = [lt.as_string() for lt in found_trailers]
            review['trailers'] = trailer_strs
            # Strip trailer lines from the reply before parsing comments
            trailer_set = set(trailer_strs)
            stripped_lines: List[str] = []
            for line in reply_text.splitlines():
                if line.strip() not in trailer_set:
                    stripped_lines.append(line)
            reply_text = '\n'.join(stripped_lines)

        # Parse inline comments from the quoted reply
        # _extract_editor_comments strips | lines (unadopted external
        # comments) before parsing, so only adopted ones are kept
        new_comments = b4.review._extract_editor_comments(
            reply_text, diff_text=real_diff
        )
        if new_comments:
            review['comments'] = new_comments
            if 'reply' in review:
                del review['reply']
        else:
            # No structured comments found — store as raw reply
            review['reply'] = reply_text
            if 'comments' in review:
                del review['comments']
        self._save_tracking()
        self._refresh_patch_item(self._selected_idx)
        self._show_content(self._selected_idx)
        if new_comments:
            files = set(c['path'] for c in new_comments)
            self.notify(f'{len(new_comments)} comments across {len(files)} files')
        else:
            self.notify('Reply saved')

    def action_prior_review(self) -> None:
        """Show prior revision review context."""
        context = self._series.get('prior-review-context', '')
        if not context:
            self.notify('No prior review context available', severity='information')
            return
        self.push_screen(PriorReviewScreen(context))

    def action_edit_note(self) -> None:
        """View notes or jump straight to editor if none exist."""
        target = self._get_current_review_target()
        if not target:
            return

        all_reviews = target.get('reviews', {})
        has_any_notes = any(r.get('note', '') for r in all_reviews.values())

        if not has_any_notes:
            # No notes at all — go straight to the external editor
            self._edit_note_in_editor(target, '')
            return

        # Build formatted text showing all reviewers' notes
        my_email = str(self._usercfg.get('email', ''))
        ordered: List[Tuple[str, Dict[str, Any]]] = []
        if my_email in all_reviews:
            ordered.append((my_email, all_reviews[my_email]))
        for addr in sorted(all_reviews):
            if addr != my_email:
                ordered.append((addr, all_reviews[addr]))

        ts = resolve_styles(self)
        note_entries: List[Tuple[str, str, str]] = []
        for rev_email, review in ordered:
            note = review.get('note', '')
            if not note:
                continue
            if rev_email == my_email:
                header = 'Your note'
            else:
                name = review.get('name', rev_email)
                header = name
            colour = self._reviewer_colour(rev_email, target, ts)
            note_entries.append((header, colour, note))

        def _on_note(result: Optional[str]) -> None:
            if result is None:
                return
            if result == '__EDIT__':
                my_note = b4.review._get_my_review(target, self._usercfg).get(
                    'note', ''
                )
                self._edit_note_in_editor(target, my_note)
            elif result == '__DELETE__':
                self._delete_all_notes(target)

        self.push_screen(NoteScreen(note_entries), _on_note)

    _NOTE_FOOTER = (
        '\n\n'
        '# Add a private note about this patch. It will not be sent in your\n'
        '# email reply, but it will be stored in the tracking commit and\n'
        '# viewable by anyone if you push this branch to any remote.\n'
        '#\n'
        '# Lines starting with # will be removed.\n'
    )

    def _edit_note_in_editor(self, target: Dict[str, Any], existing: str) -> None:
        """Launch $EDITOR for the maintainer's note on *target*."""
        editor_text = existing + self._NOTE_FOOTER
        with self.suspend():
            result = b4.edit_in_editor(editor_text.encode(), filehint='note.txt')

        if not result:
            self.notify('Editor returned no content')
            return
        raw_text = result.decode(errors='replace')
        note_text = '\n'.join(
            ln for ln in raw_text.splitlines() if not ln.startswith('#')
        ).strip()
        if note_text == existing.strip():
            self.notify('No changes made')
            return
        review = self._ensure_review(target)
        if note_text:
            review['note'] = note_text
        elif 'note' in review:
            del review['note']
        b4.review._cleanup_review(target, self._usercfg)
        self._save_tracking()
        self._refresh_patch_item(self._selected_idx)
        self._show_content(self._selected_idx)
        if note_text:
            self.notify('Note saved')
        else:
            self.notify('Note deleted')

    def _delete_all_notes(self, target: Dict[str, Any]) -> None:
        """Delete notes from all reviewers on *target*."""
        all_reviews = target.get('reviews', {})
        changed = False
        for review in all_reviews.values():
            if 'note' in review:
                del review['note']
                changed = True
        if changed:
            # Clean up any reviewers that now have empty data
            my_email = self._usercfg.get('email', '')
            for addr in list(all_reviews):
                rev = all_reviews[addr]
                if not (
                    rev.get('trailers')
                    or rev.get('reply', '')
                    or rev.get('comments')
                    or rev.get('note', '')
                ):
                    if addr == my_email:
                        b4.review._cleanup_review(target, self._usercfg)
                    else:
                        del all_reviews[addr]
            self._save_tracking()
            self._refresh_patch_item(self._selected_idx)
            self._show_content(self._selected_idx)
            self.notify('All notes deleted')
        else:
            self.notify('No notes to delete')

    def action_edit_tocc(self) -> None:
        """Edit To/Cc/Bcc recipients for the current patch or series."""
        if self._selected_idx == 0:
            target = self._series
        else:
            target = self._patches[self._selected_idx - 1]

        header_info = target.get('header-info', {})
        to_addrs = header_info.get('to', '')
        cc_addrs = header_info.get('cc', '')
        bcc_addrs = header_info.get('bcc', '')
        show_apply_all = len(self._patches) > 0

        def _on_tocc_result(saved: Optional[bool]) -> None:
            if not saved:
                return
            # The ToCcScreen was just dismissed; grab results from it
            to_str = _tocc_screen.to_result
            cc_str = _tocc_screen.cc_result
            bcc_str = _tocc_screen.bcc_result
            apply_all = _tocc_screen.apply_all

            if apply_all:
                targets = [self._series] + list(self._patches)
            else:
                targets = [target]

            for t in targets:
                hi = t.setdefault('header-info', {})
                hi['to'] = to_str
                hi['cc'] = cc_str
                hi['tocc-edited'] = True
                if bcc_str:
                    hi['bcc'] = bcc_str
                elif 'bcc' in hi:
                    del hi['bcc']

            self._save_tracking()
            self._show_content(self._selected_idx)
            self.notify('Recipients updated')

        _tocc_screen = ToCcScreen(to_addrs, cc_addrs, bcc_addrs, show_apply_all)
        self.push_screen(_tocc_screen, _on_tocc_result)

    def action_patch_done(self) -> None:
        """Toggle the explicit 'done' state on the current patch."""
        target = self._get_current_review_target()
        if not target:
            return
        current = b4.review._get_patch_state(target, self._usercfg)
        new_state = '' if current == 'done' else 'done'
        b4.review._set_patch_state(target, self._usercfg, new_state)
        self._save_tracking()
        self._refresh_patch_item(self._selected_idx)
        total = len(self._commit_shas)
        label = 'cover' if self._selected_idx == 0 else f'{self._selected_idx}/{total}'
        self.notify(
            f'{label} marked as done' if new_state else f'{label} unmarked done'
        )

    def action_patch_skip(self) -> None:
        """Toggle the explicit 'skip' state on the current patch."""
        target = self._get_current_review_target()
        if not target:
            return
        current = b4.review._get_patch_state(target, self._usercfg)
        new_state = '' if current == 'skip' else 'skip'
        b4.review._set_patch_state(target, self._usercfg, new_state)
        self._save_tracking()
        if self._hide_skipped and new_state == 'skip':
            # Patch just got skipped while hiding is on — repopulate
            self._selected_idx = 0 if self._has_cover else 1
            self._populate_patch_list()
            self._show_content(self._selected_idx)
        else:
            self._refresh_patch_item(self._selected_idx)
            if self._preview_mode:
                self._show_content(self._selected_idx)
        total = len(self._commit_shas)
        label = 'cover' if self._selected_idx == 0 else f'{self._selected_idx}/{total}'
        self.notify(f'{label} skipped' if new_state else f'{label} unskipped')
        self.refresh_bindings()

    def action_hide_skipped(self) -> None:
        """Toggle visibility of skipped patches in the patch list."""
        self._hide_skipped = not self._hide_skipped
        # If current selection is skipped and we're hiding, move to first visible
        if self._hide_skipped:
            target = self._get_current_review_target()
            if target and b4.review._get_patch_state(target, self._usercfg) == 'skip':
                self._selected_idx = 0 if self._has_cover else 1
        self._populate_patch_list()
        self._show_content(self._selected_idx)
        self.notify(
            'Skipped patches hidden' if self._hide_skipped else 'Skipped patches shown'
        )

    def action_send(self) -> None:
        """Collect review emails and show send confirmation dialog."""
        self._save_tracking()

        draft_patches = []
        total = len(self._commit_shas)
        all_targets = [(0, self._series)] + [
            (i + 1, p) for i, p in enumerate(self._patches)
        ]
        for display_idx, target in all_targets:
            if b4.review._get_patch_state(target, self._usercfg) == 'draft':
                label = 'cover' if display_idx == 0 else f'{display_idx}/{total}'
                draft_patches.append(label)
        if draft_patches:
            self.notify(
                f'Still in draft: {", ".join(draft_patches)}. Mark as done (d) or skip (x) first.',
                severity='warning',
            )
            return

        msgs = b4.review.collect_review_emails(
            self._series,
            self._patches,
            self._cover_text,
            self._topdir,
            self._commit_shas,
        )
        if not msgs:
            self.notify('No review data to send.')
            return

        def _on_send_confirmed(confirmed: Optional[bool]) -> None:
            if not confirmed:
                return
            try:
                with self.suspend():
                    smtp, fromaddr = b4.get_smtp(dryrun=self._email_dryrun)
                    sent = b4.send_mail(
                        smtp,
                        msgs,
                        fromaddr=fromaddr,
                        patatt_sign=self._patatt_sign,
                        dryrun=self._email_dryrun,
                        output_dir=None,
                        reflect=False,
                    )
                if sent is None:
                    self.notify('Failed to send review emails.', severity='error')
                else:
                    self._reply_sent = True
                    self._tracking['series']['status'] = 'replied'
                    # Stamp sent-revision on every non-skip review so that
                    # if this series is later upgraded to a newer revision,
                    # the upgrade step can detect which reviews were already
                    # sent and auto-skip the unchanged patches.
                    my_email = str(self._usercfg.get('email', 'unknown@example.com'))
                    current_rev = int(self._series.get('revision', 1))
                    for target in [self._series] + list(self._patches):
                        review = target.get('reviews', {}).get(my_email, {})
                        if review and review.get('patch-state') != 'skip':
                            review['sent-revision'] = current_rev
                    self._save_tracking()
                    self._mark_patches_answered(msgs)
                    self.notify(f'Sent {sent} review email(s).')
            except Exception as ex:
                self.notify(f'Send failed: {ex}', severity='error')

        self.push_screen(SendScreen(msgs), _on_send_confirmed)

    def on_click(self, event: Click) -> None:
        """Detect clicks on follow-up headers or hint gutter markers."""
        try:
            viewer = self.query_one('#diff-viewer', RichLog)
        except Exception:
            return
        region = viewer.content_region
        if not region.contains(event.screen_x, event.screen_y):
            return
        content_line = int(viewer.scroll_y) + (event.screen_y - region.y)
        # Click on hint gutter → nudge to press f
        click_col = event.screen_x - region.x + int(viewer.scroll_x)
        if click_col == 0 and content_line in self._collapsed_comment_lines:
            self.notify('Press f to display inline comments')
            event.stop()
            return
        # Click on follow-up header → quick reply
        if self._followup_header_map:
            entry = self._followup_header_map.get(content_line)
            if entry:
                self._compose_followup_reply(entry)
                event.stop()

    def _compose_followup_reply(
        self, entry: Dict[str, Any], initial_text: Optional[str] = None
    ) -> None:
        """Compose a reply to a follow-up message using the external editor.

        If *initial_text* is given (re-edit loop), use it directly instead of
        building the attribution+quote from the entry.
        """
        if initial_text is not None:
            editor_text = initial_text
        else:
            orig_date = entry.get('date', '')
            orig_author = entry.get('fromname', '') or entry.get('fromemail', '')
            body = entry.get('body', '')
            quoted = '\n'.join(f'> {line}' for line in body.splitlines())
            editor_text = f'On {orig_date}, {orig_author} wrote:\n{quoted}\n\n'

        with self.suspend():
            result = b4.edit_in_editor(editor_text.encode(), filehint='reply.eml')
        reply_text = result.decode(errors='replace')
        if reply_text == editor_text:
            self.notify('No changes made')
            return

        def _on_preview(action: Optional[str]) -> None:
            if action == 'send':
                self._send_followup_reply(entry, reply_text)
            elif action == 'edit':
                self._compose_followup_reply(entry, reply_text)

        self.push_screen(FollowupReplyPreviewScreen(entry, reply_text), _on_preview)

    def _send_followup_reply(self, entry: Dict[str, Any], text: str) -> None:
        """Build and immediately send a quick reply to a follow-up message."""
        msg = entry['lmsg'].make_reply(text)
        try:
            with self.suspend():
                smtp, fromaddr = b4.get_smtp(dryrun=self._email_dryrun)
                sent = b4.send_mail(
                    smtp,
                    [msg],
                    fromaddr=fromaddr,
                    patatt_sign=self._patatt_sign,
                    dryrun=self._email_dryrun,
                    output_dir=None,
                    reflect=False,
                )
            if sent is None:
                self.notify('Failed to send reply.', severity='error')
            elif self._email_dryrun:
                self.notify(f'Dry-run: reply to {entry["fromemail"]} logged, not sent')
            else:
                self.notify(f'Reply sent to {entry["fromemail"]}')
        except Exception as ex:
            self.notify(f'Send failed: {ex}', severity='error')

    def _load_followup_msgs(self, msgs: List[Any]) -> None:
        """Parse msgs into follow-up comments and refresh the display."""
        cover_msgid = self._series.get('header-info', {}).get('msgid')

        # Minimise for body parsing (strips deep quoting, signatures)
        minimised = b4.mbox.minimize_thread(list(msgs))
        minimised_body_map: Dict[str, str] = {}
        for mmsg in minimised:
            mid = b4.LoreMessage.clean_header(mmsg.get('Message-ID', ''))
            if mid:
                mid = mid.strip('<>')
                payload = mmsg.get_payload(decode=True)
                if isinstance(payload, bytes):
                    minimised_body_map[mid] = payload.decode(errors='replace')
                elif isinstance(payload, str):
                    minimised_body_map[mid] = payload

        # Build LoreMailbox from original messages for msgid_map + followups
        lmbx = b4.LoreMailbox()
        for msg in msgs:
            lmbx.add_message(msg)

        # Build patch_msgids: msgid -> display_idx
        patch_msgids: Dict[str, int] = {}
        if cover_msgid:
            patch_msgids[cover_msgid] = 0
        for i, pmeta in enumerate(self._patches):
            pmsgid = pmeta.get('header-info', {}).get('msgid')
            if pmsgid:
                patch_msgids[pmsgid] = i + 1

        self._followup_comments = {}
        count = 0

        all_followups = lmbx.followups + lmbx.unknowns
        for lmsg in sorted(all_followups, key=lambda m: m.date):
            display_idx = _resolve_patch_for_followup(
                lmsg.in_reply_to, patch_msgids, lmbx.msgid_map
            )
            if display_idx is None:
                continue

            mbody = minimised_body_map.get(lmsg.msgid, '').strip()
            if not mbody:
                continue
            # Skip messages where minimize_thread reduced the body to
            # just an attribution line (e.g. trailer-only follow-ups
            # where get_body_parts already extracted the trailers).
            mbody_lines = [ln for ln in mbody.splitlines() if ln.strip()]
            if len(mbody_lines) <= 2 and mbody_lines[-1].strip().endswith(':'):
                continue
            # minimize_thread strips trailers from the body; re-append
            # them so the follow-up panel shows the full message.
            _htrs, _cmsg, mtrs, _basement, _sig = b4.LoreMessage.get_body_parts(
                lmsg.body
            )
            if mtrs:
                trailer_block = '\n'.join(t.as_string() for t in mtrs)
                mbody = mbody.rstrip('\n') + '\n\n' + trailer_block

            entry: Dict[str, Any] = {
                'body': mbody,
                'fromname': lmsg.fromname,
                'fromemail': lmsg.fromemail,
                'date': lmsg.date,
                'msgid': lmsg.msgid,
                'subject': lmsg.full_subject,
                'reply': lmsg.reply,
                'depth': _get_followup_depth(
                    lmsg.in_reply_to, patch_msgids, lmbx.msgid_map
                ),
                'lmsg': lmsg,
                'replies-to-diff': _chain_has_additional_patch(
                    lmsg.in_reply_to, patch_msgids, lmbx.msgid_map
                ),
            }
            self._followup_comments.setdefault(display_idx, []).append(entry)
            count += 1

        # Sort each list by date
        for fc_list in self._followup_comments.values():
            fc_list.sort(key=lambda e: e['date'])

        # Extract inline diff comments from follow-ups that quote patches
        inline_count = self._integrate_followup_inline(self._followup_comments)

        # Count stored external inline comments (sashiko, agents)
        my_email = str(self._usercfg.get('email', ''))
        ext_count = sum(
            len(rev.get('comments', []))
            for patch in self._patches
            for addr, rev in patch.get('reviews', {}).items()
            if addr != my_email
        )

        parts = []
        if count:
            parts.append(f'{count} follow-up(s)')
        if inline_count:
            parts.append(f'{inline_count} inline comment(s)')
        if ext_count:
            parts.append(f'{ext_count} external review comment(s)')
        if parts:
            self.notify(f'Loaded {", ".join(parts)}')
        else:
            self.notify('No follow-up comments found')
        self._populate_patch_list()
        self._show_content(self._selected_idx)

    def _integrate_followup_inline(
        self,
        followup_comments: Dict[int, List[Dict[str, Any]]],
    ) -> int:
        """Extract inline diff comments from follow-ups into patch reviews.

        Scans follow-up bodies for ``> ``-quoted diff content, extracts
        positioned comments, resolves them against the real diff, and
        stores them in ``patches[idx]['reviews']`` so they render inline
        in the diff view.

        Returns the number of inline comments integrated.
        """
        integrated = 0
        for display_idx, fc_list in followup_comments.items():
            if display_idx < 1:
                continue
            idx = display_idx - 1
            if idx >= len(self._patches) or idx >= len(self._commit_shas):
                continue

            patch = self._patches[idx]

            for fc in fc_list:
                body = fc.get('body', '')
                if not body:
                    continue
                if '> diff --git ' not in body and '> @@ ' not in body:
                    continue
                # Skip followups that reply to an additional patch:
                # quoted diff content is from that patch, not ours.
                if fc.get('replies-to-diff'):
                    continue

                reviewer_email = fc.get('fromemail', '')
                if not reviewer_email:
                    continue

                fc_msgid = fc.get('msgid', '')
                existing_entry = patch.get('reviews', {}).get(reviewer_email, {})
                if fc_msgid and existing_entry.get('followup-msgid') == fc_msgid:
                    continue

                comments = b4.review._extract_comments_from_quoted_reply(body)
                if not comments:
                    continue

                sha = self._commit_shas[idx]
                ecode, real_diff = b4.git_run_command(
                    self._topdir, ['diff', f'{sha}~1', sha]
                )
                if ecode == 0:
                    b4.review._resolve_comment_positions(real_diff, comments)

                reviewer_name = fc.get('fromname', '')
                patch_reviews: Dict[str, Any] = patch.setdefault('reviews', {})
                entry = patch_reviews.setdefault(reviewer_email, {})
                if reviewer_name:
                    entry['name'] = reviewer_name
                entry['comments'] = comments
                if fc_msgid:
                    entry['followup-msgid'] = fc_msgid
                    entry['provenance'] = f'{b4.LINKADDR}/{fc_msgid}'
                integrated += len(comments)

        if integrated:
            self._save_tracking()

        return integrated

    def action_followups(self) -> None:
        """Toggle follow-up comments on/off."""
        # ── Toggle off ────────────────────────────────────────────────────────
        if self._show_external_comments:
            self._show_external_comments = False
            self._followup_comments = {}
            self._followup_positions = {}
            self._populate_patch_list()
            self._show_content(self._selected_idx)
            return

        cover_msgid = self._series.get('header-info', {}).get('msgid')
        if not cover_msgid:
            self.notify('No message-id for cover letter', severity='error')
            return

        self._show_external_comments = True

        # ── Try local blob first, fall back to lore in background ────────────
        blob_sha = self._series.get('thread-blob', '')
        self.notify('Loading follow-ups\u2026')
        self.run_worker(
            lambda: self._fetch_followups_bg(cover_msgid, blob_sha),
            name='_followup_worker',
            thread=True,
        )

    def _fetch_rethreaded_threads(
        self, blob_sha: str
    ) -> Optional[List[email.message.EmailMessage]]:
        """Fetch threads for each real patch in a rethreaded series."""
        all_msgs: List[email.message.EmailMessage] = []
        seen_msgids: Set[str] = set()
        fetched_patches: Set[str] = set()
        for patch_meta in self._patches:
            pmsgid = patch_meta.get('header-info', {}).get('msgid', '')
            if not pmsgid or pmsgid in fetched_patches:
                continue
            fetched_patches.add(pmsgid)
            thread = get_thread_msgs(
                self._topdir, pmsgid, blob_sha=blob_sha, quiet=True
            )
            if thread:
                for msg in thread:
                    c_msgid = b4.LoreMessage.get_clean_msgid(msg)
                    if c_msgid and c_msgid not in seen_msgids:
                        all_msgs.append(msg)
                        seen_msgids.add(c_msgid)
        return all_msgs or None

    def _fetch_followups_bg(self, cover_msgid: str, blob_sha: str) -> None:
        """Load follow-ups from local blob or lore (background thread)."""
        with _quiet_worker():
            if self._series.get('is-rethreaded'):
                # Rethreaded series: fetch each real patch's thread
                msgs = self._fetch_rethreaded_threads(blob_sha)
            else:
                msgs = get_thread_msgs(
                    self._topdir, cover_msgid, blob_sha=blob_sha, quiet=True
                )

        if not msgs:

            def _no_msgs() -> None:
                self.notify('Could not load thread', severity='error')
                # Still refresh to show external comments (sashiko etc.)
                self._populate_patch_list()
                self._show_content(self._selected_idx)

            self.app.call_from_thread(_no_msgs)
            return

        # Cache the thread locally if we fetched from lore.
        if not blob_sha:
            change_id = self._series.get('change-id')
            if change_id:
                with _quiet_worker():
                    new_sha = b4.review.tracking._store_thread_blob(
                        self._topdir, change_id, msgs
                    )
                if new_sha:
                    self._series['thread-blob'] = new_sha

        def _finish() -> None:
            self._load_followup_msgs(msgs)
            self._mark_followup_msgs_seen(msgs)
            self._detect_maintainer_replies(msgs)

        self.app.call_from_thread(_finish)

    def _mark_followup_msgs_seen(self, msgs: List[Any]) -> None:
        """Mark all follow-up messages as Seen in the messages DB."""
        entries = []
        for msg in msgs:
            mid = b4.LoreMessage.clean_header(msg.get('Message-ID', ''))
            if mid:
                mid = mid.strip('<>')
                date_val = msg.get('Date', '')
                msg_date = None
                if date_val:
                    try:
                        msg_date = email.utils.parsedate_to_datetime(
                            str(date_val)
                        ).isoformat()
                    except Exception:
                        pass
                entries.append({'msgid': mid, 'msg_date': msg_date})
        if not entries:
            return
        try:
            from b4.review import messages

            conn = messages.get_db()
            messages.set_flags_bulk(conn, entries, 'Seen')
            conn.close()
        except Exception:
            pass

    def _mark_patches_answered(self, msgs: List[Any]) -> None:
        """Mark the original patches as Answered based on In-Reply-To."""
        entries = []
        for msg in msgs:
            irt = msg.get('In-Reply-To', '')
            if irt:
                msgid = irt.strip('<>')
                if msgid:
                    entries.append({'msgid': msgid, 'msg_date': None})
        if not entries:
            return
        try:
            from b4.review import messages

            conn = messages.get_db()
            messages.set_flags_bulk(conn, entries, 'Answered')
            conn.close()
        except Exception:
            pass

    def _detect_maintainer_replies(self, msgs: List[Any]) -> None:
        """Detect replies sent by the maintainer via their own email client.

        Marks the immediate parent of each maintainer message as Answered.
        (All messages are already marked Seen by _mark_followup_msgs_seen.)
        """
        try:
            _, maintainer_email = b4.get_mailfrom()
        except Exception:
            return
        if not maintainer_email:
            return
        maintainer_email = maintainer_email.lower()
        # Build msgid map for ancestor lookups
        msgid_map: Dict[str, Dict[str, str]] = {}
        for msg in msgs:
            mid = b4.LoreMessage.clean_header(msg.get('Message-ID', ''))
            if mid:
                mid = mid.strip('<>')
                irt = b4.LoreMessage.clean_header(msg.get('In-Reply-To', ''))
                if irt:
                    irt = irt.strip('<>')
                msgid_map[mid] = {'irt': irt, 'from': msg.get('From', '')}

        answered_entries: List[Dict[str, Optional[str]]] = []
        for info in msgid_map.values():
            from_hdr = info['from']
            if not from_hdr:
                continue
            _, addr = email.utils.parseaddr(str(from_hdr))
            if addr.lower() != maintainer_email:
                continue
            # Immediate parent → Answered
            parent_id = info['irt']
            if parent_id and parent_id in msgid_map:
                answered_entries.append({'msgid': parent_id, 'msg_date': None})

        if not answered_entries:
            return
        try:
            from b4.review import messages

            conn = messages.get_db()
            messages.set_flags_bulk(conn, answered_entries, 'Answered')
            conn.close()
        except Exception:
            pass

    def _ensure_branch_checked_out(self) -> bool:
        """Check out the review branch if not already done.

        Shell suspend and agent runs need the working tree on the review
        branch. This defers the checkout to the first time it's needed
        so that normal review operations (reading diffs, saving tracking
        data) never switch branches.
        """
        if self.branch_checked_out:
            return True
        ecode, _out = b4.git_run_command(
            self._topdir, ['checkout', self._branch], logstderr=True
        )
        if ecode != 0:
            self.notify(f'Could not check out {self._branch}', severity='error')
            return False
        self.branch_checked_out = True
        return True

    def _restore_original_branch(self) -> None:
        """Switch back to the original branch after shell/agent use."""
        if not self.branch_checked_out or not self._original_branch:
            return
        ecode, _out = b4.git_run_command(
            self._topdir, ['checkout', self._original_branch], logstderr=True
        )
        if ecode == 0:
            self.branch_checked_out = False

    def action_agent(self) -> None:
        """Run the configured review agent command."""
        import shlex

        config = b4.get_main_config()
        agent_cmd = config.get('review-agent-command')
        agent_prompt = str(config.get('review-agent-prompt-path', ''))
        if not agent_cmd or not agent_prompt:
            self.notify(
                'Review agent not configured (set b4.review-agent-command and b4.review-agent-prompt-path)',
                severity='warning',
            )
            return

        assert isinstance(agent_cmd, str)
        sp = shlex.shlex(agent_cmd, posix=True)
        sp.whitespace_split = True
        cmdargs = list(sp)

        prompt_path = os.path.join(self._topdir, agent_prompt)
        if not os.path.isfile(prompt_path):
            self.notify(
                f'Agent prompt file not found: {agent_prompt}', severity='error'
            )
            return
        cmdargs += [f'Read and execute the prompt from {prompt_path}']

        if not self._ensure_branch_checked_out():
            return

        with self.suspend():
            logger.info('Running review agent: %s', ' '.join(cmdargs))
            try:
                spop = subprocess.Popen(cmdargs, cwd=self._topdir)
                spop.wait()
            except FileNotFoundError:
                logger.critical('Agent command not found: %s', cmdargs[0])
                _wait_for_enter()
                return
            except OSError as ex:
                logger.critical('Could not start agent: %s', ex)
                _wait_for_enter()
                return
            if spop.returncode != 0:
                logger.warning('Agent exited with code %d', spop.returncode)
            else:
                logger.info('Agent finished successfully')
            _wait_for_enter()

        # Integrate any review files the agent wrote
        integrated = b4.review._integrate_agent_reviews(
            self._topdir,
            self._cover_text,
            self._tracking,
            self._commit_shas,
            self._patches,
        )
        if integrated:
            self._populate_patch_list()
            self._show_content(self._selected_idx)
            self.notify('Agent review data loaded')
        self._restore_original_branch()

    def _save_tracking(self) -> None:
        """Save tracking data to the review branch."""
        b4.review.save_tracking_ref(
            self._topdir, self._branch, self._cover_text, self._tracking
        )

    def action_suspend(self) -> None:
        """Suspend the TUI and drop to an interactive shell."""
        if not self._ensure_branch_checked_out():
            return
        old_shas = list(self._commit_shas)
        with self.suspend():
            _suspend_to_shell()
        self._reconcile_after_shell(old_shas)
        self._restore_original_branch()

    def _reconcile_after_shell(self, old_shas: List[str]) -> None:
        """Reconcile tracking data after returning from shell.

        Detects whether patch commits were rewritten (e.g. via
        ``git rebase -i`` to reword subjects) and updates the
        tracking metadata to match.  Assumes the number of patches
        has not changed and their order is preserved.
        """
        series = self._tracking.get('series', {})
        first_patch = series.get('first-patch-commit', '')
        if first_patch:
            range_spec = f'{first_patch}~1..HEAD~1'
        else:
            range_spec = f'{self._base_commit}..HEAD~1'

        ecode, out = b4.git_run_command(
            self._topdir, ['rev-list', '--reverse', range_spec]
        )
        if ecode != 0 or not out.strip():
            # Could not enumerate — tracking commit may be damaged
            self.notify(
                'Could not enumerate patch commits after shell', severity='warning'
            )
            return

        new_shas = out.strip().splitlines()

        if new_shas == old_shas:
            return

        if len(new_shas) != len(old_shas):
            self.notify(
                f'Patch count changed ({len(old_shas)} → {len(new_shas)}). '
                'Please exit and re-enter the review.',
                severity='warning',
            )
            return

        # Reload tracking from the (possibly rewritten) tip commit
        try:
            self._cover_text, self._tracking = b4.review.load_tracking(
                self._topdir, 'HEAD'
            )
        except SystemExit:
            self.notify(
                'Could not reload tracking data after shell', severity='warning'
            )
            return

        series = self._tracking.get('series', {})
        self._series = series
        self._patches = self._tracking.get('patches', [])

        # Update first-patch-commit
        series['first-patch-commit'] = new_shas[0]

        # Re-anchor inline comments against the rebased diffs
        b4.review.reanchor_patch_comments(self._topdir, new_shas, self._patches)

        # Persist updated tracking
        self._tracking['series'] = series
        b4.review.save_tracking_ref(
            self._topdir, self._branch, self._cover_text, self._tracking
        )

        # Refresh in-memory state
        self._commit_shas = new_shas
        ecode, out = b4.git_run_command(
            self._topdir, ['log', '--reverse', '--format=%s', range_spec]
        )
        if ecode == 0 and out.strip():
            self._commit_subjects = out.strip().splitlines()
        self._sha_map = {}
        for idx, full_sha in enumerate(new_shas):
            self._sha_map[full_sha[: self._abbrev_len]] = (full_sha, idx)

        # Refresh the patch list display
        self._populate_patch_list()

        self.notify('Tracking data reconciled after commit edits')

    async def action_quit(self) -> None:
        """Quit the TUI."""
        self.exit()

    def action_help(self) -> None:
        """Show help overlay."""
        config = b4.get_main_config()
        has_agent = bool(
            config.get('review-agent-command')
            and config.get('review-agent-prompt-path')
        )
        self.push_screen(HelpScreen(_review_help_lines(has_agent=has_agent)))
