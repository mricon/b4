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
import pathlib
import re

from string import Template
from typing import Any, Dict, List, Literal, Optional, Tuple

import b4
import b4.mbox
import b4.review
import b4.review.tracking

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Label, ListItem, ListView, Static
from rich.markup import escape as _escape_markup

from b4.review_tui._common import (
    logger, _wait_for_enter, _suspend_to_shell, gather_attestation_info,
    SeparatedFooter,
)
from b4.review_tui._modals import (
    ViewSeriesScreen, AttestationScreen, TakeScreen,
    CherryPickScreen, NewerRevisionWarningScreen,
    RevisionChoiceScreen, RebaseConfirmScreen, AbandonConfirmScreen,
    ArchiveConfirmScreen, RangeDiffScreen, ThankScreen,
    LimitScreen, UpdateRevisionScreen, UpdateAllScreen,
    ActionScreen, HelpScreen, TRACKING_HELP_LINES,
)


def _get_art_counts(topdir: str, branch: str) -> Optional[Tuple[int, int, int]]:
    """Load (Acked, Reviewed, Tested) trailer counts from a review branch."""
    ecode, out = b4.git_run_command(topdir, ['log', '-1', '--format=%B', branch])
    if ecode > 0 or not out:
        return None
    marker = '--- b4-review-tracking ---'
    if marker not in out:
        return None
    json_text = out.split(marker, maxsplit=1)[1].strip()
    lines = [ln for ln in json_text.splitlines() if not ln.startswith('#')]
    try:
        tracking = json.loads('\n'.join(lines))
    except (json.JSONDecodeError, ValueError):
        return None

    acked = reviewed = tested = 0
    all_followups: List[Dict[str, Any]] = list(tracking.get('followups', []))
    for patch in tracking.get('patches', []):
        all_followups.extend(patch.get('followups', []))
    for fu in all_followups:
        for t in fu.get('trailers', []):
            name = t.split(':', 1)[0].strip().lower()
            if name == 'acked-by':
                acked += 1
            elif name == 'reviewed-by':
                reviewed += 1
            elif name == 'tested-by':
                tested += 1
    return (acked, reviewed, tested)


class TrackedSeriesItem(ListItem):
    """A single tracked series entry in the listing."""

    DEFAULT_CSS = """
    TrackedSeriesItem.reviewing Label {
        text-style: bold;
    }
    TrackedSeriesItem.waiting Label {
        opacity: 50%;
    }
    """

    def __init__(self, series: Dict[str, Any]) -> None:
        super().__init__()
        self.series = series
        status = series.get('status')
        if status in ('reviewing', 'replied'):
            self.add_class('reviewing')
        elif status == 'waiting':
            self.add_class('waiting')

    def compose(self) -> ComposeResult:
        subject = self.series.get('subject', '(no subject)')
        submitter = self.series.get('sender_name', 'Unknown')
        date = self.series.get('sent_at', '')[:10]
        status = self.series.get('status', 'new')
        label_text = f'{date}  {status:<12s} {submitter:<30s} {subject}'
        yield Label(label_text, markup=False)


class TrackingApp(App[Optional[str]]):
    """Textual app for browsing tracked series.

    Returns the branch name to review, or None to exit.
    """

    TITLE = 'b4 review'

    DEFAULT_CSS = """
    TrackingApp {
        layout: vertical;
    }
    #tracking-title {
        dock: top;
        width: 100%;
        height: 1;
        background: $accent;
        color: $text;
        text-style: bold;
        content-align: center middle;
    }
    #tracking-header {
        dock: top;
        width: 100%;
        height: 1;
        background: $surface;
        color: $text-muted;
    }
    #tracking-list {
        height: 1fr;
    }
    #tracking-empty {
        height: 1fr;
        content-align: center middle;
        color: $text-muted;
    }
    #details-panel {
        dock: bottom;
        width: 100%;
        height: 0;
        background: $surface;
        border-top: solid $primary;
        padding: 0 1;
        overflow: hidden;
    }
    .details-label {
        color: $text-muted;
        width: 12;
    }
    .details-row {
        height: 1;
    }
    #detail-revisions.has-upgrade {
        color: ansi_bright_yellow;
        text-style: bold;
    }
    """

    _GRP_SERIES = Binding.Group('Series')
    _GRP_APP = Binding.Group('App')

    BINDINGS = [
        # Hidden navigation bindings
        Binding('j', 'cursor_down', 'Down', show=False),
        Binding('k', 'cursor_up', 'Up', show=False),
        Binding('escape', 'hide_details', 'Close', show=False),
        # Series-specific actions
        Binding('r', 'review', 'review', group=_GRP_SERIES),
        Binding('v', 'view', 'view', group=_GRP_SERIES),
        Binding('d', 'range_diff', 'range-diff', group=_GRP_SERIES),
        Binding('a', 'action', 'action', group=_GRP_SERIES),
        # App-global actions
        Binding('u', 'update', 'update', group=_GRP_APP),
        Binding('l', 'limit', 'limit', group=_GRP_APP),
        Binding('s', 'suspend', 'shell', group=_GRP_APP),
        Binding('p', 'patchwork', 'patchwork', group=_GRP_APP),
        Binding('q', 'quit', 'quit', group=_GRP_APP),
        Binding('question_mark', 'help', 'help', key_display='?', group=_GRP_APP),
    ]

    def __init__(self, identifier: str, original_branch: Optional[str] = None,
                 focus_change_id: Optional[str] = None,
                 email_dryrun: bool = False) -> None:
        super().__init__()
        self._identifier = identifier
        self._original_branch = original_branch
        self._focus_change_id = focus_change_id
        self._email_dryrun = email_dryrun
        self._all_series: List[Dict[str, Any]] = []
        self._selected_series: Optional[Dict[str, Any]] = None
        self._limit_pattern: str = ''
        self._db_mtime: float = 0.0
        # Detect patchwork configuration
        config = b4.get_main_config()
        self._pwkey = str(config.get('pw-key', ''))
        self._pwurl = str(config.get('pw-url', ''))
        self._pwproj = str(config.get('pw-project', ''))

    def compose(self) -> ComposeResult:
        title = f' Tracked Series — {self._identifier}'
        if self._email_dryrun:
            title += ' (email dry-run)'
        yield Static(title, id='tracking-title')
        with Vertical(id='details-panel'):
            with Horizontal(classes='details-row'):
                yield Static('Subject:', classes='details-label')
                yield Static('', id='detail-subject', markup=False)
            with Horizontal(classes='details-row'):
                yield Static('From:', classes='details-label')
                yield Static('', id='detail-from', markup=False)
            with Horizontal(classes='details-row'):
                yield Static('Sent:', classes='details-label')
                yield Static('', id='detail-sent', markup=False)
            with Horizontal(classes='details-row'):
                yield Static('Change-ID:', classes='details-label')
                yield Static('', id='detail-changeid', markup=False)
            with Horizontal(classes='details-row'):
                yield Static('Link:', classes='details-label')
                yield Static('', id='detail-link', markup=False)
            with Horizontal(classes='details-row', id='detail-revisions-row'):
                yield Static('Revisions:', classes='details-label')
                yield Static('', id='detail-revisions', markup=False)
            with Horizontal(classes='details-row', id='detail-art-row'):
                yield Static('A/R/T:', classes='details-label')
                yield Static('', id='detail-art', markup=False)
            with Horizontal(classes='details-row', id='detail-branch-row'):
                yield Static('Branch:', classes='details-label')
                yield Static('', id='detail-branch', markup=False)
        yield SeparatedFooter()

    def on_mount(self) -> None:
        self._load_series()
        self.set_interval(1, self._check_db_changed)

    def _load_series(self) -> None:
        all_series = b4.review.tracking.get_all_tracked_series(self._identifier)
        self._all_series = [s for s in all_series if s.get('status') != 'archived']
        # Record the database mtime so the polling timer can detect changes
        try:
            db_path = b4.review.tracking.get_db_path(self._identifier)
            self._db_mtime = os.path.getmtime(db_path)
        except OSError:
            pass
        # Check for review branches and update status; flag series with
        # newer revisions available so the listing can warn the maintainer.
        topdir = b4.git_get_toplevel()
        try:
            conn = b4.review.tracking.get_db(self._identifier)
        except Exception:
            conn = None
        for series in self._all_series:
            change_id = series.get('change_id', '')
            if series.get('status') == 'new':
                branch_name = f'b4/review/{change_id}'
                if b4.git_branch_exists(None, branch_name):
                    series['status'] = 'reviewing'
            if conn:
                current_rev = series.get('revision', 1)
                try:
                    newest = b4.review.tracking.get_newest_revision(conn, change_id)
                    if newest is not None and newest > current_rev:
                        series['has_newer'] = True
                    revs = b4.review.tracking.get_revisions(conn, change_id)
                    if len(revs) > 1:
                        series['has_multiple_revisions'] = True
                except Exception:
                    pass
            # Load A/R/T trailer counts from the review branch
            if topdir and series.get('status') in ('reviewing', 'replied', 'waiting'):
                branch_name = f'b4/review/{change_id}'
                art = _get_art_counts(topdir, branch_name)
                if art:
                    series['art'] = art
        if conn:
            conn.close()
        # Sort by status (reviewing/replied first) then by date (newest first)
        _active_statuses = frozenset(('reviewing', 'replied'))

        def sort_key(s: Dict[str, Any]) -> Tuple[int, str]:
            status = s.get('status', 'new')
            status_order = 0 if status in _active_statuses else 1
            # Negate date string for reverse sort (newest first within each group)
            # ISO dates sort lexicographically, so we can just reverse the string comparison
            sent_at = s.get('sent_at', '') or ''
            return (status_order, sent_at)
        # Sort by status ascending, then date descending (newest first)
        self._all_series.sort(key=sort_key)
        # Now reverse within each status group by re-sorting with stable sort
        active = [s for s in self._all_series if s.get('status') in _active_statuses]
        others = [s for s in self._all_series if s.get('status') not in _active_statuses]
        active.sort(key=lambda s: s.get('sent_at', '') or '', reverse=True)
        others.sort(key=lambda s: s.get('sent_at', '') or '', reverse=True)
        self._all_series = active + others
        self.call_later(self._refresh_list)

    def _check_db_changed(self) -> None:
        """Poll the database file mtime and reload if it changed."""
        try:
            db_path = b4.review.tracking.get_db_path(self._identifier)
            mtime = os.path.getmtime(db_path)
        except OSError:
            return
        if mtime != self._db_mtime:
            self._load_series()

    async def _refresh_list(self) -> None:
        # Remove existing list/empty widgets
        for widget in list(self.query('#tracking-header, #tracking-list, #tracking-empty')):
            await widget.remove()

        display_series = self._all_series
        if self._limit_pattern:
            pat = self._limit_pattern.lower()
            display_series = [
                s for s in display_series
                if pat in (s.get('subject', '') or '').lower()
                or pat in (s.get('sender_name', '') or '').lower()
            ]

        title = self.query_one('#tracking-title', Static)
        title_parts = f' Tracked Series — {self._identifier}'
        if self._limit_pattern:
            title_parts += f' ({len(display_series)}/{len(self._all_series)} series, limit: {self._limit_pattern})'
        else:
            title_parts += f' ({len(self._all_series)} series)'
        title.update(title_parts)

        if not display_series:
            empty = Static('No tracked series. Use "b4 review track" to add series.', id='tracking-empty')
            await self.mount(empty, before=self.query_one(Footer))
            return

        header_text = f'{"Date":<12s}{"Status":<12s} {"Submitter":<30s} {"Subject"}'
        header = Static(header_text, id='tracking-header')
        items = [TrackedSeriesItem(s) for s in display_series]
        lv = ListView(*items, id='tracking-list')
        await self.mount(header, before=self.query_one(Footer))
        await self.mount(lv, before=self.query_one(Footer))
        if self._focus_change_id:
            for idx, series in enumerate(self._all_series):
                if series.get('change_id') == self._focus_change_id:
                    lv.index = idx
                    break
            self._focus_change_id = None
        lv.focus()

    def action_limit(self) -> None:
        self.push_screen(LimitScreen(self._limit_pattern), callback=self._on_limit)

    def _on_limit(self, result: Optional[str]) -> None:
        if result is None:
            return
        self._limit_pattern = result
        self._load_series()

    def action_cursor_down(self) -> None:
        try:
            self.query_one('#tracking-list', ListView).action_cursor_down()
        except Exception:
            pass

    def action_cursor_up(self) -> None:
        try:
            self.query_one('#tracking-list', ListView).action_cursor_up()
        except Exception:
            pass

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.list_view.id != 'tracking-list':
            return
        item = event.item
        if isinstance(item, TrackedSeriesItem):
            self._selected_series = item.series
            self._show_details(item.series)
        self.refresh_bindings()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == 'tracking-list':
            self.action_review()

    _STATE_ACTIONS: Dict[str, frozenset[str]] = {
        'new': frozenset({'review', 'view', 'abandon'}),
        'reviewing': frozenset({'review', 'update_revision', 'range_diff', 'take', 'rebase', 'suspend', 'abandon', 'waiting'}),
        'replied': frozenset({'review', 'range_diff', 'take', 'rebase', 'suspend', 'archive', 'waiting'}),
        'waiting': frozenset({'review', 'view', 'range_diff', 'abandon', 'archive'}),
        'taken': frozenset({'thank', 'archive'}),
        'thanked': frozenset({'archive'}),
    }
    # All state-gated actions (union of all per-state sets)
    _GATED_ACTIONS = frozenset().union(*_STATE_ACTIONS.values())

    def check_action(self, action: str, parameters: Tuple[Any, ...]) -> Optional[bool]:
        """Hide status-specific actions based on the selected series."""
        if action == 'patchwork':
            return bool(self._pwkey and self._pwurl and self._pwproj)
        if action == 'action':
            return self._selected_series is not None
        if action in self._GATED_ACTIONS:
            if not self._selected_series:
                return False
            status = self._selected_series.get('status', 'new')
            if action not in self._STATE_ACTIONS.get(status, frozenset()):
                return False
            if action == 'update_revision':
                return bool(self._selected_series.get('has_newer'))
            if action == 'range_diff':
                return bool(self._selected_series.get('has_multiple_revisions'))
            return True
        return True

    def action_action(self) -> None:
        """Open a modal with context-sensitive actions for the selected series."""
        if not self._selected_series:
            return
        status = self._selected_series.get('status', 'new')
        actions: list[tuple[str, str]] = []
        if status in ('reviewing', 'replied'):
            actions.append(('take', 'Take (apply to branch)'))
            actions.append(('rebase', 'Rebase review branch'))
            actions.append(('waiting', 'Mark as waiting on new revision'))
        if status == 'reviewing' and self._selected_series.get('has_newer'):
            actions.append(('upgrade', 'Upgrade to newer revision'))
        if status == 'taken':
            actions.append(('thank', 'Send thank-you'))
        if status != 'thanked':
            actions.append(('abandon', 'Abandon series'))
        actions.append(('archive', 'Archive series'))
        self.push_screen(
            ActionScreen(actions),
            callback=self._on_action_selected,
        )

    def _on_action_selected(self, action: Optional[str]) -> None:
        """Dispatch the chosen action to the corresponding handler."""
        if action is None:
            return
        handler = {
            'take': self.action_take,
            'rebase': self.action_rebase,
            'abandon': self.action_abandon,
            'thank': self.action_thank,
            'upgrade': self.action_update_revision,
            'archive': self.action_archive,
            'waiting': self.action_waiting,
        }.get(action)
        if handler:
            handler()

    def action_review(self) -> None:
        if not self._selected_series:
            return
        status = self._selected_series.get('status', 'new')
        if status in ('reviewing', 'replied', 'waiting'):
            # Already checked out - go to review mode
            change_id = self._selected_series.get('change_id', '')
            revision = self._selected_series.get('revision')
            if status == 'waiting':
                # Bring back to reviewing on re-entry
                try:
                    conn = b4.review.tracking.get_db(self._identifier)
                    b4.review.tracking.update_series_status(
                        conn, change_id, 'reviewing', revision=revision)
                    conn.close()
                except Exception:
                    pass
            branch_name = f'b4/review/{change_id}'
            self.exit(branch_name)
        elif self._selected_series.get('has_newer'):
            # New series with a newer revision available — ask which to review
            current_rev = self._selected_series.get('revision', 1)
            change_id = self._selected_series.get('change_id', '')
            try:
                conn = b4.review.tracking.get_db(self._identifier)
                newest = b4.review.tracking.get_newest_revision(conn, change_id)
                conn.close()
            except Exception:
                newest = None
            if newest and newest > current_rev:
                self.push_screen(
                    RevisionChoiceScreen(current_rev, newest),
                    callback=self._on_revision_choice,
                )
            else:
                self._checkout_new_series()
        else:
            # New series - need to check out
            self._checkout_new_series()

    def _on_revision_choice(self, chosen: Optional[int]) -> None:
        """Handle the revision chosen from the RevisionChoiceScreen."""
        if chosen is None:
            return
        series = self._selected_series
        if not series:
            return
        current_rev = series.get('revision', 1)
        if chosen != current_rev:
            # Swap to the chosen revision's message_id from the DB
            change_id = series.get('change_id', '')
            try:
                conn = b4.review.tracking.get_db(self._identifier)
                revs = b4.review.tracking.get_revisions(conn, change_id)
                conn.close()
            except Exception:
                self.notify('Could not load revision data', severity='error')
                return
            for rev in revs:
                if rev['revision'] == chosen:
                    series['message_id'] = rev['message_id']
                    series['revision'] = chosen
                    break
            else:
                self.notify(f'Revision v{chosen} not found in database',
                            severity='error')
                return
        self._checkout_new_series()

    def action_view(self) -> None:
        """Preview a series in a modal dialog."""
        if not self._selected_series:
            return
        message_id = self._selected_series.get('message_id', '')
        if not message_id:
            self.notify('No message-id available for this series', severity='error')
            return
        self.push_screen(ViewSeriesScreen(message_id))

    def _checkout_new_series(self) -> None:
        """Retrieve series, check attestation, and create review branch."""
        series = self._selected_series
        if not series:
            return

        message_id = series.get('message_id', '')
        if not message_id:
            self.notify('No message-id available for this series', severity='error')
            return

        # Suspend UI for all retrieval and processing that might log
        lser = None
        att_result = None
        with self.suspend():
            logger.info('Retrieving series: %s', message_id)
            try:
                msgs = b4.review._retrieve_messages(message_id)
                wantver = series.get('revision')
                lser = b4.review._get_lore_series(msgs, wantver=wantver)
            except LookupError as ex:
                logger.critical('%s', ex)
                _wait_for_enter()
                return
            except Exception as ex:
                logger.critical('Error retrieving series: %s', ex)
                _wait_for_enter()
                return

            # Gather attestation info
            att_result = gather_attestation_info(lser)

        # Show attestation screen (TUI resumed)
        self.push_screen(
            AttestationScreen(att_result),
            callback=lambda proceed: self._on_attestation_complete(proceed, lser, series),
        )

    def _on_attestation_complete(self, proceed: bool, lser: b4.LoreSeries,
                                  series: Dict[str, Any]) -> None:
        """Handle attestation screen result."""
        if not proceed:
            self.notify('Checkout cancelled', severity='information')
            return

        # Proceed with checkout
        self._do_checkout(lser, series)

    def _do_checkout(self, lser: b4.LoreSeries, series: Dict[str, Any]) -> None:
        """Create the review branch for the series."""
        import io

        topdir = b4.git_get_toplevel()
        if not topdir:
            self.notify('Not in a git repository', severity='error')
            return

        # Determine branch name from change_id
        change_id = series.get('change_id', '')
        branch_name = f'b4/review/{change_id}'

        # Suspend UI for all checkout operations that might log
        checkout_success = False
        with self.suspend():
            # Get am-ready messages
            am_msgs = lser.get_am_ready(noaddtrailers=True, addmysob=False, addlink=False,
                                        cherrypick=None, copyccs=False, allowbadchars=False,
                                        showchecks=False)
            if not am_msgs:
                logger.critical('No patches ready for applying')
                _wait_for_enter()
                return

            # Find the top msgid
            top_msgid = None
            first_body = None
            for lmsg in lser.patches:
                if lmsg is not None:
                    first_body = lmsg.body
                    top_msgid = lmsg.msgid
                    break

            if top_msgid is None or first_body is None:
                logger.critical('Could not find any patches in the series')
                _wait_for_enter()
                return

            # Determine base commit
            base_commit = lser.base_commit
            need_guess = False

            if base_commit:
                # Check if the specified base-commit exists in this repo
                if not b4.git_commit_exists(topdir, base_commit):
                    logger.warning('Base commit %s not found in repository, will try to guess', base_commit)
                    need_guess = True
            else:
                need_guess = True

            if need_guess:
                logger.info('Guessing base commit...')
                try:
                    base_commit, nblobs, mismatches = lser.find_base(topdir, branches=None, maxdays=30)
                    if mismatches == 0:
                        logger.info('Base: %s (exact match)', base_commit)
                    elif nblobs == mismatches:
                        logger.warning('Base: failed to find matching base')
                        base_commit = None
                    else:
                        logger.info('Base: %s (best guess, %s/%s blobs matched)',
                                    base_commit, nblobs - mismatches, nblobs)
                except IndexError as ex:
                    logger.warning('Base: failed to guess (%s)', ex)
                    base_commit = None

            if not base_commit:
                logger.critical('Could not determine base commit')
                _wait_for_enter()
                return

            # Build mbox for git-am
            ifh = io.BytesIO()
            b4.save_git_am_mbox(am_msgs, ifh)
            ambytes = ifh.getvalue()

            # Get linkmask
            config = b4.get_main_config()
            linkmask = str(config.get('linkmask', ''))
            if '%s' not in linkmask:
                logger.critical('linkmask not configured properly')
                _wait_for_enter()
                return
            linkurl = linkmask % top_msgid

            try:
                logger.info('Base: %s', base_commit)
                b4.git_fetch_am_into_repo(topdir, ambytes=ambytes, at_base=base_commit, origin=linkurl)

                # Create the review branch
                b4.review.create_review_branch(topdir, branch_name, base_commit, lser,
                                               linkurl, linkmask, num_prereqs=0)
                logger.info('Review branch created: %s', branch_name)
                checkout_success = True
            except Exception as ex:
                logger.critical('Error creating review branch: %s', ex)
                _wait_for_enter()

        if not checkout_success:
            return

        # Update series status in database
        if self._identifier:
            try:
                conn = b4.review.tracking.get_db(self._identifier)
                conn.execute('UPDATE series SET status = ?, revision = ?, message_id = ? WHERE track_id = ?',
                             ('reviewing', series.get('revision'), series.get('message_id'),
                              series.get('track_id')))
                conn.commit()
                conn.close()
            except Exception as ex:
                logger.warning('Failed to update series status: %s', ex)

        # Update Patchwork state if series was tracked from Patchwork
        pw_series_id = series.get('pw_series_id')
        if pw_series_id:
            b4.review.pw_update_series_state(pw_series_id, 'under-review')

        # Exit to review mode
        self.exit(branch_name)

    def _show_details(self, series: Dict[str, Any]) -> None:
        import datetime
        import email.utils

        panel = self.query_one('#details-panel', Vertical)
        panel.styles.height = 7

        subject = series.get('subject', '(no subject)')
        revision = series.get('revision', 1)
        num_patches = series.get('num_patches', 0)
        # Format subject with version and patch count prefix
        width = len(str(num_patches)) if num_patches > 0 else 1
        subject_display = f'[v{revision},{"0" * width}/{num_patches:0{width}d}] {subject}'

        sender_name = series.get('sender_name', 'Unknown')
        sender_email = series.get('sender_email', '')
        from_str = f'{sender_name} <{sender_email}>' if sender_email else sender_name
        change_id = series.get('change_id', '')
        message_id = series.get('message_id', '')

        # Create link URL from message-id using linkmask
        link_url = ''
        if message_id:
            config = b4.get_main_config()
            linkmask = config.get('linkmask', b4.LOREADDR + '/%s')
            if isinstance(linkmask, str) and '%s' in linkmask:
                link_url = linkmask % message_id

        # Convert ISO date to RFC 822 in local timezone
        sent_str = 'Unknown'
        sent_at = series.get('sent_at', '')
        if sent_at:
            try:
                dt = datetime.datetime.fromisoformat(sent_at)
                # Convert to local timezone
                local_dt = dt.astimezone()
                sent_str = email.utils.format_datetime(local_dt)
            except (ValueError, TypeError):
                sent_str = sent_at

        self.query_one('#detail-subject', Static).update(subject_display)
        self.query_one('#detail-from', Static).update(from_str)
        self.query_one('#detail-sent', Static).update(sent_str)
        self.query_one('#detail-changeid', Static).update(change_id)
        self.query_one('#detail-link', Static).update(link_url)

        # Show known revisions from SQLite
        height = 7
        revision = series.get('revision', 1)
        revisions_row = self.query_one('#detail-revisions-row', Horizontal)
        try:
            conn = b4.review.tracking.get_db(self._identifier)
            revs = b4.review.tracking.get_revisions(conn, change_id)
            conn.close()
            if revs:
                rev_str = ', '.join(f'v{r["revision"]}' for r in revs)
                rev_widget = self.query_one('#detail-revisions', Static)
                status = series.get('status', 'new')
                if series.get('has_newer') and status == 'reviewing':
                    rev_str += f' (upgrade from v{revision} with [a]ction)'
                    rev_widget.add_class('has-upgrade')
                elif series.get('has_newer') and status == 'new':
                    newest = max(r['revision'] for r in revs)
                    rev_str += f' (v{newest} available)'
                    rev_widget.add_class('has-upgrade')
                elif series.get('has_newer') and status == 'waiting':
                    newest = max(r['revision'] for r in revs)
                    rev_str += f' (v{newest} available, will auto-upgrade on update)'
                    rev_widget.add_class('has-upgrade')
                else:
                    rev_widget.remove_class('has-upgrade')
                rev_widget.update(rev_str)
                revisions_row.display = True
                height += 1
            else:
                revisions_row.display = False
        except Exception:
            revisions_row.display = False

        # Show A/R/T trailer counts for series with review branches
        art_row = self.query_one('#detail-art-row', Horizontal)
        art = series.get('art')
        if art:
            a, r, t = art
            art_str = ' / '.join(str(x) if x else '-' for x in (a, r, t))
            self.query_one('#detail-art', Static).update(art_str)
            art_row.display = True
            height += 1
        else:
            art_row.display = False

        # Show branch name for series being reviewed
        status = series.get('status', 'new')
        branch_row = self.query_one('#detail-branch-row', Horizontal)
        if status in ('reviewing', 'replied', 'waiting'):
            branch_name = f'b4/review/{change_id}'
            self.query_one('#detail-branch', Static).update(branch_name)
            branch_row.display = True
            height += 1
        else:
            branch_row.display = False

        panel.styles.height = height

    def action_update(self) -> None:
        """Fetch threads and update revisions/trailers for all tracked series."""
        if not self._all_series:
            self.notify('No tracked series to update', severity='warning')
            return

        config = b4.get_main_config()
        linkmask = str(config.get('linkmask', 'https://lore.kernel.org/r/%s'))
        topdir = b4.git_get_toplevel()

        self.push_screen(
            UpdateAllScreen(self._all_series, self._identifier, linkmask, topdir),
            callback=self._on_update_all_complete,
        )

    def _on_update_all_complete(self, result: Optional[Dict[str, int]]) -> None:
        """Build a summary notification from the update-all result."""
        if result is None:
            return
        checked = result.get('series_checked', 0)
        updated = result.get('series_updated', 0)
        promoted = result.get('promoted', 0)
        errors = result.get('errors', 0)

        parts = [f'Checked {checked} series']
        if updated:
            parts.append(f'{updated} updated')
        if promoted:
            parts.append(f'{promoted} promoted from waiting')
        if errors:
            parts.append(f'{errors} error(s)')

        severity: Literal['information', 'warning'] = 'warning' if errors else 'information'
        self.notify(', '.join(parts), severity=severity)
        self._load_series()

    def action_hide_details(self) -> None:
        panel = self.query_one('#details-panel', Vertical)
        if panel.styles.height and panel.styles.height.value > 0:
            panel.styles.height = 0
            self._selected_series = None

    def action_take(self) -> None:
        """Show take options dialog for the selected series."""
        if not self._selected_series:
            return
        status = self._selected_series.get('status', 'new')
        if status not in ('reviewing', 'replied'):
            self.notify('Series must be checked out before taking', severity='warning')
            return

        # Determine the target branch suggestion
        if self._original_branch:
            target_branch = self._original_branch
        else:
            # Fall back: check for master, main, or empty
            topdir = b4.git_get_toplevel()
            if topdir and b4.git_branch_exists(topdir, 'master'):
                target_branch = 'master'
            elif topdir and b4.git_branch_exists(topdir, 'main'):
                target_branch = 'main'
            else:
                target_branch = ''

        series = self._selected_series
        change_id = series.get('change_id', '')
        review_branch = f'b4/review/{change_id}'

        # Check if a newer revision is known to exist
        current_rev = series.get('revision', 1)
        newer_versions: List[int] = []
        topdir_take = b4.git_get_toplevel()
        if topdir_take:
            try:
                _ct, trk = b4.review.load_tracking(topdir_take, review_branch)
                newer_versions = trk.get('series', {}).get('newer-versions', [])
            except SystemExit:
                pass
        if not newer_versions and self._identifier and change_id:
            try:
                conn = b4.review.tracking.get_db(self._identifier)
                newest = b4.review.tracking.get_newest_revision(conn, change_id)
                conn.close()
                if newest is not None and newest > current_rev:
                    newer_versions = list(range(current_rev + 1, newest + 1))
            except Exception:
                pass

        if newer_versions:
            # Require explicit confirmation before taking an older revision
            self.push_screen(
                NewerRevisionWarningScreen(current_rev, newer_versions),
                callback=lambda proceed: self._on_newer_revision_acknowledged(
                    proceed, target_branch, change_id, review_branch, series),
            )
        else:
            self._show_take_screen(target_branch, change_id, review_branch, series)

    def _on_newer_revision_acknowledged(self, proceed: bool, target_branch: str,
                                        change_id: str, review_branch: str,
                                        series: Dict[str, Any]) -> None:
        """Handle result of the newer-revision warning."""
        if not proceed:
            return
        self._show_take_screen(target_branch, change_id, review_branch, series)

    def _show_take_screen(self, target_branch: str, change_id: str,
                          review_branch: str, series: Dict[str, Any]) -> None:
        """Push the TakeScreen dialog."""
        num_patches = series.get('num_patches', 0) or 0
        take_screen = TakeScreen(target_branch, review_branch, num_patches=num_patches)
        self.push_screen(
            take_screen,
            callback=lambda confirmed: self._on_take_confirmed(
                confirmed, change_id, review_branch, take_screen, series),
        )

    def _on_take_confirmed(self, confirmed: bool, change_id: str,
                           review_branch: str, take_screen: 'TakeScreen',
                           series: Dict[str, Any]) -> None:
        """Handle take confirmation result."""
        if not confirmed:
            return
        if take_screen.method_result == 'merge':
            with self.suspend():
                self._do_take_merge(change_id, review_branch, take_screen)
            self._load_series()
        elif take_screen.method_result == 'linear':
            with self.suspend():
                self._do_take_am(change_id, review_branch, take_screen, series,
                                 cherrypick=None)
            self._load_series()
        elif take_screen.method_result == 'cherry-pick':
            # Load tracking to get the patch list for cherry-pick selection
            topdir = b4.git_get_toplevel()
            if not topdir:
                self.notify('Not in a git repository', severity='error')
                return
            try:
                _cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
            except SystemExit:
                self.notify('Could not load tracking data', severity='error')
                return
            patches = tracking.get('patches', [])
            if not patches:
                self.notify('No patches found in tracking data', severity='error')
                return
            pick_screen = CherryPickScreen(patches)
            self.push_screen(
                pick_screen,
                callback=lambda picked: self._on_cherrypick_confirmed(
                    picked, change_id, review_branch, take_screen, series,
                    pick_screen),
            )

    def _on_cherrypick_confirmed(self, confirmed: bool, change_id: str,
                                 review_branch: str, take_screen: 'TakeScreen',
                                 series: Dict[str, Any],
                                 pick_screen: 'CherryPickScreen') -> None:
        """Handle cherry-pick selection result."""
        if not confirmed:
            return
        with self.suspend():
            self._do_take_am(change_id, review_branch, take_screen, series,
                             cherrypick=pick_screen.selected_indices)
        self._load_series()

    @staticmethod
    def _record_take_metadata(topdir: str, review_branch: str,
                              target_branch: str, commit_ids: List[str],
                              cherrypick: Optional[List[int]] = None) -> None:
        """Record taken commit IDs in the tracking data on the review branch.

        Args:
            topdir: Repository top-level directory.
            review_branch: The b4/review/... branch with the tracking commit.
            target_branch: Branch the patches were applied to.
            commit_ids: Ordered list of commit SHAs that were applied.
            cherrypick: If set, the 1-based patch indices that were picked.
        """
        import datetime
        try:
            cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
        except SystemExit:
            logger.warning('Could not load tracking data for recording take metadata')
            return

        series = tracking.get('series', {})
        series['taken'] = {
            'branch': target_branch,
            'date': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d'),
        }
        tracking['series'] = series

        patches = tracking.get('patches', [])
        if cherrypick:
            # Map selected 1-based indices to commit IDs
            for ci, pidx in enumerate(cherrypick):
                pi = pidx - 1  # convert to 0-based patches list index
                if pi < len(patches) and ci < len(commit_ids):
                    patches[pi]['taken'] = {'commit-id': commit_ids[ci]}
        else:
            # All patches taken in order
            for pi, patch in enumerate(patches):
                if pi < len(commit_ids):
                    patch['taken'] = {'commit-id': commit_ids[pi]}

        if not b4.review.save_tracking_ref(topdir, review_branch, cover_text, tracking):
            logger.warning('Could not save take metadata to tracking commit')

    def _do_take_merge(self, change_id: str, review_branch: str,
                       take_screen: 'TakeScreen') -> None:
        """Perform a merge-based take operation."""
        target_branch = take_screen.target_result

        # Setup
        topdir = b4.git_get_toplevel()
        if not topdir:
            logger.critical('Not in a git repository')
            return

        try:
            cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
        except SystemExit:
            logger.critical('Could not load tracking data from %s', review_branch)
            _wait_for_enter()
            return

        series = tracking.get('series', {})

        # Build merge message from template
        config = b4.get_config_from_git('b4\\..*')
        merge_template = b4.mbox.DEFAULT_MERGE_TEMPLATE
        if config.get('shazam-merge-template'):
            try:
                merge_template = b4.read_template(str(config['shazam-merge-template']))
            except FileNotFoundError:
                logger.critical('ERROR: shazam-merge-template says to use %s, but it does not exist',
                                config['shazam-merge-template'])
                _wait_for_enter()
                return

        # Extract cover message body
        covermessage = ''
        if cover_text:
            _githeaders, message, _trailers, _basement, _sig = b4.LoreMessage.get_body_parts(cover_text)
            covermessage = message.strip()
        if not covermessage:
            covermessage = '(no cover letter message)'

        # Clean subject: strip [PATCH vN M/N] prefix
        subject = series.get('subject', '')
        clean_subject = re.sub(r'^\s*\[.*?]\s*', '', subject).strip()
        if not clean_subject:
            clean_subject = subject

        # Determine number of patches
        num_patches = len(tracking.get('patches', []))

        # Populate template
        tptvals = {
            'seriestitle': clean_subject,
            'authorname': series.get('fromname', ''),
            'authoremail': series.get('fromemail', ''),
            'covermessage': covermessage,
            'midurl': series.get('link', ''),
            'mid': series.get('header-info', {}).get('msgid', ''),
            'patch_or_series': 'patch series' if num_patches > 1 else 'patch',
        }
        body = Template(merge_template).safe_substitute(tptvals)

        # Strip Link: line if not requested
        if not take_screen.add_link:
            body = re.sub(r'^Link:.*\n?', '', body, flags=re.MULTILINE)

        # Append Signed-off-by if requested
        if take_screen.add_signoff:
            usercfg = b4.get_config_from_git('user\\..*')
            uname = usercfg.get('name', '')
            uemail = usercfg.get('email', '')
            if uname and uemail:
                sob = f'Signed-off-by: {uname} <{uemail}>'
                body = body.rstrip('\n') + '\n\n' + sob + '\n'

        # Open editor
        try:
            edited = b4.edit_in_editor(body.encode(), filehint='MERGE_MSG')
        except Exception as ex:
            logger.critical('Editor error: %s', ex)
            _wait_for_enter()
            return
        merge_msg = edited.decode(errors='replace').strip()
        if not merge_msg:
            logger.info('Empty merge message, aborting')
            _wait_for_enter()
            return

        # Save current branch so we can restore on failure
        ecode, out = b4.git_run_command(topdir, ['symbolic-ref', '--short', 'HEAD'])
        if ecode == 0:
            prev_branch = out.strip()
        else:
            ecode, out = b4.git_run_command(topdir, ['rev-parse', 'HEAD'])
            prev_branch = out.strip()

        # Checkout target branch
        ecode, out = b4.git_run_command(topdir, ['checkout', target_branch], logstderr=True)
        if ecode != 0:
            logger.critical('Could not checkout %s: %s', target_branch, out.strip())
            _wait_for_enter()
            return

        # Write merge message to git dir
        ecode, gitdir = b4.git_run_command(topdir, ['rev-parse', '--git-dir'])
        if ecode != 0:
            logger.critical('Unable to find git directory')
            b4.git_run_command(topdir, ['checkout', prev_branch], logstderr=True)
            _wait_for_enter()
            return
        mmf = os.path.join(gitdir.strip(), 'b4-merge-msg')
        with open(mmf, 'w') as fh:
            fh.write(merge_msg)

        # Perform merge: review_branch~1 excludes the tracking commit at tip
        gitargs = ['merge', '--no-ff', '--no-edit', '-F', mmf, f'{review_branch}~1']
        ecode, out = b4.git_run_command(topdir, gitargs, logstderr=True)

        # Clean up message file
        try:
            os.unlink(mmf)
        except OSError:
            pass

        if ecode != 0:
            logger.critical('Merge failed: %s', out.strip())
            logger.critical('Aborting merge...')
            b4.git_run_command(topdir, ['merge', '--abort'], logstderr=True)
            b4.git_run_command(topdir, ['checkout', prev_branch], logstderr=True)
            _wait_for_enter()
            return

        logger.info('Merged %s into %s', review_branch, target_branch)

        # Record per-patch commit IDs from the review branch
        base_commit = series.get('base-commit', '')
        if base_commit:
            ecode, out = b4.git_run_command(
                topdir, ['rev-list', '--reverse', f'{base_commit}..{review_branch}~1'])
            if ecode == 0:
                commit_ids = out.strip().splitlines()
                self._record_take_metadata(topdir, review_branch, target_branch,
                                           commit_ids)

        # Record the series as taken in the tracking database
        if self._identifier and change_id:
            revision = series.get('revision')
            try:
                conn = b4.review.tracking.get_db(self._identifier)
                b4.review.tracking.update_series_status(conn, change_id, 'taken',
                                                        revision=revision)
                conn.close()
            except Exception as ex:
                logger.warning('Could not update series status: %s', ex)
        # Update Patchwork state if series was tracked from Patchwork
        if self._selected_series:
            pw_sid = self._selected_series.get('pw_series_id')
            if pw_sid:
                b4.review.pw_update_series_state(pw_sid, 'accepted')
        _wait_for_enter()

    def _do_take_am(self, change_id: str, review_branch: str,
                    take_screen: 'TakeScreen', series: Dict[str, Any],
                    cherrypick: Optional[List[int]]) -> None:
        """Perform a linear or cherry-pick take via git-am."""
        import io

        target_branch = take_screen.target_result

        topdir = b4.git_get_toplevel()
        if not topdir:
            logger.critical('Not in a git repository')
            return

        # Load tracking to get follow-up trailers
        try:
            _cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
        except SystemExit:
            logger.critical('Could not load tracking data from %s', review_branch)
            _wait_for_enter()
            return

        t_series = tracking.get('series', {})

        # Re-fetch original messages from lore
        message_id = series.get('message_id', '')
        if not message_id:
            logger.critical('No message-id available, cannot retrieve series')
            _wait_for_enter()
            return

        logger.info('Retrieving series: %s', message_id)
        try:
            msgs = b4.review._retrieve_messages(message_id)
        except LookupError as ex:
            logger.critical('%s', ex)
            _wait_for_enter()
            return
        except Exception as ex:
            logger.critical('Error retrieving series: %s', ex)
            _wait_for_enter()
            return

        # Build LoreSeries with follow-up trailers
        lmbx = b4.LoreMailbox()
        for msg in msgs:
            lmbx.add_message(msg)

        wantver = t_series.get('revision', None)
        lser = lmbx.get_series(wantver, sloppytrailers=False,
                               codereview_trailers=False)
        if lser is None:
            logger.critical('Could not find series in retrieved messages')
            _wait_for_enter()
            return

        # Also apply any per-patch follow-up trailers from tracking data
        # that may have been collected outside the thread
        patches_meta = tracking.get('patches', [])
        cover_followups = tracking.get('followups', [])
        for followup in cover_followups:
            for tstr in followup.get('trailers', []):
                if ': ' not in tstr:
                    continue
                tname, tval = tstr.split(': ', maxsplit=1)
                fltr = b4.LoreTrailer(name=tname, value=tval)
                if lser.patches[0] is not None and fltr not in lser.patches[0].followup_trailers:
                    lser.patches[0].followup_trailers.append(fltr)
        for i, pmeta in enumerate(patches_meta):
            pidx = i + 1  # patches[0] is cover letter
            if pidx >= len(lser.patches) or lser.patches[pidx] is None:
                continue
            patch = lser.patches[pidx]
            assert patch is not None
            for followup in pmeta.get('followups', []):
                for tstr in followup.get('trailers', []):
                    if ': ' not in tstr:
                        continue
                    tname, tval = tstr.split(': ', maxsplit=1)
                    fltr = b4.LoreTrailer(name=tname, value=tval)
                    if fltr not in patch.followup_trailers:
                        patch.followup_trailers.append(fltr)

        # Get am-ready messages
        am_msgs = lser.get_am_ready(noaddtrailers=False,
                                    addmysob=take_screen.add_signoff,
                                    addlink=take_screen.add_link,
                                    cherrypick=cherrypick,
                                    copyccs=False,
                                    allowbadchars=False)
        if not am_msgs:
            logger.critical('No patches ready for applying')
            _wait_for_enter()
            return

        if cherrypick:
            logger.info('Prepared %d patch(es) (cherry-picked: %s)',
                        len(am_msgs), ', '.join(str(x) for x in cherrypick))
        else:
            logger.info('Prepared %d patch(es)', len(am_msgs))

        # Build mbox bytes for git-am
        ifh = io.BytesIO()
        b4.save_git_am_mbox(am_msgs, ifh)
        ambytes = ifh.getvalue()

        # Save current branch so we can report it on failure
        ecode, out = b4.git_run_command(topdir, ['symbolic-ref', '--short', 'HEAD'])
        if ecode == 0:
            prev_branch = out.strip()
        else:
            ecode, out = b4.git_run_command(topdir, ['rev-parse', 'HEAD'])
            prev_branch = out.strip()

        # Checkout target branch
        ecode, out = b4.git_run_command(topdir, ['checkout', target_branch], logstderr=True)
        if ecode != 0:
            logger.critical('Could not checkout %s: %s', target_branch, out.strip())
            _wait_for_enter()
            return

        # Save HEAD before git-am so we can find the new commits afterwards
        ecode, out = b4.git_run_command(topdir, ['rev-parse', 'HEAD'])
        pre_am_head = out.strip() if ecode == 0 else ''

        # Run git-am
        ecode, out = b4.git_run_command(topdir, ['am'], stdin=ambytes, logstderr=True)
        if ecode != 0:
            logger.critical('git-am failed:')
            logger.critical(out.strip())
            logger.critical('---')
            logger.critical('Resolve the conflict, then run: git am --continue')
            logger.critical('Or abort with: git am --abort')
            _wait_for_enter()
            return

        logger.info(out.strip())
        logger.info('Applied %d patch(es) to %s', len(am_msgs), target_branch)

        # Record per-patch commit IDs in the tracking data
        if pre_am_head:
            ecode, out = b4.git_run_command(
                topdir, ['rev-list', '--reverse', f'{pre_am_head}..HEAD'])
            if ecode == 0:
                commit_ids = out.strip().splitlines()
                self._record_take_metadata(topdir, review_branch, target_branch,
                                           commit_ids, cherrypick=cherrypick)

        # Record the series as taken in the tracking database
        if self._identifier and change_id:
            revision = series.get('revision')
            try:
                conn = b4.review.tracking.get_db(self._identifier)
                b4.review.tracking.update_series_status(conn, change_id, 'taken',
                                                        revision=revision)
                conn.close()
            except Exception as ex:
                logger.warning('Could not update series status: %s', ex)
        # Update Patchwork state if series was tracked from Patchwork
        if self._selected_series:
            pw_sid = self._selected_series.get('pw_series_id')
            if pw_sid:
                b4.review.pw_update_series_state(pw_sid, 'accepted')
        _wait_for_enter()

    def action_rebase(self) -> None:
        """Rebase the review branch on top of current HEAD."""
        if not self._selected_series:
            return
        status = self._selected_series.get('status', 'new')
        if status not in ('reviewing', 'replied'):
            self.notify('Series must be checked out before rebasing', severity='warning')
            return

        change_id = self._selected_series.get('change_id', '')
        review_branch = f'b4/review/{change_id}'

        # Get current branch name for confirmation dialog
        current_branch = self._original_branch or 'HEAD'

        self.push_screen(
            RebaseConfirmScreen(current_branch, review_branch),
            callback=lambda confirmed: self._on_rebase_confirmed(confirmed, review_branch),
        )

    def _on_rebase_confirmed(self, confirmed: bool, review_branch: str) -> None:
        """Handle rebase confirmation result."""
        if not confirmed:
            return

        # Run rebase in suspended mode to show output
        with self.suspend():
            self._do_rebase(review_branch)

    def _do_rebase(self, review_branch: str) -> None:
        """Perform the actual rebase operation."""
        topdir = b4.git_get_toplevel()
        if not topdir:
            logger.critical('Not in a git repository')
            return

        # Load tracking data from the review branch
        try:
            cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
        except SystemExit:
            logger.critical('Could not load tracking data from %s', review_branch)
            _wait_for_enter()
            return

        series = tracking.get('series', {})
        base_commit = series.get('base-commit', '')

        # Get current HEAD
        ecode, out = b4.git_run_command(topdir, ['rev-parse', 'HEAD'])
        if ecode != 0:
            logger.critical('Could not resolve HEAD')
            _wait_for_enter()
            return
        current_head = out.strip()

        # Check if series is already based on current HEAD
        ecode, out = b4.git_run_command(topdir, ['rev-parse', base_commit])
        if ecode == 0 and out.strip() == current_head:
            # Base commit is already HEAD
            logger.info('Series is already based on current HEAD')
            _wait_for_enter()
            return

        # Get the range of commits in the review branch (excluding tracking commit)
        # The tracking commit is at the tip, so we need HEAD~1
        ecode, out = b4.git_run_command(topdir, ['rev-parse', f'{review_branch}~1'])
        if ecode != 0:
            logger.critical('Could not resolve review branch tip')
            _wait_for_enter()
            return
        series_tip = out.strip()

        # Check if series applies cleanly to current HEAD using sparse worktree
        logger.info('Testing if series applies cleanly to HEAD...')
        try:
            with b4.git_temp_worktree(topdir, current_head) as gwt:
                # Set up sparse checkout for minimal disk usage
                ecode, out = b4.git_run_command(gwt, ['sparse-checkout', 'set'], logstderr=True)
                if ecode != 0:
                    logger.warning('Could not set up sparse checkout: %s', out.strip())
                ecode, out = b4.git_run_command(gwt, ['checkout', '-f'], logstderr=True)
                if ecode != 0:
                    logger.warning('Could not checkout sparse worktree: %s', out.strip())

                # Try cherry-picking the commits
                gitargs = ['cherry-pick', f'{base_commit}..{series_tip}']
                ecode, out = b4.git_run_command(gwt, gitargs, logstderr=True)
                if ecode != 0:
                    logger.critical('Series does not apply cleanly to current HEAD')
                    logger.critical('Cherry-pick output:')
                    logger.critical(out.strip())
                    logger.critical('')
                    logger.critical('Please rebase manually')
                    _wait_for_enter()
                    return
                logger.info('Series applies cleanly')
        except Exception as ex:
            logger.critical('Error testing series applicability: %s', ex)
            _wait_for_enter()
            return

        # Perform the actual rebase
        logger.info('Rebasing %s onto HEAD...', review_branch)

        # First, checkout the review branch (at the tracking commit)
        ecode, out = b4.git_run_command(topdir, ['checkout', review_branch], logstderr=True)
        if ecode != 0:
            logger.critical('Could not checkout review branch: %s', out.strip())
            _wait_for_enter()
            return

        # Reset to before the tracking commit (now at series_tip)
        ecode, out = b4.git_run_command(topdir, ['reset', '--hard', 'HEAD~1'], logstderr=True)
        if ecode != 0:
            logger.critical('Could not reset to before tracking commit: %s', out.strip())
            _wait_for_enter()
            return

        # Rebase the patches onto current_head
        # --onto current_head base_commit means: take commits after base_commit and replay onto current_head
        ecode, out = b4.git_run_command(topdir, ['rebase', '--onto', current_head, base_commit], logstderr=True)
        if ecode != 0:
            logger.critical('Rebase failed: %s', out.strip())
            logger.critical('Aborting rebase...')
            b4.git_run_command(topdir, ['rebase', '--abort'], logstderr=True)
            # Try to restore the original branch state
            b4.git_run_command(topdir, ['checkout', review_branch], logstderr=True)
            _wait_for_enter()
            return

        # Update tracking data with new base commit
        series['base-commit'] = current_head

        # Enumerate new patch commit SHAs and update first-patch-commit
        ecode, out = b4.git_run_command(
            topdir, ['rev-list', '--reverse', f'{current_head}..HEAD'])
        if ecode == 0 and out.strip():
            new_shas = out.strip().splitlines()
            series['first-patch-commit'] = new_shas[0]
            # Re-anchor inline comments against rebased diffs
            patches = tracking.get('patches', [])
            b4.review.reanchor_patch_comments(topdir, new_shas, patches)

        tracking['series'] = series

        # Re-create the tracking commit
        commit_msg = cover_text + '\n\n' + b4.review.make_review_magic_json(tracking)
        ecode, out = b4.git_run_command(topdir, ['commit', '--allow-empty', '-F', '-'],
                                        stdin=commit_msg.encode(), logstderr=True)
        if ecode != 0:
            logger.critical('Could not create new tracking commit: %s', out.strip())
            _wait_for_enter()
            return

        logger.info('Successfully rebased %s onto %s', review_branch, current_head[:12])
        _wait_for_enter()

    def action_range_diff(self) -> None:
        """Show range-diff between the current review and another revision."""
        if not self._selected_series:
            return
        status = self._selected_series.get('status', 'new')
        if status not in ('reviewing', 'replied', 'waiting'):
            self.notify('Series must be checked out before range-diff', severity='warning')
            return

        change_id = self._selected_series.get('change_id', '')
        current_rev = self._selected_series.get('revision', 1)

        try:
            conn = b4.review.tracking.get_db(self._identifier)
            revisions = b4.review.tracking.get_revisions(conn, change_id)
            conn.close()
        except Exception as ex:
            self.notify(f'Could not load revisions: {ex}', severity='error')
            return

        others = [r for r in revisions if r['revision'] != current_rev]
        if not others:
            self.notify(_escape_markup('No other known revisions. Try [u]pdate.'), severity='warning')
            return

        self.push_screen(
            RangeDiffScreen(current_rev, revisions),
            callback=lambda chosen: self._on_range_diff_selected(chosen, change_id, current_rev),
        )

    def _on_range_diff_selected(self, chosen: Optional[int], change_id: str,
                                 current_rev: int) -> None:
        """Handle the revision chosen from the range-diff modal."""
        if chosen is None:
            return
        with self.suspend():
            self._do_range_diff(change_id, current_rev, chosen)

    def _do_range_diff(self, change_id: str, current_rev: int, other_rev: int) -> None:
        """Compute and display range-diff between two revisions."""
        topdir = b4.git_get_toplevel()
        if not topdir:
            logger.critical('Not in a git repository')
            _wait_for_enter()
            return

        # --- Resolve the current review branch range ---
        branch = f'b4/review/{change_id}'
        try:
            cover_text, tracking = b4.review.load_tracking(topdir, branch)
        except SystemExit:
            logger.critical('Could not load tracking data from %s', branch)
            _wait_for_enter()
            return

        t_series = tracking.get('series', {})
        first_patch = t_series.get('first-patch-commit', '')
        if first_patch:
            cur_start = f'{first_patch}~1'
        else:
            cur_start = t_series.get('base-commit', '')
        cur_end = f'{branch}~1'

        if not cur_start:
            logger.critical('Cannot determine patch range for %s', branch)
            _wait_for_enter()
            return

        # --- Fetch the comparison version ---
        try:
            conn = b4.review.tracking.get_db(self._identifier)
            revisions = b4.review.tracking.get_revisions(conn, change_id)
            conn.close()
        except Exception as ex:
            logger.critical('Could not load revisions: %s', ex)
            _wait_for_enter()
            return

        other_msgid = ''
        for r in revisions:
            if r['revision'] == other_rev:
                other_msgid = r.get('message_id', '')
                break

        if not other_msgid:
            logger.critical('No message-id recorded for v%d', other_rev)
            _wait_for_enter()
            return

        logger.info('Fetching v%d from lore...', other_rev)
        msgs = b4.get_pi_thread_by_msgid(other_msgid)
        if not msgs:
            logger.critical('Could not retrieve thread for v%d', other_rev)
            _wait_for_enter()
            return

        msgs = b4.mbox.get_extra_series(msgs, direction=1, wantvers=[other_rev])
        if current_rev != other_rev:
            msgs = b4.mbox.get_extra_series(msgs, direction=-1, wantvers=[other_rev])

        lmbx = b4.LoreMailbox()
        for msg in msgs:
            lmbx.add_message(msg)

        lser = lmbx.get_series(other_rev, sloppytrailers=False,
                               codereview_trailers=False)
        if lser is None:
            logger.critical('Could not find series v%d in retrieved messages', other_rev)
            _wait_for_enter()
            return

        logger.info('Preparing fake-am range for v%d...', other_rev)
        other_start, other_end = lser.make_fake_am_range(gitdir=topdir)
        if other_start is None or other_end is None:
            logger.critical('Could not create fake-am range for v%d', other_rev)
            _wait_for_enter()
            return

        # --- Order sides: older on left, newer on right ---
        if other_rev < current_rev:
            left_start, left_end = other_start, other_end
            right_start, right_end = cur_start, cur_end
        else:
            left_start, left_end = cur_start, cur_end
            right_start, right_end = other_start, other_end

        # --- Run git range-diff ---
        logger.info('Running range-diff...')
        gitargs = ['range-diff', '--color',
                    f'{left_start}..{left_end}',
                    f'{right_start}..{right_end}']
        ecode, out = b4.git_run_command(topdir, gitargs)
        if ecode != 0:
            logger.critical('git range-diff failed (exit %d)', ecode)
            if out.strip():
                logger.critical(out.strip())
            _wait_for_enter()
            return

        if not out.strip():
            logger.info('No differences found between v%d and v%d',
                        min(other_rev, current_rev), max(other_rev, current_rev))
            _wait_for_enter()
            return

        b4.view_in_pager(out.encode(), filehint='range-diff.txt')

    def action_abandon(self) -> None:
        """Abandon the selected series."""
        if not self._selected_series:
            return
        change_id = self._selected_series.get('change_id', '')
        revision = self._selected_series.get('revision')
        review_branch = f'b4/review/{change_id}'
        has_branch = b4.git_branch_exists(None, review_branch)
        self.push_screen(
            AbandonConfirmScreen(change_id, review_branch, has_branch),
            callback=lambda confirmed: self._on_abandon_confirmed(
                confirmed, change_id, review_branch, has_branch,
                revision=revision),
        )

    def _on_abandon_confirmed(self, confirmed: bool, change_id: str,
                               review_branch: str, has_branch: bool,
                               revision: Optional[int] = None) -> None:
        if not confirmed:
            return
        topdir = b4.git_get_toplevel()
        if not topdir:
            self.notify('Not in a git repository', severity='error')
            return
        # Delete the review branch if it exists
        if has_branch:
            # If currently on that branch, switch away first
            ecode, out = b4.git_run_command(
                topdir, ['symbolic-ref', '--short', 'HEAD'])
            if ecode == 0 and out.strip() == review_branch:
                ecode, out = b4.git_run_command(
                    topdir, ['rev-parse', f'{review_branch}~1'],
                    logstderr=True)
                if ecode > 0:
                    self.notify('Could not determine parent commit',
                                severity='error')
                    return
                parent = out.strip()
                ecode, out = b4.git_run_command(
                    topdir, ['checkout', parent], logstderr=True)
                if ecode > 0:
                    self.notify(f'Could not switch away from {review_branch}',
                                severity='error')
                    return
            ecode, out = b4.git_run_command(
                topdir, ['branch', '-D', review_branch], logstderr=True)
            if ecode > 0:
                self.notify(f'Failed to delete branch {review_branch}',
                            severity='error')
                return
        # Delete from tracking database
        try:
            conn = b4.review.tracking.get_db(self._identifier)
            b4.review.tracking.delete_series(conn, change_id, revision=revision)
            conn.close()
        except Exception as ex:
            self.notify(f'DB error: {ex}', severity='error')
            return
        self.notify(f'Abandoned {change_id}')
        self._selected_series = None
        panel = self.query_one('#details-panel', Vertical)
        panel.styles.height = 0
        self._load_series()

    def action_update_revision(self) -> None:
        """Upgrade the review branch to a newer revision of the series."""
        if not self._selected_series:
            return
        status = self._selected_series.get('status', 'new')
        if status != 'reviewing':
            self.notify('Series must be checked out before upgrading',
                        severity='warning')
            return

        change_id = self._selected_series.get('change_id', '')
        current_rev = self._selected_series.get('revision', 1)
        review_branch = f'b4/review/{change_id}'

        # Discover newer revisions from tracking data and DB
        newer_versions: List[int] = []
        topdir = b4.git_get_toplevel()
        if topdir:
            try:
                _ct, trk = b4.review.load_tracking(topdir, review_branch)
                newer_versions = trk.get('series', {}).get('newer-versions', [])
            except SystemExit:
                pass
        if not newer_versions and self._identifier and change_id:
            try:
                conn = b4.review.tracking.get_db(self._identifier)
                newest = b4.review.tracking.get_newest_revision(conn, change_id)
                conn.close()
                if newest is not None and newest > current_rev:
                    newer_versions = list(range(current_rev + 1, newest + 1))
            except Exception:
                pass

        if not newer_versions:
            self.notify(
                _escape_markup('No newer revisions known. Try [u]pdate first.'),
                severity='warning')
            return

        # Look up revision metadata from the DB
        try:
            conn = b4.review.tracking.get_db(self._identifier)
            revisions = b4.review.tracking.get_revisions(conn, change_id)
            conn.close()
        except Exception as ex:
            self.notify(f'Could not load revisions: {ex}', severity='error')
            return

        newer_revs = [r for r in revisions if r['revision'] in newer_versions]
        if not newer_revs:
            self.notify(
                _escape_markup('No newer revisions known. Try [u]pdate first.'),
                severity='warning')
            return

        if len(newer_revs) == 1:
            # Only one newer revision — go straight to the upgrade
            self._do_update_revision(change_id, current_rev,
                                     newer_revs[0]['revision'])
            return

        self.push_screen(
            UpdateRevisionScreen(current_rev, revisions),
            callback=lambda chosen: (
                self._do_update_revision(change_id, current_rev, chosen)
                if chosen is not None else None
            ),
        )

    def _do_update_revision(self, change_id: str, current_rev: int,
                            target_rev: int) -> None:
        """Upgrade the review branch from *current_rev* to *target_rev*.

        Saves maintainer reviews keyed by patch-id, archives the old
        branch, checks out the new revision, then restores reviews onto
        patches whose patch-id matches.
        """
        import io

        review_branch = f'b4/review/{change_id}'

        with self.suspend():
            topdir = b4.git_get_toplevel()
            if not topdir:
                logger.critical('Not in a git repository')
                _wait_for_enter()
                return

            # --- 1. Save maintainer review data keyed by patch-id ---
            logger.info('Saving review data from v%d...', current_rev)
            patch_ids = b4.review.get_review_branch_patch_ids(topdir, review_branch)
            cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
            patches = tracking.get('patches', [])

            saved_reviews: Dict[str, Dict[str, Any]] = {}
            for idx, _sha, patch_id in patch_ids:
                if patch_id is None or idx >= len(patches):
                    continue
                reviews = patches[idx].get('reviews')
                if reviews:
                    saved_reviews[patch_id] = {
                        'reviews': reviews,
                    }

            logger.info('Saved review data for %d patch(es)', len(saved_reviews))

            # --- 2. Archive the old revision ---
            logger.info('Archiving v%d...', current_rev)
            pw_series_id = None
            if self._selected_series:
                pw_series_id = self._selected_series.get('pw_series_id')
            if not self._archive_branch(change_id, current_rev, review_branch,
                                        pw_series_id=pw_series_id, notify=False):
                logger.critical('Failed to archive v%d', current_rev)
                _wait_for_enter()
                return

            # --- 3. Fetch and create new review branch ---
            logger.info('Fetching v%d...', target_rev)

            # Look up message-id for the target revision
            try:
                conn = b4.review.tracking.get_db(self._identifier)
                revisions = b4.review.tracking.get_revisions(conn, change_id)
                conn.close()
            except Exception as ex:
                logger.critical('Could not load revisions: %s', ex)
                _wait_for_enter()
                return

            target_msgid = ''
            target_subject = ''
            for r in revisions:
                if r['revision'] == target_rev:
                    target_msgid = r.get('message_id', '')
                    target_subject = r.get('subject', '')
                    break

            if not target_msgid:
                logger.critical('No message-id recorded for v%d', target_rev)
                _wait_for_enter()
                return

            try:
                msgs = b4.review._retrieve_messages(target_msgid)
                lser = b4.review._get_lore_series(msgs)
            except LookupError as ex:
                logger.critical('%s', ex)
                _wait_for_enter()
                return
            except Exception as ex:
                logger.critical('Error retrieving series: %s', ex)
                _wait_for_enter()
                return

            # Get am-ready messages
            am_msgs = lser.get_am_ready(noaddtrailers=True, addmysob=False,
                                        addlink=False, cherrypick=None,
                                        copyccs=False, allowbadchars=False,
                                        showchecks=False)
            if not am_msgs:
                logger.critical('No patches ready for applying')
                _wait_for_enter()
                return

            top_msgid = None
            first_body = None
            for lmsg in lser.patches:
                if lmsg is not None:
                    first_body = lmsg.body
                    top_msgid = lmsg.msgid
                    break

            if top_msgid is None or first_body is None:
                logger.critical('Could not find any patches in the series')
                _wait_for_enter()
                return

            # Determine base commit
            base_commit = lser.base_commit
            need_guess = False

            if base_commit:
                if not b4.git_commit_exists(topdir, base_commit):
                    logger.warning(
                        'Base commit %s not found, will try to guess',
                        base_commit)
                    need_guess = True
            else:
                need_guess = True

            if need_guess:
                logger.info('Guessing base commit...')
                try:
                    base_commit, nblobs, mismatches = lser.find_base(
                        topdir, branches=None, maxdays=30)
                    if mismatches == 0:
                        logger.info('Base: %s (exact match)', base_commit)
                    elif nblobs == mismatches:
                        logger.warning('Base: failed to find matching base')
                        base_commit = None
                    else:
                        logger.info(
                            'Base: %s (best guess, %s/%s blobs matched)',
                            base_commit, nblobs - mismatches, nblobs)
                except IndexError as ex:
                    logger.warning('Base: failed to guess (%s)', ex)
                    base_commit = None

            if not base_commit:
                logger.critical('Could not determine base commit')
                _wait_for_enter()
                return

            # Build mbox for git-am
            ifh = io.BytesIO()
            b4.save_git_am_mbox(am_msgs, ifh)
            ambytes = ifh.getvalue()

            config = b4.get_main_config()
            linkmask = str(config.get('linkmask', 'https://lore.kernel.org/r/%s'))
            if '%s' not in linkmask:
                logger.critical('linkmask not configured properly')
                _wait_for_enter()
                return
            linkurl = linkmask % top_msgid

            try:
                logger.info('Base: %s', base_commit)
                b4.git_fetch_am_into_repo(topdir, ambytes=ambytes,
                                          at_base=base_commit, origin=linkurl)
                b4.review.create_review_branch(topdir, review_branch,
                                               base_commit, lser, linkurl,
                                               linkmask, num_prereqs=0)
                logger.info('Review branch created: %s', review_branch)
            except Exception as ex:
                logger.critical('Error creating review branch: %s', ex)
                _wait_for_enter()
                return

            # Ensure target revision is tracked in the DB
            if self._identifier:
                try:
                    conn = b4.review.tracking.get_db(self._identifier)
                    sender_name = getattr(lser, 'fromname', '') or ''
                    sender_email = getattr(lser, 'fromemail', '') or ''
                    sent_at = ''
                    ref_msg = None
                    for p in lser.patches:
                        if p is not None:
                            ref_msg = p
                            break
                    if ref_msg and ref_msg.date:
                        sent_at = ref_msg.date.isoformat()
                    b4.review.tracking.add_series_to_db(
                        conn, change_id, target_rev,
                        target_subject, sender_name, sender_email,
                        sent_at, target_msgid,
                        lser.expected or len(am_msgs))
                    b4.review.tracking.update_series_status(
                        conn, change_id, 'reviewing', revision=target_rev)
                    conn.close()
                except Exception as ex:
                    logger.warning('Failed to update DB for v%d: %s',
                                   target_rev, ex)

            # --- 4. Restore maintainer review data ---
            logger.info('Restoring reviews...')
            new_patch_ids = b4.review.get_review_branch_patch_ids(
                topdir, review_branch)
            new_cover_text, new_tracking = b4.review.load_tracking(
                topdir, review_branch)
            new_patches = new_tracking.get('patches', [])

            restored = 0
            for idx, _sha, patch_id in new_patch_ids:
                if patch_id is None or idx >= len(new_patches):
                    continue
                if patch_id in saved_reviews:
                    new_patches[idx]['reviews'] = saved_reviews[patch_id]['reviews']
                    restored += 1

            # Re-anchor inline comments against new revision diffs
            new_shas = [sha for _idx, sha, _pid in new_patch_ids]
            b4.review.reanchor_patch_comments(topdir, new_shas, new_patches)

            b4.review.save_tracking_ref(topdir, review_branch,
                                        new_cover_text, new_tracking)
            logger.info('Restored reviews for %d of %d patch(es)',
                        restored, len(new_patch_ids))
            logger.info('Upgrade to v%d complete', target_rev)
            _wait_for_enter()

        # Exit to review mode on the updated branch
        self.exit(review_branch)

    def action_waiting(self) -> None:
        """Put the selected series into waiting state."""
        if not self._selected_series:
            return
        status = self._selected_series.get('status', 'new')
        if status not in ('reviewing', 'replied'):
            return
        change_id = self._selected_series.get('change_id', '')
        revision = self._selected_series.get('revision')
        try:
            conn = b4.review.tracking.get_db(self._identifier)
            b4.review.tracking.update_series_status(
                conn, change_id, 'waiting', revision=revision)
            conn.close()
        except Exception as ex:
            self.notify(f'Error: {ex}', severity='error')
            return
        self.notify('Series moved to waiting')
        self._load_series()

    def action_archive(self) -> None:
        """Archive a taken/thanked series."""
        if not self._selected_series:
            return
        change_id = self._selected_series.get('change_id', '')
        revision = self._selected_series.get('revision')
        pw_series_id = self._selected_series.get('pw_series_id')
        review_branch = f'b4/review/{change_id}'
        has_branch = b4.git_branch_exists(None, review_branch)
        self.push_screen(
            ArchiveConfirmScreen(change_id, review_branch, has_branch),
            callback=lambda confirmed: self._on_archive_confirmed(
                confirmed, change_id, review_branch, has_branch, pw_series_id,
                revision=revision),
        )

    def _archive_branch(self, change_id: str, revision: Optional[int],
                        review_branch: str, pw_series_id: Optional[int] = None,
                        notify: bool = True) -> bool:
        """Archive a review branch and update the tracking database.

        Creates a tar.gz archive of the cover letter, tracking metadata,
        and patches, then deletes the branch and marks the series as
        archived.  Returns True on success.

        When *notify* is False, TUI notifications are suppressed (useful
        when called from within ``suspend()``).
        """
        import io
        import tarfile
        import time
        import b4.ez

        topdir = b4.git_get_toplevel()
        if not topdir:
            if notify:
                self.notify('Not in a git repository', severity='error')
            return False

        tio = io.BytesIO()
        mnow = int(time.time())
        tarpath = ''

        has_branch = b4.git_branch_exists(None, review_branch)
        if has_branch:
            # Load tracking data from the review branch
            cover_text, tracking = b4.review.load_tracking(topdir, review_branch)

            # Get patch range from tracking
            series_info = tracking.get('series', {})
            first_patch = series_info.get('first-patch-commit', '')
            if not first_patch:
                if notify:
                    self.notify('No patch commits found in tracking data',
                                severity='error')
                return False

            with tarfile.open(fileobj=tio, mode='w:gz') as tfh:
                # Add cover letter
                ifh = io.BytesIO()
                ifh.write(cover_text.encode())
                b4.ez.write_to_tar(tfh, f'{change_id}/cover.txt', mnow, ifh)
                ifh.close()
                # Add tracking metadata
                ifh = io.BytesIO()
                ifh.write(b4.review.make_review_magic_json(tracking).encode())
                b4.ez.write_to_tar(tfh, f'{change_id}/tracking.js', mnow, ifh)
                ifh.close()
                # Add patches as mbox
                patches = b4.git_range_to_patches(
                    None, f'{first_patch}~1', f'{review_branch}~1')
                if patches:
                    ifh = io.BytesIO()
                    b4.save_git_am_mbox([patch[1] for patch in patches], ifh)
                    b4.ez.write_to_tar(
                        tfh, f'{change_id}/patches.mbx', mnow, ifh)
                    ifh.close()

            # Write archive to data directory
            datadir = b4.get_data_dir()
            archpath = os.path.join(datadir, 'review-archived')
            pathlib.Path(archpath).mkdir(parents=True, exist_ok=True)
            tarpath = os.path.join(archpath, f'{change_id}.tar.gz')
            with open(tarpath, mode='wb') as tout:
                tout.write(tio.getvalue())

            # Delete the review branch
            ecode, out = b4.git_run_command(
                topdir, ['symbolic-ref', '--short', 'HEAD'])
            if ecode == 0 and out.strip() == review_branch:
                ecode, out = b4.git_run_command(
                    topdir, ['rev-parse', f'{review_branch}~1'],
                    logstderr=True)
                if ecode > 0:
                    if notify:
                        self.notify('Could not determine parent commit',
                                    severity='error')
                    return False
                parent = out.strip()
                ecode, out = b4.git_run_command(
                    topdir, ['checkout', parent], logstderr=True)
                if ecode > 0:
                    if notify:
                        self.notify(
                            f'Could not switch away from {review_branch}',
                            severity='error')
                    return False
            ecode, out = b4.git_run_command(
                topdir, ['branch', '-D', review_branch], logstderr=True)
            if ecode > 0:
                if notify:
                    self.notify(f'Failed to delete branch {review_branch}',
                                severity='error')
                return False

        # Update tracking database
        try:
            conn = b4.review.tracking.get_db(self._identifier)
            b4.review.tracking.update_series_status(conn, change_id, 'archived',
                                                    revision=revision)
            conn.close()
        except Exception as ex:
            if notify:
                self.notify(f'DB error: {ex}', severity='error')
            return False

        # Mark as archived in Patchwork
        if pw_series_id:
            b4.review.pw_update_series_state(pw_series_id, 'accepted', archived=True)

        if notify:
            if has_branch:
                self.notify(f'Archived {change_id} to {tarpath}')
            else:
                self.notify(f'Archived {change_id}')
        return True

    def _on_archive_confirmed(self, confirmed: bool, change_id: str,
                               review_branch: str, has_branch: bool,
                               pw_series_id: Optional[int] = None,
                               revision: Optional[int] = None) -> None:
        if not confirmed:
            return
        if self._archive_branch(change_id, revision, review_branch,
                                pw_series_id=pw_series_id):
            self._selected_series = None
            panel = self.query_one('#details-panel', Vertical)
            panel.styles.height = 0
            self._load_series()

    def action_thank(self) -> None:
        """Compose and preview a thank-you reply for a taken series."""
        import argparse
        import b4.review
        import b4.ty

        series = self._selected_series
        if not series:
            return
        if series.get('status', 'new') != 'taken':
            self.notify('Series must be taken before sending thanks', severity='warning')
            return

        change_id = series.get('change_id', '')
        review_branch = f'b4/review/{change_id}'
        topdir = b4.git_get_toplevel()
        if not topdir:
            self.notify('Not in a git repository', severity='error')
            return

        try:
            cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
        except SystemExit:
            self.notify('Could not load tracking data', severity='error')
            return

        trk_series = tracking.get('series', {})
        hi = trk_series.get('header-info', {})
        taken = trk_series.get('taken', {})
        target_branch = taken.get('branch', 'unknown')

        # Build per-patch tuples (subject, pwhash, msgid, prefix) and commits list
        trk_patches = tracking.get('patches', [])
        expected = trk_series.get('expected', len(trk_patches))
        padlen = len(str(expected)) if expected else 1
        patches_tuples: List[Tuple[str, str, str, str]] = []
        commits: List[Tuple[int, Optional[str]]] = []
        has_untaken = False
        for pi, pmeta in enumerate(trk_patches):
            title = pmeta.get('title', '')
            # Strip [PATCH ...] prefix to get the clean subject
            clean_subject = re.sub(r'^\[.*?]\s*', '', title)
            msgid = pmeta.get('header-info', {}).get('msgid', '')
            prefix = '%s/%s' % (str(pi + 1).zfill(padlen), expected)
            patches_tuples.append((clean_subject, '', msgid, prefix))
            patch_taken = pmeta.get('taken', {})
            cid = patch_taken.get('commit-id')
            if cid:
                commits.append((pi + 1, cid))
            else:
                commits.append((pi + 1, None))
                has_untaken = True

        # Assemble jsondata for ty.generate_am_thanks
        usercfg = b4.get_user_config()
        config = b4.get_main_config()
        jsondata: Dict[str, Any] = {
            'fromname': trk_series.get('fromname', ''),
            'fromemail': trk_series.get('fromemail', ''),
            'to': hi.get('to', ''),
            'cc': hi.get('cc', ''),
            'references': hi.get('references', ''),
            'msgid': hi.get('msgid', ''),
            'sentdate': hi.get('sentdate', ''),
            'subject': trk_series.get('subject', ''),
            'myname': config.get('thanks-from-name', usercfg.get('name', '')),
            'myemail': config.get('thanks-from-email', usercfg.get('email', '')),
            'signature': b4.get_email_signature(),
            'quote': b4.make_quote(cover_text),
            'patches': patches_tuples,
            'commits': commits,
            'cherrypick': has_untaken,
            'branch': target_branch,
        }

        # Build a minimal cmdargs for ty.generate_am_thanks / make_reply
        cmdargs = argparse.Namespace()
        cmdargs.metoo = False
        cmdargs.since = None

        try:
            msg = b4.ty.generate_am_thanks(topdir, jsondata, target_branch, cmdargs)
        except Exception as ex:
            self.notify(f'Failed to generate thank-you: {ex}', severity='error')
            return

        self._show_thank_preview(msg)

    def _show_thank_preview(self, msg: email.message.EmailMessage) -> None:
        """Push the ThankScreen modal and handle edit/send/cancel."""

        def _on_thank_result(result: Optional[str]) -> None:
            if result is None:
                return
            if result == '__EDIT__':
                self._edit_thank_message(msg)
            elif result == '__SEND__':
                self._send_thank_message(msg)

        self.push_screen(ThankScreen(msg), _on_thank_result)

    def _edit_thank_message(self, msg: email.message.EmailMessage) -> None:
        """Open the thank-you message in $EDITOR and re-show preview."""
        msg_bytes = msg.as_bytes(policy=b4.emlpolicy)
        try:
            with self.suspend():
                edited = b4.edit_in_editor(msg_bytes, filehint='thanks.eml')
        except Exception as ex:
            self.notify(f'Editor error: {ex}', severity='error')
            return
        new_msg = email.parser.BytesParser(policy=b4.emlpolicy).parsebytes(edited)
        self._show_thank_preview(new_msg)

    def _send_thank_message(self, msg: email.message.EmailMessage) -> None:
        """Send the thank-you message via SMTP."""
        series = self._selected_series
        if not series:
            return
        try:
            with self.suspend():
                smtp, fromaddr = b4.get_smtp(dryrun=self._email_dryrun)
                sent = b4.send_mail(smtp, [msg], fromaddr=fromaddr,
                                    patatt_sign=False, dryrun=self._email_dryrun,
                                    output_dir=None, reflect=False)
            if sent is None:
                self.notify('Failed to send thank-you message', severity='error')
                return
            # Update status to thanked
            change_id = series.get('change_id', '')
            revision = series.get('revision')
            if self._identifier and change_id:
                try:
                    conn = b4.review.tracking.get_db(self._identifier)
                    b4.review.tracking.update_series_status(conn, change_id, 'thanked',
                                                            revision=revision)
                    conn.close()
                except Exception as ex:
                    logger.warning('Could not update series status: %s', ex)
            self.notify('Thank-you message sent')
            self._load_series()
        except Exception as ex:
            self.notify(f'Send failed: {ex}', severity='error')

    #: Sentinel return value indicating the user wants to open PwApp.
    PATCHWORK_SENTINEL = '__patchwork__'

    def action_patchwork(self) -> None:
        """Exit to the outer loop so it can launch the Patchwork TUI."""
        if not (self._pwkey and self._pwurl and self._pwproj):
            self.notify('Patchwork not configured (need b4.pw-key, b4.pw-url, b4.pw-project)',
                        severity='error')
            return
        self.exit(self.PATCHWORK_SENTINEL)

    def action_suspend(self) -> None:
        """Suspend the TUI and drop to an interactive shell."""
        with self.suspend():
            _suspend_to_shell()

    def action_help(self) -> None:
        """Show keybinding help."""
        self.push_screen(HelpScreen(TRACKING_HELP_LINES))

    async def action_quit(self) -> None:
        self.exit()

