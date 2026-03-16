#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import datetime
import email.message
import email.parser
import email.policy
import email.utils
import io
import json
import os
import pathlib
import re
import sqlite3

from string import Template
from typing import Any, Dict, List, Literal, Optional, Tuple

import b4
import b4.mbox
import b4.review
import b4.review.tracking

from rich.text import Text as RichText
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import Footer, Label, ListItem, ListView, Static
from textual.worker import Worker, WorkerState
from b4.review_tui._common import (
    logger, resolve_styles, _wait_for_enter, _suspend_to_shell,
    SeparatedFooter, _quiet_worker, CheckRunnerMixin,
    _fix_ansi_theme, display_width, pad_display,
)
from b4.review_tui._modals import (
    BaseSelectionScreen, WorkerScreen, TakeScreen, TakeConfirmScreen,
    CherryPickScreen, NewerRevisionWarningScreen,
    RevisionChoiceScreen, RebaseScreen, TargetBranchScreen,
    AbandonConfirmScreen,
    ArchiveConfirmScreen, RangeDiffScreen, ThankScreen, QueueScreen, QueueDeliveryScreen,
    LimitScreen, UpdateRevisionScreen, UpdateAllScreen,
    ActionScreen, HelpScreen, SnoozeScreen, TRACKING_HELP_LINES,
)


# Single-character Unicode symbols for each series status.
_STATUS_SYMBOLS: Dict[str, str] = {
    'new':       '★',  # U+2605 black star
    'reviewing': '✎',  # U+270E lower right pencil (matches review app)
    'replied':   '↩',  # U+21A9 leftwards arrow with hook
    'waiting':   '↻',  # U+21BB clockwise open circle arrow
    'accepted':  '∈',  # U+2208 element of
    'snoozed':   '⏸',  # U+23F8 double vertical bar
    'thanked':   '✓',  # U+2713 check mark
    'gone':      'ø',  # U+00F8 latin small letter o with stroke
}

# Statuses where the maintainer can take action right now.
_ACTIONABLE_STATUSES: frozenset[str] = frozenset({
    'new', 'reviewing', 'replied', 'accepted', 'thanked',
})


def _resolve_worktree_am_conflict(topdir: str, cex: 'b4.AmConflictError') -> bool:
    """Handle an AmConflictError by dropping the user into a shell.

    Disables sparse checkout in the worktree, suspends to an interactive
    shell for conflict resolution, then checks the outcome:

    - If the user completed ``git am --continue``, fetches the result
      into FETCH_HEAD and removes the worktree.  Returns True.
    - If the user aborted (``git am --abort``) or exited without
      finishing, cleans up the worktree and returns False.
    """
    logger.critical('---')
    logger.critical(cex.output)
    logger.critical('---')
    logger.critical('Patch did not apply cleanly.')
    # Disable sparse checkout so user can see and edit files
    b4.git_run_command(cex.worktree_path, ['sparse-checkout', 'disable'],
                       logstderr=True, rundir=cex.worktree_path)
    # Save worktree HEAD before shell so we can detect abort
    _ecode, wt_head_before = b4.git_run_command(
        cex.worktree_path, ['rev-parse', 'HEAD'],
        logstderr=True, rundir=cex.worktree_path)
    wt_head_before = wt_head_before.strip()
    logger.info('You can resolve the conflict in the worktree.')
    logger.info('Use "git am --continue" after resolving, or "git am --abort" to give up.')
    _suspend_to_shell(hint='b4 conflict', cwd=cex.worktree_path)
    # Check if am is still in progress (user exited without finishing)
    ecode, wt_gitdir = b4.git_run_command(
        cex.worktree_path, ['rev-parse', '--git-dir'],
        logstderr=True, rundir=cex.worktree_path)
    if ecode == 0:
        rebase_apply = os.path.join(wt_gitdir.strip(), 'rebase-apply')
    else:
        rebase_apply = ''
    if rebase_apply and os.path.isdir(rebase_apply):
        logger.warning('Conflict resolution incomplete, aborting')
        b4.git_run_command(topdir, ['worktree', 'remove', '--force', cex.worktree_path])
        return False
    # Check if am was aborted (HEAD unchanged from before shell)
    _ecode, wt_head_after = b4.git_run_command(
        cex.worktree_path, ['rev-parse', 'HEAD'],
        logstderr=True, rundir=cex.worktree_path)
    if wt_head_after.strip() == wt_head_before:
        logger.warning('Conflict resolution aborted')
        b4.git_run_command(topdir, ['worktree', 'remove', '--force', cex.worktree_path])
        return False
    # am completed -- fetch result into FETCH_HEAD
    logger.info('Conflict resolved, fetching result...')
    ecode, _out = b4.git_run_command(topdir, ['fetch', cex.worktree_path], logstderr=True)
    b4.git_run_command(topdir, ['worktree', 'remove', '--force', cex.worktree_path])
    if ecode > 0:
        logger.critical('Unable to fetch from resolved worktree')
        return False
    return True


def _format_snooze_until(value: str) -> str:
    """Format a snoozed_until value for display.

    If *value* starts with ``tag:`` return ``until tag <tagname>``.
    If *value* contains ``T`` (a full ISO datetime), show a relative
    duration like "in 2h 30m" plus the local date/time.  Otherwise
    return the value as-is (backward compat for date-only strings).
    """
    if value.startswith('tag:'):
        return f'until tag {value[4:]}'
    if 'T' not in value:
        return f'until {value}'
    try:
        target = datetime.datetime.fromisoformat(value)
        if target.tzinfo is None:
            target = target.replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        delta = target - now
        total_seconds = int(delta.total_seconds())
        if total_seconds <= 0:
            return 'expired'
        parts: List[str] = []
        days = total_seconds // 86400
        remaining = total_seconds % 86400
        hours = remaining // 3600
        remaining %= 3600
        minutes = remaining // 60
        if days:
            parts.append(f'{days}d')
        if hours:
            parts.append(f'{hours}h')
        if minutes:
            parts.append(f'{minutes}m')
        relative = ' '.join(parts) if parts else '<1m'
        local_dt = target.astimezone()
        local_str = local_dt.strftime('%Y-%m-%d %H:%M')
        return f'wakes in {relative} ({local_str})'
    except (ValueError, TypeError):
        return value


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


def _format_attestation(att: str, app: Any = None) -> Optional[RichText]:
    """Format an attestation DB value into a Rich text snippet.

    Returns None when there is nothing to display (e.g. 'pending', 'none').
    """
    entries = att.split(';') if att and att not in ('pending', 'none') else []
    if not entries:
        return None
    # resolve_styles needs the app; fall back to plain colours if unavailable
    if app is not None:
        ts = resolve_styles(app)
    else:
        ts = {'success': 'green', 'error': 'red', 'warning': 'dark_orange'}
    text = RichText()
    for i, entry in enumerate(entries):
        if i > 0:
            text.append(', ')
        status, identity = entry.split(':', 1) if ':' in entry else (entry, '')
        if status == 'signed':
            text.append(f'\u2714 {identity}', style=ts['success'])
        elif status == 'nokey':
            text.append(f'? {identity}', style=ts['warning'])
            text.append(' (no key)', style='dim')
        elif status == 'badsig':
            text.append(f'\u2718 {identity}', style=ts['error'])
            text.append(' (signature failed)', style='dim')
        else:
            text.append(entry)
    return text


class TrackedSeriesItem(ListItem):
    """A single tracked series entry in the listing."""

    DEFAULT_CSS = """
    TrackedSeriesItem.non-actionable Label {
        text-style: dim;
    }
    TrackedSeriesItem.gone Label {
        text-style: dim italic;
    }
    """

    def __init__(self, series: Dict[str, Any]) -> None:
        super().__init__()
        self.series = series
        status = series.get('status', 'new')
        if status not in _ACTIONABLE_STATUSES:
            self.add_class('non-actionable')
        if status == 'gone':
            self.add_class('gone')

    def compose(self) -> ComposeResult:
        subject = self.series.get('subject', '(no subject)')
        submitter = self.series.get('sender_name', 'Unknown')
        revision = self.series.get('revision', 1)
        num_patches = self.series.get('num_patches', 0)
        status = self.series.get('status', 'new')
        symbol = _STATUS_SYMBOLS.get(status, '?')
        flag = '*' if self.series.get('needs_update') else ' '
        art = self.series.get('art')
        if art:
            a, r, t = art
            art_str = f'{a}·{r}·{t}'
        else:
            art_str = '-'
        fc = self.series.get('message_count')
        sc = self.series.get('seen_message_count')
        if fc is not None:
            delta = (fc - sc) if (sc is not None and fc > sc) else 0
        else:
            delta = 0
        # Msgs display: "1" (all seen), "6" accent (all new), "6(3)" mixed
        if fc is None:
            fu_base = '-'
            fu_badge = ''
            base_accent = False
        elif fc == 0:
            fu_base = '0'
            fu_badge = ''
            base_accent = False
        elif delta == fc:
            # All follow-ups are new
            fu_base = str(fc)
            fu_badge = ''
            base_accent = True
        elif delta > 0:
            # Mixed: total + (unseen)
            fu_base = str(fc)
            fu_badge = f'({delta})'
            base_accent = False
        else:
            # All seen
            fu_base = str(fc)
            fu_badge = ''
            base_accent = False
        # Build compact prefix using LoreSubject to extract subsystem/modifier tokens
        ls = b4.LoreSubject(subject)
        extras = ls.get_extra_prefixes(exclude=['patch'])
        width = len(str(num_patches)) if num_patches > 0 else 1
        parts = extras + [f'v{revision}', f'{"0" * width}/{num_patches:0{width}d}']
        subject_display = f'[{",".join(parts)}] {ls.subject}'
        if display_width(submitter) > 20:
            while display_width(submitter) > 19:
                submitter = submitter[:-1]
            submitter += '…'
        submitter = pad_display(submitter, 20)
        att = self.series.get('attestation') or ''
        att_entries = att.split(';') if att and att not in ('pending', 'none') else []
        label = RichText(no_wrap=True, overflow='ellipsis')
        label.append(submitter)
        if att_entries and all(e.startswith('signed:') for e in att_entries):
            ts = resolve_styles(self.app)
            label.append('\u2714', style=ts['success'])  # ✔
        else:
            label.append(' ')
        label.append(' ')
        label.append(art_str.rjust(7))
        base_style = ''
        badge_style = ''
        if base_accent or fu_badge:
            ts = resolve_styles(self.app)
            accent = f"bold {ts['warning']}"
            if base_accent:
                base_style = accent
            if fu_badge:
                badge_style = accent
        label.append(f'  {fu_base.rjust(3)}', style=base_style)
        label.append(f'{fu_badge:<3s}', style=badge_style)
        label.append(f'  {symbol}{flag}  {subject_display}')
        yield Label(label, markup=False)


class TrackingApp(CheckRunnerMixin, App[Optional[str]]):
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
        background: $primary-darken-2;
        color: $text;
        text-style: bold;
    }
    #title-left {
        width: 1fr;
        content-align: left middle;
    }
    #title-right {
        width: auto;
        content-align: right middle;
        padding: 0 1;
    }
    #tracking-header {
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
        width: 13;
    }
    .details-row {
        height: 1;
    }
    #detail-revisions.has-upgrade {
        color: ansi_bright_yellow;
        text-style: bold;
    }
    TrackingApp:ansi #tracking-title {
        background: ansi_bright_black;
        color: ansi_default;
        text-style: bold;
    }
    TrackingApp:ansi #title-left {
        background: ansi_bright_black;
        color: ansi_default;
        text-style: bold;
    }
    TrackingApp:ansi #title-right {
        background: ansi_bright_black;
        color: ansi_default;
        text-style: bold;
    }
    TrackingApp:ansi #tracking-header {
        background: ansi_default;
        color: ansi_default;
        text-style: dim;
    }
    TrackingApp:ansi #details-panel {
        background: ansi_default;
        border-top: solid ansi_default;
    }
    TrackingApp:ansi .details-label {
        color: ansi_default;
        text-style: dim;
    }
    """

    BINDING_GROUPS = {
        'review': 'Series', 'check': 'Series', 'thread': 'Series',
        'range_diff': 'Series', 'action': 'Series', 'update_one': 'Series',
        'target_branch': 'Series',
        'update_all': 'App', 'process_queue': 'App', 'limit': 'App',
        'suspend': 'App', 'patchwork': 'App', 'quit': 'App', 'help': 'App',
    }

    BINDINGS = [
        # Hidden navigation bindings
        Binding('j', 'cursor_down', 'Down', show=False),
        Binding('k', 'cursor_up', 'Up', show=False),
        Binding('escape', 'hide_details', 'Close', show=False),
        # Series-specific actions
        Binding('r', 'review', 'review'),
        Binding('t', 'target_branch', 'target'),
        Binding('c', 'check', 'ci'),
        Binding('e', 'thread', 'thread'),
        Binding('a', 'action', 'action'),
        Binding('u', 'update_one', 'update'),
        Binding('d', 'range_diff', 'range-diff'),
        # App-global actions
        Binding('l', 'limit', 'limit'),
        Binding('s', 'suspend', 'shell'),
        Binding('p', 'patchwork', 'patchwork'),
        Binding('U', 'update_all', 'Update all', key_display='U'),
        Binding('Q', 'process_queue', 'Queue', key_display='Q'),
        Binding('q', 'quit', 'quit'),
        Binding('question_mark', 'help', 'help', key_display='?'),
    ]

    def __init__(self, identifier: str, original_branch: Optional[str] = None,
                 focus_change_id: Optional[str] = None,
                 email_dryrun: bool = False,
                 patatt_sign: bool = True) -> None:
        super().__init__()
        self._identifier = identifier
        self._original_branch = original_branch
        self._focus_change_id = focus_change_id
        self._email_dryrun = email_dryrun
        self._patatt_sign = patatt_sign
        self._all_series: List[Dict[str, Any]] = []
        self._selected_series: Optional[Dict[str, Any]] = None
        self._limit_pattern: str = ''
        self._db_mtime: float = 0.0
        # Detect patchwork configuration
        config = b4.get_main_config()
        self._pwkey = str(config.get('pw-key', ''))
        self._pwurl = str(config.get('pw-url', ''))
        self._pwproj = str(config.get('pw-project', ''))
        # Remember last snooze choices within the session
        self._last_snooze_source: str = ''
        self._last_snooze_input: str = ''
        # CI check modal state
        self._check_loading: Optional[Any] = None
        # Thanks queue count
        self._queue_count: int = 0
        # Show target branch binding only when configured
        self._has_target_branches = bool(
            b4.review.tracking.get_review_target_branches())

    def _refresh_msg_count(self, series: Dict[str, Any],
                           total_messages: int) -> None:
        """Opportunistically refresh message count after fetching messages."""
        if not self._identifier:
            return
        b4.review.tracking.refresh_message_count(
            self._identifier,
            series.get('change_id', ''),
            series.get('revision', 1),
            total_messages,
        )

    def compose(self) -> ComposeResult:
        title = f' Tracked Series — {self._identifier}'
        if self._email_dryrun:
            title += ' (DRY-RUN)'
        with Horizontal(id='tracking-title'):
            yield Static(title, id='title-left')
            yield Static('', id='title-right')
        with Vertical(id='details-panel'):
            with Horizontal(classes='details-row'):
                yield Static('Subject:', classes='details-label')
                yield Static('', id='detail-subject', markup=False)
            with Horizontal(classes='details-row'):
                yield Static('From:', classes='details-label')
                yield Static('', id='detail-from', markup=False)
            with Horizontal(classes='details-row', id='detail-attestation-row'):
                yield Static('Attestation:', classes='details-label')
                yield Static('', id='detail-attestation')
            with Horizontal(classes='details-row'):
                yield Static('Sent:', classes='details-label')
                yield Static('', id='detail-sent', markup=False)
            with Horizontal(classes='details-row'):
                yield Static('Status:', classes='details-label')
                yield Static('', id='detail-status', markup=False)
            with Horizontal(classes='details-row'):
                yield Static('Change-ID:', classes='details-label')
                yield Static('', id='detail-changeid', markup=False)
            with Horizontal(classes='details-row'):
                yield Static('Link:', classes='details-label')
                yield Static('', id='detail-link', markup=False)
            with Horizontal(classes='details-row', id='detail-revisions-row'):
                yield Static('Revisions:', classes='details-label')
                yield Static('', id='detail-revisions', markup=False)
            with Horizontal(classes='details-row', id='detail-branch-row'):
                yield Static('Branch:', classes='details-label')
                yield Static('', id='detail-branch', markup=False)
            with Horizontal(classes='details-row', id='detail-target-row'):
                yield Static('Target:', classes='details-label')
                yield Static('', id='detail-target', markup=False)
        yield SeparatedFooter()

    def on_mount(self) -> None:
        _fix_ansi_theme(self)
        self._refresh_queue_indicator()
        self._load_series()
        self.set_interval(1, self._check_db_changed)
        topdir = b4.git_get_toplevel()
        if topdir and b4.review.tracking.db_exists(self._identifier):
            self.run_worker(lambda: self._startup_rescan(topdir),
                            name='_startup_rescan', thread=True)

    def _startup_rescan(self, topdir: str) -> Dict[str, int]:
        """Rescan review branches in the background on app startup."""
        with _quiet_worker():
            return b4.review.tracking.rescan_branches(self._identifier, topdir)

    async def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.name != '_startup_rescan':
            return
        if event.state == WorkerState.SUCCESS:
            result = event.worker.result or {}
            gone = result.get('gone', 0)
            if gone:
                self.notify(f'{gone} review branch(es) are gone', severity='warning')
            # Only rebuild the list when something actually changed; the DB is
            # only written when a branch SHA differs, so _check_db_changed()
            # naturally stays quiet on a no-op rescan.
            if gone or result.get('changed', 0):
                self._load_series()

    @staticmethod
    def _restore_snoozed_tracking(topdir: str, review_branch: str) -> str:
        """Restore previous state from snoozed tracking commit metadata.

        Reads the snoozed dict from the tracking commit, restores the
        previous status, removes the snoozed key, and saves the commit.
        Returns the previous status (defaults to 'reviewing').
        """
        cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
        trk_series = tracking.get('series', {})
        snoozed_info = trk_series.get('snoozed', {})
        prev_status = str(snoozed_info.get('previous_state', 'reviewing'))
        trk_series['status'] = prev_status
        trk_series.pop('snoozed', None)
        tracking['series'] = trk_series
        b4.review.save_tracking_ref(topdir, review_branch, cover_text, tracking)
        return prev_status

    def _auto_wake_snoozed(self) -> None:
        """Auto-wake snoozed series whose wake-up condition has been met.

        Checks two conditions:
        - Time-based: the snoozed_until date has passed.
        - Tag-based: the target git tag now exists.

        For each woken series, restores the previous status in both
        the tracking commit and the database.
        """
        try:
            conn = b4.review.tracking.get_db(self._identifier)
        except (FileNotFoundError, Exception):
            return
        try:
            topdir = b4.git_get_toplevel()
            # Wake series whose snooze date has passed
            for entry in b4.review.tracking.get_expired_snoozed(conn):
                self._wake_one(conn, entry, topdir)
            # Wake series whose target tag now exists
            if topdir:
                for entry in b4.review.tracking.get_tag_snoozed(conn):
                    tagname = entry['snoozed_until'][4:]  # strip 'tag:' prefix
                    if b4.git_revparse_tag(topdir, tagname):
                        self._wake_one(conn, entry, topdir)
        finally:
            conn.close()

    def _wake_one(self, conn: 'sqlite3.Connection',
                  entry: Dict[str, Any],
                  topdir: Optional[str]) -> None:
        """Restore a single snoozed series to its previous state."""
        cid = entry['change_id']
        rev = entry['revision']
        prev_status = 'reviewing'
        review_branch = f'b4/review/{cid}'
        if topdir and b4.git_branch_exists(topdir, review_branch):
            try:
                prev_status = self._restore_snoozed_tracking(topdir, review_branch)
            except (SystemExit, Exception):
                pass
        b4.review.tracking.unsnooze_series(conn, cid, prev_status, revision=rev)

    def _load_series(self) -> None:
        self._auto_wake_snoozed()

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
        try:
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
                        if not revs and series.get('status') not in ('new', 'gone', 'snoozed'):
                            series['needs_update'] = True
                    except Exception:
                        pass
                # Load A/R/T trailer counts from the review branch
                if topdir and series.get('status') in ('reviewing', 'replied', 'waiting'):
                    branch_name = f'b4/review/{change_id}'
                    art = _get_art_counts(topdir, branch_name)
                    if art:
                        series['art'] = art
        finally:
            if conn:
                conn.close()
        # Sort: actionable series first, non-actionable at the bottom.
        # Within each group, sort by when the maintainer started tracking
        # (added_at descending) — newest-tracked at the top, like an inbox.
        self._all_series.sort(
            key=lambda s: s.get('added_at') or s.get('sent_at') or '',
            reverse=True,
        )
        self._all_series.sort(
            key=lambda s: 0 if s.get('status', 'new') in _ACTIONABLE_STATUSES else 1
        )
        self.call_later(self._refresh_list)

    def _check_db_changed(self) -> None:
        """Poll the database file mtime and reload if it changed."""
        # Skip while a modal is active — the DB may be changing (e.g. during
        # an update) and rebuilding the list behind the modal causes flickering.
        if len(self.app.screen_stack) > 1:
            return
        try:
            db_path = b4.review.tracking.get_db_path(self._identifier)
            mtime = os.path.getmtime(db_path)
        except OSError:
            return
        if mtime != self._db_mtime:
            self._load_series()

    @staticmethod
    def _matches_limit(series: Dict[str, Any], pattern: str) -> bool:
        """Test whether *series* matches the limit *pattern*.

        The pattern is split on whitespace.  Tokens starting with
        ``s:`` filter by status substring, ``t:`` by target-branch
        substring, and bare tokens by subject or sender name.  All
        tokens must match (AND logic).
        """
        for token in pattern.lower().split():
            if token.startswith('s:'):
                needle = token[2:]
                if needle not in (series.get('status', '') or '').lower():
                    return False
            elif token.startswith('t:'):
                needle = token[2:]
                if needle not in (series.get('target_branch', '') or '').lower():
                    return False
            else:
                if (token not in (series.get('subject', '') or '').lower()
                        and token not in (series.get('sender_name', '') or '').lower()):
                    return False
        return True

    async def _refresh_list(self) -> None:
        display_series = self._all_series
        if self._limit_pattern:
            display_series = [
                s for s in display_series
                if self._matches_limit(s, self._limit_pattern)
            ]

        left = self.query_one('#title-left', Static)
        title_text = f' Tracked Series — {self._identifier}'
        if self._email_dryrun:
            title_text += ' (DRY-RUN)'
        if self._limit_pattern:
            title_text += f' (limit: {self._limit_pattern})'
        left.update(title_text)

        # Suppress rendering while we swap old widgets for new ones.
        # Without this, the remove-then-mount sequence can produce a
        # single intermediate frame showing only the title bar before
        # the new list is mounted.
        with self.app.batch_update():
            # Remove existing list/empty widgets
            for widget in list(self.query('#tracking-header, #tracking-list, #tracking-empty')):
                await widget.remove()

            if not display_series:
                empty = Static('No tracked series. Use "b4 review track" to add series.', id='tracking-empty')
                await self.mount(empty, before=self.query_one(Footer))
                return

            header_text = f'{"Submitter":<20s}{"A":>1s} {"A·R·T":>7s}  {"Msgs":>6s}  {"S":<4s}{"Subject"}'
            header = Static(header_text, id='tracking-header')

            list_items: List[ListItem] = [TrackedSeriesItem(s) for s in display_series]
            lv = ListView(*list_items, id='tracking-list')
            await self.mount(header, before=self.query_one(Footer))
            await self.mount(lv, before=self.query_one(Footer))

        if self._focus_change_id:
            for idx, item in enumerate(list_items):
                if isinstance(item, TrackedSeriesItem) and item.series.get('change_id') == self._focus_change_id:
                    lv.index = idx
                    break
            self._focus_change_id = None
        lv.focus()

        # Populate the details panel for the highlighted item now that
        # the widget tree is stable.  The Highlighted event may have
        # fired during batch_update before #details-panel was queryable.
        highlighted = lv.highlighted_child
        if isinstance(highlighted, TrackedSeriesItem):
            self._show_details(highlighted.series)

    def action_limit(self) -> None:
        self.push_screen(LimitScreen(self._limit_pattern,
                                     hint='Prefixes: s:<status>  t:<target-branch>'),
                         callback=self._on_limit)

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
            if not self._selected_series:
                return
            status = self._selected_series.get('status', 'new')
            if status == 'reviewing':
                self.action_review()
            else:
                self.action_action()


    _STATE_ACTIONS: Dict[str, frozenset[str]] = {
        'new': frozenset({'review', 'range_diff', 'abandon', 'snooze', 'waiting', 'target_branch'}),
        'reviewing': frozenset({'review', 'update_revision', 'range_diff', 'take', 'rebase', 'abandon', 'waiting', 'snooze', 'target_branch'}),
        'replied': frozenset({'review', 'range_diff', 'take', 'rebase', 'archive', 'waiting', 'snooze', 'target_branch'}),
        'waiting': frozenset({'review', 'range_diff', 'abandon', 'archive', 'snooze', 'target_branch'}),
        'accepted': frozenset({'review', 'range_diff', 'thank', 'archive'}),
        'snoozed': frozenset({'review', 'range_diff', 'unsnooze', 'abandon', 'target_branch'}),
        'thanked': frozenset({'archive'}),
        'gone': frozenset({'abandon', 'review'}),
    }
    # All state-gated actions (union of all per-state sets)
    _GATED_ACTIONS = frozenset().union(*_STATE_ACTIONS.values())

    def check_action(self, action: str, parameters: Tuple[Any, ...]) -> Optional[bool]:
        """Hide status-specific actions based on the selected series."""
        if action == 'process_queue':
            return self._queue_count > 0
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
            if action == 'target_branch':
                return self._has_target_branches
            return True
        return True

    def action_action(self) -> None:
        """Open a modal with context-sensitive actions for the selected series."""
        if not self._selected_series:
            return
        status = self._selected_series.get('status', 'new')
        actions: list[tuple[str, str]] = []
        if status in ('new', 'gone'):
            actions.append(('review', 'Review'))
            if status == 'new' and self._selected_series.get('has_newer'):
                actions.append(('upgrade', 'Upgrade to newer revision'))
            actions.append(('abandon', 'Abandon series'))
            if status == 'new':
                actions.append(('waiting', 'Mark as waiting on new revision'))
                actions.append(('snooze', 'Snooze (defer until later)'))
        elif status == 'snoozed':
            actions.append(('unsnooze', 'Wake up (unsnooze)'))
            actions.append(('abandon', 'Abandon series'))
            actions.append(('archive', 'Archive series'))
        else:
            if status in ('reviewing', 'replied'):
                actions.append(('take', 'Take (apply to branch)'))
                actions.append(('rebase', 'Rebase review branch'))
                actions.append(('waiting', 'Mark as waiting on new revision'))
                actions.append(('snooze', 'Snooze (defer until later)'))
            if status == 'reviewing' and self._selected_series.get('has_newer'):
                actions.append(('upgrade', 'Upgrade to newer revision'))
            if status == 'waiting':
                actions.append(('review', 'Review'))
            if status == 'accepted':
                actions.append(('review', 'Return to reviewing'))
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
            'review': self.action_review,
            'take': self.action_take,
            'rebase': self.action_rebase,
            'abandon': self.action_abandon,
            'thank': self.action_thank,
            'upgrade': self.action_update_revision,
            'archive': self.action_archive,
            'waiting': self.action_waiting,
            'snooze': self.action_snooze,
            'unsnooze': self.action_unsnooze,
        }.get(action)
        if handler:
            handler()

    def action_review(self) -> None:
        if not self._selected_series:
            return
        status = self._selected_series.get('status', 'new')
        if status in ('reviewing', 'replied', 'waiting', 'accepted', 'snoozed'):
            # Already checked out - go to review mode
            change_id = self._selected_series.get('change_id', '')
            revision = self._selected_series.get('revision')
            branch_name = f'b4/review/{change_id}'
            try:
                conn = b4.review.tracking.get_db(self._identifier)
            except Exception:
                conn = None
            try:
                if status == 'snoozed':
                    # Unsnooze: clear snoozed_until + restore tracking commit
                    topdir = b4.git_get_toplevel()
                    if topdir and b4.git_branch_exists(topdir, branch_name):
                        try:
                            self._restore_snoozed_tracking(topdir, branch_name)
                        except (SystemExit, Exception):
                            pass
                    if conn:
                        b4.review.tracking.unsnooze_series(
                            conn, change_id, 'reviewing', revision=revision)
                elif status in ('waiting', 'accepted'):
                    # Bring back to reviewing on re-entry
                    if conn:
                        b4.review.tracking.update_series_status(
                            conn, change_id, 'reviewing', revision=revision)
                    topdir = b4.git_get_toplevel()
                    if topdir:
                        b4.review.update_tracking_status(topdir, branch_name, 'reviewing')
                # Clear the followup badge — user is about to read this series
                if conn and self._identifier and isinstance(revision, int):
                    b4.review.tracking.mark_all_messages_seen(conn, change_id, revision)
            except Exception:
                pass
            finally:
                if conn:
                    conn.close()
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

    def action_thread(self) -> None:
        """View a series thread in the lite thread viewer."""
        if not self._selected_series:
            return
        message_id = self._selected_series.get('message_id', '')
        if not message_id:
            self.notify('No message-id available for this series', severity='error')
            return
        tracking_info = None
        if self._identifier:
            tracking_info = {
                'identifier': self._identifier,
                'change_id': self._selected_series.get('change_id', ''),
                'revision': self._selected_series.get('revision', 1),
            }
        self._focus_change_id = self._selected_series.get('change_id')
        from b4.review_tui._lite_app import LiteThreadScreen
        self.push_screen(LiteThreadScreen(message_id,
                                          email_dryrun=self._email_dryrun,
                                          patatt_sign=self._patatt_sign,
                                          tracking_info=tracking_info))

    def _checkout_new_series(self) -> None:
        """Retrieve series, build am-ready mbox, and show base selection."""
        series = self._selected_series
        if not series:
            return

        message_id = series.get('message_id', '')
        if not message_id:
            self.notify('No message-id available for this series', severity='error')
            return

        def _fetch_and_prepare() -> Tuple[b4.LoreSeries, bytes, str, str]:
            with _quiet_worker():
                msgs = b4.review._retrieve_messages(message_id)
                self._refresh_msg_count(series, len(msgs))
                wantver = series.get('revision')
                lser = b4.review._get_lore_series(msgs, wantver=wantver)

                am_msgs = lser.get_am_ready(
                    noaddtrailers=True, addmysob=False, addlink=False,
                    cherrypick=None, copyccs=False, allowbadchars=False,
                    showchecks=False)
                if not am_msgs:
                    raise LookupError('No patches ready for applying')

                ifh = io.BytesIO()
                b4.save_git_am_mbox(am_msgs, ifh)
                ambytes = ifh.getvalue()

                # Determine best base: series-specified or guessed
                initial_base = 'HEAD'
                base_hint = ''
                topdir = b4.git_get_toplevel()
                if lser.base_commit and topdir:
                    bc = lser.base_commit
                    short = bc[:12] if len(bc) > 12 else bc
                    if b4.git_commit_exists(topdir, bc):
                        initial_base = short
                        base_hint = f'Series base: {short}'
                    else:
                        base_hint = f'Series base: {short} (not in repo)'
                if topdir and initial_base == 'HEAD':
                    # No usable series base — try guessing.
                    # Exclude b4 review branches — they are never
                    # useful as a base for applying new series.
                    try:
                        guessed, nblobs, mismatches = lser.find_base(
                            topdir,
                            branches=['--exclude=refs/heads/b4/review/*',
                                      '--all'],
                            maxdays=30)
                        if guessed:
                            # find_base returns a describe name (e.g. heads/foo);
                            # resolve it to a SHA for the input field
                            ecode, sha_out = b4.git_run_command(
                                topdir, ['rev-parse', '--verify', guessed])
                            sha = sha_out.strip() if ecode == 0 else ''
                            short_sha = sha[:12] if sha else guessed
                            if mismatches == 0:
                                initial_base = short_sha
                                base_hint = (f'Guessed base: {guessed}'
                                             f' (exact match)')
                            elif nblobs != mismatches:
                                matched = nblobs - mismatches
                                initial_base = short_sha
                                base_hint = (f'Guessed base: {guessed}'
                                             f' ({matched}/{nblobs} blobs)')
                            else:
                                base_hint = 'Could not find a matching base'
                    except (IndexError, Exception):
                        pass

                # Check attestation while we have the messages
                att = b4.review.check_series_attestation(lser)
                if att and self._identifier:
                    b4.review.tracking.update_attestation(
                        self._identifier,
                        series.get('change_id', ''),
                        series.get('revision', 1),
                        att)

                return lser, ambytes, initial_base, base_hint

        self.push_screen(
            WorkerScreen('Retrieving series\u2026', _fetch_and_prepare),
            callback=lambda result: self._on_series_fetched(result, series),
        )

    def _on_series_fetched(self, result: Any,
                            series: Dict[str, Any]) -> None:
        """Handle the result from the series fetch worker."""
        if result is None:
            return

        lser, ambytes, initial_base, base_hint = result

        # Build base commit suggestions: HEAD, configured targets, recent branches
        base_suggestions: List[str] = ['HEAD']
        for cb in b4.review.tracking.get_review_target_branches():
            if cb not in base_suggestions:
                base_suggestions.append(cb)
        topdir = b4.git_get_toplevel()
        if topdir:
            gitdir = b4.git_get_common_dir(topdir)
            if gitdir:
                recent = b4.review.tracking.get_recent_take_branches(gitdir)
                if recent:
                    for rb in recent:
                        if rb not in base_suggestions:
                            base_suggestions.append(rb)

        self.push_screen(
            BaseSelectionScreen(initial_base, lser, ambytes,
                                base_suggestions=base_suggestions,
                                base_hint=base_hint,
                                subject=series.get('subject', '')),
            callback=lambda base_sha: self._on_base_selected(
                base_sha, lser, series, ambytes),
        )

    def _on_base_selected(self, base_sha: Optional[str],
                           lser: b4.LoreSeries,
                           series: Dict[str, Any],
                           ambytes: bytes) -> None:
        """Handle base selection screen result."""
        if base_sha is None:
            self.notify('Checkout cancelled', severity='information')
            return
        self._do_checkout(lser, series, base_commit=base_sha,
                          ambytes=ambytes)

    def _discover_newer_versions(self, change_id: str,
                                 current_rev: int,
                                 review_branch: str) -> List[int]:
        """Look up newer revision numbers from tracking data and DB."""
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
        return newer_versions

    @staticmethod
    def _resolve_base_commit(topdir: str,
                             lser: 'b4.LoreSeries') -> Optional[str]:
        """Determine the base commit for a series, guessing if needed.

        Returns the base commit SHA or None if it cannot be determined.
        """
        base_commit = lser.base_commit
        need_guess = False
        if base_commit:
            if not b4.git_commit_exists(topdir, base_commit):
                logger.warning('Base commit %s not found in repository, will try to guess',
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
                    logger.info('Base: %s (best guess, %s/%s blobs matched)',
                                base_commit, nblobs - mismatches, nblobs)
            except IndexError as ex:
                logger.warning('Base: failed to guess (%s)', ex)
                base_commit = None

        return base_commit

    def _do_checkout(self, lser: b4.LoreSeries, series: Dict[str, Any],
                     base_commit: str, ambytes: bytes) -> None:
        """Create the review branch for the series.

        Args:
            lser: The LoreSeries to check out
            series: Tracking database series dict
            base_commit: Resolved base commit SHA (from BaseSelectionScreen)
            ambytes: Pre-built mbox bytes for git-am
        """
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

            # Get linkmask
            config = b4.get_main_config()
            linkmask = str(config.get('linkmask', ''))
            if '%s' not in linkmask:
                logger.critical('linkmask not configured properly')
                _wait_for_enter()
                return
            linkurl = linkmask % top_msgid

            # Prepare blob ancestors for three-way merge if needed
            if lser.complete:
                _checked, mismatches = lser.check_applies_clean(gitdir=topdir)
                if mismatches:
                    rstart, rend = lser.make_fake_am_range(gitdir=topdir)
                    if rstart and rend:
                        logger.info('Prepared fake commit range for 3-way merge (%.12s..%.12s)', rstart, rend)

            try:
                logger.info('Base: %s', base_commit)
                b4.git_fetch_am_into_repo(topdir, ambytes=ambytes, at_base=base_commit,
                                          origin=linkurl, am_flags=['-3'])

                # Create the review branch
                b4.review.create_review_branch(topdir, branch_name, base_commit, lser,
                                               linkurl, linkmask, num_prereqs=0,
                                               identifier=self._identifier,
                                               status='reviewing')
                logger.info('Review branch created: %s', branch_name)
                checkout_success = True
            except b4.AmConflictError as cex:
                if not _resolve_worktree_am_conflict(topdir, cex):
                    _wait_for_enter()
                    return
                b4._rewrite_fetch_head_origin(topdir, cex.worktree_path, linkurl)
                # Create the review branch from resolved result
                b4.review.create_review_branch(topdir, branch_name, base_commit, lser,
                                               linkurl, linkmask, num_prereqs=0,
                                               identifier=self._identifier,
                                               status='reviewing')
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

        # Carry per-series target branch from DB to tracking commit
        _co_change_id = series.get('change_id', '')
        if self._identifier and _co_change_id and topdir:
            try:
                conn = b4.review.tracking.get_db(self._identifier)
                db_target = b4.review.tracking.get_target_branch(
                    conn, _co_change_id, revision=series.get('revision'))
                conn.close()
                if db_target and b4.git_branch_exists(topdir, branch_name):
                    cover_text, tracking = b4.review.load_tracking(topdir, branch_name)
                    trk_series = tracking.get('series', {})
                    if not trk_series.get('target-branch'):
                        trk_series['target-branch'] = db_target
                        tracking['series'] = trk_series
                        b4.review.save_tracking_ref(topdir, branch_name, cover_text, tracking)
            except (SystemExit, Exception):
                pass

        # Update Patchwork state if series was tracked from Patchwork
        pw_series_id = series.get('pw_series_id')
        if pw_series_id:
            b4.review.pw_update_series_state(pw_series_id, 'under-review')

        # Clear the followup badge — user is about to review this series
        _co_change_id = series.get('change_id', '')
        _co_revision = series.get('revision', 1)
        if self._identifier and _co_change_id and isinstance(_co_revision, int):
            try:
                conn = b4.review.tracking.get_db(self._identifier)
                b4.review.tracking.mark_all_messages_seen(conn, _co_change_id, _co_revision)
                conn.close()
            except Exception:
                pass

        # Exit to review mode
        self.exit(branch_name)

    def _show_details(self, series: Dict[str, Any]) -> None:

        try:
            panel = self.query_one('#details-panel', Vertical)
        except NoMatches:
            return

        raw_subject = series.get('subject', '(no subject)')
        revision = series.get('revision', 1)
        num_patches = series.get('num_patches', 0) or 0
        ls = b4.LoreSubject(raw_subject)
        extras = ls.get_extra_prefixes(exclude=['patch'])
        width = len(str(num_patches)) if num_patches > 0 else 1
        parts = extras + [f'v{revision}', f'{"0" * width}/{num_patches:0{width}d}']
        subject = f'[{",".join(parts)}] {ls.subject}'

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

        status_raw = series.get('status', 'new')
        symbol = _STATUS_SYMBOLS.get(status_raw, '?')
        status_str = f'{symbol}  {status_raw}'
        if status_raw == 'snoozed':
            try:
                conn = b4.review.tracking.get_db(self._identifier)
                snoozed_until = b4.review.tracking.get_snoozed_until(
                    conn, series.get('change_id', ''),
                    revision=series.get('revision'))
                conn.close()
                if snoozed_until:
                    status_str += f' ({_format_snooze_until(snoozed_until)})'
            except Exception:
                pass

        self.query_one('#detail-subject', Static).update(subject)
        self.query_one('#detail-from', Static).update(from_str)
        self.query_one('#detail-sent', Static).update(sent_str)
        self.query_one('#detail-status', Static).update(status_str)
        self.query_one('#detail-changeid', Static).update(change_id)
        self.query_one('#detail-link', Static).update(link_url)

        # Attestation row
        att = series.get('attestation') or ''
        att_row = self.query_one('#detail-attestation-row', Horizontal)
        att_widget = self.query_one('#detail-attestation', Static)
        if att == 'pending' or att == '':
            att_widget.update(RichText('pending (run [u]pdate)', style='dim'))
            att_row.display = True
        elif att == 'none':
            att_widget.update(RichText('no signatures', style='dim'))
            att_row.display = True
        else:
            att_text = _format_attestation(att, app=self)
            if att_text is not None:
                att_widget.update(att_text)
                att_row.display = True
            else:
                att_row.display = False

        # Show known revisions from SQLite
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
            else:
                if series.get('needs_update'):
                    rev_widget = self.query_one('#detail-revisions', Static)
                    rev_widget.add_class('has-upgrade')
                    rev_widget.update('run [u]pdate to load revision data')
                    revisions_row.display = True
                else:
                    revisions_row.display = False
        except Exception:
            revisions_row.display = False

        # Show branch name for series with a review branch
        status = series.get('status', 'new')
        branch_row = self.query_one('#detail-branch-row', Horizontal)
        if status in ('reviewing', 'replied', 'waiting', 'snoozed'):
            branch_name = f'b4/review/{change_id}'
            self.query_one('#detail-branch', Static).update(branch_name)
            branch_row.display = True
        else:
            branch_row.display = False

        # Show target branch if set (per-series, tracking commit, or config default)
        target_row = self.query_one('#detail-target-row', Horizontal)
        target_branch = self._resolve_target_branch(series)
        if target_branch:
            self.query_one('#detail-target', Static).update(target_branch)
            target_row.display = True
        else:
            target_row.display = False

        visible_rows = sum(1 for child in panel.children if child.display)
        panel.styles.height = visible_rows + 2  # +1 border-top, +1 footer

    def _resolve_target_branch(self, series: Dict[str, Any]) -> Optional[str]:
        """Resolve the target branch for a series.

        Priority: tracking commit > DB > config default.
        """
        change_id = series.get('change_id', '')
        status = series.get('status', 'new')
        topdir = b4.git_get_toplevel()

        # Check tracking commit for states with a review branch
        if status in ('reviewing', 'replied', 'waiting', 'snoozed') and topdir:
            review_branch = f'b4/review/{change_id}'
            if b4.git_branch_exists(topdir, review_branch):
                try:
                    _cover, tracking = b4.review.load_tracking(topdir, review_branch)
                    trk_target = tracking.get('series', {}).get('target-branch')
                    if trk_target:
                        return str(trk_target)
                except (SystemExit, Exception):
                    pass

        # Check DB
        try:
            conn = b4.review.tracking.get_db(self._identifier)
            db_target = b4.review.tracking.get_target_branch(
                conn, change_id, revision=series.get('revision'))
            conn.close()
            if db_target:
                return db_target
        except Exception:
            pass

        # Fall back to config default
        return b4.review.tracking.get_review_target_branch_default()

    def action_target_branch(self) -> None:
        """Set the target branch for the selected series."""
        if not self._selected_series:
            return
        series = self._selected_series
        change_id = series.get('change_id', '')

        # Load current target
        current_target = self._resolve_target_branch(series) or ''

        # Build suggestion list from config branches + recent take branches
        suggestions: List[str] = list(b4.review.tracking.get_review_target_branches())
        topdir = b4.git_get_toplevel()
        if topdir:
            gitdir = b4.git_get_common_dir(topdir)
            if gitdir:
                recent = b4.review.tracking.get_recent_take_branches(gitdir)
                for rb in recent:
                    if rb not in suggestions:
                        suggestions.append(rb)

        # Pass review branch for local applicability checks, or
        # message_id for lore fetch if no local branch
        status = series.get('status', 'new')
        review_branch: Optional[str] = None
        if status in ('reviewing', 'replied', 'waiting', 'snoozed'):
            rb = f'b4/review/{change_id}'
            if topdir and b4.git_branch_exists(topdir, rb):
                review_branch = rb

        self.push_screen(
            TargetBranchScreen(current_target, suggestions=suggestions or None,
                               subject=series.get('subject', ''),
                               message_id=series.get('message_id', ''),
                               revision=series.get('revision'),
                               review_branch=review_branch),
            callback=self._on_target_branch_set,
        )

    def _on_target_branch_set(self, result: Optional[str]) -> None:
        """Handle target branch dialog result."""
        if result is None:
            # Cancelled
            return
        series = self._selected_series
        if not series:
            return
        change_id = series.get('change_id', '')
        revision = series.get('revision')
        # Empty string means clear
        target_value = result if result else None

        # Update tracking commit if review branch exists
        topdir = b4.git_get_toplevel()
        status = series.get('status', 'new')
        review_branch = f'b4/review/{change_id}'
        if topdir and status in ('reviewing', 'replied', 'waiting', 'snoozed'):
            if b4.git_branch_exists(topdir, review_branch):
                try:
                    cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
                    trk_series = tracking.get('series', {})
                    if target_value:
                        trk_series['target-branch'] = target_value
                    else:
                        trk_series.pop('target-branch', None)
                    tracking['series'] = trk_series
                    b4.review.save_tracking_ref(topdir, review_branch, cover_text, tracking)
                except (SystemExit, Exception) as ex:
                    logger.warning('Could not update tracking commit: %s', ex)

        # Update database
        try:
            conn = b4.review.tracking.get_db(self._identifier)
            b4.review.tracking.update_target_branch(conn, change_id, target_value,
                                                    revision=revision)
            conn.close()
        except Exception as ex:
            logger.warning('Could not update target branch in DB: %s', ex)

        if target_value:
            self.notify(f'Target branch set to {target_value}')
        else:
            self.notify('Target branch cleared')

        # Refresh details panel
        self._show_details(series)

    def action_update_one(self) -> None:
        """Fetch thread and update revisions/trailers for the selected series."""
        if not self._selected_series:
            self.notify('No series selected', severity='warning')
            return

        config = b4.get_main_config()
        linkmask = str(config.get('linkmask', 'https://lore.kernel.org/r/%s'))
        topdir = b4.git_get_toplevel()

        self._focus_change_id = self._selected_series.get('change_id')
        self.push_screen(
            UpdateAllScreen([self._selected_series], self._identifier,
                            linkmask, topdir),
            callback=self._on_update_complete,
        )

    def action_update_all(self) -> None:
        """Fetch threads and update revisions/trailers for all tracked series."""
        if not self._all_series:
            self.notify('No tracked series to update', severity='warning')
            return

        config = b4.get_main_config()
        linkmask = str(config.get('linkmask', 'https://lore.kernel.org/r/%s'))
        topdir = b4.git_get_toplevel()

        # Skip snoozed series during update-all
        update_list = [s for s in self._all_series if s.get('status') != 'snoozed']

        if self._selected_series:
            self._focus_change_id = self._selected_series.get('change_id')
        self.push_screen(
            UpdateAllScreen(update_list, self._identifier, linkmask, topdir),
            callback=self._on_update_complete,
        )

    def _on_update_complete(self, result: Optional[Dict[str, int]]) -> None:
        """Build a summary notification from an update result."""
        if result is None:
            return
        checked = result.get('series_checked', 0)
        updated = result.get('series_updated', 0)
        promoted = result.get('promoted', 0)
        errors = result.get('errors', 0)
        gone = result.get('gone', 0)

        if gone:
            self.notify(f'{gone} review branch(es) are gone', severity='warning')

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
        if self._selected_series is not None:
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

        series = self._selected_series

        # Determine the target branch suggestion.
        # Priority: per-series target > recent take branch > config default >
        # original branch > master/main
        per_series_target = self._resolve_target_branch(series)
        target_branch = ''
        if per_series_target:
            target_branch = per_series_target
        elif self._original_branch:
            target_branch = self._original_branch
        else:
            topdir = b4.git_get_toplevel()
            if topdir and b4.git_branch_exists(topdir, 'master'):
                target_branch = 'master'
            elif topdir and b4.git_branch_exists(topdir, 'main'):
                target_branch = 'main'

        change_id = series.get('change_id', '')
        review_branch = f'b4/review/{change_id}'

        # Check if a newer revision is known to exist
        current_rev = series.get('revision', 1)
        newer_versions = self._discover_newer_versions(
            change_id, current_rev, review_branch)

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
        # Start with user config preference; skip detection below may override it.
        _valid_take_methods = {'merge', 'linear', 'cherry-pick'}
        b4cfg = b4.get_config_from_git(r'b4\..*')
        cfg_method = str(b4cfg.get('review-default-take-method', ''))
        default_method: Optional[str] = cfg_method if cfg_method in _valid_take_methods else None
        topdir = b4.git_get_toplevel()
        if topdir:
            try:
                _cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
                usercfg = b4.get_user_config()
                patches = tracking.get('patches', [])
                if any(b4.review._get_patch_state(p, usercfg) == 'skip' for p in patches):
                    default_method = 'cherry-pick'
            except Exception:
                pass
        recent_branches = None
        gitdir = b4.git_get_common_dir(topdir) if topdir else None
        if gitdir:
            recent_branches = b4.review.tracking.get_recent_take_branches(gitdir)
        # Only use recent-take as default if no per-series target was provided
        per_series_target = self._resolve_target_branch(series)
        if recent_branches and not per_series_target:
            target_branch = recent_branches[0]
        # Build the suggestion list: config branches + recent take branches
        all_suggestions: List[str] = list(b4.review.tracking.get_review_target_branches())
        if recent_branches:
            for rb in recent_branches:
                if rb not in all_suggestions:
                    all_suggestions.append(rb)
        if target_branch and target_branch not in all_suggestions:
            all_suggestions.append(target_branch)
        recent_branches = all_suggestions or None
        take_screen = TakeScreen(target_branch, review_branch, num_patches=num_patches,
                                 default_method=default_method,
                                 recent_branches=recent_branches,
                                 subject=series.get('subject', ''))
        self.push_screen(
            take_screen,
            callback=lambda confirmed: self._on_take_confirmed(
                confirmed, change_id, review_branch, take_screen, series),
        )

    def _on_take_confirmed(self, confirmed: bool, change_id: str,
                           review_branch: str, take_screen: 'TakeScreen',
                           series: Dict[str, Any]) -> None:
        """Handle take screen result — proceed to cherry-pick or confirm."""
        if not confirmed:
            return
        if take_screen.method_result == 'cherry-pick':
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
            usercfg = b4.get_user_config()
            preselected = [
                i + 1 for i, p in enumerate(patches)
                if b4.review._get_patch_state(p, usercfg) != 'skip'
            ]
            # Only pre-populate if some patches are actually skipped
            if len(preselected) == len(patches):
                preselected = []
            pick_screen = CherryPickScreen(patches, preselected=preselected or None)
            self.push_screen(
                pick_screen,
                callback=lambda picked: self._on_cherrypick_confirmed(
                    picked, change_id, review_branch, take_screen, series,
                    pick_screen),
            )
        else:
            self._show_take_confirm(
                take_screen.method_result, take_screen.target_result,
                change_id, review_branch, take_screen, series)

    def _on_cherrypick_confirmed(self, confirmed: bool, change_id: str,
                                 review_branch: str, take_screen: 'TakeScreen',
                                 series: Dict[str, Any],
                                 pick_screen: 'CherryPickScreen') -> None:
        """Handle cherry-pick selection — proceed to confirm screen."""
        if not confirmed:
            return
        self._show_take_confirm(
            'cherry-pick', take_screen.target_result,
            change_id, review_branch, take_screen, series,
            cherrypick=pick_screen.selected_indices)

    def _show_take_confirm(self, method: str, target_branch: str,
                           change_id: str, review_branch: str,
                           take_screen: 'TakeScreen',
                           series: Dict[str, Any],
                           cherrypick: Optional[List[int]] = None) -> None:
        """Push the TakeConfirmScreen for final confirmation."""
        subject = series.get('subject', '')
        confirm_screen = TakeConfirmScreen(
            method, target_branch, review_branch, subject=subject,
            cherrypick=cherrypick)
        self.push_screen(
            confirm_screen,
            callback=lambda ok: self._on_take_final(
                ok, method, change_id, review_branch, take_screen,
                series, confirm_screen, cherrypick),
        )

    def _on_take_final(self, confirmed: bool, method: str,
                       change_id: str, review_branch: str,
                       take_screen: 'TakeScreen',
                       series: Dict[str, Any],
                       confirm_screen: 'TakeConfirmScreen',
                       cherrypick: Optional[List[int]] = None) -> None:
        """Execute the actual take after final confirmation."""
        if not confirmed:
            return
        take_screen.accept_series = confirm_screen.accept_series
        if method == 'merge':
            with self.suspend():
                self._do_take_merge(change_id, review_branch, take_screen, series)
            self._load_series()
        else:
            with self.suspend():
                self._do_take_am(change_id, review_branch, take_screen, series,
                                 cherrypick=cherrypick)
            self._load_series()

    @staticmethod
    def _record_take_metadata(topdir: str, review_branch: str,
                              target_branch: str, commit_ids: List[str],
                              cherrypick: Optional[List[int]] = None,
                              accepted: bool = True) -> None:
        """Record taken commit IDs in the tracking data on the review branch.

        Args:
            topdir: Repository top-level directory.
            review_branch: The b4/review/... branch with the tracking commit.
            target_branch: Branch the patches were applied to.
            commit_ids: Ordered list of commit SHAs that were applied.
            cherrypick: If set, the 1-based patch indices that were picked.
            accepted: If True, mark the series status as 'accepted'.
        """
        try:
            cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
        except SystemExit:
            logger.warning('Could not load tracking data for recording take metadata')
            return

        series = tracking.get('series', {})
        if accepted:
            series['status'] = 'accepted'
        take_info = {
            'branch': target_branch,
            'date': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d'),
            'accepted': accepted,
        }
        series['taken'] = take_info
        series.setdefault('takes', []).append(take_info)

        # Record the branch tip commit for CI lookups (e.g. KernelCI).
        # HEAD is still on target_branch at this point.
        ecode, tip_out = b4.git_run_command(topdir, ['rev-parse', 'HEAD'])
        if ecode == 0 and tip_out.strip():
            tip_entry = {
                'date': take_info['date'],
                'branch': target_branch,
                'sha': tip_out.strip(),
            }
            series.setdefault('branch-tips', []).append(tip_entry)

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
                       take_screen: 'TakeScreen',
                       series: Dict[str, Any]) -> None:
        """Perform a merge-based take operation."""
        target_branch = take_screen.target_result

        # Setup
        topdir = b4.git_get_toplevel()
        if not topdir:
            logger.critical('Not in a git repository')
            return

        # Prepare trailer-amended mbox bytes from local review branch
        ambytes = self._prepare_am_messages(review_branch, take_screen, series)
        if ambytes is None:
            return

        try:
            cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
        except SystemExit:
            logger.critical('Could not load tracking data from %s', review_branch)
            _wait_for_enter()
            return

        t_series = tracking.get('series', {})

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
        subject = t_series.get('subject', '')
        clean_subject = b4.LoreSubject(subject).subject or subject

        # Determine number of patches
        num_patches = len(tracking.get('patches', []))

        # Populate template
        tptvals = {
            'seriestitle': clean_subject,
            'authorname': t_series.get('fromname', ''),
            'authoremail': t_series.get('fromemail', ''),
            'covermessage': covermessage,
            'midurl': t_series.get('link', ''),
            'mid': t_series.get('header-info', {}).get('msgid', ''),
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
                stripped = body.rstrip('\n')
                # If the body already ends with a trailer (e.g. Link:),
                # keep them in the same block without a blank line.
                last_line = stripped.rsplit('\n', 1)[-1]
                if re.match(r'^[A-Za-z-]+:\s', last_line):
                    body = stripped + '\n' + sob + '\n'
                else:
                    body = stripped + '\n\n' + sob + '\n'

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

        # Apply trailer-amended patches in a sparse worktree and fetch
        # into FETCH_HEAD, so individual commits carry their trailers.
        base_commit = t_series.get('base-commit', '')
        if not base_commit:
            # Fall back to target branch HEAD
            ecode, out = b4.git_run_command(topdir, ['rev-parse', target_branch])
            if ecode != 0:
                logger.critical('Could not resolve %s', target_branch)
                _wait_for_enter()
                return
            base_commit = out.strip()

        try:
            b4.git_fetch_am_into_repo(topdir, ambytes, at_base=base_commit, am_flags=['-3'])
        except b4.AmConflictError as cex:
            if not _resolve_worktree_am_conflict(topdir, cex):
                _wait_for_enter()
                return
        except RuntimeError:
            _wait_for_enter()
            return

        # Save current branch so we can restore on failure
        prev_branch = b4.git_get_current_branch(topdir)
        if prev_branch is None:
            prev_branch = b4.git_revparse_obj('HEAD', gitdir=topdir)

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

        # Merge FETCH_HEAD (trailer-amended patches) instead of the
        # review branch directly, so each commit carries its trailers.
        gitargs = ['merge', '--no-ff', '--no-edit', '-F', mmf, 'FETCH_HEAD']
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

        # Record per-patch commit IDs from the merged branch.
        # After --no-ff merge, HEAD^2 is the tip of the merged side;
        # the individual patch commits are base_commit..HEAD^2.
        ecode, out = b4.git_run_command(
            topdir, ['rev-list', '--reverse', f'{base_commit}..HEAD^2'])
        if ecode == 0 and out.strip():
            commit_ids = out.strip().splitlines()
            self._record_take_metadata(topdir, review_branch, target_branch,
                                       commit_ids,
                                       accepted=take_screen.accept_series)

        self._finalize_take(topdir, target_branch, change_id, t_series,
                            take_screen.accept_series)
        _wait_for_enter()

    def _finalize_take(self, topdir: str, target_branch: str,
                       change_id: str, series: Dict[str, Any],
                       accepted: bool) -> None:
        """Common post-take steps: record branch, update DB, update Patchwork."""
        common_dir = b4.git_get_common_dir(topdir)
        if common_dir:
            b4.review.tracking.record_take_branch(common_dir, target_branch)

        if accepted and self._identifier and change_id:
            revision = series.get('revision')
            existing_target = None
            try:
                conn = b4.review.tracking.get_db(self._identifier)
                b4.review.tracking.update_series_status(conn, change_id, 'accepted',
                                                        revision=revision)
                # Record the take target as the series target branch if not already set
                existing_target = b4.review.tracking.get_target_branch(
                    conn, change_id, revision=revision)
                if not existing_target:
                    b4.review.tracking.update_target_branch(
                        conn, change_id, target_branch, revision=revision)
                conn.close()
            except Exception as ex:
                logger.warning('Could not update series status: %s', ex)
            # Also update the tracking commit
            review_branch = f'b4/review/{change_id}'
            if not existing_target and b4.git_branch_exists(topdir, review_branch):
                try:
                    cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
                    trk_series = tracking.get('series', {})
                    if not trk_series.get('target-branch'):
                        trk_series['target-branch'] = target_branch
                        tracking['series'] = trk_series
                        b4.review.save_tracking_ref(topdir, review_branch,
                                                    cover_text, tracking)
                except (SystemExit, Exception):
                    pass

        if accepted and self._selected_series:
            pw_sid = self._selected_series.get('pw_series_id')
            if pw_sid:
                b4.review.pw_update_series_state(pw_sid, 'accepted')

    def _prepare_am_messages(
        self,
        review_branch: str,
        take_screen: 'TakeScreen',
        series: Dict[str, Any],
        cherrypick: Optional[List[int]] = None,
    ) -> Optional[bytes]:
        """Generate patches from local review branch and prepare trailer-amended mbox bytes.

        Loads tracking from the review branch, generates patches from local
        commits (instead of re-fetching from lore), injects original
        Message-IDs and follow-up trailers, and runs get_am_ready() to
        produce mbox bytes suitable for git-am.

        Returns mbox bytes on success, or None on failure.
        """
        topdir = b4.git_get_toplevel()
        if not topdir:
            logger.critical('Not in a git repository')
            return None

        # Load tracking to get follow-up trailers
        try:
            _cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
        except SystemExit:
            logger.critical('Could not load tracking data from %s', review_branch)
            _wait_for_enter()
            return None

        t_series = tracking.get('series', {})

        # Determine patch range from local review branch
        first_patch = t_series.get('first-patch-commit', '')
        if first_patch:
            range_start = f'{first_patch}~1'
        else:
            range_start = t_series.get('base-commit', '')
        range_end = f'{review_branch}~1'  # exclude tracking commit

        if not range_start:
            logger.critical('Cannot determine patch range for %s', review_branch)
            _wait_for_enter()
            return None

        # Generate patches from local commits
        revision = t_series.get('revision', 1)
        try:
            local_patches = b4.git_range_to_patches(topdir, range_start, range_end,
                                                    revision=revision)
        except RuntimeError as ex:
            logger.critical('Could not generate patches: %s', ex)
            _wait_for_enter()
            return None

        if not local_patches:
            logger.critical('No patches found in range %s..%s', range_start, range_end)
            _wait_for_enter()
            return None

        # Inject original Message-IDs so Link trailers point to lore
        patches_meta = tracking.get('patches', [])
        for i, (_commit, msg) in enumerate(local_patches):
            if i < len(patches_meta):
                orig_msgid = patches_meta[i].get('header-info', {}).get('msgid', '')
                if orig_msgid:
                    msg.add_header('Message-Id', f'<{orig_msgid}>')

        # Build LoreSeries from local patches
        lmbx = b4.LoreMailbox()
        for _commit, msg in local_patches:
            lmbx.add_message(msg)

        lser = lmbx.get_series(revision, sloppytrailers=False,
                               codereview_trailers=False)
        if lser is None:
            logger.critical('Could not build series from local patches')
            _wait_for_enter()
            return None

        # Apply cover follow-up trailers to every patch (no cover letter
        # in local patches, so distribute to all)
        cover_followups = tracking.get('followups', [])
        for followup in cover_followups:
            for tstr in followup.get('trailers', []):
                if ': ' not in tstr:
                    continue
                tname, tval = tstr.split(': ', maxsplit=1)
                fltr = b4.LoreTrailer(name=tname, value=tval)
                for lmsg in lser.patches[1:]:
                    if lmsg is not None and fltr not in lmsg.followup_trailers:
                        lmsg.followup_trailers.append(fltr)

        # Apply per-patch follow-up trailers
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
            return None

        if cherrypick:
            logger.info('Prepared %d patch(es) (cherry-picked: %s)',
                        len(am_msgs), ', '.join(str(x) for x in cherrypick))
        else:
            logger.info('Prepared %d patch(es)', len(am_msgs))

        # Build mbox bytes for git-am
        ifh = io.BytesIO()
        b4.save_git_am_mbox(am_msgs, ifh)
        return ifh.getvalue()

    def _do_take_am(self, change_id: str, review_branch: str,
                    take_screen: 'TakeScreen', series: Dict[str, Any],
                    cherrypick: Optional[List[int]]) -> None:
        """Perform a linear or cherry-pick take via git-am."""
        target_branch = take_screen.target_result

        topdir = b4.git_get_toplevel()
        if not topdir:
            logger.critical('Not in a git repository')
            return

        ambytes = self._prepare_am_messages(review_branch, take_screen, series,
                                            cherrypick=cherrypick)
        if ambytes is None:
            return

        # Save current branch so we can report it on failure
        prev_branch = b4.git_get_current_branch(topdir)
        if prev_branch is None:
            prev_branch = b4.git_revparse_obj('HEAD', gitdir=topdir)

        # Checkout target branch
        ecode, out = b4.git_run_command(topdir, ['checkout', target_branch], logstderr=True)
        if ecode != 0:
            logger.critical('Could not checkout %s: %s', target_branch, out.strip())
            _wait_for_enter()
            return

        # Save HEAD before git-am so we can find the new commits afterwards
        ecode, out = b4.git_run_command(topdir, ['rev-parse', 'HEAD'])
        pre_am_head = out.strip() if ecode == 0 else ''

        # Run git-am with three-way merge
        ecode, out = b4.git_run_command(topdir, ['am', '-3'], stdin=ambytes, logstderr=True)
        if ecode != 0:
            logger.critical('git-am failed:')
            logger.critical(out.strip())
            logger.info('You can resolve the conflict now.')
            logger.info('Use "git am --continue" after resolving, or "git am --abort" to give up.')
            _suspend_to_shell(hint='b4 conflict')
            # Check if am is still in progress (user exited without finishing)
            rebase_apply_path = os.path.join(topdir, '.git', 'rebase-apply')
            if os.path.isdir(rebase_apply_path):
                logger.warning('Conflict resolution incomplete')
                logger.warning('Run "git am --abort" to clean up')
                _wait_for_enter()
                return
            # Check if am was aborted (HEAD unchanged)
            ecode, current_head = b4.git_run_command(topdir, ['rev-parse', 'HEAD'], logstderr=True)
            if ecode != 0 or current_head.strip() == pre_am_head:
                logger.warning('Conflict resolution aborted')
                _wait_for_enter()
                return
            logger.info('Conflict resolved, patches applied.')

        logger.info(out.strip())
        logger.info('Applied patches to %s', target_branch)

        # Record per-patch commit IDs in the tracking data
        if pre_am_head:
            ecode, out = b4.git_run_command(
                topdir, ['rev-list', '--reverse', f'{pre_am_head}..HEAD'])
            if ecode == 0:
                commit_ids = out.strip().splitlines()
                self._record_take_metadata(topdir, review_branch, target_branch,
                                           commit_ids, cherrypick=cherrypick,
                                           accepted=take_screen.accept_series)

        self._finalize_take(topdir, target_branch, change_id, series,
                            take_screen.accept_series)
        _wait_for_enter()

    def action_rebase(self) -> None:
        """Rebase the review branch on top of current HEAD."""
        if not self._selected_series:
            return
        status = self._selected_series.get('status', 'new')
        if status not in ('reviewing', 'replied'):
            self.notify('Series must be checked out before rebasing', severity='warning')
            return

        series = self._selected_series
        change_id = series.get('change_id', '')
        review_branch = f'b4/review/{change_id}'

        # Determine the default target branch.
        # Priority: per-series target > recent take branch > original branch
        per_series_target = self._resolve_target_branch(series)
        current_branch = self._original_branch or 'HEAD'
        recent_branches = None
        topdir = b4.git_get_toplevel()
        if topdir:
            gitdir = b4.git_get_common_dir(topdir)
            if gitdir:
                recent_branches = b4.review.tracking.get_recent_take_branches(gitdir)
        if per_series_target:
            current_branch = per_series_target
        elif recent_branches:
            current_branch = recent_branches[0]
        # Ensure the original branch is always in the suggestion list
        if current_branch and recent_branches is not None and current_branch not in recent_branches:
            recent_branches.append(current_branch)
        elif current_branch and recent_branches is None:
            recent_branches = [current_branch]

        rebase_screen = RebaseScreen(current_branch, review_branch,
                                     recent_branches=recent_branches,
                                     subject=self._selected_series.get('subject', ''))
        self.push_screen(
            rebase_screen,
            callback=lambda confirmed: self._on_rebase_confirmed(
                confirmed, review_branch, rebase_screen),
        )

    def _on_rebase_confirmed(self, confirmed: bool, review_branch: str,
                             rebase_screen: 'RebaseScreen') -> None:
        """Handle rebase confirmation result."""
        if not confirmed:
            return

        # Run rebase in suspended mode to show output
        with self.suspend():
            self._do_rebase(review_branch, rebase_screen.target_result)

    def _do_rebase(self, review_branch: str, target_branch: str) -> None:
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

        # Resolve target branch to a commit SHA
        ecode, out = b4.git_run_command(topdir, ['rev-parse', target_branch])
        if ecode != 0:
            logger.critical('Could not resolve %s', target_branch)
            _wait_for_enter()
            return
        target_head = out.strip()

        # Check if series is already based on target
        ecode, out = b4.git_run_command(topdir, ['rev-parse', base_commit])
        if ecode == 0 and out.strip() == target_head:
            logger.info('Series is already based on %s', target_branch)
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

        # Check if series applies cleanly to target using sparse worktree
        logger.info('Testing if series applies cleanly to %s...', target_branch)
        applies_clean = False
        try:
            with b4.git_temp_worktree(topdir, target_head) as gwt:
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
                    logger.warning('Series does not apply cleanly to %s', target_branch)
                    logger.warning('Will attempt rebase with conflict resolution')
                else:
                    applies_clean = True
                    logger.info('Series applies cleanly')
        except Exception as ex:
            logger.critical('Error testing series applicability: %s', ex)
            _wait_for_enter()
            return

        # Perform the actual rebase
        logger.info('Rebasing %s onto %s...', review_branch, target_branch)

        # Remember where we are so we can restore on failure
        ecode, original_branch = b4.git_run_command(topdir, ['rev-parse', '--abbrev-ref', 'HEAD'],
                                                     logstderr=True)
        if ecode != 0:
            logger.critical('Could not determine current branch')
            _wait_for_enter()
            return
        original_branch = original_branch.strip()

        # First, checkout the review branch (at the tracking commit)
        ecode, out = b4.git_run_command(topdir, ['checkout', review_branch], logstderr=True)
        if ecode != 0:
            logger.critical('Could not checkout review branch: %s', out.strip())
            _wait_for_enter()
            return

        # Save the tracking commit SHA so we can restore on failure
        ecode, tracking_commit = b4.git_run_command(topdir, ['rev-parse', 'HEAD'], logstderr=True)
        if ecode != 0:
            logger.critical('Could not resolve tracking commit')
            b4.git_run_command(topdir, ['checkout', original_branch], logstderr=True)
            _wait_for_enter()
            return
        tracking_commit = tracking_commit.strip()

        # Reset to before the tracking commit (now at series_tip)
        ecode, out = b4.git_run_command(topdir, ['reset', '--hard', 'HEAD~1'], logstderr=True)
        if ecode != 0:
            logger.critical('Could not reset to before tracking commit: %s', out.strip())
            b4.git_run_command(topdir, ['reset', '--hard', tracking_commit], logstderr=True)
            b4.git_run_command(topdir, ['checkout', original_branch], logstderr=True)
            _wait_for_enter()
            return

        # Rebase the patches onto target_head
        # --onto target_head base_commit means: take commits after base_commit and replay onto target_head
        ecode, out = b4.git_run_command(topdir, ['rebase', '--onto', target_head, base_commit], logstderr=True)
        if ecode != 0:
            if applies_clean:
                # Test said clean but real rebase failed — something is wrong, abort
                logger.critical('Rebase failed unexpectedly: %s', out.strip())
                logger.critical('Aborting rebase...')
                b4.git_run_command(topdir, ['rebase', '--abort'], logstderr=True)
                b4.git_run_command(topdir, ['reset', '--hard', tracking_commit], logstderr=True)
                b4.git_run_command(topdir, ['checkout', original_branch], logstderr=True)
                _wait_for_enter()
                return

            logger.critical('---')
            logger.critical(out.strip())
            logger.critical('---')
            logger.critical('Rebase had conflicts.')
            logger.info('You can resolve the conflicts in your working tree.')
            logger.info('Use "git rebase --continue" after resolving, or "git rebase --abort" to give up.')
            _suspend_to_shell(hint='b4 rebase')
            # Check if rebase is still in progress (user exited without finishing)
            ecode, gitdir = b4.git_run_command(topdir, ['rev-parse', '--git-dir'], logstderr=True)
            rebase_in_progress = False
            if ecode == 0:
                gitdir = gitdir.strip()
                rebase_in_progress = (os.path.isdir(os.path.join(gitdir, 'rebase-merge'))
                                      or os.path.isdir(os.path.join(gitdir, 'rebase-apply')))
            if rebase_in_progress:
                logger.warning('Rebase not completed, aborting')
                b4.git_run_command(topdir, ['rebase', '--abort'], logstderr=True)
                b4.git_run_command(topdir, ['reset', '--hard', tracking_commit], logstderr=True)
                b4.git_run_command(topdir, ['checkout', original_branch], logstderr=True)
                _wait_for_enter()
                return
            # Check if the rebase was aborted (HEAD back at pre-rebase state)
            ecode, current_head = b4.git_run_command(topdir, ['rev-parse', 'HEAD'], logstderr=True)
            if ecode != 0 or current_head.strip() == series_tip:
                logger.warning('Rebase was aborted')
                b4.git_run_command(topdir, ['reset', '--hard', tracking_commit], logstderr=True)
                b4.git_run_command(topdir, ['checkout', original_branch], logstderr=True)
                _wait_for_enter()
                return
            # Verify target is an ancestor of HEAD (rebase actually landed)
            ecode, _out = b4.git_run_command(
                topdir, ['merge-base', '--is-ancestor', target_head, 'HEAD'], logstderr=True)
            if ecode != 0:
                logger.warning('Rebase result does not include %s, something went wrong', target_branch)
                b4.git_run_command(topdir, ['reset', '--hard', tracking_commit], logstderr=True)
                b4.git_run_command(topdir, ['checkout', original_branch], logstderr=True)
                _wait_for_enter()
                return
            logger.info('Rebase conflicts resolved')

        # Update tracking data with new base commit
        series['base-commit'] = target_head

        # Enumerate new patch commit SHAs and update first-patch-commit
        ecode, out = b4.git_run_command(
            topdir, ['rev-list', '--reverse', f'{target_head}..HEAD'])
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

        # Switch back to the original branch
        b4.git_run_command(topdir, ['checkout', original_branch], logstderr=True)
        logger.info('Successfully rebased %s onto %s', review_branch, target_head[:12])
        _wait_for_enter()

    def _get_check_context(self) -> Optional[Tuple[str, str, str]]:
        if not self._selected_series:
            return None
        message_id = self._selected_series.get('message_id', '')
        subject = self._selected_series.get('subject', '(no subject)')
        change_id = self._selected_series.get('change_id', '')
        return (message_id, subject, change_id)

    def action_range_diff(self) -> None:
        """Show range-diff between the current review and another revision."""
        if not self._selected_series:
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
            self.notify('No other known revisions. Try \\[u]pdate.', severity='warning')
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

    @staticmethod
    def _fetch_fake_am_range(
        topdir: str, revisions: List[Dict[str, Any]], rev: int,
        blob_sha: str = '',
    ) -> Optional[Tuple[str, str]]:
        """Fetch a revision and create a fake-am commit range.

        If *blob_sha* is provided, tries the cached thread blob first
        before falling back to a lore fetch.

        Returns (range_start, range_end) on success, or None on failure.
        """
        msgs = None

        # Try cached thread blob first
        if blob_sha:
            mbox_bytes = b4.review.tracking.get_thread_mbox(topdir, blob_sha)
            if mbox_bytes:
                logger.info('Using cached thread blob for v%d', rev)
                msgs = b4.split_and_dedupe_pi_results(mbox_bytes)

        # Fall back to lore fetch
        if not msgs:
            msgid = ''
            for r in revisions:
                if r['revision'] == rev:
                    msgid = r.get('message_id', '')
                    break
            if not msgid:
                logger.critical('No message-id recorded for v%d', rev)
                return None

            logger.info('Fetching v%d from lore...', rev)
            msgs = b4.get_pi_thread_by_msgid(msgid)
            if not msgs:
                logger.critical('Could not retrieve thread for v%d', rev)
                return None

            msgs = b4.mbox.get_extra_series(msgs, direction=1, wantvers=[rev])
            msgs = b4.mbox.get_extra_series(msgs, direction=-1, wantvers=[rev])

        lmbx = b4.LoreMailbox()
        for msg in msgs:
            lmbx.add_message(msg)

        lser = lmbx.get_series(rev, sloppytrailers=False,
                               codereview_trailers=False)
        if lser is None:
            logger.critical('Could not find series v%d in retrieved messages', rev)
            return None

        logger.info('Preparing fake-am range for v%d...', rev)
        start, end = lser.make_fake_am_range(gitdir=topdir)
        if start is None or end is None:
            logger.critical('Could not create fake-am range for v%d', rev)
            return None

        return start, end

    def _do_range_diff(self, change_id: str, current_rev: int, other_rev: int) -> None:
        """Compute and display range-diff between two revisions."""
        topdir = b4.git_get_toplevel()
        if not topdir:
            logger.critical('Not in a git repository')
            _wait_for_enter()
            return

        # --- Load revisions from the tracking database ---
        try:
            conn = b4.review.tracking.get_db(self._identifier)
            revisions = b4.review.tracking.get_revisions(conn, change_id)
            conn.close()
        except Exception as ex:
            logger.critical('Could not load revisions: %s', ex)
            _wait_for_enter()
            return

        # --- Resolve the current revision range ---
        # Use local review branch if available, otherwise fetch from lore
        branch = f'b4/review/{change_id}'
        cur_start: Optional[str] = None
        cur_end: Optional[str] = None
        blob_sha = ''
        if b4.git_branch_exists(topdir, branch):
            try:
                _cover_text, tracking = b4.review.load_tracking(topdir, branch)
                t_series = tracking.get('series', {})
                first_patch = t_series.get('first-patch-commit', '')
                if first_patch:
                    cur_start = f'{first_patch}~1'
                else:
                    cur_start = t_series.get('base-commit', '')
                cur_end = f'{branch}~1'
                blob_sha = t_series.get('thread-blob', '')
            except SystemExit:
                pass

        if not cur_start or not cur_end:
            # No local branch — fetch from lore
            result = self._fetch_fake_am_range(topdir, revisions, current_rev)
            if result is None:
                _wait_for_enter()
                return
            cur_start, cur_end = result

        # --- Fetch the other version (try cached blob, fall back to lore) ---
        result = self._fetch_fake_am_range(topdir, revisions, other_rev,
                                           blob_sha=blob_sha)
        if result is None:
            _wait_for_enter()
            return
        other_start, other_end = result

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

    def _delete_review_branch(self, topdir: str, review_branch: str,
                              notify: bool = True) -> bool:
        """Delete a review branch, switching away if currently on it.

        Returns True on success, False on failure.
        """
        if b4.git_get_current_branch(topdir) == review_branch:
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
                    self.notify(f'Could not switch away from {review_branch}',
                                severity='error')
                return False
        ecode, out = b4.git_run_command(
            topdir, ['branch', '-D', review_branch], logstderr=True)
        if ecode > 0:
            if notify:
                self.notify(f'Failed to delete branch {review_branch}',
                            severity='error')
            return False
        return True

    def action_abandon(self) -> None:
        """Abandon the selected series."""
        if not self._selected_series:
            return
        change_id = self._selected_series.get('change_id', '')
        revision = self._selected_series.get('revision')
        review_branch = f'b4/review/{change_id}'
        has_branch = b4.git_branch_exists(None, review_branch)
        self.push_screen(
            AbandonConfirmScreen(change_id, review_branch, has_branch,
                                 subject=self._selected_series.get('subject', '')),
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
            if not self._delete_review_branch(topdir, review_branch):
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
        if status not in ('reviewing', 'new'):
            self.notify('Series must be checked out or new to upgrade',
                        severity='warning')
            return

        change_id = self._selected_series.get('change_id', '')
        current_rev = self._selected_series.get('revision', 1)
        review_branch = f'b4/review/{change_id}'

        # Discover newer revisions from tracking data and DB
        newer_versions = self._discover_newer_versions(
            change_id, current_rev, review_branch)

        if not newer_versions:
            self.notify(
                'No newer revisions known. Try \\[u]pdate first.',
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
                'No newer revisions known. Try \\[u]pdate first.',
                severity='warning')
            return

        if status == 'new':
            # No review branch — just update the DB record
            if len(newer_revs) == 1:
                self._do_switch_revision(change_id, current_rev,
                                         newer_revs[0])
                return
            self.push_screen(
                UpdateRevisionScreen(current_rev, revisions),
                callback=lambda chosen: (
                    self._switch_revision_by_number(
                        change_id, current_rev, chosen, revisions)
                    if chosen is not None else None
                ),
            )
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

    def _do_switch_revision(self, change_id: str, current_rev: int,
                            rev_info: Dict[str, Any]) -> None:
        """Switch a not-yet-checked-out series to a different revision.

        Simply updates the database record — no branch operations needed.
        """
        target_rev = rev_info['revision']
        new_msgid = rev_info.get('message_id', '')
        new_subject = rev_info.get('subject')
        try:
            conn = b4.review.tracking.get_db(self._identifier)
            b4.review.tracking.update_series_revision(
                conn, change_id, current_rev, target_rev,
                new_msgid, new_subject)
            conn.close()
        except Exception as ex:
            self.notify(f'Could not update revision: {ex}', severity='error')
            return
        self.notify(f'Now tracking v{target_rev}')
        self._focus_change_id = change_id
        self._load_series()

    def _switch_revision_by_number(self, change_id: str, current_rev: int,
                                   chosen: int,
                                   revisions: List[Dict[str, Any]]) -> None:
        """Callback wrapper: find the revision dict and call _do_switch_revision."""
        for rev in revisions:
            if rev['revision'] == chosen:
                self._do_switch_revision(change_id, current_rev, rev)
                return
        self.notify(f'Revision v{chosen} not found', severity='error')

    def _do_update_revision(self, change_id: str, current_rev: int,
                            target_rev: int) -> None:
        """Upgrade the review branch from *current_rev* to *target_rev*.

        Saves maintainer reviews keyed by patch-id, archives the old
        branch, checks out the new revision, then restores reviews onto
        patches whose patch-id matches.
        """
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
            _cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
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

            # --- 1b. Render prior review context ---
            old_series = tracking.get('series', {})
            usercfg = b4.get_user_config()
            maintainer_email = str(usercfg.get('email', ''))
            prior_context = b4.review.tracking.render_prior_review_context(
                maintainer_email, current_rev, old_series, patches)
            prior_thread_blob = old_series.get('thread-context-blob', '')
            prior_msgid = old_series.get('header-info', {}).get('msgid', '')

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
            base_commit = self._resolve_base_commit(topdir, lser)
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

            # Prepare blob ancestors for three-way merge if needed
            if lser.complete:
                _checked, mismatches = lser.check_applies_clean(gitdir=topdir)
                if mismatches:
                    rstart, rend = lser.make_fake_am_range(gitdir=topdir)
                    if rstart and rend:
                        logger.info('Prepared fake commit range for 3-way merge (%.12s..%.12s)', rstart, rend)

            try:
                logger.info('Base: %s', base_commit)
                b4.git_fetch_am_into_repo(topdir, ambytes=ambytes,
                                          at_base=base_commit, origin=linkurl,
                                          am_flags=['-3'])
                b4.review.create_review_branch(topdir, review_branch,
                                               base_commit, lser, linkurl,
                                               linkmask, num_prereqs=0,
                                               identifier=self._identifier,
                                               status='reviewing')
                logger.info('Review branch created: %s', review_branch)
            except b4.AmConflictError as cex:
                if not _resolve_worktree_am_conflict(topdir, cex):
                    _wait_for_enter()
                    return
                b4._rewrite_fetch_head_origin(topdir, cex.worktree_path, linkurl)
                # Create the review branch from resolved result
                b4.review.create_review_branch(topdir, review_branch,
                                               base_commit, lser, linkurl,
                                               linkmask, num_prereqs=0,
                                               identifier=self._identifier,
                                               status='reviewing')
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

            new_tracking['series']['status'] = 'reviewing'
            if prior_context:
                new_tracking['series']['prior-review-context'] = prior_context
            if prior_thread_blob:
                new_tracking['series']['prior-thread-context-blob'] = prior_thread_blob
            if prior_msgid:
                new_tracking['series']['prior-revision-msgid'] = prior_msgid
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
        if status not in ('new', 'reviewing', 'replied'):
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
        topdir = b4.git_get_toplevel()
        if topdir and status != 'new':
            branch_name = f'b4/review/{change_id}'
            b4.review.update_tracking_status(topdir, branch_name, 'waiting')
        self.notify('Series moved to waiting')
        self._load_series()

    def action_snooze(self) -> None:
        """Snooze the selected series until a future date."""
        if not self._selected_series:
            return
        status = self._selected_series.get('status', 'new')
        if status not in ('new', 'reviewing', 'replied'):
            self.notify('Cannot snooze a series in this state', severity='warning')
            return
        self.push_screen(
            SnoozeScreen(last_source=self._last_snooze_source,
                         last_input=self._last_snooze_input,
                         subject=self._selected_series.get('subject', '')),
            callback=self._on_snooze_confirmed,
        )

    def _on_snooze_confirmed(self, result: Optional[Dict[str, str]]) -> None:
        """Handle snooze dialog result."""
        if result is None:
            return
        series = self._selected_series
        if not series:
            return
        change_id = series.get('change_id', '')
        revision = series.get('revision')
        previous_status = series.get('status', 'new')
        until_value = result['until']

        # Update tracking commit metadata
        topdir = b4.git_get_toplevel()
        review_branch = f'b4/review/{change_id}'
        if topdir and b4.git_branch_exists(topdir, review_branch):
            try:
                cover_text, tracking = b4.review.load_tracking(topdir, review_branch)
                trk_series = tracking.get('series', {})
                trk_series['status'] = 'snoozed'
                trk_series['snoozed'] = {
                    'until': until_value,
                    'previous_state': previous_status,
                }
                tracking['series'] = trk_series
                b4.review.save_tracking_ref(topdir, review_branch, cover_text, tracking)
            except (SystemExit, Exception) as ex:
                logger.warning('Could not update tracking commit: %s', ex)

        # Update database
        try:
            conn = b4.review.tracking.get_db(self._identifier)
            b4.review.tracking.snooze_series(conn, change_id, until_value,
                                             revision=revision)
            conn.close()
        except Exception as ex:
            self.notify(f'Error: {ex}', severity='error')
            return

        # Remember snooze choices for next time
        self._last_snooze_source = result.get('source', '')
        self._last_snooze_input = result.get('input', '')

        self.notify(f'Snoozed, {_format_snooze_until(until_value)}')
        self._load_series()

    def action_unsnooze(self) -> None:
        """Wake up a snoozed series, restoring its previous state."""
        if not self._selected_series:
            return
        if self._selected_series.get('status') != 'snoozed':
            return
        change_id = self._selected_series.get('change_id', '')
        revision = self._selected_series.get('revision')

        # Read previous state from tracking commit
        previous_status = 'reviewing'  # default fallback
        topdir = b4.git_get_toplevel()
        review_branch = f'b4/review/{change_id}'
        if topdir and b4.git_branch_exists(topdir, review_branch):
            try:
                previous_status = self._restore_snoozed_tracking(topdir, review_branch)
            except (SystemExit, Exception) as ex:
                logger.warning('Could not update tracking commit: %s', ex)

        # Update database
        try:
            conn = b4.review.tracking.get_db(self._identifier)
            b4.review.tracking.unsnooze_series(conn, change_id, previous_status,
                                               revision=revision)
            conn.close()
        except Exception as ex:
            self.notify(f'Error: {ex}', severity='error')
            return

        self.notify(f'Unsnoozed, restored to {previous_status}')
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
            ArchiveConfirmScreen(change_id, review_branch, has_branch,
                                 subject=self._selected_series.get('subject', '')),
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
            if not self._delete_review_branch(topdir, review_branch, notify=notify):
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
        if series.get('status', 'new') != 'accepted':
            self.notify('Series must be accepted before sending thanks', severity='warning')
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
            clean_subject = b4.LoreSubject(title).subject or title
            msgid = pmeta.get('header-info', {}).get('msgid', '')
            prefix = '%s/%s' % (str(pi + 1).zfill(padlen), expected)
            patches_tuples.append((clean_subject, '', msgid, prefix))
            patch_taken = pmeta.get('taken', {})
            cid = patch_taken.get('commit-id')
            if cid:
                commits.append((pi + 1, cid))
            else:
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

        # Compute checkurl from last taken commit for queue support
        checkurl: Optional[str] = None
        cidmask = config.get('thanks-commit-url-mask')
        if isinstance(cidmask, str) and cidmask and '%' in cidmask:
            # Find the last commit ID (highest patch index with a commit)
            last_cid: Optional[str] = None
            for _idx, cid in commits:
                if cid is not None:
                    last_cid = cid
            if last_cid:
                checkurl = cidmask % last_cid

        self._show_thank_preview(msg, checkurl=checkurl)

    def _show_thank_preview(self, msg: email.message.EmailMessage,
                            checkurl: Optional[str] = None) -> None:
        """Push the ThankScreen modal and handle edit/send/queue/cancel."""

        def _on_thank_result(result: Optional[str]) -> None:
            if result is None:
                return
            if result == '__EDIT__':
                self._edit_thank_message(msg, checkurl=checkurl)
            elif result == '__SEND__':
                self._send_thank_message(msg)
            elif result == '__QUEUE__' and checkurl:
                self._queue_thank_message(msg, checkurl)

        self.push_screen(ThankScreen(msg, checkurl=checkurl), _on_thank_result)

    def _edit_thank_message(self, msg: email.message.EmailMessage,
                            checkurl: Optional[str] = None) -> None:
        """Open the thank-you message in $EDITOR and re-show preview."""
        msg_bytes = msg.as_bytes(policy=b4.emlpolicy)
        try:
            with self.suspend():
                edited = b4.edit_in_editor(msg_bytes, filehint='thanks.eml')
        except Exception as ex:
            self.notify(f'Editor error: {ex}', severity='error')
            return
        new_msg = email.parser.BytesParser(policy=b4.emlpolicy).parsebytes(edited)
        self._show_thank_preview(new_msg, checkurl=checkurl)

    def _queue_thank_message(self, msg: email.message.EmailMessage, checkurl: str) -> None:
        """Queue the thanks message for delivery once commits are public."""
        import b4.ty

        series = self._selected_series
        if not series:
            return
        change_id = series.get('change_id', '')
        revision = series.get('revision', 1)
        try:
            b4.ty.queue_message(msg, checkurl,
                                change_id, revision,
                                dryrun=self._email_dryrun)
        except Exception as ex:
            self.notify(f'Failed to queue message: {ex}', severity='error')
            return

        self.notify('Queued — will send when commits are published')
        self._refresh_queue_indicator()

    def _send_thank_message(self, msg: email.message.EmailMessage) -> None:
        """Send the thank-you message via SMTP."""
        series = self._selected_series
        if not series:
            return
        try:
            with self.suspend():
                smtp, fromaddr = b4.get_smtp(dryrun=self._email_dryrun)
                sent = b4.send_mail(smtp, [msg], fromaddr=fromaddr,
                                    patatt_sign=self._patatt_sign, dryrun=self._email_dryrun,
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
                topdir = b4.git_get_toplevel()
                if topdir:
                    review_branch = f'b4/review/{change_id}'
                    b4.review.update_tracking_status(topdir, review_branch, 'thanked')
            self.notify('Thank-you message sent')
            self._load_series()
        except Exception as ex:
            self.notify(f'Send failed: {ex}', severity='error')

    def _refresh_queue_indicator(self) -> None:
        """Update the title-bar queue count and Q binding visibility."""
        import b4.ty
        self._queue_count = b4.ty.get_queued_count(dryrun=self._email_dryrun)
        try:
            right = self.query_one('#title-right', Static)
        except Exception:
            return
        if self._queue_count:
            right.update(f'{self._queue_count} queued ')
        else:
            right.update('')
        self.refresh_bindings()

    def action_process_queue(self) -> None:
        """Show the queue modal and optionally deliver."""
        import b4.ty
        entries = b4.ty.get_queued_messages(dryrun=self._email_dryrun)
        if not entries:
            self.notify('No queued thanks messages')
            return

        def _on_queue_result(result: Optional[str]) -> None:
            if result == '__DELIVER__':
                self._deliver_queue()

        self.push_screen(QueueScreen(entries), _on_queue_result)

    def _deliver_queue(self) -> None:
        """Push a delivery modal with progress bar."""

        def _on_delivery_result(result: Optional[Tuple[int, int, List[Tuple[str, int]]]]) -> None:
            if result is None:
                self.notify('Queue delivery cancelled or failed', severity='warning')
                self._refresh_queue_indicator()
                return
            delivered, pending, delivered_series = result
            # Mark delivered series as thanked
            for change_id, revision in delivered_series:
                if self._identifier and change_id:
                    try:
                        conn = b4.review.tracking.get_db(self._identifier)
                        b4.review.tracking.update_series_status(
                            conn, change_id, 'thanked', revision=revision)
                        conn.close()
                    except Exception as ex:
                        logger.warning('Could not update series status: %s', ex)
                    topdir = b4.git_get_toplevel()
                    if topdir:
                        review_branch = f'b4/review/{change_id}'
                        b4.review.update_tracking_status(topdir, review_branch, 'thanked')
            parts = []
            if delivered:
                parts.append(f'{delivered} delivered')
            if pending:
                parts.append(f'{pending} still pending')
            self.notify(', '.join(parts) if parts else 'Queue empty')
            self._refresh_queue_indicator()
            if delivered_series:
                self._load_series()

        self.push_screen(
            QueueDeliveryScreen(
                self._queue_count,
                dryrun=self._email_dryrun,
                patatt_sign=self._patatt_sign,
            ),
            _on_delivery_result,
        )

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

