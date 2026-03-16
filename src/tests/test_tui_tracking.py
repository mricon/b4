#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Integration tests for the TrackingApp TUI.

Uses real SQLite databases (via b4.review.tracking) and git repos
(via the gitdir fixture), but no network access.  Tests exercise
core user workflows: series listing, navigation, filtering,
status transitions, and modal interactions.
"""
import json
import os
import pathlib
import pytest

from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

import b4
import b4.review
import b4.review.tracking as tracking

from textual.widgets import Input, Label, ListView, Static

from b4.review_tui._tracking_app import TrackingApp, TrackedSeriesItem
from b4.review_tui._modals import (
    ActionScreen,
    ActionItem,
    ConfirmScreen,
    HelpScreen,
    LimitScreen,
    SetStateScreen,
    SnoozeScreen,
    TargetBranchScreen,
)


# ---------------------------------------------------------------------------
# Compat helper — Textual ≥ 1.0 (pip) uses Static.content,
# older builds (e.g. Fedora 43 package) still use Static.renderable.
# ---------------------------------------------------------------------------

def _static_text(widget: Any) -> str:
    """Return the text content of a Static widget across Textual versions."""
    if hasattr(widget, 'content'):
        return str(widget.content)
    return str(widget.renderable)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_db(identifier: str, series_list: List[Dict[str, Any]]) -> None:
    """Create and populate a tracking database with test series."""
    conn = tracking.init_db(identifier)
    for s in series_list:
        tracking.add_series_to_db(
            conn,
            change_id=s['change_id'],
            revision=s.get('revision', 1),
            subject=s.get('subject', '[PATCH] test'),
            sender_name=s.get('sender_name', 'Test Author'),
            sender_email=s.get('sender_email', 'author@example.com'),
            sent_at=s.get('sent_at', '2026-01-15T10:00:00+00:00'),
            message_id=s.get('message_id', f'{s["change_id"]}@example.com'),
            num_patches=s.get('num_patches', 1),
        )
        # Set status if specified (add_series_to_db always starts as 'new')
        status = s.get('status')
        if status and status != 'new':
            conn.execute(
                'UPDATE series SET status = ? WHERE change_id = ? AND revision = ?',
                (status, s['change_id'], s.get('revision', 1)),
            )
            conn.commit()
        # Set message counts if specified
        mc = s.get('message_count')
        if mc is not None:
            conn.execute(
                'UPDATE series SET message_count = ?, seen_message_count = ? '
                'WHERE change_id = ? AND revision = ?',
                (mc, s.get('seen_message_count', mc),
                 s['change_id'], s.get('revision', 1)),
            )
            conn.commit()
    conn.close()


def _create_review_branch(gitdir: str, change_id: str,
                          identifier: str = 'test-project',
                          revision: int = 1,
                          status: str = 'reviewing',
                          subject: str = 'Test series',
                          sender_name: str = 'Test Author',
                          sender_email: str = 'test@example.com') -> str:
    """Create a fake b4 review branch with a proper tracking commit.

    Returns the branch name.
    """
    branch_name = f'b4/review/{change_id}'
    # Get current HEAD as base
    ecode, base_sha = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
    assert ecode == 0
    base_sha = base_sha.strip()
    # Create the branch at HEAD
    ecode, _ = b4.git_run_command(gitdir, ['branch', branch_name, base_sha])
    assert ecode == 0
    # Build tracking metadata
    trk = {
        'series': {
            'identifier': identifier,
            'change-id': change_id,
            'revision': revision,
            'status': status,
            'subject': subject,
            'fromname': sender_name,
            'fromemail': sender_email,
            'expected': 1,
            'complete': True,
            'base-commit': base_sha,
            'prerequisite-commits': [],
            'first-patch-commit': base_sha,
            'header-info': {},
        },
        'followups': [],
        'patches': [],
    }
    commit_msg = f'{subject}\n\n{b4.review.make_review_magic_json(trk)}'
    # Create an empty tracking commit on the branch
    ecode, tree = b4.git_run_command(gitdir, ['rev-parse', f'{branch_name}^{{tree}}'])
    assert ecode == 0
    tree = tree.strip()
    ecode, new_sha = b4.git_run_command(
        gitdir, ['commit-tree', tree, '-p', base_sha],
        stdin=commit_msg.encode(),
    )
    assert ecode == 0
    new_sha = new_sha.strip()
    ecode, _ = b4.git_run_command(
        gitdir, ['update-ref', f'refs/heads/{branch_name}', new_sha])
    assert ecode == 0
    return branch_name


SAMPLE_SERIES: List[Dict[str, Any]] = [
    {
        'change_id': 'test-change-alpha',
        'subject': '[PATCH net-next] alpha: add widget support',
        'sender_name': 'Alice Author',
        'sender_email': 'alice@example.com',
        'sent_at': '2026-03-10T10:00:00+00:00',
        'message_id': 'alpha-v1@example.com',
        'num_patches': 3,
        'message_count': 5,
        'seen_message_count': 3,
    },
    {
        'change_id': 'test-change-bravo',
        'subject': '[PATCH drm] bravo: fix cursor rendering',
        'sender_name': 'Bob Builder',
        'sender_email': 'bob@example.com',
        'sent_at': '2026-03-09T08:00:00+00:00',
        'message_id': 'bravo-v1@example.com',
        'num_patches': 1,
    },
    {
        'change_id': 'test-change-charlie',
        'subject': '[PATCH v2 bpf] charlie: verifier refactor',
        'sender_name': 'Charlie Coder',
        'sender_email': 'charlie@example.com',
        'sent_at': '2026-03-08T12:00:00+00:00',
        'message_id': 'charlie-v2@example.com',
        'num_patches': 7,
        'revision': 2,
    },
]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestTrackingAppStartup:
    """Tests for the TrackingApp startup and series listing."""

    @pytest.mark.asyncio
    async def test_empty_database(self, tmp_path: pathlib.Path) -> None:
        """App should show empty message when no series are tracked."""
        _seed_db('test-empty', [])

        app = TrackingApp('test-empty')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # Should show the "no tracked series" message
            empty = app.query('#tracking-empty')
            assert len(empty) > 0

    @pytest.mark.asyncio
    async def test_series_listed(self, tmp_path: pathlib.Path) -> None:
        """App should display all seeded series."""
        _seed_db('test-listing', SAMPLE_SERIES)

        app = TrackingApp('test-listing')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            assert len(list(lv.children)) == 3

    @pytest.mark.asyncio
    async def test_title_shows_identifier_and_count(self, tmp_path: pathlib.Path) -> None:
        _seed_db('test-title', SAMPLE_SERIES)

        app = TrackingApp('test-title')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            title = app.query_one('#title-left', Static)
            assert 'test-title' in _static_text(title)

    @pytest.mark.asyncio
    async def test_series_sorted_by_added_at(self, tmp_path: pathlib.Path) -> None:
        """Series should appear newest-tracked-first (by added_at)."""
        _seed_db('test-sort', SAMPLE_SERIES)

        app = TrackingApp('test-sort')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            items = [c for c in lv.children if isinstance(c, TrackedSeriesItem)]
            # All are 'new' (actionable); sorted by added_at desc — last
            # inserted (charlie) appears first, first inserted (alpha) last.
            subjects = [i.series['subject'] for i in items]
            assert 'charlie' in subjects[0]
            assert 'bravo' in subjects[1]
            assert 'alpha' in subjects[2]


class TestTrackingNavigation:
    """Tests for keyboard navigation in the tracking list."""

    @pytest.mark.asyncio
    async def test_jk_navigation(self, tmp_path: pathlib.Path) -> None:
        _seed_db('test-nav', SAMPLE_SERIES)

        app = TrackingApp('test-nav')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            assert lv.index == 0

            await pilot.press('j')
            await pilot.pause()
            assert lv.index == 1

            await pilot.press('j')
            await pilot.pause()
            assert lv.index == 2

            await pilot.press('k')
            await pilot.pause()
            assert lv.index == 1

    @pytest.mark.asyncio
    async def test_help_opens_and_closes(self, tmp_path: pathlib.Path) -> None:
        _seed_db('test-help', SAMPLE_SERIES)

        app = TrackingApp('test-help')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()

            await pilot.press('question_mark')
            await pilot.pause()
            assert isinstance(app.screen, HelpScreen)

            await pilot.press('q')
            await pilot.pause()
            assert not isinstance(app.screen, HelpScreen)


class TestTrackingLimit:
    """Tests for the limit/filter functionality."""

    @pytest.mark.asyncio
    async def test_limit_filters_by_subject(self, tmp_path: pathlib.Path) -> None:
        _seed_db('test-limit', SAMPLE_SERIES)

        app = TrackingApp('test-limit')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            assert len(list(lv.children)) == 3

            # Open limit dialog and filter for 'drm'
            await pilot.press('l')
            await pilot.pause()
            assert isinstance(app.screen, LimitScreen)

            from textual.widgets import Input
            inp = app.screen.query_one('#limit-input', Input)
            inp.value = 'drm'
            await pilot.press('enter')
            await pilot.pause()

            # Should now show only the 'bravo' series
            lv = app.query_one('#tracking-list', ListView)
            items = [c for c in lv.children if isinstance(c, TrackedSeriesItem)]
            assert len(items) == 1
            assert 'bravo' in items[0].series['subject']

    @pytest.mark.asyncio
    async def test_limit_filters_by_sender(self, tmp_path: pathlib.Path) -> None:
        _seed_db('test-limit-sender', SAMPLE_SERIES)

        app = TrackingApp('test-limit-sender')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()

            await pilot.press('l')
            await pilot.pause()

            from textual.widgets import Input
            inp = app.screen.query_one('#limit-input', Input)
            inp.value = 'Charlie'
            await pilot.press('enter')
            await pilot.pause()

            lv = app.query_one('#tracking-list', ListView)
            items = [c for c in lv.children if isinstance(c, TrackedSeriesItem)]
            assert len(items) == 1
            assert 'charlie' in items[0].series['subject']

    @pytest.mark.asyncio
    async def test_clear_limit(self, tmp_path: pathlib.Path) -> None:
        _seed_db('test-limit-clear', SAMPLE_SERIES)

        app = TrackingApp('test-limit-clear')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()

            # Apply a filter
            await pilot.press('l')
            await pilot.pause()
            from textual.widgets import Input
            inp = app.screen.query_one('#limit-input', Input)
            inp.value = 'alpha'
            await pilot.press('enter')
            await pilot.pause()

            lv = app.query_one('#tracking-list', ListView)
            assert len([c for c in lv.children if isinstance(c, TrackedSeriesItem)]) == 1

            # Clear the filter
            await pilot.press('l')
            await pilot.pause()
            inp = app.screen.query_one('#limit-input', Input)
            inp.value = ''
            await pilot.press('enter')
            await pilot.pause()

            lv = app.query_one('#tracking-list', ListView)
            assert len([c for c in lv.children if isinstance(c, TrackedSeriesItem)]) == 3

    @pytest.mark.asyncio
    async def test_limit_title_shows_count(self, tmp_path: pathlib.Path) -> None:
        _seed_db('test-limit-title', SAMPLE_SERIES)

        app = TrackingApp('test-limit-title')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()

            await pilot.press('l')
            await pilot.pause()
            from textual.widgets import Input
            inp = app.screen.query_one('#limit-input', Input)
            inp.value = 'alpha'
            await pilot.press('enter')
            await pilot.pause()

            title = app.query_one('#title-left', Static)
            assert 'alpha' in _static_text(title)


class TestTrackingLimitPrefixes:
    """Tests for s: and t: prefix filters in the limit dialog."""

    @pytest.mark.asyncio
    async def test_limit_by_status(self, tmp_path: pathlib.Path) -> None:
        """s:snoozed should show only snoozed series."""
        _seed_db('test-limit-status', [
            {
                'change_id': 'ls-new',
                'subject': '[PATCH] new one',
                'message_id': 'lsn@ex.com',
            },
            {
                'change_id': 'ls-snoozed',
                'subject': '[PATCH] snoozed one',
                'status': 'snoozed',
                'message_id': 'lss@ex.com',
            },
        ])

        app = TrackingApp('test-limit-status')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('l')
            await pilot.pause()
            from textual.widgets import Input
            inp = app.screen.query_one('#limit-input', Input)
            inp.value = 's:snoozed'
            await pilot.press('enter')
            await pilot.pause()

            lv = app.query_one('#tracking-list', ListView)
            items = [c for c in lv.children if isinstance(c, TrackedSeriesItem)]
            assert len(items) == 1
            assert items[0].series['status'] == 'snoozed'

    def test_matches_limit_status_substring(self) -> None:
        """s:re should match both reviewing and replied."""
        m = TrackingApp._matches_limit
        assert m({'status': 'reviewing'}, 's:re')
        assert m({'status': 'replied'}, 's:re')
        assert not m({'status': 'new'}, 's:re')
        assert not m({'status': 'snoozed'}, 's:re')

    def test_matches_limit_target_branch(self) -> None:
        """t:next should match series with target_branch containing 'next'."""
        m = TrackingApp._matches_limit
        assert m({'target_branch': 'net-next'}, 't:next')
        assert m({'target_branch': 'bpf-next'}, 't:next')
        assert not m({'target_branch': 'bpf'}, 't:next')
        assert not m({'target_branch': None}, 't:next')
        assert not m({}, 't:next')

    def test_matches_limit_combined(self) -> None:
        """s:new bpf should match new series with 'bpf' in subject."""
        m = TrackingApp._matches_limit
        series_new_bpf = {'status': 'new', 'subject': '[PATCH bpf] fix verifier'}
        series_new_net = {'status': 'new', 'subject': '[PATCH net] fix routing'}
        series_snoozed_bpf = {'status': 'snoozed', 'subject': '[PATCH bpf] old'}
        assert m(series_new_bpf, 's:new bpf')
        assert not m(series_new_net, 's:new bpf')
        assert not m(series_snoozed_bpf, 's:new bpf')


class TestTrackingStatusGroups:
    """Tests for status grouping and display."""

    @pytest.mark.asyncio
    async def test_actionable_before_non_actionable(self, tmp_path: pathlib.Path) -> None:
        """Actionable series (new) should appear before non-actionable (snoozed).

        We use only statuses that don't require a real review branch
        (new, snoozed) to avoid the background rescan worker marking
        them as 'gone'.
        """
        mixed_series = [
            {
                'change_id': 'snoozed-1',
                'subject': '[PATCH] snoozed series',
                'status': 'snoozed',
                'sent_at': '2026-03-10T11:00:00+00:00',
                'message_id': 'snoozed@ex.com',
            },
            {
                'change_id': 'new-2',
                'subject': '[PATCH] new series B',
                'sent_at': '2026-03-10T09:00:00+00:00',
                'message_id': 'new2@ex.com',
            },
            {
                'change_id': 'new-1',
                'subject': '[PATCH] new series A',
                'sent_at': '2026-03-10T10:00:00+00:00',
                'message_id': 'new1@ex.com',
            },
        ]
        _seed_db('test-groups', mixed_series)

        app = TrackingApp('test-groups')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            items = [c for c in lv.children if isinstance(c, TrackedSeriesItem)]
            statuses = [i.series['status'] for i in items]
            # actionable (new) before non-actionable (snoozed); within new, by added_at desc
            assert statuses == ['new', 'new', 'snoozed']
            assert 'new series A' in items[0].series['subject']
            assert 'new series B' in items[1].series['subject']

    @pytest.mark.asyncio
    async def test_archived_not_shown(self, tmp_path: pathlib.Path) -> None:
        """Archived series should be excluded from the list."""
        series_with_archived = [
            {
                'change_id': 'visible-1',
                'subject': '[PATCH] visible',
                'message_id': 'vis@ex.com',
            },
            {
                'change_id': 'archived-1',
                'subject': '[PATCH] archived',
                'status': 'archived',
                'message_id': 'arch@ex.com',
            },
        ]
        _seed_db('test-archived', series_with_archived)

        app = TrackingApp('test-archived')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            items = [c for c in lv.children if isinstance(c, TrackedSeriesItem)]
            assert len(items) == 1
            assert items[0].series['change_id'] == 'visible-1'


class TestTrackingFocusChangeId:
    """Tests for the focus_change_id startup parameter."""

    @pytest.mark.asyncio
    async def test_focus_on_specific_series(self, tmp_path: pathlib.Path) -> None:
        _seed_db('test-focus', SAMPLE_SERIES)

        app = TrackingApp('test-focus', focus_change_id='test-change-charlie')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            assert lv.index == 0  # charlie is 1st (last inserted, added_at desc)


class TestTrackingQuit:
    """Tests for quitting the app."""

    @pytest.mark.asyncio
    async def test_q_exits(self, tmp_path: pathlib.Path) -> None:
        _seed_db('test-quit', SAMPLE_SERIES)

        app = TrackingApp('test-quit')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('q')
            await pilot.pause()
            # App should have exited (return value is None)
            assert app.return_value is None


# ---------------------------------------------------------------------------
# Tests with real git repos (review branches)
# ---------------------------------------------------------------------------

class TestTrackingWithReviewBranch:
    """Tests that use the gitdir fixture for real review branches."""

    @pytest.mark.asyncio
    async def test_reviewing_status_with_branch(self, gitdir: str) -> None:
        """Series with a real review branch should appear as 'reviewing'."""
        identifier = 'test-reviewing'
        change_id = 'test-review-branch-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] series with review branch',
            'status': 'reviewing',
            'message_id': 'review-branch-1@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            items = [c for c in lv.children if isinstance(c, TrackedSeriesItem)]
            assert len(items) == 1
            assert items[0].series['status'] == 'reviewing'

    @pytest.mark.asyncio
    async def test_review_exits_app_with_branch_name(self, gitdir: str) -> None:
        """Pressing 'r' on a reviewing series should exit with branch name."""
        identifier = 'test-review-exit'
        change_id = 'test-exit-branch'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] exit test',
            'status': 'reviewing',
            'message_id': 'exit@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('r')
            await pilot.pause()
            # App should exit with the branch name
            assert app.return_value == f'b4/review/{change_id}'

    @pytest.mark.asyncio
    async def test_enter_on_reviewing_exits_to_review(self, gitdir: str) -> None:
        """Enter on a 'reviewing' series should go directly to review mode."""
        identifier = 'test-enter-review'
        change_id = 'test-enter-branch'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] enter test',
            'status': 'reviewing',
            'message_id': 'enter@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('enter')
            await pilot.pause()
            assert app.return_value == f'b4/review/{change_id}'

    @pytest.mark.asyncio
    async def test_waiting_to_reviewing_on_review(self, gitdir: str) -> None:
        """Pressing 'r' on a waiting series should change it to reviewing."""
        identifier = 'test-wait-review'
        change_id = 'test-waiting-branch'
        _create_review_branch(gitdir, change_id, identifier=identifier,
                              status='waiting')
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] waiting test',
            'status': 'waiting',
            'message_id': 'waiting@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # The action menu should appear for 'waiting' via Enter
            await pilot.press('r')
            await pilot.pause()
            # App exits to review mode
            assert app.return_value == f'b4/review/{change_id}'

            # Verify status was updated in DB
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT status FROM series WHERE change_id = ?',
                (change_id,))
            row = cursor.fetchone()
            conn.close()
            assert row[0] == 'reviewing'

    @pytest.mark.asyncio
    async def test_messages_marked_seen_on_review(self, gitdir: str) -> None:
        """Entering review should mark all messages as seen."""
        identifier = 'test-seen'
        change_id = 'test-seen-branch'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] seen test',
            'status': 'reviewing',
            'message_id': 'seen@ex.com',
            'message_count': 10,
            'seen_message_count': 3,
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('r')
            await pilot.pause()

            # Verify message counts are equal in DB
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT message_count, seen_message_count FROM series WHERE change_id = ?',
                (change_id,))
            row = cursor.fetchone()
            conn.close()
            assert row[0] == row[1]  # seen should equal total


class TestTrackingActionMenu:
    """Tests for the context-sensitive action menu."""

    @pytest.mark.asyncio
    async def test_action_menu_for_new_series(self, tmp_path: pathlib.Path) -> None:
        """New series should show review/abandon/snooze actions."""
        _seed_db('test-action-new', [{
            'change_id': 'new-action-1',
            'subject': '[PATCH] new action test',
            'message_id': 'action-new@ex.com',
        }])

        app = TrackingApp('test-action-new')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)

            # Check available actions
            lv = app.screen.query_one('#action-list', ListView)
            from b4.review_tui._modals import ActionItem
            actions = [c.key for c in lv.children if isinstance(c, ActionItem)]
            assert 'review' in actions
            assert 'abandon' in actions
            assert 'snooze' in actions
            # These should NOT be available for 'new'
            assert 'take' not in actions
            assert 'rebase' not in actions

            # Cancel
            await pilot.press('escape')
            await pilot.pause()
            assert not isinstance(app.screen, ActionScreen)

    @pytest.mark.asyncio
    async def test_action_menu_for_reviewing(self, gitdir: str) -> None:
        """Reviewing series should show take/rebase/waiting/snooze actions."""
        identifier = 'test-action-reviewing'
        change_id = 'reviewing-action-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] reviewing action test',
            'status': 'reviewing',
            'message_id': 'action-rev@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)

            lv = app.screen.query_one('#action-list', ListView)
            from b4.review_tui._modals import ActionItem
            actions = [c.key for c in lv.children if isinstance(c, ActionItem)]
            assert 'take' in actions
            assert 'rebase' in actions
            assert 'waiting' in actions
            assert 'snooze' in actions

            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_action_menu_for_snoozed(self, tmp_path: pathlib.Path) -> None:
        """Snoozed series should show unsnooze/abandon actions."""
        _seed_db('test-action-snoozed', [{
            'change_id': 'snoozed-action-1',
            'subject': '[PATCH] snoozed action test',
            'status': 'snoozed',
            'message_id': 'action-snz@ex.com',
        }])

        app = TrackingApp('test-action-snoozed')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)

            lv = app.screen.query_one('#action-list', ListView)
            from b4.review_tui._modals import ActionItem
            actions = [c.key for c in lv.children if isinstance(c, ActionItem)]
            assert 'unsnooze' in actions
            assert 'abandon' in actions
            # Should NOT have take/rebase/snooze
            assert 'take' not in actions
            assert 'snooze' not in actions

            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_enter_on_new_opens_action_menu(self, tmp_path: pathlib.Path) -> None:
        """Enter on a 'new' series should open action menu (not review)."""
        _seed_db('test-enter-new', [{
            'change_id': 'enter-new-1',
            'subject': '[PATCH] enter new test',
            'message_id': 'enter-new@ex.com',
        }])

        app = TrackingApp('test-enter-new')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('enter')
            await pilot.pause()
            # Should open action menu, not exit the app
            assert isinstance(app.screen, ActionScreen)

            await pilot.press('escape')


class TestTrackingUpgradeNewSeries:
    """Tests for upgrading a new (not checked-out) series to a newer revision."""

    @pytest.mark.asyncio
    async def test_action_menu_shows_upgrade_for_new_with_newer(
            self, tmp_path: pathlib.Path) -> None:
        """New series with a newer revision available should offer upgrade."""
        identifier = 'test-upgrade-new'
        change_id = 'upgrade-new-1'
        conn = tracking.init_db(identifier)
        tracking.add_series_to_db(
            conn, change_id=change_id, revision=12,
            subject='[PATCH v12] test upgrade',
            sender_name='Test', sender_email='t@ex.com',
            sent_at='2026-01-15T10:00:00+00:00',
            message_id='v12@ex.com', num_patches=2)
        # Add v13 to the revisions table so has_newer is set
        tracking.add_revision(conn, change_id, 13, 'v13@ex.com',
                              subject='[PATCH v13] test upgrade')
        conn.close()

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)
            lv = app.screen.query_one('#action-list', ListView)
            from b4.review_tui._modals import ActionItem
            actions = [c.key for c in lv.children if isinstance(c, ActionItem)]
            assert 'upgrade' in actions
            assert 'review' in actions
            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_action_menu_no_upgrade_without_newer(
            self, tmp_path: pathlib.Path) -> None:
        """New series without newer revisions should not offer upgrade."""
        _seed_db('test-upgrade-none', [{
            'change_id': 'upgrade-none-1',
            'subject': '[PATCH] no newer test',
            'message_id': 'only@ex.com',
        }])

        app = TrackingApp('test-upgrade-none')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)
            lv = app.screen.query_one('#action-list', ListView)
            from b4.review_tui._modals import ActionItem
            actions = [c.key for c in lv.children if isinstance(c, ActionItem)]
            assert 'upgrade' not in actions
            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_upgrade_switches_revision(
            self, tmp_path: pathlib.Path) -> None:
        """Upgrade on a new series should update the DB to the newer revision."""
        identifier = 'test-upgrade-switch'
        change_id = 'upgrade-switch-1'
        conn = tracking.init_db(identifier)
        tracking.add_series_to_db(
            conn, change_id=change_id, revision=12,
            subject='[PATCH v12] switch test',
            sender_name='Test', sender_email='t@ex.com',
            sent_at='2026-01-15T10:00:00+00:00',
            message_id='v12@ex.com', num_patches=2)
        # Set message counts so we can verify they get reset
        conn.execute(
            'UPDATE series SET message_count = 6, seen_message_count = 4'
            ' WHERE change_id = ?', (change_id,))
        conn.commit()
        tracking.add_revision(conn, change_id, 13, 'v13@ex.com',
                              subject='[PATCH v13] switch test')
        conn.close()

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)

            # Select 'upgrade' — it should be in the list
            lv = app.screen.query_one('#action-list', ListView)
            from b4.review_tui._modals import ActionItem
            for child in lv.children:
                if isinstance(child, ActionItem) and child.key == 'upgrade':
                    lv.index = lv.children.index(child)
                    break
            await pilot.press('enter')
            await pilot.pause()

            # Verify the DB was updated to v13 with counts reset
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT revision, message_id, message_count,'
                ' seen_message_count FROM series'
                ' WHERE change_id = ?', (change_id,))
            row = cursor.fetchone()
            conn.close()
            assert row is not None
            assert row[0] == 13
            assert row[1] == 'v13@ex.com'
            assert row[2] is None  # message_count reset
            assert row[3] is None  # seen_message_count reset


class TestTrackingSnooze:
    """Tests for the snooze workflow."""

    @pytest.mark.asyncio
    async def test_snooze_new_series(self, tmp_path: pathlib.Path) -> None:
        """Snoozing a new series should update the database."""
        identifier = 'test-snooze'
        _seed_db(identifier, [{
            'change_id': 'snooze-test-1',
            'subject': '[PATCH] snooze me',
            'message_id': 'snooze@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()

            # Open action menu and select snooze
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)
            await pilot.press('s')  # shortcut for snooze
            await pilot.pause()

            # Should now be on SnoozeScreen
            assert isinstance(app.screen, SnoozeScreen)

            # Enter a tag snooze
            tag_input = app.screen.query_one('#snooze-tag', Input)
            tag_input.value = 'v6.15-rc1'
            await pilot.press('ctrl+y')
            await pilot.pause()

            # Should be back on main screen
            assert not isinstance(app.screen, SnoozeScreen)

            # Verify DB was updated
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT status, snoozed_until FROM series WHERE change_id = ?',
                ('snooze-test-1',))
            row = cursor.fetchone()
            conn.close()
            assert row[0] == 'snoozed'
            assert row[1] == 'tag:v6.15-rc1'

    @pytest.mark.asyncio
    async def test_snooze_cancel(self, tmp_path: pathlib.Path) -> None:
        """Cancelling snooze should leave the series unchanged."""
        identifier = 'test-snooze-cancel'
        _seed_db(identifier, [{
            'change_id': 'snooze-cancel-1',
            'subject': '[PATCH] do not snooze',
            'message_id': 'nosnooze@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            await pilot.press('s')
            await pilot.pause()
            assert isinstance(app.screen, SnoozeScreen)

            await pilot.press('escape')
            await pilot.pause()

            # Verify status unchanged
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT status FROM series WHERE change_id = ?',
                ('snooze-cancel-1',))
            row = cursor.fetchone()
            conn.close()
            assert row[0] == 'new'

    @pytest.mark.asyncio
    async def test_snooze_with_review_branch(self, gitdir: str) -> None:
        """Snoozing a reviewing series should also update the tracking commit."""
        identifier = 'test-snooze-branch'
        change_id = 'snooze-branch-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] snooze branch test',
            'status': 'reviewing',
            'message_id': 'snzbr@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            await pilot.press('s')
            await pilot.pause()
            assert isinstance(app.screen, SnoozeScreen)

            dur_input = app.screen.query_one('#snooze-duration', Input)
            dur_input.value = '2w'
            await pilot.press('ctrl+y')
            await pilot.pause()

            # Verify DB
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT status FROM series WHERE change_id = ?',
                (change_id,))
            row = cursor.fetchone()
            conn.close()
            assert row[0] == 'snoozed'

            # Verify tracking commit was updated
            cover_text, trk = b4.review.load_tracking(
                gitdir, f'b4/review/{change_id}')
            assert trk['series']['status'] == 'snoozed'
            assert 'snoozed' in trk['series']
            assert trk['series']['snoozed']['previous_state'] == 'reviewing'


class TestTrackingAbandon:
    """Tests for the abandon workflow."""

    @pytest.mark.asyncio
    async def test_abandon_new_series(self, tmp_path: pathlib.Path) -> None:
        """Abandoning a new series should remove it from the DB."""
        identifier = 'test-abandon'
        _seed_db(identifier, [
            {
                'change_id': 'keep-1',
                'subject': '[PATCH] keep me',
                'sent_at': '2026-03-10T11:00:00+00:00',
                'message_id': 'keep@ex.com',
            },
            {
                'change_id': 'abandon-1',
                'subject': '[PATCH] abandon me',
                'sent_at': '2026-03-10T12:00:00+00:00',
                'message_id': 'abandon@ex.com',
            },
        ])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # First series is 'abandon-1' (last inserted, added_at desc)
            assert app._selected_series is not None
            assert app._selected_series['change_id'] == 'abandon-1'

            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)

            # Select 'abandon' from the menu
            await pilot.press('A')  # shortcut for abandon
            await pilot.pause()

            # Should show confirm dialog
            assert isinstance(app.screen, ConfirmScreen)

            await pilot.press('y')
            await pilot.pause()

            # Verify the abandoned series is gone from DB
            conn = tracking.get_db(identifier)
            cursor = conn.execute('SELECT change_id FROM series')
            remaining = [row[0] for row in cursor.fetchall()]
            conn.close()
            assert 'keep-1' in remaining
            assert 'abandon-1' not in remaining

    @pytest.mark.asyncio
    async def test_abandon_cancel(self, tmp_path: pathlib.Path) -> None:
        """Cancelling abandon should leave the series intact."""
        identifier = 'test-abandon-cancel'
        _seed_db(identifier, [{
            'change_id': 'noabandon-1',
            'subject': '[PATCH] do not abandon',
            'message_id': 'noabandon@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            await pilot.press('A')
            await pilot.pause()
            assert isinstance(app.screen, ConfirmScreen)

            await pilot.press('escape')
            await pilot.pause()

            # Still in DB
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT change_id FROM series WHERE change_id = ?',
                ('noabandon-1',))
            assert cursor.fetchone() is not None
            conn.close()

    @pytest.mark.asyncio
    async def test_abandon_with_branch_deletes_branch(self, gitdir: str) -> None:
        """Abandoning a series with a review branch should delete the branch."""
        identifier = 'test-abandon-branch'
        change_id = 'abandon-branch-1'
        branch_name = _create_review_branch(
            gitdir, change_id, identifier=identifier)
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] abandon with branch',
            'status': 'reviewing',
            'message_id': 'abr@ex.com',
        }])

        # Verify branch exists before
        assert b4.git_branch_exists(gitdir, branch_name)

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            # For reviewing, abandon is in the action list
            assert isinstance(app.screen, ActionScreen)
            await pilot.press('A')
            await pilot.pause()
            assert isinstance(app.screen, ConfirmScreen)
            await pilot.press('y')
            await pilot.pause()

            # Branch should be gone
            assert not b4.git_branch_exists(gitdir, branch_name)

            # DB should be clean
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT change_id FROM series WHERE change_id = ?',
                (change_id,))
            assert cursor.fetchone() is None
            conn.close()


class TestTrackingWaiting:
    """Tests for the 'mark as waiting' workflow."""

    @pytest.mark.asyncio
    async def test_mark_as_waiting(self, gitdir: str) -> None:
        """Marking a reviewing series as waiting should update DB and tracking."""
        identifier = 'test-waiting'
        change_id = 'waiting-test-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] wait for v2',
            'status': 'reviewing',
            'message_id': 'wait@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)

            await pilot.press('w')  # shortcut for waiting
            await pilot.pause()

            # Verify DB status
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT status FROM series WHERE change_id = ?',
                (change_id,))
            row = cursor.fetchone()
            conn.close()
            assert row[0] == 'waiting'

            # Verify tracking commit
            cover_text, trk = b4.review.load_tracking(
                gitdir, f'b4/review/{change_id}')
            assert trk['series']['status'] == 'waiting'

    @pytest.mark.asyncio
    async def test_mark_new_as_waiting(self, gitdir: str) -> None:
        """Marking a new (unimported) series as waiting should update DB only."""
        identifier = 'test-new-waiting'
        change_id = 'new-waiting-1'
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] needs v2',
            'message_id': 'newwait@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)

            await pilot.press('w')  # shortcut for waiting
            await pilot.pause()

            # Verify DB status changed
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT status FROM series WHERE change_id = ?',
                (change_id,))
            row = cursor.fetchone()
            conn.close()
            assert row[0] == 'waiting'


class TestTrackingDetailPanel:
    """Tests for the detail panel shown on series highlight."""

    @pytest.mark.asyncio
    async def test_detail_panel_shows_on_highlight(self, tmp_path: pathlib.Path) -> None:
        _seed_db('test-detail', SAMPLE_SERIES)

        app = TrackingApp('test-detail')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()

            from textual.containers import Vertical
            panel = app.query_one('#details-panel', Vertical)
            # Panel should have non-zero height (auto-shown on first highlight)
            assert panel.styles.height is not None

    @pytest.mark.asyncio
    async def test_detail_panel_hides_on_escape(self, tmp_path: pathlib.Path) -> None:
        _seed_db('test-detail-hide', SAMPLE_SERIES)

        app = TrackingApp('test-detail-hide')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()

            await pilot.press('escape')
            await pilot.pause()

            from textual.containers import Vertical
            panel = app.query_one('#details-panel', Vertical)
            assert panel.styles.height.value == 0  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_detail_panel_updates_on_navigation(self, tmp_path: pathlib.Path) -> None:
        """Navigating to a different series should update the detail panel."""
        _seed_db('test-detail-nav', SAMPLE_SERIES)

        app = TrackingApp('test-detail-nav')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # Should be showing charlie details (last inserted, added_at desc)
            assert app._selected_series is not None
            assert 'charlie' in app._selected_series.get('subject', '')

            await pilot.press('j')
            await pilot.pause()
            assert app._selected_series is not None
            assert 'bravo' in app._selected_series.get('subject', '')

            await pilot.press('j')
            await pilot.pause()
            assert app._selected_series is not None
            assert 'alpha' in app._selected_series.get('subject', '')


class TestTrackingMultipleSeries:
    """Tests for workflows involving multiple series."""

    @pytest.mark.asyncio
    async def test_mixed_statuses_with_branches(self, gitdir: str) -> None:
        """App should correctly display a mix of new and reviewing series."""
        identifier = 'test-mixed'
        change_id_rev = 'mixed-reviewing-1'
        _create_review_branch(gitdir, change_id_rev, identifier=identifier,
                              subject='Reviewing series')
        _seed_db(identifier, [
            {
                'change_id': change_id_rev,
                'subject': '[PATCH] reviewing series',
                'status': 'reviewing',
                'sent_at': '2026-03-10T12:00:00+00:00',
                'message_id': 'rev@ex.com',
            },
            {
                'change_id': 'mixed-new-1',
                'subject': '[PATCH] new series',
                'sent_at': '2026-03-10T11:00:00+00:00',
                'message_id': 'new@ex.com',
            },
            {
                'change_id': 'mixed-snoozed-1',
                'subject': '[PATCH] snoozed series',
                'status': 'snoozed',
                'sent_at': '2026-03-10T10:00:00+00:00',
                'message_id': 'snz@ex.com',
            },
        ])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            items = [c for c in lv.children if isinstance(c, TrackedSeriesItem)]
            assert len(items) == 3

            statuses = [i.series['status'] for i in items]
            # Both reviewing and new are actionable (top), snoozed is not (bottom).
            # Within actionable, sorted by added_at desc (new inserted after reviewing).
            assert statuses[0] == 'new'
            assert statuses[1] == 'reviewing'
            assert statuses[2] == 'snoozed'

    @pytest.mark.asyncio
    async def test_navigate_and_review_second_series(self, gitdir: str) -> None:
        """Navigate to a non-first series and enter review mode."""
        identifier = 'test-nav-review'
        change_id = 'nav-review-target'
        _create_review_branch(gitdir, change_id, identifier=identifier,
                              subject='Target series')
        _seed_db(identifier, [
            {
                'change_id': 'nav-review-first',
                'subject': '[PATCH] first (new)',
                'sent_at': '2026-03-10T12:00:00+00:00',
                'message_id': 'first@ex.com',
            },
            {
                'change_id': change_id,
                'subject': '[PATCH] target (reviewing)',
                'status': 'reviewing',
                'sent_at': '2026-03-10T11:00:00+00:00',
                'message_id': 'target@ex.com',
            },
        ])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            # Active series (reviewing) comes first in the list
            items = [c for c in lv.children if isinstance(c, TrackedSeriesItem)]
            assert items[0].series['status'] == 'reviewing'

            # It's already highlighted at index 0, press r
            await pilot.press('r')
            await pilot.pause()
            assert app.return_value == f'b4/review/{change_id}'


class TestTrackingSnoozeRemembersChoice:
    """Tests for snooze remembering last choices within a session."""

    @pytest.mark.asyncio
    async def test_snooze_remembers_last_input(self, tmp_path: pathlib.Path) -> None:
        """Second snooze should pre-populate with the first snooze's input."""
        identifier = 'test-snooze-memory'
        _seed_db(identifier, [
            {
                'change_id': 'mem-1',
                'subject': '[PATCH] first',
                'message_id': 'mem1@ex.com',
            },
            {
                'change_id': 'mem-2',
                'subject': '[PATCH] second',
                'message_id': 'mem2@ex.com',
            },
        ])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()

            # Snooze the first series with a tag
            await pilot.press('a')
            await pilot.pause()
            await pilot.press('s')
            await pilot.pause()
            tag_input = app.screen.query_one('#snooze-tag', Input)
            tag_input.value = 'v6.15-rc3'
            await pilot.press('ctrl+y')
            await pilot.pause()
            await pilot.pause()

            # Move to the other (non-snoozed) series before snoozing it.
            # The cursor may still be on the just-snoozed item, so press
            # down then up to ensure we land on a non-snoozed item.
            first_cid = app._selected_series.get('change_id') if app._selected_series else None
            if app._selected_series and app._selected_series.get('status') == 'snoozed':
                await pilot.press('down')
                await pilot.pause()
                # If down didn't change, try up
                if app._selected_series and app._selected_series.get('change_id') == first_cid:
                    await pilot.press('up')
                    await pilot.pause()

            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)
            await pilot.press('s')
            await pilot.pause()
            assert isinstance(app.screen, SnoozeScreen)
            # The tag field should be pre-populated
            tag_input = app.screen.query_one('#snooze-tag', Input)
            assert tag_input.value == 'v6.15-rc3'

            await pilot.press('escape')


# ---------------------------------------------------------------------------
# Lifecycle / state-machine tests
# ---------------------------------------------------------------------------

def _get_db_status(identifier: str, change_id: str) -> str:
    """Read the current status of a series from the tracking database."""
    conn = tracking.get_db(identifier)
    cursor = conn.execute(
        'SELECT status FROM series WHERE change_id = ?',
        (change_id,))
    row = cursor.fetchone()
    conn.close()
    assert row is not None, f'Series {change_id} not found in DB'
    return str(row[0])


def _get_action_keys(app: TrackingApp) -> List[str]:
    """Get the list of action keys from the currently-open ActionScreen."""
    assert isinstance(app.screen, ActionScreen)
    lv = app.screen.query_one('#action-list', ListView)
    return [c.key for c in lv.children if isinstance(c, ActionItem)]


class TestSeriesLifecycle:
    """End-to-end lifecycle: new → reviewing → waiting → reviewing
    → snoozed → unsnoozed → accepted (seeded) → archived (mocked).

    Drives every transition that the TUI can perform headlessly, and
    seeds the DB directly for transitions requiring network or
    external processes (take, thank).
    """

    @pytest.mark.asyncio
    async def test_full_lifecycle(self, gitdir: str) -> None:
        """Drive a single series through the reviewing → waiting →
        reviewing → snoozed → unsnoozed → accepted → archived lifecycle.

        We start from 'reviewing' because new → reviewing requires
        network calls (_checkout_new_series).  For accepted → archived
        we mock _archive_branch to avoid tar/file I/O.
        """
        identifier = 'test-lifecycle'
        change_id = 'lifecycle-series-1'
        branch_name = f'b4/review/{change_id}'

        # Seed series as 'reviewing' with a real review branch
        _create_review_branch(gitdir, change_id, identifier=identifier,
                              status='reviewing')
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] lifecycle test series',
            'sender_name': 'Lifecycle Author',
            'sender_email': 'lifecycle@example.com',
            'status': 'reviewing',
            'message_id': 'lifecycle@ex.com',
        }])

        # === Phase 1: reviewing → waiting ===
        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # Verify action menu for 'reviewing'
            await pilot.press('a')
            await pilot.pause()
            actions = _get_action_keys(app)
            assert 'take' in actions
            assert 'rebase' in actions
            assert 'waiting' in actions
            assert 'snooze' in actions
            assert 'abandon' in actions
            # Select 'waiting'
            await pilot.press('w')
            await pilot.pause()

        assert _get_db_status(identifier, change_id) == 'waiting'

        # Verify tracking commit also updated
        cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        assert trk['series']['status'] == 'waiting'

        # === Phase 2: waiting → reviewing (re-review) ===
        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # Verify action menu for 'waiting'
            await pilot.press('a')
            await pilot.pause()
            actions = _get_action_keys(app)
            assert 'review' in actions
            assert 'abandon' in actions
            assert 'archive' in actions
            assert 'take' not in actions
            assert 'snooze' not in actions
            await pilot.press('escape')
            await pilot.pause()

            # Press 'r' to re-review → exits app
            await pilot.press('r')
            await pilot.pause()
            assert app.return_value == branch_name

        assert _get_db_status(identifier, change_id) == 'reviewing'

        # === Phase 3: reviewing → snoozed ===
        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            await pilot.press('s')  # snooze shortcut
            await pilot.pause()
            assert isinstance(app.screen, SnoozeScreen)

            tag_input = app.screen.query_one('#snooze-tag', Input)
            tag_input.value = 'v6.15-rc1'
            await pilot.press('ctrl+y')
            await pilot.pause()

        assert _get_db_status(identifier, change_id) == 'snoozed'

        # Verify tracking commit stores previous_state
        cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        assert trk['series']['status'] == 'snoozed'
        assert trk['series']['snoozed']['previous_state'] == 'reviewing'

        # === Phase 4: snoozed → unsnoozed (back to reviewing) ===
        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # Verify action menu for 'snoozed'
            await pilot.press('a')
            await pilot.pause()
            actions = _get_action_keys(app)
            assert 'unsnooze' in actions
            assert 'abandon' in actions
            assert 'archive' in actions
            assert 'snooze' not in actions
            assert 'take' not in actions

            # Select 'unsnooze' via shortcut
            await pilot.press('u')
            await pilot.pause()

        assert _get_db_status(identifier, change_id) == 'reviewing'

        # Verify tracking commit restored
        cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        assert trk['series']['status'] == 'reviewing'
        assert 'snoozed' not in trk['series']

        # === Phase 5: reviewing → accepted (seed directly) ===
        # The real 'take' flow needs suspend + am + editor, so we seed.
        conn = tracking.get_db(identifier)
        conn.execute(
            'UPDATE series SET status = ? WHERE change_id = ?',
            ('accepted', change_id))
        conn.commit()
        conn.close()
        # Also update the tracking commit
        b4.review.update_tracking_status(gitdir, branch_name, 'accepted')

        # === Phase 6: verify 'accepted' action menu ===
        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            actions = _get_action_keys(app)
            assert 'thank' in actions
            assert 'abandon' in actions
            assert 'archive' in actions
            # Should NOT have take/snooze/etc, but review is allowed
            assert 'review' in actions
            assert 'take' not in actions
            assert 'snooze' not in actions
            assert 'waiting' not in actions
            await pilot.press('escape')

        # === Phase 7: accepted → archived (mock _archive_branch) ===
        def _mock_archive(self_app: TrackingApp, cid: str,
                          rev: Optional[int], rbranch: str,
                          pw_series_id: Optional[int] = None,
                          notify: bool = True) -> bool:
            """Simplified archive: just update DB status."""
            aconn = tracking.get_db(self_app._identifier)
            tracking.update_series_status(aconn, cid, 'archived',
                                          revision=rev)
            aconn.close()
            return True

        app = TrackingApp(identifier)
        with patch.object(TrackingApp, '_archive_branch', _mock_archive):
            async with app.run_test(size=(120, 30)) as pilot:
                await pilot.pause()
                await pilot.press('a')
                await pilot.pause()
                actions = _get_action_keys(app)
                assert 'archive' in actions
                # Select 'archive'
                await pilot.press('x')  # shortcut for archive
                await pilot.pause()
                # Should show confirmation dialog
                assert isinstance(app.screen, ConfirmScreen)
                await pilot.press('y')
                await pilot.pause()

        assert _get_db_status(identifier, change_id) == 'archived'

    @pytest.mark.asyncio
    async def test_new_directly_to_snoozed(self, tmp_path: pathlib.Path) -> None:
        """A new series can be snoozed without ever entering review."""
        identifier = 'test-lifecycle-snooze-new'
        change_id = 'direct-snooze-1'
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] snooze from new',
            'message_id': 'ds@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            await pilot.press('s')
            await pilot.pause()
            assert isinstance(app.screen, SnoozeScreen)
            dur_input = app.screen.query_one('#snooze-duration', Input)
            dur_input.value = '3d'
            await pilot.press('ctrl+y')
            await pilot.pause()

        assert _get_db_status(identifier, change_id) == 'snoozed'

    @pytest.mark.asyncio
    async def test_thanked_to_archived(self, gitdir: str) -> None:
        """A thanked series can only be archived."""
        identifier = 'test-lifecycle-thanked'
        change_id = 'thanked-series-1'
        _create_review_branch(gitdir, change_id, identifier=identifier,
                              status='thanked')
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] thanked ready for archive',
            'status': 'thanked',
            'message_id': 'thanked@ex.com',
        }])

        # Verify action menu: only 'archive' should be available
        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            actions = _get_action_keys(app)
            assert actions == ['archive']

            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_accepted_action_menu(self, gitdir: str) -> None:
        """Accepted series should show review, thank, abandon, and archive."""
        identifier = 'test-lifecycle-accepted'
        change_id = 'accepted-menu-1'
        _create_review_branch(gitdir, change_id, identifier=identifier,
                              status='accepted')
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] accepted series menu test',
            'status': 'accepted',
            'message_id': 'acc@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            actions = _get_action_keys(app)
            assert set(actions) == {'review', 'thank', 'abandon', 'archive'}
            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_gone_series_actions(self, tmp_path: pathlib.Path) -> None:
        """A 'gone' series (branch deleted externally) should allow
        review and abandon."""
        identifier = 'test-lifecycle-gone'
        _seed_db(identifier, [{
            'change_id': 'gone-1',
            'subject': '[PATCH] gone series',
            'status': 'gone',
            'message_id': 'gone@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            actions = _get_action_keys(app)
            assert actions == ['review', 'abandon']
            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_snooze_roundtrip_preserves_previous_state(self, gitdir: str) -> None:
        """Unsnooze should restore the previous state stored in tracking.

        We seed a series as 'snoozed' with previous_state='waiting' in
        the tracking commit, then unsnooze via the TUI and verify it
        restores to 'waiting' (not the default 'reviewing').
        """
        identifier = 'test-lifecycle-snooze-wait'
        change_id = 'snooze-wait-1'
        branch_name = f'b4/review/{change_id}'
        # Create branch with 'snoozed' status + snoozed metadata
        _create_review_branch(gitdir, change_id, identifier=identifier,
                              status='snoozed')
        # Manually inject snoozed.previous_state into tracking commit
        cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        trk['series']['snoozed'] = {
            'until': 'tag:v99',
            'previous_state': 'waiting',
        }
        b4.review.save_tracking_ref(gitdir, branch_name, cover_text, trk)

        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] waiting then snoozed',
            'status': 'snoozed',
            'message_id': 'sw@ex.com',
        }])

        # Unsnooze should restore to 'waiting'
        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            await pilot.press('u')
            await pilot.pause()

        assert _get_db_status(identifier, change_id) == 'waiting'

        # Verify tracking commit cleaned up
        cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        assert trk['series']['status'] == 'waiting'
        assert 'snoozed' not in trk['series']

    @pytest.mark.asyncio
    async def test_abandon_from_any_branch_state(self, gitdir: str) -> None:
        """Abandon should work from reviewing, waiting, and snoozed states."""
        for status in ('reviewing', 'snoozed'):
            identifier = f'test-lifecycle-abandon-{status}'
            change_id = f'abandon-{status}'
            _create_review_branch(gitdir, change_id, identifier=identifier,
                                  status=status)
            _seed_db(identifier, [{
                'change_id': change_id,
                'subject': f'[PATCH] abandon from {status}',
                'status': status,
                'message_id': f'ab-{status}@ex.com',
            }])

            app = TrackingApp(identifier)
            async with app.run_test(size=(120, 30)) as pilot:
                await pilot.pause()
                await pilot.press('a')
                await pilot.pause()
                actions = _get_action_keys(app)
                assert 'abandon' in actions, f'abandon missing for {status}'
                await pilot.press('A')  # abandon shortcut
                await pilot.pause()
                assert isinstance(app.screen, ConfirmScreen)
                await pilot.press('y')
                await pilot.pause()

            # Verify series removed from DB
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT change_id FROM series WHERE change_id = ?',
                (change_id,))
            assert cursor.fetchone() is None, \
                f'Series should be gone after abandon from {status}'
            conn.close()

            # Verify branch deleted
            branch_name = f'b4/review/{change_id}'
            assert not b4.git_branch_exists(gitdir, branch_name), \
                f'Branch should be deleted after abandon from {status}'


@patch('b4.review.tracking.get_review_target_branches', return_value=['master'])
class TestTargetBranch:
    """Tests for per-series target branch tracking."""

    @pytest.mark.asyncio
    async def test_set_target_branch_from_new(self, _mock_branches: Any, gitdir: str) -> None:
        """Press t on a new series, type a branch, confirm — DB is updated."""
        identifier = 'test-target-new'
        change_id = 'target-new-1'
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] target branch test',
            'message_id': 'target-new@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # Press t to open target branch dialog
            await pilot.press('t')
            await pilot.pause()
            assert isinstance(app.screen, TargetBranchScreen)

            # Type branch name and confirm
            inp = app.screen.query_one('#target-branch-input', Input)
            inp.value = 'master'
            await pilot.pause()
            # Use ctrl+y to confirm
            with patch('b4.git_branch_exists', return_value=True):
                await pilot.press('ctrl+y')
            await pilot.pause()

            # Verify DB updated
            conn = tracking.get_db(identifier)
            target = tracking.get_target_branch(conn, change_id)
            conn.close()
            assert target == 'master'

    @pytest.mark.asyncio
    async def test_set_target_branch_from_reviewing(self, _mock_branches: Any, gitdir: str) -> None:
        """Set target on a reviewing series — tracking commit updated too."""
        identifier = 'test-target-rev'
        change_id = 'target-rev-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] target reviewing test',
            'status': 'reviewing',
            'message_id': 'target-rev@ex.com',
        }])

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('t')
            await pilot.pause()
            assert isinstance(app.screen, TargetBranchScreen)

            inp = app.screen.query_one('#target-branch-input', Input)
            inp.value = 'master'
            await pilot.pause()
            with patch('b4.git_branch_exists', return_value=True):
                await pilot.press('ctrl+y')
            await pilot.pause()

            # Verify DB updated
            conn = tracking.get_db(identifier)
            target = tracking.get_target_branch(conn, change_id)
            conn.close()
            assert target == 'master'

            # Verify tracking commit updated
            review_branch = f'b4/review/{change_id}'
            _cover, trk = b4.review.load_tracking(gitdir, review_branch)
            assert trk['series'].get('target-branch') == 'master'

    @pytest.mark.asyncio
    async def test_target_branch_in_details(self, gitdir: str) -> None:
        """Verify detail panel shows Target: row when target is set."""
        identifier = 'test-target-detail'
        change_id = 'target-detail-1'
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] target detail test',
            'message_id': 'target-detail@ex.com',
        }])
        # Set target in DB
        conn = tracking.get_db(identifier)
        tracking.update_target_branch(conn, change_id, 'sound/for-next')
        conn.close()

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # Detail panel should be visible after selecting series
            target_widget = app.query_one('#detail-target', Static)
            text = _static_text(target_widget)
            assert 'sound/for-next' in text

    @pytest.mark.asyncio
    async def test_clear_target_branch(self, _mock_branches: Any, gitdir: str) -> None:
        """Ctrl+d in modal clears the target branch."""
        identifier = 'test-target-clear'
        change_id = 'target-clear-1'
        _seed_db(identifier, [{
            'change_id': change_id,
            'subject': '[PATCH] clear target test',
            'message_id': 'target-clear@ex.com',
        }])
        # Set target first
        conn = tracking.get_db(identifier)
        tracking.update_target_branch(conn, change_id, 'old-branch')
        conn.close()

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('t')
            await pilot.pause()
            assert isinstance(app.screen, TargetBranchScreen)
            # Ctrl+d to clear
            await pilot.press('ctrl+d')
            await pilot.pause()
            await pilot.pause()

            # Screen should be dismissed
            assert not isinstance(app.screen, TargetBranchScreen)

            # Verify DB cleared
            conn = tracking.get_db(identifier)
            target = tracking.get_target_branch(conn, change_id)
            conn.close()
            assert target is None
