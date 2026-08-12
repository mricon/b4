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

import email.message
import os
import pathlib
import sqlite3
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest.mock import patch

import pytest

pytest.importorskip('textual')

from textual.widgets import Footer, Input, ListView, Static

import b4
import b4.review
import b4.review.tracking as tracking
import b4.review_tui._entry as _entry
from b4 import (
    _abort_worktree_op,
    _worktree_has_unmerged,
    _worktree_inprogress_op,
    _worktree_merge_in_progress,
)
from b4.review_tui._modals import (
    ActionItem,
    ActionScreen,
    BaseSelectionScreen,
    CherryPickScreen,
    ConfirmScreen,
    HelpScreen,
    LimitScreen,
    LinkRevisionScreen,
    RebaseScreen,
    SnoozeScreen,
    TakeConfirmScreen,
    TargetBranchScreen,
)
from b4.review_tui._tracking_app import (
    TrackedSeriesItem,
    TrackingApp,
    _build_base_suggestions,
    _detect_initial_base,
    _effective_tier,
    _resolve_worktree_take_conflict,
    _shazam_merge_flags,
    _take_worktree,
    _TakeWorktree,
    _worktree_for_branch,
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
                (
                    mc,
                    s.get('seen_message_count', mc),
                    s['change_id'],
                    s.get('revision', 1),
                ),
            )
            conn.commit()
    conn.close()


def _create_review_branch(
    gitdir: str,
    change_id: str,
    identifier: str = 'test-project',
    revision: int = 1,
    status: str = 'reviewing',
    subject: str = 'Test series',
    sender_name: str = 'Test Author',
    sender_email: str = 'test@example.com',
    with_patch: bool = False,
) -> str:
    """Create a fake b4 review branch with a proper tracking commit.

    With ``with_patch``, a real patch commit modifying file1.txt sits
    between the base and the tracking commit, and the tracking metadata
    describes it.  Returns the branch name.
    """
    branch_name = f'b4/review/{change_id}'
    # Get current HEAD as base
    ecode, base_sha = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
    assert ecode == 0
    base_sha = base_sha.strip()
    # Create the branch at HEAD
    ecode, _ = b4.git_run_command(gitdir, ['branch', branch_name, base_sha])
    assert ecode == 0
    parent_sha = base_sha
    patches: List[Dict[str, Any]] = []
    if with_patch:
        ecode, _ = b4.git_run_command(gitdir, ['checkout', branch_name])
        assert ecode == 0
        with open(os.path.join(gitdir, 'file1.txt'), 'a') as fh:
            fh.write(f'{change_id} tweak\n')
        b4.git_run_command(gitdir, ['add', 'file1.txt'])
        ecode, _ = b4.git_run_command(
            gitdir, ['commit', '-m', f'{change_id}: tweak file1']
        )
        assert ecode == 0
        ecode, parent_sha = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        parent_sha = parent_sha.strip()
        ecode, _ = b4.git_run_command(gitdir, ['checkout', 'master'])
        assert ecode == 0
        patches = [{'title': f'{change_id}: tweak file1', 'link': ''}]
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
            'first-patch-commit': parent_sha,
            'header-info': {},
        },
        'followups': [],
        'patches': patches,
    }
    commit_msg = f'{subject}\n\n{b4.review.make_review_magic_json(trk)}'
    # Create an empty tracking commit on the branch
    ecode, tree = b4.git_run_command(gitdir, ['rev-parse', f'{branch_name}^{{tree}}'])
    assert ecode == 0
    tree = tree.strip()
    ecode, new_sha = b4.git_run_command(
        gitdir,
        ['commit-tree', tree, '-p', parent_sha],
        stdin=commit_msg.encode(),
    )
    assert ecode == 0
    new_sha = new_sha.strip()
    ecode, _ = b4.git_run_command(
        gitdir, ['update-ref', f'refs/heads/{branch_name}', new_sha]
    )
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
    async def test_series_listed_newest_first(self, tmp_path: pathlib.Path) -> None:
        """App should display all seeded series, newest-tracked-first."""
        _seed_db('test-listing', SAMPLE_SERIES)

        app = TrackingApp('test-listing')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            items = [c for c in lv.children if isinstance(c, TrackedSeriesItem)]
            # All are 'new' (actionable); sorted by added_at desc — last
            # inserted (charlie) appears first, first inserted (alpha) last.
            subjects = [i.series['subject'] for i in items]
            assert len(subjects) == 3
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
    async def test_refresh_preserves_scroll_position(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A list rebuild (e.g. after 'u') must not scroll the viewport."""
        many = [
            {
                'change_id': f'test-change-{i:02d}',
                'subject': f'[PATCH] series {i:02d}',
                'sender_name': f'Author {i:02d}',
                'sender_email': f'a{i:02d}@example.com',
                'sent_at': f'2026-03-{(i % 27) + 1:02d}T10:00:00+00:00',
                'message_id': f'series-{i:02d}-v1@example.com',
            }
            for i in range(40)
        ]
        _seed_db('test-scroll', many)

        app = TrackingApp('test-scroll')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            # Move deep enough into the list that the view scrolls down,
            # then back up a bit so the cursor sits mid-viewport rather
            # than at the bottom edge (which a minimal scroll-into-view
            # after the rebuild would happen to reproduce).
            lv.index = 30
            await pilot.pause()
            await pilot.pause()
            lv.index = 26
            await pilot.pause()
            await pilot.pause()
            scroll_before = round(lv.scroll_y)
            assert scroll_before > 0
            assert app._selected_series is not None
            change_id = app._selected_series['change_id']

            # Reload the same way _on_update_complete does after 'u'
            app._focus_change_id = change_id
            app._invalidate_caches()
            app._load_series()
            await pilot.pause()
            await pilot.pause()
            await pilot.pause()

            new_lv = app.query_one('#tracking-list', ListView)
            assert new_lv is not lv
            assert new_lv.index == 26
            assert round(new_lv.scroll_y) == scroll_before
            assert round(new_lv.vertical_scrollbar.position) == scroll_before
            assert app._selected_series is not None
            assert app._selected_series['change_id'] == change_id

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


class TestRefreshListWithoutFooter:
    """Regression test for the Footer mount race (flaky NoMatches).

    Under load, a queued _refresh_list callback can run while the
    Footer is not (yet, or no longer) mounted; _refresh_list must
    rebuild the list rather than crash with NoMatches.
    """

    @pytest.mark.asyncio
    async def test_refresh_survives_missing_footer(
        self, tmp_path: pathlib.Path
    ) -> None:
        _seed_db('test-nofooter', SAMPLE_SERIES)

        app = TrackingApp('test-nofooter')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()

            await app.query_one(Footer).remove()
            await app._refresh_list()
            await pilot.pause()

            lv = app.query_one('#tracking-list', ListView)
            items = [c for c in lv.children if isinstance(c, TrackedSeriesItem)]
            assert len(items) == 3


class TestTrackingLimit:
    """Tests for the limit/filter functionality."""

    @staticmethod
    async def _apply_limit(pilot: Any, app: TrackingApp, value: str) -> None:
        """Open the limit dialog, enter value, and apply it."""
        await pilot.press('l')
        await pilot.pause()
        assert isinstance(app.screen, LimitScreen)
        inp = app.screen.query_one('#limit-input', Input)
        inp.value = value
        await pilot.press('enter')
        await pilot.pause()

    @staticmethod
    def _items(app: TrackingApp) -> List[TrackedSeriesItem]:
        lv = app.query_one('#tracking-list', ListView)
        return [c for c in lv.children if isinstance(c, TrackedSeriesItem)]

    @pytest.mark.asyncio
    async def test_limit_apply_and_clear(self, tmp_path: pathlib.Path) -> None:
        """Limits filter by subject and sender, show in the title, and clear."""
        _seed_db('test-limit', SAMPLE_SERIES)

        app = TrackingApp('test-limit')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            assert len(self._items(app)) == 3

            # Filter by subject substring; the active limit shows in the title
            await self._apply_limit(pilot, app, 'drm')
            items = self._items(app)
            assert len(items) == 1
            assert 'bravo' in items[0].series['subject']
            title = app.query_one('#title-left', Static)
            assert 'drm' in _static_text(title)

            # Filter by sender name
            await self._apply_limit(pilot, app, 'Charlie')
            items = self._items(app)
            assert len(items) == 1
            assert 'charlie' in items[0].series['subject']

            # Clearing the limit restores the full list
            await self._apply_limit(pilot, app, '')
            assert len(self._items(app)) == 3


class TestTrackingLimitPrefixes:
    """Tests for s: and t: prefix filters in the limit dialog."""

    @pytest.mark.asyncio
    async def test_limit_by_status(self, tmp_path: pathlib.Path) -> None:
        """s:snoozed should show only snoozed series."""
        _seed_db(
            'test-limit-status',
            [
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
            ],
        )

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

    @pytest.mark.parametrize(
        'series,limit,expected',
        [
            # s: matches on status substring (s:re → reviewing, replied)
            pytest.param({'status': 'reviewing'}, 's:re', True, id='s-reviewing'),
            pytest.param({'status': 'replied'}, 's:re', True, id='s-replied'),
            pytest.param({'status': 'new'}, 's:re', False, id='s-new'),
            pytest.param({'status': 'snoozed'}, 's:re', False, id='s-snoozed'),
            # t: matches on target_branch substring
            pytest.param(
                {'target_branch': 'net-next'}, 't:next', True, id='t-net-next'
            ),
            pytest.param(
                {'target_branch': 'bpf-next'}, 't:next', True, id='t-bpf-next'
            ),
            pytest.param({'target_branch': 'bpf'}, 't:next', False, id='t-bpf'),
            pytest.param({'target_branch': None}, 't:next', False, id='t-none'),
            pytest.param({}, 't:next', False, id='t-unset'),
            # s: composes with bare tokens (subject) under AND logic
            pytest.param(
                {'status': 'new', 'subject': '[PATCH bpf] fix verifier'},
                's:new bpf',
                True,
                id='and-both-match',
            ),
            pytest.param(
                {'status': 'new', 'subject': '[PATCH net] fix routing'},
                's:new bpf',
                False,
                id='and-subject-differs',
            ),
            pytest.param(
                {'status': 'snoozed', 'subject': '[PATCH bpf] old'},
                's:new bpf',
                False,
                id='and-status-differs',
            ),
            # up: keeps only series with a newer revision available;
            # truthy variants behave the same as a bare `up:`
            pytest.param({'has_newer': True}, 'up:', True, id='up-has-newer'),
            pytest.param({'has_newer': False}, 'up:', False, id='up-no-newer'),
            pytest.param({}, 'up:', False, id='up-unset'),
            pytest.param({'has_newer': True}, 'up:yes', True, id='up-yes'),
            pytest.param({'has_newer': True}, 'up:1', True, id='up-1'),
            # up:no / up:0 invert, hiding upgradable series
            pytest.param({'has_newer': True}, 'up:no', False, id='up-no-inverts'),
            pytest.param({'has_newer': False}, 'up:no', True, id='up-no-keeps'),
            pytest.param({}, 'up:0', True, id='up-0-unset'),
            # up: composes with other tokens under AND logic
            pytest.param(
                {'status': 'waiting', 'has_newer': True},
                's:waiting up:',
                True,
                id='up-and-status-match',
            ),
            pytest.param(
                {'status': 'waiting', 'has_newer': False},
                's:waiting up:',
                False,
                id='up-and-no-newer',
            ),
            pytest.param(
                {'status': 'reviewing', 'has_newer': True},
                's:waiting up:',
                False,
                id='up-and-status-differs',
            ),
        ],
    )
    def test_matches_limit(
        self, series: Dict[str, Any], limit: str, expected: bool
    ) -> None:
        assert bool(TrackingApp._matches_limit(series, limit)) is expected


class TestEffectiveTier:
    """Tests for _effective_tier — waiting series wake into the actionable tier."""

    @pytest.mark.parametrize(
        'series,tier',
        [
            # Plain statuses match their status tier
            pytest.param({'status': 'new'}, 0, id='new'),
            pytest.param({'status': 'reviewing'}, 0, id='reviewing'),
            pytest.param({'status': 'partial'}, 0, id='partial'),
            pytest.param({'status': 'replied'}, 1, id='replied'),
            pytest.param({'status': 'accepted'}, 1, id='accepted'),
            pytest.param({'status': 'snoozed'}, 2, id='snoozed'),
            pytest.param({'status': 'gone'}, 2, id='gone'),
            # Waiting stays inactive until the awaited revision arrives,
            # then rejoins tier 0
            pytest.param({'status': 'waiting'}, 2, id='waiting'),
            pytest.param(
                {'status': 'waiting', 'has_newer': False}, 2, id='waiting-no-newer'
            ),
            pytest.param(
                {'status': 'waiting', 'has_newer': True}, 0, id='waiting-woken'
            ),
            # Only waiting is woken; a newer revision alone doesn't
            # reorder other statuses
            pytest.param(
                {'status': 'snoozed', 'has_newer': True}, 2, id='snoozed-has-newer'
            ),
            pytest.param(
                {'status': 'accepted', 'has_newer': True}, 1, id='accepted-has-newer'
            ),
            # A queued (accepted) series keeps its queued tier regardless
            pytest.param({'status': 'accepted', 'queued': True}, 2, id='queued'),
        ],
    )
    def test_effective_tier(self, series: Dict[str, Any], tier: int) -> None:
        assert _effective_tier(series) == tier


class TestTrackingStatusGroups:
    """Tests for status grouping and display."""

    @pytest.mark.asyncio
    async def test_actionable_before_non_actionable(
        self, tmp_path: pathlib.Path
    ) -> None:
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
    async def test_waiting_with_newer_wakes_into_actionable_tier(
        self, gitdir: str
    ) -> None:
        """A waiting series whose awaited revision arrived rejoins tier 0.

        Waiting normally sits in the inactive tier at the bottom, but once a
        newer revision is known (has_newer) the upgrade it was waiting for is
        available — so it sorts above inactive series and is no longer dimmed.

        The waiting series keeps its review branch (parked from reviewing);
        a branchless waiting series would be marked 'gone' on rescan instead.
        The comparison series is snoozed, which is exempt from gone-marking so
        it can safely stay branchless.
        """
        identifier = 'test-groups-wake'
        _create_review_branch(
            gitdir, 'waiting-w', identifier=identifier, status='waiting'
        )
        _seed_db(
            identifier,
            [
                {
                    'change_id': 'snoozed-w',
                    'subject': '[PATCH] snoozed series',
                    'status': 'snoozed',
                    'sent_at': '2026-03-10T12:00:00+00:00',
                    'message_id': 'snz-w@ex.com',
                },
                {
                    'change_id': 'waiting-w',
                    'subject': '[PATCH] waiting series',
                    'status': 'waiting',
                    'sent_at': '2026-03-10T09:00:00+00:00',
                    'message_id': 'wait-w@ex.com',
                },
            ],
        )
        # Record a v2 for the waiting series so has_newer is computed at load.
        conn = tracking.get_db(identifier)
        tracking.add_revision(
            conn,
            'waiting-w',
            2,
            'wait-w-v2@ex.com',
            subject='[PATCH v2] waiting series',
        )
        conn.close()

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            lv = app.query_one('#tracking-list', ListView)
            items = [c for c in lv.children if isinstance(c, TrackedSeriesItem)]
            by_cid = {i.series['change_id']: i for i in items}
            assert set(by_cid) == {'waiting-w', 'snoozed-w'}
            waiting_item = by_cid['waiting-w']
            snoozed_item = by_cid['snoozed-w']
            # The woken waiting series sorts into the actionable tier, above
            # the snoozed one, despite its older sent_at.
            assert items.index(waiting_item) < items.index(snoozed_item)
            assert waiting_item.series['status'] == 'waiting'
            assert waiting_item.series.get('has_newer') is True
            # ...and it is no longer rendered as non-actionable (undimmed).
            assert not waiting_item.has_class('non-actionable')
            assert snoozed_item.has_class('non-actionable')

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
    async def test_q_warns_and_capital_q_exits(self, tmp_path: pathlib.Path) -> None:
        _seed_db('test-quit', SAMPLE_SERIES)

        app = TrackingApp('test-quit')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('q')
            await pilot.pause()
            # Bare 'q' must not quit; it shows a hint pointing at 'Q'
            assert app._exit is False
            messages = [n.message for n in app._notifications]
            assert any("'Q'" in m for m in messages)

            await pilot.press('Q')
            await pilot.pause()
            assert app._exit is True


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
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] series with review branch',
                    'status': 'reviewing',
                    'message_id': 'review-branch-1@ex.com',
                }
            ],
        )

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
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] exit test',
                    'status': 'reviewing',
                    'message_id': 'exit@ex.com',
                }
            ],
        )

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
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] enter test',
                    'status': 'reviewing',
                    'message_id': 'enter@ex.com',
                }
            ],
        )

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
        _create_review_branch(
            gitdir, change_id, identifier=identifier, status='waiting'
        )
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] waiting test',
                    'status': 'waiting',
                    'message_id': 'waiting@ex.com',
                }
            ],
        )

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
                'SELECT status FROM series WHERE change_id = ?', (change_id,)
            )
            row = cursor.fetchone()
            conn.close()
            assert row[0] == 'reviewing'

    @pytest.mark.asyncio
    async def test_messages_marked_seen_on_review(self, gitdir: str) -> None:
        """Entering review should mark all messages as seen."""
        identifier = 'test-seen'
        change_id = 'test-seen-branch'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] seen test',
                    'status': 'reviewing',
                    'message_id': 'seen@ex.com',
                    'message_count': 10,
                    'seen_message_count': 3,
                }
            ],
        )

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('r')
            await pilot.pause()

            # Verify message counts are equal in DB
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT message_count, seen_message_count FROM series WHERE change_id = ?',
                (change_id,),
            )
            row = cursor.fetchone()
            conn.close()
            assert row[0] == row[1]  # seen should equal total


class TestTrackingActionMenu:
    """Tests for the context-sensitive action menu."""

    @pytest.mark.asyncio
    async def test_action_menu_for_new_series(self, tmp_path: pathlib.Path) -> None:
        """New series should show review/abandon/snooze actions."""
        _seed_db(
            'test-action-new',
            [
                {
                    'change_id': 'new-action-1',
                    'subject': '[PATCH] new action test',
                    'message_id': 'action-new@ex.com',
                }
            ],
        )

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
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] reviewing action test',
                    'status': 'reviewing',
                    'message_id': 'action-rev@ex.com',
                }
            ],
        )

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
        _seed_db(
            'test-action-snoozed',
            [
                {
                    'change_id': 'snoozed-action-1',
                    'subject': '[PATCH] snoozed action test',
                    'status': 'snoozed',
                    'message_id': 'action-snz@ex.com',
                }
            ],
        )

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
        _seed_db(
            'test-enter-new',
            [
                {
                    'change_id': 'enter-new-1',
                    'subject': '[PATCH] enter new test',
                    'message_id': 'enter-new@ex.com',
                }
            ],
        )

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
        self, tmp_path: pathlib.Path
    ) -> None:
        """New series with a newer revision available should offer upgrade."""
        identifier = 'test-upgrade-new'
        change_id = 'upgrade-new-1'
        conn = tracking.init_db(identifier)
        tracking.add_series_to_db(
            conn,
            change_id=change_id,
            revision=12,
            subject='[PATCH v12] test upgrade',
            sender_name='Test',
            sender_email='t@ex.com',
            sent_at='2026-01-15T10:00:00+00:00',
            message_id='v12@ex.com',
            num_patches=2,
        )
        # Add v13 to the revisions table so has_newer is set
        tracking.add_revision(
            conn, change_id, 13, 'v13@ex.com', subject='[PATCH v13] test upgrade'
        )
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
        self, tmp_path: pathlib.Path
    ) -> None:
        """New series without newer revisions should not offer upgrade."""
        _seed_db(
            'test-upgrade-none',
            [
                {
                    'change_id': 'upgrade-none-1',
                    'subject': '[PATCH] no newer test',
                    'message_id': 'only@ex.com',
                }
            ],
        )

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
    async def test_upgrade_switches_revision(self, tmp_path: pathlib.Path) -> None:
        """Upgrade on a new series should update the DB to the newer revision."""
        identifier = 'test-upgrade-switch'
        change_id = 'upgrade-switch-1'
        conn = tracking.init_db(identifier)
        tracking.add_series_to_db(
            conn,
            change_id=change_id,
            revision=12,
            subject='[PATCH v12] switch test',
            sender_name='Test',
            sender_email='t@ex.com',
            sent_at='2026-01-15T10:00:00+00:00',
            message_id='v12@ex.com',
            num_patches=2,
        )
        # Set message counts so we can verify they get reset
        conn.execute(
            'UPDATE series SET message_count = 6, seen_message_count = 4'
            ' WHERE change_id = ?',
            (change_id,),
        )
        conn.commit()
        tracking.add_revision(
            conn, change_id, 13, 'v13@ex.com', subject='[PATCH v13] switch test'
        )
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
                ' WHERE change_id = ?',
                (change_id,),
            )
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
        _seed_db(
            identifier,
            [
                {
                    'change_id': 'snooze-test-1',
                    'subject': '[PATCH] snooze me',
                    'message_id': 'snooze@ex.com',
                }
            ],
        )

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
            # https://github.com/python/mypy/issues/9457:
            # app.screen is stale-narrowed across await.
            conn = tracking.get_db(identifier)  # type: ignore[unreachable]
            cursor = conn.execute(
                'SELECT status, snoozed_until FROM series WHERE change_id = ?',
                ('snooze-test-1',),
            )
            row = cursor.fetchone()
            conn.close()
            assert row[0] == 'snoozed'
            assert row[1] == 'tag:v6.15-rc1'

    @pytest.mark.asyncio
    async def test_snooze_cancel(self, tmp_path: pathlib.Path) -> None:
        """Cancelling snooze should leave the series unchanged."""
        identifier = 'test-snooze-cancel'
        _seed_db(
            identifier,
            [
                {
                    'change_id': 'snooze-cancel-1',
                    'subject': '[PATCH] do not snooze',
                    'message_id': 'nosnooze@ex.com',
                }
            ],
        )

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
                'SELECT status FROM series WHERE change_id = ?', ('snooze-cancel-1',)
            )
            row = cursor.fetchone()
            conn.close()
            assert row[0] == 'new'

    @pytest.mark.asyncio
    async def test_snooze_with_review_branch(self, gitdir: str) -> None:
        """Snoozing a reviewing series should also update the tracking commit."""
        identifier = 'test-snooze-branch'
        change_id = 'snooze-branch-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] snooze branch test',
                    'status': 'reviewing',
                    'message_id': 'snzbr@ex.com',
                }
            ],
        )

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
                'SELECT status FROM series WHERE change_id = ?', (change_id,)
            )
            row = cursor.fetchone()
            conn.close()
            assert row[0] == 'snoozed'

            # Verify tracking commit was updated
            _cover_text, trk = b4.review.load_tracking(gitdir, f'b4/review/{change_id}')
            assert trk['series']['status'] == 'snoozed'
            assert 'snoozed' in trk['series']
            assert trk['series']['snoozed']['previous_state'] == 'reviewing'


class TestTrackingUpgradeGating:
    """Upgrade availability is gated on has_newer, orthogonal to status.

    Regression coverage for the cluster reported by Mark Brown: a series
    parked as 'waiting' (08646dc) or stuck at 'partial' (cc3f07d) could not
    reach the upgrade action, forcing a manual 'return to reviewing' first.
    Upgrade is now offered and enabled from any state once a newer revision
    is known.
    """

    def _seed_with_newer(self, identifier: str, change_id: str, status: str) -> None:
        """Seed a v1 series in *status* with a v2 recorded (so has_newer)."""
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] gating test',
                    'status': status,
                    'message_id': 'v1@ex.com',
                }
            ],
        )
        conn = tracking.get_db(identifier)
        tracking.add_revision(
            conn, change_id, 2, 'v2@ex.com', subject='[PATCH v2] gating test'
        )
        conn.close()

    @pytest.mark.asyncio
    async def test_waiting_series_offers_and_enables_upgrade(self, gitdir: str) -> None:
        """A waiting series with a newer revision offers upgrade in the menu."""
        identifier = 'test-upgrade-waiting'
        change_id = 'upgrade-waiting-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        self._seed_with_newer(identifier, change_id, 'waiting')

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # check_action gate is has_newer alone, regardless of status.
            assert app.check_action('update_revision', ()) is True
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)
            lv = app.screen.query_one('#action-list', ListView)
            from b4.review_tui._modals import ActionItem

            actions = [c.key for c in lv.children if isinstance(c, ActionItem)]
            assert 'upgrade' in actions
            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_partial_series_offers_and_enables_upgrade(self, gitdir: str) -> None:
        """A partial series with a newer revision offers upgrade (cc3f07d)."""
        identifier = 'test-upgrade-partial'
        change_id = 'upgrade-partial-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        self._seed_with_newer(identifier, change_id, 'partial')

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            assert app.check_action('update_revision', ()) is True
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)
            lv = app.screen.query_one('#action-list', ListView)
            from b4.review_tui._modals import ActionItem

            actions = [c.key for c in lv.children if isinstance(c, ActionItem)]
            assert 'upgrade' in actions
            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_waiting_without_newer_has_no_upgrade(self, gitdir: str) -> None:
        """A waiting series with no newer revision must not offer upgrade."""
        identifier = 'test-upgrade-waiting-none'
        change_id = 'upgrade-waiting-none-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] no newer',
                    'status': 'waiting',
                    'message_id': 'only@ex.com',
                }
            ],
        )

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            assert app.check_action('update_revision', ()) is False
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)
            lv = app.screen.query_one('#action-list', ListView)
            from b4.review_tui._modals import ActionItem

            actions = [c.key for c in lv.children if isinstance(c, ActionItem)]
            assert 'upgrade' not in actions
            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_waiting_without_branch_switches_revision_in_db(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Upgrading a branchless waiting series takes the DB-only path.

        A series parked as 'waiting' straight from 'new' has no review
        branch, so the upgrade advances the tracked revision in the database
        rather than running the git upgrade workflow.
        """
        identifier = 'test-upgrade-waiting-nobranch'
        change_id = 'upgrade-waiting-nobranch-1'
        self._seed_with_newer(identifier, change_id, 'waiting')

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_update_revision()
            await pilot.pause()

            conn = tracking.get_db(identifier)
            row = conn.execute(
                'SELECT revision FROM series WHERE change_id = ?', (change_id,)
            ).fetchone()
            conn.close()
            assert row[0] == 2


class TestTrackingAbandon:
    """Tests for the abandon workflow."""

    @pytest.mark.asyncio
    async def test_abandon_new_series(self, tmp_path: pathlib.Path) -> None:
        """Abandoning a new series should remove it from the DB."""
        identifier = 'test-abandon'
        _seed_db(
            identifier,
            [
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
            ],
        )

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
        _seed_db(
            identifier,
            [
                {
                    'change_id': 'noabandon-1',
                    'subject': '[PATCH] do not abandon',
                    'message_id': 'noabandon@ex.com',
                }
            ],
        )

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
                'SELECT change_id FROM series WHERE change_id = ?', ('noabandon-1',)
            )
            assert cursor.fetchone() is not None
            conn.close()

    @pytest.mark.asyncio
    async def test_abandon_with_branch_deletes_branch(self, gitdir: str) -> None:
        """Abandoning a series with a review branch should delete the branch."""
        identifier = 'test-abandon-branch'
        change_id = 'abandon-branch-1'
        branch_name = _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] abandon with branch',
                    'status': 'reviewing',
                    'message_id': 'abr@ex.com',
                }
            ],
        )

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
                'SELECT change_id FROM series WHERE change_id = ?', (change_id,)
            )
            assert cursor.fetchone() is None
            conn.close()

    @pytest.mark.asyncio
    async def test_abandon_from_the_branch_lands_on_a_branch(self, gitdir: str) -> None:
        """Deleting the branch HEAD is on detaches it to the parent commit
        first, because that is all delete_review_branch() can name.  Left
        that way the session ends on a commit with no branch on it, and the
        restore in run_tracking_tui() reads a detached HEAD as no branch of
        ours and declines to help."""
        identifier = 'test-abandon-onbranch'
        change_id = 'abandon-onbranch-1'
        branch_name = _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] abandon from the branch',
                    'status': 'reviewing',
                    'message_id': 'abo@ex.com',
                }
            ],
        )
        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', branch_name])
        assert ecode == 0

        app = TrackingApp(identifier, 'master')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._on_abandon_confirmed(True, change_id, branch_name, True)
            await pilot.pause()

        assert not b4.git_branch_exists(gitdir, branch_name)
        assert b4.git_get_current_branch(gitdir) == 'master'

    @pytest.mark.asyncio
    async def test_archive_from_the_branch_lands_on_a_branch(self, gitdir: str) -> None:
        """Archiving deletes the branch at the end, so it detaches HEAD the
        same way abandoning does."""
        identifier = 'test-archive-onbranch'
        change_id = 'archive-onbranch-1'
        branch_name = _create_review_branch(
            gitdir, change_id, identifier=identifier, with_patch=True
        )
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] archive from the branch',
                    'status': 'accepted',
                    'message_id': 'aro@ex.com',
                }
            ],
        )
        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', branch_name])
        assert ecode == 0

        app = TrackingApp(identifier, 'master')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            assert app._archive_branch(change_id, 1, branch_name)
            await pilot.pause()

        assert not b4.git_branch_exists(gitdir, branch_name)
        assert b4.git_get_current_branch(gitdir) == 'master'

    @pytest.mark.asyncio
    async def test_abandon_lands_back_on_a_detached_head(self, gitdir: str) -> None:
        """A session that started detached came from a commit, not a branch.

        delete_review_branch() can only name the deleted branch's parent, so
        without the session's own starting point the user is left parked on
        whatever that happens to be."""
        identifier = 'test-abandon-detached'
        change_id = 'abandon-detached-1'
        branch_name = _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] abandon detached',
                    'status': 'reviewing',
                    'message_id': 'abd@ex.com',
                }
            ],
        )
        ecode, out = b4.git_run_command(gitdir, ['rev-parse', 'master'])
        assert ecode == 0
        start_sha = out.strip()
        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', branch_name])
        assert ecode == 0

        app = TrackingApp(
            identifier, None, original_head=['checkout', '--detach', start_sha]
        )
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._on_abandon_confirmed(True, change_id, branch_name, True)
            await pilot.pause()

        assert not b4.git_branch_exists(gitdir, branch_name)
        assert b4.git_get_current_branch(gitdir) is None
        ecode, out = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        assert out.strip() == start_sha

    @pytest.mark.asyncio
    async def test_abandon_from_elsewhere_leaves_head_alone(self, gitdir: str) -> None:
        """HEAD was never on the deleted branch, so nothing moved it and
        nothing should move it back."""
        identifier = 'test-abandon-elsewhere'
        change_id = 'abandon-elsewhere-1'
        branch_name = _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] abandon from elsewhere',
                    'status': 'reviewing',
                    'message_id': 'abe@ex.com',
                }
            ],
        )
        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', '-b', 'mine'])
        assert ecode == 0

        app = TrackingApp(identifier, 'master')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._on_abandon_confirmed(True, change_id, branch_name, True)
            await pilot.pause()

        assert not b4.git_branch_exists(gitdir, branch_name)
        assert b4.git_get_current_branch(gitdir) == 'mine'


class TestTrackingWaiting:
    """Tests for the 'mark as waiting' workflow."""

    @pytest.mark.asyncio
    async def test_mark_as_waiting(self, gitdir: str) -> None:
        """Marking a reviewing series as waiting should update DB and tracking."""
        identifier = 'test-waiting'
        change_id = 'waiting-test-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] wait for v2',
                    'status': 'reviewing',
                    'message_id': 'wait@ex.com',
                }
            ],
        )

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
                'SELECT status FROM series WHERE change_id = ?', (change_id,)
            )
            row = cursor.fetchone()
            conn.close()
            assert row[0] == 'waiting'

            # Verify tracking commit
            _cover_text, trk = b4.review.load_tracking(gitdir, f'b4/review/{change_id}')
            assert trk['series']['status'] == 'waiting'

    @pytest.mark.asyncio
    async def test_mark_new_as_waiting(self, gitdir: str) -> None:
        """Marking a new (unimported) series as waiting should update DB only."""
        identifier = 'test-new-waiting'
        change_id = 'new-waiting-1'
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] needs v2',
                    'message_id': 'newwait@ex.com',
                }
            ],
        )

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
                'SELECT status FROM series WHERE change_id = ?', (change_id,)
            )
            row = cursor.fetchone()
            conn.close()
            assert row[0] == 'waiting'

    @pytest.mark.asyncio
    async def test_selected_series_synced_after_external_db_change(
        self, tmp_path: pathlib.Path
    ) -> None:
        """_selected_series must reflect a DB change after _load_series() + refresh.

        Regression: before the fix, _selected_series held a reference to the
        old series dict and was only updated via the async Highlighted event.
        A caller that opened the action menu between _load_series() and the
        Highlighted event would see stale status-dependent items.
        """
        identifier = 'test-selected-sync'
        change_id = 'sync-test-1'
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] sync test',
                    'status': 'reviewing',
                    'message_id': 'sync@ex.com',
                }
            ],
        )

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()

            # Simulate an external DB change (another process updated the status)
            conn = tracking.get_db(identifier)
            conn.execute(
                'UPDATE series SET status = ? WHERE change_id = ?',
                ('waiting', change_id),
            )
            conn.commit()
            conn.close()

            # Trigger reload the same way _check_db_changed does
            app._invalidate_caches()
            app._load_series()

            # Drain call_later(_refresh_list) and any Highlighted events
            await pilot.pause()

            # After the refresh, _selected_series must agree with _all_series
            fresh = next(s for s in app._all_series if s.get('change_id') == change_id)
            assert fresh.get('status') == 'waiting'
            assert app._selected_series is not None
            assert app._selected_series.get('status') == 'waiting', (
                '_selected_series still shows stale status after _refresh_list; '
                'action_action() would have built the wrong menu'
            )

    @pytest.mark.asyncio
    async def test_action_menu_reflects_status_after_waiting_transition(
        self, gitdir: str
    ) -> None:
        """Action menu must show waiting-state items immediately after transition.

        Regression: broonie reported needing to close and reopen the action menu
        to get the correct items after a status change.  After marking a series
        as 'waiting', pressing 'a' again should offer 'Review' (a waiting-state
        action) and NOT offer 'Take' (a reviewing-only action).
        """
        identifier = 'test-action-refresh'
        change_id = 'action-refresh-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] action refresh test',
                    'status': 'reviewing',
                    'message_id': 'acref@ex.com',
                }
            ],
        )

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()

            # Open action menu and mark as waiting
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)
            await pilot.press('w')  # waiting shortcut
            await pilot.pause()

            # Open action menu again — must reflect the new 'waiting' state
            await pilot.press('a')
            await pilot.pause()
            assert isinstance(app.screen, ActionScreen)

            action_screen = app.screen
            assert isinstance(action_screen, ActionScreen)
            lv = action_screen.query_one('#action-list', ListView)
            actions = [c.key for c in lv.children if isinstance(c, ActionItem)]

            # 'waiting' state offers review, not take/rebase
            assert 'review' in actions, (
                f'Expected review in waiting-state menu, got: {actions}'
            )
            assert 'take' not in actions, (
                f'take should not appear in waiting-state menu, got: {actions}'
            )


class TestTrackingDetailPanel:
    """Tests for the detail panel shown on series highlight."""

    @pytest.mark.asyncio
    async def test_detail_panel_lifecycle(self, tmp_path: pathlib.Path) -> None:
        """The panel auto-shows, follows navigation, and hides on escape."""
        _seed_db('test-detail', SAMPLE_SERIES)

        app = TrackingApp('test-detail')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()

            from textual.containers import Vertical

            # Panel should have non-zero height (auto-shown on first
            # highlight), showing charlie (last inserted, added_at desc)
            panel = app.query_one('#details-panel', Vertical)
            assert panel.styles.height is not None
            assert app._selected_series is not None
            assert 'charlie' in app._selected_series.get('subject', '')
            subject_widget = app.query_one('#detail-subject', Static)
            from_widget = app.query_one('#detail-from', Static)
            assert (
                _static_text(subject_widget)
                == '[bpf,v2,0/7] charlie: verifier refactor'
            )
            assert _static_text(from_widget) == 'Charlie Coder <charlie@example.com>'

            # Navigating to a different series updates the panel
            await pilot.press('j')
            await pilot.pause()
            assert app._selected_series is not None
            assert 'bravo' in app._selected_series.get('subject', '')
            assert (
                _static_text(subject_widget)
                == '[drm,v1,0/1] bravo: fix cursor rendering'
            )
            assert _static_text(from_widget) == 'Bob Builder <bob@example.com>'

            await pilot.press('j')
            await pilot.pause()
            assert app._selected_series is not None
            assert 'alpha' in app._selected_series.get('subject', '')

            # Escape hides the panel
            await pilot.press('escape')
            await pilot.pause()
            assert panel.styles.height is not None
            assert panel.styles.height.value == 0


class TestTrackingMultipleSeries:
    """Tests for workflows involving multiple series."""

    @pytest.mark.asyncio
    async def test_mixed_statuses_with_branches(self, gitdir: str) -> None:
        """App should correctly display a mix of new and reviewing series."""
        identifier = 'test-mixed'
        change_id_rev = 'mixed-reviewing-1'
        _create_review_branch(
            gitdir, change_id_rev, identifier=identifier, subject='Reviewing series'
        )
        _seed_db(
            identifier,
            [
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
            ],
        )

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
        _create_review_branch(
            gitdir, change_id, identifier=identifier, subject='Target series'
        )
        _seed_db(
            identifier,
            [
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
            ],
        )

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
        _seed_db(
            identifier,
            [
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
            ],
        )

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
            first_cid = (
                app._selected_series.get('change_id') if app._selected_series else None
            )
            if app._selected_series and app._selected_series.get('status') == 'snoozed':
                await pilot.press('down')
                await pilot.pause()
                # If down didn't change, try up
                if (
                    app._selected_series
                    and app._selected_series.get('change_id') == first_cid
                ):
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
    cursor = conn.execute('SELECT status FROM series WHERE change_id = ?', (change_id,))
    row = cursor.fetchone()
    conn.close()
    assert row is not None, f'Series {change_id} not found in DB'
    return str(row[0])


def _get_action_keys(app: TrackingApp) -> List[str]:
    """Get the list of action keys from the currently-open ActionScreen."""
    assert isinstance(app.screen, ActionScreen)
    lv = app.screen.query_one('#action-list', ListView)
    return [c.key for c in lv.children if isinstance(c, ActionItem)]


class TestLinkRevisionAction:
    """The 'link a revision' action is offered and opens the input modal."""

    @pytest.mark.asyncio
    async def test_link_action_offered_and_dispatches(
        self, tmp_path: pathlib.Path
    ) -> None:
        identifier = 'test-link-action'
        _seed_db(
            identifier,
            [
                {
                    'change_id': 'link-1',
                    'subject': '[PATCH] linkable series',
                    'status': 'new',
                    'message_id': 'link@ex.com',
                }
            ],
        )
        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            assert 'link' in _get_action_keys(app)
            # Selecting it opens the message-id input modal.
            await pilot.press('l')
            await pilot.pause()
            assert isinstance(app.screen, LinkRevisionScreen)
            await pilot.press('escape')


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
        _create_review_branch(
            gitdir, change_id, identifier=identifier, status='reviewing'
        )
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] lifecycle test series',
                    'sender_name': 'Lifecycle Author',
                    'sender_email': 'lifecycle@example.com',
                    'status': 'reviewing',
                    'message_id': 'lifecycle@ex.com',
                }
            ],
        )

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
        _cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
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
        _cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
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
        _cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        assert trk['series']['status'] == 'reviewing'
        assert 'snoozed' not in trk['series']

        # === Phase 5: reviewing → accepted (seed directly) ===
        # The real 'take' flow needs suspend + am + editor, so we seed.
        conn = tracking.get_db(identifier)
        conn.execute(
            'UPDATE series SET status = ? WHERE change_id = ?', ('accepted', change_id)
        )
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
        def _mock_archive(
            self_app: TrackingApp,
            cid: str,
            rev: Optional[int],
            rbranch: str,
            pw_series_id: Optional[int] = None,
            notify: bool = True,
        ) -> bool:
            """Simplified archive: just update DB status."""
            aconn = tracking.get_db(self_app._identifier)
            tracking.update_series_status(aconn, cid, 'archived', revision=rev)
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
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] snooze from new',
                    'message_id': 'ds@ex.com',
                }
            ],
        )

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
        """A thanked series offers reopen-to-reviewing and archive."""
        identifier = 'test-lifecycle-thanked'
        change_id = 'thanked-series-1'
        _create_review_branch(
            gitdir, change_id, identifier=identifier, status='thanked'
        )
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] thanked ready for archive',
                    'status': 'thanked',
                    'message_id': 'thanked@ex.com',
                }
            ],
        )

        # Verify action menu: 'review' (reopen) and 'archive' should be available
        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            actions = _get_action_keys(app)
            assert actions == ['review', 'archive']

            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_accepted_action_menu(self, gitdir: str) -> None:
        """Accepted series should show review, thank, abandon, and archive."""
        identifier = 'test-lifecycle-accepted'
        change_id = 'accepted-menu-1'
        _create_review_branch(
            gitdir, change_id, identifier=identifier, status='accepted'
        )
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] accepted series menu test',
                    'status': 'accepted',
                    'message_id': 'acc@ex.com',
                }
            ],
        )

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            actions = _get_action_keys(app)
            assert set(actions) == {'review', 'thank', 'abandon', 'archive'}
            # 'Return to reviewing' (review) sits just above the
            # abandon/archive block, not at the top of the menu.
            assert actions == ['thank', 'review', 'abandon', 'archive']
            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_gone_series_actions(self, tmp_path: pathlib.Path) -> None:
        """A 'gone' series (branch deleted externally) should allow
        review and abandon."""
        identifier = 'test-lifecycle-gone'
        _seed_db(
            identifier,
            [
                {
                    'change_id': 'gone-1',
                    'subject': '[PATCH] gone series',
                    'status': 'gone',
                    'message_id': 'gone@ex.com',
                }
            ],
        )

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
        _create_review_branch(
            gitdir, change_id, identifier=identifier, status='snoozed'
        )
        # Manually inject snoozed.previous_state into tracking commit
        cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        trk['series']['snoozed'] = {
            'until': 'tag:v99',
            'previous_state': 'waiting',
        }
        b4.review.save_tracking_ref(gitdir, branch_name, cover_text, trk)

        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] waiting then snoozed',
                    'status': 'snoozed',
                    'message_id': 'sw@ex.com',
                }
            ],
        )

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
        _cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        assert trk['series']['status'] == 'waiting'
        assert 'snoozed' not in trk['series']

    @pytest.mark.asyncio
    async def test_abandon_from_any_branch_state(self, gitdir: str) -> None:
        """Abandon should work from reviewing, waiting, and snoozed states."""
        for status in ('reviewing', 'snoozed'):
            identifier = f'test-lifecycle-abandon-{status}'
            change_id = f'abandon-{status}'
            _create_review_branch(
                gitdir, change_id, identifier=identifier, status=status
            )
            _seed_db(
                identifier,
                [
                    {
                        'change_id': change_id,
                        'subject': f'[PATCH] abandon from {status}',
                        'status': status,
                        'message_id': f'ab-{status}@ex.com',
                    }
                ],
            )

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
                'SELECT change_id FROM series WHERE change_id = ?', (change_id,)
            )
            assert cursor.fetchone() is None, (
                f'Series should be gone after abandon from {status}'
            )
            conn.close()

            # Verify branch deleted
            branch_name = f'b4/review/{change_id}'
            assert not b4.git_branch_exists(gitdir, branch_name), (
                f'Branch should be deleted after abandon from {status}'
            )

    @pytest.mark.asyncio
    async def test_partial_action_menu(self, gitdir: str) -> None:
        """A 'partial' series offers take/rebase/thank/etc."""
        identifier = 'test-lifecycle-partial-menu'
        change_id = 'partial-menu-1'
        _create_review_branch(
            gitdir, change_id, identifier=identifier, status='partial'
        )
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH 0/4] partial series',
                    'status': 'partial',
                    'message_id': 'partial-menu@ex.com',
                    'num_patches': 4,
                }
            ],
        )

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('a')
            await pilot.pause()
            actions = _get_action_keys(app)
            assert 'take' in actions
            assert 'rebase' in actions
            assert 'thank' in actions
            assert 'waiting' in actions
            assert 'snooze' in actions
            assert 'abandon' in actions
            assert 'archive' in actions
            # 'Return to reviewing' (review) sits just above the
            # abandon/archive block rather than near the top.
            assert actions.index('review') > actions.index('thank')
            assert actions[-3:] == ['review', 'abandon', 'archive']
            await pilot.press('escape')

    @pytest.mark.asyncio
    async def test_partial_status_visible_in_listing(self, gitdir: str) -> None:
        """A 'partial' series appears in the normal listing (not hidden)."""
        identifier = 'test-lifecycle-partial-visible'
        change_id = 'partial-visible-1'
        _create_review_branch(
            gitdir, change_id, identifier=identifier, status='partial'
        )
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH 0/3] partially applied series',
                    'status': 'partial',
                    'message_id': 'partial-vis@ex.com',
                    'num_patches': 3,
                }
            ],
        )

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            assert len(app._all_series) == 1
            assert app._all_series[0].get('status') == 'partial'

    def test_record_take_metadata_partial_coverage(self, gitdir: str) -> None:
        """Cherry-picking a subset of patches → status 'partial' in tracking blob."""
        identifier = 'test-partial-coverage'
        change_id = 'partial-cov-1'
        branch_name = _create_review_branch(
            gitdir, change_id, identifier=identifier, status='reviewing'
        )
        # Inject 4-patch tracking data into the blob
        cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        trk['patches'] = [
            {'subject': f'patch {i}', 'message-id': f'p{i}@ex.com'} for i in range(1, 5)
        ]
        b4.review.save_tracking_ref(gitdir, branch_name, cover_text, trk)

        app = TrackingApp.__new__(TrackingApp)

        # Take only patches 1 and 2 (1-based cherry-pick indices)
        result = app._record_take_metadata(
            gitdir,
            branch_name,
            'master',
            ['aaa', 'bbb'],
            cherrypick=[1, 2],
            accepted=True,
        )

        assert result == 'partial', f'expected partial, got {result!r}'
        _, updated = b4.review.load_tracking(gitdir, branch_name)
        patches = updated.get('patches', [])
        assert patches[0].get('taken') is not None  # patch 1 taken
        assert patches[1].get('taken') is not None  # patch 2 taken
        assert patches[2].get('taken') is None  # patch 3 untaken
        assert patches[3].get('taken') is None  # patch 4 untaken
        assert updated['series']['status'] == 'partial'

    def test_record_take_metadata_full_coverage_promotes_accepted(
        self, gitdir: str
    ) -> None:
        """Taking remaining patches after a partial take → auto-promotes to 'accepted'."""
        identifier = 'test-full-coverage'
        change_id = 'full-cov-1'
        branch_name = _create_review_branch(
            gitdir, change_id, identifier=identifier, status='partial'
        )
        # Inject 3-patch tracking data with patches 1+2 already taken
        cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        trk['patches'] = [
            {
                'subject': 'patch 1',
                'message-id': 'p1@ex.com',
                'taken': {'commit-id': 'abc'},
            },
            {
                'subject': 'patch 2',
                'message-id': 'p2@ex.com',
                'taken': {'commit-id': 'def'},
            },
            {'subject': 'patch 3', 'message-id': 'p3@ex.com'},
        ]
        trk['series']['status'] = 'partial'
        b4.review.save_tracking_ref(gitdir, branch_name, cover_text, trk)

        app = TrackingApp.__new__(TrackingApp)

        # Take the remaining patch 3 (completing coverage)
        result = app._record_take_metadata(
            gitdir,
            branch_name,
            'master',
            ['fff'],
            cherrypick=[3],
            accepted=True,
        )

        assert result == 'accepted', f'expected accepted, got {result!r}'
        _, updated = b4.review.load_tracking(gitdir, branch_name)
        patches = updated.get('patches', [])
        assert all(p.get('taken') for p in patches), 'all patches should be taken'
        assert updated['series']['status'] == 'accepted'

    def test_record_take_metadata_unreadable_tracking(self, gitdir: str) -> None:
        """The patches are applied by the time this runs, so a tracking commit
        that cannot be read is a missing record and not a take that never
        happened.  Saying None for both leaves the caller unable to tell them
        apart, and 'unrecorded' must not reach the status column either."""
        change_id = 'take-unrecorded-1'
        branch_name = _create_review_branch(
            gitdir, change_id, identifier='test-unrecorded', status='reviewing'
        )
        app = TrackingApp.__new__(TrackingApp)
        app._identifier = 'test-unrecorded'
        app._selected_series = None

        with patch.object(b4.review, 'load_tracking', side_effect=SystemExit(1)):
            result = app._record_take_metadata(
                gitdir, branch_name, 'master', ['abc'], accepted=True
            )
        assert result == 'unrecorded'

        statuses: List[str] = []
        with patch.object(
            tracking,
            'update_series_status',
            lambda conn, cid, status, revision=None: statuses.append(status),
        ):
            app._finalize_take(gitdir, 'master', change_id, {'revision': 1}, result)
        assert not statuses

    def test_record_take_metadata_branch_tip_is_target_not_head(
        self, gitdir: str
    ) -> None:
        """branch-tips records the *target branch* tip, not the current HEAD.

        Regression: the merge-take path advances target_branch in a separate
        worktree and never checks out target_branch in the current checkout, so
        reading HEAD here recorded the wrong commit (the launch branch) for the
        CI-lookup metadata.
        """
        change_id = 'branch-tip-1'
        branch_name = _create_review_branch(
            gitdir, change_id, identifier='test-branch-tip', status='reviewing'
        )
        cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        trk['patches'] = [{'subject': 'patch 1', 'message-id': 'p1@ex.com'}]
        b4.review.save_tracking_ref(gitdir, branch_name, cover_text, trk)

        # A target branch whose tip is advanced beyond the current HEAD
        # (master), so HEAD and the target tip are distinguishable.
        b4.git_run_command(gitdir, ['branch', 'take-target'])
        ecode, tree = b4.git_run_command(gitdir, ['rev-parse', 'take-target^{tree}'])
        assert ecode == 0
        ecode, newsha = b4.git_run_command(
            gitdir,
            ['commit-tree', tree.strip(), '-p', 'take-target'],
            stdin=b'advance target\n',
        )
        assert ecode == 0
        b4.git_run_command(
            gitdir, ['update-ref', 'refs/heads/take-target', newsha.strip()]
        )

        app = TrackingApp.__new__(TrackingApp)
        app._record_take_metadata(
            gitdir, branch_name, 'take-target', ['commit-a'], accepted=True
        )

        _, updated = b4.review.load_tracking(gitdir, branch_name)
        tips = updated['series'].get('branch-tips', [])
        assert tips, 'expected a branch-tips entry'
        _, target_tip = b4.git_run_command(gitdir, ['rev-parse', 'take-target'])
        _, head = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert tips[-1]['branch'] == 'take-target'
        assert tips[-1]['sha'] == target_tip.strip()
        # The bug recorded HEAD (master); guard against a regression.
        assert tips[-1]['sha'] != head.strip()

    @pytest.mark.asyncio
    async def test_thank_partial_series_cherrypicks_taken(self, gitdir: str) -> None:
        """Thanking a 'partial' series proceeds and thanks only taken patches.

        Regression (bug a01c5b5): action_thank used to bail with "Series must
        be accepted before sending thanks" for anything but 'accepted', so a
        partially-applied series could never send a thank-you — blocking the
        "I'm done, thanks for the bits I took" workflow.  Verify the guard now
        admits 'partial' and that the generated thank-you is in cherry-pick
        mode listing only the commits actually taken.
        """
        from unittest import mock

        identifier = 'test-thank-partial'
        change_id = 'thank-partial-1'
        branch_name = _create_review_branch(
            gitdir, change_id, identifier=identifier, status='partial'
        )
        # 3-patch series: patches 1+2 taken, patch 3 still open.
        cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        trk['series']['expected'] = 3
        trk['series']['taken'] = {'branch': 'master'}
        trk['patches'] = [
            {
                'title': '[PATCH 1/3] patch one',
                'header-info': {'msgid': 'p1@ex.com'},
                'taken': {'commit-id': 'aaa111'},
            },
            {
                'title': '[PATCH 2/3] patch two',
                'header-info': {'msgid': 'p2@ex.com'},
                'taken': {'commit-id': 'bbb222'},
            },
            {
                'title': '[PATCH 3/3] patch three',
                'header-info': {'msgid': 'p3@ex.com'},
            },
        ]
        b4.review.save_tracking_ref(gitdir, branch_name, cover_text, trk)

        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH 0/3] partial thank series',
                    'status': 'partial',
                    'message_id': 'thank-partial@ex.com',
                    'num_patches': 3,
                }
            ],
        )

        captured: Dict[str, Any] = {}

        def _fake_generate(
            topdir: str, jsondata: Dict[str, Any], target: str, cmdargs: Any
        ) -> email.message.EmailMessage:
            captured['jsondata'] = jsondata
            return email.message.EmailMessage()

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            problems: List[str] = []
            orig_notify = app.notify

            def _capture_notify(message: str, *a: Any, **k: Any) -> None:
                if k.get('severity') in ('warning', 'error'):
                    problems.append(f'{k.get("severity")}: {message}')
                return orig_notify(message, *a, **k)

            with (
                mock.patch.object(app, 'notify', _capture_notify),
                mock.patch.object(app, '_show_thank_preview') as mock_preview,
                mock.patch('b4.ty.generate_am_thanks', side_effect=_fake_generate),
            ):
                app.action_thank()

            assert not problems, f'unexpected notification(s): {problems}'
            mock_preview.assert_called_once()

        jsondata = captured.get('jsondata')
        assert jsondata is not None, 'generate_am_thanks was never reached'
        # Cherry-pick mode flagged because not every patch was taken.
        assert jsondata['cherrypick'] is True
        # Only the two taken patches contribute commits (by 1-based index).
        assert jsondata['commits'] == [(1, 'aaa111'), (2, 'bbb222')]

    def test_partial_series_ingests_new_revision(self, gitdir: str) -> None:
        """A 'partial' series must ingest an incoming v2 and record it.

        Regression: before the partial state was introduced, cherry-picking
        a subset of patches drove the whole series into the accepted→thanked→
        archived terminal flow, so a v2 was never ingested.  This test verifies
        that update_series_tracking() treats 'partial' as an active status:
        it must write 'newer-versions: [2]' into the tracking commit and leave
        the DB status unchanged at 'partial'.
        """
        from unittest import mock

        identifier = 'test-partial-ingest'
        change_id = 'partial-ingest-1'

        # Seed DB: v1, partial (patches 1+2 taken, patch 3 still open)
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH 0/3] a three-patch series',
                    'status': 'partial',
                    'message_id': f'{change_id}@example.com',
                    'num_patches': 3,
                    'revision': 1,
                }
            ],
        )

        # Record v1 in the revisions table so only v2 is counted as new
        conn = tracking.get_db(identifier)
        tracking.add_revision(conn, change_id, 1, f'{change_id}@example.com')
        conn.close()

        # Create review branch with partial state and per-patch tracking data
        branch_name = _create_review_branch(
            gitdir, change_id, identifier=identifier, status='partial'
        )
        cover_text, trk = b4.review.load_tracking(gitdir, branch_name)
        trk['patches'] = [
            {
                'subject': 'patch 1',
                'message-id': 'p1@example.com',
                'taken': {'commit-id': 'aaa111'},
            },
            {
                'subject': 'patch 2',
                'message-id': 'p2@example.com',
                'taken': {'commit-id': 'bbb222'},
            },
            {'subject': 'patch 3', 'message-id': 'p3@example.com'},
        ]
        trk['series']['status'] = 'partial'
        b4.review.save_tracking_ref(gitdir, branch_name, cover_text, trk)

        # v1 mock: no cover, all-None patches → _collect_followups never called
        v1_mock = mock.Mock()
        v1_mock.revision = 1
        v1_mock.expected = 3
        v1_mock.change_id = change_id
        v1_mock.has_cover = False
        v1_mock.patches = [None, None, None, None]
        v1_mock.fromname = 'Test Author'
        v1_mock.fromemail = 'author@example.com'
        v1_mock.subject = '[PATCH 0/3] a three-patch series'
        v1_mock.fingerprint = None

        # v2 mock: needs a cover with msgid so add_revision can record it
        v2_cover = mock.Mock()
        v2_cover.msgid = 'cover-v2@example.com'
        v2_cover.full_subject = '[PATCH v2 0/3] a three-patch series'
        v2_mock = mock.Mock()
        v2_mock.revision = 2
        v2_mock.change_id = change_id
        v2_mock.patches = [None, None, None, None]
        v2_mock.fingerprint = None

        mock_lmbx = mock.Mock()
        mock_lmbx.series = {1: v1_mock, 2: v2_mock}
        # Cover letters live in the mailbox's parse-time covers dict, never in
        # a raw series' patches[0] — that only happens in get_series().
        mock_lmbx.covers = {2: v2_cover}
        mock_lmbx.get_series.return_value = v1_mock

        series_dict = {
            'change_id': change_id,
            'revision': 1,
            'status': 'partial',
            'message_id': f'{change_id}@example.com',
        }

        with (
            mock.patch('b4.review._review.retrieve_series_messages', return_value=[]),
            mock.patch('b4.review._review.check_series_attestation', return_value=None),
            mock.patch('b4.LoreMailbox', return_value=mock_lmbx),
        ):
            result = b4.review.update_series_tracking(
                series_dict, identifier, 'https://example.com/%s', topdir=gitdir
            )

        assert result.get('error') is None, f'unexpected error: {result["error"]}'
        assert result['new_revisions'] == 1, (
            f'expected 1 new revision, got {result["new_revisions"]}'
        )

        # Tracking commit must carry newer-versions = [2]
        _, updated = b4.review.load_tracking(gitdir, branch_name)
        assert updated['series'].get('newer-versions') == [2], (
            f'expected newer-versions=[2], got {updated["series"].get("newer-versions")!r}'
        )

        # DB status must remain 'partial' — revision discovery must not promote
        conn = tracking.get_db(identifier)
        row = conn.execute(
            'SELECT status FROM series WHERE change_id = ? AND revision = ?',
            (change_id, 1),
        ).fetchone()
        conn.close()
        assert row['status'] == 'partial', (
            f'status should stay partial after v2 ingestion, got {row["status"]!r}'
        )


class TestShazamMergeFlags:
    """The take->merge path passes b4.shazam-merge-flags through verbatim (like
    `b4 shazam`) and reconciles Signed-off-by with the take dialog's checkbox as
    a single, deduped git-merge flag (config is authoritative).
    """

    def test_unset_config_defaults_to_signoff(self) -> None:
        # Default shazam-merge-flags is '--signoff'; with the (config-defaulted)
        # checkbox on, exactly one --signoff is passed.
        assert _shazam_merge_flags({}, True) == ['--signoff']

    def test_unset_config_checkbox_off_yields_no_signoff(self) -> None:
        assert _shazam_merge_flags({}, False) == ['--no-signoff']

    def test_config_flags_pass_through_verbatim(self) -> None:
        # --log/--stat/--gpg-sign survive unchanged; signoff is appended once.
        assert _shazam_merge_flags(
            {'shazam-merge-flags': '--gpg-sign --stat --log'}, True
        ) == ['--gpg-sign', '--stat', '--log', '--signoff']

    def test_config_signoff_is_not_duplicated(self) -> None:
        # An explicit --signoff in config is deduped against the checkbox flag.
        assert _shazam_merge_flags({'shazam-merge-flags': '--signoff --log'}, True) == [
            '--log',
            '--signoff',
        ]
        assert _shazam_merge_flags(
            {'shazam-merge-flags': '--signoff --log'}, False
        ) == ['--log', '--no-signoff']

    def test_config_no_signoff_overridden_by_checkbox(self) -> None:
        assert _shazam_merge_flags(
            {'shazam-merge-flags': '--no-signoff --log'}, True
        ) == ['--log', '--signoff']
        assert _shazam_merge_flags(
            {'shazam-merge-flags': '--no-signoff --log'}, False
        ) == ['--log', '--no-signoff']

    def test_strategy_short_flag_is_passed_through(self) -> None:
        # In `git merge`, -s is --strategy (it takes an argument), NOT a short
        # form of --signoff. It must survive untouched, else `-s ours` would
        # lose the -s and leave `ours` as a bogus merge operand.
        assert _shazam_merge_flags({'shazam-merge-flags': '-s ours'}, True) == [
            '-s',
            'ours',
            '--signoff',
        ]

    def test_empty_config_still_honors_checkbox(self) -> None:
        assert _shazam_merge_flags({'shazam-merge-flags': ''}, True) == ['--signoff']
        assert _shazam_merge_flags({'shazam-merge-flags': ''}, False) == [
            '--no-signoff'
        ]


class TestWorktreeForBranch:
    """Resolving which worktree holds a branch, for cross-worktree takes."""

    def test_finds_and_ignores_other_worktrees(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        # The fixture checks out 'master' in the main worktree.
        main = _worktree_for_branch(gitdir, 'master')
        assert main is not None and pathlib.Path(main).samefile(gitdir)

        # A branch that is not checked out anywhere resolves to None.
        b4.git_run_command(gitdir, ['branch', 'topic'])
        assert _worktree_for_branch(gitdir, 'topic') is None

        # Once checked out in a linked worktree, it resolves to that path.
        wt = str(tmp_path / 'wt-topic')
        ecode, _ = b4.git_run_command(gitdir, ['worktree', 'add', wt, 'topic'])
        assert ecode == 0
        found = _worktree_for_branch(gitdir, 'topic')
        assert found is not None and pathlib.Path(found).samefile(wt)

        # An unknown branch resolves to None.
        assert _worktree_for_branch(gitdir, 'no-such-branch') is None


class TestCrossWorktreeFetch:
    """git_fetch_am_into_repo must land FETCH_HEAD in the target worktree.

    The merge-take path applies patches via git_fetch_am_into_repo(merge_dir,
    ...) and then merges ``git -C merge_dir ... FETCH_HEAD``. FETCH_HEAD is
    per-worktree; if the fetch runs against the caller's cwd instead of
    merge_dir, the commits land in the wrong worktree and the merge reads a
    stale/missing FETCH_HEAD -- silently merging unrelated commits.
    """

    def test_fetch_head_lands_in_target_worktree_not_cwd(
        self, gitdir: str, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Build an am-able patch on top of master without needing a committer
        # identity or disturbing HEAD (mirrors _create_review_branch).
        patchfile = pathlib.Path(gitdir) / 'cross_wt_patch.txt'
        patchfile.write_text('cross-worktree marker\n')
        b4.git_run_command(gitdir, ['add', 'cross_wt_patch.txt'])
        ecode, tree = b4.git_run_command(gitdir, ['write-tree'])
        assert ecode == 0
        ecode, commit = b4.git_run_command(
            gitdir,
            ['commit-tree', tree.strip(), '-p', 'master'],
            stdin=b'add cross_wt_patch\n',
        )
        assert ecode == 0
        ecode, mbox = b4.git_run_command(
            gitdir, ['format-patch', '-1', '--stdout', commit.strip()], decode=False
        )
        assert ecode == 0
        # Restore a clean master (drop the staged file) so at_base=master and
        # its FETCH_HEAD start fresh.
        b4.git_run_command(gitdir, ['reset', '--hard', 'master'])

        # Drive the fetch from a *different* worktree than gitdir. gitdir is the
        # primary worktree (its .git is a directory) -- the case that used to
        # leak the process cwd into the FETCH_HEAD location.
        other = str(tmp_path / 'other-wt')
        ecode, _ = b4.git_run_command(gitdir, ['worktree', 'add', other, '-b', 'other'])
        assert ecode == 0
        monkeypatch.chdir(other)

        b4.git_fetch_am_into_repo(gitdir, mbox, at_base='master', am_flags=['-3'])

        # FETCH_HEAD must be readable from gitdir and carry the patched file --
        # i.e. it landed in gitdir's per-worktree FETCH_HEAD, not `other`'s.
        ecode, blob = b4.git_run_command(
            gitdir, ['show', 'FETCH_HEAD:cross_wt_patch.txt']
        )
        assert ecode == 0, 'FETCH_HEAD did not land in the target worktree'
        assert blob.strip() == 'cross-worktree marker'


def _gitlink_bump_series(gitdir: str, name: str = 'sub') -> b4.LoreSeries:
    """A 1-patch series that bumps the submodule gitlink.

    The patch carries an ``index <old>..<new> 160000`` line, so the fake-am
    tree synthesized from it holds a gitlink of its own -- which is what makes
    make_fake_am_range's ``reset --hard`` recurse.
    """
    ecode, newlink = b4.git_run_command(gitdir, ['rev-parse', 'master'])
    assert ecode == 0
    ecode, _ = b4.git_run_command(
        gitdir,
        ['update-index', '--cacheinfo', f'160000,{newlink.strip()},{name}'],
    )
    assert ecode == 0
    ecode, tree = b4.git_run_command(gitdir, ['write-tree'])
    assert ecode == 0
    ecode, commit = b4.git_run_command(
        gitdir,
        ['commit-tree', tree.strip(), '-p', 'master'],
        stdin=f'bump {name}\n'.encode(),
    )
    assert ecode == 0
    ecode, mbox = b4.git_run_command(
        gitdir, ['format-patch', '-1', '--stdout', commit.strip()], decode=False
    )
    assert ecode == 0
    assert b'160000' in mbox, 'patch does not carry a gitlink index line'
    ecode, _ = b4.git_run_command(gitdir, ['reset', '--hard', 'master'])
    assert ecode == 0
    msgs = b4.mailsplit_bytes(mbox)
    for idx, msg in enumerate(msgs):
        if not msg['Message-Id']:
            msg['Message-Id'] = f'<gitlink-bump-{idx}@test.local>'
    return b4.review._get_lore_series(msgs)


class TestScratchWorktreeSubmodules:
    """b4's scratch worktrees must ignore the user's submodule.recurse.

    A fresh linked worktree has no per-worktree submodule clones, so a
    recursing checkout or reset dies with "fatal: not a git repository:
    .../worktrees/<wt>/modules/<name>" before anything is applied. In a repo
    carrying submodules (the b4 repo itself among them) that killed every
    review-branch creation and shazam apply.
    """

    def test_fetch_am_ignores_submodule_recurse(
        self, gitdir: str, add_unpopulated_submodule: Callable[..., str]
    ) -> None:
        add_unpopulated_submodule(gitdir)

        # An am-able patch on top of the submodule-bearing master.
        patchfile = pathlib.Path(gitdir) / 'sub_recurse_patch.txt'
        patchfile.write_text('submodule recurse marker\n')
        ecode, _ = b4.git_run_command(gitdir, ['add', 'sub_recurse_patch.txt'])
        assert ecode == 0
        ecode, tree = b4.git_run_command(gitdir, ['write-tree'])
        assert ecode == 0
        ecode, commit = b4.git_run_command(
            gitdir,
            ['commit-tree', tree.strip(), '-p', 'master'],
            stdin=b'add sub_recurse_patch\n',
        )
        assert ecode == 0
        ecode, mbox = b4.git_run_command(
            gitdir, ['format-patch', '-1', '--stdout', commit.strip()], decode=False
        )
        assert ecode == 0
        ecode, _ = b4.git_run_command(gitdir, ['reset', '--hard', 'master'])
        assert ecode == 0

        # Only now flip the config the bug needs, so the fixture setup above
        # never ran under recursion itself.
        b4.git_set_config(gitdir, 'submodule.recurse', 'true')

        b4.git_fetch_am_into_repo(gitdir, mbox, at_base='master', am_flags=['-3'])

        ecode, blob = b4.git_run_command(
            gitdir, ['show', 'FETCH_HEAD:sub_recurse_patch.txt']
        )
        assert ecode == 0, 'scratch-worktree apply failed under submodule.recurse'
        assert blob.strip() == 'submodule recurse marker'

    def test_fake_am_range_ignores_scratch_worktree_config(
        self,
        gitdir: str,
        monkeypatch: pytest.MonkeyPatch,
        add_unpopulated_submodule: Callable[..., str],
    ) -> None:
        """The fake-am staging worktree is a scratch worktree too.

        Its ``reset --hard`` recurses once the synthesized tree carries a
        gitlink, and its ``git am`` builds throwaway commits nothing will ever
        ship -- so it must not reach for the user's signing key either.
        """
        add_unpopulated_submodule(gitdir)
        lser = _gitlink_bump_series(gitdir)
        b4.git_set_config(gitdir, 'submodule.recurse', 'true')
        _poison_gpg_signing(monkeypatch)

        start, end = lser.make_fake_am_range(gitdir=gitdir, at_base='master')

        assert start, 'fake-am range died in the scratch worktree'
        assert end
        assert b4.git_commit_exists(gitdir, start)
        assert b4.git_commit_exists(gitdir, end)


class TestMergeTakeSkipRouting:
    """Take routing when patches are skipped (bug 6d1d35c).

    The merge method must still be usable with skipped patches: it should
    offer the patch picker (pre-deselecting skipped patches) so a
    cover-letter merge commit can exclude them, while a merge with nothing
    skipped takes the whole series without prompting.
    """

    def _setup_branch(
        self, gitdir: str, change_id: str, skip_indices: List[int]
    ) -> str:
        branch = _create_review_branch(gitdir, change_id, status='reviewing')
        cover_text, trk = b4.review.load_tracking(gitdir, branch)
        usercfg = b4.get_user_config()
        patches: List[Dict[str, Any]] = []
        for i in range(1, 4):
            p: Dict[str, Any] = {'subject': f'patch {i}', 'message-id': f'p{i}@ex.com'}
            if i in skip_indices:
                b4.review._set_patch_state(p, usercfg, 'skip')
            patches.append(p)
        trk['patches'] = patches
        b4.review.save_tracking_ref(gitdir, branch, cover_text, trk)
        return branch

    def _route(
        self, gitdir: str, branch: str, method: str
    ) -> tuple[list[Any], list[Any]]:
        from types import SimpleNamespace

        app = TrackingApp.__new__(TrackingApp)
        pushed: list[Any] = []
        confirmed: list[Any] = []
        app.push_screen = lambda screen, callback=None: pushed.append(screen)  # type: ignore[method-assign, assignment]  # ty: ignore[invalid-assignment]
        app._show_take_confirm = (  # type: ignore[method-assign]  # ty: ignore[invalid-assignment]
            lambda *a, **k: confirmed.append((a, k))
        )
        app.notify = lambda *a, **k: None  # type: ignore[method-assign]  # ty: ignore[invalid-assignment]
        take_screen: Any = SimpleNamespace(method_result=method, target_result='master')
        app._on_take_confirmed(
            True,
            'cid',
            branch,
            take_screen,
            {'subject': 'Test series'},
        )
        return pushed, confirmed

    def test_merge_with_skips_opens_picker(self, gitdir: str) -> None:
        """Merge + skipped patches → picker with skipped pre-deselected."""
        branch = self._setup_branch(gitdir, 'merge-skip-1', skip_indices=[2])
        pushed, confirmed = self._route(gitdir, branch, 'merge')
        assert len(pushed) == 1, 'expected the patch picker to be pushed'
        assert isinstance(pushed[0], CherryPickScreen)
        assert not confirmed, 'should not skip straight to confirm'
        # Patch 2 is skipped → only 1 and 3 pre-selected
        assert pushed[0]._preselected == [1, 3]

    def test_merge_without_skips_goes_straight_to_confirm(self, gitdir: str) -> None:
        """Merge with nothing skipped → no picker, whole series merged."""
        branch = self._setup_branch(gitdir, 'merge-noskip-1', skip_indices=[])
        pushed, confirmed = self._route(gitdir, branch, 'merge')
        assert not pushed, 'no picker expected when nothing is skipped'
        assert len(confirmed) == 1
        args, kwargs = confirmed[0]
        assert args[0] == 'merge'
        assert kwargs.get('cherrypick') is None

    def test_cherrypick_always_opens_picker(self, gitdir: str) -> None:
        """Cherry-pick offers the picker even with nothing skipped."""
        branch = self._setup_branch(gitdir, 'cp-noskip-1', skip_indices=[])
        pushed, confirmed = self._route(gitdir, branch, 'cherry-pick')
        assert len(pushed) == 1
        assert isinstance(pushed[0], CherryPickScreen)
        assert not confirmed

    def test_cherrypick_confirmed_preserves_merge_method(self, gitdir: str) -> None:
        """A skip-trimmed merge keeps method='merge' after the picker."""
        from types import SimpleNamespace

        branch = self._setup_branch(gitdir, 'merge-keep-1', skip_indices=[2])
        app = TrackingApp.__new__(TrackingApp)
        confirmed: list[Any] = []
        app._show_take_confirm = (  # type: ignore[method-assign]  # ty: ignore[invalid-assignment]
            lambda *a, **k: confirmed.append((a, k))
        )
        take_screen: Any = SimpleNamespace(
            method_result='merge', target_result='master'
        )
        pick_screen: Any = SimpleNamespace(selected_indices=[1, 3])
        app._on_cherrypick_confirmed(
            True,
            'cid',
            branch,
            take_screen,
            {'subject': 'Test'},
            pick_screen,
        )
        assert len(confirmed) == 1
        args, kwargs = confirmed[0]
        assert args[0] == 'merge', 'method must remain merge, not cherry-pick'
        assert kwargs.get('cherrypick') == [1, 3]


@patch('b4.review.tracking.get_review_target_branches', return_value=['master'])
class TestTargetBranch:
    """Tests for per-series target branch tracking."""

    @pytest.mark.asyncio
    async def test_set_target_branch_from_new(
        self, _mock_branches: Any, gitdir: str
    ) -> None:
        """Press t on a new series, type a branch, confirm — DB is updated."""
        identifier = 'test-target-new'
        change_id = 'target-new-1'
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] target branch test',
                    'message_id': 'target-new@ex.com',
                }
            ],
        )

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
    async def test_set_target_branch_from_reviewing(
        self, _mock_branches: Any, gitdir: str
    ) -> None:
        """Set target on a reviewing series — tracking commit updated too."""
        identifier = 'test-target-rev'
        change_id = 'target-rev-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] target reviewing test',
                    'status': 'reviewing',
                    'message_id': 'target-rev@ex.com',
                }
            ],
        )

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
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] target detail test',
                    'message_id': 'target-detail@ex.com',
                }
            ],
        )
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
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH] clear target test',
                    'message_id': 'target-clear@ex.com',
                }
            ],
        )
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
            # https://github.com/python/mypy/issues/9457:
            # app.screen is stale-narrowed across await.
            conn = tracking.get_db(identifier)  # type: ignore[unreachable]
            target = tracking.get_target_branch(conn, change_id)
            conn.close()
            assert target is None


class TestDetectInitialBase:
    """The b4.review-apply-base override in the base pre-fill chain."""

    @staticmethod
    def _head_sha(gitdir: str) -> str:
        ecode, out = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        return out.strip()

    def test_series_base_prefilled_without_config(self, gitdir: str) -> None:
        lser = _make_mock_lser()
        lser.base_commit = self._head_sha(gitdir)
        short = lser.base_commit[:12]
        with patch('b4.get_main_config', return_value={}):
            initial_base, base_hint = _detect_initial_base(lser, gitdir)
        assert initial_base == short
        assert base_hint == f'Series base: {short}'

    def test_config_base_overrides_series_base(self, gitdir: str) -> None:
        lser = _make_mock_lser()
        lser.base_commit = self._head_sha(gitdir)
        short = lser.base_commit[:12]
        with patch('b4.get_main_config', return_value={'review-apply-base': 'HEAD'}):
            initial_base, base_hint = _detect_initial_base(lser, gitdir)
        assert initial_base == 'HEAD'
        assert base_hint == f'Configured base: HEAD; Series base: {short}'

    def test_config_base_branch_name_no_series_base(self, gitdir: str) -> None:
        lser = _make_mock_lser()
        with (
            patch('b4.get_main_config', return_value={'review-apply-base': 'master'}),
            patch.object(b4.LoreSeries, 'find_base', side_effect=IndexError),
        ):
            initial_base, base_hint = _detect_initial_base(lser, gitdir)
        assert initial_base == 'master'
        assert base_hint == 'Configured base: master'

    def test_config_base_unresolvable_falls_back(self, gitdir: str) -> None:
        lser = _make_mock_lser()
        lser.base_commit = self._head_sha(gitdir)
        short = lser.base_commit[:12]
        with patch(
            'b4.get_main_config', return_value={'review-apply-base': 'no-such-ref'}
        ):
            initial_base, base_hint = _detect_initial_base(lser, gitdir)
        assert initial_base == short
        assert base_hint == (
            f'Configured base no-such-ref not found; Series base: {short}'
        )

    def test_config_base_unresolvable_no_series_base(self, gitdir: str) -> None:
        lser = _make_mock_lser()
        with (
            patch(
                'b4.get_main_config', return_value={'review-apply-base': 'no-such-ref'}
            ),
            patch.object(b4.LoreSeries, 'find_base', side_effect=IndexError),
        ):
            initial_base, base_hint = _detect_initial_base(lser, gitdir)
        assert initial_base == 'HEAD'
        assert base_hint == 'Configured base no-such-ref not found'

    def test_suggestions_include_config_base(self, gitdir: str) -> None:
        cfg = {
            'review-apply-base': 'master',
            'review-target-branch': ['for-next'],
        }
        with patch('b4.get_main_config', return_value=cfg):
            suggestions = _build_base_suggestions()
        assert suggestions[:3] == ['HEAD', 'master', 'for-next']

    def test_suggestions_no_config_base(self, gitdir: str) -> None:
        with patch('b4.get_main_config', return_value={}):
            suggestions = _build_base_suggestions()
        assert suggestions == ['HEAD']


# ---------------------------------------------------------------------------
# Helpers for update-revision tests
# ---------------------------------------------------------------------------


def _make_mock_lser(
    revision: int = 2,
    expected: int = 1,
    complete: bool = False,
    subject: str = '(untitled)',
) -> b4.LoreSeries:
    """Build a minimal LoreSeries usable by _on_update_* callbacks.

    Patches list contains a single MagicMock with msgid and body
    attributes so the Phase 3 metadata extraction succeeds.
    """
    from unittest.mock import MagicMock

    lser = b4.LoreSeries(revision, expected)
    lser.complete = complete
    lser.subject = subject
    lser.fromname = 'Test Author'
    lser.fromemail = 'test@example.com'
    mock_patch = MagicMock()
    mock_patch.msgid = 'test-update-msgid@example.com'
    mock_patch.body = 'patch body'
    mock_patch.date = None
    lser.patches = [mock_patch]
    return lser


def _setup_update_test(
    gitdir: str,
    identifier: str,
    change_id: str,
    current_rev: int = 1,
    target_rev: int = 2,
) -> str:
    """Seed a DB + review branch for update-revision tests.

    Returns the review branch name.
    """
    branch = _create_review_branch(
        gitdir,
        change_id,
        identifier=identifier,
        revision=current_rev,
        status='reviewing',
    )
    _seed_db(
        identifier,
        [
            {
                'change_id': change_id,
                'subject': f'[PATCH v{current_rev}] update test',
                'revision': current_rev,
                'status': 'reviewing',
                'message_id': f'v{current_rev}@ex.com',
            }
        ],
    )
    # Register the target revision so _do_update_revision can look it up
    conn = tracking.get_db(identifier)
    tracking.add_revision(
        conn,
        change_id,
        target_rev,
        f'v{target_rev}@ex.com',
        subject=f'[PATCH v{target_rev}] update test',
    )
    conn.close()
    return branch


class TestUpdateRevisionWorkflow:
    """Tests for the three-phase update-revision workflow.

    The refactored _do_update_revision uses a temporary upgrade branch
    so the old review branch is never modified until the new revision
    has been successfully applied.
    """

    # --- Phase 1: _do_update_revision (DB lookup + worker push) ----------

    @pytest.mark.asyncio
    async def test_no_msgid_shows_error(self, gitdir: str) -> None:
        """Target revision without a message-id should notify an error."""
        identifier = 'test-update-nomsgid'
        change_id = 'update-nomsgid-1'
        _create_review_branch(gitdir, change_id, identifier=identifier)
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH v1] no msgid test',
                    'status': 'reviewing',
                    'message_id': 'v1@ex.com',
                }
            ],
        )
        # Register v2 without a message-id
        conn = tracking.get_db(identifier)
        tracking.add_revision(
            conn, change_id, 2, '', subject='[PATCH v2] no msgid test'
        )
        conn.close()

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # Call the method directly — worker should not be pushed
            app._do_update_revision(change_id, 1, 2)
            await pilot.pause()
            # Should stay on the main screen, not a WorkerScreen
            assert not isinstance(
                app.screen,
                __import__(
                    'b4.review_tui._modals', fromlist=['WorkerScreen']
                ).WorkerScreen,
            )

    def test_fetch_worker_reports_progress(self, tmp_path: pathlib.Path) -> None:
        """Fetching an upgrade should describe each potentially slow step."""
        identifier = 'test-update-progress'
        change_id = 'update-progress-1'
        _seed_db(
            identifier,
            [
                {
                    'change_id': change_id,
                    'subject': '[PATCH v1] progress test',
                    'status': 'reviewing',
                    'message_id': 'v1@ex.com',
                }
            ],
        )
        conn = tracking.get_db(identifier)
        tracking.add_revision(
            conn,
            change_id,
            2,
            'v2@ex.com',
            subject='[PATCH v2] progress test',
            is_rethreaded=True,
        )
        conn.close()

        captured: Dict[str, Any] = {}
        statuses: List[str] = []

        def _retrieve(
            series: Dict[str, Any],
            project: str,
            progress_cb: Optional[Callable[[int, int], None]] = None,
        ) -> List[email.message.EmailMessage]:
            captured['series'] = series
            captured['project'] = project
            captured['progress_cb'] = progress_cb
            assert progress_cb is not None
            progress_cb(0, 3)
            progress_cb(1, 3)
            progress_cb(3, 3)
            return [email.message.EmailMessage()]

        lser = _make_mock_lser(expected=3)
        mock_patch = lser.patches[0]
        assert mock_patch is not None
        lser.patches = [None, mock_patch, mock_patch, mock_patch]
        am_msgs = [email.message.EmailMessage() for _ in range(3)]

        app = TrackingApp(identifier)
        with (
            patch.object(app, 'push_screen') as push_screen,
            patch.object(
                app,
                'call_from_thread',
                side_effect=lambda _update, status: statuses.append(status),
            ),
            patch(
                'b4.review.retrieve_series_messages',
                side_effect=_retrieve,
            ),
            patch('b4.review._get_lore_series', return_value=lser),
            patch.object(lser, 'get_am_ready', return_value=am_msgs),
            patch(
                'b4.save_git_am_mbox',
                side_effect=lambda _msgs, dest: dest.write(b'mbox'),
            ),
            patch('b4.git_get_toplevel', return_value='/repo'),
            patch(
                'b4.review_tui._tracking_app._detect_initial_base',
                return_value=('base-sha', 'base hint'),
            ),
        ):
            app._do_update_revision(change_id, 1, 2)
            worker_screen = push_screen.call_args.args[0]

            assert worker_screen._status == 'Fetching v2 from lore…'
            result = worker_screen._fn()

        assert captured['project'] == identifier
        assert captured['series']['revision'] == 2
        assert captured['series']['is_rethreaded'] is True
        assert callable(captured['progress_cb'])
        assert statuses == [
            'Fetching patch threads 0/3…',
            'Fetching patch threads 1/3…',
            'Fetching patch threads 3/3…',
            'Preparing 3 patches…',
            'Finding base commit…',
        ]
        assert result[-1] == 3

    # --- Phase 2: _on_update_prepared (base selection screen) ------------

    @pytest.mark.asyncio
    async def test_prepared_none_is_noop(self, tmp_path: pathlib.Path) -> None:
        """A None result (worker cancelled) should do nothing."""
        identifier = 'test-update-none'
        _seed_db(
            identifier,
            [
                {
                    'change_id': 'noop-1',
                    'subject': '[PATCH] noop',
                    'message_id': 'noop@ex.com',
                }
            ],
        )
        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._on_update_prepared(
                None, 'noop-1', 1, 2, 'v2@ex.com', 'subj', 'b4/review/noop-1'
            )
            await pilot.pause()
            # No BaseSelectionScreen should be pushed
            from b4.review_tui._modals import BaseSelectionScreen

            assert not isinstance(app.screen, BaseSelectionScreen)

    @pytest.mark.asyncio
    async def test_prepared_pushes_base_selection(self, tmp_path: pathlib.Path) -> None:
        """Successful worker result should push BaseSelectionScreen."""
        identifier = 'test-update-base'
        _seed_db(
            identifier,
            [
                {
                    'change_id': 'base-1',
                    'subject': '[PATCH] base select',
                    'message_id': 'base@ex.com',
                }
            ],
        )
        lser = _make_mock_lser()
        ambytes = b'fake mbox'
        result = (lser, ambytes, 'abc123456789', 'Guessed base: foo', 1)

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._on_update_prepared(
                result,
                'base-1',
                1,
                2,
                'v2@ex.com',
                '[PATCH v2] base select',
                'b4/review/base-1',
            )
            await pilot.pause()
            from b4.review_tui._modals import BaseSelectionScreen

            assert isinstance(app.screen, BaseSelectionScreen)

    @pytest.mark.asyncio
    async def test_prepared_prefers_series_own_title(
        self, tmp_path: pathlib.Path
    ) -> None:
        """The fetched series' title wins over a stale catalog subject.

        Regression (bug 8bb6e4c): the catalog may name patch 1/N when the
        revision was recorded before its cover letter was seen, and the
        upgrade carried that through to the series list.
        """
        identifier = 'test-update-title'
        _seed_db(
            identifier,
            [
                {
                    'change_id': 'title-1',
                    'subject': 'thing: do things better',
                    'message_id': 'v1@ex.com',
                }
            ],
        )
        lser = _make_mock_lser(subject='thing: do things better')
        result = (lser, b'fake mbox', 'abc123456789', '', 1)

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._on_update_prepared(
                result,
                'title-1',
                1,
                2,
                'v2@ex.com',
                '[PATCH v2 1/3] thing: part 1',
                'b4/review/title-1',
            )
            await pilot.pause()
            from b4.review_tui._modals import BaseSelectionScreen

            assert isinstance(app.screen, BaseSelectionScreen)
            assert app.screen._subject == 'thing: do things better'

    @pytest.mark.asyncio
    async def test_prepared_untitled_series_keeps_catalog_title(
        self, tmp_path: pathlib.Path
    ) -> None:
        """A series that never learned its title must not beat the catalog.

        LoreSeries carries an '(untitled)' placeholder until its cover or
        patch 1 is seen; a thread missing both still am-preps (get_am_ready()
        skips absent patches), and storing the placeholder would clobber a
        good catalog subject.
        """
        identifier = 'test-update-untitled'
        _seed_db(
            identifier,
            [
                {
                    'change_id': 'title-2',
                    'subject': 'thing: do things better',
                    'message_id': 'v1@ex.com',
                }
            ],
        )
        lser = _make_mock_lser(subject='(untitled)')
        result = (lser, b'fake mbox', 'abc123456789', '', 1)

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._on_update_prepared(
                result,
                'title-2',
                1,
                2,
                'v2@ex.com',
                '[PATCH v2 0/3] thing: do things better',
                'b4/review/title-2',
            )
            await pilot.pause()
            from b4.review_tui._modals import BaseSelectionScreen

            assert isinstance(app.screen, BaseSelectionScreen)
            assert app.screen._subject == '[PATCH v2 0/3] thing: do things better'

    # --- Phase 3: _on_update_base_selected (apply + swap) ----------------

    @pytest.mark.asyncio
    async def test_base_selected_none_cancels(self, tmp_path: pathlib.Path) -> None:
        """Passing None as base_sha should cancel the update."""
        identifier = 'test-update-cancel'
        _seed_db(
            identifier,
            [
                {
                    'change_id': 'cancel-1',
                    'subject': '[PATCH] cancel',
                    'message_id': 'cancel@ex.com',
                }
            ],
        )
        lser = _make_mock_lser()

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._on_update_base_selected(
                None,
                lser,
                b'mbox',
                1,
                'cancel-1',
                1,
                2,
                'v2@ex.com',
                'subj',
                'b4/review/cancel-1',
            )
            await pilot.pause()
            # App should still be running — not exited
            assert app.is_running

    @pytest.mark.asyncio
    async def test_apply_failure_preserves_old_branch(self, gitdir: str) -> None:
        """When git-am fails the old review branch must remain intact."""
        identifier = 'test-update-fail'
        change_id = 'update-fail-1'
        review_branch = _setup_update_test(gitdir, identifier, change_id)
        upgrade_branch = f'b4/review/_tmp-{change_id}-v2-upgrade'

        # Snapshot old branch HEAD before the attempt
        ecode, old_head = b4.git_run_command(gitdir, ['rev-parse', review_branch])
        assert ecode == 0
        old_head = old_head.strip()

        lser = _make_mock_lser()

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            with (
                patch.object(
                    app, 'suspend', return_value=__import__('contextlib').nullcontext()
                ),
                patch.object(app, 'exit'),
                patch('b4.review_tui._tracking_app._wait_for_enter'),
                patch(
                    'b4.git_fetch_am_into_repo',
                    side_effect=RuntimeError('apply failed'),
                ),
            ):
                app._on_update_base_selected(
                    'HEAD',
                    lser,
                    b'mbox',
                    1,
                    change_id,
                    1,
                    2,
                    'v2@ex.com',
                    'subj',
                    review_branch,
                )
            await pilot.pause()

        # Old review branch must still exist with unchanged HEAD
        assert b4.git_branch_exists(gitdir, review_branch)
        ecode, cur_head = b4.git_run_command(gitdir, ['rev-parse', review_branch])
        assert ecode == 0
        assert cur_head.strip() == old_head

        # Upgrade branch must not exist
        assert not b4.git_branch_exists(gitdir, upgrade_branch)

        # DB should still show original revision
        conn = tracking.get_db(identifier)
        cursor = conn.execute(
            'SELECT revision, status FROM series WHERE change_id = ?', (change_id,)
        )
        row = cursor.fetchone()
        conn.close()
        assert row[0] == 1
        assert row[1] == 'reviewing'

    @pytest.mark.asyncio
    async def test_conflict_abort_preserves_old_branch(self, gitdir: str) -> None:
        """When user aborts conflict resolution the old branch stays."""
        identifier = 'test-update-abort'
        change_id = 'update-abort-1'
        review_branch = _setup_update_test(gitdir, identifier, change_id)
        upgrade_branch = f'b4/review/_tmp-{change_id}-v2-upgrade'

        ecode, old_head = b4.git_run_command(gitdir, ['rev-parse', review_branch])
        assert ecode == 0
        old_head = old_head.strip()

        lser = _make_mock_lser()
        conflict = b4.AmConflictError('/tmp/fake-wt', 'conflict output')

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            with (
                patch.object(
                    app, 'suspend', return_value=__import__('contextlib').nullcontext()
                ),
                patch.object(app, 'exit'),
                patch('b4.review_tui._tracking_app._wait_for_enter'),
                patch('b4.git_fetch_am_into_repo', side_effect=conflict),
                patch(
                    'b4.resolve_am_conflict_in_shell',
                    return_value=False,
                ),
            ):
                app._on_update_base_selected(
                    'HEAD',
                    lser,
                    b'mbox',
                    1,
                    change_id,
                    1,
                    2,
                    'v2@ex.com',
                    'subj',
                    review_branch,
                )
            await pilot.pause()

        # Old review branch must be untouched
        assert b4.git_branch_exists(gitdir, review_branch)
        ecode, cur_head = b4.git_run_command(gitdir, ['rev-parse', review_branch])
        assert ecode == 0
        assert cur_head.strip() == old_head

        # Upgrade branch must not linger
        assert not b4.git_branch_exists(gitdir, upgrade_branch)

    @pytest.mark.asyncio
    async def test_successful_upgrade_renames_branch(self, gitdir: str) -> None:
        """On success the upgrade branch replaces the old review branch."""
        identifier = 'test-update-ok'
        change_id = 'update-ok-1'
        review_branch = _setup_update_test(gitdir, identifier, change_id)

        lser = _make_mock_lser()

        # Pre-create the upgrade branch to simulate create_review_branch
        ecode, base = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        base = base.strip()

        def _fake_create(
            topdir: str,
            branch: str,
            base_commit: str,
            lser_arg: b4.LoreSeries,
            linkurl: str,
            linkmask: str,
            num_prereqs: int = 0,
            identifier: Optional[str] = None,
            status: str = 'reviewing',
            **kwargs: Any,
        ) -> None:
            """Simulate create_review_branch by making a real branch."""
            branch_suffix = branch.removeprefix('b4/review/')
            _create_review_branch(
                topdir,
                branch_suffix,
                identifier=identifier or 'test',
                revision=2,
                status='reviewing',
            )

        def _mock_archive(
            self_app: TrackingApp,
            cid: str,
            rev: Optional[int],
            rbranch: str,
            pw_series_id: Optional[int] = None,
            notify: bool = True,
        ) -> bool:
            """Delete branch + mark archived in DB."""
            b4.git_run_command(gitdir, ['branch', '-D', rbranch])
            aconn = tracking.get_db(self_app._identifier)
            tracking.update_series_status(aconn, cid, 'archived', revision=rev)
            aconn.close()
            return True

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            with (
                patch.object(
                    app, 'suspend', return_value=__import__('contextlib').nullcontext()
                ),
                patch('b4.review_tui._tracking_app._wait_for_enter'),
                patch('b4.git_fetch_am_into_repo'),
                patch('b4.review.create_review_branch', side_effect=_fake_create),
                patch('b4.review.get_review_branch_patch_ids', return_value=[]),
                patch(
                    'b4.review.load_tracking',
                    return_value=('', {'series': {}, 'patches': []}),
                ),
                patch('b4.review.reanchor_patch_comments'),
                patch('b4.review.save_tracking_ref'),
                patch.object(TrackingApp, '_archive_branch', _mock_archive),
            ):
                app._on_update_base_selected(
                    base,
                    lser,
                    b'mbox',
                    1,
                    change_id,
                    1,
                    2,
                    'v2@ex.com',
                    '[PATCH v2] update test',
                    review_branch,
                )
            await pilot.pause()

            # Upgrade branch should be gone (was renamed)
            assert not b4.git_branch_exists(
                gitdir, f'b4/review/_tmp-{change_id}-v2-upgrade'
            )
            # Upgrade branch should have been renamed to review branch
            assert b4.git_branch_exists(gitdir, review_branch)

            # DB should show v2 as reviewing
            conn = tracking.get_db(identifier)
            cursor = conn.execute(
                'SELECT revision, status FROM series'
                ' WHERE change_id = ? AND revision = 2',
                (change_id,),
            )
            row = cursor.fetchone()
            conn.close()
            assert row is not None
            assert row[1] == 'reviewing'

            # Should return to tracking list, not exit to review
            assert app.is_running

    @pytest.mark.asyncio
    async def test_successful_upgrade_restores_original_branch(
        self, gitdir: str
    ) -> None:
        """A finished upgrade puts the worktree back where it found it.

        create_review_branch() checks HEAD out onto the upgrade branch and the
        swap renames that onto the review branch, so HEAD is left sitting on
        the review branch.  The tracking list comes back up when this returns,
        and quitting from there stranded the user on the review branch.
        """
        identifier = 'test-update-restore'
        change_id = 'update-restore-1'
        review_branch = _setup_update_test(gitdir, identifier, change_id)

        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', '-b', 'work'])
        assert ecode == 0

        lser = _make_mock_lser()

        def _fake_create(topdir: str, branch: str, *args: Any, **kwargs: Any) -> None:
            """Create the branch and check it out, as the real one does."""
            _create_review_branch(
                topdir,
                branch.removeprefix('b4/review/'),
                identifier=identifier,
                revision=2,
                status='reviewing',
            )
            ecode, _o = b4.git_run_command(topdir, ['checkout', '-q', branch])
            assert ecode == 0

        def _mock_archive(
            self_app: TrackingApp,
            cid: str,
            rev: Optional[int],
            rbranch: str,
            pw_series_id: Optional[int] = None,
            notify: bool = True,
        ) -> bool:
            b4.git_run_command(gitdir, ['branch', '-D', rbranch])
            aconn = tracking.get_db(self_app._identifier)
            tracking.update_series_status(aconn, cid, 'archived', revision=rev)
            aconn.close()
            return True

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            with (
                patch.object(
                    app, 'suspend', return_value=__import__('contextlib').nullcontext()
                ),
                patch('b4.review_tui._tracking_app._wait_for_enter'),
                patch('b4.git_fetch_am_into_repo'),
                patch('b4.review.create_review_branch', side_effect=_fake_create),
                patch('b4.review.get_review_branch_patch_ids', return_value=[]),
                patch(
                    'b4.review.load_tracking',
                    return_value=('', {'series': {}, 'patches': []}),
                ),
                patch('b4.review.reanchor_patch_comments'),
                patch('b4.review.save_tracking_ref'),
                patch.object(TrackingApp, '_archive_branch', _mock_archive),
            ):
                app._on_update_base_selected(
                    'HEAD',
                    lser,
                    b'mbox',
                    1,
                    change_id,
                    1,
                    2,
                    'v2@ex.com',
                    '[PATCH v2] update test',
                    review_branch,
                )
            await pilot.pause()

        # The upgrade landed, and the worktree is back on the user's branch.
        assert b4.git_branch_exists(gitdir, review_branch)
        assert b4.git_get_current_branch(gitdir) == 'work'

    @pytest.mark.asyncio
    async def test_upgrade_from_a_detached_head_puts_it_back(self, gitdir: str) -> None:
        """A detached HEAD is where the user was too.

        The upgrade renames the temporary branch onto the review branch and
        HEAD follows, so a session that started detached ends up parked on a
        branch it never asked for, with its own commit only in the reflog.
        """
        identifier = 'test-update-detached'
        change_id = 'update-detached-1'
        review_branch = _setup_update_test(gitdir, identifier, change_id)

        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', '--detach'])
        assert ecode == 0
        ecode, out = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        start_sha = out.strip()

        lser = _make_mock_lser()

        def _fake_create(topdir: str, branch: str, *args: Any, **kwargs: Any) -> None:
            _create_review_branch(
                topdir,
                branch.removeprefix('b4/review/'),
                identifier=identifier,
                revision=2,
                status='reviewing',
            )
            ecode, _o = b4.git_run_command(topdir, ['checkout', '-q', branch])
            assert ecode == 0

        def _mock_archive(
            self_app: TrackingApp,
            cid: str,
            rev: Optional[int],
            rbranch: str,
            pw_series_id: Optional[int] = None,
            notify: bool = True,
        ) -> bool:
            b4.git_run_command(gitdir, ['branch', '-D', rbranch])
            aconn = tracking.get_db(self_app._identifier)
            tracking.update_series_status(aconn, cid, 'archived', revision=rev)
            aconn.close()
            return True

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            with (
                patch.object(
                    app, 'suspend', return_value=__import__('contextlib').nullcontext()
                ),
                patch('b4.review_tui._tracking_app._wait_for_enter'),
                patch('b4.git_fetch_am_into_repo'),
                patch('b4.review.create_review_branch', side_effect=_fake_create),
                patch('b4.review.get_review_branch_patch_ids', return_value=[]),
                patch(
                    'b4.review.load_tracking',
                    return_value=('', {'series': {}, 'patches': []}),
                ),
                patch('b4.review.reanchor_patch_comments'),
                patch('b4.review.save_tracking_ref'),
                patch.object(TrackingApp, '_archive_branch', _mock_archive),
            ):
                app._on_update_base_selected(
                    'HEAD',
                    lser,
                    b'mbox',
                    1,
                    change_id,
                    1,
                    2,
                    'v2@ex.com',
                    '[PATCH v2] update test',
                    review_branch,
                )
            await pilot.pause()

        assert b4.git_branch_exists(gitdir, review_branch)
        assert b4.git_get_current_branch(gitdir) is None
        ecode, out = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        assert out.strip() == start_sha

    @pytest.mark.asyncio
    async def test_apply_failure_restores_original_branch(self, gitdir: str) -> None:
        """A create that moves HEAD and then fails leaves nothing behind.

        create_review_branch() reports failure by exiting rather than raising,
        and SystemExit is not an Exception, so the handler has to catch it too
        or the cleanup is skipped and the user is left standing on a half-built
        upgrade branch.
        """
        identifier = 'test-update-failrestore'
        change_id = 'update-failrestore-1'
        review_branch = _setup_update_test(gitdir, identifier, change_id)
        upgrade_branch = f'b4/review/_tmp-{change_id}-v2-upgrade'

        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', '-b', 'work'])
        assert ecode == 0

        lser = _make_mock_lser()

        def _fake_create(topdir: str, branch: str, *args: Any, **kwargs: Any) -> None:
            """Move HEAD onto the new branch, then die the way the real one does."""
            ecode, _o = b4.git_run_command(topdir, ['checkout', '-q', '-b', branch])
            assert ecode == 0
            raise SystemExit(1)

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            with (
                patch.object(
                    app, 'suspend', return_value=__import__('contextlib').nullcontext()
                ),
                patch('b4.review_tui._tracking_app._wait_for_enter'),
                patch('b4.git_fetch_am_into_repo'),
                patch('b4.review.create_review_branch', side_effect=_fake_create),
            ):
                app._on_update_base_selected(
                    'HEAD',
                    lser,
                    b'mbox',
                    1,
                    change_id,
                    1,
                    2,
                    'v2@ex.com',
                    'subj',
                    review_branch,
                )
            await pilot.pause()

        assert b4.git_get_current_branch(gitdir) == 'work'
        assert not b4.git_branch_exists(gitdir, upgrade_branch)
        assert b4.git_branch_exists(gitdir, review_branch)

    @pytest.mark.asyncio
    async def test_abandoned_conflict_clears_a_leftover_branch(
        self, gitdir: str
    ) -> None:
        """The upgrade branch name is derived from the series, so every
        attempt at the same upgrade reuses it.  Backing out of the conflict
        shell has to take an earlier attempt's leftover with it, or the next
        attempt walks into create_review_branch() refusing the name."""
        identifier = 'test-update-leftover'
        change_id = 'update-leftover-1'
        review_branch = _setup_update_test(gitdir, identifier, change_id)
        upgrade_branch = f'b4/review/_tmp-{change_id}-v2-upgrade'

        # An earlier attempt that ended somewhere without cleanup.
        ecode, _out = b4.git_run_command(gitdir, ['branch', upgrade_branch])
        assert ecode == 0

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            with (
                patch.object(
                    app, 'suspend', return_value=__import__('contextlib').nullcontext()
                ),
                patch('b4.review_tui._tracking_app._wait_for_enter'),
                patch(
                    'b4.git_fetch_am_into_repo',
                    side_effect=b4.AmConflictError('/tmp/wt', 'conflict'),
                ),
                patch('b4.resolve_am_conflict_in_shell', return_value=False),
            ):
                app._on_update_base_selected(
                    'HEAD',
                    _make_mock_lser(),
                    b'mbox',
                    1,
                    change_id,
                    1,
                    2,
                    'v2@ex.com',
                    'subj',
                    review_branch,
                )
            await pilot.pause()

        assert not b4.git_branch_exists(gitdir, upgrade_branch)
        # Backing out costs the upgrade, never the series being upgraded.
        assert b4.git_branch_exists(gitdir, review_branch)

    @pytest.mark.asyncio
    async def test_archive_failure_leaves_both_branches(self, gitdir: str) -> None:
        """If archiving fails, both branches are left for manual recovery."""
        identifier = 'test-update-archfail'
        change_id = 'update-archfail-1'
        review_branch = _setup_update_test(gitdir, identifier, change_id)
        upgrade_branch = f'b4/review/_tmp-{change_id}-v2-upgrade'

        lser = _make_mock_lser()

        def _fake_create(topdir: str, branch: str, *args: Any, **kwargs: Any) -> None:
            branch_suffix = branch.removeprefix('b4/review/')
            _create_review_branch(
                topdir,
                branch_suffix,
                identifier=identifier,
                revision=2,
                status='reviewing',
            )

        app = TrackingApp(identifier)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            with (
                patch.object(
                    app, 'suspend', return_value=__import__('contextlib').nullcontext()
                ),
                patch.object(app, 'exit'),
                patch('b4.review_tui._tracking_app._wait_for_enter'),
                patch('b4.git_fetch_am_into_repo'),
                patch('b4.review.create_review_branch', side_effect=_fake_create),
                patch('b4.review.get_review_branch_patch_ids', return_value=[]),
                patch(
                    'b4.review.load_tracking',
                    return_value=('', {'series': {}, 'patches': []}),
                ),
                patch('b4.review.reanchor_patch_comments'),
                patch('b4.review.save_tracking_ref'),
                patch.object(TrackingApp, '_archive_branch', return_value=False),
            ):
                app._on_update_base_selected(
                    'HEAD',
                    lser,
                    b'mbox',
                    1,
                    change_id,
                    1,
                    2,
                    'v2@ex.com',
                    'subj',
                    review_branch,
                )
            await pilot.pause()

        # Both branches should exist — user can recover manually
        assert b4.git_branch_exists(gitdir, review_branch)
        assert b4.git_branch_exists(gitdir, upgrade_branch)


class TestCheckoutFailure:
    """A series that will not apply costs the series, not the session."""

    @staticmethod
    def _checkout(app: TrackingApp, dies: Any) -> None:
        """Run _do_checkout with a create_review_branch that raises *dies*."""
        series = {'change_id': 'checkout-fail', 'revision': 1, 'message_id': 'm@ex.com'}
        with (
            patch.object(
                app, 'suspend', return_value=__import__('contextlib').nullcontext()
            ),
            patch('b4.review_tui._tracking_app._wait_for_enter'),
            patch('b4.git_fetch_am_into_repo'),
            patch('b4.review.create_review_branch', side_effect=dies),
        ):
            app._do_checkout(_make_mock_lser(revision=1), series, 'HEAD', b'mbox')

    @pytest.mark.asyncio
    async def test_the_exit_a_failed_create_reports_with_is_caught(
        self, gitdir: str
    ) -> None:
        """create_review_branch() exits rather than raising, and SystemExit is
        not an Exception, so it used to unwind through the suspend and out of
        the key handler -- taking the session down over one series."""
        app = TrackingApp('test-checkout-fail')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            self._checkout(app, SystemExit(1))
            await pilot.pause()
            assert app.is_running

    @pytest.mark.asyncio
    async def test_a_create_after_a_resolved_conflict_is_caught_too(
        self, gitdir: str
    ) -> None:
        """The branch used to be created a second time from inside the
        conflict handler, where the handler beside it cannot reach: an except
        block is not covered by its own siblings."""
        app = TrackingApp('test-checkout-conflict')
        created: List[str] = []

        def _die(topdir: str, branch: str, *a: Any, **kw: Any) -> None:
            created.append(branch)
            raise SystemExit(1)

        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            with (
                patch.object(
                    app, 'suspend', return_value=__import__('contextlib').nullcontext()
                ),
                patch('b4.review_tui._tracking_app._wait_for_enter'),
                patch(
                    'b4.git_fetch_am_into_repo',
                    side_effect=b4.AmConflictError('/tmp/wt', 'conflict'),
                ),
                patch('b4.resolve_am_conflict_in_shell', return_value=True),
                patch('b4.review.create_review_branch', side_effect=_die),
            ):
                app._do_checkout(
                    _make_mock_lser(revision=1),
                    {'change_id': 'checkout-conflict', 'revision': 1},
                    'HEAD',
                    b'mbox',
                )
            await pilot.pause()
            assert app.is_running
        # The resolve leads into the one create, not a second copy of it.
        assert created == ['b4/review/checkout-conflict']

    @pytest.mark.asyncio
    async def test_an_abandoned_conflict_creates_nothing(self, gitdir: str) -> None:
        """Backing out of the conflict shell leaves the series untouched."""
        app = TrackingApp('test-checkout-abandon')
        created: List[str] = []

        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            with (
                patch.object(
                    app, 'suspend', return_value=__import__('contextlib').nullcontext()
                ),
                patch('b4.review_tui._tracking_app._wait_for_enter'),
                patch(
                    'b4.git_fetch_am_into_repo',
                    side_effect=b4.AmConflictError('/tmp/wt', 'conflict'),
                ),
                patch('b4.resolve_am_conflict_in_shell', return_value=False),
                patch(
                    'b4.review.create_review_branch',
                    side_effect=lambda _t, b, *a, **k: created.append(b),
                ),
            ):
                app._do_checkout(
                    _make_mock_lser(revision=1),
                    {'change_id': 'checkout-abandon', 'revision': 1},
                    'HEAD',
                    b'mbox',
                )
            await pilot.pause()
            assert app.is_running
        assert not created


class TestLoadSeriesCaching:
    """Tests for _load_series batching and caching."""

    @pytest.mark.asyncio
    async def test_caches_survive_db_poll_no_change(
        self, tmp_path: pathlib.Path
    ) -> None:
        """Caches should persist when _check_db_changed finds no change."""
        _seed_db('cache-nochg', SAMPLE_SERIES)

        app = TrackingApp('cache-nochg')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            tips_id = id(app._cached_branch_tips)
            app._check_db_changed()
            await pilot.pause()
            # Same object — cache was not rebuilt
            assert id(app._cached_branch_tips) == tips_id

    @pytest.mark.asyncio
    async def test_full_invalidation_clears_all_caches(
        self, tmp_path: pathlib.Path
    ) -> None:
        """_invalidate_caches() without change_id clears everything."""
        _seed_db('cache-full-inv', SAMPLE_SERIES)

        app = TrackingApp('cache-full-inv')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            assert app._cached_branch_tips is not None
            app._invalidate_caches()
            assert app._cached_branch_tips is None
            # https://github.com/python/mypy/issues/9457:
            # app._cached_branch_tips is stale-narrowed across a method call.
            assert app._cached_newest_revisions is None  # type: ignore[unreachable]
            assert app._cached_revision_counts is None
            assert app._cached_art_counts is None

    @pytest.mark.asyncio
    async def test_selective_invalidation_keeps_other_caches(
        self, tmp_path: pathlib.Path
    ) -> None:
        """_invalidate_caches(change_id) only evicts that ART entry."""
        _seed_db('cache-sel-inv', SAMPLE_SERIES)

        app = TrackingApp('cache-sel-inv')
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            # Manually populate ART cache with test data
            app._cached_art_counts = {
                'b4/review/test-change-alpha': (1, 2, 0),
                'b4/review/test-change-bravo': (0, 1, 0),
            }
            app._invalidate_caches('test-change-alpha')
            # Alpha evicted, bravo still there
            assert 'b4/review/test-change-alpha' not in app._cached_art_counts
            assert 'b4/review/test-change-bravo' in app._cached_art_counts
            # Other caches untouched
            assert app._cached_branch_tips is not None
            assert app._cached_newest_revisions is not None


# ---------------------------------------------------------------------------
# Cross-worktree takes (merge + am share _take_worktree)
# ---------------------------------------------------------------------------


def _canned_am_patch(gitdir: str, tmp_path: pathlib.Path, fname: str) -> bytes:
    """Build a real, cleanly-applying mbox (adds *fname*) via git format-patch.

    Uses a detached worktree so it works even though master is checked out in
    the main worktree; the patch adds a brand-new file so it applies on any
    base without conflicts.
    """
    wt = str(tmp_path / f'patchgen-{fname}')
    ecode, _ = b4.git_run_command(gitdir, ['worktree', 'add', '--detach', wt, 'master'])
    assert ecode == 0
    try:
        (pathlib.Path(wt) / fname).write_text('hello from take\n')
        b4.git_run_command(wt, ['add', fname])
        ecode, _ = b4.git_run_command(wt, ['commit', '-m', f'add {fname}'])
        assert ecode == 0
        ecode, patch = b4.git_run_command(wt, ['format-patch', '-1', '--stdout'])
        assert ecode == 0
    finally:
        b4.git_run_command(gitdir, ['worktree', 'remove', '--force', wt])
    return patch.encode()


class TestTakeWorktreeHelper:
    """The shared _take_worktree picks the right worktree and cleans up.

    Both take paths (merge and am) route through this, so a target that is
    checked out elsewhere is applied there, an unchecked-out target gets a
    throwaway worktree, and the current checkout is never touched.
    """

    def test_uses_existing_worktree_and_leaves_it(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        b4.git_run_command(gitdir, ['branch', 'target', 'master'])
        linked = str(tmp_path / 'target-wt')
        ecode, _ = b4.git_run_command(gitdir, ['worktree', 'add', linked, 'target'])
        assert ecode == 0
        with _take_worktree(gitdir, 'target') as wt:
            assert wt is not None
            assert not wt.is_temp
            assert os.path.realpath(wt.path) == os.path.realpath(linked)
        # An existing worktree must survive the context.
        assert os.path.isdir(linked)

    def test_creates_and_removes_throwaway(self, gitdir: str) -> None:
        b4.git_run_command(gitdir, ['branch', 'target', 'master'])
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir
        throwaway = os.path.join(common_dir, 'b4-take-worktree')
        with _take_worktree(gitdir, 'target') as wt:
            assert wt is not None
            assert wt.is_temp
            assert os.path.realpath(wt.path) == os.path.realpath(throwaway)
            assert os.path.isdir(throwaway)
        # The throwaway is torn down on exit.
        assert not os.path.isdir(throwaway)

    def test_keep_preserves_throwaway(self, gitdir: str) -> None:
        b4.git_run_command(gitdir, ['branch', 'target', 'master'])
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir
        throwaway = os.path.join(common_dir, 'b4-take-worktree')
        with _take_worktree(gitdir, 'target') as wt:
            assert wt is not None and wt.is_temp
            wt.keep()
        # keep() leaves an unfinished worktree in place for the user.
        assert os.path.isdir(throwaway)


class TestAmTakeWorktree:
    """Regression: take->am must apply in the target branch's worktree.

    Reported failure: applying a series to a branch already checked out in
    another worktree died with "fatal: '<branch>' is already used by worktree
    ...".  The am path now mirrors the merge path and never checks out the
    target in the current worktree.
    """

    def _run_am(self, gitdir: str, target_branch: str, ambytes: bytes) -> None:
        from types import SimpleNamespace

        change_id = 'am-wt-1'
        review_branch = _create_review_branch(gitdir, change_id, status='reviewing')
        app = TrackingApp.__new__(TrackingApp)
        app._identifier = None  # type: ignore[assignment]  # ty: ignore[invalid-assignment]
        app._selected_series = {}
        app._prepare_am_messages = lambda *a, **k: ambytes  # type: ignore[method-assign]  # ty: ignore[invalid-assignment]
        take_screen: Any = SimpleNamespace(
            target_result=target_branch,
            add_signoff=False,
            add_link=False,
            accept_series=False,
        )
        with patch('b4.review_tui._tracking_app._wait_for_enter'):
            app._do_take_am(
                change_id, review_branch, take_screen, {'subject': 'x'}, None
            )

    def test_applies_to_target_in_other_worktree(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        # Target checked out in a *separate* worktree -- the reported failure.
        b4.git_run_command(gitdir, ['branch', 'vfs.fixes', 'master'])
        linked = str(tmp_path / 'vfs.fixes-wt')
        ecode, _ = b4.git_run_command(gitdir, ['worktree', 'add', linked, 'vfs.fixes'])
        assert ecode == 0

        ecode, head_before = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        ecode, branch_before = b4.git_run_command(
            gitdir, ['rev-parse', '--abbrev-ref', 'HEAD']
        )

        ambytes = _canned_am_patch(gitdir, tmp_path, 'takefile.txt')
        self._run_am(gitdir, 'vfs.fixes', ambytes)

        # The patch landed on vfs.fixes...
        ecode, subj = b4.git_run_command(
            gitdir, ['log', '-1', '--format=%s', 'vfs.fixes']
        )
        assert ecode == 0 and subj.strip() == 'add takefile.txt'
        # ...without disturbing the current checkout.
        ecode, head_after = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert head_after.strip() == head_before.strip()
        ecode, branch_after = b4.git_run_command(
            gitdir, ['rev-parse', '--abbrev-ref', 'HEAD']
        )
        assert branch_after.strip() == branch_before.strip()

    def test_applies_via_throwaway_when_not_checked_out(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        # Target exists but is checked out nowhere -> throwaway worktree.
        b4.git_run_command(gitdir, ['branch', 'vfs.fixes', 'master'])
        ecode, head_before = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])

        ambytes = _canned_am_patch(gitdir, tmp_path, 'takefile.txt')
        self._run_am(gitdir, 'vfs.fixes', ambytes)

        ecode, subj = b4.git_run_command(
            gitdir, ['log', '-1', '--format=%s', 'vfs.fixes']
        )
        assert ecode == 0 and subj.strip() == 'add takefile.txt'
        # Current checkout untouched and the throwaway worktree is gone.
        ecode, head_after = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert head_after.strip() == head_before.strip()
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir
        assert not os.path.isdir(os.path.join(common_dir, 'b4-take-worktree'))

    def test_applies_into_main_worktree_from_other_cwd(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        # Regression: target checked out in the MAIN worktree while b4 is driven
        # from a different cwd. git_run_command targets a primary worktree via
        # --git-dir (not -C), so the apply must anchor its cwd (rundir) to the
        # target worktree, else git-am writes the patched files into the wrong
        # one -- committing to the branch but leaving the target worktree dirty.
        side = str(tmp_path / 'side-wt')
        b4.git_run_command(gitdir, ['branch', 'sidebr', 'master'])
        ecode, _ = b4.git_run_command(gitdir, ['worktree', 'add', side, 'sidebr'])
        assert ecode == 0

        ambytes = _canned_am_patch(gitdir, tmp_path, 'takefile.txt')

        olddir = os.getcwd()
        os.chdir(side)
        try:
            self._run_am(gitdir, 'master', ambytes)
        finally:
            os.chdir(olddir)

        # The patch landed on master, written into the MAIN worktree...
        ecode, subj = b4.git_run_command(gitdir, ['log', '-1', '--format=%s', 'master'])
        assert ecode == 0 and subj.strip() == 'add takefile.txt'
        assert os.path.isfile(os.path.join(gitdir, 'takefile.txt'))
        # ...not leaked into the driving worktree, and the target stays clean.
        assert not os.path.isfile(os.path.join(side, 'takefile.txt'))
        ecode, status = b4.git_run_command(
            gitdir, ['status', '--porcelain', '--untracked-files=no']
        )
        assert ecode == 0 and status.strip() == ''


class TestTakeThankArchiveChain:
    """The take dialog's thank-and-archive checkbox chains into the thank
    flow only when the take leaves the series fully accepted."""

    def _run_take_final(
        self,
        take_status: Optional[str],
        thank_and_archive: bool,
        accept_series: bool = True,
    ) -> Tuple[List[Tuple[Dict[str, Any], bool]], List[str]]:
        """Drive _on_take_final with a mocked take returning *take_status*.

        Returns (recorded _start_thank calls, notification messages).
        """
        import contextlib
        from types import SimpleNamespace

        thanks: List[Tuple[Dict[str, Any], bool]] = []
        notices: List[str] = []
        app = TrackingApp.__new__(TrackingApp)
        take_screen: Any = SimpleNamespace(
            accept_series=accept_series, thank_and_archive=thank_and_archive
        )
        confirm_screen: Any = SimpleNamespace(accept_series=accept_series)
        series = {'change_id': 'chain-1', 'subject': 'x', 'status': 'reviewing'}
        with (
            patch.object(TrackingApp, 'suspend', lambda self: contextlib.nullcontext()),
            patch.object(TrackingApp, '_invalidate_caches', lambda self, cid: None),
            patch.object(TrackingApp, '_load_series', lambda self: None),
            patch.object(
                TrackingApp, '_do_take_merge', lambda self, *a, **k: take_status
            ),
            patch.object(
                TrackingApp,
                '_start_thank',
                lambda self, series, archive_after=False: thanks.append(
                    (series, archive_after)
                ),
            ),
            patch.object(
                TrackingApp,
                'notify',
                lambda self, message, **k: notices.append(str(message)),
            ),
        ):
            app._on_take_final(
                True,
                'merge',
                'chain-1',
                'b4/review/chain-1',
                take_screen,
                series,
                confirm_screen,
            )
        return thanks, notices

    def test_accepted_take_chains_into_thank(self) -> None:
        thanks, _notices = self._run_take_final('accepted', True)
        assert len(thanks) == 1
        chained, archive_after = thanks[0]
        assert archive_after
        # The chained series dict reflects the post-take status, so the
        # thank flow sees an accepted series regardless of reload timing.
        assert chained['status'] == 'accepted'
        assert chained['change_id'] == 'chain-1'

    def test_partial_take_does_not_chain(self) -> None:
        thanks, notices = self._run_take_final('partial', True)
        assert not thanks
        assert any('partially applied' in n for n in notices)

    def test_aborted_take_says_so(self) -> None:
        """A take that never finished is reported as such, not as a series
        the maintainer declined to accept."""
        thanks, notices = self._run_take_final(None, True)
        assert not thanks
        assert any('take did not complete' in n for n in notices)

    def test_unaccepted_take_does_not_chain(self) -> None:
        thanks, notices = self._run_take_final(None, True, accept_series=False)
        assert not thanks
        assert any('not marked accepted' in n for n in notices)

    def test_unrecorded_take_says_so(self) -> None:
        """The patches went in but the tracking data could not be read, so
        there is no coverage to chain on -- and 'did not complete' would send
        the maintainer looking for an apply that did happen."""
        thanks, notices = self._run_take_final('unrecorded', True)
        assert not thanks
        assert any('was not recorded' in n for n in notices)

    def test_unchecked_box_never_chains(self) -> None:
        thanks, notices = self._run_take_final('accepted', False)
        assert not thanks
        assert not notices


class TestSendThankMessage:
    """Everything after a successful send is bookkeeping, and bookkeeping
    must not be able to claim the send failed."""

    def _send(
        self, archive_raises: bool, dryrun: bool = False
    ) -> Tuple[List[Tuple[str, str]], List[List[Any]]]:
        """Drive _send_thank_message with a send that succeeds.

        Returns (notifications as (message, severity), mark_outgoing_seen
        calls).
        """
        import contextlib

        notices: List[Tuple[str, str]] = []
        seen_calls: List[List[Any]] = []
        archived: List[str] = []
        app = TrackingApp.__new__(TrackingApp)
        app._email_dryrun = dryrun
        app._patatt_sign = False
        app._identifier = ''
        msg = email.message.EmailMessage()
        msg['Message-Id'] = '<thanks@example.com>'
        series = {'change_id': 'send-1', 'revision': 1}

        def _archive(self: Any, _series: Dict[str, Any]) -> None:
            archived.append(str(_series.get('change_id', '')))
            if archive_raises:
                raise OSError(28, 'No space left on device')

        with (
            patch.object(TrackingApp, 'suspend', lambda self: contextlib.nullcontext()),
            patch.object(TrackingApp, '_invalidate_caches', lambda self, cid: None),
            patch.object(TrackingApp, '_load_series', lambda self: None),
            patch.object(TrackingApp, '_archive_after_thanks', _archive),
            patch.object(
                TrackingApp,
                'notify',
                lambda self, message, severity='information', **k: notices.append(
                    (str(message), severity)
                ),
            ),
            patch('b4.get_smtp', return_value=(None, 'me@example.com')),
            patch('b4.send_mail', return_value=0 if dryrun else 1),
            patch(
                'b4.review_tui._tracking_app.mark_outgoing_seen',
                lambda msgs, dryrun=False: seen_calls.append(list(msgs)),
            ),
        ):
            app._send_thank_message(msg, series, archive_after=True)
        self.archived = archived
        return notices, seen_calls

    def test_marks_the_sent_message_seen(self) -> None:
        """The thank-you is a reply into the series thread, so it comes back
        from the list; recording it at send time keeps the badge dark."""
        _notices, seen_calls = self._send(archive_raises=False)
        assert len(seen_calls) == 1
        assert seen_calls[0][0]['Message-Id'] == '<thanks@example.com>'

    def test_failed_archive_is_not_a_send_failure(self) -> None:
        """A broken archive must never read as 'Send failed': that tells the
        maintainer to re-send a note that is already on the list."""
        notices, _seen = self._send(archive_raises=True)
        texts = [n for n, _sev in notices]
        assert 'Thank-you message sent' in texts
        assert not any('Send failed' in n for n in texts)
        assert any('No space left on device' in n for n in texts)

    def test_a_dry_run_is_not_recorded_as_thanked(self) -> None:
        """--email-dry-run logs the note and stops there.  Marking the series
        thanked -- and archiving it, which deletes the review branch -- would
        spend a real series on a rehearsal."""
        notices, seen = self._send(archive_raises=False, dryrun=True)
        texts = [n for n, _sev in notices]
        assert any('Dry-run' in n for n in texts)
        assert not any('Thank-you message sent' in n for n in texts)
        assert not seen
        assert not self.archived


# ---------------------------------------------------------------------------
# take->merge conflict resolution (must never drop a non-empty commit)
# ---------------------------------------------------------------------------


def _conflict_base(gitdir: str) -> str:
    """Commit a shared file onto the current branch; return the new HEAD sha."""
    (pathlib.Path(gitdir) / 'shared.txt').write_text('a\nb\nc\n')
    b4.git_run_command(gitdir, ['add', 'shared.txt'])
    ecode, _ = b4.git_run_command(gitdir, ['commit', '-m', 'add shared.txt'])
    assert ecode == 0
    ecode, base = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
    assert ecode == 0
    return base.strip()


def _conflicted_merge_worktree(gitdir: str, tmp_path: pathlib.Path) -> Tuple[str, str]:
    """Park a worktree on a conflicted ``git merge``.

    The merged-in ("theirs") side edits the shared file (forcing the conflict)
    *and* adds a brand-new file -- the kind of non-empty change that
    ``b4 shazam --resolve`` silently drops via ``git add -u``. Returns
    (worktree_path, pre_merge_head).
    """
    base = _conflict_base(gitdir)
    b4.git_run_command(gitdir, ['branch', 'ours', base])
    b4.git_run_command(gitdir, ['branch', 'theirs', base])

    ours_wt = str(tmp_path / 'ours-wt')
    ecode, _ = b4.git_run_command(gitdir, ['worktree', 'add', ours_wt, 'ours'])
    assert ecode == 0
    (pathlib.Path(ours_wt) / 'shared.txt').write_text('a\nOURS\nc\n')
    b4.git_run_command(ours_wt, ['add', 'shared.txt'])
    ecode, _ = b4.git_run_command(ours_wt, ['commit', '-m', 'ours edits shared'])
    assert ecode == 0

    theirs_wt = str(tmp_path / 'theirs-wt')
    ecode, _ = b4.git_run_command(gitdir, ['worktree', 'add', theirs_wt, 'theirs'])
    assert ecode == 0
    (pathlib.Path(theirs_wt) / 'shared.txt').write_text('a\nTHEIRS\nc\n')
    (pathlib.Path(theirs_wt) / 'newfile.txt').write_text('brand new\n')
    b4.git_run_command(theirs_wt, ['add', '-A'])
    ecode, _ = b4.git_run_command(
        theirs_wt, ['commit', '-m', 'theirs edits shared and adds newfile']
    )
    assert ecode == 0
    b4.git_run_command(gitdir, ['worktree', 'remove', '--force', theirs_wt])

    ecode, pre = b4.git_run_command(ours_wt, ['rev-parse', 'HEAD'])
    assert ecode == 0
    pre = pre.strip()
    ecode, _ = b4.git_run_command(
        ours_wt, ['merge', '--no-ff', 'theirs'], logstderr=True
    )
    assert ecode != 0  # conflict on shared.txt
    return ours_wt, pre


def _resolve_shared(*_args: Any, **kwargs: Any) -> None:
    """_suspend_to_shell stand-in: resolve the conflict and finish the merge."""
    cwd = kwargs['cwd']
    (pathlib.Path(cwd) / 'shared.txt').write_text('a\nRESOLVED\nc\n')
    b4.git_run_command(cwd, ['add', 'shared.txt'])
    ecode, _ = b4.git_run_command(cwd, ['commit', '--no-edit'])
    assert ecode == 0


class TestMergeConflictResolution:
    """take->merge finishes the *same* real merge, dropping nothing.

    Unlike ``b4 shazam --resolve`` (which replays not-yet-applied patches with
    ``git apply --3way`` + ``git add -u`` and so silently omits a patch that
    adds a new file), the conflicted ``git merge`` is completed in place, so the
    merged-in side stays fully reachable and every added file survives.
    """

    def test_in_progress_detects_and_clears(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        wt, _pre = _conflicted_merge_worktree(gitdir, tmp_path)
        assert _worktree_merge_in_progress(wt) is True
        b4.git_run_command(wt, ['merge', '--abort'])
        assert _worktree_merge_in_progress(wt) is False

    def test_resolution_keeps_added_file(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        wt, pre = _conflicted_merge_worktree(gitdir, tmp_path)
        handle = _TakeWorktree(wt, is_temp=False)
        with patch(
            'b4.review_tui._tracking_app._suspend_to_shell',
            side_effect=_resolve_shared,
        ):
            ok = _resolve_worktree_take_conflict(
                handle, 'merge', pre, _worktree_merge_in_progress
            )
        assert ok is True
        # A real two-parent merge commit...
        ecode, parents = b4.git_run_command(wt, ['rev-list', '--parents', '-1', 'HEAD'])
        assert ecode == 0 and len(parents.split()) == 3
        # ...with the merged-in side fully reachable (no commit dropped)...
        ecode, theirs = b4.git_run_command(wt, ['rev-parse', 'theirs'])
        assert ecode == 0
        ecode, _ = b4.git_run_command(
            wt, ['merge-base', '--is-ancestor', theirs.strip(), 'HEAD']
        )
        assert ecode == 0
        # ...and the brand-new file (shazam --resolve drops it) is present.
        ecode, content = b4.git_run_command(wt, ['show', 'HEAD:newfile.txt'])
        assert ecode == 0 and content.strip() == 'brand new'
        ecode, shared = b4.git_run_command(wt, ['show', 'HEAD:shared.txt'])
        assert ecode == 0 and 'RESOLVED' in shared

    def test_abort_returns_false_and_restores_head(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        wt, pre = _conflicted_merge_worktree(gitdir, tmp_path)
        handle = _TakeWorktree(wt, is_temp=False)

        def _abort(*_a: Any, **kw: Any) -> None:
            b4.git_run_command(kw['cwd'], ['merge', '--abort'])

        with patch('b4.review_tui._tracking_app._suspend_to_shell', side_effect=_abort):
            ok = _resolve_worktree_take_conflict(
                handle, 'merge', pre, _worktree_merge_in_progress
            )
        assert ok is False
        ecode, head = b4.git_run_command(wt, ['rev-parse', 'HEAD'])
        assert ecode == 0 and head.strip() == pre
        assert _worktree_merge_in_progress(wt) is False

    def test_incomplete_keeps_throwaway(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        wt, pre = _conflicted_merge_worktree(gitdir, tmp_path)
        handle = _TakeWorktree(wt, is_temp=True)
        # User exits the shell without finishing the merge.
        with patch('b4.review_tui._tracking_app._suspend_to_shell'):
            ok = _resolve_worktree_take_conflict(
                handle, 'merge', pre, _worktree_merge_in_progress
            )
        assert ok is False
        assert handle._keep is True
        assert _worktree_merge_in_progress(wt) is True

    def test_real_worktree_incomplete_auto_aborts(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        """A real checkout left mid-op is aborted, never poisoned.

        Counterpart to test_incomplete_keeps_throwaway: a throwaway worktree is
        kept for the user, but a real checkout must be restored -- otherwise its
        unmerged index breaks the user's git work and makes the next take fail
        cryptically on top of it.
        """
        wt, pre = _conflicted_merge_worktree(gitdir, tmp_path)
        handle = _TakeWorktree(wt, is_temp=False)
        # User exits the shell WITHOUT finishing or aborting the merge.
        with patch('b4.review_tui._tracking_app._suspend_to_shell'):
            ok = _resolve_worktree_take_conflict(
                handle, 'merge', pre, _worktree_merge_in_progress
            )
        assert ok is False
        assert _worktree_merge_in_progress(wt) is False
        assert _worktree_has_unmerged(wt) is False
        ecode, head = b4.git_run_command(wt, ['rev-parse', 'HEAD'])
        assert ecode == 0 and head.strip() == pre


def _strip_merge_pseudo_refs(wt: str) -> None:
    """Leave *wt*'s index unmerged but remove its in-progress-merge markers.

    Reproduces the resting state that breaks the next take: stage>0 entries with
    no MERGE_HEAD/etc, which git refuses to start a fresh op on top of yet no
    ``--abort`` can clear.
    """
    ecode, gd = b4.git_run_command(wt, ['rev-parse', '--absolute-git-dir'])
    assert ecode == 0
    for fname in ('MERGE_HEAD', 'MERGE_MSG', 'AUTO_MERGE'):
        try:
            os.unlink(os.path.join(gd.strip(), fname))
        except OSError:
            pass


class TestWorktreeOpDetection:
    """_worktree_inprogress_op / _worktree_has_unmerged / _abort_worktree_op."""

    def test_detects_merge_and_clean(self, gitdir: str, tmp_path: pathlib.Path) -> None:
        wt, _pre = _conflicted_merge_worktree(gitdir, tmp_path)
        assert _worktree_inprogress_op(wt) == 'merge'
        assert _worktree_has_unmerged(wt) is True
        b4.git_run_command(wt, ['merge', '--abort'])
        assert _worktree_inprogress_op(wt) is None
        assert _worktree_has_unmerged(wt) is False

    def test_detects_cherry_pick(self, gitdir: str, tmp_path: pathlib.Path) -> None:
        wt, _pre = _conflicted_merge_worktree(gitdir, tmp_path)
        b4.git_run_command(wt, ['merge', '--abort'])
        # The same divergent edit to shared.txt now conflicts as a cherry-pick.
        ecode, _ = b4.git_run_command(wt, ['cherry-pick', 'theirs'], logstderr=True)
        assert ecode != 0
        assert _worktree_inprogress_op(wt) == 'cherry-pick'
        b4.git_run_command(wt, ['cherry-pick', '--abort'])
        assert _worktree_inprogress_op(wt) is None

    def test_abort_op_aborts_merge(self, gitdir: str, tmp_path: pathlib.Path) -> None:
        wt, pre = _conflicted_merge_worktree(gitdir, tmp_path)
        assert _abort_worktree_op(wt) == 'merge'
        ecode, head = b4.git_run_command(wt, ['rev-parse', 'HEAD'])
        assert ecode == 0 and head.strip() == pre
        assert _worktree_inprogress_op(wt) is None
        assert _worktree_has_unmerged(wt) is False

    def test_abort_op_resets_bare_unmerged_index(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        wt, _pre = _conflicted_merge_worktree(gitdir, tmp_path)
        _strip_merge_pseudo_refs(wt)
        assert _worktree_inprogress_op(wt) is None
        assert _worktree_has_unmerged(wt) is True
        assert _abort_worktree_op(wt) == 'reset'
        assert _worktree_has_unmerged(wt) is False

    def test_abort_op_noop_on_clean(self, gitdir: str, tmp_path: pathlib.Path) -> None:
        b4.git_run_command(gitdir, ['branch', 'target', 'master'])
        linked = str(tmp_path / 'clean-wt')
        ecode, _ = b4.git_run_command(gitdir, ['worktree', 'add', linked, 'target'])
        assert ecode == 0
        assert _abort_worktree_op(linked) is None


class TestTakeWorktreeRefusesDirtyTarget:
    """_take_worktree refuses a target worktree that is mid-op or conflicted.

    A take's git-am/git-merge would otherwise fail cryptically on top of the
    leftover state; refuse up front instead, without discarding state that may
    be the user's own.
    """

    def test_refuses_inprogress_merge(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        wt, _pre = _conflicted_merge_worktree(gitdir, tmp_path)  # 'ours' is in wt
        with patch('b4.review_tui._tracking_app._wait_for_enter'):
            with _take_worktree(gitdir, 'ours') as handle:
                assert handle is None
        # Refusing must leave the conflicted state untouched for the user.
        assert _worktree_merge_in_progress(wt) is True

    def test_refuses_bare_unmerged_index(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        wt, _pre = _conflicted_merge_worktree(gitdir, tmp_path)
        _strip_merge_pseudo_refs(wt)
        assert _worktree_inprogress_op(wt) is None
        assert _worktree_has_unmerged(wt) is True
        with patch('b4.review_tui._tracking_app._wait_for_enter'):
            with _take_worktree(gitdir, 'ours') as handle:
                assert handle is None

    def test_allows_clean_target(self, gitdir: str, tmp_path: pathlib.Path) -> None:
        b4.git_run_command(gitdir, ['branch', 'target', 'master'])
        linked = str(tmp_path / 'clean-target')
        ecode, _ = b4.git_run_command(gitdir, ['worktree', 'add', linked, 'target'])
        assert ecode == 0
        with _take_worktree(gitdir, 'target') as handle:
            assert handle is not None
            assert not handle.is_temp


def _series_mbox_add_and_edit(gitdir: str, tmp_path: pathlib.Path, base: str) -> bytes:
    """Two patches at *base*: add newfile.txt, then edit shared.txt line 2."""
    wt = str(tmp_path / 'seriesgen')
    ecode, _ = b4.git_run_command(gitdir, ['worktree', 'add', '--detach', wt, base])
    assert ecode == 0
    try:
        (pathlib.Path(wt) / 'newfile.txt').write_text('brand new\n')
        b4.git_run_command(wt, ['add', 'newfile.txt'])
        ecode, _ = b4.git_run_command(wt, ['commit', '-m', 'add newfile.txt'])
        assert ecode == 0
        (pathlib.Path(wt) / 'shared.txt').write_text('a\nPATCH\nc\n')
        b4.git_run_command(wt, ['add', 'shared.txt'])
        ecode, _ = b4.git_run_command(wt, ['commit', '-m', 'edit shared.txt'])
        assert ecode == 0
        ecode, patches = b4.git_run_command(
            wt, ['format-patch', '--stdout', f'{base}..HEAD']
        )
        assert ecode == 0
    finally:
        b4.git_run_command(gitdir, ['worktree', 'remove', '--force', wt])
    return patches.encode()


class TestDoTakeMergeConflict:
    """End-to-end: _do_take_merge resolves a real merge conflict in place."""

    def _run(self, gitdir: str, target_branch: str, ambytes: bytes) -> None:
        from types import SimpleNamespace

        change_id = 'merge-conflict-e2e'
        review_branch = _create_review_branch(gitdir, change_id, status='reviewing')
        app = TrackingApp.__new__(TrackingApp)
        app._identifier = None  # type: ignore[assignment]  # ty: ignore[invalid-assignment]
        app._selected_series = {}
        app._prepare_am_messages = lambda *a, **k: ambytes  # type: ignore[method-assign]  # ty: ignore[invalid-assignment]
        take_screen: Any = SimpleNamespace(
            target_result=target_branch,
            add_signoff=False,
            add_link=False,
            accept_series=False,
        )
        with (
            patch('b4.review_tui._tracking_app._wait_for_enter'),
            patch(
                'b4.review_tui._tracking_app._suspend_to_shell',
                side_effect=_resolve_shared,
            ),
        ):
            app._do_take_merge(
                change_id, review_branch, take_screen, {'subject': 'x'}, None
            )

    def test_resolves_without_dropping_added_file(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        base = _conflict_base(gitdir)
        # Target diverges on shared.txt and is checked out nowhere (throwaway).
        b4.git_run_command(gitdir, ['branch', 'target', base])
        twt = str(tmp_path / 'target-edit')
        ecode, _ = b4.git_run_command(gitdir, ['worktree', 'add', twt, 'target'])
        assert ecode == 0
        (pathlib.Path(twt) / 'shared.txt').write_text('a\nTARGET\nc\n')
        b4.git_run_command(twt, ['add', 'shared.txt'])
        b4.git_run_command(twt, ['commit', '-m', 'target diverges'])
        b4.git_run_command(gitdir, ['worktree', 'remove', '--force', twt])

        ambytes = _series_mbox_add_and_edit(gitdir, tmp_path, base)
        self._run(gitdir, 'target', ambytes)

        # target advanced to a real two-parent merge commit...
        ecode, parents = b4.git_run_command(
            gitdir, ['rev-list', '--parents', '-1', 'target']
        )
        assert ecode == 0 and len(parents.split()) == 3
        # ...the added-file patch survived (the shazam --resolve drop bug)...
        ecode, content = b4.git_run_command(gitdir, ['show', 'target:newfile.txt'])
        assert ecode == 0 and content.strip() == 'brand new'
        ecode, shared = b4.git_run_command(gitdir, ['show', 'target:shared.txt'])
        assert ecode == 0 and 'RESOLVED' in shared
        # ...and the throwaway worktree was cleaned up.
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None
        assert not os.path.isdir(os.path.join(common_dir, 'b4-take-worktree'))


def _poison_gpg_signing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force commit.gpgsign=true with a signing backend that always fails.

    The appended entries override conftest's gpgsign=false injection, so
    any git command that tries to sign fails outright; only a command
    that explicitly disables signing (git -c commit.gpgsign=false, which
    outranks environment config) can create commits.

    gpg.format is pinned because the suite does not isolate the global
    git config: under gpg.format=ssh git signs through gpg.ssh.program
    and never looks at gpg.program, so the probes would sign happily and
    these tests would pass with the fix reverted.

    Build fixtures before poisoning -- they commit normally.
    """
    entries = [
        ('commit.gpgsign', 'true'),
        ('gpg.format', 'openpgp'),
        ('gpg.program', '/bin/false'),
    ]
    count = int(os.environ.get('GIT_CONFIG_COUNT', '0'))
    monkeypatch.setenv('GIT_CONFIG_COUNT', str(count + len(entries)))
    for idx, (key, value) in enumerate(entries, start=count):
        monkeypatch.setenv(f'GIT_CONFIG_KEY_{idx}', key)
        monkeypatch.setenv(f'GIT_CONFIG_VALUE_{idx}', value)


def _one_patch_mbox(gitdir: str) -> bytes:
    """Build mbox bytes for one patch that applies cleanly to master."""
    ecode, _ = b4.git_run_command(gitdir, ['checkout', '-b', 'sign-tweak'])
    assert ecode == 0
    with open(os.path.join(gitdir, 'file1.txt'), 'a') as fh:
        fh.write('sign-tweak\n')
    b4.git_run_command(gitdir, ['add', 'file1.txt'])
    ecode, _ = b4.git_run_command(gitdir, ['commit', '-m', 'sign-tweak file1'])
    assert ecode == 0
    ecode, mbox = b4.git_run_command(
        gitdir, ['format-patch', '-1', '--stdout'], decode=False
    )
    assert ecode == 0
    b4.git_run_command(gitdir, ['checkout', 'master'])
    b4.git_run_command(gitdir, ['branch', '-D', 'sign-tweak'])
    return mbox


class TestTestApplyNoSigning:
    """Throwaway test-applies must never gpg-sign their commits.

    With commit.gpgsign=true and a card-backed key, a signing git-am in a
    modal worker pops pinentry on the tty the live TUI owns -- the TUI
    repaints over the prompt and swallows the PIN, hanging the apply.
    With gpg poisoned to always fail, these pass only if the test-apply
    disables signing.
    """

    @pytest.mark.parametrize(
        'screen_cls',
        [RebaseScreen, TargetBranchScreen, BaseSelectionScreen],
        ids=lambda c: c.__name__,
    )
    def test_static_test_apply_does_not_sign(
        self,
        gitdir: str,
        monkeypatch: pytest.MonkeyPatch,
        screen_cls: Any,
    ) -> None:
        ambytes = _one_patch_mbox(gitdir)
        _poison_gpg_signing(monkeypatch)
        ok, detail = screen_cls._test_apply_at(ambytes, 'master')
        assert ok, f'{screen_cls.__name__} test-apply tried to sign: {detail}'

    def test_take_confirm_test_apply_does_not_sign(
        self, gitdir: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        branch = _create_review_branch(gitdir, 'sign-take', with_patch=True)
        _poison_gpg_signing(monkeypatch)
        screen = TakeConfirmScreen('linear', 'master', branch)
        ok, detail = screen._test_take()
        assert ok, f'take test-apply tried to sign: {detail}'


class TestTestApplySubmoduleRecurse:
    """The same test-applies must survive the user's submodule.recurse.

    Their scratch worktree is as fresh as any other, so the sparse
    ``checkout -f`` hits the same missing-submodule-clone fatal and every
    probe reports a failure that has nothing to do with the patches.
    """

    @pytest.mark.parametrize(
        'screen_cls',
        [RebaseScreen, TargetBranchScreen, BaseSelectionScreen],
        ids=lambda c: c.__name__,
    )
    def test_static_test_apply_ignores_submodule_recurse(
        self,
        gitdir: str,
        screen_cls: Any,
        add_unpopulated_submodule: Callable[..., str],
    ) -> None:
        ambytes = _one_patch_mbox(gitdir)
        add_unpopulated_submodule(gitdir)
        b4.git_set_config(gitdir, 'submodule.recurse', 'true')
        ok, detail = screen_cls._test_apply_at(ambytes, 'master')
        assert ok, f'{screen_cls.__name__} test-apply recursed: {detail}'

    def test_take_confirm_test_apply_ignores_submodule_recurse(
        self, gitdir: str, add_unpopulated_submodule: Callable[..., str]
    ) -> None:
        branch = _create_review_branch(gitdir, 'recurse-take', with_patch=True)
        add_unpopulated_submodule(gitdir)
        b4.git_set_config(gitdir, 'submodule.recurse', 'true')
        screen = TakeConfirmScreen('linear', 'master', branch)
        ok, detail = screen._test_take()
        assert ok, f'take test-apply recursed: {detail}'


class TestTrackingEntryBranchRestore:
    """run_tracking_tui() puts the worktree back on the way out."""

    def test_quitting_after_an_upgrade_restores_the_branch(self, gitdir: str) -> None:
        """The tracking list has actions of its own that move HEAD.

        Upgrading a series to a newer revision checks out an upgrade branch
        and renames it onto the review branch.  Quitting from the list then
        went straight out of the loop, past a restore that only ran after a
        review pass, and left the worktree on the review branch.
        """
        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', '-b', 'work'])
        assert ecode == 0
        review_branch = 'b4/review/entry-restore-1'

        class _MovesHeadThenQuits:
            PATCHWORK_SENTINEL = TrackingApp.PATCHWORK_SENTINEL

            def __init__(
                self, identifier: str, original_branch: Optional[str], **kw: Any
            ) -> None:
                pass

            def run(self, mouse: bool = True) -> Optional[str]:
                b4.git_run_command(gitdir, ['checkout', '-q', '-b', review_branch])
                return None

        with patch.object(_entry, 'TrackingApp', _MovesHeadThenQuits):
            _entry.run_tracking_tui('test-entry-restore')

        assert b4.git_get_current_branch(gitdir) == 'work'

    def test_quitting_after_an_upgrade_restores_a_detached_head(
        self, gitdir: str
    ) -> None:
        """A session that started detached has a commit to go back to, and
        putting the user on a branch instead is not restoring anything."""
        ecode, out = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        start_sha = out.strip()
        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', '--detach'])
        assert ecode == 0
        review_branch = 'b4/review/entry-restore-detached'

        class _MovesHeadThenQuits:
            PATCHWORK_SENTINEL = TrackingApp.PATCHWORK_SENTINEL

            def __init__(
                self, identifier: str, original_branch: Optional[str], **kw: Any
            ) -> None:
                pass

            def run(self, mouse: bool = True) -> Optional[str]:
                b4.git_run_command(gitdir, ['checkout', '-q', '-b', review_branch])
                return None

        with patch.object(_entry, 'TrackingApp', _MovesHeadThenQuits):
            _entry.run_tracking_tui('test-entry-restore-detached')

        assert b4.git_get_current_branch(gitdir) is None
        ecode, out = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        assert out.strip() == start_sha

    def test_a_failed_tracking_load_still_restores_the_branch(
        self, gitdir: str
    ) -> None:
        """load_tracking() exits rather than raising on a branch carrying no
        tracking commit, and SystemExit is not an Exception, so it sailed past
        the status sync's guard and out of run_tracking_tui() -- taking the
        branch restore with it."""
        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', '-b', 'work'])
        assert ecode == 0
        review_branch = 'b4/review/entry-syncfail-1'
        runs = {'n': 0}

        class _ReviewsThenQuits:
            PATCHWORK_SENTINEL = TrackingApp.PATCHWORK_SENTINEL

            def __init__(
                self, identifier: str, original_branch: Optional[str], **kw: Any
            ) -> None:
                pass

            def run(self, mouse: bool = True) -> Optional[str]:
                runs['n'] += 1
                if runs['n'] > 1:
                    return None
                b4.git_run_command(gitdir, ['checkout', '-q', '-b', review_branch])
                return review_branch

        with (
            patch.object(_entry, 'TrackingApp', _ReviewsThenQuits),
            patch.object(_entry, 'ReviewApp'),
            patch.object(
                b4.review,
                '_prepare_review_session',
                return_value={'series': {'revision': 1}},
            ),
            patch.object(b4.review, 'load_tracking', side_effect=SystemExit(1)),
        ):
            _entry.run_tracking_tui('test-entry-syncfail')

        assert b4.git_get_current_branch(gitdir) == 'work'

    def test_a_failed_status_sync_closes_the_database(self, gitdir: str) -> None:
        """The connection is opened inside the guard that swallows the
        failure, so a write that raises used to skip the close and leave it
        open for the rest of the session."""
        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', '-b', 'work'])
        assert ecode == 0
        review_branch = 'b4/review/entry-dbclose-1'
        runs = {'n': 0}
        closed: List[bool] = []

        class _Conn:
            def close(self) -> None:
                closed.append(True)

        class _ReviewsThenQuits:
            PATCHWORK_SENTINEL = TrackingApp.PATCHWORK_SENTINEL

            def __init__(
                self, identifier: str, original_branch: Optional[str], **kw: Any
            ) -> None:
                pass

            def run(self, mouse: bool = True) -> Optional[str]:
                runs['n'] += 1
                if runs['n'] > 1:
                    return None
                return review_branch

        def _boom(*args: Any, **kwargs: Any) -> None:
            raise sqlite3.OperationalError('database is locked')

        with (
            patch.object(_entry, 'TrackingApp', _ReviewsThenQuits),
            patch.object(_entry, 'ReviewApp'),
            patch.object(
                b4.review,
                '_prepare_review_session',
                return_value={'series': {'revision': 1}},
            ),
            patch.object(
                b4.review,
                'load_tracking',
                return_value=('', {'series': {'status': 'replied'}}),
            ),
            patch.object(tracking, 'get_db', return_value=_Conn()),
            patch.object(tracking, 'update_series_status', side_effect=_boom),
        ):
            _entry.run_tracking_tui('test-entry-dbclose')

        assert closed == [True]
