#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Integration tests for the ReviewApp TUI.

Tests the shell-return reconciliation logic that detects and handles
cosmetic commit edits (e.g. reworded subjects via git rebase -i).
"""

import json
from typing import Any, Dict, List, Tuple
from unittest import mock

import pytest

pytest.importorskip('textual')

import b4
import b4.review
from b4.review_tui._review_app import ReviewApp

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_review_branch_with_patches(
    gitdir: str,
    change_id: str,
    patch_messages: List[str],
    identifier: str = 'test-project',
    revision: int = 1,
    status: str = 'reviewing',
    subject: str = 'Test series',
) -> Tuple[str, List[str]]:
    """Create a review branch with real patch commits and a tracking commit.

    Each entry in *patch_messages* becomes a separate commit (with an
    empty diff via --allow-empty).  A tracking commit is appended at the
    tip.

    Returns (branch_name, list_of_patch_commit_shas).
    """
    branch_name = f'b4/review/{change_id}'

    # Base commit
    ecode, base_sha = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
    assert ecode == 0
    base_sha = base_sha.strip()

    # Create the branch
    ecode, _ = b4.git_run_command(gitdir, ['branch', branch_name, base_sha])
    assert ecode == 0
    ecode, _ = b4.git_run_command(gitdir, ['checkout', branch_name])
    assert ecode == 0

    # Create patch commits
    patch_shas: List[str] = []
    for msg in patch_messages:
        ecode, _ = b4.git_run_command(gitdir, ['commit', '--allow-empty', '-m', msg])
        assert ecode == 0
        ecode, sha = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        patch_shas.append(sha.strip())

    # Build tracking metadata
    patches_meta: List[Dict[str, Any]] = []
    for i, _sha in enumerate(patch_shas):
        patches_meta.append(
            {
                'header-info': {'msgid': f'{change_id}-patch{i + 1}@example.com'},
                'followups': [],
            }
        )

    trk: Dict[str, Any] = {
        'series': {
            'identifier': identifier,
            'change-id': change_id,
            'revision': revision,
            'status': status,
            'subject': subject,
            'fromname': 'Test Author',
            'fromemail': 'test@example.com',
            'expected': len(patch_messages),
            'complete': True,
            'base-commit': base_sha,
            'prerequisite-commits': [],
            'first-patch-commit': patch_shas[0],
            'header-info': {},
        },
        'followups': [],
        'patches': patches_meta,
    }
    commit_msg = f'{subject}\n\n{b4.review.make_review_magic_json(trk)}'

    # Create tracking commit (empty)
    ecode, _ = b4.git_run_command(gitdir, ['commit', '--allow-empty', '-m', commit_msg])
    assert ecode == 0

    return branch_name, patch_shas


def _build_session(gitdir: str, branch_name: str) -> Dict[str, Any]:
    """Build a ReviewApp session dict from a review branch."""
    cover_text, tracking = b4.review.load_tracking(gitdir, branch_name)
    series = tracking['series']
    patches = tracking.get('patches', [])
    base_commit = series['base-commit']

    first_patch = series.get('first-patch-commit', '')
    if first_patch:
        range_spec = f'{first_patch}~1..{branch_name}~1'
    else:
        range_spec = f'{base_commit}..{branch_name}~1'

    ecode, out = b4.git_run_command(gitdir, ['rev-list', '--reverse', range_spec])
    assert ecode == 0
    commit_shas = out.strip().splitlines()

    ecode, out = b4.git_run_command(
        gitdir, ['log', '--reverse', '--format=%s', range_spec]
    )
    assert ecode == 0
    commit_subjects = out.strip().splitlines()

    ecode, out = b4.git_run_command(gitdir, ['rev-parse', '--short', 'HEAD'])
    abbrev_len = len(out.strip()) if ecode == 0 else 7

    sha_map: Dict[str, Tuple[str, int]] = {}
    for idx, full_sha in enumerate(commit_shas):
        sha_map[full_sha[:abbrev_len]] = (full_sha, idx)

    usercfg = b4.get_user_config()

    return {
        'topdir': gitdir,
        'branch': branch_name,
        'cover_text': cover_text,
        'tracking': tracking,
        'series': series,
        'patches': patches,
        'base_commit': base_commit,
        'commit_shas': commit_shas,
        'commit_subjects': commit_subjects,
        'sha_map': sha_map,
        'abbrev_len': abbrev_len,
        'default_identity': f'{usercfg.get("name", "Test")} <{usercfg.get("email", "test@example.com")}>',
        'usercfg': usercfg,
        'cover_subject_clean': series.get('subject', ''),
    }


def _save_tracking_msg(gitdir: str) -> str:
    """Save the tracking commit message from HEAD."""
    ecode, msg = b4.git_run_command(gitdir, ['log', '-1', '--format=%B', 'HEAD'])
    assert ecode == 0
    return msg.strip()


def _rewrite_patches(
    gitdir: str, base_sha: str, new_subjects: List[str], trk_msg: str
) -> None:
    """Reset to base and recreate patches + tracking commit.

    Hard-resets to *base_sha*, creates one --allow-empty commit per
    subject in *new_subjects*, then recreates the tracking commit
    from *trk_msg*.
    """
    ecode, _ = b4.git_run_command(gitdir, ['reset', '--hard', base_sha])
    assert ecode == 0
    for subj in new_subjects:
        ecode, _ = b4.git_run_command(gitdir, ['commit', '--allow-empty', '-m', subj])
        assert ecode == 0
    ecode, _ = b4.git_run_command(gitdir, ['commit', '--allow-empty', '-m', trk_msg])
    assert ecode == 0


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestTrailerConsolidation:
    """Tests for consolidating matching trailers onto a cover letter."""

    @pytest.mark.asyncio
    async def test_coverless_patch_keeps_trailer_with_comments(
        self, gitdir: str
    ) -> None:
        """A coverless patch sends its trailer and comments in one email."""
        branch, _patch_shas = _create_review_branch_with_patches(
            gitdir, 'coverless-trailer', ['patch 1']
        )
        session = _build_session(gitdir, branch)
        session['cover_text'] = (
            'patch 1\n\nNOTE: No cover letter provided by the author.'
        )
        my_email = str(session['usercfg']['email'])
        session['patches'][0]['reviews'] = {
            my_email: {
                'name': str(session['usercfg']['name']),
                'comments': [{'path': 'file', 'line': 1, 'text': 'Comment'}],
            }
        }

        app = ReviewApp(session)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('t')
            await pilot.pause()
            await pilot.press('r')
            await pilot.press('q')
            await pilot.pause()

            assert 'reviews' not in app._series
            patch_review = app._patches[0]['reviews'][my_email]
            assert patch_review['trailers'] == [f'Reviewed-by: {app._default_identity}']
            assert patch_review['comments']

            with mock.patch(
                'b4.review._review._build_review_email',
                return_value=mock.sentinel.email,
            ):
                msgs = b4.review.collect_review_emails(
                    app._series,
                    app._patches,
                    app._cover_text,
                    app._topdir,
                    app._commit_shas,
                )
            assert msgs == [mock.sentinel.email]


class TestReplyVerbatim:
    """The edited reply buffer is the source of truth and is kept verbatim."""

    @pytest.mark.asyncio
    async def test_edit_reply_keeps_buffer_and_parses_trailers(
        self, gitdir: str
    ) -> None:
        import contextlib

        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'reply-verbatim', ['patch 1']
        )
        session = _build_session(gitdir, branch)
        app = ReviewApp(session)
        my_email = str(session['usercfg']['email'])

        buffer = (
            'Thanks for the new version!\n'
            '\n'
            'You need to Cc\n'
            'stable: without that fix things break.\n'
            '\n'
            'Reviewed-by: Me <me@example.com>'
        )
        seen: List[str] = []

        def fake_editor(data: bytes, filehint: str = '') -> bytes:
            seen.append(data.decode())
            return buffer.encode()

        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._selected_idx = 1
            with (
                mock.patch('b4.edit_in_editor', side_effect=fake_editor),
                mock.patch.object(app, 'suspend', lambda: contextlib.nullcontext()),
            ):
                app.action_edit_reply()
                await pilot.pause()

                review = app._patches[0]['reviews'][my_email]
                # Buffer stored verbatim — nothing relocated or stripped.
                assert review['reply'] == buffer
                # Trailer derived for display; prose "stable:" is NOT a trailer.
                assert review['trailers'] == ['Reviewed-by: Me <me@example.com>']

                # Re-opening seeds the editor with the verbatim buffer, so the
                # trailer the maintainer typed is still visible.
                app.action_edit_reply()
                await pilot.pause()
                assert 'Reviewed-by: Me <me@example.com>' in seen[-1]


class TestReconcileAfterShell:
    """Tests for _reconcile_after_shell tracking fixup."""

    @pytest.mark.asyncio
    async def test_no_changes(self, gitdir: str) -> None:
        """No-op when commits are unchanged after shell return."""
        branch, patch_shas = _create_review_branch_with_patches(
            gitdir, 'reconcile-noop', ['patch 1', 'patch 2']
        )
        session = _build_session(gitdir, branch)

        app = ReviewApp(session)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            old_shas = list(app._commit_shas)
            app._reconcile_after_shell(old_shas)
            # Nothing should change
            assert app._commit_shas == old_shas
            assert app._series['first-patch-commit'] == patch_shas[0]

    @pytest.mark.asyncio
    async def test_reworded_commits(self, gitdir: str) -> None:
        """Tracking is updated after commit messages are reworded."""
        branch, patch_shas = _create_review_branch_with_patches(
            gitdir, 'reconcile-reword', ['original subject 1', 'original subject 2']
        )
        session = _build_session(gitdir, branch)
        base_sha = session['base_commit']

        app = ReviewApp(session)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            old_shas = list(app._commit_shas)
            assert len(old_shas) == 2

            # Simulate rewording both commits (as git rebase -i would)
            trk_msg = _save_tracking_msg(gitdir)
            _rewrite_patches(
                gitdir, base_sha, ['reworded subject 1', 'reworded subject 2'], trk_msg
            )

            app._reconcile_after_shell(old_shas)

            # SHAs should have changed
            assert app._commit_shas != old_shas
            assert len(app._commit_shas) == 2
            # first-patch-commit should be updated
            assert app._series['first-patch-commit'] == app._commit_shas[0]
            assert app._series['first-patch-commit'] != patch_shas[0]
            # Subjects should reflect the reword
            assert app._commit_subjects == ['reworded subject 1', 'reworded subject 2']
            # sha_map should be updated
            assert len(app._sha_map) == 2

    @pytest.mark.asyncio
    async def test_single_reword_preserves_unchanged(self, gitdir: str) -> None:
        """Only the reworded commit gets a new SHA; unchanged ones keep theirs."""
        branch, _patch_shas = _create_review_branch_with_patches(
            gitdir, 'reconcile-partial', ['keep this one', 'change this one']
        )
        session = _build_session(gitdir, branch)

        app = ReviewApp(session)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            old_shas = list(app._commit_shas)

            # Reword only the second commit: reset to after first patch,
            # then recreate second + tracking
            trk_msg = _save_tracking_msg(gitdir)
            ecode, _ = b4.git_run_command(gitdir, ['reset', '--hard', old_shas[0]])
            assert ecode == 0
            ecode, _ = b4.git_run_command(
                gitdir, ['commit', '--allow-empty', '-m', 'changed subject 2']
            )
            assert ecode == 0
            ecode, _ = b4.git_run_command(
                gitdir, ['commit', '--allow-empty', '-m', trk_msg]
            )
            assert ecode == 0

            app._reconcile_after_shell(old_shas)

            assert len(app._commit_shas) == 2
            # First commit unchanged
            assert app._commit_shas[0] == old_shas[0]
            # Second commit changed
            assert app._commit_shas[1] != old_shas[1]
            assert app._commit_subjects[1] == 'changed subject 2'

    @pytest.mark.asyncio
    async def test_patch_count_mismatch(self, gitdir: str) -> None:
        """Warns and does not update when patch count changes."""
        branch, patch_shas = _create_review_branch_with_patches(
            gitdir, 'reconcile-mismatch', ['patch 1', 'patch 2', 'patch 3']
        )
        session = _build_session(gitdir, branch)
        base_sha = session['base_commit']

        app = ReviewApp(session)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            old_shas = list(app._commit_shas)
            assert len(old_shas) == 3

            # Simulate squashing: recreate with fewer patches
            trk_msg = _save_tracking_msg(gitdir)
            _rewrite_patches(gitdir, base_sha, ['patch 1', 'squashed 2+3'], trk_msg)

            # Reconcile should NOT update tracking
            app._reconcile_after_shell(old_shas)

            # Original state should be preserved
            assert app._commit_shas == old_shas
            assert app._series['first-patch-commit'] == patch_shas[0]

    @pytest.mark.asyncio
    async def test_tracking_commit_persisted(self, gitdir: str) -> None:
        """The on-disk tracking commit is amended with new first-patch-commit."""
        branch, _patch_shas = _create_review_branch_with_patches(
            gitdir, 'reconcile-persist', ['persist patch 1', 'persist patch 2']
        )
        session = _build_session(gitdir, branch)
        base_sha = session['base_commit']

        app = ReviewApp(session)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            old_shas = list(app._commit_shas)

            # Reword both patches
            trk_msg = _save_tracking_msg(gitdir)
            _rewrite_patches(
                gitdir, base_sha, ['reworded persist 1', 'reworded persist 2'], trk_msg
            )

            app._reconcile_after_shell(old_shas)

            # Verify the on-disk tracking commit was updated
            _cover_text, tracking = b4.review.load_tracking(gitdir, branch)
            disk_first = tracking['series']['first-patch-commit']
            assert disk_first == app._commit_shas[0]
            assert disk_first != old_shas[0]


class TestLoreNodeShutdown:
    """The app cancels the shared lore node when it quits.

    Single-shot network workers block inside one fetch and cannot poll a
    cancellation flag, so the app cancels the lore node on shutdown to
    unblock any in-flight request instead of stalling on exit.
    """

    @pytest.mark.asyncio
    async def test_quit_cancels_lore_node(self, gitdir: str) -> None:
        branch, _patch_shas = _create_review_branch_with_patches(
            gitdir, 'shutdown-cancel', ['patch 1']
        )
        session = _build_session(gitdir, branch)

        node = mock.Mock()
        app = ReviewApp(session)
        # Patch the singleton accessor so we observe the shutdown cancel
        # without touching real lore state.
        with mock.patch('b4.get_lore_node', return_value=node):
            async with app.run_test(size=(120, 30)) as pilot:
                await pilot.pause()
                await pilot.press('q')
                await pilot.pause()

        # on_unmount fired during shutdown and cancelled the node.
        assert node.cancel.called


class TestRenderDetailLines:
    """The check-details renderer surfaces checkpatch source-line context."""

    def _render(self, details: List[Dict[str, str]]) -> str:
        from rich.text import Text

        from b4.review_tui._modals import TrackingCheckResultsScreen

        # _render_detail_lines only touches the class-level _STATUS_DOTS, so we
        # can exercise it without standing up a full Textual screen.
        screen = object.__new__(TrackingCheckResultsScreen)
        body = Text()
        screen._render_detail_lines(body, json.dumps(details))
        return body.plain

    def test_srcline_rendered_as_indented_context(self) -> None:
        out = self._render(
            [
                {
                    'status': 'warn',
                    'description': 'Possible unwrapped commit description',
                    'srcline': 'A very long commit message line over the limit',
                }
            ]
        )
        assert 'Possible unwrapped commit description' in out
        assert '    A very long commit message line over the limit' in out

    def test_no_srcline_no_extra_line(self) -> None:
        out = self._render(
            [{'status': 'fail', 'description': 'ERROR: trailing whitespace'}]
        )
        assert 'ERROR: trailing whitespace' in out
        # Only the finding line itself, no indented context underneath.
        assert '\n    ' not in out
