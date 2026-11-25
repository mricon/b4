#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Integration tests for the ReviewApp TUI.

Covers follow-up reply composition and sending, the shell-return
reconciliation that detects cosmetic commit edits (e.g. reworded subjects
via git rebase -i), range-diff filtering and gating, check-detail
rendering, and the branch-restore logic on exit.
"""

import copy
import datetime
import email.message
import json
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest import mock

import pytest

pytest.importorskip('textual')

from textual.widgets import ListView, RichLog, Static

import b4
import b4.review
import b4.review._review
import b4.review.tracking
from b4.review._review import NO_COVER_NOTE
from b4.review_tui._common import filter_range_diff_for_commit
from b4.review_tui._modals import ConfirmScreen, NoteScreen, SendScreen
from b4.review_tui._review_app import FollowupItem, PatchListItem, ReviewApp

from .helpers.mail import followup_thread
from .helpers.tracking import create_review_branch
from .helpers.tui import (
    CUT_BUFFER,
    CUT_INSTRUCTION,
    CUT_TRIMMED,
    current_screen,
    static_text,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_review_branch_with_patches(
    gitdir: str,
    change_id: str,
    patch_messages: List[str],
    **kwargs: Any,
) -> Tuple[str, List[str]]:
    """Create a review branch with real patch commits and leave HEAD on it.

    Returns (branch_name, list_of_patch_commit_shas).
    """
    branch = create_review_branch(
        gitdir, change_id, patch_messages=patch_messages, checkout=True, **kwargs
    )
    return branch, branch.patch_shas


def _selected_followup(app: ReviewApp) -> Optional[str]:
    """Read the selection fresh, past mypy narrowing it to what we set."""
    return app._selected_followup_msgid


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
            assert [msg for _review, msg in msgs] == [mock.sentinel.email]


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

        def fake_editor(data: bytes, filehint: str = '', **kwargs: Any) -> bytes:
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

    @pytest.mark.asyncio
    async def test_trailer_menu_keeps_unmanaged_trailers(self, gitdir: str) -> None:
        """Toggling a menu trailer must not delete a hand-typed Fixes: line.

        Regression test for the report in
        https://lore.kernel.org/tools/b2c44799-85a9-4576-9aae-b43eb1092315@kernel.org/
        """
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'trailer-menu-fixes', ['patch 1']
        )
        session = _build_session(gitdir, branch)
        my_email = str(session['usercfg']['email'])
        buffer = (
            'Please add a Fixes tag. Here I guess it should be:\n'
            '\n'
            'Fixes: 1234567890ab ("some patch")\n'
        )
        session['patches'][0]['reviews'] = {
            my_email: {
                'name': str(session['usercfg']['name']),
                'reply': buffer,
            }
        }

        app = ReviewApp(session)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._selected_idx = 1
            await pilot.press('t')
            await pilot.pause()
            await pilot.press('r')
            await pilot.press('q')
            await pilot.pause()

            review = app._patches[0]['reviews'][my_email]
            assert 'Fixes: 1234567890ab ("some patch")' in review['reply']
            assert f'Reviewed-by: {app._default_identity}' in review['reply']
            assert review['trailers'] == [
                'Fixes: 1234567890ab ("some patch")',
                f'Reviewed-by: {app._default_identity}',
            ]

    @pytest.mark.asyncio
    async def test_trailer_menu_heals_crlf_buffer(self, gitdir: str) -> None:
        """A stored buffer with legacy CRLF endings comes out LF-only after a
        trailer toggle, instead of gaining mixed line endings."""
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'trailer-menu-crlf', ['patch 1']
        )
        session = _build_session(gitdir, branch)
        my_email = str(session['usercfg']['email'])
        session['patches'][0]['reviews'] = {
            my_email: {
                'name': str(session['usercfg']['name']),
                'reply': 'Thanks, looks good!\r\n',
            }
        }

        app = ReviewApp(session)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._selected_idx = 1
            await pilot.press('t')
            await pilot.pause()
            await pilot.press('r')
            await pilot.press('q')
            await pilot.pause()

            review = app._patches[0]['reviews'][my_email]
            assert '\r' not in review['reply']
            assert review['reply'] == (
                f'Thanks, looks good!\n\nReviewed-by: {app._default_identity}'
            )


class TestTrailerMenuAfterSend:
    """A trailer already sent must not end up in a follow-up reply buffer.

    After a send the reply moves out of the review, so a follow-up starts
    from a fresh buffer that does not hold the sent trailers.  That buffer
    is sent verbatim, so any sent trailer written into it goes to the list
    a second time.
    """

    SENT = 'Reviewed-by: Me <me@example.com>'
    SENT_NACK = 'NACKed-by: Me <me@example.com>'

    def _app(
        self, gitdir: str, change_id: str, sent: str, reply: str
    ) -> Tuple[ReviewApp, str]:
        """Return (an app whose review of patch 1 sent *sent* and now holds
        the follow-up buffer *reply*, my email)."""
        # Two patches, so that a trailer staged on one is not promoted to
        # the cover letter
        branch, _shas = _create_review_branch_with_patches(
            gitdir, change_id, ['patch 1', 'patch 2']
        )
        session = _build_session(gitdir, branch)
        my_email = str(session['usercfg']['email'])
        my_review = {
            'name': str(session['usercfg']['name']),
            'trailers': [sent],
            'sent': {'trailers': [sent]},
            'sent-revision': 1,
        }
        if reply:
            my_review['reply'] = reply
        session['patches'][0]['reviews'] = {my_email: my_review}
        return ReviewApp(session), my_email

    async def _menu(
        self,
        gitdir: str,
        change_id: str,
        result: Optional[List[str]],
        sent: str = SENT,
        reply: str = 'One more thing.\n',
    ) -> Tuple[Any, Dict[str, Any]]:
        """Open the trailer menu after a send and answer *result*.

        Returns (the menu screen shown, my review after the answer).
        """
        shown: List[Any] = []

        def _answer(screen: Any, callback: Any = None) -> None:
            shown.append(screen)
            if result is not None:
                callback(result)

        app, my_email = self._app(gitdir, change_id, sent, reply)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._selected_idx = 1
            with mock.patch.object(app, 'push_screen', _answer):
                app.action_trailer()
            await pilot.pause()
            return shown[0], app._patches[0]['reviews'][my_email]

    @pytest.mark.asyncio
    async def test_sent_trailer_shown_ticked(self, gitdir: str) -> None:
        screen, _review = await self._menu(gitdir, 'trailer-sent-ticked', None)
        assert 'Reviewed-by' in screen._existing

    @pytest.mark.asyncio
    async def test_sent_trailer_not_written_to_buffer(self, gitdir: str) -> None:
        """Confirming the menu with the sent trailer ticked leaves it out of
        the buffer, and keeps it in the review as sent."""
        _screen, my_review = await self._menu(
            gitdir, 'trailer-sent-confirm', ['Reviewed-by']
        )
        assert 'Reviewed-by' not in my_review['reply']
        assert my_review['trailers'] == [self.SENT]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        'reply',
        [
            pytest.param('Fine now.\n', id='follow-up-buffer'),
            pytest.param('', id='no-buffer'),
        ],
    )
    async def test_ack_after_sent_nack_takes_over(
        self, gitdir: str, reply: str
    ) -> None:
        """The sent NACKed-by shows ticked, and it supersedes the others.
        Ticking Acked-by next to it must still stage the ack, or there is
        no way to take a NACK back."""
        _screen, my_review = await self._menu(
            gitdir,
            f'trailer-ack-after-nack-{bool(reply)}',
            ['NACKed-by', 'Acked-by'],
            sent=self.SENT_NACK,
            reply=reply,
        )
        assert [t.split(':')[0] for t in my_review['trailers']] == ['Acked-by']
        if reply:
            assert 'Acked-by: ' in my_review['reply']

    @pytest.mark.asyncio
    async def test_sent_trailer_stays_in_overlay(self, gitdir: str) -> None:
        """The follow-up buffer does not hold the sent trailer, but it is
        still part of my review and must not vanish from its summary."""
        app, _my_email = self._app(
            gitdir, 'trailer-sent-overlay', self.SENT, 'One more thing.\n'
        )
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._selected_idx = 1
            overlay = app.query_one('#trailer-overlay')
            with mock.patch.object(overlay, 'update') as update:
                app._refresh_trailer_overlay()
            assert 'Reviewed-by' in update.call_args.args[0].plain


class TestFollowupSelection:
    """Per-message follow-up selection is scoped to the patch being shown."""

    @pytest.mark.asyncio
    async def test_selected_followup_cleared_on_show_content(self, gitdir: str) -> None:
        """Switching patches forgets the follow-up picked under the old one."""
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'followup-sel', ['patch 1', 'patch 2']
        )
        app = ReviewApp(_build_session(gitdir, branch))
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._selected_followup_msgid = 'reply@example.com'
            assert app.check_action('edit_reply', ()) is True
            app._show_content(2)
            await pilot.pause()
            assert _selected_followup(app) is None
            assert app._selected_idx == 2

    @pytest.mark.asyncio
    async def test_same_author_followups_are_separate_targets(
        self, gitdir: str
    ) -> None:
        """Two replies from one author get two entries; reply hits the picked one."""
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'followup-same-author', ['patch 1']
        )
        app = ReviewApp(_build_session(gitdir, branch))
        entries = [
            {
                'msgid': f'reply-{n}@example.com',
                'fromname': 'Alice',
                'fromemail': 'alice@example.com',
                'date': datetime.datetime(2026, 1, n, tzinfo=datetime.timezone.utc),
                'body': f'Reply number {n}.',
            }
            for n in (1, 2)
        ]
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._followup_comments = {1: entries}
            app._populate_patch_list()
            await pilot.pause()
            lv = app.query_one('#patch-list', ListView)
            items = [c for c in lv.children if isinstance(c, FollowupItem)]
            assert [i.msgid for i in items] == [e['msgid'] for e in entries]

            lv.index = lv.children.index(items[1])
            await pilot.pause()
            assert _selected_followup(app) == 'reply-2@example.com'
            positions = app._followup_positions
            assert positions['reply-1@example.com'] != positions['reply-2@example.com']
            with mock.patch.object(app, '_compose_followup_reply') as compose:
                app.action_edit_reply()
            compose.assert_called_once_with(entries[1])


class TestFollowupSnipMarker:
    """Quick follow-up replies expose and resolve the snip marker."""

    def test_compose_includes_marker_instructions(self, gitdir: str) -> None:
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'followup-snip-instructions', ['patch 1']
        )
        app = ReviewApp(_build_session(gitdir, branch))
        entry = {
            'date': 'Thu, 1 Jan 2026 12:00:00 +0000',
            'fromname': 'Reviewer',
            'fromemail': 'reviewer@example.com',
            'body': 'First line.\nSecond line.',
        }

        with mock.patch(
            'b4.review_tui._review_app.suspend_and_edit', return_value=None
        ) as edit:
            app._compose_followup_reply(entry)

        editor_text = edit.call_args.args[1].decode()
        assert editor_text.startswith('# Put ">--cut--" alone on a line')
        assert '# back to your last note; b4 resolves it when you send.' in editor_text
        assert '> First line.\n> Second line.' in editor_text

    def test_send_resolves_marker_and_drops_trailing_quote(self, gitdir: str) -> None:
        import contextlib

        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'followup-snip-send', ['patch 1']
        )
        session = _build_session(gitdir, branch)
        session['email_dryrun'] = True
        app = ReviewApp(session)
        lmsg = mock.Mock()
        outgoing = email.message.EmailMessage()
        lmsg.make_reply.return_value = outgoing
        entry = {'lmsg': lmsg, 'fromemail': 'reviewer@example.com'}
        buffer = CUT_INSTRUCTION + CUT_BUFFER

        with (
            mock.patch.object(
                app, 'suspend', side_effect=lambda: contextlib.nullcontext()
            ),
            mock.patch.object(app, 'notify'),
            mock.patch('b4.get_smtp', return_value=(None, 'me@example.com')),
            mock.patch('b4.send_mail', return_value=0) as send_mail,
        ):
            app._send_followup_reply(entry, buffer)

        lmsg.make_reply.assert_called_once_with(
            CUT_TRIMMED + '\n\n-- \n' + b4.get_email_signature()
        )
        assert send_mail.call_args.args[1] == [outgoing]


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
        """Tracking, in memory and on disk, is updated after commit messages
        are reworded."""
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
            # The on-disk tracking commit was amended with the new
            # first-patch-commit too.
            _cover_text, tracking = b4.review.load_tracking(gitdir, branch)
            disk_first = tracking['series']['first-patch-commit']
            assert disk_first == app._commit_shas[0]
            assert disk_first != old_shas[0]

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


class TestEditorFailure:
    """A broken editor is reported, never fatal."""

    @pytest.mark.asyncio
    async def test_editor_error_does_not_tear_down_the_app(self, gitdir: str) -> None:
        """An exception from the editor used to unwind out of the key handler
        and kill the app, taking the rest of the session's unsaved review
        state with it."""
        import contextlib

        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'editor-error', ['patch 1']
        )
        session = _build_session(gitdir, branch)
        app = ReviewApp(session)
        my_email = str(session['usercfg']['email'])

        def boom(*args: Any, **kwargs: Any) -> bytes:
            raise RuntimeError('editor exploded')

        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._selected_idx = 1
            with (
                mock.patch('b4.edit_in_editor', side_effect=boom),
                mock.patch.object(app, 'suspend', lambda: contextlib.nullcontext()),
                mock.patch.object(app, 'notify') as notified,
            ):
                app.action_edit_reply()
                await pilot.pause()

            assert app.is_running
            assert notified.call_args.kwargs.get('severity') == 'error'
            reviews = app._patches[0].get('reviews', {})
            assert not reviews.get(my_email, {}).get('reply')


class TestBranchRestore:
    """b4 only puts back a branch it moved itself."""

    def test_restore_skips_a_checkout_b4_did_not_make(self, gitdir: str) -> None:
        """The worktree the TUI runs in is shared with the user's other
        terminals; a branch they switched to there is not ours to undo."""
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'restore-foreign', ['patch 1']
        )
        session = _build_session(gitdir, branch)
        session['original_branch'] = 'master'
        app = ReviewApp(session)
        app.branch_checked_out = True

        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', '-b', 'mine'])
        assert ecode == 0

        app._restore_original_branch()
        assert b4.git_get_current_branch(gitdir) == 'mine'
        assert app.branch_checked_out is False

    def test_restore_undoes_b4s_own_checkout(self, gitdir: str) -> None:
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'restore-own', ['patch 1']
        )
        session = _build_session(gitdir, branch)
        session['original_branch'] = 'master'
        app = ReviewApp(session)
        assert app._ensure_branch_checked_out()
        assert b4.git_get_current_branch(gitdir) == branch

        app._restore_original_branch()
        assert b4.git_get_current_branch(gitdir) == 'master'
        assert app.branch_checked_out is False

    def test_restore_lands_back_on_a_detached_head(self, gitdir: str) -> None:
        """A session that started detached has a commit to go back to, and a
        branch name is not it -- so nothing used to put the user back."""
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'restore-detached', ['patch 1']
        )
        ecode, _out = b4.git_run_command(
            gitdir, ['checkout', '-q', '--detach', 'master']
        )
        assert ecode == 0
        ecode, out = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        start_sha = out.strip()

        session = _build_session(gitdir, branch)
        session['original_head'] = ['checkout', '--detach', start_sha]
        app = ReviewApp(session)
        assert app._ensure_branch_checked_out()
        assert b4.git_get_current_branch(gitdir) == branch

        app._restore_original_branch()
        assert b4.git_get_current_branch(gitdir) is None
        ecode, out = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        assert out.strip() == start_sha
        assert app.branch_checked_out is False


class TestSkippedReplies:
    """Skipping a patch keeps it out of a take, not out of the conversation:
    a reply can explain why the patch is not being taken."""

    @pytest.mark.asyncio
    async def test_skipped_reply_is_previewed(self, gitdir: str) -> None:
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'skipped-preview', ['patch 1']
        )
        session = _build_session(gitdir, branch)
        my_email = str(session['usercfg']['email'])
        reply = 'Please fix this before I can take it.'
        session['patches'][0]['reviews'] = {
            my_email: {'patch-state': 'skip', 'reply': reply}
        }
        app = ReviewApp(session)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app._show_content(1)
            await pilot.press('e')
            await pilot.pause()
            viewer = app.query_one('#diff-viewer', RichLog)
            assert reply in '\n'.join(line.text for line in viewer.lines)

    @pytest.mark.asyncio
    @pytest.mark.parametrize('how', ['skip', 'landed'])
    async def test_hiding_skipped_keeps_unsent_replies_visible(
        self, gitdir: str, how: str
    ) -> None:
        """A hidden patch must not carry mail out unseen: H only hides
        skipped patches that have nothing left to send. Patches that landed
        elsewhere are hidden along with skipped ones."""
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'skipped-hide', ['patch 1', 'patch 2']
        )
        session = _build_session(gitdir, branch)
        my_email = str(session['usercfg']['email'])
        session['patches'][0]['reviews'] = {
            my_email: {'patch-state': 'skip', 'reply': 'Not taking this.'}
        }
        if how == 'landed':
            session['patches'][1]['landed'] = 'abc123'
        else:
            session['patches'][1]['reviews'] = {my_email: {'patch-state': 'skip'}}
        app = ReviewApp(session)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press('H')
            await pilot.pause()
            shown = [
                item.patch_idx
                for item in app.query_one('#patch-list', ListView).query(PatchListItem)
            ]
            assert 1 in shown
            assert 2 not in shown


class TestSendBookkeeping:
    """Everything after the SMTP handoff is bookkeeping, and bookkeeping must
    never be able to claim the send failed."""

    async def _send(
        self,
        gitdir: str,
        change_id: str,
        dryrun: bool = False,
        reviews: Optional[List[Dict[str, Any]]] = None,
        check: Optional[Callable[[ReviewApp], None]] = None,
        **patches: Any,
    ) -> Tuple[List[str], bool, List[Dict[str, Any]]]:
        """Drive action_send with staged reviews and a send that succeeds.

        *reviews* are my reviews, one per patch; by default a single patch
        with a reply and a trailer.  *check* looks at the app once the send
        is over.  *patches* are extra mock.patch.object() keyword targets on
        the app.
        Returns (notification texts, app still running, patches after send).
        """
        import contextlib

        if reviews is None:
            reviews = [
                {
                    'reply': 'Looks good.',
                    'trailers': ['Reviewed-by: Me <me@example.com>'],
                    'patch-state': 'done',
                }
            ]
        branch, _shas = _create_review_branch_with_patches(
            gitdir, change_id, [f'patch {n}' for n in range(1, len(reviews) + 1)]
        )
        session = _build_session(gitdir, branch)
        session['email_dryrun'] = dryrun
        app = ReviewApp(session)
        my_email = str(session['usercfg']['email'])

        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            for patch, my_review in zip(app._patches, reviews):
                patch['reviews'] = {my_email: my_review}
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(app, 'suspend', lambda: contextlib.nullcontext())
                )

                # SendScreen is a confirmation dialog; answer yes for it.
                def _confirm(screen: Any, callback: Any = None) -> None:
                    assert callback is not None
                    callback(True)

                stack.enter_context(mock.patch.object(app, 'push_screen', _confirm))
                stack.enter_context(mock.patch('b4.get_smtp', return_value=(None, 'm')))
                stack.enter_context(
                    mock.patch('b4.send_mail', return_value=0 if dryrun else 1)
                )
                stack.enter_context(
                    mock.patch('b4.review_tui._review_app.mark_outgoing_seen')
                )
                stack.enter_context(mock.patch.object(app, '_mark_patches_answered'))
                for name, kwargs in patches.items():
                    stack.enter_context(mock.patch.object(app, name, **kwargs))
                notified = stack.enter_context(mock.patch.object(app, 'notify'))
                app.action_send()
                await pilot.pause()
                if check is not None:
                    check(app)
            texts = [str(call.args[0]) for call in notified.call_args_list]
            return texts, app.is_running, app._patches

    @pytest.mark.asyncio
    async def test_unwritable_tracking_is_reported_but_not_as_a_send_failure(
        self, gitdir: str
    ) -> None:
        """save_tracking_ref() returns False rather than raising, so this used
        to pass unnoticed -- and the next session would offer the same reviews
        as unsent, inviting the maintainer to send them twice."""
        texts, running, _ = await self._send(
            gitdir, 'send-notracking', _save_tracking={'return_value': False}
        )
        assert running
        assert any('Sent 1 review email' in t for t in texts)
        assert not any('Send failed' in t for t in texts)
        assert any('could not record it' in t for t in texts)

    @pytest.mark.asyncio
    async def test_raising_bookkeeping_is_not_a_send_failure(self, gitdir: str) -> None:
        """The mail is on the list by then; reporting 'Send failed' would tell
        the maintainer to send it again."""
        texts, running, _ = await self._send(
            gitdir,
            'send-bookkeeping-boom',
            _mark_patches_answered={
                'side_effect': OSError(28, 'No space left on device')
            },
        )
        assert running
        assert any('Sent 1 review email' in t for t in texts)
        assert not any('Send failed' in t for t in texts)
        assert any('No space left on device' in t for t in texts)

    @pytest.mark.asyncio
    async def test_skipped_reply_is_sent(self, gitdir: str) -> None:
        """Only the skipped patch that has a reply sends, and only it is
        recorded as sent."""
        with mock.patch(
            'b4.review_tui._review_app.SendScreen', wraps=SendScreen
        ) as screen:
            texts, _running, patches = await self._send(
                gitdir,
                'send-skipped',
                reviews=[
                    {'patch-state': 'skip', 'reply': 'Not taking this, see v2.'},
                    {'patch-state': 'skip'},
                ],
            )
        assert any('Sent 1 review email' in t for t in texts)
        (skipped_msgids,) = [
            call.kwargs['skipped_msgids'] for call in screen.call_args_list
        ]
        assert len(skipped_msgids) == 1
        my_email = str(b4.get_user_config()['email'])
        assert 'sent-revision' in patches[0]['reviews'][my_email]
        assert 'sent-revision' not in patches[1]['reviews'][my_email]

    @pytest.mark.asyncio
    async def test_sent_skipped_reply_leaves_the_hidden_list(self, gitdir: str) -> None:
        """H keeps a skipped patch listed only while it has mail to send,
        so the row must go once that mail is out."""

        def _check(app: ReviewApp) -> None:
            shown = [
                item.patch_idx
                for item in app.query_one('#patch-list', ListView).query(PatchListItem)
            ]
            assert 1 not in shown
            assert 2 in shown

        await self._send(
            gitdir,
            'send-skipped-hidden',
            reviews=[
                {'patch-state': 'skip', 'reply': 'Not taking this.'},
                {'patch-state': 'done', 'reply': 'Applied, thanks.'},
            ],
            check=_check,
            _hide_skipped={'new': True},
        )

    @pytest.mark.asyncio
    async def test_draft_hint_does_not_offer_skip(self, gitdir: str) -> None:
        """Skipping no longer holds a draft back, so the draft warning must
        not suggest it as the way to send everything else."""
        texts, _running, _patches = await self._send(
            gitdir, 'send-draft-hint', reviews=[{'reply': 'Half a thought'}]
        )
        draft = [t for t in texts if 'Still in draft' in t]
        assert 'Mark as done (d)' in draft[0]
        assert 'skip' not in draft[0]

    @pytest.mark.asyncio
    async def test_a_dry_run_is_not_recorded_as_sent(self, gitdir: str) -> None:
        """--email-dry-run logs the mail and stops there.  Stamping
        sent-revision on it would make the next real session treat these
        reviews as already sent and offer none of them."""
        texts, running, _ = await self._send(gitdir, 'send-dryrun', dryrun=True)
        assert running
        assert any('Dry-run' in t for t in texts)
        assert not any('Sent 0 review email' in t for t in texts)

    @pytest.mark.asyncio
    async def test_a_review_that_did_not_go_out_is_not_recorded_as_sent(
        self, gitdir: str
    ) -> None:
        """No email can be built for a patch without a message-id.  Recording
        its review as sent anyway would claim that what it holds went out,
        and it would never be offered again."""
        stuck = {'trailers': ['Reviewed-by: Me <me@example.com>']}
        fresh = {'trailers': ['Acked-by: Me <me@example.com>']}
        build = b4.review._review._build_review_email

        def _build(
            series: Dict[str, Any],
            patch_meta: Optional[Dict[str, Any]],
            review: Dict[str, Any],
            *args: Any,
        ) -> Optional[email.message.EmailMessage]:
            if review is stuck:
                return None
            return build(series, patch_meta, review, *args)

        with mock.patch.object(b4.review._review, '_build_review_email', _build):
            texts, running, patches = await self._send(
                gitdir, 'send-not-built', reviews=[stuck, fresh]
            )
        assert running
        assert any('Sent 1 review email' in t for t in texts)
        my_reviews = [next(iter(p['reviews'].values())) for p in patches]
        assert 'sent' in my_reviews[1]
        assert 'sent' not in my_reviews[0]
        assert 'sent-revision' not in my_reviews[0]


class TestSessionRestorePoint:
    """_prepare_review_session() records where HEAD has to go back to."""

    def test_records_the_branch(self, gitdir: str) -> None:
        import argparse

        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'session-head-branch', ['patch 1']
        )
        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', 'master'])
        assert ecode == 0
        session = b4.review._prepare_review_session(argparse.Namespace(branch=branch))
        assert session['original_branch'] == 'master'
        assert session['original_head'] == ['checkout', 'master']

    def test_records_a_detached_head(self, gitdir: str) -> None:
        """Without the commit there is no name for where the user was, so the
        review app has nothing to put them back on."""
        import argparse

        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'session-head-detached', ['patch 1']
        )
        ecode, _out = b4.git_run_command(
            gitdir, ['checkout', '-q', '--detach', 'master']
        )
        assert ecode == 0
        ecode, out = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0, out
        sha = out.strip()

        session = b4.review._prepare_review_session(argparse.Namespace(branch=branch))
        assert session['original_branch'] is None
        assert session['original_head'] == ['checkout', '--detach', sha]


# ---------------------------------------------------------------------------
# filter_range_diff_for_commit
# ---------------------------------------------------------------------------

_RANGE_DIFF_SAMPLE = (
    '1:  aaaa1111 = 1:  bbbb1111 first patch\n'
    '2:  aaaa2222 ! 2:  bbbb2222 second patch\n'
    '    @@ Commit message\n'
    '    -old text\n'
    '    +new text\n'
    '3:  aaaa3333 < -:  -------- third patch (dropped)\n'
    '-:  -------- > 3:  bbbb4444 fourth patch (added)\n'
)


class TestFilterRangeDiffForCommit:
    def test_matches_right_side_block(self) -> None:
        """Reviewing the newest revision: the current commit is on the right
        side of the range-diff, and only its block should be returned."""
        block = filter_range_diff_for_commit(_RANGE_DIFF_SAMPLE, 'bbbb2222' + 'f' * 32)
        assert block == (
            '2:  aaaa2222 ! 2:  bbbb2222 second patch\n'
            '    @@ Commit message\n'
            '    -old text\n'
            '    +new text\n'
        )

    def test_matches_left_side_block(self) -> None:
        """Comparing against a newer revision puts the current commit on the
        left side; the block must still be found."""
        block = filter_range_diff_for_commit(_RANGE_DIFF_SAMPLE, 'aaaa3333' + '0' * 32)
        assert block == '3:  aaaa3333 < -:  -------- third patch (dropped)\n'

    @pytest.mark.parametrize(
        'sha',
        [
            pytest.param('--------', id='placeholder-dashes'),
            pytest.param('cccc9999', id='unknown'),
        ],
    )
    def test_no_match_returns_none(self, sha: str) -> None:
        """Placeholder dashes on either side must not be treated as commits,
        and an unknown sha finds nothing."""
        assert filter_range_diff_for_commit(_RANGE_DIFF_SAMPLE, sha) is None

    def test_ansi_colours_ignored_for_matching_but_preserved(self) -> None:
        """git range-diff --color wraps the headers in ANSI sequences; they
        must not confuse matching, and the block keeps its colours."""
        coloured = (
            '\x1b[33m1:  aaaa1111 = 1:  bbbb1111\x1b[m first patch\n'
            '\x1b[33m2:  aaaa2222 ! 2:  bbbb2222\x1b[m second patch\n'
            '    \x1b[36m@@ Commit message\x1b[m\n'
            '    \x1b[31m-old text\x1b[m\n'
            '    \x1b[32m+new text\x1b[m\n'
        )
        block = filter_range_diff_for_commit(coloured, 'bbbb2222' + 'f' * 32)
        assert block == (
            '\x1b[33m2:  aaaa2222 ! 2:  bbbb2222\x1b[m second patch\n'
            '    \x1b[36m@@ Commit message\x1b[m\n'
            '    \x1b[31m-old text\x1b[m\n'
            '    \x1b[32m+new text\x1b[m\n'
        )

    def test_wide_series_padding(self) -> None:
        """Counters are right-aligned in series with 10+ patches; padded
        headers must still be recognized as block boundaries."""
        output = (
            ' 9:  aaaa9999 =  9:  bbbb9999 ninth patch\n'
            '10:  aaaa0000 ! 10:  bbbb0000 tenth patch\n'
            '    @@ Commit message\n'
            '    +more\n'
        )
        block = filter_range_diff_for_commit(output, 'bbbb0000' + '0' * 32)
        assert block == (
            '10:  aaaa0000 ! 10:  bbbb0000 tenth patch\n'
            '    @@ Commit message\n'
            '    +more\n'
        )


def test_fetch_fake_am_range_falls_back_to_lore(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no usable thread blob the range-diff fetches from lore, and an
    empty fetch result is reported as None rather than raising."""
    from b4.review_tui._common import fetch_fake_am_range

    events: List[str] = []

    def fake_fetch(msgid: str, **kw: Any) -> None:
        events.append('fetch')
        return None

    monkeypatch.setattr(b4, 'get_pi_thread_by_msgid', fake_fetch)

    revisions: List[Dict[str, Any]] = [
        {'revision': 1, 'message_id': 'x@example.com', 'thread_blob': None}
    ]
    assert fetch_fake_am_range('/nonexistent', revisions, 1) is None
    assert events == ['fetch']


class TestRangeDiffBindingGate:
    """The D binding only shows when other revisions are known."""

    def _patch_tracking(
        self, monkeypatch: pytest.MonkeyPatch, revisions: List[Dict[str, Any]]
    ) -> None:
        monkeypatch.setattr(
            b4.review.tracking, 'get_repo_identifier', lambda topdir: 'test-project'
        )
        monkeypatch.setattr(b4.review.tracking, 'db_exists', lambda identifier: True)
        monkeypatch.setattr(
            b4.review.tracking, 'get_db', lambda identifier: mock.Mock()
        )
        monkeypatch.setattr(
            b4.review.tracking,
            'get_revisions',
            lambda conn, change_id: revisions,
        )

    @pytest.mark.parametrize(
        'revisions',
        [
            pytest.param(None, id='no-tracking-db'),
            pytest.param([{'revision': 1}], id='own-only'),
        ],
    )
    def test_hidden_without_other_revisions(
        self,
        gitdir: str,
        monkeypatch: pytest.MonkeyPatch,
        revisions: Optional[List[Dict[str, Any]]],
    ) -> None:
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'rdgate-hidden', ['patch 1']
        )
        session = _build_session(gitdir, branch)
        if revisions is not None:
            self._patch_tracking(monkeypatch, revisions)
        app = ReviewApp(session)
        assert app._has_other_revisions is False
        assert app.check_action('range_diff', ()) is False

    def test_shown_with_other_revision(
        self, gitdir: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'rdgate-multi', ['patch 1']
        )
        session = _build_session(gitdir, branch)
        self._patch_tracking(monkeypatch, [{'revision': 1}, {'revision': 2}])
        app = ReviewApp(session)
        assert app._has_other_revisions is True
        assert app.check_action('range_diff', ()) is True
        # Range-diff is a review-mode action; email mode hides it
        app._preview_mode = True
        assert app.check_action('range_diff', ()) is False


# ---------------------------------------------------------------------------
# PatchListItem pre-mount styling (github #80)
# ---------------------------------------------------------------------------


class TestPatchListItemPreMountStyling:
    """A PatchListItem must be styleable before its children have mounted.

    Textual < 7.0 runs a widget's on_mount() *before* its composed children
    are mounted, so the original query_one(Label) there raised NoMatches and
    crashed the whole review TUI on the Textual versions distros ship
    (github #80). The fix holds a direct reference to the Label instead.

    These tests provoke the same condition on any Textual version by styling
    an item that was never mounted, so they do not need an old Textual to
    regress -- a reintroduced query_one() fails here on current Textual too.
    """

    @pytest.mark.parametrize(
        'state,expected',
        [
            ('skip', 'dim'),
            ('unchanged', 'dim'),
            ('done', 'bold'),
        ],
    )
    def test_styles_apply_before_mount(self, state: str, expected: str) -> None:
        item = PatchListItem('a patch', 3, state)
        # Never mounted, so compose() has not run and there is no child to
        # query. This is exactly what old Textual did at on_mount() time.
        item._apply_state_style()
        assert str(item._label.styles.text_style) == expected

    def test_plain_state_leaves_style_unset(self) -> None:
        item = PatchListItem('a patch', 0)
        item._apply_state_style()
        # Textual stringifies an unset text_style as 'none', not ''.
        assert str(item._label.styles.text_style) == 'none'

    def test_label_is_composed(self) -> None:
        """The held reference must be what compose() yields, not a copy."""
        item = PatchListItem('a patch', 1, 'done')
        assert list(item.compose()) == [item._label]


class TestLoadFollowupMsgs:
    """What the follow-up pane gets from a thread."""

    @pytest.mark.asyncio
    async def test_every_reply_loaded(self, gitdir: str) -> None:
        """What each entry holds is covered by TestParseFollowupComments;
        this checks that the pane gets them all, replies without "Re:"
        included."""
        branch, _shas = _create_review_branch_with_patches(
            gitdir, 'load-followups', ['patch 1']
        )
        app = ReviewApp(_build_session(gitdir, branch))
        patch_msgid = app._patches[0]['header-info']['msgid']
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            with mock.patch.object(app, '_save_tracking'):
                app._load_followup_msgs(followup_thread(patch_msgid))
            await pilot.pause()

        entries = {e['msgid']: e for e in app._followup_comments[1]}
        assert sorted(entries) == ['alt@x', 'no-re@x', 'on-alt@x', 'on-p1@x']
        assert entries['on-alt@x']['depth'] == 1


# ---------------------------------------------------------------------------
# Series notes without a cover letter
# ---------------------------------------------------------------------------
#
# A series sent without a cover letter has no series row in the patch list,
# so series-level notes (typically an agent review) are shown next to the
# notes of whichever patch is selected.

NOTES_AGENT = 'agent@example.com'
SERIES_NOTE = 'Series summary.\n\nA detailed observation about the whole series.'


def _notes_session(
    gitdir: str, count: int = 1, *, has_cover: bool = False
) -> Dict[str, Any]:
    """Build a session whose series carries an agent note."""
    branch, _shas = _create_review_branch_with_patches(
        gitdir, 'coverless-notes', [f'Patch {i}' for i in range(1, count + 1)]
    )
    session = _build_session(gitdir, branch)
    if not has_cover:
        session['cover_text'] = f'Patch series\n\n{NO_COVER_NOTE}'
    session['series']['reviews'] = {
        NOTES_AGENT: {'name': 'Review Agent', 'source': 'agent', 'note': SERIES_NOTE}
    }
    return session


def _stored_notes_app(session: Dict[str, Any]) -> ReviewApp:
    """Save the session's tracking data and start an app from the stored copy.

    Loading from the branch makes the test see what b4 actually persisted,
    not the dicts the test built in memory.
    """
    assert b4.review.save_tracking_ref(
        session['topdir'], session['branch'], session['cover_text'], session['tracking']
    )
    return ReviewApp(_build_session(session['topdir'], session['branch']))


def _overlay_text(app: ReviewApp) -> str:
    overlay = app.query_one('#trailer-overlay', Static)
    app._refresh_trailer_overlay()
    assert overlay.display
    return static_text(overlay)


def _note_entries(app: ReviewApp) -> List[Tuple[str, str]]:
    """Return (header, note) pairs of the open NoteScreen."""
    screen = current_screen(app)
    assert isinstance(screen, NoteScreen)
    return [(h, n) for h, _colour, n in screen._note_entries]


def _note_hint(app: ReviewApp) -> str:
    """Return the key hint line of the open NoteScreen."""
    return static_text(current_screen(app).query_one('#note-hint', Static))


@pytest.mark.asyncio
async def test_coverless_series_only_note_visible_without_moving_stored_data(
    gitdir: str,
) -> None:
    """A series note must show up, and viewing it must not touch storage."""
    session = _notes_session(gitdir)
    app = _stored_notes_app(session)
    before = copy.deepcopy(app._tracking)
    ecode, original_tip = b4.git_run_command(gitdir, ['rev-parse', app._branch])
    assert ecode == 0

    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        assert app._selected_idx == 1
        overlay = _overlay_text(app)
        assert 'Review Agent (series)' in overlay
        assert 'Series summary.' in overlay
        assert 'view full note with N' in overlay
        # With a note to show, N opens the viewer rather than the editor.
        with mock.patch.object(app, '_edit_note_in_editor') as editor:
            await pilot.press('N')
            await pilot.pause()
            editor.assert_not_called()
        assert _note_entries(app) == [('Review Agent (series)', SERIES_NOTE)]
        # The series note is on screen but e opens the patch note: say so.
        assert 'e edit patch note' in _note_hint(app)
        await pilot.press('escape')
        await pilot.pause()
        assert app._tracking == before

    _, stored = b4.review.load_tracking(gitdir, app._branch)
    assert stored == before
    assert b4.git_run_command(gitdir, ['rev-parse', app._branch]) == (0, original_tip)


@pytest.mark.asyncio
async def test_coverless_series_note_shown_with_each_patch_without_merging_reviewer(
    gitdir: str,
) -> None:
    """The same reviewer keeps separate patch and series notes on every patch."""
    session = _notes_session(gitdir, 2)
    for idx, patch in enumerate(session['patches'], 1):
        patch['reviews'] = {
            NOTES_AGENT: {'name': 'Review Agent', 'note': f'Patch {idx} observation.'}
        }
    app = _stored_notes_app(session)

    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        for idx in (1, 2):
            app._show_content(idx)
            await pilot.pause()
            overlay = _overlay_text(app)
            assert 'Series summary.' in overlay
            assert f'Patch {idx} observation.' in overlay
            assert f'Patch {3 - idx} observation.' not in overlay
            await pilot.press('N')
            await pilot.pause()
            assert _note_entries(app) == [
                ('Review Agent', f'Patch {idx} observation.'),
                ('Review Agent (series)', SERIES_NOTE),
            ]
            await pilot.press('escape')
            await pilot.pause()


@pytest.mark.asyncio
async def test_real_cover_keeps_series_notes_separate(gitdir: str) -> None:
    """With a cover letter, series notes stay on the series row only."""
    session = _notes_session(gitdir, has_cover=True)
    session['patches'][0]['reviews'] = {
        NOTES_AGENT: {'name': 'Review Agent', 'note': 'Patch observation.'}
    }
    app = _stored_notes_app(session)

    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        for idx, expected, excluded in (
            (0, SERIES_NOTE, 'Patch observation.'),
            (1, 'Patch observation.', 'Series summary.'),
        ):
            app._show_content(idx)
            await pilot.pause()
            overlay = _overlay_text(app)
            assert expected.splitlines()[0] in overlay
            assert excluded not in overlay
            assert '(series)' not in overlay
            await pilot.press('N')
            await pilot.pause()
            assert _note_entries(app) == [('Review Agent', expected)]
            assert 'patch note' not in _note_hint(app)
            await pilot.press('escape')
            await pilot.pause()


@pytest.mark.asyncio
async def test_coverless_series_note_keeps_reviewer_colour(gitdir: str) -> None:
    """A reviewer's patch row and (series) row must share one colour.

    z@ is the second "other" reviewer on the patch but the only one on the
    series, so picking the colour per stored dict would split it in two.
    """
    session = _notes_session(gitdir)
    session['series']['reviews'] = {
        'z@example.com': {'name': 'Zed', 'note': 'Zed series note.'}
    }
    session['patches'][0]['reviews'] = {
        'a@example.com': {'name': 'Ay', 'note': 'Ay patch note.'},
        'z@example.com': {'name': 'Zed', 'note': 'Zed patch note.'},
    }
    app = _stored_notes_app(session)

    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        await pilot.press('N')
        await pilot.pause()
        screen = current_screen(app)
        assert isinstance(screen, NoteScreen)
        colours = {h: c for h, c, _n in screen._note_entries}
        assert colours['Zed'] == colours['Zed (series)']
        assert colours['Ay'] != colours['Zed']


@pytest.mark.asyncio
@pytest.mark.parametrize('existing_patch_note', ['', 'My patch note.'])
async def test_edit_from_combined_notes_edits_current_patch_only(
    gitdir: str, existing_patch_note: str
) -> None:
    """Editing from the combined view must never rewrite the series note."""
    session = _notes_session(gitdir)
    my_email = str(session['usercfg']['email'])
    session['series']['reviews'][my_email] = {
        'name': 'Maintainer',
        'note': 'My series note.',
    }
    if existing_patch_note:
        session['patches'][0]['reviews'] = {
            my_email: {'name': 'Maintainer', 'note': existing_patch_note}
        }
    app = _stored_notes_app(session)
    series_before = copy.deepcopy(app._series)

    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        await pilot.press('N')
        await pilot.pause()
        assert isinstance(app.screen, NoteScreen)
        with mock.patch(
            'b4.review_tui._review_app.suspend_and_edit',
            return_value=b'Updated patch note.',
        ) as edit:
            await pilot.press('e')
            await pilot.pause()
        edit.assert_called_once()
        editor_text = edit.call_args.args[1].decode()
        assert editor_text == existing_patch_note + app._NOTE_FOOTER
        assert app._patches[0]['reviews'][my_email]['note'] == 'Updated patch note.'
        assert app._series == series_before

    _, stored = b4.review.load_tracking(gitdir, app._branch)
    assert stored['series'] == series_before
    assert stored['patches'][0]['reviews'][my_email]['note'] == 'Updated patch note.'


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'has_cover,confirm',
    [
        pytest.param(False, True, id='coverless-confirmed'),
        pytest.param(False, False, id='coverless-cancelled'),
        pytest.param(True, None, id='cover-not-asked'),
    ],
)
async def test_delete_all_notes_asks_only_when_series_notes_shown(
    gitdir: str, has_cover: bool, confirm: Optional[bool]
) -> None:
    """Deleting also drops series notes shown on every patch, so ask first.

    With a cover letter the viewer holds only the patch's own notes, so the
    delete stays a single key press and leaves the series notes alone.

    Only notes go: comments, trailers and the notes of other patches stay,
    and reviewers left with nothing are removed.
    """
    session = _notes_session(gitdir, 2, has_cover=has_cover)
    my_email = str(session['usercfg']['email'])
    comment = {'path': 'file1.txt', 'line': 1, 'text': 'Keep this inline comment.'}
    trailer = 'Reviewed-by: Maintainer <maintainer@example.com>'
    session['series']['reviews'][NOTES_AGENT]['comments'] = [comment]
    session['series']['reviews'][my_email] = {
        'name': 'Maintainer',
        'note': 'My series note.',
        'trailers': [trailer],
    }
    session['patches'][0]['reviews'] = {
        NOTES_AGENT: {
            'name': 'Review Agent',
            'note': 'Patch observation.',
            'comments': [comment],
        },
        my_email: {
            'name': 'Maintainer',
            'note': 'My patch note.',
            'trailers': [trailer],
        },
        'other@example.com': {'name': 'Other', 'note': 'A note with no other data.'},
    }
    session['patches'][1]['reviews'] = {
        NOTES_AGENT: {'name': 'Review Agent', 'note': 'Keep other patch note.'}
    }
    app = _stored_notes_app(session)
    expected = copy.deepcopy(app._tracking)
    deleted = [] if confirm is False else [expected['patches'][0]]
    if confirm:
        deleted.append(expected['series'])
    for target in deleted:
        for review in target['reviews'].values():
            review.pop('note', None)
    if deleted:
        del expected['patches'][0]['reviews']['other@example.com']

    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.pause()
        app._show_content(1)
        await pilot.pause()
        await pilot.press('N')
        await pilot.pause()
        await pilot.press('d')
        await pilot.pause()
        if confirm is None:
            assert not isinstance(current_screen(app), ConfirmScreen)
        else:
            assert isinstance(current_screen(app), ConfirmScreen)
            await pilot.press('y' if confirm else 'escape')
            await pilot.pause()
        assert app._tracking == expected
        overlay = _overlay_text(app)
        assert ('Series summary.' in overlay) is (confirm is False)
        assert ('Patch observation.' in overlay) is (confirm is False)
        assert '1 comments across 1 files' in overlay
        assert 'Reviewed-by' in overlay

    _, stored = b4.review.load_tracking(gitdir, app._branch)
    assert stored == expected
