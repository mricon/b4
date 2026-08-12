import argparse
import datetime
import io
import logging
import os
import pathlib
import re
import sqlite3
from email.message import EmailMessage
from typing import Any, Dict, List
from unittest import mock

import pytest

pytest.importorskip('textual')

import b4
import b4.review
import liblore
from b4.review import tracking as review_tracking
from b4.review_tui._modals import SnoozeScreen
from b4.review_tui._tracking_app import _format_attestation, _format_snooze_until


class TestGetReviewDataDir:
    """Tests for get_review_data_dir()."""

    def test_creates_directory(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify the review data directory is created."""
        reviewdir = review_tracking.get_review_data_dir()
        assert os.path.isdir(reviewdir)
        assert reviewdir.endswith('b4/review')


class TestDbOperations:
    """Tests for database operations."""

    def test_init_db_creates_schema(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify init_db creates the expected schema."""
        conn = review_tracking.init_db('test-init')
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]
        assert 'schema_version' in tables
        assert 'series' in tables
        conn.close()

    def test_init_db_sets_version(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify schema version is set."""
        conn = review_tracking.init_db('test-version')
        cursor = conn.execute('SELECT version FROM schema_version')
        version = cursor.fetchone()[0]
        assert version == review_tracking.SCHEMA_VERSION
        conn.close()

    def test_db_exists(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify db_exists returns correct values."""
        assert not review_tracking.db_exists('nonexistent')
        review_tracking.init_db('exists-test').close()
        assert review_tracking.db_exists('exists-test')

    def test_get_db_raises_for_missing(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify get_db raises FileNotFoundError for missing database."""
        with pytest.raises(FileNotFoundError):
            review_tracking.get_db('does-not-exist')

    def test_add_series_to_db(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify series can be added to the database."""
        conn = review_tracking.init_db('add-series-test')
        track_id = review_tracking.add_series_to_db(
            conn,
            change_id='test-change-id',
            revision=1,
            subject='Test series subject',
            sender_name='Test Author',
            sender_email='author@example.com',
            sent_at='2024-01-15T10:00:00+00:00',
            message_id='test-msgid@example.com',
            num_patches=3,
        )

        assert track_id == 1
        cursor = conn.execute(
            'SELECT track_id, change_id, subject FROM series WHERE change_id = ?',
            ('test-change-id',),
        )
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == track_id
        assert row[2] == 'Test series subject'
        conn.close()

    def test_add_series_with_pw_series_id(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify series can be added with patchwork series ID."""
        conn = review_tracking.init_db('pw-series-test')
        track_id = review_tracking.add_series_to_db(
            conn,
            change_id='test-change-id',
            revision=1,
            subject='Test subject',
            sender_name='Test Author',
            sender_email='author@example.com',
            sent_at='2024-01-15T10:00:00+00:00',
            message_id='test-msgid@example.com',
            num_patches=3,
            pw_series_id=12345,
        )

        cursor = conn.execute(
            'SELECT pw_series_id FROM series WHERE track_id = ?', (track_id,)
        )
        row = cursor.fetchone()
        assert row[0] == 12345
        conn.close()

    def test_add_series_multiple_revisions(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify multiple revisions can be tracked for the same change-id."""
        conn = review_tracking.init_db('multi-rev-test')

        # Add v1
        track_id_v1 = review_tracking.add_series_to_db(
            conn,
            'change-123',
            1,
            'Subject v1',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'msgid-v1@example.com',
            3,
        )
        # Add v2
        track_id_v2 = review_tracking.add_series_to_db(
            conn,
            'change-123',
            2,
            'Subject v2',
            'Author',
            'a@example.com',
            '2024-01-16T10:00:00+00:00',
            'msgid-v2@example.com',
            4,
        )

        # Different track_ids
        assert track_id_v1 != track_id_v2

        cursor = conn.execute(
            'SELECT track_id, revision, num_patches FROM series WHERE change_id = ? ORDER BY revision',
            ('change-123',),
        )
        rows = cursor.fetchall()
        assert len(rows) == 2
        assert rows[0] == (track_id_v1, 1, 3)
        assert rows[1] == (track_id_v2, 2, 4)
        conn.close()

    def test_add_series_upsert(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify adding same (change_id, revision) updates the record."""
        conn = review_tracking.init_db('upsert-test')

        track_id_1 = review_tracking.add_series_to_db(
            conn,
            'change-456',
            1,
            'Subject',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'msgid-old@example.com',
            3,
        )
        track_id_2 = review_tracking.add_series_to_db(
            conn,
            'change-456',
            1,
            'Subject',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'msgid-new@example.com',
            5,
        )

        # Same track_id after upsert
        assert track_id_1 == track_id_2

        cursor = conn.execute(
            'SELECT track_id, message_id, num_patches FROM series WHERE change_id = ? AND revision = ?',
            ('change-456', 1),
        )
        row = cursor.fetchone()
        assert row == (track_id_1, 'msgid-new@example.com', 5)
        conn.close()

    def test_get_tracked_pw_series_ids(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify get_tracked_pw_series_ids returns correct IDs."""
        conn = review_tracking.init_db('pw-ids-test')
        # Add series with pw_series_id
        review_tracking.add_series_to_db(
            conn,
            'change-1',
            1,
            'Subject 1',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'msgid@example.com',
            3,
            pw_series_id=100,
        )
        review_tracking.add_series_to_db(
            conn,
            'change-2',
            1,
            'Subject 2',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'msgid@example.com',
            3,
            pw_series_id=200,
        )
        # Add series without pw_series_id
        review_tracking.add_series_to_db(
            conn,
            'change-3',
            1,
            'Subject 3',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'msgid@example.com',
            3,
        )
        conn.close()

        ids = review_tracking.get_tracked_pw_series_ids('pw-ids-test')
        assert ids == {100, 200}

    def test_is_pw_series_tracked(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify is_pw_series_tracked works correctly."""
        conn = review_tracking.init_db('is-tracked-test')
        review_tracking.add_series_to_db(
            conn,
            'change-1',
            1,
            'Subject',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'msgid@example.com',
            3,
            pw_series_id=12345,
        )
        conn.close()

        assert review_tracking.is_pw_series_tracked('is-tracked-test', 12345) is True
        assert review_tracking.is_pw_series_tracked('is-tracked-test', 99999) is False

    def test_get_all_tracked_series(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify get_all_tracked_series returns all series with correct fields."""
        conn = review_tracking.init_db('all-series-test')
        review_tracking.add_series_to_db(
            conn,
            'change-1',
            1,
            'First series',
            'Author One',
            'one@example.com',
            '2024-01-15T10:00:00+00:00',
            'msgid-1@example.com',
            3,
        )
        review_tracking.add_series_to_db(
            conn,
            'change-2',
            2,
            'Second series',
            'Author Two',
            'two@example.com',
            '2024-01-16T10:00:00+00:00',
            'msgid-2@example.com',
            5,
        )
        conn.close()

        result = review_tracking.get_all_tracked_series('all-series-test')
        assert len(result) == 2
        # Results are ordered by added_at DESC, so the second one is first
        assert result[0]['subject'] == 'Second series'
        assert result[0]['revision'] == 2
        assert result[0]['sender_name'] == 'Author Two'
        assert result[0]['status'] == 'new'
        assert result[1]['subject'] == 'First series'
        assert result[1]['revision'] == 1

    def test_queries_against_nonexistent_db(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify read queries return empty results for a missing db."""
        project = 'nonexistent-project'
        assert review_tracking.get_tracked_pw_series_ids(project) == set()
        assert review_tracking.is_pw_series_tracked(project, 12345) is False
        assert review_tracking.get_all_tracked_series(project) == []


class TestRepoMetadata:
    """Tests for repository metadata operations."""

    def test_save_and_get_repo_metadata(self, gitdir: str) -> None:
        """Verify metadata can be saved and retrieved."""
        git_dir = os.path.join(gitdir, '.git')
        review_tracking.save_repo_metadata(git_dir, 'test-project')

        metadata_path = review_tracking.get_repo_metadata_path(git_dir)
        assert os.path.exists(metadata_path)

        identifier = review_tracking.get_repo_identifier(gitdir)
        assert identifier == 'test-project'

    def test_get_repo_identifier_returns_none_for_missing(self, gitdir: str) -> None:
        """Verify get_repo_identifier returns None when no metadata exists."""
        identifier = review_tracking.get_repo_identifier(gitdir)
        assert identifier is None

    def test_get_repo_identifier_resolves_from_worktree(self, gitdir: str) -> None:
        """Verify get_repo_identifier resolves identifier from worktree."""
        # Enroll the main repo
        git_dir = os.path.join(gitdir, '.git')
        review_tracking.save_repo_metadata(git_dir, 'worktree-project')

        # Create a real worktree
        worktree_dir = os.path.join(str(os.path.dirname(gitdir)), 'worktree')
        out, _logstr = b4.git_run_command(
            gitdir, ['worktree', 'add', worktree_dir, '-b', 'wt-branch']
        )
        assert out == 0

        identifier = review_tracking.get_repo_identifier(worktree_dir)
        assert identifier == 'worktree-project'


class TestResolveIdentifier:
    """Tests for resolve_identifier()."""

    def test_uses_cmdargs_identifier(self, gitdir: str) -> None:
        """Verify command line identifier takes precedence."""
        # Set up repo metadata
        git_dir = os.path.join(gitdir, '.git')
        review_tracking.save_repo_metadata(git_dir, 'repo-identifier')

        cmdargs = argparse.Namespace(identifier='cmdline-identifier')
        result = review_tracking.resolve_identifier(cmdargs, gitdir)
        assert result == 'cmdline-identifier'

    def test_falls_back_to_repo_metadata(self, gitdir: str) -> None:
        """Verify falls back to repo metadata when no cmdargs identifier."""
        git_dir = os.path.join(gitdir, '.git')
        review_tracking.save_repo_metadata(git_dir, 'repo-identifier')

        cmdargs = argparse.Namespace(identifier=None)
        result = review_tracking.resolve_identifier(cmdargs, gitdir)
        assert result == 'repo-identifier'

    def test_returns_none_when_no_identifier(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify returns None when no identifier available."""
        cmdargs = argparse.Namespace(identifier=None)
        # Pass a non-git directory
        result = review_tracking.resolve_identifier(cmdargs, str(tmp_path))
        assert result is None


class TestCmdEnroll:
    """Tests for cmd_enroll()."""

    def test_enroll_creates_database(self, gitdir: str) -> None:
        """Verify enroll creates the database."""
        cmdargs = argparse.Namespace(repo_path=gitdir, identifier='enroll-test')
        review_tracking.cmd_enroll(cmdargs)

        assert review_tracking.db_exists('enroll-test')

    def test_enroll_creates_metadata_file(self, gitdir: str) -> None:
        """Verify enroll creates metadata file in .git directory."""
        cmdargs = argparse.Namespace(repo_path=gitdir, identifier='metadata-test')
        review_tracking.cmd_enroll(cmdargs)

        metadata_path = os.path.join(gitdir, '.git', 'b4-review', 'metadata.json')
        assert os.path.exists(metadata_path)

    def test_enroll_uses_dirname_as_default_identifier(self, gitdir: str) -> None:
        """Verify enroll uses directory name as default identifier."""
        cmdargs = argparse.Namespace(repo_path=gitdir, identifier=None)
        review_tracking.cmd_enroll(cmdargs)

        dirname = os.path.basename(gitdir)
        assert review_tracking.db_exists(dirname)

    def test_enroll_uses_current_directory_when_no_path(self, gitdir: str) -> None:
        """Verify enroll uses current directory when no path specified."""
        # gitdir fixture already changes cwd to the test repo
        cmdargs = argparse.Namespace(repo_path=None, identifier='current-dir-test')
        review_tracking.cmd_enroll(cmdargs)

        assert review_tracking.db_exists('current-dir-test')
        metadata_path = os.path.join(gitdir, '.git', 'b4-review', 'metadata.json')
        assert os.path.exists(metadata_path)

    def test_enroll_fails_when_no_path_and_not_in_repo(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify enroll fails when no path and not in a git repo."""
        # Change to a non-git directory
        non_git_dir = os.path.join(str(tmp_path), 'not-a-repo')
        os.makedirs(non_git_dir)
        oldcwd = os.getcwd()
        os.chdir(non_git_dir)
        try:
            cmdargs = argparse.Namespace(repo_path=None, identifier='test')
            with pytest.raises(SystemExit) as exc_info:
                review_tracking.cmd_enroll(cmdargs)
            assert exc_info.value.code == 1
        finally:
            os.chdir(oldcwd)

    @pytest.mark.parametrize(
        'create_dir', [False, True], ids=['nonexistent', 'non-git-dir']
    )
    def test_enroll_fails_for_bad_repo_path(
        self, tmp_path: pytest.TempPathFactory, create_dir: bool
    ) -> None:
        """Verify enroll fails for paths that are not git repositories."""
        bad_path = os.path.join(str(tmp_path), 'not-a-repo')
        if create_dir:
            os.makedirs(bad_path)

        cmdargs = argparse.Namespace(repo_path=bad_path, identifier='test')
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_enroll(cmdargs)
        assert exc_info.value.code == 1

    def test_enroll_fails_when_repo_already_enrolled(self, gitdir: str) -> None:
        """Verify enroll fails when repository already has metadata."""
        # First enrollment
        cmdargs = argparse.Namespace(repo_path=gitdir, identifier='first-id')
        review_tracking.cmd_enroll(cmdargs)

        # Second enrollment of same repo should fail
        cmdargs2 = argparse.Namespace(repo_path=gitdir, identifier='second-id')
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_enroll(cmdargs2)
        assert exc_info.value.code == 1

    @mock.patch('builtins.input', return_value='y')
    def test_enroll_reuses_existing_db_when_confirmed(
        self, mock_input: mock.Mock, gitdir: str, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify enroll can reuse existing database for different repo."""
        # Create database via first enrollment
        cmdargs = argparse.Namespace(repo_path=gitdir, identifier='shared-db')
        review_tracking.cmd_enroll(cmdargs)

        # Create a second git repo
        second_repo = os.path.join(str(tmp_path), 'second-repo')
        b4.git_run_command(None, ['init', second_repo])

        # Enroll second repo with same identifier - user confirms
        cmdargs2 = argparse.Namespace(repo_path=second_repo, identifier='shared-db')
        review_tracking.cmd_enroll(cmdargs2)

        # Metadata file should exist in second repo's .git
        metadata_path = os.path.join(second_repo, '.git', 'b4-review', 'metadata.json')
        assert os.path.exists(metadata_path)
        mock_input.assert_called_once()

    @mock.patch('builtins.input', return_value='n')
    def test_enroll_aborts_when_existing_db_declined(
        self, mock_input: mock.Mock, gitdir: str, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify enroll aborts when user declines to use existing database."""
        # Create database via first enrollment
        cmdargs = argparse.Namespace(repo_path=gitdir, identifier='declined-db')
        review_tracking.cmd_enroll(cmdargs)

        # Create a second git repo
        second_repo = os.path.join(str(tmp_path), 'second-repo')
        b4.git_run_command(None, ['init', second_repo])

        # Enroll second repo with same identifier - user declines
        cmdargs2 = argparse.Namespace(repo_path=second_repo, identifier='declined-db')
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_enroll(cmdargs2)
        # Exit code 0 for user-initiated cancellation
        assert exc_info.value.code == 0

        # Metadata file should NOT exist in second repo
        metadata_path = os.path.join(second_repo, '.git', 'b4-review', 'metadata.json')
        assert not os.path.exists(metadata_path)

    def test_enroll_from_worktree_writes_metadata_to_common_dir(
        self, gitdir: str
    ) -> None:
        """Verify enroll from a worktree writes metadata to the shared .git."""
        # Create a real worktree
        worktree_dir = os.path.join(str(os.path.dirname(gitdir)), 'worktree')
        out, _logstr = b4.git_run_command(
            gitdir, ['worktree', 'add', worktree_dir, '-b', 'wt-branch']
        )
        assert out == 0

        cmdargs = argparse.Namespace(repo_path=worktree_dir, identifier='worktree-test')
        review_tracking.cmd_enroll(cmdargs)

        # Database should be created
        assert review_tracking.db_exists('worktree-test')
        # Metadata should exist in the main repo's .git directory
        metadata_path = os.path.join(gitdir, '.git', 'b4-review', 'metadata.json')
        assert os.path.exists(metadata_path)

    def test_enroll_from_worktree_already_enrolled(self, gitdir: str) -> None:
        """Verify enrolling from worktree exits 0 when repo already enrolled."""
        # Enroll the main repo first
        cmdargs = argparse.Namespace(repo_path=gitdir, identifier='main-id')
        review_tracking.cmd_enroll(cmdargs)

        # Create a real worktree
        worktree_dir = os.path.join(str(os.path.dirname(gitdir)), 'worktree')
        out, _logstr = b4.git_run_command(
            gitdir, ['worktree', 'add', worktree_dir, '-b', 'wt-branch']
        )
        assert out == 0

        # Enrolling from worktree with same identifier should exit 0
        cmdargs2 = argparse.Namespace(repo_path=worktree_dir, identifier='main-id')
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_enroll(cmdargs2)
        assert exc_info.value.code == 0

    def test_enroll_from_worktree_conflicting_identifier(self, gitdir: str) -> None:
        """Verify enrolling from worktree fails with a different identifier."""
        # Enroll the main repo first
        cmdargs = argparse.Namespace(repo_path=gitdir, identifier='main-id')
        review_tracking.cmd_enroll(cmdargs)

        # Create a real worktree
        worktree_dir = os.path.join(str(os.path.dirname(gitdir)), 'worktree')
        out, _logstr = b4.git_run_command(
            gitdir, ['worktree', 'add', worktree_dir, '-b', 'wt-branch']
        )
        assert out == 0

        # Enrolling from worktree with different identifier should fail
        cmdargs2 = argparse.Namespace(repo_path=worktree_dir, identifier='different-id')
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_enroll(cmdargs2)
        assert exc_info.value.code == 1


class TestCmdTrack:
    """Tests for cmd_track()."""

    def _make_mock_lore_message(
        self,
        msgid: str = 'test-msgid@example.com',
        fromname: str = 'Test Author',
        fromemail: str = 'author@example.com',
        subject: str = 'Test patch',
        date: datetime.datetime = datetime.datetime(
            2024, 1, 15, 10, 0, 0, tzinfo=datetime.timezone.utc
        ),
    ) -> mock.Mock:
        """Create a mock LoreMessage."""
        lmsg = mock.Mock()
        lmsg.msgid = msgid
        lmsg.fromname = fromname
        lmsg.fromemail = fromemail
        lmsg.subject = subject
        lmsg.date = date
        lmsg.lsubject.get_slug.return_value = 'test-series'
        return lmsg

    def _make_mock_lore_series(
        self,
        revision: int = 1,
        expected: int = 3,
        change_id: str | None = 'test-change-id',
        has_cover: bool = True,
        cover_msgid: str = 'cover@example.com',
        first_patch_msgid: str = 'patch1@example.com',
        fromname: str = 'Test Author',
        fromemail: str = 'author@example.com',
        subject: str = 'Test series',
        all_patches_present: bool = False,
    ) -> mock.Mock:
        """Create a mock LoreSeries."""
        lser = mock.Mock()
        lser.revision = revision
        lser.expected = expected
        lser.change_id = change_id
        lser.has_cover = has_cover
        lser.fromname = fromname
        lser.fromemail = fromemail
        lser.subject = subject
        lser.fingerprint = 'mock-fingerprint-0123456789ab'

        # Set up patches list
        cover = self._make_mock_lore_message(cover_msgid) if has_cover else None
        patch1 = self._make_mock_lore_message(first_patch_msgid)
        if all_patches_present:
            lser.patches = [cover, patch1] + [
                self._make_mock_lore_message(f'patch{at}@example.com')
                for at in range(2, expected + 1)
            ]
        else:
            lser.patches = [cover, patch1, None, None]  # Cover + 3 patches (2 missing)
        # Mirror what LoreSeries.add_patch() derives, so callers that check
        # completeness see something truthful instead of a truthy Mock.
        lser.complete = None not in lser.patches[1:]

        return lser

    @mock.patch('b4.retrieve_messages')
    @mock.patch('b4.LoreMailbox')
    def test_track_with_change_id(
        self, mock_mailbox_class: mock.Mock, mock_retrieve: mock.Mock, gitdir: str
    ) -> None:
        """Verify tracking a series with a change-id."""
        # Set up enrolled project
        cmdargs_enroll = argparse.Namespace(repo_path=gitdir, identifier='track-test')
        review_tracking.cmd_enroll(cmdargs_enroll)

        # Mock the series retrieval
        mock_msg = mock.Mock()
        mock_retrieve.return_value = ('test-msgid', [mock_msg])

        mock_lser = self._make_mock_lore_series(change_id='real-change-id')
        mock_mailbox = mock.Mock()
        mock_mailbox.series = {1: mock_lser}
        mock_mailbox.get_series.return_value = mock_lser
        mock_mailbox_class.return_value = mock_mailbox

        cmdargs = argparse.Namespace(
            series_id='test-msgid@example.com',
            identifier='track-test',
            msgid=None,
            noparent=False,
            wantname=None,
            wantver=None,
        )
        review_tracking.cmd_track(cmdargs)

        # Verify it was added to database
        conn = review_tracking.get_db('track-test')
        cursor = conn.execute('SELECT change_id, revision FROM series')
        row = cursor.fetchone()
        assert row['change_id'] == 'real-change-id'
        assert row['revision'] == 1
        conn.close()

    @mock.patch('b4.retrieve_messages')
    @mock.patch('b4.LoreMailbox')
    def test_track_generates_change_id_without_change_id(
        self, mock_mailbox_class: mock.Mock, mock_retrieve: mock.Mock, gitdir: str
    ) -> None:
        """Verify tracking generates a change-id when series has none."""
        cmdargs_enroll = argparse.Namespace(repo_path=gitdir, identifier='noid-test')
        review_tracking.cmd_enroll(cmdargs_enroll)

        mock_msg = mock.Mock()
        mock_retrieve.return_value = ('test-msgid', [mock_msg])

        mock_lser = self._make_mock_lore_series(change_id=None)
        mock_mailbox = mock.Mock()
        mock_mailbox.series = {1: mock_lser}
        mock_mailbox.get_series.return_value = mock_lser
        mock_mailbox_class.return_value = mock_mailbox

        cmdargs = argparse.Namespace(
            series_id='test-msgid@example.com',
            identifier='noid-test',
            msgid=None,
            noparent=False,
            wantname=None,
            wantver=None,
        )
        review_tracking.cmd_track(cmdargs)

        conn = review_tracking.get_db('noid-test')
        cursor = conn.execute('SELECT change_id FROM series')
        row = cursor.fetchone()
        # Format: YYYYMMDD-slug-fingerprint[:12], fully determined by the
        # mock message date, subject slug, and series fingerprint.
        assert row['change_id'] == '20240115-test-series-mock-fingerp'
        conn.close()

    @mock.patch('b4.retrieve_messages')
    @mock.patch('b4.LoreMailbox')
    def test_track_warns_when_thread_incomplete(
        self,
        mock_mailbox_class: mock.Mock,
        mock_retrieve: mock.Mock,
        gitdir: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Verify a partial import is called out instead of looking successful."""
        cmdargs_enroll = argparse.Namespace(repo_path=gitdir, identifier='partial-test')
        review_tracking.cmd_enroll(cmdargs_enroll)

        mock_retrieve.return_value = ('test-msgid', [mock.Mock()])

        # Default mock series claims 3 patches but only carries patch 1.
        mock_lser = self._make_mock_lore_series()
        mock_mailbox = mock.Mock()
        mock_mailbox.series = {1: mock_lser}
        mock_mailbox.get_series.return_value = mock_lser
        mock_mailbox_class.return_value = mock_mailbox

        cmdargs = argparse.Namespace(
            series_id='test-msgid@example.com',
            identifier='partial-test',
            msgid=None,
            noparent=False,
            wantname=None,
            wantver=None,
        )
        with caplog.at_level(logging.CRITICAL, logger='b4'):
            review_tracking.cmd_track(cmdargs)

        assert 'Thread incomplete' in caplog.text
        assert 'missing 2 of 3 patches' in caplog.text
        assert '2, 3' in caplog.text

    @mock.patch('b4.retrieve_messages')
    @mock.patch('b4.LoreMailbox')
    def test_track_no_warning_when_thread_complete(
        self,
        mock_mailbox_class: mock.Mock,
        mock_retrieve: mock.Mock,
        gitdir: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Verify a full import stays quiet about completeness."""
        cmdargs_enroll = argparse.Namespace(repo_path=gitdir, identifier='full-test')
        review_tracking.cmd_enroll(cmdargs_enroll)

        mock_retrieve.return_value = ('test-msgid', [mock.Mock()])

        mock_lser = self._make_mock_lore_series(all_patches_present=True)
        mock_mailbox = mock.Mock()
        mock_mailbox.series = {1: mock_lser}
        mock_mailbox.get_series.return_value = mock_lser
        mock_mailbox_class.return_value = mock_mailbox

        cmdargs = argparse.Namespace(
            series_id='test-msgid@example.com',
            identifier='full-test',
            msgid=None,
            noparent=False,
            wantname=None,
            wantver=None,
        )
        with caplog.at_level(logging.CRITICAL, logger='b4'):
            review_tracking.cmd_track(cmdargs)

        assert 'Thread incomplete' not in caplog.text

    @mock.patch('b4.retrieve_messages')
    @mock.patch('b4.LoreMailbox')
    def test_track_uses_first_patch_without_cover(
        self, mock_mailbox_class: mock.Mock, mock_retrieve: mock.Mock, gitdir: str
    ) -> None:
        """Verify tracking uses first patch msgid when no cover letter."""
        cmdargs_enroll = argparse.Namespace(
            repo_path=gitdir, identifier='no-cover-test'
        )
        review_tracking.cmd_enroll(cmdargs_enroll)

        mock_msg = mock.Mock()
        mock_retrieve.return_value = ('test-msgid', [mock_msg])

        mock_lser = self._make_mock_lore_series(
            has_cover=False, first_patch_msgid='first-patch@example.com'
        )
        mock_mailbox = mock.Mock()
        mock_mailbox.series = {1: mock_lser}
        mock_mailbox.get_series.return_value = mock_lser
        mock_mailbox_class.return_value = mock_mailbox

        cmdargs = argparse.Namespace(
            series_id='test-msgid@example.com',
            identifier='no-cover-test',
            msgid=None,
            noparent=False,
            wantname=None,
            wantver=None,
        )
        review_tracking.cmd_track(cmdargs)

        conn = review_tracking.get_db('no-cover-test')
        cursor = conn.execute('SELECT message_id FROM series')
        row = cursor.fetchone()
        assert row['message_id'] == 'first-patch@example.com'
        conn.close()

    @mock.patch('b4.retrieve_messages')
    @mock.patch('b4.LoreMailbox')
    def test_track_new_version_recognizes_existing_series(
        self, mock_mailbox_class: mock.Mock, mock_retrieve: mock.Mock, gitdir: str
    ) -> None:
        """Tracking v3 of an already-tracked v2 must not create a new series.

        Regression test for bug 70fe607.  Mark Brown reported that tracking v2
        of a series and then tracking v3 of the same series recorded v3 as a
        brand-new, unrelated series instead of recognizing it as a new version
        of the one already tracked.

        The series carries no embedded Change-Id (the typical kernel
        submission), so b4 synthesizes one from date+slug+fingerprint.  Both
        the fingerprint (a per-revision content hash, see
        ``LoreSeries.fingerprint``) and the synthesized change-id therefore
        differ between v2 and v3, so an exact change-id/fingerprint match on
        the requested version alone never matches the existing v2 -- the
        overlap is recognized through the discovered older sibling.
        """
        cmdargs_enroll = argparse.Namespace(repo_path=gitdir, identifier='upgrade-test')
        review_tracking.cmd_enroll(cmdargs_enroll)

        mock_retrieve.return_value = ('test-msgid', [mock.Mock()])

        # v2: no embedded Change-Id, so b4 synthesizes one. Its fingerprint is
        # a per-revision content hash.
        v2 = self._make_mock_lore_series(
            revision=2, change_id=None, cover_msgid='v2-cover@example.com'
        )
        v2.fingerprint = 'a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1'

        # --- Track v2 ---
        mbx_v2 = mock.Mock()
        mbx_v2.series = {2: v2}
        mbx_v2.get_series.return_value = v2
        mock_mailbox_class.return_value = mbx_v2

        review_tracking.cmd_track(
            argparse.Namespace(
                series_id='v2-cover@example.com',
                identifier='upgrade-test',
                msgid=None,
                noparent=False,
                wantname=None,
                wantver=None,
            )
        )

        # v3 of the SAME logical series: still no embedded Change-Id, and the
        # changed content yields a different fingerprint -> a different
        # synthesized change-id.
        v3 = self._make_mock_lore_series(
            revision=3, change_id=None, cover_msgid='v3-cover@example.com'
        )
        v3.fingerprint = 'b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2'

        # When tracking v3, b4's revision discovery also pulls in the older
        # v2, so both are present in the rebuilt mailbox -- the data needed to
        # recognize the already-tracked series is in hand.
        mbx_v3 = mock.Mock()
        mbx_v3.series = {2: v2, 3: v3}
        mbx_v3.get_series.return_value = v3
        mock_mailbox_class.return_value = mbx_v3

        # "The already tracked series logic kicks in": v3 is recognized as a
        # new version of the existing series rather than tracked afresh.
        review_tracking.cmd_track(
            argparse.Namespace(
                series_id='v3-cover@example.com',
                identifier='upgrade-test',
                msgid=None,
                noparent=False,
                wantname=None,
                wantver=None,
            )
        )

        conn = review_tracking.get_db('upgrade-test')
        series_rows = conn.execute('SELECT change_id, revision FROM series').fetchall()

        # Exactly one tracked series, never two.
        assert len(series_rows) == 1, (
            'v3 of an already-tracked series was recorded as a separate '
            'series instead of being recognized as an upgrade of the '
            f'existing one: {[dict(r) for r in series_rows]}'
        )
        change_id = series_rows[0]['change_id']

        # v3 is folded into the existing series as a known revision, so the
        # upgrade can be offered from the tracked series.
        revs = {r['revision'] for r in review_tracking.get_revisions(conn, change_id)}
        conn.close()
        assert revs == {2, 3}, f'expected v2+v3 under one change-id, got {revs}'

    def _track(self, series_id: str, identifier: str) -> None:
        review_tracking.cmd_track(
            argparse.Namespace(
                series_id=series_id,
                identifier=identifier,
                msgid=None,
                noparent=False,
                wantname=None,
                wantver=None,
            )
        )

    @mock.patch('b4.retrieve_messages')
    @mock.patch('b4.LoreMailbox')
    def test_track_new_version_of_archived_series_hints_forget(
        self,
        mock_mailbox_class: mock.Mock,
        mock_retrieve: mock.Mock,
        gitdir: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A new version folding into an archived series must hint at forget.

        Archived series are not shown in the review TUI, so the usual
        "upgrade in the TUI" advice points at nothing the maintainer can
        find (Mark Brown's partially-applied-series report).
        """
        cmdargs_enroll = argparse.Namespace(repo_path=gitdir, identifier='arch-hint')
        review_tracking.cmd_enroll(cmdargs_enroll)
        mock_retrieve.return_value = ('test-msgid', [mock.Mock()])

        v1 = self._make_mock_lore_series(
            revision=1, change_id='cid-arch', cover_msgid='arch-v1@example.com'
        )
        mbx_v1 = mock.Mock()
        mbx_v1.series = {1: v1}
        mbx_v1.get_series.return_value = v1
        mock_mailbox_class.return_value = mbx_v1
        self._track('arch-v1@example.com', 'arch-hint')

        conn = review_tracking.get_db('arch-hint')
        conn.execute("UPDATE series SET status = 'archived'")
        conn.commit()
        conn.close()

        v2 = self._make_mock_lore_series(
            revision=2, change_id='cid-arch', cover_msgid='arch-v2@example.com'
        )
        mbx_v2 = mock.Mock()
        mbx_v2.series = {1: v1, 2: v2}
        mbx_v2.get_series.return_value = v2
        mock_mailbox_class.return_value = mbx_v2

        with caplog.at_level(logging.INFO, logger='b4'):
            self._track('arch-v2@example.com', 'arch-hint')

        assert 'b4 review forget cid-arch' in caplog.text
        assert 'Upgrade the series in the review TUI' not in caplog.text

    @mock.patch('b4.retrieve_messages')
    @mock.patch('b4.LoreMailbox')
    def test_track_already_tracked_hints_forget(
        self,
        mock_mailbox_class: mock.Mock,
        mock_retrieve: mock.Mock,
        gitdir: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Re-tracking with nothing new to record must hint at forget."""
        cmdargs_enroll = argparse.Namespace(repo_path=gitdir, identifier='dup-hint')
        review_tracking.cmd_enroll(cmdargs_enroll)
        mock_retrieve.return_value = ('test-msgid', [mock.Mock()])

        v1 = self._make_mock_lore_series(
            revision=1, change_id='cid-dup', cover_msgid='dup-v1@example.com'
        )
        mbx = mock.Mock()
        mbx.series = {1: v1}
        mbx.get_series.return_value = v1
        mock_mailbox_class.return_value = mbx
        self._track('dup-v1@example.com', 'dup-hint')

        with caplog.at_level(logging.CRITICAL, logger='b4'):
            with pytest.raises(SystemExit) as excinfo:
                self._track('dup-v1@example.com', 'dup-hint')
        assert excinfo.value.code == 1
        assert 'b4 review forget cid-dup' in caplog.text

    @mock.patch('b4.review.tracking.resolve_identifier', return_value=None)
    def test_track_fails_without_identifier(
        self, mock_resolve: mock.Mock, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify track fails when no identifier can be resolved."""
        cmdargs = argparse.Namespace(
            series_id='test-msgid@example.com',
            identifier=None,
            msgid=None,
            noparent=False,
            wantname=None,
            wantver=None,
        )
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_track(cmdargs)
        assert exc_info.value.code == 1

    @mock.patch('b4.retrieve_messages')
    def test_track_fails_for_unenrolled_project(
        self, mock_retrieve: mock.Mock, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify track fails when project is not enrolled."""
        cmdargs = argparse.Namespace(
            series_id='test-msgid@example.com',
            identifier='not-enrolled',
            msgid=None,
            noparent=False,
            wantname=None,
            wantver=None,
        )
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_track(cmdargs)
        assert exc_info.value.code == 1

    @mock.patch('b4.retrieve_messages')
    def test_track_fails_when_retrieval_fails(
        self, mock_retrieve: mock.Mock, gitdir: str
    ) -> None:
        """Verify track fails when series retrieval fails."""
        cmdargs_enroll = argparse.Namespace(
            repo_path=gitdir, identifier='retrieval-fail'
        )
        review_tracking.cmd_enroll(cmdargs_enroll)

        mock_retrieve.return_value = (None, None)

        cmdargs = argparse.Namespace(
            series_id='test-msgid@example.com',
            identifier='retrieval-fail',
            msgid=None,
            noparent=False,
            wantname=None,
            wantver=None,
        )
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_track(cmdargs)
        assert exc_info.value.code == 1


class TestRevisions:
    """Tests for revision tracking helpers."""

    def test_add_revision(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify a revision can be added and retrieved."""
        conn = review_tracking.init_db('rev-add-test')
        review_tracking.add_revision(
            conn,
            'change-abc',
            1,
            'msgid-v1@example.com',
            subject='Test v1',
            link='https://lore.kernel.org/r/msgid-v1',
        )
        revs = review_tracking.get_revisions(conn, 'change-abc')
        assert len(revs) == 1
        assert revs[0]['change_id'] == 'change-abc'
        assert revs[0]['revision'] == 1
        assert revs[0]['message_id'] == 'msgid-v1@example.com'
        assert revs[0]['subject'] == 'Test v1'
        assert revs[0]['link'] == 'https://lore.kernel.org/r/msgid-v1'
        assert revs[0]['found_at'] is not None
        conn.close()

    def test_add_revision_idempotent(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify inserting the same revision twice results in one row."""
        conn = review_tracking.init_db('rev-idem-test')
        review_tracking.add_revision(conn, 'change-abc', 1, 'msgid-v1@example.com')
        review_tracking.add_revision(conn, 'change-abc', 1, 'msgid-v1-dup@example.com')
        revs = review_tracking.get_revisions(conn, 'change-abc')
        assert len(revs) == 1
        # First insert wins (INSERT OR IGNORE)
        assert revs[0]['message_id'] == 'msgid-v1@example.com'
        conn.close()

    def test_get_revisions_ordered(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify revisions are returned in ascending order."""
        conn = review_tracking.init_db('rev-order-test')
        review_tracking.add_revision(conn, 'change-abc', 1, 'msgid-v1@example.com')
        review_tracking.add_revision(conn, 'change-abc', 3, 'msgid-v3@example.com')
        review_tracking.add_revision(conn, 'change-abc', 2, 'msgid-v2@example.com')
        revs = review_tracking.get_revisions(conn, 'change-abc')
        assert len(revs) == 3
        assert [r['revision'] for r in revs] == [1, 2, 3]
        conn.close()

    def test_get_newest_revision(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify get_newest_revision returns the maximum version."""
        conn = review_tracking.init_db('rev-newest-test')
        review_tracking.add_revision(conn, 'change-abc', 1, 'msgid-v1@example.com')
        review_tracking.add_revision(conn, 'change-abc', 3, 'msgid-v3@example.com')
        review_tracking.add_revision(conn, 'change-abc', 2, 'msgid-v2@example.com')
        assert review_tracking.get_newest_revision(conn, 'change-abc') == 3
        conn.close()

    def test_revision_queries_empty_db(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify revision queries return empty results when no revisions exist."""
        conn = review_tracking.init_db('rev-empty-test')
        assert review_tracking.get_newest_revision(conn, 'nonexistent') is None
        assert review_tracking.get_all_newest_revisions(conn) == {}
        assert review_tracking.get_all_revision_counts(conn) == {}
        assert review_tracking.get_all_revisions_grouped(conn) == {}
        conn.close()

    def test_get_all_newest_revisions(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify bulk newest-revision query returns all change_ids."""
        conn = review_tracking.init_db('rev-bulk-newest-test')
        review_tracking.add_revision(conn, 'change-a', 1, 'a-v1@example.com')
        review_tracking.add_revision(conn, 'change-a', 3, 'a-v3@example.com')
        review_tracking.add_revision(conn, 'change-b', 2, 'b-v2@example.com')
        result = review_tracking.get_all_newest_revisions(conn)
        assert result == {'change-a': 3, 'change-b': 2}
        conn.close()

    def test_get_all_revision_counts(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify bulk revision-count query returns correct counts."""
        conn = review_tracking.init_db('rev-bulk-count-test')
        review_tracking.add_revision(conn, 'change-a', 1, 'a-v1@example.com')
        review_tracking.add_revision(conn, 'change-a', 2, 'a-v2@example.com')
        review_tracking.add_revision(conn, 'change-a', 3, 'a-v3@example.com')
        review_tracking.add_revision(conn, 'change-b', 1, 'b-v1@example.com')
        result = review_tracking.get_all_revision_counts(conn)
        assert result == {'change-a': 3, 'change-b': 1}
        conn.close()

    def test_get_all_revisions_grouped(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify bulk grouped revisions returns correct per-change-id lists."""
        conn = review_tracking.init_db('rev-bulk-grouped-test')
        review_tracking.add_revision(
            conn, 'change-a', 2, 'a-v2@example.com', subject='A v2'
        )
        review_tracking.add_revision(
            conn, 'change-a', 1, 'a-v1@example.com', subject='A v1'
        )
        review_tracking.add_revision(
            conn, 'change-b', 1, 'b-v1@example.com', subject='B v1'
        )
        result = review_tracking.get_all_revisions_grouped(conn)
        assert set(result.keys()) == {'change-a', 'change-b'}
        # change-a should be sorted ascending
        assert [r['revision'] for r in result['change-a']] == [1, 2]
        assert len(result['change-b']) == 1
        conn.close()

    def test_delete_series(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify delete_series removes series and revisions for a change_id."""
        conn = review_tracking.init_db('del-series-test')
        # Add a series with revisions
        review_tracking.add_series_to_db(
            conn,
            'change-del',
            1,
            'Subject',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'msgid@example.com',
            3,
        )
        review_tracking.add_revision(conn, 'change-del', 1, 'msgid-v1@example.com')
        review_tracking.add_revision(conn, 'change-del', 2, 'msgid-v2@example.com')
        # Add another series that should not be affected
        review_tracking.add_series_to_db(
            conn,
            'change-keep',
            1,
            'Keep',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'keep@example.com',
            1,
        )
        review_tracking.add_revision(conn, 'change-keep', 1, 'keep-v1@example.com')
        _insert_patches(conn, 'change-del', 1, ['del-p1@example.com'])
        _insert_patches(conn, 'change-keep', 1, ['keep-p1@example.com'])

        review_tracking.delete_series(conn, 'change-del')

        # Deleted change_id should be gone from all three tables
        cursor = conn.execute(
            'SELECT * FROM series WHERE change_id = ?', ('change-del',)
        )
        assert cursor.fetchone() is None
        assert review_tracking.get_revisions(conn, 'change-del') == []
        assert review_tracking.get_series_patches(conn, 'change-del', 1) == []

        # Other change_id should be untouched
        cursor = conn.execute(
            'SELECT * FROM series WHERE change_id = ?', ('change-keep',)
        )
        assert cursor.fetchone() is not None
        assert len(review_tracking.get_revisions(conn, 'change-keep')) == 1
        assert len(review_tracking.get_series_patches(conn, 'change-keep', 1)) == 1
        conn.close()


class TestUpdateSeriesStatus:
    """Tests for update_series_status()."""

    def test_updates_existing_series(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('status-update-test')
        review_tracking.add_series_to_db(
            conn,
            'change-status',
            1,
            'Subject',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'msgid@example.com',
            3,
        )

        review_tracking.update_series_status(conn, 'change-status', 'reviewing')

        cursor = conn.execute(
            'SELECT status FROM series WHERE change_id = ?', ('change-status',)
        )
        assert cursor.fetchone()[0] == 'reviewing'
        conn.close()

    def test_noop_for_nonexistent_change_id(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('status-noop-test')
        # Should not raise
        review_tracking.update_series_status(conn, 'nonexistent', 'reviewing')
        conn.close()


class TestGitGetCommonDir:
    """Tests for git_get_common_dir()."""

    def test_returns_git_dir_for_main_repo(self, gitdir: str) -> None:
        """Verify git_get_common_dir returns .git path for a normal repo."""
        result = b4.git_get_common_dir(gitdir)
        assert result is not None
        expected = os.path.join(gitdir, '.git')
        assert os.path.normpath(result) == os.path.normpath(expected)

    def test_returns_shared_git_dir_from_worktree(self, gitdir: str) -> None:
        """Verify git_get_common_dir returns the shared .git from a worktree."""
        worktree_dir = os.path.join(str(os.path.dirname(gitdir)), 'worktree')
        out, _logstr = b4.git_run_command(
            gitdir, ['worktree', 'add', worktree_dir, '-b', 'wt-branch']
        )
        assert out == 0

        result = b4.git_get_common_dir(worktree_dir)
        assert result is not None
        expected = os.path.join(gitdir, '.git')
        assert os.path.normpath(result) == os.path.normpath(expected)

    def test_returns_none_for_non_git_dir(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify git_get_common_dir returns None outside a git repo."""
        non_git = os.path.join(str(tmp_path), 'not-a-repo')
        os.makedirs(non_git)
        result = b4.git_get_common_dir(non_git)
        assert result is None


def _create_review_branch(
    topdir: str, change_id: str, tracking_data: Dict[str, Any]
) -> str:
    """Helper: create a b4/review/<change_id> branch with a tracking commit."""
    branch = f'b4/review/{change_id}'
    cover_text = f'Cover letter for {change_id}'
    commit_msg = cover_text + '\n\n' + b4.review.make_review_magic_json(tracking_data)
    # Create an orphan-ish branch off current HEAD
    b4.git_run_command(topdir, ['branch', branch])
    # Create a tracking commit on it via commit-tree
    ecode, tree = b4.git_run_command(topdir, ['rev-parse', f'{branch}^{{tree}}'])
    assert ecode == 0
    tree = tree.strip()
    ecode, parent = b4.git_run_command(topdir, ['rev-parse', branch])
    assert ecode == 0
    parent = parent.strip()
    ecode, new_sha = b4.git_run_command(
        topdir,
        ['commit-tree', tree, '-p', parent, '-F', '-'],
        stdin=commit_msg.encode(),
    )
    assert ecode == 0
    new_sha = new_sha.strip()
    ecode, _ = b4.git_run_command(
        topdir, ['update-ref', f'refs/heads/{branch}', new_sha]
    )
    assert ecode == 0
    return branch


class TestUpdateTrackingStatus:
    """Tests for update_tracking_status() helper."""

    def test_updates_status(self, gitdir: str) -> None:
        """Verify update_tracking_status writes status to tracking commit."""
        tracking_data = {
            'series': {
                'identifier': 'test-proj',
                'status': 'reviewing',
                'revision': 1,
                'change-id': 'status-test',
                'subject': 'Test',
                'fromname': 'Author',
                'fromemail': 'a@example.com',
                'expected': 1,
                'complete': True,
                'base-commit': 'abc123',
                'prerequisite-commits': [],
                'first-patch-commit': 'def456',
                'header-info': {},
                'link': '',
            },
            'followups': [],
            'patches': [],
        }
        branch = _create_review_branch(gitdir, 'status-test', tracking_data)

        result = b4.review.update_tracking_status(gitdir, branch, 'replied')
        assert result is True

        # Read back and verify
        _cover, trk = b4.review.load_tracking(gitdir, branch)
        assert trk['series']['status'] == 'replied'

    def test_round_trip(self, gitdir: str) -> None:
        """Verify status survives a write-then-read round-trip."""
        tracking_data = {
            'series': {
                'identifier': 'test-proj',
                'status': 'reviewing',
                'revision': 2,
                'change-id': 'roundtrip-test',
                'subject': 'Roundtrip',
                'fromname': 'Author',
                'fromemail': 'a@example.com',
                'expected': 3,
                'complete': True,
                'base-commit': 'abc123',
                'prerequisite-commits': [],
                'first-patch-commit': 'def456',
                'header-info': {},
                'link': '',
            },
            'followups': [],
            'patches': [],
        }
        branch = _create_review_branch(gitdir, 'roundtrip-test', tracking_data)

        for new_status in ('replied', 'waiting', 'accepted', 'thanked'):
            b4.review.update_tracking_status(gitdir, branch, new_status)
            _cover, trk = b4.review.load_tracking(gitdir, branch)
            assert trk['series']['status'] == new_status

    def test_returns_false_for_missing_branch(self, gitdir: str) -> None:
        """Verify update_tracking_status returns False for non-existent branch."""
        result = b4.review.update_tracking_status(
            gitdir, 'b4/review/nonexistent', 'replied'
        )
        assert result is False


class TestGetReviewBranches:
    """Tests for get_review_branches()."""

    def test_lists_review_branches(self, gitdir: str) -> None:
        """Verify get_review_branches finds b4/review/* branches."""
        tracking_data: Dict[str, Any] = {
            'series': {
                'identifier': 'test-proj',
                'status': 'reviewing',
                'revision': 1,
                'change-id': 'branch-list-1',
                'subject': 'Test 1',
                'fromname': 'A',
                'fromemail': 'a@example.com',
                'expected': 1,
                'complete': True,
                'base-commit': 'abc',
                'prerequisite-commits': [],
                'first-patch-commit': 'def',
                'header-info': {},
                'link': '',
            },
            'followups': [],
            'patches': [],
        }
        _create_review_branch(gitdir, 'branch-list-1', tracking_data)
        tracking_data['series']['change-id'] = 'branch-list-2'
        _create_review_branch(gitdir, 'branch-list-2', tracking_data)

        branches = review_tracking.get_review_branches(gitdir)
        names = set(branches)
        assert 'b4/review/branch-list-1' in names
        assert 'b4/review/branch-list-2' in names

    def test_returns_empty_when_none(self, gitdir: str) -> None:
        """Verify get_review_branches returns empty list with no review branches."""
        branches = review_tracking.get_review_branches(gitdir)
        assert branches == []


class TestRescanBranches:
    """Tests for rescan_branches()."""

    def _make_tracking_data(
        self,
        change_id: str,
        identifier: str = 'rescan-proj',
        status: str = 'reviewing',
        revision: int = 1,
        subject: str = 'Test series',
    ) -> Dict[str, Any]:
        return {
            'series': {
                'identifier': identifier,
                'status': status,
                'revision': revision,
                'change-id': change_id,
                'subject': subject,
                'fromname': 'Test Author',
                'fromemail': 'author@example.com',
                'expected': 3,
                'complete': True,
                'base-commit': 'abc123',
                'prerequisite-commits': [],
                'first-patch-commit': 'def456',
                'header-info': {
                    'msgid': f'{change_id}@example.com',
                    'sentdate': 'Mon, 15 Jan 2024 10:00:00 +0000',
                },
                'link': f'https://lore.kernel.org/r/{change_id}',
            },
            'followups': [],
            'patches': [],
        }

    def test_rescan_single_branch(self, gitdir: str) -> None:
        """Verify rescan populates DB from a single branch."""
        identifier = 'rescan-single'
        review_tracking.init_db(identifier).close()

        tracking_data = self._make_tracking_data(
            'single-change', identifier=identifier, status='replied'
        )
        branch = _create_review_branch(gitdir, 'single-change', tracking_data)

        review_tracking.rescan_branches(identifier, gitdir, branch=branch)

        conn = review_tracking.get_db(identifier)
        cursor = conn.execute(
            'SELECT change_id, status, revision FROM series WHERE change_id = ?',
            ('single-change',),
        )
        row = cursor.fetchone()
        assert row is not None
        assert row['change_id'] == 'single-change'
        assert row['status'] == 'replied'
        assert row['revision'] == 1
        conn.close()

    def test_rescan_marks_gone(self, gitdir: str) -> None:
        """Verify full rescan marks missing branches as 'gone'."""
        identifier = 'rescan-gone'
        conn = review_tracking.init_db(identifier)
        # Add a series to DB with 'reviewing' status but no corresponding branch
        review_tracking.add_series_to_db(
            conn,
            'gone-change',
            1,
            'Gone series',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'msgid@example.com',
            3,
        )
        review_tracking.update_series_status(conn, 'gone-change', 'reviewing')
        conn.close()

        review_tracking.rescan_branches(identifier, gitdir)

        conn = review_tracking.get_db(identifier)
        cursor = conn.execute(
            'SELECT status FROM series WHERE change_id = ?', ('gone-change',)
        )
        row = cursor.fetchone()
        assert row['status'] == 'gone'
        conn.close()

    def test_rescan_skips_mismatched_identifier(self, gitdir: str) -> None:
        """Verify rescan skips branches with a different identifier."""
        identifier = 'rescan-mismatch'
        review_tracking.init_db(identifier).close()

        # Create branch with a different identifier
        tracking_data = self._make_tracking_data(
            'mismatch-change', identifier='other-project'
        )
        _create_review_branch(gitdir, 'mismatch-change', tracking_data)

        review_tracking.rescan_branches(identifier, gitdir)

        conn = review_tracking.get_db(identifier)
        cursor = conn.execute(
            'SELECT * FROM series WHERE change_id = ?', ('mismatch-change',)
        )
        row = cursor.fetchone()
        assert row is None
        conn.close()

    def test_rescan_preserves_non_active_statuses(self, gitdir: str) -> None:
        """Verify full rescan does not mark accepted/thanked series as gone."""
        identifier = 'rescan-preserve'
        conn = review_tracking.init_db(identifier)
        # Add an 'accepted' series with no branch — should NOT become 'gone'
        review_tracking.add_series_to_db(
            conn,
            'accepted-change',
            1,
            'Accepted',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'msgid@example.com',
            3,
        )
        review_tracking.update_series_status(conn, 'accepted-change', 'accepted')
        conn.close()

        review_tracking.rescan_branches(identifier, gitdir)

        conn = review_tracking.get_db(identifier)
        cursor = conn.execute(
            'SELECT status FROM series WHERE change_id = ?', ('accepted-change',)
        )
        row = cursor.fetchone()
        assert row['status'] == 'accepted'
        conn.close()

    def test_rescan_all_branches(self, gitdir: str) -> None:
        """Verify full rescan processes all review branches."""
        identifier = 'rescan-all'
        review_tracking.init_db(identifier).close()

        for i in range(3):
            cid = f'all-change-{i}'
            tracking_data = self._make_tracking_data(cid, identifier=identifier)
            _create_review_branch(gitdir, cid, tracking_data)

        review_tracking.rescan_branches(identifier, gitdir)

        conn = review_tracking.get_db(identifier)
        cursor = conn.execute('SELECT COUNT(*) FROM series')
        count = cursor.fetchone()[0]
        assert count == 3
        conn.close()

    def test_sha_skips_unchanged_branch(self, gitdir: str) -> None:
        """Verify that a second rescan with no branch changes reports changed=0."""
        identifier = 'rescan-sha-skip'
        review_tracking.init_db(identifier).close()

        tracking_data = self._make_tracking_data('sha-skip', identifier=identifier)
        _create_review_branch(gitdir, 'sha-skip', tracking_data)

        # First rescan: new branch, should be processed.
        result = review_tracking.rescan_branches(identifier, gitdir)
        assert result['changed'] == 1

        # Second rescan: branch unchanged, should be skipped entirely.
        result = review_tracking.rescan_branches(identifier, gitdir)
        assert result['changed'] == 0
        assert result['gone'] == 0

    def test_sha_detects_changed_branch(self, gitdir: str) -> None:
        """Verify that updating a branch's tracking commit triggers a re-read."""
        identifier = 'rescan-sha-change'
        review_tracking.init_db(identifier).close()

        tracking_data = self._make_tracking_data(
            'sha-change', identifier=identifier, status='reviewing'
        )
        branch = _create_review_branch(gitdir, 'sha-change', tracking_data)

        # First rescan: registers the branch with status 'reviewing'.
        result = review_tracking.rescan_branches(identifier, gitdir)
        assert result['changed'] == 1

        # Amend the tracking commit on the branch with a different status.
        tracking_data['series']['status'] = 'replied'
        new_msg = 'Cover\n\n' + b4.review.make_review_magic_json(tracking_data)
        _ecode, tree = b4.git_run_command(gitdir, ['rev-parse', f'{branch}^{{tree}}'])
        tree = tree.strip()
        _ecode, parent = b4.git_run_command(gitdir, ['rev-parse', branch])
        parent = parent.strip()
        _ecode, new_sha = b4.git_run_command(
            gitdir,
            ['commit-tree', tree, '-p', parent, '-F', '-'],
            stdin=new_msg.encode(),
        )
        b4.git_run_command(
            gitdir, ['update-ref', f'refs/heads/{branch}', new_sha.strip()]
        )

        # Second rescan: SHA changed, should re-read and update status.
        result = review_tracking.rescan_branches(identifier, gitdir)
        assert result['changed'] == 1

        conn = review_tracking.get_db(identifier)
        row = conn.execute(
            'SELECT status FROM series WHERE change_id = ?', ('sha-change',)
        ).fetchone()
        assert row['status'] == 'replied'
        conn.close()


class TestFollowupCounts:
    """Tests for message_count / seen_message_count tracking."""

    def test_schema_has_followup_columns(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify fresh DB has message_count, seen_message_count, last_update_check, last_activity_at."""
        conn = review_tracking.init_db('fc-schema-test')
        cursor = conn.execute('PRAGMA table_info(series)')
        col_names = {row[1] for row in cursor.fetchall()}
        assert 'message_count' in col_names
        assert 'seen_message_count' in col_names
        assert 'last_update_check' in col_names
        assert 'last_activity_at' in col_names
        conn.close()

    def test_migration_adds_followup_columns(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify v1 DB gets followup/update columns during migration."""
        import sqlite3 as _sqlite3

        db_path = review_tracking.get_db_path('fc-migration-test')
        # Manually build a schema-version 1 database (no branch_sha, no followup cols)
        raw = _sqlite3.connect(db_path)
        raw.executescript("""
            CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
            CREATE TABLE series (
                track_id INTEGER PRIMARY KEY,
                change_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                status TEXT DEFAULT 'new',
                UNIQUE (change_id, revision)
            );
        """)
        raw.execute('INSERT INTO schema_version (version) VALUES (1)')
        raw.commit()
        raw.close()

        # open via get_db which triggers migration
        conn = review_tracking.get_db('fc-migration-test')
        cursor = conn.execute('PRAGMA table_info(series)')
        col_names = {row[1] for row in cursor.fetchall()}
        assert 'branch_sha' in col_names
        assert 'message_count' in col_names
        assert 'seen_message_count' in col_names
        assert 'last_update_check' in col_names
        assert 'last_activity_at' in col_names
        assert 'has_cover' not in col_names
        row = conn.execute('SELECT version FROM schema_version').fetchone()
        assert row[0] == review_tracking.SCHEMA_VERSION
        conn.close()

    def test_mark_all_messages_seen_clears_badge(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """mark_all_messages_seen sets seen_message_count = message_count."""
        conn = review_tracking.init_db('fc-seen-test')
        review_tracking.add_series_to_db(
            conn,
            'fc-seen',
            1,
            'Subject',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'cover3@example.com',
            3,
        )
        # Manually set a delta
        conn.execute(
            'UPDATE series SET message_count = 10, seen_message_count = 6'
            ' WHERE change_id = ?',
            ('fc-seen',),
        )
        conn.commit()

        review_tracking.mark_all_messages_seen(conn, 'fc-seen', 1)
        conn.close()

        # Reopen with get_db to get row_factory for named column access
        conn = review_tracking.get_db('fc-seen-test')
        row = conn.execute(
            'SELECT message_count, seen_message_count FROM series WHERE change_id = ?',
            ('fc-seen',),
        ).fetchone()
        assert row['message_count'] == 10
        assert row['seen_message_count'] == 10
        conn.close()


def _make_test_msg(msgid: str = 'test@example.com') -> EmailMessage:
    """Return a minimal EmailMessage suitable for passing to _store_thread_blob."""
    msg = EmailMessage()
    msg['Message-ID'] = f'<{msgid}>'
    msg['From'] = 'Test Author <author@example.com>'
    msg['Date'] = 'Mon, 15 Jan 2024 10:00:00 +0000'
    msg['Subject'] = 'Test'
    msg.set_payload('Hello world\n')
    return msg


def _make_blob_tracking_data(
    change_id: str, identifier: str = 'blob-proj'
) -> Dict[str, Any]:
    """Return a minimal tracking dict for blob tests."""
    return {
        'series': {
            'identifier': identifier,
            'status': 'reviewing',
            'revision': 1,
            'change-id': change_id,
            'subject': 'Test series',
            'fromname': 'Test Author',
            'fromemail': 'author@example.com',
            'expected': 3,
            'complete': True,
            'base-commit': 'abc123',
            'prerequisite-commits': [],
            'first-patch-commit': 'def456',
            'header-info': {
                'msgid': f'{change_id}@example.com',
                'sentdate': 'Mon, 15 Jan 2024 10:00:00 +0000',
            },
            'link': f'https://lore.kernel.org/r/{change_id}',
        },
        'followups': [],
        'patches': [],
    }


class TestFollowupBlob:
    """Tests for _store_thread_blob() and get_thread_mbox()."""

    def test_store_thread_blob_writes_blob_and_updates_tracking_json(
        self, gitdir: str
    ) -> None:
        """_store_thread_blob serializes msgs via save_mboxrd_mbox and records SHA."""
        change_id = 'blob-write-test'
        _create_review_branch(gitdir, change_id, _make_blob_tracking_data(change_id))

        msgs = [_make_test_msg('cover@example.com')]
        blob_sha = review_tracking._store_thread_blob(gitdir, change_id, msgs)
        assert blob_sha is not None

        # Blob content must equal what save_mboxrd_mbox produces for those messages
        expected_buf = io.BytesIO()
        b4.save_mboxrd_mbox(msgs, expected_buf)
        ecode, content = b4.git_run_command(
            gitdir, ['cat-file', 'blob', blob_sha], decode=False
        )
        assert ecode == 0
        assert content == expected_buf.getvalue()

        # Tracking commit JSON must carry the blob SHA
        _cover, loaded = b4.review.load_tracking(gitdir, f'b4/review/{change_id}')
        assert loaded['series']['thread-blob'] == blob_sha

    def test_store_thread_blob_skips_update_when_sha_unchanged(
        self, gitdir: str
    ) -> None:
        """_store_thread_blob avoids a new tracking commit when SHA is unchanged."""
        change_id = 'blob-nochurn-test'
        _create_review_branch(gitdir, change_id, _make_blob_tracking_data(change_id))

        msgs = [_make_test_msg('nochurn@example.com')]

        sha1 = review_tracking._store_thread_blob(gitdir, change_id, msgs)
        assert sha1 is not None

        ecode, tip1 = b4.git_run_command(
            gitdir, ['rev-parse', f'b4/review/{change_id}']
        )
        assert ecode == 0

        # Second call with identical messages — SHA and branch tip unchanged
        sha2 = review_tracking._store_thread_blob(gitdir, change_id, msgs)
        assert sha2 == sha1

        ecode, tip2 = b4.git_run_command(
            gitdir, ['rev-parse', f'b4/review/{change_id}']
        )
        assert ecode == 0
        assert tip2.strip() == tip1.strip()

    def test_get_thread_mbox_returns_bytes(self, gitdir: str) -> None:
        """get_thread_mbox returns the exact bytes written to the blob."""
        sample = b'From mboxrd@z Thu Jan  1 00:00:00 1970\nSubject: hi\n\nbody\n'
        ecode, blob_sha = b4.git_run_command(
            gitdir, ['hash-object', '-w', '--stdin'], stdin=sample
        )
        assert ecode == 0

        result = review_tracking.get_thread_mbox(gitdir, blob_sha.strip())
        assert result == sample

    def test_get_thread_mbox_returns_none_for_missing_sha(self, gitdir: str) -> None:
        """get_thread_mbox returns None (not an exception) for a bogus SHA."""
        result = review_tracking.get_thread_mbox(gitdir, 'deadbeef' * 5)
        assert result is None


class TestPatchState:
    """Tests for _get_patch_state() and _set_patch_state()."""

    _EMAIL = 'reviewer@example.com'
    _USERCFG: b4.ConfigDictT = {'email': _EMAIL, 'name': 'Test Reviewer'}

    def _make_target(self, review_data: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Return a minimal target dict, optionally with review data."""
        if review_data is None:
            return {}
        return {'reviews': {self._EMAIL: {'name': 'Test Reviewer', **review_data}}}

    def test_no_data(self) -> None:
        """Empty reviews dict → no state."""
        target = self._make_target()
        assert b4.review._get_patch_state(target, self._USERCFG) == ''

    def test_note_only(self) -> None:
        """A private note alone never triggers 'draft'."""
        target = self._make_target({'note': 'just a private note'})
        assert b4.review._get_patch_state(target, self._USERCFG) == ''

    def test_comments(self) -> None:
        """Inline comments list → 'draft'."""
        target = self._make_target(
            {'comments': [{'path': 'a.c', 'line': 1, 'text': 'hi'}]}
        )
        assert b4.review._get_patch_state(target, self._USERCFG) == 'draft'

    def test_reply(self) -> None:
        """Non-empty reply text → 'draft'."""
        target = self._make_target({'reply': 'Looks good overall but...'})
        assert b4.review._get_patch_state(target, self._USERCFG) == 'draft'

    def test_reviewed_by(self) -> None:
        """Reviewed-by trailer → 'done'."""
        target = self._make_target(
            {'trailers': ['Reviewed-by: Test Reviewer <reviewer@example.com>']}
        )
        assert b4.review._get_patch_state(target, self._USERCFG) == 'done'

    def test_acked_by(self) -> None:
        """Acked-by trailer → 'done'."""
        target = self._make_target(
            {'trailers': ['Acked-by: Test Reviewer <reviewer@example.com>']}
        )
        assert b4.review._get_patch_state(target, self._USERCFG) == 'done'

    def test_nacked_by_alone(self) -> None:
        """NACKed-by trailer alone → 'draft' (explanation required)."""
        target = self._make_target(
            {'trailers': ['NACKed-by: Test Reviewer <reviewer@example.com>']}
        )
        assert b4.review._get_patch_state(target, self._USERCFG) == 'draft'

    def test_nacked_by_with_acked(self) -> None:
        """NACK wins over Acked-by — result is still 'draft'."""
        target = self._make_target(
            {
                'trailers': [
                    'NACKed-by: Test Reviewer <reviewer@example.com>',
                    'Acked-by: Test Reviewer <reviewer@example.com>',
                ]
            }
        )
        assert b4.review._get_patch_state(target, self._USERCFG) == 'draft'

    def test_explicit_done(self) -> None:
        """Stored patch-state=done with no other content → 'done'."""
        target = self._make_target({'patch-state': 'done'})
        assert b4.review._get_patch_state(target, self._USERCFG) == 'done'

    def test_explicit_skip(self) -> None:
        """Stored patch-state=skip → 'skip'."""
        target = self._make_target({'patch-state': 'skip'})
        assert b4.review._get_patch_state(target, self._USERCFG) == 'skip'

    def test_explicit_done_beats_nack(self) -> None:
        """Explicit done overrides a NACKed-by trailer (human override wins)."""
        target = self._make_target(
            {
                'patch-state': 'done',
                'trailers': ['NACKed-by: Test Reviewer <reviewer@example.com>'],
            }
        )
        assert b4.review._get_patch_state(target, self._USERCFG) == 'done'

    def test_thread_reviewed_by_from_me(self) -> None:
        """An approval trailer I sent to the list before tracking → 'done'."""
        target = {
            'followups': [
                {
                    'fromemail': self._EMAIL,
                    'trailers': ['Reviewed-by: Test Reviewer <reviewer@example.com>'],
                }
            ]
        }
        assert b4.review._get_patch_state(target, self._USERCFG) == 'done'

    def test_thread_acked_by_from_me(self) -> None:
        """An Acked-by I sent to the list is detected too."""
        target = {
            'followups': [
                {
                    'fromemail': 'Reviewer@Example.COM',  # case-insensitive match
                    'trailers': ['Acked-by: Test Reviewer <reviewer@example.com>'],
                }
            ]
        }
        assert b4.review._get_patch_state(target, self._USERCFG) == 'done'

    def test_thread_approval_from_other_ignored(self) -> None:
        """An approval from someone else does not mark the patch done."""
        target = {
            'followups': [
                {
                    'fromemail': 'somebody@else.example.com',
                    'trailers': ['Reviewed-by: Some Body <somebody@else.example.com>'],
                }
            ]
        }
        assert b4.review._get_patch_state(target, self._USERCFG) == ''

    def test_thread_nack_from_me_vetoes(self) -> None:
        """My own NACK in the thread vetoes auto-done (stays neutral)."""
        target = {
            'followups': [
                {
                    'fromemail': self._EMAIL,
                    'trailers': [
                        'Acked-by: Test Reviewer <reviewer@example.com>',
                        'NACKed-by: Test Reviewer <reviewer@example.com>',
                    ],
                }
            ]
        }
        assert b4.review._get_patch_state(target, self._USERCFG) == ''

    def test_manual_skip_beats_thread_approval(self) -> None:
        """A manual skip supersedes an auto-detected thread approval."""
        target = {
            'reviews': {self._EMAIL: {'name': 'Test Reviewer', 'patch-state': 'skip'}},
            'followups': [
                {
                    'fromemail': self._EMAIL,
                    'trailers': ['Reviewed-by: Test Reviewer <reviewer@example.com>'],
                }
            ],
        }
        assert b4.review._get_patch_state(target, self._USERCFG) == 'skip'

    def test_draft_comment_beats_thread_approval(self) -> None:
        """An in-progress inline comment supersedes auto-detected thread approval."""
        target = {
            'reviews': {
                self._EMAIL: {
                    'name': 'Test Reviewer',
                    'comments': [{'path': 'a.c', 'line': 1, 'text': 'wait'}],
                }
            },
            'followups': [
                {
                    'fromemail': self._EMAIL,
                    'trailers': ['Reviewed-by: Test Reviewer <reviewer@example.com>'],
                }
            ],
        }
        assert b4.review._get_patch_state(target, self._USERCFG) == 'draft'

    def test_thread_approval_beats_external(self) -> None:
        """My prior list approval shows 'done', not 'external', when others commented."""
        target = {
            'reviews': {
                'other@example.com': {
                    'name': 'Other',
                    'comments': [{'path': 'a.c', 'line': 1, 'text': 'nit'}],
                }
            },
            'followups': [
                {
                    'fromemail': self._EMAIL,
                    'trailers': ['Reviewed-by: Test Reviewer <reviewer@example.com>'],
                }
            ],
        }
        assert b4.review._get_patch_state(target, self._USERCFG) == 'done'

    def test_set_and_clear(self) -> None:
        """_set_patch_state done then clear → state '' and entry cleaned up."""
        target: dict[str, Any] = {}
        b4.review._set_patch_state(target, self._USERCFG, 'done')
        assert b4.review._get_patch_state(target, self._USERCFG) == 'done'
        b4.review._set_patch_state(target, self._USERCFG, '')
        assert b4.review._get_patch_state(target, self._USERCFG) == ''
        # The review entry should have been cleaned up entirely
        assert not target.get('reviews', {})

    def test_set_skip_preserves_entry(self) -> None:
        """_set_patch_state skip keeps the review entry (not GC'd)."""
        target: dict[str, Any] = {}
        b4.review._set_patch_state(target, self._USERCFG, 'skip')
        assert b4.review._get_patch_state(target, self._USERCFG) == 'skip'
        # Entry must still be present so the skip is persisted
        assert self._USERCFG['email'] in target.get('reviews', {})

    def test_toggle_plain_done_round_trip(self) -> None:
        """Toggle on a bare patch: '' → done → '' (no lingering state)."""
        target: dict[str, Any] = {}
        assert b4.review._toggle_patch_done(target, self._USERCFG) == 'done'
        assert b4.review._get_patch_state(target, self._USERCFG) == 'done'
        assert b4.review._toggle_patch_done(target, self._USERCFG) == ''
        assert b4.review._get_patch_state(target, self._USERCFG) == ''
        assert not target.get('reviews', {})

    def test_toggle_unmarks_trailer_backed_done(self) -> None:
        """Unmarking a Reviewed-by patch stores explicit 'draft', not '' (which
        would re-derive 'done' from the trailer)."""
        target = self._make_target(
            {'trailers': ['Reviewed-by: Test Reviewer <reviewer@example.com>']}
        )
        assert b4.review._get_patch_state(target, self._USERCFG) == 'done'
        # Pressing 'd' must actually take it out of the done state.
        assert b4.review._toggle_patch_done(target, self._USERCFG) == 'draft'
        assert b4.review._get_patch_state(target, self._USERCFG) == 'draft'
        # Toggling again returns it to done so it can be sent.
        assert b4.review._toggle_patch_done(target, self._USERCFG) == 'done'
        assert b4.review._get_patch_state(target, self._USERCFG) == 'done'

    def test_toggle_unmarks_thread_approval_done(self) -> None:
        """Unmarking a patch that derives 'done' from a prior list approval also
        falls back to explicit 'draft'."""
        target = {
            'followups': [
                {
                    'fromemail': self._EMAIL,
                    'trailers': ['Reviewed-by: Test Reviewer <reviewer@example.com>'],
                }
            ]
        }
        assert b4.review._get_patch_state(target, self._USERCFG) == 'done'
        assert b4.review._toggle_patch_done(target, self._USERCFG) == 'draft'
        assert b4.review._get_patch_state(target, self._USERCFG) == 'draft'

    def test_explicit_draft_beats_trailer(self) -> None:
        """A stored patch-state=draft overrides a Reviewed-by trailer."""
        target = self._make_target(
            {
                'patch-state': 'draft',
                'trailers': ['Reviewed-by: Test Reviewer <reviewer@example.com>'],
            }
        )
        assert b4.review._get_patch_state(target, self._USERCFG) == 'draft'


class TestBuildReplyFromComments:
    """Tests for _build_reply_from_comments() context-limiting logic."""

    # Minimal diff with a 40-line added hunk so we can test truncation.
    # Lines are numbered from 1 in the diff (b_line), matching comment['line'].
    _DIFF = (
        'diff --git a/foo.py b/foo.py\n'
        '--- a/foo.py\n'
        '+++ b/foo.py\n'
        '@@ -0,0 +1,40 @@\n' + ''.join(f'+line{i}\n' for i in range(1, 41))
    )

    def _make_comment(self, line: int, text: str) -> dict[str, Any]:
        return {'path': 'b/foo.py', 'line': line, 'text': text}

    def _call(self, comments: list[dict[str, Any]]) -> list[str]:
        result = b4.review._build_reply_from_comments(self._DIFF, comments, [])
        return result.splitlines()

    def _skip_markers(self, lines: list[str]) -> list[str]:
        """Return all skip-marker lines from the output."""
        return [line for line in lines if line.startswith('> [ ... skip')]

    def test_short_hunk_no_skip_marker(self) -> None:
        """Comment within 5 lines of hunk start → no skip marker of any kind."""
        lines = self._call([self._make_comment(3, 'nice')])
        assert not self._skip_markers(lines)
        # @@ header always present
        assert any('@@ -0,0 +1,40 @@' in line for line in lines)
        # All 3 added lines quoted
        assert '> +line1' in lines
        assert '> +line2' in lines
        assert '> +line3' in lines
        # Line 4 not quoted
        assert '> +line4' not in lines

    def test_few_skipped_lines_included_directly(self) -> None:
        """Gap of fewer than 3 lines → lines included, no skip marker."""
        # Comment on line 8: window_start=3, skipped=2 (lines 1-2 before window)
        lines = self._call([self._make_comment(8, 'here')])
        assert not self._skip_markers(lines)
        # Lines 1 and 2 should be included directly (gap < 3)
        assert '> +line1' in lines
        assert '> +line2' in lines
        assert '> +line8' in lines

    def test_distant_comment_gets_skip_marker(self) -> None:
        """Comment far from hunk start → skip marker with line count inserted."""
        lines = self._call([self._make_comment(20, 'issue here')])
        markers = self._skip_markers(lines)
        assert len(markers) == 1
        assert 'skip 14 lines' in markers[0]
        # @@ header present
        assert any('@@ -0,0 +1,40 @@' in line for line in lines)
        # Only lines 15-20 quoted (5 context + the commented line)
        assert '> +line15' in lines
        assert '> +line20' in lines
        # Line 14 not quoted
        assert '> +line14' not in lines
        # Comment text present
        assert 'issue here' in lines

    def test_two_distant_comments_skip_marker_between(self) -> None:
        """Two comments far apart produce exactly one skip marker between them.

        Comment at line 2 is close to the @@ header (no leading marker);
        comment at line 30 is far enough from line 2 to need a gap marker.
        """
        comments = [
            self._make_comment(2, 'first comment'),
            self._make_comment(30, 'second comment'),
        ]
        lines = self._call(comments)
        assert len(self._skip_markers(lines)) == 1
        assert 'first comment' in lines
        assert 'second comment' in lines

    def test_two_comments_both_distant_two_skip_markers(self) -> None:
        """Two comments both far from hunk start and each other → two skip markers."""
        comments = [
            self._make_comment(20, 'first comment'),
            self._make_comment(40, 'second comment'),
        ]
        lines = self._call(comments)
        assert len(self._skip_markers(lines)) == 2
        assert 'first comment' in lines
        assert 'second comment' in lines

    def test_two_adjacent_comments_no_extra_skip_marker(self) -> None:
        """Two comments close together → only one skip marker (before first window)."""
        comments = [
            self._make_comment(20, 'a'),
            self._make_comment(22, 'b'),
        ]
        lines = self._call(comments)
        assert len(self._skip_markers(lines)) == 1
        # Context window for comment at 20: lines 15-20
        # Comment at 22: lines 21-22 (adjacent, no second skip)
        assert '> +line15' in lines
        assert '> +line22' in lines

    def test_hunk_header_always_present(self) -> None:
        """The @@ hunk header is always included even for a comment on line 20."""
        lines = self._call([self._make_comment(20, 'end')])
        assert any('@@ -0,0 +1,40 @@' in line for line in lines)
        assert self._skip_markers(lines)
        assert '> +line20' in lines
        assert '> +line14' not in lines

    def test_no_duplicate_lines_between_comments(self) -> None:
        """Lines are never quoted twice when two comments share context."""
        comments = [
            self._make_comment(8, 'x'),
            self._make_comment(10, 'y'),
        ]
        lines = self._call(comments)
        quoted = [line for line in lines if line.startswith('> +')]
        # Each quoted diff line should appear exactly once
        assert len(quoted) == len(set(quoted))


class TestFormatSnoozeUntil:
    """Tests for the _format_snooze_until() display helper."""

    @pytest.mark.parametrize(
        'value,expected',
        [
            pytest.param('2026-04-01', 'until 2026-04-01', id='date-only'),
            pytest.param('tag:v6.15-rc3', 'until tag v6.15-rc3', id='tag'),
            pytest.param('NOT_A_DATE', 'NOT_A_DATE', id='invalid-datetime'),
        ],
    )
    def test_literal_values(self, value: str, expected: str) -> None:
        """Non-datetime values are formatted without computing a countdown."""
        assert _format_snooze_until(value) == expected

    def test_expired_datetime(self) -> None:
        """A datetime in the past returns 'expired'."""
        past = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        ).isoformat()
        assert _format_snooze_until(past) == 'expired'

    @pytest.mark.parametrize(
        'delta,expected_prefix',
        [
            pytest.param(
                datetime.timedelta(days=1, hours=2, minutes=30, seconds=30),
                'wakes in 1d 2h 30m',
                id='days-hours-minutes',
            ),
            pytest.param(
                datetime.timedelta(hours=3, seconds=30),
                'wakes in 3h',
                id='hours-only',
            ),
            pytest.param(
                datetime.timedelta(minutes=45, seconds=30),
                'wakes in 45m',
                id='minutes-only',
            ),
            pytest.param(
                datetime.timedelta(seconds=20),
                'wakes in <1m',
                id='under-a-minute',
            ),
        ],
    )
    def test_future_countdown(
        self, delta: datetime.timedelta, expected_prefix: str
    ) -> None:
        """Future datetimes show only the leading nonzero countdown components."""
        target = datetime.datetime.now(datetime.timezone.utc) + delta
        result = _format_snooze_until(target.isoformat())
        assert result.startswith(expected_prefix)

    def test_local_time_shown(self) -> None:
        """The parenthesised local time uses YYYY-MM-DD HH:MM format."""
        target = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            hours=6
        )
        result = _format_snooze_until(target.isoformat())
        local_dt = target.astimezone()
        expected_str = local_dt.strftime('%Y-%m-%d %H:%M')
        assert expected_str in result
        assert re.search(r'\(\d{4}-\d{2}-\d{2} \d{2}:\d{2}\)', result)


class TestSnoozeDurationRegex:
    """Tests for SnoozeScreen._DURATION_RE pattern matching."""

    @pytest.mark.parametrize(
        'input_str,expected_value,expected_unit',
        [
            ('30m', 30, 'm'),
            ('3h', 3, 'h'),
            ('1d', 1, 'd'),
            ('2w', 2, 'w'),
            ('7', 7, ''),
            ('30 m', 30, 'm'),
            ('3H', 3, 'H'),
            ('1D', 1, 'D'),
            ('2W', 2, 'W'),
            ('45M', 45, 'M'),
        ],
    )
    def test_valid_durations(
        self, input_str: str, expected_value: int, expected_unit: str
    ) -> None:
        """Valid duration strings are parsed correctly."""
        m = SnoozeScreen._DURATION_RE.match(input_str)
        assert m is not None
        assert int(m.group(1)) == expected_value
        assert m.group(2) == expected_unit

    @pytest.mark.parametrize(
        'input_str',
        [
            'abc',
            '3x',
            'h3',
            'm',
            '',
            '3.5h',
            '-1d',
            '3hh',
        ],
    )
    def test_invalid_durations(self, input_str: str) -> None:
        """Invalid duration strings are rejected."""
        assert SnoozeScreen._DURATION_RE.match(input_str) is None


class TestGetExpiredSnoozedDatetime:
    """Verify get_expired_snoozed() works with full ISO datetimes."""

    def _make_snoozed_series(
        self, conn: Any, change_id: str, snoozed_until: str
    ) -> None:
        """Insert a snoozed series with a given wake-up time."""
        review_tracking.add_series_to_db(
            conn,
            change_id=change_id,
            revision=1,
            subject='Test subject',
            sender_name='Test Author',
            sender_email='test@example.com',
            sent_at='2026-01-01T10:00:00+00:00',
            message_id=f'{change_id}@example.com',
            num_patches=1,
        )
        review_tracking.snooze_series(conn, change_id, snoozed_until)

    def test_past_datetime_is_expired(self) -> None:
        """A series snoozed until a past datetime shows up as expired."""
        conn = review_tracking.init_db('snooze-past-dt')
        past = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
        ).isoformat()
        self._make_snoozed_series(conn, 'past-dt-id', past)
        expired = review_tracking.get_expired_snoozed(conn)
        assert len(expired) == 1
        assert expired[0]['change_id'] == 'past-dt-id'
        conn.close()

    def test_future_datetime_not_expired(self) -> None:
        """A series snoozed until a future datetime does not show up."""
        conn = review_tracking.init_db('snooze-future-dt')
        future = (
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
        ).isoformat()
        self._make_snoozed_series(conn, 'future-dt-id', future)
        expired = review_tracking.get_expired_snoozed(conn)
        assert len(expired) == 0
        conn.close()

    def test_past_date_only_is_expired(self) -> None:
        """A legacy date-only value in the past still works."""
        conn = review_tracking.init_db('snooze-past-date')
        yesterday = (
            datetime.datetime.now(datetime.timezone.utc).date()
            - datetime.timedelta(days=1)
        ).isoformat()
        self._make_snoozed_series(conn, 'past-date-id', yesterday)
        expired = review_tracking.get_expired_snoozed(conn)
        assert len(expired) == 1
        assert expired[0]['change_id'] == 'past-date-id'
        conn.close()

    def test_future_date_only_not_expired(self) -> None:
        """A legacy date-only value in the future still works."""
        conn = review_tracking.init_db('snooze-future-date')
        tomorrow = (
            datetime.datetime.now(datetime.timezone.utc).date()
            + datetime.timedelta(days=2)
        ).isoformat()
        self._make_snoozed_series(conn, 'future-date-id', tomorrow)
        expired = review_tracking.get_expired_snoozed(conn)
        assert len(expired) == 0
        conn.close()

    def test_mixed_date_and_datetime(self) -> None:
        """Both legacy date-only and new datetime values handled together."""
        conn = review_tracking.init_db('snooze-mixed')
        past_dt = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=30)
        ).isoformat()
        yesterday = (
            datetime.datetime.now(datetime.timezone.utc).date()
            - datetime.timedelta(days=1)
        ).isoformat()
        future_dt = (
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=5)
        ).isoformat()
        self._make_snoozed_series(conn, 'expired-dt', past_dt)
        self._make_snoozed_series(conn, 'expired-date', yesterday)
        self._make_snoozed_series(conn, 'still-sleeping', future_dt)
        expired = review_tracking.get_expired_snoozed(conn)
        expired_ids = {e['change_id'] for e in expired}
        assert expired_ids == {'expired-dt', 'expired-date'}
        conn.close()

    def test_tag_snoozed_not_in_expired(self) -> None:
        """Tag-based snoozed entries don't appear in time-based expiry results."""
        conn = review_tracking.init_db('snooze-tag-not-expired')
        self._make_snoozed_series(conn, 'tag-id', 'tag:v6.15-rc3')
        expired = review_tracking.get_expired_snoozed(conn)
        assert len(expired) == 0
        conn.close()

    def test_get_tag_snoozed(self) -> None:
        """get_tag_snoozed returns only tag: prefixed entries."""
        conn = review_tracking.init_db('snooze-tag-query')
        # Add a tag-based snooze
        self._make_snoozed_series(conn, 'tag-id', 'tag:v6.15-rc3')
        # Add a time-based snooze
        future = (
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
        ).isoformat()
        self._make_snoozed_series(conn, 'time-id', future)
        tag_results = review_tracking.get_tag_snoozed(conn)
        assert len(tag_results) == 1
        assert tag_results[0]['change_id'] == 'tag-id'
        assert tag_results[0]['snoozed_until'] == 'tag:v6.15-rc3'
        conn.close()


# -- Tests for attestation DB operations -------------------------------------


class TestAttestationDb:
    """Tests for attestation storage and schema migration."""

    def _add_test_series(
        self, conn: Any, change_id: str = 'att-test-id', revision: int = 1
    ) -> int:
        """Insert a minimal series row and return its track_id."""
        return review_tracking.add_series_to_db(
            conn,
            change_id=change_id,
            revision=revision,
            subject='Test attestation series',
            sender_name='Test Author',
            sender_email='author@example.com',
            sent_at='2024-06-01T10:00:00+00:00',
            message_id='att-test@example.com',
            num_patches=2,
        )

    def test_new_series_has_pending_attestation(self) -> None:
        """Newly added series default to 'pending' attestation."""
        conn = review_tracking.init_db('att-default')
        self._add_test_series(conn)
        row = conn.execute(
            "SELECT attestation FROM series WHERE change_id = 'att-test-id'"
        ).fetchone()
        assert row[0] == 'pending'
        conn.close()

    def test_update_attestation_stores_value(self) -> None:
        """update_attestation() writes the value to the DB."""
        ident = 'att-update'
        conn = review_tracking.init_db(ident)
        self._add_test_series(conn)
        conn.close()
        review_tracking.update_attestation(
            ident, 'att-test-id', 1, 'signed:DKIM/kernel.org'
        )
        conn = review_tracking.get_db(ident)
        row = conn.execute(
            "SELECT attestation FROM series WHERE change_id = 'att-test-id'"
        ).fetchone()
        assert row[0] == 'signed:DKIM/kernel.org'
        conn.close()

    def test_update_attestation_none_value(self) -> None:
        """update_attestation() can store None (policy off)."""
        ident = 'att-none'
        conn = review_tracking.init_db(ident)
        self._add_test_series(conn)
        conn.close()
        review_tracking.update_attestation(ident, 'att-test-id', 1, None)
        conn = review_tracking.get_db(ident)
        row = conn.execute(
            "SELECT attestation FROM series WHERE change_id = 'att-test-id'"
        ).fetchone()
        assert row[0] is None
        conn.close()

    def test_update_attestation_overwrite(self) -> None:
        """update_attestation() overwrites a previous value."""
        ident = 'att-overwrite'
        conn = review_tracking.init_db(ident)
        self._add_test_series(conn)
        conn.close()
        review_tracking.update_attestation(ident, 'att-test-id', 1, 'none')
        review_tracking.update_attestation(
            ident, 'att-test-id', 1, 'signed:DKIM/kernel.org'
        )
        conn = review_tracking.get_db(ident)
        row = conn.execute(
            "SELECT attestation FROM series WHERE change_id = 'att-test-id'"
        ).fetchone()
        assert row[0] == 'signed:DKIM/kernel.org'
        conn.close()

    def test_update_attestation_wrong_revision_no_crash(self) -> None:
        """update_attestation() for a non-existent revision silently does nothing."""
        ident = 'att-wrong-rev'
        conn = review_tracking.init_db(ident)
        self._add_test_series(conn)
        conn.close()
        # revision 99 doesn't exist — should not raise
        review_tracking.update_attestation(
            ident, 'att-test-id', 99, 'signed:DKIM/kernel.org'
        )
        conn = review_tracking.get_db(ident)
        row = conn.execute(
            "SELECT attestation FROM series WHERE change_id = 'att-test-id'"
        ).fetchone()
        assert row[0] == 'pending'  # unchanged
        conn.close()

    def test_get_all_tracked_series_includes_attestation(self) -> None:
        """get_all_tracked_series() includes the attestation field."""
        ident = 'att-listing'
        conn = review_tracking.init_db(ident)
        self._add_test_series(conn)
        conn.close()
        review_tracking.update_attestation(
            ident, 'att-test-id', 1, 'nokey:ed25519/dev@example.com'
        )
        series_list = review_tracking.get_all_tracked_series(ident)
        assert len(series_list) == 1
        assert series_list[0]['attestation'] == 'nokey:ed25519/dev@example.com'

    def test_get_all_tracked_series_includes_snoozed_until(self) -> None:
        """get_all_tracked_series() includes snoozed_until for snoozed series."""
        ident = 'snoozed-listing'
        conn = review_tracking.init_db(ident)
        self._add_test_series(conn)
        review_tracking.snooze_series(
            conn, 'att-test-id', '2026-06-01T00:00:00', revision=1
        )
        conn.close()
        series_list = review_tracking.get_all_tracked_series(ident)
        assert len(series_list) == 1
        assert series_list[0]['snoozed_until'] == '2026-06-01T00:00:00'

    def test_schema_v4_migration_adds_attestation(self) -> None:
        """Migrating from schema v4 adds the attestation column."""
        import sqlite3

        ident = 'att-migrate-v4'
        # Create a v4-style database manually
        db_path = review_tracking.get_db_path(ident)
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        conn = sqlite3.connect(db_path)
        # Create the tables without the attestation column
        conn.executescript("""
            CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
            INSERT INTO schema_version VALUES (4);
            CREATE TABLE series (
                track_id INTEGER PRIMARY KEY,
                change_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                subject TEXT,
                sender_name TEXT,
                sender_email TEXT,
                sent_at TEXT,
                added_at TEXT,
                message_id TEXT,
                num_patches INTEGER,
                pw_series_id INTEGER,
                status TEXT DEFAULT 'new',
                fingerprint TEXT,
                branch_sha TEXT,
                message_count INT,
                seen_message_count INT,
                last_update_check TEXT,
                last_activity_at TEXT,
                snoozed_until TEXT,
                UNIQUE (change_id, revision)
            );
            INSERT INTO series (change_id, revision, subject) VALUES ('migrate-id', 1, 'Test');
        """)
        conn.close()
        # Opening via get_db triggers migration
        conn = review_tracking.get_db(ident)
        row = conn.execute(
            "SELECT attestation FROM series WHERE change_id = 'migrate-id'"
        ).fetchone()
        assert row[0] == 'pending'
        version = conn.execute('SELECT version FROM schema_version').fetchone()[0]
        assert version == review_tracking.SCHEMA_VERSION
        conn.close()


# -- Tests for _format_attestation() display helper --------------------------


class TestFormatAttestation:
    """Tests for the _format_attestation() display helper."""

    @pytest.mark.parametrize('status', ['pending', 'none', ''])
    def test_no_display_text(self, status: str) -> None:
        """Pending, no-signature and empty statuses produce no display text."""
        assert _format_attestation(status) is None

    @pytest.mark.parametrize(
        'value,fragments',
        [
            pytest.param(
                'signed:DKIM/kernel.org',
                ['\u2714', 'DKIM/kernel.org'],  # ✔
                id='signed',
            ),
            pytest.param(
                'nokey:ed25519/user@example.com',
                ['?', 'ed25519/user@example.com', '(no key)'],
                id='nokey',
            ),
            pytest.param(
                'badsig:ed25519/user@example.com',
                ['\u2718', 'ed25519/user@example.com', '(signature failed)'],  # ✘
                id='badsig',
            ),
        ],
    )
    def test_entry_shows_mark_identity_and_hint(
        self, value: str, fragments: List[str]
    ) -> None:
        """Each attestation status renders its mark, identity and hint."""
        text = _format_attestation(value)
        assert text is not None
        for fragment in fragments:
            assert fragment in text.plain

    @pytest.mark.parametrize(
        'value',
        [
            pytest.param('mystery:foo/bar', id='unknown-status'),
            pytest.param('weirdvalue', id='no-colon'),
        ],
    )
    def test_unrecognised_entry_shown_verbatim(self, value: str) -> None:
        """Unknown statuses and colon-less entries are shown verbatim."""
        text = _format_attestation(value)
        assert text is not None
        assert value in text.plain

    def test_multiple_attestors_comma_separated(self) -> None:
        """Multiple attestors are comma-separated in the output."""
        text = _format_attestation(
            'signed:DKIM/kernel.org;nokey:ed25519/dev@example.com'
        )
        assert text is not None
        plain = text.plain
        assert ', ' in plain
        assert 'DKIM/kernel.org' in plain
        assert 'ed25519/dev@example.com' in plain


# ---------------------------------------------------------------------------
# Cancellation: update_series_tracking
# ---------------------------------------------------------------------------


class TestUpdateSeriesTrackingCancellation:
    """OperationCancelledError propagates rather than being swallowed."""

    def test_propagates_when_retrieve_raises(self) -> None:
        """OperationCancelledError from retrieve_series_messages is re-raised.

        The broad ``except (LookupError, Exception)`` guard in
        update_series_tracking must not swallow a cancellation — it must
        bubble up so the TUI worker loop and CLI signal handler can act on it.
        """
        series: Dict[str, Any] = {
            'change_id': 'cancel-test',
            'revision': 1,
            'status': 'new',
            'message_id': 'test@example.com',
        }
        with mock.patch(
            'b4.review._review.retrieve_series_messages',
            side_effect=liblore.OperationCancelledError('network stalled'),
        ):
            with pytest.raises(liblore.OperationCancelledError):
                b4.review.update_series_tracking(
                    series, 'test-id', 'https://example.com/%s'
                )


# ---------------------------------------------------------------------------
# Message counts: update_series_tracking
# ---------------------------------------------------------------------------


class TestUpdateSeriesTrackingCounts:
    """The message count is refreshed regardless of series status."""

    def test_accepted_series_still_updates_counts(self) -> None:
        """An accepted (applied) series still gets its message count refreshed.

        Regression: the count update used to be skipped for
        accepted/thanked/snoozed series, so once a series was applied the
        unread badge never appeared again — new follow-up mail was fetched
        on update but message_count stayed frozen.
        """
        identifier = 'count-accepted-test'
        change_id = 'count-accepted-1'
        conn = review_tracking.init_db(identifier)
        review_tracking.add_series_to_db(
            conn,
            change_id,
            1,
            'Subject',
            'Author',
            'a@example.com',
            '2024-01-15T10:00:00+00:00',
            'cover@example.com',
            3,
        )
        review_tracking.update_series_status(conn, change_id, 'accepted')
        # Baseline from the reviewing days: 5 messages, all seen
        conn.execute(
            'UPDATE series SET message_count = 5, seen_message_count = 5'
            ' WHERE change_id = ?',
            (change_id,),
        )
        conn.commit()
        conn.close()

        # The refetched thread has grown to 7 messages
        msgs = [_make_test_msg(f'reply-{i}@example.com') for i in range(7)]

        v1_patch = mock.Mock()
        v1_patch.msgid = 'cover@example.com'
        v1_patch.full_subject = '[PATCH 0/3] test'
        v1_mock = mock.Mock()
        v1_mock.revision = 1
        v1_mock.patches = [v1_patch, None, None, None]
        v1_mock.fingerprint = None
        mock_lmbx = mock.Mock()
        mock_lmbx.series = {1: v1_mock}
        mock_lmbx.covers = {}
        mock_lmbx.get_series.return_value = None

        series_dict: Dict[str, Any] = {
            'change_id': change_id,
            'revision': 1,
            'status': 'accepted',
            'message_id': 'cover@example.com',
        }
        with (
            mock.patch('b4.review._review.retrieve_series_messages', return_value=msgs),
            mock.patch('b4.LoreMailbox', return_value=mock_lmbx),
        ):
            result = b4.review.update_series_tracking(
                series_dict, identifier, 'https://example.com/%s'
            )

        assert result.get('error') is None
        assert result.get('counts_updated') is True

        conn = review_tracking.get_db(identifier)
        row = conn.execute(
            'SELECT message_count, seen_message_count FROM series WHERE change_id = ?',
            (change_id,),
        ).fetchone()
        conn.close()
        # Count refreshed, seen untouched — the badge shows (2)
        assert row['message_count'] == 7
        assert row['seen_message_count'] == 5


# ---------------------------------------------------------------------------
# Cancellation: cmd_track
# ---------------------------------------------------------------------------


class TestCmdTrackCancellation:
    """cmd_track exits with code 130 when the network operation is interrupted."""

    def _make_cmdargs(self) -> argparse.Namespace:
        return argparse.Namespace(
            series_id='test@example.com',
            rethread=None,
            wantver=None,
            identifier='test-id',
        )

    def test_operation_cancelled_exits_130(self, tmp_path: pathlib.Path) -> None:
        """OperationCancelledError from retrieve_messages causes sys.exit(130)."""
        cmdargs = self._make_cmdargs()
        with (
            mock.patch('b4.review.tracking.resolve_identifier', return_value='test-id'),
            mock.patch('b4.review.tracking.db_exists', return_value=True),
            mock.patch(
                'b4.retrieve_messages',
                side_effect=liblore.OperationCancelledError('cancelled'),
            ),
            mock.patch('b4.git_get_toplevel', return_value=str(tmp_path)),
        ):
            with pytest.raises(SystemExit) as exc_info:
                review_tracking.cmd_track(cmdargs)

        assert exc_info.value.code == 130

    def test_keyboard_interrupt_exits_130(self, tmp_path: pathlib.Path) -> None:
        """KeyboardInterrupt from retrieve_messages causes sys.exit(130)."""
        cmdargs = self._make_cmdargs()
        with (
            mock.patch('b4.review.tracking.resolve_identifier', return_value='test-id'),
            mock.patch('b4.review.tracking.db_exists', return_value=True),
            mock.patch('b4.retrieve_messages', side_effect=KeyboardInterrupt()),
            mock.patch('b4.git_get_toplevel', return_value=str(tmp_path)),
        ):
            with pytest.raises(SystemExit) as exc_info:
                review_tracking.cmd_track(cmdargs)

        assert exc_info.value.code == 130


# ---------------------------------------------------------------------------
# Manual revision linking (feature/review-manual-revision-link)
#
# Red spec — written test-first, before the implementation exists.  These
# pin down the schema-v9 groundwork (per-revision fingerprint + source
# provenance) and the precedence rule that a manual link must win over, and
# never be downgraded by, heuristic auto-discovery.  See plan.otl v0.16
# "Manual revision linking", git-bug 47d5a4c.
# ---------------------------------------------------------------------------


def _make_legacy_v8_db(identifier: str) -> str:
    """Create a schema-v8 database on disk (revisions without fingerprint/source).

    Returns the database path.  Used to exercise the v8 -> v9 migration.
    """
    path = review_tracking.get_db_path(identifier)
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
        CREATE TABLE revisions (
            change_id   TEXT NOT NULL,
            revision    INTEGER NOT NULL,
            message_id  TEXT NOT NULL,
            subject     TEXT,
            link        TEXT,
            found_at    TEXT,
            thread_blob TEXT,
            PRIMARY KEY (change_id, revision)
        );
        """
    )
    conn.execute('INSERT INTO schema_version (version) VALUES (8)')
    conn.execute(
        'INSERT INTO revisions (change_id, revision, message_id, subject, link, found_at)'
        ' VALUES (?, ?, ?, ?, ?, ?)',
        (
            'legacy-change',
            2,
            'legacy-v2@example.com',
            'Legacy v2',
            '',
            '2026-01-01T00:00:00+00:00',
        ),
    )
    conn.commit()
    conn.close()
    return path


class TestRevisionFingerprintSchema:
    """Tier 1: schema-v9 groundwork for manual revision linking."""

    def test_revisions_has_fingerprint_and_source_columns(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Fresh databases carry fingerprint + source on the revisions table."""
        conn = review_tracking.init_db('mrl-cols-test')
        cols = {row[1] for row in conn.execute('PRAGMA table_info(revisions)')}
        conn.close()
        assert 'fingerprint' in cols
        assert 'source' in cols

    def test_revisions_fingerprint_is_indexed(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """A fingerprint lookup index exists so absorption stays cheap at scale."""
        conn = review_tracking.init_db('mrl-index-test')
        indexed_cols = set()
        for idx in conn.execute('PRAGMA index_list(revisions)'):
            idx_name = idx[1]
            for col in conn.execute(f'PRAGMA index_info({idx_name})'):
                indexed_cols.add(col[2])
        conn.close()
        assert 'fingerprint' in indexed_cols

    def test_migration_v8_to_v9_preserves_rows(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Migrating a populated v8 DB adds the columns without losing data."""
        _make_legacy_v8_db('mrl-migrate-test')
        # get_db() runs _migrate_db_if_needed() on open.
        conn = review_tracking.get_db('mrl-migrate-test')

        cols = {row[1] for row in conn.execute('PRAGMA table_info(revisions)')}
        assert 'fingerprint' in cols
        assert 'source' in cols

        version = conn.execute('SELECT version FROM schema_version').fetchone()[0]
        assert version == review_tracking.SCHEMA_VERSION

        revs = review_tracking.get_revisions(conn, 'legacy-change')
        conn.close()
        assert len(revs) == 1
        assert revs[0]['message_id'] == 'legacy-v2@example.com'
        # Pre-existing rows are auto-discovered, so they default to 'heuristic'.
        assert revs[0]['source'] == 'heuristic'
        assert revs[0]['fingerprint'] is None


class TestRevisionSourceProvenance:
    """Tier 2: add_revision fingerprint/source contract and precedence."""

    def test_add_revision_stores_fingerprint_and_source(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('mrl-store-test')
        review_tracking.add_revision(
            conn,
            'change-abc',
            4,
            'v4@example.com',
            fingerprint='fp-deadbeef',
            source='manual',
        )
        revs = review_tracking.get_revisions(conn, 'change-abc')
        conn.close()
        assert revs[0]['fingerprint'] == 'fp-deadbeef'
        assert revs[0]['source'] == 'manual'

    def test_add_revision_defaults_to_heuristic(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('mrl-default-test')
        review_tracking.add_revision(conn, 'change-abc', 1, 'v1@example.com')
        revs = review_tracking.get_revisions(conn, 'change-abc')
        conn.close()
        assert revs[0]['source'] == 'heuristic'

    def test_manual_link_upgrades_heuristic(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """A manual link over a heuristic row promotes the source to manual."""
        conn = review_tracking.init_db('mrl-upgrade-test')
        review_tracking.add_revision(conn, 'change-abc', 3, 'v3@example.com')
        review_tracking.add_revision(
            conn, 'change-abc', 3, 'v3@example.com', source='manual'
        )
        revs = review_tracking.get_revisions(conn, 'change-abc')
        conn.close()
        assert len(revs) == 1
        assert revs[0]['source'] == 'manual'

    def test_heuristic_does_not_downgrade_manual(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """A later heuristic pass must not clobber a manual link."""
        conn = review_tracking.init_db('mrl-nodowngrade-test')
        review_tracking.add_revision(
            conn, 'change-abc', 3, 'v3@example.com', source='manual'
        )
        review_tracking.add_revision(
            conn, 'change-abc', 3, 'v3@example.com', source='heuristic'
        )
        revs = review_tracking.get_revisions(conn, 'change-abc')
        conn.close()
        assert revs[0]['source'] == 'manual'

    def test_add_revision_backfills_missing_fingerprint(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """A fingerprint-less row gets its fingerprint filled in on a later add."""
        conn = review_tracking.init_db('mrl-backfill-test')
        review_tracking.add_revision(conn, 'change-abc', 1, 'v1@example.com')
        review_tracking.add_revision(
            conn, 'change-abc', 1, 'v1@example.com', fingerprint='fp-late'
        )
        revs = review_tracking.get_revisions(conn, 'change-abc')
        conn.close()
        assert revs[0]['fingerprint'] == 'fp-late'
        # message_id remains first-wins, as before.
        assert revs[0]['message_id'] == 'v1@example.com'

    def test_find_revision_by_fingerprint(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Fingerprint lookup locates the owning (change_id, revision)."""
        conn = review_tracking.init_db('mrl-find-test')
        review_tracking.add_revision(
            conn, 'change-xyz', 5, 'v5@example.com', fingerprint='fp-unique'
        )
        hit = review_tracking.find_revision_by_fingerprint(conn, 'fp-unique')
        conn.close()
        assert hit is not None
        assert hit['change_id'] == 'change-xyz'
        assert hit['revision'] == 5

    def test_find_revision_by_fingerprint_misses(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Unknown or empty fingerprints return None rather than raising."""
        conn = review_tracking.init_db('mrl-find-miss-test')
        review_tracking.add_revision(
            conn, 'change-xyz', 5, 'v5@example.com', fingerprint='fp-unique'
        )
        assert review_tracking.find_revision_by_fingerprint(conn, 'nope') is None
        assert review_tracking.find_revision_by_fingerprint(conn, '') is None
        assert review_tracking.find_revision_by_fingerprint(conn, None) is None
        conn.close()


class TestFindExistingChangeId:
    """find_existing_change_id() recognizes an already-tracked thread.

    Underpins bug 70fe607: a new version of a tracked series is recognized
    through its discovered older siblings, not the requested version itself.
    """

    def test_matches_series_fingerprint(self, tmp_path: pytest.TempPathFactory) -> None:
        """A discovered revision matches the tracked version's fingerprint.

        The originally-tracked revision's fingerprint lives in the ``series``
        table (auto-discovered revisions store none), so that is the signal
        for a thread tracked by the b4 review track / update flow.
        """
        conn = review_tracking.init_db('fec-series-fp')
        review_tracking.add_series_to_db(
            conn,
            change_id='tracked-cid',
            revision=2,
            subject='Tracked v2',
            sender_name='A',
            sender_email='a@example.com',
            sent_at=None,
            message_id='v2-cover@example.com',
            num_patches=1,
            fingerprint='fp-v2',
        )
        # Probe with the *new* version first (no match), then the discovered
        # older sibling whose fingerprint is on record.
        found = review_tracking.find_existing_change_id(
            conn,
            [('fp-v3', 'v3-cover@example.com'), ('fp-v2', 'v2-cover@example.com')],
        )
        conn.close()
        assert found == 'tracked-cid'

    def test_message_id_wins_over_colliding_fingerprint(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """A message-id match must win over a colliding fingerprint.

        Hardening for bug 78c0fa1: fingerprints can collide for content-poor
        series, so they are consulted only as a fallback.  Here a discovered
        revision carries a fingerprint that matches series A but a message-id
        that belongs to series B; it must resolve to B, not A.
        """
        conn = review_tracking.init_db('fec-precedence')
        review_tracking.add_series_to_db(
            conn,
            change_id='series-a',
            revision=1,
            subject='Series A',
            sender_name='A',
            sender_email='a@example.com',
            sent_at=None,
            message_id='a-cover@example.com',
            num_patches=1,
            fingerprint='COLLIDE',
        )
        review_tracking.add_series_to_db(
            conn,
            change_id='series-b',
            revision=1,
            subject='Series B',
            sender_name='A',
            sender_email='a@example.com',
            sent_at=None,
            message_id='b-cover@example.com',
            num_patches=1,
            fingerprint='distinct-b',
        )
        found = review_tracking.find_existing_change_id(
            conn, [('COLLIDE', 'b-cover@example.com')]
        )
        conn.close()
        assert found == 'series-b'

    def test_matches_revision_message_id(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """A discovered revision matches a recorded revision message-id.

        Message-ids are the reliable signal: every auto-discovered revision
        records one even though it stores no fingerprint.
        """
        conn = review_tracking.init_db('fec-rev-msgid')
        review_tracking.add_series_to_db(
            conn,
            change_id='tracked-cid',
            revision=2,
            subject='Tracked v2',
            sender_name='A',
            sender_email='a@example.com',
            sent_at=None,
            message_id='v2-cover@example.com',
            num_patches=1,
            fingerprint='fp-v2',
        )
        # Auto-discovered revision: message-id on record, no fingerprint.
        review_tracking.add_revision(conn, 'tracked-cid', 1, 'v1-cover@example.com')
        found = review_tracking.find_existing_change_id(
            conn,
            [(None, 'v1-cover@example.com'), (None, 'v3-cover@example.com')],
        )
        conn.close()
        assert found == 'tracked-cid'

    def test_no_match_returns_none(self, tmp_path: pytest.TempPathFactory) -> None:
        """An unrelated thread (no shared fingerprint or message-id) misses."""
        conn = review_tracking.init_db('fec-miss')
        review_tracking.add_series_to_db(
            conn,
            change_id='tracked-cid',
            revision=2,
            subject='Tracked v2',
            sender_name='A',
            sender_email='a@example.com',
            sent_at=None,
            message_id='v2-cover@example.com',
            num_patches=1,
            fingerprint='fp-v2',
        )
        found = review_tracking.find_existing_change_id(
            conn,
            [('fp-other', 'other-cover@example.com'), (None, None)],
        )
        conn.close()
        assert found is None


# ---------------------------------------------------------------------------
# Tier 3: duplicate absorption.  When a posting being linked is already
# tracked as its own stray series, absorb it as a revision of the target
# change_id rather than leaving a duplicate behind.
# ---------------------------------------------------------------------------


def _insert_patches(
    conn: sqlite3.Connection, change_id: str, revision: int, msgids: list[str]
) -> None:
    """Directly seed series_patches rows for test setup."""
    for pos, mid in enumerate(msgids, start=1):
        conn.execute(
            'INSERT INTO series_patches'
            ' (change_id, revision, position, message_id, subject)'
            ' VALUES (?, ?, ?, ?, ?)',
            (change_id, revision, pos, mid, f'[PATCH {pos}] thing'),
        )
    conn.commit()


def _seed_stray_series(
    conn: sqlite3.Connection, change_id: str, revision: int, fingerprint: str
) -> None:
    """Seed a fully tracked stand-alone series (series + revision + patches)."""
    review_tracking.add_series_to_db(
        conn,
        change_id=change_id,
        revision=revision,
        subject=f'Stray {change_id} v{revision}',
        sender_name='Srinivas',
        sender_email='srinivas@example.com',
        sent_at='2026-03-20T00:00:00+00:00',
        message_id=f'{change_id}-v{revision}@example.com',
        num_patches=2,
        fingerprint=fingerprint,
    )
    review_tracking.add_revision(
        conn,
        change_id,
        revision,
        f'{change_id}-v{revision}@example.com',
        subject=f'Stray {change_id} v{revision}',
        fingerprint=fingerprint,
    )
    _insert_patches(
        conn,
        change_id,
        revision,
        [f'{change_id}-p1@example.com', f'{change_id}-p2@example.com'],
    )


class TestAbsorbSeriesAsRevision:
    """Tier 3: absorb_series_as_revision() re-homes a stray duplicate."""

    def test_absorb_rehomes_revision_and_deletes_stray(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('mrl-absorb-test')
        # Target series A with v1 already tracked (heuristic).
        review_tracking.add_revision(conn, 'series-A', 1, 'a-v1@example.com')
        # Stray series B independently tracked as its own v2.
        _seed_stray_series(conn, 'series-B', 2, 'fp-stray-b')

        absorbed = review_tracking.absorb_series_as_revision(
            conn, 'series-A', 'series-B', 2
        )
        assert absorbed is True

        revs_a = review_tracking.get_revisions(conn, 'series-A')
        assert [r['revision'] for r in revs_a] == [1, 2]
        rev2 = next(r for r in revs_a if r['revision'] == 2)
        assert rev2['message_id'] == 'series-B-v2@example.com'
        assert rev2['fingerprint'] == 'fp-stray-b'
        assert rev2['source'] == 'manual'
        # v1 left untouched.
        rev1 = next(r for r in revs_a if r['revision'] == 1)
        assert rev1['source'] == 'heuristic'

        # Patches copied across.
        patches = review_tracking.get_series_patches(conn, 'series-A', 2)
        assert [p['message_id'] for p in patches] == [
            'series-B-p1@example.com',
            'series-B-p2@example.com',
        ]

        # Stray fully removed.
        assert review_tracking.get_revisions(conn, 'series-B') == []
        assert review_tracking.get_series_patches(conn, 'series-B', 2) == []
        srow = conn.execute(
            "SELECT COUNT(*) FROM series WHERE change_id = 'series-B'"
        ).fetchone()
        conn.close()
        assert srow[0] == 0

    def test_absorb_missing_stray_is_noop(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('mrl-absorb-noop-test')
        review_tracking.add_revision(conn, 'series-A', 1, 'a-v1@example.com')
        absorbed = review_tracking.absorb_series_as_revision(
            conn, 'series-A', 'series-B', 2
        )
        revs_a = review_tracking.get_revisions(conn, 'series-A')
        conn.close()
        assert absorbed is False
        assert [r['revision'] for r in revs_a] == [1]

    def test_absorb_idempotent_when_called_twice(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('mrl-absorb-twice-test')
        review_tracking.add_revision(conn, 'series-A', 1, 'a-v1@example.com')
        _seed_stray_series(conn, 'series-B', 2, 'fp-stray-b')

        first = review_tracking.absorb_series_as_revision(
            conn, 'series-A', 'series-B', 2
        )
        second = review_tracking.absorb_series_as_revision(
            conn, 'series-A', 'series-B', 2
        )
        revs_a = review_tracking.get_revisions(conn, 'series-A')
        conn.close()
        assert first is True
        assert second is False
        assert [r['revision'] for r in revs_a] == [1, 2]


# ---------------------------------------------------------------------------
# Tier 4: fingerprint semantics guard.  These pin the LoreSeries.fingerprint
# and __eq__ contracts the absorption logic and the future consumer rely on.
# They pass against current behaviour; their job is to fail loudly if a
# refactor ever changes it.
# ---------------------------------------------------------------------------

_AUTHOR = 'Author <author@example.com>'

_MINIMAL_DIFF = """\
Fix bar.

Signed-off-by: Author <author@example.com>
---
 foo.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/foo.c b/foo.c
index aaa..bbb 100644
--- a/foo.c
+++ b/foo.c
@@ -1,3 +1,4 @@
 void foo(void) {
+    bar();
 }
"""


def _build_series(
    subject: str, from_addr: str, revision: int, msgid: str = ''
) -> 'b4.LoreSeries':
    """Build a one-patch LoreSeries from a synthetic message."""
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['Date'] = 'Thu, 19 Mar 2026 08:51:12 +0530'
    msg['Message-Id'] = msgid or f'<{abs(hash(subject + from_addr))}@test.com>'
    msg.set_payload(_MINIMAL_DIFF)
    lmbx = b4.LoreMailbox()
    lmbx.add_message(msg)
    lser = lmbx.get_series(revision)
    assert lser is not None
    return lser


class TestFingerprintSemantics:
    """Tier 4: guard the fingerprint/__eq__ contract."""

    def test_different_revisions_differ(self) -> None:
        """Two revisions never share a fingerprint (revision is folded in)."""
        v1 = _build_series('[PATCH] foo: fix bar', _AUTHOR, 1)
        v2 = _build_series('[PATCH v2] foo: fix bar', _AUTHOR, 2)
        assert v1.fingerprint != v2.fingerprint

    def test_identical_posting_matches(self) -> None:
        """The same exact posting hashes identically (idempotent ingest)."""
        a = _build_series('[PATCH v2] foo: fix bar', _AUTHOR, 2, msgid='<x@test.com>')
        b = _build_series('[PATCH v2] foo: fix bar', _AUTHOR, 2, msgid='<x@test.com>')
        assert a.fingerprint == b.fingerprint

    def test_same_patches_different_sender(self) -> None:
        """Same patch-ids, different sender: fingerprints differ, __eq__ True."""
        a = _build_series('[PATCH v2] foo: fix bar', 'Alice <alice@example.com>', 2)
        b = _build_series('[PATCH v2] foo: fix bar', 'Bob <bob@example.com>', 2)
        assert a.fingerprint != b.fingerprint
        assert a == b


# ---------------------------------------------------------------------------
# Tier 5: link-a-revision orchestration.  record_linked_revision() folds a
# fetched series into an existing change_id as a manual link (absorbing a
# stray duplicate when one exists, surfacing a revision collision, and
# promoting a waiting series); unlink_revision() undoes a manual link;
# link_revision() is the thin fetch+delegate wrapper.
# ---------------------------------------------------------------------------


def _patch_email(subject: str, from_addr: str, msgid: str) -> EmailMessage:
    """Build a raw one-patch EmailMessage for fetch-wrapper tests."""
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['Date'] = 'Fri, 20 Mar 2026 14:49:18 +0000'
    msg['Message-Id'] = msgid
    msg.set_payload(_MINIMAL_DIFF)
    return msg


def _seed_target(
    conn: sqlite3.Connection,
    change_id: str,
    revision: int,
    status: str = 'reviewing',
) -> None:
    """Seed a tracked target series (series row + one heuristic revision)."""
    review_tracking.add_series_to_db(
        conn,
        change_id=change_id,
        revision=revision,
        subject=f'{change_id} v{revision}',
        sender_name='Author',
        sender_email='author@example.com',
        sent_at='2026-03-09T00:00:00+00:00',
        message_id=f'{change_id}-v{revision}@example.com',
        num_patches=1,
    )
    conn.execute(
        'UPDATE series SET status = ? WHERE change_id = ? AND revision = ?',
        (status, change_id, revision),
    )
    review_tracking.add_revision(
        conn,
        change_id,
        revision,
        f'{change_id}-v{revision}@example.com',
    )
    conn.commit()


class TestRecordLinkedRevision:
    """Tier 5: record_linked_revision() core logic."""

    def test_link_newer_revision_records_manual(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('mrl-link-new-test')
        _seed_target(conn, 'series-A', 1)
        lser = _build_series('[PATCH v2] foo: fix bar', _AUTHOR, 2)

        result = review_tracking.record_linked_revision(conn, 'series-A', lser)

        assert result['status'] == 'linked'
        assert result['revision'] == 2
        revs = review_tracking.get_revisions(conn, 'series-A')
        assert [r['revision'] for r in revs] == [1, 2]
        rev2 = next(r for r in revs if r['revision'] == 2)
        assert rev2['source'] == 'manual'
        # Patches were recorded for the linked revision.
        assert len(review_tracking.get_series_patches(conn, 'series-A', 2)) == 1
        # No new series row was created.
        cids = {row[0] for row in conn.execute('SELECT DISTINCT change_id FROM series')}
        conn.close()
        assert cids == {'series-A'}

    def test_link_older_revision(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('mrl-link-old-test')
        _seed_target(conn, 'series-A', 3)
        lser = _build_series('[PATCH] foo: fix bar', _AUTHOR, 1)

        result = review_tracking.record_linked_revision(conn, 'series-A', lser)
        revs = review_tracking.get_revisions(conn, 'series-A')
        conn.close()
        assert result['status'] == 'linked'
        assert [r['revision'] for r in revs] == [1, 3]

    def test_link_collision_blocks_without_force(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('mrl-link-collide-test')
        _seed_target(conn, 'series-A', 1)
        review_tracking.add_revision(conn, 'series-A', 2, 'pre-v2@example.com')
        lser = _build_series('[PATCH v2] foo: fix bar', _AUTHOR, 2)

        result = review_tracking.record_linked_revision(conn, 'series-A', lser)
        revs = review_tracking.get_revisions(conn, 'series-A')
        conn.close()
        assert result['status'] == 'collision'
        # Existing v2 untouched.
        rev2 = next(r for r in revs if r['revision'] == 2)
        assert rev2['message_id'] == 'pre-v2@example.com'
        assert rev2['source'] == 'heuristic'

    def test_link_collision_force_overrides(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('mrl-link-force-test')
        _seed_target(conn, 'series-A', 1)
        review_tracking.add_revision(conn, 'series-A', 2, 'pre-v2@example.com')
        lser = _build_series('[PATCH v2] foo: fix bar', _AUTHOR, 2)

        result = review_tracking.record_linked_revision(
            conn, 'series-A', lser, force=True
        )
        revs = review_tracking.get_revisions(conn, 'series-A')
        conn.close()
        assert result['status'] == 'linked'
        rev2 = next(r for r in revs if r['revision'] == 2)
        assert rev2['source'] == 'manual'

    def test_link_promotes_waiting_series(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('mrl-link-promote-test')
        _seed_target(conn, 'series-A', 1, status='waiting')
        lser = _build_series('[PATCH v2] foo: fix bar', _AUTHOR, 2)

        result = review_tracking.record_linked_revision(conn, 'series-A', lser)
        status = conn.execute(
            "SELECT status FROM series WHERE change_id = 'series-A'"
        ).fetchone()[0]
        conn.close()
        assert result['promoted'] is True
        assert status == 'reviewing'

    def test_link_absorbs_stray_duplicate(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('mrl-link-absorb-test')
        _seed_target(conn, 'series-A', 1)
        lser = _build_series('[PATCH v2] foo: fix bar', _AUTHOR, 2)
        # The stray was tracked from the same posting, so it shares a fingerprint.
        _seed_stray_series(conn, 'series-B', 2, lser.fingerprint)

        result = review_tracking.record_linked_revision(conn, 'series-A', lser)

        assert result['status'] == 'linked'
        assert result['absorbed'] is True
        revs = review_tracking.get_revisions(conn, 'series-A')
        assert [r['revision'] for r in revs] == [1, 2]
        # Stray is gone.
        assert review_tracking.get_revisions(conn, 'series-B') == []
        conn.close()


class TestUnlinkRevision:
    """Tier 5: unlink_revision() undoes a manual link only."""

    def test_unlink_manual_revision(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('mrl-unlink-test')
        review_tracking.add_revision(
            conn, 'series-A', 2, 'v2@example.com', source='manual'
        )
        _insert_patches(conn, 'series-A', 2, ['v2-p1@example.com'])

        removed = review_tracking.unlink_revision(conn, 'series-A', 2)
        revs = review_tracking.get_revisions(conn, 'series-A')
        patches = review_tracking.get_series_patches(conn, 'series-A', 2)
        conn.close()
        assert removed is True
        assert revs == []
        assert patches == []

    def test_unlink_refuses_heuristic(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('mrl-unlink-refuse-test')
        review_tracking.add_revision(conn, 'series-A', 2, 'v2@example.com')

        removed = review_tracking.unlink_revision(conn, 'series-A', 2)
        revs = review_tracking.get_revisions(conn, 'series-A')
        conn.close()
        assert removed is False
        assert [r['revision'] for r in revs] == [2]


class TestLinkRevisionWrapper:
    """Tier 5: link_revision() fetch+delegate wrapper."""

    @mock.patch('b4.retrieve_messages')
    def test_link_revision_not_found_graceful(
        self, mock_retrieve: mock.Mock, tmp_path: pytest.TempPathFactory
    ) -> None:
        review_tracking.init_db('mrl-wrap-miss-test').close()
        conn = review_tracking.get_db('mrl-wrap-miss-test')
        _seed_target(conn, 'series-A', 1)
        conn.close()

        mock_retrieve.return_value = ('x', [])
        result = review_tracking.link_revision(
            'mrl-wrap-miss-test', 'series-A', 'bogus@msgid'
        )

        conn = review_tracking.get_db('mrl-wrap-miss-test')
        revs = review_tracking.get_revisions(conn, 'series-A')
        conn.close()
        assert result == {
            'status': 'not-found',
            'revision': None,
            'absorbed': False,
            'promoted': False,
        }
        assert [r['revision'] for r in revs] == [1]

    @mock.patch('b4.retrieve_messages')
    def test_link_revision_success_path(
        self, mock_retrieve: mock.Mock, tmp_path: pytest.TempPathFactory
    ) -> None:
        review_tracking.init_db('mrl-wrap-ok-test').close()
        conn = review_tracking.get_db('mrl-wrap-ok-test')
        _seed_target(conn, 'series-A', 1)
        conn.close()

        msg = _patch_email('[PATCH v2] foo: fix bar', _AUTHOR, '<v2@example.com>')
        mock_retrieve.return_value = ('v2@example.com', [msg])
        result = review_tracking.link_revision(
            'mrl-wrap-ok-test', 'series-A', 'v2@example.com'
        )

        conn = review_tracking.get_db('mrl-wrap-ok-test')
        revs = review_tracking.get_revisions(conn, 'series-A')
        conn.close()
        assert result['status'] == 'linked'
        assert [r['revision'] for r in revs] == [1, 2]
        rev2 = next(r for r in revs if r['revision'] == 2)
        assert rev2['source'] == 'manual'


class TestFetchSeriesForLink:
    """Tier 6 support: fetch_series_for_link() builds a series or returns None."""

    @mock.patch('b4.retrieve_messages')
    def test_returns_series_on_success(self, mock_retrieve: mock.Mock) -> None:
        msg = _patch_email('[PATCH v2] foo: fix bar', _AUTHOR, '<v2@example.com>')
        mock_retrieve.return_value = ('v2@example.com', [msg])
        lser = review_tracking.fetch_series_for_link('v2@example.com')
        assert lser is not None
        assert lser.revision == 2

    @mock.patch('b4.retrieve_messages')
    def test_returns_none_on_empty_fetch(self, mock_retrieve: mock.Mock) -> None:
        mock_retrieve.return_value = ('x', [])
        assert review_tracking.fetch_series_for_link('bogus@msgid') is None

    @mock.patch('b4.retrieve_messages')
    def test_returns_none_on_fetch_error(self, mock_retrieve: mock.Mock) -> None:
        """A fetch that raises is swallowed and reported as None."""
        mock_retrieve.side_effect = RuntimeError('lore unreachable')
        assert review_tracking.fetch_series_for_link('x@example.com') is None

    @mock.patch('b4.retrieve_messages')
    def test_returns_none_for_non_patch_messages(
        self, mock_retrieve: mock.Mock
    ) -> None:
        """Messages that don't form a parseable series yield None."""
        msg = EmailMessage()
        msg['From'] = _AUTHOR
        msg['Subject'] = 'Re: some discussion'
        msg['Message-Id'] = '<x@example.com>'
        msg.set_content('just words, no patch')
        mock_retrieve.return_value = ('x', [msg])
        assert review_tracking.fetch_series_for_link('x@example.com') is None


# ---------------------------------------------------------------------------
# Rethread <-> version-upgrade composition (feature/rethread-upgrade-compose)
#
# Red spec — written test-first.  A series tracked at vN and rethreaded at
# vN+1 must reassemble correctly on upgrade.  That needs per-revision rethread
# state (schema v10), patch storage on the upgrade-link recording path, and a
# retrieval seam that honours the per-revision flag.  None of this exists yet.
# ---------------------------------------------------------------------------


def _pos_diff(n: int) -> str:
    """A self-contained one-file diff, distinct per patch position."""
    return (
        f'Change part {n}.\n\n'
        'Signed-off-by: Author <author@example.com>\n'
        '---\n'
        f' f{n}.c | 1 +\n'
        ' 1 file changed, 1 insertion(+)\n\n'
        f'diff --git a/f{n}.c b/f{n}.c\n'
        'index aaa..bbb 100644\n'
        f'--- a/f{n}.c\n'
        f'+++ b/f{n}.c\n'
        '@@ -1,3 +1,4 @@\n'
        f' void f{n}(void) {{\n'
        f'+    bar{n}();\n'
        ' }\n'
    )


def _series_msgs(
    base: str, author: str, rev: int, n: int, cover: bool = False
) -> list[EmailMessage]:
    """Return the messages making up an n-patch series at the given revision."""
    msgs: list[EmailMessage] = []
    if cover:
        msg = EmailMessage()
        msg['Subject'] = f'[PATCH v{rev} 0/{n}] {base}: do things better'
        msg['From'] = author
        msg['Date'] = 'Thu, 19 Mar 2026 08:51:10 +0530'
        msg['Message-Id'] = f'<{base}-v{rev}-p0@example.com>'
        msg.set_payload('This series makes things better.\n')
        msgs.append(msg)
    for i in range(1, n + 1):
        msg = EmailMessage()
        msg['Subject'] = f'[PATCH v{rev} {i}/{n}] {base}: part {i}'
        msg['From'] = author
        msg['Date'] = 'Thu, 19 Mar 2026 08:51:12 +0530'
        msg['Message-Id'] = f'<{base}-v{rev}-p{i}@example.com>'
        msg.set_payload(_pos_diff(i))
        msgs.append(msg)
    return msgs


def _build_lmbx(
    base: str, author: str, rev: int, n: int, cover: bool = False
) -> 'b4.LoreMailbox':
    """Build a LoreMailbox holding one n-patch series at the given revision.

    With *cover*, a 0/n cover letter is included; it lands in the mailbox's
    parse-time ``covers`` dict (never injected into the series, since these
    tests do not run ``get_series()``).
    """
    lmbx = b4.LoreMailbox()
    for msg in _series_msgs(base, author, rev, n, cover=cover):
        lmbx.add_message(msg)
    return lmbx


def _make_legacy_v9_db(identifier: str) -> str:
    """Create a schema-v9 database (revisions without is_rethreaded)."""
    path = review_tracking.get_db_path(identifier)
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
        CREATE TABLE revisions (
            change_id   TEXT NOT NULL,
            revision    INTEGER NOT NULL,
            message_id  TEXT NOT NULL,
            subject     TEXT,
            link        TEXT,
            found_at    TEXT,
            thread_blob TEXT,
            fingerprint TEXT,
            source      TEXT DEFAULT 'heuristic',
            PRIMARY KEY (change_id, revision)
        );
        """
    )
    conn.execute('INSERT INTO schema_version (version) VALUES (9)')
    conn.execute(
        'INSERT INTO revisions (change_id, revision, message_id, source)'
        ' VALUES (?, ?, ?, ?)',
        ('legacy-change', 5, 'legacy-v5@example.com', 'heuristic'),
    )
    conn.commit()
    conn.close()
    return path


class TestSchemaV10Rethread:
    """Layer 1: per-revision rethread tracking lands in schema v10."""

    def test_revisions_has_is_rethreaded_column(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('rt-up-cols')
        cols = {row[1] for row in conn.execute('PRAGMA table_info(revisions)')}
        conn.close()
        assert 'is_rethreaded' in cols

    def test_migration_v9_to_v10_adds_column_and_keeps_rows(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        _make_legacy_v9_db('rt-up-migrate')
        conn = review_tracking.get_db('rt-up-migrate')  # runs migration on open
        cols = {row[1] for row in conn.execute('PRAGMA table_info(revisions)')}
        assert 'is_rethreaded' in cols
        version = conn.execute('SELECT version FROM schema_version').fetchone()[0]
        assert version == review_tracking.SCHEMA_VERSION
        revs = review_tracking.get_revisions(conn, 'legacy-change')
        conn.close()
        assert len(revs) == 1
        # Pre-existing rows default to "not rethreaded".
        assert not revs[0]['is_rethreaded']


class TestAddRevisionRethreadFlag:
    """Layer 1: add_revision stores the flag and never downgrades it."""

    def test_flag_round_trips(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('rt-up-flag')
        review_tracking.add_revision(
            conn, 'cid', 2, 'v2@example.com', is_rethreaded=True
        )
        revs = review_tracking.get_revisions(conn, 'cid')
        conn.close()
        assert revs[0]['is_rethreaded']

    def test_flag_not_downgraded_on_readd(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('rt-up-flag-keep')
        review_tracking.add_revision(
            conn, 'cid', 2, 'v2@example.com', is_rethreaded=True
        )
        # A later heuristic re-add (no flag) must not clear it.
        review_tracking.add_revision(conn, 'cid', 2, 'v2@example.com')
        revs = review_tracking.get_revisions(conn, 'cid')
        conn.close()
        assert revs[0]['is_rethreaded']


class TestRecordDiscoveredRethreaded:
    """Layer 2: the upgrade-link recording path stores patches + flag."""

    def test_rethreaded_rev_gets_patches_and_flag(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('rt-up-rdr')
        lmbx = _build_lmbx('thing', _AUTHOR, 6, 3)
        new = review_tracking._record_discovered_revisions(
            conn, 'cid-X', lmbx, '', rethreaded_revs={6}
        )
        assert 6 in new
        revs = review_tracking.get_revisions(conn, 'cid-X')
        r6 = next(r for r in revs if r['revision'] == 6)
        patches = review_tracking.get_series_patches(conn, 'cid-X', 6)
        conn.close()
        assert r6['is_rethreaded']
        assert len(patches) == 3

    def test_normal_rev_left_unflagged(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('rt-up-rdr-normal')
        lmbx = _build_lmbx('thing', _AUTHOR, 6, 3)
        review_tracking._record_discovered_revisions(conn, 'cid-Y', lmbx, '')
        revs = review_tracking.get_revisions(conn, 'cid-Y')
        r6 = next(r for r in revs if r['revision'] == 6)
        patches = review_tracking.get_series_patches(conn, 'cid-Y', 6)
        conn.close()
        assert not r6['is_rethreaded']
        assert patches == []


# ---------------------------------------------------------------------------
# Discovered revisions must be identified by their cover letter when the
# author sent one (bug 8bb6e4c): a raw, never-get_series()'d revision has no
# cover injected into patches[0], so recording used to fall through to the
# first patch's subject/msgid.
# ---------------------------------------------------------------------------


class TestRecordDiscoveredCoverSubject:
    """_record_discovered_revisions prefers the parse-time cover letter."""

    def test_cover_subject_and_msgid_preferred(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('rdr-cover')
        lmbx = _build_lmbx('thing', _AUTHOR, 6, 3, cover=True)
        review_tracking._record_discovered_revisions(conn, 'cid-C', lmbx, '')
        revs = review_tracking.get_revisions(conn, 'cid-C')
        conn.close()
        r6 = next(r for r in revs if r['revision'] == 6)
        assert r6['subject'] == '[PATCH v6 0/3] thing: do things better'
        assert r6['message_id'] == 'thing-v6-p0@example.com'

    def test_no_cover_falls_back_to_first_patch(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('rdr-nocover')
        lmbx = _build_lmbx('thing', _AUTHOR, 6, 3)
        review_tracking._record_discovered_revisions(conn, 'cid-N', lmbx, '')
        revs = review_tracking.get_revisions(conn, 'cid-N')
        conn.close()
        r6 = next(r for r in revs if r['revision'] == 6)
        assert r6['subject'] == '[PATCH v6 1/3] thing: part 1'
        assert r6['message_id'] == 'thing-v6-p1@example.com'

    def test_rethreaded_rev_skips_cover(self, tmp_path: pytest.TempPathFactory) -> None:
        """A rethreaded revision's msgid must stay a real, fetchable patch."""
        conn = review_tracking.init_db('rdr-rt-cover')
        lmbx = _build_lmbx('thing', _AUTHOR, 6, 3, cover=True)
        review_tracking._record_discovered_revisions(
            conn, 'cid-R', lmbx, '', rethreaded_revs={6}
        )
        revs = review_tracking.get_revisions(conn, 'cid-R')
        conn.close()
        r6 = next(r for r in revs if r['revision'] == 6)
        assert r6['message_id'] == 'thing-v6-p1@example.com'

    @pytest.mark.parametrize(
        'source, expected_subject',
        [
            pytest.param(
                'heuristic',
                '[PATCH v6 0/3] thing: do things better',
                id='heuristic-row-healed',
            ),
            pytest.param(
                'manual',
                '[PATCH v6 1/3] thing: part 1',
                id='manual-link-preserved',
            ),
        ],
    )
    def test_cover_subject_heal_respects_provenance(
        self,
        source: str,
        expected_subject: str,
        tmp_path: pytest.TempPathFactory,
    ) -> None:
        """Re-recording with a cover heals a heuristic row, never a manual one.

        Both rows start from the same stale first-patch subject and differ
        only in provenance, so the diverging outcomes prove the distinction —
        a manual link is preserved even when its subject looks like the
        pre-fix fallback.
        """
        conn = review_tracking.init_db(f'rdr-heal-{source}')
        review_tracking.add_revision(
            conn,
            'cid-H',
            6,
            'thing-v6-p1@example.com',
            subject='[PATCH v6 1/3] thing: part 1',
            source=source,
        )
        lmbx = _build_lmbx('thing', _AUTHOR, 6, 3, cover=True)
        review_tracking._record_discovered_revisions(conn, 'cid-H', lmbx, '')
        revs = review_tracking.get_revisions(conn, 'cid-H')
        conn.close()
        r6 = next(r for r in revs if r['revision'] == 6)
        assert r6['subject'] == expected_subject
        # Other core fields keep first-wins semantics.
        assert r6['message_id'] == 'thing-v6-p1@example.com'


class TestUpdateSeriesTrackingCoverSubject:
    """[u]pdate discovers revisions too, and must name them the same way.

    update_series_tracking() recorded them by hand instead of going through
    _record_discovered_revisions(), so it kept picking the first present patch
    of a raw LoreSeries (bug 8bb6e4c).  That is the path the TUI actually runs,
    so an upgrade re-titled the series after patch 1/N.
    """

    def _update(
        self, identifier: str, change_id: str, revision: int, msgs: list[EmailMessage]
    ) -> Dict[str, Any]:
        series: Dict[str, Any] = {
            'change_id': change_id,
            'revision': revision,
            'status': 'new',
            'message_id': f'thing-v{revision}-p0@example.com',
        }
        with (
            mock.patch('b4.review._review.retrieve_series_messages', return_value=msgs),
            mock.patch('b4.review._review.check_series_attestation', return_value=None),
        ):
            return b4.review.update_series_tracking(
                series, identifier, 'https://example.com/%s'
            )

    def test_discovered_revision_named_after_cover(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        identifier = 'ust-cover'
        change_id = 'cid-U'
        conn = review_tracking.init_db(identifier)
        review_tracking.add_series_to_db(
            conn,
            change_id,
            1,
            'thing: do things better',
            'Author',
            'author@example.com',
            '2026-03-19T08:51:10+00:00',
            'thing-v1-p0@example.com',
            3,
        )
        review_tracking.add_revision(
            conn,
            change_id,
            1,
            'thing-v1-p0@example.com',
            subject='[PATCH v1 0/3] thing: do things better',
        )
        conn.close()

        msgs = _series_msgs('thing', _AUTHOR, 1, 3, cover=True)
        msgs += _series_msgs('thing', _AUTHOR, 2, 3, cover=True)
        result = self._update(identifier, change_id, 1, msgs)

        assert result['error'] is None
        assert result['new_revisions'] == 1
        conn = review_tracking.get_db(identifier)
        revs = review_tracking.get_revisions(conn, change_id)
        conn.close()
        r2 = next(r for r in revs if r['revision'] == 2)
        assert r2['subject'] == '[PATCH v2 0/3] thing: do things better'
        assert r2['message_id'] == 'thing-v2-p0@example.com'

    def test_stale_series_title_is_realigned(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """A series an upgrade left titled after patch 1/N heals on update."""
        identifier = 'ust-realign'
        change_id = 'cid-V'
        conn = review_tracking.init_db(identifier)
        review_tracking.add_series_to_db(
            conn,
            change_id,
            2,
            '[PATCH v2 1/3] thing: part 1',
            'Author',
            'author@example.com',
            '2026-03-19T08:51:12+00:00',
            'thing-v2-p1@example.com',
            3,
        )
        review_tracking.add_revision(
            conn,
            change_id,
            2,
            'thing-v2-p1@example.com',
            subject='[PATCH v2 1/3] thing: part 1',
        )
        conn.close()

        msgs = _series_msgs('thing', _AUTHOR, 2, 3, cover=True)
        result = self._update(identifier, change_id, 2, msgs)

        assert result['error'] is None
        conn = review_tracking.get_db(identifier)
        row = conn.execute(
            'SELECT subject FROM series WHERE change_id = ? AND revision = ?',
            (change_id, 2),
        ).fetchone()
        conn.close()
        assert row['subject'] == '[PATCH v2 0/3] thing: do things better'


class TestRealignSeriesSubject:
    """realign_series_subject() re-titles only from an actual cover letter."""

    def _seed(self, identifier: str, series_subject: str) -> None:
        conn = review_tracking.init_db(identifier)
        review_tracking.add_series_to_db(
            conn,
            'cid-A',
            3,
            series_subject,
            'Author',
            'author@example.com',
            '2026-03-19T08:51:10+00:00',
            'thing-v3-p1@example.com',
            2,
        )
        conn.close()

    def _realign(self, identifier: str, cover: bool) -> bool:
        lmbx = _build_lmbx('thing', _AUTHOR, 3, 2, cover=cover)
        conn = review_tracking.get_db(identifier)
        ret = review_tracking.realign_series_subject(conn, 'cid-A', 3, lmbx)
        conn.close()
        return ret

    def _subject(self, identifier: str) -> str:
        conn = review_tracking.get_db(identifier)
        row = conn.execute(
            "SELECT subject FROM series WHERE change_id = 'cid-A'"
        ).fetchone()
        conn.close()
        return str(row['subject'])

    def test_realigns_first_patch_title(self, tmp_path: pytest.TempPathFactory) -> None:
        self._seed('rsj-fix', '[PATCH v3 1/2] thing: part 1')
        assert self._realign('rsj-fix', cover=True) is True
        assert self._subject('rsj-fix') == '[PATCH v3 0/2] thing: do things better'

    def test_prefix_only_difference_is_left_alone(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """The track and upgrade paths format the prefix differently."""
        self._seed('rsj-pfx', 'thing: do things better')
        assert self._realign('rsj-pfx', cover=True) is False
        assert self._subject('rsj-pfx') == 'thing: do things better'

    def test_coverless_thread_never_overwrites(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Without a cover there is nothing better than what is stored.

        Re-titling from the first-patch fallback would corrupt every correctly
        titled row whose cover letter is not in the fetched thread.
        """
        self._seed('rsj-nocover', 'thing: do things better')
        assert self._realign('rsj-nocover', cover=False) is False
        assert self._subject('rsj-nocover') == 'thing: do things better'

    def test_missing_series_row_is_a_noop(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('rsj-none')
        lmbx = _build_lmbx('thing', _AUTHOR, 3, 2, cover=True)
        assert review_tracking.realign_series_subject(conn, 'cid-A', 3, lmbx) is False
        conn.close()


class TestCmdTrackRethreadUpgrade:
    """Layer 2 (integration): rethreaded vN+1 links onto a tracked vN."""

    def test_rethreaded_upgrade_records_patches_and_flag(self, gitdir: str) -> None:
        review_tracking.cmd_enroll(
            argparse.Namespace(repo_path=gitdir, identifier='rt-up-track')
        )
        # An already-tracked v5 under change-id cid-A.
        conn = review_tracking.get_db('rt-up-track')
        review_tracking.add_series_to_db(
            conn,
            change_id='cid-A',
            revision=5,
            subject='thing',
            sender_name='Author',
            sender_email='author@example.com',
            sent_at='2026-03-09T00:00:00+00:00',
            message_id='cid-A-v5@example.com',
            num_patches=3,
            fingerprint='fp-v5',
        )
        review_tracking.add_revision(conn, 'cid-A', 5, 'cid-A-v5@example.com')
        conn.close()

        # A rethreaded v6 that carries the same embedded change-id (so it lands
        # in the already-tracked branch) — modelling the upgrade.
        cover = mock.Mock(msgid='v6-cover@example.com', subject='thing cover')
        p1 = mock.Mock(msgid='v6-p1@example.com', subject='[PATCH v6 1/3] a')
        mock_lser = mock.Mock()
        mock_lser.revision = 6
        mock_lser.expected = 3
        mock_lser.change_id = 'cid-A'
        mock_lser.fromname = 'Author'
        mock_lser.fromemail = 'author@example.com'
        mock_lser.subject = 'thing'
        mock_lser.fingerprint = 'fp-v6'
        mock_lser.has_cover = True
        mock_lser.patches = [cover, p1, None, None]

        mock_mbx = mock.Mock()
        mock_mbx.series = {6: mock_lser}
        mock_mbx.get_series.return_value = mock_lser

        cmdargs = argparse.Namespace(
            series_id=None,
            rethread=['c1@q', 'c2@q', 'c3@q', 'c4@q'],
            identifier='rt-up-track',
            wantver=None,
        )
        with (
            mock.patch(
                'b4.retrieve_rethreaded_messages',
                return_value=('v6-p1@example.com', [mock.Mock()], True),
            ),
            mock.patch('b4.LoreMailbox', return_value=mock_mbx),
            mock.patch('b4.can_network', False),
        ):
            review_tracking.cmd_track(cmdargs)

        conn = review_tracking.get_db('rt-up-track')
        revs = review_tracking.get_revisions(conn, 'cid-A')
        r6 = next((r for r in revs if r['revision'] == 6), None)
        patches = review_tracking.get_series_patches(conn, 'cid-A', 6)
        # No duplicate stray series got created.
        cids = {row[0] for row in conn.execute('SELECT DISTINCT change_id FROM series')}
        conn.close()
        assert r6 is not None
        assert r6['is_rethreaded']
        assert len(patches) >= 1
        assert cids == {'cid-A'}


class TestRetrieveSeriesMessagesRethreadSeam:
    """Layer 3: the upgrade retrieval seam honours the per-revision flag."""

    def test_reassembles_from_patches_when_flag_set(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        review_tracking.init_db('rt-up-seam').close()
        conn = review_tracking.get_db('rt-up-seam')
        review_tracking.add_revision(
            conn, 'cid', 6, 'v6-root@example.com', is_rethreaded=True
        )
        _insert_patches(conn, 'cid', 6, ['p1@q', 'p2@q', 'p3@q'])
        # Derive the flag the way the upgrade path will — from get_revisions.
        r6 = next(
            r for r in review_tracking.get_revisions(conn, 'cid') if r['revision'] == 6
        )
        conn.close()
        series = {
            'change_id': 'cid',
            'revision': 6,
            'message_id': 'v6-root@example.com',
            'is_rethreaded': bool(r6['is_rethreaded']),
        }

        reassembled = [mock.Mock(), mock.Mock(), mock.Mock()]
        forwarded_callback: list[Any] = []

        def _fetch_rethread_messages(
            msgids: list[str], nocache: bool = False, progress_cb: Any = None
        ) -> tuple[list[str], list[Any]]:
            assert nocache is True
            forwarded_callback.append(progress_cb)
            return msgids, reassembled

        progress_cb = mock.Mock()
        with (
            mock.patch(
                'b4.fetch_rethread_messages',
                side_effect=_fetch_rethread_messages,
            ),
            mock.patch(
                'b4.LoreSeries.rethread_series',
                return_value=('p1@q', reassembled),
            ),
        ):
            out = b4.review.retrieve_series_messages(
                series, 'rt-up-seam', progress_cb=progress_cb
            )
        assert out == reassembled
        assert forwarded_callback == [progress_cb]

    def test_normal_fetch_reports_single_step_progress(self) -> None:
        """A normal single-thread fetch reports its start and completion."""
        series = {
            'change_id': 'cid',
            'revision': 6,
            'message_id': 'v6-root@example.com',
            'is_rethreaded': False,
        }
        msgs = [mock.Mock()]
        events: list[Any] = []

        def _retrieve(message_id: str) -> list[Any]:
            events.append(('fetch', message_id))
            return msgs

        with mock.patch('b4.review._review._retrieve_messages', side_effect=_retrieve):
            out = b4.review.retrieve_series_messages(
                series,
                'rt-up-seam-normal',
                progress_cb=lambda completed, total: events.append(
                    ('progress', completed, total)
                ),
            )

        assert out == msgs
        assert events == [
            ('progress', 0, 1),
            ('fetch', 'v6-root@example.com'),
            ('progress', 1, 1),
        ]


class TestRethreadFlagCarriedOnLink:
    """Layer 5: absorb + manual link carry the rethread flag onto the target."""

    def test_absorb_carries_flag(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('rt-up-absorb')
        review_tracking.add_revision(conn, 'series-A', 1, 'a-v1@example.com')
        _seed_stray_series(conn, 'series-B', 2, 'fp-stray-b')
        conn.execute("UPDATE series SET is_rethreaded = 1 WHERE change_id = 'series-B'")
        conn.commit()

        review_tracking.absorb_series_as_revision(conn, 'series-A', 'series-B', 2)
        revs = review_tracking.get_revisions(conn, 'series-A')
        conn.close()
        rev2 = next(r for r in revs if r['revision'] == 2)
        assert rev2['is_rethreaded']

    def test_record_linked_carries_flag(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('rt-up-link')
        _seed_target(conn, 'series-A', 1)
        lser = _build_series('[PATCH v2] foo: fix bar', _AUTHOR, 2)
        review_tracking.record_linked_revision(
            conn, 'series-A', lser, is_rethreaded=True
        )
        revs = review_tracking.get_revisions(conn, 'series-A')
        conn.close()
        rev2 = next(r for r in revs if r['revision'] == 2)
        assert rev2['is_rethreaded']


# ---------------------------------------------------------------------------
# Cross-machine portability of the rethread/upgrade catalog
# (feature/rethread-upgrade-portable)
#
# Red spec — the revisions catalog (incl. rethreaded patch lists) must travel
# in the review branch tracking commit so another machine can rebuild it.
# build_known_revisions/record_known_revisions and the rescan replay don't
# exist yet.
# ---------------------------------------------------------------------------


def _make_review_branch_with_catalog(
    gitdir: str,
    identifier: str,
    change_id: str,
    revision: int,
    known_revisions: list[dict[str, Any]],
) -> str:
    """Create a review branch whose tracking commit carries known-revisions."""
    branch = f'b4/review/{change_id}'
    ecode, base = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
    assert ecode == 0
    base = base.strip()
    b4.git_run_command(gitdir, ['branch', branch, base])
    b4.git_run_command(gitdir, ['checkout', branch])
    trk = {
        'series': {
            'identifier': identifier,
            'change-id': change_id,
            'revision': revision,
            'status': 'reviewing',
            'subject': change_id,
            'fromname': 'Author',
            'fromemail': 'author@example.com',
            'expected': 1,
            'complete': True,
            'base-commit': base,
            'prerequisite-commits': [],
            'first-patch-commit': base,
            'link': '',
            'header-info': {'msgid': f'{change_id}-v{revision}@example.com'},
            'is-rethreaded': False,
        },
        'followups': [],
        'patches': [],
        'known-revisions': known_revisions,
    }
    commit_msg = f'{change_id}\n\n{b4.review.make_review_magic_json(trk)}'
    b4.git_run_command(gitdir, ['commit', '--allow-empty', '-m', commit_msg])
    b4.git_run_command(gitdir, ['checkout', 'master'])
    return branch


class TestKnownRevisionsCatalog:
    """Step 1: serialize/replay the revisions catalog for the tracking commit."""

    def test_build_record_round_trip(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('rt-port-rt')
        review_tracking.add_revision(conn, 'cid', 5, 'v5@example.com')
        review_tracking.add_revision(
            conn,
            'cid',
            6,
            'v6@example.com',
            fingerprint='fp6',
            source='manual',
            is_rethreaded=True,
        )
        _insert_patches(conn, 'cid', 6, ['p1@example.com', 'p2@example.com'])
        known = review_tracking.build_known_revisions(conn, 'cid')
        conn.close()

        conn2 = review_tracking.init_db('rt-port-rt2')
        review_tracking.record_known_revisions(conn2, 'cid', known)
        revs = review_tracking.get_revisions(conn2, 'cid')
        r6 = next(r for r in revs if r['revision'] == 6)
        patches = review_tracking.get_series_patches(conn2, 'cid', 6)
        conn2.close()

        assert {r['revision'] for r in revs} == {5, 6}
        assert r6['is_rethreaded']
        assert r6['source'] == 'manual'
        assert r6['fingerprint'] == 'fp6'
        assert [p['message_id'] for p in patches] == [
            'p1@example.com',
            'p2@example.com',
        ]

    def test_record_is_sticky_and_no_downgrade(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('rt-port-sticky')
        review_tracking.add_revision(
            conn, 'cid', 6, 'v6@example.com', source='manual', is_rethreaded=True
        )
        # Replaying a weaker/older catalog entry must not clobber state.
        review_tracking.record_known_revisions(
            conn,
            'cid',
            [{'revision': 6, 'message-id': 'v6@example.com', 'source': 'heuristic'}],
        )
        revs = review_tracking.get_revisions(conn, 'cid')
        conn.close()
        r6 = next(r for r in revs if r['revision'] == 6)
        assert r6['is_rethreaded']
        assert r6['source'] == 'manual'


class TestRescanReplaysCatalog:
    """Step 2: rescan_branches rebuilds the catalog from a synced branch."""

    def test_pending_rethreaded_revision_survives_sync(self, gitdir: str) -> None:
        identifier = 'rt-port-rescan'
        known = [
            {'revision': 5, 'message-id': 'v5@example.com', 'source': 'heuristic'},
            {
                'revision': 6,
                'message-id': 'v6cover@example.com',
                'is-rethreaded': True,
                'patches': [
                    {'position': 1, 'message-id': 'p1@example.com', 'subject': 'a'},
                    {'position': 2, 'message-id': 'p2@example.com', 'subject': 'b'},
                    {'position': 3, 'message-id': 'p3@example.com', 'subject': 'c'},
                ],
            },
        ]
        _make_review_branch_with_catalog(gitdir, identifier, 'cid-A', 5, known)
        # Fresh DB (as on a second machine) with no knowledge of v6.
        review_tracking.init_db(identifier).close()
        review_tracking.rescan_branches(identifier, gitdir, 'b4/review/cid-A')

        conn = review_tracking.get_db(identifier)
        revs = review_tracking.get_revisions(conn, 'cid-A')
        r6 = next((r for r in revs if r['revision'] == 6), None)
        patches = review_tracking.get_series_patches(conn, 'cid-A', 6)
        conn.close()
        assert {r['revision'] for r in revs} == {5, 6}
        assert r6 is not None
        assert r6['is_rethreaded']
        assert [p['message_id'] for p in patches] == [
            'p1@example.com',
            'p2@example.com',
            'p3@example.com',
        ]


class TestSyncRevisionsCatalogToBranch:
    """Step 3: the writer mirrors the DB catalog onto the review branch."""

    def test_sync_writes_catalog_to_branch(self, gitdir: str) -> None:
        identifier = 'rt-port-sync'
        # A review branch exists for v5 with no catalog yet.
        _make_review_branch_with_catalog(gitdir, identifier, 'cid-A', 5, [])
        conn = review_tracking.init_db(identifier)
        review_tracking.add_revision(conn, 'cid-A', 5, 'v5@example.com')
        review_tracking.add_revision(
            conn, 'cid-A', 6, 'v6@example.com', is_rethreaded=True
        )
        _insert_patches(conn, 'cid-A', 6, ['p1@example.com', 'p2@example.com'])
        conn.close()

        wrote = review_tracking.sync_revisions_catalog_to_branch(
            gitdir, identifier, 'cid-A'
        )
        assert wrote is True

        _cover, tracking = b4.review.load_tracking(gitdir, 'b4/review/cid-A')
        known = {e['revision']: e for e in tracking.get('known-revisions', [])}
        assert set(known) == {5, 6}
        assert known[6].get('is-rethreaded') is True
        assert [p['message-id'] for p in known[6]['patches']] == [
            'p1@example.com',
            'p2@example.com',
        ]

        # Idempotent: a second sync with no DB change rewrites nothing.
        assert (
            review_tracking.sync_revisions_catalog_to_branch(
                gitdir, identifier, 'cid-A'
            )
            is False
        )

    def test_sync_no_branch_is_noop(self, tmp_path: pytest.TempPathFactory) -> None:
        review_tracking.init_db('rt-port-sync-nobranch').close()
        assert (
            review_tracking.sync_revisions_catalog_to_branch(
                None, 'rt-port-sync-nobranch', 'cid-A'
            )
            is False
        )


class TestKnownProjects:
    """Tests for the identifier→repository reverse mapping."""

    def test_record_and_list(self, gitdir: str) -> None:
        conn = review_tracking.init_db('mapped')
        conn.close()
        review_tracking.save_repo_metadata(os.path.join(gitdir, '.git'), 'mapped')
        review_tracking.record_repo_path('mapped', gitdir)
        assert review_tracking.get_known_projects() == [('mapped', gitdir)]

    def test_stale_path_yields_none(self, tmp_path: pathlib.Path) -> None:
        conn = review_tracking.init_db('ghost')
        conn.close()
        review_tracking.record_repo_path('ghost', str(tmp_path / 'moved-away'))
        assert review_tracking.get_known_projects() == [('ghost', None)]

    def test_unrecorded_yields_none(self, tmp_path: pathlib.Path) -> None:
        conn = review_tracking.init_db('bare')
        conn.close()
        assert review_tracking.get_known_projects() == [('bare', None)]


class TestAutoWakeSnoozed:
    """Tests for the extracted snooze wake-up sweep."""

    def test_wakes_expired(self, tmp_path: pathlib.Path) -> None:
        conn = review_tracking.init_db('wakeful')
        review_tracking.add_series_to_db(
            conn,
            'cid-1',
            1,
            'subj',
            'Name',
            'e@example.com',
            None,
            '<m@id>',
            1,
        )
        review_tracking.snooze_series(conn, 'cid-1', '2000-01-01T00:00:00')
        conn.close()
        assert review_tracking.auto_wake_snoozed('wakeful', None) == 1
        conn = review_tracking.get_db('wakeful')
        row = conn.execute(
            'SELECT status FROM series WHERE change_id = ?', ('cid-1',)
        ).fetchone()
        conn.close()
        assert row[0] == 'reviewing'


class TestUpdateMessageCountSeenBump:
    """Tests for the seen_bump handling in update_message_count_from_msgs()."""

    @staticmethod
    def _make_msgs(count: int) -> list[EmailMessage]:
        msgs = []
        for i in range(count):
            msg = EmailMessage()
            msg['Message-Id'] = f'<m{i}@example.com>'
            msg['Date'] = f'Mon, 27 Jul 2026 10:{i:02d}:00 +0000'
            msgs.append(msg)
        return msgs

    @staticmethod
    def _setup_series(identifier: str) -> sqlite3.Connection:
        conn = review_tracking.init_db(identifier)
        conn.row_factory = sqlite3.Row
        review_tracking.add_series_to_db(
            conn,
            'bump-cid',
            1,
            'Test series',
            'Author',
            'author@example.com',
            '2026-07-27T09:00:00+00:00',
            'm0@example.com',
            2,
        )
        return conn

    @staticmethod
    def _get_counts(conn: sqlite3.Connection) -> tuple[int, int]:
        row = conn.execute(
            'SELECT message_count, seen_message_count FROM series'
            ' WHERE change_id = ? AND revision = ?',
            ('bump-cid', 1),
        ).fetchone()
        return row['message_count'], row['seen_message_count']

    def test_first_fetch_ignores_bump(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = self._setup_series('bump-first')
        review_tracking.update_message_count_from_msgs(
            conn, 'bump-cid', 1, self._make_msgs(3), seen_bump=5
        )
        assert self._get_counts(conn) == (3, 3)
        conn.close()

    def test_bump_advances_seen(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = self._setup_series('bump-adv')
        review_tracking.update_message_count_from_msgs(
            conn, 'bump-cid', 1, self._make_msgs(3)
        )
        review_tracking.update_message_count_from_msgs(
            conn, 'bump-cid', 1, self._make_msgs(5), seen_bump=1
        )
        # 2 new messages, 1 of them already read: badge shows 1 unread
        assert self._get_counts(conn) == (5, 4)
        conn.close()

    def test_no_bump_keeps_seen(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = self._setup_series('bump-none')
        review_tracking.update_message_count_from_msgs(
            conn, 'bump-cid', 1, self._make_msgs(3)
        )
        review_tracking.update_message_count_from_msgs(
            conn, 'bump-cid', 1, self._make_msgs(5)
        )
        assert self._get_counts(conn) == (5, 3)
        conn.close()

    def test_bump_clamped_to_count(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = self._setup_series('bump-clamp')
        review_tracking.update_message_count_from_msgs(
            conn, 'bump-cid', 1, self._make_msgs(3)
        )
        review_tracking.update_message_count_from_msgs(
            conn, 'bump-cid', 1, self._make_msgs(4), seen_bump=10
        )
        assert self._get_counts(conn) == (4, 4)
        conn.close()

    def test_unchanged_count_no_write(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = self._setup_series('bump-same')
        review_tracking.update_message_count_from_msgs(
            conn, 'bump-cid', 1, self._make_msgs(3)
        )
        changed = review_tracking.update_message_count_from_msgs(
            conn, 'bump-cid', 1, self._make_msgs(3), seen_bump=2
        )
        assert changed is False
        assert self._get_counts(conn) == (3, 3)
        conn.close()


class TestFindTrackedChangeId:
    """Tests for find_tracked_change_id()."""

    def _seed(self, conn: sqlite3.Connection) -> None:
        review_tracking.add_series_to_db(
            conn,
            'cid-forget',
            2,
            'Subject',
            'Author',
            'a@example.com',
            '2026-07-01T10:00:00+00:00',
            'primary-v2@example.com',
            2,
        )
        review_tracking.add_revision(conn, 'cid-forget', 3, 'linked-v3@example.com')
        _insert_patches(
            conn, 'cid-forget', 2, ['p1-v2@example.com', 'p2-v2@example.com']
        )

    def test_match_by_change_id(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('ftci-cid')
        self._seed(conn)
        assert review_tracking.find_tracked_change_id(conn, 'cid-forget') == (
            'cid-forget'
        )
        conn.close()

    def test_match_by_series_message_id(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('ftci-series-mid')
        self._seed(conn)
        found = review_tracking.find_tracked_change_id(conn, 'primary-v2@example.com')
        assert found == 'cid-forget'
        conn.close()

    def test_match_by_revision_message_id(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        conn = review_tracking.init_db('ftci-rev-mid')
        self._seed(conn)
        found = review_tracking.find_tracked_change_id(conn, 'linked-v3@example.com')
        assert found == 'cid-forget'
        conn.close()

    def test_match_by_patch_message_id(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('ftci-patch-mid')
        self._seed(conn)
        found = review_tracking.find_tracked_change_id(conn, 'p2-v2@example.com')
        assert found == 'cid-forget'
        conn.close()

    def test_no_match(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('ftci-miss')
        self._seed(conn)
        assert review_tracking.find_tracked_change_id(conn, 'nope@example.com') is None
        assert review_tracking.find_tracked_change_id(conn, '') is None
        conn.close()


class TestCmdForget:
    """Tests for cmd_forget()."""

    def _enroll_and_seed(self, gitdir: str, identifier: str) -> None:
        cmdargs = argparse.Namespace(repo_path=gitdir, identifier=identifier)
        review_tracking.cmd_enroll(cmdargs)
        conn = review_tracking.get_db(identifier)
        review_tracking.add_series_to_db(
            conn,
            'cid-gone',
            1,
            'Archived series',
            'Mark',
            'mark@example.com',
            '2026-06-01T10:00:00+00:00',
            'gone-v1@example.com',
            3,
        )
        conn.execute(
            "UPDATE series SET status = 'archived' WHERE change_id = 'cid-gone'"
        )
        review_tracking.add_revision(conn, 'cid-gone', 1, 'gone-v1@example.com')
        review_tracking.add_revision(conn, 'cid-gone', 2, 'gone-v2@example.com')
        _insert_patches(conn, 'cid-gone', 1, ['gone-p1@example.com'])
        review_tracking.add_series_to_db(
            conn,
            'cid-keep',
            1,
            'Unrelated series',
            'Other',
            'other@example.com',
            '2026-06-02T10:00:00+00:00',
            'keep-v1@example.com',
            1,
        )
        conn.commit()
        conn.close()

    def _rows_left(self, identifier: str, change_id: str) -> Dict[str, int]:
        conn = review_tracking.get_db(identifier)
        counts = {}
        for table in ('series', 'revisions', 'series_patches'):
            counts[table] = conn.execute(
                f'SELECT COUNT(*) FROM {table} WHERE change_id = ?', (change_id,)
            ).fetchone()[0]
        conn.close()
        return counts

    def test_forget_confirmed(
        self, gitdir: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Confirming erases every record of the series, and only that one."""
        self._enroll_and_seed(gitdir, 'forget-yes')
        monkeypatch.setattr('builtins.input', lambda _prompt: 'y')
        cmdargs = argparse.Namespace(
            series_id='gone-v2@example.com', identifier='forget-yes'
        )
        review_tracking.cmd_forget(cmdargs)
        assert self._rows_left('forget-yes', 'cid-gone') == {
            'series': 0,
            'revisions': 0,
            'series_patches': 0,
        }
        assert self._rows_left('forget-yes', 'cid-keep')['series'] == 1

    def test_forget_declined(
        self, gitdir: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Declining the confirmation leaves everything in place."""
        self._enroll_and_seed(gitdir, 'forget-no')
        monkeypatch.setattr('builtins.input', lambda _prompt: 'n')
        cmdargs = argparse.Namespace(series_id='cid-gone', identifier='forget-no')
        with pytest.raises(SystemExit) as excinfo:
            review_tracking.cmd_forget(cmdargs)
        assert excinfo.value.code == 0
        assert self._rows_left('forget-no', 'cid-gone') == {
            'series': 1,
            'revisions': 2,
            'series_patches': 1,
        }

    def test_forget_no_match(
        self, gitdir: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unknown identifier fails without asking for confirmation."""
        self._enroll_and_seed(gitdir, 'forget-miss')

        def _no_input(_prompt: str) -> str:
            raise AssertionError('confirmation must not be requested')

        monkeypatch.setattr('builtins.input', _no_input)
        cmdargs = argparse.Namespace(
            series_id='unknown@example.com', identifier='forget-miss'
        )
        with pytest.raises(SystemExit) as excinfo:
            review_tracking.cmd_forget(cmdargs)
        assert excinfo.value.code == 1

    def test_forget_deletes_review_branch(
        self, gitdir: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A leftover review branch is deleted along with the records."""
        self._enroll_and_seed(gitdir, 'forget-branch')
        ecode, _ = b4.git_run_command(gitdir, ['branch', 'b4/review/cid-gone'])
        assert ecode == 0
        monkeypatch.setattr('builtins.input', lambda _prompt: 'yes')
        cmdargs = argparse.Namespace(
            series_id='gone-v1@example.com', identifier='forget-branch'
        )
        review_tracking.cmd_forget(cmdargs)
        assert not b4.git_branch_exists(gitdir, 'b4/review/cid-gone')
        assert self._rows_left('forget-branch', 'cid-gone')['series'] == 0

    def test_forget_refuses_checked_out_branch(
        self, gitdir: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The review branch being checked out aborts before confirmation."""
        self._enroll_and_seed(gitdir, 'forget-checkedout')
        ecode, _ = b4.git_run_command(gitdir, ['checkout', '-b', 'b4/review/cid-gone'])
        assert ecode == 0

        def _no_input(_prompt: str) -> str:
            raise AssertionError('confirmation must not be requested')

        monkeypatch.setattr('builtins.input', _no_input)
        cmdargs = argparse.Namespace(
            series_id='cid-gone', identifier='forget-checkedout'
        )
        with pytest.raises(SystemExit) as excinfo:
            review_tracking.cmd_forget(cmdargs)
        assert excinfo.value.code == 1
        assert self._rows_left('forget-checkedout', 'cid-gone')['series'] == 1


class TestUpdateSkipsCheckedOutBranch:
    """update_series_tracking leaves a checked-out review branch alone."""

    def _tracking_data(self, change_id: str) -> Dict[str, Any]:
        return {
            'series': {
                'identifier': 'co-test',
                'status': 'reviewing',
                'revision': 1,
                'change-id': change_id,
                'subject': 'Test',
                'fromname': 'Author',
                'fromemail': 'a@example.com',
                'expected': 1,
                'complete': True,
                'base-commit': 'abc123',
                'prerequisite-commits': [],
                'first-patch-commit': 'def456',
                'header-info': {},
                'link': '',
            },
            'followups': [],
            'patches': [],
        }

    def _run_update(self, gitdir: str, change_id: str) -> Dict[str, Any]:
        conn = review_tracking.init_db('co-test')
        review_tracking.add_series_to_db(
            conn,
            change_id,
            1,
            'Test',
            'Author',
            'a@example.com',
            '2026-07-01T00:00:00+00:00',
            'cover@example.com',
            1,
        )
        review_tracking.update_series_status(conn, change_id, 'reviewing')
        conn.close()

        msgs = [_make_test_msg('cover@example.com')]
        mock_lmbx = mock.Mock()
        mock_lmbx.series = {}
        mock_lmbx.covers = {}
        # get_series returning None makes the branch-update section fail
        # with a recognizable error — a sentinel showing it was entered.
        mock_lmbx.get_series.return_value = None

        series_dict: Dict[str, Any] = {
            'change_id': change_id,
            'revision': 1,
            'status': 'reviewing',
            'message_id': 'cover@example.com',
        }
        with (
            mock.patch('b4.review._review.retrieve_series_messages', return_value=msgs),
            mock.patch('b4.LoreMailbox', return_value=mock_lmbx),
        ):
            return b4.review.update_series_tracking(
                series_dict, 'co-test', 'https://example.com/%s', topdir=gitdir
            )

    def test_checked_out_branch_left_alone(self, gitdir: str) -> None:
        """A checked-out branch is skipped: flag set, tip untouched."""
        change_id = 'co-checkedout'
        branch = _create_review_branch(
            gitdir, change_id, self._tracking_data(change_id)
        )
        ecode, _ = b4.git_run_command(gitdir, ['checkout', branch])
        assert ecode == 0
        ecode, tip_before = b4.git_run_command(gitdir, ['rev-parse', branch])
        assert ecode == 0

        result = self._run_update(gitdir, change_id)

        assert result.get('checked_out') is True
        assert result.get('error') is None
        ecode, tip_after = b4.git_run_command(gitdir, ['rev-parse', branch])
        assert ecode == 0
        assert tip_after == tip_before
        # DB-side maintenance still ran
        assert result.get('counts_updated') is True

    def test_parked_branch_still_updated(self, gitdir: str) -> None:
        """Control: with the branch not checked out the section is entered
        (and fails on the mocked-away series — the sentinel error)."""
        change_id = 'co-parked'
        _create_review_branch(gitdir, change_id, self._tracking_data(change_id))

        result = self._run_update(gitdir, change_id)

        assert result.get('checked_out') is None
        assert result.get('error') == 'Could not find series v1 in retrieved messages'


class TestAutoWakeSkipsCheckedOutBranch:
    """auto_wake_snoozed defers waking a checked-out review branch."""

    def _seed_snoozed(self, gitdir: str, identifier: str, change_id: str) -> str:
        tracking_data = {
            'series': {
                'identifier': identifier,
                'status': 'snoozed',
                'revision': 1,
                'change-id': change_id,
                'subject': 'Test',
                'fromname': 'Author',
                'fromemail': 'a@example.com',
                'expected': 1,
                'complete': True,
                'base-commit': 'abc123',
                'prerequisite-commits': [],
                'first-patch-commit': 'def456',
                'header-info': {},
                'link': '',
                'snoozed': {'previous_state': 'replied'},
            },
            'followups': [],
            'patches': [],
        }
        branch = _create_review_branch(gitdir, change_id, tracking_data)
        conn = review_tracking.init_db(identifier)
        review_tracking.add_series_to_db(
            conn,
            change_id,
            1,
            'Test',
            'Author',
            'a@example.com',
            '2026-07-01T00:00:00+00:00',
            'cover@example.com',
            1,
        )
        review_tracking.snooze_series(conn, change_id, '2020-01-01')
        conn.close()
        return branch

    def _status(self, identifier: str, change_id: str) -> str:
        conn = review_tracking.get_db(identifier)
        row = conn.execute(
            'SELECT status FROM series WHERE change_id = ?', (change_id,)
        ).fetchone()
        conn.close()
        return str(row[0])

    def test_wake_deferred_while_checked_out(self, gitdir: str) -> None:
        identifier = 'wake-co-test'
        change_id = 'wake-co'
        branch = self._seed_snoozed(gitdir, identifier, change_id)
        ecode, _ = b4.git_run_command(gitdir, ['checkout', branch])
        assert ecode == 0
        ecode, tip_before = b4.git_run_command(gitdir, ['rev-parse', branch])
        assert ecode == 0

        woken = review_tracking.auto_wake_snoozed(identifier, gitdir)

        assert woken == 0
        assert self._status(identifier, change_id) == 'snoozed'
        ecode, tip_after = b4.git_run_command(gitdir, ['rev-parse', branch])
        assert tip_after == tip_before

        # Once the maintainer moves away, the next sweep wakes it up.
        ecode, _ = b4.git_run_command(gitdir, ['checkout', 'master'])
        assert ecode == 0
        woken = review_tracking.auto_wake_snoozed(identifier, gitdir)
        assert woken == 1
        assert self._status(identifier, change_id) == 'replied'
