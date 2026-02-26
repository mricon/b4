import argparse
import datetime
import os
from unittest import mock

import pytest

from b4.review import tracking as review_tracking


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
            num_patches=3
        )

        assert track_id == 1
        cursor = conn.execute('SELECT track_id, change_id, subject FROM series WHERE change_id = ?',
                              ('test-change-id',))
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == track_id
        assert row[2] == 'Test series subject'
        conn.close()

    def test_add_series_with_pw_series_id(self, tmp_path: pytest.TempPathFactory) -> None:
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
            pw_series_id=12345
        )

        cursor = conn.execute('SELECT pw_series_id FROM series WHERE track_id = ?', (track_id,))
        row = cursor.fetchone()
        assert row[0] == 12345
        conn.close()

    def test_add_series_multiple_revisions(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify multiple revisions can be tracked for the same change-id."""
        conn = review_tracking.init_db('multi-rev-test')

        # Add v1
        track_id_v1 = review_tracking.add_series_to_db(
            conn, 'change-123', 1, 'Subject v1', 'Author', 'a@example.com',
            '2024-01-15T10:00:00+00:00', 'msgid-v1@example.com', 3
        )
        # Add v2
        track_id_v2 = review_tracking.add_series_to_db(
            conn, 'change-123', 2, 'Subject v2', 'Author', 'a@example.com',
            '2024-01-16T10:00:00+00:00', 'msgid-v2@example.com', 4
        )

        # Different track_ids
        assert track_id_v1 != track_id_v2

        cursor = conn.execute(
            'SELECT track_id, revision, num_patches FROM series WHERE change_id = ? ORDER BY revision',
            ('change-123',)
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
            conn, 'change-456', 1, 'Subject', 'Author', 'a@example.com',
            '2024-01-15T10:00:00+00:00', 'msgid-old@example.com', 3
        )
        track_id_2 = review_tracking.add_series_to_db(
            conn, 'change-456', 1, 'Subject', 'Author', 'a@example.com',
            '2024-01-15T10:00:00+00:00', 'msgid-new@example.com', 5
        )

        # Same track_id after upsert
        assert track_id_1 == track_id_2

        cursor = conn.execute(
            'SELECT track_id, message_id, num_patches FROM series WHERE change_id = ? AND revision = ?',
            ('change-456', 1)
        )
        row = cursor.fetchone()
        assert row == (track_id_1, 'msgid-new@example.com', 5)
        conn.close()

    def test_get_tracked_pw_series_ids(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify get_tracked_pw_series_ids returns correct IDs."""
        conn = review_tracking.init_db('pw-ids-test')
        # Add series with pw_series_id
        review_tracking.add_series_to_db(
            conn, 'change-1', 1, 'Subject 1', 'Author', 'a@example.com',
            '2024-01-15T10:00:00+00:00', 'msgid@example.com', 3,
            pw_series_id=100
        )
        review_tracking.add_series_to_db(
            conn, 'change-2', 1, 'Subject 2', 'Author', 'a@example.com',
            '2024-01-15T10:00:00+00:00', 'msgid@example.com', 3,
            pw_series_id=200
        )
        # Add series without pw_series_id
        review_tracking.add_series_to_db(
            conn, 'change-3', 1, 'Subject 3', 'Author', 'a@example.com',
            '2024-01-15T10:00:00+00:00', 'msgid@example.com', 3
        )
        conn.close()

        ids = review_tracking.get_tracked_pw_series_ids('pw-ids-test')
        assert ids == {100, 200}

    def test_get_tracked_pw_series_ids_nonexistent_db(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify get_tracked_pw_series_ids returns empty set for missing db."""
        ids = review_tracking.get_tracked_pw_series_ids('nonexistent-project')
        assert ids == set()

    def test_is_pw_series_tracked(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify is_pw_series_tracked works correctly."""
        conn = review_tracking.init_db('is-tracked-test')
        review_tracking.add_series_to_db(
            conn, 'change-1', 1, 'Subject', 'Author', 'a@example.com',
            '2024-01-15T10:00:00+00:00', 'msgid@example.com', 3,
            pw_series_id=12345
        )
        conn.close()

        assert review_tracking.is_pw_series_tracked('is-tracked-test', 12345) is True
        assert review_tracking.is_pw_series_tracked('is-tracked-test', 99999) is False

    def test_is_pw_series_tracked_nonexistent_db(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify is_pw_series_tracked returns False for missing db."""
        assert review_tracking.is_pw_series_tracked('nonexistent', 12345) is False

    def test_get_all_tracked_series(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify get_all_tracked_series returns all series with correct fields."""
        conn = review_tracking.init_db('all-series-test')
        review_tracking.add_series_to_db(
            conn, 'change-1', 1, 'First series', 'Author One', 'one@example.com',
            '2024-01-15T10:00:00+00:00', 'msgid-1@example.com', 3
        )
        review_tracking.add_series_to_db(
            conn, 'change-2', 2, 'Second series', 'Author Two', 'two@example.com',
            '2024-01-16T10:00:00+00:00', 'msgid-2@example.com', 5
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

    def test_get_all_tracked_series_nonexistent_db(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify get_all_tracked_series returns empty list for missing db."""
        result = review_tracking.get_all_tracked_series('nonexistent-project')
        assert result == []


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

    def test_get_repo_identifier_returns_none_for_worktree(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify get_repo_identifier returns None for worktrees."""
        # Simulate a worktree by making .git a file instead of directory
        worktree_dir = os.path.join(str(tmp_path), 'worktree')
        os.makedirs(worktree_dir)
        git_file = os.path.join(worktree_dir, '.git')
        with open(git_file, 'w') as f:
            f.write('gitdir: /some/path/.git/worktrees/name\n')

        identifier = review_tracking.get_repo_identifier(worktree_dir)
        assert identifier is None


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

    def test_returns_none_when_no_identifier(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify returns None when no identifier available."""
        cmdargs = argparse.Namespace(identifier=None)
        # Pass a non-git directory
        result = review_tracking.resolve_identifier(cmdargs, str(tmp_path))
        assert result is None


class TestCmdEnroll:
    """Tests for cmd_enroll()."""

    def test_enroll_creates_database(self, gitdir: str) -> None:
        """Verify enroll creates the database."""
        cmdargs = argparse.Namespace(
            repo_path=gitdir,
            identifier='enroll-test'
        )
        review_tracking.cmd_enroll(cmdargs)

        assert review_tracking.db_exists('enroll-test')

    def test_enroll_creates_metadata_file(self, gitdir: str) -> None:
        """Verify enroll creates metadata file in .git directory."""
        cmdargs = argparse.Namespace(
            repo_path=gitdir,
            identifier='metadata-test'
        )
        review_tracking.cmd_enroll(cmdargs)

        metadata_path = os.path.join(gitdir, '.git', 'b4-review', 'metadata.json')
        assert os.path.exists(metadata_path)

    def test_enroll_uses_dirname_as_default_identifier(self, gitdir: str) -> None:
        """Verify enroll uses directory name as default identifier."""
        cmdargs = argparse.Namespace(
            repo_path=gitdir,
            identifier=None
        )
        review_tracking.cmd_enroll(cmdargs)

        dirname = os.path.basename(gitdir)
        assert review_tracking.db_exists(dirname)

    def test_enroll_uses_current_directory_when_no_path(self, gitdir: str) -> None:
        """Verify enroll uses current directory when no path specified."""
        # gitdir fixture already changes cwd to the test repo
        cmdargs = argparse.Namespace(
            repo_path=None,
            identifier='current-dir-test'
        )
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
            cmdargs = argparse.Namespace(
                repo_path=None,
                identifier='test'
            )
            with pytest.raises(SystemExit) as exc_info:
                review_tracking.cmd_enroll(cmdargs)
            assert exc_info.value.code == 1
        finally:
            os.chdir(oldcwd)

    def test_enroll_fails_for_nonexistent_path(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify enroll fails for non-existent paths."""
        cmdargs = argparse.Namespace(
            repo_path='/nonexistent/path',
            identifier='test'
        )
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_enroll(cmdargs)
        assert exc_info.value.code == 1

    def test_enroll_fails_for_non_git_directory(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify enroll fails for non-git directories."""
        non_git_dir = os.path.join(str(tmp_path), 'not-a-repo')
        os.makedirs(non_git_dir)

        cmdargs = argparse.Namespace(
            repo_path=non_git_dir,
            identifier='test'
        )
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_enroll(cmdargs)
        assert exc_info.value.code == 1

    def test_enroll_fails_when_repo_already_enrolled(self, gitdir: str) -> None:
        """Verify enroll fails when repository already has metadata."""
        # First enrollment
        cmdargs = argparse.Namespace(
            repo_path=gitdir,
            identifier='first-id'
        )
        review_tracking.cmd_enroll(cmdargs)

        # Second enrollment of same repo should fail
        cmdargs2 = argparse.Namespace(
            repo_path=gitdir,
            identifier='second-id'
        )
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_enroll(cmdargs2)
        assert exc_info.value.code == 1

    @mock.patch('builtins.input', return_value='y')
    def test_enroll_reuses_existing_db_when_confirmed(
        self, mock_input: mock.Mock, gitdir: str, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify enroll can reuse existing database for different repo."""
        # Create database via first enrollment
        cmdargs = argparse.Namespace(
            repo_path=gitdir,
            identifier='shared-db'
        )
        review_tracking.cmd_enroll(cmdargs)

        # Create a second git repo
        second_repo = os.path.join(str(tmp_path), 'second-repo')
        os.makedirs(second_repo)
        os.makedirs(os.path.join(second_repo, '.git'))

        # Enroll second repo with same identifier - user confirms
        cmdargs2 = argparse.Namespace(
            repo_path=second_repo,
            identifier='shared-db'
        )
        review_tracking.cmd_enroll(cmdargs2)

        # Metadata file should exist in second repo
        metadata_path = os.path.join(second_repo, '.git', 'b4-review', 'metadata.json')
        assert os.path.exists(metadata_path)
        mock_input.assert_called_once()

    @mock.patch('builtins.input', return_value='n')
    def test_enroll_aborts_when_existing_db_declined(
        self, mock_input: mock.Mock, gitdir: str, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify enroll aborts when user declines to use existing database."""
        # Create database via first enrollment
        cmdargs = argparse.Namespace(
            repo_path=gitdir,
            identifier='declined-db'
        )
        review_tracking.cmd_enroll(cmdargs)

        # Create a second git repo
        second_repo = os.path.join(str(tmp_path), 'second-repo')
        os.makedirs(second_repo)
        os.makedirs(os.path.join(second_repo, '.git'))

        # Enroll second repo with same identifier - user declines
        cmdargs2 = argparse.Namespace(
            repo_path=second_repo,
            identifier='declined-db'
        )
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_enroll(cmdargs2)
        # Exit code 0 for user-initiated cancellation
        assert exc_info.value.code == 0

        # Metadata file should NOT exist in second repo
        metadata_path = os.path.join(second_repo, '.git', 'b4-review', 'metadata.json')
        assert not os.path.exists(metadata_path)

    def test_enroll_worktree_no_metadata_file(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify enroll doesn't create metadata file for worktrees."""
        # Create a fake worktree (directory with .git as a file)
        worktree_dir = os.path.join(str(tmp_path), 'worktree')
        os.makedirs(worktree_dir)
        git_file = os.path.join(worktree_dir, '.git')
        with open(git_file, 'w') as f:
            f.write('gitdir: /some/path/.git/worktrees/name\n')

        cmdargs = argparse.Namespace(
            repo_path=worktree_dir,
            identifier='worktree-test'
        )
        review_tracking.cmd_enroll(cmdargs)

        # Database should be created
        assert review_tracking.db_exists('worktree-test')
        # But no metadata directory should exist
        metadata_dir = os.path.join(worktree_dir, '.git', 'b4-review')
        assert not os.path.exists(metadata_dir)


class TestCmdTrack:
    """Tests for cmd_track()."""

    def _make_mock_lore_message(
        self,
        msgid: str = 'test-msgid@example.com',
        fromname: str = 'Test Author',
        fromemail: str = 'author@example.com',
        date: datetime.datetime = datetime.datetime(2024, 1, 15, 10, 0, 0, tzinfo=datetime.timezone.utc)
    ) -> mock.Mock:
        """Create a mock LoreMessage."""
        lmsg = mock.Mock()
        lmsg.msgid = msgid
        lmsg.fromname = fromname
        lmsg.fromemail = fromemail
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
        subject: str = 'Test series'
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
        lser.patches = [cover, patch1, None, None]  # Cover + 3 patches (2 missing)

        return lser

    @mock.patch('b4.retrieve_messages')
    @mock.patch('b4.LoreMailbox')
    def test_track_with_change_id(
        self,
        mock_mailbox_class: mock.Mock,
        mock_retrieve: mock.Mock,
        gitdir: str
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
            wantver=None
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
        self,
        mock_mailbox_class: mock.Mock,
        mock_retrieve: mock.Mock,
        gitdir: str
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
            wantver=None
        )
        review_tracking.cmd_track(cmdargs)

        conn = review_tracking.get_db('noid-test')
        cursor = conn.execute('SELECT change_id FROM series')
        row = cursor.fetchone()
        # Format: YYYYMMDD-slug-fingerprint[:12]
        change_id = row['change_id']
        assert change_id.startswith('20240115-')
        assert 'test-series' in change_id
        conn.close()

    @mock.patch('b4.retrieve_messages')
    @mock.patch('b4.LoreMailbox')
    def test_track_uses_first_patch_without_cover(
        self,
        mock_mailbox_class: mock.Mock,
        mock_retrieve: mock.Mock,
        gitdir: str
    ) -> None:
        """Verify tracking uses first patch msgid when no cover letter."""
        cmdargs_enroll = argparse.Namespace(repo_path=gitdir, identifier='no-cover-test')
        review_tracking.cmd_enroll(cmdargs_enroll)

        mock_msg = mock.Mock()
        mock_retrieve.return_value = ('test-msgid', [mock_msg])

        mock_lser = self._make_mock_lore_series(
            has_cover=False,
            first_patch_msgid='first-patch@example.com'
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
            wantver=None
        )
        review_tracking.cmd_track(cmdargs)

        conn = review_tracking.get_db('no-cover-test')
        cursor = conn.execute('SELECT message_id FROM series')
        row = cursor.fetchone()
        assert row['message_id'] == 'first-patch@example.com'
        conn.close()

    @mock.patch('b4.retrieve_messages')
    def test_track_fails_without_identifier(
        self,
        mock_retrieve: mock.Mock,
        tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify track fails when no identifier can be resolved."""
        cmdargs = argparse.Namespace(
            series_id='test-msgid@example.com',
            identifier=None,
            msgid=None,
            noparent=False,
            wantname=None,
            wantver=None
        )
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_track(cmdargs)
        assert exc_info.value.code == 1

    @mock.patch('b4.retrieve_messages')
    def test_track_fails_for_unenrolled_project(
        self,
        mock_retrieve: mock.Mock,
        tmp_path: pytest.TempPathFactory
    ) -> None:
        """Verify track fails when project is not enrolled."""
        cmdargs = argparse.Namespace(
            series_id='test-msgid@example.com',
            identifier='not-enrolled',
            msgid=None,
            noparent=False,
            wantname=None,
            wantver=None
        )
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_track(cmdargs)
        assert exc_info.value.code == 1

    @mock.patch('b4.retrieve_messages')
    def test_track_fails_when_retrieval_fails(
        self,
        mock_retrieve: mock.Mock,
        gitdir: str
    ) -> None:
        """Verify track fails when series retrieval fails."""
        cmdargs_enroll = argparse.Namespace(repo_path=gitdir, identifier='retrieval-fail')
        review_tracking.cmd_enroll(cmdargs_enroll)

        mock_retrieve.return_value = (None, None)

        cmdargs = argparse.Namespace(
            series_id='test-msgid@example.com',
            identifier='retrieval-fail',
            msgid=None,
            noparent=False,
            wantname=None,
            wantver=None
        )
        with pytest.raises(SystemExit) as exc_info:
            review_tracking.cmd_track(cmdargs)
        assert exc_info.value.code == 1


class TestRevisions:
    """Tests for revision tracking helpers."""

    def test_add_revision(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify a revision can be added and retrieved."""
        conn = review_tracking.init_db('rev-add-test')
        review_tracking.add_revision(conn, 'change-abc', 1, 'msgid-v1@example.com',
                                     subject='Test v1', link='https://lore.kernel.org/r/msgid-v1')
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

    def test_get_newest_revision_empty(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify get_newest_revision returns None when no revisions exist."""
        conn = review_tracking.init_db('rev-empty-test')
        assert review_tracking.get_newest_revision(conn, 'nonexistent') is None
        conn.close()

    def test_delete_series(self, tmp_path: pytest.TempPathFactory) -> None:
        """Verify delete_series removes series and revisions for a change_id."""
        conn = review_tracking.init_db('del-series-test')
        # Add a series with revisions
        review_tracking.add_series_to_db(
            conn, 'change-del', 1, 'Subject', 'Author', 'a@example.com',
            '2024-01-15T10:00:00+00:00', 'msgid@example.com', 3)
        review_tracking.add_revision(conn, 'change-del', 1, 'msgid-v1@example.com')
        review_tracking.add_revision(conn, 'change-del', 2, 'msgid-v2@example.com')
        # Add another series that should not be affected
        review_tracking.add_series_to_db(
            conn, 'change-keep', 1, 'Keep', 'Author', 'a@example.com',
            '2024-01-15T10:00:00+00:00', 'keep@example.com', 1)
        review_tracking.add_revision(conn, 'change-keep', 1, 'keep-v1@example.com')

        review_tracking.delete_series(conn, 'change-del')

        # Deleted change_id should be gone from both tables
        cursor = conn.execute('SELECT * FROM series WHERE change_id = ?',
                              ('change-del',))
        assert cursor.fetchone() is None
        assert review_tracking.get_revisions(conn, 'change-del') == []

        # Other change_id should be untouched
        cursor = conn.execute('SELECT * FROM series WHERE change_id = ?',
                              ('change-keep',))
        assert cursor.fetchone() is not None
        assert len(review_tracking.get_revisions(conn, 'change-keep')) == 1
        conn.close()

class TestUpdateSeriesStatus:
    """Tests for update_series_status()."""

    def test_updates_existing_series(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('status-update-test')
        review_tracking.add_series_to_db(
            conn, 'change-status', 1, 'Subject', 'Author', 'a@example.com',
            '2024-01-15T10:00:00+00:00', 'msgid@example.com', 3)

        review_tracking.update_series_status(conn, 'change-status', 'reviewing')

        cursor = conn.execute(
            'SELECT status FROM series WHERE change_id = ?', ('change-status',))
        assert cursor.fetchone()[0] == 'reviewing'
        conn.close()

    def test_noop_for_nonexistent_change_id(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = review_tracking.init_db('status-noop-test')
        # Should not raise
        review_tracking.update_series_status(conn, 'nonexistent', 'reviewing')
        conn.close()
