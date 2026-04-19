import argparse
import json
import os
from typing import Any, Dict, Optional, Tuple
from unittest.mock import patch

import pytest

import b4
import b4.mbox


class TestAmConflictError:
    """Tests for the AmConflictError exception class."""

    def test_stores_worktree_path_and_output(self) -> None:
        exc = b4.AmConflictError('/tmp/worktree', 'patch failed to apply')
        assert exc.worktree_path == '/tmp/worktree'
        assert exc.output == 'patch failed to apply'

    def test_inherits_from_runtime_error(self) -> None:
        exc = b4.AmConflictError('/tmp/wt', 'conflict')
        assert isinstance(exc, RuntimeError)

    def test_catchable_as_runtime_error(self) -> None:
        with pytest.raises(RuntimeError):
            raise b4.AmConflictError('/tmp/wt', 'conflict')

    def test_str_is_output(self) -> None:
        exc = b4.AmConflictError('/tmp/wt', 'the error output')
        assert str(exc) == 'the error output'

    def test_empty_output(self) -> None:
        exc = b4.AmConflictError('/tmp/wt', '')
        assert exc.output == ''
        assert exc.worktree_path == '/tmp/wt'


class TestRewriteFetchHeadOrigin:
    """Tests for the _rewrite_fetch_head_origin helper."""

    def test_rewrites_worktree_path(self, gitdir: str) -> None:
        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        with open(fh_path, 'w') as fh:
            fh.write("abc123\t\tnot-for-merge\tbranch 'master' of /tmp/b4-worktree\n")

        b4._rewrite_fetch_head_origin(gitdir, '/tmp/b4-worktree',
                                      'https://lore.kernel.org/r/test@msg')

        with open(fh_path, 'r') as fh:
            contents = fh.read()
        assert '/tmp/b4-worktree' not in contents
        assert 'patches from https://lore.kernel.org/r/test@msg' in contents

    def test_noop_when_old_origin_absent(self, gitdir: str) -> None:
        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        original = "abc123\t\tnot-for-merge\tbranch 'master' of /some/other/path\n"
        with open(fh_path, 'w') as fh:
            fh.write(original)

        b4._rewrite_fetch_head_origin(gitdir, '/tmp/nonexistent',
                                      'https://example.com')

        with open(fh_path, 'r') as fh:
            contents = fh.read()
        assert contents == original

    def test_rewrites_multiple_occurrences(self, gitdir: str) -> None:
        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        with open(fh_path, 'w') as fh:
            fh.write("aaa\t\tnot-for-merge\tbranch 'master' of /tmp/wt\n"
                     "bbb\t\tnot-for-merge\tbranch 'master' of /tmp/wt\n")

        b4._rewrite_fetch_head_origin(gitdir, '/tmp/wt', 'https://example.com')

        with open(fh_path, 'r') as fh:
            contents = fh.read()
        assert contents.count('patches from https://example.com') == 2
        assert '/tmp/wt' not in contents


def _build_clean_patches(gitdir: str) -> Tuple[bytes, str]:
    """Create 2 patches on a temp branch, return (mbox_bytes, base_commit).

    The patches are based on the current HEAD so they apply cleanly
    when at_base=base_commit.
    """
    ecode, base = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
    base = base.strip()

    # Create patches on a detached temp branch
    b4.git_run_command(gitdir, ['checkout', '-b', 'clean-patches'])
    with open(os.path.join(gitdir, 'file1.txt'), 'a') as fh:
        fh.write('Added by clean patch 1.\n')
    b4.git_run_command(gitdir, ['add', 'file1.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Clean patch 1'])

    with open(os.path.join(gitdir, 'file1.txt'), 'a') as fh:
        fh.write('Added by clean patch 2.\n')
    b4.git_run_command(gitdir, ['add', 'file1.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Clean patch 2'])

    ecode, mbox = b4.git_run_command(gitdir, ['format-patch', '-2', '--stdout'])
    assert ecode == 0

    # Return to master
    b4.git_run_command(gitdir, ['checkout', 'master'])
    b4.git_run_command(gitdir, ['branch', '-D', 'clean-patches'])

    return mbox.encode(), base


def _build_conflicting_patches(gitdir: str) -> Tuple[bytes, str]:
    """Create a patch that will conflict with a change on master.

    Both the patch and master rewrite all of file1.txt differently,
    so three-way merge detects a conflict.

    Returns (mbox_bytes, base_commit_before_master_modification).
    """
    ecode, base = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
    base = base.strip()

    # Create patch on a temp branch (from original HEAD)
    b4.git_run_command(gitdir, ['checkout', '-b', 'conflict-patch'])
    with open(os.path.join(gitdir, 'file1.txt'), 'w') as fh:
        fh.write('PATCH version of file 1.\n'
                 'Rewritten entirely by the patch.\n')
    b4.git_run_command(gitdir, ['add', 'file1.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Rewrite file1 (patch side)'])

    ecode, mbox = b4.git_run_command(gitdir, ['format-patch', '-1', '--stdout'])
    assert ecode == 0

    # Make a conflicting change on master (same lines, different content)
    b4.git_run_command(gitdir, ['checkout', 'master'])
    b4.git_run_command(gitdir, ['branch', '-D', 'conflict-patch'])
    with open(os.path.join(gitdir, 'file1.txt'), 'w') as fh:
        fh.write('MASTER version of file 1.\n'
                 'Also rewritten, but differently.\n')
    b4.git_run_command(gitdir, ['add', 'file1.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Rewrite file1 (master side)'])

    return mbox.encode(), base


class TestGitFetchAmIntoRepo:
    """Integration tests for git_fetch_am_into_repo with three-way merge."""

    def test_clean_apply_with_three_way(self, gitdir: str) -> None:
        """Patches apply cleanly with -3 flag, worktree is cleaned up."""
        ambytes, base = _build_clean_patches(gitdir)
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None
        gwt = os.path.join(common_dir, 'b4-shazam-worktree')

        b4.git_fetch_am_into_repo(gitdir, ambytes, at_base=base,
                                  am_flags=['-3'])

        # Worktree should be cleaned up after success
        assert not os.path.exists(gwt)

        # FETCH_HEAD should exist
        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        assert os.path.exists(fh_path)

    def test_clean_apply_with_origin_rewrites_fetch_head(self, gitdir: str) -> None:
        """When origin is provided, FETCH_HEAD is rewritten to show it."""
        ambytes, base = _build_clean_patches(gitdir)
        origin = 'https://lore.kernel.org/r/test@example.com'

        b4.git_fetch_am_into_repo(gitdir, ambytes, at_base=base,
                                  origin=origin, am_flags=['-3'])

        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        with open(fh_path, 'r') as fh:
            contents = fh.read()
        assert f'patches from {origin}' in contents

    def test_conflict_raises_am_conflict_error(self, gitdir: str) -> None:
        """AmConflictError is raised when patches conflict."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        try:
            with pytest.raises(b4.AmConflictError) as exc_info:
                b4.git_fetch_am_into_repo(gitdir, ambytes, at_base='HEAD',
                                          am_flags=['-3'])

            assert exc_info.value.worktree_path != ''
            assert exc_info.value.output != ''
        finally:
            # Clean up worktree
            common_dir = b4.git_get_common_dir(gitdir)
            if common_dir:
                gwt = os.path.join(common_dir, 'b4-shazam-worktree')
                if os.path.exists(gwt):
                    b4.git_run_command(gitdir, ['worktree', 'remove', '--force', gwt])

    def test_conflict_preserves_worktree(self, gitdir: str) -> None:
        """On conflict, the worktree is preserved for user resolution."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        try:
            with pytest.raises(b4.AmConflictError) as exc_info:
                b4.git_fetch_am_into_repo(gitdir, ambytes, at_base='HEAD',
                                          am_flags=['-3'])

            wt_path = exc_info.value.worktree_path
            # Worktree must still exist for user to resolve
            assert os.path.isdir(wt_path)
            # rebase-apply should be present (am still in progress)
            ecode, wt_gitdir = b4.git_run_command(
                wt_path, ['rev-parse', '--git-dir'],
                logstderr=True, rundir=wt_path)
            assert ecode == 0
            rebase_apply = os.path.join(wt_gitdir.strip(), 'rebase-apply')
            assert os.path.isdir(rebase_apply)
        finally:
            # Clean up worktree
            common_dir = b4.git_get_common_dir(gitdir)
            if common_dir:
                gwt = os.path.join(common_dir, 'b4-shazam-worktree')
                if os.path.exists(gwt):
                    b4.git_run_command(gitdir, ['worktree', 'remove', '--force', gwt])

    def test_clean_apply_without_three_way(self, gitdir: str) -> None:
        """Patches also apply cleanly without -3 (baseline)."""
        ambytes, base = _build_clean_patches(gitdir)

        b4.git_fetch_am_into_repo(gitdir, ambytes, at_base=base,
                                  am_flags=[])

        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        assert os.path.exists(fh_path)

    def test_check_only_with_three_way(self, gitdir: str) -> None:
        """check_only mode returns early without fetching, even with -3."""
        ambytes, base = _build_clean_patches(gitdir)

        # Remove any existing FETCH_HEAD
        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        if os.path.exists(fh_path):
            os.unlink(fh_path)

        b4.git_fetch_am_into_repo(gitdir, ambytes, at_base=base,
                                  check_only=True, am_flags=['-3'])

        # check_only should not fetch (no FETCH_HEAD created)
        assert not os.path.exists(fh_path)

        # Worktree should still be cleaned up
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None
        gwt = os.path.join(common_dir, 'b4-shazam-worktree')
        assert not os.path.exists(gwt)


class TestSuspendToShellCwd:
    """Test that _suspend_to_shell passes cwd to subprocess.run."""

    @patch('b4.tui._common.subprocess.run')
    def test_cwd_passed_through(self, mock_run: Any,
                                monkeypatch: pytest.MonkeyPatch) -> None:
        from b4.review_tui._common import _suspend_to_shell
        # Use a shell name that is neither bash nor zsh so we hit
        # the simple else branch (no tempfile/rcfile logic).
        monkeypatch.setenv('SHELL', '/tmp/fakeshell')

        _suspend_to_shell(cwd='/tmp/test-worktree')

        mock_run.assert_called_once()
        _args, kwargs = mock_run.call_args
        assert kwargs.get('cwd') == '/tmp/test-worktree'

    @patch('b4.tui._common.subprocess.run')
    def test_cwd_none_by_default(self, mock_run: Any,
                                 monkeypatch: pytest.MonkeyPatch) -> None:
        from b4.review_tui._common import _suspend_to_shell
        monkeypatch.setenv('SHELL', '/tmp/fakeshell')

        _suspend_to_shell()

        mock_run.assert_called_once()
        _args, kwargs = mock_run.call_args
        assert kwargs.get('cwd') is None

    @patch('b4.tui._common.subprocess.run')
    def test_hint_appears_in_env(self, mock_run: Any,
                                 monkeypatch: pytest.MonkeyPatch) -> None:
        from b4.review_tui._common import _suspend_to_shell
        monkeypatch.setenv('SHELL', '/tmp/fakeshell')

        _suspend_to_shell(hint='b4 conflict', cwd='/tmp/wt')

        mock_run.assert_called_once()
        _args, kwargs = mock_run.call_args
        assert kwargs['env']['B4_REVIEW'] == 'b4 conflict'


class TestConflictResolutionFlow:
    """Integration tests for the conflict resolution workflow.

    These exercise the same git operations that the TUI conflict
    handlers use (sparse-checkout disable, rebase-apply detection,
    fetch from worktree), without requiring the TUI itself.
    """

    def test_worktree_resolve_and_fetch(self, gitdir: str) -> None:
        """Full worktree flow: conflict -> resolve -> fetch succeeds."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        with pytest.raises(b4.AmConflictError) as exc_info:
            b4.git_fetch_am_into_repo(gitdir, ambytes, at_base='HEAD',
                                      am_flags=['-3'])

        wt = exc_info.value.worktree_path

        # --- same steps the TUI handler takes ---
        # 1. Disable sparse checkout so files are visible
        b4.git_run_command(wt, ['sparse-checkout', 'disable'],
                           logstderr=True, rundir=wt)
        assert os.path.exists(os.path.join(wt, 'file1.txt'))

        # 2. Simulate user resolving: accept theirs and continue
        b4.git_run_command(wt, ['checkout', '--theirs', '.'],
                           logstderr=True, rundir=wt)
        b4.git_run_command(wt, ['add', '-A'],
                           logstderr=True, rundir=wt)
        ecode, _out = b4.git_run_command(wt, ['am', '--continue'],
                                         logstderr=True, rundir=wt)
        assert ecode == 0

        # 3. Verify rebase-apply is gone (am completed)
        ecode, wt_gitdir = b4.git_run_command(
            wt, ['rev-parse', '--git-dir'],
            logstderr=True, rundir=wt)
        assert ecode == 0
        rebase_apply = os.path.join(wt_gitdir.strip(), 'rebase-apply')
        assert not os.path.isdir(rebase_apply)

        # 4. Fetch result into main repo
        ecode, _out = b4.git_run_command(gitdir, ['fetch', wt], logstderr=True)
        assert ecode == 0
        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        assert os.path.exists(fh_path)

        # 5. Clean up worktree
        b4.git_run_command(gitdir, ['worktree', 'remove', '--force', wt])
        assert not os.path.exists(wt)

    def test_worktree_unresolved_detected(self, gitdir: str) -> None:
        """When user doesn't resolve, rebase-apply is still present."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        with pytest.raises(b4.AmConflictError) as exc_info:
            b4.git_fetch_am_into_repo(gitdir, ambytes, at_base='HEAD',
                                      am_flags=['-3'])

        wt = exc_info.value.worktree_path

        # User returns from shell without resolving
        ecode, wt_gitdir = b4.git_run_command(
            wt, ['rev-parse', '--git-dir'],
            logstderr=True, rundir=wt)
        assert ecode == 0
        rebase_apply = os.path.join(wt_gitdir.strip(), 'rebase-apply')
        assert os.path.isdir(rebase_apply)

        # Handler cleans up the worktree
        b4.git_run_command(gitdir, ['worktree', 'remove', '--force', wt])
        assert not os.path.exists(wt)

    def test_sparse_checkout_disable_exposes_files(self, gitdir: str) -> None:
        """Disabling sparse checkout makes worktree files visible."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        with pytest.raises(b4.AmConflictError) as exc_info:
            b4.git_fetch_am_into_repo(gitdir, ambytes, at_base='HEAD',
                                      am_flags=['-3'])

        wt = exc_info.value.worktree_path

        # Before: sparse checkout may hide files
        # (the worktree was created with sparse-checkout set to empty)
        b4.git_run_command(wt, ['sparse-checkout', 'disable'],
                           logstderr=True, rundir=wt)

        # All repo files should now be visible
        assert os.path.exists(os.path.join(wt, 'file1.txt'))
        assert os.path.exists(os.path.join(wt, 'file2.txt'))
        assert os.path.exists(os.path.join(wt, 'lipsum.txt'))

        b4.git_run_command(gitdir, ['worktree', 'remove', '--force', wt])

    def test_fetch_head_origin_rewrite_after_resolve(self, gitdir: str) -> None:
        """After resolving and fetching, FETCH_HEAD origin is rewritten."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        with pytest.raises(b4.AmConflictError) as exc_info:
            b4.git_fetch_am_into_repo(gitdir, ambytes, at_base='HEAD',
                                      am_flags=['-3'])

        wt = exc_info.value.worktree_path

        # Resolve and fetch
        b4.git_run_command(wt, ['sparse-checkout', 'disable'],
                           logstderr=True, rundir=wt)
        b4.git_run_command(wt, ['checkout', '--theirs', '.'],
                           logstderr=True, rundir=wt)
        b4.git_run_command(wt, ['add', '-A'],
                           logstderr=True, rundir=wt)
        b4.git_run_command(wt, ['am', '--continue'],
                           logstderr=True, rundir=wt)
        b4.git_run_command(gitdir, ['fetch', wt], logstderr=True)

        # Rewrite FETCH_HEAD (as the TUI handler does)
        origin = 'https://lore.kernel.org/r/test@example.com'
        b4._rewrite_fetch_head_origin(gitdir, wt, origin)

        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        with open(fh_path, 'r') as fh:
            contents = fh.read()
        assert wt not in contents
        assert f'patches from {origin}' in contents

        b4.git_run_command(gitdir, ['worktree', 'remove', '--force', wt])


class TestDirectAmConflictFlow:
    """Integration tests for the direct git-am conflict path (_do_take_am).

    This path runs git-am directly on the user's working branch
    (not in a worktree), so resolution happens in-place.
    """

    def test_am_conflict_and_resolution(self, gitdir: str) -> None:
        """Direct git-am -3 conflict, resolved with --continue."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        # Run git-am directly (as _do_take_am does)
        ecode, _out = b4.git_run_command(gitdir, ['am', '-3'],
                                         stdin=ambytes, logstderr=True)
        assert ecode != 0

        # rebase-apply should exist
        rebase_apply = os.path.join(gitdir, '.git', 'rebase-apply')
        assert os.path.isdir(rebase_apply)

        # Resolve: accept theirs and continue
        b4.git_run_command(gitdir, ['checkout', '--theirs', '.'],
                           logstderr=True)
        b4.git_run_command(gitdir, ['add', '-A'], logstderr=True)
        ecode, _out = b4.git_run_command(gitdir, ['am', '--continue'],
                                         logstderr=True)
        assert ecode == 0
        assert not os.path.isdir(rebase_apply)

    def test_am_conflict_unresolved(self, gitdir: str) -> None:
        """Direct git-am -3 conflict, user aborts."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        ecode, _out = b4.git_run_command(gitdir, ['am', '-3'],
                                         stdin=ambytes, logstderr=True)
        assert ecode != 0

        # rebase-apply is present (handler detects this)
        rebase_apply = os.path.join(gitdir, '.git', 'rebase-apply')
        assert os.path.isdir(rebase_apply)

        # Abort (as user would after incomplete resolution)
        b4.git_run_command(gitdir, ['am', '--abort'], logstderr=True)
        assert not os.path.isdir(rebase_apply)


# ---------------------------------------------------------------------------
# Tier 4 — Shazam state machine tests
# ---------------------------------------------------------------------------

def _build_multi_patch_conflict(gitdir: str) -> Tuple[bytes, str]:
    """Create a 3-patch mbox where patches 1-2 are clean but patch 3 conflicts.

    Patches 1-2 modify file2.txt and lipsum.txt (no conflict with master).
    Patch 3 rewrites file1.txt (conflicts with master's rewrite).

    Returns (mbox_bytes, original_base_commit).
    """
    ecode, base = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
    base = base.strip()

    # Create 3 patches on a temp branch
    b4.git_run_command(gitdir, ['checkout', '-b', 'multi-patch'])

    # Patch 1: modify file2.txt (clean)
    with open(os.path.join(gitdir, 'file2.txt'), 'a') as fh:
        fh.write('Added by patch 1.\n')
    b4.git_run_command(gitdir, ['add', 'file2.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Patch 1: modify file2'])

    # Patch 2: modify lipsum.txt (clean)
    with open(os.path.join(gitdir, 'lipsum.txt'), 'a') as fh:
        fh.write('\nExtra paragraph from patch 2.\n')
    b4.git_run_command(gitdir, ['add', 'lipsum.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Patch 2: modify lipsum'])

    # Patch 3: rewrite file1.txt (will conflict with master)
    with open(os.path.join(gitdir, 'file1.txt'), 'w') as fh:
        fh.write('PATCH version of file1.\nRewritten by patch 3.\n')
    b4.git_run_command(gitdir, ['add', 'file1.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Patch 3: rewrite file1'])

    ecode, mbox = b4.git_run_command(gitdir, ['format-patch', '-3', '--stdout'])
    assert ecode == 0

    # Back to master, make a conflicting change to file1.txt only
    b4.git_run_command(gitdir, ['checkout', 'master'])
    b4.git_run_command(gitdir, ['branch', '-D', 'multi-patch'])
    with open(os.path.join(gitdir, 'file1.txt'), 'w') as fh:
        fh.write('MASTER version of file1.\nConflicting rewrite.\n')
    b4.git_run_command(gitdir, ['add', 'file1.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Master: rewrite file1'])

    return mbox.encode(), base


def _make_shazam_state(common_dir: str,
                       state: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
    """Create shazam state file and patches dir.

    Returns (state_file_path, patches_dir_path).
    """
    state_file = os.path.join(common_dir, 'b4-shazam-state.json')
    patches_dir = os.path.join(common_dir, 'b4-shazam-patches')
    os.makedirs(patches_dir, exist_ok=True)
    if state is None:
        state = {'origin': 'https://example.com', 'merge_flags': '--signoff'}
    with open(state_file, 'w') as fh:
        json.dump(state, fh)
    return state_file, patches_dir


class TestLoadShazamState:
    """Tests for _load_shazam_state."""

    def test_valid_state_loaded(self, gitdir: str) -> None:
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None
        state_file, patches_dir = _make_shazam_state(common_dir)
        try:
            _topdir, _cdir, sf, loaded = b4.mbox._load_shazam_state(
                require_state=True)
            assert loaded == {'origin': 'https://example.com',
                              'merge_flags': '--signoff'}
            assert sf == state_file
        finally:
            os.unlink(state_file)
            os.rmdir(patches_dir)

    def test_missing_state_exits(self, gitdir: str) -> None:
        with pytest.raises(SystemExit) as exc_info:
            b4.mbox._load_shazam_state(require_state=True)
        assert exc_info.value.code == 1

    def test_optional_state_returns_none(self, gitdir: str) -> None:
        _topdir, _cdir, _sf, loaded = b4.mbox._load_shazam_state(
            require_state=False)
        assert loaded is None

    def test_missing_patches_dir_exits(self, gitdir: str) -> None:
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None
        # Create state file but NOT the patches dir
        state_file = os.path.join(common_dir, 'b4-shazam-state.json')
        with open(state_file, 'w') as fh:
            json.dump({'origin': 'test'}, fh)
        try:
            with pytest.raises(SystemExit) as exc_info:
                b4.mbox._load_shazam_state(require_state=True)
            assert exc_info.value.code == 1
        finally:
            if os.path.exists(state_file):
                os.unlink(state_file)


class TestShazamAbort:
    """Tests for shazam_abort cleanup."""

    def test_cleans_up_all_artifacts(self, gitdir: str) -> None:
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None

        state_file, patches_dir = _make_shazam_state(common_dir)
        # Add a fake patch file
        with open(os.path.join(patches_dir, '0000'), 'w') as fh:
            fh.write('patch data')

        cmdargs = argparse.Namespace()
        b4.mbox.shazam_abort(cmdargs)

        assert not os.path.exists(patches_dir)
        assert not os.path.exists(state_file)

    def test_cleans_up_stale_worktree(self, gitdir: str) -> None:
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None

        state_file, patches_dir = _make_shazam_state(common_dir)

        # Create a stale worktree
        gwt = os.path.join(common_dir, 'b4-shazam-worktree')
        b4.git_run_command(gitdir, ['worktree', 'add', '--detach', gwt, 'HEAD'])
        assert os.path.isdir(gwt)

        cmdargs = argparse.Namespace()
        b4.mbox.shazam_abort(cmdargs)

        assert not os.path.exists(gwt)
        assert not os.path.exists(patches_dir)
        assert not os.path.exists(state_file)

    def test_noop_when_nothing_to_clean(self, gitdir: str) -> None:
        cmdargs = argparse.Namespace()
        # Should not raise
        b4.mbox.shazam_abort(cmdargs)


class TestStartMergeResolve:
    """Integration tests for _start_merge_resolve.

    This function extracts remaining patches from a failed git-am
    worktree, fetches successfully-applied patches, starts a merge,
    and applies remaining patches one-by-one.
    """

    def test_creates_state_and_patches(self, gitdir: str) -> None:
        """After a multi-patch conflict, state files are created."""
        ambytes, _base = _build_multi_patch_conflict(gitdir)
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None

        with pytest.raises(b4.AmConflictError) as exc_info:
            b4.git_fetch_am_into_repo(gitdir, ambytes, at_base='HEAD',
                                      am_flags=['-3'])

        state = {
            'origin': 'https://example.com',
            'merge_template_values': {},
            'merge_template': 'Test merge\n\nConflict resolution test.',
            'merge_flags': '--signoff',
            'no_interactive': True,
        }

        # _start_merge_resolve exits(1) because remaining patch 3 conflicts
        with pytest.raises(SystemExit) as exit_info:
            b4.mbox._start_merge_resolve(
                gitdir, exc_info.value, common_dir, state)
        assert exit_info.value.code == 1

        # State file and patches dir should exist
        state_file = os.path.join(common_dir, 'b4-shazam-state.json')
        patches_dir = os.path.join(common_dir, 'b4-shazam-patches')
        assert os.path.exists(state_file)
        assert os.path.isdir(patches_dir)

        # One remaining patch was extracted (patch 3)
        with open(os.path.join(patches_dir, 'total'), 'r') as fh:
            assert fh.read().strip() == '1'

        # Worktree should be removed
        gwt = os.path.join(common_dir, 'b4-shazam-worktree')
        assert not os.path.exists(gwt)

        # Clean up for fixture teardown
        b4.git_run_command(gitdir, ['merge', '--abort'], logstderr=True)

    def test_full_resolve_continue_flow(self, gitdir: str) -> None:
        """Full flow: conflict -> resolve -> shazam --continue -> merge commit."""
        ambytes, _base = _build_multi_patch_conflict(gitdir)
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None

        # Step 1: trigger conflict
        with pytest.raises(b4.AmConflictError) as exc_info:
            b4.git_fetch_am_into_repo(gitdir, ambytes, at_base='HEAD',
                                      am_flags=['-3'])

        state = {
            'origin': 'https://example.com',
            'merge_template_values': {},
            'merge_template': 'Test merge\n\nResolved conflict.',
            'merge_flags': '--signoff',
            'no_interactive': True,
        }

        # Step 2: _start_merge_resolve extracts patches, starts merge,
        # applies remaining patch 3 which conflicts -> exit(1)
        with pytest.raises(SystemExit):
            b4.mbox._start_merge_resolve(
                gitdir, exc_info.value, common_dir, state)

        # Step 3: resolve the conflict (accept any content)
        with open(os.path.join(gitdir, 'file1.txt'), 'w') as fh:
            fh.write('Resolved content for file1.\n')
        b4.git_run_command(gitdir, ['add', 'file1.txt'])

        # Step 4: shazam --continue
        cmdargs = argparse.Namespace()
        # Should complete successfully (no SystemExit)
        b4.mbox.shazam_continue(cmdargs)

        # Step 5: verify merge commit was created
        ecode, _log_out = b4.git_run_command(
            gitdir, ['log', '--oneline', '-1', '--format=%s'])
        assert ecode == 0
        # The commit was made with -F (the merge template content)
        # Just verify a commit exists on top of our branch
        ecode, parents = b4.git_run_command(
            gitdir, ['rev-list', '--parents', '-1', 'HEAD'])
        assert ecode == 0
        # Merge commit has 2 parents
        parent_list = parents.strip().split()
        assert len(parent_list) == 3  # commit_hash parent1 parent2

        # State files should be cleaned up
        state_file = os.path.join(common_dir, 'b4-shazam-state.json')
        patches_dir = os.path.join(common_dir, 'b4-shazam-patches')
        assert not os.path.exists(state_file)
        assert not os.path.exists(patches_dir)

    def test_abort_after_conflict(self, gitdir: str) -> None:
        """After conflict, shazam --abort cleans everything up."""
        ambytes, _base = _build_multi_patch_conflict(gitdir)
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None

        with pytest.raises(b4.AmConflictError) as exc_info:
            b4.git_fetch_am_into_repo(gitdir, ambytes, at_base='HEAD',
                                      am_flags=['-3'])

        state = {
            'origin': 'https://example.com',
            'merge_template_values': {},
            'merge_template': 'Test merge',
            'merge_flags': '--signoff',
            'no_interactive': True,
        }

        with pytest.raises(SystemExit):
            b4.mbox._start_merge_resolve(
                gitdir, exc_info.value, common_dir, state)

        # Abort instead of resolving
        cmdargs = argparse.Namespace()
        b4.mbox.shazam_abort(cmdargs)

        # Everything should be cleaned up
        state_file = os.path.join(common_dir, 'b4-shazam-state.json')
        patches_dir = os.path.join(common_dir, 'b4-shazam-patches')
        assert not os.path.exists(state_file)
        assert not os.path.exists(patches_dir)

        # Merge should be aborted (no MERGE_HEAD)
        merge_head = os.path.join(gitdir, '.git', 'MERGE_HEAD')
        assert not os.path.exists(merge_head)
