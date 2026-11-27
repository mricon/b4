import os
import shutil
import subprocess
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from unittest.mock import patch

import pytest

import b4
import b4.mbox


@pytest.fixture
def applied_log(gitdir: str, tmp_path: Path) -> Path:
    """Install a post-applypatch hook that logs each applied patch's subject.

    Returns the log file, which does not exist until the hook runs once.
    """
    hooksdir = tmp_path / 'hooks'
    hooksdir.mkdir()
    log = tmp_path / 'applied.log'
    hook = hooksdir / 'post-applypatch'
    hook.write_text(f'#!/bin/sh\ngit log -1 --format=%s >> "{log}"\n')
    hook.chmod(0o755)
    b4.git_set_config(gitdir, 'core.hooksPath', str(hooksdir))
    return log


class TestAmConflictError:
    """Tests for the AmConflictError exception class."""

    @pytest.mark.parametrize(
        'output',
        [
            pytest.param('patch failed to apply', id='stores-worktree-path-and-output'),
            pytest.param('', id='empty-output'),
        ],
    )
    def test_stores_worktree_path_and_output(self, output: str) -> None:
        exc = b4.AmConflictError('/tmp/worktree', output)
        assert exc.worktree_path == '/tmp/worktree'
        assert exc.output == output

    def test_inherits_from_runtime_error(self) -> None:
        exc = b4.AmConflictError('/tmp/wt', 'conflict')
        assert isinstance(exc, RuntimeError)

    def test_str_is_output(self) -> None:
        exc = b4.AmConflictError('/tmp/wt', 'the error output')
        assert str(exc) == 'the error output'


class TestRewriteFetchHeadOrigin:
    """Tests for the _rewrite_fetch_head_origin helper."""

    def test_noop_when_old_origin_absent(self, gitdir: str) -> None:
        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        original = "abc123\t\tnot-for-merge\tbranch 'master' of /some/other/path\n"
        with open(fh_path, 'w') as fh:
            fh.write(original)

        b4._rewrite_fetch_head_origin(gitdir, '/tmp/nonexistent', 'https://example.com')

        with open(fh_path, 'r') as fh:
            contents = fh.read()
        assert contents == original

    def test_rewrites_multiple_occurrences(self, gitdir: str) -> None:
        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        with open(fh_path, 'w') as fh:
            fh.write(
                "aaa\t\tnot-for-merge\tbranch 'master' of /tmp/wt\n"
                "bbb\t\tnot-for-merge\tbranch 'master' of /tmp/wt\n"
            )

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
        fh.write('PATCH version of file 1.\nRewritten entirely by the patch.\n')
    b4.git_run_command(gitdir, ['add', 'file1.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Rewrite file1 (patch side)'])

    ecode, mbox = b4.git_run_command(gitdir, ['format-patch', '-1', '--stdout'])
    assert ecode == 0

    # Make a conflicting change on master (same lines, different content)
    b4.git_run_command(gitdir, ['checkout', 'master'])
    b4.git_run_command(gitdir, ['branch', '-D', 'conflict-patch'])
    with open(os.path.join(gitdir, 'file1.txt'), 'w') as fh:
        fh.write('MASTER version of file 1.\nAlso rewritten, but differently.\n')
    b4.git_run_command(gitdir, ['add', 'file1.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Rewrite file1 (master side)'])

    return mbox.encode(), base


class TestGitFetchAmIntoRepo:
    """Integration tests for git_fetch_am_into_repo with three-way merge."""

    @pytest.mark.parametrize(
        'am_flags',
        [
            pytest.param(['-3'], id='with-three-way'),
            # The baseline: the patches also apply cleanly without -3.
            pytest.param([], id='without-three-way'),
        ],
    )
    def test_clean_apply(self, gitdir: str, am_flags: List[str]) -> None:
        """Patches apply cleanly, with or without -3; worktree is cleaned up."""
        ambytes, base = _build_clean_patches(gitdir)
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None
        gwt = os.path.join(common_dir, 'b4-shazam-worktree')

        b4.git_fetch_am_into_repo(gitdir, ambytes, at_base=base, am_flags=am_flags)

        # Worktree should be cleaned up after success
        assert not os.path.exists(gwt)

        # FETCH_HEAD should exist
        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        assert os.path.exists(fh_path)

    def test_clean_apply_with_origin_rewrites_fetch_head(self, gitdir: str) -> None:
        """When origin is provided, FETCH_HEAD is rewritten to show it."""
        ambytes, base = _build_clean_patches(gitdir)
        origin = 'https://lore.kernel.org/r/test@example.com'

        b4.git_fetch_am_into_repo(
            gitdir, ambytes, at_base=base, origin=origin, am_flags=['-3']
        )

        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        with open(fh_path, 'r') as fh:
            contents = fh.read()
        assert f'patches from {origin}' in contents

    def test_conflict_raises_am_conflict_error(self, gitdir: str) -> None:
        """AmConflictError is raised when patches conflict, and the worktree
        is preserved for user resolution."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        try:
            with pytest.raises(b4.AmConflictError) as exc_info:
                b4.git_fetch_am_into_repo(
                    gitdir, ambytes, at_base='HEAD', am_flags=['-3']
                )

            assert exc_info.value.worktree_path != ''
            assert exc_info.value.output != ''
            wt_path = exc_info.value.worktree_path
            # Worktree must still exist for user to resolve
            assert os.path.isdir(wt_path)
            # rebase-apply should be present (am still in progress)
            ecode, wt_gitdir = b4.git_run_command(
                wt_path, ['rev-parse', '--git-dir'], logstderr=True, rundir=wt_path
            )
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

    def test_check_only_with_three_way(self, gitdir: str) -> None:
        """check_only mode returns early without fetching, even with -3."""
        ambytes, base = _build_clean_patches(gitdir)

        # Remove any existing FETCH_HEAD
        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        if os.path.exists(fh_path):
            os.unlink(fh_path)

        b4.git_fetch_am_into_repo(
            gitdir, ambytes, at_base=base, check_only=True, am_flags=['-3']
        )

        # check_only should not fetch (no FETCH_HEAD created)
        assert not os.path.exists(fh_path)

        # Worktree should still be cleaned up
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None
        gwt = os.path.join(common_dir, 'b4-shazam-worktree')
        assert not os.path.exists(gwt)

    def test_check_only_runs_no_hooks(self, gitdir: str, applied_log: Path) -> None:
        """A check throws its commits away, so it must not run git am hooks.

        Hooks have side effects that outlive the scratch worktree (git notes,
        notifications), and here they would be about commits nobody keeps.
        """
        ambytes, base = _build_clean_patches(gitdir)

        b4.git_fetch_am_into_repo(
            gitdir, ambytes, at_base=base, check_only=True, am_flags=['-3']
        )

        assert not applied_log.exists()


def _build_subdir_three_way(gitdir: str) -> Tuple[bytes, str]:
    """Build a patch that only applies via a 3-way merge, on a subdirectory file.

    The submitter edits one line and the maintainer edits a different line
    close enough to sit inside the same hunk context, so the patch cannot
    apply directly but the 3-way merge resolves it without conflict. The file
    lives in a subdirectory, so it must be among the sparse paths that get
    materialized: git refuses to write skip-worktree paths during a merge.

    Returns (mbox bytes, base commit sha).
    """
    subdir = os.path.join(gitdir, 'drivers')
    os.makedirs(subdir, exist_ok=True)
    body = ['line %d' % num for num in range(1, 21)]
    with open(os.path.join(subdir, 'thing.c'), 'w') as fh:
        fh.write('\n'.join(body) + '\n')
    b4.git_run_command(gitdir, ['add', 'drivers/thing.c'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Add drivers/thing.c'])
    ecode, base = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
    assert ecode == 0
    base = base.strip()

    # Submitter side: change line 10.
    b4.git_run_command(gitdir, ['checkout', '-b', 'submitter'])
    submitted = list(body)
    submitted[9] = 'line 10 changed by submitter'
    with open(os.path.join(subdir, 'thing.c'), 'w') as fh:
        fh.write('\n'.join(submitted) + '\n')
    b4.git_run_command(gitdir, ['add', 'drivers/thing.c'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Touch line 10'])
    ecode, mbox = b4.git_run_command(
        gitdir, ['format-patch', '-1', '--stdout'], decode=False
    )
    assert ecode == 0

    # Maintainer side: change line 12, inside the submitted hunk's context.
    b4.git_run_command(gitdir, ['checkout', 'master'])
    b4.git_run_command(gitdir, ['branch', '-D', 'submitter'])
    maintained = list(body)
    maintained[11] = 'line 12 changed by maintainer'
    with open(os.path.join(subdir, 'thing.c'), 'w') as fh:
        fh.write('\n'.join(maintained) + '\n')
    b4.git_run_command(gitdir, ['add', 'drivers/thing.c'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Touch line 12'])

    return mbox, base


@pytest.mark.parametrize(
    'mbox,expected',
    [
        pytest.param(
            b'diff --git a/drivers/foo.c b/drivers/foo.c\n'
            b'--- a/drivers/foo.c\n'
            b'+++ b/drivers/foo.c\n',
            {'drivers/foo.c'},
            id='plain-modification',
        ),
        pytest.param(
            b'diff --git a/new.c b/new.c\n'
            b'new file mode 100644\n'
            b'--- /dev/null\n'
            b'+++ b/new.c\n',
            {'new.c'},
            id='new-file-skips-dev-null',
        ),
        pytest.param(
            b'diff --git a/gone.c b/gone.c\n'
            b'deleted file mode 100644\n'
            b'--- a/gone.c\n'
            b'+++ /dev/null\n',
            {'gone.c'},
            id='deletion-skips-dev-null',
        ),
        pytest.param(
            b'diff --git a/old/name.c b/new/name.c\nsimilarity index 95%\n',
            {'old/name.c', 'new/name.c'},
            id='rename-collects-both-sides',
        ),
        pytest.param(
            b'diff --git a/old name.c b/new name.c\nsimilarity index 95%\n',
            {'old name.c', 'new name.c'},
            id='rename-with-spaces-in-names',
        ),
        pytest.param(
            b'diff --git a/img.png b/img.png\nGIT binary patch\n',
            {'img.png'},
            id='binary-patch-has-no-file-lines',
        ),
        # A commit-message line that looks like a diff header is skipped.
        pytest.param(
            b'--- v1 to v2 notes\ndiff --git a/real.c b/real.c\n',
            {'real.c'},
            id='ignores-unmappable-prose',
        ),
        pytest.param(b'Subject: nothing here\n', set(), id='empty-mbox'),
    ],
)
def test_touched_paths_from_am(mbox: bytes, expected: set[str]) -> None:
    """The patch-path scanner that drives the sparse checkout."""
    assert b4._touched_paths_from_am(mbox) == expected


class TestSparsePatternsForPaths:
    """Tests for rendering touched paths as non-cone sparse patterns."""

    def test_paths_are_anchored_and_sorted(self) -> None:
        out = b4._sparse_patterns_for_paths({'b/two.c', 'a/one.c'})
        lines = out.decode().splitlines()
        assert lines == ['/.gitattributes', '/.gitmodules', '/a/one.c', '/b/two.c']

    def test_glob_characters_are_escaped(self) -> None:
        """Non-cone patterns are gitignore globs, so wildcards need escaping."""
        out = b4._sparse_patterns_for_paths({'dir/img[1].png', 'dir/a*b.c'})
        lines = out.decode().splitlines()
        assert '/dir/img\\[1\\].png' in lines
        assert '/dir/a\\*b.c' in lines


class TestSparseAmAvoidsFullCheckout:
    """The scratch worktree materializes only the paths the patches touch."""

    def test_three_way_in_subdir_needs_no_full_materialization(
        self, gitdir: str
    ) -> None:
        ambytes, base = _build_subdir_three_way(gitdir)

        calls: list[list[str]] = []
        real_run = b4.git_run_command

        def recording_run(*args: Any, **kwargs: Any) -> Any:
            if len(args) > 1 and isinstance(args[1], list):
                calls.append(args[1])
            return real_run(*args, **kwargs)

        with patch('b4.git_run_command', side_effect=recording_run):
            b4.git_fetch_am_into_repo(
                gitdir, ambytes, at_base=base, am_flags=['-3'], resolve=True
            )

        # The 3-way ran inside the sparse worktree: no full-tree replay.
        assert not any(
            'disable' in call and 'sparse-checkout' in call for call in calls
        )
        # And the sparse set was the touched path, not the old empty set.
        sparse_sets = [
            call for call in calls if 'sparse-checkout' in call and 'set' in call
        ]
        assert len(sparse_sets) == 1
        assert '--no-cone' in sparse_sets[0]

        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        assert os.path.exists(fh_path)

    def test_result_matches_full_checkout_replay(self, gitdir: str) -> None:
        """The sparse 3-way produces the same tree the full replay would."""
        ambytes, base = _build_subdir_three_way(gitdir)

        b4.git_fetch_am_into_repo(
            gitdir, ambytes, at_base=base, am_flags=['-3'], resolve=True
        )
        ecode, sparse_tree = b4.git_run_command(
            gitdir, ['rev-parse', 'FETCH_HEAD^{tree}']
        )
        assert ecode == 0

        # Now force the old behaviour (empty sparse set) and compare.
        with patch('b4._touched_paths_from_am', return_value=set()):
            b4.git_fetch_am_into_repo(
                gitdir, ambytes, at_base=base, am_flags=['-3'], resolve=True
            )
        ecode, replay_tree = b4.git_run_command(
            gitdir, ['rev-parse', 'FETCH_HEAD^{tree}']
        )
        assert ecode == 0
        assert sparse_tree.strip() == replay_tree.strip()


class TestSuspendToShellCwd:
    """Test that _suspend_to_shell passes cwd to subprocess.run."""

    @pytest.mark.parametrize(
        'kwargs,expected_cwd',
        [
            pytest.param(
                {'cwd': '/tmp/test-worktree'},
                '/tmp/test-worktree',
                id='cwd-passed-through',
            ),
            pytest.param({}, None, id='cwd-none-by-default'),
        ],
    )
    @patch('b4.subprocess.run')
    def test_cwd(
        self,
        mock_run: Any,
        monkeypatch: pytest.MonkeyPatch,
        kwargs: Dict[str, Any],
        expected_cwd: Optional[str],
    ) -> None:
        from b4 import _suspend_to_shell

        # Use a shell name that is neither bash nor zsh so we hit
        # the simple else branch (no tempfile/rcfile logic).
        monkeypatch.setenv('SHELL', '/tmp/fakeshell')

        _suspend_to_shell(**kwargs)

        mock_run.assert_called_once()
        _args, run_kwargs = mock_run.call_args
        assert run_kwargs.get('cwd') == expected_cwd

    @patch('b4.subprocess.run')
    def test_hint_appears_in_env(
        self, mock_run: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from b4 import _suspend_to_shell

        monkeypatch.setenv('SHELL', '/tmp/fakeshell')

        _suspend_to_shell(hint='b4 conflict', cwd='/tmp/wt')

        mock_run.assert_called_once()
        _args, kwargs = mock_run.call_args
        assert kwargs['env']['B4_REVIEW'] == 'b4 conflict'

    @patch('b4.subprocess.run')
    def test_extra_env_reaches_shell_only(
        self, mock_run: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # git am --continue in this shell runs the remaining patches' hooks,
        # so they need the same series variables the first am got.
        from b4 import _suspend_to_shell

        monkeypatch.setenv('SHELL', '/tmp/fakeshell')
        monkeypatch.delenv('B4_SERIES_URL', raising=False)

        _suspend_to_shell(extra_env={'B4_SERIES_URL': 'https://example.com/x'})

        _args, kwargs = mock_run.call_args
        assert kwargs['env']['B4_SERIES_URL'] == 'https://example.com/x'
        assert 'B4_SERIES_URL' not in os.environ


# Runs after startup, standing in for the first prompt: precmd hooks fire
# only before a prompt, and a non-interactive test never reaches one.
_ZSH_PROBE = """
for f in $precmd_functions; do $f; done
print -r -- "B4TEST ps1=$PS1"
print -r -- "B4TEST zdotdir=${ZDOTDIR-<unset>}"
print -r -- "B4TEST hooks=${precmd_functions[*]}"
print -r -- "B4TEST seen=$SEEN"
"""


@pytest.mark.skipif(shutil.which('zsh') is None, reason='zsh is not installed')
class TestSuspendToShellZsh:
    """Run the zsh sub-shell for real against typical user configurations.

    b4 points ZDOTDIR at its own directory to add the prompt hint, so
    each case checks that the user's own startup files still load as
    usual, and that the hint and b4's hook do not leak into the shell.
    """

    @staticmethod
    def _run(monkeypatch: pytest.MonkeyPatch, home: Path) -> Dict[str, str]:
        monkeypatch.setenv('SHELL', shutil.which('zsh') or 'zsh')
        monkeypatch.setenv('HOME', str(home))
        real_run = subprocess.run
        output: Dict[str, str] = {}

        def _probe(cmd: List[str], env: Dict[str, str], cwd: Optional[str]) -> None:
            # -d skips the system-wide rc files, which differ per distro.
            res = real_run(
                [cmd[0], '-d', '-i', '-c', _ZSH_PROBE],
                env=env,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
            )
            for line in res.stdout.splitlines():
                if line.startswith('B4TEST '):
                    key, val = line[7:].split('=', 1)
                    output[key] = val

        with patch('b4.subprocess.run', side_effect=_probe):
            b4._suspend_to_shell(hint='b4')
        return output

    def test_zshenv_variables_reach_zshrc(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Unexported settings from .zshenv are visible in .zshrc.

        Setups like home-manager define variables in .zshenv that .zshrc
        then uses; they are not exported, so the parent shell's
        environment does not carry them into the sub-shell.
        """
        monkeypatch.delenv('ZDOTDIR', raising=False)
        (tmp_path / '.zshenv').write_text('MYVAR=from-zshenv\n')
        (tmp_path / '.zshrc').write_text('SEEN=$MYVAR\n')
        out = self._run(monkeypatch, tmp_path)
        assert out['seen'] == 'from-zshenv'
        assert out['ps1'].startswith('(b4) ')

    def test_zshenv_moving_zdotdir(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A .zshenv that moves ZDOTDIR still gets its own .zshrc and the hint.

        Keeping the config in ~/.config/zsh this way is common; the hint
        must not be lost when the user's .zshenv changes ZDOTDIR.
        """
        monkeypatch.delenv('ZDOTDIR', raising=False)
        confdir = tmp_path / '.config' / 'zsh'
        confdir.mkdir(parents=True)
        (tmp_path / '.zshenv').write_text('ZDOTDIR="$HOME/.config/zsh"\n')
        (confdir / '.zshrc').write_text("SEEN=config-zshrc\nPS1='user> '\n")
        out = self._run(monkeypatch, tmp_path)
        assert out['seen'] == 'config-zshrc'
        assert out['ps1'] == '(b4) user> '
        assert out['zdotdir'] == str(confdir)

    @pytest.mark.parametrize(
        'zdotdir_name',
        [
            pytest.param(None, id='home'),
            # Quotes and $ must reach zsh as plain path characters.
            pytest.param('it\'s "$odd" dir', id='odd-chars'),
        ],
    )
    def test_zdotdir_restored(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        zdotdir_name: Optional[str],
    ) -> None:
        """The shell ends up with the user's own ZDOTDIR, or none at all.

        b4's temporary directory is removed when the shell exits, so
        nothing in the shell may keep pointing at it; and a user who
        never set ZDOTDIR should not suddenly have one.
        """
        if zdotdir_name is None:
            monkeypatch.delenv('ZDOTDIR', raising=False)
            zdotdir = tmp_path
            expected = '<unset>'
        else:
            zdotdir = tmp_path / zdotdir_name
            zdotdir.mkdir()
            monkeypatch.setenv('ZDOTDIR', str(zdotdir))
            expected = str(zdotdir)
        (zdotdir / '.zshrc').write_text("SEEN=zshrc\nPS1='user> '\n")
        out = self._run(monkeypatch, tmp_path)
        assert out['seen'] == 'zshrc'
        assert out['ps1'] == '(b4) user> '
        assert out['zdotdir'] == expected
        assert '_b4' not in out['hooks']

    def test_hint_survives_replaced_fpath(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The hint does not depend on zsh's bundled functions.

        A .zshenv may point fpath at the user's own functions only, and
        then helpers like add-zsh-hook cannot be autoloaded.
        """
        monkeypatch.delenv('ZDOTDIR', raising=False)
        (tmp_path / '.zshenv').write_text('fpath=("$HOME/funcs")\n')
        (tmp_path / '.zshrc').write_text("PS1='user> '\n")
        out = self._run(monkeypatch, tmp_path)
        assert out['ps1'] == '(b4) user> '
        assert '_b4' not in out['hooks']

    def test_no_user_config(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Without any startup files the shell still starts with the hint."""
        monkeypatch.delenv('ZDOTDIR', raising=False)
        out = self._run(monkeypatch, tmp_path)
        assert out['ps1'].startswith('(b4) ')


class TestConflictResolutionFlow:
    """Integration tests for the conflict resolution workflow.

    The scratch worktree starts out sparse, holding only the paths the
    patches touch.  These tests exercise the same git operations that the
    TUI conflict handlers use (sparse-checkout disable to expose the whole
    tree, rebase-apply detection, fetch from worktree), without requiring
    the TUI itself.
    """

    def test_worktree_resolve_and_fetch(self, gitdir: str) -> None:
        """Full worktree flow: conflict -> resolve -> fetch succeeds."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        with pytest.raises(b4.AmConflictError) as exc_info:
            b4.git_fetch_am_into_repo(gitdir, ambytes, at_base='HEAD', am_flags=['-3'])

        wt = exc_info.value.worktree_path

        # --- same steps the TUI handler takes ---
        # 1. Disable sparse checkout so the whole tree is visible
        b4.git_run_command(
            wt, ['sparse-checkout', 'disable'], logstderr=True, rundir=wt
        )
        assert os.path.exists(os.path.join(wt, 'file1.txt'))

        # 2. Simulate user resolving: accept theirs and continue
        b4.git_run_command(wt, ['checkout', '--theirs', '.'], logstderr=True, rundir=wt)
        b4.git_run_command(wt, ['add', '-A'], logstderr=True, rundir=wt)
        ecode, _out = b4.git_run_command(
            wt, ['am', '--continue'], logstderr=True, rundir=wt
        )
        assert ecode == 0

        # 3. Verify rebase-apply is gone (am completed)
        ecode, wt_gitdir = b4.git_run_command(
            wt, ['rev-parse', '--git-dir'], logstderr=True, rundir=wt
        )
        assert ecode == 0
        rebase_apply = os.path.join(wt_gitdir.strip(), 'rebase-apply')
        assert not os.path.isdir(rebase_apply)

        # 4. Fetch result into main repo
        ecode, _out = b4.git_run_command(gitdir, ['fetch', wt], logstderr=True)
        assert ecode == 0
        fh_path = os.path.join(gitdir, '.git', 'FETCH_HEAD')
        assert os.path.exists(fh_path)

        # 5. Rewrite FETCH_HEAD so it names the patch source, not the
        #    scratch worktree (as the TUI handler does)
        origin = 'https://lore.kernel.org/r/test@example.com'
        b4._rewrite_fetch_head_origin(gitdir, wt, origin)
        with open(fh_path, 'r') as fh:
            contents = fh.read()
        assert wt not in contents
        assert f'patches from {origin}' in contents

        # 6. Clean up worktree
        b4.git_run_command(gitdir, ['worktree', 'remove', '--force', wt])
        assert not os.path.exists(wt)

    def test_worktree_unresolved_detected(self, gitdir: str) -> None:
        """When user doesn't resolve, rebase-apply is still present."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        with pytest.raises(b4.AmConflictError) as exc_info:
            b4.git_fetch_am_into_repo(gitdir, ambytes, at_base='HEAD', am_flags=['-3'])

        wt = exc_info.value.worktree_path

        # User returns from shell without resolving
        ecode, wt_gitdir = b4.git_run_command(
            wt, ['rev-parse', '--git-dir'], logstderr=True, rundir=wt
        )
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
            b4.git_fetch_am_into_repo(gitdir, ambytes, at_base='HEAD', am_flags=['-3'])

        wt = exc_info.value.worktree_path

        # Before: only the paths the patch touches (file1.txt) were
        # materialized; the rest of the tree is hidden by the sparse checkout.
        assert os.path.exists(os.path.join(wt, 'file1.txt'))
        assert not os.path.exists(os.path.join(wt, 'file2.txt'))
        b4.git_run_command(
            wt, ['sparse-checkout', 'disable'], logstderr=True, rundir=wt
        )

        # All repo files should now be visible
        assert os.path.exists(os.path.join(wt, 'file1.txt'))
        assert os.path.exists(os.path.join(wt, 'file2.txt'))
        assert os.path.exists(os.path.join(wt, 'lipsum.txt'))

        b4.git_run_command(gitdir, ['worktree', 'remove', '--force', wt])


class TestDirectAmConflictFlow:
    """Integration tests for the direct git-am conflict path (_do_take_am).

    This path runs git-am directly on the user's working branch
    (not in a worktree), so resolution happens in-place.  It only drives
    plain git commands; it does not call into b4 itself.
    """

    def test_am_conflict_and_resolution(self, gitdir: str) -> None:
        """Direct git-am -3 conflict, resolved with --continue."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        # Run git-am directly (as _do_take_am does)
        ecode, _out = b4.git_run_command(
            gitdir, ['am', '-3'], stdin=ambytes, logstderr=True
        )
        assert ecode != 0

        # rebase-apply should exist
        rebase_apply = os.path.join(gitdir, '.git', 'rebase-apply')
        assert os.path.isdir(rebase_apply)

        # Resolve: accept theirs and continue
        b4.git_run_command(gitdir, ['checkout', '--theirs', '.'], logstderr=True)
        b4.git_run_command(gitdir, ['add', '-A'], logstderr=True)
        ecode, _out = b4.git_run_command(gitdir, ['am', '--continue'], logstderr=True)
        assert ecode == 0
        assert not os.path.isdir(rebase_apply)

    def test_am_conflict_unresolved(self, gitdir: str) -> None:
        """Direct git-am -3 conflict, user aborts."""
        ambytes, _base = _build_conflicting_patches(gitdir)

        ecode, _out = b4.git_run_command(
            gitdir, ['am', '-3'], stdin=ambytes, logstderr=True
        )
        assert ecode != 0

        # rebase-apply is present (handler detects this)
        rebase_apply = os.path.join(gitdir, '.git', 'rebase-apply')
        assert os.path.isdir(rebase_apply)

        # Abort (as user would after incomplete resolution)
        b4.git_run_command(gitdir, ['am', '--abort'], logstderr=True)
        assert not os.path.isdir(rebase_apply)


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


def _build_subdir_conflict(gitdir: str) -> bytes:
    """2-patch mbox whose conflicting patch touches a file in a SUBDIRECTORY.

    The shazam worktree is a sparse checkout that materializes the paths the
    patches touch, so ``drivers/foo.txt`` is on disk and git's 3-way merge can
    record the conflict in it. A conflict that leaves a clean index (no
    markers) would let ``git am --skip`` silently drop the patch, so the
    conflict must be recorded as unmerged. With ``resolve=True``,
    git_fetch_am_into_repo also replays a failed am on a full worktree.
    Patch 1 changes a root file cleanly; patch 2 changes ``drivers/foo.txt``
    and conflicts with master.
    """
    # Seed a subdirectory file on master so it is part of the base tree.
    os.makedirs(os.path.join(gitdir, 'drivers'), exist_ok=True)
    with open(os.path.join(gitdir, 'drivers', 'foo.txt'), 'w') as fh:
        fh.write('1\n2\n3\n')
    b4.git_run_command(gitdir, ['add', 'drivers/foo.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Seed drivers/foo.txt'])

    b4.git_run_command(gitdir, ['checkout', '-b', 'subdir-patch'])
    with open(os.path.join(gitdir, 'file2.txt'), 'a') as fh:
        fh.write('Added by patch 1.\n')
    b4.git_run_command(gitdir, ['add', 'file2.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Patch 1: modify file2'])
    with open(os.path.join(gitdir, 'drivers', 'foo.txt'), 'w') as fh:
        fh.write('1\nPATCH\n3\n')
    b4.git_run_command(gitdir, ['add', 'drivers/foo.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Patch 2: change drivers/foo'])

    ecode, mbox = b4.git_run_command(gitdir, ['format-patch', '-2', '--stdout'])
    assert ecode == 0

    b4.git_run_command(gitdir, ['checkout', 'master'])
    b4.git_run_command(gitdir, ['branch', '-D', 'subdir-patch'])
    with open(os.path.join(gitdir, 'drivers', 'foo.txt'), 'w') as fh:
        fh.write('1\nMASTER\n3\n')
    b4.git_run_command(gitdir, ['add', 'drivers/foo.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Master: change drivers/foo'])
    return mbox.encode()


def _build_subdir_clean_3way(gitdir: str) -> bytes:
    """1-patch mbox: a subdir change that 3-way merges CLEANLY against master.

    The patch edits ``drivers/foo.txt`` near (but clear of) a line master also
    changed, so the direct ``git apply`` misses on context and falls back to a
    3-way merge that is clean. The subdir file is one of the touched paths, so
    it is materialized in the sparse shazam worktree and the 3-way merge
    succeeds there -- ``git_fetch_am_into_repo(resolve=True)`` must NOT report
    a conflict.
    """
    lines = ''.join('%d\n' % n for n in range(1, 21))
    os.makedirs(os.path.join(gitdir, 'drivers'), exist_ok=True)
    with open(os.path.join(gitdir, 'drivers', 'foo.txt'), 'w') as fh:
        fh.write(lines)
    b4.git_run_command(gitdir, ['add', 'drivers/foo.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Seed drivers/foo.txt'])

    b4.git_run_command(gitdir, ['checkout', '-b', 'clean3'])
    with open(os.path.join(gitdir, 'drivers', 'foo.txt'), 'w') as fh:
        fh.write(lines.replace('10\n', 'TEN-from-patch\n'))
    b4.git_run_command(gitdir, ['add', 'drivers/foo.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Patch: drivers/foo line 10'])

    ecode, mbox = b4.git_run_command(gitdir, ['format-patch', '-1', '--stdout'])
    assert ecode == 0

    b4.git_run_command(gitdir, ['checkout', 'master'])
    b4.git_run_command(gitdir, ['branch', '-D', 'clean3'])
    # Line 13 is inside the patch's context window for line 10 (forces 3-way)
    # but two lines clear of it, so the merge is clean rather than a conflict.
    with open(os.path.join(gitdir, 'drivers', 'foo.txt'), 'w') as fh:
        fh.write(lines.replace('13\n', 'THIRTEEN-master\n'))
    b4.git_run_command(gitdir, ['add', 'drivers/foo.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'Master: drivers/foo line 13'])
    return mbox.encode()


def _trigger_am_conflict(
    gitdir: str, extra_env: Optional[Dict[str, str]] = None
) -> Tuple[b4.AmConflictError, str]:
    """Run a conflicting multi-patch git-am inside the shazam worktree.

    Applying onto HEAD (which carries master's conflicting file1 rewrite) makes
    patch 3 fail, so git_fetch_am_into_repo raises and leaves the in-progress
    git-am parked in the worktree -- exactly the state ``b4 shazam --resolve``
    hands to the subshell. Returns (the error, the am's base commit).
    """
    ambytes, _base = _build_multi_patch_conflict(gitdir)
    _ecode, head = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
    with pytest.raises(b4.AmConflictError) as exc_info:
        b4.git_fetch_am_into_repo(
            gitdir,
            ambytes,
            at_base='HEAD',
            am_flags=['-3'],
            resolve=True,
            extra_env=extra_env,
        )
    return exc_info.value, head.strip()


def _resolve_in_shell(actions: Callable[[str], None]) -> Callable[..., None]:
    """Build a _suspend_to_shell stand-in that drives the conflict worktree.

    resolve_am_conflict_in_shell calls _suspend_to_shell(hint=..., cwd=<worktree>,
    ...) then inspects the worktree. Patching it with this stand-in runs
    *actions(worktree)* in place of the interactive shell -- i.e. whatever the user
    would type (resolve + ``git am --continue``, ``git am --abort``, or nothing).
    """

    def _side_effect(*_args: Any, **kwargs: Any) -> None:
        actions(kwargs['cwd'])

    return _side_effect


class TestShazamResolveInline:
    """``b4 shazam --resolve`` resolves the conflict inline via a subshell."""

    def test_resolve_merges_and_keeps_every_patch(self, gitdir: str) -> None:
        cex, _base = _trigger_am_conflict(gitdir)
        wt = cex.worktree_path

        def finish_am(worktree: str) -> None:
            with open(os.path.join(worktree, 'file1.txt'), 'w') as fh:
                fh.write('Resolved file1.\n')
            b4.git_run_command(worktree, ['add', 'file1.txt'], rundir=worktree)
            ecode, _out = b4.git_run_command(
                worktree, ['am', '--continue'], rundir=worktree
            )
            assert ecode == 0

        with patch('b4._suspend_to_shell', side_effect=_resolve_in_shell(finish_am)):
            ok = b4.resolve_am_conflict_in_shell(
                gitdir, cex, origin='https://example.com'
            )
        # Success: the worktree is gone and the series sits in FETCH_HEAD.
        assert ok is True
        assert not os.path.exists(wt)

        # Merge it exactly like the clean shazam path would (under pytest
        # _run_shazam_merge runs the merge captured and exits with its code).
        with pytest.raises(SystemExit) as exit_info:
            b4.mbox._run_shazam_merge(
                gitdir,
                merge_template='Merge test series\n\nResolved conflict.\n',
                tptvals={},
                merge_flags='--signoff',
                no_interactive=True,
                do_merge=True,
            )
        assert exit_info.value.code == 0

        # A real two-parent merge commit resulted...
        ecode, parents = b4.git_run_command(
            gitdir, ['rev-list', '--parents', '-1', 'HEAD']
        )
        assert ecode == 0 and len(parents.split()) == 3

        # ...and EVERY patch survived: patch 1 (file2), 2 (lipsum), 3 (file1).
        ecode, file2 = b4.git_run_command(gitdir, ['show', 'HEAD:file2.txt'])
        assert ecode == 0 and 'Added by patch 1.' in file2
        ecode, lipsum = b4.git_run_command(gitdir, ['show', 'HEAD:lipsum.txt'])
        assert ecode == 0 and 'Extra paragraph from patch 2.' in lipsum
        ecode, file1 = b4.git_run_command(gitdir, ['show', 'HEAD:file1.txt'])
        assert ecode == 0 and 'Resolved file1.' in file1

    def test_resolve_unfinished_am_tears_down(self, gitdir: str) -> None:
        # Leaving the shell with the git-am still parked is treated as "gave up":
        # the worktree is torn down and no merge happens.
        cex, _base = _trigger_am_conflict(gitdir)
        wt = cex.worktree_path
        _e, head_before = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])

        def do_nothing(_worktree: str) -> None:
            pass

        with patch('b4._suspend_to_shell', side_effect=_resolve_in_shell(do_nothing)):
            ok = b4.resolve_am_conflict_in_shell(gitdir, cex)
        assert ok is False
        assert not os.path.exists(wt)
        _e, head_after = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert head_after.strip() == head_before.strip()

    def test_resolve_shell_gets_series_env(self, gitdir: str) -> None:
        # The hooks of every patch applied by "git am --continue" in the
        # shell must see the series variables, not just the patches before
        # the conflict. The conflict carries them from the am to the shell,
        # so a caller cannot give the two different environments.
        series_env = {'B4_SERIES_URL': 'https://example.com/x'}
        cex, _base = _trigger_am_conflict(gitdir, extra_env=series_env)

        with patch('b4._suspend_to_shell') as mock_shell:
            b4.resolve_am_conflict_in_shell(gitdir, cex)
        assert mock_shell.call_args.kwargs['extra_env'] == series_env

    def test_resolve_aborted_am_tears_down(self, gitdir: str) -> None:
        # Regression: "git am --abort" after a partial multi-patch apply resets the
        # worktree HEAD all the way back to base. The HEAD-vs-base check must catch
        # that as "nothing applied" (a before/after-HEAD compare would not), so we
        # refuse rather than merge a no-op that silently drops the whole series.
        cex, _base = _trigger_am_conflict(gitdir)
        wt = cex.worktree_path
        _e, head_before = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])

        def abort_am(worktree: str) -> None:
            ecode, _out = b4.git_run_command(
                worktree, ['am', '--abort'], rundir=worktree
            )
            assert ecode == 0

        with patch('b4._suspend_to_shell', side_effect=_resolve_in_shell(abort_am)):
            ok = b4.resolve_am_conflict_in_shell(gitdir, cex)
        assert ok is False
        assert not os.path.exists(wt)
        # No commit was made on the branch.
        _e, head_after = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert head_after.strip() == head_before.strip()

    def test_conflict_pins_am_base_commit(self, gitdir: str) -> None:
        # Regression for the silent-drop bug: the am's base must be pinned on the
        # AmConflictError when the conflict is raised (while the worktree HEAD
        # still points at base), not re-derived from a symbolic 'HEAD' against the
        # worktree later -- by then git-am has advanced HEAD to the applied tip, so
        # a *successful* resolve would otherwise be misread as "nothing applied".
        cex, base = _trigger_am_conflict(gitdir)
        assert cex.base_sha == base


class TestSubdirConflictResolve:
    """Regression: a conflict in a subdirectory file must be resolvable.

    The conflict must be recorded as an unmerged path with markers in the
    worktree (not left as a clean index, which would let the patch be
    silently dropped), so the user can resolve it and every patch survives.
    """

    def test_subdir_conflict_records_markers_and_keeps_patch(self, gitdir: str) -> None:
        ambytes = _build_subdir_conflict(gitdir)
        _e, _base = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])

        with pytest.raises(b4.AmConflictError) as exc_info:
            b4.git_fetch_am_into_repo(
                gitdir, ambytes, at_base='HEAD', am_flags=['-3'], resolve=True
            )
        wt = exc_info.value.worktree_path

        # The subdir file is materialized and recorded as an unmerged conflict
        # (if it were absent or clean the patch would be lost).
        assert os.path.exists(os.path.join(wt, 'drivers', 'foo.txt'))
        _ecode, unmerged = b4.git_run_command(
            wt, ['diff', '--name-only', '--diff-filter=U'], rundir=wt
        )
        assert 'drivers/foo.txt' in unmerged

        def finish(worktree: str) -> None:
            with open(os.path.join(worktree, 'drivers', 'foo.txt'), 'w') as fh:
                fh.write('1\nRESOLVED\n3\n')
            b4.git_run_command(worktree, ['add', 'drivers/foo.txt'], rundir=worktree)
            ecode, _out = b4.git_run_command(
                worktree, ['am', '--continue'], rundir=worktree
            )
            assert ecode == 0

        with patch('b4._suspend_to_shell', side_effect=_resolve_in_shell(finish)):
            ok = b4.resolve_am_conflict_in_shell(
                gitdir, exc_info.value, origin='https://example.com'
            )
        assert ok is True
        assert not os.path.exists(wt)

        with pytest.raises(SystemExit) as exit_info:
            b4.mbox._run_shazam_merge(
                gitdir,
                merge_template='Merge series\n\nResolved.\n',
                tptvals={},
                merge_flags='--signoff',
                no_interactive=True,
                do_merge=True,
            )
        assert exit_info.value.code == 0

        # Both patches survived: patch 1 (file2) and patch 2 (drivers/foo).
        ecode, file2 = b4.git_run_command(gitdir, ['show', 'HEAD:file2.txt'])
        assert ecode == 0 and 'Added by patch 1.' in file2
        ecode, foo = b4.git_run_command(gitdir, ['show', 'HEAD:drivers/foo.txt'])
        assert ecode == 0 and 'RESOLVED' in foo


class TestSubdirCleanThreeWay:
    """Regression: a clean 3-way in a subdir file must not be a phantom conflict.

    The 3-way merge of the subdir file is clean, so ``resolve=True`` must
    complete normally -- not raise AmConflictError and send the user off to
    resolve a conflict that does not exist.
    """

    def test_clean_subdir_3way_does_not_raise(self, gitdir: str) -> None:
        common_dir = b4.git_get_common_dir(gitdir)
        assert common_dir is not None
        ambytes = _build_subdir_clean_3way(gitdir)

        # Must NOT raise: the 3-way merge is clean.
        b4.git_fetch_am_into_repo(
            gitdir, ambytes, at_base='HEAD', am_flags=['-3'], resolve=True
        )

        # The series landed in FETCH_HEAD with BOTH edits 3-way merged.
        ecode, foo = b4.git_run_command(gitdir, ['show', 'FETCH_HEAD:drivers/foo.txt'])
        assert ecode == 0
        assert 'TEN-from-patch' in foo and 'THIRTEEN-master' in foo

        # Worktree torn down, nothing parked for resolution.
        assert not os.path.exists(os.path.join(common_dir, 'b4-shazam-worktree'))


def _build_mixed_conflict(gitdir: str) -> bytes:
    """2-patch mbox whose second patch conflicts in one file and not another.

    Patch 1 changes a root file cleanly. Patch 2 changes ``drivers/foo.txt``,
    which conflicts with master, and ``drivers/bar.txt``, which needs a 3-way
    merge that is clean.
    """
    bar = ''.join('%d\n' % n for n in range(1, 21))

    def commit(msg: str, files: Dict[str, str], mode: str = 'w') -> None:
        for name, content in files.items():
            path = os.path.join(gitdir, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, mode) as fh:
                fh.write(content)
        b4.git_run_command(gitdir, ['add', *files])
        b4.git_run_command(gitdir, ['commit', '-m', msg])

    commit('Seed drivers', {'drivers/foo.txt': '1\n2\n3\n', 'drivers/bar.txt': bar})

    b4.git_run_command(gitdir, ['checkout', '-b', 'mixed-patch'])
    commit('Patch 1: modify file2', {'file2.txt': 'Added by patch 1.\n'}, mode='a')
    commit(
        'Patch 2: change drivers',
        {
            'drivers/foo.txt': '1\nPATCH\n3\n',
            'drivers/bar.txt': bar.replace('10\n', 'TEN-from-patch\n'),
        },
    )
    ecode, mbox = b4.git_run_command(gitdir, ['format-patch', '-2', '--stdout'])
    assert ecode == 0

    b4.git_run_command(gitdir, ['checkout', 'master'])
    b4.git_run_command(gitdir, ['branch', '-D', 'mixed-patch'])
    # Line 13 of bar.txt is inside the patch's context for line 10 (forces a
    # 3-way) but clear of it, so only foo.txt is a real conflict.
    commit(
        'Master: change drivers',
        {
            'drivers/foo.txt': '1\nMASTER\n3\n',
            'drivers/bar.txt': bar.replace('13\n', 'THIRTEEN-master\n'),
        },
    )
    return mbox.encode()


class TestAmHooksRunOncePerPatch:
    """A conflict must not make git am hooks run again for applied patches.

    Hooks have side effects outside the scratch worktree: a post-applypatch
    hook may add a git note or notify another system. When the am stops, the
    patches before the conflict are already applied and their hooks have
    run, so getting the conflict ready for the user must not apply them a
    second time.
    """

    @pytest.mark.parametrize(
        'builder,sparse_paths,applied',
        [
            # The usual case: the conflicting file is in the sparse checkout.
            pytest.param(
                lambda gitdir: _build_multi_patch_conflict(gitdir)[0],
                None,
                ['Patch 1: modify file2', 'Patch 2: modify lipsum'],
                id='conflict-in-sparse-set',
            ),
            # The conflicting file could not be mapped to a sparse path, so
            # the am stops without recording the conflict.
            pytest.param(
                _build_subdir_conflict,
                set(),
                ['Patch 1: modify file2'],
                id='conflict-outside-sparse-set',
            ),
        ],
    )
    def test_hooks_run_once_before_conflict(
        self,
        gitdir: str,
        applied_log: Path,
        builder: Callable[[str], bytes],
        sparse_paths: Optional[Set[str]],
        applied: List[str],
    ) -> None:
        ambytes = builder(gitdir)

        with ExitStack() as stack:
            if sparse_paths is not None:
                stack.enter_context(
                    patch('b4._touched_paths_from_am', return_value=sparse_paths)
                )
            with pytest.raises(b4.AmConflictError) as exc_info:
                b4.git_fetch_am_into_repo(
                    gitdir, ambytes, at_base='HEAD', am_flags=['-3'], resolve=True
                )

        assert applied_log.read_text().splitlines() == applied
        # However the am got here, the user must find a conflict to resolve.
        wt = exc_info.value.worktree_path
        _ecode, unmerged = b4.git_run_command(
            wt, ['diff', '--name-only', '--diff-filter=U'], rundir=wt
        )
        assert unmerged.strip()

    def test_git_without_retry_still_parks_conflict(self, gitdir: str) -> None:
        """Before git 2.46 there is no ``git am --retry`` to finish in place.

        Such a git starts the series over on the full tree. That runs the
        hooks again, but the user must still get a conflict they can resolve.
        """
        ambytes = _build_subdir_conflict(gitdir)

        with (
            patch('b4._touched_paths_from_am', return_value=set()),
            patch('b4.git_check_minimal_version', return_value=False),
        ):
            with pytest.raises(b4.AmConflictError) as exc_info:
                b4.git_fetch_am_into_repo(
                    gitdir, ambytes, at_base='HEAD', am_flags=['-3'], resolve=True
                )

        wt = exc_info.value.worktree_path
        _ecode, unmerged = b4.git_run_command(
            wt, ['diff', '--name-only', '--diff-filter=U'], rundir=wt
        )
        assert 'drivers/foo.txt' in unmerged

    def test_conflict_with_file_outside_sparse_set(
        self, gitdir: str, applied_log: Path
    ) -> None:
        """A patch that conflicts in one file keeps its other files' changes.

        One patch has a real conflict in a checked-out file and also touches
        a file the sparse checkout does not have. Whatever state the first
        attempt leaves, the user must be able to resolve the conflict and
        get the whole patch, with the hooks of earlier patches run once.
        """
        ambytes = _build_mixed_conflict(gitdir)

        with patch(
            'b4._touched_paths_from_am',
            return_value={'file2.txt', 'drivers/foo.txt'},
        ):
            with pytest.raises(b4.AmConflictError) as exc_info:
                b4.git_fetch_am_into_repo(
                    gitdir, ambytes, at_base='HEAD', am_flags=['-3'], resolve=True
                )
        assert applied_log.read_text().splitlines() == ['Patch 1: modify file2']

        def finish(worktree: str) -> None:
            with open(os.path.join(worktree, 'drivers', 'foo.txt'), 'w') as fh:
                fh.write('1\nRESOLVED\n3\n')
            b4.git_run_command(worktree, ['add', 'drivers/foo.txt'], rundir=worktree)
            ecode, _out = b4.git_run_command(
                worktree, ['am', '--continue'], rundir=worktree
            )
            assert ecode == 0

        with patch('b4._suspend_to_shell', side_effect=_resolve_in_shell(finish)):
            assert b4.resolve_am_conflict_in_shell(gitdir, exc_info.value)

        ecode, foo = b4.git_run_command(gitdir, ['show', 'FETCH_HEAD:drivers/foo.txt'])
        assert ecode == 0 and 'RESOLVED' in foo
        ecode, bar = b4.git_run_command(gitdir, ['show', 'FETCH_HEAD:drivers/bar.txt'])
        assert ecode == 0
        assert 'TEN-from-patch' in bar and 'THIRTEEN-master' in bar


@pytest.mark.parametrize(
    'has_retry',
    [
        pytest.param(True, id='am-retry'),
        # Before git 2.46 the series starts over on the full tree instead.
        pytest.param(False, id='start-over'),
    ],
)
def test_retried_patch_hook_sees_series_env(
    gitdir: str, tmp_path: Path, has_retry: bool
) -> None:
    """A patch applied on the second try gets the same hook environment.

    When the sparse checkout stops the am, the patch is applied by a second
    git am call on the full tree. Its hooks must see the series variables
    too, or a hook that records them would skip just that patch.
    """
    hooksdir = tmp_path / 'hooks'
    hooksdir.mkdir()
    record = tmp_path / 'urls.txt'
    hook = hooksdir / 'post-applypatch'
    hook.write_text(f'#!/bin/sh\necho "$B4_SERIES_URL" >> "{record}"\n')
    hook.chmod(0o755)
    b4.git_set_config(gitdir, 'core.hooksPath', str(hooksdir))
    ambytes = _build_subdir_clean_3way(gitdir)

    with ExitStack() as stack:
        # An empty sparse set makes the first attempt stop on the patch.
        stack.enter_context(patch('b4._touched_paths_from_am', return_value=set()))
        if not has_retry:
            stack.enter_context(
                patch('b4.git_check_minimal_version', return_value=False)
            )
        b4.git_fetch_am_into_repo(
            gitdir,
            ambytes,
            at_base='HEAD',
            am_flags=['-3'],
            resolve=True,
            extra_env={'B4_SERIES_URL': 'https://example.com/x'},
        )

    assert record.read_text().splitlines() == ['https://example.com/x']
