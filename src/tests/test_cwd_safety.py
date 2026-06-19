"""Regression tests for process-global ``os.chdir`` hazards.

b4's review TUI runs git operations in Textual worker threads, but several
helpers (``git_temp_worktree`` and ``_run_command(rundir=)``) historically
mutated the *process* working directory via ``os.chdir``.  Because
cwd is global to the whole process, a worker thread's chdir is visible to — and
clobbered by — every other thread.  This reliably crashed ``b4 review`` when a
``BaseSelectionScreen`` test-apply worker held the process cwd inside a throwaway
worktree while the main thread ran the checkout (reported by Mark Brown against a
78-patch ASoC series; FileNotFoundError restoring a since-deleted temp dir).

These tests pin the invariant that worktree/rundir operations must NOT move the
process cwd, while still addressing the right repository and worktree.
"""

import os
import pathlib
import threading

import pytest

import b4
from b4 import review


def _build_one_patch_series(gitdir: str) -> tuple[b4.LoreSeries, str]:
    """Build a 1-patch LoreSeries that modifies an existing tracked file.

    Modifying an *existing* file means the patch carries real ``index a..b``
    blob lines that resolve against the repo, which is what
    ``make_fake_am_range`` needs to synthesize its fake-am base tree.
    Returns ``(lser, base_commit)`` where ``base_commit`` still holds the old
    blob, so the series applies on top of it.
    """
    _ecode, base = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
    base = base.strip()

    b4.git_run_command(gitdir, ['checkout', '-b', 'cwd-fakeam'])
    with open(os.path.join(gitdir, 'file1.txt'), 'a') as fh:
        fh.write('Tweaked by cwd-safety fake-am test.\n')
    b4.git_run_command(gitdir, ['add', 'file1.txt'])
    b4.git_run_command(gitdir, ['commit', '-m', 'cwd-safety: tweak file1'])

    _ecode, mbox = b4.git_run_command(gitdir, ['format-patch', '-1', '--stdout'])

    b4.git_run_command(gitdir, ['checkout', 'master'])
    b4.git_run_command(gitdir, ['branch', '-D', 'cwd-fakeam'])

    msgs = b4.mailsplit_bytes(mbox.encode())
    # git format-patch doesn't emit a Message-Id here; LoreMailbox needs one.
    for idx, msg in enumerate(msgs):
        if not msg['Message-Id']:
            msg['Message-Id'] = f'<cwd-fakeam-{idx}@test.local>'
    lser = review._get_lore_series(msgs)
    return lser, base


class TestWorktreeCwdRace:
    """The process cwd must stay put while a worker uses a temp worktree."""

    def test_temp_worktree_in_thread_keeps_process_cwd_stable(
        self, gitdir: str
    ) -> None:
        """A worker thread inside ``git_temp_worktree`` must not move the cwd
        observed by the main thread.

        Reproduces the root cause of Mark Brown's crash: with chdir-based
        worktrees this fails because the worker's ``os.chdir`` into the temp
        worktree is global and visible on the main thread.
        """
        start_cwd = os.getcwd()
        entered = threading.Event()
        release = threading.Event()
        errors: list[Exception] = []

        def worker() -> None:
            try:
                with b4.git_temp_worktree(gitdir, 'HEAD'):
                    # Worktree is now open; on the buggy implementation the
                    # process cwd has just been chdir'd into the temp dir.
                    entered.set()
                    release.wait(timeout=10)
            except Exception as ex:  # pragma: no cover - surfaced via errors
                errors.append(ex)
                entered.set()

        t = threading.Thread(target=worker)
        t.start()
        try:
            assert entered.wait(timeout=10)
            observed = os.getcwd()
        finally:
            release.set()
            t.join(timeout=10)

        assert not errors, f'worker raised: {errors}'
        assert observed == start_cwd


class TestRunCommandRundir:
    """``_run_command(rundir=)`` must run the child elsewhere without chdir."""

    def test_rundir_does_not_call_chdir(
        self,
        gitdir: str,
        tmp_path: pathlib.Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Running a command with ``rundir`` set must not touch the process
        cwd at all — the child's directory is the subprocess's concern.

        Fails on the chdir-based implementation, which round-trips
        ``os.chdir(rundir)`` / ``os.chdir(curdir)``.
        """
        foreign = tmp_path / 'foreign'
        foreign.mkdir()
        os.chdir(foreign)

        chdir_calls: list[str] = []
        real_chdir = os.chdir

        def spy_chdir(path: str) -> None:
            chdir_calls.append(os.fspath(path))
            real_chdir(path)

        monkeypatch.setattr(os, 'chdir', spy_chdir)

        ecode, out, _err = b4._run_command(
            ['git', '--no-pager', 'rev-parse', '--show-toplevel'], rundir=gitdir
        )

        assert ecode == 0
        # The command really ran inside the repo, not the foreign cwd.
        assert os.path.realpath(out.decode().strip()) == os.path.realpath(gitdir)
        # ...and it did so without mutating the process cwd.
        assert chdir_calls == []
        assert os.path.realpath(os.getcwd()) == os.path.realpath(foreign)


class TestMakeFakeAmRangeNoChdir:
    """``make_fake_am_range`` is the worst offender (it had zero tests).

    Its temp worktree is the one that crashed for Mark Brown.  Pin that it
    produces a valid fake-am range *without* ever mutating the process cwd.
    """

    def test_make_fake_am_range_does_not_chdir(
        self, gitdir: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        lser, base = _build_one_patch_series(gitdir)
        start_cwd = os.getcwd()

        chdir_calls: list[str] = []
        real_chdir = os.chdir

        def spy_chdir(path: str) -> None:
            chdir_calls.append(os.fspath(path))
            real_chdir(path)

        monkeypatch.setattr(os, 'chdir', spy_chdir)

        start, end = lser.make_fake_am_range(gitdir=gitdir, at_base=base)

        # Correctness: a usable range was produced...
        assert start, 'make_fake_am_range produced no start commit'
        assert end, 'make_fake_am_range produced no end commit'
        assert b4.git_commit_exists(gitdir, start)
        assert b4.git_commit_exists(gitdir, end)
        # ...without ever moving the process cwd.
        assert chdir_calls == []
        assert os.path.realpath(os.getcwd()) == os.path.realpath(start_cwd)
