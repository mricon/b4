# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Arm Ltd.

import argparse
import json
import logging
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional
from unittest import mock

import pytest

import b4
import b4.command
from b4 import review
from b4.review import _review, batch
from b4.review import tracking as review_tracking

from .helpers.tracking import create_review_branch

MY_EMAIL = 'test-override@example.com'
AGENT_NAME = 'Review Agent'
AGENT_EMAIL = 'agent@example.com'

# Stands in for an agent CLI.  Logs what it was started with and where, then
# behaves as the mode argument says.
FAKE_AGENT = """\
import json
import os
import subprocess
import sys

mode, log, prompt = sys.argv[1], sys.argv[2], sys.argv[-1]


def git(*args):
    return subprocess.check_output(('git',) + args, text=True).strip()


branch = git('symbolic-ref', '--short', 'HEAD')
head = git('rev-parse', 'HEAD')
common_dir = git('rev-parse', '--path-format=absolute', '--git-common-dir')
review_root = os.path.join(common_dir, 'b4-review')
with open('file1.txt') as fh:
    file1 = fh.read()
run = {
    'branch': branch,
    'prompt': prompt,
    'toplevel': git('rev-parse', '--show-toplevel'),
    'status': git('status', '--porcelain=v1'),
    'file1': file1,
    'pending': sorted(
        name
        for name in os.listdir(review_root)
        if os.path.isdir(os.path.join(review_root, name))
    ),
    # What the repository says is checked out where, as b4 sees it
    'worktree_branches': [
        line.split(' ', 1)[1]
        for line in subprocess.check_output(
            ['git', '--git-dir', common_dir, 'worktree', 'list', '--porcelain'],
            text=True,
        ).splitlines()
        if line.startswith('branch ')
    ],
}
with open(log, 'a') as fh:
    fh.write(json.dumps(run) + '\\n')

if mode == 'silent' or os.environ.get('FAKE_AGENT_FAIL_ON') == branch:
    sys.exit(3 if mode != 'silent' else 0)
if mode == 'scribble':
    with open('file1.txt', 'a') as fh:
        fh.write('scribble\\n')
    with open('leftover.txt', 'w') as fh:
        fh.write('leftover\\n')

# What the sample prompt has an agent do
review_dir = os.path.join(review_root, head)
os.makedirs(review_dir, exist_ok=True)
with open(os.path.join(review_dir, 'identity.txt'), 'w') as fh:
    fh.write('Review Agent <agent@example.com>\\n')
if mode == 'unfinished':
    sys.exit(3)
with open(os.path.join(review_dir, 'series.txt'), 'w') as fh:
    fh.write('No issues found\\n')
if mode == 'failed':
    sys.exit(3)

# Things that happen to a series while an agent is looking at it
message = git('log', '-1', '--format=%B')
if mode == 'retrack':
    # Its tracking data is updated
    message = message.replace('"status": "reviewing"', '"status": "replied"')
    git('commit', '-q', '--amend', '--allow-empty', '-m', message)
if mode == 'restack':
    # It gets another patch
    git('reset', '-q', '--hard', 'HEAD~1')
    git('commit', '-q', '--allow-empty', '-m', 'One more patch')
    git('commit', '-q', '--allow-empty', '-m', message)
"""


def _agent_review(name: str = AGENT_NAME) -> Dict[str, Any]:
    return {
        'name': name,
        'source': 'agent',
        'source-revision': 1,
        'note': 'Looks fine',
    }


def _tracking(
    status: str = 'reviewing',
    series_reviews: Optional[Dict[str, Any]] = None,
    patch_reviews: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    series: Dict[str, Any] = {'status': status}
    if series_reviews is not None:
        series['reviews'] = series_reviews
    patch: Dict[str, Any] = {'title': 'patch 1'}
    if patch_reviews is not None:
        patch['reviews'] = patch_reviews
    return {'series': series, 'patches': [patch]}


def test_batch_parser_and_dispatch() -> None:
    parser = b4.command.setup_parser()
    cmdargs = parser.parse_args(
        ['review', 'batch', 'agent', '--agent-name', AGENT_NAME, '--dry-run']
    )

    assert cmdargs.review_subcmd == 'batch'
    assert cmdargs.batch_subcmd == 'agent'
    assert cmdargs.agent_name == AGENT_NAME
    assert cmdargs.dryrun is True

    with mock.patch('b4.review.batch.cmd_agent') as cmd_agent:
        review.main(cmdargs)

    cmd_agent.assert_called_once_with(cmdargs)

    # Only the sub-command that was asked for may run
    cmdargs.batch_subcmd = 'something-else'
    with mock.patch('b4.review.batch.cmd_agent') as cmd_agent:
        with pytest.raises(SystemExit):
            review.main(cmdargs)
    cmd_agent.assert_not_called()


class TestNeedsAgentReview:
    """Which stored reviews count as an agent having looked at a series."""

    @pytest.mark.parametrize(
        'entry,expected',
        [
            (_agent_review(), True),
            ({'name': 'x', 'source': 'other', 'note': 'n'}, False),
            # Without a recorded source nothing is guessed, so a series is
            # never quietly left out over a review that may be someone else's
            ({'name': AGENT_NAME, 'note': 'Looks fine'}, False),
            ({'name': AGENT_NAME, 'comments': [{'text': 'x'}]}, False),
        ],
    )
    def test_is_agent_review(self, entry: Dict[str, Any], expected: bool) -> None:
        assert batch._is_agent_review(entry, 1) is expected

    def test_series_without_reviews_needs_one(self) -> None:
        assert batch._needs_agent_review(_tracking(), None)

    @pytest.mark.parametrize('status', ['new', 'replied', 'snoozed', 'waiting'])
    def test_only_reviewing_series(self, status: str) -> None:
        assert not batch._needs_agent_review(_tracking(status), None)

    def test_review_on_series_or_any_patch_counts(self) -> None:
        reviews = {AGENT_EMAIL: _agent_review()}
        on_series = _tracking(series_reviews=reviews)
        on_patch = _tracking(patch_reviews=reviews)
        assert not batch._needs_agent_review(on_series, None)
        assert not batch._needs_agent_review(on_patch, None)

    def test_non_agent_reviews_do_not_count(self) -> None:
        tracking = _tracking(
            series_reviews={MY_EMAIL: {'name': 'Me', 'note': 'My own note'}},
            patch_reviews={
                'b4-upgrade@internal': {'name': 'B4 Upgrade', 'note': 'Unchanged'}
            },
        )
        assert batch._needs_agent_review(tracking, None)

    def test_review_of_an_earlier_revision_does_not_count(self) -> None:
        """An upgrade carries the reviews of unchanged patches over to the new
        revision, but no agent has looked at that revision yet."""
        tracking = _tracking(patch_reviews={AGENT_EMAIL: _agent_review()})
        tracking['series']['revision'] = 2
        assert batch._needs_agent_review(tracking, None)
        assert batch._needs_agent_review(tracking, AGENT_NAME)

    @pytest.mark.parametrize(
        'agent_name,expected',
        [
            (None, False),
            (AGENT_NAME, False),
            ('Other Agent', True),
            (AGENT_NAME.lower(), True),
        ],
    )
    def test_agent_name_must_match_exactly(
        self, agent_name: Optional[str], expected: bool
    ) -> None:
        tracking = _tracking(patch_reviews={AGENT_EMAIL: _agent_review()})
        assert batch._needs_agent_review(tracking, agent_name) is expected


class TestCmdAgent:
    @pytest.fixture
    def agent_log(self, gitdir: str, tmp_path: pathlib.Path) -> pathlib.Path:
        """Configure the fake agent; returns the log of its invocations."""
        log = tmp_path / 'agent.log'
        self._configure_agent(gitdir, tmp_path, log, 'review')
        return log

    @staticmethod
    def _configure_agent(
        gitdir: str, tmp_path: pathlib.Path, log: pathlib.Path, mode: str
    ) -> None:
        script = tmp_path / 'fake-agent.py'
        script.write_text(FAKE_AGENT)
        with open(os.path.join(gitdir, '.git', 'agent-reviewer.md'), 'w') as fh:
            fh.write('Review the series.\n')
        b4.MAIN_CONFIG['review-agent-command'] = (
            f'{sys.executable} {script} {mode} {log}'
        )
        b4.MAIN_CONFIG['review-agent-prompt-path'] = '.git/agent-reviewer.md'

    @staticmethod
    def _run(agent_name: Optional[str] = None, dryrun: bool = False) -> None:
        batch.cmd_agent(argparse.Namespace(agent_name=agent_name, dryrun=dryrun))

    @staticmethod
    def _invocations(log: pathlib.Path) -> List[Dict[str, Any]]:
        """Return what the fake agent logged about each of its runs."""
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    @classmethod
    def _branches(cls, log: pathlib.Path) -> List[str]:
        """Return the branches the fake agent was run on, in order."""
        return [run['branch'] for run in cls._invocations(log)]

    @staticmethod
    def _tip(gitdir: str, branch: str) -> str:
        ecode, out = b4.git_run_command(gitdir, ['rev-parse', branch])
        assert ecode == 0
        return out.strip()

    @staticmethod
    def _agent_note(gitdir: str, branch: str) -> Optional[Dict[str, Any]]:
        _cover, tracking = review.load_tracking(gitdir, branch)
        entry: Optional[Dict[str, Any]] = (
            tracking['series'].get('reviews', {}).get(AGENT_EMAIL)
        )
        return entry

    @staticmethod
    def _write_review(review_dir: str, note: str) -> None:
        """Put the files of a whole agent review in *review_dir*."""
        os.makedirs(review_dir)
        with open(os.path.join(review_dir, 'identity.txt'), 'w') as fh:
            fh.write(f'{AGENT_NAME} <{AGENT_EMAIL}>\n')
        with open(os.path.join(review_dir, 'series.txt'), 'w') as fh:
            fh.write(note + '\n')

    @staticmethod
    def _worktree(gitdir: str) -> str:
        """Return where the batch puts its worktree."""
        return os.path.join(gitdir, '.git', 'b4-agent-worktree')

    @classmethod
    def _assert_no_worktree(cls, gitdir: str) -> None:
        """Check that the batch worktree is gone, and that git agrees."""
        assert not os.path.lexists(cls._worktree(gitdir))
        ecode, out = b4.git_run_command(gitdir, ['worktree', 'list', '--porcelain'])
        assert ecode == 0
        worktrees = [line for line in out.splitlines() if line.startswith('worktree ')]
        assert worktrees == [f'worktree {gitdir}']

    def test_reviews_only_series_that_need_it(
        self, gitdir: str, agent_log: pathlib.Path
    ) -> None:
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        create_review_branch(
            gitdir,
            'done',
            with_patch=True,
            series_extra={'reviews': {AGENT_EMAIL: _agent_review()}},
        )
        create_review_branch(gitdir, 'replied', with_patch=True, status='replied')
        needs_tip = self._tip(gitdir, needs)
        done_tip = self._tip(gitdir, 'b4/review/done')

        self._run()

        runs = self._invocations(agent_log)
        assert [run['branch'] for run in runs] == [needs]
        # The series is checked out for the agent away from the main tree,
        # with no review files waiting for it
        assert runs[0]['toplevel'] == self._worktree(gitdir)
        assert runs[0]['status'] == ''
        assert runs[0]['pending'] == []
        # ...but is told that is where its review goes
        prompt = runs[0]['prompt']
        assert os.path.join(gitdir, '.git', 'agent-reviewer.md') in prompt
        assert review.get_agent_review_dir(gitdir, needs_tip) in prompt
        assert 'series.txt' in prompt

        entry = self._agent_note(gitdir, needs)
        assert entry == {
            'name': AGENT_NAME,
            'source': 'agent',
            'source-revision': 1,
            'note': 'No issues found',
        }
        assert self._tip(gitdir, 'b4/review/done') == done_tip
        # The review is stored, with nothing left of how it got there
        assert os.listdir(os.path.join(gitdir, '.git', 'b4-review')) == [
            'agent-batch.lock'
        ]
        self._assert_no_worktree(gitdir)
        assert b4.git_get_current_branch(gitdir) == 'master'

        # Nothing is left to do, so a second run starts no agent
        self._run()
        assert len(self._invocations(agent_log)) == 1

    @pytest.mark.parametrize(
        'command_key', ['review-agent-command', 'review-agent-batch-command']
    )
    def test_review_directory_substitution_with_a_wrapper(
        self,
        gitdir: str,
        tmp_path: pathlib.Path,
        command_key: str,
    ) -> None:
        # Expanded paths must stay a single argument even when unquoted in
        # the template and when the repository path contains spaces.
        moved = tmp_path / 'repository with spaces'
        os.rename(gitdir, moved)
        os.chdir(moved)
        gitdir = str(moved)
        log = tmp_path / 'agent.log'
        self._configure_agent(gitdir, tmp_path, log, 'review')
        wrapper = tmp_path / 'agent wrapper.py'
        wrapper.write_text(
            'import os, runpy, subprocess, sys\n'
            'assert len(sys.argv) == 5, sys.argv\n'
            'assert sys.argv[1] == "--write-dir"\n'
            'assert sys.argv[3] == "--"\n'
            'head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()\n'
            'common = subprocess.check_output(["git", "rev-parse", '
            '"--path-format=absolute", "--git-common-dir"], text=True).strip()\n'
            'expected = os.path.join(common, "b4-review", head)\n'
            'assert sys.argv[2] == expected, sys.argv\n'
            'assert os.path.isdir(expected), expected\n'
            'assert os.listdir(expected) == []\n'
            'assert expected in sys.argv[4]\n'
            f'sys.argv = [{str(tmp_path / "fake-agent.py")!r}, "review", '
            f'{str(log)!r}, sys.argv[4]]\n'
            'runpy.run_path(sys.argv[0], run_name="__main__")\n'
        )
        b4.MAIN_CONFIG[command_key] = (
            shlex.join([sys.executable, str(wrapper)]) + ' --write-dir {review_dir} --'
        )
        first = create_review_branch(gitdir, 'a-first', with_patch=True)
        second = create_review_branch(gitdir, 'b-second', with_patch=True)
        tips = [self._tip(gitdir, branch) for branch in (first, second)]

        self._run()

        runs = self._invocations(log)
        assert [run['branch'] for run in runs] == [first, second]
        assert [run['pending'] for run in runs] == [[tip] for tip in tips]
        for branch in (first, second):
            entry = self._agent_note(gitdir, branch)
            assert entry is not None
            assert entry['note'] == 'No issues found'
        self._assert_no_worktree(gitdir)

    def test_branch_under_review_is_checked_out(
        self, gitdir: str, agent_log: pathlib.Path
    ) -> None:
        """While the agent works on a branch, the rest of b4 and git must see
        it as checked out, so that nothing rewrites or deletes it underneath
        the agent (b4.git_branch_checked_out() asks `git worktree list`)."""
        needs = create_review_branch(gitdir, 'needs', with_patch=True)

        self._run()

        runs = self._invocations(agent_log)
        assert [run['branch'] for run in runs] == [needs]
        assert f'refs/heads/{needs}' in runs[0]['worktree_branches']
        self._assert_no_worktree(gitdir)

    def test_dry_run_lists_without_running(
        self, gitdir: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        # No agent is configured: a dry run does not need one
        needs = create_review_branch(gitdir, 'needs', subject='Needs a review')
        create_review_branch(gitdir, 'replied', status='replied')
        tip = self._tip(gitdir, needs)

        # Building the branches logged their names too
        caplog.clear()
        with caplog.at_level(logging.INFO, logger='b4'):
            self._run(dryrun=True)

        assert f'{needs} (v1): Needs a review' in caplog.text
        assert 'b4/review/replied' not in caplog.text
        assert self._tip(gitdir, needs) == tip
        assert not os.path.exists(os.path.join(gitdir, '.git', 'b4-review'))
        self._assert_no_worktree(gitdir)

    def test_leaves_the_working_tree_alone(
        self, gitdir: str, agent_log: pathlib.Path
    ) -> None:
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        # Work in progress of every kind: staged, unstaged and untracked
        with open(os.path.join(gitdir, 'file2.txt'), 'a') as fh:
            fh.write('staged work\n')
        ecode, _out = b4.git_run_command(gitdir, ['add', 'file2.txt'], rundir=gitdir)
        assert ecode == 0
        with open(os.path.join(gitdir, 'file1.txt'), 'a') as fh:
            fh.write('work in progress\n')
        with open(os.path.join(gitdir, 'notes.txt'), 'w') as fh:
            fh.write('untracked work\n')

        def _status() -> str:
            ecode, out = b4.git_run_command(
                gitdir, ['status', '--porcelain=v1'], rundir=gitdir
            )
            assert ecode == 0
            return out

        before = _status()
        assert before.splitlines() == [' M file1.txt', 'M  file2.txt', '?? notes.txt']

        self._run()

        # The agent was shown the series and none of that
        runs = self._invocations(agent_log)
        assert [run['branch'] for run in runs] == [needs]
        assert runs[0]['status'] == ''
        assert 'work in progress' not in runs[0]['file1']
        assert self._agent_note(gitdir, needs) is not None
        # ...and all of it is still there
        assert _status() == before
        with open(os.path.join(gitdir, 'file1.txt')) as fh:
            assert fh.read().endswith('work in progress\n')
        assert b4.git_get_current_branch(gitdir) == 'master'
        self._assert_no_worktree(gitdir)

    def test_failure_does_not_stop_the_batch(
        self,
        gitdir: str,
        agent_log: pathlib.Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        broken = create_review_branch(gitdir, 'a-broken', with_patch=True)
        works = create_review_branch(gitdir, 'b-works', with_patch=True)
        monkeypatch.setenv('FAKE_AGENT_FAIL_ON', broken)

        with pytest.raises(SystemExit) as exc:
            self._run()

        assert exc.value.code == 1
        assert self._branches(agent_log) == [broken, works]
        assert f'Agent review failed for {broken}' in caplog.text
        assert 'agent exited with code 3' in caplog.text
        assert self._agent_note(gitdir, broken) is None
        assert self._agent_note(gitdir, works) is not None
        self._assert_no_worktree(gitdir)

        # The failed series is picked up again by the next run
        monkeypatch.delenv('FAKE_AGENT_FAIL_ON')
        self._run()
        assert self._branches(agent_log) == [broken, works, broken]
        assert self._agent_note(gitdir, broken) is not None

    @pytest.mark.parametrize('substitute', [False, True])
    def test_no_review_data_is_a_failure(
        self,
        gitdir: str,
        tmp_path: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
        substitute: bool,
    ) -> None:
        log = tmp_path / 'agent.log'
        self._configure_agent(gitdir, tmp_path, log, 'silent')
        if substitute:
            b4.MAIN_CONFIG['review-agent-command'] = (
                f'{b4.MAIN_CONFIG["review-agent-command"]} {{review_dir}}'
            )
        needs = create_review_branch(gitdir, 'needs', with_patch=True)

        with pytest.raises(SystemExit) as exc:
            self._run()

        assert exc.value.code == 1
        assert 'agent produced no review data' in caplog.text
        assert len(self._invocations(log)) == 1
        _cover, tracking = review.load_tracking(gitdir, needs)
        assert batch._needs_agent_review(tracking, None)
        assert os.listdir(os.path.join(gitdir, '.git', 'b4-review')) == [
            'agent-batch.lock'
        ]
        self._assert_no_worktree(gitdir)

    def test_review_directory_creation_failure_does_not_start_agent(
        self,
        gitdir: str,
        agent_log: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        b4.MAIN_CONFIG['review-agent-command'] = (
            f'{b4.MAIN_CONFIG["review-agent-command"]} {{review_dir}}'
        )
        broken = create_review_branch(gitdir, 'a-broken', with_patch=True)
        works = create_review_branch(gitdir, 'b-works', with_patch=True)
        review_dir = review.get_agent_review_dir(gitdir, self._tip(gitdir, broken))
        makedirs = os.makedirs

        def _makedirs(path: str, *args: Any, **kwargs: Any) -> None:
            if path == review_dir:
                raise PermissionError('Cannot create review output')
            makedirs(path, *args, **kwargs)

        with mock.patch('b4.review.batch.os.makedirs', side_effect=_makedirs):
            with pytest.raises(SystemExit) as exc:
                self._run()

        assert exc.value.code == 1
        assert 'could not create the agent review directory' in caplog.text
        assert self._branches(agent_log) == [works]
        assert self._agent_note(gitdir, broken) is None
        assert self._agent_note(gitdir, works) is not None
        self._assert_no_worktree(gitdir)

    def test_unsaved_review_is_kept_for_the_next_run(
        self,
        gitdir: str,
        agent_log: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A review that was paid for but could not be stored fails the series,
        and the next run stores it without starting the agent again."""
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        tip = self._tip(gitdir, needs)

        with mock.patch.object(_review, 'save_tracking_ref', return_value=False):
            with pytest.raises(SystemExit) as exc:
                self._run()

        assert exc.value.code == 1
        assert 'Unable to save agent reviews' in caplog.text
        assert self._agent_note(gitdir, needs) is None
        assert os.path.isdir(review.get_agent_review_dir(gitdir, tip))

        self._run()

        assert self._branches(agent_log) == [needs]
        entry = self._agent_note(gitdir, needs)
        assert entry is not None
        assert entry['note'] == 'No issues found'

    def test_imports_review_files_from_earlier_run(
        self, gitdir: str, agent_log: pathlib.Path
    ) -> None:
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        review_dir = os.path.join(gitdir, '.git', 'b4-review', self._tip(gitdir, needs))
        self._write_review(review_dir, 'Left by an earlier run')

        self._run()

        assert self._invocations(agent_log) == []
        entry = self._agent_note(gitdir, needs)
        assert entry is not None
        assert entry['note'] == 'Left by an earlier run'
        assert not os.path.exists(review_dir)

    @pytest.mark.parametrize('identity', [None, 'Missing email address'])
    def test_clears_rejected_review_files_before_starting_agent(
        self,
        gitdir: str,
        tmp_path: pathlib.Path,
        identity: Optional[str],
    ) -> None:
        log = tmp_path / 'agent.log'
        self._configure_agent(gitdir, tmp_path, log, 'review')
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        review_dir = pathlib.Path(
            review.get_agent_review_dir(gitdir, self._tip(gitdir, needs))
        )
        review_dir.mkdir(parents=True)
        if identity is not None:
            (review_dir / 'identity.txt').write_text(identity)
        (review_dir / '0001.txt').write_text('Stale finding from an earlier run\n')

        self._run()

        # The fresh agent writes only a series summary. The rejected patch
        # note must not be imported under its identity.
        assert self._branches(log) == [needs]
        entry = self._agent_note(gitdir, needs)
        assert entry is not None
        assert entry['note'] == 'No issues found'
        _cover, tracking = review.load_tracking(gitdir, needs)
        assert 'reviews' not in tracking['patches'][0]
        assert not review_dir.exists()

    def test_review_cleanup_failure_does_not_start_agent(
        self,
        gitdir: str,
        agent_log: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        broken = create_review_branch(gitdir, 'a-broken', with_patch=True)
        works = create_review_branch(gitdir, 'b-works', with_patch=True)
        review_dir = review.get_agent_review_dir(gitdir, self._tip(gitdir, broken))
        os.makedirs(review_dir)
        with open(os.path.join(review_dir, '0001.txt'), 'w') as fh:
            fh.write('Stale finding\n')
        rmtree = shutil.rmtree

        def _rmtree(path: str, *args: Any, **kwargs: Any) -> None:
            if path == review_dir:
                raise PermissionError('Cannot remove old review')
            rmtree(path, *args, **kwargs)

        with mock.patch('b4.review.batch.shutil.rmtree', side_effect=_rmtree):
            with pytest.raises(SystemExit) as exc:
                self._run()

        assert exc.value.code == 1
        assert 'could not clean the agent review directory' in caplog.text
        assert self._branches(agent_log) == [works]
        assert self._agent_note(gitdir, broken) is None
        assert self._agent_note(gitdir, works) is not None
        self._assert_no_worktree(gitdir)

    def test_agent_name_only_skips_that_agent(
        self,
        gitdir: str,
        agent_log: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        other = create_review_branch(
            gitdir,
            'other-agent',
            with_patch=True,
            series_extra={
                'reviews': {'other@example.com': _agent_review('Other Agent')}
            },
        )

        # Any agent review is enough by default
        self._run()
        assert self._invocations(agent_log) == []

        self._run(agent_name=AGENT_NAME)
        assert self._branches(agent_log) == [other]
        _cover, tracking = review.load_tracking(gitdir, other)
        assert set(tracking['series']['reviews']) == {
            'other@example.com',
            AGENT_EMAIL,
        }

        # Now it has a review under that name too
        self._run(agent_name=AGENT_NAME)
        assert len(self._invocations(agent_log)) == 1

        # The configured agent does not change with the name, so asking for
        # one it never writes reviews as keeps selecting the series
        with caplog.at_level(logging.WARNING, logger='b4'):
            self._run(agent_name='Third Agent')
        assert len(self._invocations(agent_log)) == 2
        assert 'will select it again' in caplog.text

    def test_rejects_empty_agent_name(
        self, gitdir: str, agent_log: pathlib.Path
    ) -> None:
        create_review_branch(gitdir, 'needs', with_patch=True)

        with pytest.raises(SystemExit) as exc:
            self._run(agent_name='')

        assert exc.value.code == 1
        assert self._invocations(agent_log) == []

    def test_requires_agent_configuration(self, gitdir: str) -> None:
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        tip = self._tip(gitdir, needs)

        with pytest.raises(SystemExit) as exc:
            self._run()

        assert exc.value.code == 1
        assert self._tip(gitdir, needs) == tip

    @pytest.mark.parametrize('interactive_configured', [False, True])
    def test_uses_batch_command_override(
        self,
        gitdir: str,
        tmp_path: pathlib.Path,
        agent_log: pathlib.Path,
        interactive_configured: bool,
    ) -> None:
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        b4.MAIN_CONFIG['review-agent-batch-command'] = b4.MAIN_CONFIG.pop(
            'review-agent-command'
        )
        if interactive_configured:
            b4.MAIN_CONFIG['review-agent-command'] = str(
                tmp_path / 'interactive-agent-must-not-run'
            )

        self._run()

        assert self._branches(agent_log) == [needs]
        entry = self._agent_note(gitdir, needs)
        assert entry is not None
        assert entry['note'] == 'No issues found'

    @pytest.mark.parametrize(
        'command', ['', '   ', 'agent "unterminated', ['agent', 'another-agent']]
    )
    def test_invalid_batch_command_does_not_fall_back(
        self,
        gitdir: str,
        agent_log: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
        command: Any,
    ) -> None:
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        b4.MAIN_CONFIG['review-agent-batch-command'] = command

        with pytest.raises(SystemExit) as exc:
            self._run()

        assert exc.value.code == 1
        assert 'b4.review-agent-batch-command' in caplog.text
        assert self._invocations(agent_log) == []
        assert self._agent_note(gitdir, needs) is None

    def test_agent_changes_do_not_reach_the_next_series(
        self,
        gitdir: str,
        tmp_path: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        log = tmp_path / 'agent.log'
        self._configure_agent(gitdir, tmp_path, log, 'scribble')
        first = create_review_branch(gitdir, 'a-first', with_patch=True)
        second = create_review_branch(gitdir, 'b-second', with_patch=True)

        with caplog.at_level(logging.WARNING, logger='b4'):
            self._run()

        # Both series are reviewed, the second from as clean a checkout as
        # the first: neither the change nor the new file is there
        runs = self._invocations(log)
        assert [run['branch'] for run in runs] == [first, second]
        assert [run['status'] for run in runs] == ['', '']
        assert 'scribble' not in runs[1]['file1']
        assert f'changed files in the review worktree while reviewing {first}' in (
            caplog.text
        )
        assert self._agent_note(gitdir, first) is not None
        assert self._agent_note(gitdir, second) is not None
        # None of it gets anywhere near the main tree either
        ecode, out = b4.git_run_command(
            gitdir, ['status', '--porcelain=v1'], rundir=gitdir
        )
        assert ecode == 0
        assert out == ''
        self._assert_no_worktree(gitdir)

    def test_keeps_tracking_changes_made_during_review(
        self, gitdir: str, tmp_path: pathlib.Path
    ) -> None:
        log = tmp_path / 'agent.log'
        self._configure_agent(gitdir, tmp_path, log, 'retrack')
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        tip = self._tip(gitdir, needs)

        self._run()

        # The review was written for a tracking commit that is no longer
        # the tip of the branch, and is stored on top of the one that is
        assert self._branches(log) == [needs]
        assert self._tip(gitdir, needs) != tip
        _cover, tracking = review.load_tracking(gitdir, needs)
        assert tracking['series']['status'] == 'replied'
        assert tracking['series']['reviews'][AGENT_EMAIL]['note'] == 'No issues found'
        assert os.listdir(os.path.join(gitdir, '.git', 'b4-review')) == [
            'agent-batch.lock'
        ]

    @pytest.mark.parametrize('always', [False, True])
    def test_keeps_tracking_changes_made_while_storing(
        self,
        gitdir: str,
        agent_log: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
        always: bool,
    ) -> None:
        """The tracking data can change between the batch loading it and
        saving the review on top (e.g. a save from the TUI).  That change
        must survive, and the review is stored on top of it; a branch that
        never holds still fails the series, keeping the review for later."""
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        real_save = _review.save_tracking_ref
        races: List[int] = []

        def _save(topdir: str, branch: str, *args: Any, **kwargs: Any) -> bool:
            if always or not races:
                races.append(len(races))
                cover, tracking = review.load_tracking(topdir, branch)
                tracking['series']['concurrent'] = len(races)
                assert real_save(topdir, branch, cover, tracking)
            return real_save(topdir, branch, *args, **kwargs)

        with mock.patch.object(_review, 'save_tracking_ref', side_effect=_save):
            if always:
                with pytest.raises(SystemExit):
                    self._run()
            else:
                self._run()

        assert self._branches(agent_log) == [needs]
        _cover, tracking = review.load_tracking(gitdir, needs)
        assert tracking['series']['concurrent'] == len(races)
        if always:
            assert 'kept changing while the review was stored' in caplog.text
            assert self._agent_note(gitdir, needs) is None
            assert os.path.isdir(
                review.get_agent_review_dir(gitdir, self._tip(gitdir, needs))
            )
        else:
            assert tracking['series']['reviews'][AGENT_EMAIL]['note'] == (
                'No issues found'
            )

    def test_drops_review_of_series_that_changed(
        self,
        gitdir: str,
        tmp_path: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        log = tmp_path / 'agent.log'
        self._configure_agent(gitdir, tmp_path, log, 'restack')
        needs = create_review_branch(gitdir, 'needs', with_patch=True)

        with pytest.raises(SystemExit) as exc:
            self._run()

        assert exc.value.code == 1
        assert 'the series changed while it was being reviewed' in caplog.text
        assert self._agent_note(gitdir, needs) is None
        # The review is not kept for a later run to find either
        assert os.listdir(os.path.join(gitdir, '.git', 'b4-review')) == [
            'agent-batch.lock'
        ]
        self._assert_no_worktree(gitdir)

    @pytest.mark.parametrize('mode', ['unfinished', 'failed'])
    def test_unfinished_review_is_not_imported(
        self,
        gitdir: str,
        tmp_path: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
        mode: str,
    ) -> None:
        log = tmp_path / 'agent.log'
        self._configure_agent(gitdir, tmp_path, log, mode)
        first = create_review_branch(gitdir, 'a-first', with_patch=True)
        second = create_review_branch(gitdir, 'b-second', with_patch=True)

        with pytest.raises(SystemExit) as exc:
            self._run()

        # An agent that gives up half way has reviewed nothing, and what it
        # did write is gone by the time the next one starts
        assert exc.value.code == 1
        assert caplog.text.count('agent exited with code 3') >= 2
        runs = self._invocations(log)
        assert [run['branch'] for run in runs] == [first, second]
        assert [run['pending'] for run in runs] == [[], []]
        _cover, tracking = review.load_tracking(gitdir, first)
        assert 'reviews' not in tracking['series']

    def test_interrupted_review_is_not_imported(
        self, gitdir: str, agent_log: pathlib.Path
    ) -> None:
        """Files an agent wrote before it was interrupted are not a review:
        importing them later would pass half a review off as a whole one."""
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        review_dir = review.get_agent_review_dir(gitdir, self._tip(gitdir, needs))
        marker = pathlib.Path(gitdir, '.git', 'b4-review', 'agent-batch.unfinished')
        marked: List[Optional[str]] = []

        def interrupted(*args: Any, **kwargs: Any) -> None:
            # Nobody is there to answer an agent that asks a question
            assert kwargs['stdin'] is subprocess.DEVNULL
            self._write_review(review_dir, 'Half a review')
            # A batch that is killed here cannot clean up after itself, so
            # the next one has to be able to tell what was left unfinished
            marked.append(marker.read_text().strip() if marker.exists() else None)
            raise KeyboardInterrupt

        with mock.patch('b4.review.batch.subprocess.run', side_effect=interrupted):
            with pytest.raises(SystemExit) as exc:
                self._run()

        assert exc.value.code == 130
        assert marked == [os.path.basename(review_dir)]
        assert not os.path.exists(review_dir)
        assert not marker.exists()

        self._run()
        assert self._branches(agent_log) == [needs]
        entry = self._agent_note(gitdir, needs)
        assert entry is not None
        assert entry['note'] == 'No issues found'

    def test_review_of_killed_batch_is_not_imported(
        self, gitdir: str, agent_log: pathlib.Path
    ) -> None:
        """A batch that was killed outright leaves the files of the review it
        was waiting for; the next batch must review that series afresh."""
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        review_dir = review.get_agent_review_dir(gitdir, self._tip(gitdir, needs))
        self._write_review(review_dir, 'Half a review')
        marker = pathlib.Path(gitdir, '.git', 'b4-review', 'agent-batch.unfinished')
        marker.write_text(os.path.basename(review_dir) + '\n')

        self._run()

        assert self._branches(agent_log) == [needs]
        entry = self._agent_note(gitdir, needs)
        assert entry is not None
        assert entry['note'] == 'No issues found'
        assert not marker.exists()

    def test_reviews_an_upgraded_series_again(
        self, gitdir: str, agent_log: pathlib.Path
    ) -> None:
        """The agent review an upgrade carried over on an unchanged patch does
        not stand for a review of the new revision."""
        upgraded = create_review_branch(gitdir, 'upgraded', with_patch=True, revision=2)
        cover, tracking = review.load_tracking(gitdir, upgraded)
        tracking['patches'][0]['reviews'] = {AGENT_EMAIL: _agent_review()}
        assert review.save_tracking_ref(gitdir, upgraded, cover, tracking)

        self._run()

        assert self._branches(agent_log) == [upgraded]
        entry = self._agent_note(gitdir, upgraded)
        assert entry is not None
        assert entry['source-revision'] == 2

        self._run()
        assert len(self._invocations(agent_log)) == 1

    def test_skips_series_with_a_newer_revision(
        self,
        gitdir: str,
        agent_log: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A review of a revision that is about to be replaced is paid for
        and then thrown away by the upgrade."""
        stale = create_review_branch(gitdir, 'stale', with_patch=True)
        current = create_review_branch(gitdir, 'current', with_patch=True)
        conn = review_tracking.init_db('test-project')
        review_tracking.add_revision(conn, 'stale', 1, 'stale-v1@example.com')
        review_tracking.add_revision(conn, 'stale', 2, 'stale-v2@example.com')
        review_tracking.add_revision(conn, 'current', 1, 'current-v1@example.com')
        conn.close()

        with caplog.at_level(logging.INFO):
            self._run()

        assert self._branches(agent_log) == [current]
        assert f'Skipping {stale}: v2 is available' in caplog.text

    def test_summary_counts_skipped_series(
        self,
        gitdir: str,
        agent_log: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A series that stopped needing a review while the batch ran must
        show in the summary, or the numbers do not add up."""
        replied = create_review_branch(gitdir, 'replied', with_patch=True)
        cover, tracking = review.load_tracking(gitdir, replied)
        candidates = batch._find_candidates(gitdir, None)
        tracking['series']['status'] = 'replied'
        assert review.save_tracking_ref(gitdir, replied, cover, tracking)

        with (
            mock.patch.object(batch, '_find_candidates', return_value=candidates),
            caplog.at_level(logging.INFO),
        ):
            self._run()

        assert self._invocations(agent_log) == []
        assert '0 completed, 0 imported from earlier runs, 1 skipped, 0 failed' in (
            caplog.text
        )

    def test_review_replaces_stale_files_at_the_new_tip(self, gitdir: str) -> None:
        """A review is filed under the tip it is stored on.  Files already
        there are not part of it and must not keep it from being stored."""
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        tip = self._tip(gitdir, needs)
        _cover, tracking = review.load_tracking(gitdir, needs)
        commit_shas = batch._patch_commits(gitdir, tip, tracking['series'])
        review_dir = review.get_agent_review_dir(gitdir, '0' * 40)
        self._write_review(review_dir, 'Fresh review')
        stale_dir = review.get_agent_review_dir(gitdir, tip)
        os.makedirs(stale_dir)
        pathlib.Path(stale_dir, '0001.txt').write_text('Stale note\n')

        assert batch._store_review(gitdir, needs, review_dir, commit_shas)

        entry = self._agent_note(gitdir, needs)
        assert entry is not None
        assert entry['note'] == 'Fresh review'
        _cover, tracking = review.load_tracking(gitdir, needs)
        assert 'reviews' not in tracking['patches'][0]
        assert not os.path.exists(review_dir)
        assert not os.path.exists(stale_dir)

    def test_review_of_a_deleted_branch_is_removed(self, gitdir: str) -> None:
        """Nothing will ever look for the review of a branch that is gone."""
        review_dir = review.get_agent_review_dir(gitdir, '0' * 40)
        self._write_review(review_dir, 'Nobody wants this')

        with pytest.raises(batch._AgentFailure, match='went away'):
            batch._store_review(gitdir, 'b4/review/gone', review_dir, [])

        assert not os.path.exists(review_dir)

    def test_stops_when_agent_cannot_be_started(
        self,
        gitdir: str,
        tmp_path: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        with open(os.path.join(gitdir, '.git', 'agent-reviewer.md'), 'w') as fh:
            fh.write('Review the series.\n')
        b4.MAIN_CONFIG['review-agent-command'] = str(tmp_path / 'no-such-agent')
        b4.MAIN_CONFIG['review-agent-prompt-path'] = '.git/agent-reviewer.md'
        create_review_branch(gitdir, 'a-first', with_patch=True)
        create_review_branch(gitdir, 'b-second', with_patch=True)

        with pytest.raises(SystemExit) as exc:
            self._run()

        assert exc.value.code == 1
        assert caplog.text.count('Could not start the review agent') == 1
        self._assert_no_worktree(gitdir)

    def test_branch_checked_out_elsewhere_fails_alone(
        self,
        gitdir: str,
        agent_log: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        other = create_review_branch(gitdir, 'b-other', with_patch=True)
        mine = create_review_branch(gitdir, 'a-mine', with_patch=True, checkout=True)
        assert b4.git_get_current_branch(gitdir) == mine

        with pytest.raises(SystemExit) as exc:
            self._run()

        # Git does not hand out a branch that somebody is on, which is no
        # reason not to review the others
        assert exc.value.code == 1
        assert f'Agent review failed for {mine}' in caplog.text
        assert 'could not check out the branch' in caplog.text
        assert self._branches(agent_log) == [other]
        assert self._agent_note(gitdir, mine) is None
        assert self._agent_note(gitdir, other) is not None
        assert b4.git_get_current_branch(gitdir) == mine
        self._assert_no_worktree(gitdir)

    @pytest.mark.parametrize('linked', [False, True])
    def test_replaces_worktree_left_by_interrupted_batch(
        self, gitdir: str, agent_log: pathlib.Path, linked: bool
    ) -> None:
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        # A batch that was killed leaves its worktree behind, complete with
        # whatever the agent did there...
        stale = self._worktree(gitdir)
        if linked:
            # ...still registered with git
            ecode, _out = b4.git_run_command(gitdir, ['worktree', 'add', stale, needs])
            assert ecode == 0
        else:
            # ...or a plain directory git has no record of
            os.makedirs(stale)
        with open(os.path.join(stale, 'leftover.txt'), 'w') as fh:
            fh.write('leftover\n')

        self._run()

        runs = self._invocations(agent_log)
        assert [run['branch'] for run in runs] == [needs]
        assert runs[0]['status'] == ''
        assert runs[0]['pending'] == []
        entry = self._agent_note(gitdir, needs)
        assert entry is not None
        assert entry['note'] == 'No issues found'
        self._assert_no_worktree(gitdir)

    def test_replaces_worktree_that_was_deleted_by_hand(
        self, gitdir: str, agent_log: pathlib.Path
    ) -> None:
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        # Git still has the worktree down as holding the branch
        stale = self._worktree(gitdir)
        ecode, _out = b4.git_run_command(gitdir, ['worktree', 'add', stale, needs])
        assert ecode == 0
        shutil.rmtree(stale)

        self._run()

        assert self._branches(agent_log) == [needs]
        assert self._agent_note(gitdir, needs) is not None
        self._assert_no_worktree(gitdir)

    def test_only_one_batch_at_a_time(
        self,
        gitdir: str,
        agent_log: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        create_review_branch(gitdir, 'needs', with_patch=True)
        # Another batch is in the middle of a review
        running = self._worktree(gitdir)
        os.makedirs(running)
        lock = os.path.join(gitdir, '.git', 'b4-review', 'agent-batch.lock')

        with b4.lockfile_nb(lock):
            with pytest.raises(SystemExit) as exc:
                self._run()

        assert exc.value.code == 1
        assert 'Another batch of agent reviews is running' in caplog.text
        assert self._invocations(agent_log) == []
        # Its worktree is not ours to take away
        assert os.path.isdir(running)

    def test_runs_from_a_subdirectory(
        self, gitdir: str, agent_log: pathlib.Path
    ) -> None:
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        subdir = os.path.join(gitdir, 'subdir')
        os.mkdir(subdir)
        os.chdir(subdir)

        self._run()

        runs = self._invocations(agent_log)
        assert [run['branch'] for run in runs] == [needs]
        assert runs[0]['toplevel'] == self._worktree(gitdir)
        assert self._agent_note(gitdir, needs) is not None
        assert b4.git_get_current_branch(gitdir) == 'master'
        # Nothing was checked out into the subdirectory
        assert os.listdir(subdir) == []
        self._assert_no_worktree(gitdir)

    def test_runs_from_a_linked_worktree(
        self, gitdir: str, tmp_path: pathlib.Path, agent_log: pathlib.Path
    ) -> None:
        needs = create_review_branch(gitdir, 'needs', with_patch=True)
        # The prompt path is relative to the top of the tree b4 is run in,
        # and there is no .git directory to keep it in here
        prompt_path = tmp_path / 'agent-reviewer.md'
        prompt_path.write_text('Review the series.\n')
        b4.MAIN_CONFIG['review-agent-prompt-path'] = str(prompt_path)
        linked = str(tmp_path / 'linked')
        ecode, _out = b4.git_run_command(
            gitdir, ['worktree', 'add', '--detach', linked, 'master']
        )
        assert ecode == 0
        os.chdir(linked)

        self._run()

        # The batch worktree is where it always is, in the git directory
        # all the worktrees share, and so is the review on its way through
        runs = self._invocations(agent_log)
        assert [run['branch'] for run in runs] == [needs]
        assert runs[0]['toplevel'] == self._worktree(gitdir)
        assert self._agent_note(gitdir, needs) is not None
        assert os.listdir(os.path.join(gitdir, '.git', 'b4-review')) == [
            'agent-batch.lock'
        ]
        assert not os.path.lexists(self._worktree(gitdir))
        assert os.path.isdir(linked)
