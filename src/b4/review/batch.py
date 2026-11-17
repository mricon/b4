#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Arm Ltd.
#
"""Non-interactive batch operations on review branches.

``b4 review batch agent`` runs the review agent, unattended, on every
reviewing series that has no agent review yet.  Agent runs are slow, so
they happen in a worktree of the batch's own, leaving the user's tree free.
"""

import argparse
import contextlib
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple

import b4
import b4.review
import b4.review.tracking

logger = b4.logger

# Temporary branches (e.g. revision upgrade work branches) are not series.
_TMP_BRANCH_PREFIX = f'{b4.review.REVIEW_BRANCH_PREFIX}_tmp-'
# Both live in the common git dir: the worktree, and the lock that guards it.
_WORKTREE_NAME = 'b4-agent-worktree'
_LOCK_NAME = 'agent-batch.lock'
# Next to the lock: names the review directory of the agent that is running.
_UNFINISHED_NAME = 'agent-batch.unfinished'
# A save only loses to another save made at the same time; a few tries do.
_STORE_ATTEMPTS = 3

# Unlike the TUI's prompt, this insists on a series.txt: without a stored
# review, a series that had no issues would be picked again by every run.
_AGENT_PROMPT = (
    'Read and execute the prompt from {prompt_path}. '
    'This is an unattended batch run, so do not ask questions or wait for '
    'input. Write the review files to {review_dir}. '
    'Always write identity.txt and series.txt: '
    'if you find no issues, series.txt must still contain a one-line summary '
    'saying so.'
)


class _AgentFailure(Exception):
    """The agent review of one series did not produce a usable result."""


class _BatchAbort(Exception):
    """Something is wrong that would affect every remaining series."""


class _Candidate(NamedTuple):
    branch: str
    revision: Any
    subject: str


def _is_agent_review(entry: Dict[str, Any], revision: Any) -> bool:
    """Tell whether a stored review entry is an agent's review of *revision*.

    Only the ``source`` that agent imports record counts: guessing from
    older entries could leave a series out over someone else's review.
    A review of another revision does not count either: an upgrade carries
    it over on the patches that did not change, and the rest are unseen.
    """
    return bool(
        entry.get('source') == 'agent' and entry.get('source-revision') == revision
    )


def _agent_reviewer_names(tracking: Dict[str, Any]) -> Set[str]:
    """Return the display names of the agents that reviewed this revision."""
    names: Set[str] = set()
    series = tracking.get('series')
    revision = series.get('revision', 1) if isinstance(series, dict) else 1
    targets: List[Any] = [series]
    targets.extend(tracking.get('patches') or [])
    for target in targets:
        if not isinstance(target, dict):
            continue
        reviews = target.get('reviews')
        if not isinstance(reviews, dict):
            continue
        for entry in reviews.values():
            if isinstance(entry, dict) and _is_agent_review(entry, revision):
                names.add(str(entry.get('name', '')))
    return names


def _needs_agent_review(tracking: Dict[str, Any], agent_name: Optional[str]) -> bool:
    """Tell whether a series should be handed to the agent.

    Only series in the reviewing state qualify.  Without *agent_name* a
    review from any agent is enough to leave a series alone; with it, only
    a review stored under exactly that reviewer name is.
    """
    series = tracking.get('series')
    if not isinstance(series, dict):
        return False
    if series.get('status', 'reviewing') != 'reviewing':
        return False
    names = _agent_reviewer_names(tracking)
    if agent_name is None:
        return not names
    return agent_name not in names


def _newer_revision(series: Dict[str, Any]) -> Optional[int]:
    """Return the newest known revision of a series, if this is not it."""
    identifier = series.get('identifier')
    change_id = series.get('change-id')
    if not identifier or not change_id:
        return None
    try:
        conn = b4.review.tracking.get_db(identifier)
        try:
            newest = b4.review.tracking.get_newest_revision(conn, change_id)
        finally:
            conn.close()
    except Exception as ex:
        logger.debug('Could not look up the revisions of %s: %s', change_id, ex)
        return None
    if newest is not None and newest > int(series.get('revision', 1)):
        return newest
    return None


def _find_candidates(topdir: str, agent_name: Optional[str]) -> List[_Candidate]:
    """List the review branches that are waiting for an agent review."""
    candidates: List[_Candidate] = []
    for branch in b4.review.tracking.get_review_branches(topdir):
        if branch.startswith(_TMP_BRANCH_PREFIX):
            continue
        try:
            _cover_text, tracking = b4.review.load_tracking(topdir, branch)
        except (SystemExit, Exception) as ex:
            logger.warning('Skipping %s: %s', branch, ex)
            continue
        if not _needs_agent_review(tracking, agent_name):
            continue
        series = tracking['series']
        # The upgrade would drop what the agent says about changed patches.
        newer = _newer_revision(series)
        if newer:
            logger.info('Skipping %s: v%d is available', branch, newer)
            continue
        candidates.append(
            _Candidate(
                branch=branch,
                revision=series.get('revision', 1),
                subject=str(series.get('subject') or '(no subject)'),
            )
        )
    return candidates


def _has_review_files(topdir: str, branch: str) -> bool:
    """Tell whether an earlier agent run left review files for *branch*."""
    ecode, out = b4.git_run_command(topdir, ['rev-parse', branch])
    if ecode != 0:
        return False
    return os.path.isdir(b4.review.get_agent_review_dir(topdir, out.strip()))


def _get_agent_command(topdir: str) -> b4.review.AgentCommand:
    """Return the configured batch agent command, or exit."""
    try:
        return b4.review.get_agent_command(topdir, batch=True)
    except b4.review.AgentConfigError as ex:
        logger.critical('%s', ex)
        sys.exit(1)


class _AgentWorktree:
    """The linked worktree the agent runs in.

    As a real linked worktree it shows the branch under review as checked
    out, so git and b4 leave that branch alone.  It is created lazily, and
    the caller's batch lock makes removing a leftover one safe.
    """

    def __init__(self, topdir: str, common_dir: str) -> None:
        self.path = os.path.join(common_dir, _WORKTREE_NAME)
        self._topdir = topdir
        self._created = False

    def _git(self, args: List[str], logstderr: bool = True) -> Tuple[int, str]:
        return b4.git_run_command(
            self.path, args, logstderr=logstderr, rundir=self.path
        )

    def _create(self, branch: str) -> None:
        if os.path.lexists(self.path):
            logger.info('Removing the review worktree left by an interrupted batch')
            if not self.remove():
                raise _BatchAbort(f'Could not remove {self.path}')
        # --force re-registers a path git still lists after it was deleted.
        gitargs = ['worktree', 'add', '--force', '--detach', '--no-checkout']
        gitargs += [self.path, branch]
        ecode, out = b4.git_run_command(self._topdir, gitargs, logstderr=True)
        if ecode != 0:
            raise _BatchAbort(f'Could not create a review worktree: {out.strip()}')
        self._created = True

    def checkout(self, branch: str) -> str:
        """Put a pristine checkout of *branch* in the tree; return its tip.

        The branch, not its commit, is checked out so the agent sees what it
        would from the TUI.  Git refuses a branch checked out elsewhere.
        """
        reused = self._created
        if not reused:
            self._create(branch)
        ecode, out = self._git([*b4.SCRATCH_GIT_OPTS, 'checkout', '--force', branch])
        if ecode != 0:
            lines = out.strip().splitlines()
            raise _AgentFailure(
                'could not check out the branch' + (f': {lines[-1]}' if lines else '')
            )
        if reused:
            # checkout --force restored changed files; drop added ones too.
            ecode, out = self._git(['clean', '-ffdxq'])
            if ecode != 0:
                raise _AgentFailure('could not clean the review worktree')
        ecode, out = self._git(['rev-parse', 'HEAD'], logstderr=False)
        if ecode != 0 or not out.strip():
            raise _AgentFailure('could not tell what was checked out')
        return out.strip()

    def is_clean(self) -> bool:
        """Tell whether the files git tracks are as they were checked out."""
        ecode, out = self._git(
            ['status', '--porcelain=v1', '--untracked-files=no'], logstderr=False
        )
        return ecode == 0 and not out.strip()

    def remove(self) -> bool:
        """Remove the tree, if there is one.  True if it is gone."""
        if not self._created and not os.path.lexists(self.path):
            return True
        self._created = False
        b4.git_run_command(
            self._topdir, ['worktree', 'remove', '--force', self.path], logstderr=True
        )
        # Not a registered worktree (or git failed): remove what is left.
        shutil.rmtree(self.path, ignore_errors=True)
        if os.path.lexists(self.path):
            logger.warning('Could not remove the review worktree %s', self.path)
            return False
        return True


def _load_tracking(topdir: str, branch: str) -> Tuple[str, Dict[str, Any]]:
    """Load the cover letter and tracking data of a review branch."""
    try:
        return b4.review.load_tracking(topdir, branch)
    except (SystemExit, Exception) as ex:
        raise _AgentFailure('could not load tracking data') from ex


def _branch_tip(topdir: str, branch: str) -> str:
    """Return the commit *branch* points to."""
    ecode, out = b4.git_run_command(topdir, ['rev-parse', branch])
    if ecode != 0 or not out.strip():
        raise _AgentFailure('the branch went away while it was being reviewed')
    return out.strip()


def _patch_commits(topdir: str, tip: str, series: Dict[str, Any]) -> List[str]:
    """List the patch commits below the tracking commit *tip*, oldest first."""
    first_patch = series.get('first-patch-commit', '')
    if first_patch:
        range_spec = f'{first_patch}~1..{tip}~1'
    else:
        range_spec = f'{series.get("base-commit", "")}..{tip}~1'
    ecode, out = b4.git_run_command(topdir, ['rev-list', '--reverse', range_spec])
    if ecode > 0 or not out.strip():
        raise _AgentFailure('unable to list patch commits')
    return out.strip().splitlines()


def _import_reviews(
    topdir: str,
    branch: str,
    tip: str,
    cover_text: str,
    tracking: Dict[str, Any],
    commit_shas: List[str],
) -> bool:
    """Store the review files waiting for *tip*, if *branch* is still there."""
    patches: List[Dict[str, Any]] = tracking.setdefault('patches', [])
    try:
        return b4.review._integrate_agent_reviews(
            topdir,
            cover_text,
            tracking,
            commit_shas,
            patches,
            branch=branch,
            expected_tip=tip,
        )
    except Exception as ex:
        raise _AgentFailure(str(ex)) from ex


def _store_review(
    topdir: str, branch: str, review_dir: str, commit_shas: List[str]
) -> Optional[Dict[str, Any]]:
    """Store the review an agent wrote to *review_dir* on *branch*.

    The tracking data may have been saved (e.g. from the TUI) meanwhile.
    The review still holds if the patches are unchanged, and goes on top.
    Returns the stored tracking data, or None (removing the files) if the
    review was unusable.
    """
    for _attempt in range(_STORE_ATTEMPTS):
        try:
            tip = _branch_tip(topdir, branch)
        except _AgentFailure:
            shutil.rmtree(review_dir, ignore_errors=True)
            raise
        cover_text, tracking = _load_tracking(topdir, tip)
        if _patch_commits(topdir, tip, tracking.get('series') or {}) != commit_shas:
            shutil.rmtree(review_dir, ignore_errors=True)
            raise _AgentFailure('the series changed while it was being reviewed')
        # Review files are filed under the tip they are for.
        dest = b4.review.get_agent_review_dir(topdir, tip)
        if dest != review_dir:
            try:
                # Whatever is filed there already is not this review.
                if os.path.lexists(dest):
                    shutil.rmtree(dest)
                os.rename(review_dir, dest)
            except OSError as ex:
                raise _AgentFailure(f'could not collect the review: {ex}') from ex
            review_dir = dest
        try:
            imported = _import_reviews(
                topdir, branch, tip, cover_text, tracking, commit_shas
            )
        except _AgentFailure:
            if _branch_tip(topdir, branch) == tip:
                raise
            continue
        if not imported:
            shutil.rmtree(review_dir, ignore_errors=True)
            return None
        return tracking
    # Leave the files where the next run will look for them.
    with contextlib.suppress(_AgentFailure, OSError):
        tip = _branch_tip(topdir, branch)
        os.rename(review_dir, b4.review.get_agent_review_dir(topdir, tip))
    raise _AgentFailure('the tracking data kept changing while the review was stored')


def _drop_unfinished_review(marker: str) -> bool:
    """Remove the review files *marker* names, and the marker itself.

    Returns True if there was a marker.
    """
    try:
        with open(marker, 'r') as fh:
            name = fh.read().strip()
    except OSError:
        return False
    # The marker only ever names a directory next to itself.
    if name and name == os.path.basename(name):
        shutil.rmtree(os.path.join(os.path.dirname(marker), name), ignore_errors=True)
    with contextlib.suppress(OSError):
        os.unlink(marker)
    return True


def _run_agent(agent_cmd: List[str], rundir: str, review_dir: str) -> int:
    """Run the agent in *rundir* and return its exit code.

    What an agent wrote before it failed or was interrupted is not a review,
    and importing it later would pass a part of one off as the whole.  So
    such files are removed, and the marker lets the next batch do that if
    this one is killed first.
    """
    marker = os.path.join(os.path.dirname(review_dir), _UNFINISHED_NAME)
    try:
        with open(marker, 'w') as fh:
            fh.write(os.path.basename(review_dir) + '\n')
    except OSError as ex:
        raise _BatchAbort(f'Could not write {marker}: {ex}') from ex
    finished = False
    try:
        # With nothing to read, an agent that asks a question gets no answer
        # right away instead of holding up the batch.
        returncode = subprocess.run(
            agent_cmd, cwd=rundir, stdin=subprocess.DEVNULL, check=False
        ).returncode
        finished = returncode == 0
    except OSError as ex:
        # No series is going to fare any better than this one did.
        raise _BatchAbort(f'Could not start the review agent: {ex}') from ex
    finally:
        if finished:
            with contextlib.suppress(OSError):
                os.unlink(marker)
        else:
            _drop_unfinished_review(marker)
    return returncode


def _review_branch(
    topdir: str,
    worktree: _AgentWorktree,
    branch: str,
    agent: b4.review.AgentCommand,
    agent_name: Optional[str],
) -> str:
    """Get an agent review onto one review branch.

    Returns ``reviewed`` when the agent ran and its review was imported,
    ``imported`` when review files left by an earlier run made a new run
    unnecessary, and ``skipped`` when the series stopped being eligible
    while the batch was running.  Raises :class:`_AgentFailure` when no
    usable review was obtained.
    """
    if not b4.git_branch_exists(topdir, branch):
        return 'skipped'
    tip = _branch_tip(topdir, branch)
    cover_text, tracking = _load_tracking(topdir, tip)
    # Earlier agent runs can take long enough for this to have changed.
    if not _needs_agent_review(tracking, agent_name):
        return 'skipped'

    series: Dict[str, Any] = tracking['series']
    patches: List[Dict[str, Any]] = tracking.setdefault('patches', [])
    commit_shas = _patch_commits(topdir, tip, series)

    # A finished review that was not stored yet (a failed save, a run from
    # the TUI) spares paying for the same review twice.
    if _import_reviews(
        topdir, branch, tip, cover_text, tracking, commit_shas
    ) and not _needs_agent_review(tracking, agent_name):
        return 'imported'

    # The prompt points the agent at this blob.  Writing it moves the tip
    # the review is filed under, so it must happen before the agent starts.
    change_id = series.get('change-id')
    if (
        change_id
        and series.get('thread-blob')
        and not series.get('thread-context-blob')
    ):
        b4.review.tracking.ensure_thread_context_blob(
            topdir, change_id, series, patches
        )

    # The agent files its review under the commit it finds at HEAD.
    start_sha = worktree.checkout(branch)
    review_dir = b4.review.get_agent_review_dir(topdir, start_sha)
    # Files the import above rejected must not mix into the fresh review.
    try:
        if os.path.lexists(review_dir):
            shutil.rmtree(review_dir)
    except OSError as ex:
        raise _AgentFailure(f'could not clean the agent review directory: {ex}') from ex
    try:
        agent.make_review_dir(review_dir)
    except OSError as ex:
        raise _AgentFailure(
            f'could not create the agent review directory: {ex}'
        ) from ex
    prompt = _AGENT_PROMPT.format(prompt_path=agent.prompt_path, review_dir=review_dir)
    agent_cmd = agent.command_line(prompt, review_dir)

    logger.debug('Running review agent: %s', ' '.join(agent_cmd))
    returncode = _run_agent(agent_cmd, worktree.path, review_dir)

    # The next checkout discards such changes, but the user should know.
    if not worktree.is_clean():
        logger.warning(
            'The agent changed files in the review worktree while reviewing %s; '
            'the changes are discarded',
            branch,
        )

    if returncode != 0:
        raise _AgentFailure(f'agent exited with code {returncode}')

    try:
        written = os.path.isdir(review_dir) and bool(os.listdir(review_dir))
    except OSError as ex:
        raise _AgentFailure(f'could not collect the review: {ex}') from ex
    stored = None
    if written:
        stored = _store_review(topdir, branch, review_dir, commit_shas)
    else:
        agent.drop_empty_review_dir(review_dir)

    if stored is None:
        raise _AgentFailure('agent produced no review data')

    # --agent-name does not choose the agent, so the review that was just
    # stored may be under another name and leave the series selected.
    if agent_name is not None and _needs_agent_review(stored, agent_name):
        logger.warning(
            '%s was reviewed as %s, not %s: the same --agent-name will select it again',
            branch,
            ', '.join(sorted(_agent_reviewer_names(stored))),
            agent_name,
        )
    return 'reviewed'


def main(cmdargs: argparse.Namespace) -> None:
    if cmdargs.batch_subcmd == 'agent':
        cmd_agent(cmdargs)
    else:
        logger.critical('Unknown batch sub-command: %s', cmdargs.batch_subcmd)
        sys.exit(1)


def cmd_agent(cmdargs: argparse.Namespace) -> None:
    """Run the review agent on reviewing series that have no agent review.

    A failed review does not stop the batch, but makes it exit non-zero.
    """
    topdir = b4.git_get_toplevel()
    if not topdir:
        logger.critical('Not in a git repository.')
        sys.exit(1)

    dryrun = bool(getattr(cmdargs, 'dryrun', False))
    agent_name: Optional[str] = getattr(cmdargs, 'agent_name', None)
    if agent_name is not None and not agent_name.strip():
        # It would select every series, as no review has an empty name.
        logger.critical('--agent-name needs a reviewer name')
        sys.exit(1)

    agent: Optional[b4.review.AgentCommand] = None
    if not dryrun:
        agent = _get_agent_command(topdir)

    candidates = _find_candidates(topdir, agent_name)
    if not candidates:
        logger.info('No review branches need an agent review.')
        return

    if dryrun:
        logger.info('Review branches that would be sent to the review agent:')
        for cand in candidates:
            note = ''
            if _has_review_files(topdir, cand.branch):
                note = ' [review files from an earlier run would be imported first]'
            logger.info(
                '  %s (v%s): %s%s', cand.branch, cand.revision, cand.subject, note
            )
        logger.info('Dry run: %d review branch(es) would be reviewed.', len(candidates))
        return

    assert agent is not None
    common_dir = b4.git_get_common_dir(topdir)
    if not common_dir:
        logger.critical('Could not find the git directory of %s.', topdir)
        sys.exit(1)
    lock_path = os.path.join(
        common_dir, b4.review.tracking.REVIEW_METADATA_DIR, _LOCK_NAME
    )
    worktree = _AgentWorktree(topdir, common_dir)

    counts = {'reviewed': 0, 'imported': 0, 'skipped': 0}
    failures: List[Tuple[str, str]] = []
    stopped = 0
    removed = True
    with contextlib.ExitStack() as stack:
        # Two batches would share the worktree and pay for the same reviews.
        try:
            stack.enter_context(b4.lockfile_nb(lock_path))
        except b4.LockHeldError:
            logger.critical(
                'Another batch of agent reviews is running in this repository.'
            )
            sys.exit(1)
        if _drop_unfinished_review(
            os.path.join(os.path.dirname(lock_path), _UNFINISHED_NAME)
        ):
            logger.info('Removed the unfinished review left by an interrupted batch')
        try:
            for num, cand in enumerate(candidates, 1):
                logger.info(
                    'Reviewing %s (%d/%d): %s',
                    cand.branch,
                    num,
                    len(candidates),
                    cand.subject,
                )
                try:
                    outcome = _review_branch(
                        topdir, worktree, cand.branch, agent, agent_name
                    )
                except _AgentFailure as ex:
                    failures.append((cand.branch, str(ex)))
                    logger.critical('Agent review failed for %s: %s', cand.branch, ex)
                    continue
                counts[outcome] += 1
                if outcome == 'imported':
                    logger.info(
                        '%s: imported the review left by an earlier run', cand.branch
                    )
                elif outcome == 'skipped':
                    logger.info('%s: no longer needs an agent review', cand.branch)
        except _BatchAbort as ex:
            logger.critical('%s', ex)
            logger.critical('Stopping the batch.')
            stopped = 1
        except KeyboardInterrupt:
            logger.critical('Interrupted, stopping the batch.')
            stopped = 130
        finally:
            removed = worktree.remove()

    logger.info(
        'Agent reviews: %d completed, %d imported from earlier runs, '
        '%d skipped, %d failed',
        counts['reviewed'],
        counts['imported'],
        counts['skipped'],
        len(failures),
    )
    for branch, reason in failures:
        logger.info('  failed: %s: %s', branch, reason)

    if stopped:
        sys.exit(stopped)
    if failures or not removed:
        sys.exit(1)
