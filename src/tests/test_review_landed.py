# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Tests for recognizing posted patches that have landed in another tree.

Landed patches are skipped without a human looking at them, so these tests
care as much about what must NOT match (an edited diff, a commit that only
exists locally) as about what must.
"""

import datetime
import logging
from typing import List, Optional, Union

import pytest

import b4
from b4.review import landed

from .helpers.patches import ALGO_NEW, ALGO_OLD, commit_file, post_patch

NOW = datetime.datetime.now(tz=datetime.timezone.utc)


@pytest.mark.parametrize(
    'configured, expected, warned',
    [
        (None, [], False),
        ('origin', ['origin'], False),
        (['origin', 'nosuch', 'origin'], ['origin'], True),
    ],
)
def test_landed_remotes_are_existing_remotes_only(
    gitdir: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    configured: Union[None, str, List[str]],
    expected: List[str],
    warned: bool,
) -> None:
    """Only remotes the user has are read; a typo is reported, not fatal."""
    monkeypatch.setitem(b4.MAIN_CONFIG, 'review-check-landed', configured)

    with caplog.at_level(logging.WARNING, logger='b4'):
        assert landed.get_landed_remotes(gitdir) == expected

    assert ('nosuch' in caplog.text) is warned


def test_landed_remotes_come_from_git_config(gitdir: str) -> None:
    """Several remotes can be listed by repeating the key, as with other lists."""
    for remote in ('linux-next', 'net-next'):
        ecode, _out = b4.git_run_command(
            gitdir, ['remote', 'add', remote, f'https://example.org/{remote}.git']
        )
        assert ecode == 0
        ecode, _out = b4.git_run_command(
            gitdir, ['config', '--add', 'b4.review-check-landed', remote]
        )
        assert ecode == 0

    b4._setup_main_config(topdir=gitdir)

    assert landed.get_landed_remotes(gitdir) == ['linux-next', 'net-next']


def _publish(gitdir: str, ref: str) -> None:
    """Make HEAD the tip of a remote-tracking branch, as a fetch would."""
    ecode, _out = b4.git_run_command(gitdir, ['update-ref', ref, 'HEAD'])
    assert ecode == 0


def _reset(gitdir: str, commit: str) -> None:
    ecode, _out = b4.git_run_command(gitdir, ['reset', '-q', '--hard', commit])
    assert ecode == 0


def _find(gitdir: str, posted: b4.LoreMessage) -> Optional[str]:
    index = landed.LandedIndex.build(gitdir, ['upstream'], NOW)
    found = index.find(posted)
    return found[1] if found else None


@pytest.mark.parametrize(
    'trailer',
    [
        'Link: https://lore.kernel.org/r/posted@example.com',
        'Link: https://patch.msgid.link/posted@example.com',
        'Message-ID: <posted@example.com>',
    ],
)
def test_commit_naming_the_posting_has_landed(gitdir: str, trailer: str) -> None:
    """A commit naming the posting is the strongest proof, even with edits."""
    base = b4.git_revparse_obj('HEAD', gitdir)
    posted_commit = commit_file(gitdir, 'file1.txt', 'as posted\n', 'landed: fix\n')
    posted = b4.LoreMessage(post_patch(gitdir, posted_commit, 'posted@example.com'))
    _reset(gitdir, base)
    commit_file(
        gitdir, 'file1.txt', 'edited by maintainer\n', f'landed: fix\n\n{trailer}\n'
    )
    _publish(gitdir, 'refs/remotes/upstream/master')

    assert _find(gitdir, posted) == 'msgid'


def test_same_diff_made_with_another_algorithm_has_landed(gitdir: str) -> None:
    """Without a Link:, the exact diff proves it, whatever algorithm made it."""
    commit_file(gitdir, 'algo.c', ALGO_OLD, 'landed: add algo.c\n')
    commit = commit_file(gitdir, 'algo.c', ALGO_NEW, 'landed: switch to fib\n')
    posted = b4.LoreMessage(
        post_patch(gitdir, commit, 'histo@example.com', algo='histogram')
    )
    _publish(gitdir, 'refs/remotes/upstream/master')

    assert _find(gitdir, posted) == 'patch-id'


@pytest.mark.parametrize(
    'applied_content, applied_subject',
    [
        ('edited by maintainer\n', 'landed: fix\n'),
        ('as posted\n', 'landed: fix, reworded\n'),
    ],
    ids=['edited-diff', 'reworded-subject'],
)
def test_guesses_never_count_as_landed(
    gitdir: str, applied_content: str, applied_subject: str
) -> None:
    """Same subject with another diff, or same diff with another subject.

    Either could be the posted patch, but a wrong guess would hide a patch
    from review, so neither counts without a Link: or Message-ID:.
    """
    base = b4.git_revparse_obj('HEAD', gitdir)
    posted_commit = commit_file(gitdir, 'file1.txt', 'as posted\n', 'landed: fix\n')
    posted = b4.LoreMessage(post_patch(gitdir, posted_commit, 'posted@example.com'))
    _reset(gitdir, base)
    commit_file(gitdir, 'file1.txt', applied_content, applied_subject)
    _publish(gitdir, 'refs/remotes/upstream/master')

    assert _find(gitdir, posted) is None


@pytest.mark.parametrize(
    'ref',
    [None, 'refs/remotes/other/master', 'refs/heads/upstream-copy'],
    ids=['local-only', 'unconfigured-remote', 'local-branch'],
)
def test_only_configured_remotes_count(gitdir: str, ref: Optional[str]) -> None:
    """Local work and remotes the user did not list never make a patch landed."""
    commit = commit_file(gitdir, 'file1.txt', 'change\n', 'landed: fix\n')
    posted = b4.LoreMessage(post_patch(gitdir, commit, 'posted@example.com'))
    if ref:
        _publish(gitdir, ref)

    assert _find(gitdir, posted) is None


def test_commits_long_before_the_posting_are_not_read(gitdir: str) -> None:
    """The walk stops well before the oldest posting, so old history is skipped."""
    commit = commit_file(gitdir, 'file1.txt', 'change\n', 'landed: fix\n')
    posted = b4.LoreMessage(post_patch(gitdir, commit, 'posted@example.com'))
    _publish(gitdir, 'refs/remotes/upstream/master')
    much_later = NOW + landed.SINCE_SLACK + datetime.timedelta(days=1)

    index = landed.LandedIndex.build(gitdir, ['upstream'], much_later)

    assert index.find(posted) is None


def test_no_remotes_reads_nothing(gitdir: str) -> None:
    """With no remotes configured, nothing is walked and nothing has landed."""
    commit = commit_file(gitdir, 'file1.txt', 'change\n', 'landed: fix\n')
    posted = b4.LoreMessage(post_patch(gitdir, commit, 'posted@example.com'))
    _publish(gitdir, 'refs/remotes/upstream/master')

    assert landed.LandedIndex.build(gitdir, [], NOW).find(posted) is None
