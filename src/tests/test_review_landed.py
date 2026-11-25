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
from typing import Any, Dict, List, Optional, Union
from unittest import mock

import pytest

import b4
import b4.review
from b4.review import landed
from b4.review import tracking as review_tracking

from .helpers.mail import AUTHOR, series_msgs
from .helpers.patches import ALGO_NEW, ALGO_OLD, commit_file, post_patch
from .helpers.tracking import create_review_branch, make_tracking_data

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


def test_unreadable_remotes_raise_instead_of_finding_nothing(
    gitdir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty answer would make every landed patch look dropped."""
    monkeypatch.setattr(b4, 'git_run_command', lambda *args, **kwargs: (128, 'fatal'))

    with pytest.raises(RuntimeError):
        landed.LandedIndex.build(gitdir, ['upstream'], NOW)


def test_no_remotes_reads_nothing(gitdir: str) -> None:
    """With no remotes configured, nothing is walked and nothing has landed."""
    commit = commit_file(gitdir, 'file1.txt', 'change\n', 'landed: fix\n')
    posted = b4.LoreMessage(post_patch(gitdir, commit, 'posted@example.com'))
    _publish(gitdir, 'refs/remotes/upstream/master')

    assert landed.LandedIndex.build(gitdir, [], NOW).find(posted) is None


# ---------------------------------------------------------------------------
# Recording landed patches
# ---------------------------------------------------------------------------

IDENT = 'landed-test'


def _track(change_id: str, status: str = 'reviewing') -> List[Any]:
    """Track a two-patch series with a cover letter; return its messages."""
    msgs = series_msgs(change_id, AUTHOR, 1, 2, cover=True)
    lmbx = b4.LoreMailbox()
    for msg in msgs:
        lmbx.add_message(msg)
    lser = lmbx.get_series(1)
    assert lser is not None
    conn = review_tracking.init_db(IDENT)
    review_tracking.add_series_to_db(
        conn,
        change_id,
        1,
        f'{change_id}: do things better',
        'Author',
        'author@example.com',
        '2026-03-19T00:00:00+00:00',
        f'{change_id}-v1-p0@example.com',
        2,
    )
    review_tracking.add_series_patches(conn, change_id, 1, lser)
    review_tracking.update_series_status(conn, change_id, status)
    conn.close()
    return msgs


def _landed(change_id: str) -> Dict[int, str]:
    conn = review_tracking.get_db(IDENT)
    try:
        return review_tracking.get_landed_patches(conn, change_id, 1)
    finally:
        conn.close()


def _index(*msgids: str) -> landed.LandedIndex:
    """An index where each of *msgids* has landed as commit 'c-<msgid>'."""
    return landed.LandedIndex(None, {m: f'c-{m}' for m in msgids}, {})


def _update(
    change_id: str,
    msgs: List[Any],
    index: Optional[landed.LandedIndex],
    topdir: Optional[str] = None,
) -> Dict[str, Any]:
    series = {
        'change_id': change_id,
        'revision': 1,
        'status': 'reviewing',
        'message_id': f'{change_id}-v1-p0@example.com',
    }
    with (
        mock.patch('b4.review._review.retrieve_series_messages', return_value=msgs),
        mock.patch('b4.review._review.check_series_attestation', return_value=None),
    ):
        return b4.review.update_series_tracking(
            series, IDENT, 'https://example.com/%s', topdir=topdir, landed_index=index
        )


def test_landed_patches_survive_a_patch_list_rebuild() -> None:
    """Landed belongs to the posted message, so rebuilding the list keeps it.

    Several code paths delete and re-insert a series' patch rows (track,
    rescan, revision import); none of them may forget what has landed.
    """
    _track('rebuild')
    conn = review_tracking.get_db(IDENT)
    review_tracking.set_landed_patches(conn, {'rebuild-v1-p2@example.com': 'abc'})
    lmbx = b4.LoreMailbox()
    for msg in series_msgs('rebuild', AUTHOR, 1, 2, cover=True):
        lmbx.add_message(msg)
    lser = lmbx.get_series(1)
    assert lser is not None
    review_tracking.add_series_patches(conn, 'rebuild', 1, lser)
    conn.close()

    assert _landed('rebuild') == {2: 'abc'}


def test_older_database_gains_the_landed_table() -> None:
    review_tracking.init_db(IDENT).close()
    conn = review_tracking.get_db(IDENT)
    conn.execute('DROP TABLE landed_patches')
    conn.execute('UPDATE schema_version SET version = 10')
    conn.commit()
    conn.close()

    conn = review_tracking.get_db(IDENT)
    review_tracking.set_landed_patches(conn, {'migrated@example.com': 'abc'})
    rows = conn.execute('SELECT message_id FROM landed_patches').fetchall()
    conn.close()

    assert [row[0] for row in rows] == ['migrated@example.com']


def test_update_records_landed_patches_and_forgets_dropped_ones() -> None:
    """Each update recomputes: a patch dropped from a remote stops being landed."""
    msgs = _track('recompute')

    _update('recompute', msgs, _index('recompute-v1-p2@example.com'))
    assert _landed('recompute') == {2: 'c-recompute-v1-p2@example.com'}

    _update('recompute', msgs, _index())
    assert _landed('recompute') == {}


def test_update_without_an_index_keeps_what_is_known() -> None:
    """No index means the remotes could not be read, which is not "nothing landed"."""
    msgs = _track('unknown')
    conn = review_tracking.get_db(IDENT)
    review_tracking.set_landed_patches(conn, {'unknown-v1-p1@example.com': 'abc'})
    conn.close()

    _update('unknown', msgs, None)

    assert _landed('unknown') == {1: 'abc'}


def _review_branch(gitdir: str, change_id: str, checkout: bool = False) -> str:
    """Create the two-patch review branch of a series made by _track()."""
    tracking = make_tracking_data(
        change_id,
        identifier=IDENT,
        expected=2,
        patches=[
            {
                'title': f'part {i}',
                'header-info': {'msgid': f'{change_id}-v1-p{i}@example.com'},
            }
            for i in (1, 2)
        ],
    )
    return create_review_branch(
        gitdir, change_id, tracking_data=tracking, checkout=checkout
    )


@pytest.mark.parametrize('checked_out', [False, True])
def test_review_branch_shows_what_an_update_found(
    gitdir: str, checked_out: bool
) -> None:
    """Whoever loads a review branch sees the landed patches right away.

    That includes a branch that was checked out during the update: updates
    leave such a branch alone, and the maintainer is most likely to look
    at exactly that one next.
    """
    change_id = 'branch'
    msgs = _track(change_id)
    branch = _review_branch(gitdir, change_id, checkout=checked_out)

    result = _update(change_id, msgs, _index(f'{change_id}-v1-p2@example.com'), gitdir)

    assert result.get('error') is None
    _cover, loaded = b4.review.load_tracking(gitdir, branch)
    assert 'landed' not in loaded['patches'][0]
    assert loaded['patches'][1]['landed'] == f'c-{change_id}-v1-p2@example.com'

    _update(change_id, msgs, _index(), gitdir)
    _cover, loaded = b4.review.load_tracking(gitdir, branch)
    assert all('landed' not in p for p in loaded['patches'])


def _sweep(
    monkeypatch: pytest.MonkeyPatch,
    topdir: Optional[str],
    build: mock.Mock,
    remotes: Optional[List[str]] = None,
) -> List[Any]:
    """Run update_all_tracking over two series; return the index each one got."""
    series: List[Dict[str, Any]] = [
        {'change_id': 'a', 'subject': 'a', 'sent_at': '2026-04-01T00:00:00+00:00'},
        {'change_id': 'b', 'subject': 'b', 'sent_at': '2026-03-01T12:00:00+00:00'},
        {'change_id': 'c', 'subject': 'c', 'sent_at': None},
    ]
    monkeypatch.setattr(review_tracking, 'rescan_branches', lambda *args: {})
    monkeypatch.setattr(landed, 'get_landed_remotes', lambda topdir: remotes or [])
    monkeypatch.setattr(landed.LandedIndex, 'build', build)
    seen: List[Any] = []

    def fake_update(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        seen.append(kwargs.get('landed_index'))
        return {'new_revisions': 0, 'new_trailers': 0, 'error': None}

    monkeypatch.setattr(b4.review, 'update_series_tracking', fake_update)
    b4.review.update_all_tracking(
        IDENT, 'https://example.com/%s', topdir=topdir, series_list=series
    )
    return seen


def test_sweep_reads_the_remotes_once_from_the_oldest_posting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index = _index()
    build = mock.Mock(return_value=index)

    seen = _sweep(monkeypatch, '/repo', build, remotes=['upstream'])

    build.assert_called_once_with(
        '/repo',
        ['upstream'],
        datetime.datetime(2026, 3, 1, 12, tzinfo=datetime.timezone.utc),
    )
    assert seen == [index, index, index]


def test_sweep_without_remotes_still_recomputes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing every remote from the config must clear what was landed."""
    build = mock.Mock(return_value=_index())

    seen = _sweep(monkeypatch, '/repo', build)

    assert build.call_args.args[1] == []
    assert seen[0] is build.return_value


@pytest.mark.parametrize('topdir', [None, '/repo'], ids=['no-repo', 'git-fails'])
def test_sweep_that_cannot_read_remotes_changes_nothing(
    monkeypatch: pytest.MonkeyPatch, topdir: Optional[str]
) -> None:
    build = mock.Mock(side_effect=RuntimeError('git log failed'))

    seen = _sweep(monkeypatch, topdir, build, remotes=['upstream'])

    assert seen == [None, None, None]


# ---------------------------------------------------------------------------
# The landed patch state
# ---------------------------------------------------------------------------

ME = 'me@example.com'


@pytest.mark.parametrize(
    'review, others, expected',
    [
        ({}, {}, 'landed'),
        ({'patch-state': 'unchanged'}, {}, 'landed'),
        ({}, {'agent@example.com': {'comments': [{'line': 1}]}}, 'landed'),
        ({'patch-state': 'skip'}, {}, 'skip'),
        ({'patch-state': 'done'}, {}, 'done'),
        ({'reply': 'Applied elsewhere, but one more thing...'}, {}, 'draft'),
    ],
    ids=['plain', 'unchanged', 'external', 'skip', 'done', 'my-reply'],
)
def test_landed_state_yields_to_anything_the_maintainer_did(
    review: Dict[str, Any], others: Dict[str, Any], expected: str
) -> None:
    """Landed hides a patch like skip, so it must never hide the maintainer's work.

    Anything the maintainer did to the patch (a state, a reply) wins;
    landed only replaces states nobody acted on.
    """
    reviews: Dict[str, Any] = dict(others)
    if review:
        reviews[ME] = review
    patch = {'landed': 'abc123', 'reviews': reviews}

    assert b4.review._get_patch_state(patch, {'email': ME}) == expected


def test_show_info_names_the_landed_patches(gitdir: str) -> None:
    """Scripts and review agents cannot read the database, so show-info tells them.

    The tracking commit they read says nothing about landed patches.
    """
    change_id = 'info'
    _track(change_id)
    branch = _review_branch(gitdir, change_id)
    assert b4.review.get_review_info(gitdir, branch)['landed-patches'] is None

    conn = review_tracking.get_db(IDENT)
    review_tracking.set_landed_patches(
        conn, {f'{change_id}-v1-p{i}@example.com': f'c{i}' for i in (1, 2)}
    )
    conn.close()

    assert b4.review.get_review_info(gitdir, branch)['landed-patches'] == '1 2'
