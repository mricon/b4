# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Builders for ``b4 review`` tracking state: branches, metadata, databases."""

import os
from typing import Any, Dict, List, Optional

import b4
import b4.review
from b4.review import tracking

DEFAULT_SENT_AT = '2026-01-15T10:00:00+00:00'


# ---------------------------------------------------------------------------
# Tracking metadata
# ---------------------------------------------------------------------------


def make_tracking_data(
    change_id: str,
    *,
    identifier: str = 'test-project',
    revision: int = 1,
    status: str = 'reviewing',
    subject: str = 'Test series',
    sender_name: str = 'Test Author',
    sender_email: str = 'test@example.com',
    expected: int = 1,
    base_commit: str = 'abc123',
    first_patch_commit: str = 'def456',
    link: str = '',
    header_info: Optional[Dict[str, Any]] = None,
    patches: Optional[List[Dict[str, Any]]] = None,
    followups: Optional[List[Dict[str, Any]]] = None,
    series_extra: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a tracking-commit dict as ``make_review_magic_json`` expects it.

    *series_extra* is merged into the ``series`` sub-dict (for keys like
    ``snoozed`` or ``target-branch``); *extra* is merged at the top level
    (for keys like ``known-revisions``).
    """
    series: Dict[str, Any] = {
        'identifier': identifier,
        'change-id': change_id,
        'revision': revision,
        'status': status,
        'subject': subject,
        'fromname': sender_name,
        'fromemail': sender_email,
        'expected': expected,
        'complete': True,
        'base-commit': base_commit,
        'prerequisite-commits': [],
        'first-patch-commit': first_patch_commit,
        'link': link,
        'header-info': header_info if header_info is not None else {},
    }
    if series_extra:
        series.update(series_extra)
    trk: Dict[str, Any] = {
        'series': series,
        'followups': followups if followups is not None else [],
        'patches': patches if patches is not None else [],
    }
    if extra:
        trk.update(extra)
    return trk


# ---------------------------------------------------------------------------
# Review branches
# ---------------------------------------------------------------------------


class ReviewBranch(str):
    """A review branch name that also remembers the commits it was built from.

    It is a plain ``str`` for every existing caller; ``base_sha`` and
    ``patch_shas`` are there for tests that need to look at the commits.
    """

    base_sha: str
    patch_shas: List[str]

    def __new__(
        cls, name: str, *, base_sha: str, patch_shas: List[str]
    ) -> 'ReviewBranch':
        obj = super().__new__(cls, name)
        obj.base_sha = base_sha
        obj.patch_shas = list(patch_shas)
        return obj


def _git(gitdir: str, args: List[str]) -> str:
    ecode, out = b4.git_run_command(gitdir, args)
    assert ecode == 0, f'git {" ".join(args)} failed: {out}'
    return out.strip()


def create_review_branch(
    gitdir: str,
    change_id: str,
    *,
    identifier: str = 'test-project',
    revision: int = 1,
    status: str = 'reviewing',
    subject: str = 'Test series',
    sender_name: str = 'Test Author',
    sender_email: str = 'test@example.com',
    link: str = '',
    patch_messages: Optional[List[str]] = None,
    num_real_commits: int = 0,
    with_patch: bool = False,
    series_extra: Optional[Dict[str, Any]] = None,
    tracking_data: Optional[Dict[str, Any]] = None,
    checkout: bool = False,
) -> ReviewBranch:
    """Create ``b4/review/<change_id>`` off HEAD with a tracking commit at the tip.

    Patch commits between the base and the tracking commit come from one
    of three knobs:

    * *patch_messages*: one empty commit per message, used verbatim;
    * *num_real_commits*: that many empty ``patch N: do thing N`` commits;
    * *with_patch*: one real commit appending a line to ``file1.txt``.

    Each patch commit gets a ``patches`` entry carrying its title and a
    synthetic ``header-info`` msgid of ``<change_id>-patch<N>@example.com``.
    *series_extra* is merged into the ``series`` sub-dict.  Pass
    *tracking_data* to use a ready-made dict instead of building one.

    HEAD is restored to where it was unless *checkout* is true, in which
    case it stays on the new branch.
    """
    branch_name = f'b4/review/{change_id}'
    base_sha = _git(gitdir, ['rev-parse', 'HEAD'])
    ecode, orig_ref = b4.git_run_command(
        gitdir, ['symbolic-ref', '--short', '-q', 'HEAD']
    )
    orig_ref = orig_ref.strip() if ecode == 0 else base_sha

    _git(gitdir, ['branch', branch_name, base_sha])
    _git(gitdir, ['checkout', '-q', branch_name])

    messages: List[str] = []
    if patch_messages is not None:
        messages = list(patch_messages)
    elif num_real_commits:
        messages = [f'patch {i}: do thing {i}' for i in range(1, num_real_commits + 1)]
    elif with_patch:
        messages = [f'{change_id}: tweak file1']

    patch_shas: List[str] = []
    for msg in messages:
        if with_patch:
            with open(os.path.join(gitdir, 'file1.txt'), 'a') as fh:
                fh.write(f'{change_id} tweak\n')
            _git(gitdir, ['add', 'file1.txt'])
            _git(gitdir, ['commit', '-q', '-m', msg])
        else:
            _git(gitdir, ['commit', '-q', '--allow-empty', '-m', msg])
        patch_shas.append(_git(gitdir, ['rev-parse', 'HEAD']))

    if tracking_data is None:
        patches_meta: List[Dict[str, Any]] = [
            {
                'title': msg.splitlines()[0],
                'link': '',
                'header-info': {'msgid': f'{change_id}-patch{i}@example.com'},
                'followups': [],
            }
            for i, msg in enumerate(messages, 1)
        ]
        tracking_data = make_tracking_data(
            change_id,
            identifier=identifier,
            revision=revision,
            status=status,
            subject=subject,
            sender_name=sender_name,
            sender_email=sender_email,
            expected=max(len(patch_shas), 1),
            base_commit=base_sha,
            first_patch_commit=patch_shas[0] if patch_shas else base_sha,
            link=link,
            patches=patches_meta,
            series_extra=series_extra,
        )
        cover = subject
    else:
        cover = tracking_data['series'].get('subject', subject)

    commit_msg = f'{cover}\n\n{b4.review.make_review_magic_json(tracking_data)}'
    _git(gitdir, ['commit', '-q', '--allow-empty', '-m', commit_msg])

    if not checkout:
        _git(gitdir, ['checkout', '-q', orig_ref])

    return ReviewBranch(branch_name, base_sha=base_sha, patch_shas=patch_shas)


def add_worktree(gitdir: str, name: str = 'worktree', branch: str = 'wt-branch') -> str:
    """Add a linked worktree next to *gitdir* on a fresh *branch*; return its path."""
    worktree_dir = os.path.join(os.path.dirname(gitdir), name)
    _git(gitdir, ['worktree', 'add', worktree_dir, '-b', branch])
    return worktree_dir


# ---------------------------------------------------------------------------
# Tracking database
# ---------------------------------------------------------------------------


def seed_series(
    identifier: str,
    change_id: str,
    *,
    revision: int = 1,
    status: str = 'new',
    subject: Optional[str] = None,
    sender_name: str = 'Test Author',
    sender_email: str = 'author@example.com',
    sent_at: Optional[str] = DEFAULT_SENT_AT,
    message_id: Optional[str] = None,
    num_patches: int = 1,
    message_count: Optional[int] = None,
    seen_message_count: Optional[int] = None,
    revisions: Optional[List[int]] = None,
    patch_rows: bool = False,
    stamp_activity: bool = False,
) -> None:
    """Add one tracked series to the *identifier* database, creating it if needed.

    * *status* other than ``new`` is written directly; with *stamp_activity*
      it goes through ``update_series_status`` and bumps ``last_activity_at``.
    * *revisions* lists revision numbers to record in the ``revisions``
      table (``message_id`` becomes ``<change_id>-v<N>@example.com``).
    * *patch_rows* adds *num_patches* rows to ``series_patches``.
    """
    if subject is None:
        subject = f'[PATCH] {change_id}'
    if message_id is None:
        message_id = f'{change_id}@example.com'
    conn = (
        tracking.get_db(identifier)
        if tracking.db_exists(identifier)
        else tracking.init_db(identifier)
    )
    tracking.add_series_to_db(
        conn,
        change_id=change_id,
        revision=revision,
        subject=subject,
        sender_name=sender_name,
        sender_email=sender_email,
        sent_at=sent_at,
        message_id=message_id,
        num_patches=num_patches,
    )
    if status != 'new':
        if stamp_activity:
            tracking.update_series_status(conn, change_id, status, revision=revision)
        else:
            conn.execute(
                'UPDATE series SET status = ? WHERE change_id = ? AND revision = ?',
                (status, change_id, revision),
            )
    if message_count is not None:
        conn.execute(
            'UPDATE series SET message_count = ?, seen_message_count = ? '
            'WHERE change_id = ? AND revision = ?',
            (
                message_count,
                seen_message_count if seen_message_count is not None else message_count,
                change_id,
                revision,
            ),
        )
    for rv in revisions or []:
        rv_msgid = message_id if rv == revision else f'{change_id}-v{rv}@example.com'
        tracking.add_revision(conn, change_id, rv, rv_msgid)
    if patch_rows:
        conn.executemany(
            'INSERT INTO series_patches (change_id, revision, position, message_id,'
            ' subject) VALUES (?, ?, ?, ?, ?)',
            [
                (
                    change_id,
                    revision,
                    pos,
                    f'{change_id}-p{pos}@example.com',
                    f'patch {pos}',
                )
                for pos in range(1, num_patches + 1)
            ],
        )
    conn.commit()
    conn.close()


def seed_db(identifier: str, series_list: List[Dict[str, Any]]) -> None:
    """Create the *identifier* database and seed it from a list of kwargs dicts.

    Each dict holds ``change_id`` plus any keyword accepted by ``seed_series``.
    An empty list still creates the (empty) database.
    """
    if not tracking.db_exists(identifier):
        tracking.init_db(identifier).close()
    for s in series_list:
        seed_series(identifier, **s)
