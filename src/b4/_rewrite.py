#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
#
"""Native history rewriting for b4, backed by pygit2.

Replaces the previous git-filter-repo integration for the b4 workflows that
rewrite commits (``store_cover``, the trailer updater, and ``prep --claim``).
Migrates ``refs/notes/*`` entries from old commit OIDs onto the new ones,
which git-filter-repo does not do (newren/git-filter-repo#22).

Rewritten commits are always re-stamped with the *current* user as committer
(fresh timestamp), while authorship is preserved. A tool must never claim
that someone else committed an object it just created -- that is a lie about
provenance, not a credit. See the discussion at
https://lore.kernel.org/all/CAHk-=wj4a_CvL6-=8gobwScstu-gJpX4XbX__hvcE=e9zaQ_9A@mail.gmail.com/
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

import pygit2
from pygit2.enums import ReferenceType, SortMode

import b4

logger = b4.logger


class RewriteTargetMovedError(RuntimeError):
    """Raised when the ref being rewritten moved while the rewrite ran.

    Publishing the rewritten tip anyway would silently discard whatever
    moved the ref, so nothing is published and the newer history stays.
    """

    def __init__(self, refname: str, expected: str, found: Optional[str]) -> None:
        self.refname = refname
        self.expected = expected
        self.found = found
        super().__init__(
            '%s moved from %s to %s during the rewrite; nothing was changed'
            % (refname, expected[:12], found[:12] if found else 'elsewhere')
        )


class ThirdpartyCommitterError(RuntimeError):
    """Raised when a rewrite would touch commits committed by someone else.

    Re-creating such a commit would record the *current* user as its
    committer, falsely attesting that they committed work they did not.
    Callers that genuinely intend to take ownership (``prep --claim``) opt
    in with ``allow_thirdparty_committer=True``.
    """

    def __init__(self, commits: List[Tuple[str, str]]) -> None:
        # commits: [(hex, committer_email), ...]
        self.commits = commits
        super().__init__(
            'refusing to rewrite %d commit(s) committed by another identity'
            % len(commits)
        )


def _collect_notes(
    repo: pygit2.Repository,
    in_range_hex: Iterable[str],
) -> Dict[str, Dict[str, bytes]]:
    """Snapshot ``{notes_ref: {annotated_hex: note_bytes}}`` before rewriting.

    Only keeps entries whose annotated commit is in the rewrite range.
    """
    in_range_set = set(in_range_hex)
    snap: Dict[str, Dict[str, bytes]] = {}
    notes_refs = [r for r in repo.references if r.startswith('refs/notes/')]
    for nref in notes_refs:
        entries: Dict[str, bytes] = {}
        try:
            # The C impl accepts an optional ref positional arg (see
            # pygit2/src/repository.c Repository_notes), but the type stub
            # omits it. Ignore the call-arg mypy complaint here.
            for note in repo.notes(nref):  # type: ignore[call-arg] # ty: ignore[too-many-positional-arguments]
                ahex = str(note.annotated_id)
                if ahex not in in_range_set:
                    continue
                if hasattr(note, 'data') and note.data is not None:
                    entries[ahex] = bytes(note.data)
                else:
                    entries[ahex] = note.message.encode('utf-8', errors='replace')
        except (KeyError, pygit2.GitError):
            continue
        if entries:
            snap[nref] = entries
    return snap


def _current_committer() -> pygit2.Signature:
    """Build a committer signature for the current user with a fresh timestamp.

    Identity comes from the same source as the rest of b4's committer checks
    (``user.name`` / ``user.email``, with the usual env fallbacks), so a
    rewrite stamps the person actually running b4 -- never a preserved,
    possibly third-party committer.
    """
    usercfg = b4.get_user_config()
    name = usercfg.get('name')
    email = usercfg.get('email')
    if not name or not email:
        raise RuntimeError(
            'Cannot determine the current git identity (user.name / user.email) '
            'to use as the committer; configure it and try again.'
        )
    # No time argument -> pygit2 uses "now" with the local UTC offset.
    return pygit2.Signature(str(name), str(email))


def _get_rewrite_target(
    repo: pygit2.Repository, backup_ref: Optional[str]
) -> Tuple[str, str]:
    """Return ``(refname, backup_refname)`` for the ref that HEAD names.

    On a branch, that is the branch, backed up to ``refs/original/<branch>``
    unless *backup_ref* says otherwise. A detached HEAD is rewritten in
    place and stays detached. It has no name to derive a backup from, so
    the caller must name one.
    """
    if repo.head_is_detached:
        if not backup_ref:
            raise RuntimeError('Rewriting a detached HEAD needs an explicit backup ref')
        return 'HEAD', backup_ref
    refname = repo.head.name
    if backup_ref:
        return refname, backup_ref
    return refname, 'refs/original/' + refname.removeprefix('refs/heads/')


def _check_target(repo: pygit2.Repository, refname: str, expected: pygit2.Oid) -> None:
    ref = repo.references.get(refname)
    if ref is None:
        raise RewriteTargetMovedError(refname, str(expected), None)
    if ref.type != ReferenceType.DIRECT:
        # A detached HEAD that now names a branch was checked out elsewhere
        raise RewriteTargetMovedError(refname, str(expected), None)
    if ref.target != expected:
        raise RewriteTargetMovedError(refname, str(expected), str(ref.target))


def _can_lock_refs(repo: pygit2.Repository) -> bool:
    # Reference transactions are new in pygit2 1.19
    return hasattr(repo, 'transaction')


def _publish_tip(
    repo: pygit2.Repository,
    refname: str,
    backup_name: str,
    old_tip: pygit2.Oid,
    new_tip: pygit2.Oid,
    reflog_msg: str,
) -> None:
    """Back up *old_tip* and move *refname* to *new_tip*, if it is unmoved.

    With reference transactions, both refs stay locked from the check to
    the update, so no other git process can move them in between. Older
    pygit2 has no locking, which leaves a short window between checking
    the ref and updating it.
    """
    backup_msg = 'b4: replace backup' if backup_name in repo.references else None
    if _can_lock_refs(repo):
        with repo.transaction() as txn:
            txn.lock_ref(refname)
            txn.lock_ref(backup_name)
            _check_target(repo, refname, old_tip)
            txn.set_target(backup_name, old_tip, message=backup_msg)
            txn.set_target(refname, new_tip, message=reflog_msg)
        return

    _check_target(repo, refname, old_tip)
    if backup_msg:
        logger.debug('Overwriting existing %s', backup_name)
        repo.references[backup_name].set_target(old_tip, backup_msg)
    else:
        repo.references.create(backup_name, old_tip)
    repo.references[refname].set_target(new_tip, reflog_msg)


def rewrite_commits(
    edit_map: Dict[str, str],
    start: str,
    end: str = 'HEAD',
    *,
    reflog_msg: str = 'b4: rewrite commits',
    gitdir: Optional[str] = None,
    force: bool = False,
    allow_thirdparty_committer: bool = False,
    backup_ref: Optional[str] = None,
) -> Dict[str, str]:
    """Rewrite commits in ``(start, end]`` using pygit2.

    For each commit in the walk whose hex OID appears in *edit_map*, the
    provided message replaces the original. Trees, authors, and parent
    relationships are preserved verbatim, but every rewritten commit is
    re-stamped with the *current* user as committer (fresh timestamp): a
    rewrite re-creates the object, so the current user is its committer.
    GPG signatures are dropped (matches the previous git-filter-repo
    behavior). Commits not in *edit_map* are still re-emitted when any
    ancestor inside the range was rewritten, because their parent OIDs
    change.

    With *force* the whole range is re-emitted even when *edit_map* is empty,
    so the committer re-stamp alone takes effect (used by ``prep --claim`` to
    take ownership of commits left under a stale identity). Without it, an
    empty *edit_map* is a no-op.

    Unless *allow_thirdparty_committer* is set, the rewrite refuses (raising
    :class:`ThirdpartyCommitterError`) when any commit in range was committed by
    someone other than the current user: re-creating it would falsely record
    the current user as its committer. ``prep --claim`` opts in deliberately.

    Any git-notes attached (under any ``refs/notes/*`` ref) to commits in
    the rewrite range are migrated to the new commit OIDs with note bytes
    preserved verbatim.

    The ref that HEAD names is the one rewritten, and *end* must be its tip.
    On a branch, that is the branch, and a detached HEAD is moved in place
    and stays detached. The old tip is saved to a backup ref first, replacing
    any earlier backup: ``refs/original/<branch>`` on a branch, *backup_ref*
    when it is given, which is required on a detached HEAD. If the ref no
    longer points at the old tip when the new one is ready,
    :class:`RewriteTargetMovedError` is raised and no ref is changed.
    Appends a reflog entry on the rewritten ref using *reflog_msg*.
    Calls ``b4.ez.run_rewrite_hook('pre')`` before any mutation and
    ``run_rewrite_hook('post')`` after. Both hooks are SKIPPED on the
    no-op fast path.

    Returns ``{old_hex: new_hex}`` for every rewritten commit, or an empty
    dict when there is nothing to do.
    """
    if not edit_map and not force:
        logger.debug('rewrite_commits: empty edit_map, skipping')
        return {}

    # Lazy import to avoid a cycle: ez.py imports from this module.
    from b4.ez import run_rewrite_hook

    if gitdir is None:
        gd = b4.git_get_gitdir()
        if not isinstance(gd, str):
            raise RuntimeError('Unable to locate gitdir for rewrite')
        gitdir = gd
    repo = pygit2.Repository(gitdir)
    target_refname, backup_name = _get_rewrite_target(repo, backup_ref)
    old_tip = repo.revparse_single('HEAD').id
    start_oid = repo.revparse_single(start).id
    end_oid = repo.revparse_single(end).id
    if end_oid != old_tip:
        raise RuntimeError(
            '%s is not the tip of %s; rewriting it would drop the commits above it'
            % (end, target_refname)
        )

    run_rewrite_hook('pre')

    walker = repo.walk(end_oid, SortMode.TOPOLOGICAL | SortMode.REVERSE)
    walker.hide(start_oid)
    old_commits = list(walker)
    if not old_commits:
        run_rewrite_hook('post')
        return {}

    in_range_hex = {str(c.id) for c in old_commits}
    notes_snap = _collect_notes(repo, in_range_hex)

    # The current user committed these rewritten objects, not whoever
    # committed the originals. Stamp one signature for the whole batch.
    committer = _current_committer()

    # Never silently rewrite commits committed by someone else into our name.
    if not allow_thirdparty_committer:
        thirdparty = [
            (str(c.id), c.committer.email)
            for c in old_commits
            if c.committer.email != committer.email
        ]
        if thirdparty:
            run_rewrite_hook('post')
            raise ThirdpartyCommitterError(thirdparty)

    logger.debug(
        'Rewriting %d commit(s) as committer %s', len(old_commits), committer.email
    )
    for c in old_commits:
        subject = c.message.splitlines()[0] if c.message else ''
        logger.debug('  %s %s', str(c.id)[:12], subject)

    oid_map: Dict[str, str] = {}
    new_tip_oid: Optional[pygit2.Oid] = None
    for old in old_commits:
        old_hex = str(old.id)
        new_parent_oids = [
            repo[oid_map[str(p.id)]].id if str(p.id) in oid_map else p.id
            for p in old.parents
        ]
        if old_hex in edit_map:
            new_msg = edit_map[old_hex]
            if not new_msg.endswith('\n'):
                new_msg = new_msg + '\n'
        else:
            new_msg = old.message

        new_oid = repo.create_commit(
            None,  # don't update any ref yet
            old.author,
            committer,
            new_msg,
            old.tree_id,
            new_parent_oids,
        )
        oid_map[old_hex] = str(new_oid)
        new_tip_oid = new_oid

    assert new_tip_oid is not None  # old_commits was non-empty

    try:
        _publish_tip(
            repo, target_refname, backup_name, old_tip, new_tip_oid, reflog_msg
        )
    except RewriteTargetMovedError:
        run_rewrite_hook('post')
        raise

    # Migrate notes (no-op fast path when there were none).
    if notes_snap:
        try:
            sig = repo.default_signature
        except KeyError:
            sig = pygit2.Signature('b4', 'b4@localhost')
        # TODO: batching via TreeBuilder would collapse N notes-ref commits
        # into one per ref. For now, each create_note yields one commit on
        # the notes ref; acceptable for typical b4 series sizes.
        for nref, entries in notes_snap.items():
            for old_hex, note_bytes in entries.items():
                new_hex = oid_map.get(old_hex)
                if not new_hex:
                    continue
                msg = note_bytes.decode('utf-8', errors='replace')
                # create_note() only accepts positional args despite the
                # docstring suggesting defaults. ref=nref, force=True.
                repo.create_note(msg, sig, sig, new_hex, nref, True)

    logger.debug(
        'Rewrote %d commits; migrated notes under %d ref(s)',
        len(oid_map),
        len(notes_snap),
    )
    run_rewrite_hook('post')
    return oid_map
