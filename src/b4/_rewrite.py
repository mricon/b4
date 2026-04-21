#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
#
"""Native message-only history rewriting for b4, backed by pygit2.

Replaces the previous git-filter-repo integration for the two b4 workflows
that rewrite commit messages (``store_cover`` and the trailer updater).
Migrates ``refs/notes/*`` entries from old commit OIDs onto the new ones,
which git-filter-repo does not do (newren/git-filter-repo#22).
"""

from __future__ import annotations

from typing import Dict, Iterable, Optional

import pygit2
from pygit2.enums import SortMode

import b4

logger = b4.logger


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


def rewrite_commit_messages(
    edit_map: Dict[str, str],
    start: str,
    end: str = 'HEAD',
    *,
    reflog_msg: str = 'b4: rewrite commit messages',
    gitdir: Optional[str] = None,
) -> Dict[str, str]:
    """Rewrite commit messages in ``(start, end]`` using pygit2.

    For each commit in the walk whose hex OID appears in *edit_map*, the
    provided message replaces the original. Trees, authors, committers, and
    parent relationships are preserved verbatim. GPG signatures are dropped
    (matches the previous git-filter-repo behavior). Commits not in
    *edit_map* are still re-emitted when any ancestor inside the range was
    rewritten, because their parent OIDs change.

    Any git-notes attached (under any ``refs/notes/*`` ref) to commits in
    the rewrite range are migrated to the new commit OIDs with note bytes
    preserved verbatim.

    Creates ``refs/original/<branch>`` as a backup before updating the live
    branch ref. Appends a reflog entry on the branch ref using *reflog_msg*.
    Calls ``b4.ez.run_rewrite_hook('pre')`` before any mutation and
    ``run_rewrite_hook('post')`` after. Both hooks are SKIPPED when
    *edit_map* is empty (no-op fast path).

    Returns ``{old_hex: new_hex}`` for every rewritten commit, or an empty
    dict when there is nothing to do.
    """
    if not edit_map:
        logger.debug('rewrite_commit_messages: empty edit_map, skipping')
        return {}

    # Lazy import to avoid a cycle: ez.py imports from this module.
    from b4.ez import run_rewrite_hook

    run_rewrite_hook('pre')

    if gitdir is None:
        gd = b4.git_get_gitdir()
        if not isinstance(gd, str):
            raise RuntimeError('Unable to locate gitdir for rewrite')
        gitdir = gd
    repo = pygit2.Repository(gitdir)

    head_ref = repo.head  # raises if HEAD is detached; callers guard this
    branch_refname = head_ref.name

    start_oid = repo.revparse_single(start).id
    end_oid = repo.revparse_single(end).id

    walker = repo.walk(end_oid, SortMode.TOPOLOGICAL | SortMode.REVERSE)
    walker.hide(start_oid)
    old_commits = list(walker)
    if not old_commits:
        run_rewrite_hook('post')
        return {}

    in_range_hex = {str(c.id) for c in old_commits}
    notes_snap = _collect_notes(repo, in_range_hex)

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
            old.committer,
            new_msg,
            old.tree_id,
            new_parent_oids,
        )
        oid_map[old_hex] = str(new_oid)
        new_tip_oid = new_oid

    assert new_tip_oid is not None  # old_commits was non-empty

    # Backup the original branch tip, then move the branch to the new tip.
    short = branch_refname
    if short.startswith('refs/heads/'):
        short = short[len('refs/heads/') :]
    backup_name = f'refs/original/{short}'
    old_tip = head_ref.target
    if backup_name in repo.references:
        logger.debug('Overwriting existing %s', backup_name)
        repo.references[backup_name].set_target(old_tip, 'b4: replace backup')
    else:
        repo.references.create(backup_name, old_tip)

    repo.references[branch_refname].set_target(new_tip_oid, reflog_msg)

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
