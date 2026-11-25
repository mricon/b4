#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Recognize tracked patches that have already landed in another tree.

Only remote-tracking branches the user already has are read. b4 never
fetches for this, so the answer is as fresh as the user's last fetch.

Landed patches are skipped without a human looking at them, so only exact
evidence counts: a commit naming the posting in a Link: or Message-ID:
trailer, or a commit with the very same diff. A missed match leaves the
patch up for review, which is safe; a wrong one would hide it.
"""

import datetime
from typing import Dict, List, Optional, Set, Tuple

import b4

logger = b4.logger

CONFIG_KEY = 'review-check-landed'

# Commit dates can predate the posting: git am --committer-date-is-author-date
# keeps the date the author wrote the patch, which may be weeks before sending.
SINCE_SLACK = datetime.timedelta(days=90)


def get_landed_remotes(topdir: str) -> List[str]:
    """Return the configured remotes to check, keeping only ones that exist."""
    val = b4.get_main_config().get(CONFIG_KEY)
    if isinstance(val, str):
        configured = [val]
    elif isinstance(val, list):
        configured = [str(v) for v in val if v]
    else:
        configured = []
    existing = set(b4.git_get_command_lines(topdir, ['remote']))
    remotes: List[str] = []
    for remote in configured:
        if remote in remotes:
            continue
        if remote not in existing:
            logger.warning(
                'b4.%s: no remote named "%s", ignoring it', CONFIG_KEY, remote
            )
            continue
        remotes.append(remote)
    return remotes


class LandedIndex:
    """Commits on the configured remotes, indexed for finding posted patches."""

    def __init__(
        self,
        gitdir: Optional[str],
        by_msgid: Dict[str, str],
        by_subject: Dict[str, List[str]],
    ) -> None:
        self._gitdir = gitdir
        self._by_msgid = by_msgid
        self._by_subject = by_subject
        self._patch_ids: Dict[str, Set[str]] = {}

    @classmethod
    def build(
        cls,
        gitdir: Optional[str],
        remotes: List[str],
        posted_since: datetime.datetime,
    ) -> 'LandedIndex':
        """Read the remotes' commits once, from shortly before *posted_since*."""
        by_msgid: Dict[str, str] = {}
        by_subject: Dict[str, List[str]] = {}
        if not remotes:
            return cls(gitdir, by_msgid, by_subject)
        since = int((posted_since - SINCE_SLACK).timestamp())
        gitargs = [
            'log',
            '-z',
            '--no-merges',
            f'--since=@{since}',
            '--format=%H%x1f%s%x1f%(trailers:key=Link,key=Message-ID,unfold,separator=%x1e)',
        ]
        gitargs += [f'--glob=refs/remotes/{remote}/*' for remote in remotes]
        gitargs.append('--')
        ecode, out = b4.git_run_command(gitdir, gitargs)
        if ecode > 0:
            logger.warning('Could not read commits from %s', ', '.join(remotes))
            return cls(gitdir, by_msgid, by_subject)
        for record in out.split('\x00'):
            fields = record.strip('\n').split('\x1f')
            if len(fields) != 3:
                continue
            commit, subject, trailer_lines = fields
            by_subject.setdefault(subject, []).append(commit)
            trailers = []
            for line in trailer_lines.split('\x1e'):
                name, sep, value = line.partition(':')
                if sep:
                    trailers.append(
                        b4.LoreTrailer(name=name.strip(), value=value.strip())
                    )
            for msgid in b4.get_trailer_msgids(trailers):
                by_msgid.setdefault(msgid, commit)
        return cls(gitdir, by_msgid, by_subject)

    def find(self, lmsg: b4.LoreMessage) -> Optional[Tuple[str, str]]:
        """Return (commit, how) when *lmsg* has landed, else None.

        *how* is 'msgid' or 'patch-id'. The subject only picks which commits
        get the costly patch-id check; it never decides on its own.
        """
        commit = self._by_msgid.get(lmsg.msgid)
        if commit:
            return commit, 'msgid'
        patch_id = lmsg.git_patch_id
        if not patch_id:
            return None
        for commit in self._by_subject.get(lmsg.subject, []):
            if patch_id in self._commit_patch_ids(commit):
                return commit, 'patch-id'
        return None

    def _commit_patch_ids(self, commit: str) -> Set[str]:
        if commit not in self._patch_ids:
            try:
                self._patch_ids[commit] = {
                    pid for _algo, pid in b4.git_commit_patch_ids(self._gitdir, commit)
                }
            except RuntimeError as ex:
                logger.debug('%s', ex)
                self._patch_ids[commit] = set()
        return self._patch_ids[commit]
