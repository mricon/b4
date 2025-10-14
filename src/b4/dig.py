#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import os
import sys
import b4
import argparse
import email.parser

from email.message import EmailMessage
from typing import List, Set, Optional

logger = b4.logger

# Supported diff algorithms we will try to match
try_diff_algos: List[str] = [
    'myers',
    'histogram',
    'patience',
    'minimal',
]


def dig_commitish(cmdargs: argparse.Namespace) -> None:
    config = b4.get_main_config()
    cfg_llval = config.get('linkmask', '')
    if isinstance(cfg_llval, str) and '%s' in cfg_llval:
        linkmask = cfg_llval
    else:
        linkmask = f'{b4.LOREADDR}/%s/'
    # Are we inside a git repo?
    topdir = b4.git_get_toplevel()
    if not topdir:
        logger.error("Not inside a git repository.")
        sys.exit(1)

    # Can we resolve this commit to an object?
    commit = b4.git_revparse_obj(f'{cmdargs.commitish}^0', topdir)
    if not commit:
        logger.error('Cannot find a commit matching %s', cmdargs.commitish)
        sys.exit(1)

    logger.info('Digging into commit %s', commit)
    # Make sure it has exactly one parent (not a merge)
    ecode, out = b4.git_run_command(
        topdir, ['show', '--no-patch', '--format=%p', commit],
    )
    if ecode > 0:
        logger.error('Could not get commit info for %s', commit)
        sys.exit(1)
    if out.strip().count(' ') != 0:
        logger.error('Merge commit detected, please specify a single-parent commit.')
        sys.exit(1)

    # Find commit's author and subject from git
    ecode, out = b4.git_run_command(
        topdir, ['show', '--no-patch', '--format=%ae %s', commit],
    )
    if ecode > 0:
        logger.error('Could not get commit info for %s', commit)
        sys.exit(1)
    fromeml, csubj = out.strip().split(maxsplit=1)
    logger.debug('fromeml=%s, csubj=%s', fromeml, csubj)
    logger.info('Attempting to match by exact patch-id...')
    showargs = [
        '--format=email',
        '--binary',
        '--encoding=utf-8',
        '--find-renames',
    ]
    # Keep a record so we don't try git-patch-id on identical patches
    bpatches: Set[bytes] = set()
    lmbx: Optional[b4.LoreMailbox] = None
    for algo in try_diff_algos:
        logger.debug('Trying with diff-algorithm=%s', algo)
        algoarg = f'--diff-algorithm={algo}'
        logger.debug('showargs=%s', showargs + [algoarg])
        ecode, bpatch = b4.git_run_command(
            topdir, ['show'] + showargs + [algoarg] + [commit],
            decode=False,
        )
        if ecode > 0:
            logger.error('Could not get a patch out of %s', commit)
            sys.exit(1)
        if bpatch in bpatches:
            logger.debug('Already saw this patch, skipping diff-algorithm=%s', algo)
            continue
        bpatches.add(bpatch)
        gitargs = ['patch-id', '--stable']
        ecode, out = b4.git_run_command(topdir, gitargs, stdin=bpatch)
        if ecode > 0 or not len(out.strip()):
            logger.error('Could not compute patch-id for commit %s', commit)
            sys.exit(1)
        patch_id = out.split(maxsplit=1)[0]
        logger.debug('Patch-id for commit %s is %s', commit, patch_id)
        logger.info('Trying to find matching series by patch-id %s', patch_id)
        lmbx = b4.get_series_by_patch_id(patch_id)
        if lmbx:
            logger.info('Found matching series by patch-id')
            break

    if not lmbx:
        logger.info('Attempting to match by author and subject...')
        q = '(s:"%s" AND f:"%s")' % (csubj.replace('"', ''), fromeml)
        msgs = b4.get_pi_search_results(q)
        if msgs:
            logger.info('Found %s matching messages', len(msgs))
            lmbx = b4.LoreMailbox()
            for msg in msgs:
                lmbx.add_message(msg)
        else:
            logger.error('Could not find anything matching commit %s', commit)
            # Look at the commit message and find any Link: trailers
            ecode, out = b4.git_run_command(
                topdir, ['show', '--no-patch', '--format=%B', commit],
            )
            if ecode > 0:
                logger.error('Could not get commit message for %s', commit)
                sys.exit(1)
            trailers, _ = b4.LoreMessage.find_trailers(out)
            ltrs = [t for t in trailers if t.name.lower() == 'link']
            if ltrs:
                logger.info('---')
                logger.info('Try following these Link trailers:')
                for ltr in ltrs:
                    logger.info('  %s', ltr.as_string())
            sys.exit(1)

    # Grab the latest series and see if we have a change_id
    revs = list(lmbx.series.keys())
    revs.sort(key=lambda r: lmbx.series[r].submission_date or 0)

    change_id: Optional[str] = None
    lser = lmbx.get_series(codereview_trailers=False)
    for rev in revs:
        change_id = lmbx.series[rev].change_id
        if not change_id:
            continue
        logger.info('Backfilling any missing series by change-id')
        logger.debug('change_id=%s', change_id)
        # Fill in the rest of the series by change_id
        q = f'nq:"change-id:{change_id}"'
        q_msgs = b4.get_pi_search_results(q, full_threads=True)
        if q_msgs:
            for q_msg in q_msgs:
                lmbx.add_message(q_msg)
        break

    logger.debug('Number of series in the mbox: %d', len(lmbx.series))
    logger.info('---')
    logger.info('This patch is present in the following series:')
    logger.info('---')
    for rev in revs:
        firstmsg: Optional[b4.LoreMessage] = None
        pref = f'  v{rev}: '
        lser = lmbx.series[rev]
        lmsg: Optional[b4.LoreMessage] = None
        if lser.has_cover:
            firstmsg = lser.patches[0]
        for lmsg in lser.patches[1:]:
            if lmsg is None:
                continue
            if firstmsg is None:
                firstmsg = lmsg
            if lmsg.git_patch_id == patch_id:
                logger.debug('Matched by exact patch-id')
                break
            if lmsg.subject == csubj:
                logger.debug('Matched by subject')
                break

        if firstmsg is None:
            logger.error('Internal error: no patches in the series?')
            sys.exit(1)
        if lmsg is None:
            # Use the first patch in the series as a fallback
            lmsg = firstmsg
        logger.info('%s%s', pref, lmsg.full_subject)
        logger.info('%s%s', ' ' * len(pref), linkmask % lmsg.msgid)


def main(cmdargs: argparse.Namespace) -> None:
    if cmdargs.commitish:
        dig_commitish(cmdargs)
