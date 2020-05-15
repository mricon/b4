#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import os
import sys
import b4
import b4.mbox
import mailbox
from tempfile import mkstemp


logger = b4.logger


def make_fake_commit_range(gitdir, lser):
    logger.info('Preparing fake-am for v%s: %s', lser.revision, lser.subject)
    with b4.git_temp_worktree(gitdir):
        # We are in a temporary chdir at this time, so writing to a known file should be safe
        mbxf = '.__git-am__'
        mbx = mailbox.mbox(mbxf)
        # Logic largely borrowed from gj_tools
        seenfiles = set()
        for lmsg in lser.patches[1:]:
            logger.debug('Looking at %s', lmsg.full_subject)
            lmsg.load_hashes()
            for fn, fi in lmsg.blob_indexes:
                if fn in seenfiles:
                    # We already processed this file, so this blob won't match
                    continue
                seenfiles.add(fn)
                if set(fi) == {'0'}:
                    # New file creation, nothing to do here
                    logger.debug('  New file: %s', fn)
                    continue
                # Try to grab full ref_id of this hash
                ecode, out = b4.git_run_command(gitdir, ['rev-parse', fi])
                if ecode > 0:
                    logger.critical('  ERROR: Could not find matching blob for %s (%s)', fn, fi)
                    # TODO: better handling
                    return None, None
                logger.debug('  Found matching blob for: %s', fn)
                fullref = out.strip()
                gitargs = ['update-index', '--add', '--cacheinfo', f'0644,{fullref},{fn}']
                ecode, out = b4.git_run_command(None, gitargs)
                if ecode > 0:
                    logger.critical('  ERROR: Could not run update-index for %s (%s)', fn, fullref)
                    return None, None
            mbx.add(lmsg.msg.as_string(policy=b4.emlpolicy).encode('utf-8'))

        mbx.close()
        ecode, out = b4.git_run_command(None, ['write-tree'])
        if ecode > 0:
            logger.critical('ERROR: Could not write fake-am tree')
            return None, None
        treeid = out.strip()
        # At this point we have a worktree with files that should cleanly receive a git am
        gitargs = ['commit-tree', treeid + '^{tree}', '-F', '-']
        ecode, out = b4.git_run_command(None, gitargs, stdin='Initial fake commit'.encode('utf-8'))
        if ecode > 0:
            logger.critical('ERROR: Could not commit-tree')
            return None, None
        start_commit = out.strip()
        b4.git_run_command(None, ['reset', '--hard', start_commit])
        ecode, out = b4.git_run_command(None, ['am', mbxf])
        if ecode > 0:
            logger.critical('ERROR: Could not fake-am version %s', lser.revision)
            return None, None
        ecode, out = b4.git_run_command(None, ['rev-parse', 'HEAD'])
        end_commit = out.strip()
        logger.info('  range: %.12s..%.12s', start_commit, end_commit)

    return start_commit, end_commit


def main(cmdargs):
    msgid = b4.get_msgid(cmdargs)
    if cmdargs.wantvers and len(cmdargs.wantvers) > 2:
        logger.critical('Can only compare two versions at a time')
        sys.exit(1)

    # start by grabbing the mbox provided
    savefile = mkstemp('b4-diff-to')[1]
    mboxfile = b4.get_pi_thread_by_msgid(msgid, savefile, useproject=cmdargs.useproject, nocache=cmdargs.nocache)
    if mboxfile is None:
        logger.critical('Unable to retrieve thread: %s', msgid)
        return
    logger.info('Retrieved %s messages in the thread', len(mboxfile))
    b4.mbox.get_extra_series(mboxfile, direction=-1, wantvers=cmdargs.wantvers)
    mbx = mailbox.mbox(mboxfile)
    count = len(mbx)
    logger.info('---')
    logger.info('Analyzing %s messages in the thread', count)
    lmbx = b4.LoreMailbox()
    for key, msg in mbx.items():
        lmbx.add_message(msg)
    if cmdargs.wantvers and len(cmdargs.wantvers) == 1:
        upper = max(lmbx.series.keys())
        lower = cmdargs.wantvers[0]
    elif cmdargs.wantvers and len(cmdargs.wantvers) == 2:
        upper = max(cmdargs.wantvers)
        lower = min(cmdargs.wantvers)
    else:
        upper = max(lmbx.series.keys())
        lower = min(lmbx.series.keys())

    if upper == lower:
        logger.critical('Could not find previous revision')
        os.unlink(mboxfile)
        sys.exit(1)

    if upper not in lmbx.series:
        logger.critical('Could not find revision %s', upper)
        os.unlink(mboxfile)
        sys.exit(1)
    if lower not in lmbx.series:
        logger.critical('Could not find revision %s', lower)
        os.unlink(mboxfile)
        sys.exit(1)

    # Prepare the lower fake-am range
    lsc, lec = make_fake_commit_range(cmdargs.gitdir, lmbx.series[lower])
    if lsc is None or lec is None:
        logger.critical('---')
        logger.critical('Could not create fake-am range for lower series v%s', lower)
        os.unlink(mboxfile)
        sys.exit(1)
    # Prepare the upper fake-am range
    usc, uec = make_fake_commit_range(cmdargs.gitdir, lmbx.series[upper])
    if usc is None or uec is None:
        logger.critical('---')
        logger.critical('Could not create fake-am range for upper series v%s', upper)
        os.unlink(mboxfile)
        sys.exit(1)
    logger.info('---')
    logger.info('Success, you may now run:')
    logger.info('    git range-diff %.12s..%.12s %.12s..%.12s', lsc, lec, usc, uec)

