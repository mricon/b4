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
import shutil
import urllib.parse

from tempfile import mkstemp


logger = b4.logger


def make_fake_commit_range(gitdir, lser):
    start_commit = end_commit = None
    # Do we have it in cache already?
    cachedir = b4.get_cache_dir()
    # Use the msgid of the first non-None patch in the series
    msgid = None
    for lmsg in lser.patches:
        if lmsg is not None:
            msgid = lmsg.msgid
            break
    if msgid is None:
        logger.critical('Cannot operate on an empty series')
        return None, None
    cachefile = os.path.join(cachedir, '%s.fakeam' % urllib.parse.quote_plus(msgid))
    if os.path.exists(cachefile):
        stalecache = False
        with open(cachefile, 'r') as fh:
            cachedata = fh.read()
            chunks = cachedata.strip().split()
            if len(chunks) == 2:
                start_commit, end_commit = chunks
            else:
                stalecache = True
        if start_commit is not None and end_commit is not None:
            # Make sure they are still there
            ecode, out = b4.git_run_command(gitdir, ['cat-file', '-e', start_commit])
            if ecode > 0:
                stalecache = True
            else:
                ecode, out = b4.git_run_command(gitdir, ['cat-file', '-e', end_commit])
                if ecode > 0:
                    stalecache = True
                else:
                    logger.debug('Using previously generated range')
                    return start_commit, end_commit

        if stalecache:
            logger.debug('Stale cache for [v%s] %s', lser.revision, lser.subject)
            os.unlink(cachefile)

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
            if not len(lmsg.blob_indexes):
                logger.critical('ERROR: some patches do not have indexes')
                logger.critical('       automatic range-diff would be misleading')
                return None, None
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

    with open(cachefile, 'w') as fh:
        logger.debug('Saving into cache: %s', cachefile)
        logger.debug('    %s..%s', start_commit, end_commit)
        fh.write(f'{start_commit} {end_commit}\n')

    return start_commit, end_commit


def diff_same_thread_series(cmdargs):
    msgid = b4.get_msgid(cmdargs)
    wantvers = cmdargs.wantvers
    if wantvers and len(wantvers) > 2:
        logger.critical('Can only compare two versions at a time')
        sys.exit(1)

    # start by grabbing the mbox provided
    savefile = mkstemp('b4-diff-to')[1]
    # Do we have a cache of this lookup?
    cachedir = b4.get_cache_dir()
    if wantvers:
        cachefile = os.path.join(cachedir, '%s-%s.diff.mbx' % (urllib.parse.quote_plus(msgid),
                                                               '-'.join([str(x) for x in wantvers])))
    else:
        cachefile = os.path.join(cachedir, '%s-latest.diff.mbx' % urllib.parse.quote_plus(msgid))
    if os.path.exists(cachefile) and not cmdargs.nocache:
        logger.info('Using cached copy of the lookup')
        shutil.copyfile(cachefile, savefile)
        mboxfile = savefile
    else:
        mboxfile = b4.get_pi_thread_by_msgid(msgid, savefile, useproject=cmdargs.useproject, nocache=cmdargs.nocache)
        if mboxfile is None:
            logger.critical('Unable to retrieve thread: %s', msgid)
            return
        b4.mbox.get_extra_series(mboxfile, direction=-1, wantvers=wantvers)
        shutil.copyfile(mboxfile, cachefile)

    mbx = mailbox.mbox(mboxfile)
    count = len(mbx)
    logger.info('---')
    logger.info('Analyzing %s messages in the thread', count)
    lmbx = b4.LoreMailbox()
    for key, msg in mbx.items():
        lmbx.add_message(msg)

    mbx.close()
    os.unlink(mboxfile)

    if wantvers and len(wantvers) == 1:
        upper = max(lmbx.series.keys())
        lower = wantvers[0]
    elif wantvers and len(wantvers) == 2:
        upper = max(wantvers)
        lower = min(wantvers)
    else:
        upper = max(lmbx.series.keys())
        lower = min(lmbx.series.keys())

    if upper == lower:
        logger.critical('Could not find previous revision')
        return None, None

    if upper not in lmbx.series:
        return None, None

    if lower not in lmbx.series:
        return None, None

    return lmbx.series[lower], lmbx.series[upper]


def diff_mboxes(cmdargs):
    chunks = list()
    for mboxfile in cmdargs.ambox:
        if not os.path.exists(mboxfile):
            logger.critical('Cannot open %s', mboxfile)
            return None, None

        mbx = mailbox.mbox(mboxfile)
        count = len(mbx)
        logger.info('Loading %s messages from %s', count, mboxfile)
        lmbx = b4.LoreMailbox()
        for key, msg in mbx.items():
            lmbx.add_message(msg)
        if len(lmbx.series) > 1:
            logger.critical('More than one series version in %s, will use latest', mboxfile)

        chunks.append(lmbx.series[max(lmbx.series.keys())])

    return chunks


def main(cmdargs):
    if cmdargs.ambox is not None:
        lser, user = diff_mboxes(cmdargs)
    else:
        lser, user = diff_same_thread_series(cmdargs)

    if lser is None or user is None:
        sys.exit(1)

    # Prepare the lower fake-am range
    lsc, lec = make_fake_commit_range(cmdargs.gitdir, lser)
    if lsc is None or lec is None:
        logger.critical('---')
        logger.critical('Could not create fake-am range for lower series v%s', lser.revision)
        sys.exit(1)
    # Prepare the upper fake-am range
    usc, uec = make_fake_commit_range(cmdargs.gitdir, user)
    if usc is None or uec is None:
        logger.critical('---')
        logger.critical('Could not create fake-am range for upper series v%s', user.revision)
        sys.exit(1)
    grdcmd = 'git range-diff %.12s..%.12s %.12s..%.12s' % (lsc, lec, usc, uec)
    if cmdargs.nodiff:
        logger.info('Success, to compare v%s and v%s:', lser.revision, user.revision)
        logger.info(f'    {grdcmd}')
        sys.exit(0)
    logger.info('Diffing v%s and v%s', lser.revision, user.revision)
    logger.info('    Running: %s', grdcmd)
    gitargs = ['range-diff', f'{lsc}..{lec}', f'{usc}..{uec}']
    if cmdargs.outdiff is None or cmdargs.color:
        gitargs.append('--color')
    ecode, rdiff = b4.git_run_command(cmdargs.gitdir, gitargs)
    if ecode > 0:
        logger.critical('Unable to generate diff')
        logger.critical('Try running it yourself:')
        logger.critical(f'    {grdcmd}')
        sys.exit(1)
    if cmdargs.outdiff is not None:
        logger.info('Writing %s', cmdargs.outdiff)
        fh = open(cmdargs.outdiff, 'w')
    else:
        logger.info('---')
        fh = sys.stdout
    fh.write(rdiff)
