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
import email
import shutil
import pathlib

logger = b4.logger


def diff_same_thread_series(cmdargs):
    msgid = b4.get_msgid(cmdargs)
    wantvers = cmdargs.wantvers
    if wantvers and len(wantvers) > 2:
        logger.critical('Can only compare two versions at a time')
        sys.exit(1)

    # start by grabbing the mbox provided
    # Do we have a cache of this lookup?
    identifier = msgid
    if wantvers:
        identifier += '-' + '-'.join([str(x) for x in wantvers])

    cachedir = b4.get_cache_file(identifier, suffix='diff.msgs')
    if os.path.exists(cachedir) and not cmdargs.nocache:
        logger.info('Using cached copy of the lookup')
        msgs = list()
        for msg in os.listdir(cachedir):
            with open(os.path.join(cachedir, msg), 'rb') as fh:
                msgs.append(email.message_from_binary_file(fh))
    else:
        msgs = b4.get_pi_thread_by_msgid(msgid, nocache=cmdargs.nocache)
        if not msgs:
            logger.critical('Unable to retrieve thread: %s', msgid)
            return
        msgs = b4.mbox.get_extra_series(msgs, direction=-1, wantvers=wantvers)
        if os.path.exists(cachedir):
            shutil.rmtree(cachedir)
        pathlib.Path(cachedir).mkdir(parents=True)
        at = 0
        for msg in msgs:
            with open(os.path.join(cachedir, '%04d' % at), 'wb') as fh:
                fh.write(msg.as_bytes(policy=b4.emlpolicy))
            at += 1

    count = len(msgs)
    logger.info('---')
    logger.info('Analyzing %s messages in the thread', count)
    lmbx = b4.LoreMailbox()
    for msg in msgs:
        lmbx.add_message(msg)

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
        logger.critical('ERROR: Could not auto-find previous revision')
        logger.critical('       Run "b4 am -T" manually, then "b4 diff -m mbx1 mbx2"')
        return None, None

    if upper not in lmbx.series:
        return None, None

    if lower not in lmbx.series:
        return None, None

    if not lmbx.series[lower].complete:
        lmbx.partial_reroll(lower, sloppytrailers=False)

    if not lmbx.series[upper].complete:
        lmbx.partial_reroll(upper, sloppytrailers=False)

    return lmbx.series[lower], lmbx.series[upper]


def diff_mboxes(cmdargs):
    chunks = list()
    for mboxfile in cmdargs.ambox:
        if not os.path.exists(mboxfile):
            logger.critical('Cannot open %s', mboxfile)
            return None, None

        if os.path.isdir(mboxfile):
            mbx = mailbox.Maildir(mboxfile)
        else:
            mbx = mailbox.mbox(mboxfile)
        count = len(mbx)
        logger.info('Loading %s messages from %s', count, mboxfile)
        lmbx = b4.LoreMailbox()
        for key, msg in mbx.items():
            lmbx.add_message(msg)
        if len(lmbx.series) < 1:
            logger.critical('No valid patches found in %s', mboxfile)
            sys.exit(1)
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
    lsc, lec = lser.make_fake_am_range(gitdir=cmdargs.gitdir)
    if lsc is None or lec is None:
        logger.critical('---')
        logger.critical('Could not create fake-am range for lower series v%s', lser.revision)
        sys.exit(1)
    # Prepare the upper fake-am range
    usc, uec = user.make_fake_am_range(gitdir=cmdargs.gitdir)
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
