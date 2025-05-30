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
import email
import email.parser
import shutil
import pathlib
import argparse
import shlex

from typing import Tuple, Optional, List
from email.message import EmailMessage

logger = b4.logger


def diff_same_thread_series(cmdargs: argparse.Namespace) -> Tuple[Optional[b4.LoreSeries], Optional[b4.LoreSeries]]:
    msgid = b4.get_msgid(cmdargs)
    if not msgid:
        logger.critical('Please pass msgid on the command-line')
        sys.exit(1)
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
    msgs: Optional[List[EmailMessage]]
    if os.path.exists(cachedir) and not cmdargs.nocache:
        logger.info('Using cached copy of the lookup')
        msgs = list()
        for cachemsg in os.listdir(cachedir):
            with open(os.path.join(cachedir, cachemsg), 'rb') as fh:
                msgs.append(email.parser.BytesParser(policy=b4.emlpolicy, _class=EmailMessage).parse(fh))
    else:
        msgs = b4.get_pi_thread_by_msgid(msgid, nocache=cmdargs.nocache)
        if not msgs:
            logger.critical('Unable to retrieve thread: %s', msgid)
            return None, None
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

    if not len(lmbx.series):
        logger.critical('Could not find any patches in the series.')
        sys.exit(1)

    if wantvers and len(wantvers) == 1:
        upper = max(lmbx.series.keys())
        lower = wantvers[0]
    elif wantvers and len(wantvers) == 2:
        upper = max(wantvers)
        lower = min(wantvers)
    else:
        upper = max(lmbx.series.keys())
        lower = upper
        while True:
            lower -= 1
            if lower in lmbx.series:
                break
            if lower < 1:
                logger.critical('Could not find lower series to compare against.')
                sys.exit(1)

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


def diff_mboxes(cmdargs: argparse.Namespace) -> Tuple[Optional[b4.LoreSeries], Optional[b4.LoreSeries]]:
    chunks = list()
    for mboxfile in cmdargs.ambox:
        if not os.path.exists(mboxfile):
            logger.critical('Cannot open %s', mboxfile)
            sys.exit(1)

        mb_msgs = b4.get_msgs_from_mailbox_or_maildir(mboxfile)
        count = len(mb_msgs)

        logger.info('Loading %s messages from %s', count, mboxfile)
        lmbx = b4.LoreMailbox()
        for msg in mb_msgs:
            lmbx.add_message(msg)
        if len(lmbx.series) < 1:
            logger.critical('No valid patches found in %s', mboxfile)
            sys.exit(1)
        if len(lmbx.series) > 1:
            logger.critical('More than one series version in %s, will use latest', mboxfile)

        chunks.append(lmbx.series[max(lmbx.series.keys())])

    return chunks[0], chunks[1]


def main(cmdargs: argparse.Namespace) -> None:
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
    rd_opts = []
    if cmdargs.range_diff_opts:
        sp = shlex.shlex(cmdargs.range_diff_opts, posix=True)
        sp.whitespace_split = True
        rd_opts = list(sp)
    grdcmd = 'git range-diff %s%.12s..%.12s %.12s..%.12s' % (
        " ".join(rd_opts) + " " if rd_opts else "",
        lsc, lec, usc, uec)
    if cmdargs.nodiff:
        logger.info('Success, to compare v%s and v%s:', lser.revision, user.revision)
        logger.info(f'    {grdcmd}')
        sys.exit(0)
    logger.info('---')
    logger.info('Diffing v%s and v%s', lser.revision, user.revision)
    logger.info('    Running: %s', grdcmd)
    gitargs = ['range-diff'] + rd_opts + [f'{lsc}..{lec}', f'{usc}..{uec}']
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
        with open(cmdargs.outdiff, 'w') as fh:
            fh.write(rdiff)
    else:
        logger.info('---')
        sys.stdout.write(rdiff)
