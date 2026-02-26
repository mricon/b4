#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import sys
import b4
import argparse
import re
import urllib.parse
import datetime

import b4.mbox

from email.message import EmailMessage
import email.utils
from typing import List, Set, Optional

logger = b4.logger

# Supported diff algorithms we will try to match
try_diff_algos: List[str] = [
    'myers',
    'histogram',
    'patience',
    'minimal',
]


def try_links(links: Set[str]) -> None:
    logger.info('Try following these Link trailers:')
    for link in links:
        logger.info('  Link: %s', link)


def print_one_match(subject: str, link: str) -> None:
    logger.info('---')
    logger.info(subject)
    sys.stdout.write(f'{link}\n')


def get_all_msgids_from_urls(urls: Set[str]) -> Set[str]:
    msgids: Set[str] = set()
    for url in urls:
        matches = re.search(r'^https?://[^@]+/([^/]+@[^/]+)', url, re.IGNORECASE)
        if matches:
            chunks = matches.groups()
            msgids.add(urllib.parse.unquote(chunks[0]))
    return msgids


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
    try:
        commit = b4.git_revparse_obj(f'{cmdargs.commitish}^0', topdir)
    except RuntimeError:
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

    # Look at the commit message and find any Link: trailers
    links: Set[str] = set()
    ecode, out = b4.git_run_command(
        topdir, ['show', '--no-patch', '--format=%B', commit],
    )
    if ecode > 0:
        logger.error('Could not get commit message for %s', commit)
        sys.exit(1)
    trailers, _ = b4.LoreMessage.find_trailers(out)
    ltrs = [t for t in trailers if t.name.lower() == 'link']
    if ltrs:
        links = set(ltr.value for ltr in ltrs)

    msgids = get_all_msgids_from_urls(links)
    # Make a copy for finding best match later
    linked_msgids = set(msgids)

    # Find commit's author and subject from git
    ecode, out = b4.git_run_command(
        topdir, ['show', '--no-patch', '--format=%as %ae %s', commit],
    )
    if ecode > 0:
        logger.error('Could not get commit info for %s', commit)
        sys.exit(1)
    cdate, fromeml, csubj = out.strip().split(maxsplit=2)
    logger.debug('cdate=%s, fromeml=%s, csubj=%s', cdate, fromeml, csubj)
    # Add 24 hours to the date to account for timezones
    # First, parse YYYY-MM-DD into datetime
    cdate_dt = datetime.datetime.strptime(cdate, '%Y-%m-%d')
    cdate_dt += datetime.timedelta(days=1)
    # Convert into YYYYMMDD format for xapian range search
    pidate = cdate_dt.strftime('%Y%m%d')
    logger.info('Attempting to match by exact patch-id...')
    showargs = [
        '--format=email',
        '--binary',
        '--encoding=utf-8',
        '--find-renames',
    ]
    # Keep a record so we don't try git-patch-id on identical patches
    bpatches: Set[bytes] = set()
    msgs: Optional[List[EmailMessage]] = None
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
        logger.info('Trying to find matching series by patch-id %s (%s)', patch_id, algo)
        # Limit lookup by date prior to the commit date, to weed out any false-positives from
        # backports or from erroneously resent series
        extra_query = f'AND d:..{pidate}'
        logger.debug('extra_query=%s', extra_query)
        msgs = b4.get_msgs_by_patch_id(patch_id, nocache=cmdargs.nocache, extra_query=extra_query)
        if msgs:
            logger.info('Found matching series by patch-id')
            for msg in msgs:
                msgid = b4.LoreMessage.get_clean_msgid(msg)
                if msgid:
                    logger.debug('Adding from patch-id matches: %s', msgid)
                    msgids.add(msgid)
            break

    if not msgs:
        logger.info('Attempting to match by author and subject...')
        q = '(s:"%s" AND f:"%s" AND d:..%s)' % (csubj.replace('"', ''), fromeml, pidate)
        logger.debug('q=%s', q)
        msgs = b4.get_pi_search_results(q, nocache=cmdargs.nocache, full_threads=False)
        if msgs:
            for msg in msgs:
                msgid = b4.LoreMessage.get_clean_msgid(msg)
                if msgid:
                    logger.debug('Adding from author+subject matches: %s', msgid)
                    msgids.add(msgid)
        if not msgs and not msgids:
            logger.error('Could not find anything matching commit %s', commit)
            if links:
                try_links(links)
            sys.exit(1)

    logger.info('Will consider promising messages: %s', len(msgids))
    logger.debug('msgids: %s', msgids)
    # Go one by one and grab threads by message-id
    seen_msgids: Set[str] = set()
    lmbxs: List[b4.LoreMailbox] = list()
    for msgid in msgids:
        if not msgid or msgid in seen_msgids:
            logger.debug('Skipping duplicate or invalid msgid %s', msgid)
            continue
        seen_msgids.add(msgid)
        logger.debug('Fetching thread by msgid %s', msgid)
        lmbx = b4.get_series_by_msgid(msgid)
        if not lmbx:
            logger.error('Could not fetch thread for msgid %s, skipping', msgid)
            continue
        if not lmbx.series:
            logger.debug('No series found in this mailbox, skipping')
            continue
        lmbxs.append(lmbx)

    if not lmbxs:
        logger.error('Could not fetch any threads for the matching messages!')
        sys.exit(1)

    lsers: List[b4.LoreSeries] = list()
    for lmbx in lmbxs:
        maxrev = max(lmbx.series.keys())
        if cmdargs.all_series and len(lmbx.series) < maxrev:
            logger.debug('Fetching prior series')
            # Do we have a change-id in this series?
            lser = lmbx.get_series(codereview_trailers=False)
            fillin_q: str = ''
            if lser and lser.change_id:
                logger.debug('Found change-id %s in the series', lser.change_id)
                fillin_q = f'nq:"change-id:{lser.change_id}"'
            elif lser and lser.subject and lser.fromemail:
                # We're going to match by first patch/cover letter subject and author.
                # It's not perfect, but it's the best we can do without a change-id.
                fillin_q = '(s:"%s" AND f:"%s")' % (lser.subject.replace('"', ''), lser.fromemail)
            if fillin_q:
                fillin_q += f' AND d:..{pidate}'
                logger.debug('fillin_q=%s', fillin_q)
                q_msgs = b4.get_pi_search_results(fillin_q, nocache=cmdargs.nocache, full_threads=True)
                if q_msgs:
                    for q_msg in q_msgs:
                        lmbx.add_message(q_msg)
                        q_msgid = b4.LoreMessage.get_clean_msgid(q_msg)
                        if q_msgid:
                            seen_msgids.add(q_msgid)

        for lser in lmbx.series.values():
            if lser and lser not in lsers:
                lsers.append(lser)

    if not len(lsers):
        logger.error('Could not find any series containing this patch!')
        if links:
            try_links(links)
        sys.exit(1)

    lsers.sort(key=lambda r: r.submission_date or 0)
    logger.debug('Number of matching series: %d', len(lsers))
    lmsg: Optional[b4.LoreMessage] = None
    if not cmdargs.all_series:
        all_lmsgs: List[b4.LoreMessage] = list()
        for lser in reversed(lsers):
            for lmsg in lser.patches[1:]:
                if lmsg is None:
                    continue
                all_lmsgs.append(lmsg)

        logger.debug('Number of candidate patches: %d', len(all_lmsgs))
        # First try to find the exact message by Linked message-id
        best_match: Optional[b4.LoreMessage] = None
        for lmsg in all_lmsgs:
            if lmsg.msgid in linked_msgids:
                logger.debug('matched by message-id')
                best_match = lmsg
                break
        if not best_match:
            # Next, try to find by exact patch-id
            for lmsg in all_lmsgs:
                if lmsg.git_patch_id == patch_id:
                    logger.debug('matched by exact patch-id')
                    best_match = lmsg
                    break
        if not best_match:
            # Finally, try to find by subject match
            for lmsg in all_lmsgs:
                if lmsg.subject == csubj:
                    logger.debug('matched by subject')
                    best_match = lmsg
                    break
        if not best_match:
            logger.error('Could not find a matching patch in any series!')
            if links:
                try_links(links)
            sys.exit(1)

        print_one_match(best_match.full_subject, linkmask % best_match.msgid)

        if cmdargs.save_mbox:
            msgs = b4.get_pi_thread_by_msgid(best_match.msgid, quiet=True)
            if not msgs:
                logger.error('Could not fetch thread for msgid %s', best_match.msgid)
                sys.exit(1)
            logger.info('---')
            b4.mbox.save_msgs_as_mbox(cmdargs.save_mbox, msgs)
            logger.info('Saved matched thread to %s', cmdargs.save_mbox)
            return

        if cmdargs.who:
            allto = email.utils.getaddresses(best_match.msg.get_all('to', []))
            allcc = email.utils.getaddresses(best_match.msg.get_all('cc', []))
            allrto = email.utils.getaddresses(best_match.msg.get_all('reply-to', []))
            if not allrto:
                allrto = [(best_match.fromname, best_match.fromemail)]
            allwho: List[Tuple[str, str]] = list()
            seen_addrs: Set[str] = set()
            # Make it unique, but keep the order
            for pair in allrto + allto + allcc:
                if pair[1] not in seen_addrs:
                    seen_addrs.add(pair[1])
                    allwho.append(pair)
            logger.info('---')
            logger.info('People originally included in this patch:')
            logger.info(b4.format_addrs(allwho, header_safe=False))

        return

    logger.info('---')
    logger.info('This patch belongs in the following series:')
    logger.info('---')
    for lser in lsers:
        firstmsg: Optional[b4.LoreMessage] = None
        pref = f'  v{lser.revision}: '
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
        logger.info('%s%s', pref, firstmsg.full_subject)
        logger.info('%sDate: %s, From: %s <%s>', ' ' * len(pref),
                    firstmsg.date.strftime('%Y-%m-%d'), firstmsg.fromname, firstmsg.fromemail)
        logger.info('%s%s', ' ' * len(pref), linkmask % lmsg.msgid)


def main(cmdargs: argparse.Namespace) -> None:
    if cmdargs.commitish:
        dig_commitish(cmdargs)
