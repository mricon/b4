#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022 CTERA Networks. All Rights Reserved.
#
__author__ = 'Amir Goldstein <amir73il@gmail.com>'

import os
import sys
import b4
import b4.mbox
import mailbox
import email
import shutil
import pathlib
import re

logger = b4.logger

MSG_BODY_TEST_REF_RE = [
        re.compile(r'\b(btrfs|ceph|cifs|ext4|f2fs|generic|nfs|ocfs2|overlay|perf|shared|udf|xfs)/([0-9]{3})\b'),
]

def note_series(lser, notes, tests, fh, rst):
    cover = None
    if lser.has_cover:
        cover = lser.patches[0]
    elif len(lser.patches) > 1:
        cover = lser.patches[1]

    if not cover:
        logger.critical('No cover letter found for patch series')
        return False

    if cover.msgid in notes:
        logger.debug('Duplicate series: %s', cover.subject)
        return True

    notes[cover.msgid] = cover
    config = b4.get_main_config()
    link = (config['linkmask'] % cover.msgid)
    if rst:
        fh.write('\n- `%s <%s>`_\n' % (cover.full_subject, link))
    else:
        fh.write('\n- %s\n  [%s]\n' % (cover.full_subject, link))
    if tests:
        fh.write('  Tests: %s\n' % ' '.join(sorted(tests)))
    return True

def note_latest_series(msgs, notes, fh, rst):
    count = len(msgs)
    logger.debug('---')
    logger.debug('Analyzing %s messages in the thread', count)
    lmbx = b4.LoreMailbox()
    tests = set()
    # Add covers of all revisions first, so we are sure to find the right cover
    # when we add the message
    for msg in msgs:
        lmsg = b4.LoreMessage(msg)
        if lmsg.body is None:
            logger.critical('Could not find a plain part in the message body')
            continue
        lmbx.add_message(msg, needcover=True)
        for tests_re in MSG_BODY_TEST_REF_RE:
            for match in re.finditer(tests_re, lmsg.body):
                test = match.group(0)
                if not test in tests:
                    logger.debug('Found reference to test: %s\n' % test)
                    tests.add(test)

    lser = lmbx.get_series()
    if lser is None or len(lser.patches) == 0:
        logger.critical('No posted patches found')
        return False

    return note_series(lser, notes, tests, fh, rst)


# Breakup patch queue into series and report notes for every series
def release_notes(msgs, cmdargs, fh, rst):
    fh.write('\n');
    if not rst:
        fh.write('---\n')
    notes = {}

    for msg in msgs:
        # Strip prefixes from subject
        lsub = b4.LoreSubject(msg['Subject'])
        if not lsub.subject:
            continue;
        logger.debug('Message: %s', lsub.subject)
        if lsub.counter == 0:
            # Cover letter of PR
            prsub = lsub.subject
            if prsub.startswith('Re: '):
                prsub = prsub[4:]
            prmsgid = b4.LoreMessage.get_clean_msgid(msg, header='In-Reply-To')
            if prmsgid:
                config = b4.get_main_config()
                link = (config['linkmask'] % prmsgid)
                if rst:
                    fh.write('`%s: <%s>`_\n\n' % (prsub, link))
                else:
                    fh.write('Changes in %s:\n  [%s]\n' % (prsub, link))
            continue;

        # Find public-inbox series whose first patch matches this msg subject
        ser_msgs = b4.mbox.get_extra_series([], base_msg=msg, direction=0,
                                         nocache=cmdargs.nocache,
                                         useproject=cmdargs.useproject)
        # Report notes for found series
        found = False
        if len(ser_msgs) > 0:
            found = note_latest_series(ser_msgs, notes, fh, rst)
        if not found:
            fh.write('\n- [PATH ?/?] %s\n' % lsub.subject)

    if not notes:
        logger.critical('No posted patches found')

    fh.write('\n');
    if not rst:
        fh.write('---\n')


def main(cmdargs):
    msgid, msgs = b4.mbox.get_msgs(cmdargs)
    if not msgs:
        logger.critical('Unable to retrieve messages')
        sys.exit(1)

    rst = False
    if cmdargs.outfile is not None:
        logger.info('Writing %s', cmdargs.outfile)
        fh = open(cmdargs.outfile, 'w')
        rst = cmdargs.outfile.endswith('.rst')
    else:
        fh = sys.stdout

    release_notes(msgs, cmdargs, fh, rst)
