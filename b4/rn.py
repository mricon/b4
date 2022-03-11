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

logger = b4.logger

def note_series(lser, notes, fh):
    cover = None
    if lser.has_cover:
        cover = lser.patches[0]
    elif len(lser.patches) > 1:
        cover = lser.patches[1]

    if not cover:
        logger.critical('No cover letter found for patch series')
        return

    if cover.msgid in notes:
        logger.debug('Duplicate series: %s', cover.subject)
        return

    notes[cover.msgid] = cover
    config = b4.get_main_config()
    fh.write('\n- %s\n' % cover.full_subject)
    fh.write('  [%s]\n' % (config['linkmask'] % cover.msgid))


def note_latest_series(msgs, notes, fh):
    count = len(msgs)
    logger.debug('---')
    logger.debug('Analyzing %s messages in the thread', count)
    lmbx = b4.LoreMailbox()
    # Add covers of all revisions first, so we are sure to find the right cover
    # when we add the message
    for msg in msgs:
        lmbx.add_message(msg, needcover=True)

    lser = lmbx.get_series()
    if lser is None or len(lser.patches) == 0:
        logger.critical('No posted patches found')
        return None

    note_series(lser, notes, fh)


# Breakup patch queue into series and report notes for every series
def release_notes(msgs, cmdargs, fh):
    fh.write('\n---\n')
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
            fh.write('Changes in %s:\n' % prsub)
            prmsgid = b4.LoreMessage.get_clean_msgid(msg, header='In-Reply-To')
            if prmsgid:
                config = b4.get_main_config()
                fh.write('  [%s]\n' % (config['linkmask'] % prmsgid))
            continue;

        # Find public-inbox series whose first patch matches this msg subject
        ser_msgs = b4.mbox.get_extra_series([], base_msg=msg, direction=0,
                                         nocache=cmdargs.nocache,
                                         useproject=cmdargs.useproject)
        # Report notes for found series
        if len(ser_msgs) > 0:
            note_latest_series(ser_msgs, notes, fh)

    if not notes:
        logger.critical('No posted patches found')

    fh.write('\n---\n')


def main(cmdargs):
    msgid, msgs = b4.mbox.get_msgs(cmdargs)
    if not msgs:
        logger.critical('Unable to retrieve messages')
        sys.exit(1)

    if cmdargs.outfile is not None:
        logger.info('Writing %s', cmdargs.outfile)
        fh = open(cmdargs.outfile, 'w')
    else:
        fh = sys.stdout

    release_notes(msgs, cmdargs, fh)
