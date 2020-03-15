#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
#

import sys
import os
import re
import email
import email.utils
import email.message
import smtplib
import mailbox
import b4

logger = b4.logger


def create_attestation(cmdargs):
    attlines = list()
    subject = 'Patch attestation'
    for patchfile in cmdargs.patchfile:
        with open(patchfile, 'r', encoding='utf-8') as fh:
            content = fh.read()
            if content.find('From') != 0:
                logger.info('SKIP | %s', os.path.basename(patchfile))
                continue
            msg = email.message_from_string(content)
            lmsg = b4.LoreMessage(msg)
            lmsg.load_hashes()
            att = lmsg.attestation
            if att is None:
                logger.info('SKIP | %s', os.path.basename(patchfile))
                # See if it's a cover letter
                if lmsg.counters_inferred or lmsg.counter > 0:
                    # No
                    continue
                newprefs = list()
                for prefix in lmsg.lsubject.prefixes:
                    if prefix.lower() == 'patch':
                        newprefs.append('PSIGN')
                    elif prefix == '%s/%s' % (lmsg.counter, lmsg.expected):
                        newprefs.append('X/%s' % lmsg.expected)
                    else:
                        newprefs.append(prefix)
                subject = '[%s] %s' % (' '.join(newprefs), lmsg.subject)
                continue
            logger.info('HASH | %s', os.path.basename(patchfile))
            attlines.append('%s:' % att.attid)
            attlines.append('  i: %s' % att.i)
            attlines.append('  m: %s' % att.m)
            attlines.append('  p: %s' % att.p)

    payload = '\n'.join(attlines)

    usercfg = b4.get_user_config()
    gpgargs = list()
    if 'signingkey' in usercfg:
        gpgargs += ['-u', usercfg['signingkey']]
    gpgargs += ['--clearsign',
                '--comment', 'att-fmt-ver: %s' % b4.ATTESTATION_FORMAT_VER,
                '--comment', 'att-hash: sha256',
                ]

    ecode, signed = b4.gpg_run_command(gpgargs, stdin=payload.encode('utf-8'))
    if ecode > 0:
        config = b4.get_main_config()
        logger.critical('ERROR: Unable to sign using %s', config['gpgbin'])
        sys.exit(1)

    att_msg = email.message.EmailMessage()
    att_msg.set_payload(signed.encode('utf-8'))
    sender = cmdargs.sender
    if '>' not in sender:
        sender = '<%s>' % sender
    att_msg['From'] = sender
    att_msg['To'] = '<signatures@kernel.org>'
    att_msg['Message-Id'] = email.utils.make_msgid(domain='kernel.org')
    att_msg['Subject'] = subject

    logger.info('---')
    if not cmdargs.nosubmit:
        # Try to deliver it via mail.kernel.org
        try:
            mailserver = smtplib.SMTP('mail.kernel.org', 587)
            # identify ourselves to smtp gmail client
            mailserver.ehlo()
            # secure our email with tls encryption
            mailserver.starttls()
            # re-identify ourselves as an encrypted connection
            mailserver.ehlo()
            logger.info('Delivering via mail.kernel.org')
            mailserver.sendmail('devnull@kernel.org', 'signatures@kernel.org', att_msg.as_string())
            mailserver.quit()
            sys.exit(0)
        except Exception as ex:
            logger.info('Could not deliver: %s', ex)

    # Future iterations will also be able to submit this to a RESTful URL
    # at git.kernel.org, in order not to depend on avaialbility of SMTP gateways
    with open(cmdargs.output, 'wb') as fh:
        fh.write(att_msg.as_bytes())

    logger.info('Wrote %s', cmdargs.output)
    logger.info('You can send it using:')
    logger.info('  sendmail -oi signatures@kernel.org < %s', cmdargs.output)
    logger.info('  mutt -H %s', cmdargs.output)


def verify_attestation(cmdargs):
    config = b4.get_main_config()
    if cmdargs.tofu:
        config['attestation-trust-model'] = 'tofu'

    exact_from_match = True
    if cmdargs.ignorefrom:
        exact_from_match = False

    mbx = mailbox.mbox(cmdargs.mbox[0])
    if cmdargs.attfile:
        b4.LoreAttestationDocument.load_from_file(cmdargs.attfile)
    eligible = list()
    for msg in mbx:
        lmsg = b4.LoreMessage(msg)
        if lmsg.has_diff:
            eligible.append(lmsg)
            continue
        # See if body has "att-fmt-ver
        if re.search(r'^Comment: att-fmt-ver:', lmsg.body, re.I | re.M):
            logger.debug('Found attestation message')
            b4.LoreAttestationDocument.load_from_string(lmsg.msgid, lmsg.body)

        logger.debug('SKIP | %s', msg['Subject'])

    if not len(eligible):
        logger.error('No patches found in %s', cmdargs.mbox[0])
        sys.exit(1)

    logger.info('---')
    attrailers = set()
    ecode = 1
    if config['attestation-checkmarks'] == 'fancy':
        attpass = b4.PASS_FANCY
        attfail = b4.FAIL_FANCY
    else:
        attpass = b4.PASS_SIMPLE
        attfail = b4.FAIL_SIMPLE

    for lmsg in eligible:
        attdoc = lmsg.get_attestation(lore_lookup=True, exact_from_match=exact_from_match)
        if not attdoc:
            logger.critical('%s %s', attfail, lmsg.full_subject)
            if not cmdargs.nofast:
                logger.critical('Aborting due to failure.')
                ecode = 1
                break
            else:
                ecode = 128
                continue
        if ecode != 128:
            ecode = 0
        logger.critical('%s %s', attpass, lmsg.full_subject)
        attrailers.add(attdoc.attestor.get_trailer(lmsg.fromemail))

    logger.critical('---')
    if ecode > 0:
        logger.critical('Attestation verification failed.')
        errors = set()
        for attdoc in b4.ATTESTATIONS:
            errors.update(attdoc.errors)
        if len(errors):
            logger.critical('---')
            logger.critical('The validation process reported the following errors:')
            for error in errors:
                logger.critical('  %s %s', attfail, error)
    else:
        logger.critical('All patches passed attestation:')
        for attrailer in attrailers:
            logger.critical('  %s %s', attpass, attrailer)

    sys.exit(ecode)
