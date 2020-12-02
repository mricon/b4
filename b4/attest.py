#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
#

import sys
import email
import email.utils
import email.message
import email.header
import b4
import argparse
import base64

logger = b4.logger


def in_header_attest(lmsg: b4.LoreMessage, mode: str = 'pgp', replace: bool = False) -> None:
    if lmsg.msg.get(b4.HDR_PATCH_HASHES):
        if not replace:
            logger.info(' attest: message already attested')
            return
        del lmsg.msg[b4.HDR_PATCH_HASHES]
        del lmsg.msg[b4.HDR_PATCH_SIG]

    logger.info(' attest: generating attestation hashes')
    if not lmsg.attestation:
        raise RuntimeError('Could not calculate patch attestation')

    headers = list()
    hparts = [
        'v=1',
        'h=sha256',
        f'i={lmsg.attestation.ib}',
        f'm={lmsg.attestation.mb}',
        f'p={lmsg.attestation.pb}',
    ]
    if lmsg.git_patch_id:
        hparts.append(f'g={lmsg.git_patch_id}')

    hhname, hhval = b4.dkim_canonicalize_header(b4.HDR_PATCH_HASHES, '; '.join(hparts))
    headers.append(f'{hhname}:{hhval}')

    logger.debug('Signing with mode=%s', mode)
    if mode == 'pgp':
        usercfg = b4.get_user_config()
        keyid = usercfg.get('signingkey')
        identity = usercfg.get('email')
        if not identity:
            raise RuntimeError('Please set user.email to use this feature')
        if not keyid:
            raise RuntimeError('Please set user.signingKey to use this feature')

        logger.debug('Using i=%s, s=0x%s', identity, keyid.rstrip('!'))
        gpgargs = ['-b', '-u', f'{keyid}']

        hparts = [
            'm=pgp',
            f'i={identity}',
            's=0x%s' % keyid.rstrip('!'),
            'b=',
        ]

        shname, shval = b4.dkim_canonicalize_header(b4.HDR_PATCH_SIG, '; '.join(hparts))
        headers.append(f'{shname}:{shval}')
        payload = '\r\n'.join(headers).encode()
        ecode, out, err = b4.gpg_run_command(gpgargs, payload)
        if ecode > 0:
            logger.critical('Running gpg failed')
            logger.critical(err.decode())
            raise RuntimeError('Running gpg failed')
        bdata = base64.b64encode(out).decode()
        shval += header_splitter(bdata)
    else:
        raise NotImplementedError('Mode %s not implemented' % mode)

    hhdr = email.header.make_header([(hhval.encode(), 'us-ascii')], maxlinelen=78)
    shdr = email.header.make_header([(shval.encode(), 'us-ascii')], maxlinelen=78)
    lmsg.msg[b4.HDR_PATCH_HASHES] = hhdr
    lmsg.msg[b4.HDR_PATCH_SIG] = shdr


def header_splitter(longstr: str, limit: int = 77) -> str:
    splitstr = list()
    first = True
    while len(longstr) > limit:
        at = limit
        if first:
            first = False
            at -= 2
        splitstr.append(longstr[:at])
        longstr = longstr[at:]
    splitstr.append(longstr)
    return ' '.join(splitstr)


def attest_patches(cmdargs: argparse.Namespace) -> None:
    for pf in cmdargs.patchfile:
        with open(pf, 'rb') as fh:
            msg = email.message_from_bytes(fh.read())
        lmsg = b4.LoreMessage(msg)
        lmsg.load_hashes()
        if not lmsg.attestation:
            logger.debug('Nothing to attest in %s, skipped')
            continue
        logger.info('Attesting: %s', pf)
        in_header_attest(lmsg, replace=True)
        with open(pf, 'wb') as fh:
            fh.write(lmsg.msg.as_bytes())


def mutt_filter() -> None:
    if sys.stdin.isatty():
        logger.error('Error: Mutt mode expects a message on stdin')
        sys.exit(1)
    inb = sys.stdin.buffer.read()
    # Quick exit if we don't find x-patch-sig
    if inb.find(b'X-Patch-Sig:') < 0:
        sys.stdout.buffer.write(inb)
        return
    msg = email.message_from_bytes(inb)
    try:
        if msg.get('x-patch-sig'):
            lmsg = b4.LoreMessage(msg)
            lmsg.load_hashes()
            latt = lmsg.attestation
            if latt:
                if latt.validate(msg):
                    trailer = latt.lsig.attestor.get_trailer(lmsg.fromemail)
                    msg.add_header('Attested-By', trailer)
                elif latt.lsig:
                    if not latt.lsig.errors:
                        failed = list()
                        if not latt.pv:
                            failed.append('patch content')
                        if not latt.mv:
                            failed.append('commit message')
                        if not latt.iv:
                            failed.append('patch metadata')
                        latt.lsig.errors.add('signature failed (%s)' % ', '.join(failed))
                    msg.add_header('Attestation-Failed', ', '.join(latt.lsig.errors))
            # Delete the x-patch-hashes and x-patch-sig headers so
            # they don't boggle up the view
            for i in reversed(range(len(msg._headers))):  # noqa
                hdrName = msg._headers[i][0].lower()  # noqa
                if hdrName in ('x-patch-hashes', 'x-patch-sig'):
                    del msg._headers[i]  # noqa
    except:  # noqa
        # Don't prevent email from being displayed even if we died horribly
        sys.stdout.buffer.write(inb)
        return

    sys.stdout.buffer.write(msg.as_bytes(policy=b4.emlpolicy))
