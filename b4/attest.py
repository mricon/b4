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
import smtplib
import b4
import argparse
import base64
import logging

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
        f'g={lmsg.git_patch_id}',
        f'i={lmsg.attestation.ib}',
        f'm={lmsg.attestation.mb}',
        f'p={lmsg.attestation.pb}',
    ]
    hhname, hhval = b4.dkim_canonicalize_header(b4.HDR_PATCH_HASHES, '; '.join(hparts))
    headers.append(f'{hhname}:{hhval}')

    logger.debug('Signing with mode=%s', mode)
    if mode == 'pgp':
        usercfg = b4.get_user_config()
        keyid = usercfg.get('signingkey')
        if not keyid:
            raise RuntimeError('Please set user.signingKey to use this feature')

        logger.debug('Using i=%s, s=0x%s', lmsg.fromemail, keyid.rstrip('!'))
        gpgargs = ['-b', '-u', f'{keyid}']

        hparts = [
            'm=pgp',
            f'i={lmsg.fromemail}',
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


def attest_and_send(cmdargs: argparse.Namespace):
    # Grab the message from stdin as bytes
    if sys.stdin.isatty():
        logger.critical('Pass the message to attest as stdin')
        sys.exit(1)

    inbytes = sys.stdin.buffer.read()
    msg = email.message_from_bytes(inbytes)
    lmsg = b4.LoreMessage(msg)
    lmsg.load_hashes()
    if not lmsg.attestation:
        logger.debug('Nothing to attest in %s, sending as-is')
        outbytes = inbytes
    else:
        in_header_attest(lmsg)
        outbytes = lmsg.msg.as_bytes()

    if cmdargs.nosend:
        logger.info('--- MESSAGE FOLLOWS ---')
        sys.stdout.buffer.write(outbytes)
        return

    if cmdargs.identity:
        cfgname = f'sendemail\\.{cmdargs.identity}\\..*'
    else:
        cfgname = 'sendemail\\..*'

    scfg = b4.get_config_from_git(cfgname)
    sserver = scfg.get('smtpserver')
    if not sserver:
        logger.critical('MISSING: smtpserver option in %s', cfgname)
        sys.exit(1)
    if sserver[0] == '/':
        args = [sserver, '-i'] + cmdargs.recipients
        extraopts = scfg.get('smtpserveroption')
        if extraopts:
            args += extraopts.split()
        ecode, out, err = b4._run_command(args, outbytes) # noqa
        sys.stdout.buffer.write(out)
        sys.stderr.buffer.write(err)
        sys.exit(ecode)

    sport = int(scfg.get('smtpserverport', '0'))
    sdomain = scfg.get('smtpdomain')
    suser = scfg.get('smtpuser')
    spass = scfg.get('smtppass')
    senc = scfg.get('smtpencryption', 'tls')
    sfrom = scfg.get('from')
    if not sfrom:
        sfrom = lmsg.fromemail

    logger.info('Connecting to %s', sserver)
    if senc == 'ssl':
        sconn = smtplib.SMTP_SSL(host=sserver, port=sport, local_hostname=sdomain)
    else:
        sconn = smtplib.SMTP(host=sserver, port=sport, local_hostname=sdomain)
        if senc == 'tls':
            sconn.starttls()
    if suser:
        logger.info('Logging in as user %s', suser)
        sconn.login(suser, spass)

    logger.info('Sending %s', lmsg.full_subject)
    sconn.sendmail(sfrom, cmdargs.recipients, outbytes)


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


if __name__ == '__main__':
    # Special mode for running b4-send-email
    # noinspection PyTypeChecker
    parser = argparse.ArgumentParser(
        prog='b4-send-email',
        description='A drop-in wrapper for git-send-email to attest patches before sending',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='Add more debugging info to the output')
    parser.add_argument('-q', '--quiet', action='store_true', default=False,
                        help='Output critical information only')
    parser.add_argument('-i', dest='_compat', action='store_true', default=True,
                        help='Sendmail compatibility thingamabob')
    parser.add_argument('--identity', default='b4',
                        help='The sendemail identity to use for real smtp/sendmail settings')
    parser.add_argument('-n', '--no-send', dest='nosend', action='store_true', default=False,
                        help='Do not send, just output what would be sent')
    parser.add_argument('recipients', nargs='+', help='Message recipients')
    _cmdargs = parser.parse_args()
    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('b4: %(message)s')
    ch.setFormatter(formatter)

    if _cmdargs.quiet:
        ch.setLevel(logging.CRITICAL)
    elif _cmdargs.debug:
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)

    logger.addHandler(ch)
    attest_and_send(_cmdargs)
