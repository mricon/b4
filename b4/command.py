#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import argparse
import logging
import b4
import sys

logger = b4.logger


def cmd_mbox_common_opts(sp):
    sp.add_argument('msgid', nargs='?',
                    help='Message ID to process, or pipe a raw message')
    sp.add_argument('-o', '--outdir', default='.',
                    help='Output into this directory')
    sp.add_argument('-p', '--use-project', dest='useproject', default=None,
                    help='Use a specific project instead of guessing (linux-mm, linux-hardening, etc)')
    sp.add_argument('-c', '--check-newer-revisions', dest='checknewer', action='store_true', default=False,
                    help='Check if newer patch revisions exist')
    sp.add_argument('-n', '--mbox-name', dest='wantname', default=None,
                    help='Filename to name the mbox file')
    sp.add_argument('-m', '--use-local-mbox', dest='localmbox', default=None,
                    help='Instead of grabbing a thread from lore, process this mbox file')
    sp.add_argument('-C', '--no-cache', dest='nocache', action='store_true', default=False,
                    help='Do not use local cache')


def cmd_mbox(cmdargs):
    import b4.mbox
    b4.mbox.main(cmdargs)


def cmd_am(cmdargs):
    import b4.mbox
    b4.mbox.main(cmdargs)


def cmd_attest(cmdargs):
    import b4.attest
    b4.attest.create_attestation(cmdargs)


def cmd_verify(cmdargs):
    import b4.attest
    b4.attest.verify_attestation(cmdargs)


def cmd():
    parser = argparse.ArgumentParser(
        description='A tool to work with public-inbox patches',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--version', action='version', version=b4.__VERSION__)
    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='Add more debugging info to the output')
    parser.add_argument('-q', '--quiet', action='store_true', default=False,
                        help='Output critical information only')

    subparsers = parser.add_subparsers(help='sub-command help', dest='subcmd')

    # b4 mbox
    sp_mbox = subparsers.add_parser('mbox', help='Download a thread as an mbox file')
    cmd_mbox_common_opts(sp_mbox)
    sp_mbox.set_defaults(func=cmd_mbox)

    # b4 am
    sp_am = subparsers.add_parser('am', help='Create an mbox file that is ready to git-am')
    cmd_mbox_common_opts(sp_am)
    sp_am.add_argument('-v', '--use-version', dest='wantver', type=int, default=None,
                       help='Get a specific version of the patch/series')
    sp_am.add_argument('-t', '--apply-cover-trailers', dest='covertrailers', action='store_true', default=False,
                       help='Apply trailers sent to the cover letter to all patches')
    sp_am.add_argument('-T', '--no-add-trailers', dest='noaddtrailers', action='store_true', default=False,
                       help='Do not add or sort any trailers')
    sp_am.add_argument('-s', '--add-my-sob', dest='addmysob', action='store_true', default=False,
                       help='Add your own signed-off-by to every patch')
    sp_am.add_argument('-l', '--add-link', dest='addlink', action='store_true', default=False,
                       help='Add a lore.kernel.org/r/ link to every patch')
    sp_am.add_argument('-Q', '--quilt-ready', dest='quiltready', action='store_true', default=False,
                       help='Save mbox patches in a quilt-ready folder')
    sp_am.set_defaults(func=cmd_am)

    # b4 attest
    sp_att = subparsers.add_parser('attest', help='Submit cryptographic attestation for patches')
    # GDPR-proofing: by default, we add as little PII-sensitive info as possible
    sp_att.add_argument('-f', '--from', dest='sender', default='devnull@kernel.org',
                        help='Use a custom From field')
    sp_att.add_argument('-n', '--no-submit', dest='nosubmit', action='store_true', default=False,
                        help='Do not submit attestation, just save the message ready to send')
    sp_att.add_argument('-o', '--output', default='xxxx-attestation-letter.patch',
                        help='Save attestation message in this file if not submitting it')
    sp_att.add_argument('patchfile', nargs='+', help='Patches to attest')
    sp_att.set_defaults(func=cmd_attest)

    # b4 verify
    sp_ver = subparsers.add_parser('attverify', help='Verify cryptographic attestation of patches in an mbox')
    sp_ver.add_argument('-i', '--attestation-file', dest='attfile',
                        help='Use this file for attestation data instead of querying lore.kernel.org')
    sp_ver.add_argument('-t', '--tofu', action='store_true', default=False,
                        help='Force TOFU trust model (otherwise uses your global GnuPG setting)')
    sp_ver.add_argument('-X', '--no-fast-exit', dest='nofast', action='store_true', default=False,
                        help='Do not exit after first failure')
    sp_ver.add_argument('-F', '--ignore-from-mismatch', dest='ignorefrom', action='store_true',
                        default=False, help='Ignore mismatches between From: and PGP uid data')
    sp_ver.add_argument('mbox', nargs=1, help='Mbox containing patches to attest')
    sp_ver.set_defaults(func=cmd_verify)

    cmdargs = parser.parse_args()

    logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)

    if cmdargs.quiet:
        ch.setLevel(logging.CRITICAL)
    elif cmdargs.debug:
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)

    logger.addHandler(ch)

    if 'func' not in cmdargs:
        parser.print_help()
        sys.exit(1)

    cmdargs.func(cmdargs)


if __name__ == '__main__':
    cmd()
