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


def cmd_retrieval_common_opts(sp):
    sp.add_argument('msgid', nargs='?',
                    help='Message ID to process, or pipe a raw message')
    sp.add_argument('-p', '--use-project', dest='useproject', default=None,
                    help='Use a specific project instead of guessing (linux-mm, linux-hardening, etc)')
    sp.add_argument('-m', '--use-local-mbox', dest='localmbox', default=None,
                    help='Instead of grabbing a thread from lore, process this mbox file (or - for stdin)')
    sp.add_argument('-C', '--no-cache', dest='nocache', action='store_true', default=False,
                    help='Do not use local cache')


def cmd_mbox_common_opts(sp):
    cmd_retrieval_common_opts(sp)
    sp.add_argument('-o', '--outdir', default='.',
                    help='Output into this directory (or use - to output mailbox contents to stdout)')
    sp.add_argument('-c', '--check-newer-revisions', dest='checknewer', action='store_true', default=False,
                    help='Check if newer patch revisions exist')
    sp.add_argument('-n', '--mbox-name', dest='wantname', default=None,
                    help='Filename to name the mbox destination')
    sp.add_argument('-M', '--save-as-maildir', dest='maildir', action='store_true', default=False,
                    help='Save as maildir (avoids mbox format ambiguities)')


def cmd_mbox(cmdargs):
    import b4.mbox
    b4.mbox.main(cmdargs)


def cmd_kr(cmdargs):
    import b4.kr
    b4.kr.main(cmdargs)


def cmd_am(cmdargs):
    import b4.mbox
    b4.mbox.main(cmdargs)


def cmd_attest(cmdargs):
    import b4.attest
    if len(cmdargs.patchfile):
        b4.attest.attest_patches(cmdargs)
    else:
        logger.critical('ERROR: missing patches to attest')
        sys.exit(1)


def cmd_pr(cmdargs):
    import b4.pr
    b4.pr.main(cmdargs)


def cmd_ty(cmdargs):
    import b4.ty
    b4.ty.main(cmdargs)


def cmd_diff(cmdargs):
    import b4.diff
    b4.diff.main(cmdargs)


def cmd():
    # noinspection PyTypeChecker
    parser = argparse.ArgumentParser(
        prog='b4',
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
    sp_mbox.add_argument('-f', '--filter-dupes', dest='filterdupes', action='store_true', default=False,
                         help='When adding messages to existing maildir, filter out duplicates')
    sp_mbox.set_defaults(func=cmd_mbox)

    # b4 am
    sp_am = subparsers.add_parser('am', help='Create an mbox file that is ready to git-am')
    cmd_mbox_common_opts(sp_am)
    sp_am.add_argument('-v', '--use-version', dest='wantver', type=int, default=None,
                       help='Get a specific version of the patch/series')
    sp_am.add_argument('-t', '--apply-cover-trailers', dest='covertrailers', action='store_true', default=False,
                       help='Apply trailers sent to the cover letter to all patches')
    sp_am.add_argument('-S', '--sloppy-trailers', dest='sloppytrailers', action='store_true', default=False,
                       help='Apply trailers without email address match checking')
    sp_am.add_argument('-T', '--no-add-trailers', dest='noaddtrailers', action='store_true', default=False,
                       help='Do not add or sort any trailers')
    sp_am.add_argument('-s', '--add-my-sob', dest='addmysob', action='store_true', default=False,
                       help='Add your own signed-off-by to every patch')
    sp_am.add_argument('-l', '--add-link', dest='addlink', action='store_true', default=False,
                       help='Add a lore.kernel.org/r/ link to every patch')
    sp_am.add_argument('-Q', '--quilt-ready', dest='quiltready', action='store_true', default=False,
                       help='Save patches in a quilt-ready folder')
    sp_am.add_argument('-P', '--cherry-pick', dest='cherrypick', default=None,
                       help='Cherry-pick a subset of patches (e.g. "-P 1-2,4,6-", '
                            '"-P _" to use just the msgid specified, or '
                            '"-P *globbing*" to match on commit subject)')
    sp_am.add_argument('-g', '--guess-base', dest='guessbase', action='store_true', default=False,
                       help='Try to guess the base of the series (if not specified)')
    sp_am.add_argument('-3', '--prep-3way', dest='threeway', action='store_true', default=False,
                       help='Prepare for a 3-way merge '
                            '(tries to ensure that all index blobs exist by making a fake commit range)')
    sp_am.add_argument('--cc-trailers', dest='copyccs', action='store_true', default=False,
                       help='Copy all Cc\'d addresses into Cc: trailers')
    sp_am.add_argument('--no-cover', dest='nocover', action='store_true', default=False,
                       help='Do not save the cover letter (on by default when using -o -)')
    sp_am.add_argument('--no-partial-reroll', dest='nopartialreroll', action='store_true', default=False,
                       help='Do not reroll partial series when detected')
    sp_am.set_defaults(func=cmd_am)

    # b4 attest
    sp_att = subparsers.add_parser('attest', help='Create cryptographic attestation for a set of patches')
    sp_att.add_argument('-f', '--from', dest='sender', default=None,
                        help='OBSOLETE: this option does nothing and will be removed')
    sp_att.add_argument('-n', '--no-submit', dest='nosubmit', action='store_true', default=False,
                        help='OBSOLETE: this option does nothing and will be removed')
    sp_att.add_argument('-o', '--output', default=None,
                        help='OBSOLETE: this option does nothing and will be removed')
    sp_att.add_argument('-m', '--mutt-filter', default=None,
                        help='OBSOLETE: this option does nothing and will be removed')
    sp_att.add_argument('patchfile', nargs='*', help='Patches to attest')
    sp_att.set_defaults(func=cmd_attest)

    # b4 pr
    sp_pr = subparsers.add_parser('pr', help='Fetch a pull request found in a message ID')
    sp_pr.add_argument('-g', '--gitdir', default=None,
                       help='Operate on this git tree instead of current dir')
    sp_pr.add_argument('-b', '--branch', default=None,
                       help='Check out FETCH_HEAD into this branch after fetching')
    sp_pr.add_argument('-c', '--check', action='store_true', default=False,
                       help='Check if pull request has already been applied')
    sp_pr.add_argument('-e', '--explode', action='store_true', default=False,
                       help='Convert a pull request into an mbox full of patches')
    sp_pr.add_argument('-o', '--output-mbox', dest='outmbox', default=None,
                       help='Save exploded messages into this mailbox (default: msgid.mbx)')
    sp_pr.add_argument('-l', '--retrieve-links', action='store_true', dest='getlinks', default=False,
                       help='Attempt to retrieve any Link: URLs (use with -e)')
    sp_pr.add_argument('-f', '--from-addr', dest='mailfrom', default=None,
                       help='Use this From: in exploded messages (use with -e)')
    sp_pr.add_argument('msgid', nargs='?',
                       help='Message ID to process, or pipe a raw message')
    sp_pr.set_defaults(func=cmd_pr)

    # b4 ty
    sp_ty = subparsers.add_parser('ty', help='Generate thanks email when something gets merged/applied')
    sp_ty.add_argument('-g', '--gitdir', default=None,
                       help='Operate on this git tree instead of current dir')
    sp_ty.add_argument('-o', '--outdir', default='.',
                       help='Write thanks files into this dir (default=.)')
    sp_ty.add_argument('-l', '--list', action='store_true', default=False,
                       help='List pull requests and patch series you have retrieved')
    sp_ty.add_argument('-s', '--send', default=None,
                       help='Generate thankyous for specific entries from -l (e.g.: 1,3-5,7-; or "all")')
    sp_ty.add_argument('-d', '--discard', default=None,
                       help='Discard specific messages from -l (e.g.: 1,3-5,7-; or "all")')
    sp_ty.add_argument('-a', '--auto', action='store_true', default=False,
                       help='Use the Auto-Thankanator to figure out what got applied/merged')
    sp_ty.add_argument('-b', '--branch', default=None,
                       help='The branch to check against, instead of current')
    sp_ty.add_argument('--since', default='1.week',
                       help='The --since option to use when auto-matching patches (default=1.week)')
    sp_ty.set_defaults(func=cmd_ty)

    # b4 diff
    sp_diff = subparsers.add_parser('diff', help='Show a range-diff to previous series revision')
    sp_diff.add_argument('msgid', nargs='?',
                         help='Message ID to process, or pipe a raw message')
    sp_diff.add_argument('-g', '--gitdir', default=None,
                         help='Operate on this git tree instead of current dir')
    sp_diff.add_argument('-p', '--use-project', dest='useproject', default=None,
                         help='Use a specific project instead of guessing (linux-mm, linux-hardening, etc)')
    sp_diff.add_argument('-C', '--no-cache', dest='nocache', action='store_true', default=False,
                         help='Do not use local cache')
    sp_diff.add_argument('-v', '--compare-versions', dest='wantvers', type=int, default=None, nargs='+',
                         help='Compare specific versions instead of latest and one before that, e.g. -v 3 5')
    sp_diff.add_argument('-n', '--no-diff', dest='nodiff', action='store_true', default=False,
                         help='Do not generate a diff, just show the command to do it')
    sp_diff.add_argument('-o', '--output-diff', dest='outdiff', default=None,
                         help='Save diff into this file instead of outputting to stdout')
    sp_diff.add_argument('-c', '--color', dest='color', action='store_true', default=False,
                         help='Force color output even when writing to file')
    sp_diff.add_argument('-m', '--compare-am-mboxes', dest='ambox', nargs=2, default=None,
                         help='Compare two mbx files prepared with "b4 am"')
    sp_diff.set_defaults(func=cmd_diff)

    # b4 kr
    sp_kr = subparsers.add_parser('kr', help='Keyring operations')
    cmd_retrieval_common_opts(sp_kr)
    sp_kr.add_argument('--show-keys', dest='showkeys', action='store_true', default=False,
                       help='Show all developer keys found in a thread')
    sp_kr.set_defaults(func=cmd_kr)

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
    # We're running from a checkout, so reflect git commit in the version
    import os
    # noinspection PyBroadException
    try:
        if b4.__VERSION__.find('-dev') > 0:
            base = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
            dotgit = os.path.join(base, '.git')
            ecode, short = b4.git_run_command(dotgit, ['rev-parse', '--short', 'HEAD'])
            if ecode == 0:
                b4.__VERSION__ = '%s-%.5s' % (b4.__VERSION__, short.strip())
    except Exception as ex:
        # Any failures above are non-fatal
        pass
    cmd()
