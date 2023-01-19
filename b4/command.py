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
    sp.add_argument('-m', '--use-local-mbox', dest='localmbox', default=None,
                    help='Instead of grabbing a thread from lore, process this mbox file (or - for stdin)')
    sp.add_argument('--stdin-pipe-sep',
                    help='When accepting messages on stdin, split using this pipe separator string')
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


def cmd_am_common_opts(sp):
    sp.add_argument('-v', '--use-version', dest='wantver', type=int, default=None,
                    help='Get a specific version of the patch/series')
    sp.add_argument('-t', '--apply-cover-trailers', dest='covertrailers', action='store_true', default=False,
                    help='Apply trailers sent to the cover letter to all patches')
    sp.add_argument('-S', '--sloppy-trailers', dest='sloppytrailers', action='store_true', default=False,
                    help='Apply trailers without email address match checking')
    sp.add_argument('-T', '--no-add-trailers', dest='noaddtrailers', action='store_true', default=False,
                    help='Do not add any trailers from follow-up messages')
    sp.add_argument('-s', '--add-my-sob', dest='addmysob', action='store_true', default=False,
                    help='Add your own signed-off-by to every patch')
    sp.add_argument('-l', '--add-link', dest='addlink', action='store_true', default=False,
                    help='Add a Link: with message-id lookup URL to every patch')
    sp.add_argument('-P', '--cherry-pick', dest='cherrypick', default=None,
                    help='Cherry-pick a subset of patches (e.g. "-P 1-2,4,6-", '
                         '"-P _" to use just the msgid specified, or '
                         '"-P *globbing*" to match on commit subject)')
    sp.add_argument('--cc-trailers', dest='copyccs', action='store_true', default=False,
                    help='Copy all Cc\'d addresses into Cc: trailers')
    sp.add_argument('--no-parent', dest='noparent', action='store_true', default=False,
                    help='Break thread at the msgid specified and ignore any parent messages')
    sp.add_argument('--allow-unicode-control-chars', dest='allowbadchars', action='store_true', default=False,
                    help='Allow unicode control characters (very rarely legitimate)')


def cmd_mbox(cmdargs):
    import b4.mbox
    b4.mbox.main(cmdargs)


def cmd_kr(cmdargs):
    import b4.kr
    b4.kr.main(cmdargs)


def cmd_prep(cmdargs):
    import b4.ez
    b4.ez.cmd_prep(cmdargs)


def cmd_trailers(cmdargs):
    import b4.ez
    b4.ez.cmd_trailers(cmdargs)


def cmd_send(cmdargs):
    import b4.ez
    b4.ez.cmd_send(cmdargs)


def cmd_am(cmdargs):
    import b4.mbox
    b4.mbox.main(cmdargs)


def cmd_shazam(cmdargs):
    import b4.mbox
    b4.mbox.main(cmdargs)


def cmd_pr(cmdargs):
    import b4.pr
    b4.pr.main(cmdargs)


def cmd_ty(cmdargs):
    import b4.ty
    b4.ty.main(cmdargs)


def cmd_diff(cmdargs):
    import b4.diff
    b4.diff.main(cmdargs)


def setup_parser() -> argparse.ArgumentParser:
    # noinspection PyTypeChecker
    parser = argparse.ArgumentParser(
        prog='b4',
        description='A tool to work with patches in public-inbox archives',
        epilog='Online docs available at https://b4.docs.kernel.org',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument('--version', action='version', version=b4.__VERSION__)
    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='Add more debugging info to the output')
    parser.add_argument('-q', '--quiet', action='store_true', default=False,
                        help='Output critical information only')
    parser.add_argument('-n', '--no-interactive', action='store_true', default=False,
                        help='Do not ask any interactive questions')
    parser.add_argument('--offline-mode', action='store_true', default=False,
                        help='Do not perform any network queries')
    parser.add_argument('--no-stdin', action='store_true', default=False,
                        help='Disable TTY detection for stdin')

    subparsers = parser.add_subparsers(help='sub-command help', dest='subcmd')

    # b4 mbox
    sp_mbox = subparsers.add_parser('mbox', help='Download a thread as an mbox file')
    cmd_mbox_common_opts(sp_mbox)
    sp_mbox.add_argument('-f', '--filter-dupes', dest='filterdupes', action='store_true', default=False,
                         help='When adding messages to existing maildir, filter out duplicates')
    sp_mbox.add_argument('-r', '--refetch', dest='refetch', metavar='MBOX', default=False,
                         help='Refetch all messages in specified mbox with their original headers')
    sp_mbox.set_defaults(func=cmd_mbox)

    # b4 am
    sp_am = subparsers.add_parser('am', help='Create an mbox file that is ready to git-am')
    cmd_mbox_common_opts(sp_am)
    cmd_am_common_opts(sp_am)
    sp_am.add_argument('-Q', '--quilt-ready', dest='quiltready', action='store_true', default=False,
                       help='Save patches in a quilt-ready folder')
    sp_am.add_argument('-g', '--guess-base', dest='guessbase', action='store_true', default=False,
                       help='Try to guess the base of the series (if not specified)')
    sp_am.add_argument('-b', '--guess-branch', dest='guessbranch', nargs='+', action='extend', type=str, default=None,
                       help='When guessing base, restrict to this branch (use with -g)')
    sp_am.add_argument('--guess-lookback', dest='guessdays', type=int, default=21,
                       help='When guessing base, go back this many days from the patch date (default: 2 weeks)')
    sp_am.add_argument('-3', '--prep-3way', dest='threeway', action='store_true', default=False,
                       help='Prepare for a 3-way merge '
                            '(tries to ensure that all index blobs exist by making a fake commit range)')
    sp_am.add_argument('--no-cover', dest='nocover', action='store_true', default=False,
                       help='Do not save the cover letter (on by default when using -o -)')
    sp_am.add_argument('--no-partial-reroll', dest='nopartialreroll', action='store_true', default=False,
                       help='Do not reroll partial series when detected')
    sp_am.set_defaults(func=cmd_am)

    # b4 shazam
    sp_sh = subparsers.add_parser('shazam', help='Like b4 am, but applies the series to your tree')
    cmd_retrieval_common_opts(sp_sh)
    cmd_am_common_opts(sp_sh)
    sh_g = sp_sh.add_mutually_exclusive_group()
    sh_g.add_argument('-H', '--make-fetch-head', dest='makefetchhead', action='store_true', default=False,
                      help='Attempt to treat series as a pull request and fetch it into FETCH_HEAD')
    sh_g.add_argument('-M', '--merge', dest='merge', action='store_true', default=False,
                      help='Attempt to merge series as if it were a pull request (execs git-merge)')
    sp_sh.add_argument('--guess-lookback', dest='guessdays', type=int, default=21,
                       help=('(use with -H or -M) When guessing base, go back this many days from the patch date '
                             '(default: 3 weeks)'))
    sp_sh.set_defaults(func=cmd_shazam)

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
    sp_pr.add_argument('-s', '--send-as-identity', dest='sendidentity', default=None,
                       help=('Use git-send-email to send exploded series (use with -e);'
                             'the identity must match a [sendemail "identity"] config section'))
    sp_pr.add_argument('--dry-run', dest='dryrun', action='store_true', default=False,
                       help='Force a --dry-run on git-send-email invocation (use with -s)')
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
    sp_ty.add_argument('-t', '--thank-for', dest='thankfor', default=None,
                       help='Generate thankyous for specific entries from -l (e.g.: 1,3-5,7-; or "all")')
    sp_ty.add_argument('-d', '--discard', default=None,
                       help='Discard specific messages from -l (e.g.: 1,3-5,7-; or "all")')
    sp_ty.add_argument('-a', '--auto', action='store_true', default=False,
                       help='Use the Auto-Thankanator to figure out what got applied/merged')
    sp_ty.add_argument('-b', '--branch', default=None,
                       help='The branch to check against, instead of current')
    sp_ty.add_argument('--since', default='1.week',
                       help='The --since option to use when auto-matching patches (default=1.week)')
    sp_ty.add_argument('-S', '--send-email', action='store_true', dest='sendemail', default=False,
                       help='Send email instead of writing out .thanks files')
    sp_ty.add_argument('--dry-run', action='store_true', dest='dryrun', default=False,
                       help='Print out emails instead of sending them')
    sp_ty.add_argument('--pw-set-state', default=None,
                       help='Set this patchwork state instead of default (use with -a, -t or -d)')
    sp_ty.set_defaults(func=cmd_ty)

    # b4 diff
    sp_diff = subparsers.add_parser('diff', help='Show a range-diff to previous series revision')
    sp_diff.add_argument('msgid', nargs='?',
                         help='Message ID to process, or pipe a raw message')
    sp_diff.add_argument('-g', '--gitdir', default=None,
                         help='Operate on this git tree instead of current dir')
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

    # b4 prep
    sp_prep = subparsers.add_parser('prep', help='Work on patch series to submit for mailing list review')
    sp_prep.add_argument('-c', '--auto-to-cc', action='store_true', default=False,
                       help='Automatically populate cover letter trailers with To and Cc addresses')
    sp_prep.add_argument('--force-revision', metavar='N', type=int,
                       help='Force revision to be this number instead')
    sp_prep.add_argument('--set-prefixes', metavar='PREFIX', nargs='+',
                       help='Extra prefixes to add to [PATCH] (e.g.: RFC mydrv)')

    spp_g = sp_prep.add_mutually_exclusive_group()
    spp_g.add_argument('-p', '--format-patch', metavar='OUTPUT_DIR',
                       help='Output prep-tracked commits as patches')
    spp_g.add_argument('--edit-cover', action='store_true', default=False,
                       help='Edit the cover letter in your defined $EDITOR (or core.editor)')
    spp_g.add_argument('--show-revision', action='store_true', default=False,
                       help='Show current series revision number')
    spp_g.add_argument('--compare-to', metavar='vN',
                       help='Display a range-diff to previously sent revision N')
    spp_g.add_argument('--manual-reroll', dest='reroll', default=None, metavar='COVER_MSGID',
                       help='Mark current revision as sent and reroll (requires cover letter msgid)')
    spp_g.add_argument('--show-info', action='store_true', default=False,
                       help='Show current series info in a column-parseable format')

    ag_prepn = sp_prep.add_argument_group('Create new branch', 'Create a new branch for working on patch series')
    ag_prepn.add_argument('-n', '--new', dest='new_series_name',
                          help='Create a new branch for working on a patch series')
    ag_prepn.add_argument('-f', '--fork-point', dest='fork_point',
                          help='When creating a new branch, use this fork point instead of HEAD')
    ag_prepn.add_argument('-F', '--from-thread', metavar='MSGID', dest='msgid',
                          help='When creating a new branch, use this thread')
    ag_prepe = sp_prep.add_argument_group('Enroll existing branch', 'Enroll existing branch for prep work')
    ag_prepe.add_argument('-e', '--enroll', dest='enroll_base',
                          help='Enroll current branch, using the passed tag, branch, or commit as fork base')
    sp_prep.set_defaults(func=cmd_prep)

    # b4 trailers
    sp_trl = subparsers.add_parser('trailers', help='Operate on trailers received for mailing list reviews')
    sp_trl.add_argument('-u', '--update', action='store_true', default=False,
                        help='Update branch commits with latest received trailers')
    sp_trl.add_argument('-S', '--sloppy-trailers', dest='sloppytrailers', action='store_true', default=False,
                        help='Apply trailers without email address match checking')
    sp_trl.add_argument('-F', '--trailers-from', dest='trailers_from',
                        help='Look for trailers in the thread with this msgid instead of using the series change-id')
    sp_trl.add_argument('--since', default='1.month',
                        help='The --since option to use with -F when auto-matching patches (default=1.month)')
    cmd_retrieval_common_opts(sp_trl)
    sp_trl.set_defaults(func=cmd_trailers)

    # b4 send
    sp_send = subparsers.add_parser('send', help='Submit your work for review on the mailing lists')
    sp_send.add_argument('-d', '--dry-run', dest='dryrun', action='store_true', default=False,
                         help='Do not send, just dump out raw smtp messages to the stdout')
    sp_send.add_argument('-o', '--output-dir',
                         help='Do not send, write raw messages to this directory (forces --dry-run)')
    sp_send.add_argument('--reflect', action='store_true', default=False,
                         help='Send everything to yourself instead of the actual recipients')
    sp_send.add_argument('--no-trailer-to-cc', action='store_true', default=False,
                         help='Do not add any addresses found in the cover or patch trailers to To: or Cc:')
    sp_send.add_argument('--to', nargs='+', help='Addresses to add to the To: list')
    sp_send.add_argument('--cc', nargs='+', help='Addresses to add to the Cc: list')
    sp_send.add_argument('--not-me-too', action='store_true', default=False,
                         help='Remove yourself from the To: or Cc: list')
    sp_send.add_argument('--resend', metavar='vN', default=None,
                         help='Resend a previously sent version of the series')
    sp_send.add_argument('--no-sign', action='store_true', default=False,
                         help='Do not add the cryptographic attestation signature header')
    ag_sendh = sp_send.add_argument_group('Web submission', 'Authenticate with the web submission endpoint')
    ag_sendh.add_argument('--web-auth-new', dest='auth_new', action='store_true', default=False,
                          help='Initiate a new web authentication request')
    ag_sendh.add_argument('--web-auth-verify', dest='auth_verify', metavar='VERIFY_TOKEN',
                          help='Submit the token received via verification email')
    sp_send.set_defaults(func=cmd_send)

    return parser


def cmd():
    parser = setup_parser()
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

    if cmdargs.offline_mode:
        logger.info('Running in OFFLINE mode')
        b4.can_network = False

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
