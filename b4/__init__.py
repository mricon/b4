# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
import subprocess
import logging
import hashlib
import re
import sys
import gzip
import os
import fnmatch
import email.utils
import email.policy
import email.header
import email.generator
import email.quoprimime
import tempfile
import pathlib
import argparse
import smtplib
import shlex
import textwrap

import urllib.parse
import datetime
import time
import copy
import shutil
import mailbox
# noinspection PyCompatibility
import pwd

import requests

from pathlib import Path
from contextlib import contextmanager
from typing import Optional, Tuple, Set, List, BinaryIO, Union, Sequence, Literal

from email import charset
charset.add_charset('utf-8', None)
# Policy we use for saving mail locally
emlpolicy = email.policy.EmailPolicy(utf8=True, cte_type='8bit', max_line_length=None)

# Presence of these characters requires quoting of the name in the header
# adapted from email._parseaddr
qspecials = re.compile(r'[()<>@,:;.\"\[\]]')

try:
    import dkim
    can_dkim = True
except ModuleNotFoundError:
    can_dkim = False

try:
    import patatt
    can_patatt = True
except ModuleNotFoundError:
    can_patatt = False

# global setting allowing us to turn off networking
can_network = True

__VERSION__ = '0.12.0'
PW_REST_API_VERSION = '1.2'


def _dkim_log_filter(record):
    # Hide all dkim logging output in normal operation by setting the level to
    # DEBUG. If debugging output has been enabled then prefix dkim logging
    # output to make its origin clear.
    record.levelno = logging.DEBUG
    record.levelname = 'DEBUG'
    record.msg = 'DKIM: ' + record.msg
    return True


logger = logging.getLogger('b4')
dkimlogger = logger.getChild('dkim')
dkimlogger.addFilter(_dkim_log_filter)

HUNK_RE = re.compile(r'^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@')
FILENAME_RE = re.compile(r'^(---|\+\+\+) (\S+)')
DIFF_RE = re.compile(r'^(---.*\n\+\+\+|GIT binary patch|diff --git \w/\S+ \w/\S+)', flags=re.M | re.I)
DIFFSTAT_RE = re.compile(r'^\s*\d+ file.*\d+ (insertion|deletion)', flags=re.M | re.I)

ATT_PASS_SIMPLE = 'v'
ATT_FAIL_SIMPLE = 'x'
ATT_PASS_FANCY = '\033[32m\u2713\033[0m'
ATT_FAIL_FANCY = '\033[31m\u2717\033[0m'

DEVSIG_HDR = 'X-Developer-Signature'
LOREADDR = 'https://lore.kernel.org'

DEFAULT_CONFIG = {
    'midmask': LOREADDR + '/all/%s',
    'linkmask': LOREADDR + '/r/%s',
    'searchmask': LOREADDR + '/all/?x=m&t=1&q=%s',
    'listid-preference': '*.feeds.kernel.org,*.linux.dev,*.kernel.org,*',
    'save-maildirs': 'no',
    # off: do not bother checking attestation
    # check: print an attaboy when attestation is found
    # softfail: print a warning when no attestation found
    # hardfail: exit with an error when no attestation found
    'attestation-policy': 'softfail',
    # How many days before we consider attestation too old?
    'attestation-staleness-days': '30',
    # Should we check DKIM signatures if we don't find any other attestation?
    'attestation-check-dkim': 'yes',
    # We'll use the default gnupg homedir, unless you set it here
    'attestation-gnupghome': None,
    # Do you like simple or fancy checkmarks?
    'attestation-checkmarks': 'fancy',
    # How long to keep things in cache before expiring (minutes)?
    'cache-expire': '10',
    # Used when creating summaries for b4 ty
    'thanks-commit-url-mask': None,
    # See thanks-pr-template.example
    'thanks-pr-template': None,
    # See thanks-am-template.example
    'thanks-am-template': None,
    # If this is not set, we'll use what we find in 
    # git-config for gpg.program, and if that's not set,
    # we'll use "gpg" and hope for the better
    'gpgbin': None,
    # When sending mail, use this sendemail identity configuration
    'sendemail-identity': None,
}

# This is where we store actual config
MAIN_CONFIG = None
# This is git-config user.*
USER_CONFIG = None
# This is git-config sendemail.*
SENDEMAIL_CONFIG = None

# Used for storing our requests session
REQSESSION = None
# Indicates that we've cleaned cache already
_CACHE_CLEANED = False
# Used to track mailmap replacements
MAILMAP_INFO = dict()


class LoreMailbox:
    msgid_map: dict
    series: dict
    covers: dict
    followups: list
    unknowns: list

    def __init__(self):
        self.msgid_map = dict()
        self.series = dict()
        self.covers = dict()
        self.trailer_map = dict()
        self.followups = list()
        self.unknowns = list()

    def __repr__(self):
        out = list()
        for key, lser in self.series.items():
            out.append(str(lser))
        out.append('--- Followups ---')
        for lmsg in self.followups:
            out.append('  %s' % lmsg.full_subject)
        out.append('--- Unknowns ---')
        for lmsg in self.unknowns:
            out.append('  %s' % lmsg.full_subject)

        return '\n'.join(out)

    def get_by_msgid(self, msgid: str) -> Optional['LoreMessage']:
        if msgid in self.msgid_map:
            return self.msgid_map[msgid]
        return None

    def partial_reroll(self, revision, sloppytrailers):
        # Is it a partial reroll?
        # To qualify for a partial reroll:
        # 1. Needs to be version > 1
        # 2. Replies need to be to the exact X/N of the previous revision
        if revision <= 1 or revision - 1 not in self.series:
            return
        # Are existing patches replies to previous revisions with the same counter?
        pser = self.get_series(revision-1, sloppytrailers=sloppytrailers)
        lser = self.series[revision]
        sane = True
        for patch in lser.patches:
            if patch is None:
                continue
            if patch.in_reply_to is None or patch.in_reply_to not in self.msgid_map:
                logger.debug('Patch not sent as a reply-to')
                sane = False
                break
            ppatch = self.msgid_map[patch.in_reply_to]
            found = False
            while True:
                if patch.counter == ppatch.counter and patch.expected == ppatch.expected:
                    logger.debug('Found a previous matching patch in v%s', ppatch.revision)
                    found = True
                    break
                # Do we have another level up?
                if ppatch.in_reply_to is None or ppatch.in_reply_to not in self.msgid_map:
                    break
                ppatch = self.msgid_map[ppatch.in_reply_to]

            if not found:
                sane = False
                logger.debug('Patch not a reply to a patch with the same counter/expected (%s/%s != %s/%s)',
                             patch.counter, patch.expected, ppatch.counter, ppatch.expected)
                break

        if not sane:
            logger.debug('Not a sane partial reroll')
            return
        logger.info('Partial reroll detected, reconstituting from v%s', pser.revision)
        logger.debug('Reconstituting a partial reroll')
        at = 0
        for patch in lser.patches:
            if pser.patches[at] is None:
                at += 1
                continue
            if patch is None:
                ppatch = copy.deepcopy(pser.patches[at])
                ppatch.revision = lser.revision
                ppatch.reroll_from_revision = pser.revision
                lser.patches[at] = ppatch
            else:
                patch.reroll_from_revision = lser.revision
            at += 1
        if None not in lser.patches[1:]:
            lser.complete = True
            lser.partial_reroll = True
            if lser.patches[0] is not None:
                lser.has_cover = True
            lser.subject = pser.subject
            logger.debug('Reconstituted successfully')

    def get_series(self, revision=None, sloppytrailers=False, reroll=True) -> Optional['LoreSeries']:
        if revision is None:
            if not len(self.series):
                return None
            # Use the highest revision
            revision = max(self.series.keys())
        elif revision not in self.series.keys():
            return None

        lser = self.series[revision]

        # Is it empty?
        empty = True
        for lmsg in lser.patches:
            if lmsg is not None:
                empty = False
                break
        if empty:
            logger.critical('All patches in series v%s are missing.', lser.revision)
            return None

        if not lser.complete and reroll:
            self.partial_reroll(revision, sloppytrailers)

        # Grab our cover letter if we have one
        if revision in self.covers:
            lser.add_patch(self.covers[revision])
            lser.has_cover = True
        else:
            # Let's find the first patch with an in-reply-to and see if that
            # is our cover letter
            for member in lser.patches:
                if member is not None and member.in_reply_to is not None:
                    potential = self.get_by_msgid(member.in_reply_to)
                    if potential is not None and potential.has_diffstat and not potential.has_diff:
                        # This is *probably* the cover letter
                        lser.patches[0] = potential
                        lser.has_cover = True
                        break

        # Do we have any follow-ups?
        for fmsg in self.followups:
            logger.debug('Analyzing follow-up: %s (%s)', fmsg.full_subject, fmsg.fromemail)
            # If there are no trailers in this one, ignore it
            if not len(fmsg.trailers):
                logger.debug('  no trailers found, skipping')
                continue
            # Go up through the follow-ups and tally up trailers until
            # we either run out of in-reply-tos, or we find a patch in
            # one of our series
            if fmsg.in_reply_to is None:
                # Check if there's something matching in References
                refs = fmsg.msg.get('References', '')
                pmsg = None
                for ref in refs.split():
                    refid = ref.strip('<>')
                    if refid in self.msgid_map and refid != fmsg.msgid:
                        pmsg = self.msgid_map[refid]
                        break
                if pmsg is None:
                    # Can't find the message we're replying to here
                    continue
            elif fmsg.in_reply_to in self.msgid_map:
                pmsg = self.msgid_map[fmsg.in_reply_to]
            else:
                logger.debug('  missing message, skipping: %s', fmsg.in_reply_to)
                continue

            trailers, mismatches = fmsg.get_trailers(sloppy=sloppytrailers)
            for ltr in mismatches:
                lser.trailer_mismatches.add((ltr.name, ltr.value, fmsg.fromname, fmsg.fromemail))
            lvl = 1
            while True:
                logger.debug('%sParent: %s', ' ' * lvl, pmsg.full_subject)
                logger.debug('%sTrailers:', ' ' * lvl)
                for ltr in trailers:
                    logger.debug('%s%s: %s', ' ' * (lvl+1), ltr.name, ltr.value)
                if pmsg.has_diff and not pmsg.reply:
                    # We found the patch for these trailers
                    if pmsg.revision != revision:
                        # add this into our trailer map to carry over trailers from
                        # previous revisions to current revision if patch id did
                        # not change
                        if pmsg.pwhash:
                            if pmsg.pwhash not in self.trailer_map:
                                self.trailer_map[pmsg.pwhash] = list()
                            self.trailer_map[pmsg.pwhash] += trailers
                    pmsg.followup_trailers += trailers
                    break
                if not pmsg.reply:
                    # Could be a cover letter
                    pmsg.followup_trailers += trailers
                    break
                if pmsg.in_reply_to and pmsg.in_reply_to in self.msgid_map:
                    lvl += 1
                    for pltr in pmsg.trailers:
                        pltr.lmsg = pmsg
                        trailers.append(pltr)
                    pmsg = self.msgid_map[pmsg.in_reply_to]
                    continue
                break

        # Carry over trailers from previous series if patch/metadata did not change
        for lmsg in lser.patches:
            if lmsg is None or lmsg.pwhash is None:
                continue
            if lmsg.pwhash in self.trailer_map:
                lmsg.followup_trailers += self.trailer_map[lmsg.pwhash]

        return lser

    def add_message(self, msg: email.message.Message) -> None:
        msgid = LoreMessage.get_clean_msgid(msg)
        if msgid and msgid in self.msgid_map:
            logger.debug('Already have a message with this msgid, skipping %s', msgid)
            return

        lmsg = LoreMessage(msg)
        logger.debug('Looking at: %s', lmsg.full_subject)

        if msgid:
            self.msgid_map[lmsg.msgid] = lmsg

        if lmsg.reply:
            # We'll figure out where this belongs later
            logger.debug('  adding to followups')
            self.followups.append(lmsg)
            return

        if lmsg.counter == 0 and (not lmsg.counters_inferred or lmsg.has_diffstat):
            # Cover letter
            # Add it to covers -- we'll deal with them later
            logger.debug('  adding as v%s cover letter', lmsg.revision)
            self.covers[lmsg.revision] = lmsg
            return

        if lmsg.has_diff:
            if lmsg.revision not in self.series:
                if lmsg.revision_inferred and lmsg.in_reply_to:
                    # We have an inferred revision here.
                    # Do we have an upthread cover letter that specifies a revision?
                    irt = self.get_by_msgid(lmsg.in_reply_to)
                    if irt is not None and irt.has_diffstat and not irt.has_diff:
                        # Yes, this is very likely our cover letter
                        logger.debug('  fixed revision to v%s', irt.revision)
                        lmsg.revision = irt.revision
                    # alternatively, see if upthread is patch 1
                    elif lmsg.counter > 0 and irt is not None and irt.has_diff and irt.counter == 1:
                        logger.debug('  fixed revision to v%s', irt.revision)
                        lmsg.revision = irt.revision

            # Run our check again
            if lmsg.revision not in self.series:
                self.series[lmsg.revision] = LoreSeries(lmsg.revision, lmsg.expected)
                if len(self.series) > 1:
                    logger.debug('Found new series v%s', lmsg.revision)

            # Attempt to auto-number series from the same author who did not bother
            # to set v2, v3, etc. in the patch revision
            if (lmsg.counter == 1 and lmsg.counters_inferred
                    and not lmsg.reply and lmsg.lsubject.patch and not lmsg.lsubject.resend):
                omsg = self.series[lmsg.revision].patches[lmsg.counter]
                if (omsg is not None and omsg.counters_inferred and lmsg.fromemail == omsg.fromemail
                        and omsg.date < lmsg.date):
                    lmsg.revision = len(self.series) + 1
                    self.series[lmsg.revision] = LoreSeries(lmsg.revision, lmsg.expected)
                    logger.info('Assuming new revision: v%s (%s)', lmsg.revision, lmsg.full_subject)
            logger.debug('  adding as patch')
            self.series[lmsg.revision].add_patch(lmsg)
            return

        logger.debug('  adding to unknowns')
        self.unknowns.append(lmsg)


class LoreSeries:
    revision: int
    expected: int
    patches: List[Optional['LoreMessage']]
    followups: List['LoreMessage']
    trailer_mismatches: Set[Tuple[str, str, str, str]]
    complete: bool = False
    has_cover: bool = False
    partial_reroll: bool = False
    subject: str
    indexes: Optional[List[Tuple[str, str]]] = None
    base_commit: Optional[str] = None
    change_id: Optional[str] = None

    def __init__(self, revision: int, expected: int) -> None:
        self.revision = revision
        self.expected = expected
        self.patches = [None] * (expected+1)
        self.followups = list()
        self.trailer_mismatches = set()
        self.subject = '(untitled)'

    def __repr__(self):
        out = list()
        out.append('- Series: [v%s] %s' % (self.revision, self.subject))
        out.append('  revision: %s' % self.revision)
        out.append('  expected: %s' % self.expected)
        out.append('  complete: %s' % self.complete)
        out.append('  has_cover: %s' % self.has_cover)
        out.append('  base_commit: %s' % self.base_commit)
        out.append('  change_id: %s' % self.change_id)
        out.append('  partial_reroll: %s' % self.partial_reroll)
        out.append('  patches:')
        at = 0
        for member in self.patches:
            if member is not None:
                out.append('    [%s/%s] %s' % (at, self.expected, member.subject))
            else:
                out.append('    [%s/%s] MISSING' % (at, self.expected))
            at += 1

        return '\n'.join(out)

    def add_patch(self, lmsg: 'LoreMessage') -> None:
        while len(self.patches) < lmsg.expected + 1:
            self.patches.append(None)
        self.expected = lmsg.expected
        if self.patches[lmsg.counter] is not None:
            # Okay, weird, is the one in there a reply?
            omsg = self.patches[lmsg.counter]
            if omsg.reply or (omsg.counters_inferred and not lmsg.counters_inferred):
                # Replace that one with this one
                logger.debug('  replacing existing: %s', omsg.subject)
                self.patches[lmsg.counter] = lmsg
        else:
            self.patches[lmsg.counter] = lmsg
        self.complete = not (None in self.patches[1:])
        if lmsg.counter == 0:
            # This is a cover letter
            if '\nbase-commit:' in lmsg.body:
                matches = re.search(r'^base-commit: .*?([\da-f]+)', lmsg.body, flags=re.I | re.M)
                if matches:
                    self.base_commit = matches.groups()[0]
            if '\nchange-id:' in lmsg.body:
                matches = re.search(r'^change-id:\s+(\S+)', lmsg.body, flags=re.I | re.M)
                if matches:
                    self.change_id = matches.groups()[0]

        if self.patches[0] is not None:
            self.subject = self.patches[0].subject
        elif self.patches[1] is not None:
            self.subject = self.patches[1].subject

    def get_slug(self, extended: bool = False) -> str:
        # Find the first non-None entry
        lmsg = None
        for lmsg in self.patches:
            if lmsg is not None:
                break

        if lmsg is None:
            return 'undefined'

        prefix = lmsg.date.strftime('%Y%m%d')
        authorline = email.utils.getaddresses([str(x) for x in lmsg.msg.get_all('from', [])])[0]
        if extended:
            local = authorline[1].split('@')[0]
            unsafe = '%s_%s_%s' % (prefix, local, lmsg.subject)
            slug = re.sub(r'\W+', '_', unsafe).strip('_').lower()
        else:
            author = re.sub(r'\W+', '_', authorline[1]).strip('_').lower()
            slug = '%s_%s' % (prefix, author)

        if self.revision != 1:
            slug = 'v%s_%s' % (self.revision, slug)

        return slug[:100]

    def add_extra_trailers(self, trailers: tuple) -> None:
        for lmsg in self.patches[1:]:
            if lmsg is None:
                continue
            lmsg.followup_trailers += trailers

    def add_cover_trailers(self) -> None:
        if self.patches[0] and self.patches[0].followup_trailers:  # noqa
            self.add_extra_trailers(self.patches[0].followup_trailers)  # noqa

    def get_am_ready(self, noaddtrailers=False, covertrailers=False, addmysob=False, addlink=False,
                     linkmask=None, cherrypick=None, copyccs=False, allowbadchars=False) -> List[email.message.Message]:

        usercfg = get_user_config()
        config = get_main_config()

        if addmysob:
            if 'name' not in usercfg or 'email' not in usercfg:
                logger.critical('WARNING: Unable to add your Signed-off-by: git returned no user.name or user.email')
                addmysob = False

        attpolicy = config['attestation-policy']
        try:
            maxdays = int(config['attestation-staleness-days'])
        except ValueError:
            logger.info('WARNING: attestation-staleness-days must be an int')
            maxdays = 0

        # Loop through all patches and see if attestation is the same for all of them,
        # since it usually is
        attref = None
        attsame = True
        attmark = None
        attcrit = False
        if attpolicy != 'off':
            logger.info('Checking attestation on all messages, may take a moment...')
            for lmsg in self.patches[1:]:
                if lmsg is None:
                    attsame = False
                    break

                checkmark, trailers, attcrit = lmsg.get_attestation_trailers(attpolicy, maxdays)
                if attref is None:
                    attref = trailers
                    attmark = checkmark
                    continue
                if set(trailers) == set(attref):
                    continue
                attsame = False
                logger.debug('Attestation info is not the same')
                break

        if covertrailers:
            self.add_cover_trailers()

        at = 1
        msgs = list()
        logger.info('---')
        for lmsg in self.patches[1:]:
            if cherrypick is not None:
                if at not in cherrypick:
                    at += 1
                    logger.debug('  skipped: [%s/%s] (not in cherrypick)', at, self.expected)
                    continue
                if lmsg is None:
                    logger.critical('CRITICAL: [%s/%s] is missing, cannot cherrypick', at, self.expected)
                    raise KeyError('Cherrypick not in series')

            if lmsg is not None:
                extras = list()
                if addlink:
                    if linkmask is None:
                        linkmask = config.get('linkmask')
                    linkval = linkmask % lmsg.msgid
                    lltr = LoreTrailer(name='Link', value=linkval)
                    extras.append(lltr)

                if attsame and not attcrit:
                    if attmark:
                        logger.info('  %s %s', attmark, lmsg.get_am_subject())
                    else:
                        logger.info('  %s', lmsg.get_am_subject())

                else:
                    checkmark, trailers, critical = lmsg.get_attestation_trailers(attpolicy, maxdays)
                    if checkmark:
                        logger.info('  %s %s', checkmark, lmsg.get_am_subject())
                    else:
                        logger.info('  %s', lmsg.get_am_subject())

                    for trailer in trailers:
                        logger.info('    %s', trailer)

                    if critical:
                        import sys
                        logger.critical('---')
                        logger.critical('Exiting due to attestation-policy: hardfail')
                        sys.exit(128)

                add_trailers = True
                if noaddtrailers:
                    add_trailers = False
                msg = lmsg.get_am_message(add_trailers=add_trailers, extras=extras, copyccs=copyccs,
                                          addmysob=addmysob, allowbadchars=allowbadchars)
                msgs.append(msg)
            else:
                logger.error('  ERROR: missing [%s/%s]!', at, self.expected)
            at += 1

        if attpolicy == 'off':
            return msgs

        if attsame and attref:
            logger.info('  ---')
            for trailer in attref:
                logger.info('  %s', trailer)

        if not (can_dkim and can_patatt):
            logger.info('  ---')
            if not can_dkim:
                logger.info('  NOTE: install dkimpy for DKIM signature verification')
            if not can_patatt:
                logger.info('  NOTE: install patatt for end-to-end signature verification')

        return msgs

    def populate_indexes(self):
        self.indexes = list()
        seenfiles = set()
        for lmsg in self.patches[1:]:
            if lmsg is None or lmsg.blob_indexes is None:
                continue
            for ofn, obh, nfn in lmsg.blob_indexes:
                if ofn in seenfiles:
                    # if we have seen this file once already, then it's a repeat patch
                    # it's no longer going to match current hash
                    continue
                seenfiles.add(ofn)
                if set(obh) == {'0'}:
                    # New file, will for sure apply clean
                    continue
                self.indexes.append((ofn, obh))

    def check_applies_clean(self, gitdir: str, at: Optional[str] = None) -> Tuple[int, list]:
        if self.indexes is None:
            self.populate_indexes()

        mismatches = list()
        if at is None:
            at = 'HEAD'
        for fn, bh in self.indexes:
            ecode, out = git_run_command(gitdir, ['ls-tree', at, fn])
            if ecode == 0 and len(out):
                chunks = out.split()
                if chunks[2].startswith(bh):
                    logger.debug('%s hash: matched', fn)
                    continue
                else:
                    logger.debug('%s hash: %s (expected: %s)', fn, chunks[2], bh)
            else:
                # Couldn't get this file, continue
                logger.debug('Could not look up %s:%s', at, fn)
            mismatches.append((fn, bh))

        return len(self.indexes), mismatches

    def find_base(self, gitdir: str, branches: Optional[list] = None, maxdays: int = 30) -> Tuple[str, len, len]:
        # Find the date of the first patch we have
        pdate = datetime.datetime.now()
        for lmsg in self.patches:
            if lmsg is None:
                continue
            pdate = lmsg.date
            break

        # Find the latest commit on that date
        guntil = pdate.strftime('%Y-%m-%d')
        if branches:
            where = branches
        else:
            where = ['--all']

        gitargs = ['log', '--pretty=oneline', '--until', guntil, '--max-count=1'] + where
        lines = git_get_command_lines(gitdir, gitargs)
        if not lines:
            raise IndexError
        commit = lines[0].split()[0]
        checked, mismatches = self.check_applies_clean(gitdir, commit)
        fewest = len(mismatches)
        if fewest > 0:
            since = pdate - datetime.timedelta(days=maxdays)
            gsince = since.strftime('%Y-%m-%d')
            logger.debug('Starting --find-object from %s to %s', gsince, guntil)
            best = commit
            for fn, bi in mismatches:
                logger.debug('Finding tree matching %s=%s in %s', fn, bi, where)
                gitargs = ['log', '--pretty=oneline', '--since', gsince, '--until', guntil,
                           '--find-object', bi] + where
                lines = git_get_command_lines(gitdir, gitargs)
                if not lines:
                    logger.debug('Could not find object %s in the tree', bi)
                    continue
                for line in lines:
                    commit = line.split()[0]
                    logger.debug('commit=%s', commit)
                    # We try both that commit and the one preceding it, in case it was a deletion
                    # Keep track of the fewest mismatches
                    for tc in [commit, f'{commit}~1']:
                        sc, sm = self.check_applies_clean(gitdir, tc)
                        if len(sm) < fewest and len(sm) != sc:
                            fewest = len(sm)
                            best = tc
                            logger.debug('fewest=%s, best=%s', fewest, best)
                            if fewest == 0:
                                break
                        if fewest == 0:
                            break
                    if fewest == 0:
                        break
                if fewest == 0:
                    break
        else:
            best = commit
        if fewest == len(self.indexes):
            # None of the blobs matched
            raise IndexError

        lines = git_get_command_lines(gitdir, ['describe', '--all', best])
        if len(lines):
            return lines[0], len(self.indexes), fewest

        raise IndexError

    def make_fake_am_range(self, gitdir):
        start_commit = end_commit = None
        # Use the msgid of the first non-None patch in the series
        msgid = None
        for lmsg in self.patches:
            if lmsg is not None:
                msgid = lmsg.msgid
                break
        if msgid is None:
            logger.critical('Cannot operate on an empty series')
            return None, None
        cachedata = get_cache(msgid, suffix='fakeam')
        if cachedata and not self.partial_reroll:
            stalecache = False
            chunks = cachedata.strip().split()
            if len(chunks) == 2:
                start_commit, end_commit = chunks
            else:
                stalecache = True
            if start_commit is not None and end_commit is not None:
                # Make sure they are still there
                ecode, out = git_run_command(gitdir, ['cat-file', '-e', start_commit])
                if ecode > 0:
                    stalecache = True
                else:
                    ecode, out = git_run_command(gitdir, ['cat-file', '-e', end_commit])
                    if ecode > 0:
                        stalecache = True
                    else:
                        logger.debug('Using previously generated range')
                        return start_commit, end_commit

            if stalecache:
                logger.debug('Stale cache for [v%s] %s', self.revision, self.subject)
                clear_cache(msgid, suffix='fakeam')

        logger.info('Preparing fake-am for v%s: %s', self.revision, self.subject)
        with git_temp_worktree(gitdir):
            # We are in a temporary chdir at this time, so writing to a known file should be safe
            mbxf = '.__git-am__'
            mbx = mailbox.mbox(mbxf)
            # Logic largely borrowed from gj_tools
            seenfiles = set()
            for lmsg in self.patches[1:]:
                if lmsg is None:
                    logger.critical('ERROR: v%s series incomplete; unable to create a fake-am range', self.revision)
                    return None, None
                logger.debug('Looking at %s', lmsg.full_subject)
                if not lmsg.blob_indexes:
                    logger.critical('ERROR: some patches do not have indexes')
                    logger.critical('       unable to create a fake-am range')
                    return None, None
                for ofn, ofi, nfn in lmsg.blob_indexes:
                    if ofn in seenfiles:
                        # We already processed this file, so this blob won't match
                        continue
                    seenfiles.add(ofn)
                    if set(ofi) == {'0'}:
                        # New file creation, nothing to do here
                        logger.debug('  New file: %s', ofn)
                        continue
                    if not ofn == nfn:
                        # renamed file, make sure to not add the new name later on
                        logger.debug('  Renamed file: %s -> %s', ofn, nfn)
                        seenfiles.add(nfn)
                    # Try to grab full ref_id of this hash
                    ecode, out = git_run_command(gitdir, ['rev-parse', ofi])
                    if ecode > 0:
                        logger.critical('  ERROR: Could not find matching blob for %s (%s)', ofn, ofi)
                        logger.critical('         If you know on which tree this patchset is based,')
                        logger.critical('         add it as a remote and perform "git remote update"')
                        logger.critical('         in order to fetch the missing objects.')
                        return None, None
                    logger.debug('  Found matching blob for: %s', ofn)
                    fullref = out.strip()
                    gitargs = ['update-index', '--add', '--cacheinfo', f'0644,{fullref},{ofn}']
                    ecode, out = git_run_command(None, gitargs)
                    if ecode > 0:
                        logger.critical('  ERROR: Could not run update-index for %s (%s)', ofn, fullref)
                        return None, None
                mbx.add(lmsg.msg.as_string(policy=emlpolicy).encode('utf-8'))

            mbx.close()
            ecode, out = git_run_command(None, ['write-tree'])
            if ecode > 0:
                logger.critical('ERROR: Could not write fake-am tree')
                return None, None
            treeid = out.strip()
            # At this point we have a worktree with files that should cleanly receive a git am
            gitargs = ['commit-tree', treeid + '^{tree}', '-F', '-']
            ecode, out = git_run_command(None, gitargs, stdin='Initial fake commit'.encode('utf-8'))
            if ecode > 0:
                logger.critical('ERROR: Could not commit-tree')
                return None, None
            start_commit = out.strip()
            git_run_command(None, ['reset', '--hard', start_commit])
            ecode, out = git_run_command(None, ['am', mbxf])
            if ecode > 0:
                logger.critical('ERROR: Could not fake-am version %s', self.revision)
                return None, None
            ecode, out = git_run_command(None, ['rev-parse', 'HEAD'])
            end_commit = out.strip()
            logger.info('  range: %.12s..%.12s', start_commit, end_commit)

        logger.debug('Saving into cache:')
        logger.debug('    %s..%s', start_commit, end_commit)
        save_cache(f'{start_commit} {end_commit}\n', msgid, suffix='fakeam')

        return start_commit, end_commit

    def save_cover(self, outfile):
        # noinspection PyUnresolvedReferences
        cover_msg = self.patches[0].get_am_message(add_trailers=False)
        with open(outfile, 'wb') as fh:
            fh.write(LoreMessage.get_msg_as_bytes(cover_msg, headers='decode'))
        logger.critical('Cover: %s', outfile)


class LoreTrailer:
    type: str
    name: str
    lname: str
    value: str
    extinfo: Optional[str] = None
    addr: Optional[Tuple[str, str]] = None
    lmsg = None
    # Small list of recognized utility trailers
    _utility: Set[str] = {'fixes', 'link', 'buglink', 'obsoleted-by', 'message-id', 'change-id', 'base-commit'}

    def __init__(self, name: Optional[str] = None, value: Optional[str] = None, extinfo: Optional[str] = None,
                 msg: Optional[email.message.Message] = None):
        if name is None:
            self.name = 'Signed-off-by'
            ucfg = get_user_config()
            self.value = '%s <%s>' % (ucfg['name'], ucfg['email'])
            self.type = 'person'
            self.addr = (ucfg['name'], ucfg['email'])
        else:
            self.name = name
            self.value = value
            if name.lower() in self._utility or '://' in value:
                self.type = 'utility'
            elif re.search(r'\S+@\S+\.\S+', value):
                self.type = 'person'
                self.addr = email.utils.parseaddr(value)
            else:
                self.type = 'unknown'
        self.lname = self.name.lower()
        self.extinfo = extinfo
        self.msg = msg

    def as_string(self, omit_extinfo: bool = False) -> str:
        ret = f'{self.name}: {self.value}'
        if not self.extinfo or omit_extinfo:
            return ret
        # extinfo can be either be [on the next line], or  # at the end
        if self.extinfo.lstrip()[0] == '#':
            ret += self.extinfo
        else:
            ret += f'\n{self.extinfo}'

        return ret

    def email_eq(self, cmp_email: str, fuzzy: bool = True) -> bool:
        if not self.addr:
            return False
        our = self.addr[1].lower()
        their = cmp_email.lower()
        if our == their:
            return True
        if not fuzzy:
            return False

        if '@' not in our or '@' not in their:
            return False

        # Strip extended local parts often added by people, e.g.:
        # comparing foo@example.com and foo+kernel@example.com should match
        our = re.sub(r'\+[^@]+@', '@', our)
        their = re.sub(r'\+[^@]+@', '@', their)
        if our == their:
            return True

        # See if domain part of one of the addresses is a subset of the other one,
        # which should match cases like foo@linux.intel.com and foo@intel.com
        olocal, odomain = our.split('@', maxsplit=1)
        tlocal, tdomain = their.split('@', maxsplit=1)
        if olocal != tlocal:
            return False

        if (abs(odomain.count('.')-tdomain.count('.')) == 1
                and (odomain.endswith(f'.{tdomain}') or tdomain.endswith(f'.{odomain}'))):
            return True

        return False

    def __eq__(self, other):
        # We never compare extinfo, we just tack it if we find a match
        return self.lname == other.lname and self.value.lower() == other.value.lower()

    def __hash__(self):
        return hash(f'{self.lname}: {self.value}')

    def __repr__(self):
        out = list()
        out.append('  type: %s' % self.type)
        out.append('  name: %s' % self.name)
        out.append('  value: %s' % self.value)
        out.append('  extinfo: %s' % self.extinfo)

        return '\n'.join(out)


class LoreMessage:
    def __init__(self, msg):
        self.msg = msg
        self.msgid = None

        # Subject-based info
        self.lsubject = None
        self.full_subject = None
        self.subject = None
        self.reply = False
        self.revision = 1
        self.reroll_from_revision = None
        self.counter = 1
        self.expected = 1
        self.revision_inferred = True
        self.counters_inferred = True

        # Header-based info
        self.in_reply_to = None
        self.fromname = None
        self.fromemail = None
        self.date = None

        # Body and body-based info
        self.body = None
        self.message = None
        self.charset = 'utf-8'
        self.has_diff = False
        self.has_diffstat = False
        self.trailers = list()
        self.followup_trailers = list()

        # These are populated by pr
        self.pr_base_commit = None
        self.pr_repo = None
        self.pr_ref = None
        self.pr_tip_commit = None
        self.pr_remote_tip_commit = None

        # Patchwork hash
        self.pwhash = None
        # Blob indexes
        self.blob_indexes = None

        self.msgid = LoreMessage.get_clean_msgid(self.msg)
        self.lsubject = LoreSubject(msg['Subject'])
        # Copy them into this object for convenience
        self.full_subject = self.lsubject.full_subject
        self.subject = self.lsubject.subject
        self.reply = self.lsubject.reply
        self.revision = self.lsubject.revision
        self.counter = self.lsubject.counter
        self.expected = self.lsubject.expected
        self.revision_inferred = self.lsubject.revision_inferred
        self.counters_inferred = self.lsubject.counters_inferred

        # Loaded when attestors property is called
        self._attestors = None

        # Handle [PATCH 6/5]
        if self.counter > self.expected:
            self.expected = self.counter

        self.in_reply_to = LoreMessage.get_clean_msgid(self.msg, header='In-Reply-To')

        try:
            fromdata = email.utils.getaddresses([LoreMessage.clean_header(str(x))
                                                 for x in self.msg.get_all('from', [])])[0]
            self.fromname = fromdata[0]
            self.fromemail = fromdata[1]
            if not len(self.fromname.strip()):
                self.fromname = self.fromemail
        except IndexError:
            pass

        msgdate = self.msg.get('Date')
        if msgdate:
            self.date = email.utils.parsedate_to_datetime(str(msgdate))
        else:
            # An email without a Date: field?
            self.date = datetime.datetime.now()
        # Force it to UTC if it's naive
        if self.date.tzinfo is None:
            self.date = self.date.replace(tzinfo=datetime.timezone.utc)

        # walk until we find the first text/plain part
        mcharset = self.msg.get_content_charset()
        if not mcharset:
            mcharset = 'utf-8'
        self.charset = mcharset

        for part in msg.walk():
            cte = part.get_content_type()
            if cte.find('/plain') < 0 and cte.find('/x-patch') < 0:
                continue
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            pcharset = part.get_content_charset()
            if not pcharset:
                pcharset = mcharset
            try:
                payload = payload.decode(pcharset, errors='replace')
                self.charset = pcharset
            except LookupError:
                # what kind of encoding is that?
                # Whatever, we'll use utf-8 and hope for the best
                payload = payload.decode('utf-8', errors='replace')
                part.set_param('charset', 'utf-8')
                self.charset = 'utf-8'
            if self.body is None:
                self.body = payload
                continue
            # If we already found a body, but we now find something that contains a diff,
            # then we prefer this part
            if DIFF_RE.search(payload):
                self.body = payload

        if self.body is None:
            # Woah, we didn't find any usable parts
            logger.debug('  No plain or patch parts found in message')
            logger.info('  Not plaintext: %s', self.full_subject)
            return

        if DIFFSTAT_RE.search(self.body):
            self.has_diffstat = True
        if DIFF_RE.search(self.body):
            self.has_diff = True
            self.pwhash = LoreMessage.get_patchwork_hash(self.body)
            self.blob_indexes = LoreMessage.get_indexes(self.body)

        trailers, others = LoreMessage.find_trailers(self.body, followup=True)
        # We only pay attention to trailers that are sent in reply
        if trailers and self.in_reply_to and not self.has_diff:
            logger.debug('A follow-up missing a Re: but containing a trailer with no patch diff')
            self.reply = True
        if self.reply:
            for trailer in trailers:
                # These are commonly part of patch/commit metadata
                badtrailers = {'from', 'author', 'cc', 'to'}
                if trailer.lname not in badtrailers:
                    self.trailers.append(trailer)

    def get_trailers(self, sloppy: bool = False) -> Tuple[List[LoreTrailer], Set[LoreTrailer]]:
        trailers = list()
        mismatches = set()

        for ltr in self.trailers:
            ltr.lmsg = self
            if sloppy or ltr.type != 'person':
                trailers.append(ltr)
                continue

            if ltr.email_eq(self.fromemail):
                logger.debug('  trailer email match')
                trailers.append(ltr)
                continue

            # Does the name match, at least?
            nmatch = False
            tlname = ltr.addr[0].lower()
            hlname = self.fromname.lower()

            if tlname == hlname:
                logger.debug('  trailer exact name match')
                nmatch = True
            # Finally, see if the header From has a comma in it and try to find all
            # parts in the trailer name
            elif hlname.find(',') > 0:
                nmatch = True
                for nchunk in hlname.split(','):
                    if hlname.find(nchunk.strip()) < 0:
                        nmatch = False
                        break
            if nmatch:
                logger.debug('  trailer fuzzy name match')
                trailers.append(ltr)
                continue

            logger.debug('trailer did not match: %s: %s', ltr.name, ltr.value)
            mismatches.add(ltr)

        return trailers, mismatches

    @property
    def attestors(self):
        if self._attestors is not None:
            return self._attestors

        self._attestors = list()

        config = get_main_config()
        if config['attestation-policy'] == 'off':
            return self._attestors

        logger.debug('Loading attestation: %s', self.full_subject)
        if self.msg.get(DEVSIG_HDR):
            self._load_patatt_attestors()
        if self.msg.get('dkim-signature') and config['attestation-check-dkim'] == 'yes':
            self._load_dkim_attestors()

        logger.debug('Attestors: %s', len(self._attestors))
        return self._attestors

    def _load_dkim_attestors(self) -> None:
        if not can_network:
            logger.debug('Message has DKIM signatures, but can_network is off')
            return
        if not can_dkim:
            logger.debug('Message has DKIM signatures, but can_dkim is off')
            return

        # Yank out all DKIM-Signature headers and try them in reverse order
        # until we come to a passing one
        dkhdrs = list()
        for header in list(self.msg._headers):  # noqa
            if header[0].lower() == 'dkim-signature':
                dkhdrs.append(header)
                self.msg._headers.remove(header) # noqa
        dkhdrs.reverse()

        seenatts = list()
        for hn, hval in dkhdrs:
            # Handle MIME encoded-word syntax or other types of header encoding if
            # present.
            if '?q?' in hval:
                hval = str(email.header.make_header(email.header.decode_header(hval)))
            errors = list()
            hdata = LoreMessage.get_parts_from_header(hval)
            logger.debug('Loading DKIM attestation for d=%s, s=%s', hdata['d'], hdata['s'])

            identity = hdata.get('i')
            if not identity:
                identity = hdata.get('d')
            ts = hdata.get('t')
            signtime = None
            if ts:
                signtime = LoreAttestor.parse_ts(ts)
            else:
                # See if date is included in the h: field
                sh = hdata.get('h')
                if 'date' in sh.lower().split(':'):
                    signtime = self.date

            self.msg._headers.append((hn, hval))  # noqa
            try:
                res = dkim.verify(self.msg.as_bytes(policy=emlpolicy), logger=dkimlogger)
                logger.debug('DKIM verify results: %s=%s', identity, res)
            except Exception as ex:  # noqa
                # Usually, this is due to some DNS resolver failure, which we can't
                # possibly cleanly try/catch. Just mark it as failed and move on.
                logger.debug('DKIM attestation failed: %s', ex)
                errors.append(str(ex))
                res = False

            attestor = LoreAttestorDKIM(res, identity, signtime, errors)
            if attestor.check_identity(self.fromemail):
                # use this one, regardless of any other DKIM signatures
                self._attestors.append(attestor)
                return

            self.msg._headers.pop(-1)  # noqa
            seenatts.append(attestor)

        # No exact domain matches, so return everything we have
        self._attestors += seenatts

    def _trim_body(self) -> None:
        # Get the length specified in the X-Developer-Signature header
        xdsh = self.msg.get('X-Developer-Signature')
        if not xdsh:
            return
        matches = re.search(r'\s+l=(\d+)', xdsh)
        if not matches:
            return
        bl = int(matches.groups()[0])
        i, m, p = get_mailinfo(self.msg.as_bytes(policy=emlpolicy), scissors=False)
        bb = b''
        for line in re.sub(rb'[\r\n]*$', b'', m + p).split(b'\n'):
            bb += re.sub(rb'[\r\n]*$', b'', line) + b'\r\n'
        if len(bb) > bl:
            self.body = bb[:bl].decode()
            # This may have potentially resulted in in-body From/Subject being removed,
            # so make sure we account for this in the message headers
            self.lsubject.subject = self.subject = i.get('Subject')
            self.fromname = i.get('Author')
            self.fromemail = i.get('Email')

    def _load_patatt_attestors(self) -> None:
        if not can_patatt:
            logger.debug('Message has %s headers, but can_patatt is off', DEVSIG_HDR)
            return

        # load our key sources if necessary
        ddir = get_data_dir()
        pdir = os.path.join(ddir, 'keyring')
        config = get_main_config()
        sources = config.get('keyringsrc')
        if not sources:
            # fallback to patatt's keyring if none is specified for b4
            patatt_config = patatt.get_config_from_git(r'patatt\..*', multivals=['keyringsrc'])
            sources = patatt_config.get('keyringsrc')
            if not sources:
                sources = ['ref:::.keys', 'ref:::.local-keys', 'ref::refs/meta/keyring:']
        if pdir not in sources:
            sources.append(pdir)

        # Push our logger and GPGBIN into patatt
        patatt.logger = logger
        patatt.GPGBIN = config['gpgbin']

        logger.debug('Loading patatt attestations with sources=%s', str(sources))

        success = False
        trim_body = False
        while True:
            attestations = patatt.validate_message(self.msg.as_bytes(policy=emlpolicy), sources, trim_body=trim_body)
            # Do we have any successes?
            for attestation in attestations:
                if attestation[0] == patatt.RES_VALID:
                    success = True
                    break
            if success:
                if trim_body:
                    # If we only succeeded after trimming the body, then we MUST set the body
                    # to that value, otherwise someone can append arbitrary content after the l= value
                    # limit message.
                    self._trim_body()
                break
            if not success and trim_body:
                break
            trim_body = True

        for result, identity, signtime, keysrc, keyalgo, errors in attestations:
            if keysrc and keysrc.startswith('(default keyring)/'):
                fpr = keysrc.split('/', 1)[1]
                uids = get_gpg_uids(fpr)
                idmatch = False
                for uid in uids:
                    if uid.find(identity) >= 0:
                        idmatch = True
                        break
                if not idmatch:
                    # Take the first identity in the list and use that instead
                    parts = email.utils.parseaddr(uids[0])
                    identity = parts[1]

            if signtime:
                signdt = LoreAttestor.parse_ts(signtime)
            else:
                signdt = None
            attestor = LoreAttestorPatatt(result, identity, signdt, keysrc, keyalgo, errors)
            self._attestors.append(attestor)

    def get_attestation_trailers(self, attpolicy: str, maxdays: int = 0) -> Tuple[str, list, bool]:
        trailers = list()
        checkmark = None
        critical = False
        for attestor in self.attestors:
            if attestor.passing and maxdays and not attestor.check_time_drift(self.date, maxdays):
                logger.debug('The time drift is too much, marking as non-passing')
                attestor.passing = False
            if not attestor.passing:
                # Is it a person-trailer for which we have a key?
                if attestor.level == 'person':
                    if attestor.have_key:
                        # This was signed, and we have a key, but it's failing
                        trailers.append('%s BADSIG: %s' % (attestor.checkmark, attestor.trailer))
                        checkmark = attestor.checkmark
                    elif attpolicy in ('softfail', 'hardfail'):
                        trailers.append('%s No key: %s' % (attestor.checkmark, attestor.trailer))
                        # This is not critical even in hardfail
                        continue
                elif attpolicy in ('softfail', 'hardfail'):
                    if not checkmark:
                        checkmark = attestor.checkmark
                    trailers.append('%s BADSIG: %s' % (attestor.checkmark, attestor.trailer))

                if attpolicy == 'hardfail':
                    critical = True
            else:
                passing = False
                if not checkmark:
                    checkmark = attestor.checkmark
                if attestor.check_identity(self.fromemail):
                    passing = True
                else:
                    # Do we have an x-original-from?
                    xofh = self.msg.get('X-Original-From')
                    if xofh:
                        logger.debug('Using X-Original-From for identity check')
                        xpair = email.utils.getaddresses([xofh])[0]
                        if attestor.check_identity(xpair[1]):
                            passing = True
                            # Fix our fromname and fromemail, mostly for thanks-tracking
                            self.fromname = xpair[0]
                            self.fromemail = xpair[1]
                            # Drop the reply-to header if it's exactly the same
                            for header in list(self.msg._headers):  # noqa
                                if header[0].lower() == 'reply-to' and header[1].find(xpair[1]) > 0:
                                    self.msg._headers.remove(header)  # noqa
                if passing:
                    trailers.append('%s Signed: %s' % (attestor.checkmark, attestor.trailer))
                else:
                    trailers.append('%s Signed: %s (From: %s)' % (attestor.checkmark, attestor.trailer,
                                                                  self.fromemail))

        return checkmark, trailers, critical

    def __repr__(self):
        out = list()
        out.append('msgid: %s' % self.msgid)
        out.append(str(self.lsubject))

        out.append('  fromname: %s' % self.fromname)
        out.append('  fromemail: %s' % self.fromemail)
        out.append('  date: %s' % str(self.date))
        out.append('  in_reply_to: %s' % self.in_reply_to)

        # Header-based info
        out.append('  --- begin body ---')
        for line in self.body.split('\n'):
            out.append('  |%s' % line)
        out.append('  --- end body ---')

        # Body and body-based info
        out.append('  has_diff: %s' % self.has_diff)
        out.append('  has_diffstat: %s' % self.has_diffstat)
        out.append('  --- begin my trailers ---')
        for trailer in self.trailers:
            out.append('  |%s' % str(trailer))
        out.append('  --- begin followup trailers ---')
        for trailer in self.followup_trailers:
            out.append('  |%s' % str(trailer))
        out.append('  --- end trailers ---')
        out.append('  --- begin attestors ---')
        for attestor in self.attestors:
            out.append('  |%s' % str(attestor))
        out.append('  --- end attestors ---')

        return '\n'.join(out)

    @staticmethod
    def clean_header(hdrval):
        if hdrval is None:
            return ''

        if hdrval.find('=?') >= 0:
            # Do we have any email addresses in there?
            if re.search(r'<\S+@\S+>', hdrval, flags=re.I | re.M):
                newaddrs = list()
                for addr in email.utils.getaddresses([hdrval]):
                    if addr[0].find('=?') >= 0:
                        # Nothing wrong with nested calls, right?
                        addr = (LoreMessage.clean_header(addr[0]), addr[1])
                    # Work around https://github.com/python/cpython/issues/100900
                    if re.search(r'[^\w\s]', addr[0]):
                        newaddrs.append(f'"{addr[0]}" <{addr[1]}>')
                    else:
                        newaddrs.append(email.utils.formataddr(addr))
                return ', '.join(newaddrs)

            decoded = ''
            for hstr, hcs in email.header.decode_header(hdrval):
                if hcs is None:
                    hcs = 'utf-8'
                try:
                    decoded += hstr.decode(hcs, errors='replace')
                except LookupError:
                    # Try as utf-8
                    decoded += hstr.decode('utf-8', errors='replace')
                except (UnicodeDecodeError, AttributeError):
                    decoded += hstr
        else:
            decoded = hdrval

        new_hdrval = re.sub(r'\n?\s+', ' ', decoded)
        return new_hdrval.strip()

    @staticmethod
    def wrap_header(hdr, width: int = 75, nl: str = '\n',
                    transform: Literal['encode', 'decode', 'preserve'] = 'preserve') -> bytes:
        hname, hval = hdr
        if hname.lower() in ('to', 'cc', 'from', 'x-original-from'):
            _parts = [f'{hname}: ',]
            first = True
            for addr in email.utils.getaddresses([hval]):
                if transform == 'encode' and not addr[0].isascii():
                    addr = (email.quoprimime.header_encode(addr[0].encode(), charset='utf-8'), addr[1])
                    qp = format_addrs([addr], clean=False)
                elif transform == 'decode':
                    qp = format_addrs([addr], clean=True)
                else:
                    qp = format_addrs([addr], clean=False)
                # See if there is enough room on the existing line
                if first:
                    _parts[-1] += qp
                    first = False
                    continue
                if len(_parts[-1] + ', ' + qp) > width:
                    _parts[-1] += ', '
                    _parts.append(qp)
                    continue
                _parts[-1] += ', ' + qp
        else:
            if transform == 'decode' and hval.find('?=') >= 0:
                hdata = f'{hname}: ' + LoreMessage.clean_header(hval)
            else:
                hdata = f'{hname}: {hval}'
            if transform != 'encode' or hval.isascii():
                if len(hdata) <= width:
                    return hdata.encode()
                # Use simple textwrap, with a small trick that ensures that long non-breakable
                # strings don't show up on the next line from the bare header
                hdata = hdata.replace(': ', ':_', 1)
                wrapped = textwrap.wrap(hdata, break_long_words=False, break_on_hyphens=False,
                                        subsequent_indent=' ', width=width)
                return nl.join(wrapped).replace(':_', ': ', 1).encode()

            qp = f'{hname}: ' + email.quoprimime.header_encode(hval.encode(), charset='utf-8')
            # is it longer than width?
            if len(qp) <= width:
                return qp.encode()

            _parts = list()
            while len(qp) > width:
                wrapat = width - 2
                if len(_parts):
                    # Also allow for the ' ' at the front on continuation lines
                    wrapat -= 1
                # Make sure we don't break on a =XX escape sequence
                while '=' in qp[wrapat-2:wrapat]:
                    wrapat -= 1
                _parts.append(qp[:wrapat] + '?=')
                qp = ('=?utf-8?q?' + qp[wrapat:])
            _parts.append(qp)
        return f'{nl} '.join(_parts).encode()

    @staticmethod
    def get_msg_as_bytes(msg: email.message.Message, nl: str ='\n',
                         headers: Literal['encode', 'decode', 'preserve'] = 'preserve') -> bytes:
        bdata = b''
        for hname, hval in msg.items():
            bdata += LoreMessage.wrap_header((hname, str(hval)), nl=nl, transform=headers) + nl.encode()
        bdata += nl.encode()
        payload = msg.get_payload(decode=True)
        for bline in payload.split(b'\n'):
            bdata += re.sub(rb'[\r\n]*$', b'', bline) + nl.encode()
        return bdata

    @staticmethod
    def get_parts_from_header(hstr: str) -> dict:
        hstr = re.sub(r'\s*', '', hstr)
        hdata = dict()
        for chunk in hstr.split(';'):
            parts = chunk.split('=', 1)
            if len(parts) < 2:
                continue
            hdata[parts[0]] = parts[1]
        return hdata

    @staticmethod
    def get_clean_msgid(msg: email.message.Message, header='Message-Id') -> str:
        msgid = None
        raw = msg.get(header)
        if raw:
            matches = re.search(r'<([^>]+)>', LoreMessage.clean_header(raw))
            if matches:
                msgid = matches.groups()[0]
        return msgid

    @staticmethod
    def get_preferred_duplicate(msg1: email.message.Message, msg2: email.message.Message) -> email.message.Message:
        config = get_main_config()
        listid1 = LoreMessage.get_clean_msgid(msg1, 'list-id')
        if listid1:
            prefidx1 = 0
            for listglob in config['listid-preference']:
                if fnmatch.fnmatch(listid1, listglob):
                    break
                prefidx1 += 1
        else:
            prefidx1 = config['listid-preference'].index('*')

        listid2 = LoreMessage.get_clean_msgid(msg2, 'list-id')
        if listid2:
            prefidx2 = 0
            for listglob in config['listid-preference']:
                if fnmatch.fnmatch(listid2, listglob):
                    break
                prefidx2 += 1
        else:
            prefidx2 = config['listid-preference'].index('*')

        if prefidx1 <= prefidx2:
            logger.debug('Picked duplicate from preferred source: %s', listid1)
            return msg1
        logger.debug('Picked duplicate from preferred source: %s', listid2)
        return msg2

    @staticmethod
    def get_patch_id(diff: str) -> Optional[str]:
        gitargs = ['patch-id', '--stable']
        ecode, out = git_run_command(None, gitargs, stdin=diff.encode())
        if ecode > 0 or not len(out.strip()):
            return None
        return out.split(maxsplit=1)[0]

    @staticmethod
    def get_patchwork_hash(diff: str) -> str:
        """Generate a hash from a diff. Lifted verbatim from patchwork."""

        prefixes = ['-', '+', ' ']
        hashed = hashlib.sha1()

        for line in diff.split('\n'):
            if len(line) <= 0:
                continue

            hunk_match = HUNK_RE.match(line)
            filename_match = FILENAME_RE.match(line)

            if filename_match:
                # normalise -p1 top-directories
                if filename_match.group(1) == '---':
                    filename = 'a/'
                else:
                    filename = 'b/'
                filename += '/'.join(filename_match.group(2).split('/')[1:])

                line = filename_match.group(1) + ' ' + filename
            elif hunk_match:
                # remove line numbers, but leave line counts
                def fn(x):
                    if not x:
                        return 1
                    return int(x)

                line_nos = list(map(fn, hunk_match.groups()))
                line = '@@ -%d +%d @@' % tuple(line_nos)
            elif line[0] in prefixes:
                # if we have a +, - or context line, leave as-is
                pass
            else:
                # other lines are ignored
                continue

            hashed.update((line + '\n').encode('utf-8'))

        return hashed.hexdigest()

    @staticmethod
    def get_indexes(diff: str) -> Set[tuple]:
        indexes = set()
        oldfile = None
        newfile = None
        for line in diff.split('\n'):
            if line.find('diff ') != 0 and line.find('index ') != 0:
                continue
            matches = re.search(r'^diff\s+--git\s+\w/(.*)\s+\w/(.*)$', line)
            if matches:
                oldfile = matches.groups()[0]
                newfile = matches.groups()[1]
                continue
            matches = re.search(r'^index\s+([\da-f]+)\.\.[\da-f]+.*$', line)
            if matches and oldfile is not None and newfile is not None:
                indexes.add((oldfile, matches.groups()[0], newfile))
        return indexes

    @staticmethod
    def find_trailers(body: str, followup: bool = False) -> Tuple[List[LoreTrailer], List[str]]:
        ignores = {'phone', 'email'}
        headers = {'subject', 'date', 'from'}
        nonperson = {'fixes', 'subject', 'date', 'link', 'buglink', 'obsoleted-by', 'change-id', 'base-commit'}
        # Ignore everything below standard email signature marker
        body = body.split('\n-- \n', 1)[0].strip() + '\n'
        # Fix some more common copypasta trailer wrapping
        # Fixes: abcd0123 (foo bar
        # baz quux)
        body = re.sub(r'^(\S+:\s+[\da-f]+\s+\([^)]+)\n([^\n]+\))', r'\1 \2', body, flags=re.M)
        # Signed-off-by: Long Name
        # <email.here@example.com>
        body = re.sub(r'^(\S+:\s+[^<]+)\n(<[^>]+>)$', r'\1 \2', body, flags=re.M)
        # Signed-off-by: Foo foo <foo@foo.com>
        # [for the thing that the thing is too long the thing that is
        # thing but thing]
        # (too false-positivey, commented out)
        # body = re.sub(r'^(\[[^]]+)\n([^]]+]$)', r'\1 \2', body, flags=re.M)
        trailers = list()
        others = list()
        was_trailer = False
        for line in body.split('\n'):
            line = line.strip('\r')
            matches = re.search(r'^\s*(\w\S+):\s+(\S.*)', line, flags=re.I)
            if matches:
                oname, ovalue = list(matches.groups())
                # We only accept headers if we haven't seen any non-trailer lines
                lname = oname.lower()
                if lname in ignores:
                    logger.debug('Ignoring known non-trailer: %s', line)
                    continue
                if len(others) and lname in headers:
                    logger.debug('Ignoring %s (header after other content)', line)
                    continue
                if followup:
                    if not lname.isascii():
                        logger.debug('Ignoring known non-ascii follow-up trailer: %s', lname)
                        continue
                    mperson = re.search(r'\S+@\S+\.\S+', ovalue)
                    if not mperson and lname not in nonperson:
                        logger.debug('Ignoring %s (not a recognized non-person trailer)', line)
                        continue
                    if re.search(r'https?://', ovalue):
                        logger.debug('Ignoring %s (not a recognized link trailer)', line)
                        continue

                extinfo = None
                mextinfo = re.search(r'(.*\S+)(\s+#[^#]+)$', ovalue)
                if mextinfo:
                    logger.debug('Trailer contains hashtag extinfo: %s', line)
                    # Found extinfo of the hashtag genre
                    egr = mextinfo.groups()
                    ovalue = egr[0]
                    extinfo = egr[1]

                was_trailer = True
                ltrailer = LoreTrailer(name=oname, value=ovalue, extinfo=extinfo)
                trailers.append(ltrailer)
                continue
            # Is it an extended info line, e.g.:
            # Signed-off-by: Foo Foo <foo@foo.com>
            # [for the foo bits]
            if len(line) > 2 and was_trailer and re.search(r'^\s*\[[^]]+]\s*$', line):
                trailers[-1].extinfo = line
                was_trailer = False
                continue
            was_trailer = False
            others.append(line)

        return trailers, others

    @staticmethod
    def rebuild_message(headers: List[LoreTrailer], message: str, trailers: List[LoreTrailer],
                        basement: str, signature: str) -> str:
        body = ''
        if headers:
            for ltr in headers:
                # There is no [extdata] in git headers, so we omit it
                body += ltr.as_string(omit_extinfo=True) + '\n'
            body += '\n'

        if len(message):
            body += message.rstrip('\r\n') + '\n'
            if len(trailers):
                body += '\n'

        for ltr in trailers:
            body += ltr.as_string() + '\n'

        if len(basement):
            if not len(trailers):
                body += '\n'
            body += '---\n'
            body += basement.rstrip('\r\n') + '\n'

        if len(signature):
            body += '-- \n'
            body += signature.rstrip('\r\n') + '\n'

        return body

    @staticmethod
    def get_body_parts(body: str) -> Tuple[List[LoreTrailer], str, List[LoreTrailer], str, str]:
        # remove any starting/trailing blank lines
        body = body.replace('\r', '')
        body = body.strip('\n')
        # Extra git-relevant headers, like From:, Subject:, Date:, etc
        githeaders = list()
        # commit message
        message = ''
        # everything below the ---
        basement = ''
        # conformant signature --\s\n
        signature = ''
        sparts = body.rsplit('\n-- \n', 1)
        if len(sparts) > 1:
            signature = sparts[1]
            body = sparts[0].rstrip('\n')

        parts = re.split('^---\n', body, maxsplit=1, flags=re.M)
        if len(parts) == 2:
            basement = parts[1].rstrip('\n')
        elif body.find('\ndiff ') >= 0:
            parts = body.split('\ndiff ', 1)
            if len(parts) == 2:
                parts[1] = 'diff ' + parts[1]
            basement = parts[1].rstrip('\n')

        mbody = parts[0].strip('\n')

        # Split into paragraphs
        bpara = mbody.split('\n\n')

        # Is every line of the first part in a header format?
        mparts = list()
        h, o = LoreMessage.find_trailers(bpara[0])
        if len(o):
            # Not everything was a header, so we don't treat it as headers
            mparts.append(bpara[0])
        else:
            githeaders = h

        # Any lines of the last part match the header format?
        trailers, nlines = LoreMessage.find_trailers(bpara[-1])

        if len(bpara) == 1:
            if githeaders == trailers:
                # This is a message that consists of just trailers?
                githeaders = list()
            if nlines:
                message = '\n'.join(nlines)
            return githeaders, message, trailers, basement, signature

        # Add all parts between first and last to mparts
        if len(bpara) > 2:
            mparts += bpara[1:-1]

        if len(nlines):
            # Add them as the last part
            mparts.append('\n'.join(nlines))

        message = '\n\n'.join(mparts)

        return githeaders, message, trailers, basement, signature

    def fix_trailers(self, extras: Optional[List[LoreTrailer]] = None,
                     copyccs: bool = False, addmysob: bool = False,
                     fallback_order: str = '*',
                     omit_trailers: Optional[List[str]] = None) -> None:

        config = get_main_config()

        bheaders, message, btrailers, basement, signature = LoreMessage.get_body_parts(self.body)

        sobtr = LoreTrailer()
        hasmysob = False
        if sobtr in btrailers:
            # Our own signoff always moves to the bottom of all trailers
            hasmysob = True
            btrailers.remove(sobtr)

        new_trailers = self.followup_trailers
        if extras:
            new_trailers += extras

        if sobtr in new_trailers:
            # Our own signoff always moves to the bottom of all trailers
            new_trailers.remove(sobtr)
            addmysob = True

        if copyccs:
            alldests = email.utils.getaddresses([str(x) for x in self.msg.get_all('to', [])])
            alldests += email.utils.getaddresses([str(x) for x in self.msg.get_all('cc', [])])
            # Sort by domain name, then local
            alldests.sort(key=lambda x: x[1].find('@') > 0 and x[1].split('@')[1] + x[1].split('@')[0] or x[1])
            for pair in alldests:
                found = False
                for fltr in btrailers + new_trailers:
                    if fltr.email_eq(pair[1]):
                        # already present
                        found = True
                        break

                if not found:
                    if len(pair[0]):
                        altr = LoreTrailer(name='Cc', value=f'{pair[0]} <{pair[1]}>')
                    else:
                        altr = LoreTrailer(name='Cc', value=pair[1])
                    new_trailers.append(altr)

        torder = config.get('trailer-order', fallback_order)
        if torder and torder != '*':
            # this only applies to trailers within our chain of custody, so walk existing
            # body trailers backwards and stop at the outermost Signed-off-by we find (if any)
            for bltr in reversed(btrailers):
                if bltr.lname == 'signed-off-by':
                    break
                btrailers.remove(bltr)
                new_trailers.insert(0, bltr)

            ordered_trailers = list()
            for glob in [x.strip().lower() for x in torder.split(',')]:
                if not len(new_trailers):
                    break
                for ltr in list(new_trailers):
                    if fnmatch.fnmatch(ltr.lname, glob):
                        ordered_trailers.append(ltr)
                        new_trailers.remove(ltr)
            if len(new_trailers):
                # Tack them to the bottom
                ordered_trailers += new_trailers
            new_trailers = ordered_trailers

        attpolicy = config['attestation-policy']
        fixtrailers = btrailers

        # load trailers we should ignore
        ignore_from = config.get('trailers-ignore-from')
        if ignore_from:
            ignores = [x[1].lower() for x in email.utils.getaddresses([ignore_from])]
        else:
            ignores = list()

        ignored = set()
        for ltr in new_trailers:
            if ltr in fixtrailers or ltr in ignored:
                continue

            if ltr.addr and ltr.addr[1].lower() in ignores:
                logger.info('    x %s', ltr.as_string(omit_extinfo=True))
                ignored.add(ltr)
                continue

            fixtrailers.append(ltr)
            extra = ''
            if ltr.lmsg is not None:
                for attestor in ltr.lmsg.attestors:
                    if attestor.passing:
                        extra = ' (%s %s)' % (attestor.checkmark, attestor.trailer)
                    elif attpolicy in ('hardfail', 'softfail'):
                        extra = ' (%s %s)' % (attestor.checkmark, attestor.trailer)
                        if attpolicy == 'hardfail':
                            import sys
                            logger.critical('---')
                            logger.critical('Exiting due to attestation-policy: hardfail')
                            sys.exit(1)

                logger.info('    + %s%s', ltr.as_string(omit_extinfo=True), extra)

            elif extras is not None and ltr in extras:
                logger.info('    + %s%s', ltr.as_string(omit_extinfo=True), extra)

        if addmysob or hasmysob:
            # Tack on our signoff at the bottom
            fixtrailers.append(sobtr)
            if not hasmysob:
                logger.info('    + %s', sobtr.as_string(omit_extinfo=True))

        if omit_trailers and fixtrailers:
            for ltr in fixtrailers:
                if ltr.lname in omit_trailers:
                    fixtrailers.remove(ltr)

        # Build the new commit message in case we're working directly
        # on the tree.
        self.message = self.subject + '\n\n'
        if len(message):
            self.message += message.rstrip('\r\n') + '\n'
            if len(fixtrailers):
                self.message += '\n'
        if len(fixtrailers):
            for ltr in fixtrailers:
                self.message += ltr.as_string() + '\n'
        # Split the basement along '---', in case there is extra info in the
        # message of the commit (used by devs to keep extra info about the patch)
        bparts = re.split(r'^---\n', basement, flags=re.M)
        for bpart in list(bparts):
            # If it's a diff or diffstat, we don't care to keep it
            if DIFF_RE.search(bpart) or DIFFSTAT_RE.search(bpart):
                bparts.remove(bpart)
        if bparts:
            self.message += '---\n' + '---\n'.join(bparts)

        self.body = LoreMessage.rebuild_message(bheaders, message, fixtrailers, basement, signature)

    def get_am_subject(self, indicate_reroll=True, use_subject=None):
        # Return a clean patch subject
        parts = ['PATCH']
        if self.lsubject.rfc:
            parts.append('RFC')
        if self.reroll_from_revision:
            if indicate_reroll:
                if self.reroll_from_revision != self.revision:
                    parts.append('v%d->v%d' % (self.reroll_from_revision, self.revision))
                else:
                    parts.append(' %s  v%d' % (' ' * len(str(self.reroll_from_revision)), self.revision))
            else:
                parts.append('v%d' % self.revision)
        elif not self.revision_inferred:
            parts.append('v%d' % self.revision)
        if not self.lsubject.counters_inferred:
            parts.append('%d/%d' % (self.lsubject.counter, self.lsubject.expected))

        if not use_subject:
            use_subject = self.lsubject.subject

        return '[%s] %s' % (' '.join(parts), use_subject)

    def get_am_message(self, add_trailers=True, addmysob=False, extras=None, copyccs=False, allowbadchars=False):
        # Look through the body to make sure there aren't any suspicious unicode control flow chars
        # First, encode into ascii and compare for a quickie utf8 presence test
        if not allowbadchars and self.body.encode('ascii', errors='replace') != self.body.encode():
            import unicodedata
            logger.debug('Body contains non-ascii characters. Running Unicode Cf char tests.')
            for line in self.body.split('\n'):
                # Does this line have any unicode?
                if line.encode() == line.encode('ascii', errors='replace'):
                    continue
                ucats = {unicodedata.category(ch) for ch in line.rstrip('\r')}
                # If we have Cf (control flow characters) but not Lo ("letter other") characters,
                # indicating a language other than latin, then there's likely something funky going on
                if 'Cf' in ucats and 'Lo' not in ucats:
                    # find the offending char
                    at = 0
                    for c in line.rstrip('\r'):
                        if unicodedata.category(c) == 'Cf':
                            logger.critical('---')
                            logger.critical('WARNING: Message contains suspicious unicode control characters!')
                            logger.critical('         Subject: %s', self.full_subject)
                            logger.critical('            Line: %s', line.rstrip('\r'))
                            logger.critical('            ------%s^', '-'*at)
                            logger.critical('            Char: %s (%s)', unicodedata.name(c), hex(ord(c)))
                            logger.critical('         If you are sure about this, rerun with the right flag to allow.')
                            sys.exit(1)
                        at += 1

        # Remove anything that's cut off by scissors
        mi_msg = email.message.EmailMessage()
        mi_msg['From'] = self.msg['From']
        mi_msg['Date'] = self.msg['Date']
        mi_msg['Subject'] = self.msg['Subject']
        mi_msg.set_payload(self.body, charset='utf-8')
        mi_msg.set_charset('utf-8')

        i, m, p = get_mailinfo(mi_msg.as_bytes(policy=emlpolicy), scissors=True)
        self.body = m.decode() + p.decode()
        if add_trailers:
            self.fix_trailers(copyccs=copyccs, addmysob=addmysob, extras=extras)

        am_msg = email.message.EmailMessage()
        if i.get('Author'):
            hfrom = f'{i.get("Author")} <{i.get("Email")}>'
        else:
            hfrom = i.get('Email')
        am_msg.add_header('Subject', self.get_am_subject(indicate_reroll=False, use_subject=i.get('Subject')))
        am_msg.add_header('From', hfrom)
        am_msg.add_header('Date', i.get('Date'))
        am_msg.add_header('Message-Id', f'<{self.msgid}>')
        am_msg.set_payload(self.body, charset='utf-8')
        return am_msg


class LoreSubject:
    def __init__(self, subject):
        # Subject-based info
        self.full_subject = None
        self.subject = None
        self.reply = False
        self.resend = False
        self.patch = False
        self.rfc = False
        self.revision = 1
        self.counter = 1
        self.expected = 1
        self.revision_inferred = True
        self.counters_inferred = True
        self.prefixes = list()

        subject = re.sub(r'\s+', ' ', LoreMessage.clean_header(subject)).strip()
        self.full_subject = subject

        # Is it a reply?
        if re.search(r'^(Re|Aw|Fwd):', subject, re.I) or re.search(r'^\w{2,3}:\s*\[', subject):
            self.reply = True
            self.subject = subject
            # We don't care to parse the rest
            return

        # Remove any brackets inside brackets
        while True:
            oldsubj = subject
            subject = re.sub(r'\[([^]]*)\[([^\[\]]*)]', r'[\1\2]', subject)
            subject = re.sub(r'\[([^]]*)]([^\[\]]*)]', r'[\1\2]', subject)
            if oldsubj == subject:
                break

        # Find all [foo] in the title
        while subject.find('[') == 0:
            matches = re.search(r'^\[([^]]*)]', subject)
            if not matches:
                break

            bracketed = matches.groups()[0].strip()
            # Fix [PATCHv3] to be properly [PATCH v3]
            bracketed = re.sub(r'(patch)(v\d+)', r'\1 \2', bracketed, flags=re.I)

            for chunk in bracketed.split():
                # Remove any trailing commas or semicolons
                chunk = chunk.strip(',;')
                if re.search(r'^\d{1,4}/\d{1,4}$', chunk):
                    counters = chunk.split('/')
                    self.counter = int(counters[0])
                    self.expected = int(counters[1])
                    self.counters_inferred = False
                elif re.search(r'^v\d+$', chunk, re.IGNORECASE):
                    self.revision = int(chunk[1:])
                    self.revision_inferred = False
                elif chunk.lower().find('rfc') == 0:
                    self.rfc = True
                elif chunk.lower().find('resend') == 0:
                    self.resend = True
                elif chunk.lower().find('patch') == 0:
                    self.patch = True
                self.prefixes.append(chunk)
            subject = re.sub(r'^\s*\[[^]]*]\s*', '', subject)
        self.subject = subject

    def get_extra_prefixes(self, exclude: Optional[List[str]] = None) -> List[str]:
        ret = list()
        for _prf in self.prefixes:
            if exclude and _prf in exclude:
                continue
            if _prf.lower() == 'patch':
                continue
            elif re.search(r'v\d+', _prf, flags=re.I):
                continue
            elif re.search(r'\d+/\d+', _prf):
                continue
            ret.append(_prf)

        return ret

    def get_rebuilt_subject(self, eprefixes: Optional[List[str]] = None):
        _pfx = self.get_extra_prefixes()
        if eprefixes:
            for _epfx in eprefixes:
                if _epfx not in _pfx:
                    _pfx.append(_epfx)
        if self.revision > 1:
            _pfx.append(f'v{self.revision}')
        if self.expected > 1:
            _pfx.append('%s/%s' % (str(self.counter).zfill(len(str(self.expected))), self.expected))

        if len(_pfx):
            return '[PATCH ' + ' '.join(_pfx) + '] ' + self.subject
        else:
            return f'[PATCH] {self.subject}'

    def get_slug(self, sep='_', with_counter: bool = True):
        unsafe = self.subject
        if with_counter:
            unsafe = '%04d%s%s' % (self.counter, sep, unsafe)
        return re.sub(r'\W+', sep, unsafe).strip(sep).lower()

    def __repr__(self):
        out = list()
        out.append('  full_subject: %s' % self.full_subject)
        out.append('  subject: %s' % self.subject)
        out.append('  reply: %s' % self.reply)
        out.append('  resend: %s' % self.resend)
        out.append('  patch: %s' % self.patch)
        out.append('  rfc: %s' % self.rfc)
        out.append('  revision: %s' % self.revision)
        out.append('  revision_inferred: %s' % self.revision_inferred)
        out.append('  counter: %s' % self.counter)
        out.append('  expected: %s' % self.expected)
        out.append('  counters_inferred: %s' % self.counters_inferred)
        out.append('  prefixes: %s' % ', '.join(self.prefixes))

        return '\n'.join(out)


class LoreAttestor:
    mode: Optional[str]
    level: Optional[str]
    identity: Optional[str]
    signtime: Optional[any]
    keysrc: Optional[str]
    keyalgo: Optional[str]
    passing: bool
    have_key: bool
    errors: list

    def __init__(self) -> None:
        self.mode = None
        self.level = None
        self.identity = None
        self.signtime = None
        self.keysrc = None
        self.keyalgo = None
        self.passing = False
        self.have_key = False
        self.errors = list()

    @property
    def checkmark(self) -> str:
        config = get_main_config()
        if config['attestation-checkmarks'] == 'fancy':
            if self.passing:
                return ATT_PASS_FANCY
            return ATT_FAIL_FANCY
        if self.passing:
            return ATT_PASS_SIMPLE
        return ATT_FAIL_SIMPLE

    @property
    def trailer(self):
        if self.keyalgo:
            mode = self.keyalgo
        else:
            mode = self.mode

        return '%s/%s' % (mode, self.identity.lower())

    def check_time_drift(self, emldate, maxdays: int = 30) -> bool:
        if not self.passing or self.signtime is None:
            return False

        maxdrift = datetime.timedelta(days=maxdays)

        sdrift = self.signtime - emldate
        if sdrift > maxdrift:
            self.errors.append('Time drift between Date and t too great (%s)' % sdrift)
            return False

        logger.debug('PASS : time drift between Date and t (%s)', sdrift)
        return True

    def check_identity(self, emlfrom: str) -> bool:
        if not self.passing or not emlfrom:
            return False

        if self.level == 'domain':
            if emlfrom.lower().endswith('@' + self.identity.lower()):
                logger.debug('PASS : sig domain %s matches from identity %s', self.identity, emlfrom)
                return True
            self.errors.append('signing domain %s does not match From: %s' % (self.identity, emlfrom))
            return False

        if emlfrom.lower() == self.identity.lower():
            logger.debug('PASS : sig identity %s matches from identity %s', self.identity, emlfrom)
            return True
        self.errors.append('signing identity %s does not match From: %s' % (self.identity, emlfrom))
        return False

    @staticmethod
    def parse_ts(ts: Optional[str]):
        try:
            return datetime.datetime.utcfromtimestamp(int(ts)).replace(tzinfo=datetime.timezone.utc)
        except:  # noqa
            logger.debug('Failed parsing t=%s', ts)
        return None

    def __repr__(self):
        out = list()
        out.append('    mode: %s' % self.mode)
        out.append('   level: %s' % self.level)
        out.append('identity: %s' % self.identity)
        out.append('signtime: %s' % self.signtime)
        out.append('  keysrc: %s' % self.keysrc)
        out.append(' keyalgo: %s' % self.keyalgo)
        out.append(' passing: %s' % self.passing)
        out.append('have_key: %s' % self.have_key)
        out.append('  errors: %s' % ','.join(self.errors))
        return '\n'.join(out)


class LoreAttestorDKIM(LoreAttestor):
    def __init__(self, passing: bool, identity: str, signtime: Optional[any], errors: list) -> None:
        super().__init__()
        self.mode = 'DKIM'
        self.level = 'domain'
        self.keysrc = 'DNS'
        self.signtime = signtime
        self.passing = passing
        self.errors = errors
        if identity.find('@') >= 0:
            self.identity = identity.split('@')[1]
        else:
            self.identity = identity


class LoreAttestorPatatt(LoreAttestor):
    def __init__(self, result: bool, identity: str, signtime: Optional[any], keysrc: str, keyalgo: str,
                 errors: list) -> None:
        super().__init__()
        self.mode = 'patatt'
        self.level = 'person'
        self.identity = identity
        self.signtime = signtime
        self.keysrc = keysrc
        self.keyalgo = keyalgo
        self.errors = errors
        if result == patatt.RES_VALID:
            self.passing = True
            self.have_key = True
        elif result >= patatt.RES_BADSIG:
            self.have_key = True


def _run_command(cmdargs: List[str], stdin: Optional[bytes] = None,
                 rundir: Optional[str] = None) -> Tuple[int, bytes, bytes]:
    if rundir:
        logger.debug('Changing dir to %s', rundir)
        curdir = os.getcwd()
        os.chdir(rundir)
    else:
        curdir = None

    logger.debug('Running %s' % ' '.join(cmdargs))
    sp = subprocess.Popen(cmdargs, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, error) = sp.communicate(input=stdin)
    if curdir:
        logger.debug('Changing back into %s', curdir)
        os.chdir(curdir)

    return sp.returncode, output, error


def gpg_run_command(args: List[str], stdin: Optional[bytes] = None) -> Tuple[int, bytes, bytes]:
    config = get_main_config()
    cmdargs = [config['gpgbin'], '--batch', '--no-auto-key-retrieve', '--no-auto-check-trustdb']
    if config['attestation-gnupghome'] is not None:
        cmdargs += ['--homedir', config['attestation-gnupghome']]
    cmdargs += args

    return _run_command(cmdargs, stdin=stdin)


def git_run_command(gitdir: Optional[str], args: List[str], stdin: Optional[bytes] = None,
                    logstderr: bool = False, decode: bool = True) -> Tuple[int, Union[str, bytes]]:
    cmdargs = ['git', '--no-pager']
    if gitdir:
        if os.path.exists(os.path.join(gitdir, '.git')):
            gitdir = os.path.join(gitdir, '.git')
        cmdargs += ['--git-dir', gitdir]

    # counteract some potential local settings
    if args[0] == 'log':
        args.insert(1, '--no-abbrev-commit')

    cmdargs += args

    ecode, out, err = _run_command(cmdargs, stdin=stdin)

    if decode:
        out = out.decode(errors='replace')

    if logstderr and len(err.strip()):
        if decode:
            err = err.decode(errors='replace')
        logger.debug('Stderr: %s', err)
        out += err

    return ecode, out


def git_credential_fill(gitdir: Optional[str], protocol: str, host: str, username: str) -> Optional[str]:
    stdin = f'protocol={protocol}\nhost={host}\nusername={username}\n'.encode()
    ecode, out = git_run_command(gitdir, args=['credential', 'fill'], stdin=stdin)
    if ecode == 0:
        for line in out.splitlines():
            if not line.startswith('password='):
                continue
            chunks = line.split('=', maxsplit=1)
            return chunks[1]
    return None


def git_get_command_lines(gitdir: Optional[str], args: list) -> List[str]:
    ecode, out = git_run_command(gitdir, args)
    lines = list()
    if out:
        for line in out.split('\n'):
            if line == '':
                continue
            lines.append(line)

    return lines


def git_get_repo_status(gitdir: Optional[str] = None, untracked: bool = False) -> List[str]:
    args = ['status', '--porcelain=v1']
    if not untracked:
        args.append('--untracked-files=no')
    return git_get_command_lines(gitdir, args)


@contextmanager
def git_temp_worktree(gitdir=None, commitish=None):
    """Context manager that creates a temporary work tree and chdirs into it. The
    worktree is deleted when the contex manager is closed. Taken from gj_tools."""
    dfn = None
    try:
        with tempfile.TemporaryDirectory() as dfn:
            gitargs = ['worktree', 'add', '--detach', '--no-checkout', dfn]
            if commitish:
                gitargs.append(commitish)
            git_run_command(gitdir, gitargs)
            with in_directory(dfn):
                yield dfn
    finally:
        if dfn is not None:
            git_run_command(gitdir, ['worktree', 'remove', '--force', dfn])


@contextmanager
def git_temp_clone(gitdir=None):
    """Context manager that creates a temporary shared clone."""
    if gitdir is None:
        topdir = git_get_toplevel()
        if topdir and os.path.isdir(os.path.join(topdir, '.git')):
            gitdir = os.path.join(topdir, '.git')

    if not gitdir:
        logger.critical('Current directory is not a git checkout. Try using -g.')
        return None

    with tempfile.TemporaryDirectory() as dfn:
        gitargs = ['clone', '--mirror', '--shared', gitdir, dfn]
        git_run_command(None, gitargs)
        yield dfn


@contextmanager
def in_directory(dirname):
    """Context manager that chdirs into a directory and restores the original
    directory when closed. Taken from gj_tools."""
    cdir = os.getcwd()
    try:
        os.chdir(dirname)
        yield True
    finally:
        os.chdir(cdir)


def git_set_config(fullpath: Optional[str], param: str, value: str, operation: str = '--replace-all'):
    args = ['config', operation, param, value]
    ecode, out = git_run_command(fullpath, args)
    return ecode


def get_config_from_git(regexp: str, defaults: Optional[dict] = None,
                        multivals: Optional[list] = None, source: Optional[str] = None) -> dict:
    if multivals is None:
        multivals = list()
    args = ['config']
    if source:
        args += ['--file', source]
    args += ['-z', '--get-regexp', regexp]
    ecode, out = git_run_command(None, args)
    gitconfig = defaults
    if not gitconfig:
        gitconfig = dict()
    if not out:
        return gitconfig

    for line in out.split('\x00'):
        if not line:
            continue
        key, value = line.split('\n', 1)
        try:
            chunks = key.split('.')
            cfgkey = chunks[-1].lower()
            if cfgkey in multivals:
                if cfgkey not in gitconfig:
                    gitconfig[cfgkey] = list()
                gitconfig[cfgkey].append(value)
            else:
                gitconfig[cfgkey] = value
        except ValueError:
            logger.debug('Ignoring git config entry %s', line)

    return gitconfig


def get_main_config() -> dict:
    global MAIN_CONFIG
    if MAIN_CONFIG is None:
        defcfg = copy.deepcopy(DEFAULT_CONFIG)
        # some options can be provided via the toplevel .b4-config file,
        # so load them up and use as defaults
        topdir = git_get_toplevel()
        wtglobs = ['send-*', '*mask', '*template*', 'trailer*', 'pw-*']
        if topdir:
            wtcfg = os.path.join(topdir, '.b4-config')
            if os.access(wtcfg, os.R_OK):
                logger.debug('Loading worktree configs from %s', wtcfg)
                wtconfig = get_config_from_git(r'b4\..*', source=wtcfg)
                logger.debug('wtcfg=%s', wtconfig)
                for key, val in wtconfig.items():
                    if val.startswith('./'):
                        # replace it with full topdir path
                        val = os.path.abspath(os.path.join(topdir, val))
                    for wtglob in wtglobs:
                        if fnmatch.fnmatch(key, wtglob):
                            logger.debug('wtcfg: %s=%s', key, val)
                            defcfg[key] = val
                            break
        config = get_config_from_git(r'b4\..*', defaults=defcfg, multivals=['keyringsrc'])
        config['listid-preference'] = config['listid-preference'].split(',')
        config['listid-preference'].remove('*')
        config['listid-preference'].append('*')
        if config['gpgbin'] is None:
            gpgcfg = get_config_from_git(r'gpg\..*', {'program': 'gpg'})
            config['gpgbin'] = gpgcfg['program']

        MAIN_CONFIG = config

    return MAIN_CONFIG


def get_data_dir(appname: str = 'b4') -> str:
    if 'XDG_DATA_HOME' in os.environ:
        datahome = os.environ['XDG_DATA_HOME']
    else:
        datahome = os.path.join(str(pathlib.Path.home()), '.local', 'share')
    datadir = os.path.join(datahome, appname)
    pathlib.Path(datadir).mkdir(parents=True, exist_ok=True)
    return datadir


def get_cache_dir(appname: str = 'b4') -> str:
    global _CACHE_CLEANED
    if 'XDG_CACHE_HOME' in os.environ:
        cachehome = os.environ['XDG_CACHE_HOME']
    else:
        cachehome = os.path.join(str(pathlib.Path.home()), '.cache')
    cachedir = os.path.join(cachehome, appname)
    pathlib.Path(cachedir).mkdir(parents=True, exist_ok=True)
    if _CACHE_CLEANED:
        return cachedir

    # Delete all .mbx and .lookup files older than cache-expire
    config = get_main_config()
    try:
        expmin = int(config['cache-expire']) * 60
    except ValueError:
        logger.critical('ERROR: cache-expire must be an integer (minutes): %s', config['cache-expire'])
        expmin = 600
    expage = time.time() - expmin
    for entry in os.listdir(cachedir):
        if entry.find('.mbx') <= 0 and entry.find('.lookup') <= 0 and entry.find('.msgs') <= 0:
            continue
        fullpath = os.path.join(cachedir, entry)
        st = os.stat(fullpath)
        if st.st_mtime < expage:
            logger.debug('Cleaning up cache: %s', entry)
            if os.path.isdir(fullpath):
                shutil.rmtree(fullpath)
            else:
                os.unlink(os.path.join(cachedir, entry))
    _CACHE_CLEANED = True
    return cachedir


def get_cache_file(identifier: str, suffix: Optional[str] = None):
    cachedir = get_cache_dir()
    cachefile = hashlib.sha1(identifier.encode()).hexdigest()
    if suffix:
        cachefile = f'{cachefile}.{suffix}'
    return os.path.join(cachedir, cachefile)


def get_cache(identifier: str, suffix: Optional[str] = None) -> Optional[str]:
    fullpath = get_cache_file(identifier, suffix=suffix)
    try:
        with open(fullpath) as fh:
            logger.debug('Using cache %s for %s', fullpath, identifier)
            return fh.read()
    except FileNotFoundError:
        logger.debug('Cache miss for %s', identifier)
    return None


def clear_cache(identifier: str, suffix: Optional[str] = None) -> None:
    fullpath = get_cache_file(identifier, suffix=suffix)
    if os.path.exists(fullpath):
        os.unlink(fullpath)
        logger.debug('Removed cache %s for %s', fullpath, identifier)


def save_cache(contents: str, identifier: str, suffix: Optional[str] = None, mode: str = 'w') -> None:
    fullpath = get_cache_file(identifier, suffix=suffix)
    try:
        with open(fullpath, mode) as fh:
            fh.write(contents)
            logger.debug('Saved cache %s for %s', fullpath, identifier)
    except FileNotFoundError:
        logger.debug('Could not write cache %s for %s', fullpath, identifier)


def get_user_config():
    global USER_CONFIG
    if USER_CONFIG is None:
        USER_CONFIG = get_config_from_git(r'user\..*')
        if 'name' not in USER_CONFIG:
            udata = pwd.getpwuid(os.getuid())
            USER_CONFIG['name'] = udata.pw_gecos
    return USER_CONFIG


def get_requests_session():
    global REQSESSION
    if REQSESSION is None:
        REQSESSION = requests.session()
        REQSESSION.headers.update({'User-Agent': 'b4/%s' % __VERSION__})
    return REQSESSION


def get_msgid_from_stdin() -> Optional[str]:
    if not sys.stdin.isatty():
        from email.parser import BytesParser
        message = BytesParser().parsebytes(
            sys.stdin.buffer.read(), headersonly=True)
        return message.get('Message-ID', None)
    return None


def get_msgid(cmdargs: argparse.Namespace) -> Optional[str]:
    if not cmdargs.msgid and not cmdargs.no_stdin:
        logger.debug('Getting Message-ID from stdin')
        msgid = get_msgid_from_stdin()
    else:
        msgid = cmdargs.msgid

    if msgid is None:
        return None

    msgid = msgid.strip('<>')
    # Handle the case when someone pastes a full URL to the message
    # Is this a patchwork URL?
    matches = re.search(r'^https?://.*/project/.*/patch/([^/]+@[^/]+)', msgid, re.IGNORECASE)
    if matches:
        logger.debug('Looks like a patchwork URL')
        chunks = matches.groups()
        msgid = urllib.parse.unquote(chunks[0])
        return msgid

    # Does it look like a public-inbox URL?
    matches = re.search(r'^https?://[^/]+/([^/]+)/([^/]+@[^/]+)', msgid, re.IGNORECASE)
    if matches:
        chunks = matches.groups()
        config = get_main_config()
        myloc = urllib.parse.urlparse(config['midmask'])
        wantloc = urllib.parse.urlparse(msgid)
        if myloc.netloc != wantloc.netloc:
            logger.debug('Overriding midmask with passed url parameters')
            config['midmask'] = f'{wantloc.scheme}://{wantloc.netloc}/{chunks[0]}/%s'
        msgid = urllib.parse.unquote(chunks[1])
    # Handle special case when msgid is prepended by id: or rfc822msgid:
    if msgid.find('id:') >= 0:
        msgid = re.sub(r'^\w*id:', '', msgid)

    return msgid


def get_strict_thread(msgs, msgid, noparent=False):
    want = {msgid}
    ignore = set()
    got = set()
    seen = set()
    maybe = dict()
    strict = list()
    while True:
        for msg in msgs:
            c_msgid = LoreMessage.get_clean_msgid(msg)
            if c_msgid in ignore:
                continue
            seen.add(c_msgid)
            if c_msgid in got:
                continue
            logger.debug('Looking at: %s', c_msgid)

            refs = set()
            msgrefs = list()
            if msg.get('In-Reply-To', None):
                msgrefs += email.utils.getaddresses([str(x) for x in msg.get_all('in-reply-to', [])])
            if msg.get('References', None):
                msgrefs += email.utils.getaddresses([str(x) for x in msg.get_all('references', [])])
            # If noparent is set, we pretend the message we got passed has no references, and add all
            # parent references of this message to ignore
            if noparent and msgid == c_msgid:
                logger.info('Breaking thread to remove parents of %s', msgid)
                ignore = set([x[1] for x in msgrefs])
                msgrefs = list()

            for ref in set([x[1] for x in msgrefs]):
                if ref in ignore:
                    continue
                if ref in got or ref in want:
                    want.add(c_msgid)
                elif len(ref):
                    refs.add(ref)
                    if c_msgid not in want:
                        if ref not in maybe:
                            maybe[ref] = set()
                        logger.debug('Going into maybe: %s->%s', ref, c_msgid)
                        maybe[ref].add(c_msgid)

            if c_msgid in want:
                strict.append(msg)
                got.add(c_msgid)
                want.update(refs)
                want.discard(c_msgid)
                logger.debug('Kept in thread: %s', c_msgid)
                if c_msgid in maybe:
                    # Add all these to want
                    want.update(maybe[c_msgid])
                    maybe.pop(c_msgid)
                # Add all maybes that have the same ref into want
                for ref in refs:
                    if ref in maybe:
                        want.update(maybe[ref])
                        maybe.pop(ref)

        # Remove any entries not in "seen" (missing messages)
        for c_msgid in set(want):
            if c_msgid not in seen or c_msgid in got:
                want.remove(c_msgid)
        if not len(want):
            break

    if not len(strict):
        return None

    if len(msgs) > len(strict):
        logger.debug('Reduced thread to requested matches only (%s->%s)', len(msgs), len(strict))

    return strict


def mailsplit_bytes(bmbox: bytes, outdir: str, pipesep: Optional[str] = None) -> List[email.message.Message]:
    msgs = list()
    if pipesep:
        logger.debug('Mailsplitting using pipesep=%s', pipesep)
        if '\\' in pipesep:
            import codecs
            pipesep = codecs.decode(pipesep.encode(), 'unicode_escape')
        for chunk in bmbox.split(pipesep.encode()):
            if chunk.strip():
                msgs.append(email.message_from_bytes(chunk, policy=emlpolicy))
        return msgs

    logger.debug('Mailsplitting the mbox into %s', outdir)
    args = ['mailsplit', '--mboxrd', '-o%s' % outdir]
    ecode, out = git_run_command(None, args, stdin=bmbox)
    if ecode > 0:
        logger.critical('Unable to parse mbox received from the server')
        return msgs
    # Read in the files
    for msg in os.listdir(outdir):
        with open(os.path.join(outdir, msg), 'rb') as fh:
            msgs.append(email.message_from_binary_file(fh, policy=emlpolicy))
    return msgs


def get_pi_search_results(query: str, nocache: bool = False) -> Optional[List[email.message.Message]]:
    config = get_main_config()
    searchmask = config.get('searchmask')
    if not searchmask:
        logger.critical('b4.searchmask is not defined')
        return None
    msgs = list()
    query = urllib.parse.quote_plus(query)
    query_url = searchmask % query
    cachedir = get_cache_file(query_url, 'pi.msgs')
    if os.path.exists(cachedir) and not nocache:
        logger.debug('Using cached copy: %s', cachedir)
        for msg in os.listdir(cachedir):
            with open(os.path.join(cachedir, msg), 'rb') as fh:
                msgs.append(email.message_from_binary_file(fh, policy=emlpolicy))
                return msgs

    loc = urllib.parse.urlparse(query_url)
    logger.info('Grabbing search results from %s', loc.netloc)
    session = get_requests_session()
    # For the query to retrieve a mbox file, we need to send a POST request
    resp = session.post(query_url, data='')
    if resp.status_code == 404:
        logger.info('Nothing matching that query.')
        return None
    if resp.status_code != 200:
        logger.info('Server returned an error: %s', resp.status_code)
        return None
    t_mbox = gzip.decompress(resp.content)
    resp.close()
    if not len(t_mbox):
        logger.critical('No messages found for that query')
        return None

    return split_and_dedupe_pi_results(t_mbox, cachedir=cachedir)


def split_and_dedupe_pi_results(t_mbox: bytes, cachedir: Optional[str] = None) -> List[email.message.Message]:
    # Convert into individual files using git-mailsplit
    with tempfile.TemporaryDirectory(suffix='-mailsplit') as tfd:
        msgs = mailsplit_bytes(t_mbox, tfd)

    deduped = dict()

    for msg in msgs:
        msgid = LoreMessage.get_clean_msgid(msg)
        if msgid in deduped:
            deduped[msgid] = LoreMessage.get_preferred_duplicate(deduped[msgid], msg)
            continue
        deduped[msgid] = msg

    msgs = list(deduped.values())
    if cachedir:
        if os.path.exists(cachedir):
            shutil.rmtree(cachedir)
        pathlib.Path(cachedir).mkdir(parents=True, exist_ok=True)
        for at, msg in enumerate(msgs):
            with open(os.path.join(cachedir, '%04d' % at), 'wb') as fh:
                fh.write(msg.as_bytes(policy=emlpolicy))

    return msgs


def get_pi_thread_by_url(t_mbx_url: str, nocache: bool = False):
    msgs = list()
    cachedir = get_cache_file(t_mbx_url, 'pi.msgs')
    if os.path.exists(cachedir) and not nocache:
        logger.debug('Using cached copy: %s', cachedir)
        for msg in os.listdir(cachedir):
            with open(os.path.join(cachedir, msg), 'rb') as fh:
                msgs.append(email.message_from_binary_file(fh, policy=emlpolicy))
        return msgs

    logger.critical('Grabbing thread from %s', t_mbx_url.split('://')[1])
    session = get_requests_session()
    resp = session.get(t_mbx_url)
    if resp.status_code == 404:
        logger.critical('That message-id is not known.')
        return None
    if resp.status_code != 200:
        logger.critical('Server returned an error: %s', resp.status_code)
        return None
    t_mbox = gzip.decompress(resp.content)
    resp.close()
    if not len(t_mbox):
        logger.critical('No messages found for that query')
        return None

    return split_and_dedupe_pi_results(t_mbox, cachedir=cachedir)


def get_pi_thread_by_msgid(msgid: str, nocache: bool = False,
                           onlymsgids: Optional[set] = None) -> Optional[list]:
    qmsgid = urllib.parse.quote_plus(msgid)
    config = get_main_config()
    loc = urllib.parse.urlparse(config['midmask'])
    # The public-inbox instance may provide a unified index at /all/.
    # In fact, /all/ naming is arbitrary, but for now we are going to
    # hardcode it to lore.kernel.org settings and maybe make it configurable
    # in the future, if necessary.
    if loc.path.startswith('/all/'):
        projurl = '%s://%s/all' % (loc.scheme, loc.netloc)
    else:
        # Grab the head from lore, to see where we are redirected
        midmask = config['midmask'] % qmsgid
        logger.info('Looking up %s', midmask)
        session = get_requests_session()
        resp = session.head(midmask)
        if resp.status_code < 300 or resp.status_code > 400:
            logger.critical('That message-id is not known.')
            return None
        # Pop msgid from the end of the redirect
        chunks = resp.headers['Location'].rstrip('/').split('/')
        projurl = '/'.join(chunks[:-1])
        resp.close()
    t_mbx_url = '%s/%s/t.mbox.gz' % (projurl, qmsgid)
    logger.debug('t_mbx_url=%s', t_mbx_url)

    msgs = get_pi_thread_by_url(t_mbx_url, nocache=nocache)
    if not msgs:
        return None

    if onlymsgids:
        strict = list()
        for msg in msgs:
            if LoreMessage.get_clean_msgid(msg) in onlymsgids:
                strict.append(msg)
            # also grab any messages where this msgid is in the references header
            for onlymsgid in onlymsgids:
                if msg.get('references', '').find(onlymsgid) >= 0:
                    strict.append(msg)
    else:
        strict = get_strict_thread(msgs, msgid)

    return strict


def git_range_to_patches(gitdir: Optional[str], start: str, end: str,
                         prefixes: Optional[List[str]] = None,
                         revision: Optional[int] = 1,
                         msgid_tpt: Optional[str] = None,
                         seriests: Optional[int] = None,
                         mailfrom: Optional[Tuple[str, str]] = None,
                         extrahdrs: Optional[List[Tuple[str, str]]] = None,
                         ignore_commits: Optional[Set[str]] = None) -> List[Tuple[str, email.message.Message]]:
    commits = git_get_command_lines(gitdir, ['rev-list', '--reverse', f'{start}..{end}'])
    if not commits:
        raise RuntimeError(f'Could not run rev-list {start}..{end}')
    if ignore_commits is None:
        ignore_commits = set()

    # Go through them once to drop ignored commits and get bodies
    patches = list()
    for commit in commits:
        if commit in ignore_commits:
            logger.debug('Ignoring commit %s', commit)
            continue
        ecode, out = git_run_command(gitdir, ['show', '--format=email', '--patch-with-stat', '--encoding=utf-8',
                                              commit], decode=False)
        if ecode > 0:
            raise RuntimeError(f'Could not get a patch out of {commit}')
        msg = email.message_from_bytes(out, policy=emlpolicy)
        patches.append((commit, msg))

    fullcount = len(patches)
    if fullcount == 0:
        raise RuntimeError(f'Could not run rev-list {start}..{end}')

    vlines = git_get_command_lines(None, ['--version'])
    if len(vlines) == 1:
        gitver = vlines[0].split()[-1]
    else:
        gitver = None

    expected = len(patches)
    for counter, (commit, msg) in enumerate(patches):
        msg.set_charset('utf-8')
        # Clean From to remove any 7bit-safe encoding
        origfrom = LoreMessage.clean_header(msg.get('From'))
        lsubject = LoreSubject(msg.get('Subject'))
        lsubject.counter = counter + 1
        lsubject.expected = expected
        lsubject.revision = revision
        subject = lsubject.get_rebuilt_subject(eprefixes=prefixes)

        logger.debug('  %s', subject)
        msg.replace_header('Subject', subject)

        inbodyhdrs = list()
        setfrom = origfrom
        if mailfrom:
            # Move the original From and Date into the body
            origpair = email.utils.parseaddr(origfrom)
            if origpair[1] != mailfrom[1]:
                setfrom = format_addrs([mailfrom])
                inbodyhdrs.append(f'From: {origfrom}')
        msg.replace_header('From', setfrom)

        if seriests:
            patchts = seriests + counter + 1
            origdate = msg.get('Date')
            if origdate:
                msg.replace_header('Date', email.utils.formatdate(patchts, localtime=True))
            else:
                msg.add_header('Date', email.utils.formatdate(patchts, localtime=True))

        payload = msg.get_payload(decode=True)
        if isinstance(payload, bytes):
            payload = payload.decode()
            if inbodyhdrs:
                payload = '\n'.join(inbodyhdrs) + '\n\n' + payload
            if gitver and not payload.find('\n-- \n') > 0:
                payload += f'\n-- \n{gitver}\n'
            msg.set_payload(payload, charset='utf-8')

        if extrahdrs is None:
            extrahdrs = list()
        for hdrname, hdrval in extrahdrs:
            try:
                msg.replace_header(hdrname, hdrval)
            except KeyError:
                msg.add_header(hdrname, hdrval)

        if msgid_tpt:
            msg.add_header('Message-Id', msgid_tpt % str(lsubject.counter))

    return patches


def git_commit_exists(gitdir, commit_id):
    gitargs = ['cat-file', '-e', commit_id]
    ecode, out = git_run_command(gitdir, gitargs)
    return ecode == 0


def git_branch_contains(gitdir, commit_id):
    gitargs = ['branch', '--format=%(refname:short)', '--contains', commit_id]
    lines = git_get_command_lines(gitdir, gitargs)
    return lines


def git_get_toplevel(path: Optional[str] = None) -> Optional[str]:
    topdir = None
    # Are we in a git tree and if so, what is our toplevel?
    gitargs = ['rev-parse', '--show-toplevel']
    lines = git_get_command_lines(path, gitargs)
    if len(lines) == 1:
        topdir = lines[0]
    return topdir


def format_addrs(pairs, clean=True):
    addrs = list()
    for pair in pairs:
        if pair[0] == pair[1]:
            addrs.append(pair[1])
            continue
        if clean:
            # Remove any quoted-printable header junk from the name
            pair = (LoreMessage.clean_header(pair[0]), pair[1])
        # Work around https://github.com/python/cpython/issues/100900
        if not pair[0].startswith('=?') and not pair[0].startswith('"') and qspecials.search(pair[0]):
            quoted = email.utils.quote(pair[0])
            addrs.append(f'"{quoted}" <{pair[1]}>')
            continue
        addrs.append(email.utils.formataddr(pair))
    return ', '.join(addrs)


def make_quote(body, maxlines=5):
    headers, message, trailers, basement, signature = LoreMessage.get_body_parts(body)
    if not len(message):
        # Sometimes there is no message, just trailers
        return '> \n'
    # Remove common greetings
    message = re.sub(r'^(hi|hello|greetings|dear)\W.*\n+', '', message, flags=re.I)
    quotelines = list()
    qcount = 0
    for line in message.split('\n'):
        # Quote the first paragraph only and then [snip] if we quoted more than maxlines
        if qcount > maxlines and not len(line.strip()):
            quotelines.append('> ')
            quotelines.append('> [...]')
            break
        quotelines.append('> %s' % line.rstrip())
        qcount += 1
    return '\n'.join(quotelines)


def parse_int_range(intrange, upper=None):
    # Remove all whitespace
    intrange = re.sub(r'\s', '', intrange)
    for n in intrange.split(','):
        if n.isdigit():
            yield int(n)
        elif n.find('<') == 0 and len(n) > 1 and n[1:].isdigit():
            yield from range(1, int(n[1:]))
        elif n.find('-') > 0:
            nr = n.split('-')
            if nr[0].isdigit() and nr[1].isdigit():
                yield from range(int(nr[0]), int(nr[1])+1)
            elif not len(nr[1]) and nr[0].isdigit() and upper:
                yield from range(int(nr[0]), upper+1)
        else:
            logger.critical('Unknown range value specified: %s', n)


def check_gpg_status(status: str) -> Tuple[bool, bool, bool, Optional[str], Optional[str]]:
    good = False
    valid = False
    trusted = False
    keyid = None
    signtime = None

    # Do we have a BADSIG?
    bs_matches = re.search(r'^\[GNUPG:] BADSIG ([\dA-F]+)\s+(.*)$', status, flags=re.M)
    if bs_matches:
        keyid = bs_matches.groups()[0]
        return good, valid, trusted, keyid, signtime

    gs_matches = re.search(r'^\[GNUPG:] GOODSIG ([\dA-F]+)\s+(.*)$', status, flags=re.M)
    if gs_matches:
        good = True
        keyid = gs_matches.groups()[0]
    vs_matches = re.search(r'^\[GNUPG:] VALIDSIG ([\dA-F]+) (\d{4}-\d{2}-\d{2}) (\d+)', status, flags=re.M)
    if vs_matches:
        valid = True
        signtime = vs_matches.groups()[2]
    ts_matches = re.search(r'^\[GNUPG:] TRUST_(FULLY|ULTIMATE)', status, flags=re.M)
    if ts_matches:
        trusted = True

    return good, valid, trusted, keyid, signtime


def get_gpg_uids(keyid: str) -> list:
    gpgargs = ['--with-colons', '--list-keys', keyid]
    ecode, out, err = gpg_run_command(gpgargs)
    if ecode > 0:
        raise KeyError('Unable to get UIDs list matching key %s' % keyid)

    keyinfo = out.decode()
    uids = list()
    for line in keyinfo.split('\n'):
        if line[:4] != 'uid:':
            continue
        chunks = line.split(':')
        if chunks[1] in ('r',):
            # Revoked UID, ignore
            continue
        uids.append(chunks[9])

    return uids


def save_git_am_mbox(msgs: list[email.message.Message], dest: BinaryIO):
    # Git-am has its own understanding of what "mbox" format is that differs from Python's
    # mboxo implementation. Specifically, it never escapes the ">From " lines found in bodies
    # unless invoked with --patch-format=mboxrd (this is wrong, because ">From " escapes are also
    # required in the original mbox "mboxo" format).
    # So, save in the format that git-am expects
    for msg in msgs:
        dest.write(b'From git@z Thu Jan  1 00:00:00 1970\n')
        dest.write(LoreMessage.get_msg_as_bytes(msg, headers='decode'))


def save_mboxrd_mbox(msgs: list[email.message.Message], dest: BinaryIO, mangle_from: bool = False):
    gen = email.generator.BytesGenerator(dest, mangle_from_=mangle_from, policy=emlpolicy)
    for msg in msgs:
        dest.write(b'From mboxrd@z Thu Jan  1 00:00:00 1970\n')
        gen.flatten(msg)


def save_maildir(msgs: list, dest):
    d_new = os.path.join(dest, 'new')
    pathlib.Path(d_new).mkdir(parents=True)
    d_cur = os.path.join(dest, 'cur')
    pathlib.Path(d_cur).mkdir(parents=True)
    d_tmp = os.path.join(dest, 'tmp')
    pathlib.Path(d_tmp).mkdir(parents=True)
    for msg in msgs:
        # make a slug out of it
        lsubj = LoreSubject(msg.get('subject', ''))
        slug = '%04d_%s' % (lsubj.counter, re.sub(r'\W+', '_', lsubj.subject).strip('_').lower())
        with open(os.path.join(d_tmp, f'{slug}.eml'), 'wb') as mfh:
            mfh.write(LoreMessage.get_msg_as_bytes(msg, headers='decode'))
        os.rename(os.path.join(d_tmp, f'{slug}.eml'), os.path.join(d_new, f'{slug}.eml'))


def get_mailinfo(bmsg: bytes, scissors: bool = False) -> Tuple[dict, bytes, bytes]:
    with tempfile.TemporaryDirectory() as tfd:
        m_out = os.path.join(tfd, 'm')
        p_out = os.path.join(tfd, 'p')
        if scissors:
            cmdargs = ['mailinfo', '--encoding=UTF-8', '--scissors', m_out, p_out]
        else:
            cmdargs = ['mailinfo', '--encoding=UTF-8', '--no-scissors', m_out, p_out]

        ecode, info = git_run_command(None, cmdargs, bmsg)
        if not len(info.strip()):
            raise ValueError('Could not get mailinfo')

        i = dict()
        m = b''
        p = b''
        for line in info.split('\n'):
            line = line.strip()
            if not line:
                continue
            chunks = line.split(':',  1)
            i[chunks[0]] = chunks[1].strip()

            with open(m_out, 'rb') as mfh:
                m = mfh.read()
            with open(p_out, 'rb') as pfh:
                p = pfh.read()
    return i, m, p


def read_template(tptfile):
    # bubbles up FileNotFound
    tpt = ''
    if tptfile.find('~') >= 0:
        tptfile = os.path.expanduser(tptfile)
    if tptfile.find('$') >= 0:
        tptfile = os.path.expandvars(tptfile)
    with open(tptfile, 'r', encoding='utf-8') as fh:
        for line in fh:
            if len(line) and line[0] == '#':
                continue
            tpt += line
    return tpt


def get_sendemail_config() -> dict:
    global SENDEMAIL_CONFIG
    if SENDEMAIL_CONFIG is None:
        # Get the default settings first
        config = get_main_config()
        identity = config.get('sendemail-identity')
        _basecfg = get_config_from_git(r'sendemail\.[^.]+$')
        if identity:
            # Use this identity to override what we got from the default one
            sconfig = get_config_from_git(rf'sendemail\.{identity}\..*', defaults=_basecfg)
            sectname = f'sendemail.{identity}'
            if not len(sconfig):
                raise smtplib.SMTPException('Unable to find %s settings in any applicable git config' % sectname)
        else:
            sconfig = _basecfg
            sectname = 'sendemail'
        logger.debug('Using values from %s', sectname)
        SENDEMAIL_CONFIG = sconfig

    return SENDEMAIL_CONFIG


def get_smtp(dryrun: bool = False) -> Tuple[Union[smtplib.SMTP, smtplib.SMTP_SSL, list, None], str]:
    sconfig = get_sendemail_config()
    # Limited support for smtp settings to begin with, but should cover the vast majority of cases
    fromaddr = sconfig.get('from')
    if not fromaddr:
        # We fall back to user.email
        usercfg = get_user_config()
        fromaddr = usercfg['email']

    server = sconfig.get('smtpserver', 'localhost')
    port = sconfig.get('smtpserverport', 0)
    try:
        port = int(port)
    except ValueError:
        raise smtplib.SMTPException('Invalid smtpport entry in config')

    # If server contains slashes, then it's a local command
    if '/' in server:
        server = os.path.expanduser(os.path.expandvars(server))
        sp = shlex.shlex(server, posix=True)
        sp.whitespace_split = True
        smtp = list(sp)
        if '-i' not in smtp:
            smtp.append('-i')
        # Do we have the envelopesender defined?
        env_sender = sconfig.get('envelopesender', '')
        if env_sender:
            envpair = email.utils.parseaddr(env_sender)
        else:
            envpair = email.utils.parseaddr(fromaddr)
        if envpair[1]:
            smtp += ['-f', envpair[1]]
        return smtp, fromaddr

    encryption = sconfig.get('smtpencryption')
    if dryrun:
        return None, fromaddr

    logger.info('Connecting to %s:%s', server, port)
    # We only authenticate if we have encryption
    if encryption:
        if encryption in ('tls', 'starttls'):
            # We do startssl
            smtp = smtplib.SMTP(server, port)
            # Introduce ourselves
            smtp.ehlo()
            # Start encryption
            smtp.starttls()
            # Introduce ourselves again to get new criteria
            smtp.ehlo()
        elif encryption in ('ssl', 'smtps'):
            # We do TLS from the get-go
            smtp = smtplib.SMTP_SSL(server, port)
        else:
            raise smtplib.SMTPException('Unclear what to do with smtpencryption=%s' % encryption)

        # If we got to this point, we should do authentication.
        auser = sconfig.get('smtpuser')
        apass = sconfig.get('smtppass')
        if auser and not apass:
            # Try with git-credential-helper
            if port:
                gchost = f'{server}:{port}'
            else:
                gchost = server
            apass = git_credential_fill(None, protocol='smtp', host=gchost, username=auser)
            if not apass:
                raise smtplib.SMTPException('No password specified for connecting to %s', server)
        if auser and apass:
            # Let any exceptions bubble up
            smtp.login(auser, apass)
    else:
        # We assume you know what you're doing if you don't need encryption
        smtp = smtplib.SMTP(server, port)

    return smtp, fromaddr


def get_patchwork_session(pwkey: str, pwurl: str) -> Tuple[requests.Session, str]:
    session = requests.session()
    session.headers.update({
        'User-Agent': 'b4/%s' % __VERSION__,
        'Authorization': f'Token {pwkey}',
    })
    url = '/'.join((pwurl.rstrip('/'), 'api', PW_REST_API_VERSION))
    logger.debug('pw url=%s', url)
    return session, url


def patchwork_set_state(msgids: List[str], state: str) -> bool:
    # Do we have a pw-key defined in config?
    config = get_main_config()
    pwkey = config.get('pw-key')
    pwurl = config.get('pw-url')
    pwproj = config.get('pw-project')
    if not (pwkey and pwurl and pwproj):
        logger.debug('Patchwork support requires pw-key, pw-url and pw-project settings')
        return False
    pses, url = get_patchwork_session(pwkey, pwurl)
    patches_url = '/'.join((url, 'patches'))
    tochange = list()
    seen = set()
    for msgid in msgids:
        if msgid in seen:
            continue
        # Two calls, first to look up the patch-id, second to update its state
        params = [
            ('project', pwproj),
            ('archived', 'false'),
            ('msgid', msgid),
        ]
        try:
            logger.debug('looking up patch_id of msgid=%s', msgid)
            rsp = pses.get(patches_url, params=params, stream=False)
            rsp.raise_for_status()
            pdata = rsp.json()
            for entry in pdata:
                patch_id = entry.get('id')
                if patch_id:
                    title = entry.get('name')
                    if entry.get('state') != state:
                        seen.add(msgid)
                        tochange.append((patch_id, title))
        except requests.exceptions.RequestException as ex:
            logger.debug('Patchwork REST error: %s', ex)

    if tochange:
        logger.info('---')
        loc = urllib.parse.urlparse(pwurl)
        logger.info('Patchwork: setting state on %s/%s', loc.netloc, pwproj)
        for patch_id, title in tochange:
            patchid_url = '/'.join((patches_url, str(patch_id), ''))
            logger.debug('patchid_url=%s', patchid_url)
            data = [
                ('state', state),
            ]
            try:
                rsp = pses.patch(patchid_url, data=data, stream=False)
                rsp.raise_for_status()
                newdata = rsp.json()
                if newdata.get('state') == state:
                    logger.info(' -> %s : %s', state, title)
            except requests.exceptions.RequestException as ex:
                logger.debug('Patchwork REST error: %s', ex)


def send_mail(smtp: Union[smtplib.SMTP, smtplib.SMTP_SSL, None], msgs: Sequence[email.message.Message],
              fromaddr: Optional[str], destaddrs: Optional[Union[set, list]] = None,
              patatt_sign: bool = False, dryrun: bool = False,
              output_dir: Optional[str] = None, web_endpoint: Optional[str] = None,
              reflect: bool = False) -> Optional[int]:

    tosend = list()
    if output_dir is not None:
        dryrun = True

    for msg in msgs:
        if not msg.get('X-Mailer'):
            msg.add_header('X-Mailer', f'b4 {__VERSION__}')
        msg.set_charset('utf-8')

        if dryrun or web_endpoint:
            nl = '\n'
        else:
            nl = '\r\n'

        bdata = LoreMessage.get_msg_as_bytes(msg, nl=nl, headers='encode')

        subject = msg.get('Subject', '')
        ls = LoreSubject(subject)
        if patatt_sign:
            import patatt
            # patatt.logger = logger
            try:
                bdata = patatt.rfc2822_sign(bdata)
            except patatt.NoKeyError as ex:
                logger.critical('CRITICAL: Error signing: no key configured')
                logger.critical('          Run "patatt genkey" or configure "user.signingKey" to use PGP')
                logger.critical('          As a last resort, rerun with --no-sign')
                raise RuntimeError(str(ex))
            except patatt.SigningError as ex:
                raise RuntimeError('Failure trying to patatt-sign: %s' % str(ex))
        if dryrun:
            if output_dir:
                filen = '%s.eml' % ls.get_slug(sep='-')
                logger.info('  %s', filen)
                write_to = os.path.join(output_dir, filen)
                with open(write_to, 'wb') as fh:
                    fh.write(bdata)
                continue
            logger.info('    --- DRYRUN: message follows ---')
            logger.info('    | ' + bdata.decode().rstrip().replace('\n', '\n    | '))
            logger.info('    --- DRYRUN: message ends ---')
            continue
        if not destaddrs:
            alldests = email.utils.getaddresses([str(x) for x in msg.get_all('to', [])])
            alldests += email.utils.getaddresses([str(x) for x in msg.get_all('cc', [])])
            myaddrs = {x[1] for x in alldests}
        else:
            myaddrs = destaddrs

        tosend.append((myaddrs, bdata, ls))

    if not len(tosend):
        return 0

    logger.info('---')
    if web_endpoint:
        if reflect:
            logger.info('Reflecting via web endpoint %s', web_endpoint)
            wpaction = 'reflect'
        else:
            logger.info('Sending via web endpoint %s', web_endpoint)
            wpaction = 'receive'
        req = {
            'action': wpaction,
            'messages': [x[1].decode() for x in tosend],
        }
        ses = get_requests_session()
        res = ses.post(web_endpoint, json=req)
        try:
            rdata = res.json()
            if rdata.get('result') == 'success':
                return len(tosend)
        except Exception as ex:  # noqa
            logger.critical('Odd response from the endpoint: %s', res.text)
            return 0

        if rdata.get('result') == 'error':
            logger.critical('Error from endpoint: %s', rdata.get('message'))
            return 0

    sent = 0
    envpair = email.utils.parseaddr(fromaddr)
    if isinstance(smtp, list):
        # This is a local command
        if reflect:
            logger.info('Reflecting via "%s"', ' '.join(smtp))
        else:
            logger.info('Sending via "%s"', ' '.join(smtp))
        for destaddrs, bdata, lsubject in tosend:
            logger.info('  %s', lsubject.full_subject)
            if reflect:
                cmdargs = list(smtp) + [envpair[1]]
            else:
                cmdargs = list(smtp) + list(destaddrs)
            ecode, out, err = _run_command(cmdargs, stdin=bdata)
            if ecode > 0:
                raise RuntimeError('Error running %s: %s' % (' '.join(smtp), err.decode()))
            sent += 1

    elif smtp:
        for destaddrs, bdata, lsubject in tosend:
            # Force compliant eols
            bdata = re.sub(rb'\r\n|\n|\r(?!\n)', b'\r\n', bdata)
            logger.info('  %s', lsubject.full_subject)
            if reflect:
                smtp.sendmail(fromaddr, [envpair[1]], bdata)
            else:
                smtp.sendmail(fromaddr, destaddrs, bdata)
            sent += 1

    return sent


def git_get_current_branch(gitdir: Optional[str] = None, short: bool = True) -> Optional[str]:
    gitargs = ['symbolic-ref', '-q', 'HEAD']
    ecode, out = git_run_command(gitdir, gitargs)
    if ecode > 0:
        logger.critical('Not able to get current branch (git symbolic-ref HEAD)')
        return None
    mybranch = out.strip()
    if short:
        return re.sub(r'^refs/heads/', '', mybranch)
    return mybranch


def get_excluded_addrs() -> Set[str]:
    config = get_main_config()
    excludes = set()
    c_excludes = config.get('email-exclude')
    if c_excludes:
        for entry in c_excludes.split(','):
            excludes.add(entry.strip())

    return excludes


def cleanup_email_addrs(addresses: List[Tuple[str, str]], excludes: Set[str],
                        gitdir: Optional[str]) -> List[Tuple[str, str]]:
    global MAILMAP_INFO
    for entry in list(addresses):
        # Only qualified addresses, please
        if not len(entry[1].strip()) or '@' not in entry[1]:
            addresses.remove(entry)
            continue
        # Check if it's in excludes
        removed = False
        for exclude in excludes:
            if fnmatch.fnmatch(entry[1], exclude):
                logger.debug('Removed %s due to matching %s', entry[1], exclude)
                addresses.remove(entry)
                removed = True
                break
        if removed:
            continue
        # Check if it's mailmap-replaced
        if entry[1] in MAILMAP_INFO:
            if MAILMAP_INFO[entry[1]]:
                addresses.remove(entry)
                addresses.append(MAILMAP_INFO[entry[1]])
            continue
        logger.debug('Checking if %s is mailmap-replaced', entry[1])
        args = ['check-mailmap', f'<{entry[1]}>']
        ecode, out = git_run_command(gitdir, args)
        if ecode != 0:
            MAILMAP_INFO[entry[1]] = None
            continue
        replacement = email.utils.getaddresses([out.strip()])
        if len(replacement) == 1:
            if entry[1] == replacement[0][1]:
                MAILMAP_INFO[entry[1]] = None
                continue
            logger.debug('Replaced %s with mailmap-updated %s', entry[1], replacement[0][1])
            MAILMAP_INFO[entry[1]] = replacement[0]
            addresses.remove(entry)
            addresses.append(replacement[0])

    return addresses


def get_email_signature() -> str:
    usercfg = get_user_config()
    # Do we have a .signature file?
    sigfile = os.path.join(str(Path.home()), '.signature')
    if os.path.exists(sigfile):
        with open(sigfile, 'r', encoding='utf-8') as fh:
            signature = fh.read()
    else:
        signature = '%s <%s>' % (usercfg['name'], usercfg['email'])

    return signature


def retrieve_messages(cmdargs: argparse.Namespace) -> Tuple[Optional[str], Optional[list]]:
    msgid = None
    if not cmdargs.localmbox:
        if not can_network:
            raise LookupError('Cannot retrieve threads from remote in offline mode')
        msgid = get_msgid(cmdargs)
        if not msgid:
            raise LookupError('Pipe a message or pass msgid as parameter')

        pickings = set()
        if 'cherrypick' in cmdargs and cmdargs.cherrypick == '_':
            # Just that msgid, please
            pickings = {msgid}
        msgs = get_pi_thread_by_msgid(msgid, nocache=cmdargs.nocache, onlymsgids=pickings)
        if not msgs:
            return None, msgs
    else:
        if cmdargs.localmbox == '-':
            # The entire mbox is passed via stdin, so mailsplit it and use the first message for our msgid
            with tempfile.TemporaryDirectory() as tfd:
                msgs = mailsplit_bytes(sys.stdin.buffer.read(), tfd, pipesep=cmdargs.stdin_pipe_sep)
            if not len(msgs):
                raise LookupError('Stdin did not contain any messages')

        elif os.path.exists(cmdargs.localmbox):
            msgid = get_msgid(cmdargs)
            if os.path.isdir(cmdargs.localmbox):
                in_mbx = mailbox.Maildir(cmdargs.localmbox)
            else:
                in_mbx = mailbox.mbox(cmdargs.localmbox)

            if msgid:
                msgs = get_strict_thread(in_mbx, msgid)
                if not msgs:
                    raise LookupError('Could not find %s in %s' % (msgid, cmdargs.localmbox))
            else:
                msgs = in_mbx
        else:
            raise LookupError('Mailbox %s does not exist' % cmdargs.localmbox)

    if msgid and 'noparent' in cmdargs and cmdargs.noparent:
        msgs = get_strict_thread(msgs, msgid, noparent=True)

    if not msgid and msgs:
        for msg in msgs:
            msgid = msg.get('Message-ID', None)
            if msgid:
                msgid = msgid.strip('<>')
                break

    return msgid, msgs

def git_revparse_obj(gitobj: str) -> str:
    ecode, out = git_run_command(None, ['rev-parse', gitobj])
    if ecode > 0:
        raise RuntimeError('No such object: %s' % gitobj)
    return out.strip()
