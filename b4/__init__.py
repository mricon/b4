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
import tempfile
import pathlib

import requests
import urllib.parse
import datetime
import time
import copy
import shutil
import mailbox
# noinspection PyCompatibility
import pwd

from contextlib import contextmanager
from typing import Optional, Tuple, Set, List

from email import charset
charset.add_charset('utf-8', None)
emlpolicy = email.policy.EmailPolicy(utf8=True, cte_type='8bit', max_line_length=None)

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

__VERSION__ = '0.7.3'

logger = logging.getLogger('b4')

HUNK_RE = re.compile(r'^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@')
FILENAME_RE = re.compile(r'^(---|\+\+\+) (\S+)')

ATT_PASS_SIMPLE = 'v'
ATT_FAIL_SIMPLE = 'x'
ATT_PASS_FANCY = '\033[32m\u2713\033[0m'
ATT_FAIL_FANCY = '\033[31m\u2717\033[0m'

DEVSIG_HDR = 'X-Developer-Signature'

# You can use bash-style globbing here
WANTHDRS = [
    'sender',
    'from',
    'to',
    'cc',
    'subject',
    'date',
    'message-id',
    'resent-message-id',
    'reply-to',
    'in-reply-to',
    'references',
    'list-id',
    'errors-to',
    'x-mailing-list',
    'resent-to',
]

# You can use bash-style globbing here
# end with '*' to include any other trailers
# You can change the default in your ~/.gitconfig, e.g.:
# [b4]
#   # remember to end with ,*
#   trailer-order=link*,fixes*,cc*,reported*,suggested*,original*,co-*,tested*,reviewed*,acked*,signed-off*,*
#   (another common)
#   trailer-order=fixes*,reported*,suggested*,original*,co-*,signed-off*,tested*,reviewed*,acked*,cc*,link*,*
#
# Or use _preserve_ (alias to *) to keep the order unchanged

DEFAULT_TRAILER_ORDER = '*'

LOREADDR = 'https://lore.kernel.org'

DEFAULT_CONFIG = {
    'midmask': LOREADDR + '/r/%s',
    'linkmask': LOREADDR + '/r/%s',
    'trailer-order': DEFAULT_TRAILER_ORDER,
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
}

# This is where we store actual config
MAIN_CONFIG = None
# This is git-config user.*
USER_CONFIG = None

# Used for storing our requests session
REQSESSION = None
# Indicates that we've cleaned cache already
_CACHE_CLEANED = False


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

    def get_by_msgid(self, msgid):
        if msgid in self.msgid_map:
            return self.msgid_map[msgid]
        return None

    def backfill(self, revision):
        if revision in self.covers and self.covers[revision] is not None:
            patch = self.covers[revision]
        else:
            # Find first non-None member in patches
            lser = self.series[revision]
            patch = None
            for patch in lser.patches:
                if patch is not None:
                    break
        logger.info('---')
        logger.info('Thread incomplete, attempting to backfill')
        for project in get_lore_projects_from_msg(patch.msg):
            projurl = 'https://lore.kernel.org/%s/' % project
            # Try to backfill from that project
            backfills = get_pi_thread_by_msgid(patch.msgid, useproject=project)
            if not backfills:
                continue
            was = len(self.msgid_map)
            for msg in backfills:
                self.add_message(msg)
            if len(self.msgid_map) > was:
                logger.info('Loaded %s messages from %s', len(self.msgid_map)-was, projurl)
            if self.series[revision].complete:
                logger.info('Successfully backfilled missing patches')
                break

    def partial_reroll(self, revision, sloppytrailers, backfill):
        # Is it a partial reroll?
        # To qualify for a partial reroll:
        # 1. Needs to be version > 1
        # 2. Replies need to be to the exact X/N of the previous revision
        if revision <= 1 or revision - 1 not in self.series:
            return
        # Are existing patches replies to previous revisions with the same counter?
        pser = self.get_series(revision-1, sloppytrailers=sloppytrailers, backfill=backfill)
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

    def get_series(self, revision=None, sloppytrailers=False, backfill=True, reroll=True):
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
            self.partial_reroll(revision, sloppytrailers, backfill)

        if not lser.complete and backfill:
            self.backfill(revision)

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
            for trailer in mismatches:
                lser.trailer_mismatches.add((trailer[0], trailer[1], fmsg.fromname, fmsg.fromemail))
            lvl = 1
            while True:
                logger.debug('%sParent: %s', ' ' * lvl, pmsg.full_subject)
                logger.debug('%sTrailers:', ' ' * lvl)
                for trailer in trailers:
                    logger.debug('%s%s: %s', ' ' * (lvl+1), trailer[0], trailer[1])
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
                    for ptrailer in pmsg.trailers:
                        trailers.append(tuple(ptrailer + [pmsg]))
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

    def add_message(self, msg):
        msgid = LoreMessage.get_clean_msgid(msg)
        if msgid in self.msgid_map:
            logger.debug('Already have a message with this msgid, skipping %s', msgid)
            return

        lmsg = LoreMessage(msg)
        logger.debug('Looking at: %s', lmsg.full_subject)
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
            # to set v2, v3, etc in the patch revision
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
    def __init__(self, revision, expected):
        self.revision = revision
        self.expected = expected
        self.patches = [None] * (expected+1)
        self.followups = list()
        self.trailer_mismatches = set()
        self.complete = False
        self.has_cover = False
        self.partial_reroll = False
        self.subject = '(untitled)'

    def __repr__(self):
        out = list()
        out.append('- Series: [v%s] %s' % (self.revision, self.subject))
        out.append('  revision: %s' % self.revision)
        out.append('  expected: %s' % self.expected)
        out.append('  complete: %s' % self.complete)
        out.append('  has_cover: %s' % self.has_cover)
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

    def add_patch(self, lmsg):
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
        if self.patches[0] is not None:
            # noinspection PyUnresolvedReferences
            self.subject = self.patches[0].subject
        elif self.patches[1] is not None:
            # noinspection PyUnresolvedReferences
            self.subject = self.patches[1].subject

    def get_slug(self, extended=False):
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

    def get_am_ready(self, noaddtrailers=False, covertrailers=False, trailer_order=None, addmysob=False,
                     addlink=False, linkmask=None, cherrypick=None, copyccs=False) -> list:

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
                if self.has_cover and covertrailers and self.patches[0].followup_trailers:  # noqa
                    lmsg.followup_trailers += self.patches[0].followup_trailers  # noqa
                if addmysob:
                    lmsg.followup_trailers.append(('Signed-off-by',
                                                   '%s <%s>' % (usercfg['name'], usercfg['email']), None, None))
                if addlink:
                    lmsg.followup_trailers.append(('Link', linkmask % lmsg.msgid, None, None))

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
                msg = lmsg.get_am_message(add_trailers=add_trailers, trailer_order=trailer_order, copyccs=copyccs)
                slug = '%04d_%s' % (lmsg.counter, re.sub(r'\W+', '_', lmsg.subject).strip('_').lower())
                msgs.append((slug, msg))
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

    def check_applies_clean(self, gitdir, when=None):
        # Go through indexes and see if this series should apply cleanly
        mismatches = 0
        seenfiles = set()
        for lmsg in self.patches[1:]:
            if lmsg is None or lmsg.blob_indexes is None:
                continue
            for fn, bh in lmsg.blob_indexes:
                if fn in seenfiles:
                    # if we have seen this file once already, then it's a repeat patch
                    # and it's no longer going to match current hash
                    continue
                seenfiles.add(fn)
                if set(bh) == {'0'}:
                    # New file, will for sure apply clean
                    continue
                fullpath = os.path.join(gitdir, fn)
                if when is None:
                    if not os.path.exists(fullpath):
                        mismatches += 1
                        continue
                    cmdargs = ['hash-object', fullpath]
                    ecode, out = git_run_command(None, cmdargs)
                else:
                    logger.debug('Checking hash on %s:%s', when, fn)
                    # XXX: We should probably pipe the two commands instead of reading into memory,
                    #      so something to consider for the future
                    ecode, out = git_run_command(gitdir, ['show', f'{when}:{fn}'])
                    if ecode > 0:
                        # Couldn't get this file, continue
                        logger.debug('Could not look up %s:%s', when, fn)
                        mismatches += 1
                        continue
                    cmdargs = ['hash-object', '--stdin']
                    ecode, out = git_run_command(None, cmdargs, stdin=out.encode())
                if ecode == 0:
                    if out.find(bh) != 0:
                        logger.debug('%s hash: %s (expected: %s)', fn, out.strip(), bh)
                        mismatches += 1
                    else:
                        logger.debug('%s hash: matched', fn)

        return len(seenfiles), mismatches

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
                save_cache(None, msgid, suffix='fakeam')

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
                for fn, fi in lmsg.blob_indexes:
                    if fn in seenfiles:
                        # We already processed this file, so this blob won't match
                        continue
                    seenfiles.add(fn)
                    if set(fi) == {'0'}:
                        # New file creation, nothing to do here
                        logger.debug('  New file: %s', fn)
                        continue
                    # Try to grab full ref_id of this hash
                    ecode, out = git_run_command(gitdir, ['rev-parse', fi])
                    if ecode > 0:
                        logger.critical('  ERROR: Could not find matching blob for %s (%s)', fn, fi)
                        logger.critical('         If you know on which tree this patchset is based,')
                        logger.critical('         add it as a remote and perform "git remote update"')
                        logger.critical('         in order to fetch the missing objects.')
                        return None, None
                    logger.debug('  Found matching blob for: %s', fn)
                    fullref = out.strip()
                    gitargs = ['update-index', '--add', '--cacheinfo', f'0644,{fullref},{fn}']
                    ecode, out = git_run_command(None, gitargs)
                    if ecode > 0:
                        logger.critical('  ERROR: Could not run update-index for %s (%s)', fn, fullref)
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
        cover_msg = self.patches[0].get_am_message(add_trailers=False, trailer_order=None)
        with open(outfile, 'w') as fh:
            fh.write(cover_msg.as_string(policy=emlpolicy))
        logger.critical('Cover: %s', outfile)


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

        diffre = re.compile(r'^(---.*\n\+\+\+|GIT binary patch|diff --git \w/\S+ \w/\S+)', re.M | re.I)
        diffstatre = re.compile(r'^\s*\d+ file.*\d+ (insertion|deletion)', re.M | re.I)

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
            if diffre.search(payload):
                self.body = payload

        if self.body is None:
            # Woah, we didn't find any usable parts
            logger.debug('  No plain or patch parts found in message')
            logger.info('  Not plaintext: %s', self.full_subject)
            return

        if diffstatre.search(self.body):
            self.has_diffstat = True
        if diffre.search(self.body):
            self.has_diff = True
            self.pwhash = LoreMessage.get_patchwork_hash(self.body)
            self.blob_indexes = LoreMessage.get_indexes(self.body)

        # We only pay attention to trailers that are sent in reply
        if self.reply:
            trailers, others = LoreMessage.find_trailers(self.body, followup=True)
            for trailer in trailers:
                # These are commonly part of patch/commit metadata
                badtrailers = ('from', 'author', 'cc', 'to')
                if trailer[0].lower() not in badtrailers:
                    self.trailers.append(trailer)

    def get_trailers(self, sloppy=False):
        trailers = list()
        mismatches = set()

        for tname, tvalue, extdata in self.trailers:
            if sloppy or tname.lower() in ('fixes', 'obsoleted-by'):
                trailers.append((tname, tvalue, extdata, self))
                continue

            tmatch = False
            namedata = email.utils.getaddresses([tvalue])[0]
            tfrom = re.sub(r'\+[^@]+@', '@', namedata[1].lower())
            hfrom = re.sub(r'\+[^@]+@', '@', self.fromemail.lower())
            tlname = namedata[0].lower()
            hlname = self.fromname.lower()
            tchunks = tfrom.split('@')
            hchunks = hfrom.split('@')
            if tfrom == hfrom:
                logger.debug('  trailer exact email match')
                tmatch = True
            # See if domain part of one of the addresses is a subset of the other one,
            # which should match cases like @linux.intel.com and @intel.com
            elif (len(tchunks) == 2 and len(hchunks) == 2
                  and tchunks[0] == hchunks[0]
                  and (tchunks[1].find(hchunks[1]) >= 0 or hchunks[1].find(tchunks[1]) >= 0)):
                logger.debug('  trailer fuzzy email match')
                tmatch = True
            # Does the name match, at least?
            elif tlname == hlname:
                logger.debug('  trailer exact name match')
                tmatch = True
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
                    tmatch = True
            if tmatch:
                trailers.append((tname, tvalue, extdata, self))
            else:
                mismatches.add((tname, tvalue, extdata, self))

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
        if not can_dkim:
            logger.debug('Message has DKIM signatures, but can_dkim is off')
            return

        # Yank out all DKIM-Signature headers and try them in reverse order
        # until we come to a passing one
        dkhdrs = list()
        for header in list(self.msg._headers):  # noqa
            # Also remove any List- headers set by lore.kernel.org
            if header[0].lower().startswith('list-') and header[1].find('//lore.kernel.org/') > 0:
                self.msg._headers.remove(header) # noqa
            elif header[0].lower() == 'dkim-signature':
                dkhdrs.append(header)
                self.msg._headers.remove(header) # noqa
        dkhdrs.reverse()

        seenatts = list()
        for hn, hval in dkhdrs:
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
            res = dkim.verify(self.msg.as_bytes())

            attestor = LoreAttestorDKIM(res, identity, signtime, errors)
            logger.debug('DKIM verify results: %s=%s', identity, res)
            if attestor.check_identity(self.fromemail):
                # use this one, regardless of any other DKIM signatures
                self._attestors.append(attestor)
                return

            self.msg._headers.pop(-1)  # noqa
            seenatts.append(attestor)

        # No exact domain matches, so return everything we have
        self._attestors += seenatts

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
            sources = ['ref:::.keys', 'ref:::.local-keys', 'ref::refs/meta/keyring:']
        if pdir not in sources:
            sources.append(pdir)

        # Push our logger and GPGBIN into patatt
        patatt.logger = logger
        patatt.GPGBIN = config['gpgbin']

        logger.debug('Loading patatt attestations with sources=%s', str(sources))

        attestations = patatt.validate_message(self.msg.as_bytes(), sources)
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

            signdt = LoreAttestor.parse_ts(signtime)
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
                    checkmark = attestor.checkmark
                    trailers.append('%s BADSIG: %s' % (attestor.checkmark, attestor.trailer))

                if attpolicy == 'hardfail':
                    critical = True
            else:
                if not checkmark:
                    checkmark = attestor.checkmark
                if attestor.check_identity(self.fromemail):
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

        decoded = ''
        for hstr, hcs in email.header.decode_header(hdrval):
            if hcs is None:
                hcs = 'utf-8'
            try:
                decoded += hstr.decode(hcs, errors='replace')
            except LookupError:
                # Try as utf-u
                decoded += hstr.decode('utf-8', errors='replace')
            except (UnicodeDecodeError, AttributeError):
                decoded += hstr
        new_hdrval = re.sub(r'\n?\s+', ' ', decoded)
        return new_hdrval.strip()

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
    def get_clean_msgid(msg, header='Message-Id'):
        msgid = None
        raw = msg.get(header)
        if raw:
            matches = re.search(r'<([^>]+)>', LoreMessage.clean_header(raw))
            if matches:
                msgid = matches.groups()[0]
        return msgid

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
        curfile = None
        for line in diff.split('\n'):
            if line.find('diff ') != 0 and line.find('index ') != 0:
                continue
            matches = re.search(r'^diff\s+--git\s+\w/(.*)\s+\w/(.*)$', line)
            if matches and matches.groups()[0] == matches.groups()[1]:
                curfile = matches.groups()[0]
                continue
            matches = re.search(r'^index\s+([0-9a-f]+)\.\.[0-9a-f]+.*$', line)
            if matches and curfile is not None:
                indexes.add((curfile, matches.groups()[0]))
        return indexes

    @staticmethod
    def find_trailers(body, followup=False):
        ignores = {'phone', 'email'}
        headers = {'subject', 'date', 'from'}
        nonperson = {'fixes', 'subject', 'date', 'link', 'buglink', 'obsoleted-by'}
        # Ignore everything below standard email signature marker
        body = body.split('\n-- \n', 1)[0].strip() + '\n'
        # Fix some more common copypasta trailer wrapping
        # Fixes: abcd0123 (foo bar
        # baz quux)
        body = re.sub(r'^(\S+:\s+[0-9a-f]+\s+\([^)]+)\n([^\n]+\))', r'\1 \2', body, flags=re.M)
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
            matches = re.search(r'^(\w\S+):\s+(\S.*)', line, flags=re.I)
            if matches:
                groups = list(matches.groups())
                # We only accept headers if we haven't seen any non-trailer lines
                tname = groups[0].lower()
                if tname in ignores:
                    logger.debug('Ignoring known non-trailer: %s', line)
                    continue
                if len(others) and tname in headers:
                    logger.debug('Ignoring %s (header after other content)', line)
                    continue
                if followup:
                    mperson = re.search(r'\S+@\S+\.\S+', groups[1])
                    if not mperson and tname not in nonperson:
                        logger.debug('Ignoring %s (not a recognized non-person trailer)', line)
                        continue
                was_trailer = True
                groups.append(None)
                trailers.append(groups)
                continue
            # Is it an extended info line, e.g.:
            # Signed-off-by: Foo Foo <foo@foo.com>
            # [for the foo bits]
            if len(line) > 2 and line[0] == '[' and line[-1] == ']' and was_trailer:
                trailers[-1][2] = line
                was_trailer = False
                continue
            was_trailer = False
            others.append(line)

        return trailers, others

    @staticmethod
    def get_body_parts(body):
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

    def fix_trailers(self, trailer_order=None, copyccs=False):
        config = get_main_config()
        attpolicy = config['attestation-policy']

        bheaders, message, btrailers, basement, signature = LoreMessage.get_body_parts(self.body)
        # Now we add mix-in trailers
        trailers = btrailers + self.followup_trailers

        if copyccs:
            alldests = email.utils.getaddresses([str(x) for x in self.msg.get_all('to', [])])
            alldests += email.utils.getaddresses([str(x) for x in self.msg.get_all('cc', [])])
            # Sort by domain name, then local
            alldests.sort(key=lambda x: x[1].find('@') > 0 and x[1].split('@')[1] + x[1].split('@')[0] or x[1])
            for pair in alldests:
                found = False
                for ftr in trailers:
                    if ftr[1].lower().find(pair[1].lower()) >= 0:
                        # already present
                        found = True
                        break

                if not found:
                    if len(pair[0]):
                        trailers.append(('Cc', f'{pair[0]} <{pair[1]}>', None, None))  # noqa
                    else:
                        trailers.append(('Cc', pair[1], None, None))  # noqa

        fixtrailers = list()
        if trailer_order is None:
            trailer_order = DEFAULT_TRAILER_ORDER
        elif trailer_order in ('preserve', '_preserve_'):
            trailer_order = '*'

        for trailermatch in trailer_order:
            for trailer in trailers:
                if list(trailer[:3]) in fixtrailers:
                    # Dupe
                    continue
                if fnmatch.fnmatch(trailer[0].lower(), trailermatch.strip()):
                    fixtrailers.append(list(trailer[:3]))
                    if trailer[:3] not in btrailers:
                        extra = ''
                        if trailer[3] is not None:
                            fmsg = trailer[3]
                            for attestor in fmsg.attestors:  # noqa
                                if attestor.passing:
                                    extra = ' (%s %s)' % (attestor.checkmark, attestor.trailer)
                                elif attpolicy in ('hardfail', 'softfail'):
                                    extra = ' (%s %s)' % (attestor.checkmark, attestor.trailer)
                                    if attpolicy == 'hardfail':
                                        import sys
                                        logger.critical('---')
                                        logger.critical('Exiting due to attestation-policy: hardfail')
                                        sys.exit(1)

                        logger.info('    + %s: %s%s', trailer[0], trailer[1], extra)
                    else:
                        logger.debug('    . %s: %s', trailer[0], trailer[1])

        # Reconstitute the message
        self.body = ''
        if bheaders:
            for bheader in bheaders:
                # There is no [extdata] in git headers, so we ignore bheader[2]
                self.body += '%s: %s\n' % (bheader[0], bheader[1])
            self.body += '\n'

        if len(message):
            self.body += message + '\n'
            if len(fixtrailers):
                self.body += '\n'

        if len(fixtrailers):
            for trailer in fixtrailers:
                self.body += '%s: %s\n' % (trailer[0], trailer[1])
                if trailer[2]:
                    self.body += '%s\n' % trailer[2]
        if len(basement):
            self.body += '---\n'
            self.body += basement
            self.body += '\n'
        if len(signature):
            self.body += '-- \n'
            self.body += signature
            self.body += '\n'

    def get_am_subject(self):
        # Return a clean patch subject
        parts = ['PATCH']
        if self.lsubject.rfc:
            parts.append('RFC')
        if self.reroll_from_revision:
            if self.reroll_from_revision != self.revision:
                parts.append('v%d->v%d' % (self.reroll_from_revision, self.revision))
            else:
                parts.append(' %s  v%d' % (' ' * len(str(self.reroll_from_revision)), self.revision))
        elif not self.revision_inferred:
            parts.append('v%d' % self.revision)
        if not self.lsubject.counters_inferred:
            parts.append('%d/%d' % (self.lsubject.counter, self.lsubject.expected))

        return '[%s] %s' % (' '.join(parts), self.lsubject.subject)

    def get_am_message(self, add_trailers=True, trailer_order=None, copyccs=False):
        if add_trailers:
            self.fix_trailers(trailer_order=trailer_order, copyccs=copyccs)
        am_body = self.body.rstrip('\r\n')
        am_msg = email.message.EmailMessage()
        am_msg.set_payload(am_body.encode() + b'\n')
        # Clean up headers
        for hdrname, hdrval in self.msg.items():
            lhdrname = hdrname.lower()
            wanthdr = False
            for hdrmatch in WANTHDRS:
                if fnmatch.fnmatch(lhdrname, hdrmatch):
                    wanthdr = True
                    break
            if wanthdr:
                new_hdrval = LoreMessage.clean_header(hdrval)
                # noinspection PyBroadException
                try:
                    am_msg.add_header(hdrname, new_hdrval)
                except:
                    # A broad except to handle any potential weird header conditions
                    pass
        am_msg.set_charset('utf-8')
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
                if re.search(r'^\d{1,3}/\d{1,3}$', chunk):
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

    def get_slug(self):
        unsafe = '%04d_%s' % (self.counter, self.subject)
        return re.sub(r'\W+', '_', unsafe).strip('_').lower()

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

        return '%s/%s' % (mode, self.identity)

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
            if emlfrom.endswith('@' + self.identity):
                logger.debug('PASS : sig domain %s matches from identity %s', self.identity, emlfrom)
                return True
            self.errors.append('signing domain %s does not match From: %s' % (self.identity, emlfrom))
            return False

        if emlfrom == self.identity:
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
        self.identity = identity.lstrip('@')
        self.errors = errors


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


def _run_command(cmdargs: list, stdin: Optional[bytes] = None) -> Tuple[int, bytes, bytes]:
    logger.debug('Running %s' % ' '.join(cmdargs))
    sp = subprocess.Popen(cmdargs, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, error) = sp.communicate(input=stdin)

    return sp.returncode, output, error


def gpg_run_command(args: List[str], stdin: Optional[bytes] = None) -> Tuple[int, bytes, bytes]:
    config = get_main_config()
    cmdargs = [config['gpgbin'], '--batch', '--no-auto-key-retrieve', '--no-auto-check-trustdb']
    if config['attestation-gnupghome'] is not None:
        cmdargs += ['--homedir', config['attestation-gnupghome']]
    cmdargs += args

    return _run_command(cmdargs, stdin=stdin)


def git_run_command(gitdir: Optional[str], args: List[str], stdin: Optional[bytes] = None,
                    logstderr: bool = False) -> Tuple[int, str]:
    cmdargs = ['git', '--no-pager']
    if gitdir:
        if os.path.exists(os.path.join(gitdir, '.git')):
            gitdir = os.path.join(gitdir, '.git')
        cmdargs += ['--git-dir', gitdir]
    cmdargs += args

    ecode, out, err = _run_command(cmdargs, stdin=stdin)

    out = out.decode(errors='replace')

    if logstderr and len(err.strip()):
        err = err.decode(errors='replace')
        logger.debug('Stderr: %s', err)
        out += err

    return ecode, out


def git_get_command_lines(gitdir: Optional[str], args: list) -> List[str]:
    ecode, out = git_run_command(gitdir, args)
    lines = list()
    if out:
        for line in out.split('\n'):
            if line == '':
                continue
            lines.append(line)

    return lines


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
            git_run_command(gitdir, ['worktree', 'remove', dfn])


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


def get_config_from_git(regexp: str, defaults: Optional[dict] = None, multivals: Optional[list] = None) -> dict:
    if multivals is None:
        multivals = list()
    args = ['config', '-z', '--get-regexp', regexp]
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
        config = get_config_from_git(r'b4\..*', defaults=DEFAULT_CONFIG, multivals=['keyringsrc'])
        # Legacy name was get-lore-mbox, so load those as well
        config = get_config_from_git(r'get-lore-mbox\..*', defaults=config)
        config['trailer-order'] = config['trailer-order'].split(',')
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


def get_cache_file(identifier, suffix=None):
    cachedir = get_cache_dir()
    cachefile = hashlib.sha1(identifier.encode()).hexdigest()
    if suffix:
        cachefile = f'{cachefile}.{suffix}'
    return os.path.join(cachedir, cachefile)


def get_cache(identifier, suffix=None):
    fullpath = get_cache_file(identifier, suffix=suffix)
    try:
        with open(fullpath) as fh:
            logger.debug('Using cache %s for %s', fullpath, identifier)
            return fh.read()
    except FileNotFoundError:
        logger.debug('Cache miss for %s', identifier)
    return None


def save_cache(contents, identifier, suffix=None, mode='w'):
    fullpath = get_cache_file(identifier, suffix=suffix)
    if not contents:
        # noinspection PyBroadException
        try:
            os.unlink(fullpath)
            logger.debug('Removed cache %s for %s', fullpath, identifier)
        except:
            pass
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


def get_msgid_from_stdin():
    if not sys.stdin.isatty():
        message = email.message_from_bytes(sys.stdin.buffer.read())
        return message.get('Message-ID', None)
    return None


def get_msgid(cmdargs) -> Optional[str]:
    if not cmdargs.msgid:
        logger.debug('Getting Message-ID from stdin')
        msgid = get_msgid_from_stdin()
    else:
        msgid = cmdargs.msgid

    if msgid is None:
        return None

    msgid = msgid.strip('<>')
    # Handle the case when someone pastes a full URL to the message
    matches = re.search(r'^https?://[^/]+/([^/]+)/([^/]+@[^/]+)', msgid, re.IGNORECASE)
    if matches:
        chunks = matches.groups()
        msgid = urllib.parse.unquote(chunks[1])
        # Infer the project name from the URL, if possible
        if chunks[0] != 'r':
            cmdargs.useproject = chunks[0]
    # Handle special case when msgid is prepended by id: or rfc822msgid:
    if msgid.find('id:') >= 0:
        msgid = re.sub(r'^\w*id:', '', msgid)

    return msgid


def get_strict_thread(msgs, msgid):
    want = {msgid}
    got = set()
    seen = set()
    maybe = dict()
    strict = list()
    while True:
        for msg in msgs:
            c_msgid = LoreMessage.get_clean_msgid(msg)
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
            for ref in set([x[1] for x in msgrefs]):
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
        logger.debug('Reduced mbox to strict matches only (%s->%s)', len(msgs), len(strict))

    return strict


def mailsplit_bytes(bmbox: bytes, outdir: str) -> list:
    logger.debug('Mailsplitting the mbox into %s', outdir)
    args = ['mailsplit', '--mboxrd', '-o%s' % outdir]
    ecode, out = git_run_command(None, args, stdin=bmbox)
    msgs = list()
    if ecode > 0:
        logger.critical('Unable to parse mbox received from the server')
        return msgs
    # Read in the files
    for msg in os.listdir(outdir):
        with open(os.path.join(outdir, msg), 'rb') as fh:
            msgs.append(email.message_from_binary_file(fh))
    return msgs


def get_pi_thread_by_url(t_mbx_url, nocache=False):
    msgs = list()
    cachedir = get_cache_file(t_mbx_url, 'pi.msgs')
    if os.path.exists(cachedir) and not nocache:
        logger.debug('Using cached copy: %s', cachedir)
        for msg in os.listdir(cachedir):
            with open(os.path.join(cachedir, msg), 'rb') as fh:
                msgs.append(email.message_from_binary_file(fh))
        return msgs

    logger.critical('Grabbing thread from %s', t_mbx_url.split('://')[1])
    session = get_requests_session()
    resp = session.get(t_mbx_url)
    if resp.status_code != 200:
        logger.critical('Server returned an error: %s', resp.status_code)
        return None
    t_mbox = gzip.decompress(resp.content)
    resp.close()
    if not len(t_mbox):
        logger.critical('No messages found for that query')
        return None
    # Convert into individual files using git-mailsplit
    with tempfile.TemporaryDirectory(suffix='-mailsplit') as tfd:
        msgs = mailsplit_bytes(t_mbox, tfd)
        if os.path.exists(cachedir):
            shutil.rmtree(cachedir)
        shutil.copytree(tfd, cachedir)
    return msgs


def get_pi_thread_by_msgid(msgid, useproject=None, nocache=False, onlymsgids: Optional[set] = None):
    qmsgid = urllib.parse.quote_plus(msgid)
    config = get_main_config()
    # Grab the head from lore, to see where we are redirected
    midmask = config['midmask'] % qmsgid
    loc = urllib.parse.urlparse(midmask)
    if useproject:
        projurl = '%s://%s/%s' % (loc.scheme, loc.netloc, useproject)
    else:
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


@contextmanager
def git_format_patches(gitdir, start, end, prefixes=None, extraopts=None):
    with tempfile.TemporaryDirectory() as tmpd:
        gitargs = ['format-patch', '--cover-letter', '-o', tmpd, '--signature', f'b4 {__VERSION__}']
        if prefixes is not None and len(prefixes):
            gitargs += ['--subject-prefix', ' '.join(prefixes)]
        if extraopts:
            gitargs += extraopts
        gitargs += ['%s..%s' % (start, end)]
        ecode, out = git_run_command(gitdir, gitargs)
        if ecode > 0:
            logger.critical('ERROR: Could not convert pull request into patches')
            logger.critical(out)
            yield None
        yield tmpd


def git_commit_exists(gitdir, commit_id):
    gitargs = ['cat-file', '-e', commit_id]
    ecode, out = git_run_command(gitdir, gitargs)
    return ecode == 0


def git_branch_contains(gitdir, commit_id):
    gitargs = ['branch', '--format=%(refname:short)', '--contains', commit_id]
    lines = git_get_command_lines(gitdir, gitargs)
    return lines


def git_get_toplevel(path=None):
    topdir = None
    # Are we in a git tree and if so, what is our toplevel?
    gitargs = ['rev-parse', '--show-toplevel']
    lines = git_get_command_lines(path, gitargs)
    if len(lines) == 1:
        topdir = lines[0]
    return topdir


def format_addrs(pairs, clean=True):
    addrs = set()
    for pair in pairs:
        pair = list(pair)
        if pair[0] == pair[1]:
            pair[0] = ''
        if clean:
            # Remove any quoted-printable header junk from the name
            pair[0] = LoreMessage.clean_header(pair[0])
        addrs.add(email.utils.formataddr(pair))  # noqa
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


def check_gpg_status(status: str) -> Tuple[bool, bool, bool, str, str]:
    good = False
    valid = False
    trusted = False
    keyid = None
    signtime = ''

    gs_matches = re.search(r'^\[GNUPG:] GOODSIG ([0-9A-F]+)\s+(.*)$', status, flags=re.M)
    if gs_matches:
        good = True
    vs_matches = re.search(r'^\[GNUPG:] VALIDSIG ([0-9A-F]+) (\d{4}-\d{2}-\d{2}) (\d+)', status, flags=re.M)
    if vs_matches:
        valid = True
        keyid = vs_matches.groups()[0]
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


def save_git_am_mbox(msgs: list, dest):
    # Git-am has its own understanding of what "mbox" format is that differs from Python's
    # mboxo implementation. Specifically, it never escapes the ">From " lines found in bodies
    # unless invoked with --patch-format=mboxrd (this is wrong, because ">From " escapes are also
    # required in the original mbox "mboxo" format).
    # So, save in the format that git-am expects
    # "dest" should be a file handler in writable+binary mode
    for msg in msgs:
        bmsg = msg.as_bytes(unixfrom=True, policy=emlpolicy)
        # public-inbox unixfrom says "mboxrd", so replace it with something else
        # so there is no confusion as it's NOT mboxrd
        bmsg = re.sub(b'^From mboxrd@z ', b'From git@z ', bmsg)
        bmsg = bmsg.rstrip(b'\r\n') + b'\n\n'
        dest.write(bmsg)


def get_lore_projects_from_msg(msg) -> list:
    cachedir = get_cache_dir()
    listmap = os.path.join(cachedir, 'lists.map.lookup')
    if not os.path.exists(listmap):
        # lists.map is a custom service running on lore.kernel.org, so it is
        # meaningless to make this a configurable URL
        session = get_requests_session()
        resp = session.get('https://lore.kernel.org/lists.map')
        if resp.status_code != 200:
            logger.debug('Unable to retrieve lore.kernel.org/lists.map')
            return list()
        content = resp.content.decode()
        with open(listmap, 'w') as fh:
            fh.write(content)
    else:
        with open(listmap, 'r') as fh:
            content = fh.read()

    projmap = dict()
    for line in content.split('\n'):
        if line.find(':') <= 0:
            continue
        chunks = line.split(':')
        projmap[chunks[0]] = chunks[1].strip()

    allto = email.utils.getaddresses([str(x) for x in msg.get_all('to', [])])
    allto += email.utils.getaddresses([str(x) for x in msg.get_all('cc', [])])
    projects = list()
    for entry in allto:
        if entry[1] in projmap:
            projects.append(projmap[entry[1]])

    return projects
