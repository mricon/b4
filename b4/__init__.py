# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
import subprocess
import logging
import hashlib
import re
import os
import fnmatch
import email.utils
import email.policy
import requests
import urllib.parse
import datetime
import time

from pathlib import Path
from tempfile import mkstemp

from email import charset
charset.add_charset('utf-8', None)
emlpolicy = email.policy.EmailPolicy(utf8=True, cte_type='8bit', max_line_length=None)

__VERSION__ = '0.3.4'
ATTESTATION_FORMAT_VER = '0.1'

logger = logging.getLogger('b4')

HUNK_RE = re.compile(r'^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@')
FILENAME_RE = re.compile(r'^(---|\+\+\+) (\S+)')

PASS_SIMPLE = '[P]'
FAIL_SIMPLE = '[F]'
PASS_FANCY = '[\033[32m✓\033[0m]'
FAIL_FANCY = '[\033[31m✗\033[0m]'

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
DEFAULT_TRAILER_ORDER = 'fixes*,reported*,suggested*,original*,co-*,signed-off*,tested*,reviewed*,acked*,cc*,link*,*'

LOREADDR = 'https://lore.kernel.org'

DEFAULT_CONFIG = {
    'midmask': LOREADDR + '/r/%s',
    'linkmask': LOREADDR + '/r/%s',
    'trailer-order': DEFAULT_TRAILER_ORDER,
    # off: do not bother checking attestation
    # check: print an attaboy when attestation is found
    # softfail: print a warning when no attestation found
    # hardfail: exit with an error when no attestation found
    'attestation-policy': 'check',
    # "gpg" (whatever gpg is configured to do) or "tofu" to force tofu mode
    'attestation-trust-model': 'gpg',
    # strict: must match one of the uids on the key to pass
    # loose: any valid and trusted key will be accepted
    'attestation-uid-match': 'loose',
    # How many days before we consider attestation too old?
    'attestation-staleness-days': '30',
    # NB! This whole behaviour will change once public-inbox
    # gains support for cross-list searches
    'attestation-query-url': LOREADDR + '/signatures/',
    # We'll use the default gnupg homedir, unless you set it here
    'attestation-gnupghome': None,
    # Do you like simple or fancy checkmarks?
    'attestation-checkmarks': 'fancy',
    # How long to keep things in cache before expiring (minutes)?
    'cache-expire': '10',
    # If this is not set, we'll use what we find in 
    # git-config for gpg.program, and if that's not set,
    # we'll use "gpg" and hope for the better
    'gpgbin': None,
}

# This is where we store actual config
MAIN_CONFIG = None
# This is git-config user.*
USER_CONFIG = None

# Used for tracking attestations we have already looked up
ATTESTATIONS = list()
# Used for keeping a cache of subkey lookups to minimize shelling out to gpg
SUBKEY_DATA = dict()
# Used for storing our requests session
REQSESSION = None
# Indicates that we've cleaned cache already
_CACHE_CLEANED = False


class LoreMailbox:
    def __init__(self):
        self.msgid_map = dict()
        self.series = dict()
        self.covers = dict()
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

    def get_series(self, revision=None):
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

        # Grab our cover letter if we have one
        if revision in self.covers.keys():
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
            # if it's for the wrong revision, ignore it
            if not fmsg.revision_inferred and lser.revision != fmsg.revision:
                logger.debug('  follow-up for the wrong revision, skipping')
                continue
            # Go up through the follow-ups and tally up trailers until
            # we either run out of in-reply-tos, or we find a patch in
            # our series
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
            else:
                pmsg = self.msgid_map[fmsg.in_reply_to]

            trailers = set(fmsg.trailers)
            lvl = 1
            while True:
                logger.debug('%sParent: %s', ' ' * lvl, pmsg.full_subject)
                logger.debug('%sTrailers:', ' ' * lvl)
                for trailer in trailers:
                    logger.debug('%s%s: %s', ' ' * (lvl+1), trailer[0], trailer[1])
                found = False
                if lser.revision != pmsg.revision:
                    break
                for lmsg in lser.patches:
                    if lmsg is not None and lmsg.msgid == pmsg.msgid:
                        # Confirmed, this is our parent patch
                        lmsg.followup_trailers.update(trailers)
                        found = True
                        break
                if found:
                    break
                elif pmsg.in_reply_to and pmsg.in_reply_to in self.msgid_map:
                    lvl += 1
                    trailers.update(pmsg.trailers)
                    pmsg = self.msgid_map[pmsg.in_reply_to]
                else:
                    break

        return lser

    def add_message(self, msg):
        lmsg = LoreMessage(msg)
        logger.debug('Looking at: %s', lmsg.full_subject)
        self.msgid_map[lmsg.msgid] = lmsg

        if lmsg.counter == 0 and lmsg.has_diffstat:
            # Cover letter
            # Add it to covers -- we'll deal with them later
            logger.debug('  adding as v%s cover letter', lmsg.revision)
            self.covers[lmsg.revision] = lmsg
            return

        if lmsg.reply:
            # We'll figure out where this belongs later
            logger.debug('  adding to followups')
            self.followups.append(lmsg)
            return

        if re.search(r'^Comment: att-fmt-ver:', lmsg.body, re.I | re.M):
            logger.debug('Found attestation message')
            LoreAttestationDocument.load_from_string(lmsg.msgid, lmsg.body)
            # We don't keep it, because it's not useful for us beyond this point
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

            # Run our check again
            if lmsg.revision not in self.series:
                self.series[lmsg.revision] = LoreSeries(lmsg.revision, lmsg.expected)
                if len(self.series) > 1:
                    logger.info('Found new series v%s', lmsg.revision)

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
        self.complete = False
        self.has_cover = False

    def __repr__(self):
        out = list()
        if self.has_cover:
            out.append('- Series: [v%s] %s' % (self.revision, self.patches[0].subject))
        elif self.patches[1] is not None:
            out.append('- Series: [v%s] %s' % (self.revision, self.patches[1].subject))
        else:
            out.append('- Series: [v%s] (untitled)' % self.revision)

        out.append('  revision: %s' % self.revision)
        out.append('  expected: %s' % self.expected)
        out.append('  complete: %s' % self.complete)
        out.append('  has_cover: %s' % self.has_cover)
        out.append('  patches:')
        at = 0
        for member in self.patches:
            if member is not None:
                out.append('    [%s/%s] %s' % (at, self.expected, member.subject))
                if member.followup_trailers:
                    out.append('       Add: %s' % ', '.join(member.followup_trailers))
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

    def get_slug(self, extended=False):
        # Find the first non-None entry
        lmsg = None
        for lmsg in self.patches:
            if lmsg is not None:
                break

        if lmsg is None:
            return 'undefined'

        prefix = lmsg.date.strftime('%Y%m%d')
        authorline = email.utils.getaddresses(lmsg.msg.get_all('from', []))[0]
        if extended:
            local = authorline[1].split('@')[0]
            unsafe = '%s_%s_%s' % (prefix, local, lmsg.subject)
            slug = re.sub(r'\W+', '_', unsafe).strip('_').lower()
        else:
            author = re.sub(r'\W+', '_', authorline[1]).strip('_').lower()
            slug = '%s_%s' % (prefix, author)

        if self.revision != 1:
            slug = 'v%s_%s' % (self.revision, slug)

        return slug

    def save_am_mbox(self, mbx, noaddtrailers, covertrailers,
                     trailer_order=None, addmysob=False, addlink=False, linkmask=None):

        usercfg = get_user_config()
        config = get_main_config()

        if addmysob:
            if 'name' not in usercfg or 'email' not in usercfg:
                logger.critical('WARNING: Unable to add your Signed-off-by: git returned no user.name or user.email')
                addmysob = False

        attdata = [None] * self.expected
        attpolicy = config['attestation-policy']
        try:
            attstaled = int(config['attestation-staleness-days'])
        except ValueError:
            attstaled = 30
        exact_from_match = False
        if config['attestation-uid-match'] == 'strict':
            exact_from_match = True

        if config['attestation-checkmarks'] == 'fancy':
            attpass = PASS_FANCY
            attfail = FAIL_FANCY
        else:
            attpass = PASS_SIMPLE
            attfail = FAIL_SIMPLE

        at = 1
        atterrors = list()
        for lmsg in self.patches[1:]:
            if lmsg is not None:
                if self.has_cover and covertrailers and self.patches[0].followup_trailers:
                    lmsg.followup_trailers.update(self.patches[0].followup_trailers)
                if addmysob:
                    lmsg.followup_trailers.add(('Signed-off-by', '%s <%s>' % (usercfg['name'], usercfg['email'])))
                if addlink:
                    lmsg.followup_trailers.add(('Link', linkmask % lmsg.msgid))

                if attpolicy != 'off':
                    lore_lookup = False
                    if at == 1:
                        # We only hit lore on the first patch
                        lore_lookup = True
                    attdoc = lmsg.get_attestation(lore_lookup=lore_lookup, exact_from_match=exact_from_match)
                    if attdoc is None:
                        if attpolicy in ('softfail', 'hardfail'):
                            logger.info('  %s %s', attfail, lmsg.full_subject)
                            # Which part failed?
                            failed = ['commit metadata', 'commit message', 'patch content']
                            for attdoc in ATTESTATIONS:
                                for i, m, p in attdoc.hashes:
                                    if p == lmsg.attestation.p:
                                        failed.remove('patch content')
                                    if m == lmsg.attestation.m:
                                        failed.remove('commit message')
                                    if i == lmsg.attestation.i:
                                        failed.remove('commit metadata')
                            atterrors.append('Patch %s/%s failed attestation (%s)' % (at, lmsg.expected,
                                                                                      ', '.join(failed)))
                        else:
                            logger.info('  %s', lmsg.full_subject)
                    else:
                        if attpolicy == 'check':
                            # switch to softfail policy now that we have at least one hit
                            attpolicy = 'softfail'
                        # Make sure it's not too old compared to the message date
                        # Timezone doesn't matter as we calculate whole days
                        tdelta = lmsg.date.replace(tzinfo=None) - attdoc.sigdate
                        if tdelta.days > attstaled:
                            # Uh-oh, attestation is too old!
                            logger.info('  %s %s', attfail, lmsg.full_subject)
                            atterrors.append('Attestation for %s/%s is over %sd old: %sd' % (at, lmsg.expected,
                                                                                             attstaled, tdelta.days))
                        else:
                            logger.info('  %s %s', attpass, lmsg.full_subject)
                            attdata[at-1] = attdoc.attestor.get_trailer(lmsg.fromemail)
                else:
                    logger.info('  %s', lmsg.full_subject)

                add_trailers = True
                if noaddtrailers:
                    add_trailers = False
                msg = lmsg.get_am_message(add_trailers=add_trailers, trailer_order=trailer_order)
                # Pass a policy that avoids most legacy encoding horrors
                mbx.add(msg.as_bytes(policy=emlpolicy))
            else:
                logger.error('  ERROR: missing [%s/%s]!', at, self.expected)
            at += 1

        if attpolicy == 'off':
            return mbx
        failed = None in attdata
        if not failed:
            logger.info('  ---')
            for trailer in set(attdata):
                logger.info('  %s %s', attpass, trailer)
            return mbx

        errors = set(atterrors)
        for attdoc in ATTESTATIONS:
            errors.update(attdoc.errors)

        if errors:
            logger.critical('  ---')
            logger.critical('  Attestation is available, but did not succeed:')
            for error in errors:
                logger.critical('    %s %s', attfail, error)

        if attpolicy == 'hardfail':
            import sys
            sys.exit(128)

        return mbx

    def save_cover(self, outfile):
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
        self.has_diff = False
        self.has_diffstat = False
        self.trailers = set()
        self.followup_trailers = set()

        self.attestation = None

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

        # Handle [PATCH 6/5]
        if self.counter > self.expected:
            self.expected = self.counter

        self.in_reply_to = LoreMessage.get_clean_msgid(self.msg, header='In-Reply-To')

        try:
            fromdata = email.utils.getaddresses(self.msg.get_all('from', []))[0]
            self.fromname = fromdata[0]
            self.fromemail = fromdata[1]
        except IndexError:
            pass

        self.date = email.utils.parsedate_to_datetime(str(self.msg['Date']))

        diffre = re.compile(r'^(---.*\n\+\+\+|GIT binary patch)', re.M | re.I)
        diffstatre = re.compile(r'^\s*\d+ file.*\d+ (insertion|deletion)', re.M | re.I)

        # walk until we find the first text/plain part
        mcharset = self.msg.get_content_charset()
        if not mcharset:
            mcharset = 'utf-8'

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
            payload = payload.decode(pcharset, errors='replace')
            if self.body is None:
                self.body = payload
                continue
            # If we already found a body, but we now find something that contains a diff,
            # then we prefer this part
            if diffre.search(payload):
                self.body = payload

        if diffstatre.search(self.body):
            self.has_diffstat = True
        if diffre.search(self.body):
            self.has_diff = True

        # We only pay attention to trailers that are sent in reply
        if self.reply:
            # Do we have a Fixes: trailer?
            matches = re.findall(r'^\s*Fixes:[ \t]+([a-f0-9]+\s+\(.*\))\s*$', self.body, re.MULTILINE)
            if matches:
                for tvalue in matches:
                    self.trailers.add(('Fixes', tvalue))

            # Do we have something that looks like a person-trailer?
            matches = re.findall(r'^\s*([\w-]+):[ \t]+(.*<\S+>)\s*$', self.body, re.MULTILINE)
            if matches:
                # Basic sanity checking -- the trailer must match the name or the email
                # in the From header, to avoid false-positive trailer parsing errors
                for tname, tvalue in matches:
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
                        self.trailers.add((tname, tvalue))
                    else:
                        logger.debug('  ignoring "%s: %s" due to from mismatch (from: %s %s)', tname, tvalue,
                                     self.fromname, self.fromemail)

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

        return '\n'.join(out)

    @staticmethod
    def clean_header(hdrval):
        uval = hdrval.replace('\n', ' ')
        new_hdrval = re.sub(r'\s+', ' ', uval)
        return new_hdrval.strip()

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
    def get_patch_hash(diff):
        # The aim is to represent the patch as if you did the following:
        # git diff HEAD~.. | dos2unix | sha256sum
        #
        # This subroutine removes anything at the beginning of diff data, like
        # diffstat or any other auxiliary data, and anything trailing at the end
        # XXX: This currently doesn't work for git binary patches
        #
        diff = diff.replace('\r', '')

        # For keeping a buffer of lines preceding @@ ... @@
        buflines = list()

        phasher = hashlib.sha256()

        # Used for counting where we are in the patch
        pp = 0
        for line in diff.split('\n'):
            hunk_match = HUNK_RE.match(line)
            if hunk_match:
                # logger.debug('Crunching %s', line)
                mlines, plines = hunk_match.groups()
                pp = int(plines)
                addlines = list()
                for bline in reversed(buflines):
                    # Go backward and add lines until we get to the start
                    # or encounter a blank line
                    if len(bline.strip()) == 0:
                        break
                    addlines.append(bline)
                if addlines:
                    phasher.update(('\n'.join(reversed(addlines)) + '\n').encode('utf-8'))
                buflines = list()
                # Feed this line to the hasher
                phasher.update((line + '\n').encode('utf-8'))
                continue
            if pp > 0:
                # Inside the patch
                phasher.update((line + '\n').encode('utf-8'))
                if len(line) and line[0] == '-':
                    continue
                pp -= 1
                continue
            # Not anything we recognize, so stick into buflines
            buflines.append(line)

        return phasher.hexdigest()

    def load_hashes(self):
        msg_out = mkstemp()
        patch_out = mkstemp()
        cmdargs = ['mailinfo', '--encoding=UTF-8', msg_out[1], patch_out[1]]
        emlout = self.msg.as_string(policy=emlpolicy)
        ecode, info = git_run_command(None, cmdargs, emlout.encode('utf-8'))
        if ecode > 0:
            logger.debug('ERROR: Could not get mailinfo')
            return
        ihasher = hashlib.sha256()

        for line in info.split('\n'):
            # We don't use the "Date:" field because it is likely to be
            # mangled between when git-format-patch generates it and
            # when it is sent out by git-send-email (or other tools).
            if re.search(r'^(Author|Email|Subject):', line):
                ihasher.update((line + '\n').encode('utf-8'))
        i = ihasher.hexdigest()

        with open(msg_out[1], 'r') as mfh:
            msg = mfh.read()
            mhasher = hashlib.sha256()
            mhasher.update(msg.encode('utf-8'))
            m = mhasher.hexdigest()
        os.unlink(msg_out[1])

        p = None
        with open(patch_out[1], 'r') as pfh:
            patch = pfh.read()
            if len(patch.strip()):
                p = LoreMessage.get_patch_hash(patch)
        os.unlink(patch_out[1])

        if i and m and p:
            self.attestation = LoreAttestation(i, m, p)

    def fix_trailers(self, trailer_order=None):
        bodylines = self.body.split('\n')
        # Get existing trailers
        # 1. Find the first ---
        # 2. Go backwards and grab everything matching ^[\w-]+:\s.*$ until a blank line
        fixlines = list()
        trailersdone = False
        for line in bodylines:
            if trailersdone:
                fixlines.append(line)
                continue

            if line.strip() == '---':
                # Start going backwards in fixlines
                btrailers = list()
                for rline in reversed(fixlines):
                    if not len(rline.strip()):
                        break
                    matches = re.search(r'^([\w-]+):\s+(.*)', rline)
                    if not matches:
                        break
                    fixlines.pop()
                    btrailers.append(matches.groups())

                # Now we add mix-in trailers
                btrailers.reverse()
                trailers = set(self.followup_trailers)
                trailers.update(set(btrailers))
                added = list()
                if trailer_order is None:
                    trailer_order = DEFAULT_TRAILER_ORDER
                for trailermatch in trailer_order:
                    for trailer in trailers:
                        if trailer in added:
                            continue
                        if fnmatch.fnmatch(trailer[0].lower(), trailermatch.strip()):
                            fixlines.append('%s: %s' % trailer)
                            if trailer not in btrailers:
                                logger.info('    + %s: %s' % trailer)
                            else:
                                logger.debug('    . %s: %s' % trailer)
                            added.append(trailer)
                trailersdone = True
            fixlines.append(line)
        self.body = '\n'.join(fixlines)

    def get_am_message(self, add_trailers=True, trailer_order=None):
        if add_trailers:
            self.fix_trailers(trailer_order=trailer_order)
        am_body = self.body
        am_msg = email.message.EmailMessage()
        am_msg.set_payload(am_body.encode('utf-8'))
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

    def _load_attestation(self, lore_lookup=True):
        self.load_hashes()
        if self.attestation:
            self.attestation.validate(lore_lookup=lore_lookup)

    def get_attestation(self, lore_lookup=True, exact_from_match=True):
        self._load_attestation(lore_lookup=lore_lookup)
        if not self.attestation or not self.attestation.passing:
            return None

        for attdoc in self.attestation.attdocs:
            if not exact_from_match:
                # We return the first hit
                return attdoc
            # Does this doc have an exact match?
            uid = attdoc.attestor.get_matching_uid(self.fromemail)
            if uid[1] == self.fromemail:
                return attdoc
            # stick an error in the first available attdoc saying
            # that exact from match failed
            self.attestation.attdocs[0].errors.add('Exact UID match failed for %s' % self.fromemail)

        return None


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
        # Remove any leading [] that don't have "patch", "resend" or "rfc" in them
        while True:
            oldsubj = subject
            subject = re.sub(r'^\s*\[[^\]]*\]\s*(\[[^\]]*(:?patch|resend|rfc).*)', '\\1', subject, flags=re.IGNORECASE)
            if oldsubj == subject:
                break

        # Remove any brackets inside brackets
        while True:
            oldsubj = subject
            subject = re.sub(r'^\s*\[([^\]]*)\[([^\[\]]*)\]', '[\\1\\2]', subject)
            subject = re.sub(r'^\s*\[([^\]]*)\]([^\[\]]*)\]', '[\\1\\2]', subject)
            if oldsubj == subject:
                break

        self.full_subject = subject
        # Is it a reply?
        if re.search(r'^(Re|Aw|Fwd):', subject, re.I) or re.search(r'^\w{2,3}:\s*\[', subject):
            self.reply = True
            subject = re.sub(r'^\w+:\s*\[', '[', subject)

        # Find all [foo] in the title
        while subject.find('[') == 0:
            matches = re.search(r'^\[([^\]]*)\]', subject)
            for chunk in matches.groups()[0].split():
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
            subject = re.sub(r'^\s*\[[^\]]*\]\s*', '', subject)
        self.subject = subject

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
    def __init__(self, keyid):
        self.keyid = keyid
        self.uids = list()

        self.load_subkey_uids()

    def load_subkey_uids(self):
        global SUBKEY_DATA
        if self.keyid not in SUBKEY_DATA:
            gpgargs = ['--with-colons', '--list-keys', self.keyid]
            ecode, keyinfo = gpg_run_command(gpgargs)
            if ecode > 0:
                logger.critical('ERROR: Unable to get UIDs list matching key %s', self.keyid)
                return

            uids = list()
            for line in keyinfo.split('\n'):
                if line[:4] != 'uid:':
                    continue
                chunks = line.split(':')
                if chunks[1] in ('r',):
                    # Revoked UID, ignore
                    continue
                uids.append(chunks[9])
            SUBKEY_DATA[self.keyid] = email.utils.getaddresses(uids)

        self.uids = SUBKEY_DATA[self.keyid]

    def get_primary_uid(self):
        return self.uids[0]

    def get_matching_uid(self, fromaddr):
        for uid in self.uids:
            if fromaddr == uid[1]:
                return uid

        logger.debug('No exact match, returning primary UID')
        return self.uids[0]

    def get_trailer(self, fromaddr):
        if fromaddr:
            uid = self.get_matching_uid(fromaddr)
        else:
            uid = self.uids[0]

        return 'Attestation-by: %s <%s> (pgp: %s)' % (uid[0], uid[1], self.keyid)

    def __repr__(self):
        out = list()
        out.append('  keyid: %s' % self.keyid)
        for uid in self.uids:
            out.append('    uid: %s <%s>' % uid)
        return '\n'.join(out)


class LoreAttestationDocument:
    def __init__(self, source, sigdata):
        self.source = source
        self.good = False
        self.valid = False
        self.trusted = False
        self.sigdate = None
        self.passing = False
        self.attestor = None
        self.hashes = set()
        self.errors = set()

        gpgargs = ['--verify', '--status-fd=1']
        config = get_main_config()
        if config['attestation-trust-model'] == 'tofu':
            gpgargs += ['--trust-model', 'tofu', '--tofu-default-policy', 'good']

        logger.debug('Validating document obtained from %s', self.source)
        ecode, output = gpg_run_command(gpgargs, stdin=sigdata.encode('utf-8'))
        if ecode == 0:
            # We're looking for both GOODSIG and VALIDSIG
            gs_matches = re.search(r'^\[GNUPG:\] GOODSIG ([0-9A-F]+)\s+.*$', output, re.M)
            if gs_matches:
                logger.debug('  GOODSIG')
                self.good = True
                keyid = gs_matches.groups()[0]
                self.attestor = LoreAttestor(keyid)
                puid = '%s <%s>' % self.attestor.get_primary_uid()
                vs_matches = re.search(r'^\[GNUPG:\] VALIDSIG ([0-9A-F]+) (\d{4}-\d{2}-\d{2}) (\d+)', output, re.M)
                if vs_matches:
                    logger.debug('  VALIDSIG')
                    self.valid = True
                    ymd = vs_matches.groups()[1]
                    self.sigdate = datetime.datetime.strptime(ymd, '%Y-%m-%d')
                    # Do we have a TRUST_(FULLY|ULTIMATE)?
                    ts_matches = re.search(r'^\[GNUPG:\] TRUST_(FULLY|ULTIMATE)', output, re.M)
                    if ts_matches:
                        logger.debug('  TRUST_%s', ts_matches.groups()[0])
                        self.trusted = True
                    else:
                        self.errors.add('Insufficient trust (model=%s): %s (%s)'
                                        % (config['attestation-trust-model'], keyid, puid))
                else:
                    self.errors.add('Signature not valid from key: %s (%s)' % (keyid, puid))
        else:
            # Are we missing a key?
            matches = re.search(r'^\[GNUPG:\] NO_PUBKEY ([0-9A-F]+)$', output, re.M)
            if matches:
                self.errors.add('Missing public key: %s' % matches.groups()[0])
            else:
                logger.debug('NOGOOD: Signature on %s failed to verify', self.source)
            return

        if self.good and self.valid and self.trusted:
            self.passing = True

        if source.find('http') == 0:
            # We only cache known-good attestations obtained from remote
            cachedir = get_cache_dir()
            cachename = '%s.attestation' % urllib.parse.quote_plus(source.strip('/').split('/')[-1])
            fullpath = os.path.join(cachedir, cachename)
            with open(fullpath, 'w') as fh:
                logger.debug('Saved attestation in cache: %s', cachename)
                fh.write(sigdata)

        hg = [None, None, None]
        for line in sigdata.split('\n'):
            # It's a yaml document, but we don't parse it as yaml for safety reasons
            line = line.rstrip()
            if re.search(r'^([0-9a-f-]{26}:|-----BEGIN.*)$', line):
                if None not in hg:
                    self.hashes.add(tuple(hg))
                    hg = [None, None, None]
                continue
            matches = re.search(r'^\s+([imp]):\s*([0-9a-f]{64})$', line)
            if matches:
                t, v = matches.groups()
                if t == 'i':
                    hg[0] = v
                elif t == 'm':
                    hg[1] = v
                elif t == 'p':
                    hg[2] = v

    def __repr__(self):
        out = list()
        out.append('  source: %s' % self.source)
        out.append('  good: %s' % self.good)
        out.append('  valid: %s' % self.valid)
        out.append('  trusted: %s' % self.trusted)
        if self.attestor is not None:
            out.append('  attestor: %s' % self.attestor.keyid)

        out.append('  --- validation errors ---')
        for error in self.errors:
            out.append('  | %s' % error)
        out.append('  --- hashes ---')
        for hg in self.hashes:
            out.append('  | %s-%s-%s' % (hg[0][:8], hg[1][:8], hg[2][:8]))
        return '\n'.join(out)

    @staticmethod
    def get_from_cache(attid):
        cachedir = get_cache_dir()
        attdocs = list()
        for entry in os.listdir(cachedir):
            if entry.find('.attestation') <= 0:
                continue
            fullpath = os.path.join(cachedir, entry)
            with open(fullpath, 'r') as fh:
                content = fh.read()
                # Can't be 0, because it has to have pgp ascii wrapper
                if content.find(attid) > 0:
                    attdoc = LoreAttestationDocument(fullpath, content)
                    attdocs.append(attdoc)
        return attdocs

    @staticmethod
    def get_from_lore(attid):
        attdocs = list()
        # XXX: Querying this via the Atom feed is a temporary kludge until we have
        #      proper search API on lore.kernel.org
        cachedir = get_cache_dir()
        cachefile = os.path.join(cachedir, '%s.lookup' % urllib.parse.quote_plus(attid))
        status = None
        if os.path.exists(cachefile):
            with open(cachefile, 'r') as fh:
                try:
                    status = int(fh.read())
                except ValueError:
                    pass
        if status is not None and status != 200:
            logger.debug('Cache says looking up %s = %s', attid, status)
            return attdocs

        config = get_main_config()
        queryurl = '%s?%s' % (config['attestation-query-url'],
                              urllib.parse.urlencode({'q': attid, 'x': 'A', 'o': '-1'}))
        logger.debug('Query URL: %s', queryurl)
        session = get_requests_session()
        resp = session.get(queryurl)
        if resp.status_code != 200:
            # Record this as a bad hit
            with open(cachefile, 'w') as fh:
                fh.write(str(resp.status_code))

        matches = re.findall(
            r'link\s+href="([^"]+)".*?(-----BEGIN PGP SIGNED MESSAGE-----.*?-----END PGP SIGNATURE-----)',
            resp.content.decode('utf-8'), flags=re.DOTALL
        )

        if matches:
            for link, sigdata in matches:
                attdoc = LoreAttestationDocument(link, sigdata)
                attdocs.append(attdoc)

        return attdocs

    @staticmethod
    def load_from_file(afile):
        global ATTESTATIONS
        with open(afile, 'r') as fh:
            sigdata = fh.read()
            ATTESTATIONS.append(LoreAttestationDocument(afile, sigdata))

    @staticmethod
    def load_from_string(source, content):
        global ATTESTATIONS
        ATTESTATIONS.append(LoreAttestationDocument(source, content))


class LoreAttestation:
    def __init__(self, i, m, p):
        self.attid = '%s-%s-%s' % (i[:8], m[:8], p[:8])
        self.i = i
        self.m = m
        self.p = p
        self.passing = False
        self.attdocs = list()

    def _check_if_passing(self):
        global ATTESTATIONS
        hg = (self.i, self.m, self.p)
        for attdoc in ATTESTATIONS:
            if hg in attdoc.hashes and attdoc.passing:
                self.passing = True
                self.attdocs.append(attdoc)

    def validate(self, lore_lookup=True):
        global ATTESTATIONS
        self._check_if_passing()

        if not len(self.attdocs):
            attdocs = LoreAttestationDocument.get_from_cache(self.attid)
            ATTESTATIONS += attdocs
            self._check_if_passing()

        if not len(self.attdocs) and lore_lookup:
            attdocs = LoreAttestationDocument.get_from_lore(self.attid)
            ATTESTATIONS += attdocs
            self._check_if_passing()

    def __repr__(self):
        out = list()
        out.append('  attid: %s' % self.attid)
        out.append('    i: %s' % self.i)
        out.append('    m: %s' % self.m)
        out.append('    p: %s' % self.p)
        out.append('  --- attdocs ---')
        for attdoc in self.attdocs:
            out.append(str(attdoc))
        return '\n'.join(out)


def _run_command(cmdargs, stdin=None, logstderr=False):
    logger.debug('Running %s' % ' '.join(cmdargs))

    sp = subprocess.Popen(cmdargs,
                          stdout=subprocess.PIPE,
                          stdin=subprocess.PIPE,
                          stderr=subprocess.PIPE)

    (output, error) = sp.communicate(input=stdin)

    output = output.decode('utf-8', errors='replace')

    if logstderr and len(error.strip()):
        logger.debug('Stderr: %s', error.decode('utf-8', errors='replace'))

    return sp.returncode, output


def gpg_run_command(args, stdin=None, logstderr=False):
    config = get_main_config()
    cmdargs = [config['gpgbin'], '--batch', '--no-auto-key-retrieve', '--no-auto-check-trustdb']
    if config['attestation-gnupghome'] is not None:
        cmdargs += ['--homedir', config['attestation-gnupghome']]
    cmdargs += args

    return _run_command(cmdargs, stdin=stdin, logstderr=logstderr)


def git_run_command(gitdir, args, stdin=None, logstderr=False):
    cmdargs = ['git', '--no-pager']
    if gitdir:
        cmdargs += ['--git-dir', gitdir]
    cmdargs += args

    return _run_command(cmdargs, stdin=stdin, logstderr=logstderr)


def git_get_command_lines(gitdir, args):
    ecode, out = git_run_command(gitdir, args)
    lines = list()
    if out:
        for line in out.split('\n'):
            if line == '':
                continue
            lines.append(line)

    return lines


def get_config_from_git(regexp, defaults=None):
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
            cfgkey = chunks[-1]
            gitconfig[cfgkey.lower()] = value
        except ValueError:
            logger.debug('Ignoring git config entry %s', line)

    return gitconfig


def get_main_config():
    global MAIN_CONFIG
    if MAIN_CONFIG is None:
        config = get_config_from_git(r'b4\..*', defaults=DEFAULT_CONFIG)
        # Legacy name was get-lore-mbox, so load those as well
        config = get_config_from_git(r'get-lore-mbox\..*', defaults=config)
        config['trailer-order'] = config['trailer-order'].split(',')
        if config['gpgbin'] is None:
            gpgcfg = get_config_from_git(r'gpg\..*', {'program': 'gpg'})
            config['gpgbin'] = gpgcfg['program']
        MAIN_CONFIG = config
    return MAIN_CONFIG


def get_cache_dir():
    global _CACHE_CLEANED
    if 'XDG_CACHE_HOME' in os.environ:
        cachehome = os.environ['XDG_CACHE_HOME']
    else:
        cachehome = os.path.join(str(Path.home()), '.cache')
    cachedir = os.path.join(cachehome, 'b4')
    Path(cachedir).mkdir(parents=True, exist_ok=True)
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
        if entry.find('.mbx') <= 0 and entry.find('.lookup') <= 0:
            continue
        st = os.stat(os.path.join(cachedir, entry))
        if st.st_mtime < expage:
            logger.debug('Cleaning up cache: %s', entry)
            os.unlink(os.path.join(cachedir, entry))
    _CACHE_CLEANED = True
    return cachedir


def get_user_config():
    global USER_CONFIG
    if USER_CONFIG is None:
        USER_CONFIG = get_config_from_git(r'user\..*')
    return USER_CONFIG


def get_requests_session():
    global REQSESSION
    if REQSESSION is None:
        REQSESSION = requests.session()
        REQSESSION.headers.update({'User-Agent': 'b4/%s' % __VERSION__})
    return REQSESSION


def save_strict_thread(in_mbx, out_mbx, msgid):
    want = {msgid}
    got = set()
    seen = set()
    while True:
        for msg in in_mbx:
            c_msgid = LoreMessage.get_clean_msgid(msg)
            seen.add(c_msgid)
            if c_msgid in got:
                continue

            refs = list()
            for ref in msg.get('References', msg.get('In-Reply-To', '')).split():
                ref = ref.strip().strip('<>')
                if ref in got or ref in want:
                    want.add(c_msgid)
                elif len(ref):
                    refs.append(ref)

            if c_msgid in want:
                out_mbx.add(msg)
                got.add(c_msgid)
                want.update(refs)
                want.discard(c_msgid)
                logger.debug('Kept in thread: %s', c_msgid)

        # Remove any entries not in "seen" (missing messages)
        for c_msgid in set(want):
            if c_msgid not in seen:
                want.remove(c_msgid)
        if not len(want):
            break

    if not len(out_mbx):
        return None

    if len(in_mbx) > len(out_mbx):
        logger.info('Reduced thread to strict matches only (%s->%s)', len(in_mbx), len(out_mbx))
