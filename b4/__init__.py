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
import requests
import urllib.parse
import datetime
import time
import shutil
import mailbox
import pwd
import base64

from pathlib import Path
from tempfile import mkstemp, TemporaryDirectory
from contextlib import contextmanager

from email import charset
charset.add_charset('utf-8', None)
emlpolicy = email.policy.EmailPolicy(utf8=True, cte_type='8bit', max_line_length=None)

try:
    import dns.resolver
    import dkim

    can_dkim_verify = True
    _resolver = dns.resolver.get_default_resolver()
except ModuleNotFoundError:
    can_dkim_verify = False
    _resolver = None

__VERSION__ = '0.6.2'

logger = logging.getLogger('b4')

HUNK_RE = re.compile(r'^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@')
FILENAME_RE = re.compile(r'^(---|\+\+\+) (\S+)')

PASS_SIMPLE = '[P]'
WEAK_SIMPLE = '[D]'
FAIL_SIMPLE = '[F]'
PASS_FANCY = '\033[32m\u2714\033[0m'
WEAK_FANCY = '\033[32m\u2713\033[0m'
FAIL_FANCY = '\033[31m\u2717\033[0m'

HDR_PATCH_HASHES = 'X-Patch-Hashes'
HDR_PATCH_SIG = 'X-Patch-Sig'

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

# Used for tracking attestations we have already looked up
ATTESTATIONS = list()
# Used for keeping a cache of subkey lookups to minimize shelling out to gpg
SUBKEY_DATA = dict()
# Used for storing our requests session
REQSESSION = None
# Indicates that we've cleaned cache already
_CACHE_CLEANED = False
# Used for dkim key lookups
_DKIM_DNS_CACHE = dict()


class LoreMailbox:
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
        cachedir = get_cache_dir()
        listmap = os.path.join(cachedir, 'lists.map.lookup')
        if not os.path.exists(listmap):
            # lists.map is a custom service running on lore.kernel.org, so it is
            # meaningless to make this a configurable URL
            session = get_requests_session()
            resp = session.get('https://lore.kernel.org/lists.map')
            if resp.status_code != 200:
                logger.debug('Unable to retrieve lore.kernel.org/lists.map')
                return
            content = resp.content.decode('utf-8')
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

        allto = email.utils.getaddresses([str(x) for x in patch.msg.get_all('to', [])])
        allto += email.utils.getaddresses([str(x) for x in patch.msg.get_all('cc', [])])
        listarc = patch.msg.get_all('list-archive', [])
        for entry in allto:
            if entry[1] in projmap:
                projurl = 'https://lore.kernel.org/%s/' % projmap[entry[1]]
                # Make sure we don't re-query the same project we just used
                reused = False
                for arcurl in listarc:
                    if projurl in arcurl:
                        reused = True
                        break
                if reused:
                    continue
                # Try to backfill from that project
                tmp_mbox = mkstemp('b4-backfill-mbox')[1]
                get_pi_thread_by_msgid(patch.msgid, tmp_mbox, useproject=projmap[entry[1]])
                mbx = mailbox.mbox(tmp_mbox)
                was = len(self.msgid_map)
                for msg in mbx:
                    self.add_message(msg)
                mbx.close()
                os.unlink(tmp_mbox)
                if len(self.msgid_map) > was:
                    logger.info('Loaded %s messages from %s', len(self.msgid_map)-was, projurl)
                if self.series[revision].complete:
                    logger.info('Successfully backfilled missing patches')
                    break

    def get_series(self, revision=None, sloppytrailers=False, backfill=True):
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

        if not lser.complete and backfill:
            self.backfill(revision)

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
                        # previous revisions to current revision if patch/metadata did
                        # not change
                        pmsg.load_hashes()
                        if pmsg.attestation:
                            attid = pmsg.attestation.attid
                            if attid not in self.trailer_map:
                                self.trailer_map[attid] = list()
                            self.trailer_map[attid] += trailers
                    pmsg.followup_trailers += trailers
                    break
                if not pmsg.reply:
                    # Could be a cover letter
                    pmsg.followup_trailers += trailers
                    break
                if pmsg.in_reply_to and pmsg.in_reply_to in self.msgid_map:
                    lvl += 1
                    trailers += pmsg.trailers
                    pmsg = self.msgid_map[pmsg.in_reply_to]
                    continue
                break

        # Carry over trailers from previous series if patch/metadata did not change
        for lmsg in lser.patches:
            if lmsg is None or lmsg.attestation is None:
                continue
            lmsg.load_hashes()
            if lmsg.attestation.attid in self.trailer_map:
                lmsg.followup_trailers += self.trailer_map[lmsg.attestation.attid]

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
        self.subject = '(untitled)'

    def __repr__(self):
        out = list()
        out.append('- Series: [v%s] %s' % (self.revision, self.subject))
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

    def save_am_mbox(self, mbx, noaddtrailers=False, covertrailers=False, trailer_order=None, addmysob=False,
                     addlink=False, linkmask=None, cherrypick=None, copyccs=False):

        usercfg = get_user_config()
        config = get_main_config()

        if addmysob:
            if 'name' not in usercfg or 'email' not in usercfg:
                logger.critical('WARNING: Unable to add your Signed-off-by: git returned no user.name or user.email')
                addmysob = False

        attdata = [(None, None)] * len(self.patches[1:])
        attpolicy = config['attestation-policy']

        if config['attestation-checkmarks'] == 'fancy':
            attpass = PASS_FANCY
            attfail = FAIL_FANCY
            attweak = WEAK_FANCY
        else:
            attpass = PASS_SIMPLE
            attfail = FAIL_SIMPLE
            attweak = WEAK_SIMPLE

        at = 1
        atterrors = list()
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

                if attpolicy != 'off':
                    lmsg.load_hashes()
                    latt = lmsg.attestation
                    if latt and latt.validate(lmsg.msg):
                        if latt.lsig.attestor and latt.lsig.attestor.mode == 'domain':
                            logger.info('  %s %s', attweak, lmsg.full_subject)
                            attdata[at-1] = (latt.lsig.attestor.get_trailer(lmsg.fromemail), attweak) # noqa
                        else:
                            logger.info('  %s %s', attpass, lmsg.full_subject)
                            attdata[at-1] = (latt.lsig.attestor.get_trailer(lmsg.fromemail), attpass) # noqa
                    else:
                        if latt and latt.lsig and attpolicy in ('softfail', 'hardfail'):
                            logger.info('  %s %s', attfail, lmsg.full_subject)
                            if latt and latt.lsig and latt.lsig.attestor and latt.lsig.attestor.mode == 'domain':
                                atterrors.append('Failed %s attestation' % latt.lsig.attestor.get_trailer())
                            elif latt and latt.lsig and latt.lsig.attestor:
                                failed = list()
                                if not latt.pv:
                                    failed.append('patch content')
                                if not latt.mv:
                                    failed.append('commit message')
                                if not latt.iv:
                                    failed.append('patch metadata')
                                atterrors.append('Patch %s/%s failed attestation (%s)' % (at, lmsg.expected,
                                                                                          ', '.join(failed)))
                        else:
                            logger.info('  %s', lmsg.full_subject)
                else:
                    logger.info('  %s', lmsg.full_subject)

                add_trailers = True
                if noaddtrailers:
                    add_trailers = False
                msg = lmsg.get_am_message(add_trailers=add_trailers, trailer_order=trailer_order, copyccs=copyccs)
                # Pass a policy that avoids most legacy encoding horrors
                mbx.add(msg.as_bytes(policy=emlpolicy))
            else:
                logger.error('  ERROR: missing [%s/%s]!', at, self.expected)
            at += 1

        if attpolicy == 'off':
            return mbx

        failed = (None, None) in attdata
        if not failed:
            logger.info('  ---')
            for trailer, attmode in set(attdata):
                logger.info('  %s Attestation-by: %s', attmode, trailer)
            return mbx
        elif not can_dkim_verify and config.get('attestation-check-dkim') == 'yes':
            logger.info('  ---')
            logger.info('  NOTE: install dkimpy for DKIM signature verification')

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
                    gitdir = os.path.join(gitdir, '.git')
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
        if cachedata:
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
                lmsg.load_hashes()
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

        self.attestation = None
        # Patchwork hash
        self.pwhash = None
        # Git patch-id
        self.git_patch_id = None
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

        # We only pay attention to trailers that are sent in reply
        if self.reply:
            trailers, others = LoreMessage.find_trailers(self.body, followup=True)
            for trailer in trailers:
                # These are commonly part of patch/commit metadata
                badtrailers = ('from', 'author', 'cc', 'to')
                if trailer[0].lower() not in badtrailers:
                    self.trailers.append(trailer)

    def get_trailers(self, sloppy=False):
        mismatches = set()
        if sloppy:
            return self.trailers, mismatches

        trailers = list()
        for tname, tvalue, extdata in self.trailers:
            if tname.lower() in ('fixes',):
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
        if hdrval is None:
            return ''

        decoded = ''
        for hstr, hcs in email.header.decode_header(hdrval):
            if hcs is None:
                hcs = 'utf-8'
            try:
                decoded += hstr.decode(hcs)
            except LookupError:
                # Try as utf-u
                decoded += hstr.decode('utf-8', errors='replace')
            except (UnicodeDecodeError, AttributeError):
                decoded += hstr
        new_hdrval = re.sub(r'\n?\s+', ' ', decoded)
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
    def get_patchwork_hash(diff):
        # Make sure we just have the diff without any extraneous content.
        diff = LoreMessage.get_clean_diff(diff)
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
    def get_indexes(diff):
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
    def get_clean_diff(diff):
        diff = diff.replace('\r', '')

        # For keeping a buffer of lines preceding @@ ... @@
        buflines = list()
        difflines = ''

        # Used for counting where we are in the patch
        pp = mm = 0
        inside_binary_chunk = False
        for line in diff.split('\n'):
            if not len(line):
                if inside_binary_chunk:
                    inside_binary_chunk = False
                    # add all buflines to difflines
                    difflines += '\n'.join(buflines) + '\n\n'
                    buflines = list()
                    continue
                buflines.append(line)
                continue
            elif inside_binary_chunk:
                buflines.append(line)
                continue
            # If line starts with 'index ' and previous line starts with 'deleted ', then
            # it's a file delete and therefore doesn't have a regular hunk.
            if line.find('index ') == 0 and len(buflines) > 1 and buflines[-1].find('deleted ') == 0:
                # add this and 2 preceding lines to difflines and reset buflines
                buflines.append(line)
                difflines += '\n'.join(buflines[-3:]) + '\n'
                buflines = list()
                continue
            if line.find('delta ') == 0 or line.find('literal ') == 0:
                # we are inside a binary patch
                inside_binary_chunk = True
                buflines.append(line)
                continue
            hunk_match = HUNK_RE.match(line)
            if hunk_match:
                # logger.debug('Crunching %s', line)
                mlines, plines = hunk_match.groups()
                try:
                    pp = int(plines)
                except TypeError:
                    pp = 1
                try:
                    mm = int(mlines)
                except TypeError:
                    mm = 1
                addlines = list()
                for bline in reversed(buflines):
                    # Go backward and add lines until we get to the start
                    # or encounter a blank line
                    if len(bline.strip()) == 0:
                        break
                    addlines.append(bline)
                if addlines:
                    difflines += '\n'.join(reversed(addlines)) + '\n'
                buflines = list()
                # Feed this line to the hasher
                difflines += line + '\n'
                continue
            if pp > 0 or mm > 0:
                # Inside the patch
                difflines += line + '\n'
                if line[0] in (' ', '-'):
                    mm -= 1
                if line[0] in (' ', '+'):
                    pp -= 1
                continue
            # Not anything we recognize, so stick into buflines
            buflines.append(line)
        return difflines

    def load_hashes(self):
        if self.attestation is not None:
            return
        logger.debug('Calculating hashes for: %s', self.full_subject)
        # Calculate git-patch-id first
        cmdargs = ['patch-id', '--stable']
        msg = self.get_am_message(add_trailers=False)
        stdin = msg.as_string(policy=emlpolicy).encode()
        ecode, out = git_run_command(None, cmdargs, stdin)
        if ecode > 0:
            # Git doesn't think there's a patch there
            return
        fline = out.split('\n')[0]
        if len(fline) >= 40:
            self.git_patch_id = fline[:40]

        msg_out = mkstemp()
        patch_out = mkstemp()
        cmdargs = ['mailinfo', '--encoding=UTF-8', msg_out[1], patch_out[1]]
        ecode, info = git_run_command(None, cmdargs, stdin)
        if ecode > 0:
            logger.debug('ERROR: Could not get mailinfo')
            return
        i = hashlib.sha256()
        m = hashlib.sha256()
        p = hashlib.sha256()

        for line in info.split('\n'):
            # We don't use the "Date:" field because it is likely to be
            # mangled between when git-format-patch generates it and
            # when it is sent out by git-send-email (or other tools).
            if re.search(r'^(Author|Email|Subject):', line):
                i.update((line + '\n').encode())

        with open(msg_out[1], 'rb') as mfh:
            msg = mfh.read()
            m.update(msg)
        os.unlink(msg_out[1])

        with open(patch_out[1], 'rb') as pfh:
            patch = pfh.read().decode(self.charset, errors='replace')
            if len(patch.strip()):
                diff = LoreMessage.get_clean_diff(patch)
                p.update(diff.encode())
                self.pwhash = LoreMessage.get_patchwork_hash(patch)
                # Load the indexes, if we have them
                self.blob_indexes = LoreMessage.get_indexes(diff)
            else:
                p = None

        os.unlink(patch_out[1])

        if i and m and p:
            self.attestation = LoreAttestation(i, m, p)

    @staticmethod
    def find_trailers(body, followup=False):
        headers = ('subject', 'date', 'from')
        nonperson = ('fixes', 'subject', 'date', 'link', 'buglink')
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

        if config['attestation-checkmarks'] == 'fancy':
            attfail = FAIL_FANCY
            attweak = WEAK_FANCY
        else:
            attfail = FAIL_SIMPLE
            attweak = WEAK_SIMPLE

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
                        if can_dkim_verify and config.get('attestation-check-dkim') == 'yes' and attpolicy != 'off':
                            if len(trailer) > 3 and trailer[3] is not None:
                                fmsg = trailer[3]
                                attsig = LoreAttestationSignatureDKIM(fmsg.msg)  # noqa
                                if attsig.present:
                                    if attsig.passing:
                                        extra = ' (%s %s)' % (attweak, attsig.attestor.get_trailer())
                                    elif attpolicy in ('softfail', 'hardfail'):
                                        extra = ' (%s %s)' % (attfail, attsig.attestor.get_trailer())
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

    def get_am_message(self, add_trailers=True, trailer_order=None, copyccs=False):
        if add_trailers:
            self.fix_trailers(trailer_order=trailer_order, copyccs=copyccs)
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
            subject = re.sub(r'^\s*\[[^]]*]\s*(\[[^]]*(:?patch|resend|rfc).*)', r'\1', subject, flags=re.IGNORECASE)
            if oldsubj == subject:
                break

        # Remove any brackets inside brackets
        while True:
            oldsubj = subject
            subject = re.sub(r'^\s*\[([^]]*)\[([^\[\]]*)]', r'[\1\2]', subject)
            subject = re.sub(r'^\s*\[([^]]*)]([^\[\]]*)]', r'[\1\2]', subject)
            if oldsubj == subject:
                break

        self.full_subject = subject
        # Is it a reply?
        if re.search(r'^(Re|Aw|Fwd):', subject, re.I) or re.search(r'^\w{2,3}:\s*\[', subject):
            self.reply = True
            subject = re.sub(r'^\w+:\s*\[', '[', subject)

        # Fix [PATCHv3] to be properly [PATCH v3]
        subject = re.sub(r'^\[\s*(patch)(v\d+)(.*)', r'[\1 \2\3', subject, flags=re.I)

        # Find all [foo] in the title
        while subject.find('[') == 0:
            matches = re.search(r'^\[([^]]*)]', subject)
            if not matches:
                break
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
            subject = re.sub(r'^\s*\[[^]]*]\s*', '', subject)
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

    def __repr__(self):
        out = list()
        out.append('  keyid: %s' % self.keyid)
        for uid in self.uids:
            out.append('    uid: %s <%s>' % uid)
        return '\n'.join(out)


class LoreAttestorDKIM(LoreAttestor):
    def __init__(self, keyid):
        self.mode = 'domain'
        super().__init__(keyid)

    def get_trailer(self, fromaddr=None): # noqa
        if fromaddr:
            return 'DKIM/%s (From: %s)' % (self.keyid, fromaddr)
        return 'DKIM/%s' % self.keyid


class LoreAttestorPGP(LoreAttestor):
    def __init__(self, keyid):
        super().__init__(keyid)
        self.mode = 'person'
        self.load_subkey_uids()

    def load_subkey_uids(self):
        global SUBKEY_DATA
        if self.keyid not in SUBKEY_DATA:
            gpgargs = ['--with-colons', '--list-keys', self.keyid]
            ecode, out, err = gpg_run_command(gpgargs)
            if ecode > 0:
                logger.critical('ERROR: Unable to get UIDs list matching key %s', self.keyid)
                return

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

        return '%s <%s> (pgp: %s)' % (uid[0], uid[1], self.keyid)


class LoreAttestationSignature:
    def __init__(self, msg):
        self.msg = msg
        self.mode = None
        self.present = False
        self.good = False
        self.valid = False
        self.trusted = False
        self.passing = False
        self.sigdate = None
        self.attestor = None
        self.errors = set()

        config = get_main_config()
        try:
            driftd = int(config['attestation-staleness-days'])
        except ValueError:
            driftd = 30

        self.maxdrift = datetime.timedelta(days=driftd)

    def verify_time_drift(self) -> None:
        msgdt = email.utils.parsedate_to_datetime(str(self.msg['Date']))
        sdrift = self.sigdate - msgdt
        if sdrift > self.maxdrift:
            self.passing = False
            self.errors.add('Time drift between Date and t too great (%s)' % sdrift)
            return
        logger.debug('PASS : time drift between Date and t (%s)', sdrift)

    def verify_identity_domain(self, identity: str, domain: str):
        # Domain is supposed to be present in identity
        if not identity.endswith(domain):
            logger.debug('domain (d=%s) is not in identity (i=%s)', domain, identity)
            self.passing = False
            return
        fromeml = email.utils.getaddresses(self.msg.get_all('from', []))[0][1]
        if identity.find('@') < 0:
            logger.debug('identity must contain @ (i=%s)', identity)
            self.passing = False
            return
        ilocal, idomain = identity.split('@')
        # identity is supposed to be present in from
        if not fromeml.endswith(f'@{idomain}'):
            self.errors.add('identity (i=%s) does not match from (from=%s)' % (identity, fromeml))
            self.passing = False
            return
        logger.debug('identity and domain match From header')

    # @staticmethod
    # def get_dkim_key(domain: str, selector: str, timeout: int = 5) -> Tuple[str, str]:
    #     global DNSCACHE
    #     if (domain, selector) in DNSCACHE:
    #         return DNSCACHE[(domain, selector)]
    #
    #     name = f'{selector}._domainkey.{domain}.'
    #     logger.debug('DNS-lookup: %s', name)
    #     keydata = None
    #     try:
    #         a = dns.resolver.resolve(name, dns.rdatatype.TXT, raise_on_no_answer=False, lifetime=timeout) # noqa
    #         # Find v=DKIM1
    #         for r in a.response.answer:
    #             if r.rdtype == dns.rdatatype.TXT:
    #                 for item in r.items:
    #                     # Concatenate all strings
    #                     txtdata = b''.join(item.strings)
    #                     if txtdata.find(b'v=DKIM1') >= 0:
    #                         keydata = txtdata.decode()
    #                         break
    #             if keydata:
    #                 break
    #     except dns.resolver.NXDOMAIN: # noqa
    #         raise LookupError('Domain %s does not exist', name)
    #
    #     if not keydata:
    #         raise LookupError('Domain %s does not contain a DKIM record', name)
    #
    #     parts = get_parts_from_header(keydata)
    #     if 'p' not in parts:
    #         raise LookupError('Domain %s does not contain a DKIM key', name)
    #     if 'k' not in parts:
    #         raise LookupError('Domain %s does not indicate key time', name)
    #
    #     DNSCACHE[(domain, selector)] = (parts['k'], parts['p'])
    #     logger.debug('k=%s, p=%s', parts['k'], parts['p'])
    #     return parts['k'], parts['p']

    def __repr__(self):
        out = list()
        out.append('   mode: %s' % self.mode)
        out.append('present: %s' % self.present)
        out.append('   good: %s' % self.good)
        out.append('  valid: %s' % self.valid)
        out.append('trusted: %s' % self.trusted)
        if self.attestor is not None:
            out.append('  attestor: %s' % self.attestor.keyid)

        out.append('  --- validation errors ---')
        for error in self.errors:
            out.append('  | %s' % error)
        return '\n'.join(out)


class LoreAttestationSignatureDKIM(LoreAttestationSignature):
    def __init__(self, msg):
        super().__init__(msg)
        self.mode = 'dkim'
        # Doesn't quite work right, so just use dkimpy's native
        # self.native_verify()
        # return

        ejected = set()
        while True:
            dks = self.msg.get('dkim-signature')
            if not dks:
                logger.debug('No DKIM-Signature headers in the message')
                return

            self.present = True

            ddata = get_parts_from_header(dks)
            self.attestor = LoreAttestorDKIM(ddata['d'])
            # Do we have a resolve method?
            if _resolver and hasattr(_resolver, 'resolve'):
                res = dkim.verify(self.msg.as_bytes(), dnsfunc=dkim_get_txt)
            else:
                res = dkim.verify(self.msg.as_bytes())
            if not res:
                # is list-archive or archived-at part of h=?
                hline = ddata.get('h')
                if hline:
                    hsigned = set(hline.lower().split(':'))
                    if 'list-archive' in hsigned or 'archived-at' in hsigned:
                        # Public-inbox inserts additional List-Archive and Archived-At headers,
                        # which breaks DKIM signatures if these headers are included in the hash.
                        # Eject the ones created by public-inbox and try again.
                        # XXX: This may no longer be necessary at some point if public-inbox takes care
                        #      of this scenario automatically:
                        #      https://public-inbox.org/meta/20201210202145.7agtcmrtl5jec42d@chatter.i7.local
                        logger.debug('Ejecting extra List-Archive headers and retrying')
                        changed = False
                        for header in reversed(self.msg._headers):  # noqa
                            hl = header[0].lower()
                            if hl in ('list-archive', 'archived-at') and hl not in ejected:
                                self.msg._headers.remove(header)  # noqa
                                ejected.add(hl)
                                changed = True
                                break
                        if changed:
                            # go for another round
                            continue

                logger.debug('DKIM signature did NOT verify')
                logger.debug('Retrying with the next DKIM-Signature header, if any')
                at = 0
                for header in self.msg._headers:  # noqa
                    if header[0].lower() == 'dkim-signature':
                        del(self.msg._headers[at])  # noqa
                        break
                    at += 1
                continue

            self.good = True

            # Grab toplevel signature that we just verified
            self.valid = True
            self.trusted = True
            self.passing = True

            if ddata.get('t'):
                self.sigdate = datetime.datetime.utcfromtimestamp(int(ddata['t'])).replace(tzinfo=datetime.timezone.utc)
            else:
                self.sigdate = email.utils.parsedate_to_datetime(str(self.msg['Date']))
            return

    # def native_verify(self):
    #     dks = self.msg.get('dkim-signature')
    #     ddata = get_parts_from_header(dks)
    #     try:
    #         kt, kp = LoreAttestationSignature.get_dkim_key(ddata['d'], ddata['s'])
    #         if kt not in ('rsa',):  # 'ed25519'):
    #             logger.debug('DKIM key type %s not supported', kt)
    #             return
    #         pk = base64.b64decode(kp)
    #         sig = base64.b64decode(ddata['b'])
    #     except (LookupError, binascii.Error) as ex:
    #         logger.debug('Unable to look up DKIM key: %s', ex)
    #         return
    #
    #     headers = list()
    #
    #     for header in ddata['h'].split(':'):
    #         # For the POC, we assume 'relaxed/'
    #         hval = self.msg.get(header)
    #         if hval is None:
    #             # Missing headers are omitted by the DKIM RFC
    #             continue
    #         if ddata['c'].startswith('relaxed/'):
    #             hname, hval = dkim_canonicalize_header(header, str(self.msg.get(header)))
    #         else:
    #             hname = header
    #             hval = str(self.msg.get(header))
    #         headers.append(f'{hname}:{hval}')
    #
    #     # Now we add the dkim-signature header itself, without b= content
    #     if ddata['c'].startswith('relaxed/'):
    #         dname, dval = dkim_canonicalize_header('dkim-signature', dks)
    #     else:
    #         dname = 'DKIM-Signature'
    #         dval = dks
    #
    #     dval = dval.rsplit('; b=')[0] + '; b='
    #     headers.append(f'{dname}:{dval}')
    #     payload = ('\r\n'.join(headers)).encode()
    #     key = RSA.import_key(pk)
    #     hashed = SHA256.new(payload)
    #     try:
    #         # noinspection PyTypeChecker
    #         pkcs1_15.new(key).verify(hashed, sig)
    #     except (ValueError, TypeError):
    #         logger.debug('DKIM signature did not verify')
    #         self.errors.add('The DKIM signature did NOT verify!')
    #         return
    #
    #     self.good = True
    #     if not ddata.get('i'):
    #         ddata['i'] = '@' + ddata['d']
    #
    #     logger.debug('PASS : DKIM signature for d=%s, s=%s', ddata['d'], ddata['s'])
    #
    #     self.attestor = LoreAttestorDKIM(ddata['d'])
    #     self.valid = True
    #     self.trusted = True
    #     self.passing = True
    #
    #     self.verify_identity_domain(ddata['i'], ddata['d'])
    #     if ddata.get('t'):
    #         self.sigdate = datetime.datetime.utcfromtimestamp(int(ddata['t'])).replace(tzinfo=datetime.timezone.utc)
    #         self.verify_time_drift()
    #     else:
    #         self.sigdate = email.utils.parsedate_to_datetime(str(self.msg['Date']))


class LoreAttestationSignaturePGP(LoreAttestationSignature):
    def __init__(self, msg):
        super().__init__(msg)
        self.mode = 'pgp'

        shdr = msg.get(HDR_PATCH_SIG)
        if not shdr:
            return

        self.present = True
        sdata = get_parts_from_header(shdr)
        hhdr = msg.get(HDR_PATCH_HASHES)
        sig = base64.b64decode(sdata['b'])
        headers = list()
        hhname, hhval = dkim_canonicalize_header(HDR_PATCH_HASHES, str(hhdr))
        headers.append(f'{hhname}:{hhval}')
        # Now we add the sig header itself, without b= content
        shname, shval = dkim_canonicalize_header(HDR_PATCH_SIG, shdr)
        shval = shval.rsplit('; b=')[0] + '; b='
        headers.append(f'{shname}:{shval}')
        payload = ('\r\n'.join(headers)).encode()
        savefile = mkstemp('in-header-pgp-verify')[1]
        with open(savefile, 'wb') as fh:
            fh.write(sig)

        gpgargs = list()
        config = get_main_config()
        trustmodel = config.get('attestation-trust-model', 'tofu')
        if trustmodel == 'tofu':
            gpgargs += ['--trust-model', 'tofu', '--tofu-default-policy', 'good']
        gpgargs += ['--verify', '--status-fd=1', savefile, '-']
        ecode, out, err = gpg_run_command(gpgargs, stdin=payload)
        os.unlink(savefile)
        output = out.decode()

        self.good, self.valid, self.trusted, self.attestor, self.sigdate, self.errors = \
            validate_gpg_signature(output, trustmodel)

        if self.good and self.valid and self.trusted:
            self.passing = True
            self.verify_time_drift()
            # XXX: Need to verify identity domain


class LoreAttestation:
    def __init__(self, _i, _m, _p):
        self.i = _i.hexdigest()
        self.m = _m.hexdigest()
        self.p = _p.hexdigest()
        self.ib = base64.b64encode(_i.digest()).decode()
        self.mb = base64.b64encode(_m.digest()).decode()
        self.pb = base64.b64encode(_p.digest()).decode()

        self.lsig = None
        self.passing = False
        self.iv = False
        self.mv = False
        self.pv = False

    @property
    def attid(self):
        return '%s-%s-%s' % (self.i[:8], self.m[:8], self.p[:8])

    def __repr__(self):
        out = list()
        out.append('    i: %s' % self.i)
        out.append('    m: %s' % self.m)
        out.append('    p: %s' % self.p)
        out.append('    ib: %s' % self.ib)
        out.append('    mb: %s' % self.mb)
        out.append('    pb: %s' % self.pb)
        out.append('    iv: %s' % self.iv)
        out.append('    mv: %s' % self.mv)
        out.append('    pv: %s' % self.pv)
        out.append('  pass: %s' % self.passing)
        return '\n'.join(out)

    def validate(self, msg):
        # Check if we have a X-Patch-Sig header. At this time, we only support two modes:
        # - GPG mode, which we check for fist
        # - Plain DKIM mode, which we check as fall-back
        # More modes may be coming in the future, depending on feedback.
        shdr = msg.get(HDR_PATCH_SIG)
        hhdr = msg.get(HDR_PATCH_HASHES)
        if hhdr is None:
            # Do we have a dkim signature header?
            if can_dkim_verify and msg.get('DKIM-Signature'):
                config = get_main_config()
                if config.get('attestation-check-dkim') == 'yes':
                    self.lsig = LoreAttestationSignatureDKIM(msg)
                    if self.lsig.passing:
                        self.passing = True
                        self.iv = True
                        self.mv = True
                        self.pv = True
                    return self.passing
            return None

        if shdr is None:
            return None

        sdata = get_parts_from_header(shdr)
        if sdata.get('m') == 'pgp':
            self.lsig = LoreAttestationSignaturePGP(msg)
            if self.lsig.passing:
                hdata = get_parts_from_header(hhdr)
                if hdata['i'] == self.ib:
                    self.iv = True
                if hdata['m'] == self.mb:
                    self.mv = True
                if hdata['p'] == self.pb:
                    self.pv = True

            if self.iv and self.mv and self.pv:
                self.passing = True

        if self.lsig is None:
            return None

        return self.passing


def _run_command(cmdargs, stdin=None):
    logger.debug('Running %s' % ' '.join(cmdargs))

    sp = subprocess.Popen(cmdargs,
                          stdout=subprocess.PIPE,
                          stdin=subprocess.PIPE,
                          stderr=subprocess.PIPE)

    (output, error) = sp.communicate(input=stdin)

    return sp.returncode, output, error


def gpg_run_command(args, stdin=None):
    config = get_main_config()
    cmdargs = [config['gpgbin'], '--batch', '--no-auto-key-retrieve', '--no-auto-check-trustdb']
    if config['attestation-gnupghome'] is not None:
        cmdargs += ['--homedir', config['attestation-gnupghome']]
    cmdargs += args

    return _run_command(cmdargs, stdin=stdin)


def git_run_command(gitdir, args, stdin=None, logstderr=False):
    cmdargs = ['git', '--no-pager']
    if gitdir:
        if os.path.isdir(os.path.join(gitdir, '.git')):
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


def git_get_command_lines(gitdir, args):
    ecode, out = git_run_command(gitdir, args)
    lines = list()
    if out:
        for line in out.split('\n'):
            if line == '':
                continue
            lines.append(line)

    return lines


@contextmanager
def git_temp_worktree(gitdir=None):
    """Context manager that creates a temporary work tree and chdirs into it. The
    worktree is deleted when the contex manager is closed. Taken from gj_tools."""
    dfn = None
    try:
        with TemporaryDirectory() as dfn:
            git_run_command(gitdir, ['worktree', 'add', '--detach', '--no-checkout', dfn])
            with in_directory(dfn):
                yield
    finally:
        if dfn is not None:
            git_run_command(gitdir, ['worktree', 'remove', dfn])


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


def get_data_dir():
    if 'XDG_DATA_HOME' in os.environ:
        datahome = os.environ['XDG_DATA_HOME']
    else:
        datahome = os.path.join(str(Path.home()), '.local', 'share')
    datadir = os.path.join(datahome, 'b4')
    Path(datadir).mkdir(parents=True, exist_ok=True)
    return datadir


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
        message = email.message_from_string(sys.stdin.read())
        return message.get('Message-ID', None)
    logger.error('Error: pipe a message or pass msgid as parameter')
    sys.exit(1)


def get_msgid(cmdargs):
    if not cmdargs.msgid:
        logger.debug('Getting Message-ID from stdin')
        msgid = get_msgid_from_stdin()
        if msgid is None:
            logger.error('Unable to find a valid message-id in stdin.')
            sys.exit(1)
    else:
        msgid = cmdargs.msgid

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


def save_strict_thread(in_mbx, out_mbx, msgid):
    want = {msgid}
    got = set()
    seen = set()
    maybe = dict()
    while True:
        for msg in in_mbx:
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
                out_mbx.add(msg)
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

    if not len(out_mbx):
        return None

    if len(in_mbx) > len(out_mbx):
        logger.debug('Reduced mbox to strict matches only (%s->%s)', len(in_mbx), len(out_mbx))


def get_pi_thread_by_url(t_mbx_url, savefile, nocache=False):
    cachefile = get_cache_file(t_mbx_url, 'pi.mbx')
    if os.path.exists(cachefile) and not nocache:
        logger.debug('Using cached copy: %s', cachefile)
        shutil.copyfile(cachefile, savefile)
        return savefile
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
    # Convert mboxrd to mboxo that python understands
    t_mbox = t_mbox.replace(b'\n>>From ', b'\n>From ')
    with open(savefile, 'wb') as fh:
        logger.debug('Saving %s', savefile)
        fh.write(t_mbox)
    shutil.copyfile(savefile, cachefile)
    return savefile


def get_pi_thread_by_msgid(msgid, savefile, useproject=None, nocache=False):
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

    logger.critical('Grabbing thread from %s', projurl.split('://')[1])

    tmp_mbox = mkstemp('b4-lookup-mbox')[1]
    in_mbxf = get_pi_thread_by_url(t_mbx_url, tmp_mbox, nocache=nocache)
    if not in_mbxf:
        os.unlink(tmp_mbox)
        return None
    in_mbx = mailbox.mbox(in_mbxf)
    out_mbx = mailbox.mbox(savefile)
    save_strict_thread(in_mbx, out_mbx, msgid)
    in_mbx.close()
    out_mbx.close()
    os.unlink(in_mbxf)
    return savefile


def git_format_patches(gitdir, start, end, reroll=None):
    gitargs = ['format-patch', '--stdout']
    if reroll is not None:
        gitargs += ['-v', str(reroll)]
    gitargs += ['%s..%s' % (start, end)]
    ecode, out = git_run_command(gitdir, gitargs)
    return ecode, out


def git_commit_exists(gitdir, commit_id):
    gitargs = ['cat-file', '-e', commit_id]
    ecode, out = git_run_command(gitdir, gitargs)
    return ecode == 0


def git_branch_contains(gitdir, commit_id):
    gitargs = ['branch', '--format=%(refname:short)', '--contains', commit_id]
    lines = git_get_command_lines(gitdir, gitargs)
    return lines


def format_addrs(pairs):
    addrs = set()
    for pair in pairs:
        # Remove any quoted-printable header junk from the name
        addrs.add(email.utils.formataddr((LoreMessage.clean_header(pair[0]), LoreMessage.clean_header(pair[1]))))
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


def dkim_canonicalize_header(hname, hval):
    hname = hname.lower()
    hval = hval.strip()
    hval = re.sub(r'\n', '', hval)
    hval = re.sub(r'\s+', ' ', hval)
    return hname, hval


def get_parts_from_header(hstr: str) -> dict:
    hstr = re.sub(r'\s*', '', hstr)
    hdata = dict()
    for chunk in hstr.split(';'):
        parts = chunk.split('=', 1)
        if len(parts) < 2:
            continue
        hdata[parts[0]] = parts[1]
    return hdata


def validate_gpg_signature(output, trustmodel):
    good = False
    valid = False
    trusted = False
    attestor = None
    sigdate = None
    errors = set()
    gs_matches = re.search(r'^\[GNUPG:] GOODSIG ([0-9A-F]+)\s+.*$', output, re.M)
    if gs_matches:
        logger.debug('  GOODSIG')
        good = True
        keyid = gs_matches.groups()[0]
        attestor = LoreAttestorPGP(keyid)
        puid = '%s <%s>' % attestor.get_primary_uid()
        vs_matches = re.search(r'^\[GNUPG:] VALIDSIG ([0-9A-F]+) (\d{4}-\d{2}-\d{2}) (\d+)', output, re.M)
        if vs_matches:
            logger.debug('  VALIDSIG')
            valid = True
            ymd = vs_matches.groups()[1]
            sigdate = datetime.datetime.strptime(ymd, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc)
            # Do we have a TRUST_(FULLY|ULTIMATE)?
            ts_matches = re.search(r'^\[GNUPG:] TRUST_(FULLY|ULTIMATE)', output, re.M)
            if ts_matches:
                logger.debug('  TRUST_%s', ts_matches.groups()[0])
                trusted = True
            else:
                errors.add('Insufficient trust (model=%s): %s (%s)' % (trustmodel, keyid, puid))
        else:
            errors.add('Signature not valid from key: %s (%s)' % (attestor.keyid, puid))
    else:
        # Are we missing a key?
        matches = re.search(r'^\[GNUPG:] NO_PUBKEY ([0-9A-F]+)$', output, re.M)
        if matches:
            errors.add('Missing public key: %s' % matches.groups()[0])
        # Is the key expired?
        matches = re.search(r'^\[GNUPG:] EXPKEYSIG (.*)$', output, re.M)
        if matches:
            errors.add('Expired key: %s' % matches.groups()[0])

    return good, valid, trusted, attestor, sigdate, errors


def dkim_get_txt(name: bytes, timeout: int = 5):
    global _DKIM_DNS_CACHE
    if name not in _DKIM_DNS_CACHE:
        lookup = name.decode()
        logger.debug('DNS-lookup: %s', lookup)
        try:
            a = _resolver.resolve(lookup, dns.rdatatype.TXT, raise_on_no_answer=False, lifetime=timeout, search=True)
            for r in a.response.answer:
                if r.rdtype == dns.rdatatype.TXT:
                    for item in r.items:
                        # Concatenate all strings
                        txtdata = b''.join(item.strings)
                        if txtdata.find(b'p=') >= 0:
                            _DKIM_DNS_CACHE[name] = txtdata
                            return txtdata
        except dns.resolver.NXDOMAIN:
            pass
        _DKIM_DNS_CACHE[name] = None
    return _DKIM_DNS_CACHE[name]
