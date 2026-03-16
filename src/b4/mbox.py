#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import os
import sys
import mailbox
import email
import email.utils
import email.parser
import re
import time
import json
import fnmatch
import shutil
import pathlib
import io
import shlex
import argparse

import b4

from typing import Any, Optional, Union, List, Set, Dict, Tuple
from string import Template

from email.message import EmailMessage

logger = b4.logger

DEFAULT_MERGE_TEMPLATE = """Merge ${patch_or_series} "${seriestitle}"

${authorname} <${authoremail}> says:

${covermessage}

Link: ${midurl}
"""


def save_msgs_as_mbox(dest: str, msgs: List[EmailMessage], filterdupes: bool = False) -> int:
    if dest == '-':
        b4.save_mboxrd_mbox(msgs, sys.stdout.buffer, mangle_from=False)
        return len(msgs)

    if b4.is_maildir(dest):
        mdr = mailbox.Maildir(dest)
        have_msgids = set()
        added = 0
        if filterdupes:
            for emsg in mdr:
                have_msgids.add(b4.LoreMessage.get_clean_msgid(emsg))  # type: ignore[arg-type]
        for msg in msgs:
            if b4.LoreMessage.get_clean_msgid(msg) not in have_msgids:
                added += 1
                mdr.add(msg)
        return added

    with open(dest, 'wb') as fh:
        b4.save_mboxrd_mbox(msgs, fh, mangle_from=True)

    return len(msgs)


def get_base_commit(topdir: Optional[str], body: str, lser: b4.LoreSeries,
                    cmdargs: argparse.Namespace) -> str:
    base_commit = 'HEAD'

    if lser.prereq_base_commit:
        logger.debug('Setting base-commit to prereq-base-commit: %s', lser.prereq_base_commit)
        base_commit = lser.prereq_base_commit
    else:
        matches = re.search(r'base-commit: .*?([\da-f]+)', body, re.MULTILINE)
        if matches:
            base_commit = matches.groups()[0]
        else:
            # Try a more relaxed search
            matches = re.search(r'based on .*?([\da-f]{40})', body, re.MULTILINE)
            if matches:
                base_commit = matches.groups()[0]

    if base_commit and topdir:
        # Does it actually exist in this tree?
        if not b4.git_commit_exists(topdir, base_commit):
            logger.warning(' Base: base-commit %s not known, ignoring', base_commit)
            base_commit = 'HEAD'
        elif not cmdargs.mergebase:
            logger.debug(' Base: using specified base-commit %s', base_commit)

    if base_commit == 'HEAD' and topdir and cmdargs.guessbase:
        logger.info(' Base: attempting to guess base-commit...')
        try:
            base_commit, nblobs, mismatches = lser.find_base(topdir, branches=cmdargs.guessbranch,
                                                             maxdays=cmdargs.guessdays)
            if mismatches == 0:
                logger.critical(' Base: %s (exact match)', base_commit)
            elif nblobs == mismatches:
                logger.critical(' Base: failed to guess base')
            else:
                logger.critical(' Base: %s (best guess, %s/%s blobs matched)', base_commit,
                                nblobs - mismatches, nblobs)
        except IndexError as ex:
            logger.critical(' Base: failed to guess base (%s)', ex)

    if cmdargs.mergebase:
        if base_commit:
            logger.debug(' Base: overriding submitter provided base-commit %s with %s',
                           base_commit, cmdargs.mergebase)
        base_commit = cmdargs.mergebase

    return base_commit


def make_am(msgs: List[EmailMessage], cmdargs: argparse.Namespace, msgid: str) -> None:
    config = b4.get_main_config()
    outdir = cmdargs.outdir
    if outdir == '-':
        cmdargs.nocover = True
    if 'addmsgid' in cmdargs and cmdargs.addmsgid:
        logger.debug('Setting linktrailermask to Message-ID:')
        config['linktrailermask'] = 'Message-ID: <%s>'
        cmdargs.addlink = True
    wantver = cmdargs.wantver
    count = len(msgs)
    logger.info('Analyzing %s messages in the thread', count)
    lmbx = b4.LoreMailbox()
    # Go through the mbox once to populate base series
    load_codereview = True
    for msg in msgs:
        # Is it a collection of patches attached to the same message?
        # We only trigger this mode with --single-msg
        if msg.is_multipart() and ('singlemsg' in cmdargs and cmdargs.singlemsg):
            xpatches: List[EmailMessage] = list()
            xmsgid = b4.LoreMessage.get_clean_msgid(msg)
            for part in msg.walk():
                cte = part.get_content_type()
                if cte.find('/x-patch') < 0:
                    continue
                bpayload = part.get_payload(decode=True)
                if not isinstance(bpayload, bytes):
                    continue
                pcharset = part.get_content_charset()
                if not pcharset:
                    pcharset = 'utf-8'
                try:
                    payload = bpayload.decode(pcharset, errors='replace')
                except LookupError:
                    # what kind of encoding is that?
                    # Whatever, we'll use utf-8 and hope for the best
                    payload = bpayload.decode('utf-8', errors='replace')
                    part.set_param('charset', 'utf-8')
                if payload and b4.DIFF_RE.search(payload):
                    xmsg = email.parser.Parser(policy=b4.emlpolicy, _class=EmailMessage).parsestr(payload)
                    # Needs to have Subject, From, Date for us to consider it
                    if xmsg.get('Subject') and xmsg.get('From') and xmsg.get('Date'):
                        logger.debug('Found attached patch: %s', xmsg.get('Subject'))
                        xmsg['Message-ID'] = f'<att{len(xpatches)}-{xmsgid}>'
                        xpatches.append(xmsg)
            if len(xpatches):
                logger.info('Warning: Found %s patches attached to the requested message', len(xpatches))
                logger.info('         This mode ignores any follow-up trailers, use with caution')
                # Throw out lmbx and only use these
                lmbx = b4.LoreMailbox()
                load_codereview = False
                for xmsg in xpatches:
                    lmbx.add_message(xmsg)
                # Make a cover letter out of the original message
                cmsg = EmailMessage()
                cbody, ccharset = b4.LoreMessage.get_payload(msg, use_patch=False)
                cmsg['From'] = msg.get('From')
                cmsg['Date'] = msg.get('Date')
                cmsg['Message-ID'] = msg.get('Message-ID')
                cmsg['Subject'] = '[PATCH 0/0] ' + msg.get('Subject', '(no subject)')
                cmsg.set_payload(cbody, ccharset)
                lmbx.add_message(cmsg)
                break
        else:
            lmbx.add_message(msg)

    reroll = True
    if cmdargs.nopartialreroll:
        reroll = False

    lser = lmbx.get_series(revision=wantver, sloppytrailers=cmdargs.sloppytrailers, reroll=reroll,
                           codereview_trailers=load_codereview)
    if lser is None and cmdargs.cherrypick != '_':
        if wantver is None:
            logger.critical('No patches found.')
        else:
            logger.critical('Unable to find revision %s', wantver)
        return
    if lser is None:
        logger.critical('No patches found.')
        return

    if len(lmbx.series) > 1 and not wantver:
        logger.info('Will use the latest revision: v%s', lser.revision)
        logger.info('You can pick other revisions using the -vN flag')

    if cmdargs.cherrypick:
        cherrypick = list()
        if cmdargs.cherrypick == '_':
            # We might want to pick a patch sent as a followup, so create a fake series
            # and add followups with diffs
            if lser is None:
                lser = b4.LoreSeries(revision=1, expected=1)
            for followup in lmbx.followups:
                if followup.has_diff:
                    lser.add_patch(followup)
            # Only grab the exact msgid provided
            for at, lmsg in enumerate(lser.patches[1:], 1):
                if lmsg and lmsg.msgid == msgid:
                    cherrypick = [at]
                    cmdargs.cherrypick = f'<{msgid}>'
                    break
            if not len(cherrypick):
                logger.critical('Specified msgid is not present in the series, cannot cherrypick')
                sys.exit(1)
        elif cmdargs.cherrypick.find('*') >= 0:
            # Globbing on subject
            at = 0
            for lmsg in lser.patches[1:]:
                at += 1
                if lmsg is None:
                    continue
                if fnmatch.fnmatch(lmsg.subject, cmdargs.cherrypick):
                    cherrypick.append(at)
            if not len(cherrypick):
                logger.critical('Could not match "%s" to any subjects in the series', cmdargs.cherrypick)
                sys.exit(1)
        else:
            cherrypick = list(b4.parse_int_range(cmdargs.cherrypick, upper=len(lser.patches) - 1))
    else:
        cherrypick = None

    am_msgs = lser.get_am_ready(noaddtrailers=cmdargs.noaddtrailers, addmysob=cmdargs.addmysob, addlink=cmdargs.addlink,
                                cherrypick=cherrypick, copyccs=cmdargs.copyccs, allowbadchars=cmdargs.allowbadchars,
                                showchecks=cmdargs.check)
    logger.info('---')

    if cherrypick is None:
        logger.critical('Total patches: %s', len(am_msgs))
    else:
        logger.info('Total patches: %s (cherrypicked: %s)', len(am_msgs), cmdargs.cherrypick)

    if len(lser.trailer_mismatches):
        logger.critical('---')
        logger.critical('NOTE: some trailers ignored due to from/email mismatches:')
        for tname, tvalue, fname, femail in lser.trailer_mismatches:
            logger.critical('    ! Trailer: %s: %s', tname, tvalue)
            logger.critical('     Msg From: %s <%s>', fname, femail)
        logger.critical('NOTE: Rerun with -S to apply them anyway')

    top_msgid = None
    first_body = None
    for lmsg in lser.patches:
        if lmsg is not None:
            first_body = lmsg.body
            top_msgid = lmsg.msgid
            break
    if top_msgid is None or first_body is None:
        logger.critical('Could not find any patches in the series.')
        return

    topdir = b4.git_get_toplevel()

    if cmdargs.threeway:
        if not topdir:
            logger.critical('WARNING: cannot prepare 3-way (not in a git dir)')
        elif not lser.complete:
            logger.critical('WARNING: cannot prepare 3-way (series incomplete)')
        else:
            _checked, mismatches = lser.check_applies_clean(gitdir=topdir)
            if mismatches:
                rstart, rend = lser.make_fake_am_range(gitdir=None)
                if rstart and rend:
                    logger.info('Prepared fake commit range for 3-way merge (%.12s..%.12s)', rstart, rend)

    logger.critical('---')
    if lser.partial_reroll:
        logger.critical('WARNING: v%s is a partial reroll from previous revisions', lser.revision)
        logger.critical('         Please carefully review the resulting series to ensure correctness')
        logger.critical('         Pass --no-partial-reroll to disable')
        logger.critical('---')
    if not lser.complete and not cmdargs.cherrypick:
        logger.critical('WARNING: Thread incomplete!')

    am_filename = None

    linkmask = str(config.get('linkmask', ''))
    if '%s' not in linkmask:
        logger.critical('ERROR: linkmask must contain %s for the message-id')
        sys.exit(1)

    if cmdargs.subcmd == 'am':
        wantname = cmdargs.wantname
        if cmdargs.maildir or config.get('save-maildirs', 'no') == 'yes':
            save_maildir = True
            dftext = 'maildir'
        else:
            save_maildir = False
            dftext = 'mbx'

        if wantname:
            slug = wantname
            if wantname.find('.') > -1:
                slug = '.'.join(wantname.split('.')[:-1])
        else:
            slug = lser.get_slug(extended=True)

        if outdir != '-':
            pathlib.Path(outdir).mkdir(parents=True, exist_ok=True)

            am_filename = os.path.join(outdir, f'{slug}.{dftext}')
            am_cover = os.path.join(outdir, f'{slug}.cover')

            if os.path.exists(am_filename):
                if os.path.isdir(am_filename):
                    shutil.rmtree(am_filename)
                else:
                    os.unlink(am_filename)
            if save_maildir:
                b4.save_maildir(am_msgs, am_filename)
            else:
                with open(am_filename, 'wb') as fh:
                    b4.save_git_am_mbox(am_msgs, fh)
        else:
            am_cover = None
            b4.save_git_am_mbox(am_msgs, sys.stdout.buffer)

        if am_cover and lser.has_cover and not cmdargs.nocover:
            lser.save_cover(am_cover)

        linkurl = linkmask % top_msgid
        if cmdargs.quiltready:
            q_dirname = os.path.join(outdir, f'{slug}.patches')
            save_as_quilt(am_msgs, q_dirname)
            logger.critical('Quilt: %s', q_dirname)

        logger.critical(' Link: %s', linkurl)

    if cmdargs.subcmd == 'shazam':
        if not topdir:
            logger.critical('Could not figure out where your git dir is, cannot shazam.')
            sys.exit(1)

        ifh = io.BytesIO()
        if lser.prereq_patch_ids:
            logger.info(' Deps: looking for dependencies matching %s patch-ids', len(lser.prereq_patch_ids))
            query = ' OR '.join([f'patchid:{x}' for x in lser.prereq_patch_ids])
            logger.debug('query=%s', query)
            dmsgs = b4.get_pi_search_results(query)
            pmap = dict()
            if dmsgs:
                for dmsg in dmsgs:
                    dbody, _ = b4.LoreMessage.get_payload(dmsg)
                    if not b4.DIFF_RE.search(dbody):
                        continue
                    dlmsg = b4.LoreMessage(dmsg)
                    if dlmsg.git_patch_id in lser.prereq_patch_ids:
                        logger.debug('%s => %s', dlmsg.git_patch_id, dlmsg.subject)
                        pmap[dlmsg.git_patch_id] = dlmsg
            for ppid in lser.prereq_patch_ids:
                if ppid in pmap:
                    logger.info(' Deps: Applying prerequisite patch: %s', pmap[ppid].full_subject)
                    pam_msg = pmap[ppid].get_am_message(add_trailers=False)
                    b4.save_mboxrd_mbox([pam_msg], ifh)

        b4.save_git_am_mbox(am_msgs, ifh)
        ambytes = ifh.getvalue()
        if not cmdargs.makefetchhead:
            amflags = str(config.get('shazam-am-flags', ''))
            sp = shlex.shlex(amflags, posix=True)
            sp.whitespace_split = True
            amargs = list(sp) + ['--patch-format=mboxrd']
            ecode, out = b4.git_run_command(topdir, ['am'] + amargs, stdin=ambytes, logstderr=True, rundir=topdir)
            logger.info(out.strip())
            if ecode == 0:
                thanks_record_am(lser, cherrypick=cherrypick)
            sys.exit(ecode)

        base_commit = get_base_commit(topdir, first_body, lser, cmdargs)
        linkurl = linkmask % top_msgid

        merge_template = DEFAULT_MERGE_TEMPLATE
        if config.get('shazam-merge-template'):
            # Try to load this template instead
            try:
                merge_template = b4.read_template(str(config['shazam-merge-template']))
            except FileNotFoundError:
                logger.critical('ERROR: shazam-merge-template says to use %s, but it does not exist',
                                config['shazam-merge-template'])
                sys.exit(2)

        if lser.has_cover and lser.patches[0] is not None:
            clmsg: b4.LoreMessage = lser.patches[0]
            parts = b4.LoreMessage.get_body_parts(clmsg.body)
            covermessage = parts[1]
        else:
            if lser.patches[1] is None:
                logger.critical('No cover letter provided by the author and no first patch, cannot shazam')
                sys.exit(1)

            clmsg = lser.patches[1]
            covermessage = ('NOTE: No cover letter provided by the author.\n'
                            '      Add merge commit message here.')

        tptvals = {
            'seriestitle': clmsg.subject,
            'authorname': clmsg.fromname,
            'authoremail': clmsg.fromemail,
            'covermessage': covermessage,
            'mid': top_msgid,
            'midurl': linkurl,
        }
        if len(am_msgs) > 1:
            tptvals['patch_or_series'] = 'patch series'
        else:
            tptvals['patch_or_series'] = 'patch'

        mergeflags = str(config.get('shazam-merge-flags', '--signoff'))

        am_flags = ['-3']
        amflags_cfg = str(config.get('shazam-am-flags', ''))
        if amflags_cfg:
            sp = shlex.shlex(amflags_cfg, posix=True)
            sp.whitespace_split = True
            am_flags.extend(list(sp))

        try:
            if cmdargs.mergebase:
                logger.info(' Base: %s', base_commit)
            else:
                logger.info(' Base: %s (use --merge-base to override)', base_commit)
            b4.git_fetch_am_into_repo(topdir, ambytes=ambytes, at_base=base_commit,
                                       origin=linkurl, am_flags=am_flags)
        except b4.AmConflictError as cex:
            gwt = cex.worktree_path
            if not getattr(cmdargs, 'shazam_resolve', False):
                b4.git_run_command(topdir, ['worktree', 'remove', '--force', gwt])
                logger.critical('Unable to cleanly apply series, see failure log below')
                logger.critical('---')
                logger.critical(cex.output)
                logger.critical('---')
                logger.critical('Not fetching into FETCH_HEAD')
                logger.critical('Use --resolve to enable conflict resolution')
                sys.exit(1)

            common_dir = b4.git_get_common_dir(topdir)
            if not common_dir:
                logger.critical('Unable to determine git common dir')
                b4.git_run_command(topdir, ['worktree', 'remove', '--force', gwt])
                sys.exit(1)

            state = {
                'origin': linkurl,
                'merge_template_values': tptvals,
                'merge_template': merge_template,
                'merge_flags': mergeflags,
                'no_interactive': cmdargs.no_interactive,
            }
            _start_merge_resolve(topdir, cex, common_dir, state)
        except RuntimeError:
            sys.exit(1)

        gitargs = ['rev-parse', '--git-dir']
        ecode, out = b4.git_run_command(topdir, gitargs, logstderr=True)
        if ecode > 0:
            logger.critical('Unable to find git directory')
            logger.critical(out.strip())
            sys.exit(ecode)
        mmf = os.path.join(out.rstrip(), 'b4-cover')

        # Write out a sample merge message using the cover letter
        if os.path.exists(mmf):
            # Make sure any old cover letters don't confuse anyone
            os.unlink(mmf)

        body = Template(merge_template).safe_substitute(tptvals)
        with open(mmf, 'w') as mmh:
            mmh.write(body)

        sp = shlex.shlex(mergeflags, posix=True)
        sp.whitespace_split = True
        if cmdargs.no_interactive:
            edit = '--no-edit'
        else:
            edit = '--edit'
        mergeargs = ['merge', '--no-ff', '-F', mmf, edit, 'FETCH_HEAD'] + list(sp)
        mergecmd = ['git'] + mergeargs

        thanks_record_am(lser, cherrypick=cherrypick)
        if cmdargs.merge:
            if not cmdargs.no_interactive:
                logger.info('Will exec: %s', ' '.join(mergecmd))
                try:
                    input('Press Enter to continue or Ctrl-C to abort')
                except KeyboardInterrupt:
                    logger.info('')
                    sys.exit(130)
            else:
                logger.info('Invoking: %s', ' '.join(mergecmd))
            if hasattr(sys, '_running_in_pytest'):
                # Don't execvp, as this kills our tests
                _out = b4.git_run_command(None, mergeargs)
                sys.exit(_out[0])

            # We exec git-merge and let it take over
            os.execvp(mergecmd[0], mergecmd)

        logger.info('You can now merge or checkout FETCH_HEAD')
        logger.info('  e.g.: %s', ' '.join(mergecmd))
        sys.exit(0)

    if topdir:
        base_commit = get_base_commit(topdir, first_body, lser, cmdargs)
        checked, mismatched = lser.check_applies_clean(topdir, at=cmdargs.guessbranch)
        if checked and len(mismatched) == 0 and checked != len(mismatched):
            logger.critical(' Base: applies clean to current tree')
        elif base_commit != 'HEAD':
            gitbranch = lser.get_slug(extended=False)
            logger.critical('       git checkout -b %s %s', gitbranch, base_commit)

    if cmdargs.outdir != '-':
        logger.critical('       git am %s%s', '-3 ' if cmdargs.threeway else '', am_filename)

    thanks_record_am(lser, cherrypick=cherrypick)


def thanks_record_am(lser: b4.LoreSeries, cherrypick: Optional[List[int]]) -> None:
    # Are we tracking this already?
    datadir = b4.get_data_dir()
    slug = lser.get_slug(extended=True)
    filename = '%s.am' % slug

    patches = list()
    msgids = list()
    at = 0
    padlen = len(str(lser.expected))
    lmsg = None

    for pmsg in lser.patches:
        if pmsg is None:
            at += 1
            continue

        if lmsg is None:
            lmsg = pmsg

        if not pmsg.has_diff:
            # Don't care about the cover letter
            at += 1
            continue

        if cherrypick is not None and at not in cherrypick:
            logger.debug('Skipped non-cherrypicked: %s', at)
            at += 1
            continue

        # Add it for patchwork state tracking
        msgids.append(pmsg.msgid)

        if pmsg.pwhash is None:
            logger.debug('Unable to get hashes for all patches, not tracking for thanks')
            return

        prefix = '%s/%s' % (str(pmsg.counter).zfill(padlen), pmsg.expected)
        patches.append((pmsg.subject, pmsg.pwhash, pmsg.msgid, prefix))
        at += 1

    if lmsg is None:
        logger.debug('All patches missing, not tracking for thanks')
        return

    try:
        allto = email.utils.getaddresses([str(x) for x in lmsg.msg.get_all('to', [])])
    except Exception as ex:
        allto = []
        logger.debug('Unable to parse the To: header in %s: %s', lmsg.msgid, str(ex))
    try:
        allcc = email.utils.getaddresses([str(x) for x in lmsg.msg.get_all('cc', [])])
    except Exception as ex:
        allcc = []
        logger.debug('Unable to parse the Cc: header in %s: %s', lmsg.msgid, str(ex))

    # TODO: check for reply-to and x-original-from
    out = {
        'msgid': lmsg.msgid,
        'subject': lmsg.full_subject,
        'fromname': lmsg.fromname,
        'fromemail': lmsg.fromemail,
        'to': b4.format_addrs(allto, clean=False),
        'cc': b4.format_addrs(allcc, clean=False),
        'references': b4.LoreMessage.clean_header(lmsg.msg['References']),
        'sentdate': b4.LoreMessage.clean_header(lmsg.msg['Date']),
        'quote': b4.make_quote(lmsg.body, maxlines=5),
        'cherrypick': cherrypick is not None,
        'patches': patches,
    }
    fullpath = os.path.join(datadir, filename)
    with open(fullpath, 'w', encoding='utf-8') as fh:
        json.dump(out, fh, ensure_ascii=False, indent=4)
        logger.debug('Wrote %s for thanks tracking', filename)

    config = b4.get_main_config()
    pwstate = str(config.get('pw-review-state', ''))
    if pwstate:
        b4.patchwork_set_state(msgids, pwstate)


def save_as_quilt(am_msgs: List[EmailMessage], q_dirname: str) -> None:
    if os.path.exists(q_dirname):
        logger.critical('ERROR: Directory %s exists, not saving quilt patches', q_dirname)
        return
    pathlib.Path(q_dirname).mkdir(parents=True)
    patch_filenames = list()
    for msg in am_msgs:
        lsubj = b4.LoreSubject(msg.get('subject', ''))
        slug = '%04d_%s' % (lsubj.counter, re.sub(r'\W+', '_', lsubj.subject).strip('_').lower())
        patch_filename = f'{slug}.patch'
        patch_filenames.append(patch_filename)
        quilt_out = os.path.join(q_dirname, patch_filename)
        i, m, p = b4.get_mailinfo(msg.as_bytes(policy=b4.emlpolicy), scissors=True)
        with open(quilt_out, 'wb') as fh:
            if i.get('Author'):
                fh.write(b'From: %s <%s>\n' % (i.get('Author', '').encode(), i.get('Email', '').encode()))
            else:
                fh.write(b'From: %s\n' % i.get('Email', '').encode())
            fh.write(b'Subject: %s\n' % i.get('Subject', '').encode())
            fh.write(b'Date: %s\n' % i.get('Date', '').encode())
            fh.write(b'\n')
            fh.write(m)
            fh.write(p)
        logger.debug('  Wrote: %s', patch_filename)
    # Write the series file
    with open(os.path.join(q_dirname, 'series'), 'w') as sfh:
        for patch_filename in patch_filenames:
            sfh.write('%s\n' % patch_filename)


def get_extra_series(msgs: List[EmailMessage], direction: int = 1, wantvers: Optional[List[int]] = None,
                     nocache: bool = False) -> List[EmailMessage]:
    base_msg: Optional[EmailMessage] = None
    latest_revision: Optional[int] = None
    seen_msgids: Set[str] = set()
    seen_covers: Set[int] = set()
    queries: Set[str] = set()
    by_changeid: bool = False
    for msg in msgs:
        msgid = b4.LoreMessage.get_clean_msgid(msg)
        if msgid is None:
            continue
        seen_msgids.add(msgid)
        lsub = b4.LoreSubject(msg['Subject'])

        # Ignore patches above 1
        if lsub.counter > 1:
            continue

        if base_msg is not None:
            logger.debug('Current base_msg: %s', base_msg['Subject'])

        if lsub.reply:
            logger.debug('Ignoring reply: %s', lsub.full_subject)
            continue

        payload, _ = b4.LoreMessage.get_payload(msg)
        if payload:
            matches = re.search(r'^change-id:\s+(\S+)', payload, flags=re.I | re.M)
            if matches:
                logger.debug('Found change-id %s', matches.groups()[0])
                by_changeid = True
                q = 'nq:"change-id: %s"' % matches.groups()[0]
                queries.add(q)

        logger.debug('Checking the subject on %s', lsub.full_subject)
        if latest_revision is None or lsub.revision >= latest_revision:
            latest_revision = lsub.revision
            if lsub.counter == 0 and not lsub.counters_inferred:
                # And a cover letter, nice. This is the easy case
                base_msg = msg
                seen_covers.add(latest_revision)
            elif lsub.counter == 1 and latest_revision not in seen_covers:
                # A patch/series without a cover letter
                base_msg = msg

    if base_msg is None or latest_revision is None:
        return msgs

    # Get subject info from base_msg again
    lsub = b4.LoreSubject(base_msg['Subject'])
    if not len(lsub.prefixes):
        logger.debug('Not checking for new revisions: no prefixes on the cover letter.')
        return msgs
    if direction < 0 and latest_revision <= 1:
        logger.debug('This is the earliest version of the series')
        return msgs
    if direction < 0 and wantvers is None:
        wantvers = [latest_revision - 1]

    msgdate = email.utils.parsedate_tz(str(base_msg['Date']))
    if msgdate is None:
        logger.debug('Unable to parse the date, not checking for revisions')
        return msgs

    if not by_changeid:
        logger.debug('Using subject+from combo for query')
        fromeml = email.utils.getaddresses(base_msg.get_all('from', []))[0][1]
        q = '(s:"%s" AND f:"%s")' % (lsub.subject.replace('"', ''), fromeml)
        queries.add(q)

    startdate = time.strftime('%Y%m%d', msgdate[:9])
    if direction > 0:
        logger.critical('Checking for newer revisions')
        datelim = 'd:%s..' % startdate
    else:
        logger.critical('Checking for older revisions')
        # Cap backward search to 12 months to avoid matching years of
        # identically-named series (common with subject+from fallback).
        earliest = time.strftime('%Y%m%d', time.gmtime(
            time.mktime(msgdate[:9]) - 365 * 86400))
        datelim = 'd:%s..%s' % (earliest, startdate)

    q = '(%s) AND %s' % (' OR '.join(queries), datelim)
    logger.debug('Query: %s', q)
    q_msgs = b4.get_pi_search_results(q, nocache=nocache)
    if not q_msgs:
        return msgs

    seen_revisions = dict()
    for q_msg in q_msgs:
        q_msgid = b4.LoreMessage.get_clean_msgid(q_msg)
        if q_msgid is None:
            continue
        _subject = q_msg.get('Subject', '(no subject)')
        lsub = b4.LoreSubject(_subject)
        if q_msgid in seen_msgids:
            logger.debug('Skipping %s: already have it', lsub.full_subject)
            continue
        if lsub.reply:
            # These will get sorted out later
            logger.debug('Adding reply: %s', lsub.full_subject)
            logger.debug('              msgid: %s', q_msgid)
            msgs.append(q_msg)
            seen_msgids.add(q_msgid)
            continue

        if direction > 0 and lsub.revision <= latest_revision:
            logger.debug('Ignoring result (not new revision): %s', lsub.full_subject)
            continue
        if direction < 0 and lsub.revision >= latest_revision:
            logger.debug('Ignoring result (not old revision): %s', lsub.full_subject)
            continue
        if direction < 0 and wantvers and lsub.revision not in wantvers:
            logger.debug('Ignoring result (not revision we want): %s', lsub.full_subject)
            continue

        if lsub.revision == 1 and lsub.revision == latest_revision:
            # Someone sent a separate message with an identical title but no new vX in the subject line
            if direction > 0:
                # It's *probably* a new revision.
                logger.debug('Likely a new revision: %s', lsub.full_subject)
            else:
                # It's *probably* an older revision.
                logger.debug('Likely an older revision: %s', lsub.full_subject)
        elif direction > 0 and lsub.revision > latest_revision:
            logger.debug('Definitely a new revision [v%s]: %s', lsub.revision, lsub.full_subject)
        elif direction < 0 and lsub.revision < latest_revision:
            logger.debug('Definitely an older revision [v%s]: %s', lsub.revision, lsub.full_subject)
        else:
            logger.debug('No idea what this is: %s', lsub.subject)
            continue
        if lsub.revision not in seen_revisions:
            seen_revisions[lsub.revision] = 0
        seen_revisions[lsub.revision] += 1
        logger.debug('Adding: %s', lsub.full_subject)
        msgs.append(q_msg)
        seen_msgids.add(q_msgid)

    for rev, count in seen_revisions.items():
        logger.info('  Added from v%s: %s patches', rev, count)

    return msgs


def refetch(dest: str) -> None:
    mbox: Union[mailbox.Maildir, mailbox.mbox]
    if b4.is_maildir(dest):
        mbox = mailbox.Maildir(dest)
    else:
        mbox = mailbox.mbox(dest)

    by_msgid: Dict[str, EmailMessage] = dict()
    for key, msg in mbox.items():
        # We normally pass EmailMessage objects, but this works, too
        msgid = b4.LoreMessage.get_clean_msgid(msg)  # type: ignore[arg-type]
        if not msgid:
            continue
        if msgid not in by_msgid:
            amsgs = b4.get_pi_thread_by_msgid(msgid, nocache=True)
            if amsgs:
                for amsg in amsgs:
                    amsgid = b4.LoreMessage.get_clean_msgid(amsg)
                    if not amsgid:
                        continue
                    if amsgid not in by_msgid:
                        by_msgid[amsgid] = amsg
        if msgid in by_msgid:
            mbox.update(((key, by_msgid[msgid]),))
            logger.info('Refetched: %s', msg.get('Subject'))
        else:
            logger.warning('WARNING: Message-id not known: %s', msgid)
    mbox.close()


def minimize_thread(msgs: List[EmailMessage]) -> List[EmailMessage]:
    # We go through each message and minimize headers and body content
    wanthdrs = {
                'From',
                'Subject',
                'Date',
                'Message-ID',
                'Reply-To',
                'In-Reply-To',
                }
    mmsgs = list()
    for msg in msgs:
        mmsg = EmailMessage()
        for wanthdr in wanthdrs:
            cleanhdr = b4.LoreMessage.clean_header(msg[wanthdr])
            if cleanhdr:
                mmsg[wanthdr] = cleanhdr

        body, _charset = b4.LoreMessage.get_payload(msg)
        if not (b4.DIFF_RE.search(body) or b4.DIFFSTAT_RE.search(body)):
            _htrs, cmsg, _mtrs, _basement, _sig = b4.LoreMessage.get_body_parts(body)
            # split the message into quoted and unquoted chunks
            chunks: List[Tuple[bool, List[str]]] = list()
            chunk: List[str] = list()
            current = None
            for line in (cmsg.rstrip().splitlines()):
                quoted = line.startswith('>') and True or False
                if current is None:
                    current = quoted
                if current == quoted:
                    if quoted and re.search(r'^>\s*>', line):
                        # trim multiple levels of quoting
                        continue
                    if quoted and not chunk and line.strip() == '>':
                        # Trim empty lines with just > in them
                        continue
                    chunk.append(line)
                    continue

                if current:
                    while len(chunk) and chunk[-1].strip() == '>':
                        chunk.pop(-1)
                if chunk:
                    chunks.append((quoted, chunk))
                chunk = list()
                if not (quoted and line.strip() == '>'):
                    chunk.append(line)
                current = quoted

            if current is None:
                current = False

            # Don't append bottom quotes
            if chunk and not current:
                chunks.append((current, chunk))

            body = ''
            for _quoted, chunk in chunks:
                # Should we offer a way to trim the quote in some fashion?
                body += '\n'.join(chunk).strip() + '\n\n'
            if not body.strip():
                continue

        mmsg.set_payload(body, charset='utf-8')
        # mmsg.set_charset('utf-8')
        mmsgs.append(mmsg)

    return mmsgs


def _start_merge_resolve(topdir: str, cex: b4.AmConflictError,
                          common_dir: str, state: Dict[str, Any]) -> None:
    gwt = cex.worktree_path
    logger.critical('---')
    logger.critical(cex.output)
    logger.critical('---')
    logger.critical('Patch series did not apply cleanly, resolving...')

    # Find rebase-apply in the worktree
    ecode, gitdir = b4.git_run_command(gwt, ['rev-parse', '--git-dir'],
                                        logstderr=True, rundir=gwt)
    if ecode > 0:
        logger.critical('Unable to find git directory in worktree')
        b4.git_run_command(topdir, ['worktree', 'remove', '--force', gwt])
        sys.exit(1)
    rebase_apply = os.path.join(gitdir.strip(), 'rebase-apply')
    if not os.path.isdir(rebase_apply):
        logger.critical('No git-am state found in worktree.')
        b4.git_run_command(topdir, ['worktree', 'remove', '--force', gwt])
        sys.exit(1)

    # Extract remaining patches
    with open(os.path.join(rebase_apply, 'next'), 'r') as fh:
        next_num = int(fh.read().strip())
    with open(os.path.join(rebase_apply, 'last'), 'r') as fh:
        last_num = int(fh.read().strip())

    patches_dir = os.path.join(common_dir, 'b4-shazam-patches')
    if os.path.exists(patches_dir):
        shutil.rmtree(patches_dir)
    os.makedirs(patches_dir)

    patch_count = 0
    for i in range(next_num, last_num + 1):
        src = os.path.join(rebase_apply, f'{i:04d}')
        if os.path.exists(src):
            dst = os.path.join(patches_dir, f'{patch_count:04d}')
            shutil.copy2(src, dst)
            patch_count += 1

    with open(os.path.join(patches_dir, 'total'), 'w') as fh:
        fh.write(str(patch_count))
    with open(os.path.join(patches_dir, 'current'), 'w') as fh:
        fh.write('0')

    # Check for uncommitted changes
    status_lines = b4.git_get_repo_status(topdir)
    if status_lines:
        logger.critical('You have uncommitted changes in your working tree.')
        logger.critical('Please commit or stash them before resolving.')
        shutil.rmtree(patches_dir)
        b4.git_run_command(topdir, ['worktree', 'remove', '--force', gwt])
        sys.exit(1)

    # Fetch successfully applied patches into FETCH_HEAD
    logger.info('Fetching successfully applied patches into FETCH_HEAD')
    ecode, out = b4.git_run_command(topdir, ['fetch', gwt], logstderr=True)
    if ecode > 0:
        logger.critical('Unable to fetch from the worktree')
        logger.critical(out.strip())
        shutil.rmtree(patches_dir)
        b4.git_run_command(topdir, ['worktree', 'remove', '--force', gwt])
        sys.exit(1)

    # Rewrite FETCH_HEAD origin
    origin = state.get('origin')
    if origin:
        gitargs = ['rev-parse', '--git-path', 'FETCH_HEAD']
        ecode, fhf = b4.git_run_command(topdir, gitargs, logstderr=True)
        if ecode == 0:
            fhf = fhf.rstrip()
            with open(fhf, 'r') as fhh:
                contents = fhh.read()
            mmsg = 'patches from %s' % origin
            new_contents = contents.replace(gwt, mmsg)
            if new_contents != contents:
                with open(fhf, 'w') as fhh:
                    fhh.write(new_contents)

    # Remove the worktree
    b4.git_run_command(topdir, ['worktree', 'remove', '--force', gwt])

    # Save state for --continue/--abort
    state_file = os.path.join(common_dir, 'b4-shazam-state.json')
    with open(state_file, 'w') as sfh:
        json.dump(state, sfh, indent=2)

    # Start merge of successfully applied patches
    logger.info('Merging successfully applied patches into your branch...')
    ecode, out = b4.git_run_command(topdir, ['merge', '--no-ff', '--no-commit', 'FETCH_HEAD'],
                                     logstderr=True, rundir=topdir)

    if ecode > 0:
        logger.warning('Merge had conflicts:')
        logger.warning(out.strip())
        logger.warning('Resolve conflicts, then run: b4 shazam --continue')
        logger.warning('To abort: b4 shazam --abort')
        sys.exit(1)

    # Merge was clean, apply remaining patches
    _apply_remaining_patches(topdir, patches_dir, state, state_file, common_dir)
    sys.exit(0)


def _apply_remaining_patches(topdir: str, patches_dir: str, state: Dict[str, Any],
                              state_file: str, common_dir: str) -> None:
    with open(os.path.join(patches_dir, 'total'), 'r') as fh:
        total = int(fh.read().strip())
    with open(os.path.join(patches_dir, 'current'), 'r') as fh:
        current = int(fh.read().strip())

    while current < total:
        patch_file = os.path.join(patches_dir, f'{current:04d}')
        if not os.path.exists(patch_file):
            current += 1
            continue

        with open(patch_file, 'rb') as fh:
            patch_data = fh.read()

        logger.info('Applying remaining patch %d/%d...', current + 1, total)
        ecode, out = b4.git_run_command(topdir, ['apply', '--3way'],
                                         stdin=patch_data, logstderr=True, rundir=topdir)
        if ecode > 0:
            logger.critical('---')
            logger.critical(out.strip())
            logger.critical('---')
            logger.critical('Remaining patch %d/%d did not apply cleanly.', current + 1, total)
            logger.critical('Resolve conflicts in your working tree, then run: b4 shazam --continue')
            logger.critical('To abort: b4 shazam --abort')
            # Advance past this patch, its changes (with conflict markers) are in the tree
            with open(os.path.join(patches_dir, 'current'), 'w') as fh:
                fh.write(str(current + 1))
            sys.exit(1)

        # Patch applied cleanly, stage it
        b4.git_run_command(topdir, ['add', '-u'], logstderr=True, rundir=topdir)
        current += 1
        with open(os.path.join(patches_dir, 'current'), 'w') as fh:
            fh.write(str(current))

    # All patches applied, finish the merge
    _finish_shazam_merge(topdir, state, state_file, common_dir, patches_dir)


def _finish_shazam_merge(topdir: str, state: Dict[str, Any], state_file: str,
                          common_dir: str, patches_dir: str) -> None:
    b4.git_run_command(topdir, ['add', '-u'], logstderr=True, rundir=topdir)

    gitargs = ['rev-parse', '--git-dir']
    ecode, out = b4.git_run_command(topdir, gitargs, logstderr=True)
    if ecode > 0:
        logger.critical('Unable to find git directory')
        sys.exit(1)
    mmf = os.path.join(out.rstrip(), 'b4-cover')

    merge_template = state.get('merge_template', DEFAULT_MERGE_TEMPLATE)
    tptvals = state.get('merge_template_values', {})

    body = Template(merge_template).safe_substitute(tptvals)
    with open(mmf, 'w') as mmh:
        mmh.write(body)

    # Clean up state before committing -- if the commit is interactive
    # (execvp), we won't get a chance to clean up after.
    if os.path.exists(patches_dir):
        shutil.rmtree(patches_dir)
    if os.path.exists(state_file):
        os.unlink(state_file)

    no_interactive = state.get('no_interactive', False)
    mergeflags = str(state.get('merge_flags', ''))
    commitargs = ['commit', '-F', mmf]
    if mergeflags:
        sp = shlex.shlex(mergeflags, posix=True)
        sp.whitespace_split = True
        commitargs.extend(list(sp))
    if no_interactive:
        commitargs.append('--no-edit')
        ecode, out = b4.git_run_command(topdir, commitargs, logstderr=True, rundir=topdir)
        if ecode > 0:
            logger.critical('Failed to commit merge:')
            logger.critical(out.strip())
            sys.exit(1)
        logger.info(out.strip())
    else:
        # Interactive, need the terminal, so exec git directly
        commitargs.append('--edit')
        commitcmd = ['git'] + commitargs
        logger.info('Invoking: %s', ' '.join(commitcmd))
        if hasattr(sys, '_running_in_pytest'):
            _out = b4.git_run_command(None, commitargs)
            sys.exit(_out[0])
        os.chdir(topdir)
        os.execvp(commitcmd[0], commitcmd)

    if os.path.exists(mmf):
        os.unlink(mmf)
    logger.info('Merge completed successfully.')


def _load_shazam_state(require_state: bool = True) -> Tuple[str, str, str, Optional[Dict[str, Any]]]:
    topdir = b4.git_get_toplevel()
    if not topdir:
        logger.critical('Could not figure out where your git dir is.')
        sys.exit(1)
    common_dir = b4.git_get_common_dir(topdir)
    if not common_dir:
        logger.critical('Unable to determine git common dir.')
        sys.exit(1)

    state_file = os.path.join(common_dir, 'b4-shazam-state.json')
    state = None
    if require_state:
        if not os.path.exists(state_file):
            logger.critical('No shazam state found. Nothing to continue.')
            sys.exit(1)
        with open(state_file, 'r') as fh:
            state = json.load(fh)
        patches_dir = os.path.join(common_dir, 'b4-shazam-patches')
        if not os.path.isdir(patches_dir):
            logger.critical('Patches directory not found. State may be corrupted.')
            logger.critical('Run: b4 shazam --abort')
            sys.exit(1)

    return topdir, common_dir, state_file, state


def shazam_continue(cmdargs: argparse.Namespace) -> None:
    topdir, common_dir, state_file, state = _load_shazam_state(require_state=True)
    assert state is not None
    patches_dir = os.path.join(common_dir, 'b4-shazam-patches')

    # Stage any resolved files
    b4.git_run_command(topdir, ['add', '-u'], logstderr=True, rundir=topdir)

    # Check for remaining unmerged files
    _ecode, unmerged = b4.git_run_command(topdir, ['diff', '--name-only', '--diff-filter=U'],
                                          logstderr=True, rundir=topdir)
    if unmerged.strip():
        logger.critical('There are still unresolved conflicts:')
        logger.critical(unmerged.strip())
        logger.critical('Resolve them, then run: b4 shazam --continue')
        sys.exit(1)

    # Apply remaining patches and finish merge
    _apply_remaining_patches(topdir, patches_dir, state, state_file, common_dir)


def shazam_abort(cmdargs: argparse.Namespace) -> None:
    topdir, common_dir, state_file, _state = _load_shazam_state(require_state=False)
    found = False

    # Abort in-progress merge if any
    b4.git_run_command(topdir, ['merge', '--abort'], logstderr=True, rundir=topdir)

    # Clean up patches directory
    patches_dir = os.path.join(common_dir, 'b4-shazam-patches')
    if os.path.exists(patches_dir):
        shutil.rmtree(patches_dir)
        found = True

    # Clean up worktree if it exists
    gwt = os.path.join(common_dir, 'b4-shazam-worktree')
    if os.path.exists(gwt):
        b4.git_run_command(topdir, ['worktree', 'remove', '--force', gwt])
        found = True

    if os.path.exists(state_file):
        os.unlink(state_file)
        found = True

    if found:
        logger.info('Shazam aborted and cleaned up.')
    else:
        logger.info('No shazam in progress.')


def main(cmdargs: argparse.Namespace) -> None:
    # We force some settings
    if cmdargs.subcmd == 'shazam':
        if getattr(cmdargs, 'shazam_continue', False):
            return shazam_continue(cmdargs)
        if getattr(cmdargs, 'shazam_abort', False):
            return shazam_abort(cmdargs)
        cmdargs.checknewer = True
        cmdargs.threeway = False
        cmdargs.nopartialreroll = False
        cmdargs.outdir = '-'
        cmdargs.guessbranch = None
        if cmdargs.merge:
            cmdargs.makefetchhead = True
        if cmdargs.makefetchhead:
            cmdargs.guessbase = True
        else:
            cmdargs.guessbase = False
    else:
        cmdargs.mergebase = False

    if cmdargs.checknewer:
        # Force nocache mode
        cmdargs.nocache = True

    if cmdargs.subcmd == 'mbox' and cmdargs.refetch:
        return refetch(cmdargs.refetch)

    try:
        msgid, msgs = b4.retrieve_messages(cmdargs)
    except LookupError as ex:
        logger.critical('CRITICAL: %s', ex)
        sys.exit(1)

    if not msgs or not msgid:
        sys.exit(1)

    if len(msgs) and cmdargs.checknewer and b4.can_network:
        msgs = get_extra_series(msgs, direction=1, nocache=cmdargs.nocache)

    if cmdargs.subcmd in ('am', 'shazam'):
        make_am(msgs, cmdargs, msgid)
        return

    logger.info('%s messages in the thread', len(msgs))
    if cmdargs.subcmd == 'mbox' and cmdargs.minimize:
        msgs = minimize_thread(msgs)

    if cmdargs.outdir == '-':
        logger.info('---')
        save_msgs_as_mbox('-', msgs)
        return

    # Check if outdir is an existing maildir
    if b4.is_maildir(cmdargs.outdir):
        added = save_msgs_as_mbox(cmdargs.outdir, msgs, filterdupes=cmdargs.filterdupes)
        logger.info('Added %s messages to maildir %s', added, cmdargs.outdir)
        return

    config = b4.get_main_config()
    if cmdargs.maildir or config.get('save-maildirs', 'no') == 'yes':
        save_maildir = True
        dftext = 'maildir'
    else:
        save_maildir = False
        dftext = 'mbx'

    if cmdargs.wantname:
        savename = os.path.join(cmdargs.outdir, cmdargs.wantname)
    else:
        safe_msgid = re.sub(r'[^\w@.+%-]+', '_', msgid).strip('_')
        savename = os.path.join(cmdargs.outdir, f'{safe_msgid}.{dftext}')

    if save_maildir:
        if os.path.isdir(savename):
            shutil.rmtree(savename)
        mailbox.Maildir(savename, create=True)
        save_msgs_as_mbox(savename, msgs)
        logger.info('Saved maildir %s', savename)
        return

    save_msgs_as_mbox(savename, msgs)
    logger.info('Saved %s', savename)
