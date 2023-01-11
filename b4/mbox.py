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
import email.message
import email.utils
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

from typing import Optional, List
from string import Template

logger = b4.logger

DEFAULT_MERGE_TEMPLATE = """Merge ${patch_or_series} "${seriestitle}"

${authorname} <${authoremail}> says:

${covermessage}

Link: ${midurl}
"""


def make_am(msgs: List[email.message.Message], cmdargs: argparse.Namespace, msgid: str) -> None:
    config = b4.get_main_config()
    outdir = cmdargs.outdir
    if outdir == '-':
        cmdargs.nocover = True
    wantver = cmdargs.wantver
    covertrailers = cmdargs.covertrailers
    count = len(msgs)
    logger.info('Analyzing %s messages in the thread', count)
    lmbx = b4.LoreMailbox()
    # Go through the mbox once to populate base series
    for msg in msgs:
        lmbx.add_message(msg)

    reroll = True
    if cmdargs.nopartialreroll:
        reroll = False

    lser = lmbx.get_series(revision=wantver, sloppytrailers=cmdargs.sloppytrailers, reroll=reroll)
    if lser is None and wantver is None:
        logger.critical('No patches found.')
        return
    if lser is None:
        logger.critical('Unable to find revision %s', wantver)
        return
    if len(lmbx.series) > 1 and not wantver:
        logger.info('Will use the latest revision: v%s', lser.revision)
        logger.info('You can pick other revisions using the -vN flag')

    if cmdargs.cherrypick:
        cherrypick = list()
        if cmdargs.cherrypick == '_':
            # Only grab the exact msgid provided
            at = 0
            for lmsg in lser.patches[1:]:
                at += 1
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
                if fnmatch.fnmatch(lmsg.subject, cmdargs.cherrypick):
                    cherrypick.append(at)
            if not len(cherrypick):
                logger.critical('Could not match "%s" to any subjects in the series', cmdargs.cherrypick)
                sys.exit(1)
        else:
            cherrypick = list(b4.parse_int_range(cmdargs.cherrypick, upper=len(lser.patches)-1))
    else:
        cherrypick = None

    try:
        am_msgs = lser.get_am_ready(noaddtrailers=cmdargs.noaddtrailers,
                                    covertrailers=covertrailers, addmysob=cmdargs.addmysob,
                                    addlink=cmdargs.addlink, linkmask=config['linkmask'], cherrypick=cherrypick,
                                    copyccs=cmdargs.copyccs, allowbadchars=cmdargs.allowbadchars)
    except KeyError:
        sys.exit(1)

    logger.info('---')

    if cherrypick is None:
        logger.critical('Total patches: %s', len(am_msgs))
    else:
        logger.info('Total patches: %s (cherrypicked: %s)', len(am_msgs), cmdargs.cherrypick)

    if lser.has_cover and lser.patches[0].followup_trailers and not covertrailers:
        # Warn that some trailers were sent to the cover letter
        logger.critical('---')
        logger.critical('NOTE: Some trailers were sent to the cover letter:')
        tseen = set()
        for ltr in lser.patches[0].followup_trailers:
            if ltr not in tseen:
                logger.critical('      %s', ltr.as_string(omit_extinfo=True))
                tseen.add(ltr)
        logger.critical('NOTE: Rerun with -t to apply them to all patches')
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
    if top_msgid is None:
        logger.critical('Could not find any patches in the series.')
        return

    topdir = b4.git_get_toplevel()

    if cmdargs.threeway:
        if not topdir:
            logger.critical('WARNING: cannot prepare 3-way (not in a git dir)')
        elif not lser.complete:
            logger.critical('WARNING: cannot prepare 3-way (series incomplete)')
        else:
            rstart, rend = lser.make_fake_am_range(gitdir=None)
            if rstart and rend:
                logger.info('Prepared a fake commit range for 3-way merge (%.12s..%.12s)', rstart, rend)

    logger.critical('---')
    if lser.partial_reroll:
        logger.critical('WARNING: v%s is a partial reroll from previous revisions', lser.revision)
        logger.critical('         Please carefully review the resulting series to ensure correctness')
        logger.critical('         Pass --no-partial-reroll to disable')
        logger.critical('---')
    if not lser.complete and not cmdargs.cherrypick:
        logger.critical('WARNING: Thread incomplete!')

    gitbranch = lser.get_slug(extended=False)
    am_filename = None

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
            gitbranch = slug
        else:
            slug = lser.get_slug(extended=True)

        if outdir != '-':
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

        if lser.has_cover and not cmdargs.nocover:
            lser.save_cover(am_cover)

        linkurl = config['linkmask'] % top_msgid
        if cmdargs.quiltready:
            q_dirname = os.path.join(outdir, f'{slug}.patches')
            save_as_quilt(am_msgs, q_dirname)
            logger.critical('Quilt: %s', q_dirname)

        logger.critical(' Link: %s', linkurl)

    base_commit = None
    matches = re.search(r'base-commit: .*?([\da-f]+)', first_body, re.MULTILINE)
    if matches:
        base_commit = matches.groups()[0]
    else:
        # Try a more relaxed search
        matches = re.search(r'based on .*?([\da-f]{40})', first_body, re.MULTILINE)
        if matches:
            base_commit = matches.groups()[0]

    if base_commit and topdir:
        # Does it actually exist in this tree?
        if not b4.git_commit_exists(topdir, base_commit):
            logger.info(' Base: base-commit %s not known, ignoring', base_commit)
            base_commit = None
        else:
            logger.info(' Base: using specified base-commit %s', base_commit)

    if not base_commit and topdir and cmdargs.guessbase:
        logger.critical(' Base: attempting to guess base-commit...')
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
        except IndexError:
            logger.critical(' Base: failed to guess base')

    if cmdargs.subcmd == 'shazam':
        if not topdir:
            logger.critical('Could not figure out where your git dir is, cannot shazam.')
            sys.exit(1)
        ifh = io.BytesIO()
        b4.save_git_am_mbox(am_msgs, ifh)
        ambytes = ifh.getvalue()
        if not cmdargs.makefetchhead:
            amflags = config.get('shazam-am-flags', '')
            sp = shlex.shlex(amflags, posix=True)
            sp.whitespace_split = True
            amargs = list(sp)
            ecode, out = b4.git_run_command(topdir, ['am'] + amargs, stdin=ambytes, logstderr=True)
            logger.info(out.strip())
            if ecode == 0:
                thanks_record_am(lser, cherrypick=cherrypick)
            sys.exit(ecode)

        if not base_commit:
            # Try our best with HEAD, I guess
            base_commit = 'HEAD'

        with b4.git_temp_worktree(topdir, base_commit) as gwt:
            logger.info('Magic: Preparing a sparse worktree')
            ecode, out = b4.git_run_command(gwt, ['sparse-checkout', 'init'], logstderr=True)
            if ecode > 0:
                logger.critical('Error running sparse-checkout init')
                logger.critical(out)
                sys.exit(ecode)
            ecode, out = b4.git_run_command(gwt, ['checkout'], logstderr=True)
            if ecode > 0:
                logger.critical('Error running checkout into sparse workdir')
                logger.critical(out)
                sys.exit(ecode)
            ecode, out = b4.git_run_command(gwt, ['am'], stdin=ambytes, logstderr=True)
            if ecode > 0:
                logger.critical('Unable to cleanly apply series, see failure log below')
                logger.critical('---')
                logger.critical(out.strip())
                logger.critical('---')
                logger.critical('Not fetching into FETCH_HEAD')
                sys.exit(ecode)
            logger.info('---')
            logger.info(out.strip())
            logger.info('---')
            logger.info('Fetching into FETCH_HEAD')
            gitargs = ['fetch', gwt]
            ecode, out = b4.git_run_command(topdir, gitargs, logstderr=True)
            if ecode > 0:
                logger.critical('Unable to fetch from the worktree')
                logger.critical(out.strip())
                sys.exit(ecode)
            gitargs = ['rev-parse', '--git-path', 'FETCH_HEAD']
            ecode, fhf = b4.git_run_command(topdir, gitargs, logstderr=True)
            if ecode > 0:
                logger.critical('Unable to find FETCH_HEAD')
                logger.critical(out.strip())
                sys.exit(ecode)
            with open(fhf.rstrip(), 'r') as fhh:
                contents = fhh.read()
            linkurl = config['linkmask'] % top_msgid
            if len(am_msgs) > 1:
                mmsg = 'patches from %s' % linkurl
            else:
                mmsg = 'patch from %s' % linkurl
            new_contents = contents.replace(gwt, mmsg)
            if new_contents != contents:
                with open(fhf, 'w') as fhh:
                    fhh.write(new_contents)

            gitargs = ['rev-parse', '--git-dir']
            ecode, fhf = b4.git_run_command(topdir, gitargs, logstderr=True)
            if ecode > 0:
                logger.critical('Unable to find git directory')
                logger.critical(out.strip())
                sys.exit(ecode)
            mmf = os.path.join(fhf.rstrip(), 'b4-cover')
            merge_template = DEFAULT_MERGE_TEMPLATE
            if config.get('shazam-merge-template'):
                # Try to load this template instead
                try:
                    merge_template = b4.read_template(config['shazam-merge-template'])
                except FileNotFoundError:
                    logger.critical('ERROR: shazam-merge-template says to use %s, but it does not exist',
                                    config['shazam-merge-template'])
                    sys.exit(2)

            # Write out a sample merge message using the cover letter
            if os.path.exists(mmf):
                # Make sure any old cover letters don't confuse anyone
                os.unlink(mmf)

            if lser.has_cover:
                cmsg = lser.patches[0]
                parts = b4.LoreMessage.get_body_parts(cmsg.body)
                covermessage = parts[1]
            else:
                cmsg = lser.patches[1]
                covermessage = ('NOTE: No cover letter provided by the author.\n'
                                '      Add merge commit message here.')
            tptvals = {
                'seriestitle': cmsg.subject,
                'authorname': cmsg.fromname,
                'authoremail': cmsg.fromemail,
                'covermessage': covermessage,
                'midurl': linkurl,
            }
            if len(am_msgs) > 1:
                tptvals['patch_or_series'] = 'patch series'
            else:
                tptvals['patch_or_series'] = 'patch'

            body = Template(merge_template).safe_substitute(tptvals)
            with open(mmf, 'w') as mmh:
                mmh.write(body)

        mergeflags = config.get('shazam-merge-flags', '--signoff')
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
                out, logstr = b4.git_run_command(None, mergeargs)
                sys.exit(out)

            # We exec git-merge and let it take over
            os.execvp(mergecmd[0], mergecmd)

        logger.info('You can now merge or checkout FETCH_HEAD')
        logger.info('  e.g.: %s', ' '.join(mergecmd))
        sys.exit(0)

    if not base_commit:
        checked, mismatches = lser.check_applies_clean(topdir, at=cmdargs.guessbranch)
        if checked and len(mismatches) == 0 and checked != mismatches:
            logger.critical(' Base: applies clean to current tree')
            base_commit = 'HEAD'
        else:
            logger.critical(' Base: not specified')

    if base_commit is not None:
        logger.critical('       git checkout -b %s %s', gitbranch, base_commit)
    if cmdargs.outdir != '-':
        logger.critical('       git am %s', am_filename)
    thanks_record_am(lser, cherrypick=cherrypick)


def thanks_record_am(lser: b4.LoreSeries, cherrypick: bool = None) -> None:
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
        msgids.append(pmsg.msgid)

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
    except Exception as ex:  # noqa
        allto = []
        logger.debug('Unable to parse the To: header in %s: %s', lmsg.msgid, str(ex))
    try:
        allcc = email.utils.getaddresses([str(x) for x in lmsg.msg.get_all('cc', [])])
    except Exception as ex:  # noqa
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
    pwstate = config.get('pw-review-state')
    if pwstate:
        b4.patchwork_set_state(msgids, pwstate)


def save_as_quilt(am_msgs: List[email.message.Message], q_dirname: str) -> None:
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
                fh.write(b'From: %s <%s>\n' % (i.get('Author').encode(), i.get('Email').encode()))
            else:
                fh.write(b'From: %s\n' % i.get('Email').encode())
            fh.write(b'Subject: %s\n' % i.get('Subject').encode())
            fh.write(b'Date: %s\n' % i.get('Date').encode())
            fh.write(b'\n')
            fh.write(m)
            fh.write(p)
        logger.debug('  Wrote: %s', patch_filename)
    # Write the series file
    with open(os.path.join(q_dirname, 'series'), 'w') as sfh:
        for patch_filename in patch_filenames:
            sfh.write('%s\n' % patch_filename)


def get_extra_series(msgs: list, direction: int = 1, wantvers: Optional[int] = None,
                     nocache: bool = False) -> List[email.message.Message]:
    base_msg = None
    latest_revision = None
    seen_msgids = set()
    seen_covers = set()
    queries = set()
    for msg in msgs:
        msgid = b4.LoreMessage.get_clean_msgid(msg)
        seen_msgids.add(msgid)
        lsub = b4.LoreSubject(msg['Subject'])

        # Ignore patches above 1
        if lsub.counter > 1:
            continue

        if not lsub.reply:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode()
                matches = re.search(r'^change-id:\s+(\S+)', payload, flags=re.I | re.M)
                if matches:
                    logger.debug('Found change-id %s', matches.groups()[0])
                    q = 'nq:"change-id: %s"' % matches.groups()[0]
                    queries.add(q)

        if base_msg is not None:
            logger.debug('Current base_msg: %s', base_msg['Subject'])
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

    if not queries and base_msg is None:
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

    fromeml = email.utils.getaddresses(base_msg.get_all('from', []))[0][1]
    msgdate = email.utils.parsedate_tz(str(base_msg['Date']))
    q = '(s:"%s" AND f:"%s")' % (lsub.subject.replace('"', ''), fromeml)
    queries.add(q)
    startdate = time.strftime('%Y%m%d', msgdate[:9])
    if direction > 0:
        logger.critical('Checking for newer revisions')
        datelim = 'd:%s..' % startdate
    else:
        logger.critical('Checking for older revisions')
        datelim = 'd:..%s' % startdate

    q = '(%s) AND %s' % (' OR '.join(queries), datelim)
    q_msgs = b4.get_pi_search_results(q, nocache=nocache)
    if not q_msgs:
        return msgs

    seen_revisions = dict()
    for q_msg in q_msgs:
        q_msgid = b4.LoreMessage.get_clean_msgid(q_msg)
        lsub = b4.LoreSubject(q_msg.get('subject'))
        if q_msgid in seen_msgids:
            logger.debug('Skipping %s: already have it', lsub.full_subject)
            continue
        if lsub.reply:
            # These will get sorted out later
            logger.debug('Adding reply: %s', lsub.full_subject)
            msgs.append(q_msg)
            seen_msgids.add(q_msgid)
            continue

        if direction > 0 and lsub.revision <= latest_revision:
            logger.debug('Ignoring result (not new revision): %s', lsub.full_subject)
            continue
        elif direction < 0 and lsub.revision >= latest_revision:
            logger.debug('Ignoring result (not old revision): %s', lsub.full_subject)
            continue
        elif direction < 0 and lsub.revision not in wantvers:
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


def is_maildir(dest: str) -> bool:
    if (os.path.isdir(os.path.join(dest, 'new'))
            and os.path.isdir(os.path.join(dest, 'cur'))
            and os.path.isdir(os.path.join(dest, 'tmp'))):
        return True
    return False


def refetch(dest: str) -> None:
    if is_maildir(dest):
        mbox = mailbox.Maildir(dest)
    else:
        mbox = mailbox.mbox(dest)

    by_msgid = dict()
    for key, msg in mbox.items():
        msgid = b4.LoreMessage.get_clean_msgid(msg)
        if msgid not in by_msgid:
            amsgs = b4.get_pi_thread_by_msgid(msgid, nocache=True)
            for amsg in amsgs:
                amsgid = b4.LoreMessage.get_clean_msgid(amsg)
                if amsgid not in by_msgid:
                    by_msgid[amsgid] = amsg
        if msgid in by_msgid:
            mbox.update(((key, by_msgid[msgid]),))
            logger.info('Refetched: %s', msg.get('Subject'))
        else:
            logger.warn('WARNING: Message-id not known: %s', msgid)
    mbox.close()


def main(cmdargs: argparse.Namespace) -> None:
    if cmdargs.subcmd == 'shazam':
        # We force some settings
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

    if not msgs:
        sys.exit(1)

    if len(msgs) and cmdargs.checknewer and b4.can_network:
        msgs = get_extra_series(msgs, direction=1, nocache=cmdargs.nocache)

    if cmdargs.subcmd in ('am', 'shazam'):
        make_am(msgs, cmdargs, msgid)
        return

    logger.info('%s messages in the thread', len(msgs))
    if cmdargs.outdir == '-':
        logger.info('---')
        b4.save_mboxrd_mbox(msgs, sys.stdout.buffer, mangle_from=False)
        return

    # Check if outdir is a maildir
    if is_maildir(cmdargs.outdir):
        mdr = mailbox.Maildir(cmdargs.outdir)
        have_msgids = set()
        added = 0
        if cmdargs.filterdupes:
            for emsg in mdr:
                have_msgids.add(b4.LoreMessage.get_clean_msgid(emsg))
        for msg in msgs:
            if b4.LoreMessage.get_clean_msgid(msg) not in have_msgids:
                added += 1
                mdr.add(msg)
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
        md = mailbox.Maildir(savename, create=True)
        for msg in msgs:
            md.add(msg)
        md.close()
        logger.info('Saved maildir %s', savename)
        return

    with open(savename, 'wb') as fh:
        b4.save_mboxrd_mbox(msgs, fh, mangle_from=True)

    logger.info('Saved %s', savename)
