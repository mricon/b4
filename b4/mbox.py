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
import tempfile

import urllib.parse
import xml.etree.ElementTree

import b4

from typing import Optional, Tuple

logger = b4.logger


def make_am(msgs, cmdargs, msgid):
    config = b4.get_main_config()
    outdir = cmdargs.outdir
    if outdir == '-':
        cmdargs.nocover = True
    wantver = cmdargs.wantver
    wantname = cmdargs.wantname
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
                                    covertrailers=covertrailers, trailer_order=config['trailer-order'],
                                    addmysob=cmdargs.addmysob, addlink=cmdargs.addlink,
                                    linkmask=config['linkmask'], cherrypick=cherrypick,
                                    copyccs=cmdargs.copyccs)
    except KeyError:
        sys.exit(1)

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
        gitbranch = lser.get_slug(extended=False)

    if outdir != '-':
        am_filename = os.path.join(outdir, f'{slug}.{dftext}')
        am_cover = os.path.join(outdir, f'{slug}.cover')

        if os.path.exists(am_filename):
            if os.path.isdir(am_filename):
                shutil.rmtree(am_filename)
            else:
                os.unlink(am_filename)
        if save_maildir:
            d_new = os.path.join(am_filename, 'new')
            pathlib.Path(d_new).mkdir(parents=True)
            d_cur = os.path.join(am_filename, 'cur')
            pathlib.Path(d_cur).mkdir(parents=True)
            d_tmp = os.path.join(am_filename, 'tmp')
            pathlib.Path(d_tmp).mkdir(parents=True)
            for m_slug, msg in am_msgs:
                with open(os.path.join(d_tmp, f'{m_slug}.eml'), 'wb') as mfh:
                    mfh.write(msg.as_bytes(policy=b4.emlpolicy))
                os.rename(os.path.join(d_tmp, f'{m_slug}.eml'), os.path.join(d_new, f'{m_slug}.eml'))
        else:
            with open(am_filename, 'wb') as fh:
                b4.save_git_am_mbox([x[1] for x in am_msgs], fh)
    else:
        am_filename = None
        am_cover = None
        b4.save_git_am_mbox([x[1] for x in am_msgs], sys.stdout.buffer)

    logger.info('---')

    if cherrypick is None:
        logger.critical('Total patches: %s', len(am_msgs))
    else:
        logger.info('Total patches: %s (cherrypicked: %s)', len(am_msgs), cmdargs.cherrypick)
    # Check if any of the followup-trailers is an Obsoleted-by
    if not cmdargs.checknewer:
        warned = False
        for lmsg in lser.patches:
            # Only check cover letter or first patch
            if not lmsg or lmsg.counter > 1:
                continue
            for trailer in list(lmsg.followup_trailers):
                if trailer[0].lower() == 'obsoleted-by':
                    lmsg.followup_trailers.remove(trailer)
                    if warned:
                        continue
                    logger.critical('---')
                    logger.critical('WARNING: Found an Obsoleted-by follow-up trailer!')
                    logger.critical('         Rerun with -c to automatically retrieve the new series.')
                    warned = True

    if lser.has_cover and lser.patches[0].followup_trailers and not covertrailers:
        # Warn that some trailers were sent to the cover letter
        logger.critical('---')
        logger.critical('NOTE: Some trailers were sent to the cover letter:')
        tseen = set()
        for trailer in lser.patches[0].followup_trailers:
            if tuple(trailer[:2]) not in tseen:
                logger.critical('      %s: %s', trailer[0], trailer[1])
                tseen.add(tuple(trailer[:2]))
        logger.critical('NOTE: Rerun with -t to apply them to all patches')
    if len(lser.trailer_mismatches):
        logger.critical('---')
        logger.critical('NOTE: some trailers ignored due to from/email mismatches:')
        for tname, tvalue, fname, femail in lser.trailer_mismatches:
            logger.critical('    ! Trailer: %s: %s', tname, tvalue)
            logger.critical('     Msg From: %s <%s>', fname, femail)
        logger.critical('NOTE: Rerun with -S to apply them anyway')

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

    if lser.has_cover and not cmdargs.nocover:
        lser.save_cover(am_cover)

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

    linkurl = config['linkmask'] % top_msgid
    if cmdargs.quiltready:
        q_dirname = os.path.join(outdir, f'{slug}.patches')
        save_as_quilt(am_msgs, q_dirname)
        logger.critical('Quilt: %s', q_dirname)

    logger.critical(' Link: %s', linkurl)

    base_commit = None
    matches = re.search(r'base-commit: .*?([0-9a-f]+)', first_body, re.MULTILINE)
    if matches:
        base_commit = matches.groups()[0]
    else:
        # Try a more relaxed search
        matches = re.search(r'based on .*?([0-9a-f]{40})', first_body, re.MULTILINE)
        if matches:
            base_commit = matches.groups()[0]

    if base_commit:
        logger.critical(' Base: %s', base_commit)
        logger.critical('       git checkout -b %s %s', gitbranch, base_commit)
        if cmdargs.outdir != '-':
            logger.critical('       git am %s', am_filename)
    else:
        cleanmsg = ''
        if topdir is not None:
            checked, mismatches = lser.check_applies_clean(topdir)
            if mismatches == 0 and checked != mismatches:
                cleanmsg = ' (applies clean to current tree)'
            elif cmdargs.guessbase:
                # Look at the last 10 tags and see if it applies cleanly to
                # any of them. I'm not sure how useful this is, but I'm going
                # to put it in for now and maybe remove later if it causes
                # problems or slowness
                if checked != mismatches:
                    best_matches = mismatches
                    cleanmsg = ' (best guess: current tree)'
                else:
                    best_matches = None
                # sort the tags by authordate
                gitargs = ['tag', '-l', '--sort=-taggerdate']
                lines = b4.git_get_command_lines(None, gitargs)
                if lines:
                    # Check last 10 tags
                    for tag in lines[:10]:
                        logger.debug('Checking base-commit possibility for %s', tag)
                        checked, mismatches = lser.check_applies_clean(topdir, tag)
                        if mismatches == 0 and checked != mismatches:
                            cleanmsg = ' (applies clean to: %s)' % tag
                            break
                        # did they all mismatch?
                        if checked == mismatches:
                            continue
                        if best_matches is None or mismatches < best_matches:
                            best_matches = mismatches
                            cleanmsg = ' (best guess: %s)' % tag

        logger.critical(' Base: not found%s', cleanmsg)
        if cmdargs.outdir != '-':
            logger.critical('       git am %s', am_filename)

    thanks_record_am(lser, cherrypick=cherrypick)


def thanks_record_am(lser, cherrypick=None):
    # Are we tracking this already?
    datadir = b4.get_data_dir()
    slug = lser.get_slug(extended=True)
    filename = '%s.am' % slug

    patches = list()
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

        if pmsg.pwhash is None:
            logger.debug('Unable to get hashes for all patches, not tracking for thanks')
            return

        prefix = '%s/%s' % (str(pmsg.counter).zfill(padlen), pmsg.expected)
        patches.append((pmsg.subject, pmsg.pwhash, pmsg.msgid, prefix))
        at += 1

    if lmsg is None:
        logger.debug('All patches missing, not tracking for thanks')
        return

    allto = email.utils.getaddresses([str(x) for x in lmsg.msg.get_all('to', [])])
    allcc = email.utils.getaddresses([str(x) for x in lmsg.msg.get_all('cc', [])])

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


def save_as_quilt(am_msgs, q_dirname):
    if os.path.exists(q_dirname):
        logger.critical('ERROR: Directory %s exists, not saving quilt patches', q_dirname)
        return
    pathlib.Path(q_dirname).mkdir(parents=True)
    patch_filenames = list()
    with tempfile.TemporaryDirectory() as tfd:
        m_out = os.path.join(tfd, 'm')
        p_out = os.path.join(tfd, 'p')
        for slug, msg in am_msgs:
            # Run each message through git mailinfo
            cmdargs = ['mailinfo', '--encoding=UTF-8', '--scissors', m_out, p_out]
            ecode, info = b4.git_run_command(None, cmdargs, msg.as_bytes(policy=b4.emlpolicy))
            if not len(info.strip()):
                logger.critical('ERROR: Could not get mailinfo from patch %s', msg.get('Subject', '(no subject)'))
                continue
            patchinfo = dict()
            for line in info.split('\n'):
                line = line.strip()
                if not line:
                    continue
                chunks = line.split(':',  1)
                patchinfo[chunks[0]] = chunks[1].strip().encode()

            patch_filename = f'{slug}.patch'
            patch_filenames.append(patch_filename)
            quilt_out = os.path.join(q_dirname, patch_filename)
            with open(quilt_out, 'wb') as fh:
                fh.write(b'From: %s <%s>\n' % (patchinfo['Author'], patchinfo['Email']))
                fh.write(b'Subject: %s\n' % patchinfo['Subject'])
                fh.write(b'Date: %s\n' % patchinfo['Date'])
                fh.write(b'\n')
                with open(m_out, 'rb') as mfh:
                    shutil.copyfileobj(mfh, fh)
                with open(p_out, 'rb') as pfh:
                    shutil.copyfileobj(pfh, fh)
            logger.debug('  Wrote: %s', patch_filename)
    # Write the series file
    with open(os.path.join(q_dirname, 'series'), 'w') as sfh:
        for patch_filename in patch_filenames:
            sfh.write('%s\n' % patch_filename)


def get_extra_series(msgs: list, direction: int = 1, wantvers: Optional[int] = None, nocache: bool = False,
                     useproject: Optional[str] = None) -> list:
    base_msg = None
    latest_revision = None
    seen_msgids = set()
    seen_covers = set()
    obsoleted = list()
    for msg in msgs:
        msgid = b4.LoreMessage.get_clean_msgid(msg)
        seen_msgids.add(msgid)
        lsub = b4.LoreSubject(msg['Subject'])
        if direction > 0 and lsub.reply:
            # Does it have an "Obsoleted-by: trailer?
            rmsg = b4.LoreMessage(msg)
            trailers, mismatches = rmsg.get_trailers()
            for tl in trailers:
                if tl[0].lower() == 'obsoleted-by':
                    for chunk in tl[1].split('/'):
                        if chunk.find('@') > 0 and chunk not in seen_msgids:
                            obsoleted.append(chunk)
                            break
        # Ignore patches above 1
        if lsub.counter > 1:
            continue
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

    if base_msg is None:
        logger.debug('Could not find cover of 1st patch in mbox')
        return msgs

    config = b4.get_main_config()
    loc = urllib.parse.urlparse(config['midmask'])
    if not useproject:
        projects = b4.get_lore_projects_from_msg(base_msg)
        if not projects:
            logger.info('Unable to figure out list archive location')
            return msgs
        useproject = projects[0]

    listarc = '%s://%s/%s/' % (loc.scheme, loc.netloc, useproject)

    if not listarc:
        logger.info('Unable to figure out list archive location')
        return msgs

    nt_msgs = list()
    if len(obsoleted):
        for nt_msgid in obsoleted:
            logger.info('Obsoleted-by: %s', nt_msgid)
            # Grab this thread from remote
            t_mbx_url = '%s/%s/t.mbox.gz' % (listarc.rstrip('/'), nt_msgid)
            potentials = b4.get_pi_thread_by_url(t_mbx_url, nocache=nocache)
            if potentials:
                nt_msgs += potentials
                logger.info('   Added %s messages from that thread', len(potentials))
            else:
                logger.info('   No messages added from that thread')

    else:
        # Get subject info from base_msg again
        lsub = b4.LoreSubject(base_msg['Subject'])
        if not len(lsub.prefixes):
            logger.debug('Not checking for new revisions: no prefixes on the cover letter.')
            return msgs
        if direction < 0 and latest_revision <= 1:
            logger.debug('This is the latest version of the series')
            return msgs
        if direction < 0 and wantvers is None:
            wantvers = [latest_revision - 1]

        base_msgid = b4.LoreMessage.get_clean_msgid(base_msg)
        fromeml = email.utils.getaddresses(base_msg.get_all('from', []))[0][1]
        msgdate = email.utils.parsedate_tz(str(base_msg['Date']))
        startdate = time.strftime('%Y%m%d', msgdate[:9])
        if direction > 0:
            q = 's:"%s" AND f:"%s" AND d:%s..' % (lsub.subject.replace('"', ''), fromeml, startdate)
            queryurl = '%s?%s' % (listarc, urllib.parse.urlencode({'q': q, 'x': 'A', 'o': '-1'}))
            logger.critical('Checking for newer revisions on %s', listarc)
        else:
            q = 's:"%s" AND f:"%s" AND d:..%s' % (lsub.subject.replace('"', ''), fromeml, startdate)
            queryurl = '%s?%s' % (listarc, urllib.parse.urlencode({'q': q, 'x': 'A', 'o': '1'}))
            logger.critical('Checking for older revisions on %s', listarc)

        logger.debug('Query URL: %s', queryurl)
        session = b4.get_requests_session()
        resp = session.get(queryurl)
        # try to parse it
        try:
            tree = xml.etree.ElementTree.fromstring(resp.content)
        except xml.etree.ElementTree.ParseError as ex:
            logger.debug('Unable to parse results, ignoring: %s', ex)
            resp.close()
            return msgs
        resp.close()
        ns = {'atom': 'http://www.w3.org/2005/Atom'}
        entries = tree.findall('atom:entry', ns)

        for entry in entries:
            title = entry.find('atom:title', ns).text
            lsub = b4.LoreSubject(title)
            if lsub.reply or lsub.counter > 1:
                logger.debug('Ignoring result (not interesting): %s', title)
                continue
            link = entry.find('atom:link', ns).get('href')
            if direction > 0 and lsub.revision <= latest_revision:
                logger.debug('Ignoring result (not new revision): %s', title)
                continue
            elif direction < 0 and lsub.revision >= latest_revision:
                logger.debug('Ignoring result (not old revision): %s', title)
                continue
            elif direction < 0 and lsub.revision not in wantvers:
                logger.debug('Ignoring result (not revision we want): %s', title)
                continue
            if link.find('/%s/' % base_msgid) > 0:
                logger.debug('Ignoring result (same thread as ours):%s', title)
                continue
            if lsub.revision == 1 and lsub.revision == latest_revision:
                # Someone sent a separate message with an identical title but no new vX in the subject line
                if direction > 0:
                    # It's *probably* a new revision.
                    logger.debug('Likely a new revision: %s', title)
                else:
                    # It's *probably* an older revision.
                    logger.debug('Likely an older revision: %s', title)
            elif direction > 0 and lsub.revision > latest_revision:
                logger.debug('Definitely a new revision [v%s]: %s', lsub.revision, title)
            elif direction < 0 and lsub.revision < latest_revision:
                logger.debug('Definitely an older revision [v%s]: %s', lsub.revision, title)
            else:
                logger.debug('No idea what this is: %s', title)
                continue
            t_mbx_url = '%st.mbox.gz' % link
            logger.info('New revision: %s', title)
            potentials = b4.get_pi_thread_by_url(t_mbx_url, nocache=nocache)
            if potentials:
                nt_msgs += potentials
                logger.info('   Added %s messages from that thread', len(potentials))

    # Append all of these to the existing mailbox
    for nt_msg in nt_msgs:
        nt_msgid = b4.LoreMessage.get_clean_msgid(nt_msg)
        if nt_msgid in seen_msgids:
            logger.debug('Duplicate message, skipping')
            continue
        nt_subject = re.sub(r'\s+', ' ', nt_msg['Subject'])
        logger.debug('Adding: %s', nt_subject)
        msgs.append(nt_msg)
        seen_msgids.add(nt_msgid)

    return msgs


def get_msgs(cmdargs) -> Tuple[Optional[str], Optional[list]]:
    msgid = None
    if not cmdargs.localmbox:
        msgid = b4.get_msgid(cmdargs)
        if not msgid:
            logger.error('Error: pipe a message or pass msgid as parameter')
            sys.exit(1)

        pickings = set()
        try:
            if cmdargs.cherrypick == '_':
                # Just that msgid, please
                pickings = {msgid}
        except AttributeError:
            pass
        msgs = b4.get_pi_thread_by_msgid(msgid, useproject=cmdargs.useproject, nocache=cmdargs.nocache,
                                         onlymsgids=pickings)
        if not msgs:
            return None, msgs
    else:
        if cmdargs.localmbox == '-':
            # The entire mbox is passed via stdin, so mailsplit it and use the first message for our msgid
            with tempfile.TemporaryDirectory() as tfd:
                msgs = b4.mailsplit_bytes(sys.stdin.buffer.read(), tfd)
            if not len(msgs):
                logger.critical('Stdin did not contain any messages')
                sys.exit(1)

        elif os.path.exists(cmdargs.localmbox):
            msgid = b4.get_msgid(cmdargs)
            if os.path.isdir(cmdargs.localmbox):
                in_mbx = mailbox.Maildir(cmdargs.localmbox)
            else:
                in_mbx = mailbox.mbox(cmdargs.localmbox)

            if msgid:
                msgs = b4.get_strict_thread(in_mbx, msgid)
                if not msgs:
                    logger.critical('Could not find %s in %s', msgid, cmdargs.localmbox)
                    sys.exit(1)
            else:
                msgs = in_mbx
        else:
            logger.critical('Mailbox %s does not exist', cmdargs.localmbox)
            sys.exit(1)

    if not msgid and msgs:
        for msg in msgs:
            msgid = msg.get('Message-ID', None)
            if msgid:
                msgid = msgid.strip('<>')
                break

    return msgid, msgs


def main(cmdargs):
    if cmdargs.checknewer:
        # Force nocache mode
        cmdargs.nocache = True

    msgid, msgs = get_msgs(cmdargs)
    if not msgs:
        return

    if len(msgs) and cmdargs.checknewer:
        msgs = get_extra_series(msgs, direction=1, useproject=cmdargs.useproject)

    if cmdargs.subcmd == 'am':
        make_am(msgs, cmdargs, msgid)
        return

    logger.info('%s messages in the thread', len(msgs))
    if cmdargs.outdir == '-':
        logger.info('---')
        b4.save_git_am_mbox(msgs, sys.stdout.buffer)
        return

    # Check if outdir is a maildir
    if (os.path.isdir(os.path.join(cmdargs.outdir, 'new'))
            and os.path.isdir(os.path.join(cmdargs.outdir, 'cur'))
            and os.path.isdir(os.path.join(cmdargs.outdir, 'tmp'))):
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
        b4.save_git_am_mbox(msgs, fh)

    logger.info('Saved %s', savename)
