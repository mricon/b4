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

import urllib.parse
import xml.etree.ElementTree

import b4

from tempfile import mkstemp

logger = b4.logger


def mbox_to_am(mboxfile, cmdargs):
    config = b4.get_main_config()
    outdir = cmdargs.outdir
    if outdir == '-':
        cmdargs.nocover = True
    wantver = cmdargs.wantver
    wantname = cmdargs.wantname
    covertrailers = cmdargs.covertrailers
    if os.path.isdir(mboxfile):
        mbx = mailbox.Maildir(mboxfile)
    else:
        mbx = mailbox.mbox(mboxfile)
    count = len(mbx)
    logger.info('Analyzing %s messages in the thread', count)
    lmbx = b4.LoreMailbox()
    # Go through the mbox once to populate base series
    for key, msg in mbx.items():
        lmbx.add_message(msg)

    lser = lmbx.get_series(revision=wantver, sloppytrailers=cmdargs.sloppytrailers)
    if lser is None and wantver is None:
        logger.critical('No patches found.')
        return
    if lser is None:
        logger.critical('Unable to find revision %s', wantver)
        return
    if len(lmbx.series) > 1 and not wantver:
        logger.info('Will use the latest revision: v%s', lser.revision)
        logger.info('You can pick other revisions using the -vN flag')

    if wantname:
        slug = wantname
        if wantname.find('.') > -1:
            slug = '.'.join(wantname.split('.')[:-1])
        gitbranch = slug
    else:
        slug = lser.get_slug(extended=True)
        gitbranch = lser.get_slug(extended=False)

    if outdir != '-':
        am_filename = os.path.join(outdir, '%s.mbx' % slug)
        am_cover = os.path.join(outdir, '%s.cover' % slug)

        if os.path.exists(am_filename):
            os.unlink(am_filename)
    else:
        # Create a temporary file that we will remove later
        am_filename = mkstemp('b4-am-stdout')[1]
        am_cover = None

    logger.info('---')
    if cmdargs.cherrypick:
        cherrypick = list()
        if cmdargs.cherrypick == '_':
            msgid = b4.get_msgid(cmdargs)
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

    logger.critical('Writing %s', am_filename)
    mbx = mailbox.mbox(am_filename)
    try:
        am_mbx = lser.save_am_mbox(mbx, noaddtrailers=cmdargs.noaddtrailers,
                                   covertrailers=covertrailers, trailer_order=config['trailer-order'],
                                   addmysob=cmdargs.addmysob, addlink=cmdargs.addlink,
                                   linkmask=config['linkmask'], cherrypick=cherrypick,
                                   copyccs=cmdargs.copyccs)
    except KeyError:
        sys.exit(1)

    logger.info('---')

    if cherrypick is None:
        logger.critical('Total patches: %s', len(am_mbx))
    else:
        logger.info('Total patches: %s (cherrypicked: %s)', len(am_mbx), cmdargs.cherrypick)
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

    topdir = None
    # Are we in a git tree and if so, what is our toplevel?
    gitargs = ['rev-parse', '--show-toplevel']
    lines = b4.git_get_command_lines(None, gitargs)
    if len(lines) == 1:
        topdir = lines[0]

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
        q_dirname = os.path.join(outdir, '%s.patches' % slug)
        am_mbox_to_quilt(am_mbx, q_dirname)
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

    am_mbx.close()
    if cmdargs.outdir == '-':
        logger.info('---')
        with open(am_filename, 'rb') as fh:
            shutil.copyfileobj(fh, sys.stdout.buffer)
        os.unlink(am_filename)

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

        pmsg.load_hashes()
        if pmsg.attestation is None:
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
        'to': b4.format_addrs(allto),
        'cc': b4.format_addrs(allcc),
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


def am_mbox_to_quilt(am_mbx, q_dirname):
    if os.path.exists(q_dirname):
        logger.critical('ERROR: Directory %s exists, not saving quilt patches', q_dirname)
        return
    os.mkdir(q_dirname, 0o755)
    patch_filenames = list()
    for key, msg in am_mbx.items():
        # Run each message through git mailinfo
        msg_out = mkstemp(suffix=None, prefix=None, dir=q_dirname)
        patch_out = mkstemp(suffix=None, prefix=None, dir=q_dirname)
        cmdargs = ['mailinfo', '--encoding=UTF-8', msg_out[1], patch_out[1]]
        ecode, info = b4.git_run_command(None, cmdargs, msg.as_bytes(policy=b4.emlpolicy))
        if not len(info.strip()):
            logger.critical('ERROR: Could not get mailinfo from patch %s', msg['Subject'])
            continue
        patchinfo = dict()
        for line in info.split('\n'):
            line = line.strip()
            if not line:
                continue
            chunks = line.split(':',  1)
            patchinfo[chunks[0]] = chunks[1]

        slug = re.sub(r'\W+', '_', patchinfo['Subject']).strip('_').lower()
        patch_filename = '%04d_%s.patch' % (key+1, slug)
        patch_filenames.append(patch_filename)
        quilt_out = os.path.join(q_dirname, patch_filename)
        with open(quilt_out, 'wb') as fh:
            line = 'From: %s <%s>\n' % (patchinfo['Author'].strip(), patchinfo['Email'].strip())
            fh.write(line.encode('utf-8'))
            line = 'Subject: %s\n' % patchinfo['Subject'].strip()
            fh.write(line.encode('utf-8'))
            line = 'Date: %s\n' % patchinfo['Date'].strip()
            fh.write(line.encode('utf-8'))
            fh.write('\n'.encode('utf-8'))
            with open(msg_out[1], 'r') as mfh:
                fh.write(mfh.read().encode('utf-8'))
            with open(patch_out[1], 'r') as pfh:
                fh.write(pfh.read().encode('utf-8'))
        logger.debug('  Wrote: %s', patch_filename)
        os.unlink(msg_out[1])
        os.unlink(patch_out[1])
    # Write the series file
    with open(os.path.join(q_dirname, 'series'), 'w') as sfh:
        for patch_filename in patch_filenames:
            sfh.write('%s\n' % patch_filename)


def get_extra_series(mboxfile, direction=1, wantvers=None, nocache=False):
    # Open the mbox and find the latest series mentioned in it
    if os.path.isdir(mboxfile):
        mbx = mailbox.Maildir(mboxfile)
    else:
        mbx = mailbox.mbox(mboxfile)

    base_msg = None
    latest_revision = None
    seen_msgids = list()
    seen_covers = list()
    for key, msg in mbx.items():
        msgid = b4.LoreMessage.get_clean_msgid(msg)
        seen_msgids.append(msgid)
        lsub = b4.LoreSubject(msg['Subject'])
        # Ignore replies or counters above 1
        if lsub.reply or lsub.counter > 1:
            continue
        if base_msg is not None:
            logger.debug('Current base_msg: %s', base_msg['Subject'])
        logger.debug('Checking the subject on %s', lsub.full_subject)
        if latest_revision is None or lsub.revision >= latest_revision:
            latest_revision = lsub.revision
            if lsub.counter == 0 and not lsub.counters_inferred:
                # And a cover letter, nice. This is the easy case
                base_msg = msg
                seen_covers.append(latest_revision)
            elif lsub.counter == 1 and latest_revision not in seen_covers:
                # A patch/series without a cover letter
                base_msg = msg

    if base_msg is None:
        logger.debug('Could not find cover of 1st patch in mbox')
        mbx.close()
        return
    # Get subject info from base_msg again
    lsub = b4.LoreSubject(base_msg['Subject'])
    if not len(lsub.prefixes):
        logger.debug('Not checking for new revisions: no prefixes on the cover letter.')
        mbx.close()
        return
    if direction < 0 and latest_revision <= 1:
        logger.debug('This is the latest version of the series')
        mbx.close()
        return
    if direction < 0 and wantvers is None:
        wantvers = [latest_revision - 1]

    base_msgid = b4.LoreMessage.get_clean_msgid(base_msg)
    fromeml = email.utils.getaddresses(base_msg.get_all('from', []))[0][1]
    msgdate = email.utils.parsedate_tz(str(base_msg['Date']))
    startdate = time.strftime('%Y%m%d', msgdate[:9])
    listarc = base_msg.get_all('List-Archive')[-1].strip('<>')
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
        mbx.close()
        return
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
        savefile = mkstemp('b4-get')[1]
        nt_mboxfile = b4.get_pi_thread_by_url(t_mbx_url, savefile, nocache=nocache)
        nt_mbx = mailbox.mbox(nt_mboxfile)
        # Append all of these to the existing mailbox
        new_adds = 0
        for nt_msg in nt_mbx:
            nt_msgid = b4.LoreMessage.get_clean_msgid(nt_msg)
            if nt_msgid in seen_msgids:
                logger.debug('Duplicate message, skipping')
                continue
            nt_subject = re.sub(r'\s+', ' ', nt_msg['Subject'])
            logger.debug('Adding: %s', nt_subject)
            new_adds += 1
            mbx.add(nt_msg)
            seen_msgids.append(nt_msgid)
        nt_mbx.close()
        if new_adds:
            logger.info('Added %s messages from thread: %s', new_adds, title)
        logger.debug('Removing temporary %s', nt_mboxfile)
        os.unlink(nt_mboxfile)

    # We close the mbox, since we'll be reopening it later
    mbx.close()


def main(cmdargs):
    if cmdargs.checknewer:
        # Force nocache mode
        cmdargs.nocache = True

    savefile = mkstemp('b4-mbox')[1]

    if not cmdargs.localmbox:
        msgid = b4.get_msgid(cmdargs)

        threadfile = b4.get_pi_thread_by_msgid(msgid, savefile, useproject=cmdargs.useproject, nocache=cmdargs.nocache)
        if threadfile is None:
            os.unlink(savefile)
            return
    else:
        if os.path.exists(cmdargs.localmbox):
            msgid = b4.get_msgid(cmdargs)
            if os.path.isdir(cmdargs.localmbox):
                in_mbx = mailbox.Maildir(cmdargs.localmbox)
            else:
                in_mbx = mailbox.mbox(cmdargs.localmbox)
            out_mbx = mailbox.mbox(savefile)
            b4.save_strict_thread(in_mbx, out_mbx, msgid)
            if not len(out_mbx):
                logger.critical('Could not find %s in %s', msgid, cmdargs.localmbox)
                os.unlink(savefile)
                sys.exit(1)
            threadfile = savefile
        else:
            logger.critical('Mailbox %s does not exist', cmdargs.localmbox)
            os.unlink(savefile)
            sys.exit(1)

    if threadfile and cmdargs.checknewer:
        get_extra_series(threadfile, direction=1)

    if cmdargs.subcmd == 'am':
        mbox_to_am(threadfile, cmdargs)
        os.unlink(threadfile)
    else:
        mbx = mailbox.mbox(threadfile)
        logger.critical('%s messages in the thread', len(mbx))
        mbx.close()
        if cmdargs.outdir == '-':
            logger.info('---')
            with open(threadfile, 'rb') as fh:
                shutil.copyfileobj(fh, sys.stdout.buffer)
            os.unlink(threadfile)
            return

        if cmdargs.wantname:
            savefile = os.path.join(cmdargs.outdir, cmdargs.wantname)
        else:
            msgid = b4.get_msgid(cmdargs)
            savefile = os.path.join(cmdargs.outdir, '%s.mbx' % msgid)

        shutil.copy(threadfile, savefile)
        logger.info('Saved %s', savefile)
        os.unlink(threadfile)
