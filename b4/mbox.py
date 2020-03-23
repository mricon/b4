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
import shutil

import urllib.parse
import xml.etree.ElementTree
import gzip

import b4

from tempfile import mkstemp

logger = b4.logger


def get_msgid_from_stdin():
    if not sys.stdin.isatty():
        message = email.message_from_string(sys.stdin.read())
        return message.get('Message-ID', None)
    logger.error('Error: pipe a message or pass msgid as parameter')
    sys.exit(1)


def get_pi_thread_by_url(t_mbx_url, savefile):
    session = b4.get_requests_session()
    resp = session.get(t_mbx_url)
    if resp.status_code != 200:
        logger.critical('Server returned an error: %s', resp.status_code)
        return None
    t_mbox = gzip.decompress(resp.content)
    resp.close()
    if not len(t_mbox):
        logger.critical('No messages found for that query')
        return None
    with open(savefile, 'wb') as fh:
        logger.debug('Saving %s', savefile)
        fh.write(t_mbox)
    return savefile


def get_pi_thread_by_msgid(msgid, config, cmdargs):
    wantname = cmdargs.wantname
    outdir = cmdargs.outdir
    if wantname:
        savefile = os.path.join(outdir, wantname)
    else:
        # Save it into msgid.mbox
        savefile = '%s.t.mbx' % msgid
        savefile = os.path.join(outdir, savefile)

    cachedir = b4.get_cache_dir()
    cachefile = os.path.join(cachedir, '%s.pi.mbx' % urllib.parse.quote_plus(msgid))
    if os.path.exists(cachefile) and not cmdargs.nocache:
        logger.debug('Using cached copy: %s', cachefile)
        shutil.copyfile(cachefile, savefile)
        return savefile

    # Grab the head from lore, to see where we are redirected
    midmask = config['midmask'] % msgid
    logger.info('Looking up %s', midmask)
    session = b4.get_requests_session()
    resp = session.head(midmask)
    if resp.status_code < 300 or resp.status_code > 400:
        logger.critical('That message-id is not known.')
        return None
    canonical = resp.headers['Location'].rstrip('/')
    resp.close()
    t_mbx_url = '%s/t.mbox.gz' % canonical

    loc = urllib.parse.urlparse(t_mbx_url)
    if cmdargs.useproject:
        logger.debug('Modifying query to use %s', cmdargs.useproject)
        t_mbx_url = '%s://%s/%s/%s/t.mbox.gz' % (
            loc.scheme, loc.netloc, cmdargs.useproject, msgid)
        logger.debug('Will query: %s', t_mbx_url)
    logger.critical('Grabbing thread from %s', loc.netloc)
    in_mbxf = get_pi_thread_by_url(t_mbx_url, '%s-loose' % savefile)
    if not in_mbxf:
        return None
    in_mbx = mailbox.mbox(in_mbxf)
    out_mbx = mailbox.mbox(savefile)
    b4.save_strict_thread(in_mbx, out_mbx, msgid)
    in_mbx.close()
    out_mbx.close()
    os.unlink(in_mbxf)
    shutil.copyfile(savefile, cachefile)
    return savefile


def mbox_to_am(mboxfile, config, cmdargs):
    outdir = cmdargs.outdir
    wantver = cmdargs.wantver
    wantname = cmdargs.wantname
    covertrailers = cmdargs.covertrailers
    mbx = mailbox.mbox(mboxfile)
    count = len(mbx)
    logger.info('Analyzing %s messages in the thread', count)
    lmbx = b4.LoreMailbox()
    # Go through the mbox once to populate base series
    for key, msg in mbx.items():
        lmbx.add_message(msg)

    lser = lmbx.get_series(revision=wantver)
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

    am_filename = os.path.join(outdir, '%s.mbx' % slug)
    am_cover = os.path.join(outdir, '%s.cover' % slug)

    if os.path.exists(am_filename):
        os.unlink(am_filename)

    logger.info('---')
    logger.critical('Writing %s', am_filename)
    mbx = mailbox.mbox(am_filename)
    am_mbx = lser.save_am_mbox(mbx, cmdargs.noaddtrailers, covertrailers,
                               trailer_order=config['trailer-order'],
                               addmysob=cmdargs.addmysob, addlink=cmdargs.addlink,
                               linkmask=config['linkmask'])
    logger.info('---')

    logger.critical('Total patches: %s', len(am_mbx))
    if lser.has_cover and lser.patches[0].followup_trailers and not covertrailers:
        # Warn that some trailers were sent to the cover letter
        logger.critical('---')
        logger.critical('NOTE: Some trailers were sent to the cover letter:')
        for trailer in lser.patches[0].followup_trailers:
            logger.critical('      %s: %s', trailer[0], trailer[1])
        logger.critical('NOTE: Rerun with -t to apply them to all patches')

    logger.critical('---')
    if not lser.complete:
        logger.critical('WARNING: Thread incomplete!')

    if lser.has_cover:
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
        logger.critical('       git am %s', am_filename)
    else:
        logger.critical(' Base: not found, sorry')
        logger.critical('       git checkout -b %s master', gitbranch)
        logger.critical('       git am %s', am_filename)

    am_mbx.close()

    return am_filename


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


def get_newest_series(mboxfile):
    # Open the mbox and find the latest series mentioned in it
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
        if latest_revision is None or lsub.revision > latest_revision:
            # New revision
            latest_revision = lsub.revision
            if lsub.counter == 0:
                # And a cover letter, nice. This is the easy case
                base_msg = msg
                seen_covers.append(latest_revision)
                continue
            if lsub.counter == 1:
                if latest_revision not in seen_covers:
                    # A patch/series without a cover letter
                    base_msg = msg

    # Get subject info from base_msg again
    lsub = b4.LoreSubject(base_msg['Subject'])
    if not len(lsub.prefixes):
        logger.debug('Not checking for new revisions: no prefixes on the cover letter.')
        mbx.close()
        return
    base_msgid = b4.LoreMessage.get_clean_msgid(base_msg)
    fromeml = email.utils.getaddresses(base_msg.get_all('from', []))[0][1]
    msgdate = email.utils.parsedate_tz(str(base_msg['Date']))
    startdate = time.strftime('%Y%m%d', msgdate[:9])
    listarc = base_msg.get_all('List-Archive')[-1].strip('<>')
    q = 's:"%s" AND f:"%s" AND d:%s..' % (lsub.subject.replace('"', ''), fromeml, startdate)
    queryurl = '%s?%s' % (listarc, urllib.parse.urlencode({'q': q, 'x': 'A', 'o': '-1'}))
    logger.critical('Checking for newer revisions on %s', listarc)
    logger.debug('Query URL: %s', queryurl)
    session = b4.get_requests_session()
    resp = session.get(queryurl)
    # try to parse it
    try:
        tree = xml.etree.ElementTree.fromstring(resp.content)
    except xml.etree.ElementTree.ParseError as ex:
        logger.debug('Unable to parse results, ignoring', ex)
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
        if lsub.revision < latest_revision:
            logger.debug('Ignoring result (not new revision): %s', title)
            continue
        if link.find('/%s/' % base_msgid) > 0:
            logger.debug('Ignoring result (same thread as ours):%s', title)
            continue
        if lsub.revision == 1 and lsub.revision == latest_revision:
            # Someone sent a separate message with an identical title but no new vX in the subject line
            # It's *probably* a new revision.
            logger.debug('Likely a new revision: %s', title)
        elif lsub.revision > latest_revision:
            logger.debug('Definitely a new revision [v%s]: %s', lsub.revision, title)
        else:
            logger.debug('No idea what this is: %s', title)
            continue
        t_mbx_url = '%st.mbox.gz' % link
        savefile = mkstemp('b4-get')[1]
        nt_mboxfile = get_pi_thread_by_url(t_mbx_url, savefile)
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

    config = b4.get_main_config()

    if not cmdargs.localmbox:
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
            msgid = chunks[1]
            # Infer the project name from the URL, if possible
            if chunks[0] != 'r':
                cmdargs.useproject = chunks[0]

        mboxfile = get_pi_thread_by_msgid(msgid, config, cmdargs)
        if mboxfile is None:
            return

        # Move it into -thread
        threadmbox = '%s-thread' % mboxfile
        os.rename(mboxfile, threadmbox)
    else:
        if os.path.exists(cmdargs.localmbox):
            threadmbox = cmdargs.localmbox
        else:
            logger.critical('Mailbox %s does not exist', cmdargs.localmbox)
            sys.exit(1)

    if threadmbox and cmdargs.checknewer:
        get_newest_series(threadmbox)

    if cmdargs.subcmd == 'am':
        mbox_to_am(threadmbox, config, cmdargs)
        if not cmdargs.localmbox:
            os.unlink(threadmbox)
    else:
        mbx = mailbox.mbox(threadmbox)
        logger.critical('Saved %s', threadmbox)
        logger.critical('%s messages in the thread', len(mbx))
