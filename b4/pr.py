#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import os
import sys
import tempfile

import b4
import re
import mailbox
import json
import email
import gzip

import urllib.parse
import requests

from datetime import datetime, timedelta

from email import utils, charset
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart

from typing import Optional, List


charset.add_charset('utf-8', None)

logger = b4.logger

PULL_BODY_SINCE_ID_RE = [
    re.compile(r'changes since commit ([\da-f]{5,40}):', re.M | re.I)
]

# I like these
PULL_BODY_WITH_COMMIT_ID_RE = [
    re.compile(r'fetch changes up to ([\da-f]{5,40}):', re.M | re.I),
]

# I don't like these
PULL_BODY_REMOTE_REF_RE = [
    re.compile(r'^\s*([\w+-]+(?:://|@)[\w/.@:~-]+)[\s\\]+([\w/._-]+)\s*$', re.M | re.I),
    re.compile(r'^\s*([\w+-]+(?:://|@)[\w/.@~-]+)\s*$', re.M | re.I),
]


def format_addrs(pairs):
    return ', '.join([utils.formataddr(pair) for pair in pairs])


def git_get_commit_id_from_repo_ref(repo, ref):
    # We only handle git and http/s URLs
    if not (repo.find('git://') == 0 or repo.find('http://') == 0 or repo.find('https://') == 0):
        logger.info('%s uses unsupported protocol', repo)
        return None

    logger.debug('getting commit-id from: %s %s', repo, ref)
    # Drop the leading "refs/", if any
    ref = re.sub(r'^refs/', '', ref)
    # Is it a full ref name or a shortname?
    if ref.find('heads/') < 0 and ref.find('tags/') < 0:
        # Try grabbing it as a head first
        lines = b4.git_get_command_lines(None, ['ls-remote', repo, 'refs/heads/%s' % ref])
        if not lines:
            # try it as a tag, then
            lines = b4.git_get_command_lines(None, ['ls-remote', repo, 'refs/tags/%s^{}' % ref])

    elif ref.find('tags/') == 0:
        lines = b4.git_get_command_lines(None, ['ls-remote', repo, 'refs/%s^{}' % ref])

    else:
        # Grab it as a head and hope for the best
        lines = b4.git_get_command_lines(None, ['ls-remote', repo, 'refs/%s' % ref])

    if not lines:
        # Oh well, we tried
        logger.debug('did not find commit-id, ignoring pull request')
        return None

    commit_id = lines[0].split()[0]
    logger.debug('success, commit-id: %s', commit_id)
    return commit_id


def parse_pr_data(msg):
    lmsg = b4.LoreMessage(msg)
    if lmsg.body is None:
        logger.critical('Could not find a plain part in the message body')
        return None

    logger.info('Looking at: %s', lmsg.full_subject)

    for since_re in PULL_BODY_SINCE_ID_RE:
        matches = since_re.search(lmsg.body)
        if matches:
            lmsg.pr_base_commit = matches.groups()[0]
            break

    for reporef_re in PULL_BODY_REMOTE_REF_RE:
        matches = reporef_re.search(lmsg.body)
        if matches:
            chunks = matches.groups()
            lmsg.pr_repo = chunks[0]
            if len(chunks) > 1:
                lmsg.pr_ref = chunks[1]
            else:
                lmsg.pr_ref = 'refs/heads/master'
            break

    for cid_re in PULL_BODY_WITH_COMMIT_ID_RE:
        matches = cid_re.search(lmsg.body)
        if matches:
            lmsg.pr_tip_commit = matches.groups()[0]
            break

    if lmsg.pr_repo and lmsg.pr_ref:
        lmsg.pr_remote_tip_commit = git_get_commit_id_from_repo_ref(lmsg.pr_repo, lmsg.pr_ref)

    return lmsg


def attest_fetch_head(gitdir, lmsg):
    config = b4.get_main_config()
    attpolicy = config['attestation-policy']
    if config['attestation-checkmarks'] == 'fancy':
        attpass = b4.ATT_PASS_FANCY
        attfail = b4.ATT_FAIL_FANCY
    else:
        attpass = b4.ATT_PASS_SIMPLE
        attfail = b4.ATT_FAIL_SIMPLE
    # Is FETCH_HEAD a tag or a commit?
    htype = b4.git_get_command_lines(gitdir, ['cat-file', '-t', 'FETCH_HEAD'])
    passing = False
    out = ''
    otype = 'unknown'
    if len(htype):
        otype = htype[0]
    if otype == 'tag':
        ecode, out = b4.git_run_command(gitdir, ['verify-tag', '--raw', 'FETCH_HEAD'], logstderr=True)
    elif otype == 'commit':
        ecode, out = b4.git_run_command(gitdir, ['verify-commit', '--raw', 'FETCH_HEAD'], logstderr=True)

    good, valid, trusted, keyid, sigtime = b4.check_gpg_status(out)
    signer = None
    if keyid:
        try:
            uids = b4.get_gpg_uids(keyid)
            for uid in uids:
                if uid.find(f'<{lmsg.fromemail}') >= 0:
                    signer = uid
                    break
            if not signer:
                signer = uids[0]

        except KeyError:
            signer = f'{lmsg.fromname} <{lmsg.fromemail}>'

    if good and valid:
        passing = True

    out = out.strip()
    errors = set()
    if not len(out) and attpolicy != 'check':
        errors.add('Remote %s is not signed!' % otype)

    if passing:
        trailer = 'Signed: %s' % signer
        logger.info('  ---')
        logger.info('  %s %s', attpass, trailer)
        return

    if errors:
        logger.critical('  ---')
        if len(out):
            logger.critical('  Pull request is signed, but verification did not succeed:')
        else:
            logger.critical('  Pull request verification did not succeed:')
        for error in errors:
            logger.critical('    %s %s', attfail, error)

        if attpolicy == 'hardfail':
            import sys
            sys.exit(128)


def fetch_remote(gitdir, lmsg, branch=None, check_sig=True, ty_track=True):
    # Do we know anything about this base commit?
    if lmsg.pr_base_commit and not b4.git_commit_exists(gitdir, lmsg.pr_base_commit):
        logger.critical('ERROR: git knows nothing about commit %s', lmsg.pr_base_commit)
        logger.critical('       Are you running inside a git checkout and is it up-to-date?')
        return 1

    if lmsg.pr_tip_commit != lmsg.pr_remote_tip_commit:
        logger.critical('ERROR: commit-id mismatch between pull request and remote')
        logger.critical('       msg=%s, remote=%s', lmsg.pr_tip_commit, lmsg.pr_remote_tip_commit)
        return 1

    # Fetch it now
    logger.info('  Fetching %s %s', lmsg.pr_repo, lmsg.pr_ref)
    gitargs = ['fetch', lmsg.pr_repo, lmsg.pr_ref]
    ecode, out = b4.git_run_command(gitdir, gitargs, logstderr=True)
    if ecode > 0:
        logger.critical('ERROR: Could not fetch remote:')
        logger.critical(out)
        return ecode

    config = b4.get_main_config()
    if check_sig and config['attestation-policy'] != 'off':
        attest_fetch_head(gitdir, lmsg)

    logger.info('---')
    if branch:
        gitargs = ['checkout', '-b', branch, 'FETCH_HEAD']
        logger.info('Fetched into branch %s', branch)
        ecode, out = b4.git_run_command(gitdir, gitargs)
        if ecode > 0:
            logger.critical('ERROR: Failed to create branch')
            logger.critical(out)
            return ecode
    else:
        logger.info('Successfully fetched into FETCH_HEAD')

    if ty_track:
        thanks_record_pr(lmsg)

    return 0


def thanks_record_pr(lmsg):
    datadir = b4.get_data_dir()
    # Check if we're tracking it already
    filename = '%s.pr' % lmsg.pr_remote_tip_commit
    for entry in os.listdir(datadir):
        if entry == filename:
            return
    allto = utils.getaddresses([str(x) for x in lmsg.msg.get_all('to', [])])
    allcc = utils.getaddresses([str(x) for x in lmsg.msg.get_all('cc', [])])
    out = {
        'msgid': lmsg.msgid,
        'subject': lmsg.full_subject,
        'fromname': lmsg.fromname,
        'fromemail': lmsg.fromemail,
        'to': b4.format_addrs(allto, clean=False),
        'cc': b4.format_addrs(allcc, clean=False),
        'references': b4.LoreMessage.clean_header(lmsg.msg['References']),
        'remote': lmsg.pr_repo,
        'ref': lmsg.pr_ref,
        'sentdate': b4.LoreMessage.clean_header(lmsg.msg['Date']),
        'quote': b4.make_quote(lmsg.body, maxlines=6)
    }
    fullpath = os.path.join(datadir, filename)
    with open(fullpath, 'w', encoding='utf-8') as fh:
        json.dump(out, fh, ensure_ascii=False, indent=4)
        logger.debug('Wrote %s for thanks tracking', filename)

    config = b4.get_main_config()
    pwstate = config.get('pw-review-state')
    if pwstate:
        b4.patchwork_set_state(lmsg.msgid, pwstate)


def explode(gitdir: Optional[str], lmsg: b4.LoreMessage, mailfrom: Optional[str] = None,
            retrieve_links: bool = True) -> List[email.message.Message]:
    ecode = fetch_remote(gitdir, lmsg, check_sig=False, ty_track=False)
    if ecode > 0:
        raise RuntimeError('Fetching unsuccessful')

    if not lmsg.pr_base_commit:
        # Use git merge-base between HEAD and FETCH_HEAD to find
        # where we should start
        logger.info('Running git merge-base to find common ancestry')
        gitargs = ['merge-base', 'HEAD', 'FETCH_HEAD']
        ecode, out = b4.git_run_command(gitdir, gitargs, logstderr=True)
        if ecode > 0:
            logger.critical('Could not find common ancestry.')
            logger.critical(out)
            raise RuntimeError('Could not find common ancestry')
        lmsg.pr_base_commit = out.strip()
        if lmsg.pr_base_commit == lmsg.pr_tip_commit:
            logger.critical('Cannot auto-discover merge-base on a merged pull request.')
            raise RuntimeError('Cannot find merge-base on a merged pull request')

    logger.info('Generating patches starting from the base-commit')

    prefixes = list()
    for prefix in lmsg.lsubject.prefixes:
        if prefix.lower() not in ('git', 'pull'):
            prefixes.append(prefix)

    # get our To's and CC's
    allto = utils.getaddresses(lmsg.msg.get_all('to', []))
    allcc = utils.getaddresses(lmsg.msg.get_all('cc', []))

    emlfrom = email.utils.parseaddr(b4.LoreMessage.clean_header(lmsg.msg.get('From')))
    if mailfrom is None:
        mailfrom = emlfrom
    else:
        mailfrom = email.utils.parseaddr(mailfrom)
        vianame = mailfrom[0]
        if not vianame:
            vianame = 'B4 Explode'
        if emlfrom[1].lower() != mailfrom[1].lower():
            mailfrom = (f'{emlfrom[0]} via {vianame}', mailfrom[1])

    config = b4.get_main_config()
    linked_ids = set()
    if retrieve_links:
        # Insert the pull request itself into linked_ids, so we preserve it as part
        # of the archived threads.
        linked_ids.add(lmsg.msgid)

    # Build the cover message from the pull request body
    body = '%s\n\nbase-commit: %s\nPR-Link: %s\n' % (
        lmsg.body.strip(), lmsg.pr_base_commit, config['linkmask'] % lmsg.msgid)

    # Make it a multipart if we're doing retrieve_links
    if retrieve_links:
        cmsg = MIMEMultipart()
        cmsg.attach(MIMEText(body, 'plain'))
    else:
        cmsg = email.message.EmailMessage()
        cmsg.set_payload(body)

    msgid_tpt = f'<b4-exploded-%s-{lmsg.msgid}>'
    cmsg.add_header('From', b4.format_addrs([mailfrom]))
    cmsg.add_header('Subject', lmsg.full_subject)
    cmsg.add_header('Date', lmsg.msg.get('Date'))
    cmsg.set_charset('utf-8')
    cmsg.replace_header('Content-Transfer-Encoding', '8bit')

    pmsgs = b4.git_range_to_patches(gitdir, lmsg.pr_base_commit, 'FETCH_HEAD',
                                    covermsg=cmsg, prefixes=prefixes, msgid_tpt=msgid_tpt,
                                    seriests=lmsg.date.timestamp(), mailfrom=mailfrom, thread=True)

    msgs = list()
    for at, (commit, msg) in enumerate(pmsgs):
        body = msg.get_payload(decode=True)

        if isinstance(body, bytes) and retrieve_links:
            body = body.decode()
            matches = re.findall(r'^Link:\s+https?://.*/(\S+@\S+)[^/]', body, flags=re.M | re.I)
            if matches:
                linked_ids.update(matches)
            matches = re.findall(r'^Message-ID:\s+(\S+@\S+)', body, flags=re.M | re.I)
            if matches:
                linked_ids.update(matches)

        msg.add_header('To', format_addrs(allto))
        if allcc:
            msg.add_header('Cc', format_addrs(allcc))

        if lmsg.msg['List-Id']:
            msg.add_header('X-Original-List-Id', b4.LoreMessage.clean_header(lmsg.msg['List-Id']))

        msgs.append(msg)
        logger.info('  %s', re.sub(r'\n\s*', ' ' , msg.get('Subject')))

    logger.info('Exploded %s messages', len(msgs))
    if retrieve_links and linked_ids:
        with tempfile.TemporaryDirectory() as tfd:
            # Create a single mbox file with all linked conversations
            mbf = os.path.join(tfd, 'linked.mbox')
            tmbx = mailbox.mbox(mbf)
            logger.info('---')
            logger.info('Retrieving %s linked conversations', len(linked_ids))

            seen_msgids = set()
            for msgid in linked_ids:
                # Did we already retrieve it as part of a previous tread?
                if msgid in seen_msgids:
                    continue
                lmsgs = b4.get_pi_thread_by_msgid(msgid)
                if lmsgs:
                    # Append any messages we don't yet have
                    for lmsg in lmsgs:
                        amsgid = b4.LoreMessage.get_clean_msgid(lmsg)
                        if amsgid not in seen_msgids:
                            seen_msgids.add(amsgid)
                            logger.debug('Added linked: %s', lmsg.get('Subject'))
                            tmbx.add(lmsg.as_bytes(policy=b4.emlpolicy))

            if len(tmbx):
                tmbx.close()
                # gzip the mailbox and attach it to the cover letter
                with open(mbf, 'rb') as fh:
                    mbz = gzip.compress(fh.read())
                    fname = 'linked-threads.mbox.gz'
                    att = MIMEApplication(mbz, 'x-gzip')
                    att.add_header('Content-Disposition', f'attachment; filename={fname}')
                    cmsg.attach(att)

        logger.info('---')
        if len(seen_msgids):
            logger.info('Attached %s messages as linked-threads.mbox.gz', len(seen_msgids))
        else:
            logger.info('Could not retrieve any linked threads')

    return msgs


def get_pr_from_github(ghurl: str):
    loc = urllib.parse.urlparse(ghurl)
    chunks = loc.path.strip('/').split('/')
    rproj = chunks[0]
    rrepo = chunks[1]
    rpull = chunks[-1]
    apiurl = f'https://api.github.com/repos/{rproj}/{rrepo}/pulls/{rpull}'
    req = requests.session()
    # Do we have a GitHub API key?
    config = b4.get_main_config()
    ghkey = config.get('gh-api-key')
    if ghkey:
        req.headers.update({'Authorization': f'token {ghkey}'})
    req.headers.update({'Accept': 'application/vnd.github.v3+json'})
    resp = req.get(apiurl)
    if resp.status_code != 200:
        logger.critical('Server returned an error: %s', resp.status_code)
        return None
    prdata = resp.json()

    head = prdata.get('head', {})
    repo = head.get('repo', {})
    base = prdata.get('base', {})
    user = prdata.get('user', {})

    ulogin = user.get('login')
    fake_email = f'{ulogin}@github.com'
    apiurl = f'https://api.github.com/users/{ulogin}'
    resp = req.get(apiurl)
    if resp.status_code == 200:
        udata = resp.json()
        uname = udata.get('name')
        if not uname:
            uname = ulogin
        uemail = udata.get('email')
        if not uemail:
            uemail = fake_email
    else:
        uname = ulogin
        uemail = fake_email

    msg = email.message.EmailMessage(policy=b4.emlpolicy)
    msg['From'] = f'{uname} <{uemail}>'
    title = prdata.get('title', '')
    msg['Subject'] = f'[GIT PULL] {title}'
    msg['To'] = fake_email
    msg['Message-Id'] = utils.make_msgid(idstring=f'{rproj}-{rrepo}-pr-{rpull}', domain='github.com')
    created_at = utils.format_datetime(datetime.strptime(prdata.get('created_at'), '%Y-%m-%dT%H:%M:%SZ'))
    msg['Date'] = created_at
    msg.set_charset('utf-8')
    msg.set_payload(prdata.get('body', '(no body)'), charset='utf-8')
    lmsg = b4.LoreMessage(msg)
    lmsg.pr_base_commit = base.get('sha')
    lmsg.pr_repo = repo.get('clone_url')
    lmsg.pr_ref = head.get('ref')
    lmsg.pr_tip_commit = head.get('sha')
    lmsg.pr_remote_tip_commit = head.get('sha')
    return lmsg


def main(cmdargs):
    gitdir = cmdargs.gitdir
    lmsg = None

    if not cmdargs.no_stdin and not sys.stdin.isatty():
        logger.debug('Getting PR message from stdin')
        msg = email.message_from_bytes(sys.stdin.buffer.read())
        cmdargs.msgid = b4.LoreMessage.get_clean_msgid(msg)
        lmsg = parse_pr_data(msg)
    else:
        if cmdargs.msgid and 'github.com' in cmdargs.msgid and '/pull/' in cmdargs.msgid:
            logger.debug('Getting PR info from Github')
            lmsg = get_pr_from_github(cmdargs.msgid)
        else:
            logger.debug('Getting PR message from public-inbox')

            msgid = b4.get_msgid(cmdargs)
            msgs = b4.get_pi_thread_by_msgid(msgid)
            if not msgs:
                return
            for msg in msgs:
                mmsgid = b4.LoreMessage.get_clean_msgid(msg)
                if mmsgid == msgid:
                    lmsg = parse_pr_data(msg)
                    break

    if lmsg is None or lmsg.pr_remote_tip_commit is None:
        logger.critical('ERROR: Could not find pull request info in %s', cmdargs.msgid)
        sys.exit(1)

    if not lmsg.pr_tip_commit:
        lmsg.pr_tip_commit = lmsg.pr_remote_tip_commit

    if cmdargs.explode:
        # Set up a temporary clone
        with b4.git_temp_clone(gitdir) as tc:
            try:
                msgs = explode(tc, lmsg, mailfrom=cmdargs.mailfrom, retrieve_links=cmdargs.getlinks)
            except RuntimeError:
                logger.critical('Nothing exploded.')
                sys.exit(1)

        if msgs:
            if cmdargs.sendidentity:
                # Pass exploded series via git-send-email
                config = b4.get_config_from_git(rf'sendemail\.{cmdargs.sendidentity}\..*')
                if not len(config):
                    logger.critical('Not able to find sendemail.%s configuration', cmdargs.sendidentity)
                    sys.exit(1)
                # Make sure from is not overridden by current user
                mailfrom = msgs[0].get('from')
                gitargs = ['send-email', '--identity', cmdargs.sendidentity, '--from', mailfrom]
                if cmdargs.dryrun:
                    gitargs.append('--dry-run')
                # Write out everything into a temporary dir
                counter = 0
                with tempfile.TemporaryDirectory() as tfd:
                    for msg in msgs:
                        outfile = os.path.join(tfd, '%04d' % counter)
                        with open(outfile, 'wb') as tfh:
                            tfh.write(msg.as_bytes(policy=b4.emlpolicy))
                        gitargs.append(outfile)
                        counter += 1
                    ecode, out = b4.git_run_command(cmdargs.gitdir, gitargs, logstderr=True)
                    if cmdargs.dryrun:
                        logger.info(out)
                    sys.exit(ecode)

            config = b4.get_main_config()
            if config.get('save-maildirs', 'no') == 'yes':
                save_maildir = True
                dftext = 'maildir'
            else:
                save_maildir = False
                dftext = 'mbx'
            savefile = cmdargs.outmbox
            if savefile is None:
                savefile = f'{lmsg.msgid}.{dftext}'
            if os.path.exists(savefile):
                logger.info('File exists: %s', savefile)
                sys.exit(1)

            if save_maildir:
                b4.save_maildir(msgs, savefile)
            else:
                with open(savefile, 'wb') as fh:
                    b4.save_git_am_mbox(msgs, fh)
            logger.info('---')
            logger.info('Saved %s', savefile)
            sys.exit(0)
        else:
            logger.critical('Nothing exploded.')
            sys.exit(1)

    exists = b4.git_commit_exists(gitdir, lmsg.pr_tip_commit)
    if exists:
        # Is it in any branch, or just flapping in the wind?
        branches = b4.git_branch_contains(gitdir, lmsg.pr_tip_commit)
        if len(branches):
            logger.info('Pull request tip commit exists in the following branches:')
            for branch in branches:
                logger.info('  %s', branch)
            if cmdargs.check:
                sys.exit(0)
            sys.exit(1)

        # Is it at the tip of FETCH_HEAD?
        loglines = b4.git_get_command_lines(gitdir, ['log', '-1', '--pretty=oneline', 'FETCH_HEAD'])
        if len(loglines) and loglines[0].find(lmsg.pr_tip_commit) == 0:
            logger.info('Pull request is at the tip of FETCH_HEAD')
            if cmdargs.check:
                attest_fetch_head(gitdir, lmsg)
                sys.exit(0)

    elif cmdargs.check:
        logger.info('Pull request does not appear to be in this tree.')
        sys.exit(0)

    fetch_remote(gitdir, lmsg, branch=cmdargs.branch)
