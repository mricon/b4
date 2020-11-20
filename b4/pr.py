#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import os
import sys
import b4
import re
import mailbox
import json

from datetime import timedelta
from tempfile import mkstemp
from email import utils, charset

charset.add_charset('utf-8', None)

logger = b4.logger

PULL_BODY_SINCE_ID_RE = [
    re.compile(r'changes since commit ([0-9a-f]{5,40}):', re.M | re.I)
]

# I like these
PULL_BODY_WITH_COMMIT_ID_RE = [
    re.compile(r'fetch changes up to ([0-9a-f]{5,40}):', re.M | re.I),
]

# I don't like these
PULL_BODY_REMOTE_REF_RE = [
    re.compile(r'^\s*([\w+-]+(?:://|@)[\w/.@:~-]+)[\s\\]+([\w/._-]+)\s*$', re.M | re.I),
    re.compile(r'^\s*([\w+-]+(?:://|@)[\w/.@~-]+)\s*$', re.M | re.I),
]


def git_get_commit_id_from_repo_ref(repo, ref):
    # We only handle git and http/s URLs
    if not (repo.find('git://') == 0 or repo.find('http://') == 0 or repo.find('https://') == 0):
        logger.debug('%s uses unsupported protocol', repo)
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
        attpass = b4.PASS_FANCY
        attfail = b4.FAIL_FANCY
    else:
        attpass = b4.PASS_SIMPLE
        attfail = b4.FAIL_SIMPLE
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

    good, valid, trusted, attestor, sigdate, errors = b4.validate_gpg_signature(out, 'pgp')

    if good and valid and trusted:
        passing = True

    out = out.strip()
    if not len(out) and attpolicy != 'check':
        errors.add('Remote %s is not signed!' % otype)

    if passing:
        trailer = attestor.get_trailer(lmsg.fromemail)
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


def fetch_remote(gitdir, lmsg, branch=None):
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
    if config['attestation-policy'] != 'off':
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
        'to': b4.format_addrs(allto),
        'cc': b4.format_addrs(allcc),
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


def explode(gitdir, lmsg, savefile):
    # We always fetch into FETCH_HEAD when exploding
    ecode = fetch_remote(gitdir, lmsg)
    if ecode > 0:
        sys.exit(ecode)
    if not lmsg.pr_base_commit:
        # Use git merge-base between HEAD and FETCH_HEAD to find
        # where we should start
        logger.info('Running git merge-base to find common ancestry')
        gitargs = ['merge-base', 'HEAD', 'FETCH_HEAD']
        ecode, out = b4.git_run_command(gitdir, gitargs, logstderr=True)
        if ecode > 0:
            logger.critical('Could not find common ancestry.')
            logger.critical(out)
            sys.exit(ecode)
        lmsg.pr_base_commit = out.strip()
    logger.info('Generating patches starting from the base-commit')
    reroll = None
    if lmsg.revision > 1:
        reroll = lmsg.revision
    ecode, out = b4.git_format_patches(gitdir, lmsg.pr_base_commit, 'FETCH_HEAD', reroll=reroll)
    if ecode > 0:
        logger.critical('ERROR: Could not convert pull request into patches')
        logger.critical(out)
        sys.exit(ecode)

    # Fix From lines to make sure this is a valid mboxo
    out = re.sub(r'^From (?![a-f0-9]+ \w+ \w+ \d+ \d+:\d+:\d+ \d+$)', '>From ', out, 0, re.M)

    # Save patches into a temporary file
    patchmbx = mkstemp()[1]
    with open(patchmbx, 'w') as fh:
        fh.write(out)
    pmbx = mailbox.mbox(patchmbx)
    embx = mailbox.mbox(savefile)
    cover = lmsg.get_am_message()
    # Add base-commit to the cover
    body = cover.get_payload(decode=True)
    body = '%s\nbase-commit: %s\n' % (body.decode('utf-8'), lmsg.pr_base_commit)
    cover.set_payload(body)
    bout = cover.as_string(policy=b4.emlpolicy)
    embx.add(bout.encode('utf-8'))

    # Set the pull request message as cover letter
    for msg in pmbx:
        # Move the original From and Date into the body
        prepend = list()
        if msg['from'] != lmsg.msg['from']:
            cleanfrom = b4.LoreMessage.clean_header(msg['from'])
            prepend.append('From: %s' % ''.join(cleanfrom))
        prepend.append('Date: %s' % msg['date'])
        body = '%s\n\n%s' % ('\n'.join(prepend), msg.get_payload(decode=True).decode('utf-8'))
        msg.set_payload(body)
        msubj = b4.LoreSubject(msg['subject'])
        msg.replace_header('Subject', msubj.full_subject)
        # Set from, to, cc, date headers to match the original pull request
        msg.replace_header('From', b4.LoreMessage.clean_header(lmsg.msg['From']))
        # Add a number of seconds equalling the counter, in hopes it gets properly threaded
        newdate = lmsg.date + timedelta(seconds=msubj.counter)
        msg.replace_header('Date', utils.format_datetime(newdate))
        msg.add_header('To', b4.LoreMessage.clean_header(lmsg.msg['To']))
        if lmsg.msg['Cc']:
            msg.add_header('Cc', b4.LoreMessage.clean_header(lmsg.msg['Cc']))
        # Set the message-id based on the original pull request msgid
        msg.add_header('Message-Id', '<b4-exploded-%s-%s>' % (msubj.counter, lmsg.msgid))
        msg.add_header('In-Reply-To', '<%s>' % lmsg.msgid)
        if lmsg.msg['References']:
            msg.add_header('References', '%s <%s>' % (
                b4.LoreMessage.clean_header(lmsg.msg['References']), lmsg.msgid))
        else:
            msg.add_header('References', '<%s>' % lmsg.msgid)
        if lmsg.msg['List-Id']:
            msg.add_header('List-Id', b4.LoreMessage.clean_header(lmsg.msg['List-Id']))
        msg.add_header('X-Mailer', 'b4-explode/%s' % b4.__VERSION__)
        logger.info('  %s', msubj.full_subject)
        msg.set_charset('utf-8')
        bout = msg.as_string(policy=b4.emlpolicy)
        embx.add(bout.encode('utf-8'))
    logger.info('---')
    logger.info('Wrote %s patches into %s', len(pmbx), savefile)
    pmbx.close()
    os.unlink(patchmbx)
    embx.close()
    sys.exit(0)


def main(cmdargs):
    gitdir = cmdargs.gitdir

    msgid = b4.get_msgid(cmdargs)
    savefile = mkstemp()[1]
    mboxfile = b4.get_pi_thread_by_msgid(msgid, savefile)
    if mboxfile is None:
        os.unlink(savefile)
        return
    # Find the message with the msgid we were asked about
    mbx = mailbox.mbox(mboxfile)
    lmsg = None
    for msg in mbx:
        mmsgid = b4.LoreMessage.get_clean_msgid(msg)
        if mmsgid == msgid:
            lmsg = parse_pr_data(msg)

    # Got all we need from it
    mbx.close()
    os.unlink(savefile)

    if lmsg is None or lmsg.pr_remote_tip_commit is None:
        logger.critical('ERROR: Could not find pull request info in %s', msgid)
        sys.exit(1)

    if not lmsg.pr_tip_commit:
        lmsg.pr_tip_commit = lmsg.pr_remote_tip_commit

    if cmdargs.explode:
        savefile = cmdargs.outmbox
        if savefile is None:
            savefile = '%s.mbx' % lmsg.msgid
        if os.path.exists(savefile):
            logger.info('File exists: %s', savefile)
            sys.exit(1)
        explode(gitdir, lmsg, savefile)

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
