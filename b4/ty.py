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
import email
import email.message
import email.policy
import json

from string import Template
from email import utils
from pathlib import Path

logger = b4.logger

DEFAULT_PR_TEMPLATE = """
On ${sentdate}, ${fromname} wrote:
${quote}

Merged, thanks!

${summary}

Best regards,
-- 
${signature}
"""

DEFAULT_AM_TEMPLATE = """
On ${sentdate}, ${fromname} wrote:
${quote}

Applied, thanks!

${summary}

Best regards,
-- 
${signature}
"""

# Used to track commits created by current user
MY_COMMITS = None
# Used to track additional branch info
BRANCH_INFO = None


def git_get_merge_id(gitdir, commit_id, branch=None):
    # get merge commit id
    args = ['rev-list', '%s..' % commit_id, '--ancestry-path']
    if branch is not None:
        args += [branch]
    lines = b4.git_get_command_lines(gitdir, args)
    if not len(lines):
        return None
    return lines[-1]


def git_get_rev_diff(gitdir, rev):
    args = ['diff', '%s~..%s' % (rev, rev)]
    return b4.git_run_command(gitdir, args)


def git_get_commit_message(gitdir, rev):
    args = ['log', '--format=%B', '-1', rev]
    return b4.git_run_command(gitdir, args)


def make_reply(reply_template, jsondata, gitdir):
    msg = email.message.EmailMessage()
    msg['From'] = '%s <%s>' % (jsondata['myname'], jsondata['myemail'])
    excludes = b4.get_excluded_addrs()
    newto = b4.cleanup_email_addrs([(jsondata['fromname'], jsondata['fromemail'])], excludes, gitdir)

    # Exclude ourselves and original sender from allto or allcc
    excludes.add(jsondata['myemail'])
    excludes.add(jsondata['fromemail'])
    allto = b4.cleanup_email_addrs(utils.getaddresses([jsondata['to']]), excludes, gitdir)
    allcc = b4.cleanup_email_addrs(utils.getaddresses([jsondata['cc']]), excludes, gitdir)

    if newto:
        allto += newto

    msg.add_header('To', b4.format_addrs(allto))
    if allcc:
        msg.add_header('Cc', b4.format_addrs(allcc))
    msg['In-Reply-To'] = '<%s>' % jsondata['msgid']
    if len(jsondata['references']):
        msg['References'] = '%s <%s>' % (jsondata['references'], jsondata['msgid'])
    else:
        msg['References'] = '<%s>' % jsondata['msgid']

    subject = re.sub(r'^Re:\s+', '', jsondata['subject'], flags=re.I)
    if jsondata.get('cherrypick'):
        msg.add_header('Subject', 'Re: (subset) ' + subject)
    else:
        msg.add_header('Subject', 'Re: ' + subject)

    mydomain = jsondata['myemail'].split('@')[1]
    msg['Message-Id'] = email.utils.make_msgid(idstring='b4-ty', domain=mydomain)
    msg['Date'] = email.utils.formatdate(localtime=True)
    body = Template(reply_template).safe_substitute(jsondata)
    msg.set_payload(body, charset='utf-8')
    msg.set_charset('utf-8')

    return msg


def auto_locate_pr(gitdir, jsondata, branch):
    pr_commit_id = jsondata['pr_commit_id']
    logger.debug('Checking %s', jsondata['pr_commit_id'])
    if not b4.git_commit_exists(gitdir, pr_commit_id):
        return None

    onbranches = b4.git_branch_contains(gitdir, pr_commit_id)
    if not len(onbranches):
        logger.debug('%s is not on any branches', pr_commit_id)
        return None
    if branch not in onbranches:
        logger.debug('%s is not on branch %s', pr_commit_id, branch)
        return None

    # Get the merge commit
    merge_commit_id = git_get_merge_id(gitdir, pr_commit_id, branch)
    if not merge_commit_id:
        logger.debug('Could not get a merge commit-id for %s', pr_commit_id)
        return None

    # Check that we are the author of the merge commit
    gitargs = ['show', '--format=%ae', merge_commit_id]
    out = b4.git_get_command_lines(gitdir, gitargs)
    if not out:
        logger.debug('Could not get merge commit author for %s', pr_commit_id)
        return None

    usercfg = b4.get_user_config()
    if usercfg['email'] not in out:
        logger.debug('Merged by a different author, ignoring %s', pr_commit_id)
        logger.debug('Author: %s', out[0])
        return None

    return merge_commit_id


def get_all_commits(gitdir, branch, since='1.week', committer=None):
    global MY_COMMITS
    if MY_COMMITS is not None:
        return MY_COMMITS

    MY_COMMITS = dict()
    if committer is None:
        usercfg = b4.get_user_config()
        committer = usercfg['email']

    gitargs = ['log', '--committer', committer, '--no-abbrev', '--oneline', '--since', since, branch]
    lines = b4.git_get_command_lines(gitdir, gitargs)
    if not len(lines):
        logger.debug('No new commits from the current user --since=%s', since)
        return MY_COMMITS

    logger.info('Found %s of your commits since %s', len(lines), since)
    logger.info('Calculating patch hashes, may take a moment...')
    # Get patch hash of each commit
    for line in lines:
        commit_id, subject = line.split(maxsplit=1)
        ecode, out = git_get_rev_diff(gitdir, commit_id)
        pwhash = b4.LoreMessage.get_patchwork_hash(out)
        logger.debug('phash=%s', pwhash)
        # get all message-id or link trailers
        ecode, out = git_get_commit_message(gitdir, commit_id)
        matches = re.findall(r'^\s*(?:message-id|link):[ \t]+(\S+)\s*$', out, flags=re.I | re.M)
        trackers = list()
        if matches:
            for tvalue in matches:
                trackers.append(tvalue)

        MY_COMMITS[pwhash] = (commit_id, subject, trackers)

    return MY_COMMITS


def auto_locate_series(gitdir, jsondata, branch, since='1.week'):
    commits = get_all_commits(gitdir, branch, since)

    patchids = set(commits.keys())
    # We need to find all of them in the commits
    found = list()
    matches = 0
    at = 0
    for patch in jsondata['patches']:
        at += 1
        logger.debug('Checking %s', patch)
        if patch[1] in patchids:
            logger.debug('Found: %s', patch[0])
            found.append((at, commits[patch[1]][0]))
            matches += 1
        else:
            # try to locate by subject
            success = False
            for pwhash, commit in commits.items():
                if commit[1] == patch[0]:
                    logger.debug('Matched using subject')
                    found.append((at, commit[0]))
                    success = True
                    matches += 1
                    break
                elif len(patch) > 2 and len(patch[2]) and len(commit[2]):
                    for tracker in commit[2]:
                        if tracker.find(patch[2]) >= 0:
                            logger.debug('Matched using recorded message-id')
                            found.append((at, commit[0]))
                            success = True
                            matches += 1
                            break
                if success:
                    break

            if not success:
                logger.debug('  Failed to find a match for: %s', patch[0])
                found.append((at, None))

    return found


def set_branch_details(gitdir, branch, jsondata, config):
    binfo = get_branch_info(gitdir, branch)
    jsondata['branch'] = branch
    for key, val in binfo.items():
        if key == 'b4-treename':
            config['thanks-treename'] = val
        elif key == 'b4-commit-url-mask':
            config['thanks-commit-url-mask'] = val
        elif key == 'b4-pr-template':
            config['thanks-pr-template'] = val
        elif key == 'b4-am-template':
            config['thanks-am-template'] = val
        elif key == 'branch':
            jsondata['branch'] = val

    if 'thanks-treename' in config:
        jsondata['treename'] = config['thanks-treename']
    elif 'url' in binfo:
        # noinspection PyBroadException
        try:
            # Try to grab the last two chunks of the path
            purl = Path(binfo['url'])
            jsondata['treename'] = os.path.join(purl.parts[-2], purl.parts[-1])
        except:
            # Something went wrong... just use the whole URL
            jsondata['treename'] = binfo['url']
    else:
        jsondata['treename'] = 'local tree'

    return jsondata, config


def generate_pr_thanks(gitdir, jsondata, branch):
    config = b4.get_main_config()
    jsondata, config = set_branch_details(gitdir, branch, jsondata, config)
    thanks_template = DEFAULT_PR_TEMPLATE
    if config['thanks-pr-template']:
        # Try to load this template instead
        try:
            thanks_template = b4.read_template(config['thanks-pr-template'])
        except FileNotFoundError:
            logger.critical('ERROR: thanks-pr-template says to use %s, but it does not exist',
                            config['thanks-pr-template'])
            sys.exit(2)

    if 'merge_commit_id' not in jsondata:
        merge_commit_id = git_get_merge_id(gitdir, jsondata['pr_commit_id'])
        if not merge_commit_id:
            logger.critical('Could not get merge commit id for %s', jsondata['subject'])
            logger.critical('Was it actually merged?')
            sys.exit(1)
        jsondata['merge_commit_id'] = merge_commit_id
    # Make a summary
    cidmask = config['thanks-commit-url-mask']
    if not cidmask:
        cidmask = 'merge commit: %s'
    jsondata['summary'] = cidmask % jsondata['merge_commit_id']
    msg = make_reply(thanks_template, jsondata, gitdir)
    return msg


def generate_am_thanks(gitdir, jsondata, branch, since):
    config = b4.get_main_config()
    jsondata, config = set_branch_details(gitdir, branch, jsondata, config)
    thanks_template = DEFAULT_AM_TEMPLATE
    if config['thanks-am-template']:
        # Try to load this template instead
        try:
            thanks_template = b4.read_template(config['thanks-am-template'])
        except FileNotFoundError:
            logger.critical('ERROR: thanks-am-template says to use %s, but it does not exist',
                            config['thanks-am-template'])
            sys.exit(2)
    if 'commits' not in jsondata:
        commits = auto_locate_series(gitdir, jsondata, branch, since)
    else:
        commits = jsondata['commits']

    cidmask = config['thanks-commit-url-mask']
    if not cidmask:
        cidmask = 'commit: %s'
    slines = list()
    nomatch = 0
    padlen = len(str(len(commits)))
    patches = jsondata['patches']
    for at, cid in commits:
        try:
            prefix = '[%s] ' % patches[at-1][3]
        except IndexError:
            prefix = '[%s/%s] ' % (str(at).zfill(padlen), len(commits))
        slines.append('%s%s' % (prefix, patches[at-1][0]))
        if cid is None:
            slines.append('%s(no commit info)' % (' ' * len(prefix)))
            nomatch += 1
        else:
            slines.append('%s%s' % (' ' * len(prefix), cidmask % cid))
    jsondata['summary'] = '\n'.join(slines)
    if nomatch == len(commits):
        logger.critical('  WARNING: None of the patches matched for: %s', jsondata['subject'])
        logger.critical('           Please review the resulting message')
    elif nomatch > 0:
        logger.critical('  WARNING: Could not match %s of %s patches in: %s',
                        nomatch, len(commits), jsondata['subject'])
        logger.critical('           Please review the resulting message')

    msg = make_reply(thanks_template, jsondata, gitdir)
    return msg


def auto_thankanator(cmdargs):
    gitdir = cmdargs.gitdir
    wantbranch = get_wanted_branch(cmdargs)
    logger.info('Auto-thankanating commits in %s', wantbranch)
    tracked = list_tracked()
    if not len(tracked):
        logger.info('Nothing to do')
        sys.exit(0)

    applied = list()
    for jsondata in tracked:
        if 'pr_commit_id' in jsondata:
            # this is a pull request
            merge_commit_id = auto_locate_pr(gitdir, jsondata, wantbranch)
            if merge_commit_id is None:
                continue
            jsondata['merge_commit_id'] = merge_commit_id
        else:
            # This is a patch series
            commits = auto_locate_series(gitdir, jsondata, wantbranch, since=cmdargs.since)
            # Weed out series that have no matches at all
            found = False
            for commit in commits:
                if commit[1] is not None:
                    found = True
                    break
            if not found:
                continue
            jsondata['commits'] = commits
        applied.append(jsondata)
        logger.info('  Located: %s', jsondata['subject'])

    if not len(applied):
        logger.info('Nothing to do')
        sys.exit(0)

    logger.info('---')
    send_messages(applied, wantbranch, cmdargs)
    sys.exit(0)


def send_messages(listing, branch, cmdargs):
    logger.info('Generating %s thank-you letters', len(listing))
    gitdir = cmdargs.gitdir
    datadir = b4.get_data_dir()
    fromaddr = None
    smtp = None
    config = b4.get_main_config()

    if cmdargs.sendemail or config.get('ty-send-email', 'no').lower() in ['yes', 'true', '1']:
        send_email = True
        try:
            smtp, fromaddr = b4.get_smtp()
        except Exception as ex:  # noqa
            logger.critical('Failed to configure the smtp connection:')
            logger.critical(ex)
            sys.exit(1)
    else:
        # We write .thanks notes
        send_email = False
        # Check if the outdir exists and if it has any .thanks files in it
        if not os.path.exists(cmdargs.outdir):
            os.mkdir(cmdargs.outdir)

    usercfg = b4.get_user_config()
    signature = b4.get_email_signature()

    outgoing = 0
    msgids = list()
    for jsondata in listing:
        jsondata['myname'] = usercfg['name']
        jsondata['myemail'] = usercfg['email']
        jsondata['signature'] = signature
        if 'pr_commit_id' in jsondata:
            # This is a pull request
            msg = generate_pr_thanks(gitdir, jsondata, branch)
        else:
            # This is a patch series
            msg = generate_am_thanks(gitdir, jsondata, branch, cmdargs.since)

        if msg is None:
            continue

        msgids.append(jsondata['msgid'])
        for pdata in jsondata.get('patches', list()):
            msgids.append(pdata[2])

        outgoing += 1
        if send_email:
            if not fromaddr:
                fromaddr = jsondata['myemail']
            logger.info('  Sending: %s', b4.LoreMessage.clean_header(msg.get('subject')))
            b4.send_mail(smtp, [msg], fromaddr, dryrun=cmdargs.dryrun)
        else:
            slug_from = re.sub(r'\W', '_', jsondata['fromemail'])
            slug_subj = re.sub(r'\W', '_', jsondata['subject'])
            slug = '%s_%s' % (slug_from.lower(), slug_subj.lower())
            slug = re.sub(r'_+', '_', slug)
            outfile = os.path.join(cmdargs.outdir, '%s.thanks' % slug)
            logger.info('  Writing: %s', outfile)
            with open(outfile, 'wb') as fh:
                fh.write(msg.as_bytes(policy=b4.emlpolicy))
        if cmdargs.dryrun:
            logger.info('Dry run, preserving tracked series.')
        else:
            logger.debug('Cleaning up: %s', jsondata['trackfile'])
            fullpath = os.path.join(datadir, jsondata['trackfile'])
            os.rename(fullpath, '%s.sent' % fullpath)

    logger.info('---')
    if not outgoing:
        logger.info('No thanks necessary.')
        return

    config = b4.get_main_config()
    pwstate = cmdargs.pw_set_state
    if not pwstate:
        pwstate = config.get('pw-accept-state')

    if send_email:
        if cmdargs.dryrun:
            logger.info('DRYRUN: generated %s thank-you letters', outgoing)
        else:
            logger.info('Sent %s thank-you letters', outgoing)
            if pwstate:
                b4.patchwork_set_state(msgids, pwstate)
    else:
        if pwstate:
            b4.patchwork_set_state(msgids, pwstate)
            logger.info('---')
        logger.debug('Wrote %s thank-you letters', outgoing)
        logger.info('You can now run:')
        logger.info('  git send-email %s/*.thanks', cmdargs.outdir)


def list_tracked():
    # find all tracked bits
    tracked = list()
    datadir = b4.get_data_dir()
    paths = sorted(Path(datadir).iterdir(), key=os.path.getmtime)
    for fullpath in paths:
        if fullpath.suffix not in ('.pr', '.am'):
            continue
        with fullpath.open('r', encoding='utf-8') as fh:
            jsondata = json.load(fh)
            jsondata['trackfile'] = fullpath.name
            if fullpath.suffix == '.pr':
                jsondata['pr_commit_id'] = fullpath.stem
        tracked.append(jsondata)
    return tracked


def write_tracked(tracked):
    counter = 1
    config = b4.get_main_config()
    logger.info('Currently tracking:')
    for entry in tracked:
        logger.info('%3d: %s', counter, entry['subject'])
        logger.info('       From: %s <%s>', entry['fromname'], entry['fromemail'])
        logger.info('       Date: %s', entry['sentdate'])
        logger.info('       Link: %s', config['linkmask'] % entry['msgid'])
        counter += 1


def thank_selected(cmdargs):
    tracked = list_tracked()
    if not len(tracked):
        logger.info('Nothing to do')
        sys.exit(0)

    if cmdargs.thankfor == 'all':
        listing = tracked
    else:
        listing = list()
        for num in b4.parse_int_range(cmdargs.thankfor, upper=len(tracked)):
            try:
                index = int(num) - 1
                listing.append(tracked[index])
            except ValueError:
                logger.critical('Please provide the number of the message')
                logger.info('---')
                write_tracked(tracked)
                sys.exit(1)
            except IndexError:
                logger.critical('Invalid index: %s', num)
                logger.info('---')
                write_tracked(tracked)
                sys.exit(1)
    if not len(listing):
        logger.info('Nothing to do')
        sys.exit(0)

    wantbranch = get_wanted_branch(cmdargs)
    send_messages(listing, wantbranch, cmdargs)
    sys.exit(0)


def discard_selected(cmdargs):
    tracked = list_tracked()
    if not len(tracked):
        logger.info('Nothing to do')
        sys.exit(0)

    if cmdargs.discard == 'all':
        listing = tracked
    else:
        listing = list()
        for num in b4.parse_int_range(cmdargs.discard, upper=len(tracked)):
            try:
                index = int(num) - 1
                listing.append(tracked[index])
            except ValueError:
                logger.critical('Please provide the number of the message')
                logger.info('---')
                write_tracked(tracked)
                sys.exit(1)
            except IndexError:
                logger.critical('Invalid index: %s', num)
                logger.info('---')
                write_tracked(tracked)
                sys.exit(1)

    if not len(listing):
        logger.info('Nothing to do')
        sys.exit(0)

    datadir = b4.get_data_dir()
    logger.info('Discarding %s messages', len(listing))
    msgids = list()
    for jsondata in listing:
        fullpath = os.path.join(datadir, jsondata['trackfile'])
        os.rename(fullpath, '%s.discarded' % fullpath)
        logger.info('  Discarded: %s', jsondata['subject'])
        msgids.append(jsondata['msgid'])
        for pdata in jsondata.get('patches', list()):
            msgids.append(pdata[2])

    config = b4.get_main_config()
    pwstate = cmdargs.pw_set_state
    if not pwstate:
        pwstate = config.get('pw-discard-state')
    if pwstate:
        b4.patchwork_set_state(msgids, pwstate)

    sys.exit(0)


def check_stale_thanks(outdir):
    if os.path.exists(outdir):
        for entry in Path(outdir).iterdir():
            if entry.suffix == '.thanks':
                logger.critical('ERROR: Found existing .thanks files in: %s', outdir)
                logger.critical('       Please send them first (or delete if already sent).')
                logger.critical('       Refusing to run to avoid potential confusion.')
                sys.exit(1)


def get_wanted_branch(cmdargs):
    global BRANCH_INFO
    gitdir = cmdargs.gitdir
    if not cmdargs.branch:
        # Find out our current branch
        gitargs = ['symbolic-ref', '-q', 'HEAD']
        ecode, out = b4.git_run_command(gitdir, gitargs)
        if ecode > 0:
            logger.critical('Not able to get current branch (git symbolic-ref HEAD)')
            sys.exit(1)
        wantbranch = re.sub(r'^refs/heads/', '', out.strip())
        logger.debug('will check branch=%s', wantbranch)
    else:
        # Make sure it's a real branch
        gitargs = ['branch', '--format=%(refname)', '--list', '--all', cmdargs.branch]
        lines = b4.git_get_command_lines(gitdir, gitargs)
        if not len(lines):
            logger.critical('Requested branch not found in git branch --list --all %s', cmdargs.branch)
            sys.exit(1)
        wantbranch = cmdargs.branch

    return wantbranch


def get_branch_info(gitdir, branch):
    global BRANCH_INFO
    if BRANCH_INFO is not None:
        return BRANCH_INFO

    BRANCH_INFO = dict()

    remotecfg = b4.get_config_from_git('branch\\.%s\\.*' % branch)
    if remotecfg is None or 'remote' not in remotecfg:
        # Did not find a matching branch entry, so look at remotes
        gitargs = ['remote', 'show']
        lines = b4.git_get_command_lines(gitdir, gitargs)
        if not len(lines):
            # No remotes? Hmm...
            return BRANCH_INFO

        remote = None
        for entry in lines:
            if branch.find(f'{entry}/') == 0:
                remote = entry
                break

        if remote is None:
            # Not found any matching remotes
            return BRANCH_INFO

        BRANCH_INFO['remote'] = remote
        BRANCH_INFO['branch'] = branch.replace(f'{remote}/', '')

    else:
        BRANCH_INFO['remote'] = remotecfg['remote']
        if 'merge' in remotecfg:
            BRANCH_INFO['branch'] = re.sub(r'^refs/heads/', '', remotecfg['merge'])

    # Grab template overrides
    remotecfg = b4.get_config_from_git('remote\\.%s\\..*' % BRANCH_INFO['remote'])
    BRANCH_INFO.update(remotecfg)

    return BRANCH_INFO


def main(cmdargs):
    usercfg = b4.get_user_config()
    if 'email' not in usercfg:
        logger.critical('Please set user.email in gitconfig to use this feature.')
        sys.exit(1)

    if cmdargs.auto:
        check_stale_thanks(cmdargs.outdir)
        auto_thankanator(cmdargs)
    elif cmdargs.thankfor:
        check_stale_thanks(cmdargs.outdir)
        thank_selected(cmdargs)
    elif cmdargs.discard:
        discard_selected(cmdargs)
    else:
        tracked = list_tracked()
        if not len(tracked):
            logger.info('No thanks necessary.')
            sys.exit(0)
        write_tracked(tracked)
        logger.info('---')
        logger.info('You can send them using number ranges, e.g:')
        logger.info('  b4 ty -t 1-3,5,7-')
