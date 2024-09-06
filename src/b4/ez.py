#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import email.message
import os
import sys
import b4
import re
import argparse
import uuid
import time
import datetime
import json
import shlex
import email
import pathlib
import base64
import textwrap
import gzip
import io
import tarfile
import hashlib
import urllib.parse

from typing import Optional, Tuple, List, Union, Dict
from email import utils
from string import Template

try:
    import patatt

    can_patatt = True
except ModuleNotFoundError:
    can_patatt = False

try:
    import git_filter_repo as fr  # noqa

    can_gfr = True
except ModuleNotFoundError:
    can_gfr = False

logger = b4.logger

MAGIC_MARKER = '--- b4-submit-tracking ---'
# Make this configurable?
SENT_TAG_PREFIX = 'sent/'

DEFAULT_ENDPOINT = 'https://lkml.kernel.org/_b4_submit'

DEFAULT_COVER_TEMPLATE = """
${cover}

---
${shortlog}

${diffstat}
---
base-commit: ${base_commit}
change-id: ${change_id}
${prerequisites}
Best regards,
-- 
${signature}
"""

DEFAULT_CHANGELOG_TEMPLATE = """
Changes in v${newrev}:
- EDITME: describe what is new in this series revision.
- EDITME: use bulletpoints and terse descriptions.
- Link to v${oldrev}: ${oldrev_link}

"""

DEFAULT_RANGEDIFF_TEMPLATE = """
Range-diff versus v${oldrev}:

"""

DEPS_HELP = """
# All lines starting with # will be removed
#
# You can define series prerequisites using the following formats:
#
# patch-id: [patch-id as returned by git-patch-id --stable]
# change-id: [the change-id of a series, followed by a colon and series version]
# message-id: <[the message-id of a series]>
# base-commit: [commit-ish where to apply all prerequisites and your series]
#
# IMPORTANT: specify all dependencies in the order they must be applied
#
# For example:
# ------------
# patch-id: 7709c0eec24c2c0c973d6af92c7915b8d0a2e52c
# change-id: 20240320-example-change-id:v1
# change-id: 20240320-some-other-example-change-id:v5
# message-id: <20240320-some-prereq-series-v1-0@example.com>
# base-commit: v6.9-rc1
#
# All dependencies will be checked and converted into prerequisite-patch-id: entries
# during "b4 send".
"""

PFHASH_CACHE = dict()


def get_auth_configs() -> Tuple[str, str, str, str, str, str]:
    config = b4.get_main_config()
    endpoint = config.get('send-endpoint-web', '')
    if not re.search(r'^https?://', endpoint):
        endpoint = None

    if not endpoint:
        # Use the default endpoint if we are in the kernel repo
        topdir = b4.git_get_toplevel()
        if os.path.exists(os.path.join(topdir, 'Kconfig')):
            logger.debug('No sendemail configs found, will use the default web endpoint')
            endpoint = DEFAULT_ENDPOINT
        else:
            raise RuntimeError('Web submission endpoint (b4.send-endpoint-web) is not defined, or is not a web URL.')

    usercfg = b4.get_user_config()
    myemail = usercfg.get('email')
    if not myemail:
        raise RuntimeError('No email configured, set user.email')
    myname = usercfg.get('name')
    pconfig = patatt.get_main_config()
    selector = pconfig.get('selector', 'default')
    algo, keydata = patatt.get_algo_keydata(pconfig)
    return endpoint, myname, myemail, selector, algo, keydata


def auth_new() -> None:
    try:
        endpoint, myname, myemail, selector, algo, keydata = get_auth_configs()
    except patatt.NoKeyError as ex:
        logger.critical('CRITICAL: no usable signing key configured')
        logger.critical('          %s', ex)
        sys.exit(1)
    except RuntimeError as ex:
        logger.critical('CRITICAL: unable to set up web authentication')
        logger.critical('          %s', ex)
        sys.exit(1)

    if algo == 'openpgp':
        gpgargs = ['--export', '--export-options', 'export-minimal', '-a', keydata]
        ecode, out, err = b4.gpg_run_command(gpgargs)
        if ecode > 0:
            logger.critical('CRITICAL: unable to get PGP public key for %s:%s', algo, keydata)
            sys.exit(1)
        pubkey = out.decode()
    elif algo == 'ed25519':
        from nacl.signing import SigningKey
        from nacl.encoding import Base64Encoder
        sk = SigningKey(keydata.encode(), encoder=Base64Encoder)
        pubkey = base64.b64encode(sk.verify_key.encode()).decode()
    else:
        logger.critical('CRITICAL: algorithm %s not currently supported for web endpoint submission', algo)
        sys.exit(1)

    logger.info('Will submit a new email authorization request to:')
    logger.info('  Endpoint: %s', endpoint)
    logger.info('      Name: %s', myname)
    logger.info('  Identity: %s', myemail)
    logger.info('  Selector: %s', selector)
    if algo == 'openpgp':
        logger.info('    Pubkey: %s:%s', algo, keydata)
    else:
        logger.info('    Pubkey: %s:%s', algo, pubkey)
    logger.info('---')
    try:
        input('Press Enter to confirm or Ctrl-C to abort')
    except KeyboardInterrupt:
        logger.info('')
        sys.exit(130)

    req = {
        'action': 'auth-new',
        'name': myname,
        'identity': myemail,
        'selector': selector,
        'pubkey': pubkey,
    }
    logger.info('Submitting new auth request to %s', endpoint)
    ses = b4.get_requests_session()
    res = ses.post(endpoint, json=req)
    logger.info('---')
    if res.status_code == 200:
        try:
            rdata = res.json()
            if rdata.get('result') == 'success':
                logger.info('Challenge generated and sent to %s', myemail)
                logger.info('Once you receive it, run b4 send --web-auth-verify [challenge-string]')
            sys.exit(0)

        except Exception as ex:  # noqa
            logger.critical('Odd response from the endpoint: %s', res.text)
            sys.exit(1)

    logger.critical('500 response from the endpoint: %s', res.text)
    sys.exit(1)


def auth_verify(cmdargs: argparse.Namespace) -> None:
    vstr = cmdargs.auth_verify
    endpoint, myname, myemail, selector, algo, keydata = get_auth_configs()
    logger.info('Signing challenge')
    # Create a minimal message
    cmsg = email.message.EmailMessage()
    cmsg.add_header('From', myemail)
    cmsg.add_header('Subject', 'b4-send-verify')
    cmsg.set_charset('utf-8')
    cmsg.set_payload(f'verify:{vstr}\n', charset='utf-8')
    bdata = cmsg.as_bytes(policy=b4.emlpolicy)
    try:
        bdata = patatt.rfc2822_sign(bdata).decode()
    except patatt.SigningError as ex:
        logger.critical('CRITICAL: Unable to sign verification message')
        logger.critical('          %s', ex)
        sys.exit(1)

    req = {
        'action': 'auth-verify',
        'msg': bdata,
    }
    logger.info('Submitting verification to %s', endpoint)
    ses = b4.get_requests_session()
    res = ses.post(endpoint, json=req)
    logger.info('---')
    if res.status_code == 200:
        try:
            rdata = res.json()
            if rdata.get('result') == 'success':
                logger.info('Challenge successfully verified for %s', myemail)
                logger.info('You may now use this endpoint for submitting patches.')
            sys.exit(0)

        except Exception as ex:  # noqa
            logger.critical('Odd response from the endpoint: %s', res.text)
            sys.exit(1)

    logger.critical('500 response from the endpoint: %s', res.text)
    sys.exit(1)


def get_rev_count(revrange: str, maxrevs: Optional[int] = 500) -> int:
    # Check how many revisions there are between the fork-point and the current HEAD
    gitargs = ['rev-list', revrange]
    lines = b4.git_get_command_lines(None, gitargs)
    # Check if this range is too large, if requested
    if maxrevs and len(lines) > maxrevs:
        raise RuntimeError('Too many commits in the range provided: %s' % len(lines))
    return len(lines)


def get_base_forkpoint(basebranch: str, mybranch: Optional[str] = None) -> str:
    if mybranch is None:
        mybranch = b4.git_get_current_branch()
    logger.debug('Finding the fork-point with %s', basebranch)
    gitargs = ['merge-base', '--fork-point', basebranch]
    lines = b4.git_get_command_lines(None, gitargs)
    if not lines:
        gitargs = ['merge-base', mybranch, basebranch]
        lines = b4.git_get_command_lines(None, gitargs)
        if not lines:
            logger.critical('CRITICAL: Could not find common ancestor with %s', basebranch)
            raise RuntimeError('Branches %s and %s have no common ancestors' % (basebranch, mybranch))
    forkpoint = lines[0]
    logger.debug('Fork-point between %s and %s is %s', mybranch, basebranch, forkpoint)

    return forkpoint


def start_new_series(cmdargs: argparse.Namespace) -> None:
    usercfg = b4.get_user_config()
    if 'name' not in usercfg or 'email' not in usercfg:
        logger.critical('CRITICAL: Unable to add your Signed-off-by: git returned no user.name or user.email')
        sys.exit(1)

    cover = tracking = patches = thread_msgid = revision = None
    if cmdargs.msgid:
        msgid = b4.get_msgid(cmdargs)
        list_msgs = b4.get_pi_thread_by_msgid(msgid)
        if not list_msgs:
            logger.critical('CRITICAL: no messages in the thread')
            sys.exit(1)
        lmbx = b4.LoreMailbox()
        for msg in list_msgs:
            lmbx.add_message(msg)
        lser = lmbx.get_series()
        if lser.has_cover:
            cmsg = lser.patches[0]
            b64tracking = cmsg.msg.get('x-b4-tracking')
            if b64tracking:
                logger.debug('Found x-b4-tracking header, attempting to restore')
                try:
                    # If we have b=, strip that out (we only support a single format,
                    # so there is currently no need to check what it's set to)
                    if b64tracking.find('v=1; b=') >= 0:
                        chunks = b64tracking.split('b=', maxsplit=1)
                        b64tracking = chunks[1].strip()
                    ztracking = base64.b64decode(b64tracking)
                    btracking = gzip.decompress(ztracking)
                    tracking = json.loads(btracking.decode())
                    logger.debug('tracking: %s', tracking)
                    cover_sections = list()
                    for section in re.split(r'^---\n', cmsg.body, flags=re.M):
                        # we stop caring once we see a diffstat
                        if b4.DIFFSTAT_RE.search(section):
                            break
                        cover_sections.append(section)
                    cover = '\n---\n'.join(cover_sections).strip()
                except Exception as ex:  # noqa
                    logger.critical('CRITICAL: unable to restore tracking information, ignoring')
                    logger.critical('          %s', ex)

            else:
                thread_msgid = msgid

            if not cover:
                logger.debug('Unrecognized cover letter format, will use as-is')
                cover = cmsg.body

            # Escape lines starting with "#" so they don't get lost
            cover = re.sub(r'^(#.*)$', r'>\1', cover, flags=re.M)

            cover = (f'{cmsg.subject}\n\n'
                     f'EDITME: Imported from f{msgid}\n'
                     f'        Please review before sending.\n\n') + cover

            change_id = lser.change_id
            if not cmdargs.new_series_name:
                if change_id:
                    cchunks = change_id.split('-')
                    if len(cchunks) > 2:
                        cmdargs.new_series_name = '-'.join(cchunks[1:-1])
                else:
                    slug = cmsg.lsubject.get_slug(with_counter=False)
                    # If it's longer than 30 chars, use first 3 words
                    if len(slug) > 30:
                        slug = '_'.join(slug.split('_')[:3])
                    cmdargs.new_series_name = slug

            base_commit = lser.base_commit
            if base_commit and not cmdargs.fork_point:
                logger.debug('Using %s as fork-point', base_commit)
                cmdargs.fork_point = base_commit
        else:
            # Use the first patch as our thread_msgid
            thread_msgid = lser.patches[1].msgid

        # We start with next revision
        revision = lser.revision + 1
        # Do or don't add follow-up trailers? Don't add for now, let them run b4 trailers -u.
        patches = lser.get_am_ready(noaddtrailers=True)
        logger.info('---')

    mybranch = b4.git_get_current_branch()
    strategy = get_cover_strategy()
    cherry_range = None
    depends_on = None
    if cmdargs.new_series_name:
        basebranch = None
        if not cmdargs.fork_point:
            if is_prep_branch():
                logger.debug('Will use current branch as dependency.')
                pcover, ptracking = load_cover(strip_comments=True)
                depends_on = f"change-id: {ptracking['series']['change-id']}:v{ptracking['series']['revision']}"

            cmdargs.fork_point = 'HEAD'
            if mybranch:
                basebranch = mybranch
            else:
                basebranch = 'HEAD'
        else:
            # if our strategy is not "commit", then we need to know which branch we're using as base
            if strategy != 'commit':
                gitargs = ['branch', '-v', '--contains', cmdargs.fork_point]
                lines = b4.git_get_command_lines(None, gitargs)
                if not lines:
                    logger.critical('CRITICAL: no branch contains fork-point %s', cmdargs.fork_point)
                    sys.exit(1)
                for line in lines:
                    chunks = line.split(maxsplit=2)
                    # There's got to be a better way than checking for '*'
                    if chunks[0] != '*':
                        continue
                    if chunks[1] == mybranch:
                        logger.debug('branch %s does contain fork-point %s', mybranch, cmdargs.fork_point)
                        basebranch = mybranch
                        break
            else:
                basebranch = mybranch

            if basebranch is None:
                logger.critical('CRITICAL: fork-point %s is not on the current branch.', cmdargs.fork_point)
                logger.critical('          Switch to the branch you want to use as base and try again.')
                sys.exit(1)

        slug = re.sub(r'\W+', '-', cmdargs.new_series_name).strip('-').lower()
        branchname = 'b4/%s' % slug
        args = ['checkout', '-b', branchname, cmdargs.fork_point]
        ecode, out = b4.git_run_command(None, args, logstderr=True)
        if ecode > 0:
            logger.critical('CRITICAL: Failed to create a new branch %s', branchname)
            logger.critical(out)
            sys.exit(ecode)
        logger.info('Created new branch %s', branchname)
        seriesname = cmdargs.new_series_name

    elif cmdargs.enroll_base:
        basebranch = None
        branchname = b4.git_get_current_branch()
        seriesname = branchname
        slug = re.sub(r'\W+', '-', branchname).strip('-').lower()
        enroll_base = cmdargs.enroll_base
        # Convert @{upstream}, @{push} to an abbreviated ref
        gitargs = ['rev-parse', '--abbrev-ref', '--verify', enroll_base]
        ecode, out = b4.git_run_command(None, gitargs)
        if ecode > 0:
            if enroll_base == '@{upstream}' or enroll_base == '@{u}':
                logger.critical('CRITICAL: current branch has no configured upstream')
                sys.exit(1)
        elif out:
            enroll_base = out.strip()
        # Is it a branch?
        gitargs = ['show-ref', f'refs/heads/{enroll_base}', f'refs/remotes/{enroll_base}']
        lines = b4.git_get_command_lines(None, gitargs)
        if lines:
            try:
                forkpoint = get_base_forkpoint(enroll_base, mybranch)
            except RuntimeError as ex:
                logger.critical('CRITICAL: could not use %s as enrollment base:', enroll_base)
                logger.critical('          %s', ex)
                sys.exit(1)
            basebranch = enroll_base
        else:
            # Check that that object exists
            gitargs = ['rev-parse', '--verify', enroll_base]
            ecode, out = b4.git_run_command(None, gitargs)
            if ecode > 0:
                logger.critical('CRITICAL: Could not find object: %s', enroll_base)
                raise RuntimeError('Object %s not found' % enroll_base)
            forkpoint = out.strip()
            # check branches where this object lives
            heads = b4.git_branch_contains(None, forkpoint, checkall=True)
            if mybranch not in heads:
                logger.critical('CRITICAL: object %s does not exist on current branch', enroll_base)
                sys.exit(1)
            if strategy != 'commit':
                # Remove any branches starting with b4/
                heads.remove(mybranch)
                for head in list(heads):
                    if head.startswith('b4/'):
                        heads.remove(head)
                if len(heads) > 1:
                    logger.critical('CRITICAL: Multiple branches contain object %s, please pass a branch name as base',
                                    enroll_base)
                    logger.critical('          %s', ', '.join(heads))
                    sys.exit(1)
                if len(heads) < 1:
                    logger.critical('CRITICAL: No other branch contains %s: cannot use as fork base', enroll_base)
                    sys.exit(1)
                basebranch = heads.pop()

        try:
            commitcount = get_rev_count(f'{forkpoint}..')
        except RuntimeError as ex:
            logger.critical('CRITICAL: could not use %s as fork point:', enroll_base)
            logger.critical('          %s', ex)
            sys.exit(1)

        if commitcount:
            logger.info('Will track %s commits', commitcount)
        else:
            logger.info('NOTE: No new commits since fork-point "%s"', enroll_base)

        if commitcount and strategy == 'commit':
            gitargs = ['rev-parse', 'HEAD']
            lines = b4.git_get_command_lines(None, gitargs)
            if not lines:
                logger.critical('CRITICAL: Could not rev-parse current HEAD')
                sys.exit(1)
            endpoint = lines[0].strip()
            cherry_range = f'{forkpoint}..{endpoint}'
            # Reset current branch to the forkpoint
            gitargs = ['reset', '--hard', forkpoint]
            ecode, out = b4.git_run_command(None, gitargs, logstderr=True)
            if ecode > 0:
                logger.critical('CRITICAL: not able to reset current branch to %s', forkpoint)
                logger.critical(out)
                sys.exit(1)

        # Try loading existing cover info
        cover, jdata = load_cover()

    else:
        logger.critical('CRITICAL: unknown operation requested')
        sys.exit(1)

    # Store our cover letter strategy in the branch config
    b4.git_set_config(None, f'branch.{branchname}.b4-prep-cover-strategy', strategy)

    if not cover:
        # create a default cover letter and store it where the strategy indicates
        cover = ('EDITME: cover title for %s' % seriesname,
                 '',
                 '# Describe the purpose of this series. The information you put here',
                 '# will be used by the project maintainer to make a decision whether',
                 '# your patches should be reviewed, and in what priority order. Please be',
                 '# very detailed and link to any relevant discussions or sites that the',
                 '# maintainer can review to better understand your proposed changes. If you',
                 '# only have a single patch in your series, the contents of the cover',
                 '# letter will be appended to the "under-the-cut" portion of the patch.',
                 '',
                 '# Lines starting with # will be removed from the cover letter. You can',
                 '# use them to add notes or reminders to yourself. If you want to use',
                 '# markdown headers in your cover letter, start the line with ">#".',
                 '',
                 '# You can add trailers to the cover letter. Any email addresses found in',
                 '# these trailers will be added to the addresses specified/generated',
                 '# during the b4 send stage. You can also run "b4 prep --auto-to-cc" to',
                 '# auto-populate the To: and Cc: trailers based on the code being',
                 '# modified.',
                 '',
                 'Signed-off-by: %s <%s>' % (usercfg.get('name', ''), usercfg.get('email', '')),
                 '',
                 '',
                 )
        cover = '\n'.join(cover)
        logger.info('Created the default cover letter, you can edit with --edit-cover.')

    if not tracking:
        # We don't need all the entropy of uuid, just some of it
        changeid = '%s-%s-%s' % (datetime.date.today().strftime('%Y%m%d'), slug, uuid.uuid4().hex[:12])
        if revision is None:
            revision = 1
        prefixes = list()
        if cmdargs.set_prefixes:
            prefixes = list(cmdargs.set_prefixes)
        else:
            config = b4.get_main_config()
            if config.get('send-prefixes'):
                prefixes = config.get('send-prefixes').split()

        tracking = {
            'series': {
                'revision': revision,
                'change-id': changeid,
                'prefixes': prefixes,
            },
        }
        if thread_msgid:
            tracking['series']['from-thread'] = thread_msgid
        if depends_on:
            logger.info('Marking series as depending on %s', depends_on)
            tracking['series']['prerequisites'] = [depends_on]
        if strategy != 'commit':
            # We only need the base-branch info when using strategies other than 'commit'
            tracking['series']['base-branch'] = basebranch

    store_cover(cover, tracking, new=True)
    if cherry_range:
        gitargs = ['cherry-pick', cherry_range]
        ecode, out = b4.git_run_command(None, gitargs)
        if ecode > 0:
            # Woops, this is bad! At least tell them where the commit range is.
            logger.critical('Could not cherry-pick commits from range %s', cherry_range)
            sys.exit(1)

    if patches:
        logger.info('Applying %s patches', len(patches))
        logger.info('---')
        ifh = io.BytesIO()
        b4.save_git_am_mbox(patches, ifh)
        ambytes = ifh.getvalue()
        ecode, out = b4.git_run_command(None, ['am'], stdin=ambytes, logstderr=True)
        logger.info(out.strip())
        if ecode > 0:
            logger.critical('Could not apply patches from thread: %s', out)
            sys.exit(ecode)
        logger.info('---')
        logger.info('NOTE: any follow-up trailers were ignored; apply them with b4 trailers -u')


def make_magic_json(data: dict) -> str:
    mj = (f'{MAGIC_MARKER}\n'
          '# This section is used internally by b4 prep for tracking purposes.\n')
    return mj + json.dumps(data, indent=2)


def load_cover(strip_comments: bool = False, usebranch: Optional[str] = None) -> Tuple[str, dict]:
    strategy = get_cover_strategy(usebranch)
    if strategy in {'commit', 'tip-commit'}:
        cover_commit = find_cover_commit(usebranch=usebranch)
        if not cover_commit:
            cover = ''
            tracking = dict()
        else:
            gitargs = ['show', '-s', '--format=%B', cover_commit]
            ecode, out = b4.git_run_command(None, gitargs)
            if ecode > 0:
                logger.critical('CRITICAL: unable to load cover letter')
                sys.exit(1)
            contents = out
            # Split on MAGIC_MARKER
            cover, magic_json = contents.split(MAGIC_MARKER)
            # drop everything until the first {
            junk, mdata = magic_json.split('{', maxsplit=1)
            tracking = json.loads('{' + mdata)

    elif strategy == 'branch-description':
        mybranch = b4.git_get_current_branch()
        bcfg = b4.get_config_from_git(rf'branch\.{mybranch}\..*')
        cover = bcfg.get('description', '')
        tracking = json.loads(bcfg.get('b4-tracking', '{}'))

    else:
        logger.critical('Not yet supported for %s cover strategy', strategy)
        sys.exit(0)

    logger.debug('tracking data: %s', tracking)
    if strip_comments:
        cover = re.sub(r'^#.*$', '', cover, flags=re.M)
        # Unescape markdown headers
        cover = re.sub(r'^>(#.*)$', r'\1', cover, flags=re.M)
        while '\n\n\n' in cover:
            cover = cover.replace('\n\n\n', '\n\n')

    return cover.strip(), tracking


def store_cover(content: str, tracking: dict, new: bool = False) -> None:
    strategy = get_cover_strategy()
    if strategy in {'commit', 'tip-commit'}:
        cover_message = content + '\n\n' + make_magic_json(tracking)
        if new:
            args = ['commit', '--allow-empty', '-F', '-']
            ecode, out = b4.git_run_command(None, args, stdin=cover_message.encode(), logstderr=True)
            if ecode > 0:
                logger.critical('CRITICAL: Generating cover letter commit failed:')
                logger.critical(out)
                raise RuntimeError('Error saving cover letter')
        else:
            commit = find_cover_commit()
            if not commit:
                logger.critical('CRITICAL: Could not find the cover letter commit.')
                raise RuntimeError('Error saving cover letter (commit not found)')
            fred = FRCommitMessageEditor()
            fred.add(commit, cover_message)
            args = fr.FilteringOptions.parse_args(['--force', '--quiet', '--refs', f'{commit}~1..HEAD'])
            args.refs = [f'{commit}~1..HEAD']
            frf = fr.RepoFilter(args, commit_callback=fred.callback)
            logger.info('Invoking git-filter-repo to update the cover letter.')
            frf.run()

    if strategy == 'branch-description':
        mybranch = b4.git_get_current_branch(None)
        b4.git_set_config(None, f'branch.{mybranch}.description', content)
        trackstr = json.dumps(tracking)
        b4.git_set_config(None, f'branch.{mybranch}.b4-tracking', trackstr)
        logger.info('Updated branch description and tracking info.')


# Valid cover letter strategies:
# 'commit': in an empty commit at the start of the series        : implemented
# 'branch-description': in the branch description                : implemented
# 'tip-commit': in an empty commit at the tip of the branch      : implemented
# 'tag': in an annotated tag at the tip of the branch            : TODO
# 'tip-merge': in an empty merge commit at the tip of the branch : TODO
#              (once/if git upstream properly supports it)

def get_cover_strategy(usebranch: Optional[str] = None) -> str:
    if usebranch:
        branch = usebranch
    else:
        branch = b4.git_get_current_branch()
    # Check local branch config for the strategy
    bconfig = b4.get_config_from_git(rf'branch\.{branch}\..*')
    if 'b4-prep-cover-strategy' in bconfig:
        strategy = bconfig.get('b4-prep-cover-strategy')
        logger.debug('Got strategy=%s from branch-config', strategy)
    else:
        config = b4.get_main_config()
        strategy = config.get('prep-cover-strategy', 'commit')

    if strategy in {'commit', 'branch-description', 'tip-commit'}:
        return strategy

    logger.critical('CRITICAL: unknown prep-cover-strategy: %s', strategy)
    sys.exit(1)


def is_prep_branch(mustbe: bool = False, usebranch: Optional[str] = None) -> bool:
    mustmsg = 'CRITICAL: This is not a prep-managed branch.'
    if usebranch:
        mybranch = usebranch
    else:
        mybranch = b4.git_get_current_branch()
    if mybranch is None:
        # Not on any branch?
        if mustbe:
            logger.critical(mustmsg)
            sys.exit(1)
        return False

    strategy = get_cover_strategy(mybranch)
    if strategy in {'commit', 'tip-commit'}:
        if find_cover_commit(usebranch=mybranch) is None:
            if mustbe:
                logger.critical(mustmsg)
                sys.exit(1)
            return False
        return True
    if strategy == 'branch-description':
        # See if we have b4-tracking set for this branch
        bcfg = b4.get_config_from_git(rf'branch\.{mybranch}\..*')
        if bcfg.get('b4-tracking'):
            return True
        if mustbe:
            logger.critical(mustmsg)
            sys.exit(1)
        return False

    logger.critical('CRITICAL: unknown cover strategy: %s', strategy)
    sys.exit(1)


def find_cover_commit(usebranch: Optional[str] = None) -> Optional[str]:
    # Walk back commits until we find the cover letter
    # Our covers always contain the MAGIC_MARKER line
    logger.debug('Looking for the cover letter commit with magic marker "%s"', MAGIC_MARKER)
    if not usebranch:
        usebranch = b4.git_get_current_branch()
    if usebranch is None:
        logger.critical("The current repository is not tracking a branch. To use b4, please checkout a branch.")
        logger.critical("Maybe a rebase is running?")
        raise RuntimeError("Not currently on a branch, please checkout a b4-tracked branch")

    # Restrict to committer being the current person, in case an errant cover letter
    # got added into the shared tree, as in:
    # https://lore.kernel.org/c52b7bf6-734b-49fd-96e3-e4cde406f4e0@linaro.org/
    # TODO: make it possible to ignore it, to make it possible to work on deliberately shared trees?
    usercfg = b4.get_user_config()
    limit_committer = usercfg['email']
    gitargs = ['log', '--grep', MAGIC_MARKER, '-F', '--pretty=oneline', '--max-count=1', '--since=1.year',
               f'--committer={limit_committer}', usebranch]
    lines = b4.git_get_command_lines(None, gitargs)
    if not lines:
        return None
    found = lines[0].split()[0]
    logger.debug('Cover commit found in %s', found)
    return found


class FRCommitMessageEditor:
    edit_map: dict

    def __init__(self, edit_map: Optional[dict] = None):
        if edit_map:
            self.edit_map = edit_map
        else:
            self.edit_map = dict()

    def add(self, commit: str, message: str):
        self.edit_map[commit.encode()] = message.encode()

    def callback(self, commit, metadata):  # noqa
        if commit.original_id in self.edit_map:
            commit.message = self.edit_map[commit.original_id]


def edit_cover() -> None:
    is_prep_branch(mustbe=True)
    cover, tracking = load_cover()
    bcover = cover.encode()
    new_bcover = b4.edit_in_editor(bcover, filehint='COMMIT_EDITMSG')
    if new_bcover == bcover:
        logger.info('Cover letter unchanged.')
        return
    new_cover = new_bcover.decode(errors='replace').strip()
    if not len(new_cover):
        logger.info('New cover letter blank, leaving current one unchanged.')
        return

    store_cover(new_cover, tracking)
    logger.info('Cover letter updated.')


def edit_deps() -> None:
    is_prep_branch(mustbe=True)
    cover, tracking = load_cover()
    prereqs = tracking['series'].get('prerequisites', list())
    deps = '\n'.join(prereqs)
    toedit = f'{deps}\n{DEPS_HELP}'
    bdata = toedit.encode()
    new_bdata = b4.edit_in_editor(bdata, filehint='prereqs.yaml')
    if new_bdata == bdata:
        logger.info('Dependencies unchanged.')
        return
    new_data = new_bdata.decode(errors='replace').strip()
    prereqs = list()
    recognized = {'patch-id', 'change-id', 'message-id', 'base-commit'}
    if len(new_data):
        for line in new_data.split('\n'):
            entry = line.strip()
            if not entry or entry.startswith('#'):
                logger.debug('Ignoring: %s', entry)
                continue
            chunks = [x.strip() for x in entry.split(':')]
            if not chunks[0] in recognized:
                logger.warning('WARNING: Unrecognized entry: %s', entry)
            prereqs.append(entry)

    tracking['series']['prerequisites'] = prereqs
    logger.info('---')
    store_cover(cover, tracking)


def check_deps(cmdargs: argparse.Namespace) -> None:
    is_prep_branch(mustbe=True)
    cover, tracking = load_cover()
    prereqs = tracking['series'].get('prerequisites', list())
    if not prereqs:
        logger.info('This series has no defined dependencies.')
        logger.info('To add dependencies, use --edit-deps.')
        return
    res = dict()
    prereq_patches = list()
    known_patches = dict()
    base_commit = None
    for prereq in prereqs:
        logger.info('Checking %s', prereq)
        chunks = prereq.split(':')
        parts = [x.strip() for x in chunks]

        if parts[0] == 'change-id':
            change_id = parts[1]
            lmbx = b4.get_series_by_change_id(change_id, nocache=cmdargs.nocache)
            if not lmbx:
                logger.debug('FAIL: No such change-id found: %s', change_id)
                res[prereq] = (False, 'No matching change-id found on the server')
                continue
            if len(parts) > 2:
                logger.debug('Checking if %s is the latest series', parts[2])
                matches = re.search(r'^v?(\d+)', parts[2])
                if matches:
                    wantser = int(matches.groups()[0])
                    if wantser not in lmbx.series:
                        logger.debug('FAIL: No matching series %s for change-id %s', wantser, change_id)
                        res[prereq] = (False, f'No version {wantser} found for change-id {change_id}')
                        continue
                    # Is it the latest version?
                    maxser = max(lmbx.series.keys())
                    if wantser < maxser:
                        logger.debug('Fail: Newer version v%s available for change-id %s', maxser, change_id)
                        res[prereq] = (False, f'v{maxser} available for change-id {change_id} (you have: v{wantser})')
                        continue
                    logger.debug('Pass: change-id %s found and is the latest posted series', change_id)
                    res[prereq] = (True, f'Change-id {change_id} found and is the latest available version')
                    lser = lmbx.get_series(wantser, codereview_trailers=False)
                    for lmsg in lser.patches[1:]:
                        prereq_patches.append(lmsg.get_am_message(add_trailers=False))
                        known_patches[lmsg.git_patch_id] = lmsg
            else:
                maxser = max(lmbx.series.keys())
                res[prereq] = (False, f'change-id should include the revision, e.g.: {change_id}:v{maxser}')
                continue

        elif parts[0] == 'patch-id':
            patch_id = parts[1]
            if patch_id not in known_patches:
                lmbx = b4.get_series_by_patch_id(patch_id, nocache=cmdargs.nocache)
                if lmbx:
                    for rev, lser in lmbx.series.items():
                        for lmsg in lser.patches[1:]:
                            if not lmsg:
                                continue
                            ppid = lmsg.git_patch_id
                            if ppid:
                                known_patches[ppid] = lmsg
            if patch_id not in known_patches:
                logger.debug('FAIL: No such patch-id found: %s', patch_id)
                res[prereq] = (False, 'No matching patch-id found on the server')
                continue
            lmsg = known_patches[patch_id]
            prereq_patches.append(lmsg.get_am_message(add_trailers=False))
            logger.debug('PASS: patch-id found: %s', patch_id)
            res[prereq] = (True, 'Matching patch-id found on the server')

        elif parts[0] == 'message-id':
            msgid = parts[1].strip('<>')
            q_msgs = b4.get_pi_thread_by_msgid(msgid, nocache=cmdargs.nocache)
            if not q_msgs:
                logger.debug('FAIL: No such message-id found: %s', msgid)
                res[prereq] = (False, 'No matching message-id found on the server')
                continue
            # Always do no-parent for these
            s_msgs = b4.get_strict_thread(q_msgs, msgid, noparent=True)
            lmbx = b4.LoreMailbox()
            for s_msg in s_msgs:
                lmbx.add_message(s_msg)
            if len(lmbx.series) > 1:
                logger.debug('FAIL: msgid=%s is a thread with multiple series', msgid)
                res[prereq] = (False, f'Message-id <%s> has multiple posted series', msgid)
                continue

            maxser = max(lmbx.series.keys())
            lser = lmbx.get_series(maxser, codereview_trailers=False)
            for lmsg in lser.patches[1:]:
                prereq_patches.append(lmsg.get_am_message(add_trailers=False))
                known_patches[lmsg.git_patch_id] = lmsg
            logger.debug('PASS: message-id found: %s', msgid)
            res[prereq] = (True, 'Matching message-id found on the server')

        if parts[0] == 'base-commit':
            base_commit = parts[1]

    allgood = all([x[0] for x in res.values()])
    if not base_commit:
        logger.debug('FAIL: base-commit not specified')
        res['base-commit: MISSING'] = (False, 'Series with dependencies require a base-commit')
    elif allgood:
        logger.info('Testing if all patches can be applied to %s', base_commit)
        tos, ccs, tstr, mypatches = get_prep_branch_as_patches(thread=False, movefrom=False, addtracking=False)
        if get_cover_strategy() == "commit":
            # If the cover letter is stored as a commit, skip it to avoid empty patches
            prereq_patches += [x[1] for x in mypatches[1:]]
        else:
            prereq_patches += [x[1] for x in mypatches]
        gitdir = os.getcwd()
        topdir = b4.git_get_toplevel(gitdir)
        if b4.git_commit_exists(topdir, base_commit):
            for ppatch in prereq_patches:
                logger.info('  %s', ppatch.get('subject', ''))
            ifh = io.BytesIO()
            b4.save_git_am_mbox(prereq_patches, ifh)
            ambytes = ifh.getvalue()
            try:
                b4.git_fetch_am_into_repo(topdir, ambytes, at_base=base_commit, check_only=True)
                logger.debug('PASS: Prereqs cleanly apply to %s', base_commit)
                res[f'base-commit: {base_commit}'] = (True, 'All patches cleanly apply')
            except RuntimeError:
                logger.debug('FAIL: Could not cleanly apply patches to %s', base_commit)
                res[f'base-commit: {base_commit}'] = (False, 'Could not cleanly apply patches')
        else:
            logger.debug('FAIL: %s does not exist in current tree', base_commit)
            res[f'base-commit: {base_commit}'] = (False, 'Base commit not found in the current tree')
    else:
        logger.info('Not checking applicability of the series due to other errors')

    if res:
        logger.info('---')
        for prereq, info in res.items():
            if info[0]:
                logger.info('%s %s', b4.CI_FLAGS_FANCY['success'], prereq)
            else:
                logger.info('%s %s', b4.CI_FLAGS_FANCY['fail'], prereq)
                logger.info('   - %s', info[1])

    store_preflight_check('check-deps')


def get_series_start(usebranch: Optional[str] = None) -> str:
    if usebranch:
        mybranch = usebranch
    else:
        mybranch = b4.git_get_current_branch()
    strategy = get_cover_strategy(usebranch=mybranch)
    forkpoint = None
    if strategy == 'commit':
        # Start at the cover letter commit
        return find_cover_commit(usebranch=mybranch)
    if strategy == 'branch-description':
        bcfg = b4.get_config_from_git(rf'branch\.{mybranch}\..*')
        tracking = bcfg.get('b4-tracking')
        if not tracking:
            logger.critical('CRITICAL: Could not find tracking info for %s', mybranch)
            sys.exit(1)
        jdata = json.loads(tracking)
        basebranch = jdata['series']['base-branch']
        try:
            forkpoint = get_base_forkpoint(basebranch)
            commitcount = get_rev_count(f'{forkpoint}..')
        except RuntimeError:
            sys.exit(1)
        logger.debug('series_start: %s, commitcount=%s', forkpoint, commitcount)
    if strategy == 'tip-commit':
        cover, tracking = load_cover(usebranch=mybranch)
        basebranch = tracking['series']['base-branch']
        try:
            forkpoint = get_base_forkpoint(basebranch)
            commitcount = get_rev_count(f'{forkpoint}..HEAD~1')
        except RuntimeError:
            sys.exit(1)
        logger.debug('series_start: %s, commitcount=%s', forkpoint, commitcount)

    return forkpoint


def update_trailers(cmdargs: argparse.Namespace) -> None:
    if not b4.can_network and not cmdargs.localmbox:
        logger.critical('CRITICAL: To work in offline mode you have to pass a local mailbox.')
        sys.exit(1)

    usercfg = b4.get_user_config()
    if 'name' not in usercfg or 'email' not in usercfg:
        logger.critical('CRITICAL: Please set your user.name and user.email')
        sys.exit(1)

    ignore_commits = None
    changeid = None
    cover = None
    msgid = None
    end = 'HEAD'
    limit_committer = usercfg['email']
    # If we are in an b4-prep branch, we start from the beginning of the series
    if is_prep_branch():
        # Don't limit by committer in a prep branch
        limit_committer = None
        start = get_series_start()
        cover, tracking = load_cover(strip_comments=True)
        changeid = tracking['series'].get('change-id')
        if cmdargs.trailers_from:
            msgid = cmdargs.trailers_from
        else:
            msgid = tracking['series'].get('from-thread')
        strategy = get_cover_strategy()
        if strategy in {'commit', 'tip-commit'}:
            # We need to me sure we ignore the cover commit
            cover_commit = find_cover_commit()
            if cover_commit:
                ignore_commits = {cover_commit}

    elif cmdargs.since_commit:
        since_commit = b4.git_revparse_obj(cmdargs.since_commit)
        if since_commit:
            start = f'{since_commit}~1'
        else:
            logger.critical('CRITICAL: Could not resolve %s to a git commit', cmdargs.since_commit)
            sys.exit(1)

    else:
        # There doesn't appear to be a great way to find the first commit
        # where we're NOT the committer, so we get all commits since range specified where
        # we're the committer and pick the earliest commit
        gitargs = ['log', '-F', '--no-merges', f'--committer={limit_committer}', '--format=%H', '--reverse',
                   '--since', cmdargs.since]
        lines = b4.git_get_command_lines(None, gitargs)
        if not lines:
            logger.critical('CRITICAL: could not find any commits where committer=%s', limit_committer)
            sys.exit(1)
        first_commit = lines[0]
        start = f'{first_commit}~1'

    if cmdargs.msgid or cmdargs.trailers_from:
        if cmdargs.trailers_from:
            # Compatibility with b4 overall retrieval tools
            cmdargs.msgid = cmdargs.trailers_from
        msgid = b4.get_msgid(cmdargs)

    try:
        patches = b4.git_range_to_patches(None, start, end, ignore_commits=ignore_commits,
                                          limit_committer=limit_committer)
        if cover:
            cmsg = email.message.EmailMessage()
            cmsg['Subject'] = f'[PATCH 0/{len(patches)}] cover'
            cmsg['Message-Id'] = '<cover>'
            cmsg.set_payload('cover', 'us-ascii')
            patches.insert(0, ('', cmsg))
            rethread(patches)
    except RuntimeError as ex:
        logger.critical('CRITICAL: Failed to convert range to patches: %s', ex)
        sys.exit(1)

    logger.info('Finding code-review trailers for %s commits...', len(patches))
    bbox = b4.LoreMailbox()
    for commit, msg in patches:
        if commit:
            msg['Message-Id'] = f'<{commit}>'
        bbox.add_message(msg)

    commit_map = dict()
    by_subject = dict()
    for lmsg in bbox.series[1].patches:
        if not lmsg:
            continue
        by_subject[lmsg.subject] = lmsg.msgid
        commit_map[lmsg.msgid] = lmsg

    list_msgs = list()
    if changeid and b4.can_network:
        logger.info('Checking change-id "%s"', changeid)
        query = f'"change-id: {changeid}"'
        smsgs = b4.get_pi_search_results(query, nocache=True)
        if smsgs is not None:
            list_msgs += smsgs

    if msgid or cmdargs.localmbox:
        if msgid:
            cmdargs.msgid = msgid
        try:
            msgid, tmsgs = b4.retrieve_messages(cmdargs)
        except LookupError as ex:
            logger.critical('CRITICAL: %s', ex)
            sys.exit(1)
        if tmsgs is not None:
            list_msgs += tmsgs

    for list_msg in list_msgs:
        llmsg = b4.LoreMessage(list_msg)
        if not llmsg.trailers:
            continue
        if llmsg.subject in by_subject:
            # Reparent to the commit and add to followups
            commit = by_subject[llmsg.subject]
            logger.debug('Mapped "%s" to commit %s', llmsg.subject, commit)
            plmsg = commit_map[commit]
            llmsg.in_reply_to = plmsg.msgid
            bbox.followups.append(llmsg)
        elif llmsg.counter == 0 and changeid:
            logger.debug('Mapped "%s" to the cover letter', llmsg.subject)
            # Reparent to the cover and add to followups
            llmsg.in_reply_to = 'cover'
            bbox.followups.append(llmsg)
        else:
            # Match by patch-id?
            logger.debug('No match for %s', llmsg.subject)

    if msgid or changeid:
        logger.debug('Will query by change-id')
        codereview_trailers = False
    else:
        codereview_trailers = True

    lser = bbox.get_series(sloppytrailers=cmdargs.sloppytrailers, codereview_trailers=codereview_trailers)
    mismatches = list(lser.trailer_mismatches)
    config = b4.get_main_config()
    seen_froms = set()
    logger.info('---')
    # Do we have follow-up tralers sent to the cover?
    if lser.patches[0] and lser.patches[0].followup_trailers:
        logger.debug('Applying follow-up trailers from cover to all patches')
        for pmsg in lser.patches[1:]:
            logger.debug('  %s (%s)', pmsg.subject, pmsg.msgid)
            logger.debug('  + %s', [x.as_string() for x in lser.patches[0].followup_trailers])
            pmsg.followup_trailers += lser.patches[0].followup_trailers

    updates = dict()
    for lmsg in lser.patches[1:]:
        if not lmsg:
            continue
        if not lmsg.followup_trailers:
            logger.debug('No new follow-up trailers in: %s', lmsg.subject)
            continue

        commit = lmsg.msgid
        parts = b4.LoreMessage.get_body_parts(lmsg.body)
        for fltr in lmsg.followup_trailers:
            if fltr not in parts[2]:
                if commit not in updates:
                    updates[commit] = list()
                updates[commit].append(fltr)
                rendered = fltr.as_string(omit_extinfo=True)
                if rendered in seen_froms:
                    continue
                seen_froms.add(rendered)
                source = config['midmask'] % urllib.parse.quote_plus(fltr.lmsg.msgid, safe='@')
                logger.info('  + %s', rendered)
                logger.info('    %s', source)

        # Check if we've applied mismatched trailers already
        if not cmdargs.sloppytrailers and mismatches:
            for mismatch in list(mismatches):
                if b4.LoreTrailer(name=mismatch[0], value=mismatch[1]) in parts[2]:
                    logger.debug('Removing already-applied mismatch %s', mismatch[0])
                    mismatches.remove(mismatch)

    if len(mismatches):
        logger.critical('---')
        logger.critical('NOTE: some trailers ignored due to from/email mismatches:')
        for tname, tvalue, fname, femail in lser.trailer_mismatches:
            logger.critical('    ! Trailer: %s: %s', tname, tvalue)
            logger.critical('     Msg From: %s <%s>', fname, femail)
        logger.critical('NOTE: Rerun with -S to apply them anyway')

    if not updates:
        logger.info('No trailer updates found.')
        return

    try:
        logger.critical('---')
        if not cmdargs.no_interactive:
            input('Press Enter to apply these trailers or Ctrl-C to abort')
    except KeyboardInterrupt:
        logger.info('')
        sys.exit(130)

    # Create the map of new messages
    fred = FRCommitMessageEditor()
    for commit, newtrailers in updates.items():
        cmsg = commit_map[commit]
        logger.info('  %s', cmsg.subject)
        if len(newtrailers):
            cmsg.followup_trailers = newtrailers
        cmsg.fix_trailers()
        fred.add(commit, cmsg.message)
    logger.info('---')
    args = fr.FilteringOptions.parse_args(['--force', '--quiet', '--refs', f'{start}..'])
    args.refs = [f'{start}..']
    frf = fr.RepoFilter(args, commit_callback=fred.callback)
    logger.info('Invoking git-filter-repo to update trailers.')
    frf.run()
    logger.info('Trailers updated.')


def get_addresses_from_cmd(cmdargs: List[str], msgbytes: bytes) -> List[Tuple[str, str]]:
    if not cmdargs:
        return list()
    # Run this command from git toplevel
    topdir = b4.git_get_toplevel()
    ecode, out, err = b4._run_command(cmdargs, stdin=msgbytes, rundir=topdir)  # noqa
    if ecode > 0:
        logger.critical('CRITICAL: Running %s failed:', ' '.join(cmdargs))
        logger.critical(err.decode(errors='ignore'))
        raise RuntimeError('Running command failed: %s' % ' '.join(cmdargs))
    addrs = out.strip().decode(errors='ignore')
    if not addrs:
        return list()
    return utils.getaddresses(addrs.split('\n'))


def get_series_range(start_commit: Optional[str] = None, usebranch: Optional[str] = None) -> Tuple[str, str, str]:
    if usebranch:
        mybranch = usebranch
    else:
        mybranch = b4.git_get_current_branch()
    if not start_commit:
        start_commit = get_series_start(usebranch=mybranch)
    strategy = get_cover_strategy(usebranch=mybranch)
    if strategy == 'commit':
        gitargs = ['rev-parse', f'{start_commit}~1']
        lines = b4.git_get_command_lines(None, gitargs)
        base_commit = lines[0]
    else:
        base_commit = start_commit
    if strategy == 'tip-commit':
        cover_commit = find_cover_commit(usebranch=mybranch)
        end_commit = b4.git_revparse_obj(f'{cover_commit}~1')
    else:
        end_commit = b4.git_revparse_obj(mybranch)

    return base_commit, start_commit, end_commit


def get_series_details(start_commit: Optional[str] = None, usebranch: Optional[str] = None
                       ) -> Tuple[str, str, str, List[str], str, str]:
    base_commit, start_commit, end_commit = get_series_range(start_commit, usebranch)
    gitargs = ['shortlog', f'{start_commit}..{end_commit}']
    ecode, shortlog = b4.git_run_command(None, gitargs)
    gitargs = ['diff', '--stat', f'{start_commit}..{end_commit}']
    ecode, diffstat = b4.git_run_command(None, gitargs)
    gitargs = ['log', '--oneline', f'{start_commit}..{end_commit}']
    ecode, oneline = b4.git_run_command(None, gitargs)
    oneline = oneline.rstrip().splitlines()
    return base_commit, start_commit, end_commit, oneline, shortlog.rstrip(), diffstat.rstrip()


def print_pretty_addrs(addrs: list, hdrname: str) -> None:
    if len(addrs) < 1:
        return
    logger.info('%s: %s', hdrname, b4.format_addrs([addrs[0]]))
    if len(addrs) > 1:
        for addr in addrs[1:]:
            logger.info('%s  %s', ' ' * len(hdrname), b4.format_addrs([addr]))


def get_base_changeid_from_tag(tagname: str) -> Tuple[str, str, str]:
    gitargs = ['cat-file', '-p', tagname]
    ecode, tagmsg = b4.git_run_command(None, gitargs)
    if ecode > 0:
        raise RuntimeError('No such tag: %s' % tagname)
    # junk the headers
    junk, cover = tagmsg.split('\n\n', maxsplit=1)
    # Check that we have base-commit: in the body
    matches = re.search(r'^base-commit:\s*(.*)$', cover, flags=re.I | re.M)
    if not matches:
        raise RuntimeError('Tag %s does not contain base-commit info' % tagname)
    base_commit = matches.groups()[0]
    matches = re.search(r'^change-id:\s*(.*)$', cover, flags=re.I | re.M)
    if not matches:
        raise RuntimeError('Tag %s does not contain change-id info' % tagname)
    change_id = matches.groups()[0]
    return cover, base_commit, change_id


def make_msgid_tpt(change_id: str, revision: str, domain: Optional[str] = None) -> str:
    if not domain:
        usercfg = b4.get_user_config()
        myemail = usercfg.get('email')
        if myemail:
            domain = re.sub(r'^[^@]*@', '', myemail)
        else:
            # Just use "b4" for the domain name (it doesn't need to be anything real)
            domain = 'b4'

    chunks = change_id.rsplit('-', maxsplit=1)
    stablepart = chunks[0]
    # Replace the change-id origin date with current date
    chunks = stablepart.split('-', maxsplit=1)
    if len(chunks) == 2 and len(chunks[0]) == 8:
        # If someone uses b4 in year 10000, look me up.
        stablepart = '%s-%s' % (datetime.date.today().strftime('%Y%m%d'), chunks[1])

    # Message-IDs must not be predictable to avoid stuffing attacks
    randompart = uuid.uuid4().hex[:12]
    msgid_tpt = f'<{stablepart}-v{revision}-%s-{randompart}@{domain}>'
    return msgid_tpt


def get_cover_dests(cbody: str) -> Tuple[List, List, str]:
    htrs, cmsg, mtrs, basement, sig = b4.LoreMessage.get_body_parts(cbody)
    tos = list()
    ccs = list()
    for mtr in list(mtrs):
        if mtr.lname == 'to':
            tos.append(mtr.addr)
            mtrs.remove(mtr)
        elif mtr.lname == 'cc':
            ccs.append(mtr.addr)
            mtrs.remove(mtr)
    cbody = b4.LoreMessage.rebuild_message(htrs, cmsg, mtrs, basement, sig)
    return tos, ccs, cbody


def add_cover(csubject: b4.LoreSubject, msgid_tpt: str, patches: List[Tuple[str, email.message.Message]],
              cbody: str, datets: int, thread: bool = True):
    fp = patches[0][1]
    cmsg = email.message.EmailMessage()
    cmsg.add_header('From', fp['From'])
    fpls = b4.LoreSubject(fp['Subject'])

    csubject.expected = fpls.expected
    csubject.counter = 0
    csubject.revision = fpls.revision
    cmsg.add_header('Subject', csubject.get_rebuilt_subject(eprefixes=fpls.get_extra_prefixes()))
    cmsg.add_header('Date', email.utils.formatdate(datets, localtime=True))
    cmsg.add_header('Message-Id', msgid_tpt % str(0))

    cmsg.set_payload(cbody, charset='utf-8')
    cmsg.set_charset('utf-8')

    patches.insert(0, ('', cmsg))
    if thread:
        rethread(patches)


def mixin_cover(cbody: str, patches: List[Tuple[str, email.message.Message]]) -> None:
    msg = patches[0][1]
    pbody, pcharset = b4.LoreMessage.get_payload(msg)
    pheaders, pmessage, ptrailers, pbasement, psignature = b4.LoreMessage.get_body_parts(pbody)
    cheaders, cmessage, ctrailers, cbasement, csignature = b4.LoreMessage.get_body_parts(cbody)
    nbparts = list()
    nmessage = cmessage.rstrip('\r\n') + '\n'

    for ctr in list(ctrailers):
        # We hide any trailers already present in the patch itself,
        # or To:/Cc: trailers, which we parse elsewhere
        if ctr in ptrailers or ctr.lname in ('to', 'cc'):
            ctrailers.remove(ctr)
    if ctrailers:
        if nmessage:
            nmessage += '\n'
        for ctr in ctrailers:
            nmessage += ctr.as_string() + '\n'

    if len(nmessage.strip()):
        nbparts.append(nmessage)

    # Find the section with changelogs
    utility = None
    for section in re.split(r'^---\n', cbasement, flags=re.M):
        if re.search(b4.DIFFSTAT_RE, section):
            # Skip this section
            continue
        if re.search(r'^change-id: ', section, flags=re.I | re.M):
            # We move this to the bottom
            utility = section
            continue
        nbparts.append(section.strip('\r\n') + '\n')

    nbparts.append(pbasement.rstrip('\r\n') + '\n\n')
    if utility:
        nbparts.append(utility)

    newbasement = '---\n'.join(nbparts)

    pbody = b4.LoreMessage.rebuild_message(pheaders, pmessage, ptrailers, newbasement, csignature)
    msg.set_payload(pbody, charset='utf-8')
    # Check if the new body now has 8bit content and fix CTR
    if msg.get('Content-Transfer-Encoding') != '8bit' and not pbody.isascii():
        msg.replace_header('Content-Transfer-Encoding', '8bit')


def get_cover_subject_body(cover: str) -> Tuple[b4.LoreSubject, str]:
    clines = cover.splitlines()
    if len(clines) < 2 or len(clines[1].strip()) or not len(clines[0].strip()):
        csubject = '(no cover subject)'
        cbody = cover.strip()
    else:
        csubject = clines[0]
        cbody = '\n'.join(clines[2:]).strip()

    lsubject = b4.LoreSubject(csubject)
    return lsubject, cbody


def rethread(patches: List[Tuple[str, email.message.Message]]):
    refto = patches[0][1].get('message-id')
    for commit, msg in patches[1:]:
        msg.add_header('References', refto)
        msg.add_header('In-Reply-To', refto)


def get_mailfrom() -> Tuple[str, str]:
    sconfig = b4.get_sendemail_config()
    fromaddr = sconfig.get('from')
    if fromaddr:
        return email.utils.parseaddr(fromaddr)

    usercfg = b4.get_user_config()
    return usercfg.get('name'), usercfg.get('email')


def get_prep_branch_as_patches(movefrom: bool = True, thread: bool = True, addtracking: bool = True,
                               prefixes: Optional[List[str]] = None, usebranch: Optional[str] = None,
                               expandprereqs: bool = True,
                               ) -> Tuple[List, List, str, List[Tuple[str, email.message.Message]]]:
    cover, tracking = load_cover(strip_comments=True, usebranch=usebranch)

    if prefixes is None:
        prefixes = list()
    prefixes += tracking['series'].get('prefixes', list())
    start_commit = get_series_start()
    change_id = tracking['series'].get('change-id')
    revision = tracking['series'].get('revision')
    msgid_tpt = make_msgid_tpt(change_id, revision)
    seriests = int(time.time())

    mailfrom = None
    if movefrom:
        mailfrom = get_mailfrom()

    strategy = get_cover_strategy()
    ignore_commits = None
    if strategy in {'commit', 'tip-commit'}:
        cover_commit = find_cover_commit()
        if cover_commit:
            ignore_commits = {cover_commit}

    csubject, cbody = get_cover_subject_body(cover)
    for cprefix in csubject.get_extra_prefixes(exclude=prefixes):
        prefixes.append(cprefix)

    patches = b4.git_range_to_patches(None, start_commit, 'HEAD',
                                      revision=revision,
                                      prefixes=prefixes,
                                      msgid_tpt=msgid_tpt,
                                      seriests=seriests,
                                      mailfrom=mailfrom,
                                      ignore_commits=ignore_commits)

    base_commit, stc, endc, oneline, shortlog, diffstat = get_series_details(start_commit=start_commit)

    config = b4.get_main_config()
    cover_template = DEFAULT_COVER_TEMPLATE
    if config.get('prep-cover-template'):
        # Try to load this template instead
        try:
            cover_template = b4.read_template(config['prep-cover-template'])
        except FileNotFoundError:
            logger.critical('ERROR: prep-cover-template says to use %s, but it does not exist',
                            config['prep-cover-template'])
            sys.exit(2)
    prereqs = tracking['series'].get('prerequisites', list())
    prerequisites = ''
    seen_patch_ids = set()
    for prereq in prereqs:
        if prereq.startswith('patch-id:'):
            prerequisites += f'prerequisite-{prereq}\n'
            continue

        chunks = [x.strip() for x in prereq.split(':')]
        if prereq.startswith('base-commit:'):
            base_commit = b4.git_revparse_obj(chunks[1])
            if not base_commit:
                logger.warning('WARNING: unable to resolve prerequisite-base-commit %s', chunks[1])
                base_commit = chunks[1]
            else:
                logger.debug('Overriding base-commit with: %s', base_commit)
            continue

        spatches = list()
        if prereq.startswith('message-id'):
            prerequisites += f'prerequisite-{prereq}\n'
            if expandprereqs:
                msgid = chunks[1].strip('<>')
                lmbx = b4.get_series_by_msgid(msgid)
                if not lmbx:
                    logger.info('Nothing known about message-id: %s', msgid)
                    logger.info('Consider running --check-deps')
                    continue
                wantver = max(lmbx.series.keys())
                for lmsg in lmbx.series[wantver].patches:
                    if not lmsg:
                        continue
                    spatches.append(lmsg.get_am_message(add_trailers=False))

        if prereq.startswith('change-id:'):
            prerequisites += f'prerequisite-{prereq}\n'
            pcid = None
            if len(chunks) > 1:
                pcid = chunks[1]
            pver = chunks[-1]
            if expandprereqs and pcid and pver:
                tagname, revision = get_sent_tagname(pcid, SENT_TAG_PREFIX, pver)
                logger.debug('Checking if we have a sent version')
                try:
                    todests, ccdests, ppatches = get_sent_tag_as_patches(tagname, revision=revision)
                    for psha, ppatch in ppatches:
                        spatches.append(ppatch)
                except RuntimeError:
                    logger.debug('Nothing matched tagname=%s, checking remotely', tagname)
                    lmbx = b4.get_series_by_change_id(pcid)
                    if not lmbx:
                        logger.info('Nothing known about change-id: %s', pcid)
                        logger.info('Consider running --check-deps')
                        continue
                    matches = re.search(r'^v?(\d+)', pver)
                    if matches:
                        wantver = int(matches.groups()[0])
                    else:
                        wantver = max(lmbx.series.keys())
                    for lmsg in lmbx.series[wantver].patches:
                        if not lmsg:
                            continue
                        spatches.append(lmsg.get_am_message(add_trailers=False))

        for spatch in spatches:
            diff = spatch.as_string(policy=b4.emlpolicy)
            ppid = b4.LoreMessage.get_patch_id(diff)
            if ppid:
                if ppid in seen_patch_ids:
                    logger.debug('Already included patchid: %s', ppid)
                logger.debug('Adding prerequisite-patch-id %s from %s', ppid, prereq)
                prerequisites += f'prerequisite-patch-id: {ppid}\n'
                seen_patch_ids.add(ppid)

    # Put together the cover letter
    tptvals = {
        'cover': cbody,
        'shortlog': shortlog,
        'diffstat': diffstat,
        'change_id': change_id,
        'base_commit': base_commit,
        'prerequisites': prerequisites,
        'signature': b4.get_email_signature(),
    }
    if cover_template.find('${range_diff}') >= 0:
        if revision > 1:
            oldrev = revision - 1
            rangediff_template = DEFAULT_RANGEDIFF_TEMPLATE
            rd_tptvals = {
                'oldrev': oldrev,
            }
            range_diff = Template(rangediff_template.lstrip()).safe_substitute(rd_tptvals)
            range_diff += compare(oldrev, execvp=False)
            tptvals['range_diff'] = range_diff
        else:
            tptvals['range_diff'] = ""
    cover_letter = Template(cover_template.lstrip()).safe_substitute(tptvals)
    # Store tracking info in the header in a safe format, which should allow us to
    # fully restore our work from the already sent series.
    ztracking = gzip.compress(bytes(json.dumps(tracking), 'utf-8'))
    b64tracking = base64.b64encode(ztracking).decode()
    # A little trick for pretty wrapping
    wrapped = textwrap.wrap('X-B4-Tracking: v=1; b=' + b64tracking, subsequent_indent=' ', width=75)
    thdata = ''.join(wrapped).replace('X-B4-Tracking: ', '')

    alltos, allccs, cbody = get_cover_dests(cover_letter)
    if len(patches) == 1:
        mixin_cover(cbody, patches)
    else:
        add_cover(csubject, msgid_tpt, patches, cbody, seriests, thread=thread)

    if addtracking:
        patches[0][1].add_header('X-B4-Tracking', thdata)

    # Add X-Change-ID header
    patches[0][1].add_header('X-Change-ID', change_id)

    samethread = config.get('send-same-thread', '').lower() in {'yes', 'true', 'y'}
    if samethread and revision > 1:
        oldrev = revision - 1
        voldrev = f'v{oldrev}'
        try:
            oldmsgid = tracking['series']['history'][voldrev][-1]
            patches[0][1].add_header('In-Reply-To', f'<{oldmsgid}>')
            patches[0][1].add_header('References', f'<{oldmsgid}>')
        except (KeyError, IndexError):
            logger.debug('Could not find previous series msgid, skipping %s', voldrev)

    header = csubject.full_subject
    if prefixes:
        header = '[' + ', '.join(prefixes) + f'] {header}'
    tag_msg = f'{header}\n\n{cover_letter}'
    return alltos, allccs, tag_msg, patches


def get_sent_tag_as_patches(tagname: str, revision: int) -> Tuple[List, List, List[Tuple[str, email.message.Message]]]:
    cover, base_commit, change_id = get_base_changeid_from_tag(tagname)

    csubject, cbody = get_cover_subject_body(cover)
    cbody = cbody.strip() + '\n-- \n' + b4.get_email_signature()
    prefixes = ['RESEND'] + csubject.get_extra_prefixes(exclude=['RESEND'])
    msgid_tpt = make_msgid_tpt(change_id, str(revision))
    seriests = int(time.time())
    mailfrom = get_mailfrom()

    patches = b4.git_range_to_patches(None, base_commit, tagname,
                                      revision=revision,
                                      prefixes=prefixes,
                                      msgid_tpt=msgid_tpt,
                                      seriests=seriests,
                                      mailfrom=mailfrom)

    alltos, allccs, cbody = get_cover_dests(cbody)
    if len(patches) == 1:
        mixin_cover(cbody, patches)
    else:
        add_cover(csubject, msgid_tpt, patches, cbody, seriests)

    return alltos, allccs, patches


def format_patch(output_dir: str) -> None:
    try:
        tos, ccs, tstr, patches = get_prep_branch_as_patches(thread=False, movefrom=False, addtracking=False)
    except RuntimeError as ex:
        logger.critical('CRITICAL: Failed to convert range to patches: %s', ex)
        sys.exit(1)

    logger.info('Writing %s messages into %s', len(patches), output_dir)
    pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)
    for commit, msg in patches:
        if not msg:
            continue
        msg.policy = email.policy.EmailPolicy(utf8=True, cte_type='8bit')
        subject = msg.get('Subject', '')
        ls = b4.LoreSubject(subject)
        filen = '%s.patch' % ls.get_slug(sep='-')
        with open(os.path.join(output_dir, filen), 'wb') as fh:
            fh.write(msg.as_bytes(unixfrom=True, policy=b4.emlpolicy))
            logger.info('  %s', filen)


def get_check_cmds() -> Tuple[List[str], List[str]]:
    config = b4.get_main_config()
    ppcmds = list()
    scmds = list()
    if config.get('prep-perpatch-check-cmd'):
        ppcmds = config.get('prep-perpatch-check-cmd')
    else:
        # Use recommended checkpatch defaults if we find checkpatch
        topdir = b4.git_get_toplevel()
        if topdir:
            checkpatch = os.path.join(topdir, 'scripts', 'checkpatch.pl')
            if os.access(checkpatch, os.X_OK):
                ppcmds = [f'{checkpatch} -q --terse --no-summary --mailback --showfile']

    # TODO: support for a whole-series check command, (pytest, etc)
    return ppcmds, scmds


def check(cmdargs: argparse.Namespace) -> None:
    is_prep_branch(mustbe=True)
    ppcmds, scmds = get_check_cmds()

    if not ppcmds:
        logger.critical('Not able to find checkpatch and no custom command defined.')
        sys.exit(1)

    try:
        todests, ccdests, tag_msg, patches = get_prep_branch_as_patches(expandprereqs=False)
    except RuntimeError as ex:
        logger.critical('CRITICAL: Failed to convert range to patches: %s', ex)
        sys.exit(1)

    logger.info('Checking patches using:')
    local_check_cmds = list()
    for ppcmdstr in ppcmds:
        logger.info(f'  {ppcmdstr}')
        sp = shlex.shlex(ppcmdstr, posix=True)
        sp.whitespace_split = True
        local_check_cmds.append(list(sp))

    summary = {
        'success': 0,
        'warning': 0,
        'fail': 0,
    }
    logger.info('---')
    for commit, msg in patches:
        if not msg or not commit:
            continue
        report = list()
        for ppcmdargs in local_check_cmds:
            ckrep = b4.LoreMessage.run_local_check(ppcmdargs, commit, msg, nocache=cmdargs.nocache)
            if ckrep:
                report.extend(ckrep)

        lsubject = b4.LoreSubject(msg.get('Subject', ''))
        csubject = f'{commit[:12]}: {lsubject.subject}'
        worst = 'success'
        for flag, status in report:
            if flag == 'warning':
                worst = 'warning'
                continue
            if flag == 'fail':
                worst = 'fail'
                break
        if worst == 'success':
            logger.info('%s %s', b4.CI_FLAGS_FANCY['success'], csubject)
            summary['success'] += 1
            continue
        logger.info('%s %s', b4.CI_FLAGS_FANCY[worst], csubject)
        for flag, status in report:
            summary[flag] += 1
            logger.info('  %s %s', b4.CI_FLAGS_FANCY[flag], status)
    logger.info('---')
    logger.info('Success: %s, Warning: %s, Error: %s', summary['success'], summary['warning'], summary['fail'])
    store_preflight_check('check')


def cmd_send(cmdargs: argparse.Namespace) -> None:
    if cmdargs.auth_new:
        auth_new()
        return
    if cmdargs.auth_verify:
        auth_verify(cmdargs)
        return

    mybranch = b4.git_get_current_branch()

    config = b4.get_main_config()

    tag_msg = None
    cl_msgid = None
    cover, tracking = load_cover(strip_comments=True)
    if cmdargs.resend:
        if cmdargs.resend == 'latest':
            revstr = tracking['series']['revision'] - 1
        else:
            revstr = cmdargs.resend

        # Start with full change-id based tag name
        tagname, revision = get_sent_tagname(tracking['series']['change-id'], SENT_TAG_PREFIX, revstr)

        if revision is None:
            logger.critical('Could not figure out revision from %s', revstr)
            sys.exit(1)

        if not b4.git_revparse_tag(None, tagname):
            # Try initial branch-name only based version
            tagname, revision = get_sent_tagname(mybranch, SENT_TAG_PREFIX, revstr)

        try:
            todests, ccdests, patches = get_sent_tag_as_patches(tagname, revision=revision)
        except RuntimeError as ex:
            logger.critical('CRITICAL: Failed to convert tag to patches: %s', ex)
            sys.exit(1)

        logger.info('Converted the tag to %s messages', len(patches))

    else:
        status = b4.git_get_repo_status()
        if len(status):
            logger.critical('CRITICAL: Repository contains uncommitted changes.')
            logger.critical('          Stash or commit them first.')
            sys.exit(1)

        if cmdargs.preview_to:
            prefixes = ['PREVIEW']
        else:
            prefixes = None

        try:
            todests, ccdests, tag_msg, patches = get_prep_branch_as_patches(prefixes=prefixes)
        except RuntimeError as ex:
            logger.critical('CRITICAL: Failed to convert range to patches: %s', ex)
            sys.exit(1)

        logger.info('Converted the branch to %s messages', len(patches))

    usercfg = b4.get_user_config()
    myemail = usercfg.get('email')

    seen = set()
    excludes = set()
    pccs = dict()

    if cmdargs.preview_to or cmdargs.no_trailer_to_cc:
        todests = list()
        ccdests = list()
    else:
        seen.update([x[1] for x in todests])
        seen.update([x[1] for x in ccdests])
        # Go through the messages to make to/cc headers
        for commit, msg in patches:
            if not msg:
                continue
            body, charset = b4.LoreMessage.get_payload(msg)
            btrs, junk = b4.LoreMessage.find_trailers(body)
            for btr in btrs:
                if btr.type != 'person':
                    continue
                if btr.addr[1] in seen:
                    continue
                if commit:
                    if commit not in pccs:
                        pccs[commit] = list()
                    if btr.addr not in pccs[commit]:
                        pccs[commit].append(btr.addr)
                    continue
                seen.add(btr.addr[1])
                if btr.lname == 'to':
                    todests.append(btr.addr)
                    continue
                ccdests.append(btr.addr)

        excludes = b4.get_excluded_addrs()
        if cmdargs.not_me_too:
            excludes.add(myemail)

    tos = set()
    ccs = set()
    if cmdargs.preview_to:
        tos.update(cmdargs.preview_to)
    else:
        if cmdargs.to:
            tos.update(cmdargs.to)
        if config.get('send-series-to'):
            tos.add(config.get('send-series-to'))
        if cmdargs.cc:
            ccs.update(cmdargs.cc)
        if config.get('send-series-cc'):
            ccs.add(config.get('send-series-cc'))
    if ccs:
        for pair in utils.getaddresses(list(ccs)):
            if pair[1] in seen:
                continue
            seen.add(pair[1])
            ccdests.append(pair)
    if tos:
        for pair in utils.getaddresses(list(tos)):
            if pair[1] in seen:
                continue
            seen.add(pair[1])
            todests.append(pair)

    allto = list()
    allcc = list()
    alldests = set()

    if todests:
        allto = b4.cleanup_email_addrs(todests, excludes, None)
        alldests.update(set([x[1] for x in allto]))
    if ccdests:
        allcc = b4.cleanup_email_addrs(ccdests, excludes, None)
        alldests.update(set([x[1] for x in allcc]))

    if not len(allto):
        # Move all cc's into the To field if there's nothing in "To"
        allto = list(allcc)
        allcc = list()

    if cmdargs.output_dir:
        cmdargs.dryrun = True
        logger.info('Will write out messages into %s', cmdargs.output_dir)
        pathlib.Path(cmdargs.output_dir).mkdir(parents=True, exist_ok=True)

    sconfig = b4.get_sendemail_config()
    endpoint = None
    if not sconfig.get('smtpserver') or cmdargs.send_web:
        endpoint = config.get('send-endpoint-web', '')
        if not re.search(r'^https?://', endpoint):
            logger.debug('Endpoint does not start with https, ignoring: %s', endpoint)
            endpoint = None
        if not endpoint:
            # Use the default endpoint if we are in the kernel repo
            topdir = b4.git_get_toplevel()
            if os.path.exists(os.path.join(topdir, 'Kconfig')):
                logger.debug('No sendemail configs found, will use the default web endpoint')
                endpoint = DEFAULT_ENDPOINT

    # Cannot currently use endpoint with --preview-to
    if endpoint and cmdargs.preview_to:
        logger.critical('CRITICAL: cannot use the web endpoint with --preview-to')
        sys.exit(1)

    # Give the user the last opportunity to bail out
    if not cmdargs.dryrun:
        if not len(alldests):
            logger.critical('CRITICAL: Could not find any destination addresses')
            logger.critical('          try b4 prep --auto-to-cc or b4 send --to addr')
            sys.exit(1)

        if not cmdargs.resend:
            logger.debug('Running pre-flight checks')
            sinfo = get_info(usebranch=mybranch)
            pfchecks = {'needs-editing': True,
                        'needs-checking': True,
                        'needs-checking-deps': True,
                        'needs-auto-to-cc': True,
                        }
            cfg_checks = config.get('prep-pre-flight-checks', 'enable-all')
            if 'disable-all' in cfg_checks:
                logger.debug('Disabling all preflight checks')
                pfchecks = dict()
            else:
                for pfcheck in list(pfchecks.keys()):
                    if f'disable-{pfcheck}' in cfg_checks:
                        logger.debug('Disabling pre-flight check %s', pfcheck)
                        del pfchecks[pfcheck]
            failing = False
            for pfcheck in pfchecks.keys():
                pfchecks[pfcheck] = sinfo[pfcheck]
                if sinfo[pfcheck] and not failing:
                    failing = True
            if failing:
                logger.critical('---')
                logger.critical('Some pre-flight checks are failing:')
                for pfcheck, pffailing in pfchecks.items():
                    if not pffailing:
                        continue
                    if pfcheck == 'needs-editing':
                        logger.critical('  - Edit the cover   : b4 prep --edit-cover')
                    elif pfcheck == 'needs-checking':
                        logger.critical('  - Run local checks : b4 prep --check')
                    elif pfcheck == 'needs-checking-deps':
                        logger.critical('  - Run deps checks  : b4 prep --check-deps')
                    elif pfcheck == 'needs-auto-to-cc':
                        logger.critical('  - Run auto-to-cc   : b4 prep --auto-to-cc')
                try:
                    logger.critical('---')
                    input('Press Enter to ignore and send anyway or Ctrl-C to abort and fix')
                except KeyboardInterrupt:
                    logger.info('')
                    sys.exit(130)

        logger.info('---')
        print_pretty_addrs(allto, 'To')
        print_pretty_addrs(allcc, 'Cc')
        logger.info('---')
        for commit, msg in patches:
            if not msg:
                continue
            logger.info('  %s', re.sub(r'\s+', ' ', b4.LoreMessage.clean_header(msg.get('Subject'))))
            if commit in pccs:
                extracc = list()
                for pair in pccs[commit]:
                    if pair[1] not in seen:
                        extracc.append(pair)
                if extracc:
                    print_pretty_addrs(extracc, '    +Cc')

        logger.info('---')
        usercfg = b4.get_user_config()
        fromaddr = usercfg['email']
        logger.info('Ready to:')
        if endpoint:
            if cmdargs.reflect:
                logger.info('  - send the above messages to just %s (REFLECT MODE)', fromaddr)
            else:
                logger.info('  - send the above messages to actual recipients')
            logger.info('  - via web endpoint: %s', endpoint)
        else:
            if sconfig.get('from'):
                fromaddr = sconfig.get('from')
            if cmdargs.reflect:
                logger.info('  - send the above messages to just %s (REFLECT MODE)', fromaddr)
            elif cmdargs.preview_to:
                logger.info('  - send the above messages to the recipients listed (PREVIEW MODE)')
            else:
                logger.info('  - send the above messages to actual listed recipients')
            logger.info('  - with envelope-from: %s', fromaddr)

            smtpserver = sconfig.get('smtpserver', 'localhost')
            if '/' in smtpserver:
                logger.info('  - via local command %s', smtpserver)
                if cmdargs.reflect and sconfig.get('b4-really-reflect-via') != smtpserver:
                    logger.critical('---')
                    logger.critical('CRITICAL: Cowardly refusing to reflect via %s.', smtpserver)
                    logger.critical('          There is no guarantee that this command will do the right thing')
                    logger.critical('          and will not send mail to actual addressees.')
                    logger.critical('---')
                    logger.critical('If you are ABSOLUTELY SURE that this command will do the right thing,')
                    logger.critical('add the following to the [sendemail] section:')
                    logger.critical('b4-really-reflect-via = %s', smtpserver)
                    sys.exit(1)

            else:
                logger.info('  - via SMTP server %s', smtpserver)

        if not (cmdargs.reflect or cmdargs.resend or cmdargs.preview_to):
            logger.info('  - tag and reroll the series to the next revision')
        logger.info('')
        if cmdargs.reflect:
            logger.info('REFLECT MODE:')
            logger.info('    The To: and Cc: headers will be fully populated, but the only')
            logger.info('    address given to the mail server for actual delivery will be')
            logger.info('    %s', fromaddr)
            logger.info('')
            logger.info('    Addresses in To: and Cc: headers will NOT receive this series.')
            logger.info('')
        try:
            input('Press Enter to proceed or Ctrl-C to abort')
        except KeyboardInterrupt:
            logger.info('')
            sys.exit(130)

    # And now we go through each message to set addressees and send them off
    sign = True
    if cmdargs.no_sign or config.get('send-no-patatt-sign', '').lower() in {'yes', 'true', 'y'}:
        sign = False

    send_msgs = list()
    for commit, msg in patches:
        if not msg:
            continue
        if not cl_msgid:
            cl_msgid = b4.LoreMessage.get_clean_msgid(msg)

        myto = list(allto)
        mycc = list(allcc)
        if msg['To']:
            myto += email.utils.getaddresses([msg['To']])
        if msg['Cc']:
            mycc += email.utils.getaddresses([msg['Cc']])

        # extend the global cc's with per-patch cc's, if any
        if commit and commit in pccs:
            # Remove any addresses already in seen
            for pair in pccs[commit]:
                if pair[1] not in seen:
                    mycc.append(pair)
        elif not commit and len(pccs):
            # the cover letter gets sent to folks with individual patch cc's
            _seen = set(seen)
            for _commit, _ccs in pccs.items():
                for pair in _ccs:
                    if pair[1] not in _seen:
                        mycc.append(pair)
                        _seen.add(pair[1])
        if mycc and not myto:
            # Move all Cc's into To when there's no To:
            myto = mycc
            mycc = list()
        if myto:
            pto = b4.cleanup_email_addrs(myto, excludes, None)
            if msg['To']:
                msg.replace_header('To', b4.format_addrs(pto))
            else:
                msg.add_header('To', b4.format_addrs(pto))
        if mycc:
            pcc = b4.cleanup_email_addrs(mycc, excludes, None)
            if msg['Cc']:
                msg.replace_header('Cc', b4.format_addrs(pcc))
            else:
                msg.add_header('Cc', b4.format_addrs(pcc))

        send_msgs.append(msg)

    if endpoint:
        # Web endpoint always requires signing
        if not sign:
            logger.critical('CRITICAL: Web endpoint will be used for sending, but signing is turned off')
            logger.critical('          Please re-enable signing or use SMTP')
            sys.exit(1)

        try:
            sent = b4.send_mail(None, send_msgs, fromaddr=None, patatt_sign=True,
                                dryrun=cmdargs.dryrun, output_dir=cmdargs.output_dir, web_endpoint=endpoint,
                                reflect=cmdargs.reflect)
        except RuntimeError as ex:
            logger.critical('CRITICAL: %s', ex)
            sys.exit(1)
    else:
        try:
            smtp, fromaddr = b4.get_smtp(dryrun=cmdargs.dryrun)
        except Exception as ex:  # noqa
            logger.critical('Failed to configure the smtp connection:')
            logger.critical(ex)
            sys.exit(1)

        try:
            sent = b4.send_mail(smtp, send_msgs, fromaddr=fromaddr, patatt_sign=sign,
                                dryrun=cmdargs.dryrun, output_dir=cmdargs.output_dir,
                                reflect=cmdargs.reflect)
        except RuntimeError as ex:
            logger.critical('CRITICAL: %s', ex)
            sys.exit(1)

    logger.info('---')
    if cmdargs.dryrun:
        logger.info('DRYRUN: Would have sent %s messages', len(send_msgs))
        return
    if not sent:
        logger.critical('CRITICAL: Was not able to send messages.')
        sys.exit(1)

    if cmdargs.reflect:
        logger.info('Reflected %s messages', sent)
        logger.debug('Not updating cover/tracking on reflect')
        return

    logger.info('Sent %s messages', sent)

    if cmdargs.resend:
        logger.debug('Not updating cover/tracking on resend')
        return
    if cmdargs.preview_to:
        logger.debug('Not updating cover/tracking on --preview-to')
        return

    reroll(mybranch, tag_msg, cl_msgid)


def get_sent_tagname(tagbase: str, tagprefix: str, revstr: Union[str, int]) -> Tuple[str, Optional[int]]:
    revision = None
    try:
        revision = int(revstr)
    except ValueError:
        matches = re.search(r'^v(\d+)$', revstr)
        if not matches:
            # assume we got a full tag name, so try to find the revision there
            matches = re.search(r'v(\d+)$', revstr)
            if matches:
                revision = int(matches.groups()[0])
            return revstr.replace('refs/tags/', ''), revision
        revision = int(matches.groups()[0])

    if tagbase.startswith('b4/'):
        return f'{tagprefix}{tagbase[3:]}-v{revision}', revision
    return f'{tagprefix}{tagbase}-v{revision}', revision


def reroll(mybranch: str, tag_msg: str, msgid: str, tagprefix: str = SENT_TAG_PREFIX):
    # Remove signature
    chunks = tag_msg.rsplit('\n-- \n')
    if len(chunks) > 1:
        tag_msg = chunks[0] + '\n'

    cover, tracking = load_cover(strip_comments=True)
    revision = tracking['series']['revision']
    change_id = tracking['series']['change-id']

    tagname, revision = get_sent_tagname(change_id, tagprefix, revision)
    logger.debug('checking if we already have %s', tagname)
    topdir = b4.git_get_toplevel()
    if not b4.git_revparse_tag(None, tagname):
        strategy = get_cover_strategy()
        tagcommit = 'HEAD'
        try:
            if strategy == 'commit':
                base_commit, start_commit, end_commit = get_series_range(usebranch=mybranch)
                with b4.git_temp_worktree(topdir, base_commit) as gwt:
                    logger.debug('Preparing a sparse worktree')
                    ecode, out = b4.git_run_command(gwt, ['sparse-checkout', 'init'], logstderr=True)
                    if ecode > 0:
                        logger.critical('Error running sparse-checkout init')
                        logger.critical(out)
                        raise RuntimeError
                    ecode, out = b4.git_run_command(gwt, ['checkout'], logstderr=True)
                    if ecode > 0:
                        logger.critical('Error running checkout into sparse workdir')
                        logger.critical(out)
                        raise RuntimeError
                    gitargs = ['cherry-pick', f'{start_commit}..{end_commit}']
                    ecode, out = b4.git_run_command(gwt, gitargs, logstderr=True)
                    if ecode > 0:
                        # In theory, this shouldn't happen
                        logger.critical('Unable to cleanly apply series, see failure log below')
                        logger.critical('---')
                        logger.critical(out.strip())
                        logger.critical('---')
                        logger.critical('Not fetching into FETCH_HEAD')
                        raise RuntimeError
                    gitargs = ['rev-parse', 'HEAD']
                    ecode, out = b4.git_run_command(gwt, gitargs, logstderr=True)
                    if ecode > 0:
                        logger.critical('Unable to resolve FETCH_HEAD')
                        logger.critical(out.strip())
                        raise RuntimeError
                    tagcommit = out.strip()
                    gitargs = ['fetch', gwt]
                    ecode, out = b4.git_run_command(topdir, gitargs, logstderr=True)
                    if ecode > 0:
                        logger.critical('Unable to fetch from the worktree')
                        logger.critical(out.strip())
                        raise RuntimeError
            elif strategy == 'tip-commit':
                cover_commit = find_cover_commit()
                tagcommit = f'{cover_commit}~1'

            logger.info('Tagging %s', tagname)
            gitargs = ['tag', '-a', '-F', '-', tagname, tagcommit]
            ecode, out = b4.git_run_command(topdir, gitargs, stdin=tag_msg.encode())
            if ecode > 0:
                # Not a fatal error, complain about it and move on
                logger.info('Could not tag %s as %s:', tagcommit, tagname)
                logger.info(out)

        except RuntimeError as ex:
            logger.critical('Error tagging the revision: %s', ex)

    else:
        logger.info('NOTE: Tagname %s already exists', tagname)

    logger.info('Recording series message-id in cover letter tracking')
    cover, tracking = load_cover(strip_comments=False)
    vrev = f'v{revision}'
    if 'history' not in tracking['series']:
        tracking['series']['history'] = dict()
    if vrev not in tracking['series']['history']:
        tracking['series']['history'][vrev] = list()
    tracking['series']['history'][vrev].append(msgid)

    oldrev = tracking['series']['revision']
    newrev = oldrev + 1
    tracking['series']['revision'] = newrev
    sections = cover.split('---\n')
    vrev = f'v{oldrev}'
    if 'history' in tracking['series'] and vrev in tracking['series']['history']:
        # Use the latest link we have
        config = b4.get_main_config()
        oldrev_link = config.get('linkmask') % tracking['series']['history'][vrev][-1]
    else:
        oldrev_link = 'EDITME (not found in tracking)'
    tptvals = {
        'oldrev': oldrev,
        'newrev': newrev,
        'oldrev_link': oldrev_link,
    }
    prepend = Template(DEFAULT_CHANGELOG_TEMPLATE.lstrip()).safe_substitute(tptvals)
    found = False
    new_sections = list()
    for section in sections:
        if re.search(r'^changes in v\d+', section, flags=re.I | re.M):
            # This is our section
            new_sections.append(prepend + section)
            found = True
        else:
            new_sections.append(section)
    if found:
        new_cover = '---\n'.join(new_sections)
    else:
        new_cover = cover + '\n\n---\n' + prepend

    logger.info('Created new revision v%s', newrev)
    logger.info('Updating cover letter with templated changelog entries.')
    store_cover(new_cover, tracking)


def check_can_gfr() -> None:
    if not can_gfr:
        logger.critical('ERROR: b4 submit requires git-filter-repo. You should be able')
        logger.critical('       to install it from your distro packages, or from pip.')
        sys.exit(1)


def show_revision() -> None:
    is_prep_branch(mustbe=True)
    cover, tracking = load_cover()
    ts = tracking['series']
    logger.info('v%s', ts.get('revision'))
    if 'history' in ts:
        config = b4.get_main_config()
        logger.info('---')
        for rn, links in ts['history'].items():
            for link in links:
                logger.info('  %s: %s', rn, config['linkmask'] % link)


def write_to_tar(bio_tar: tarfile.TarFile, name, mtime, bio_file: io.BytesIO):
    tifo = tarfile.TarInfo(name)
    tuser = os.environ.get('USERNAME', 'user')
    tuid = os.getuid()
    tgid = os.getgid()
    tifo.uid = tuid
    tifo.gid = tgid
    tifo.uname = tuser
    tifo.gname = tuser
    tifo.mtime = mtime
    tifo.size = bio_file.tell()
    bio_file.seek(0)
    bio_tar.addfile(tifo, bio_file)


def get_prep_managed_branches(gitdir: Optional[str] = None) -> List[str]:
    lines = b4.git_get_command_lines(gitdir, ['show-ref', '--heads'])
    mybranches = list()
    if not lines:
        logger.debug('Git show-ref returned no heads')
        return mybranches
    for line in lines:
        parts = line.split(maxsplit=1)
        if parts[1].startswith('refs/heads/b4/'):
            mybranches.append(parts[1].replace('refs/heads/', ''))
    return mybranches


def cleanup(param: str) -> None:
    if param == '_show':
        # Show all b4-tracked branches
        mybranches = get_prep_managed_branches(None)
        if not len(mybranches):
            logger.info('No b4-tracked branches found')
            sys.exit(0)

        logger.info('Please specify branch:')
        for branch in mybranches:
            logger.info(' %s', branch)
        return

    mybranch = param
    if not b4.git_branch_exists(None, mybranch):
        logger.critical('Not a known branch: %s', mybranch)
        sys.exit(1)
    is_prep_branch(mustbe=True, usebranch=mybranch)
    base_commit, start_commit, end_commit = get_series_range(usebranch=mybranch)
    # start commit and end commit can't be the same
    if start_commit == end_commit:
        logger.critical('CRITICAL: %s appears to be an empty branch', mybranch)
        sys.exit(1)
    # Refuse to clean up the currently checked out branch
    curbranch = b4.git_get_current_branch()
    if curbranch == mybranch:
        logger.critical('CRITICAL: %s is currently checked out, cannot cleanup', mybranch)
        sys.exit(1)
    cover, tracking = load_cover(usebranch=mybranch)
    # Find all tags
    ts = tracking['series']
    tags = list()
    logger.info('Will archive and delete all of the following:')
    logger.info('---')
    logger.info('branch: %s', mybranch)
    if 'history' in ts:
        for rn, links in ts['history'].items():
            tagname, revision = get_sent_tagname(ts.get('change-id'), SENT_TAG_PREFIX, rn)
            tag_commit = b4.git_revparse_tag(None, tagname)
            if not tag_commit:
                tagname, revision = get_sent_tagname(mybranch, SENT_TAG_PREFIX, rn)
                tag_commit = b4.git_revparse_tag(None, tagname)
            if not tag_commit:
                logger.debug('No tag matching revision %s', revision)
                continue
            try:
                cover, base_commit, change_id = get_base_changeid_from_tag(tagname)
            except RuntimeError as ex:
                logger.debug('Could not get base-commit info from %s: %s', tagname, ex)
                continue

            logger.info(' tag: %s', tagname)
            tags.append((tagname, base_commit, tag_commit, revision, cover))
    logger.info('---')
    try:
        input('Press Enter to confirm or Ctrl-C to abort')
    except KeyboardInterrupt:
        logger.info('')
        sys.exit(130)

    tio = io.BytesIO()
    change_id = ts.get('change-id')
    deletes = list()

    with tarfile.open(fileobj=tio, mode='w:gz') as tfh:
        mnow = int(time.time())
        # Add cover
        ifh = io.BytesIO()
        ifh.write(cover.encode())
        write_to_tar(tfh, f'{change_id}/cover.txt', mnow, ifh)
        ifh.close()
        # Add tracking
        ifh = io.BytesIO()
        ifh.write(make_magic_json(tracking).encode())
        write_to_tar(tfh, f'{change_id}/tracking.js', mnow, ifh)
        ifh.close()
        # Add the current series
        logger.info('Archiving branch %s', mybranch)
        patches = b4.git_range_to_patches(None, start_commit, end_commit)
        ifh = io.BytesIO()
        b4.save_git_am_mbox([patch[1] for patch in patches], ifh)
        write_to_tar(tfh, f'{change_id}/patches.mbx', mnow, ifh)
        ifh.close()
        deletes.append(['branch', '--delete', '--force', mybranch])

        for tagname, base_commit, tag_commit, revision, cover in tags:
            logger.info('Archiving %s', tagname)
            # use tag date as mtime
            lines = b4.git_get_command_lines(None, ['log', '-1', '--format=%ct', tagname])
            if not lines:
                logger.critical('Could not get tag date for %s', tagname)
                sys.exit(1)
            mtime = int(lines[0])
            ifh = io.BytesIO()
            ifh.write(cover.encode())
            write_to_tar(tfh, f'{change_id}/{SENT_TAG_PREFIX}patches-v{revision}.cover', mtime, ifh)
            ifh.close()
            patches = b4.git_range_to_patches(None, base_commit, tag_commit)
            ifh = io.BytesIO()
            b4.save_git_am_mbox([patch[1] for patch in patches], ifh)
            write_to_tar(tfh, f'{change_id}/{SENT_TAG_PREFIX}patches-v{revision}.mbx', mtime, ifh)
            deletes.append(['tag', '--delete', tagname])

    # Write in data_dir
    datadir = b4.get_data_dir()
    archpath = os.path.join(datadir, 'prep-archived')
    pathlib.Path(archpath).mkdir(parents=True, exist_ok=True)
    tarpath = os.path.join(archpath, f'{change_id}.tar.gz')
    logger.info('Writing %s', tarpath)
    with open(tarpath, mode='wb') as tout:
        tout.write(tio.getvalue())
    logger.info('Cleaning up git refs')
    for gitargs in deletes:
        b4.git_run_command(None, gitargs)
    logger.info('---')
    logger.info('Wrote: %s', tarpath)


def show_info(param: str) -> None:
    # is param a name of the branch?
    if ':' in param:
        chunks = param.split(':')
        if len(chunks[0]):
            if b4.git_branch_exists(None, chunks[0]):
                mybranch = chunks[0]
            elif b4.git_branch_exists(None, f'b4/{chunks[0]}'):
                mybranch = f'b4/{chunks[0]}'
            else:
                logger.critical('No such branch: %s', chunks[0])
                sys.exit(1)
        else:
            mybranch = b4.git_get_current_branch()
        if not len(chunks[1]):
            getval = '_all'
        else:
            getval = chunks[1]
    elif b4.git_branch_exists(None, param):
        mybranch = param
        getval = '_all'
    else:
        mybranch = b4.git_get_current_branch()
        getval = param

    prep_info = get_info(usebranch=mybranch)
    if getval == '_all':
        for key, val in prep_info.items():
            if val is not None:
                print('%s: %s' % (key, val))
    elif getval in prep_info:
        print(prep_info[getval])
    else:
        logger.critical('No info about %s', getval)
        sys.exit(1)


def get_info(usebranch: str) -> Dict[str, str]:
    is_prep_branch(mustbe=True, usebranch=usebranch)
    cover, tracking = load_cover(usebranch=usebranch)
    csubject, cbody = get_cover_subject_body(cover)
    ts = tracking['series']
    base_commit, start_commit, end_commit, oneline, shortlog, diffstat = get_series_details(usebranch=usebranch)
    todests, ccdests, tag_msg, patches = get_prep_branch_as_patches(usebranch=usebranch, expandprereqs=False)
    prereqs = tracking['series'].get('prerequisites', list())
    tocmd, cccmd = get_auto_to_cc_cmds()
    ppcmds, scmds = get_check_cmds()
    pf_checks = get_preflight_checks(usebranch=usebranch)

    info = {
        # General information about this branch
        'branch': usebranch,
        'cover-subject': csubject.full_subject,
        'base-branch': ts.get('base-branch'),
        'base-commit': base_commit,
        'start-commit': start_commit,
        'end-commit': end_commit,
        'series-range': f'{start_commit}..{end_commit}',

        # General information about this branch status
        'prefixes': ' '.join(ts.get('prefixes', [])) or None,
        'change-id': ts.get('change-id'),
        'revision': ts.get('revision'),
        'cover-strategy': get_cover_strategy(usebranch=usebranch),

        # General information about this branch checks
        'needs-editing': b'EDITME' in b4.LoreMessage.get_msg_as_bytes(patches[0][1]),
        'needs-recipients': bool(not todests and not ccdests),
        'has-prerequisites': len(prereqs) > 0,
        'needs-auto-to-cc': None,
        'needs-checking': bool(ppcmds or scmds) and 'check' not in pf_checks,
        'needs-checking-deps': len(prereqs) > 0 and 'check-deps' not in pf_checks,
        'preflight-checks-failing': None,
    }
    info['needs-auto-to-cc'] = info["needs-recipients"] or (bool(tocmd or cccmd) and 'auto-to-cc' not in pf_checks)
    info['preflight-checks-failing'] = bool(info['needs-editing'] or info['needs-auto-to-cc'] or
                                            info['needs-checking'] or info['needs-checking-deps'])

    # Add informations about the commits in this series
    #   `commit-<hash>`: stores the subject of each commit
    #   `series-<rev>`: stores the commit range for a particular revision
    for line in oneline:
        short, subject = line.split(maxsplit=1)
        info[f'commit-{short}'] = subject
    if 'history' in ts:
        for rn, links in reversed(ts['history'].items()):
            tagname, revision = get_sent_tagname(ts.get('change-id'), SENT_TAG_PREFIX, rn)
            tag_commit = b4.git_revparse_tag(None, tagname)
            if not tag_commit:
                logger.debug('No tag %s, trying with base branch name %s', tagname, usebranch)
                tagname, revision = get_sent_tagname(usebranch, SENT_TAG_PREFIX, rn)
                tag_commit = b4.git_revparse_tag(None, tagname)
            if not tag_commit:
                logger.debug('No tag matching revision %s', revision)
                continue
            try:
                cover, base_commit, change_id = get_base_changeid_from_tag(tagname)
                info[f'series-{rn}'] = '%s..%s %s' % (base_commit[:12], tag_commit[:12], links[0])
            except RuntimeError as ex:
                logger.debug('Could not get base-commit info from %s: %s', tagname, ex)
    return info


def force_revision(forceto: int) -> None:
    cover, tracking = load_cover()
    tracking['series']['revision'] = forceto
    logger.info('Forced revision to v%s', forceto)
    store_cover(cover, tracking)


def compare(compareto: str, execvp: bool = True) -> Union[str, None]:
    cover, tracking = load_cover()
    # Try the new format first
    tagname, revision = get_sent_tagname(tracking['series']['change-id'], SENT_TAG_PREFIX, compareto)
    prev_end = b4.git_revparse_tag(None, tagname)
    if not prev_end:
        mybranch = b4.git_get_current_branch(None)
        tagname, revision = get_sent_tagname(mybranch, SENT_TAG_PREFIX, compareto)
        prev_end = b4.git_revparse_tag(None, tagname)
    if not prev_end:
        logger.critical('CRITICAL: Could not rev-parse %s', tagname)
        sys.exit(1)
    try:
        cover, base_commit, change_id = get_base_changeid_from_tag(tagname)
    except RuntimeError as ex:
        logger.critical('CRITICAL: %s', str(ex))
        sys.exit(1)
    prev_start = base_commit
    curr_start = get_series_start()
    strategy = get_cover_strategy()
    if strategy == 'tip-commit':
        cover_commit = find_cover_commit()
        series_end = f'{cover_commit}~1'
    else:
        series_end = 'HEAD'

    gitargs = ['rev-parse', series_end]
    lines = b4.git_get_command_lines(None, gitargs)
    curr_end = lines[0]
    grdcmd = ['git', 'range-diff', '%.12s..%.12s' % (prev_start, prev_end), '%.12s..%.12s' % (curr_start, curr_end)]
    logger.debug('Running %s', ' '.join(grdcmd))
    if execvp:
        # We exec range-diff and let it take over
        os.execvp(grdcmd[0], grdcmd)
    else:
        ecode, out = b4.git_run_command(None, grdcmd[1:])
        if ecode:
            logger.critical('CRITICAL: Could not execute range-diff')
            sys.exit(1)
        else:
            return out


def get_auto_to_cc_cmds() -> Tuple[List, List]:
    tocmdstr = None
    cccmdstr = None
    topdir = b4.git_get_toplevel()
    # Use recommended tocmd and cccmd defaults if we find a get_maintainer.pl
    getm = os.path.join(topdir, 'scripts', 'get_maintainer.pl')
    config = b4.get_main_config()
    if config.get('send-auto-to-cmd'):
        tocmdstr = config.get('send-auto-to-cmd')
    elif os.access(getm, os.X_OK):
        tocmdstr = f'{getm} --nogit --nogit-fallback --nogit-chief-penguins --norolestats --nol'
    if config.get('send-auto-cc-cmd'):
        cccmdstr = config.get('send-auto-cc-cmd')
    elif os.access(getm, os.X_OK):
        cccmdstr = f'{getm} --nogit --nogit-fallback --nogit-chief-penguins --norolestats --nom'

    tocmd = list()
    cccmd = list()
    if tocmdstr:
        sp = shlex.shlex(tocmdstr, posix=True)
        sp.whitespace_split = True
        tocmd = list(sp)
    if cccmdstr:
        sp = shlex.shlex(cccmdstr, posix=True)
        sp.whitespace_split = True
        cccmd = list(sp)

    return tocmd, cccmd


def auto_to_cc() -> None:
    config = b4.get_main_config()
    tocmd, cccmd = get_auto_to_cc_cmds()
    if tocmd:
        logger.info('Will collect To: addresses using %s', os.path.basename(tocmd[0]))
    if cccmd:
        logger.info('Will collect Cc: addresses using %s', os.path.basename(cccmd[0]))

    logger.debug('Getting addresses from cover letter')
    cover, tracking = load_cover(strip_comments=False)
    parts = b4.LoreMessage.get_body_parts(cover)
    seen = set()
    for ltr in parts[2]:
        if not ltr.addr:
            continue
        seen.add(ltr.addr[1])
        logger.debug('added %s to seen', ltr.addr[1])

    extras = list()
    for tname, addrs in (('To', config.get('send-series-to')), ('Cc', config.get('send-series-cc'))):
        if not addrs:
            continue
        for pair in utils.getaddresses([addrs]):
            if pair[1] in seen:
                continue
            seen.add(pair[1])
            ltr = b4.LoreTrailer(name=tname, value=b4.format_addrs([pair]))
            logger.debug('added %s to seen', ltr.addr[1])
            extras.append(ltr)

    try:
        tos, ccs, tag_msg, patches = get_prep_branch_as_patches()
    except RuntimeError:
        logger.info('No commits in branch')
        return

    logger.info('Collecting To/Cc addresses')
    # Go through the messages to make to/cc headers
    for commit, msg in patches:
        if not msg or not commit:
            continue

        logger.debug('Collecting from: %s', msg.get('subject'))
        msgbytes = msg.as_bytes()
        for tname, pairs in (('To', get_addresses_from_cmd(tocmd, msgbytes)),
                             ('Cc', get_addresses_from_cmd(cccmd, msgbytes))):
            for pair in pairs:
                if pair[1] not in seen:
                    seen.add(pair[1])
                    ltr = b4.LoreTrailer(name=tname, value=b4.format_addrs([pair]))
                    logger.debug('  => %s', ltr.as_string())
                    extras.append(ltr)

    if extras:
        # Make it a LoreMessage, so we can run a fix_trailers on it
        cmsg = email.message.EmailMessage()
        cmsg.set_payload(cover, charset='utf-8')
        clm = b4.LoreMessage(cmsg)
        fallback_order = config.get('send-trailer-order', 'To,Cc,*')
        clm.fix_trailers(extras=extras, fallback_order=fallback_order)
        logger.info('---')
        logger.info('You can trim/expand this list with: b4 prep --edit-cover')
        store_cover(clm.body, tracking)
    else:
        logger.info('No new addresses to add.')

    store_preflight_check('auto-to-cc')


def get_preflight_hash(usebranch: Optional[str] = None) -> str:
    global PFHASH_CACHE
    cachebranch = usebranch if usebranch is not None else '_current_'
    if cachebranch not in PFHASH_CACHE:
        tos, ccs, tstr, patches = get_prep_branch_as_patches(movefrom=False, thread=False, addtracking=False,
                                                             usebranch=usebranch, expandprereqs=False)
        hashed = hashlib.sha1()
        for commit, msg in patches:
            body, charset = b4.LoreMessage.get_payload(msg)
            patchid = b4.LoreMessage.get_patch_id(body)
            hashed.update(f'{patchid}\n'.encode('utf-8'))

        PFHASH_CACHE[cachebranch] = hashed.hexdigest()

    return PFHASH_CACHE[cachebranch]


def get_preflight_checks(usebranch: Optional[str] = None) -> Dict[str, str]:
    pfhash = get_preflight_hash(usebranch=usebranch)
    cacheid = f'{pfhash}-pre-flight-checks'
    pf_checks = b4.get_cache(cacheid, suffix='checks', as_json=True)
    if pf_checks is None:
        pf_checks = dict()
    return pf_checks


def store_preflight_check(identity: str) -> None:
    pf_checks = get_preflight_checks()
    pf_checks[identity] = datetime.date.today().isoformat()
    pfhash = get_preflight_hash()
    cacheid = f'{pfhash}-pre-flight-checks'
    b4.save_cache(pf_checks, cacheid, suffix='checks', is_json=True)


def set_prefixes(prefixes: list, additive: bool = False) -> None:
    cover, tracking = load_cover()
    old_prefixes = tracking['series'].get('prefixes', list())
    if len(prefixes) == 1 and not prefixes[0].strip():
        prefixes = list()
    if additive:
        new_prefixes = list(old_prefixes)
        for prefix in prefixes:
            if prefix.lower() not in [x.lower() for x in new_prefixes]:
                new_prefixes.append(prefix)
        tracking['series']['prefixes'] = new_prefixes
    else:
        new_prefixes = list(prefixes)

    tracking['series']['prefixes'] = new_prefixes
    if tracking['series']['prefixes'] != old_prefixes:
        store_cover(cover, tracking)
        if tracking['series']['prefixes']:
            logger.info('Updated extra prefixes to: %s', ' '.join(new_prefixes))
        else:
            logger.info('Removed all extra prefixes.')
    else:
        logger.info('No changes to extra prefixes.')


def cmd_prep(cmdargs: argparse.Namespace) -> None:
    check_can_gfr()
    status = b4.git_get_repo_status()
    if len(status):
        logger.critical('CRITICAL: Repository contains uncommitted changes.')
        logger.critical('          Stash or commit them first.')
        sys.exit(1)

    if cmdargs.reroll:
        msgid = cmdargs.reroll
        msgs = b4.get_pi_thread_by_msgid(msgid, onlymsgids={msgid}, nocache=True)
        mybranch = b4.git_get_current_branch(None)
        if msgs:
            for msg in msgs:
                if b4.LoreMessage.get_clean_msgid(msg) == msgid:
                    # Prepare annotated tag body from the cover letter
                    lsubject = b4.LoreSubject(msg.get('subject'))
                    cbody, charset = b4.LoreMessage.get_payload(msg)
                    prefixes = lsubject.get_extra_prefixes()
                    if prefixes:
                        subject = '[%s] %s' % (' '.join(prefixes), lsubject.subject)
                    else:
                        subject = lsubject.subject
                    tag_msg = subject + '\n\n' + cbody
                    return reroll(mybranch, tag_msg, msgid)
        logger.critical('CRITICAL: could not retrieve %s', msgid)
        sys.exit(1)

    if cmdargs.show_revision:
        return show_revision()

    if cmdargs.show_info:
        return show_info(cmdargs.show_info)

    if cmdargs.cleanup:
        return cleanup(cmdargs.cleanup)

    if cmdargs.format_patch:
        return format_patch(cmdargs.format_patch)

    if cmdargs.compare_to:
        return compare(cmdargs.compare_to)

    if cmdargs.enroll_base and cmdargs.new_series_name:
        logger.critical('CRITICAL: -n NEW_SERIES_NAME and -e [ENROLL_BASE] can not be used together.')
        sys.exit(1)

    if cmdargs.enroll_base or cmdargs.new_series_name:
        if is_prep_branch() and not cmdargs.fork_point:
            # We only support this with the commit strategy
            strategy = get_cover_strategy()
            if strategy != 'commit':
                logger.critical('CRITICAL: This appears to already be a b4-prep managed branch.')
                logger.critical('          Chaining series is only supported with the "commit" strategy.')
                logger.critical('          Switch to a different branch or use the -f flag to continue.')
                sys.exit(1)

            logger.critical('IMPORTANT: This appears to already be a b4-prep managed branch.')
            logger.critical('           The new branch will be marked as depending on this series.')
            logger.critical('           Alternatively, switch to a different branch or use the -f flag.')
            try:
                input('Press Enter to confirm or Ctrl-C to abort')
                logger.info('---')
            except KeyboardInterrupt:
                logger.info('')
                sys.exit(130)

        start_new_series(cmdargs)

    if cmdargs.force_revision:
        force_revision(cmdargs.force_revision)

    if cmdargs.set_prefixes:
        set_prefixes(cmdargs.set_prefixes)

    if cmdargs.add_prefixes:
        set_prefixes(cmdargs.add_prefixes, additive=True)

    if cmdargs.auto_to_cc:
        auto_to_cc()

    if cmdargs.edit_cover:
        return edit_cover()

    if cmdargs.edit_deps:
        return edit_deps()

    if cmdargs.check_deps:
        return check_deps(cmdargs)

    if cmdargs.check:
        return check(cmdargs)


def cmd_trailers(cmdargs: argparse.Namespace) -> None:
    check_can_gfr()
    status = b4.git_get_repo_status()
    if len(status):
        logger.critical('CRITICAL: Repository contains uncommitted changes.')
        logger.critical('          Stash or commit them first.')
        sys.exit(1)

    if cmdargs.update:
        update_trailers(cmdargs)
