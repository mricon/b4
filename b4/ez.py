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
import tempfile
import subprocess
import shlex
import email
import pathlib
import base64
import textwrap
import gzip
import io
import copy

from typing import Optional, Tuple, List
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

DEFAULT_COVER_TEMPLATE = """
${cover}

---
${shortlog}

${diffstat}
---
base-commit: ${base_commit}
change-id: ${change_id}

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


def get_auth_configs() -> Tuple[str, str, str, str, str, str]:
    config = b4.get_main_config()
    endpoint = config.get('send-endpoint-web', '')
    if not re.search(r'^https?://', endpoint):
        endpoint = None

    if not endpoint:
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
    cmsg.set_payload(f'verify:{vstr}\n')
    bdata = cmsg.as_bytes(policy=b4.emlpolicy)
    try:
        bdata = patatt.rfc2822_sign(bdata).decode()
    except patatt.SigningError as ex:
        logger.critical('CRITICAL: Unable to sign verification message')
        logger.critical('          %s', ex)
        sys.exit(1)

    req = {
        'action': 'auth-verify',
        'msg': bdata.encode(),
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
                    ztracking = base64.b64decode(b64tracking)
                    btracking = gzip.decompress(ztracking)
                    tracking = json.loads(btracking.decode())
                    logger.debug('tracking: %s', tracking)
                    cover_sections = list()
                    diffstatre = re.compile(r'^\s*\d+ file.*\d+ (insertion|deletion)', flags=re.M | re.I)
                    for section in cmsg.body.split('\n---\n'):
                        # we stop caring once we see a diffstat
                        if diffstatre.search(section):
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

        # We start with next revision
        revision = lser.revision + 1
        # Do or don't add follow-up trailers? Don't add for now, let them run b4 trailers -u.
        patches = lser.get_am_ready(noaddtrailers=True)
        logger.info('---')

    mybranch = b4.git_get_current_branch()
    strategy = get_cover_strategy()
    cherry_range = None
    if cmdargs.new_series_name:
        basebranch = None
        if not cmdargs.fork_point:
            cmdargs.fork_point = 'HEAD'
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
                if basebranch is None:
                    logger.critical('CRITICAL: fork-point %s is not on the current branch.')
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
        # Is it a branch?
        gitargs = ['show-ref', '--heads', enroll_base]
        lines = b4.git_get_command_lines(None, gitargs)
        if lines:
            try:
                forkpoint = get_base_forkpoint(enroll_base, mybranch)
            except RuntimeError as ex:
                logger.critical('CRITICAL: could not use %s as enrollment base:')
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
            heads = b4.git_branch_contains(None, forkpoint)
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
                 '# Lines starting with # will be removed from the cover letter. You can use',
                 '# them to add notes or reminders to yourself.',
                 '',
                 'EDITME: describe the purpose of this series. The information you put here',
                 'will be used by the project maintainer to make a decision whether your',
                 'patches should be reviewed, and in what priority order. Please be very',
                 'detailed and link to any relevant discussions or sites that the maintainer',
                 'can review to better understand your proposed changes. If you only have a',
                 'single patch in your series, the contents of the cover letter will be',
                 'appended to the "under-the-cut" portion of the patch.',
                 '',
                 '# You can add trailers to the cover letter. Any email addresses found in',
                 '# these trailers will be added to the addresses specified/generated during',
                 '# the b4 send stage. You can also run "b4 prep --auto-to-cc" to auto-populate',
                 '# the To: and Cc: trailers based on the code being modified.',
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
        tracking = {
            'series': {
                'revision': revision,
                'change-id': changeid,
                'base-branch': basebranch,
            },
        }
        if thread_msgid:
            tracking['series']['from-thread'] = thread_msgid

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
        ifh = io.StringIO()
        b4.save_git_am_mbox(patches, ifh)
        ambytes = ifh.getvalue().encode()
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


def load_cover(strip_comments: bool = False) -> Tuple[str, dict]:
    strategy = get_cover_strategy()
    if strategy in {'commit', 'tip-commit'}:
        cover_commit = find_cover_commit()
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

def get_cover_strategy(branch: Optional[str] = None) -> str:
    if branch is None:
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


def is_prep_branch() -> bool:
    mybranch = b4.git_get_current_branch()
    strategy = get_cover_strategy(mybranch)
    if strategy in {'commit', 'tip-commit'}:
        if find_cover_commit() is None:
            return False
        return True
    if strategy == 'branch-description':
        # See if we have b4-tracking set for this branch
        bcfg = b4.get_config_from_git(rf'branch\.{mybranch}\..*')
        if bcfg.get('b4-tracking'):
            return True
        return False

    logger.critical('CRITICAL: unknown cover strategy: %s', strategy)
    sys.exit(1)


def find_cover_commit() -> Optional[str]:
    # Walk back commits until we find the cover letter
    # Our covers always contain the MAGIC_MARKER line
    logger.debug('Looking for the cover letter commit with magic marker "%s"', MAGIC_MARKER)
    gitargs = ['log', '--grep', MAGIC_MARKER, '-F', '--pretty=oneline', '--max-count=1', '--since=1.year']
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
    cover, tracking = load_cover()
    # What's our editor? And yes, the default is vi, bite me.
    corecfg = b4.get_config_from_git(r'core\..*', {'editor': os.environ.get('EDITOR', 'vi')})
    editor = corecfg.get('editor')
    logger.debug('editor=%s', editor)
    # We give it a suffix .rst in hopes that editors autoload restructured-text rules
    with tempfile.NamedTemporaryFile(suffix='.rst') as temp_cover:
        temp_cover.write(cover.encode())
        temp_cover.seek(0)
        sp = shlex.shlex(editor, posix=True)
        sp.whitespace_split = True
        cmdargs = list(sp) + [temp_cover.name]
        logger.debug('Running %s' % ' '.join(cmdargs))
        sp = subprocess.Popen(cmdargs)
        sp.wait()
        new_cover = temp_cover.read().decode(errors='replace').strip()

    if new_cover == cover:
        logger.info('Cover letter unchanged.')
        return
    if not len(new_cover.strip()):
        logger.info('New cover letter blank, leaving current one unchanged.')
        return

    store_cover(new_cover, tracking)
    logger.info('Cover letter updated.')


def get_series_start() -> str:
    strategy = get_cover_strategy()
    forkpoint = None
    if strategy == 'commit':
        # Easy, we start at the cover letter commit
        return find_cover_commit()
    if strategy == 'branch-description':
        mybranch = b4.git_get_current_branch()
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
        cover, tracking = load_cover()
        basebranch = tracking['series']['base-branch']
        try:
            forkpoint = get_base_forkpoint(basebranch)
            commitcount = get_rev_count(f'{forkpoint}..HEAD~1')
        except RuntimeError:
            sys.exit(1)
        logger.debug('series_start: %s, commitcount=%s', forkpoint, commitcount)

    return forkpoint


def update_trailers(cmdargs: argparse.Namespace) -> None:
    usercfg = b4.get_user_config()
    if 'name' not in usercfg or 'email' not in usercfg:
        logger.critical('CRITICAL: Please set your user.name and user.email')
        sys.exit(1)

    ignore_commits = None
    # If we are in an b4-prep branch, we start from the beginning of the series
    if is_prep_branch():
        start = get_series_start()
        end = 'HEAD'
        cover, tracking = load_cover(strip_comments=True)
        changeid = tracking['series'].get('change-id')
        msgid = tracking['series'].get('from-thread')
        strategy = get_cover_strategy()
        if strategy in {'commit', 'tip-commit'}:
            # We need to me sure we ignore the cover commit
            cover_commit = find_cover_commit()
            if cover_commit:
                ignore_commits = {cover_commit}

    elif cmdargs.msgid:
        msgid = b4.get_msgid(cmdargs)
        changeid = None
        myemail = usercfg['email']
        # There doesn't appear to be a great way to find the first commit
        # where we're NOT the committer, so we get all commits since range specified where
        # we're the committer and stop at the first non-contiguous parent
        gitargs = ['log', '-F', '--no-merges', f'--committer={myemail}', '--since', cmdargs.since, '--format=%H %P']
        lines = b4.git_get_command_lines(None, gitargs)
        if not lines:
            logger.critical('CRITICAL: could not find any commits where committer=%s', myemail)
            sys.exit(1)

        prevparent = prevcommit = end = None
        for line in lines:
            commit, parent = line.split()
            if end is None:
                end = commit
            if prevparent is None:
                prevparent = parent
                continue
            if prevcommit is None:
                prevcommit = commit
            if prevparent != commit:
                break
            prevparent = parent
            prevcommit = commit
        start = f'{prevcommit}~1'
    else:
        logger.critical('CRITICAL: Please specify -F msgid to look up trailers from remote.')
        sys.exit(1)

    try:
        patches = b4.git_range_to_patches(None, start, end, ignore_commits=ignore_commits)
    except RuntimeError as ex:
        logger.critical('CRITICAL: Failed to convert range to patches: %s', ex)
        sys.exit(1)

    logger.info('Calculating patch-ids from %s commits', len(patches)-1)
    commit_map = dict()
    by_patchid = dict()
    by_subject = dict()
    updates = dict()
    for commit, msg in patches:
        if not msg:
            continue
        commit_map[commit] = msg
        body = msg.get_payload()
        patchid = b4.LoreMessage.get_patch_id(body)
        subject = msg.get('subject')
        by_subject[subject] = commit
        by_patchid[patchid] = commit

    list_msgs = list()
    if changeid:
        logger.info('Checking change-id "%s"', changeid)
        query = f'"change-id: {changeid}"'
        smsgs = b4.get_pi_search_results(query, nocache=True)
        if smsgs is not None:
            list_msgs += smsgs
    if msgid:
        logger.info('Retrieving thread matching %s', msgid)
        tmsgs = b4.get_pi_thread_by_msgid(msgid, nocache=True)
        if tmsgs is not None:
            list_msgs += tmsgs

    if list_msgs:
        bbox = b4.LoreMailbox()
        for list_msg in list_msgs:
            bbox.add_message(list_msg)

        lser = bbox.get_series(sloppytrailers=cmdargs.sloppytrailers)
        mismatches = list(lser.trailer_mismatches)
        for lmsg in lser.patches[1:]:
            addtrailers = list(lmsg.followup_trailers)
            if lser.has_cover and len(lser.patches[0].followup_trailers):
                addtrailers += list(lser.patches[0].followup_trailers)
            if not addtrailers:
                logger.debug('No follow-up trailers received to: %s', lmsg.subject)
                continue
            commit = None
            if lmsg.subject in by_subject:
                commit = by_subject[lmsg.subject]
            else:
                patchid = b4.LoreMessage.get_patch_id(lmsg.body)
                if patchid in by_patchid:
                    commit = by_patchid[patchid]
            if not commit:
                logger.debug('No match for %s', lmsg.full_subject)
                continue

            parts = b4.LoreMessage.get_body_parts(commit_map[commit].get_payload())
            for fltr in addtrailers:
                if fltr not in parts[2]:
                    if commit not in updates:
                        updates[commit] = list()
                    updates[commit].append(fltr)
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

    logger.info('---')
    # Create the map of new messages
    fred = FRCommitMessageEditor()
    for commit, newtrailers in updates.items():
        # Make it a LoreMessage, so we can run attestation on received trailers
        cmsg = b4.LoreMessage(commit_map[commit])
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
        logger.critical(err.decode())
        raise RuntimeError('Running command failed: %s' % ' '.join(cmdargs))
    addrs = out.strip().decode()
    if not addrs:
        return list()
    return utils.getaddresses(addrs.split('\n'))


def get_series_details(start_commit: str) -> Tuple[str, str, str]:
    # Not sure if we can reasonably expect all automation to handle this correctly
    # gitargs = ['describe', '--long', f'{cover_commit}~1']
    gitargs = ['rev-parse', f'{start_commit}~1']
    lines = b4.git_get_command_lines(None, gitargs)
    base_commit = lines[0]
    strategy = get_cover_strategy()
    if strategy == 'tip-commit':
        cover_commit = find_cover_commit()
        endrange = f'{cover_commit}~1'
    else:
        endrange = ''
    gitargs = ['shortlog', f'{start_commit}..{endrange}']
    ecode, shortlog = b4.git_run_command(None, gitargs)
    gitargs = ['diff', '--stat', f'{start_commit}..{endrange}']
    ecode, diffstat = b4.git_run_command(None, gitargs)
    return base_commit, shortlog.rstrip(), diffstat.rstrip()


def print_pretty_addrs(addrs: list, hdrname: str) -> None:
    if len(addrs) < 1:
        return
    logger.info('%s: %s', hdrname, b4.format_addrs([addrs[0]]))
    if len(addrs) > 1:
        for addr in addrs[1:]:
            logger.info('    %s', b4.format_addrs([addr]))


def get_sent_tag_as_patches(tagname: str, revision: Optional[str] = None,
                            prefixes: Optional[List[str]] = None,
                            hide_cover_to_cc: bool = False
                            ) -> Tuple[List, List, List[Tuple[str, email.message.Message]]]:
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
    if revision is None:
        matches = re.search(r'.*-v(\d+)$', tagname, flags=re.I | re.M)
        if not matches:
            raise RuntimeError('Could not grok revision number from %s' % tagname)
        revision = matches.groups()[0]

    # First line is the subject
    csubject, cbody = cover.split('\n', maxsplit=1)
    cbody = cbody.strip() + '\n-- \n' + b4.get_email_signature()
    if hide_cover_to_cc:
        tos, ccs, body = remove_to_cc_trailers(cbody)
    else:
        tos = list()
        ccs = list()

    cmsg = email.message.EmailMessage()
    cmsg.add_header('Subject', csubject)
    cmsg.set_payload(cbody.lstrip(), charset='utf-8')
    if prefixes is None:
        prefixes = list()
    if revision != 1:
        prefixes.append(f'v{revision}')
    seriests = int(time.time())
    msgid_tpt = make_msgid_tpt(change_id, revision)
    usercfg = b4.get_user_config()
    mailfrom = (usercfg.get('name'), usercfg.get('email'))

    patches = b4.git_range_to_patches(None, base_commit, tagname,
                                      covermsg=cmsg, prefixes=prefixes,
                                      msgid_tpt=msgid_tpt,
                                      seriests=seriests,
                                      thread=True,
                                      mailfrom=mailfrom)
    return tos, ccs, patches


def make_msgid_tpt(change_id: str, revision: str, domain: Optional[str] = None) -> str:
    if not domain:
        usercfg = b4.get_user_config()
        myemail = usercfg.get('email')
        if myemail:
            domain = re.sub(r'^[^@]*@', '', myemail)
        else:
            # Use the hostname of the system
            import platform
            domain = platform.node()

    chunks = change_id.rsplit('-', maxsplit=1)
    stablepart = chunks[0]
    # Message-IDs must not be predictable to avoid stuffing attacks
    randompart = uuid.uuid4().hex[:12]
    msgid_tpt = f'<{stablepart}-v{revision}-%s-{randompart}@{domain}>'
    return msgid_tpt


def remove_to_cc_trailers(body: str) -> Tuple[List, List, str]:
    htrs, cmsg, mtrs, basement, sig = b4.LoreMessage.get_body_parts(body)
    tos = list()
    ccs = list()
    for mtr in list(mtrs):
        if mtr.lname == 'to':
            tos.append(mtr.addr)
            mtrs.remove(mtr)
        elif mtr.lname == 'cc':
            ccs.append(mtr.addr)
            mtrs.remove(mtr)
    body = b4.LoreMessage.rebuild_message(htrs, cmsg, mtrs, basement, sig)
    return tos, ccs, body


def get_prep_branch_as_patches(prefixes: Optional[List[str]] = None,
                               movefrom: bool = True, thread: bool = True,
                               hide_cover_to_cc: bool = False
                               ) -> Tuple[List, List, List[Tuple[str, email.message.Message]]]:
    cover, tracking = load_cover(strip_comments=True)
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

    # Put together the cover letter
    csubject, cbody = cover.split('\n', maxsplit=1)

    start_commit = get_series_start()
    base_commit, shortlog, diffstat = get_series_details(start_commit=start_commit)
    change_id = tracking['series'].get('change-id')
    revision = tracking['series'].get('revision')
    tptvals = {
        'subject': csubject,
        'cover': cbody.strip(),
        'shortlog': shortlog,
        'diffstat': diffstat,
        'change_id': change_id,
        'base_commit': base_commit,
        'signature': b4.get_email_signature(),
    }
    body = Template(cover_template.lstrip()).safe_substitute(tptvals)
    if hide_cover_to_cc:
        tos, ccs, body = remove_to_cc_trailers(body)
    else:
        tos = list()
        ccs = list()

    cmsg = email.message.EmailMessage()
    cmsg.add_header('Subject', csubject)
    cmsg.set_payload(body, charset='utf-8')
    # Store tracking info in the header in a safe format, which should allow us to
    # fully restore our work from the already sent series.
    ztracking = gzip.compress(bytes(json.dumps(tracking), 'utf-8'))
    b64tracking = base64.b64encode(ztracking)
    cmsg.add_header('X-b4-tracking', ' '.join(textwrap.wrap(b64tracking.decode(), width=78)))
    if prefixes is None:
        prefixes = list()
    if revision != 1:
        prefixes.append(f'v{revision}')

    seriests = int(time.time())
    msgid_tpt = make_msgid_tpt(change_id, revision)
    if movefrom:
        usercfg = b4.get_user_config()
        mailfrom = (usercfg.get('name'), usercfg.get('email'))
    else:
        mailfrom = None

    strategy = get_cover_strategy()
    ignore_commits = None
    if strategy in {'commit', 'tip-commit'}:
        cover_commit = find_cover_commit()
        if cover_commit:
            ignore_commits = {cover_commit}

    patches = b4.git_range_to_patches(None, start_commit, 'HEAD',
                                      covermsg=cmsg, prefixes=prefixes,
                                      msgid_tpt=msgid_tpt,
                                      seriests=seriests,
                                      thread=thread,
                                      mailfrom=mailfrom,
                                      ignore_commits=ignore_commits)
    return tos, ccs, patches


def format_patch(output_dir: str) -> None:
    try:
        tos, ccs, patches = get_prep_branch_as_patches(thread=False, movefrom=False)
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
        with open(os.path.join(output_dir, filen), 'w') as fh:
            fh.write(msg.as_string(unixfrom=True, maxheaderlen=0))
            logger.info('  %s', filen)


def cmd_send(cmdargs: argparse.Namespace) -> None:
    if cmdargs.auth_new:
        auth_new()
        return
    if cmdargs.auth_verify:
        auth_verify(cmdargs)
        return

    # Should we make the sent/ prefix configurable?
    tagprefix = 'sent/'
    mybranch = b4.git_get_current_branch()
    prefixes = cmdargs.prefixes
    if cmdargs.prefixes is None:
        prefixes = list()

    config = b4.get_main_config()
    if not cmdargs.hide_cover_to_cc and config.get('send-hide-cover-to-cc', '').lower() in {'yes', 'true', '1'}:
        cmdargs.hide_cover_to_cc = True

    if cmdargs.resend:
        # We accept both a full tag name and just a vN short form
        matches = re.search(r'^v(\d+)$', cmdargs.resend)
        if matches:
            revision = matches.groups()[0]
            if mybranch.startswith('b4/'):
                tagname = f'{tagprefix}{mybranch[3:]}-v{revision}'
            else:
                tagname = f'{tagprefix}{mybranch}-v{revision}'
        else:
            revision = None
            tagname = cmdargs.resend

        prefixes.append('RESEND')
        try:
            todests, ccdests, patches = get_sent_tag_as_patches(tagname, revision=revision, prefixes=prefixes,
                                                                hide_cover_to_cc=cmdargs.hide_cover_to_cc)
        except RuntimeError as ex:
            logger.critical('CRITICAL: Failed to convert tag to patches: %s', ex)
            sys.exit(1)

        logger.info('Converted the tag to %s messages', len(patches))

    else:
        # Check if the cover letter has 'EDITME' in it
        cover, tracking = load_cover(strip_comments=True)
        if 'EDITME' in cover:
            logger.critical('CRITICAL: Looks like the cover letter needs to be edited first.')
            logger.info('---')
            logger.info(cover)
            logger.info('---')
            sys.exit(1)

        try:
            todests, ccdests, patches = get_prep_branch_as_patches(prefixes=prefixes,
                                                                   hide_cover_to_cc=cmdargs.hide_cover_to_cc)
        except RuntimeError as ex:
            logger.critical('CRITICAL: Failed to convert range to patches: %s', ex)
            sys.exit(1)
        logger.info('Converted the branch to %s messages', len(patches))

    usercfg = b4.get_user_config()
    myemail = usercfg.get('email')

    seen = set()
    excludes = set()

    if cmdargs.no_trailer_to_cc:
        todests = list()
        ccdests = list()
    else:
        seen.update(todests)
        seen.update(ccdests)
        logger.info('Populating To/Cc addresses')
        # Go through the messages to make to/cc headers
        for commit, msg in patches:
            if not msg:
                continue
            body = msg.get_payload()
            btrs, junk = b4.LoreMessage.find_trailers(body)
            for btr in btrs:
                if btr.type != 'person':
                    continue
                if btr.addr[1] in seen:
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
    if cmdargs.to:
        tos.update(cmdargs.to)
    if config.get('send-series-to'):
        tos.add(config.get('send-series-to'))
    if tos:
        for pair in utils.getaddresses(list(tos)):
            if pair[1] in seen:
                continue
            seen.add(pair[1])
            todests.append(pair)
    ccs = set()
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

    allto = list()
    allcc = list()
    alldests = set()

    if todests:
        allto = b4.cleanup_email_addrs(todests, excludes, None)
        alldests.update(set([x[1] for x in allto]))
    if ccdests:
        allcc = b4.cleanup_email_addrs(ccdests, excludes, None)
        alldests.update(set([x[1] for x in allcc]))

    if not len(alldests):
        logger.critical('CRITICAL: Could not find any destination addresses (try: b4 prep --auto-to-cc).')
        sys.exit(1)

    if not len(allto):
        # Move all cc's into the To field if there's nothing in "To"
        allto = list(allcc)
        allcc = list()

    if cmdargs.output_dir:
        cmdargs.dryrun = True
        logger.info('Will write out messages into %s', cmdargs.output_dir)
        pathlib.Path(cmdargs.output_dir).mkdir(parents=True, exist_ok=True)

    # Give the user the last opportunity to bail out
    if not cmdargs.dryrun:
        logger.info('Will send the following messages:')
        logger.info('---')
        print_pretty_addrs(allto, 'To')
        print_pretty_addrs(allcc, 'Cc')
        logger.info('---')
        for commit, msg in patches:
            if not msg:
                continue
            logger.info('  %s', re.sub(r'\s+', ' ', msg.get('Subject')))
        logger.info('---')
        try:
            input('Press Enter to send or Ctrl-C to abort')
        except KeyboardInterrupt:
            logger.info('')
            sys.exit(130)

    # And now we go through each message to set addressees and send them off
    sign = True
    if cmdargs.no_sign or config.get('send-no-patatt-sign', '').lower() in {'yes', 'true', 'y'}:
        sign = False

    cover_msg = None
    # TODO: Need to send obsoleted-by follow-ups, just need to figure out where.
    send_msgs = list()
    for commit, msg in patches:
        if not msg:
            continue
        if cover_msg is None:
            cover_msg = copy.deepcopy(msg)

        msg.add_header('To', b4.format_addrs(allto))
        if allcc:
            msg.add_header('Cc', b4.format_addrs(allcc))

        send_msgs.append(msg)

    endpoint = config.get('send-endpoint-web', '')
    if not re.search(r'^https?://', endpoint):
        endpoint = None

    if endpoint:
        # Web endpoint always requires signing
        if not sign:
            logger.critical('CRITICAL: Web endpoint is defined for sending, but signing is turned off')
            logger.critical('          Please re-enable signing or use SMTP')
            sys.exit(1)

        sent = b4.send_mail(None, send_msgs, fromaddr=None, destaddrs=None, patatt_sign=True,
                            dryrun=cmdargs.dryrun, output_dir=cmdargs.output_dir, use_web_endpoint=True)
    else:
        identity = config.get('sendemail-identity')
        try:
            smtp, fromaddr = b4.get_smtp(identity, dryrun=cmdargs.dryrun)
        except Exception as ex:  # noqa
            logger.critical('Failed to configure the smtp connection:')
            logger.critical(ex)
            sys.exit(1)

        sent = b4.send_mail(smtp, send_msgs, fromaddr=fromaddr, destaddrs=alldests, patatt_sign=sign,
                            dryrun=cmdargs.dryrun, output_dir=cmdargs.output_dir, use_web_endpoint=False)

    logger.info('---')
    if cmdargs.dryrun:
        logger.info('DRYRUN: Would have sent %s messages', len(send_msgs))
        return
    if not sent:
        logger.critical('CRITICAL: Was not able to send messages.')
        sys.exit(1)

    logger.info('Sent %s messages', sent)

    if cmdargs.resend:
        logger.debug('Not updating cover/tracking on resend')
        return

    reroll(mybranch, cover_msg)


def reroll(mybranch: str, cover_msg: email.message.Message, tagprefix: str = 'sent/'):
    # Prepare annotated tag body from the cover letter
    lsubject = b4.LoreSubject(cover_msg.get('subject'))
    cbody = cover_msg.get_payload()
    # Remove signature
    chunks = cbody.rsplit('\n-- \n')
    if len(chunks) > 1:
        cbody = chunks[0] + '\n'
    cover_body = lsubject.subject + '\n\n' + cbody

    cover, tracking = load_cover(strip_comments=True)
    revision = tracking['series']['revision']
    if mybranch.startswith('b4/'):
        tagname = f'{tagprefix}{mybranch[3:]}-v{revision}'
    else:
        tagname = f'{tagprefix}{mybranch}-v{revision}'

    logger.debug('checking if we already have %s', tagname)
    gitargs = ['rev-parse', f'refs/tags/{tagname}']
    ecode, out = b4.git_run_command(None, gitargs)
    if ecode > 0:
        try:
            strategy = get_cover_strategy()
            if strategy == 'commit':
                # Find out the head commit, which is the end of our range
                gitargs = ['rev-parse', 'HEAD']
                ecode, out = b4.git_run_command(None, gitargs)
                end_commit = out.strip()
                # Detach the head at our parent commit and apply the cover-less series
                cover_commit = find_cover_commit()
                gitargs = ['checkout', f'{cover_commit}~1']
                ecode, out = b4.git_run_command(None, gitargs)
                if ecode > 0:
                    raise RuntimeError('Could not switch to a detached head')
                # cherry-pick from cover letter to the last commit
                gitargs = ['cherry-pick', f'{cover_commit}..{end_commit}']
                ecode, out = b4.git_run_command(None, gitargs)
                if ecode > 0:
                    raise RuntimeError('Could not cherry-pick the cover-less range')
                # Find out the head commit
                gitargs = ['rev-parse', 'HEAD']
                ecode, out = b4.git_run_command(None, gitargs)
                if ecode > 0:
                    raise RuntimeError('Could not find the HEAD commit of the detached head')
                tagcommit = out.strip()
                # Switch back to our branch
                gitargs = ['checkout', mybranch]
                ecode, out = b4.git_run_command(None, gitargs)
                if ecode > 0:
                    raise RuntimeError('Could not switch back to %s' % mybranch)
            elif strategy == 'tip-commit':
                cover_commit = find_cover_commit()
                tagcommit = f'{cover_commit}~1'
            else:
                tagcommit = 'HEAD'

            logger.info('Tagging %s', tagname)
            gitargs = ['tag', '-a', '-F', '-', tagname, tagcommit]
            ecode, out = b4.git_run_command(None, gitargs, stdin=cover_body.encode())
            if ecode > 0:
                # Not a fatal error, just complain about it
                logger.info('Could not tag %s as %s:', tagcommit, tagname)
                logger.info(out)

        except RuntimeError as ex:
            logger.critical('Error tagging the revision: %s', ex)

    else:
        logger.info('NOTE: Tagname %s already exists', tagname)

    cover_msgid = b4.LoreMessage.get_clean_msgid(cover_msg)
    logger.info('Recording series message-id in cover letter tracking')
    cover, tracking = load_cover(strip_comments=False)
    vrev = f'v{revision}'
    if 'history' not in tracking['series']:
        tracking['series']['history'] = dict()
    if vrev not in tracking['series']['history']:
        tracking['series']['history'][vrev] = list()
    tracking['series']['history'][vrev].append(cover_msgid)

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
    cover, tracking = load_cover()
    ts = tracking['series']
    logger.info('v%s', ts.get('revision'))
    if 'history' in ts:
        config = b4.get_main_config()
        logger.info('---')
        for rn, links in ts['history'].items():
            for link in links:
                logger.info('  %s: %s', rn, config['linkmask'] % link)


def force_revision(forceto: int) -> None:
    cover, tracking = load_cover()
    tracking['series']['revision'] = forceto
    logger.info('Forced revision to v%s', forceto)
    store_cover(cover, tracking)


def auto_to_cc() -> None:
    tocmdstr = None
    cccmdstr = None
    topdir = b4.git_get_toplevel()
    # Use sane tocmd and cccmd defaults if we find a get_maintainer.pl
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
        logger.info('Will collect To: addresses using %s', os.path.basename(tocmd[0]))
    if cccmdstr:
        sp = shlex.shlex(cccmdstr, posix=True)
        sp.whitespace_split = True
        cccmd = list(sp)
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

    tos, ccs, patches = get_prep_branch_as_patches()
    logger.info('Collecting To/Cc addresses')
    # Go through the messages to make to/cc headers
    for commit, msg in patches:
        if not msg:
            continue
        payload = msg.get_payload()
        parts = b4.LoreMessage.get_body_parts(payload)
        for ltr in parts[2]:
            if not ltr.addr:
                continue
            if ltr.addr[1] in seen:
                continue
            seen.add(ltr.addr[1])
            logger.debug('added %s to seen', ltr.addr[1])
            # Make it a Cc: trailer
            ltr.name = 'Cc'
            extras.append(ltr)

        if not commit:
            continue

        msgbytes = msg.as_bytes()
        for tname, pairs in (('To', get_addresses_from_cmd(tocmd, msgbytes)),
                             ('Cc', get_addresses_from_cmd(cccmd, msgbytes))):
            for pair in pairs:
                if pair[1] not in seen:
                    seen.add(pair[1])
                    ltr = b4.LoreTrailer(name=tname, value=b4.format_addrs([pair]))
                    extras.append(ltr)

    if not extras:
        logger.info('No new addresses to add.')
        return

    # Make it a LoreMessage, so we can run a fix_trailers on it
    cmsg = email.message.EmailMessage()
    cmsg.set_payload(cover, charset='utf-8')
    clm = b4.LoreMessage(cmsg)
    fallback_order = config.get('send-trailer-order', 'To,Cc,*')
    clm.fix_trailers(extras=extras, fallback_order=fallback_order)
    logger.info('---')
    logger.info('You can trim/expand this list with: b4 prep --edit-cover')
    store_cover(clm.body, tracking)


def cmd_prep(cmdargs: argparse.Namespace) -> None:
    check_can_gfr()
    status = b4.git_get_repo_status()
    if len(status):
        logger.critical('CRITICAL: Repository contains uncommitted changes.')
        logger.critical('          Stash or commit them first.')
        sys.exit(1)

    if cmdargs.edit_cover:
        return edit_cover()

    if cmdargs.auto_to_cc:
        return auto_to_cc()

    if cmdargs.reroll:
        msgid = cmdargs.reroll
        msgs = b4.get_pi_thread_by_msgid(msgid, onlymsgids={msgid}, nocache=True)
        mybranch = b4.git_get_current_branch(None)
        if msgs:
            for msg in msgs:
                if b4.LoreMessage.get_clean_msgid(msg) == msgid:
                    return reroll(mybranch, msg)
        logger.critical('CRITICAL: could not retrieve %s', msgid)
        sys.exit(1)

    if cmdargs.show_revision:
        return show_revision()

    if cmdargs.force_revision:
        return force_revision(cmdargs.force_revision)

    if cmdargs.format_patch:
        return format_patch(cmdargs.format_patch)

    if is_prep_branch():
        logger.critical('CRITICAL: This appears to already be a b4-prep managed branch.')
        sys.exit(1)

    return start_new_series(cmdargs)


def cmd_trailers(cmdargs: argparse.Namespace) -> None:
    check_can_gfr()
    status = b4.git_get_repo_status()
    if len(status):
        logger.critical('CRITICAL: Repository contains uncommitted changes.')
        logger.critical('          Stash or commit them first.')
        sys.exit(1)

    if cmdargs.update:
        update_trailers(cmdargs)
