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

# from nacl.signing import SigningKey
# from nacl.encoding import Base64Encoder

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

# def auth_new(cmdargs: argparse.Namespace) -> None:
#     # Check if we have a patatt signingkey already defined
#     endpoint, name, email, ptskey = get_configs()
#     skey, pkey = get_patatt_ed25519keys(ptskey)
#     logger.info('Will submit a new email authorization request to:')
#     logger.info('  Endpoint: %s', endpoint)
#     logger.info('      Name: %s', name)
#     logger.info('     Email: %s', email)
#     logger.info('       Key: %s (%s)', pkey, ptskey)
#     logger.info('---')
#     confirm = input('Confirm selection [y/N]: ')
#     if confirm != 'y':
#         logger.info('Exiting')
#         sys.exit(0)
#     req = {
#         'action': 'auth-new',
#         'name': name,
#         'email': email,
#         'key': pkey,
#     }
#     ses = b4.get_requests_session()
#     res = ses.post(endpoint, json=req)
#     logger.info('---')
#     if res.status_code == 200:
#         try:
#             rdata = res.json()
#             if rdata.get('result') == 'success':
#                 logger.info('Challenge generated and sent to %s', email)
#                 logger.info('Once you receive it, run b4 submit --web-auth-verify [challenge-string]')
#             sys.exit(0)
#
#         except Exception as ex:  # noqa
#             logger.critical('Odd response from the endpoint: %s', res.text)
#             sys.exit(1)
#
#     logger.critical('500 response from the endpoint: %s', res.text)
#     sys.exit(1)
#
#
# def auth_verify(cmdargs: argparse.Namespace) -> None:
#     endpoint, name, email, ptskey = get_configs()
#     skey, pkey = get_patatt_ed25519keys(ptskey)
#     challenge = cmdargs.auth_verify
#     logger.info('Signing challenge using key %s', ptskey)
#     sk = SigningKey(skey.encode(), encoder=Base64Encoder)
#     bdata = sk.sign(challenge.encode(), encoder=Base64Encoder)
#     req = {
#         'action': 'auth-verify',
#         'name': name,
#         'email': email,
#         'challenge': challenge,
#         'sigdata': bdata.decode(),
#     }
#     ses = b4.get_requests_session()
#     res = ses.post(endpoint, json=req)
#     logger.info('---')
#     if res.status_code == 200:
#         try:
#             rdata = res.json()
#             if rdata.get('result') == 'success':
#                 logger.info('Challenge successfully verified for %s', email)
#                 logger.info('You may now use this endpoint for submitting patches.')
#             sys.exit(0)
#
#         except Exception as ex:  # noqa
#             logger.critical('Odd response from the endpoint: %s', res.text)
#             sys.exit(1)
#
#     logger.critical('500 response from the endpoint: %s', res.text)
#     sys.exit(1)


def start_new_series(cmdargs: argparse.Namespace) -> None:
    status = b4.git_get_repo_status()
    if len(status):
        logger.critical('CRITICAL: Repository contains uncommitted changes.')
        logger.critical('          Stash or commit them first.')
        sys.exit(1)

    usercfg = b4.get_user_config()
    if 'name' not in usercfg or 'email' not in usercfg:
        logger.critical('CRITICAL: Unable to add your Signed-off-by: git returned no user.name or user.email')
        sys.exit(1)

    if not cmdargs.fork_point:
        cmdargs.fork_point = 'HEAD'
    slug = re.sub(r'\W+', '-', cmdargs.new_series_name).strip('-').lower()
    branchname = 'b4/%s' % slug
    args = ['checkout', '-b', branchname, cmdargs.fork_point]
    ecode, out = b4.git_run_command(None, args, logstderr=True)
    if ecode > 0:
        logger.critical('CRITICAL: Failed to create a new branch %s', branchname)
        logger.critical(out)
        sys.exit(ecode)
    logger.info('Created new branch %s', branchname)
    # create an empty commit containing basic cover letter details
    msgdata = ('EDITME: cover title for %s' % cmdargs.new_series_name,
               '',
               '# Lines starting with # will be removed from the cover letter. You can use',
               '# them to add notes or reminders to yourself.',
               '',
               'EDITME: describe the purpose of this series. The information you put here',
               'will be used by the project maintainer to make a decision whether your',
               'patches should be reviewed, and in what priority order. Please be very',
               'detailed and link to any relevant discussions or sites that the maintainer',
               'can review to better understand your proposed changes.',
               '',
               'Signed-off-by: %s <%s>' % (usercfg.get('name', ''), usercfg.get('email', '')),
               '',
               '# You can add other trailers to the cover letter. Any email addresses found in',
               '# these trailers will be added to the addresses specified/generated during',
               '# the --send stage.',
               '',
               '',
               )
    # We don't need all the entropy of uuid, just some of it
    changeid = '%s-%s-%s' % (datetime.date.today().strftime('%Y%m%d'), slug, uuid.uuid4().hex[:12])
    tracking = {
        'series': {
            'revision': 1,
            'change-id': changeid,
        },
    }
    message = '\n'.join(msgdata) + make_magic_json(tracking)
    args = ['commit', '--allow-empty', '-F', '-']
    ecode, out = b4.git_run_command(None, args, stdin=message.encode(), logstderr=True)
    if ecode > 0:
        logger.critical('CRITICAL: Generating cover letter commit failed:')
        logger.critical(out)
    logger.info('Created empty commit with the cover letter.')
    logger.info('You can prepare your commits now.')


def make_magic_json(data: dict) -> str:
    mj = (f'{MAGIC_MARKER}\n'
          '# This section is used internally by b4 submit for tracking purposes.\n')
    return mj + json.dumps(data, indent=2)


def load_cover(cover_commit: str, strip_comments: bool = False) -> Tuple[str, dict]:
    # Grab the cover contents
    gitargs = ['show', '-s', '--format=%B', cover_commit]
    ecode, out = b4.git_run_command(None, gitargs)
    if ecode > 0:
        logger.critical('CRITICAL: unable to load cover letter')
        sys.exit(1)
    # Split on MAGIC_MARKER
    cover, magic_json = out.split(MAGIC_MARKER)
    # drop everything until the first {
    junk, mdata = magic_json.split('{', maxsplit=1)
    jdata = json.loads('{' + mdata)
    logger.debug('tracking data: %s', jdata)
    if strip_comments:
        cover = re.sub(r'^#.*$', '', cover, flags=re.M)
        while '\n\n\n' in cover:
            cover = cover.replace('\n\n\n', '\n\n')
    return cover.strip(), jdata


def update_cover(commit: str, content: str, tracking: dict) -> None:
    cover_message = content + '\n\n' + make_magic_json(tracking)
    fred = FRCommitMessageEditor()
    fred.add(commit, cover_message)
    args = fr.FilteringOptions.parse_args(['--force', '--quiet', '--refs', f'{commit}~1..HEAD'])
    args.refs = [f'{commit}~1..HEAD']
    frf = fr.RepoFilter(args, commit_callback=fred.callback)
    logger.info('Invoking git-filter-repo to update the cover letter.')
    frf.run()


def check_our_branch() -> bool:
    mybranch = b4.git_get_current_branch()
    if mybranch.startswith('b4/'):
        return True
    logger.info('CRITICAL: This does not look like a b4-managed branch.')
    logger.info('          "%s" does not start with "b4/"', mybranch)
    return False


def find_cover_commit() -> Optional[str]:
    # Walk back commits until we find the cover letter
    # Our covers always contain the MAGIC_MARKER line
    logger.debug('Looking for the cover letter commit with magic marker "%s"', MAGIC_MARKER)
    gitargs = ['log', '--grep', MAGIC_MARKER, '-F', '--pretty=oneline', '--max-count=1']
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


def edit_cover(cover_commit: str) -> None:
    cover, tracking = load_cover(cover_commit)
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

    update_cover(cover_commit, new_cover, tracking)
    logger.info('Cover letter updated.')


def update_trailers(cover_commit: str, cmdargs: argparse.Namespace) -> None:
    if cmdargs.signoff:
        usercfg = b4.get_user_config()
        if 'name' not in usercfg or 'email' not in usercfg:
            logger.critical('CRITICAL: Unable to add your Signed-off-by: git returned no user.name or user.email')
            sys.exit(1)
        signoff = ('Signed-off-by', f"{usercfg['name']} <{usercfg['email']}>", None)
    else:
        signoff = None

    try:
        patches = b4.git_range_to_patches(None, cover_commit, 'HEAD')
    except RuntimeError as ex:
        logger.critical('CRITICAL: Failed to convert range to patches: %s', ex)
        sys.exit(1)

    logger.info('Calculating patch-ids from %s commits', len(patches)-1)
    msg_map = dict()
    commit_map = dict()
    # Ignore the cover letter
    for commit, msg in patches[1:]:
        body = msg.get_payload()
        patchid = b4.LoreMessage.get_patch_id(body)
        msg_map[patchid] = msg
        commit_map[patchid] = commit

    if cmdargs.thread_msgid:
        cmdargs.msgid = cmdargs.thread_msgid
        msgid = b4.get_msgid(cmdargs)
        logger.info('Retrieving thread matching %s', msgid)
        list_msgs = b4.get_pi_thread_by_msgid(msgid, nocache=True)
    else:
        cover, tracking = load_cover(cover_commit, strip_comments=True)
        changeid = tracking['series'].get('change-id')
        logger.info('Checking change-id "%s"', changeid)
        query = f'"change-id: {changeid}"'
        list_msgs = b4.get_pi_search_results(query, nocache=True)

    bbox = b4.LoreMailbox()
    for list_msg in list_msgs:
        bbox.add_message(list_msg)

    updates = dict()
    lser = bbox.get_series(sloppytrailers=cmdargs.sloppytrailers)
    mismatches = list(lser.trailer_mismatches)
    for lmsg in lser.patches[1:]:
        addtrailers = list(lmsg.followup_trailers)
        if lser.has_cover and len(lser.patches[0].followup_trailers):
            addtrailers += list(lser.patches[0].followup_trailers)
        if not addtrailers:
            logger.debug('No follow-up trailers received to the %s', lmsg.subject)
            continue
        patchid = b4.LoreMessage.get_patch_id(lmsg.body)
        if patchid not in commit_map:
            logger.debug('No match for patchid %s', patchid)
            continue
        parts = b4.LoreMessage.get_body_parts(msg_map[patchid].get_payload())
        if signoff and signoff not in parts[2]:
            updates[patchid] = list()
        for ftrailer in addtrailers:
            if ftrailer[:3] not in parts[2]:
                if patchid not in updates:
                    updates[patchid] = list()
                updates[patchid].append(ftrailer)
        # Check if we've applied mismatched trailers already
        if not cmdargs.sloppytrailers and mismatches:
            for mtrailer in list(mismatches):
                check = (mtrailer[0], mtrailer[1], None)
                if check in parts[2]:
                    logger.debug('Removing already-applied mismatch %s', check)
                    mismatches.remove(mtrailer)

    if not updates:
        logger.info('No trailer updates found.')
        return

    if len(mismatches):
        logger.critical('---')
        logger.critical('NOTE: some trailers ignored due to from/email mismatches:')
        for tname, tvalue, fname, femail in lser.trailer_mismatches:
            logger.critical('    ! Trailer: %s: %s', tname, tvalue)
            logger.critical('     Msg From: %s <%s>', fname, femail)
        logger.critical('NOTE: Rerun with -S to apply them anyway')

    logger.info('---')
    # Create the map of new messages
    fred = FRCommitMessageEditor()
    for patchid, newtrailers in updates.items():
        # Make it a LoreMessage, so we can run attestation on received trailers
        cmsg = b4.LoreMessage(msg_map[patchid])
        logger.info('  %s', cmsg.subject)
        cmsg.followup_trailers = newtrailers
        cmsg.fix_trailers(signoff=signoff)
        fred.add(commit_map[patchid], cmsg.message)
    logger.info('---')
    args = fr.FilteringOptions.parse_args(['--force', '--quiet', '--refs', f'{cover_commit}..HEAD'])
    args.refs = [f'{cover_commit}..HEAD']
    frf = fr.RepoFilter(args, commit_callback=fred.callback)
    logger.info('Invoking git-filter-repo to update trailers.')
    frf.run()
    logger.info('Trailers updated.')


def get_addresses_from_cmd(cmdargs: List[str], msgbytes: bytes) -> List[Tuple[str, str]]:
    ecode, out, err = b4._run_command(cmdargs, stdin=msgbytes)  # noqa
    if ecode > 0:
        logger.critical('CRITICAL: Running %s failed:', ' '.join(cmdargs))
        logger.critical(err.decode())
        raise RuntimeError('Running command failed: %s' % ' '.join(cmdargs))
    addrs = out.strip().decode()
    if not addrs:
        return list()
    return utils.getaddresses(addrs.split('\n'))


def get_series_details(cover_commit: str) -> Tuple[str, str, str]:
    # Not sure if we can reasonably expect all automation to handle this correctly
    # gitargs = ['describe', '--long', f'{cover_commit}~1']
    gitargs = ['rev-parse', f'{cover_commit}~1']
    lines = b4.git_get_command_lines(None, gitargs)
    base_commit = lines[0]
    gitargs = ['shortlog', f'{cover_commit}..']
    ecode, shortlog = b4.git_run_command(None, gitargs)
    gitargs = ['diff', '--stat', f'{cover_commit}..']
    ecode, diffstat = b4.git_run_command(None, gitargs)
    return base_commit, shortlog.rstrip(), diffstat.rstrip()


def send(cover_commit: str, cmdargs: argparse.Namespace) -> None:
    # Check if the cover letter has 'EDITME' in it
    cover, tracking = load_cover(cover_commit, strip_comments=True)
    if 'EDITME' in cover:
        logger.critical('CRITICAL: Looks like the cover letter needs to be edited first.')
        logger.info('---')
        logger.info(cover)
        logger.info('---')
        sys.exit(1)

    config = b4.get_main_config()
    cover_template = DEFAULT_COVER_TEMPLATE
    if config.get('submit-cover-template'):
        # Try to load this template instead
        try:
            cover_template = b4.read_template(config['submit-cover-template'])
        except FileNotFoundError:
            logger.critical('ERROR: submit-cover-template says to use %s, but it does not exist',
                            config['submit-cover-template'])
            sys.exit(2)

    # Generate the patches and collect all the addresses from trailers
    parts = b4.LoreMessage.get_body_parts(cover)
    trailers = set()
    trailers.update(parts[2])

    # Put together the cover letter
    csubject, cbody = cover.split('\n', maxsplit=1)
    base_commit, shortlog, diffstat = get_series_details(cover_commit)
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
    cmsg = email.message.EmailMessage()
    cmsg.set_payload(body)
    cmsg.add_header('Subject', csubject)
    if cmdargs.prefixes:
        prefixes = list(cmdargs.prefixes)
    else:
        prefixes = list()

    prefixes.append(f'v{revision}')
    seriests = int(time.time())
    usercfg = b4.get_user_config()
    myemail = usercfg.get('email')
    myname = usercfg.get('name')
    if myemail:
        msgdomain = re.sub(r'^[^@]*@', '', myemail)
    else:
        # Use the hostname of the system
        import platform
        msgdomain = platform.node()
    chunks = change_id.rsplit('-', maxsplit=1)
    stablepart = chunks[0]
    # Message-IDs must not be predictable to avoid stuffing attacks
    randompart = uuid.uuid4().hex[:12]
    msgid_tpt = f'<{stablepart}-v{revision}-%s-{randompart}@{msgdomain}>'

    try:
        patches = b4.git_range_to_patches(None, cover_commit, 'HEAD',
                                          covermsg=cmsg, prefixes=prefixes,
                                          msgid_tpt=msgid_tpt,
                                          seriests=seriests,
                                          mailfrom=(myname, myemail))
    except RuntimeError as ex:
        logger.critical('CRITICAL: Failed to convert range to patches: %s', ex)
        sys.exit(1)

    logger.info('Converted the branch to %s patches', len(patches)-1)
    seen = set()
    todests = list()
    if config.get('submit-to'):
        for pair in utils.getaddresses([config.get('submit-to')]):
            if pair[1] not in seen:
                seen.add(pair[1])
                todests.append(pair)
    ccdests = list()
    if config.get('submit-cc'):
        for pair in utils.getaddresses([config.get('submit-cc')]):
            if pair[1] not in seen:
                seen.add(pair[1])
                ccdests.append(pair)
    excludes = set()
    # These override config values
    if cmdargs.to:
        todests = [('', x) for x in cmdargs.to]
        seen.update(set(cmdargs.to))
    if cmdargs.cc:
        ccdests = [('', x) for x in cmdargs.cc]
        seen.update(set(cmdargs.cc))

    if not cmdargs.no_auto_to_cc:
        logger.info('Populating the To: and Cc: fields with automatically collected addresses')

        # Use a sane tocmd and cccmd for the kernel
        # TODO: make it definable in the config
        tocmdstr = tocmd = None
        cccmdstr = cccmd = None
        topdir = b4.git_get_toplevel()
        getm = os.path.join(topdir, 'scripts', 'get_maintainer.pl')
        if os.access(getm, os.X_OK):
            logger.debug('Using kernel get_maintainer.pl for to and cc list')
            tocmdstr = f'{getm} --nogit --nogit-fallback --nogit-chief-penguins --norolestats --nol'
            cccmdstr = f'{getm} --nogit --nogit-fallback --nogit-chief-penguins --norolestats --nom'
        if tocmdstr:
            sp = shlex.shlex(tocmdstr, posix=True)
            sp.whitespace_split = True
            tocmd = list(sp)
        if cccmdstr:
            sp = shlex.shlex(cccmdstr, posix=True)
            sp.whitespace_split = True
            cccmd = list(sp)

        seen = set()
        # Go through them again to make to/cc headers
        for commit, msg in patches:
            if not msg:
                continue
            body = msg.get_payload()
            parts = b4.LoreMessage.get_body_parts(body)
            trailers.update(parts[2])
            msgbytes = msg.as_bytes()
            if tocmd:
                for pair in get_addresses_from_cmd(tocmd, msgbytes):
                    if pair[1] not in seen:
                        seen.add(pair[1])
                        todests.append(pair)
            if cccmd:
                for pair in get_addresses_from_cmd(cccmd, msgbytes):
                    if pair[1] not in seen:
                        seen.add(pair[1])
                        ccdests.append(pair)

        # add addresses seen in trailers
        for trailer in trailers:
            if '@' in trailer[1]:
                for pair in utils.getaddresses([trailer[1]]):
                    if pair[1] not in seen:
                        seen.add(pair[1])
                        ccdests.append(pair)

        excludes = b4.get_excluded_addrs()
        if cmdargs.not_me_too:
            excludes.add(myemail)

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
        pathlib.Path(cmdargs.output_dir).mkdir(parents=True, exist_ok=True)
        for commit, msg in patches:
            if not msg:
                continue
            msg.add_header('To', b4.format_addrs(allto))
            if allcc:
                msg.add_header('Cc', b4.format_addrs(allcc))
            msg.set_charset('utf-8')
            msg.replace_header('Content-Transfer-Encoding', '8bit')
            msg.policy = email.policy.EmailPolicy(utf8=True, cte_type='8bit')
            subject = msg.get('Subject', '')
            ls = b4.LoreSubject(subject)
            filen = '%s.patch' % ls.get_slug(sep='-')
            with open(os.path.join(cmdargs.output_dir, filen), 'w') as fh:
                fh.write(msg.as_string(unixfrom=True, maxheaderlen=80))
                logger.info('  %s', filen)
        return

    # And now we go through each message to set addressees and send them off
    sign = True
    if cmdargs.no_sign or config.get('submit-no-sign', '').lower() in {'yes', 'true', 'y'}:
        sign = False
    identity = config.get('sendemail-identity')
    try:
        smtp, fromaddr = b4.get_smtp(identity, dryrun=cmdargs.dryrun)
    except Exception as ex:  # noqa
        logger.critical('Failed to configure the smtp connection:')
        logger.critical(ex)
        sys.exit(1)

    counter = 0
    cover_msgid = None
    # TODO: Need to send obsoleted-by follow-ups, just need to figure out where.
    for commit, msg in patches:
        if not msg:
            continue
        if cover_msgid is None:
            cover_msgid = b4.LoreMessage.get_clean_msgid(msg)
        msg.add_header('To', b4.format_addrs(allto))
        if allcc:
            msg.add_header('Cc', b4.format_addrs(allcc))
        logger.info('  %s', msg.get('Subject'))
        if b4.send_smtp(smtp, msg, fromaddr=fromaddr, destaddrs=alldests, patatt_sign=sign,
                        dryrun=cmdargs.dryrun):
            counter += 1

    logger.info('---')
    if cmdargs.dryrun:
        logger.info('DRYRUN: Would have sent %s messages', counter)
        return
    else:
        logger.info('Sent %s messages', counter)

    if not cover_msgid:
        return

    logger.info('Recording series message-id in cover letter tracking')
    cover, tracking = load_cover(cover_commit, strip_comments=False)
    vrev = f'v{revision}'
    if 'history' not in tracking['series']:
        tracking['series']['history'] = dict()
    if vrev not in tracking['series']['history']:
        tracking['series']['history'][vrev] = list()
    tracking['series']['history'][vrev].append(cover_msgid)
    update_cover(cover_commit, cover, tracking)


def reroll(cover_commit: str, cmdargs: argparse.Namespace) -> None:
    cover, tracking = load_cover(cover_commit, strip_comments=False)
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
    update_cover(cover_commit, new_cover, tracking)
    logger.info('You may now edit the cover letter using "b4 submit --edit-cover"')


def main(cmdargs: argparse.Namespace) -> None:
    if not can_gfr:
        logger.critical('ERROR: b4 submit requires git-filter-repo. You should be able')
        logger.critical('       to install it from your distro packages, or from pip.')
        sys.exit(1)

    config = b4.get_main_config()
    if 'submit-endpoint' not in config:
        config['submit-endpoint'] = 'https://lkml.kernel.org/_b4_submit'

    if cmdargs.new_series_name:
        start_new_series(cmdargs)

    if not check_our_branch():
        return

    cover_commit = find_cover_commit()
    if not cover_commit:
        logger.critical('CRITICAL: Unable to find cover letter commit')
        sys.exit(1)

    if cmdargs.edit_cover:
        edit_cover(cover_commit)
        return

    elif cmdargs.update_trailers:
        update_trailers(cover_commit, cmdargs)
        return

    elif cmdargs.send:
        send(cover_commit, cmdargs)
        return

    elif cmdargs.reroll:
        reroll(cover_commit, cmdargs)
        return

    logger.critical('No action requested, please see "b4 submit --help"')
    sys.exit(1)

    # if not can_patatt:
    #    logger.critical('ERROR: b4 submit requires patatt library. See:')
    #    logger.critical('       https://git.kernel.org/pub/scm/utils/patatt/patatt.git/about/')
    #    sys.exit(1)

    # if cmdargs.web_auth_new:
    #     auth_new(cmdargs)
    #
    # if cmdargs.web_auth_verify:
    #     auth_verify(cmdargs)
