#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import argparse
import datetime
import email.message
import email.utils
import json
import os
import re
import shlex
import shutil
import textwrap
import sys
import uuid

import b4
import b4.mbox
import b4.review.tracking

from typing import Dict, Any, List, Optional, Tuple

logger = b4.logger

REVIEW_MAGIC_MARKER = '--- b4-review-tracking ---'
REVIEW_BRANCH_PREFIX = 'b4/review/'


def make_review_magic_json(data: Dict[str, Any]) -> str:
    mj = (f'{REVIEW_MAGIC_MARKER}\n'
          '# This section is used internally by b4 review for tracking purposes.\n')
    return mj + json.dumps(data, indent=2)


def _collect_followups(lmsg: b4.LoreMessage, linkmask: str) -> List[Dict[str, Any]]:
    # Skip follow-up trailers already present in the message body
    # (e.g. carried over from earlier revisions via codereview_trailers)
    body_trailers = b4.LoreMessage.get_body_parts(lmsg.body)[2]
    followups_by_msgid: Dict[str, Dict[str, Any]] = {}
    for fltr in lmsg.followup_trailers:
        if fltr.lmsg is None:
            continue
        if fltr in body_trailers:
            continue
        fmsgid = fltr.lmsg.msgid
        if fmsgid not in followups_by_msgid:
            followups_by_msgid[fmsgid] = {
                'link': linkmask % fmsgid,
                'fromname': fltr.lmsg.fromname,
                'fromemail': fltr.lmsg.fromemail,
                'trailers': list(),
            }
        followups_by_msgid[fmsgid]['trailers'].append(f'{fltr.name}: {fltr.value}')
    return list(followups_by_msgid.values())


def _collect_reply_headers(lmsg: b4.LoreMessage) -> Dict[str, str]:
    try:
        allto = email.utils.getaddresses([str(x) for x in lmsg.msg.get_all('to', [])])
    except Exception as ex:
        allto = []
        logger.debug('Unable to parse the To: header in %s: %s', lmsg.msgid, str(ex))
    try:
        allcc = email.utils.getaddresses([str(x) for x in lmsg.msg.get_all('cc', [])])
    except Exception as ex:
        allcc = []
        logger.debug('Unable to parse the Cc: header in %s: %s', lmsg.msgid, str(ex))
    try:
        reply_to = email.utils.getaddresses([str(x) for x in lmsg.msg.get_all('reply-to', [])])
    except Exception as ex:
        reply_to = []
        logger.debug('Unable to parse the Reply-To: header in %s: %s', lmsg.msgid, str(ex))

    headers: Dict[str, str] = {
        'msgid': lmsg.msgid,
        'to': b4.format_addrs(allto, clean=False),
        'cc': b4.format_addrs(allcc, clean=False),
        'references': b4.LoreMessage.clean_header(lmsg.msg['References']),
        'sentdate': b4.LoreMessage.clean_header(lmsg.msg['Date']),
    }
    if reply_to:
        headers['reply-to'] = b4.format_addrs(reply_to, clean=False)
    return headers


def _retrieve_messages(message_id: str) -> List[email.message.EmailMessage]:
    """Fetch messages for a series from lore by message-id.

    Returns the list of email.message.Message objects.
    Raises LookupError if retrieval fails or returns no messages.
    """
    cmdargs = argparse.Namespace(
        msgid=message_id,
        localmbox=None,
        nocache=True,
        noparent=False,
        wantname=None,
        wantver=None,
    )
    _ret_msgid, msgs = b4.retrieve_messages(cmdargs)
    if not msgs:
        raise LookupError(f'Could not retrieve messages for {message_id}')
    return msgs


def _get_lore_series(msgs: List[email.message.EmailMessage], sloppytrailers: bool = False,
                     wantver: Optional[int] = None) -> 'b4.LoreSeries':
    """Build a LoreMailbox from messages and return the requested series version.

    When *wantver* is ``None`` (the default), the highest version found
    in the retrieved messages is used.

    Raises LookupError if no series is found.
    """
    lmbx = b4.LoreMailbox()
    for msg in msgs:
        lmbx.add_message(msg)
    if not lmbx.series:
        raise LookupError('No series found in retrieved messages')
    if wantver is None:
        wantver = max(lmbx.series.keys())
    if wantver not in lmbx.series:
        raise LookupError(f'Series version {wantver} not found in retrieved messages')
    lser = lmbx.get_series(wantver, sloppytrailers=sloppytrailers,
                           codereview_trailers=False)
    if not lser:
        raise LookupError(f'Could not find series version {wantver}')
    return lser


def get_reference_message(lser: 'b4.LoreSeries') -> 'b4.LoreMessage':
    """Return the cover letter if present, otherwise the first patch.

    Raises LookupError if neither is available.
    """
    ref_msg = None
    if lser.has_cover and lser.patches[0] is not None:
        ref_msg = lser.patches[0]
    elif len(lser.patches) > 1 and lser.patches[1] is not None:
        ref_msg = lser.patches[1]
    if ref_msg is None:
        raise LookupError('Could not find a reference message in the series')
    return ref_msg


def determine_review_branch(lser: b4.LoreSeries, cmdargs: argparse.Namespace) -> str:
    if lser.change_id:
        change_id = lser.change_id
    else:
        slug = lser.get_slug(extended=False)
        hex12 = uuid.uuid4().hex[:12]
        today = datetime.date.today().strftime('%Y%m%d')
        change_id = f'{today}-{slug}-{hex12}'

    return f'{REVIEW_BRANCH_PREFIX}{change_id}'


def create_review_branch(topdir: str, branch_name: str, base_commit: str,
                         lser: b4.LoreSeries, linkurl: str, linkmask: str,
                         num_prereqs: int = 0) -> None:
    # Verify branch does not already exist
    ecode, out = b4.git_run_command(topdir, ['rev-parse', '--verify', branch_name])
    if ecode == 0:
        logger.critical('Branch %s already exists', branch_name)
        sys.exit(1)

    # Save current branch for potential restore on error
    current_branch: Optional[str] = None
    ecode, out = b4.git_run_command(topdir, ['symbolic-ref', '--short', 'HEAD'])
    if ecode == 0:
        current_branch = out.strip()

    # Resolve base_commit to a concrete hash before checkout changes HEAD
    ecode, out = b4.git_run_command(topdir, ['rev-parse', f'{base_commit}^{{}}'], logstderr=True)
    if ecode > 0:
        logger.critical('Unable to resolve base commit %s', base_commit)
        sys.exit(1)
    resolved_base = out.strip()

    # Create and check out the review branch
    ecode, out = b4.git_run_command(topdir, ['checkout', '-b', branch_name, resolved_base],
                                    logstderr=True)
    if ecode > 0:
        logger.critical('Unable to create branch %s at %s', branch_name, resolved_base)
        logger.critical(out.strip())
        sys.exit(1)

    # Cherry-pick the applied patches from FETCH_HEAD
    ecode, out = b4.git_run_command(topdir, ['cherry-pick', f'{resolved_base}..FETCH_HEAD'],
                                    logstderr=True)
    if ecode > 0:
        logger.critical('Unable to cherry-pick patches onto review branch')
        logger.critical(out.strip())
        # Abort the cherry-pick if in progress
        b4.git_run_command(topdir, ['cherry-pick', '--abort'], logstderr=True)
        # Restore previous branch
        if current_branch:
            b4.git_run_command(topdir, ['checkout', current_branch], logstderr=True)
        b4.git_run_command(topdir, ['branch', '-D', branch_name], logstderr=True)
        sys.exit(1)

    # Record the first patch commit (the one right after base)
    ecode, out = b4.git_run_command(topdir, ['rev-list', '--reverse',
                                             f'{resolved_base}..HEAD'], logstderr=True)
    if ecode > 0 or not out.strip():
        logger.critical('Unable to determine first patch commit')
        sys.exit(1)
    all_commits = out.strip().splitlines()
    prereq_commits = all_commits[:num_prereqs]
    first_patch_commit = all_commits[num_prereqs]

    # Build cover letter content
    clmsg: Optional[b4.LoreMessage] = None
    if lser.has_cover and lser.patches[0] is not None:
        clmsg = lser.patches[0]
        parts = b4.LoreMessage.get_body_parts(clmsg.body)
        cover_content = clmsg.subject + '\n\n' + parts[1]
    elif lser.patches[1] is not None:
        clmsg = lser.patches[1]
        cover_content = (clmsg.subject + '\n\n'
                         'NOTE: No cover letter provided by the author.')
    else:
        cover_content = 'NOTE: No cover letter or first patch available.'

    # Build cover letter follow-ups and reply headers
    cover_followups = _collect_followups(clmsg, linkmask) if clmsg else list()
    cover_reply_headers = _collect_reply_headers(clmsg) if clmsg else {}

    # Build per-patch metadata
    patches_meta = list()
    for pmsg in lser.patches[1:]:
        if pmsg is None:
            continue
        patches_meta.append({
            'title': pmsg.full_subject,
            'link': linkmask % pmsg.msgid,
            'header-info': _collect_reply_headers(pmsg),
            'followups': _collect_followups(pmsg, linkmask),
        })

    # Build tracking metadata
    tracking: Dict[str, Any] = {
        'series': {
            'revision': lser.revision,
            'change-id': lser.change_id or branch_name.removeprefix(REVIEW_BRANCH_PREFIX),
            'link': linkurl,
            'subject': clmsg.full_subject if clmsg else '',
            'fromname': lser.fromname or '',
            'fromemail': lser.fromemail or '',
            'expected': lser.expected,
            'complete': lser.complete,
            'base-commit': resolved_base,
            'prerequisite-commits': prereq_commits,
            'first-patch-commit': first_patch_commit,
            'header-info': cover_reply_headers,
        },
        'followups': cover_followups,
        'patches': patches_meta,
    }

    # Create the tracking commit at the tip of the branch
    commit_msg = cover_content + '\n\n' + make_review_magic_json(tracking)

    ecode, out = b4.git_run_command(topdir, ['commit', '--allow-empty', '-F', '-'],
                                    stdin=commit_msg.encode(), logstderr=True)
    if ecode > 0:
        logger.critical('Unable to create tracking commit')
        logger.critical(out.strip())
        # Restore previous branch
        if current_branch:
            b4.git_run_command(topdir, ['checkout', current_branch], logstderr=True)
        b4.git_run_command(topdir, ['branch', '-D', branch_name], logstderr=True)
        sys.exit(1)

    logger.info('Review branch %s created successfully', branch_name)


def main(cmdargs: argparse.Namespace) -> None:
    if not hasattr(cmdargs, 'review_subcmd') or cmdargs.review_subcmd is None:
        logger.critical('Please specify a review sub-command (e.g.: b4 review tui)')
        sys.exit(1)

    if cmdargs.review_subcmd == 'tui':
        cmd_tui(cmdargs)
    elif cmdargs.review_subcmd == 'enroll':
        b4.review.tracking.cmd_enroll(cmdargs)
    elif cmdargs.review_subcmd == 'track':
        b4.review.tracking.cmd_track(cmdargs)


def get_review_branch_patch_ids(topdir: str, branch: str) -> List[Tuple[int, str, Optional[str]]]:
    """Compute stable patch-ids for every patch commit on a review branch.

    Loads tracking data to find the first-patch-commit, then iterates
    the commit range and computes ``git patch-id --stable`` for each.

    Returns a list of ``(index, sha, patch_id)`` tuples where *index*
    is zero-based and *patch_id* may be ``None`` if computation failed.
    """
    cover_text, tracking = load_tracking(topdir, branch)
    series_info = tracking.get('series', {})
    first_patch = series_info.get('first-patch-commit', '')
    if not first_patch:
        return []

    ecode, out = b4.git_run_command(
        topdir, ['rev-list', '--reverse', f'{first_patch}~1..{branch}~1'])
    if ecode > 0 or not out.strip():
        return []

    result: List[Tuple[int, str, Optional[str]]] = []
    for idx, sha in enumerate(out.strip().splitlines()):
        ecode, bpatch = b4.git_run_command(
            topdir,
            ['show', '--format=email', '--binary', '--encoding=utf-8', sha],
            decode=False,
        )
        if ecode > 0:
            result.append((idx, sha, None))
            continue
        ecode, pid_out = b4.git_run_command(
            topdir, ['patch-id', '--stable'], stdin=bpatch)
        if ecode > 0 or not pid_out.strip():
            result.append((idx, sha, None))
            continue
        patch_id = pid_out.split(maxsplit=1)[0]
        result.append((idx, sha, patch_id))
    return result


def load_tracking(topdir: str, branch: str) -> Tuple[str, Dict[str, Any]]:
    """Load and parse the tracking commit at the tip of a review branch.

    Returns (cover_text, tracking_dict).
    """
    ecode, out = b4.git_run_command(topdir, ['log', '-1', '--format=%B', branch])
    if ecode > 0:
        logger.critical('Unable to read tracking commit from %s', branch)
        sys.exit(1)

    commit_msg = out.strip()
    if REVIEW_MAGIC_MARKER not in commit_msg:
        logger.critical('Branch %s does not contain a valid review tracking commit', branch)
        sys.exit(1)

    parts = commit_msg.split(REVIEW_MAGIC_MARKER, maxsplit=1)
    cover_text = parts[0].strip()
    json_text = parts[1].strip()
    # Strip the comment line that follows the marker
    json_lines = json_text.splitlines()
    json_clean = []
    for line in json_lines:
        if line.startswith('#'):
            continue
        json_clean.append(line)
    tracking = json.loads('\n'.join(json_clean))
    return cover_text, tracking


def save_tracking_ref(topdir: str, branch: str,
                      cover_text: str, tracking: Dict[str, Any]) -> bool:
    """Amend the tracking commit at the tip of branch without checkout.

    Uses git commit-tree + git update-ref so the current working tree
    is not disturbed.  Returns True on success.
    """
    commit_msg = cover_text + '\n\n' + make_review_magic_json(tracking)
    # Get the tree from the current tip
    ecode, out = b4.git_run_command(topdir, ['rev-parse', f'{branch}^{{tree}}'])
    if ecode > 0:
        return False
    tree = out.strip()
    # Get the parent (commit below tracking commit)
    ecode, out = b4.git_run_command(topdir, ['rev-parse', f'{branch}~1'])
    if ecode > 0:
        return False
    parent = out.strip()
    # Create a new commit object with the same tree and parent
    ecode, out = b4.git_run_command(topdir,
                                    ['commit-tree', tree, '-p', parent, '-F', '-'],
                                    stdin=commit_msg.encode())
    if ecode > 0:
        return False
    new_sha = out.strip()
    # Point the branch ref at the new commit
    ecode, out = b4.git_run_command(topdir,
                                    ['update-ref', f'refs/heads/{branch}', new_sha])
    return ecode == 0


def save_tracking(topdir: str, cover_text: str, tracking: Dict[str, Any]) -> None:
    """Amend the tip tracking commit with updated metadata."""
    commit_msg = cover_text + '\n\n' + make_review_magic_json(tracking)
    ecode, out = b4.git_run_command(topdir, ['commit', '--amend', '--allow-empty', '-F', '-'],
                                    stdin=commit_msg.encode(), logstderr=True)
    if ecode > 0:
        logger.critical('Unable to amend tracking commit')
        logger.critical(out.strip())
        sys.exit(1)


def _get_my_review(target: Dict[str, Any], usercfg: Dict[str, str]) -> Dict[str, Any]:
    """Return the current user's review sub-dict (read-only; may be empty)."""
    email = usercfg.get('email', 'unknown@example.com')
    reviews: Dict[str, Any] = target.get('reviews', {})
    result: Dict[str, Any] = reviews.get(email, {})
    return result


def _ensure_my_review(target: Dict[str, Any], usercfg: Dict[str, str]) -> Dict[str, Any]:
    """Return the current user's review sub-dict, creating it if needed."""
    email = usercfg.get('email', 'unknown@example.com')
    name = usercfg.get('name', 'Unknown')
    reviews: Dict[str, Any] = target.setdefault('reviews', {})
    entry: Dict[str, Any] = reviews.setdefault(email, {})
    entry['name'] = name
    return entry


def _cleanup_review(target: Dict[str, Any], usercfg: Dict[str, str]) -> None:
    """Remove the reviewer key when its dict becomes empty (only 'name' or less)."""
    email = usercfg.get('email', 'unknown@example.com')
    reviews = target.get('reviews', {})
    if email in reviews:
        entry = reviews[email]
        # Consider empty if only 'name' key or no keys at all
        non_name_keys = [k for k in entry if k != 'name']
        if not non_name_keys:
            del reviews[email]
    if 'reviews' in target and not target['reviews']:
        del target['reviews']


def _extract_patch_comments(edited: str, track_content: bool = False,
                            delimited_only: bool = False) -> List[Dict[str, Any]]:
    """Walk the edited patch and extract maintainer comments.

    Returns a list of dicts: [{'path': 'b/file.c', 'line': 42, 'text': '...'}, ...]
    Everything before the first "diff --git" line is ignored (instructions).
    Inside hunks, any line that is not a valid diff line (starting with
    " ", "+", "-", or "\\") is treated as a maintainer comment.  Multiline
    comments use ``>`` / ``<`` delimiters: a line consisting entirely of
    ``>`` characters opens a comment block and a line consisting entirely of
    ``<`` characters closes it (an optional leading ``+`` is tolerated for
    agent compatibility).  Comments are mapped to the nearest preceding diff
    line.  The maintainer may delete hunks they are not interested in;
    remaining hunks must be left intact.

    When *track_content* is True, each comment dict also includes a
    ``'content'`` key with the text of the last diff line before the
    comment.  This is used by :func:`_resolve_comment_positions` to
    fix line-number drift when the agent omits diff lines.

    When *delimited_only* is True, only comments inside delimiter
    blocks are collected.  Bare non-diff lines in hunks are ignored
    (they are likely context lines with stripped leading whitespace).
    Use this for agent-produced reviews where comments are always
    delimited.
    """
    edit_lines = edited.splitlines()

    # Parser states
    NORMAL = 0
    COMMENT_HEADER = 1
    COMMENT_BODY = 2
    COMMENT_TRAILER = 3

    # Skip everything before the first "diff --git" line
    in_diff = False
    in_hunk = False
    current_a_file = ''
    current_b_file = ''
    a_line = 0
    b_line = 0
    last_diff_path = ''
    last_diff_line = 0
    last_diff_content = ''

    hunk_re = re.compile(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@')
    comments: List[Dict[str, Any]] = []
    pending_comment_lines: List[str] = []
    state = NORMAL

    def _flush_comment() -> None:
        if pending_comment_lines and last_diff_path:
            text = '\n'.join(pending_comment_lines).strip()
            if text:
                comment: Dict[str, Any] = {
                    'path': last_diff_path,
                    'line': last_diff_line,
                    'text': text,
                }
                if track_content and last_diff_content:
                    comment['content'] = last_diff_content
                comments.append(comment)
        pending_comment_lines.clear()

    for line in edit_lines:
        if not in_diff:
            if line.startswith('diff --git '):
                in_diff = True
                in_hunk = False
            else:
                continue

        stripped = line.strip()

        # Comment header: skip decorative > lines until body starts
        if state == COMMENT_HEADER:
            if stripped.startswith('>') or stripped.startswith('+>'):
                continue
            state = COMMENT_BODY
            # Fall through to COMMENT_BODY handling below

        # Comment body: collect lines until closing < delimiter
        if state == COMMENT_BODY:
            if re.fullmatch(r'\+?<+', stripped):
                _flush_comment()
                state = COMMENT_TRAILER
                continue
            # Strip leading "+" that agents add when they confuse
            # comment text with diff addition lines.
            cline = line[1:] if line.startswith('+') else line
            pending_comment_lines.append(cline)
            continue

        # Comment trailer: skip decorative < lines until normal resumes
        if state == COMMENT_TRAILER:
            if stripped.startswith('<') or stripped.startswith('+<'):
                continue
            state = NORMAL
            # Fall through to normal processing of this line

        # NORMAL state — check for comment open delimiter before
        # anything else so it does not advance line counters.
        if re.fullmatch(r'\+?>+', stripped):
            _flush_comment()
            state = COMMENT_HEADER
            continue

        # Track file and hunk structure
        if line.startswith('diff --git '):
            _flush_comment()
            in_hunk = False
            continue
        if line.startswith('--- a/') or line.startswith('--- /dev/null'):
            _flush_comment()
            current_a_file = line[4:]
            continue
        if line.startswith('+++ b/') or line.startswith('+++ /dev/null'):
            _flush_comment()
            current_b_file = line[4:]
            continue
        if line.startswith('--- ') or line.startswith('+++ '):
            _flush_comment()
            continue

        hm = hunk_re.match(line)
        if hm:
            _flush_comment()
            a_line = int(hm.group(1))
            b_line = int(hm.group(2))
            last_diff_path = current_b_file
            last_diff_line = b_line
            in_hunk = True
            continue

        if in_hunk and (line.startswith(' ') or line.startswith('+')
                        or line.startswith('-') or line.startswith('\\')
                        or line == ''):
            # Valid diff line — flush any pending comment first
            _flush_comment()
            if line.startswith('-'):
                last_diff_path = current_a_file
                last_diff_line = a_line
                last_diff_content = line
                a_line += 1
            elif line.startswith('+'):
                last_diff_path = current_b_file
                last_diff_line = b_line
                last_diff_content = line
                b_line += 1
            elif line == '':
                last_diff_path = current_b_file
                last_diff_line = b_line
                last_diff_content = line
                a_line += 1
                b_line += 1
            elif line.startswith(' '):
                last_diff_path = current_b_file
                last_diff_line = b_line
                last_diff_content = line
                a_line += 1
                b_line += 1
            # "\ No newline at end of file" — no line tracking needed
            continue

        # Anything else inside a hunk is a comment (no prefix needed)
        if in_hunk and not delimited_only:
            pending_comment_lines.append(line)
            continue

        # Outside a hunk: structural lines (index, mode, etc.) — ignore
        _flush_comment()

    # Flush any trailing comment
    _flush_comment()

    return comments


def _resolve_comment_positions(
    diff_text: str,
    comments: List[Dict[str, Any]],
) -> None:
    """Resolve comment positions using line content against the real diff.

    When an agent omits diff lines from a review file, the counted line
    numbers drift.  This function walks the actual diff, builds a mapping
    from line content text to the correct ``(path, line)`` pair, and
    updates each comment that carries a ``content`` key to the correct
    position.  Comments without ``content`` (or whose content is not
    found) keep their original counted position.
    """
    if not comments:
        return

    # Only bother if at least one comment has content to resolve
    to_resolve = [c for c in comments if c.get('content')]
    if not to_resolve:
        return

    hunk_re = re.compile(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@')
    current_a_file = ''
    current_b_file = ''
    a_line = 0
    b_line = 0

    # Map content text -> (path, line); last occurrence wins if
    # duplicates exist, but that is unlikely for real diff lines.
    content_map: Dict[str, Tuple[str, int]] = {}

    for line in diff_text.splitlines():
        if line.startswith('--- a/') or line.startswith('--- /dev/null'):
            current_a_file = line[4:]
            continue
        if line.startswith('+++ b/') or line.startswith('+++ /dev/null'):
            current_b_file = line[4:]
            continue
        if line.startswith('--- ') or line.startswith('+++ '):
            continue
        if line.startswith('diff --git '):
            continue

        hm = hunk_re.match(line)
        if hm:
            a_line = int(hm.group(1))
            b_line = int(hm.group(2))
            continue

        if line.startswith('-'):
            content_map[line] = (current_a_file, a_line)
            a_line += 1
        elif line.startswith('+'):
            content_map[line] = (current_b_file, b_line)
            b_line += 1
        elif line.startswith(' ') or line == '':
            content_map[line] = (current_b_file, b_line)
            a_line += 1
            b_line += 1

    for c in to_resolve:
        content = c['content']
        if content in content_map:
            c['path'], c['line'] = content_map[content]


def reanchor_patch_comments(
    topdir: str,
    commit_shas: List[str],
    patches: List[Dict[str, Any]],
) -> None:
    """Re-anchor inline comment positions against current diffs.

    For each patch that has reviews with comments carrying a ``content``
    key, generate the diff from the corresponding commit SHA and call
    :func:`_resolve_comment_positions` to fix line-number drift.
    """
    for idx, sha in enumerate(commit_shas):
        if idx >= len(patches):
            break
        reviews = patches[idx].get('reviews')
        if not reviews:
            continue
        real_diff: Optional[str] = None
        for reviewer_data in reviews.values():
            comments = reviewer_data.get('comments')
            if not comments or not any(c.get('content') for c in comments):
                continue
            if real_diff is None:
                ecode, real_diff = b4.git_run_command(
                    topdir, ['diff', f'{sha}~1', sha])
                if ecode != 0:
                    break
            _resolve_comment_positions(real_diff, comments)


def _clear_other_comments(
    all_reviews: Dict[str, Dict[str, Any]],
    my_email: str,
) -> bool:
    """Remove inline comments from all reviewers other than *my_email*.

    When the maintainer edits inline comments, all comments are
    presented as unattributed blocks and become the maintainer's own
    on save.  This function cleans up the now-superseded originals.

    Returns True if any comments were removed.
    """
    cleared = False
    for r_email in list(all_reviews):
        if r_email == my_email:
            continue
        r_data = all_reviews[r_email]
        if 'comments' not in r_data:
            continue
        del r_data['comments']
        cleared = True
        # Clean up reviewer entry if only 'name' remains
        non_name_keys = [k for k in r_data if k != 'name']
        if not non_name_keys:
            del all_reviews[r_email]
    return cleared


def _integrate_agent_reviews(
    topdir: str,
    cover_text: str,
    tracking: Dict[str, Any],
    commit_shas: List[str],
    patches: List[Dict[str, Any]],
) -> bool:
    """Read review files from .git/b4-review/<HEAD-sha>/ and merge into tracking.

    The directory-based layout uses:
    - ``identity.txt`` for reviewer attribution (``Name <email>``)
    - ``series.txt`` for cover letter review (plain text note)
    - ``NNNN.txt`` (1-indexed) for per-patch reviews with annotated diffs

    Consumption is implicit: :func:`save_tracking` amends HEAD, changing
    its SHA so the directory no longer matches on the next run.

    Returns True if any reviews were integrated.
    """
    series = tracking['series']

    # Resolve HEAD SHA
    ecode, out = b4.git_run_command(topdir, ['rev-parse', 'HEAD'])
    if ecode != 0:
        return False
    head_sha = out.strip()

    review_dir = os.path.join(topdir, '.git', 'b4-review', head_sha)
    if not os.path.isdir(review_dir):
        return False

    # Read identity.txt
    identity_path = os.path.join(review_dir, 'identity.txt')
    try:
        with open(identity_path, 'r') as fh:
            identity_line = fh.read().strip()
    except OSError:
        logger.warning('b4-review/%s: missing identity.txt, skipping', head_sha[:12])
        return False

    m = re.match(r'^(.+?)\s+<([^>]+)>', identity_line)
    if not m:
        logger.warning('b4-review/%s: malformed identity.txt, skipping', head_sha[:12])
        return False
    reviewer_name = m.group(1)
    reviewer_email = m.group(2)

    integrated = 0

    # Read series.txt (cover letter review)
    series_path = os.path.join(review_dir, 'series.txt')
    try:
        with open(series_path, 'r') as fh:
            series_note = fh.read().strip()
    except OSError:
        series_note = ''

    if series_note:
        series_reviews: Dict[str, Any] = series.setdefault('reviews', {})
        entry: Dict[str, Any] = series_reviews.setdefault(reviewer_email, {})
        entry['name'] = reviewer_name
        old_note = entry.get('note', '')
        if old_note:
            entry['note'] = old_note + '\n\n' + series_note
        else:
            entry['note'] = series_note
        integrated += 1

    # Read NNNN.txt files (per-patch reviews, 1-indexed)
    try:
        entries = sorted(f for f in os.listdir(review_dir)
                         if re.match(r'^\d{4}\.txt$', f))
    except OSError:
        entries = []

    for fname in entries:
        patch_num = int(fname[:4])  # 1-indexed
        idx = patch_num - 1
        if idx < 0 or idx >= len(patches):
            logger.warning('b4-review/%s/%s: patch number out of range, skipping',
                           head_sha[:12], fname)
            continue
        if idx >= len(commit_shas):
            logger.warning('b4-review/%s/%s: no commit SHA for patch %d, skipping',
                           head_sha[:12], fname, patch_num)
            continue

        fpath = os.path.join(review_dir, fname)
        try:
            with open(fpath, 'r') as fh:
                file_text = fh.read()
        except OSError:
            continue

        # Split into overall note (before first diff --git) and diff portion
        note_text = ''
        diff_portion = ''
        diff_idx = file_text.find('\ndiff --git ')
        if diff_idx < 0 and file_text.startswith('diff --git '):
            diff_portion = file_text
        elif diff_idx >= 0:
            note_text = file_text[:diff_idx].strip()
            diff_portion = file_text[diff_idx + 1:]  # skip the leading newline
        else:
            note_text = file_text.strip()

        # Extract inline comments from the diff portion
        comments: List[Dict[str, Any]] = []
        if diff_portion:
            comments = _extract_patch_comments(diff_portion, track_content=True,
                                                       delimited_only=True)

        # Resolve comment positions against the real diff
        if comments:
            sha = commit_shas[idx]
            ecode, real_diff = b4.git_run_command(topdir, ['diff', f'{sha}~1', sha])
            if ecode == 0:
                _resolve_comment_positions(real_diff, comments)

        if not note_text and not comments:
            continue

        # Store in patches[idx]['reviews'][email]
        patch = patches[idx]
        patch_reviews: Dict[str, Any] = patch.setdefault('reviews', {})
        entry = patch_reviews.setdefault(reviewer_email, {})
        entry['name'] = reviewer_name
        if comments:
            existing_comments: List[Dict[str, Any]] = entry.setdefault('comments', [])
            existing_comments.extend(comments)
        if note_text:
            old_note = entry.get('note', '')
            if old_note:
                entry['note'] = old_note + '\n\n' + note_text
            else:
                entry['note'] = note_text
        integrated += 1

    if not integrated:
        return False

    # Save tracking — this amends HEAD, changing its SHA so the
    # directory is not re-consumed on the next run.
    save_tracking(topdir, cover_text, tracking)
    logger.info('Integrated agent review data from %d file(s) in b4-review/%s',
                integrated, head_sha[:12])

    # Clean up the consumed review directory
    shutil.rmtree(review_dir, ignore_errors=True)

    return True


def _reinsert_comments(diff_text: str, comments: List[Dict[str, Any]]) -> str:
    """Re-insert stored comments into a diff at their original positions.

    Walks the diff tracking file paths and line numbers, and after each
    diff line that matches a stored comment location, inserts the comment
    wrapped in ``>`` / ``>>>`` … ``<<<`` / ``<`` delimiters.
    """
    if not comments:
        return diff_text

    # Build lookup: (path, line) -> list of comment texts (in order)
    comment_map: Dict[Tuple[str, int], List[str]] = {}
    for c in comments:
        key = (c['path'], c['line'])
        comment_map.setdefault(key, []).append(c['text'])

    diff_lines = diff_text.splitlines()
    result: List[str] = []
    current_a_file = ''
    current_b_file = ''
    a_line = 0
    b_line = 0
    hunk_re = re.compile(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@')

    def _insert_comments(key: Tuple[str, int]) -> None:
        for text in comment_map.pop(key, []):
            # Wrap long single-line comments at 78 chars
            text_lines = text.splitlines()
            if len(text_lines) == 1 and len(text_lines[0]) > 78:
                text_lines = textwrap.wrap(text_lines[0], width=78)
            result.append('>')
            result.append('>>>')
            result.append('')
            for cline in text_lines:
                result.append(cline)
            result.append('')
            result.append('<<<')
            result.append('<')

    for line in diff_lines:
        result.append(line)

        # Track file and hunk structure to determine position
        if line.startswith('--- a/') or line.startswith('--- /dev/null'):
            current_a_file = line[4:]
        elif line.startswith('+++ b/') or line.startswith('+++ /dev/null'):
            current_b_file = line[4:]
        elif line.startswith('--- ') or line.startswith('+++ '):
            pass
        elif line.startswith('diff --git '):
            pass
        else:
            hm = hunk_re.match(line)
            if hm:
                a_line = int(hm.group(1))
                b_line = int(hm.group(2))
            elif line.startswith('-'):
                _insert_comments((current_a_file, a_line))
                a_line += 1
            elif line.startswith('+'):
                _insert_comments((current_b_file, b_line))
                b_line += 1
            elif line.startswith(' ') or line == '':
                # Empty lines are context lines with a stripped leading space
                _insert_comments((current_b_file, b_line))
                a_line += 1
                b_line += 1

    return '\n'.join(result) + '\n'


def _reinsert_all_comments(
    diff_text: str,
    all_reviews: Dict[str, Dict[str, Any]],
    my_email: str,
) -> str:
    """Re-insert comments from all reviewers into a diff.

    All comments are inserted as ``>`` / ``>>>`` … ``<<<`` / ``<``
    blocks regardless of their origin.  When the maintainer saves the edited
    diff, every comment becomes attributed to them and existing
    reviewer comments for this patch should be cleared by the caller.
    """
    # Collect all comments into one flat list, own first
    all_comments: List[Dict[str, Any]] = []
    if my_email in all_reviews:
        all_comments.extend(all_reviews[my_email].get('comments', []))
    for email in sorted(all_reviews):
        if email != my_email:
            all_comments.extend(all_reviews[email].get('comments', []))

    return _reinsert_comments(diff_text, all_comments)


def _build_reply_from_comments(diff_text: str,
                               comments: List[Dict[str, Any]],
                               review_trailers: List[str],
                               commit_msg: Optional[str] = None) -> str:
    """Build an email reply body from review comments.

    For each hunk that has comments, quotes the hunk up to the commented
    line, inserts the comment unquoted, and continues quoting. Hunks
    without comments are skipped. Trailers are appended at the end.

    If commit_msg is provided, the commit message body (minus the subject
    line) is quoted before the diff content.
    """
    # Build lookup: (path, line) -> list of comment texts
    comment_map: Dict[Tuple[str, int], List[str]] = {}
    for c in comments:
        key = (c['path'], c['line'])
        comment_map.setdefault(key, []).append(c['text'])

    # Determine which files+hunks have comments so we can skip the rest
    comment_files: set[str] = set()
    for c in comments:
        # Strip a/ or b/ prefix to get the plain path for file-level matching
        comment_files.add(c['path'])

    result: List[str] = []

    # Optionally quote the commit message body (minus the subject line)
    if commit_msg:
        msg_lines = commit_msg.strip().splitlines()
        if msg_lines:
            msg_lines = msg_lines[1:]
            while msg_lines and not msg_lines[0].strip():
                msg_lines.pop(0)
        for line in msg_lines:
            result.append(f'> {line}')
        if msg_lines:
            result.append('>')

    # Walk the diff, collecting hunks and inserting comments
    diff_lines = diff_text.splitlines()
    current_a_file = ''
    current_b_file = ''
    a_line = 0
    b_line = 0
    hunk_re = re.compile(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@')

    # First pass: figure out which hunks have comments by collecting
    # hunk line ranges and checking against comment_map keys
    # We'll do this in a single pass instead, buffering hunk lines
    # and flushing them only if the hunk had comments.

    hunk_buf: List[str] = []
    hunk_comments: List[Tuple[int, str]] = []
    in_hunk = False
    hunk_has_file_header = False
    file_header_buf: List[str] = []
    file_header_emitted = False

    def _flush_hunk() -> None:
        nonlocal file_header_emitted
        if not hunk_comments:
            hunk_buf.clear()
            return
        # Emit file header if not yet done
        if not file_header_emitted and file_header_buf:
            if result:
                result.append('>')
            for fh_line in file_header_buf:
                result.append(f'> {fh_line}')
            file_header_emitted = True
        # Build hunk output with comments inserted
        # hunk_comments: list of (index_in_buf, comment_text)
        # Sort by index to insert in order
        insert_map: Dict[int, List[str]] = {}
        for idx, text in hunk_comments:
            insert_map.setdefault(idx, []).append(text)
        last_comment_idx = max(insert_map)
        for i, hline in enumerate(hunk_buf):
            if i > last_comment_idx:
                break
            result.append(f'> {hline}')
            if i in insert_map:
                for text in insert_map[i]:
                    result.append('')
                    result.append(text)
                    result.append('')
        hunk_buf.clear()
        hunk_comments.clear()

    for line in diff_lines:
        if line.startswith('diff --git '):
            _flush_hunk()
            in_hunk = False
            file_header_buf.clear()
            file_header_buf.append(line)
            file_header_emitted = False
            continue

        if line.startswith('--- a/') or line.startswith('--- /dev/null'):
            current_a_file = line[4:]
            file_header_buf.append(line)
            continue
        if line.startswith('+++ b/') or line.startswith('+++ /dev/null'):
            current_b_file = line[4:]
            file_header_buf.append(line)
            continue
        if line.startswith('--- ') or line.startswith('+++ '):
            file_header_buf.append(line)
            continue

        hm = hunk_re.match(line)
        if hm:
            _flush_hunk()
            a_line = int(hm.group(1))
            b_line = int(hm.group(2))
            in_hunk = True
            hunk_buf.append(line)
            continue

        if not in_hunk:
            # Could be index/mode lines etc., add to file header
            file_header_buf.append(line)
            continue

        buf_idx = len(hunk_buf)
        hunk_buf.append(line)

        if line.startswith('-'):
            key = (current_a_file, a_line)
            for text in comment_map.pop(key, []):
                hunk_comments.append((buf_idx, text))
            a_line += 1
        elif line.startswith('+'):
            key = (current_b_file, b_line)
            for text in comment_map.pop(key, []):
                hunk_comments.append((buf_idx, text))
            b_line += 1
        elif line.startswith(' ') or line == '':
            key = (current_b_file, b_line)
            for text in comment_map.pop(key, []):
                hunk_comments.append((buf_idx, text))
            a_line += 1
            b_line += 1

    _flush_hunk()

    # Append trailers
    if review_trailers:
        result.append('')
        for t in review_trailers:
            result.append(t)

    return '\n'.join(result)


def update_series_tracking(
    series: Dict[str, Any],
    identifier: str,
    linkmask: str,
    topdir: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch thread, discover revisions, update trailers for one series.

    Returns {'new_revisions': int, 'new_trailers': int,
             'error': Optional[str]}.
    """
    from typing import Set

    result: Dict[str, Any] = {
        'new_revisions': 0,
        'new_trailers': 0,
        'error': None,
    }

    message_id = series.get('message_id', '')
    change_id = series.get('change_id', '')
    current_rev = series.get('revision', 1)
    status = series.get('status', 'new')

    if not message_id:
        result['error'] = 'No message-id for this series'
        return result

    try:
        msgs = _retrieve_messages(message_id)
    except (LookupError, Exception) as ex:
        result['error'] = str(ex)
        return result

    # Discover all available revisions (newer and older)
    if b4.can_network:
        msgs = b4.mbox.get_extra_series(msgs, direction=1, nocache=True)
        if current_rev > 1:
            msgs = b4.mbox.get_extra_series(msgs, direction=-1,
                                            wantvers=list(range(1, current_rev)),
                                            nocache=True)

    lmbx = b4.LoreMailbox()
    for msg in msgs:
        lmbx.add_message(msg)

    # Record all discovered revisions in SQLite
    try:
        conn = b4.review.tracking.get_db(identifier)
        existing_revs = set(r['revision'] for r in b4.review.tracking.get_revisions(conn, change_id))
        for v in sorted(lmbx.series.keys()):
            v_ser = lmbx.series[v]
            v_msgid = ''
            v_subject = ''
            if hasattr(v_ser, 'patches') and v_ser.patches:
                for p in v_ser.patches:
                    if p is not None:
                        v_msgid = p.msgid
                        v_subject = getattr(p, 'full_subject', '') or getattr(p, 'subject', '')
                        break
            v_link = (linkmask % v_msgid) if v_msgid and '%s' in str(linkmask) else ''
            b4.review.tracking.add_revision(conn, change_id, v, v_msgid, v_subject, v_link)
            if v not in existing_revs:
                result['new_revisions'] += 1
        conn.close()
    except Exception as ex:
        logger.warning('Could not record revisions: %s', ex)

    newer_vers = sorted(v for v in lmbx.series if v > current_rev)

    # Auto-promote waiting series when a newer revision is discovered
    if status == 'waiting' and newer_vers:
        try:
            conn = b4.review.tracking.get_db(identifier)
            b4.review.tracking.update_series_status(
                conn, change_id, 'reviewing',
                revision=series.get('revision'))
            conn.close()
            result['promoted'] = True
        except Exception as ex:
            logger.warning('Could not promote waiting series: %s', ex)

    # Update follow-up trailers if the series has a review branch
    if status in ('reviewing', 'replied', 'waiting') and topdir:
        branch = f'b4/review/{change_id}'
        wantver = current_rev

        try:
            cover_text, tracking = load_tracking(topdir, branch)
        except SystemExit:
            result['error'] = f'Could not load tracking data from {branch}'
            return result

        t_series = tracking.get('series', {})

        # Update newer-versions in tracking data
        if newer_vers:
            t_series['newer-versions'] = newer_vers
        else:
            t_series.pop('newer-versions', None)

        lser = lmbx.get_series(wantver, sloppytrailers=False,
                               codereview_trailers=True)
        if lser is None:
            result['error'] = f'Could not find series v{wantver} in retrieved messages'
            return result

        # Collect fresh cover followups
        clmsg = lser.patches[0] if lser.has_cover and lser.patches[0] is not None else None
        new_cover_followups = _collect_followups(clmsg, linkmask) if clmsg else list()

        # Collect fresh per-patch followups
        new_patch_followups: List[Any] = []
        for pmsg in lser.patches[1:]:
            if pmsg is None:
                new_patch_followups.append([])
                continue
            new_patch_followups.append(_collect_followups(pmsg, linkmask))

        # Count new trailers by diffing against existing data
        def _trailer_set(followups: List[Any]) -> Set[str]:
            s: Set[str] = set()
            for fu in followups:
                for t in fu.get('trailers', []):
                    s.add(t.lower())
            return s

        old_cover = _trailer_set(tracking.get('followups', []))
        new_cover = _trailer_set(new_cover_followups)
        new_count = len(new_cover - old_cover)

        patches = tracking.get('patches', [])
        for i, new_fu in enumerate(new_patch_followups):
            if i < len(patches):
                old_set = _trailer_set(patches[i].get('followups', []))
            else:
                old_set = set()
            new_count += len(_trailer_set(new_fu) - old_set)

        result['new_trailers'] = new_count

        # Update tracking data
        tracking['followups'] = new_cover_followups
        for i, new_fu in enumerate(new_patch_followups):
            if i < len(patches):
                patches[i]['followups'] = new_fu

        # Save using ref update (no checkout needed)
        if not save_tracking_ref(topdir, branch, cover_text, tracking):
            result['error'] = 'Error saving tracking data'
            return result

    return result


def cmd_tui(cmdargs: argparse.Namespace) -> None:
    try:
        import b4.review_tui  # noqa: F401
    except ImportError:
        logger.critical('The TUI requires the textual library.')
        logger.critical('Install it with: pip install b4[tui]')
        sys.exit(1)

    identifier = b4.review.tracking.resolve_identifier(cmdargs)
    if not identifier:
        logger.critical('Could not determine project identifier.')
        logger.critical('First run "b4 review enroll" or specify -i identifier')
        sys.exit(1)

    if not b4.review.tracking.db_exists(identifier):
        logger.critical('Project not enrolled: %s', identifier)
        logger.critical('Enroll with: b4 review enroll')
        sys.exit(1)

    b4.review_tui.run_tracking_tui(identifier, email_dryrun=cmdargs.email_dryrun)


def _prepare_review_session(cmdargs: argparse.Namespace) -> Dict[str, Any]:
    """Common setup for review tui.

    Returns dict with: topdir, branch, cover_text, tracking, series,
    patches, base_commit, commit_shas, commit_subjects, sha_map,
    abbrev_len, check_cmds, default_identity, usercfg,
    cover_subject_clean
    """
    topdir = b4.git_get_toplevel()
    if not topdir:
        logger.critical('Not in a git repository.')
        sys.exit(1)

    branch = cmdargs.branch
    if branch is None:
        ecode, out = b4.git_run_command(topdir, ['symbolic-ref', '--short', 'HEAD'])
        if ecode > 0:
            logger.critical('Could not determine current branch (detached HEAD?)')
            sys.exit(1)
        branch = out.strip()

    if not branch.startswith(REVIEW_BRANCH_PREFIX):
        logger.critical('Branch %s does not look like a review branch (expected prefix %s)',
                        branch, REVIEW_BRANCH_PREFIX)
        sys.exit(1)

    # Ensure we are on the review branch
    ecode, out = b4.git_run_command(topdir, ['symbolic-ref', '--short', 'HEAD'])
    current_branch = out.strip() if ecode == 0 else None
    if current_branch != branch:
        ecode, out = b4.git_run_command(topdir, ['checkout', branch], logstderr=True)
        if ecode > 0:
            logger.critical('Could not check out branch %s', branch)
            logger.critical(out.strip())
            sys.exit(1)

    cover_text, tracking = load_tracking(topdir, branch)
    series = tracking['series']
    patches = tracking['patches']
    base_commit = series['base-commit']

    # Determine abbreviation length from core.abbrev (default: git decides)
    ecode, out = b4.git_run_command(topdir, ['rev-parse', '--short', 'HEAD'])
    abbrev_len = len(out.strip()) if ecode == 0 else 7

    # Get ordered commit SHAs (excluding the tracking commit at tip)
    # Use first-patch-commit to skip any prerequisite commits
    first_patch = series.get('first-patch-commit', '')
    if first_patch:
        range_spec = f'{first_patch}~1..HEAD~1'
    else:
        range_spec = f'{base_commit}..HEAD~1'
    ecode, out = b4.git_run_command(topdir, ['rev-list', '--reverse', range_spec])
    if ecode > 0 or not out.strip():
        logger.critical('Unable to list patch commits')
        sys.exit(1)
    commit_shas = out.strip().splitlines()

    # Get commit subjects
    ecode, out = b4.git_run_command(topdir, ['log', '--reverse', '--format=%s',
                                              range_spec])
    if ecode > 0:
        logger.critical('Unable to get commit subjects')
        sys.exit(1)
    commit_subjects = out.strip().splitlines()

    # Build mapping: short SHA -> (full SHA, patch index)
    sha_map: Dict[str, Tuple[str, int]] = {}
    for idx, full_sha in enumerate(commit_shas):
        short_sha = full_sha[:abbrev_len]
        sha_map[short_sha] = (full_sha, idx)

    # Parse cover subject (strip email prefixes like [PATCH v2 0/3])
    cover_subject = series.get('subject', '')
    # Remove [PATCH ...] prefix if present
    cover_subject_clean = re.sub(r'^\[.*?\]\s*', '', cover_subject)
    if not cover_subject_clean:
        cover_subject_clean = cover_text.split('\n', maxsplit=1)[0] if cover_text else '(no subject)'

    # Get user identity for trailers (needed throughout the loop)
    usercfg = b4.get_user_config()
    user_name = usercfg.get('name', 'Unknown')
    user_email = usercfg.get('email', 'unknown@example.com')
    default_identity = f'{user_name} <{user_email}>'

    # Set up per-patch check commands
    config = b4.get_main_config()
    _checkcfg = config.get('review-perpatch-check-cmd')
    checkcmds: List[str] = []
    if isinstance(_checkcfg, str):
        checkcmds = [_checkcfg]
    elif isinstance(_checkcfg, list):
        checkcmds = _checkcfg
    if not checkcmds:
        # Use recommended checkpatch defaults if we find checkpatch
        checkpatch = os.path.join(topdir, 'scripts', 'checkpatch.pl')
        if os.access(checkpatch, os.X_OK):
            checkcmds = [f'{checkpatch} -q --terse --no-summary --mailback']
    check_cmds: List[List[str]] = []
    for cmdstr in checkcmds:
        sp = shlex.shlex(cmdstr, posix=True)
        sp.whitespace_split = True
        check_cmds.append(list(sp))

    # Integrate agent reviews from .git/b4-review/
    _integrate_agent_reviews(topdir, cover_text, tracking, commit_shas, patches)

    return {
        'topdir': topdir,
        'branch': branch,
        'cover_text': cover_text,
        'tracking': tracking,
        'series': series,
        'patches': patches,
        'base_commit': base_commit,
        'commit_shas': commit_shas,
        'commit_subjects': commit_subjects,
        'sha_map': sha_map,
        'abbrev_len': abbrev_len,
        'check_cmds': check_cmds,
        'default_identity': default_identity,
        'usercfg': usercfg,
        'cover_subject_clean': cover_subject_clean,
    }


def _ensure_trailers_in_body(body: str, trailers: List[str]) -> str:
    """Ensure all trailers appear in the body text.

    Checks the body for existing trailers using LoreMessage.find_trailers
    and appends any missing ones before the signature block (if present).
    """
    if not trailers:
        return body
    found, _ = b4.LoreMessage.find_trailers(body, followup=True)
    found_set = set()
    for lt in found:
        found_set.add(lt.as_string().lower())
    missing = [t for t in trailers if t.lower() not in found_set]
    if not missing:
        return body
    # Append missing trailers before the signature (if any)
    parts = body.split('\n-- \n', maxsplit=1)
    main_body = parts[0].rstrip()
    main_body += '\n\n' + '\n'.join(missing)
    if len(parts) > 1:
        main_body += '\n\n-- \n' + parts[1]
    return main_body


def _build_review_email(series: Dict[str, Any], patch_meta: Optional[Dict[str, Any]],
                        review: Dict[str, Any], cover_text: str,
                        topdir: str, commit_sha: Optional[str]) -> Optional[email.message.EmailMessage]:
    """Build an EmailMessage for a single review entry (cover or patch).

    Returns None if there is nothing to send.
    """
    trailers = review.get('trailers', [])
    reply_text = review.get('reply', '')
    comments = review.get('comments', [])

    if not trailers and not reply_text and not comments:
        return None

    # Determine header info and subject
    if patch_meta is not None:
        header_info = patch_meta.get('header-info', {})
        orig_subject = patch_meta.get('title', '')
    else:
        header_info = series.get('header-info', {})
        orig_subject = series.get('subject', '')

    if not header_info.get('msgid'):
        logger.debug('No message-id for %s, skipping', orig_subject)
        return None

    # Build attribution line for auto-generated replies
    orig_date = header_info.get('sentdate', '')
    orig_author = f'{series.get("fromname", "")} <{series.get("fromemail", "")}>'
    attribution = f'On {orig_date}, {orig_author} wrote:'

    # Build body
    if reply_text:
        body = reply_text.strip()
    elif comments and commit_sha and topdir:
        # Auto-generate reply from inline review comments
        ecode, commit_msg = b4.git_run_command(
            topdir, ['show', '--format=%B', '--no-patch', commit_sha])
        if ecode > 0:
            logger.warning('Could not get commit message for %s', commit_sha)
            return None
        ecode, diff_text = b4.git_run_command(
            topdir, ['diff', f'{commit_sha}~1', commit_sha])
        if ecode > 0:
            logger.warning('Could not get diff for %s', commit_sha)
            return None
        body = attribution + '\n' + _build_reply_from_comments(
            diff_text, comments, trailers)
    else:
        # Trailer-only reply: quote the first paragraph of the original
        if patch_meta is not None and commit_sha and topdir:
            ecode, commit_msg = b4.git_run_command(
                topdir, ['show', '--format=%B', '--no-patch', commit_sha])
            if ecode == 0 and commit_msg.strip():
                # Strip the subject line (already in Subject: Re: header)
                cm_lines = commit_msg.strip().splitlines()
                cm_body = '\n'.join(cm_lines[1:]).lstrip('\n')
                body = attribution + '\n' + b4.make_quote(cm_body) + '\n\n' + '\n'.join(trailers) \
                    if cm_body else \
                    attribution + '\n' + b4.make_quote(cover_text) + '\n\n' + '\n'.join(trailers)
            else:
                body = attribution + '\n' + b4.make_quote(cover_text) + '\n\n' + '\n'.join(trailers)
        else:
            body = attribution + '\n' + b4.make_quote(cover_text) + '\n\n' + '\n'.join(trailers)

    # Ensure all trailers appear in the body
    body = _ensure_trailers_in_body(body, trailers)

    # Append signature if not already present
    if '\n-- \n' not in body:
        signature = b4.get_email_signature()
        body += '\n\n-- \n' + signature

    # Construct the EmailMessage
    usercfg = b4.get_user_config()
    user_name = usercfg.get('name', 'Unknown')
    user_email = usercfg.get('email', 'unknown@example.com')

    msg = email.message.EmailMessage()
    msg.set_payload(body, charset='utf-8')

    subject = orig_subject
    if not subject.lower().startswith('re:'):
        subject = f'Re: {subject}'
    msg['Subject'] = subject
    msg['From'] = f'{user_name} <{user_email}>'

    # Build proper reply headers: Reply-To or From as To,
    # original To folded into Cc
    if header_info.get('reply-to'):
        to_addrs = email.utils.getaddresses([header_info['reply-to']])
    else:
        fromname = series.get('fromname', '')
        fromemail = series.get('fromemail', '')
        to_addrs = [(fromname, fromemail)]
    orig_to = email.utils.getaddresses([header_info.get('to', '')])
    orig_cc = email.utils.getaddresses([header_info.get('cc', '')])
    cc_addrs = orig_to + orig_cc

    deduped_to, deduped_cc = b4.LoreMessage.make_reply_addrs(to_addrs, cc_addrs)
    msg['To'] = b4.format_addrs(deduped_to, clean=False)
    if deduped_cc:
        msg['Cc'] = b4.format_addrs(deduped_cc, clean=False)
    if header_info.get('bcc'):
        msg['Bcc'] = header_info['bcc']
    msg['In-Reply-To'] = f'<{header_info["msgid"]}>'
    references = header_info.get('references', '')
    if references:
        msg['References'] = f'{references} <{header_info["msgid"]}>'
    else:
        msg['References'] = f'<{header_info["msgid"]}>'
    msg['Date'] = email.utils.formatdate(localtime=True)
    msg['Message-Id'] = email.utils.make_msgid()

    return msg


def collect_review_emails(
    series: Dict[str, Any],
    patches: List[Dict[str, Any]],
    cover_text: str,
    topdir: str,
    commit_shas: List[str],
) -> List[email.message.EmailMessage]:
    """Collect all review emails to send for the given series.

    Iterates cover reviews and per-patch reviews, calls
    _build_review_email() for each, and returns the flat list of
    messages.
    """
    msgs: List[email.message.EmailMessage] = []

    # Cover letter reviews (iterate all reviewers)
    for _reviewer_email, cover_review in series.get('reviews', {}).items():
        if not cover_review:
            continue
        msg = _build_review_email(series, None, cover_review, cover_text,
                                  topdir, None)
        if msg is not None:
            msgs.append(msg)

    # Per-patch reviews (iterate all reviewers per patch)
    for idx, patch_meta in enumerate(patches):
        for _reviewer_email, patch_review in patch_meta.get('reviews', {}).items():
            if not patch_review:
                continue
            commit_sha = commit_shas[idx] if idx < len(commit_shas) else None
            msg = _build_review_email(series, patch_meta, patch_review, cover_text,
                                      topdir, commit_sha)
            if msg is not None:
                msgs.append(msg)

    return msgs


def pw_fetch_series(pwkey: str, pwurl: str, pwproj: str) -> List[Dict[str, Any]]:
    """Fetch action-required series from a Patchwork instance.

    Returns a list of series dicts sorted by date (newest first).
    """
    pses, api_url = b4.get_patchwork_session(pwkey, pwurl)
    patches_url = '/'.join((api_url, 'patches'))
    params: Dict[str, Any] = {
        'project': pwproj,
        'state': ['new', 'under-review'],
        'order': '-date',
        'per_page': '250',
        'archived': 'false',
    }

    all_patches: List[Dict[str, Any]] = []
    url: Optional[str] = patches_url
    while url:
        resp = pses.get(url, params=params)
        if resp.status_code != 200:
            raise RuntimeError(f'Patchwork API error: {resp.status_code} {resp.reason}')
        all_patches.extend(resp.json())
        url = resp.links.get('next', {}).get('url')
        # Only pass params on the first request; pagination URLs include them
        params = {}

    # CI check priority: higher value = worse status (worst wins per series)
    _check_priority = {'pending': 0, 'success': 1, 'warning': 2, 'fail': 3}

    # Group patches by series ID
    series_map: Dict[int, Dict[str, Any]] = {}
    for patch in all_patches:
        patch_id = patch.get('id')
        for s in patch.get('series', []):
            sid = s.get('id')
            if not sid:
                continue
            if sid not in series_map:
                submitter = patch.get('submitter', {})
                series_map[sid] = {
                    'id': sid,
                    'name': s.get('name', '(no subject)'),
                    'submitter': submitter.get('name', submitter.get('email', 'Unknown')),
                    'submitter_email': submitter.get('email', ''),
                    'date': patch.get('date', ''),
                    'state': patch.get('state', 'new'),
                    'patch_ids': [],
                    'patch_names': {},
                    'msgid': patch.get('msgid', ''),
                    'check': patch.get('check', 'pending'),
                }
            else:
                # Keep earliest date
                existing_date = series_map[sid]['date']
                patch_date = patch.get('date', '')
                if patch_date and (not existing_date or patch_date < existing_date):
                    series_map[sid]['date'] = patch_date
                # Prefer under-review over new
                if patch.get('state') == 'under-review':
                    series_map[sid]['state'] = 'under-review'
                # Aggregate CI check: worst status wins
                patch_check = patch.get('check', 'pending')
                cur_check = series_map[sid].get('check', 'pending')
                if _check_priority.get(patch_check, 0) > _check_priority.get(cur_check, 0):
                    series_map[sid]['check'] = patch_check
            if patch_id:
                series_map[sid]['patch_ids'].append(patch_id)
                series_map[sid]['patch_names'][patch_id] = patch.get('name', '')

    return sorted(series_map.values(), key=lambda s: s.get('date', ''), reverse=True)


def pw_fetch_states(pwkey: str, pwurl: str, pwproj: str) -> List[Dict[str, Any]]:
    """Return available patch states.

    The Patchwork REST API does not expose a /states/ endpoint, so we
    use the same hardcoded defaults as git-pw.  The slug doubles as
    the display name with hyphens replaced by spaces and title-cased.

    Returns a list of state dicts with 'slug' and 'name' keys.
    """
    default_slugs = (
        'new',
        'under-review',
        'accepted',
        'rejected',
        'rfc',
        'not-applicable',
        'changes-requested',
        'awaiting-upstream',
        'superseded',
        'deferred',
    )
    return [{'slug': s, 'name': s.replace('-', ' ').title()} for s in default_slugs]


def pw_fetch_checks(pwkey: str, pwurl: str,
                    patch_ids: List[int]) -> List[Dict[str, Any]]:
    """Fetch CI check details for a list of patch IDs.

    Returns a flat list of check dicts, each augmented with 'patch_id'.
    """
    pses, api_url = b4.get_patchwork_session(pwkey, pwurl)
    all_checks: List[Dict[str, Any]] = []
    for pid in patch_ids:
        checks_url = f'{api_url}/patches/{pid}/checks/'
        try:
            resp = pses.get(checks_url)
            if resp.status_code != 200:
                continue
            for check in resp.json():
                check['patch_id'] = pid
                all_checks.append(check)
        except Exception:
            continue
    return all_checks


def pw_set_series_state(pwkey: str, pwurl: str, patch_ids: List[int],
                        state: str, archived: bool) -> Tuple[int, int]:
    """Set state and archived flag on patches by patch ID.

    Returns (success_count, failure_count).
    """
    pses, api_url = b4.get_patchwork_session(pwkey, pwurl)
    patches_url = '/'.join((api_url, 'patches'))
    ok = 0
    fail = 0
    for patch_id in patch_ids:
        patchid_url = '/'.join((patches_url, str(patch_id), ''))
        data = {
            'state': state,
            'archived': archived,
        }
        try:
            rsp = pses.patch(patchid_url, data=data, stream=False)
            rsp.raise_for_status()
            ok += 1
        except Exception as ex:
            logger.debug('Patchwork REST error on patch %s: %s', patch_id, ex)
            fail += 1
    return ok, fail


def pw_update_series_state(pw_series_id: int, state: str, archived: bool = False) -> bool:
    """Update Patchwork state for a series tracked by pw_series_id.

    Looks up pw-key and pw-url from git config, fetches the patch IDs
    for the series, and sets the requested state.  Returns True on
    success (or when Patchwork is not configured), False on failure.
    """
    config = b4.get_main_config()
    pwkey = str(config.get('pw-key', ''))
    pwurl = str(config.get('pw-url', ''))
    if not (pwkey and pwurl):
        # Patchwork not configured, nothing to do
        return True

    try:
        pses, api_url = b4.get_patchwork_session(pwkey, pwurl)
        series_url = '/'.join((api_url, 'series', str(pw_series_id), ''))
        rsp = pses.get(series_url, stream=False)
        rsp.raise_for_status()
        sdata = rsp.json()
        patch_ids = [p['id'] for p in sdata.get('patches', [])]
    except Exception as ex:
        logger.debug('Could not fetch patch IDs for pw series %s: %s', pw_series_id, ex)
        return False

    if not patch_ids:
        return True

    ok, fail = pw_set_series_state(pwkey, pwurl, patch_ids, state, archived)
    if fail:
        logger.warning('Failed to update %d/%d patches in Patchwork', fail, ok + fail)
        return False
    logger.debug('Updated %d patches to state %s in Patchwork', ok, state)
    return True
