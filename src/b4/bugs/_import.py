#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
"""Thread import engine: lore.kernel.org -> git-bug via ezgb."""
import email.utils
import logging
import re
from email.message import EmailMessage
from typing import Optional

import b4
import b4.mbox
from ezgb import Bug, GitBugRepo

logger = logging.getLogger('b4')

_HEADER_RE = re.compile(r'^([\w-]+):\s*(.+)$', re.MULTILINE | re.IGNORECASE)


def format_comment(msg: EmailMessage, scope: str = '') -> str:
    """Format an email message as an RFC 2822 comment body.

    Produces::

        From: Display Name <email@example.com>
        Date: RFC 2822 date string
        Message-ID: <msgid@host>
        In-Reply-To: <parent@host>

        Body text after blank line separator...

    If *scope* is set, an ``X-B4-Bug-Scope`` header is added to
    mark the import mode (e.g. ``no-parent``).
    """
    parts: list[str] = []
    for hdr in ('From', 'Date', 'Message-ID', 'In-Reply-To'):
        val = msg.get(hdr)
        if val is not None:
            val = b4.LoreMessage.clean_header(val)
            if val:
                parts.append(f'{hdr}: {val}')
    if scope:
        parts.append(f'X-B4-Bug-Scope: {scope}')
    parts.append('')  # blank separator per RFC 2822
    body, _charset = b4.LoreMessage.get_payload(msg)
    parts.append(body.rstrip())
    return '\n'.join(parts)


def parse_comment_header(text: str, header: str) -> Optional[str]:
    """Extract a named header from an RFC 2822 formatted comment body.

    Only searches the header block (before the first blank line)
    to avoid false matches in the message body.
    """
    header_block = text.split('\n\n', 1)[0]
    for match in _HEADER_RE.finditer(header_block):
        if match.group(1).lower() == header.lower():
            return match.group(2).strip()
    return None


def parse_comment_msgid(text: str) -> Optional[str]:
    """Extract the Message-ID from an RFC 2822 formatted comment body."""
    val = parse_comment_header(text, 'Message-ID')
    if val:
        return val.strip('<>')
    return None


def is_comment_removed(text: str) -> bool:
    """Check if a comment has been tombstoned (removed)."""
    val = parse_comment_header(text, 'X-B4-Bug-Comment')
    return val is not None and val.startswith('removed')


def make_tombstone(text: str, identity: str) -> str:
    """Build a tombstone that preserves Message-ID and In-Reply-To.

    All other content (From, Date, body) is stripped so personal
    data is no longer visible via cgit or the TUI.
    """
    parts: list[str] = []
    for hdr in ('Message-ID', 'In-Reply-To'):
        val = parse_comment_header(text, hdr)
        if val:
            parts.append(f'{hdr}: {val}')
    parts.append(f'X-B4-Bug-Comment: removed by {identity}')
    return '\n'.join(parts)


def _get_clean_msgid(msg: EmailMessage) -> Optional[str]:
    """Get the clean message-id from an EmailMessage."""
    raw = msg.get('Message-ID')
    if raw is None:
        return None
    clean = b4.LoreMessage.clean_header(raw)
    return clean.strip().strip('<>')


def _sort_by_date(msgs: list[EmailMessage]) -> list[EmailMessage]:
    """Sort messages by their Date header, oldest first."""
    def _date_key(msg: EmailMessage) -> float:
        raw = msg.get('Date')
        if raw:
            parsed = email.utils.parsedate_to_datetime(
                b4.LoreMessage.clean_header(raw),
            )
            return parsed.timestamp()
        return 0.0
    return sorted(msgs, key=_date_key)


def import_thread(
    repo: GitBugRepo, msgid: str, noparent: bool = False,
) -> Bug:
    """Import a lore.kernel.org thread as a new git-bug bug.

    Fetches the thread, minimizes quoting, creates a bug from the
    root message, and adds follow-up messages as comments.

    When *noparent* is True, only the message matching *msgid* and
    its descendants are imported (parent messages are ignored).
    """
    msgid = b4.parse_msgid(msgid)
    msgs = b4.get_pi_thread_by_msgid(msgid)
    if not msgs:
        raise RuntimeError(f'Could not retrieve thread for {msgid}')

    # Filter to sub-thread if --no-parent
    if noparent:
        filtered = b4.get_strict_thread(msgs, msgid, noparent=True)
        if not filtered:
            raise RuntimeError(
                f'No messages in sub-thread for {msgid}'
            )
        msgs = filtered

    msgs = b4.mbox.minimize_thread(msgs)
    if not msgs:
        raise RuntimeError(f'No messages after minimization for {msgid}')

    # When importing a full thread, use the oldest message as root
    # regardless of which msgid was used to locate the thread.
    # When --no-parent is set, use the requested msgid as root.
    if noparent:
        root = None
        rest: list[EmailMessage] = []
        for msg in msgs:
            msg_id = _get_clean_msgid(msg)
            if msg_id and msg_id == msgid:
                root = msg
            else:
                rest.append(msg)
        if root is None:
            sorted_msgs = _sort_by_date(msgs)
            root = sorted_msgs[0]
            rest = sorted_msgs[1:]
    else:
        sorted_msgs = _sort_by_date(msgs)
        root = sorted_msgs[0]
        rest = sorted_msgs[1:]

    # Check if this thread was already imported
    root_msgid = _get_clean_msgid(root)
    if root_msgid:
        for existing in repo.list_bugs():
            if not existing.comments:
                continue
            existing_msgid = parse_comment_msgid(existing.comments[0].text)
            if existing_msgid and existing_msgid == root_msgid:
                raise RuntimeError(
                    f'Thread already imported as bug {existing.id[:7]}: '
                    f'{existing.title}'
                )

    # Create bug from root message
    subject = b4.LoreMessage.clean_header(root.get('Subject', ''))
    if not subject:
        subject = '(no subject)'
    scope = 'no-parent' if noparent else ''
    bug = repo.create_bug(
        title=subject, body=format_comment(root, scope=scope),
    )

    # Add follow-up messages as comments, sorted by date
    rest = _sort_by_date(rest)
    for msg in rest:
        repo.add_comment(bug.id, format_comment(msg))

    # Re-read to get the full snapshot with all comments
    repo.invalidate(bug.id)
    return repo.get_bug(bug.id)


def refresh_bug(repo: GitBugRepo, bid: str) -> int:
    """Refresh a bug by fetching new messages from lore.

    Respects the ``X-B4-Bug-Scope: no-parent`` marker on the root
    comment — when present, only descendants of the root message
    are imported.

    Returns the number of new comments added.
    """
    bug = repo.get_bug(bid)
    if not bug.comments:
        logger.warning('Bug %s has no comments, cannot refresh', bid[:7])
        return 0

    # Collect existing message-ids for dedup
    known: set[str] = set()
    for comment in bug.comments:
        mid = parse_comment_msgid(comment.text)
        if mid:
            known.add(mid)

    # Get the root message-id to re-fetch the thread
    root_msgid = parse_comment_msgid(bug.comments[0].text)
    if not root_msgid:
        logger.warning('Bug %s has no Message-ID in first comment', bid[:7])
        return 0

    # Check if this was a no-parent import
    scope = parse_comment_header(bug.comments[0].text, 'X-B4-Bug-Scope')
    is_noparent = scope == 'no-parent'

    msgs = b4.get_pi_thread_by_msgid(root_msgid)
    if not msgs:
        logger.debug('No messages retrieved for %s', root_msgid)
        return 0

    # Filter to sub-thread if this was a no-parent import
    if is_noparent:
        filtered = b4.get_strict_thread(msgs, root_msgid, noparent=True)
        if not filtered:
            return 0
        msgs = filtered

    msgs = b4.mbox.minimize_thread(msgs)

    # Filter to only new messages
    new_msgs: list[EmailMessage] = []
    for msg in msgs:
        msg_id = _get_clean_msgid(msg)
        if msg_id and msg_id not in known:
            new_msgs.append(msg)

    if not new_msgs:
        return 0

    # Add new messages as comments, sorted by date
    new_msgs = _sort_by_date(new_msgs)
    for msg in new_msgs:
        repo.add_comment(bug.id, format_comment(msg))

    repo.invalidate(bug.id)
    return len(new_msgs)
