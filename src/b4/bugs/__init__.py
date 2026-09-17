#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
"""b4 bugs: manage bug reports from mailing list threads."""

import argparse
import importlib
import json
import logging
import shutil
import sys
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union

import b4

if TYPE_CHECKING:
    from datetime import datetime

    from ezgb import Bug, BugSummary, GitBugRepo

    BugLike = Union[Bug, BugSummary]

logger = logging.getLogger('b4')


def has_ezgb() -> bool:
    """Report whether bug-tracking support is available.

    Bug tracking is an optional feature, so ``ezgb`` is an optional
    dependency.  Everything under ``b4.bugs`` imports it lazily, which keeps
    ``b4`` usable (and its public modules importable) without it.

    Probes for a real attribute rather than just importing: run from a b4
    checkout, the ``ezgb`` submodule directory shadows the real package as an
    empty namespace package, and a bare import of that succeeds.
    """
    try:
        getattr(importlib.import_module('ezgb'), 'GitBugRepo')
    except (ImportError, AttributeError):
        return False
    return True


def _require_ezgb(cmdargs: Optional[argparse.Namespace] = None) -> None:
    """Exit with an install hint unless bug tracking is available."""
    if not has_ezgb():
        b4.fail_precondition(
            cmdargs,
            'no-git-bug',
            'Bug tracking requires the ezgb library.',
            'Install it with: pip install b4[bugs]',
            'It also needs the git-bug binary: https://github.com/git-bug/git-bug',
        )


def _ensure_identity(topdir: str, no_interactive: bool = False) -> bool:
    """Ensure a git-bug identity exists and is adopted.

    If no identity is adopted, try to auto-create one from the
    git user.name and user.email config. Returns True if an
    identity is available, False otherwise.
    """
    from ezgb._git import git_bug_cli

    # Check if already adopted
    ecode, out = b4.git_run_command(topdir, ['config', '--get', 'git-bug.identity'])
    if ecode == 0 and out.strip():
        return True

    if shutil.which('git-bug') is None:
        logger.critical('git-bug is not installed')
        return False

    # Check if any identities exist that we can adopt
    ecode, out, _err = git_bug_cli(topdir, ['user', '-f', 'json'])
    if ecode == 0 and out.strip():
        try:
            users = json.loads(out)
        except json.JSONDecodeError:
            users = []
        if users:
            # Try to match by email
            ecode_e, git_email = b4.git_run_command(topdir, ['config', 'user.email'])
            git_email = git_email.strip() if ecode_e == 0 else ''
            for user in users:
                if user.get('email', '') == git_email:
                    ecode, _out, _err = git_bug_cli(
                        topdir, ['user', 'adopt', user['id']]
                    )
                    if ecode == 0:
                        logger.info(
                            'Adopted existing git-bug identity: %s',
                            user.get('name', ''),
                        )
                        return True
            # No email match -- adopt the first one
            ecode, _out, _err = git_bug_cli(topdir, ['user', 'adopt', users[0]['id']])
            if ecode == 0:
                logger.info(
                    'Adopted existing git-bug identity: %s', users[0].get('name', '')
                )
                return True

    # No identities at all -- create from git config after confirmation
    ecode_n, git_name = b4.git_run_command(topdir, ['config', 'user.name'])
    ecode_e, git_email = b4.git_run_command(topdir, ['config', 'user.email'])
    git_name = git_name.strip() if ecode_n == 0 else ''
    git_email = git_email.strip() if ecode_e == 0 else ''
    if not git_name or not git_email:
        logger.critical(
            'Cannot create git-bug identity: git user.name/user.email not configured'
        )
        return False

    logger.info('No git-bug identity found for this repository.')
    logger.info('Will create and adopt: %s <%s>', git_name, git_email)
    if no_interactive:
        # Creating an identity writes to the repository, so never do it
        # behind the caller's back when there is nobody to ask.
        logger.critical('Refusing to create a git-bug identity non-interactively')
        logger.critical('Run "b4 bugs list" interactively once to set one up')
        return False
    try:
        answer = input('Proceed? [Y/n] ').strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if answer and answer != 'y':
        return False

    ecode, out, err = git_bug_cli(
        topdir,
        [
            'user',
            'new',
            '-n',
            git_name,
            '-e',
            git_email,
            '--non-interactive',
        ],
    )
    if ecode != 0:
        logger.critical('Failed to create git-bug identity: %s', err.strip())
        return False
    user_id = out.strip()

    ecode, _out, _err = git_bug_cli(topdir, ['user', 'adopt', user_id])
    if ecode != 0:
        logger.critical('Failed to adopt git-bug identity')
        return False

    logger.info('Created and adopted git-bug identity: %s <%s>', git_name, git_email)
    return True


def _get_repo(cmdargs: Optional[argparse.Namespace] = None) -> 'GitBugRepo':
    """Create a GitBugRepo for the current working tree.

    Passing *cmdargs* lets the unmet-precondition errors come out in the
    shape the caller asked for, and honours the global ``-n`` so that we
    never block on a prompt nobody is there to answer.
    """
    from ezgb import GitBugRepo

    no_interactive = cmdargs is not None and getattr(cmdargs, 'no_interactive', False)
    topdir = b4.git_get_toplevel()
    if not topdir:
        b4.fail_precondition(cmdargs, 'no-repo', 'Not in a git repository')
    if not _ensure_identity(topdir, no_interactive=no_interactive):
        b4.fail_precondition(cmdargs, 'no-identity', 'No usable git-bug identity')
    return GitBugRepo(topdir)


def cmd_import(cmdargs: argparse.Namespace) -> None:
    """Import a lore thread as a new bug."""
    from b4.bugs._import import import_thread

    repo = _get_repo(cmdargs)
    msgid = cmdargs.msgid.strip().strip('<>')
    logger.info('Importing thread %s...', msgid)
    noparent = getattr(cmdargs, 'noparent', False)
    try:
        bug = import_thread(repo, msgid, noparent=noparent)
    except RuntimeError as exc:
        logger.critical('Import failed: %s', exc)
        sys.exit(1)
    logger.info(
        'Created bug %s: %s (%d comments)', bug.id[:7], bug.title, len(bug.comments)
    )


def cmd_refresh(cmdargs: argparse.Namespace) -> None:
    """Refresh bugs with new thread messages from lore."""
    from b4.bugs._import import refresh_bug
    from ezgb import BugNotFoundError, Status

    repo = _get_repo(cmdargs)
    if cmdargs.bugid:
        try:
            bid = repo.resolve_bug_id(cmdargs.bugid)
        except (BugNotFoundError, Exception) as exc:
            logger.critical('Could not find bug: %s', exc)
            sys.exit(1)
        count = refresh_bug(repo, bid)
        logger.info('Bug %s: %d new comment(s)', bid[:7], count)
    else:
        bugs = repo.list_bugs(status=Status.OPEN)
        total = 0
        for bug in bugs:
            count = refresh_bug(repo, bug.id)
            if count:
                logger.info('Bug %s: %d new comment(s)', bug.id[:7], count)
                total += count
        logger.info('Refreshed %d bug(s), %d new comment(s) total', len(bugs), total)


def bug_last_activity(bug: 'BugLike') -> 'datetime':
    """Return the time of the most recent activity on *bug*.

    A :class:`~ezgb.BugSummary` carries this directly as *edited_at*,
    which also accounts for label and status changes.  A full
    :class:`~ezgb.Bug` does not, so fall back to its newest comment.
    """
    from ezgb import BugSummary

    if isinstance(bug, BugSummary):
        return bug.edited_at
    if bug.comments:
        return bug.comments[-1].created_at
    return bug.created_at


def bug_message_ids(bug: 'Bug') -> Tuple[Optional[str], List[str]]:
    """Return (root message-id, follow-up message-ids) for *bug*.

    Every imported message is stored as a comment whose body starts with
    an RFC 2822 header block, so the thread's message-ids are recoverable
    from the comments.  The *root* one -- the message the thread was
    imported from -- is the dedup key ``import_thread()`` itself checks
    against, and is ``None`` for a bug that was not created by an import.
    """
    from b4.bugs._import import parse_comment_msgid

    msgids = [parse_comment_msgid(comment.text) for comment in bug.comments]
    if not msgids:
        return None, []
    return msgids[0], [msgid for msgid in msgids[1:] if msgid]


def bug_to_dict(bug: 'Bug') -> Dict[str, Any]:
    """Render *bug* as a JSON-serialisable dict."""
    from ezgb import Status

    root_msgid, comment_msgids = bug_message_ids(bug)
    return {
        'id': bug.id,
        'title': bug.title,
        'status': 'open' if bug.status == Status.OPEN else 'closed',
        'labels': sorted(bug.labels),
        'root_msgid': root_msgid,
        'comment_msgids': comment_msgids,
        'last_activity': bug_last_activity(bug).isoformat(),
    }


def cmd_list(cmdargs: argparse.Namespace) -> None:
    """List tracked bugs."""
    from ezgb import Status

    repo = _get_repo(cmdargs)
    status = None
    if cmdargs.status == 'open':
        status = Status.OPEN
    elif cmdargs.status == 'closed':
        status = Status.CLOSED

    bugs = repo.list_bugs(status=status, label=cmdargs.label)
    if getattr(cmdargs, 'json_output', False):
        # An empty result is still valid JSON, so a script never has to
        # special-case "no bugs" the way the human listing does.
        print(json.dumps([bug_to_dict(bug) for bug in bugs], indent=2))
        return

    if not bugs:
        logger.info('No bugs found')
        return

    for bug in bugs:
        icon = '\u25cf' if bug.status == Status.OPEN else '\u25cb'
        labels = ' '.join(f'[{label}]' for label in sorted(bug.labels))
        logger.info('%s %s  %s  %s', icon, bug.id[:7], bug.title, labels)


def cmd_delete(cmdargs: argparse.Namespace) -> None:
    """Permanently delete a bug."""
    from ezgb import BugNotFoundError

    repo = _get_repo(cmdargs)
    try:
        bid = repo.resolve_bug_id(cmdargs.bugid)
    except BugNotFoundError as exc:
        logger.critical('Could not find bug: %s', exc)
        sys.exit(1)
    bug = repo.get_bug(bid)
    logger.info('Deleting bug %s: %s', bid[:7], bug.title)
    repo.remove_bug(bid)
    logger.info('Bug %s deleted', bid[:7])


def cmd_tui(cmdargs: argparse.Namespace) -> None:
    """Launch the bug management TUI."""
    try:
        from b4.bugs._tui import BugListApp
    except ImportError as e:
        logger.critical('The TUI requires the %s library.', e.name)
        logger.critical('Install it with: pip install b4[tui]')
        sys.exit(1)

    repo = _get_repo(cmdargs)
    no_mouse = getattr(cmdargs, 'no_mouse', False)
    email_dryrun = getattr(cmdargs, 'email_dryrun', False)
    no_sign = getattr(cmdargs, 'no_sign', False)
    app = BugListApp(repo, email_dryrun=email_dryrun, no_sign=no_sign)
    app.run(mouse=not no_mouse)


def main(cmdargs: argparse.Namespace) -> None:
    """Dispatch b4 bugs subcommands."""
    _require_ezgb(cmdargs)
    subcmd = getattr(cmdargs, 'bugs_subcmd', None)
    if subcmd is None or subcmd == 'tui':
        cmd_tui(cmdargs)
    elif subcmd == 'import':
        cmd_import(cmdargs)
    elif subcmd == 'refresh':
        cmd_refresh(cmdargs)
    elif subcmd == 'list':
        cmd_list(cmdargs)
    elif subcmd == 'delete':
        cmd_delete(cmdargs)
    else:
        logger.critical('Unknown bugs sub-command: %s', subcmd)
        sys.exit(1)
