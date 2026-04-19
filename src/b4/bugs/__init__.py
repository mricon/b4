#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
"""b4 bugs: manage bug reports from mailing list threads."""

import argparse
import json
import logging
import shutil
import sys

from ezgb._git import git_bug_cli

import b4
from ezgb import BugNotFoundError, GitBugRepo, Status

logger = logging.getLogger('b4')


def _ensure_identity(topdir: str) -> bool:
    """Ensure a git-bug identity exists and is adopted.

    If no identity is adopted, try to auto-create one from the
    git user.name and user.email config. Returns True if an
    identity is available, False otherwise.
    """
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


def _get_repo() -> GitBugRepo:
    """Create a GitBugRepo for the current working tree."""
    topdir = b4.git_get_toplevel()
    if not topdir:
        logger.critical('Not in a git repository')
        sys.exit(1)
    if not _ensure_identity(topdir):
        sys.exit(1)
    return GitBugRepo(topdir)


def cmd_import(cmdargs: argparse.Namespace) -> None:
    """Import a lore thread as a new bug."""
    from b4.bugs._import import import_thread

    repo = _get_repo()
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

    repo = _get_repo()
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


def cmd_list(cmdargs: argparse.Namespace) -> None:
    """List tracked bugs."""
    repo = _get_repo()
    status = None
    if cmdargs.status == 'open':
        status = Status.OPEN
    elif cmdargs.status == 'closed':
        status = Status.CLOSED

    bugs = repo.list_bugs(status=status, label=cmdargs.label)
    if not bugs:
        logger.info('No bugs found')
        return

    for bug in bugs:
        icon = '\u25cf' if bug.status == Status.OPEN else '\u25cb'
        labels = ' '.join(f'[{label}]' for label in sorted(bug.labels))
        logger.info('%s %s  %s  %s', icon, bug.id[:7], bug.title, labels)


def cmd_delete(cmdargs: argparse.Namespace) -> None:
    """Permanently delete a bug."""
    repo = _get_repo()
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
    except ImportError:
        logger.critical('The TUI requires the textual library.')
        logger.critical('Install it with: pip install b4[tui]')
        sys.exit(1)

    repo = _get_repo()
    no_mouse = getattr(cmdargs, 'no_mouse', False)
    email_dryrun = getattr(cmdargs, 'email_dryrun', False)
    no_sign = getattr(cmdargs, 'no_sign', False)
    app = BugListApp(repo, email_dryrun=email_dryrun, no_sign=no_sign)
    app.run(mouse=not no_mouse)


def main(cmdargs: argparse.Namespace) -> None:
    """Dispatch b4 bugs subcommands."""
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
