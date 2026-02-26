#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

from typing import Any, Dict, Optional

import b4
import b4.review
import b4.review.tracking

from b4.review_tui._common import logger
from b4.review_tui._review_app import ReviewApp
from b4.review_tui._tracking_app import TrackingApp
from b4.review_tui._pw_app import PwApp


def run_pw_tui(pwkey: str, pwurl: str, pwproj: str) -> None:
    """Launch the Patchwork series browser TUI."""
    app = PwApp(pwkey, pwurl, pwproj)
    app.run()


def run_branch_tui(session: Dict[str, Any]) -> None:
    """Launch the review TUI for a single branch."""
    app = ReviewApp(session)
    app.run()


def run_tracking_tui(identifier: str, email_dryrun: bool = False) -> None:
    """Entry point called from b4.review.cmd_tui().

    Loops between TrackingApp and ReviewApp as needed.
    If already on a review branch, goes directly to ReviewApp.
    """
    import argparse

    topdir = b4.git_get_toplevel()
    if not topdir:
        logger.critical('Not in a git repository')
        return

    # Get current branch to restore later
    ecode, out = b4.git_run_command(topdir, ['symbolic-ref', '--short', 'HEAD'])
    if ecode == 0:
        original_branch = out.strip()
    else:
        original_branch = None

    # Check if we're already on a review branch
    if original_branch and original_branch.startswith(b4.review.REVIEW_BRANCH_PREFIX):
        # Go directly to ReviewApp and exit when done
        cmdargs = argparse.Namespace(branch=original_branch)
        try:
            session = b4.review._prepare_review_session(cmdargs)
            session['email_dryrun'] = email_dryrun
            review_app = ReviewApp(session)
            review_app.run()
        except SystemExit:
            logger.warning('Could not prepare review session for branch: %s', original_branch)
        return

    # Normal tracking mode - loop between TrackingApp and ReviewApp
    focus_change_id: Optional[str] = None
    while True:
        app = TrackingApp(identifier, original_branch, focus_change_id=focus_change_id,
                          email_dryrun=email_dryrun)
        focus_change_id = None
        branch_name = app.run()

        if not branch_name:
            # User quit - exit the loop
            break

        if branch_name == TrackingApp.PATCHWORK_SENTINEL:
            # User pressed [p]atchwork — run PwApp and loop back
            config = b4.get_main_config()
            pwkey = str(config.get('pw-key', ''))
            pwurl = str(config.get('pw-url', ''))
            pwproj = str(config.get('pw-project', ''))
            if pwkey and pwurl and pwproj:
                run_pw_tui(pwkey, pwurl, pwproj)
            continue

        # User selected a branch to review - prepare session and run ReviewApp
        logger.info('Checking out branch and starting review UI...')
        cmdargs = argparse.Namespace(branch=branch_name)
        try:
            session = b4.review._prepare_review_session(cmdargs)
        except SystemExit:
            # Session prep failed (e.g., branch doesn't exist)
            logger.warning('Could not prepare review session for branch: %s', branch_name)
            continue

        session['email_dryrun'] = email_dryrun
        review_app = ReviewApp(session)
        review_app.run()

        # Remember which series was just reviewed so the tracking list
        # can position the cursor on it.
        focus_change_id = branch_name.removeprefix(b4.review.REVIEW_BRANCH_PREFIX)

        # Update status to 'replied' if a review reply was sent.
        # Derive change_id from the branch name rather than the tracking
        # JSON — the JSON's change-id may be empty for series that lack a
        # Change-Id header while the branch name always carries the
        # database's synthetic identifier.
        if review_app._reply_sent:
            change_id = focus_change_id
            revision = session['series'].get('revision')
            if change_id:
                try:
                    conn = b4.review.tracking.get_db(identifier)
                    b4.review.tracking.update_series_status(conn, change_id, 'replied',
                                                            revision=revision)
                    conn.close()
                except Exception as ex:
                    logger.warning('Could not update series status: %s', ex)

        # Restore original branch after exiting ReviewApp
        if original_branch:
            logger.info('Checking out %s and starting tracking UI...', original_branch)
            ecode, out = b4.git_run_command(topdir, ['checkout', original_branch], logstderr=True)
            if ecode != 0:
                logger.warning('Could not restore original branch: %s', original_branch)
