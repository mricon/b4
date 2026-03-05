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


def run_pw_tui(pwkey: str, pwurl: str, pwproj: str,
               email_dryrun: bool = False,
               patatt_sign: bool = True) -> None:
    """Launch the Patchwork series browser TUI."""
    app = PwApp(pwkey, pwurl, pwproj,
                email_dryrun=email_dryrun, patatt_sign=patatt_sign)
    app.run()


def run_branch_tui(session: Dict[str, Any]) -> None:
    """Launch the review TUI for a single branch."""
    app = ReviewApp(session)
    app.run()


def run_tracking_tui(identifier: str, email_dryrun: bool = False,
                     no_sign: bool = False) -> None:
    """Entry point called from b4.review.cmd_tui().

    Loops between TrackingApp and ReviewApp as needed.
    If already on a review branch, goes directly to ReviewApp.
    """
    import argparse

    topdir = b4.git_get_toplevel()
    if not topdir:
        logger.critical('Not in a git repository')
        return

    # Compute effective patatt sign flag from CLI and config
    config = b4.get_main_config()
    _cnps = str(config.get('review-no-patatt-sign', ''))
    patatt_sign = not (no_sign or _cnps.lower() in {'yes', 'true', 'y'})

    # Get current branch to restore later
    original_branch = b4.git_get_current_branch(topdir)

    # Check if we're already on a review branch
    if original_branch and original_branch.startswith(b4.review.REVIEW_BRANCH_PREFIX):
        # Go directly to ReviewApp and exit when done
        cmdargs = argparse.Namespace(branch=original_branch)
        try:
            session = b4.review._prepare_review_session(cmdargs)
            session['email_dryrun'] = email_dryrun
            session['patatt_sign'] = patatt_sign
            # Tell ReviewApp which branch to suggest so it can show a hint
            config = b4.get_main_config()
            cfg_branch = config.get('review-target-branch')
            if cfg_branch:
                switch_branch = str(cfg_branch)
            elif topdir and b4.git_branch_exists(topdir, 'master'):
                switch_branch = 'master'
            elif topdir and b4.git_branch_exists(topdir, 'main'):
                switch_branch = 'main'
            else:
                switch_branch = None
            if switch_branch:
                session['_switch_hint'] = switch_branch
            review_app = ReviewApp(session)
            review_app.run()
        except SystemExit:
            logger.warning('Could not prepare review session for branch: %s', original_branch)
        return

    # Normal tracking mode - loop between TrackingApp and ReviewApp
    focus_change_id: Optional[str] = None
    while True:
        app = TrackingApp(identifier, original_branch, focus_change_id=focus_change_id,
                          email_dryrun=email_dryrun, patatt_sign=patatt_sign)
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
                run_pw_tui(pwkey, pwurl, pwproj,
                           email_dryrun=email_dryrun,
                           patatt_sign=patatt_sign)
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
        session['patatt_sign'] = patatt_sign
        review_app = ReviewApp(session)
        review_app.run()

        # Remember which series was just reviewed so the tracking list
        # can position the cursor on it.
        focus_change_id = branch_name.removeprefix(b4.review.REVIEW_BRANCH_PREFIX)

        # Sync status from tracking commit to DB.  The ReviewApp writes
        # status changes (e.g. 'replied') into the tracking commit JSON,
        # so we read it back here and propagate to the SQLite database.
        try:
            cover_text, tracking = b4.review.load_tracking(topdir, branch_name)
            tracking_status = tracking.get('series', {}).get('status')
            revision = session['series'].get('revision')
            if tracking_status and focus_change_id:
                conn = b4.review.tracking.get_db(identifier)
                b4.review.tracking.update_series_status(
                    conn, focus_change_id, tracking_status, revision=revision)
                conn.close()
        except Exception as ex:
            logger.warning('Could not sync tracking status: %s', ex)

        # Restore original branch after exiting ReviewApp
        if original_branch:
            logger.info('Checking out %s and starting tracking UI...', original_branch)
            ecode, out = b4.git_run_command(topdir, ['checkout', original_branch], logstderr=True)
            if ecode != 0:
                logger.warning('Could not restore original branch: %s', original_branch)
