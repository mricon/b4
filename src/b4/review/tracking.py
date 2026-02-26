#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import argparse
import datetime
import json
import os
import pathlib
import sqlite3
import sys

import b4
import b4.mbox

from typing import Any, Optional

logger = b4.logger

REVIEW_METADATA_DIR = 'b4-review'
REVIEW_METADATA_FILE = 'metadata.json'

SCHEMA_VERSION = 1

SCHEMA_SQL = '''
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS series (
    track_id INTEGER PRIMARY KEY,
    change_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    subject TEXT,
    sender_name TEXT,
    sender_email TEXT,
    sent_at TEXT,
    added_at TEXT,
    message_id TEXT,
    num_patches INTEGER,
    pw_series_id INTEGER,
    status TEXT DEFAULT 'new',
    fingerprint TEXT,
    UNIQUE (change_id, revision)
);

CREATE TABLE IF NOT EXISTS revisions (
    change_id  TEXT NOT NULL,
    revision   INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    subject    TEXT,
    link       TEXT,
    found_at   TEXT,
    PRIMARY KEY (change_id, revision)
);
'''


def get_review_data_dir() -> str:
    """Get the review data directory path."""
    datadir = b4.get_data_dir()
    reviewdir = os.path.join(datadir, 'review')
    pathlib.Path(reviewdir).mkdir(parents=True, exist_ok=True)
    return reviewdir


def get_db_path(identifier: str) -> str:
    """Get the database path for a project identifier."""
    reviewdir = get_review_data_dir()
    return os.path.join(reviewdir, f'{identifier}.sqlite3')


def db_exists(identifier: str) -> bool:
    """Check if a database exists for the given identifier."""
    return os.path.exists(get_db_path(identifier))


def init_db(identifier: str) -> sqlite3.Connection:
    """Initialize a new database for the given identifier."""
    db_path = get_db_path(identifier)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.execute('INSERT OR REPLACE INTO schema_version (version) VALUES (?)', (SCHEMA_VERSION,))
    conn.commit()
    return conn


def get_db(identifier: str) -> sqlite3.Connection:
    """Get a database connection for the given identifier."""
    db_path = get_db_path(identifier)
    if not os.path.exists(db_path):
        raise FileNotFoundError(f'No database found for identifier: {identifier}')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def get_repo_metadata_path(gitdir: str) -> str:
    """Get the path to the metadata file in a git repository."""
    return os.path.join(gitdir, REVIEW_METADATA_DIR, REVIEW_METADATA_FILE)


def get_repo_identifier(topdir: str) -> Optional[str]:
    """Get the project identifier from a repository's metadata file."""
    gitdir = os.path.join(topdir, '.git')
    if not os.path.isdir(gitdir):
        # Worktree or bare repo - no metadata file support
        return None
    metadata_path = get_repo_metadata_path(gitdir)
    if not os.path.exists(metadata_path):
        return None
    try:
        with open(metadata_path, 'r') as f:
            data = json.load(f)
            identifier = data.get('identifier')
            if isinstance(identifier, str):
                return identifier
            return None
    except (json.JSONDecodeError, OSError) as e:
        logger.warning('Failed to read metadata file: %s', e)
        return None


def save_repo_metadata(gitdir: str, identifier: str) -> None:
    """Save project metadata to the repository's .git directory."""
    metadata_dir = os.path.join(gitdir, REVIEW_METADATA_DIR)
    pathlib.Path(metadata_dir).mkdir(parents=True, exist_ok=True)
    metadata_path = os.path.join(metadata_dir, REVIEW_METADATA_FILE)
    with open(metadata_path, 'w') as f:
        json.dump({'identifier': identifier}, f, indent=2)
        f.write('\n')


def resolve_identifier(cmdargs: argparse.Namespace, topdir: Optional[str] = None) -> Optional[str]:
    """Resolve project identifier from command args or repository metadata."""
    if hasattr(cmdargs, 'identifier') and cmdargs.identifier:
        return str(cmdargs.identifier)
    if topdir is None:
        topdir = b4.git_get_toplevel()
    if topdir:
        return get_repo_identifier(topdir)
    return None


def cmd_enroll(cmdargs: argparse.Namespace) -> None:
    """Enroll a repository for review tracking."""
    if cmdargs.repo_path:
        repo_path = os.path.abspath(cmdargs.repo_path)
        if not os.path.isdir(repo_path):
            logger.critical('Repository path does not exist: %s', repo_path)
            sys.exit(1)
    else:
        # Use current directory
        repo_path_opt = b4.git_get_toplevel()
        if not repo_path_opt:
            logger.critical('Not in a git repository. Specify a path or run from within a repository.')
            sys.exit(1)
        repo_path = repo_path_opt

    # Check if it's a git repository
    gitdir = os.path.join(repo_path, '.git')
    is_worktree = False

    if os.path.isfile(gitdir):
        # This is a worktree - .git is a file pointing to the main repo
        is_worktree = True
        logger.debug('Detected worktree at %s', repo_path)
    elif not os.path.isdir(gitdir):
        logger.critical('Not a git repository: %s', repo_path)
        sys.exit(1)

    # Determine identifier
    if cmdargs.identifier:
        identifier = cmdargs.identifier
    else:
        identifier = os.path.basename(repo_path)

    # Validate identifier (basic sanity check)
    if not identifier or '/' in identifier or identifier.startswith('.'):
        logger.critical('Invalid identifier: %s', identifier)
        sys.exit(1)

    # Check if this repository is already enrolled
    if not is_worktree:
        existing_id = get_repo_identifier(repo_path)
        if existing_id:
            logger.critical('Repository already enrolled with identifier: %s', existing_id)
            sys.exit(1)

    # Check if database already exists
    if db_exists(identifier):
        logger.info('Database already exists: %s', get_db_path(identifier))
        try:
            answer = input(f'Use existing database for this repository? (y/N) ')
        except KeyboardInterrupt:
            logger.info('')
            sys.exit(130)
        if answer.strip().lower() not in ('y', 'yes'):
            logger.info('Enroll cancelled.')
            sys.exit(0)
        logger.info('Using existing database: %s', get_db_path(identifier))
    else:
        # Create the database
        conn = init_db(identifier)
        conn.close()
        logger.info('Created tracking database: %s', get_db_path(identifier))

    # Create metadata file in .git directory if not a worktree
    if not is_worktree:
        save_repo_metadata(gitdir, identifier)
        logger.info('Created metadata file: %s', get_repo_metadata_path(gitdir))
    else:
        logger.info('Worktree detected - no metadata file created')
        logger.info('Use -i %s when running track commands in this worktree', identifier)

    logger.info('Project enrolled successfully with identifier: %s', identifier)


def add_series_to_db(conn: sqlite3.Connection, change_id: str, revision: int,
                     subject: Optional[str], sender_name: Optional[str],
                     sender_email: Optional[str], sent_at: Optional[str],
                     message_id: str, num_patches: int,
                     pw_series_id: Optional[int] = None,
                     fingerprint: Optional[str] = None) -> int:
    """Add a series to the tracking database. Returns the track_id."""
    added_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor = conn.execute('''
        INSERT INTO series
        (change_id, revision, subject, sender_name, sender_email, sent_at, added_at, message_id, num_patches, pw_series_id, fingerprint)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (change_id, revision) DO UPDATE SET
            subject = excluded.subject,
            sender_name = excluded.sender_name,
            sender_email = excluded.sender_email,
            sent_at = excluded.sent_at,
            added_at = excluded.added_at,
            message_id = excluded.message_id,
            num_patches = excluded.num_patches,
            pw_series_id = excluded.pw_series_id,
            fingerprint = excluded.fingerprint
        RETURNING track_id
    ''', (change_id, revision, subject, sender_name, sender_email, sent_at, added_at, message_id, num_patches, pw_series_id, fingerprint))
    track_id = cursor.fetchone()[0]
    conn.commit()
    return int(track_id)


def cmd_track(cmdargs: argparse.Namespace) -> None:
    """Track a series in the review database."""
    topdir = b4.git_get_toplevel()

    # Resolve identifier
    identifier = resolve_identifier(cmdargs, topdir)
    if not identifier:
        logger.critical('Could not determine project identifier.')
        logger.critical('Run from an enrolled repository or specify -i identifier')
        sys.exit(1)

    if not db_exists(identifier):
        logger.critical('Project not enrolled: %s', identifier)
        logger.critical('Run "b4 review enroll" first')
        sys.exit(1)

    # Parse the series identifier (message-id, URL, or change-id)
    # Support reading from stdin if no series_id provided
    series_id = cmdargs.series_id
    if not series_id:
        series_id = b4.get_msgid_from_stdin()
        if not series_id:
            logger.critical('No series identifier provided')
            logger.critical('Pipe a message or pass msgid/URL/change-id as parameter')
            sys.exit(1)

    # Set up cmdargs for retrieve_messages
    cmdargs.msgid = series_id
    cmdargs.localmbox = None
    cmdargs.nocache = False
    cmdargs.noparent = False
    cmdargs.wantname = None
    cmdargs.wantver = None

    # Retrieve the series
    logger.info('Retrieving series: %s', series_id)
    cmdargs.nocache = True
    msgid, msgs = b4.retrieve_messages(cmdargs)
    if not msgs:
        logger.critical('Could not retrieve series: %s', series_id)
        sys.exit(1)

    # Build the mailbox to determine the series revision
    lmbx = b4.LoreMailbox()
    for msg in msgs:
        lmbx.add_message(msg)

    if not lmbx.series:
        logger.critical('No series found in retrieved messages')
        sys.exit(1)

    # Get the latest revision by default, or specified version
    if hasattr(cmdargs, 'wantver') and cmdargs.wantver:
        wanted_ver = cmdargs.wantver
    else:
        wanted_ver = max(lmbx.series.keys())

    # Discover all available revisions (newer and older)
    if b4.can_network:
        msgs = b4.mbox.get_extra_series(msgs, direction=1, nocache=True)
        if wanted_ver > 1:
            msgs = b4.mbox.get_extra_series(msgs, direction=-1,
                                             wantvers=list(range(1, wanted_ver)),
                                             nocache=True)
        # Rebuild the mailbox with all discovered messages
        lmbx = b4.LoreMailbox()
        for msg in msgs:
            lmbx.add_message(msg)

    lser = lmbx.get_series(wanted_ver, sloppytrailers=False,
                           codereview_trailers=False)
    if not lser:
        logger.critical('Could not find series version %d', wanted_ver)
        sys.exit(1)

    # Extract series metadata
    revision = lser.revision
    sender_name = lser.fromname
    sender_email = lser.fromemail
    num_patches = lser.expected

    fingerprint = lser.fingerprint

    # Get message-id from cover letter or first patch
    ref_msg: Optional[b4.LoreMessage] = None
    if lser.has_cover and lser.patches[0] is not None:
        ref_msg = lser.patches[0]
    elif len(lser.patches) > 1 and lser.patches[1] is not None:
        ref_msg = lser.patches[1]

    if ref_msg is None:
        logger.critical('Could not find cover letter or first patch')
        sys.exit(1)

    message_id = ref_msg.msgid

    if lser.change_id:
        change_id = lser.change_id
        logger.debug('Using series change-id: %s', change_id)
    else:
        date_prefix = ref_msg.date.strftime('%Y%m%d')
        slug = ref_msg.lsubject.get_slug(sep='-', with_counter=False)[:60]
        change_id = f'{date_prefix}-{slug}-{fingerprint[:12]}'
        logger.info('No change-id found, generated: %s', change_id)

    # Check if this series is already tracked by change-id or by
    # content fingerprint.
    conn = get_db(identifier)
    existing = conn.execute(
        'SELECT status, revision, change_id FROM series'
        ' WHERE change_id = ? OR fingerprint = ?',
        (change_id, fingerprint),
    ).fetchone()
    if existing is not None:
        conn.close()
        logger.critical('This series is already tracked (status: %s, v%d)',
                        existing[0], existing[1])
        logger.critical('Change-ID: %s', existing[2])
        sys.exit(1)
    conn.close()

    # Get sent date
    sent_at: Optional[str] = None
    if ref_msg.date:
        sent_at = ref_msg.date.isoformat()

    # Add to database
    subject = lser.subject
    conn = get_db(identifier)
    add_series_to_db(conn, change_id, revision, subject, sender_name, sender_email,
                     sent_at, message_id, num_patches, fingerprint=fingerprint)

    # Record all discovered revisions
    config = b4.get_main_config()
    linkmask = str(config.get('linkmask', ''))
    for v in sorted(lmbx.series.keys()):
        v_ser = lmbx.series[v]
        v_msgid = ''
        v_subject = ''
        try:
            if hasattr(v_ser, 'patches') and v_ser.patches:
                for p in v_ser.patches:
                    if p is not None:
                        v_msgid = str(getattr(p, 'msgid', ''))
                        v_subject = str(getattr(p, 'full_subject', '') or getattr(p, 'subject', ''))
                        break
        except Exception:
            pass
        if not v_msgid:
            continue
        v_link = (linkmask % v_msgid) if v_msgid and '%s' in str(linkmask) else ''
        add_revision(conn, change_id, v, v_msgid, v_subject, v_link)

    conn.close()

    logger.info('Tracked series: %s v%d (%d patches)', subject, revision, num_patches)
    logger.info('  From: %s <%s>', sender_name, sender_email)
    logger.info('  Change-ID: %s', change_id)
    logger.info('  Message-ID: %s', message_id)
    if len(lmbx.series) > 1:
        versions = ', '.join(f'v{v}' for v in sorted(lmbx.series.keys()))
        logger.info('  Known revisions: %s', versions)


def get_tracked_pw_series_ids(identifier: str) -> set[int]:
    """Get the set of Patchwork series IDs that are tracked for a project."""
    if not db_exists(identifier):
        return set()
    try:
        conn = get_db(identifier)
        cursor = conn.execute('SELECT pw_series_id FROM series WHERE pw_series_id IS NOT NULL')
        result = {row[0] for row in cursor.fetchall()}
        conn.close()
        return result
    except Exception:
        return set()


def is_pw_series_tracked(identifier: str, pw_series_id: int) -> bool:
    """Check if a Patchwork series ID is tracked."""
    if not db_exists(identifier):
        return False
    try:
        conn = get_db(identifier)
        cursor = conn.execute(
            'SELECT 1 FROM series WHERE pw_series_id = ? LIMIT 1',
            (pw_series_id,)
        )
        result = cursor.fetchone() is not None
        conn.close()
        return result
    except Exception:
        return False


def get_all_tracked_series(identifier: str) -> list[dict[str, Any]]:
    """Get all tracked series for the TUI listing.

    Returns a list of dicts with keys: track_id, change_id, revision, subject,
    sender_name, sender_email, sent_at, added_at, status, num_patches,
    message_id, pw_series_id.
    """
    if not db_exists(identifier):
        return []
    try:
        conn = get_db(identifier)
        cursor = conn.execute('''
            SELECT track_id, change_id, revision, subject, sender_name, sender_email,
                   sent_at, added_at, status, num_patches, message_id, pw_series_id
            FROM series
            ORDER BY added_at DESC
        ''')
        result = []
        for row in cursor.fetchall():
            result.append({
                'track_id': row[0],
                'change_id': row[1],
                'revision': row[2],
                'subject': row[3] or '(no subject)',
                'sender_name': row[4] or 'Unknown',
                'sender_email': row[5] or '',
                'sent_at': row[6] or '',
                'added_at': row[7] or '',
                'status': row[8] or 'new',
                'num_patches': row[9] or 0,
                'message_id': row[10] or '',
                'pw_series_id': row[11],
            })
        conn.close()
        return result
    except Exception:
        return []


def add_revision(conn: sqlite3.Connection, change_id: str, revision: int,
                 message_id: str, subject: Optional[str] = None,
                 link: Optional[str] = None) -> None:
    """Insert a revision record, ignoring if already present."""
    found_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn.execute('''INSERT OR IGNORE INTO revisions
        (change_id, revision, message_id, subject, link, found_at)
        VALUES (?, ?, ?, ?, ?, ?)''',
                 (change_id, revision, message_id, subject, link, found_at))
    conn.commit()


def get_revisions(conn: sqlite3.Connection, change_id: str) -> list[dict[str, Any]]:
    """Return all known revisions for a change_id, ordered ascending."""
    cols = ('change_id', 'revision', 'message_id', 'subject', 'link', 'found_at')
    cursor = conn.execute(
        'SELECT change_id, revision, message_id, subject, link, found_at '
        'FROM revisions WHERE change_id = ? ORDER BY revision ASC',
        (change_id,))
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def get_newest_revision(conn: sqlite3.Connection, change_id: str) -> Optional[int]:
    """Return the highest known revision number, or None."""
    cursor = conn.execute(
        'SELECT MAX(revision) FROM revisions WHERE change_id = ?',
        (change_id,))
    row = cursor.fetchone()
    if row and row[0] is not None:
        return int(row[0])
    return None


def update_series_status(conn: sqlite3.Connection, change_id: str, status: str,
                         revision: Optional[int] = None) -> None:
    """Update the status of a tracked series.

    When *revision* is given only that specific revision is updated;
    otherwise all revisions sharing the *change_id* are updated (legacy
    behaviour kept for backwards compatibility).
    """
    if revision is not None:
        conn.execute('UPDATE series SET status = ? WHERE change_id = ? AND revision = ?',
                     (status, change_id, revision))
    else:
        conn.execute('UPDATE series SET status = ? WHERE change_id = ?', (status, change_id))
    conn.commit()


def delete_series(conn: sqlite3.Connection, change_id: str,
                  revision: Optional[int] = None) -> None:
    """Delete a series from the database.

    When *revision* is given only that specific revision is removed;
    otherwise all revisions sharing the *change_id* are removed (legacy
    behaviour kept for backwards compatibility).
    """
    if revision is not None:
        conn.execute('DELETE FROM revisions WHERE change_id = ? AND revision = ?',
                     (change_id, revision))
        conn.execute('DELETE FROM series WHERE change_id = ? AND revision = ?',
                     (change_id, revision))
    else:
        conn.execute('DELETE FROM revisions WHERE change_id = ?', (change_id,))
        conn.execute('DELETE FROM series WHERE change_id = ?', (change_id,))
    conn.commit()
