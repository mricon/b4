#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import argparse
import datetime
import gzip
import json
import os
import pathlib
import sqlite3
import sys
import urllib.parse

import b4
import b4.mbox

from typing import Any, Dict, List, Optional, Set, Tuple

logger = b4.logger

REVIEW_METADATA_DIR = 'b4-review'
REVIEW_METADATA_FILE = 'metadata.json'

SCHEMA_VERSION = 3

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
    branch_sha TEXT,
    followup_count INT,
    seen_followup_count INT,
    last_update_check TEXT,
    last_activity_at TEXT,
    snoozed_until TEXT,
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


def _migrate_db_if_needed(conn: sqlite3.Connection) -> None:
    """Apply any pending schema migrations in-place."""
    row = conn.execute('SELECT version FROM schema_version').fetchone()
    version = row[0] if row else 0
    if version >= SCHEMA_VERSION:
        return
    if version < 2:
        conn.execute('ALTER TABLE series ADD COLUMN branch_sha TEXT')
        conn.execute('ALTER TABLE series ADD COLUMN followup_count INT')
        conn.execute('ALTER TABLE series ADD COLUMN seen_followup_count INT')
        conn.execute('ALTER TABLE series ADD COLUMN last_update_check TEXT')
        conn.execute('ALTER TABLE series ADD COLUMN last_activity_at TEXT')
    if version < 3:
        conn.execute("UPDATE series SET status = 'accepted' WHERE status = 'taken'")
        conn.execute('ALTER TABLE series ADD COLUMN snoozed_until TEXT')
    conn.execute('UPDATE schema_version SET version = ?', (SCHEMA_VERSION,))
    conn.commit()


def get_db(identifier: str) -> sqlite3.Connection:
    """Get a database connection for the given identifier."""
    db_path = get_db_path(identifier)
    if not os.path.exists(db_path):
        raise FileNotFoundError(f'No database found for identifier: {identifier}')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    _migrate_db_if_needed(conn)
    return conn


def get_repo_metadata_path(gitdir: str) -> str:
    """Get the path to the metadata file in a git repository."""
    return os.path.join(gitdir, REVIEW_METADATA_DIR, REVIEW_METADATA_FILE)


def get_repo_identifier(topdir: str) -> Optional[str]:
    """Get the project identifier from a repository's metadata file."""
    gitdir = b4.git_get_common_dir(topdir)
    if not gitdir:
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


def get_recent_take_branches(gitdir: str, limit: int = 20) -> List[str]:
    """Return recently used take branches, most recent first."""
    metadata_path = get_repo_metadata_path(gitdir)
    if not os.path.exists(metadata_path):
        return []
    try:
        with open(metadata_path, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    branches = data.get('recent-take-branches', [])
    if not isinstance(branches, list):
        return []
    return [b for b in branches if isinstance(b, str)][:limit]


def record_take_branch(gitdir: str, branch: str) -> None:
    """Prepend branch to the recent-take-branches list in metadata.json."""
    metadata_dir = os.path.join(gitdir, REVIEW_METADATA_DIR)
    pathlib.Path(metadata_dir).mkdir(parents=True, exist_ok=True)
    metadata_path = get_repo_metadata_path(gitdir)
    data: Dict[str, Any] = {}
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    if not isinstance(data, dict):
        data = {}
    branches = data.get('recent-take-branches', [])
    if not isinstance(branches, list):
        branches = []
    # Remove existing entry so we can move it to the front
    branches = [b for b in branches if b != branch]
    branches.insert(0, branch)
    data['recent-take-branches'] = branches[:20]
    with open(metadata_path, 'w') as f:
        json.dump(data, f, indent=2)
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

    # Resolve the shared .git directory (works for both main repos and worktrees)
    gitdir = b4.git_get_common_dir(repo_path)
    if not gitdir:
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
    existing_id = get_repo_identifier(repo_path)
    if existing_id:
        if existing_id == identifier:
            logger.info('Repository already enrolled with identifier: %s', existing_id)
            sys.exit(0)
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

    # Create metadata file in shared .git directory
    save_repo_metadata(gitdir, identifier)
    logger.info('Created metadata file: %s', get_repo_metadata_path(gitdir))

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
    message_id, pw_series_id, followup_count, seen_followup_count.
    """
    if not db_exists(identifier):
        return []
    try:
        conn = get_db(identifier)
        cursor = conn.execute('''
            SELECT track_id, change_id, revision, subject, sender_name, sender_email,
                   sent_at, added_at, status, num_patches, message_id, pw_series_id,
                   followup_count, seen_followup_count, last_activity_at
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
                'followup_count': row[12],
                'seen_followup_count': row[13],
                'last_activity_at': row[14],
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

    Always stamps last_activity_at with the current UTC time so that
    within-group sort reflects maintainer activity as well as thread activity.
    """
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if revision is not None:
        conn.execute(
            'UPDATE series SET status = ?, last_activity_at = ?'
            ' WHERE change_id = ? AND revision = ?',
            (status, now, change_id, revision))
    else:
        conn.execute(
            'UPDATE series SET status = ?, last_activity_at = ?'
            ' WHERE change_id = ?',
            (status, now, change_id))
    conn.commit()


def snooze_series(conn: sqlite3.Connection, change_id: str,
                  until_date: str, revision: Optional[int] = None) -> None:
    """Set a series to snoozed status with a wake-up date.

    Args:
        conn: Database connection.
        change_id: The change-id of the series.
        until_date: ISO date string (YYYY-MM-DD) when the series should wake up.
        revision: If given, only snooze that specific revision.
    """
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if revision is not None:
        conn.execute(
            'UPDATE series SET status = ?, snoozed_until = ?, last_activity_at = ?'
            ' WHERE change_id = ? AND revision = ?',
            ('snoozed', until_date, now, change_id, revision))
    else:
        conn.execute(
            'UPDATE series SET status = ?, snoozed_until = ?, last_activity_at = ?'
            ' WHERE change_id = ?',
            ('snoozed', until_date, now, change_id))
    conn.commit()


def unsnooze_series(conn: sqlite3.Connection, change_id: str,
                    previous_status: str, revision: Optional[int] = None) -> None:
    """Restore a snoozed series to its previous status.

    Args:
        conn: Database connection.
        change_id: The change-id of the series.
        previous_status: The status to restore (e.g. 'reviewing').
        revision: If given, only unsnooze that specific revision.
    """
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if revision is not None:
        conn.execute(
            'UPDATE series SET status = ?, snoozed_until = NULL, last_activity_at = ?'
            ' WHERE change_id = ? AND revision = ?',
            (previous_status, now, change_id, revision))
    else:
        conn.execute(
            'UPDATE series SET status = ?, snoozed_until = NULL, last_activity_at = ?'
            ' WHERE change_id = ?',
            (previous_status, now, change_id))
    conn.commit()


def get_expired_snoozed(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Return all snoozed series whose wake-up time has passed."""
    cursor = conn.execute(
        "SELECT change_id, revision, snoozed_until FROM series"
        " WHERE status = 'snoozed'"
        " AND snoozed_until <= strftime('%Y-%m-%dT%H:%M:%S', 'now')"
    )
    results = []
    for row in cursor:
        results.append({
            'change_id': row[0],
            'revision': row[1],
            'snoozed_until': row[2],
        })
    return results


def get_tag_snoozed(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Return all snoozed series waiting for a git tag to appear."""
    cursor = conn.execute(
        "SELECT change_id, revision, snoozed_until FROM series"
        " WHERE status = 'snoozed'"
        " AND snoozed_until LIKE 'tag:%'"
    )
    results = []
    for row in cursor:
        results.append({
            'change_id': row[0],
            'revision': row[1],
            'snoozed_until': row[2],
        })
    return results


def get_snoozed_until(conn: sqlite3.Connection, change_id: str,
                      revision: Optional[int] = None) -> Optional[str]:
    """Return the snoozed_until date for a series, or None."""
    if revision is not None:
        row = conn.execute(
            'SELECT snoozed_until FROM series WHERE change_id = ? AND revision = ?',
            (change_id, revision)).fetchone()
    else:
        row = conn.execute(
            'SELECT snoozed_until FROM series WHERE change_id = ?',
            (change_id,)).fetchone()
    return row[0] if row else None


def get_review_branches(topdir: Optional[str] = None) -> list[str]:
    """List all b4/review/* branch names."""
    gitargs = ['for-each-ref', '--format=%(refname:short)', 'refs/heads/b4/review/']
    return b4.git_get_command_lines(topdir, gitargs)


def _resolve_canonical_url(message_id: str) -> Optional[str]:
    """Resolve the canonical public-inbox URL for a message ID.

    Performs a HEAD request via midmask and follows any redirect to find the
    list-specific canonical URL (e.g. https://lore.kernel.org/linux-kernel/msgid/).

    Returns the canonical URL (with trailing slash stripped), or None on failure.
    """
    if not b4.can_network:
        return None
    config = b4.get_main_config()
    midmask = config.get('midmask', b4.LOREADDR + '/r/%s')
    if not isinstance(midmask, str) or '%s' not in midmask:
        return None
    qmsgid = urllib.parse.quote_plus(message_id, safe='@')
    midurl = (midmask % qmsgid).rstrip('/')
    try:
        session = b4.get_requests_session()
        resp = session.head(midurl + '/', allow_redirects=False, timeout=10)
        if resp.status_code in (301, 302) and 'Location' in resp.headers:
            return resp.headers['Location'].rstrip('/')
        if resp.status_code < 400:
            return midurl
        return None
    except Exception as ex:
        logger.debug('Could not resolve canonical URL for %s: %s', message_id, ex)
        return None


def _fetch_mbox_bytes(canonical_url: str) -> Optional[bytes]:
    """Fetch and decompress the full thread mbox from public-inbox t.mbox.gz."""
    try:
        session = b4.get_requests_session()
        resp = session.get(f'{canonical_url}/t.mbox.gz', timeout=30)
        if resp.status_code != 200:
            return None
        return gzip.decompress(resp.content)
    except Exception as ex:
        logger.debug('Could not fetch mbox for %s: %s', canonical_url, ex)
        return None


def _latest_date_from_mbox(mbox_bytes: bytes) -> Optional[str]:
    """Return the most recent Date: header from mbox bytes as an ISO timestamp."""
    import email.utils as eu
    latest: Optional[datetime.datetime] = None
    for line in mbox_bytes.split(b'\n'):
        if not line.lower().startswith(b'date:'):
            continue
        date_str = line[5:].strip().decode('utf-8', errors='replace')
        try:
            dt = eu.parsedate_to_datetime(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            if latest is None or dt > latest:
                latest = dt
        except Exception:
            continue
    if latest is None:
        return None
    return latest.astimezone(datetime.timezone.utc).isoformat()


def fetch_thread_reply_count(message_id: str, num_patches: int) -> Optional[int]:
    """Fetch the full followup reply count for a thread via public-inbox t.mbox.gz.

    This is the first-fetch path: downloads the full thread mbox and counts
    the messages, then subtracts the original series messages (cover + patches)
    to get the followup count.

    Returns the followup count (>= 0), or None on failure or when offline.
    """
    canonical_url = _resolve_canonical_url(message_id)
    if canonical_url is None:
        return None
    mbox_bytes = _fetch_mbox_bytes(canonical_url)
    if mbox_bytes is None:
        return None
    total = sum(1 for line in mbox_bytes.split(b'\n') if line.startswith(b'From '))
    return max(0, total - num_patches - 1)


def _fetch_new_since(canonical_url: str, since: str) -> Optional[Tuple[int, Optional[str]]]:
    """Fetch new thread messages since a timestamp via public-inbox dt: query.

    Uses the public-inbox ``dt:`` date-range query — a POST to
    ``{canonical_url}/?x=m&q=dt:{since}..``.  Returns an empty gzipped mbox
    when nothing has arrived, making the no-op case very cheap.

    *since* is an ISO-format timestamp stored in the database.

    Returns ``(count, latest_date_iso)`` where *count* is the number of new
    messages (0 if none) and *latest_date_iso* is the most recent Date: header
    found (None if no messages or no parseable date).  Returns None on error.
    """
    try:
        dt = datetime.datetime.fromisoformat(since)
        since_fmt = dt.strftime('%Y%m%d%H%M%S')
    except (ValueError, TypeError) as ex:
        logger.debug('Could not parse last_update_check timestamp %r: %s', since, ex)
        return None

    query = urllib.parse.quote_plus(f'dt:{since_fmt}..')
    query_url = f'{canonical_url}/?x=m&q={query}'
    try:
        session = b4.get_requests_session()
        resp = session.post(query_url, data='', timeout=15)
        if resp.status_code != 200:
            return None
        if not resp.content:
            return (0, None)
        try:
            mbox_bytes = gzip.decompress(resp.content)
        except Exception:
            mbox_bytes = resp.content
        if not mbox_bytes.strip():
            return (0, None)
        count = sum(1 for line in mbox_bytes.split(b'\n') if line.startswith(b'From '))
        latest_date = _latest_date_from_mbox(mbox_bytes)
        return (count, latest_date)
    except Exception as ex:
        logger.debug('dt: query failed for %s: %s', canonical_url, ex)
        return None


def _store_thread_blob(topdir: str, change_id: str,
                       msgs: List[Any]) -> Optional[str]:
    """Serialize msgs to mboxrd and write as a git blob; update tracking commit.

    Also writes thread-context-blob (the plain-text rendered context for the
    AI agent) in the same save_tracking_ref call to avoid a second write.

    Returns the mbox blob SHA, or None on failure.  Non-fatal: a failure here
    just means the next 'f' press will fall back to a live lore fetch.
    """
    # Local import first — avoids circular deps AND prevents UnboundLocalError
    # that would occur if `import b4.review` appeared after a `b4.xxx` call.
    import io
    import b4.review as _b4_review

    buf = io.BytesIO()
    b4.save_mboxrd_mbox(msgs, buf)
    mbox_bytes = buf.getvalue()
    if not mbox_bytes:
        logger.debug('No bytes to store for thread blob for %s', change_id)
        return None

    ecode, out = b4.git_run_command(topdir,
                                    ['hash-object', '-w', '--stdin'],
                                    stdin=mbox_bytes)
    if ecode != 0:
        logger.debug('Could not write thread blob for %s', change_id)
        return None
    blob_sha = out.strip()

    branch_name = f'b4/review/{change_id}'
    if b4.git_branch_exists(topdir, branch_name):
        try:
            cover_text, tracking = _b4_review.load_tracking(topdir, branch_name)
            series = tracking.get('series', {})
            changed = False

            if series.get('thread-blob') != blob_sha:
                series['thread-blob'] = blob_sha
                changed = True

            # Build and store the context blob in the same write.
            cover_msgid = series.get('header-info', {}).get('msgid')
            cover_subject = series.get('subject', '')
            patches = tracking.get('patches', [])
            followup_comments = _parse_msgs_to_followup_comments(
                msgs, cover_msgid, patches)
            context_text = _render_thread_context(
                followup_comments, patches, cover_subject)
            if context_text.strip():
                ctx_bytes = context_text.encode()
                ecode2, ctx_out = b4.git_run_command(
                    topdir, ['hash-object', '-w', '--stdin'], stdin=ctx_bytes)
                if ecode2 == 0:
                    ctx_sha = ctx_out.strip()
                    if series.get('thread-context-blob') != ctx_sha:
                        series['thread-context-blob'] = ctx_sha
                        changed = True

            if changed:
                _b4_review.save_tracking_ref(topdir, branch_name,
                                             cover_text, tracking)
        except Exception as ex:
            logger.debug('Could not update thread blobs for %s: %s',
                         change_id, ex)
    return blob_sha


def get_thread_mbox(topdir: str, blob_sha: str) -> Optional[bytes]:
    """Read cached thread mbox bytes from a git blob; None if unavailable (e.g. GC'd)."""
    ecode, out = b4.git_run_command(topdir, ['cat-file', 'blob', blob_sha],
                                    decode=False)
    if ecode != 0:
        logger.debug("Followup blob %s not found (may have been GC'd)", blob_sha)
        return None
    return out  # type: ignore[return-value]  — bytes when decode=False


def _resolve_patch_for_followup_local(
    in_reply_to: Optional[str],
    patch_msgids: Dict[str, int],
    msgid_map: Dict[str, Any],
) -> Optional[int]:
    """Walk the in_reply_to chain to find which patch a follow-up belongs to.

    Returns the display index (0=cover, 1..N=patches) or None.
    Duplicated from review_tui._common to avoid a cross-layer import.
    """
    seen: set = set()
    current = in_reply_to
    while current and current not in seen:
        if current in patch_msgids:
            return patch_msgids[current]
        seen.add(current)
        lmsg = msgid_map.get(current)
        if lmsg is None:
            break
        current = lmsg.in_reply_to
    return None


def _get_followup_depth_local(
    in_reply_to: Optional[str],
    patch_msgids: Dict[str, int],
    msgid_map: Dict[str, Any],
    max_depth: int = 5,
) -> int:
    """Return the threading depth of a follow-up relative to its patch.

    Depth 0 = direct reply to a patch; depth N = N hops through follow-up
    replies. Capped at max_depth to prevent runaway indentation.
    Duplicated from review_tui._common to avoid a cross-layer import.
    """
    depth = 0
    seen: Set[str] = set()
    current = in_reply_to
    while current and current not in seen:
        if current in patch_msgids:
            break
        seen.add(current)
        lmsg = msgid_map.get(current)
        if lmsg is None:
            break
        depth += 1
        current = lmsg.in_reply_to
    return min(depth, max_depth)


def _parse_msgs_to_followup_comments(
    msgs: List[Any],
    cover_msgid: Optional[str],
    patches: List[Dict[str, Any]],
) -> Dict[int, List[Dict[str, Any]]]:
    """Parse email messages into a followup-comments dict.

    Returns Dict[display_idx -> List[{body, fromname, fromemail, date}]].
    display_idx 0 = cover letter, 1..N = patches.
    """
    minimised = b4.mbox.minimize_thread(list(msgs))
    minimised_body_map: Dict[str, str] = {}
    for mmsg in minimised:
        mid = b4.LoreMessage.clean_header(mmsg.get('Message-ID', ''))
        if mid:
            mid = mid.strip('<>')
            payload = mmsg.get_payload(decode=True)
            if isinstance(payload, bytes):
                minimised_body_map[mid] = payload.decode(errors='replace')
            elif isinstance(payload, str):
                minimised_body_map[mid] = payload

    lmbx = b4.LoreMailbox()
    for msg in msgs:
        lmbx.add_message(msg)

    patch_msgids: Dict[str, int] = {}
    if cover_msgid:
        patch_msgids[cover_msgid] = 0
    for i, pmeta in enumerate(patches):
        pmsgid = pmeta.get('header-info', {}).get('msgid')
        if pmsgid:
            patch_msgids[pmsgid] = i + 1

    followup_comments: Dict[int, List[Dict[str, Any]]] = {}
    for lmsg in sorted(lmbx.followups, key=lambda m: m.date):
        display_idx = _resolve_patch_for_followup_local(
            lmsg.in_reply_to, patch_msgids, lmbx.msgid_map)
        if display_idx is None:
            continue
        mbody = minimised_body_map.get(lmsg.msgid, '').strip()
        if not mbody:
            continue
        mbody_lines = [ln for ln in mbody.splitlines() if ln.strip()]
        if len(mbody_lines) <= 2 and mbody_lines[-1].strip().endswith(':'):
            continue
        _htrs, _cmsg, mtrs, _basement, _sig = b4.LoreMessage.get_body_parts(lmsg.body)
        if mtrs:
            trailer_block = '\n'.join(t.as_string() for t in mtrs)
            mbody = mbody.rstrip('\n') + '\n\n' + trailer_block
        entry: Dict[str, Any] = {
            'body': mbody,
            'fromname': lmsg.fromname,
            'fromemail': lmsg.fromemail,
            'date': lmsg.date,
            'msgid': lmsg.msgid,
            'subject': lmsg.subject,
            'depth': _get_followup_depth_local(lmsg.in_reply_to, patch_msgids, lmbx.msgid_map),
        }
        followup_comments.setdefault(display_idx, []).append(entry)

    for fc_list in followup_comments.values():
        fc_list.sort(key=lambda e: e['date'])

    return followup_comments


def _render_thread_context(
    followup_comments: Dict[int, List[Dict[str, Any]]],
    patches: List[Dict[str, Any]],
    cover_subject: str,
) -> str:
    """Render a followup-comments dict as a human-readable plain-text string."""
    lines: List[str] = []
    n_patches = len(patches)
    for display_idx in sorted(followup_comments.keys()):
        fc_list = followup_comments[display_idx]
        if not fc_list:
            continue
        if display_idx == 0:
            section = f'Follow-up: cover letter ({cover_subject})'
        else:
            patch_idx = display_idx - 1
            title = (patches[patch_idx].get('title', f'patch {display_idx}')
                     if patch_idx < len(patches) else f'patch {display_idx}')
            section = f'Follow-up: patch {display_idx}/{n_patches} — {title}'
        lines.append(f'== {section} ==')
        lines.append('')
        for entry in fc_list:
            date_str = (entry['date'].strftime('%Y-%m-%d %H:%M %z')
                        if entry.get('date') else '')
            lines.append(f"From: {entry['fromname']} <{entry['fromemail']}> | {date_str}")
            lines.append('')
            lines.append(entry['body'].rstrip())
            lines.append('')
    return '\n'.join(lines)


def ensure_thread_context_blob(topdir: str, change_id: str,
                                series: Dict[str, Any],
                                patches: List[Dict[str, Any]]) -> Optional[str]:
    """Ensure thread-context-blob exists in the tracking commit.

    Migration aid: if thread-blob was written before this feature existed
    (no thread-context-blob key), parse the stored mbox and write the context
    blob now.  Also updates the in-memory *series* dict so the caller sees
    the new key immediately.

    Returns the context blob SHA, or None if thread-blob doesn't exist or the
    operation fails.
    """
    import b4.review as _b4_review

    if series.get('thread-context-blob'):
        return series['thread-context-blob']

    blob_sha = series.get('thread-blob')
    if not blob_sha:
        return None

    mbox_bytes = get_thread_mbox(topdir, blob_sha)
    if not mbox_bytes:
        return None

    msgs = b4.split_and_dedupe_pi_results(mbox_bytes)
    if not msgs:
        return None

    cover_msgid = series.get('header-info', {}).get('msgid')
    cover_subject = series.get('subject', '')
    followup_comments = _parse_msgs_to_followup_comments(msgs, cover_msgid, patches)
    context_text = _render_thread_context(followup_comments, patches, cover_subject)
    if not context_text.strip():
        return None

    ctx_bytes = context_text.encode()
    ecode, out = b4.git_run_command(topdir, ['hash-object', '-w', '--stdin'],
                                    stdin=ctx_bytes)
    if ecode != 0:
        logger.debug('Could not write thread-context blob for %s', change_id)
        return None
    ctx_sha = out.strip()

    branch_name = f'b4/review/{change_id}'
    if b4.git_branch_exists(topdir, branch_name):
        try:
            cover_text, tracking = _b4_review.load_tracking(topdir, branch_name)
            if tracking.get('series', {}).get('thread-context-blob') != ctx_sha:
                tracking['series']['thread-context-blob'] = ctx_sha
                _b4_review.save_tracking_ref(topdir, branch_name, cover_text, tracking)
        except Exception as ex:
            logger.debug('Could not persist thread-context-blob for %s: %s', change_id, ex)

    series['thread-context-blob'] = ctx_sha
    return ctx_sha


def update_followup_counts(identifier: str,
                           series_list: List[Dict[str, Any]],
                           topdir: Optional[str] = None) -> Dict[str, int]:
    """Fetch and store followup reply counts for a list of series.

    For each active series in *series_list* that has a message_id:

    - **First fetch** (``followup_count IS NULL``): downloads the full t.json
      thread index and stores the count.  ``seen_followup_count`` is initialised
      to the same value so no badge appears until *new* activity arrives.
    - **Incremental** (``followup_count IS NOT NULL``): POSTs a ``dt:`` query
      for messages newer than ``last_update_check``.  An empty response (nothing
      new) produces **zero database writes**, keeping the DB mtime stable and
      suppressing spurious list reloads in the TUI.

    Returns ``{'updated': n, 'errors': n}`` where *updated* counts series whose
    ``followup_count`` actually changed.
    """
    updated = 0
    errors = 0
    skip_statuses = frozenset(('archived', 'accepted', 'thanked', 'snoozed'))
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    try:
        conn = get_db(identifier)
    except FileNotFoundError:
        return {'updated': 0, 'errors': 0}

    for series in series_list:
        if series.get('status') in skip_statuses:
            continue
        message_id = series.get('message_id', '')
        if not message_id:
            continue
        num_patches = int(series.get('num_patches') or 0)
        change_id = series.get('change_id', '')
        revision = series.get('revision', 1)
        if not change_id:
            continue

        row = conn.execute(
            'SELECT followup_count, seen_followup_count, last_update_check'
            ' FROM series WHERE change_id = ? AND revision = ?',
            (change_id, revision)).fetchone()

        existing_count = row['followup_count'] if row else None
        last_check = row['last_update_check'] if row else None

        canonical_url = _resolve_canonical_url(message_id)
        if canonical_url is None:
            errors += 1
            continue

        if existing_count is None or last_check is None:
            # ── First fetch: download full thread mbox ───────────────────────
            mbox_bytes = _fetch_mbox_bytes(canonical_url)
            if mbox_bytes is None:
                errors += 1
                continue
            total = sum(1 for line in mbox_bytes.split(b'\n') if line.startswith(b'From '))
            count = max(0, total - num_patches - 1)
            last_activity = _latest_date_from_mbox(mbox_bytes)
            conn.execute(
                'UPDATE series'
                ' SET followup_count = ?, seen_followup_count = ?,'
                '     last_update_check = ?, last_activity_at = ?'
                ' WHERE change_id = ? AND revision = ?',
                (count, count, now, last_activity, change_id, revision))
            conn.commit()
            updated += 1
            if topdir:
                parsed = b4.split_and_dedupe_pi_results(mbox_bytes)
                if parsed:
                    _store_thread_blob(topdir, change_id, parsed)
        else:
            # ── Incremental: dt: query for messages since last check ─────────
            result = _fetch_new_since(canonical_url, last_check)
            if result is None:
                errors += 1
                continue
            new_count, new_activity = result
            if new_count > 0:
                # New replies arrived — update count, timestamp, and latest activity
                conn.execute(
                    'UPDATE series'
                    ' SET followup_count = followup_count + ?, last_update_check = ?,'
                    '     last_activity_at = COALESCE(?, last_activity_at)'
                    ' WHERE change_id = ? AND revision = ?',
                    (new_count, now, new_activity, change_id, revision))
                conn.commit()
                updated += 1
                if topdir:
                    new_mbox = _fetch_mbox_bytes(canonical_url)
                    if new_mbox:
                        parsed = b4.split_and_dedupe_pi_results(new_mbox)
                        if parsed:
                            _store_thread_blob(topdir, change_id, parsed)
            # new_count == 0: nothing changed, no DB write at all

    conn.close()
    return {'updated': updated, 'errors': errors}


def mark_followups_seen(conn: sqlite3.Connection, change_id: str,
                        revision: int) -> None:
    """Set seen_followup_count = followup_count, clearing the unread badge."""
    conn.execute(
        'UPDATE series SET seen_followup_count = followup_count'
        ' WHERE change_id = ? AND revision = ?',
        (change_id, revision))
    conn.commit()


def rescan_branches(identifier: str, topdir: str,
                    branch: Optional[str] = None) -> Dict[str, int]:
    """Rescan review branches and sync status/metadata into the tracking DB.

    Iterates b4/review/* branches (or a single branch if specified).  For each
    branch the HEAD commit SHA is compared against the value stored in the DB;
    if they match the branch is skipped entirely (fast path).  Only branches
    whose SHA has changed (or that have no stored SHA) are fully re-read and
    upserted.  When doing a full rescan (branch=None), series whose branches
    have disappeared are marked as 'gone'.

    Returns ``{'gone': n, 'changed': n}`` where ``changed`` is the number of
    branches whose SHA differed and were re-processed.
    """
    import email.utils
    import b4.review

    if branch:
        branches = [branch]
    else:
        branches = get_review_branches(topdir)

    conn = get_db(identifier)
    scanned_change_ids: set[str] = set()
    changed = 0

    for br in branches:
        # Derive change_id from the branch name for the fast SHA check.
        change_id_from_branch = br.removeprefix('b4/review/')

        # Read the current HEAD SHA with a single cheap rev-parse call.
        ecode, sha_out = b4.git_run_command(topdir, ['rev-parse', br])
        if ecode != 0:
            logger.warning('Could not resolve HEAD for %s, skipping', br)
            continue
        current_sha = sha_out.strip()

        # Check the stored SHA for the most recent revision of this change_id.
        stored = conn.execute(
            'SELECT branch_sha FROM series WHERE change_id = ?'
            ' ORDER BY revision DESC LIMIT 1',
            (change_id_from_branch,)).fetchone()
        if stored and stored['branch_sha'] == current_sha:
            # Branch HEAD unchanged — skip the expensive tracking-commit read.
            scanned_change_ids.add(change_id_from_branch)
            continue

        # SHA changed (or no record yet) — do the full read and upsert.
        try:
            _cover_text, tracking = b4.review.load_tracking(topdir, br)
        except (SystemExit, Exception):
            logger.warning('Could not load tracking from %s, skipping', br)
            continue

        series = tracking.get('series', {})
        track_id_value = series.get('identifier')

        # Verify identifier matches (skip if mismatch)
        if track_id_value and track_id_value != identifier:
            logger.warning('Branch %s has identifier %s, expected %s; skipping',
                           br, track_id_value, identifier)
            continue

        change_id = series.get('change-id')
        if not change_id:
            logger.warning('Branch %s has no change-id, skipping', br)
            continue

        scanned_change_ids.add(change_id)
        status = series.get('status', 'reviewing')
        revision = series.get('revision', 1)

        # Parse sent date from header-info
        sent_at = None
        sentdate = series.get('header-info', {}).get('sentdate')
        if sentdate:
            try:
                dt = email.utils.parsedate_to_datetime(sentdate)
                sent_at = dt.isoformat()
            except Exception:
                pass

        message_id = series.get('header-info', {}).get('msgid', '')

        # Upsert metadata and sync status from the tracking commit.
        add_series_to_db(conn, change_id,
                         revision=revision,
                         subject=series.get('subject'),
                         sender_name=series.get('fromname'),
                         sender_email=series.get('fromemail'),
                         sent_at=sent_at,
                         message_id=message_id,
                         num_patches=series.get('expected', 0))
        update_series_status(conn, change_id, status, revision=revision)

        # Persist the new HEAD SHA so future rescans can skip this branch.
        conn.execute('UPDATE series SET branch_sha = ? WHERE change_id = ? AND revision = ?',
                     (current_sha, change_id, revision))
        conn.commit()

        logger.info('Rescanned: %s (status: %s)', change_id, status)
        changed += 1

    # Full rescan: mark missing branches as "gone"
    gone = 0
    if not branch:
        all_series = get_all_tracked_series(identifier)
        active_statuses = ('reviewing', 'replied', 'waiting')
        for s in all_series:
            sid = s.get('change_id')
            if not sid:
                continue
            if (s.get('status') in active_statuses
                    and sid not in scanned_change_ids):
                branch_name = f'b4/review/{sid}'
                if not b4.git_branch_exists(topdir, branch_name):
                    update_series_status(conn, sid, 'gone',
                                         revision=s.get('revision'))
                    logger.info('Marked as gone: %s', sid)
                    gone += 1

    conn.close()
    return {'gone': gone, 'changed': changed}



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
