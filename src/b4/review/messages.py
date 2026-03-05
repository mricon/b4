#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import os
import pathlib
import sqlite3

from typing import Dict, List, Optional

import b4

SCHEMA_SQL = '''
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS messages (
    msgid    TEXT PRIMARY KEY,
    msg_date TEXT,
    flags    TEXT DEFAULT ''
);
'''

SCHEMA_VERSION = 1


def _get_db_path() -> str:
    """Return the path to the messages database."""
    datadir = b4.get_data_dir()
    msgdir = os.path.join(datadir, 'review')
    pathlib.Path(msgdir).mkdir(parents=True, exist_ok=True)
    return os.path.join(msgdir, 'messages.sqlite3')


def get_db() -> sqlite3.Connection:
    """Get a connection to the messages database, creating it if needed."""
    db_path = _get_db_path()
    is_new = not os.path.exists(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    if is_new:
        conn.executescript(SCHEMA_SQL)
        conn.execute(
            'INSERT OR REPLACE INTO schema_version (version) VALUES (?)',
            (SCHEMA_VERSION,))
        conn.commit()
    return conn


def get_flags(conn: sqlite3.Connection, msgid: str) -> str:
    """Return the flags string for a message, or '' if not stored."""
    row = conn.execute(
        'SELECT flags FROM messages WHERE msgid = ?', (msgid,)).fetchone()
    return row[0] if row else ''


def get_flags_bulk(conn: sqlite3.Connection,
                   msgids: List[str]) -> Dict[str, str]:
    """Return {msgid: flags} for all known messages in *msgids*."""
    if not msgids:
        return {}
    placeholders = ','.join('?' * len(msgids))
    cursor = conn.execute(
        f'SELECT msgid, flags FROM messages WHERE msgid IN ({placeholders})',
        msgids)
    return {row[0]: row[1] for row in cursor.fetchall()}


def set_flag(conn: sqlite3.Connection, msgid: str, flag: str,
             msg_date: Optional[str] = None) -> None:
    """Add *flag* to a message, creating the row if needed."""
    conn.execute(
        'INSERT INTO messages (msgid, msg_date, flags)'
        ' VALUES (?, ?, ?)'
        ' ON CONFLICT(msgid) DO NOTHING',
        (msgid, msg_date, flag))
    row = conn.execute(
        'SELECT flags FROM messages WHERE msgid = ?', (msgid,)).fetchone()
    if row:
        existing = set(row[0].split())
        if flag not in existing:
            existing.add(flag)
            conn.execute(
                'UPDATE messages SET flags = ? WHERE msgid = ?',
                (' '.join(sorted(existing)), msgid))
    conn.commit()


def set_flags_bulk(conn: sqlite3.Connection,
                   entries: List[Dict[str, Optional[str]]],
                   flag: str) -> None:
    """Add *flag* to multiple messages in one transaction.

    Each entry in *entries* is ``{'msgid': ..., 'msg_date': ...}``.
    """
    for entry in entries:
        msgid = entry.get('msgid', '')
        msg_date = entry.get('msg_date')
        if not msgid:
            continue
        conn.execute(
            'INSERT INTO messages (msgid, msg_date, flags)'
            ' VALUES (?, ?, ?)'
            ' ON CONFLICT(msgid) DO NOTHING',
            (msgid, msg_date, flag))
        row = conn.execute(
            'SELECT flags FROM messages WHERE msgid = ?',
            (msgid,)).fetchone()
        if row:
            existing = set(row[0].split())
            if flag not in existing:
                existing.add(flag)
                conn.execute(
                    'UPDATE messages SET flags = ? WHERE msgid = ?',
                    (' '.join(sorted(existing)), msgid))
    conn.commit()


def remove_flag(conn: sqlite3.Connection, msgid: str, flag: str) -> None:
    """Remove *flag* from a message. Deletes the row if no flags remain."""
    row = conn.execute(
        'SELECT flags FROM messages WHERE msgid = ?', (msgid,)).fetchone()
    if not row:
        return
    existing = set(row[0].split())
    existing.discard(flag)
    if existing:
        conn.execute(
            'UPDATE messages SET flags = ? WHERE msgid = ?',
            (' '.join(sorted(existing)), msgid))
    else:
        conn.execute('DELETE FROM messages WHERE msgid = ?', (msgid,))
    conn.commit()


def cleanup_old(conn: sqlite3.Connection, max_days: int = 180) -> int:
    """Delete messages older than *max_days*. Returns count deleted."""
    import datetime
    cutoff = (datetime.datetime.now(datetime.timezone.utc)
              - datetime.timedelta(days=max_days)).isoformat()
    cursor = conn.execute(
        'DELETE FROM messages WHERE msg_date IS NOT NULL AND msg_date < ?',
        (cutoff,))
    conn.commit()
    return cursor.rowcount
