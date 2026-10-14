#!/usr/bin/env python3
"""Convert an old send-receive.py database to the new SQLite file.

send-receive.py used to keep its auth table in any database SQLAlchemy
could reach (MySQL in production). It now uses a plain sqlite3 file.
This tool reads main.dburl from the old config and copies every record,
including pending challenges, into a new file at main.dbpath:

    send-receive-migrate.py -c /path/to/old.conf -o /path/to/auth.sqlite3

Supported dburl schemes are mysql+pymysql:// and sqlite:///.
"""

import argparse
import datetime
import os
import sqlite3
import sys
import tempfile
from configparser import ConfigParser, ExtendedInterpolation
from contextlib import closing
from typing import Any, List, Sequence, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

import pymysql

DB_VERSION = 1

# Must stay the same as SCHEMA in send-receive.py
SCHEMA = """
CREATE TABLE IF NOT EXISTS auth (
    auth_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    identity TEXT NOT NULL,
    selector TEXT NOT NULL,
    pubkey TEXT NOT NULL,
    challenge TEXT,
    verified INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_selector ON auth (identity, selector);
"""

COLUMNS = (
    'auth_id',
    'created',
    'identity',
    'selector',
    'pubkey',
    'challenge',
    'verified',
)
Row = Tuple[Any, ...]

SELECT_AUTH = f'SELECT {", ".join(COLUMNS)} FROM auth ORDER BY auth_id'


class MigrationError(Exception):
    pass


def read_mysql(dburl: str) -> Tuple[List[Row], int]:
    """Return the auth rows and the last auth_id MySQL handed out."""
    parts = urlsplit(dburl)
    charset = parse_qs(parts.query).get('charset', ['utf8mb4'])[0]
    conn = pymysql.connect(
        host=parts.hostname or 'localhost',
        port=parts.port or 3306,
        user=unquote(parts.username or ''),
        password=unquote(parts.password or ''),
        database=parts.path.lstrip('/'),
        charset=charset,
    )
    with conn, conn.cursor() as cur:
        cur.execute(SELECT_AUTH)
        rows = list(cur.fetchall())
        # The counter can be above max(auth_id) if the newest records were
        # deleted, and those ids may already be in published headers.
        # MySQL 8 caches it for a day unless told otherwise. Older servers
        # don't know the variable, but a stale value is only ever too low,
        # and then max(auth_id) still holds.
        try:
            cur.execute('SET SESSION information_schema_stats_expiry = 0')
        except pymysql.err.OperationalError:
            pass
        cur.execute(
            'SELECT AUTO_INCREMENT FROM information_schema.TABLES'
            " WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'auth'"
        )
        row = cur.fetchone()
    lastid = int(row[0]) - 1 if row and row[0] else 0
    return rows, lastid


def read_sqlite(dburl: str) -> Tuple[List[Row], int]:
    # SQLAlchemy writes sqlite:///relative and sqlite:////absolute
    path = urlsplit(dburl).path[1:]
    if not path or path == ':memory:':
        raise MigrationError(f'Nothing to migrate from {dburl}')
    if not os.path.exists(path):
        raise MigrationError(f'No such database: {path}')
    with closing(sqlite3.connect(f'file:{path}?mode=ro', uri=True)) as conn:
        rows = conn.execute(SELECT_AUTH).fetchall()
    # SQLAlchemy did not use AUTOINCREMENT, so ids were already reusable
    return rows, 0


def normalize(row: Row) -> Row:
    auth_id, created, identity, selector, pubkey, challenge, verified = row
    # CURRENT_TIMESTAMP format, so old and new records sort together
    if isinstance(created, datetime.datetime):
        created = created.strftime('%Y-%m-%d %H:%M:%S')
    return (
        int(auth_id),
        str(created),
        identity,
        selector,
        pubkey,
        challenge,
        int(verified),
    )


def write_sqlite(outfile: str, rows: List[Row], lastid: int) -> None:
    if os.path.exists(outfile):
        raise MigrationError(f'Refusing to overwrite {outfile}')
    # Build in a temporary file, so a failed run leaves nothing that
    # send-receive.py could mistake for a finished database
    fd, tmpfile = tempfile.mkstemp(
        dir=os.path.dirname(os.path.abspath(outfile)), suffix='.tmp'
    )
    os.close(fd)
    try:
        with closing(sqlite3.connect(tmpfile)) as conn:
            with conn:
                conn.executescript(SCHEMA)
                placeholders = ', '.join(['?'] * len(COLUMNS))
                try:
                    conn.executemany(
                        f'INSERT INTO auth ({", ".join(COLUMNS)})'
                        f' VALUES ({placeholders})',
                        [normalize(row) for row in rows],
                    )
                except sqlite3.IntegrityError as ex:
                    raise MigrationError(f'Source data does not fit: {ex}') from ex
                conn.execute(
                    "UPDATE sqlite_sequence SET seq = ? WHERE name = 'auth' AND seq < ?",
                    (lastid, lastid),
                )
                conn.execute(f'PRAGMA user_version = {DB_VERSION}')
        # Unlike a rename, link fails if outfile showed up in the meantime
        os.link(tmpfile, outfile)
    finally:
        os.unlink(tmpfile)


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        '-c', '--config', required=True, help='Old send-receive.py config with dburl'
    )
    ap.add_argument('-o', '--output', required=True, help='New SQLite file to create')
    args = ap.parse_args(argv)

    # Read dburl from the config, so the password never shows up in ps
    parser = ConfigParser(interpolation=ExtendedInterpolation())
    if not parser.read(args.config):
        sys.stderr.write(f'Could not read {args.config}\n')
        return 1
    dburl = parser['main'].get('dburl') if parser.has_section('main') else None
    if not dburl:
        sys.stderr.write(f'No main.dburl in {args.config}\n')
        return 1

    scheme = urlsplit(dburl).scheme
    try:
        if scheme in ('mysql', 'mysql+pymysql'):
            rows, lastid = read_mysql(dburl)
        elif scheme == 'sqlite':
            rows, lastid = read_sqlite(dburl)
        else:
            raise MigrationError(f'Unsupported database scheme: {scheme}')
        write_sqlite(args.output, rows, lastid)
    except MigrationError as ex:
        sys.stderr.write(f'{ex}\n')
        return 1

    verified = sum(1 for row in rows if int(row[6]))
    print(
        f'Wrote {len(rows)} records ({verified} verified,'
        f' {len(rows) - verified} pending) to {args.output}'
    )
    print('The file is only readable by you, chown it to the web user.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
