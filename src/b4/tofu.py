#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Trust on first use (TOFU) for patatt ed25519 keys.

patatt puts the full ed25519 public key into the ``X-Developer-Key``
header of every message it signs.  When no keyring has a key for the
signer, we check the signature against that embedded key instead.  The
first key we see for an address is pinned, later series signed with
the same key make it more trusted, and a series signed with a different
key gets a loud warning.

Only series members (cover letters and patches) can pin a key or add to
its count.  Follow-ups are checked against the pins, but never change
them.

Everything is stored in ``tofu.sqlite3`` in the b4 data directory.  It
is not a cache: losing it means losing all trust history.
"""

import datetime
import email.utils
import hashlib
import os
import sqlite3
import time
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

import b4
import patatt

if TYPE_CHECKING:
    from b4 import LoreAttestor, LoreMessage, LoreSeries

logger = b4.logger

DEVKEY_HDR = 'X-Developer-Key'
TOFU_ALGO = 'ed25519'
SCHEMA_VERSION = 1

# Results of checking a signature against its embedded key never
# change, but we do not need to keep them forever.
EMBEDDED_KEEP_SECS = 30 * 86400

# Statuses that stop b4 under attestation-policy=hardfail
CRITICAL_STATUSES = ('tofu-changed', 'tofu-rejected')
# Statuses that count as a valid signature
PASSING_STATUSES = ('tofu', 'tofu-new')

# (sources, identity, cwd) -> keys found in the keyrings
_keyring_cache: Dict[Tuple[Tuple[str, ...], str, str], List[str]] = dict()
# (identity, pk) pairs we already printed a warning for in this run
_warned: Set[Tuple[str, str]] = set()


def enabled() -> bool:
    """Return True if TOFU is turned on."""
    config = b4.get_main_config()
    if config.get('attestation-policy') == 'off':
        return False
    return str(config.get('attestation-tofu', 'yes')).lower() in (
        'yes',
        'true',
        'on',
        '1',
    )


def store_path() -> str:
    return os.path.join(b4.get_data_dir(), 'tofu.sqlite3')


def connect() -> sqlite3.Connection:
    """Open the TOFU database, creating the tables if needed.

    Autocommit mode is used, so callers start their own transactions
    when they need one (``BEGIN IMMEDIATE`` for writes that decide
    something based on what they read).
    """
    conn = sqlite3.connect(store_path(), isolation_level=None)
    try:
        # The TUI and a cron sweep may both be writing
        conn.execute('PRAGMA busy_timeout = 15000')
        if conn.execute('PRAGMA user_version').fetchone()[0] < SCHEMA_VERSION:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute(
                'CREATE TABLE IF NOT EXISTS keys ('
                'identity TEXT NOT NULL, algo TEXT NOT NULL, pk TEXT NOT NULL, '
                'status TEXT NOT NULL, origin TEXT NOT NULL, '
                'first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, '
                'changed_at INTEGER NOT NULL, '
                'UNIQUE (identity, algo, pk))'
            )
            conn.execute(
                'CREATE TABLE IF NOT EXISTS sightings ('
                'identity TEXT NOT NULL, algo TEXT NOT NULL, pk TEXT NOT NULL, '
                'series_key TEXT NOT NULL, msgid TEXT NOT NULL, subject TEXT, '
                'counted INTEGER NOT NULL, seen_at INTEGER NOT NULL, '
                'UNIQUE (identity, algo, pk, series_key, msgid))'
            )
            conn.execute(
                'CREATE INDEX IF NOT EXISTS sightings_msgid ON sightings (msgid)'
            )
            conn.execute(
                'CREATE TABLE IF NOT EXISTS embedded_checked ('
                'digest TEXT PRIMARY KEY, valid INTEGER NOT NULL, '
                'trimmed INTEGER NOT NULL, checked_at INTEGER NOT NULL)'
            )
            conn.execute(f'PRAGMA user_version = {SCHEMA_VERSION}')
            conn.execute('COMMIT')
    except sqlite3.Error:
        conn.close()
        raise
    return conn


def short_key(pk: str) -> str:
    """Shorten a base64 key for display."""
    if len(pk) <= 20:
        return pk
    return f'{pk[:10]}...{pk[-8:]}'


# --- Checking a signature against its embedded key --------------------------


def embedded_keys(lmsg: 'LoreMessage', identity: str) -> List[str]:
    """Return the ``pk=`` values of the ed25519 key headers for *identity*."""
    pks: List[str] = list()
    for hval in lmsg.msg.get_all(DEVKEY_HDR, []):
        hdata = b4.LoreMessage.get_parts_from_header(str(hval))
        if hdata.get('a', '').lower() != TOFU_ALGO:
            continue
        if hdata.get('i', '').lower() != identity.lower():
            continue
        pk = hdata.get('pk')
        if pk and pk not in pks:
            pks.append(pk)
    return pks


def _embedded_digest(msgbytes: bytes, identity: str, pk: str) -> str:
    hasher = hashlib.sha256(msgbytes)
    hasher.update(b'\0')
    hasher.update(identity.encode())
    hasher.update(b'\0')
    hasher.update(pk.encode())
    return hasher.hexdigest()


def _embedded_recall(digest: str) -> Optional[Tuple[bool, bool]]:
    try:
        conn = connect()
        try:
            row = conn.execute(
                'SELECT valid, trimmed FROM embedded_checked WHERE digest = ?',
                (digest,),
            ).fetchone()
        finally:
            conn.close()
    except (OSError, sqlite3.Error) as ex:
        logger.debug('Unable to read the TOFU store: %s', ex)
        return None
    if row is None:
        return None
    return bool(row[0]), bool(row[1])


def _embedded_remember(digest: str, valid: bool, trimmed: bool) -> None:
    now = int(time.time())
    try:
        conn = connect()
        try:
            conn.execute('BEGIN')
            conn.execute(
                'DELETE FROM embedded_checked WHERE checked_at < ?',
                (now - EMBEDDED_KEEP_SECS,),
            )
            conn.execute(
                'INSERT OR REPLACE INTO embedded_checked '
                '(digest, valid, trimmed, checked_at) VALUES (?, ?, ?, ?)',
                (digest, int(valid), int(trimmed), now),
            )
            conn.execute('COMMIT')
        finally:
            conn.close()
    except (OSError, sqlite3.Error) as ex:
        logger.debug('Unable to write the TOFU store: %s', ex)


def _validate_with(
    pm: patatt.PatattMessage, identity: str, pk: str
) -> Tuple[bool, bool]:
    """Validate the signature of *identity* with *pk*: (valid, trimmed)."""
    for trim_body in (False, True):
        try:
            pm.validate(identity, pk, trim_body=trim_body)
            return True, trim_body
        except patatt.BodyValidationError:
            # Content after the l= length breaks the body hash, so try
            # again on the trimmed body
            continue
        except (patatt.Error, ValueError, TypeError, RuntimeError) as ex:
            logger.debug('Embedded key check failed for %s: %s', identity, ex)
            return False, False
    return False, False


def verify_embedded(
    lmsg: 'LoreMessage', msgbytes: bytes, identity: str
) -> Optional[Tuple[str, bool, bool]]:
    """Check the signature of *identity* against the key in the message.

    Returns None if the message carries no ed25519 key for *identity*.
    Otherwise returns ``(pk, valid, trimmed)``.  If there is more than
    one key header for the identity, the first key that validates wins.
    *trimmed* is True if the signature only passed on the body cut to
    its ``l=`` length.
    """
    pks = embedded_keys(lmsg, identity)
    if not pks:
        return None
    pm: Optional[patatt.PatattMessage] = None
    for pk in pks:
        digest = _embedded_digest(msgbytes, identity, pk)
        recalled = _embedded_recall(digest)
        if recalled is not None:
            valid, trimmed = recalled
        else:
            if pm is None:
                try:
                    pm = patatt.PatattMessage(msgbytes)
                    pm.get_sigs()
                except RuntimeError as ex:
                    logger.debug('Unable to parse the message: %s', ex)
                    return pks[0], False, False
            valid, trimmed = _validate_with(pm, identity, pk)
            _embedded_remember(digest, valid, trimmed)
        if valid:
            return pk, True, trimmed
    return pks[0], False, False


# --- Keyring lookup ----------------------------------------------------------


def _keyring_dirs(source: str, keydir: Path) -> List[Tuple[str, Path]]:
    """List the selectors in one keyring source.

    Returns ``(selector, path)`` pairs.  For a ``ref:`` source we list
    both the committed tree and the files on disk, the same places
    :func:`patatt.get_public_key` looks.  Keys stored only under
    ``by-hash/`` cannot be listed.
    """
    found: List[Tuple[str, Path]] = list()
    if source.startswith('ref:'):
        parts = source.split(':', 4)
        if len(parts) < 4:
            return found
        gitrepo, gitref, gitsub = parts[1], parts[2], parts[3]
        if not gitrepo:
            gitrepo = patatt.get_git_toplevel()
        if not gitrepo:
            return found
        gitrepo = os.path.expanduser(gitrepo)
        if '$' in gitrepo:
            gitrepo = os.path.expandvars(gitrepo)
        if os.path.isdir(os.path.join(gitrepo, '.git')):
            gittop = os.path.join(gitrepo, '.git')
        else:
            gittop = gitrepo
        subpath = os.path.join(gitsub, str(keydir))
        if not gitref:
            ecode, out, _ = patatt.git_run_command(gittop, ['symbolic-ref', 'HEAD'])
            if ecode == 0:
                gitref = out.decode().strip()
        if gitref:
            ecode, out, _ = patatt.git_run_command(
                gittop, ['ls-tree', '--name-only', f'{gitref}:{subpath}']
            )
            if ecode == 0:
                for name in out.decode().splitlines():
                    if name:
                        found.append((name, Path(subpath) / name))
        ondisk = Path(gitrepo) / subpath
    else:
        if '$' in source:
            ondisk = Path(os.path.expandvars(source)) / keydir
        else:
            ondisk = Path(source).expanduser() / keydir
    if ondisk.is_dir():
        for entry in ondisk.iterdir():
            found.append((entry.name, entry))
    return found


def keyring_keys(identity: str, sources: List[str]) -> List[str]:
    """Return every ed25519 key the keyrings have for *identity*.

    patatt looks for a key only under the selector named in the
    signature.  A keyring may have the developer's key under another
    selector, and then patatt reports "no key".  TOFU must not pin a
    new key in that case, so we look at all selectors.
    """
    identity = identity.lower()
    cachekey = (tuple(sources), identity, os.getcwd())
    if cachekey in _keyring_cache:
        return _keyring_cache[cachekey]

    keys: List[str] = list()
    try:
        keydir = patatt.make_pkey_path(TOFU_ALGO, identity, 'x').parent
    except patatt.Error:
        _keyring_cache[cachekey] = keys
        return keys
    for source in sources:
        selectors: Set[str] = set()
        for name, _path in _keyring_dirs(source, keydir):
            selectors.add(urllib.parse.unquote_plus(name))
        for selector in sorted(selectors):
            try:
                keydata, _keysrc = patatt.get_public_key(
                    source, TOFU_ALGO, identity, selector
                )
            except (KeyError, patatt.Error, OSError) as ex:
                logger.debug(
                    'No key for %s/%s in %s: %s', identity, selector, source, ex
                )
                continue
            key = keydata.decode(errors='replace').strip()
            if key and key not in keys:
                keys.append(key)
    _keyring_cache[cachekey] = keys
    return keys


def reset_caches() -> None:
    """Forget the keyring lookups and printed warnings of this run."""
    _keyring_cache.clear()
    _warned.clear()


# --- Deciding the status of one signature ------------------------------------


def sender_matches(lmsg: 'LoreMessage', identity: str) -> bool:
    """Return True if *identity* is the sender of *lmsg*.

    The sender is the From: address, or X-Original-From: when a mailing
    list rewrote From:.  This is the same rule as
    :meth:`b4.LoreAttestor.check_identity`.
    """
    identity = identity.lower()
    if lmsg.fromemail and lmsg.fromemail.lower() == identity:
        return True
    xofh = lmsg.msg.get('X-Original-From')
    if xofh:
        xpair = email.utils.getaddresses([str(xofh)])[0]
        if xpair[1].lower() == identity:
            return True
    return False


def _count_other_series(
    conn: sqlite3.Connection, identity: str, pk: str, msgid: str
) -> int:
    """Count the trusted revisions signed with *pk*, except this message's."""
    row = conn.execute(
        'SELECT COUNT(DISTINCT series_key) FROM sightings '
        'WHERE identity = ? AND algo = ? AND pk = ? AND counted = 1 '
        'AND series_key NOT IN (SELECT series_key FROM sightings WHERE msgid = ?)',
        (identity, TOFU_ALGO, pk, msgid),
    ).fetchone()
    return int(row[0])


def evaluate(attestor: 'LoreAttestor', lmsg: 'LoreMessage') -> Optional[Dict[str, Any]]:
    """Decide the TOFU status of one signature.

    The result is never cached: accepting or rejecting a key must take
    effect at once.  Returns None when TOFU has nothing to say, and the
    signature should show as "no key" as before.  Otherwise returns a
    dict with:

    - ``status``: one of ``tofu``, ``tofu-new``, ``tofu-changed``,
      ``tofu-retired``, ``tofu-rejected``
    - ``pk``: the key that signed the message
    - ``count``: how many other trusted revisions this key signed
    - ``retired``: True if a retired key signed a message we saw
      before the key was replaced
    - ``against``: for ``tofu-changed``, ``keyring`` or ``tofu``
    """
    pk = attestor.tofu_pk
    if not pk or attestor.identity is None:
        return None
    identity = attestor.identity.lower()
    info: Dict[str, Any] = {'pk': pk, 'count': 0, 'retired': False}

    if attestor.tofu_keyring:
        # The keyring has a different key for this identity under
        # another selector.  The keyring always wins.
        info['status'] = 'tofu-changed'
        info['against'] = 'keyring'
        return info

    msgid = lmsg.msgid
    try:
        conn = connect()
        try:
            rows = conn.execute(
                'SELECT pk, status, changed_at FROM keys WHERE identity = ? AND algo = ?',
                (identity, TOFU_ALGO),
            ).fetchall()
            known = {row[0]: (row[1], int(row[2])) for row in rows}
            if pk in known:
                status, changed_at = known[pk]
                info['count'] = _count_other_series(conn, identity, pk, msgid)
                if status == 'retired':
                    seen_before = conn.execute(
                        'SELECT 1 FROM sightings WHERE identity = ? AND algo = ? '
                        'AND pk = ? AND msgid = ? AND seen_at < ? LIMIT 1',
                        (identity, TOFU_ALGO, pk, msgid, changed_at),
                    ).fetchone()
                    if seen_before is None:
                        info['status'] = 'tofu-retired'
                        return info
                    info['retired'] = True
                    info['status'] = 'tofu'
                    return info
                if status == 'rejected':
                    info['status'] = 'tofu-rejected'
                    return info
                if status == 'pending':
                    info['status'] = 'tofu-changed'
                    info['against'] = 'tofu'
                    return info
                # trusted
                info['status'] = 'tofu' if info['count'] else 'tofu-new'
                return info
        finally:
            conn.close()
    except (OSError, sqlite3.Error) as ex:
        logger.debug('Unable to read the TOFU store: %s', ex)
        return None

    if known:
        # We know other keys for this identity, but not this one
        info['status'] = 'tofu-changed'
        info['against'] = 'tofu'
        return info

    # Nothing pinned yet.  Only a series member sent by the signer
    # can pin a key, so anything else stays "no key".
    if lmsg.reply or not sender_matches(lmsg, identity):
        return None
    info['status'] = 'tofu-new'
    return info


# --- Recording sightings -----------------------------------------------------


def _series_members(lser: 'LoreSeries') -> List['LoreMessage']:
    return [lmsg for lmsg in lser.patches if lmsg is not None]


def series_key(lser: 'LoreSeries') -> Optional[str]:
    """The cover letter msgid, or the msgid of the first patch we have."""
    for lmsg in lser.patches:
        if lmsg is not None:
            return lmsg.msgid
    return None


def _tofu_signatures(lmsg: 'LoreMessage') -> Dict[str, Set[str]]:
    """Return {identity: {pk, ...}} for the signatures TOFU may record."""
    sigs: Dict[str, Set[str]] = dict()
    for attestor in lmsg.attestors:
        if not attestor.tofu_pk or attestor.identity is None or attestor.tofu_keyring:
            continue
        identity = attestor.identity.lower()
        if not sender_matches(lmsg, identity):
            continue
        sigs.setdefault(identity, set()).add(attestor.tofu_pk)
    return sigs


def record_series(lser: 'LoreSeries') -> None:
    """Pin new keys and record which keys signed this revision.

    The first key we see for an identity becomes trusted.  A different
    key for an identity we already know is stored as pending, so the
    maintainer has evidence when deciding about it.

    A revision adds to a key's count only if the series is complete and
    every patch is signed with that same key.  The cover letter may be
    unsigned, but if it is signed by the same identity, the key must
    match too.  Fetching the same revision again never counts twice.
    """
    if not enabled():
        return
    skey = series_key(lser)
    if skey is None:
        return

    # identity -> pk -> [(msgid, subject), ...] in series order
    seen: Dict[str, Dict[str, List[Tuple[str, str]]]] = dict()
    # identity -> pks found on each patch (cover letter excluded)
    perpatch: Dict[str, List[Set[str]]] = dict()
    cover = lser.patches[0]
    patches = lser.patches[1:]
    for lmsg in _series_members(lser):
        for identity, pks in _tofu_signatures(lmsg).items():
            for pk in sorted(pks):
                seen.setdefault(identity, dict()).setdefault(pk, list()).append(
                    (lmsg.msgid, lmsg.full_subject)
                )
    if not seen:
        return
    for identity in seen:
        perpatch[identity] = list()
        for lmsg in patches:
            if lmsg is None:
                perpatch[identity].append(set())
            else:
                perpatch[identity].append(_tofu_signatures(lmsg).get(identity, set()))

    now = int(time.time())
    try:
        conn = connect()
    except (OSError, sqlite3.Error) as ex:
        logger.debug('Unable to open the TOFU store: %s', ex)
        return
    try:
        for identity, bypk in seen.items():
            allpks = set(bypk)
            counted_pk: Optional[str] = None
            if lser.complete and len(allpks) == 1:
                (pk,) = allpks
                if patches and all(pks == {pk} for pks in perpatch[identity]):
                    counted_pk = pk
            if counted_pk and cover is not None:
                coverpks = _tofu_signatures(cover).get(identity, set())
                if coverpks and coverpks != {counted_pk}:
                    counted_pk = None

            conn.execute('BEGIN IMMEDIATE')
            try:
                rows = conn.execute(
                    'SELECT pk, status FROM keys WHERE identity = ? AND algo = ?',
                    (identity, TOFU_ALGO),
                ).fetchall()
                known = {row[0] for row in rows}
                for pk in bypk:
                    if pk in known:
                        conn.execute(
                            'UPDATE keys SET last_seen = ? '
                            'WHERE identity = ? AND algo = ? AND pk = ?',
                            (now, identity, TOFU_ALGO, pk),
                        )
                        continue
                    # Only the very first key for an identity is pinned
                    status = 'pending' if known else 'trusted'
                    if status == 'trusted':
                        logger.debug('TOFU: pinning %s for %s', short_key(pk), identity)
                    else:
                        logger.debug(
                            'TOFU: new pending key %s for %s', short_key(pk), identity
                        )
                    conn.execute(
                        'INSERT INTO keys (identity, algo, pk, status, origin, '
                        'first_seen, last_seen, changed_at) '
                        "VALUES (?, ?, ?, ?, 'tofu', ?, ?, ?)",
                        (identity, TOFU_ALGO, pk, status, now, now, now),
                    )
                    known.add(pk)
                for pk, msgs in bypk.items():
                    counted = int(pk == counted_pk)
                    for msgid, subject in msgs:
                        conn.execute(
                            'INSERT INTO sightings (identity, algo, pk, series_key, '
                            'msgid, subject, counted, seen_at) '
                            'VALUES (?, ?, ?, ?, ?, ?, ?, ?) '
                            'ON CONFLICT (identity, algo, pk, series_key, msgid) '
                            'DO UPDATE SET counted = MAX(counted, excluded.counted)',
                            (
                                identity,
                                TOFU_ALGO,
                                pk,
                                skey,
                                msgid,
                                subject,
                                counted,
                                now,
                            ),
                        )
                conn.execute('COMMIT')
            except BaseException:
                conn.execute('ROLLBACK')
                raise
    except sqlite3.Error as ex:
        logger.debug('Unable to write the TOFU store: %s', ex)
    finally:
        conn.close()


# --- Warnings ----------------------------------------------------------------


def key_history(identity: str) -> List[Dict[str, Any]]:
    """Return what we know about the keys of *identity*, oldest first."""
    identity = identity.lower()
    out: List[Dict[str, Any]] = list()
    try:
        conn = connect()
        try:
            rows = conn.execute(
                'SELECT k.pk, k.status, k.origin, k.first_seen, k.last_seen, '
                '(SELECT COUNT(DISTINCT s.series_key) FROM sightings s '
                ' WHERE s.identity = k.identity AND s.algo = k.algo '
                ' AND s.pk = k.pk AND s.counted = 1) '
                'FROM keys k WHERE k.identity = ? AND k.algo = ? '
                'ORDER BY k.first_seen, k.rowid',
                (identity, TOFU_ALGO),
            ).fetchall()
        finally:
            conn.close()
    except (OSError, sqlite3.Error) as ex:
        logger.debug('Unable to read the TOFU store: %s', ex)
        return out
    for pk, status, origin, first_seen, last_seen, count in rows:
        out.append(
            {
                'pk': pk,
                'status': status,
                'origin': origin,
                'first_seen': int(first_seen),
                'last_seen': int(last_seen),
                'count': int(count),
            }
        )
    return out


def _fmt_day(ts: int) -> str:
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime(
        '%Y-%m-%d'
    )


def format_warning(
    identity: str, info: Dict[str, Any], keyring: List[str]
) -> List[str]:
    """Build the lines of the boxed warning for a changed or rejected key."""
    lines: List[str] = list()
    if info['status'] == 'tofu-rejected':
        lines.append(f'REJECTED KEY: {identity}')
        lines.append('This message is signed with a key you have rejected')
        lines.append('for this address.')
    else:
        lines.append(f'KEY CHANGED: {identity}')
        lines.append('This message is signed with a different key than')
        if info.get('against') == 'keyring':
            lines.append('the one in your keyring for this address.')
        else:
            lines.append('the one we trust for this address.')
    lines.append('')
    lines.append(f'  This key:     {info["pk"]}')
    if info.get('against') == 'keyring':
        for key in keyring:
            lines.append(f'  Keyring key:  {key}')
    else:
        for entry in key_history(identity):
            if entry['pk'] == info['pk'] or entry['status'] == 'pending':
                continue
            lines.append(f'  {entry["status"].capitalize() + " key:":<14}{entry["pk"]}')
            lines.append(
                f'                first seen {_fmt_day(entry["first_seen"])}, '
                f'last seen {_fmt_day(entry["last_seen"])}, '
                f'{entry["count"]} series'
            )
    lines.append('')
    lines.append('The developer may have a new key, or someone else may')
    lines.append('be sending mail in their name.  Check with the developer')
    lines.append('through a channel you trust before you apply this.')
    return lines


def print_warnings(lmsgs: List['LoreMessage']) -> List[Dict[str, Any]]:
    """Print one boxed warning per changed or rejected key in *lmsgs*.

    Each key is warned about only once per run.  Returns the warnings
    that were printed, mostly for tests.
    """
    if not enabled():
        return list()
    printed: List[Dict[str, Any]] = list()
    done = _warned
    for lmsg in lmsgs:
        for attestor in lmsg.attestors:
            if not attestor.tofu_pk or attestor.identity is None:
                continue
            identity = attestor.identity.lower()
            if (identity, attestor.tofu_pk) in done:
                continue
            info = evaluate(attestor, lmsg)
            if info is None or info['status'] not in CRITICAL_STATUSES:
                continue
            done.add((identity, attestor.tofu_pk))
            lines = format_warning(identity, info, attestor.tofu_keyring)
            width = max(len(line) for line in lines) + 4
            logger.critical('*' * width)
            for line in lines:
                logger.critical('* %s *', line.ljust(width - 4))
            logger.critical('*' * width)
            printed.append(dict(info, identity=identity))
    return printed
