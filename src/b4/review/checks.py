#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
#
__author__ = 'Konstantin Ryabitsev <konstantin@linuxfoundation.org>'

import datetime
import json
import logging
import os
import pathlib
import shlex
import sqlite3
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Tuple

import requests

import b4

logger = logging.getLogger(__name__)

_STATUS_ORDER = {'pass': 0, 'warn': 1, 'fail': 2}

# In-process cache for sashiko API responses, keyed by message-id.
# This prevents redundant API calls when checking multiple patches
# from the same series within a single check run.
_sashiko_patchset_cache: Dict[str, Optional[Dict[str, Any]]] = {}


def clear_sashiko_cache() -> None:
    """Clear the sashiko patchset cache between check runs."""
    _sashiko_patchset_cache.clear()


SCHEMA_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS check_results (
    msgid      TEXT NOT NULL,
    tool       TEXT NOT NULL,
    status     TEXT NOT NULL,
    summary    TEXT,
    url        TEXT,
    details    TEXT,
    checked_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S', 'now')),
    PRIMARY KEY (msgid, tool)
);
"""


# ---------------------------------------------------------------------------
# Cache database
# ---------------------------------------------------------------------------


def _get_db_path() -> str:
    """Return the path to the CI check cache database."""
    datadir = b4.get_data_dir()
    cidir = os.path.join(datadir, 'review')
    pathlib.Path(cidir).mkdir(parents=True, exist_ok=True)
    return os.path.join(cidir, 'ci.sqlite3')


def get_db() -> sqlite3.Connection:
    """Get a connection to the CI cache database, creating it if needed."""
    db_path = _get_db_path()
    is_new = not os.path.exists(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    if is_new:
        conn.executescript(SCHEMA_SQL)
        conn.execute(
            'INSERT OR REPLACE INTO schema_version (version) VALUES (?)',
            (SCHEMA_VERSION,),
        )
        conn.commit()
    return conn


def cleanup_old(conn: sqlite3.Connection, max_days: int = 180) -> int:
    """Delete check results older than *max_days*. Returns count deleted."""
    cutoff = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=max_days)
    ).isoformat()
    cursor = conn.execute('DELETE FROM check_results WHERE checked_at < ?', (cutoff,))
    conn.commit()
    return cursor.rowcount


def get_cached_results(
    conn: sqlite3.Connection, msgids: List[str]
) -> Dict[str, List[Dict[str, str]]]:
    """Return cached check results keyed by msgid.

    Returns ``{msgid: [{tool, status, summary, url, details}, ...]}``.
    """
    if not msgids:
        return {}
    placeholders = ','.join('?' * len(msgids))
    cursor = conn.execute(
        'SELECT msgid, tool, status, summary, url, details'
        f' FROM check_results WHERE msgid IN ({placeholders})',
        msgids,
    )
    results: Dict[str, List[Dict[str, str]]] = {}
    for row in cursor.fetchall():
        entry = {
            'tool': row['tool'],
            'status': row['status'],
            'summary': row['summary'] or '',
            'url': row['url'] or '',
            'details': row['details'] or '',
        }
        results.setdefault(row['msgid'], []).append(entry)
    return results


def store_results(
    conn: sqlite3.Connection, msgid: str, results: List[Dict[str, str]]
) -> None:
    """Store check results for a single message."""
    for entry in results:
        conn.execute(
            'INSERT OR REPLACE INTO check_results'
            ' (msgid, tool, status, summary, url, details)'
            ' VALUES (?, ?, ?, ?, ?, ?)',
            (
                msgid,
                entry['tool'],
                entry['status'],
                entry.get('summary', ''),
                entry.get('url', ''),
                entry.get('details', ''),
            ),
        )
    conn.commit()


def delete_results(conn: sqlite3.Connection, msgids: List[str]) -> None:
    """Delete all cached check results for the given message-ids."""
    if not msgids:
        return
    placeholders = ','.join('?' * len(msgids))
    conn.execute(f'DELETE FROM check_results WHERE msgid IN ({placeholders})', msgids)
    conn.commit()


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def load_check_cmds() -> Tuple[List[str], List[str]]:
    """Read check commands from git config.

    Returns ``(perpatch_cmds, series_cmds)`` as raw command strings.
    """
    config = b4.get_main_config()

    def _as_list(val: Any) -> List[str]:
        if isinstance(val, str):
            return [val]
        if isinstance(val, list):
            return list(val)
        return []

    perpatch = _as_list(config.get('review-perpatch-check-cmd'))
    if not perpatch:
        topdir = b4.git_get_toplevel()
        if topdir:
            checkpatch = os.path.join(topdir, 'scripts', 'checkpatch.pl')
            if os.access(checkpatch, os.X_OK):
                perpatch = ['_builtin_checkpatch']
    # Auto-wire patchwork CI when project is configured
    if (
        '_builtin_patchwork' not in perpatch
        and config.get('pw-project')
        and config.get('pw-url')
    ):
        perpatch.append('_builtin_patchwork')
    series = _as_list(config.get('review-series-check-cmd'))
    # Auto-wire sashiko AI review when URL is configured
    if config.get('sashiko-url'):
        if '_builtin_sashiko' not in perpatch:
            perpatch.append('_builtin_sashiko')
        if '_builtin_sashiko' not in series:
            series.append('_builtin_sashiko')
    return perpatch, series


def parse_cmd(cmdstr: str) -> List[str]:
    """Shell-split a command string into an argv list."""
    sp = shlex.shlex(cmdstr, posix=True)
    sp.whitespace_split = True
    return list(sp)


# ---------------------------------------------------------------------------
# Built-in handlers
# ---------------------------------------------------------------------------


def _run_builtin_checkpatch(msg: EmailMessage, topdir: str) -> List[Dict[str, str]]:
    """Run scripts/checkpatch.pl on a single patch message."""
    checkpatch = os.path.join(topdir, 'scripts', 'checkpatch.pl')
    if not os.access(checkpatch, os.X_OK):
        return [
            {
                'tool': 'checkpatch',
                'status': 'fail',
                'summary': 'checkpatch.pl not found or not executable',
            }
        ]

    cmdargs = [checkpatch, '-q', '--terse', '--no-summary', '--mailback']
    bdata = b4.LoreMessage.get_msg_as_bytes(msg)
    ecode, out, err = b4._run_command(cmdargs, stdin=bdata, rundir=topdir)

    out_str = out.strip().decode(errors='replace') if out and out.strip() else ''
    err_str = err.strip().decode(errors='replace') if err and err.strip() else ''

    findings: List[Dict[str, str]] = []
    worst = 'pass'
    for raw in out_str.splitlines() + err_str.splitlines():
        line = raw[2:] if raw.startswith('-:') else raw
        if not line:
            continue
        if 'ERROR:' in line:
            findings.append({'status': 'fail', 'description': line})
            worst = 'fail'
        elif 'WARNING:' in line or 'CHECK:' in line:
            findings.append({'status': 'warn', 'description': line})
            if worst != 'fail':
                worst = 'warn'
        else:
            # Continuation line — append to previous finding
            if findings:
                findings[-1]['description'] += ' ' + line
            else:
                findings.append({'status': 'pass', 'description': line})

    if not findings:
        if ecode:
            return [
                {
                    'tool': 'checkpatch',
                    'status': 'fail',
                    'summary': f'exited with error code {ecode}',
                }
            ]
        return [
            {
                'tool': 'checkpatch',
                'status': 'pass',
                'summary': 'passed all checks',
            }
        ]

    errors = sum(1 for f in findings if f['status'] == 'fail')
    warnings = sum(1 for f in findings if f['status'] == 'warn')
    parts = []
    if errors:
        parts.append(f'{errors} error{"s" if errors != 1 else ""}')
    if warnings:
        parts.append(f'{warnings} warning{"s" if warnings != 1 else ""}')
    summary = ', '.join(parts) if parts else findings[0]['description']

    return [
        {
            'tool': 'checkpatch',
            'status': worst,
            'summary': summary,
            'details': json.dumps(findings),
        }
    ]


def _run_builtin_patchwork(
    msg: EmailMessage, pwkey: str, pwurl: str
) -> List[Dict[str, str]]:
    """Query Patchwork REST API for checks on a single patch."""
    msgid = msg.get('message-id', '').strip('<> ')
    if not msgid:
        return []

    # Look up the PW patch ID for this message-id, then fetch its checks.
    try:
        pwdata = b4.LoreMessage.get_patchwork_data_by_msgid(msgid)
    except LookupError:
        logger.debug('Patchwork patch lookup failed for %s', msgid)
        return []
    patch_id = pwdata.get('id')
    if not patch_id:
        return []

    try:
        from b4.review import pw_fetch_checks

        checks = pw_fetch_checks(pwkey, pwurl, [int(patch_id)])
    except Exception as ex:
        logger.debug('Patchwork check query failed: %s', ex)
        return []

    if not checks:
        return []

    # Aggregate all PW checks into one result with worst-case status.
    worst = 'pass'
    individual: List[Dict[str, str]] = []
    counts: Dict[str, int] = {}
    for check in checks:
        state = check.get('state', 'pending')
        if state == 'success':
            status = 'pass'
        elif state in ('warning', 'pending'):
            status = 'warn'
        else:
            status = 'fail'
        if _STATUS_ORDER.get(status, 0) > _STATUS_ORDER.get(worst, 0):
            worst = status
        counts[status] = counts.get(status, 0) + 1
        individual.append(
            {
                'context': check.get('context', 'unknown'),
                'status': status,
                'state': state,
                'description': check.get('description', ''),
                'url': check.get('url', ''),
            }
        )

    summary_parts = []
    for s in ('pass', 'warn', 'fail'):
        if counts.get(s):
            summary_parts.append(f'{counts[s]} {s}')

    return [
        {
            'tool': 'patchwork',
            'status': worst,
            'summary': ', '.join(summary_parts),
            'details': json.dumps(individual),
        }
    ]


def _fetch_sashiko_patchset(msgid: str, sashiko_url: str) -> Optional[Dict[str, Any]]:
    """Fetch patchset data from sashiko, with in-process caching.

    The cache ensures only one API call per series, even when checking
    multiple patches from the same patchset.
    """
    if msgid in _sashiko_patchset_cache:
        return _sashiko_patchset_cache[msgid]

    url = f'{sashiko_url.rstrip("/")}/api/patch'
    try:
        session = b4.get_requests_session()
        resp = session.get(url, params={'id': msgid}, timeout=30)
        if resp.status_code == 404:
            _sashiko_patchset_cache[msgid] = None
            return None
        resp.raise_for_status()
        data: Dict[str, Any] = resp.json()
    except requests.RequestException as ex:
        logger.debug('Sashiko API query failed for %s: %s', msgid, ex)
        _sashiko_patchset_cache[msgid] = None
        return None

    # Cache by all message-ids in this patchset so subsequent patches
    # in the same series hit the cache instead of the network.
    cover_msgid = data.get('message_id', '')
    if cover_msgid:
        _sashiko_patchset_cache[cover_msgid] = data
    for patch in data.get('patches', []):
        p_msgid = patch.get('message_id', '')
        if p_msgid:
            _sashiko_patchset_cache[p_msgid] = data
    _sashiko_patchset_cache[msgid] = data
    return data


def _parse_sashiko_findings(review: Dict[str, Any]) -> List[Dict[str, str]]:
    """Parse findings from a sashiko review's output JSON."""
    output_str = review.get('output', '') or ''
    if not output_str:
        return []
    try:
        output = json.loads(output_str)
    except (json.JSONDecodeError, TypeError):
        return []

    raw_findings = output.get('findings', [])
    findings: List[Dict[str, str]] = []
    for f in raw_findings:
        if not isinstance(f, dict):
            continue
        severity = (f.get('severity', '') or '').lower()
        problem = f.get('problem', f.get('title', ''))
        suggestion = f.get('suggestion', '')
        if severity in ('critical', 'high'):
            status = 'fail'
        elif severity == 'medium':
            status = 'warn'
        else:
            status = 'pass'
        desc = str(problem)
        if suggestion:
            desc += f' \u2014 {suggestion}'
        findings.append(
            {
                'status': status,
                'context': f'sashiko/{severity}',
                'state': severity,
                'description': desc,
            }
        )
    return findings


def _sashiko_findings_summary(findings: List[Dict[str, str]]) -> Tuple[str, str]:
    """Return ``(worst_status, summary_text)`` for a list of findings."""
    if not findings:
        return 'pass', 'No findings'

    worst = 'pass'
    counts: Dict[str, int] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for f in findings:
        state = f.get('state', '')
        if state in counts:
            counts[state] += 1
        if _STATUS_ORDER.get(f['status'], 0) > _STATUS_ORDER.get(worst, 0):
            worst = f['status']

    parts = []
    for sev in ('critical', 'high', 'medium', 'low'):
        if counts[sev]:
            parts.append(f'{counts[sev]} {sev}')
    return worst, ', '.join(parts)


def _run_builtin_sashiko(msg: EmailMessage, sashiko_url: str) -> List[Dict[str, str]]:
    """Query sashiko AI review service for findings on a patch."""
    msgid = msg.get('message-id', '').strip('<> ')
    if not msgid:
        return []

    data = _fetch_sashiko_patchset(msgid, sashiko_url)
    if not data:
        return []

    ps_status = data.get('status', '')
    ps_id = data.get('id', '')
    reviews = data.get('reviews', [])
    patches = data.get('patches', [])
    base_url = sashiko_url.rstrip('/')
    patchset_url = f'{base_url}/patch/{ps_id}' if ps_id else ''

    # Build a map from patch message-id to sashiko patch id
    patch_id_by_msgid: Dict[str, int] = {}
    for p in patches:
        p_msgid = p.get('message_id', '')
        p_id = p.get('id')
        if p_msgid and p_id is not None:
            patch_id_by_msgid[p_msgid] = int(p_id)

    cover_msgid = data.get('message_id', '')
    is_cover = msgid == cover_msgid

    # Overall patchset status check (applies to cover letter row or
    # when the series is not yet reviewed).
    if ps_status in ('Pending', 'In Review', 'Applying'):
        return [
            {
                'tool': 'sashiko',
                'status': 'warn',
                'summary': f'Review {ps_status.lower()}',
                'url': patchset_url,
            }
        ]
    if ps_status in ('Failed', 'Failed To Apply'):
        return [
            {
                'tool': 'sashiko',
                'status': 'fail',
                'summary': ps_status,
                'url': patchset_url,
            }
        ]
    if ps_status == 'Incomplete':
        return [
            {
                'tool': 'sashiko',
                'status': 'warn',
                'summary': 'Series incomplete',
                'url': patchset_url,
            }
        ]

    if is_cover:
        # Aggregate findings across all reviews for the cover letter
        all_findings: List[Dict[str, str]] = []
        for review in reviews:
            all_findings.extend(_parse_sashiko_findings(review))
        worst, summary = _sashiko_findings_summary(all_findings)
        result: Dict[str, str] = {
            'tool': 'sashiko',
            'status': worst,
            'summary': summary,
            'url': patchset_url,
        }
        if all_findings:
            result['details'] = json.dumps(all_findings)
        return [result]

    # Per-patch: find the matching review
    sashiko_patch_id = patch_id_by_msgid.get(msgid)
    if sashiko_patch_id is None:
        return []

    for review in reviews:
        if review.get('patch_id') == sashiko_patch_id:
            review_status = review.get('status', '')
            if review_status == 'Skipped':
                result_msg = review.get('result', '') or 'Skipped'
                return [
                    {
                        'tool': 'sashiko',
                        'status': 'pass',
                        'summary': result_msg,
                        'url': patchset_url,
                    }
                ]
            if review_status in ('Pending', 'In Review'):
                return [
                    {
                        'tool': 'sashiko',
                        'status': 'warn',
                        'summary': 'Review in progress',
                        'url': patchset_url,
                    }
                ]
            if review_status == 'Failed':
                result_msg = review.get('result', '') or 'Review failed'
                return [
                    {
                        'tool': 'sashiko',
                        'status': 'fail',
                        'summary': result_msg,
                        'url': patchset_url,
                    }
                ]
            # Reviewed — parse findings
            findings = _parse_sashiko_findings(review)
            worst, summary = _sashiko_findings_summary(findings)
            result = {
                'tool': 'sashiko',
                'status': worst,
                'summary': summary,
                'url': patchset_url,
            }
            if findings:
                result['details'] = json.dumps(findings)
            return [result]

    # No review found for this patch
    return [
        {
            'tool': 'sashiko',
            'status': 'pass',
            'summary': 'No review',
            'url': patchset_url,
        }
    ]


# ---------------------------------------------------------------------------
# External command runner
# ---------------------------------------------------------------------------


def _run_external_cmd(
    cmdargs: List[str],
    msg: EmailMessage,
    topdir: str,
    extra_env: Optional[Dict[str, str]] = None,
) -> List[Dict[str, str]]:
    """Run an external check command and parse its JSON output."""
    bdata = b4.LoreMessage.get_msg_as_bytes(msg)
    saved_env: Dict[str, Optional[str]] = {}
    if extra_env:
        for key, val in extra_env.items():
            saved_env[key] = os.environ.get(key)
            os.environ[key] = val
    try:
        ecode, out, err = b4._run_command(cmdargs, stdin=bdata, rundir=topdir)
    finally:
        for key, prev in saved_env.items():
            if prev is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = prev

    if not out or not out.strip():
        if ecode:
            mycmd = os.path.basename(cmdargs[0])
            err_msg = err.strip().decode(errors='replace') if err else ''
            return [
                {
                    'tool': mycmd,
                    'status': 'fail',
                    'summary': f'exited with error code {ecode}',
                    'details': err_msg,
                }
            ]
        return []

    try:
        data = json.loads(out)
    except json.JSONDecodeError as ex:
        mycmd = os.path.basename(cmdargs[0])
        return [
            {
                'tool': mycmd,
                'status': 'fail',
                'summary': f'invalid JSON output: {ex}',
                'details': out.decode(errors='replace'),
            }
        ]

    if not isinstance(data, list):
        data = [data]

    results: List[Dict[str, str]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        tool = entry.get('tool', os.path.basename(cmdargs[0]))
        status = entry.get('status', 'fail')
        if status not in ('pass', 'warn', 'fail'):
            status = 'fail'
        results.append(
            {
                'tool': tool,
                'status': status,
                'summary': entry.get('summary', ''),
                'url': entry.get('url', ''),
                'details': entry.get('details', ''),
            }
        )
    return results


# ---------------------------------------------------------------------------
# High-level runners
# ---------------------------------------------------------------------------


def _dispatch_cmd(
    cmdstr: str,
    msg: EmailMessage,
    topdir: str,
    pwkey: str = '',
    pwurl: str = '',
    extra_env: Optional[Dict[str, str]] = None,
) -> List[Dict[str, str]]:
    """Run a single check command (built-in or external) against a message."""
    if cmdstr == '_builtin_checkpatch':
        return _run_builtin_checkpatch(msg, topdir)
    if cmdstr == '_builtin_patchwork':
        if pwkey and pwurl:
            return _run_builtin_patchwork(msg, pwkey, pwurl)
        logger.debug('_builtin_patchwork requested but pw-key/pw-url not configured')
        return []
    if cmdstr == '_builtin_sashiko':
        config = b4.get_main_config()
        sashiko_url = str(config.get('sashiko-url', ''))
        if sashiko_url:
            return _run_builtin_sashiko(msg, sashiko_url)
        logger.debug('_builtin_sashiko requested but sashiko-url not configured')
        return []

    cmdargs = parse_cmd(cmdstr)
    return _run_external_cmd(cmdargs, msg, topdir, extra_env=extra_env)


def run_perpatch_checks(
    patches: List[Tuple[str, EmailMessage]],
    cmds: List[str],
    topdir: str,
    pwkey: str = '',
    pwurl: str = '',
    extra_env: Optional[Dict[str, str]] = None,
) -> Dict[str, List[Dict[str, str]]]:
    """Run per-patch check commands on each patch.

    *patches* is a list of ``(msgid, EmailMessage)`` tuples.

    Returns ``{msgid: [result, ...]}``.
    """
    results: Dict[str, List[Dict[str, str]]] = {}
    for msgid, msg in patches:
        patch_results: List[Dict[str, str]] = []
        for cmdstr in cmds:
            try:
                patch_results.extend(
                    _dispatch_cmd(
                        cmdstr, msg, topdir, pwkey, pwurl, extra_env=extra_env
                    )
                )
            except Exception as ex:
                logger.debug('Check command %s failed: %s', cmdstr, ex)
                patch_results.append(
                    {
                        'tool': cmdstr.split()[0] if cmdstr else 'unknown',
                        'status': 'fail',
                        'summary': str(ex),
                    }
                )
        results[msgid] = patch_results
    return results


def run_series_checks(
    cover_msg: Tuple[str, EmailMessage],
    cmds: List[str],
    topdir: str,
    pwkey: str = '',
    pwurl: str = '',
    extra_env: Optional[Dict[str, str]] = None,
) -> List[Dict[str, str]]:
    """Run per-series check commands on the cover letter.

    *cover_msg* is a ``(msgid, EmailMessage)`` tuple.

    Returns ``[result, ...]``.
    """
    _msgid, msg = cover_msg
    results: List[Dict[str, str]] = []
    for cmdstr in cmds:
        try:
            results.extend(
                _dispatch_cmd(cmdstr, msg, topdir, pwkey, pwurl, extra_env=extra_env)
            )
        except Exception as ex:
            logger.debug('Series check command %s failed: %s', cmdstr, ex)
            results.append(
                {
                    'tool': cmdstr.split()[0] if cmdstr else 'unknown',
                    'status': 'fail',
                    'summary': str(ex),
                }
            )
    return results
