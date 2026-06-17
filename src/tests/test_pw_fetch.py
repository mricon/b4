#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Unit tests for the Patchwork series-fetch backlog gate.

pw_fetch_series() must not try to load a neglected project's entire history
(linux-kselftest had 28k+ outstanding patches).  It first probes the backlog
size cheaply, and only when that exceeds PW_BACKLOG_GATE does it restrict the
fetch to the last PW_WINDOW_DAYS days.  No network access: the Patchwork
session is faked.
"""

from typing import Any, Dict, List, Optional, Tuple, cast

import pytest

import b4
from b4.review._review import (
    PW_BACKLOG_GATE,
    PW_WINDOW_DAYS,
    PwFetchResult,
    _pw_count_outstanding,
    pw_fetch_series,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeResp:
    def __init__(
        self,
        payload: Optional[List[Dict[str, Any]]] = None,
        links: Optional[Dict[str, Dict[str, str]]] = None,
        status_code: int = 200,
        reason: str = 'OK',
    ) -> None:
        self._payload = payload if payload is not None else []
        self.links = links or {}
        self.status_code = status_code
        self.reason = reason

    def json(self) -> List[Dict[str, Any]]:
        return self._payload


def _patch(pid: int, sid: int, date: str) -> Dict[str, Any]:
    """A minimal Patchwork patch dict carrying one series."""
    return {
        'id': pid,
        'date': date,
        'state': 'new',
        'msgid': f'm{pid}@example.com',
        'name': f'patch {pid}',
        'submitter': {'name': 'Sub', 'email': 'sub@example.com'},
        'series': [{'id': sid, 'name': f'series {sid}'}],
        'check': 'success',
    }


class _FakeSession:
    """Fakes the Patchwork pagination contract.

    The per_page=1 probe answers with a ``last`` link whose page number equals
    *count* (mirroring real Patchwork); the actual fetch returns a single page
    of patches with no ``next`` link.  Every request's params are recorded.
    """

    def __init__(self, count: int, window_count: Optional[int] = None) -> None:
        self._count = count
        # The count returned by the per_page=1 probe when a 'since' filter is
        # present (i.e. the windowed re-probe); defaults to the full count.
        self._window_count = window_count if window_count is not None else count
        self.requests: List[Dict[str, Any]] = []

    def get(self, url: str, params: Optional[Dict[str, Any]] = None) -> _FakeResp:
        params = dict(params or {})
        self.requests.append(params)
        if str(params.get('per_page')) == '1':
            n = self._window_count if 'since' in params else self._count
            links: Dict[str, Dict[str, str]] = {}
            if n > 1:
                links['last'] = {
                    'url': f'https://pw.example.org/api/1.2/patches/'
                    f'?page={n}&per_page=1'
                }
            payload = [_patch(1, 1, '2026-06-01T00:00:00')] if n else []
            return _FakeResp(payload=payload, links=links)
        # Actual fetch: one page, two patches in one series, no next link.
        return _FakeResp(
            payload=[
                _patch(1, 1, '2026-06-01T00:00:00'),
                _patch(2, 1, '2026-06-02T00:00:00'),
            ],
            links={},
        )

    @property
    def fetch_params(self) -> List[Dict[str, Any]]:
        """Params of the non-probe (actual fetch) requests."""
        return [p for p in self.requests if str(p.get('per_page')) != '1']


def _fetch_with_backlog(
    monkeypatch: pytest.MonkeyPatch, count: int
) -> Tuple[_FakeSession, PwFetchResult]:
    sess = _FakeSession(count)
    monkeypatch.setattr(
        b4,
        'get_patchwork_session',
        lambda key, url: (sess, 'https://pw.example.org/api/1.2'),
    )
    result = pw_fetch_series('fakekey', 'https://pw.example.org', 'proj')
    return sess, result


# ---------------------------------------------------------------------------
# _pw_count_outstanding()
# ---------------------------------------------------------------------------


class TestCountOutstanding:
    def test_reads_count_from_last_link(self) -> None:
        sess = _FakeSession(count=28180)
        n = _pw_count_outstanding(
            cast(Any, sess), 'https://pw/patches', {'per_page': '250'}
        )
        assert n == 28180
        # Probed with a single item, not the full page size.
        assert sess.requests[0]['per_page'] == '1'

    def test_falls_back_to_row_count_without_last_link(self) -> None:
        # count<=1 yields no 'last' link, so we count the returned rows instead.
        sess = _FakeSession(count=1)
        n = _pw_count_outstanding(
            cast(Any, sess), 'https://pw/patches', {'per_page': '250'}
        )
        assert n == 1

    def test_zero_outstanding(self) -> None:
        sess = _FakeSession(count=0)
        n = _pw_count_outstanding(
            cast(Any, sess), 'https://pw/patches', {'per_page': '250'}
        )
        assert n == 0


# ---------------------------------------------------------------------------
# pw_fetch_series() two-step gate
# ---------------------------------------------------------------------------


class TestFetchSeriesGate:
    def test_small_backlog_fetches_everything(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sess, result = _fetch_with_backlog(monkeypatch, count=42)
        # No window applied, and the fetch carried no 'since' filter.
        assert result.window_days is None
        assert result.outstanding == 42
        assert sess.fetch_params
        assert 'since' not in sess.fetch_params[0]
        # The two patches grouped into a single series.
        assert len(result.series) == 1

    def test_large_backlog_windows_to_recent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sess, result = _fetch_with_backlog(monkeypatch, count=28180)
        # The gate fired: only the recent window was fetched.
        assert result.window_days == PW_WINDOW_DAYS
        assert result.outstanding == 28180
        assert sess.fetch_params
        assert 'since' in sess.fetch_params[0]

    def test_gate_boundary_is_strict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Exactly at the gate does not window; one over does.
        _, at_gate = _fetch_with_backlog(monkeypatch, count=PW_BACKLOG_GATE)
        assert at_gate.window_days is None
        _, over_gate = _fetch_with_backlog(monkeypatch, count=PW_BACKLOG_GATE + 1)
        assert over_gate.window_days == PW_WINDOW_DAYS


# ---------------------------------------------------------------------------
# progress_cb
# ---------------------------------------------------------------------------


class TestProgressCallback:
    def _run(
        self, monkeypatch: pytest.MonkeyPatch, sess: _FakeSession
    ) -> List[Tuple[int, int]]:
        monkeypatch.setattr(
            b4,
            'get_patchwork_session',
            lambda key, url: (sess, 'https://pw.example.org/api/1.2'),
        )
        calls: List[Tuple[int, int]] = []
        pw_fetch_series(
            'fakekey',
            'https://pw.example.org',
            'proj',
            progress_cb=lambda fetched, total: calls.append((fetched, total)),
        )
        return calls

    def test_reports_against_full_count_when_not_windowed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = self._run(monkeypatch, _FakeSession(count=42))
        # Primed at zero, then once per fetched page (one page, two patches).
        assert calls[0] == (0, 42)
        assert calls[-1] == (2, 42)
        # Totals are stable across the whole fetch.
        assert all(total == 42 for _fetched, total in calls)

    def test_reports_against_windowed_count_when_gated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Huge all-time backlog, but only 17 patches inside the recent window:
        # progress must track the windowed total, not the all-time backlog.
        sess = _FakeSession(count=28180, window_count=17)
        calls = self._run(monkeypatch, sess)
        assert calls[0] == (0, 17)
        assert all(total == 17 for _fetched, total in calls)
