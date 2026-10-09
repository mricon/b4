#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Tests for syncing tracked-series state to Patchwork.

Only series tracked from the Patchwork TUI used to carry a Patchwork
series id, so accepting, reviewing or archiving any other series never
reached Patchwork.  These tests cover the id lookup by message-id and
the config knobs (pw-accept-state, pw-review-state) that decide which
state is sent.  The Patchwork server is a fake that records requests.
"""

from typing import Any, Dict, List, Optional, Tuple

import pytest

import b4
import b4.review
import b4.review.tracking as tracking

from .helpers.tracking import seed_db

IDENTIFIER = 'pwsync'
CHANGE_ID = 'pwsync-cid'
COVER_MSGID = 'cover@example.com'
PW_SERIES_ID = 77
PW_PATCH_IDS = [701, 702]


class _FakeResp:
    def __init__(self, data: Any) -> None:
        self._data = data

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self._data


class _FakePw:
    """A tiny Patchwork REST server that knows one series.

    *covers* and *patches* map a message-id to the series id that the
    covers or patches endpoint returns for it.
    """

    def __init__(
        self,
        covers: Optional[Dict[str, int]] = None,
        patches: Optional[Dict[str, int]] = None,
    ) -> None:
        self.covers = covers or {}
        self.patches = patches or {}
        # When set, the msgid filter is ignored and every known entry is
        # listed, as a server without that filter would do.
        self.ignore_msgid_filter = False
        self.gets: List[str] = []
        self.patched: List[Tuple[str, Dict[str, Any]]] = []

    @staticmethod
    def _entry(msgid: str, series_id: int) -> Dict[str, Any]:
        # Patchwork wraps message-ids in angle brackets; b4 stores them bare.
        return {'id': 1, 'msgid': f'<{msgid}>', 'series': [{'id': series_id}]}

    def get(self, url: str, params: Any = None, stream: bool = False) -> _FakeResp:
        self.gets.append(url)
        msgid = dict(params or []).get('msgid')
        for endpoint, known in (('/covers/', self.covers), ('/patches/', self.patches)):
            if url.endswith(endpoint):
                if self.ignore_msgid_filter:
                    return _FakeResp([self._entry(m, sid) for m, sid in known.items()])
                if msgid in known:
                    return _FakeResp([self._entry(msgid, known[msgid])])
                return _FakeResp([])
        if url.endswith(f'/series/{PW_SERIES_ID}/'):
            return _FakeResp({'patches': [{'id': pid} for pid in PW_PATCH_IDS]})
        raise AssertionError(f'unexpected GET {url}')

    def patch(self, url: str, data: Any = None, stream: bool = False) -> _FakeResp:
        self.patched.append((url, dict(data)))
        return _FakeResp({})


@pytest.fixture
def fake_pw(monkeypatch: pytest.MonkeyPatch) -> _FakePw:
    """Configure Patchwork and route its session to a fake server."""
    fake = _FakePw(covers={COVER_MSGID: PW_SERIES_ID})
    b4.MAIN_CONFIG.update(
        {
            'pw-key': 'key',
            'pw-url': 'https://pw.example.org',
            'pw-project': 'proj',
        }
    )
    monkeypatch.setattr(
        b4, 'get_patchwork_session', lambda key, url: (fake, 'https://pw/api')
    )
    return fake


def _seed(message_id: str = COVER_MSGID, status: str = 'reviewing') -> None:
    seed_db(
        IDENTIFIER,
        [{'change_id': CHANGE_ID, 'message_id': message_id, 'status': status}],
    )


def _stored_pw_id() -> Optional[int]:
    conn = tracking.get_db(IDENTIFIER)
    try:
        return tracking.get_pw_series_id(conn, CHANGE_ID, revision=1)
    finally:
        conn.close()


def _sent(fake: _FakePw) -> List[Dict[str, Any]]:
    """The PATCH bodies sent, one per Patchwork patch."""
    return [data for _url, data in fake.patched]


class TestPwConfigState:
    def test_unset_is_none(self) -> None:
        assert b4.review.pw_config_state('pw-accept-state') is None

    def test_empty_is_none(self) -> None:
        b4.MAIN_CONFIG['pw-accept-state'] = ''
        assert b4.review.pw_config_state('pw-accept-state') is None

    def test_set(self) -> None:
        b4.MAIN_CONFIG['pw-review-state'] = 'under-review'
        assert b4.review.pw_config_state('pw-review-state') == 'under-review'


class TestResolvePwSeriesId:
    def test_looks_up_cover_and_stores_id(self, fake_pw: _FakePw) -> None:
        """A series tracked outside the Patchwork TUI gets its id by msgid."""
        _seed()
        assert _stored_pw_id() is None
        assert b4.review.resolve_pw_series_id(IDENTIFIER, CHANGE_ID, 1) == PW_SERIES_ID
        assert _stored_pw_id() == PW_SERIES_ID

        # Stored now, so the next call does not ask Patchwork again.
        fake_pw.gets.clear()
        assert b4.review.resolve_pw_series_id(IDENTIFIER, CHANGE_ID, 1) == PW_SERIES_ID
        assert fake_pw.gets == []

    def test_falls_back_to_patches(self, fake_pw: _FakePw) -> None:
        """Without a cover letter the message-id is the first patch."""
        fake_pw.covers = {}
        fake_pw.patches = {'patch1@example.com': PW_SERIES_ID}
        _seed(message_id='patch1@example.com')
        assert b4.review.resolve_pw_series_id(IDENTIFIER, CHANGE_ID, 1) == PW_SERIES_ID

    def test_unknown_to_patchwork(self, fake_pw: _FakePw) -> None:
        _seed(message_id='nobody@example.com')
        assert b4.review.resolve_pw_series_id(IDENTIFIER, CHANGE_ID, 1) is None
        assert _stored_pw_id() is None

    def test_ignores_entries_for_other_messages(self, fake_pw: _FakePw) -> None:
        """A server that ignores the msgid filter must not yield a wrong id.

        Such a server answers with the whole project listing. The first
        entry would be stored as this series' id for good, so only an
        entry whose msgid matches counts.
        """
        fake_pw.covers = {'other@example.com': 55}
        fake_pw.ignore_msgid_filter = True
        _seed()
        assert b4.review.resolve_pw_series_id(IDENTIFIER, CHANGE_ID, 1) is None
        assert _stored_pw_id() is None

        # The right series is still found when it is somewhere in the list.
        fake_pw.covers[COVER_MSGID] = PW_SERIES_ID
        assert b4.review.resolve_pw_series_id(IDENTIFIER, CHANGE_ID, 1) == PW_SERIES_ID

    def test_revision_defaults_to_newest(self, fake_pw: _FakePw) -> None:
        _seed()
        assert b4.review.resolve_pw_series_id(IDENTIFIER, CHANGE_ID) == PW_SERIES_ID

    def test_patchwork_not_configured(self, fake_pw: _FakePw) -> None:
        b4.MAIN_CONFIG['pw-project'] = ''
        _seed()
        assert b4.review.resolve_pw_series_id(IDENTIFIER, CHANGE_ID, 1) is None
        assert fake_pw.gets == []


class TestPwUpdateTrackedSeries:
    def test_state_only(self, fake_pw: _FakePw) -> None:
        _seed()
        assert b4.review.pw_update_tracked_series(IDENTIFIER, CHANGE_ID, 1, 'accepted')
        # One PATCH per patch, and 'archived' is left alone.
        assert _sent(fake_pw) == [{'state': 'accepted'}] * len(PW_PATCH_IDS)

    def test_archived_only(self, fake_pw: _FakePw) -> None:
        _seed()
        assert b4.review.pw_update_tracked_series(
            IDENTIFIER, CHANGE_ID, 1, None, archived=True
        )
        assert _sent(fake_pw) == [{'archived': True}] * len(PW_PATCH_IDS)

    def test_nothing_to_change_skips_lookup(self, fake_pw: _FakePw) -> None:
        _seed()
        assert b4.review.pw_update_tracked_series(IDENTIFIER, CHANGE_ID, 1, None)
        assert fake_pw.gets == []
        assert fake_pw.patched == []


class TestArchiveSeriesPatchwork:
    """archive_series archives in Patchwork; the state only when asked."""

    def test_plain_archive_keeps_state(self, fake_pw: _FakePw) -> None:
        """A manual archive or an upgrade must not claim 'accepted'."""
        _seed(status='waiting')
        ok, detail = b4.review.archive_series(None, IDENTIFIER, CHANGE_ID, 1)
        assert ok, detail
        assert _sent(fake_pw) == [{'archived': True}] * len(PW_PATCH_IDS)

    def test_archive_after_thanks_sets_accept_state(self, fake_pw: _FakePw) -> None:
        _seed(status='thanked')
        ok, detail = b4.review.archive_series(
            None, IDENTIFIER, CHANGE_ID, 1, pw_state='accepted'
        )
        assert ok, detail
        assert _sent(fake_pw) == [{'state': 'accepted', 'archived': True}] * len(
            PW_PATCH_IDS
        )


class TestTakeUpdatesPatchwork:
    """The review TUI's take sets pw-accept-state, the same as b4 ty."""

    def _take(self, gitdir: str) -> None:
        pytest.importorskip('textual')
        from b4.review_tui._tracking_app import TrackingApp

        _seed()
        app = TrackingApp(IDENTIFIER)
        series = {'change_id': CHANGE_ID, 'revision': 1}
        app._finalize_take(gitdir, 'master', CHANGE_ID, series, 'accepted')

    def test_take_sets_accept_state(self, gitdir: str, fake_pw: _FakePw) -> None:
        """The bug: a series not tracked from the Patchwork TUI was skipped."""
        b4.MAIN_CONFIG['pw-accept-state'] = 'accepted'
        self._take(gitdir)
        assert _sent(fake_pw) == [{'state': 'accepted'}] * len(PW_PATCH_IDS)
        assert _stored_pw_id() == PW_SERIES_ID

    def test_take_without_accept_state_leaves_patchwork(
        self, gitdir: str, fake_pw: _FakePw
    ) -> None:
        self._take(gitdir)
        assert fake_pw.gets == []
        assert fake_pw.patched == []
