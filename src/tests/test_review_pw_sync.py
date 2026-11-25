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

import contextlib
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

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
        assert b4.pw_config_state('pw-accept-state') is None

    def test_empty_is_none(self) -> None:
        b4.MAIN_CONFIG['pw-accept-state'] = ''
        assert b4.pw_config_state('pw-accept-state') is None

    def test_set(self) -> None:
        b4.MAIN_CONFIG['pw-review-state'] = 'under-review'
        assert b4.pw_config_state('pw-review-state') == 'under-review'


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

    def test_switched_revision_looks_up_its_own_id(self, fake_pw: _FakePw) -> None:
        """Each Patchwork series holds one revision, so a revision switch
        must not keep sending state changes to the old revision's series."""
        _seed()
        conn = tracking.get_db(IDENTIFIER)
        tracking.set_pw_series_id(conn, CHANGE_ID, 1, PW_SERIES_ID)
        tracking.update_series_revision(conn, CHANGE_ID, 1, 2, 'v2cover@example.com')
        conn.close()
        fake_pw.covers['v2cover@example.com'] = PW_SERIES_ID + 1
        assert b4.review.resolve_pw_series_id(IDENTIFIER, CHANGE_ID, 2) == (
            PW_SERIES_ID + 1
        )

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


class TestTuiFetchesKeyBeforeSync:
    """With b4.pw-user the key comes from a git credential helper, and a
    helper may ask for a passphrase on the terminal.  Every tracking-list
    action that updates Patchwork while the TUI is on the screen must
    fetch the key first, with the TUI out of the way.  Otherwise the first
    of these actions in a session runs the helper under the TUI, or in the
    queue's worker thread, where its prompt can't be seen or answered."""

    @pytest.fixture
    def app(self, gitdir: str, fake_pw: _FakePw) -> Any:
        pytest.importorskip('textual')
        from b4.review_tui._tracking_app import TrackingApp

        _seed(status='thanked')
        return TrackingApp(IDENTIFIER)

    @pytest.fixture
    def order(self, fake_pw: _FakePw, monkeypatch: pytest.MonkeyPatch) -> List[str]:
        """What happened, in order: 'key' for a fetch, the caller adds more."""
        import b4.review_tui._tracking_app as _tracking_app

        order: List[str] = []

        def _fetch(app: Any) -> str:
            # Nothing may have reached Patchwork before the key is in hand
            assert fake_pw.gets == []
            assert fake_pw.patched == []
            order.append('key')
            return 'key'

        monkeypatch.setattr(_tracking_app, 'pw_key_suspended', _fetch)
        return order

    def test_reopening_a_thanked_series(
        self, app: Any, order: List[str], fake_pw: _FakePw, gitdir: str
    ) -> None:
        b4.MAIN_CONFIG['pw-review-state'] = 'under-review'
        branch = f'b4/review/{CHANGE_ID}'
        ecode, _out = b4.git_run_command(gitdir, ['branch', branch])
        assert ecode == 0
        app._selected_series = {
            'change_id': CHANGE_ID,
            'revision': 1,
            'status': 'thanked',
        }
        with (
            mock.patch.object(b4.review, 'update_tracking_status'),
            mock.patch.object(app, 'exit') as app_exit,
        ):
            app.action_review()
        app_exit.assert_called_once_with(branch)
        assert order == ['key']
        assert _sent(fake_pw) == [{'state': 'under-review', 'archived': False}] * len(
            PW_PATCH_IDS
        )

    def test_checking_out_a_series(
        self, app: Any, order: List[str], fake_pw: _FakePw
    ) -> None:
        import b4.review_tui._tracking_app as _tracking_app

        b4.MAIN_CONFIG['pw-review-state'] = 'under-review'
        lser = mock.Mock(complete=False)
        lser.patches = [mock.Mock(body='body', msgid='patch1@example.com')]
        series = {'change_id': CHANGE_ID, 'revision': 1}
        with (
            mock.patch.object(_tracking_app, 'suspended', contextlib.nullcontext),
            mock.patch.object(b4, 'git_fetch_am_into_repo'),
            mock.patch.object(b4.review, 'create_review_branch'),
            mock.patch.object(app, 'exit') as app_exit,
        ):
            app._do_checkout(lser, series, base_commit='HEAD', ambytes=b'')
        app_exit.assert_called_once()
        assert order == ['key']
        assert _sent(fake_pw) == [{'state': 'under-review'}] * len(PW_PATCH_IDS)

    @pytest.mark.parametrize('after_thanks', [False, True])
    def test_archiving_a_series(
        self, app: Any, order: List[str], after_thanks: bool
    ) -> None:
        def _archive(*args: Any, **kwargs: Any) -> bool:
            order.append('archive')
            return False

        with mock.patch.object(app, '_archive_branch', _archive):
            if after_thanks:
                app._archive_after_thanks({'change_id': CHANGE_ID, 'revision': 1})
            else:
                app._on_archive_confirmed(True, CHANGE_ID, 'b4/review/x', True, 1)
        assert order == ['key', 'archive']

    def test_delivering_the_queue(self, app: Any, order: List[str]) -> None:
        """Delivery archives the series it was asked to, from a worker."""
        with mock.patch.object(
            app, 'push_screen', lambda *a, **k: order.append('deliver')
        ):
            app._deliver_queue()
        assert order == ['key', 'deliver']

    def test_no_fetch_when_the_action_leaves_patchwork_alone(
        self, app: Any, order: List[str], fake_pw: _FakePw
    ) -> None:
        """Without pw-review-state a checkout sends nothing to Patchwork,
        so it must not cost a passphrase prompt either."""
        import b4.review_tui._tracking_app as _tracking_app

        lser = mock.Mock(complete=False)
        lser.patches = [mock.Mock(body='body', msgid='patch1@example.com')]
        series = {'change_id': CHANGE_ID, 'revision': 1}
        with (
            mock.patch.object(_tracking_app, 'suspended', contextlib.nullcontext),
            mock.patch.object(b4, 'git_fetch_am_into_repo'),
            mock.patch.object(b4.review, 'create_review_branch'),
            mock.patch.object(app, 'exit'),
        ):
            app._do_checkout(lser, series, base_commit='HEAD', ambytes=b'')
        assert order == []
        assert fake_pw.patched == []

    def test_a_missing_key_is_reported(
        self, app: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The update is skipped without a key, and the helper's own error
        went to a screen the TUI has since redrawn."""
        import b4.review_tui._tracking_app as _tracking_app

        del b4.MAIN_CONFIG['pw-key']
        b4.MAIN_CONFIG['pw-user'] = 'me'
        monkeypatch.setattr(_tracking_app, 'pw_key_suspended', lambda app: '')
        notes: List[str] = []
        with (
            mock.patch.object(app, 'notify', lambda msg, **k: notes.append(msg)),
            mock.patch.object(app, '_archive_branch', return_value=False),
        ):
            app._on_archive_confirmed(True, CHANGE_ID, 'b4/review/x', True, 1)
        assert len(notes) == 1
        assert 'me@pw.example.org' in notes[0]
