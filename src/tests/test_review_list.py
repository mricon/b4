#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Tests for ``b4 review list``.

Deliberately free of ``pytest.importorskip('textual')``: the whole point
of this command is to be reachable from a script, so it must work with the
optional ``[tui]`` extra absent.
"""

import argparse
import json
import sqlite3
from typing import Any, List, Optional

import pytest

import b4
from b4.review import tracking as review_tracking

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed(
    identifier: str,
    change_id: str,
    *,
    revision: int = 1,
    status: str = 'new',
    subject: str = 'A series',
    sender_name: str = 'Test Author',
    num_patches: int = 1,
    message_id: Optional[str] = None,
) -> None:
    """Add one tracked series with matching revision and patch rows."""
    if message_id is None:
        message_id = f'{change_id}-cover@example.com'
    if review_tracking.db_exists(identifier):
        conn = review_tracking.get_db(identifier)
    else:
        conn = review_tracking.init_db(identifier)
    review_tracking.add_series_to_db(
        conn,
        change_id=change_id,
        revision=revision,
        subject=subject,
        sender_name=sender_name,
        sender_email='author@example.com',
        sent_at='2026-01-15T10:00:00+00:00',
        message_id=message_id,
        num_patches=num_patches,
    )
    conn.execute(
        'UPDATE series SET status = ? WHERE change_id = ? AND revision = ?',
        (status, change_id, revision),
    )
    review_tracking.add_revision(
        conn,
        change_id=change_id,
        revision=revision,
        message_id=message_id,
    )
    rows = [
        (change_id, revision, pos, f'{change_id}-p{pos}@example.com', f'patch {pos}')
        for pos in range(1, num_patches + 1)
    ]
    conn.executemany(
        'INSERT INTO series_patches (change_id, revision, position, message_id,'
        ' subject) VALUES (?, ?, ?, ?, ?)',
        rows,
    )
    conn.commit()
    conn.close()


def _args(**kwargs: Any) -> argparse.Namespace:
    """Build a cmdargs namespace with the b4 review list defaults."""
    defaults: dict[str, Any] = {
        'identifier': None,
        'all_projects': False,
        'status': None,
        'json_output': False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# collect_tracked_series()
# ---------------------------------------------------------------------------


class TestCollectTrackedSeries:
    """Tests for the data-gathering half of b4 review list."""

    def test_archived_excluded_by_default(self) -> None:
        _seed('proj', 'cid-live', status='reviewing')
        _seed('proj', 'cid-done', status='archived')
        entries = review_tracking.collect_tracked_series(identifiers=['proj'])
        assert [e['change_id'] for e in entries] == ['cid-live']

    def test_status_all_includes_archived(self) -> None:
        _seed('proj', 'cid-live', status='reviewing')
        _seed('proj', 'cid-done', status='archived')
        entries = review_tracking.collect_tracked_series(
            identifiers=['proj'], statuses=['all']
        )
        assert {e['change_id'] for e in entries} == {'cid-live', 'cid-done'}

    def test_status_filter_is_repeatable(self) -> None:
        _seed('proj', 'cid-new', status='new')
        _seed('proj', 'cid-wait', status='waiting')
        _seed('proj', 'cid-rev', status='reviewing')
        entries = review_tracking.collect_tracked_series(
            identifiers=['proj'], statuses=['new', 'waiting']
        )
        assert {e['change_id'] for e in entries} == {'cid-new', 'cid-wait'}

    def test_status_filter_can_select_archived(self) -> None:
        """An explicit --status archived overrides the default exclusion."""
        _seed('proj', 'cid-live', status='reviewing')
        _seed('proj', 'cid-done', status='archived')
        entries = review_tracking.collect_tracked_series(
            identifiers=['proj'], statuses=['archived']
        )
        assert [e['change_id'] for e in entries] == ['cid-done']

    def test_message_ids_union_all_three_tables(self) -> None:
        """A hit on any patch of a tracked series has to be recognisable."""
        _seed('proj', 'cid-1', num_patches=3, message_id='cover@example.com')
        (entry,) = review_tracking.collect_tracked_series(identifiers=['proj'])
        assert entry['message_ids'] == [
            'cover@example.com',
            'cid-1-p1@example.com',
            'cid-1-p2@example.com',
            'cid-1-p3@example.com',
        ]

    def test_message_ids_span_revisions(self) -> None:
        """Every known revision's cover contributes to the exclusion set."""
        _seed('proj', 'cid-1', revision=2, message_id='v2@example.com')
        conn = review_tracking.get_db('proj')
        review_tracking.add_revision(
            conn, change_id='cid-1', revision=1, message_id='v1@example.com'
        )
        conn.commit()
        conn.close()
        (entry,) = review_tracking.collect_tracked_series(identifiers=['proj'])
        assert 'v1@example.com' in entry['message_ids']
        assert 'v2@example.com' in entry['message_ids']

    def test_identifier_is_attached(self) -> None:
        _seed('proj-a', 'cid-a')
        _seed('proj-b', 'cid-b')
        entries = review_tracking.collect_tracked_series(all_projects=True)
        assert {(e['identifier'], e['change_id']) for e in entries} == {
            ('proj-a', 'cid-a'),
            ('proj-b', 'cid-b'),
        }

    def test_all_projects_ignores_requested_identifiers(self) -> None:
        _seed('proj-a', 'cid-a')
        _seed('proj-b', 'cid-b')
        entries = review_tracking.collect_tracked_series(
            identifiers=['proj-a'], all_projects=True
        )
        assert {e['identifier'] for e in entries} == {'proj-a', 'proj-b'}

    def test_sibling_caches_are_not_listed(self) -> None:
        """--all-projects must not trip over the non-project databases."""
        from b4.review import checks as review_checks
        from b4.review import messages as review_messages

        _seed('proj', 'cid-1')
        review_messages.get_db().close()
        review_checks.get_db().close()
        entries = review_tracking.collect_tracked_series(all_projects=True)
        assert {e['identifier'] for e in entries} == {'proj'}

    def test_unknown_identifier_exits(self) -> None:
        with pytest.raises(SystemExit) as exc:
            review_tracking.collect_tracked_series(identifiers=['no-such-project'])
        assert exc.value.code == 1

    def test_no_databases_at_all_exits(self) -> None:
        with pytest.raises(SystemExit) as exc:
            review_tracking.collect_tracked_series(all_projects=True)
        assert exc.value.code == 1

    def test_unknown_status_raises(self) -> None:
        # The CLI keeps this unreachable via argparse choices=, so it is a
        # programming error rather than user input -- but failing open here
        # would silently produce an empty exclusion set.
        _seed('proj', 'cid-1')
        with pytest.raises(ValueError, match='bogus'):
            review_tracking.collect_tracked_series(statuses=['bogus'])

    def test_every_known_status_is_accepted(self) -> None:
        _seed('proj', 'cid-1')
        for status in b4.REVIEW_STATUS_CHOICES:
            review_tracking.collect_tracked_series(statuses=[status])

    def test_orphaned_patch_rows_are_not_attributed(self) -> None:
        """Patch rows left behind by a deleted series belong to no listing."""
        _seed('proj', 'cid-1')
        conn = review_tracking.get_db('proj')
        conn.execute(
            'INSERT INTO series_patches (change_id, revision, position,'
            ' message_id, subject) VALUES (?, ?, ?, ?, ?)',
            ('cid-gone', 1, 1, 'stray@example.com', 'stray'),
        )
        conn.commit()
        conn.close()
        entries = review_tracking.collect_tracked_series(identifiers=['proj'])
        assert [e['change_id'] for e in entries] == ['cid-1']
        assert 'stray@example.com' not in entries[0]['message_ids']


# ---------------------------------------------------------------------------
# get_all_series_message_ids()
# ---------------------------------------------------------------------------


class TestGetAllSeriesMessageIds:
    """Tests for the bulk message-id lookup."""

    def test_missing_db_returns_empty(self) -> None:
        assert review_tracking.get_all_series_message_ids('nope') == {}

    def test_is_keyed_by_change_id(self) -> None:
        _seed('proj', 'cid-a', num_patches=2)
        _seed('proj', 'cid-b', num_patches=1)
        msgids = review_tracking.get_all_series_message_ids('proj')
        assert set(msgids) == {'cid-a', 'cid-b'}
        assert len(msgids['cid-a']) == 3
        assert len(msgids['cid-b']) == 2

    def test_duplicates_are_collapsed(self) -> None:
        """The cover message-id is in both series and revisions."""
        _seed('proj', 'cid-1', num_patches=0, message_id='same@example.com')
        assert review_tracking.get_all_series_message_ids('proj') == {
            'cid-1': ['same@example.com']
        }

    def test_broken_db_is_tolerated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A missing table must not take the whole listing down."""
        _seed('proj', 'cid-1')
        conn = review_tracking.get_db('proj')
        conn.execute('DROP TABLE series_patches')
        conn.commit()
        conn.close()
        msgids = review_tracking.get_all_series_message_ids('proj')
        assert msgids['cid-1'] == ['cid-1-cover@example.com']


# ---------------------------------------------------------------------------
# cmd_list()
# ---------------------------------------------------------------------------


class TestCmdList:
    """Tests for the command's output rendering."""

    def test_json_output_is_an_array_of_objects(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _seed('proj', 'cid-1', num_patches=2, subject='[PATCH 0/2] Do things')
        review_tracking.cmd_list(_args(identifier=['proj'], json_output=True))
        data = json.loads(capsys.readouterr().out)
        assert len(data) == 1
        assert data[0]['identifier'] == 'proj'
        assert data[0]['change_id'] == 'cid-1'
        assert data[0]['subject'] == '[PATCH 0/2] Do things'
        # The fields get_all_tracked_series() promises are all carried over
        for key in (
            'track_id',
            'revision',
            'sender_name',
            'sender_email',
            'sent_at',
            'added_at',
            'status',
            'num_patches',
            'message_id',
            'pw_series_id',
            'message_count',
            'seen_message_count',
            'last_activity_at',
            'attestation',
            'target_branch',
            'is_rethreaded',
            'snoozed_until',
        ):
            assert key in data[0], key
        assert 'cid-1-p2@example.com' in data[0]['message_ids']

    def test_json_output_is_empty_array_when_nothing_matches(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A script must get valid JSON even with an empty plate."""
        _seed('proj', 'cid-1', status='archived')
        review_tracking.cmd_list(_args(identifier=['proj'], json_output=True))
        assert json.loads(capsys.readouterr().out) == []

    def test_human_output_groups_by_project(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        _seed('proj-a', 'cid-a', subject='Series A', sender_name='Ada')
        _seed('proj-b', 'cid-b', subject='Series B', sender_name='Bob')
        review_tracking.cmd_list(_args(all_projects=True))
        lines = [rec.getMessage() for rec in caplog.records]
        assert 'proj-a (1 series)' in lines
        assert 'proj-b (1 series)' in lines
        assert any('Ada' in ln and 'Series A' in ln for ln in lines)
        assert any(ln.strip() == 'cid-a' for ln in lines)

    def test_human_output_says_so_when_empty(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        _seed('proj', 'cid-1', status='archived')
        review_tracking.cmd_list(_args(identifier=['proj']))
        assert 'No tracked series found.' in [
            rec.getMessage() for rec in caplog.records
        ]

    def test_full_width_sender_stays_aligned(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The sender column is padded by display width, not character count."""
        _seed('proj', 'cid-1', sender_name='戸田晃太', subject='SUBJ')
        _seed('proj', 'cid-2', sender_name='Toda Kota', subject='SUBJ')
        review_tracking.cmd_list(_args(identifier=['proj']))
        lines = [
            rec.getMessage() for rec in caplog.records if 'SUBJ' in rec.getMessage()
        ]
        assert len(lines) == 2
        from b4._textwidth import display_width

        assert display_width(lines[0]) == display_width(lines[1])


# ---------------------------------------------------------------------------
# resolve_projects()
# ---------------------------------------------------------------------------


class TestStatusVocabulary:
    """The --status vocabulary has to match what the DB actually holds."""

    def test_all_is_only_in_the_filter_choices(self) -> None:
        assert 'all' not in b4.REVIEW_SERIES_STATUSES
        assert 'all' in b4.REVIEW_STATUS_CHOICES

    def test_legacy_taken_status_is_absent(self) -> None:
        # Schema v3 migrated 'taken' to 'accepted'; offering it as a filter
        # would promise matches that can never happen.
        assert 'taken' not in b4.REVIEW_STATUS_CHOICES

    def test_covers_every_status_the_tui_can_draw(self) -> None:
        tui = pytest.importorskip('b4.review_tui._tracking_app')
        assert set(tui._STATUS_SYMBOLS).issubset(b4.REVIEW_SERIES_STATUSES)
        assert set(tui._STATUS_TIER).issubset(b4.REVIEW_SERIES_STATUSES)

    def test_archived_is_the_only_symbol_less_status(self) -> None:
        tui = pytest.importorskip('b4.review_tui._tracking_app')
        missing = set(b4.REVIEW_SERIES_STATUSES) - set(tui._STATUS_SYMBOLS)
        assert missing == {'archived'}


class TestResolveProjects:
    """Tests for the shared identifier resolution."""

    def test_named_identifiers_keep_order(self) -> None:
        _seed('proj-a', 'cid-a')
        _seed('proj-b', 'cid-b')
        projects = review_tracking.resolve_projects(['proj-b', 'proj-a'])
        assert [p[0] for p in projects] == ['proj-b', 'proj-a']

    def test_all_sentinel_selects_everything(self) -> None:
        _seed('proj-a', 'cid-a')
        _seed('proj-b', 'cid-b')
        projects = review_tracking.resolve_projects(['__all__'])
        assert sorted(p[0] for p in projects) == ['proj-a', 'proj-b']

    def test_unrecorded_project_yields_no_topdir(self) -> None:
        _seed('proj', 'cid-1')
        assert review_tracking.resolve_projects(['proj']) == [('proj', None)]

    def test_cwd_project_is_the_default(self, gitdir: str) -> None:
        """Run from inside an enrolled repository, the bare command uses it."""
        _seed('cwd-proj', 'cid-1')
        _seed('other-proj', 'cid-2')
        review_tracking.save_repo_metadata(f'{gitdir}/.git', 'cwd-proj')
        assert review_tracking.resolve_projects(None) == [('cwd-proj', gitdir)]

    def test_force_all_overrides_the_cwd_project(self, gitdir: str) -> None:
        _seed('cwd-proj', 'cid-1')
        _seed('other-proj', 'cid-2')
        review_tracking.save_repo_metadata(f'{gitdir}/.git', 'cwd-proj')
        projects = review_tracking.resolve_projects(None, force_all=True)
        assert sorted(p[0] for p in projects) == ['cwd-proj', 'other-proj']


def _table_names(identifier: str) -> List[str]:
    conn = sqlite3.connect(review_tracking.get_db_path(identifier))
    names = [
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    ]
    conn.close()
    return names


class TestIsTrackingDb:
    """Tests for the tracking-database probe."""

    def test_recognises_a_tracking_db(self) -> None:
        review_tracking.init_db('proj').close()
        assert 'series' in _table_names('proj')
        assert review_tracking.is_tracking_db(review_tracking.get_db_path('proj'))

    def test_rejects_a_sibling_cache(self) -> None:
        from b4.review import messages as review_messages

        review_messages.get_db().close()
        path = f'{review_tracking.get_review_data_dir()}/messages.sqlite3'
        assert not review_tracking.is_tracking_db(path)

    def test_rejects_a_non_database(self, tmp_path: Any) -> None:
        path = tmp_path / 'junk.sqlite3'
        path.write_text('definitely not sqlite\n')
        assert not review_tracking.is_tracking_db(str(path))
