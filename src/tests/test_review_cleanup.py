# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Arm Ltd.

import argparse
import logging
import sqlite3
from typing import Dict
from unittest import mock

import pytest

import b4.command
from b4 import review
from b4.review import tracking


def test_cleanup_parser_and_dispatch() -> None:
    parser = b4.command.setup_parser()
    cmdargs = parser.parse_args(
        ['review', 'cleanup', '--dry-run', '--identifier', 'project']
    )

    assert cmdargs.review_subcmd == 'cleanup'
    assert cmdargs.dryrun is True
    assert cmdargs.identifier == 'project'

    with mock.patch('b4.review.tracking.cmd_cleanup') as cleanup:
        review.main(cmdargs)

    cleanup.assert_called_once_with(cmdargs)


class TestCmdCleanup:
    @staticmethod
    def _seed(identifier: str, statuses: Dict[str, str]) -> None:
        conn = tracking.init_db(identifier)
        for revision, (change_id, status) in enumerate(statuses.items(), 1):
            tracking.add_series_to_db(
                conn,
                change_id,
                revision,
                f'Subject for {change_id}',
                'Author',
                'author@example.com',
                '2026-08-01T10:00:00+00:00',
                f'{change_id}@example.com',
                1,
            )
            tracking.update_series_status(conn, change_id, status, revision=revision)
            tracking.add_revision(conn, change_id, revision, f'{change_id}@example.com')
            conn.execute(
                'INSERT INTO series_patches '
                '(change_id, revision, position, message_id, subject) '
                'VALUES (?, ?, ?, ?, ?)',
                (
                    change_id,
                    revision,
                    1,
                    f'{change_id}-patch@example.com',
                    f'Patch for {change_id}',
                ),
            )
        conn.commit()
        conn.close()

    @staticmethod
    def _row_counts(identifier: str, change_id: str) -> Dict[str, int]:
        conn = tracking.get_db(identifier)
        counts = {
            table: conn.execute(
                f'SELECT COUNT(*) FROM {table} WHERE change_id = ?', (change_id,)
            ).fetchone()[0]
            for table in ('series', 'revisions', 'series_patches')
        }
        conn.close()
        return counts

    def test_abandons_only_gone_series(self) -> None:
        identifier = 'cleanup-gone'
        statuses = {
            'gone-one': 'gone',
            'keep-new': 'new',
            'gone-two': 'gone',
            'keep-archived': 'archived',
        }
        self._seed(identifier, statuses)

        # Abandon removes the whole logical series, not just the revision in
        # the series table.  Keep extra known-revision data under one Gone
        # change-id so a revision-scoped deletion would leave evidence behind.
        conn = tracking.get_db(identifier)
        tracking.add_revision(conn, 'gone-one', 99, 'gone-one-v99@example.com')
        conn.execute(
            'INSERT INTO series_patches '
            '(change_id, revision, position, message_id, subject) '
            'VALUES (?, ?, ?, ?, ?)',
            (
                'gone-one',
                99,
                1,
                'gone-one-v99-patch@example.com',
                'Extra known revision patch',
            ),
        )
        conn.commit()
        conn.close()

        tracking.cmd_cleanup(argparse.Namespace(identifier=identifier, dryrun=False))

        for change_id, status in statuses.items():
            counts = self._row_counts(identifier, change_id)
            if status == 'gone':
                assert counts == {'series': 0, 'revisions': 0, 'series_patches': 0}
            else:
                assert counts == {'series': 1, 'revisions': 1, 'series_patches': 1}

    def test_uses_newest_revision_status(self) -> None:
        identifier = 'cleanup-current-status'
        conn = tracking.init_db(identifier)
        for change_id, statuses in (
            ('keep-current', ('gone', 'reviewing')),
            ('clean-current', ('reviewing', 'gone')),
        ):
            for revision, status in enumerate(statuses, 1):
                tracking.add_series_to_db(
                    conn,
                    change_id,
                    revision,
                    f'{change_id} v{revision}',
                    'Author',
                    'author@example.com',
                    '2026-08-01T10:00:00+00:00',
                    f'{change_id}-v{revision}@example.com',
                    1,
                )
                tracking.update_series_status(
                    conn, change_id, status, revision=revision
                )
                tracking.add_revision(
                    conn,
                    change_id,
                    revision,
                    f'{change_id}-v{revision}@example.com',
                )
        conn.close()

        tracking.cmd_cleanup(argparse.Namespace(identifier=identifier, dryrun=False))

        assert self._row_counts(identifier, 'keep-current')['series'] == 2
        assert self._row_counts(identifier, 'clean-current') == {
            'series': 0,
            'revisions': 0,
            'series_patches': 0,
        }

    def test_failure_rolls_back_the_batch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        identifier = 'cleanup-rollback'
        self._seed(identifier, {'gone-one': 'gone', 'gone-two': 'gone'})
        original_delete = tracking.delete_series
        calls = 0

        def fail_on_second_delete(
            conn: sqlite3.Connection,
            change_id: str,
            revision: int | None = None,
            *,
            commit: bool = True,
        ) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError('simulated cleanup failure')
            original_delete(conn, change_id, revision, commit=commit)

        monkeypatch.setattr(tracking, 'delete_series', fail_on_second_delete)

        with pytest.raises(RuntimeError, match='simulated cleanup failure'):
            tracking.cmd_cleanup(
                argparse.Namespace(identifier=identifier, dryrun=False)
            )

        for change_id in ('gone-one', 'gone-two'):
            assert self._row_counts(identifier, change_id) == {
                'series': 1,
                'revisions': 1,
                'series_patches': 1,
            }

    def test_dry_run_lists_candidates_without_deleting(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        identifier = 'cleanup-dry-run'
        statuses = {
            'gone-one': 'gone',
            'keep-new': 'new',
            'gone-two': 'gone',
        }
        self._seed(identifier, statuses)

        with caplog.at_level(logging.INFO, logger='b4'):
            tracking.cmd_cleanup(argparse.Namespace(identifier=identifier, dryrun=True))

        assert 'gone-one' in caplog.text
        assert 'Subject for gone-one' in caplog.text
        assert 'gone-two' in caplog.text
        assert 'Subject for gone-two' in caplog.text
        assert 'keep-new' not in caplog.text
        assert 'Dry run' in caplog.text
        for change_id in statuses:
            assert self._row_counts(identifier, change_id) == {
                'series': 1,
                'revisions': 1,
                'series_patches': 1,
            }

    def test_no_gone_series_is_a_noop(self, caplog: pytest.LogCaptureFixture) -> None:
        identifier = 'cleanup-empty'
        self._seed(identifier, {'keep-new': 'new'})

        with caplog.at_level(logging.INFO, logger='b4'):
            tracking.cmd_cleanup(
                argparse.Namespace(identifier=identifier, dryrun=False)
            )

        assert 'No Gone series to clean up' in caplog.text
        assert self._row_counts(identifier, 'keep-new')['series'] == 1
