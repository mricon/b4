import datetime
import os
from typing import Dict, List, Optional

import pytest

from b4.review import messages


class TestGetDb:
    """Tests for get_db() and database creation."""

    def test_creates_database(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        db_path = messages._get_db_path()
        assert os.path.exists(db_path)
        assert db_path.endswith('messages.sqlite3')
        conn.close()

    def test_creates_schema(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]
        assert 'messages' in tables
        assert 'schema_version' in tables
        conn.close()

    def test_sets_schema_version(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        version = conn.execute('SELECT version FROM schema_version').fetchone()[0]
        assert version == messages.SCHEMA_VERSION
        conn.close()

    def test_reopens_existing(self, tmp_path: pytest.TempPathFactory) -> None:
        conn1 = messages.get_db()
        messages.set_flag(conn1, 'test@example.com', 'Seen')
        conn1.close()
        conn2 = messages.get_db()
        assert messages.get_flags(conn2, 'test@example.com') == 'Seen'
        conn2.close()


class TestGetFlags:
    """Tests for get_flags()."""

    def test_unknown_msgid(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        assert messages.get_flags(conn, 'unknown@example.com') == ''
        conn.close()

    def test_returns_flags(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        messages.set_flag(conn, 'test@example.com', 'Seen')
        assert messages.get_flags(conn, 'test@example.com') == 'Seen'
        conn.close()


class TestGetFlagsBulk:
    """Tests for get_flags_bulk()."""

    def test_empty_list(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        assert messages.get_flags_bulk(conn, []) == {}
        conn.close()

    def test_returns_known_only(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        messages.set_flag(conn, 'a@example.com', 'Seen')
        messages.set_flag(conn, 'b@example.com', 'Flagged')
        result = messages.get_flags_bulk(
            conn, ['a@example.com', 'b@example.com', 'c@example.com']
        )
        assert 'a@example.com' in result
        assert 'b@example.com' in result
        assert 'c@example.com' not in result
        conn.close()


class TestSetFlag:
    """Tests for set_flag()."""

    def test_creates_new_row(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        messages.set_flag(
            conn, 'new@example.com', 'Seen', msg_date='2026-03-05T10:00:00'
        )
        flags = messages.get_flags(conn, 'new@example.com')
        assert 'Seen' in flags
        conn.close()

    def test_adds_to_existing(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        messages.set_flag(conn, 'multi@example.com', 'Seen')
        messages.set_flag(conn, 'multi@example.com', 'Flagged')
        flags = messages.get_flags(conn, 'multi@example.com')
        assert 'Seen' in flags
        assert 'Flagged' in flags
        conn.close()

    def test_idempotent(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        messages.set_flag(conn, 'idem@example.com', 'Seen')
        messages.set_flag(conn, 'idem@example.com', 'Seen')
        flags = messages.get_flags(conn, 'idem@example.com')
        assert flags == 'Seen'
        conn.close()

    def test_flags_sorted(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        messages.set_flag(conn, 'sort@example.com', 'Seen')
        messages.set_flag(conn, 'sort@example.com', 'Flagged')
        messages.set_flag(conn, 'sort@example.com', 'Answered')
        flags = messages.get_flags(conn, 'sort@example.com')
        assert flags == 'Answered Flagged Seen'
        conn.close()


class TestSetFlagsBulk:
    """Tests for set_flags_bulk()."""

    def test_sets_multiple(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        entries: List[Dict[str, Optional[str]]] = [
            {'msgid': 'a@example.com', 'msg_date': '2026-01-01T00:00:00'},
            {'msgid': 'b@example.com', 'msg_date': '2026-01-02T00:00:00'},
            {'msgid': 'c@example.com', 'msg_date': None},
        ]
        messages.set_flags_bulk(conn, entries, 'Seen')
        result = messages.get_flags_bulk(
            conn, ['a@example.com', 'b@example.com', 'c@example.com']
        )
        assert all('Seen' in v for v in result.values())
        conn.close()

    def test_skips_empty_msgid(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        entries = [
            {'msgid': '', 'msg_date': None},
            {'msgid': 'valid@example.com', 'msg_date': None},
        ]
        messages.set_flags_bulk(conn, entries, 'Seen')
        result = messages.get_flags_bulk(conn, ['', 'valid@example.com'])
        assert '' not in result
        assert 'valid@example.com' in result
        conn.close()

    def test_adds_to_existing_flags(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        messages.set_flag(conn, 'exist@example.com', 'Seen')
        entries = [{'msgid': 'exist@example.com', 'msg_date': None}]
        messages.set_flags_bulk(conn, entries, 'Answered')
        flags = messages.get_flags(conn, 'exist@example.com')
        assert 'Seen' in flags
        assert 'Answered' in flags
        conn.close()


class TestRemoveFlag:
    """Tests for remove_flag()."""

    def test_removes_single_flag(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        messages.set_flag(conn, 'rm@example.com', 'Seen')
        messages.set_flag(conn, 'rm@example.com', 'Flagged')
        messages.remove_flag(conn, 'rm@example.com', 'Flagged')
        flags = messages.get_flags(conn, 'rm@example.com')
        assert 'Seen' in flags
        assert 'Flagged' not in flags
        conn.close()

    def test_deletes_row_when_empty(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        messages.set_flag(conn, 'del@example.com', 'Seen')
        messages.remove_flag(conn, 'del@example.com', 'Seen')
        assert messages.get_flags(conn, 'del@example.com') == ''
        conn.close()

    def test_noop_on_unknown(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        messages.remove_flag(conn, 'nonexistent@example.com', 'Seen')
        conn.close()

    def test_noop_on_absent_flag(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        messages.set_flag(conn, 'noop@example.com', 'Seen')
        messages.remove_flag(conn, 'noop@example.com', 'Flagged')
        assert messages.get_flags(conn, 'noop@example.com') == 'Seen'
        conn.close()


class TestCleanupOld:
    """Tests for cleanup_old()."""

    def test_removes_old_entries(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        old_date = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=200)
        ).isoformat()
        messages.set_flag(conn, 'old@example.com', 'Seen', msg_date=old_date)
        messages.set_flag(
            conn,
            'recent@example.com',
            'Seen',
            msg_date=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        deleted = messages.cleanup_old(conn, max_days=180)
        assert deleted == 1
        assert messages.get_flags(conn, 'old@example.com') == ''
        assert messages.get_flags(conn, 'recent@example.com') == 'Seen'
        conn.close()

    def test_keeps_null_date(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = messages.get_db()
        messages.set_flag(conn, 'nodate@example.com', 'Seen')
        deleted = messages.cleanup_old(conn, max_days=0)
        assert deleted == 0
        assert messages.get_flags(conn, 'nodate@example.com') == 'Seen'
        conn.close()
