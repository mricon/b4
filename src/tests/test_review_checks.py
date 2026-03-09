import datetime
import json
import os
import sqlite3
from email.message import EmailMessage
from typing import Any, Dict, List
from unittest import mock

import pytest

from b4.review import checks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_msg(subject: str = 'test patch', msgid: str = 'abc@example.com',
              body: str = 'dummy') -> EmailMessage:
    """Create a minimal EmailMessage for testing."""
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['Message-Id'] = f'<{msgid}>'
    msg.set_content(body)
    return msg


# ---------------------------------------------------------------------------
# SQLite cache: store / retrieve / delete / cleanup
# ---------------------------------------------------------------------------

class TestCacheDb:
    """Tests for the CI check cache database."""

    def test_get_db_creates_schema(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = checks.get_db()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]
        assert 'check_results' in tables
        assert 'schema_version' in tables
        conn.close()

    def test_store_and_retrieve(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = checks.get_db()
        results = [
            {'tool': 'lint', 'status': 'pass', 'summary': 'ok',
             'url': '', 'details': ''},
            {'tool': 'build', 'status': 'fail', 'summary': 'broken',
             'url': 'https://ci.example.com', 'details': 'error on line 5'},
        ]
        checks.store_results(conn, 'msg1@example', results)
        cached = checks.get_cached_results(conn, ['msg1@example'])
        assert 'msg1@example' in cached
        assert len(cached['msg1@example']) == 2
        tools = {r['tool'] for r in cached['msg1@example']}
        assert tools == {'lint', 'build'}
        conn.close()

    def test_retrieve_empty(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = checks.get_db()
        cached = checks.get_cached_results(conn, ['nonexistent@example'])
        assert cached == {}
        conn.close()

    def test_retrieve_empty_list(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = checks.get_db()
        cached = checks.get_cached_results(conn, [])
        assert cached == {}
        conn.close()

    def test_store_replaces_existing(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = checks.get_db()
        checks.store_results(conn, 'msg@ex', [
            {'tool': 'lint', 'status': 'pass', 'summary': 'v1'}])
        checks.store_results(conn, 'msg@ex', [
            {'tool': 'lint', 'status': 'fail', 'summary': 'v2'}])
        cached = checks.get_cached_results(conn, ['msg@ex'])
        assert cached['msg@ex'][0]['status'] == 'fail'
        assert cached['msg@ex'][0]['summary'] == 'v2'
        conn.close()

    def test_delete_results(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = checks.get_db()
        checks.store_results(conn, 'a@ex', [
            {'tool': 't1', 'status': 'pass'}])
        checks.store_results(conn, 'b@ex', [
            {'tool': 't1', 'status': 'pass'}])
        checks.delete_results(conn, ['a@ex'])
        cached = checks.get_cached_results(conn, ['a@ex', 'b@ex'])
        assert 'a@ex' not in cached
        assert 'b@ex' in cached
        conn.close()

    def test_delete_empty_list(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = checks.get_db()
        checks.delete_results(conn, [])  # should not raise
        conn.close()

    def test_cleanup_old(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = checks.get_db()
        checks.store_results(conn, 'recent@ex', [
            {'tool': 't', 'status': 'pass'}])
        # Manually backdate one row
        old_date = (datetime.datetime.now(datetime.timezone.utc)
                    - datetime.timedelta(days=200)).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO check_results"
            " (msgid, tool, status, checked_at)"
            " VALUES (?, ?, ?, ?)",
            ('old@ex', 't', 'pass', old_date))
        conn.commit()
        deleted = checks.cleanup_old(conn, max_days=180)
        assert deleted == 1
        cached = checks.get_cached_results(conn, ['recent@ex', 'old@ex'])
        assert 'recent@ex' in cached
        assert 'old@ex' not in cached
        conn.close()


# ---------------------------------------------------------------------------
# parse_cmd
# ---------------------------------------------------------------------------

class TestParseCmd:
    """Tests for parse_cmd shell splitting."""

    def test_simple(self) -> None:
        assert checks.parse_cmd('/usr/bin/check') == ['/usr/bin/check']

    def test_with_args(self) -> None:
        assert checks.parse_cmd('check --verbose -q') == [
            'check', '--verbose', '-q']

    def test_quoted_arg(self) -> None:
        assert checks.parse_cmd('check "hello world"') == [
            'check', 'hello world']

    def test_single_quotes(self) -> None:
        assert checks.parse_cmd("check 'hello world'") == [
            'check', 'hello world']


# ---------------------------------------------------------------------------
# _run_builtin_checkpatch output parsing
# ---------------------------------------------------------------------------

class TestBuiltinCheckpatch:
    """Tests for _run_builtin_checkpatch output parsing."""

    def _run(self, stdout: str, stderr: str = '',
             ecode: int = 0, topdir: str = '/fake') -> List[Dict[str, str]]:
        msg = _make_msg()
        with mock.patch('os.access', return_value=True), \
             mock.patch('b4._run_command', return_value=(
                 ecode,
                 stdout.encode() if stdout else b'',
                 stderr.encode() if stderr else b'')), \
             mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''):
            return checks._run_builtin_checkpatch(msg, topdir)

    def test_clean_pass(self) -> None:
        results = self._run('', ecode=0)
        assert len(results) == 1
        assert results[0]['status'] == 'pass'
        assert results[0]['tool'] == 'checkpatch'

    def test_error_lines(self) -> None:
        results = self._run('ERROR: trailing whitespace\n')
        assert results[0]['status'] == 'fail'
        assert '1 error' in results[0]['summary']

    def test_warning_lines(self) -> None:
        results = self._run('WARNING: missing Signed-off-by\n')
        assert results[0]['status'] == 'warn'
        assert '1 warning' in results[0]['summary']

    def test_check_treated_as_warning(self) -> None:
        results = self._run('CHECK: braces not needed\n')
        assert results[0]['status'] == 'warn'

    def test_mixed_errors_and_warnings(self) -> None:
        output = 'ERROR: bad thing\nWARNING: mild thing\nWARNING: another\n'
        results = self._run(output)
        assert results[0]['status'] == 'fail'
        assert '1 error' in results[0]['summary']
        assert '2 warnings' in results[0]['summary']

    def test_continuation_lines(self) -> None:
        output = 'WARNING: first part\n  continuation of warning\n'
        results = self._run(output)
        findings = json.loads(results[0]['details'])
        assert len(findings) == 1
        assert 'continuation' in findings[0]['description']

    def test_nonzero_exit_no_output(self) -> None:
        results = self._run('', ecode=1)
        assert results[0]['status'] == 'fail'
        assert 'error code' in results[0]['summary']

    def test_not_executable(self) -> None:
        msg = _make_msg()
        with mock.patch('os.access', return_value=False):
            results = checks._run_builtin_checkpatch(msg, '/fake')
        assert results[0]['status'] == 'fail'
        assert 'not found' in results[0]['summary']

    def test_dash_prefix_stripped(self) -> None:
        results = self._run('-:42: WARNING: something bad\n')
        findings = json.loads(results[0]['details'])
        # The leading "-:" should be stripped
        assert not findings[0]['description'].startswith('-:')


# ---------------------------------------------------------------------------
# _run_external_cmd JSON protocol
# ---------------------------------------------------------------------------

class TestRunExternalCmd:
    """Tests for _run_external_cmd JSON parsing."""

    def _run(self, stdout: str, stderr: str = '',
             ecode: int = 0) -> List[Dict[str, str]]:
        msg = _make_msg()
        with mock.patch('b4._run_command', return_value=(
                ecode,
                stdout.encode() if stdout else b'',
                stderr.encode() if stderr else b'')), \
             mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''):
            return checks._run_external_cmd(['mycheck'], msg, '/fake')

    def test_valid_json_array(self) -> None:
        data = [{'tool': 'ci', 'status': 'pass', 'summary': 'ok'}]
        results = self._run(json.dumps(data))
        assert len(results) == 1
        assert results[0]['tool'] == 'ci'
        assert results[0]['status'] == 'pass'

    def test_single_object_wrapped(self) -> None:
        data = {'tool': 'ci', 'status': 'warn', 'summary': 'hmm'}
        results = self._run(json.dumps(data))
        assert len(results) == 1
        assert results[0]['status'] == 'warn'

    def test_invalid_json(self) -> None:
        results = self._run('not json at all')
        assert len(results) == 1
        assert results[0]['status'] == 'fail'
        assert 'invalid JSON' in results[0]['summary']

    def test_empty_output_zero_exit(self) -> None:
        results = self._run('')
        assert results == []

    def test_empty_output_nonzero_exit(self) -> None:
        results = self._run('', ecode=1)
        assert len(results) == 1
        assert results[0]['status'] == 'fail'
        assert 'error code' in results[0]['summary']

    def test_invalid_status_defaults_to_fail(self) -> None:
        data = [{'tool': 'ci', 'status': 'banana'}]
        results = self._run(json.dumps(data))
        assert results[0]['status'] == 'fail'

    def test_missing_tool_uses_basename(self) -> None:
        data = [{'status': 'pass'}]
        results = self._run(json.dumps(data))
        assert results[0]['tool'] == 'mycheck'

    def test_non_dict_entries_skipped(self) -> None:
        data = [{'tool': 'ci', 'status': 'pass'}, 'garbage', 42]
        results = self._run(json.dumps(data))
        assert len(results) == 1

    def test_optional_fields_default_empty(self) -> None:
        data = [{'tool': 'ci', 'status': 'pass'}]
        results = self._run(json.dumps(data))
        assert results[0]['summary'] == ''
        assert results[0]['url'] == ''
        assert results[0]['details'] == ''

    def test_stderr_in_error_details(self) -> None:
        results = self._run('', stderr='something broke', ecode=1)
        assert 'something broke' in results[0]['details']

    def test_extra_env_set_during_run(self) -> None:
        captured_env: Dict[str, str] = {}

        def fake_run(cmdargs: Any, stdin: Any = None,
                     rundir: Any = None) -> Any:
            captured_env['B4_TRACKING_FILE'] = os.environ.get('B4_TRACKING_FILE', '')
            return (0, b'[]', b'')

        msg = _make_msg()
        with mock.patch('b4._run_command', side_effect=fake_run), \
             mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''):
            checks._run_external_cmd(['mycheck'], msg, '/fake',
                                     extra_env={'B4_TRACKING_FILE': '/tmp/test.json'})
        assert captured_env['B4_TRACKING_FILE'] == '/tmp/test.json'
        # Env var should be cleaned up after the call
        assert 'B4_TRACKING_FILE' not in os.environ

    def test_extra_env_restored_on_error(self) -> None:
        msg = _make_msg()
        os.environ['B4_TRACKING_FILE'] = 'original'
        try:
            with mock.patch('b4._run_command', side_effect=RuntimeError('boom')), \
                 mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''):
                try:
                    checks._run_external_cmd(
                        ['mycheck'], msg, '/fake',
                        extra_env={'B4_TRACKING_FILE': '/tmp/new.json'})
                except RuntimeError:
                    pass
            assert os.environ.get('B4_TRACKING_FILE') == 'original'
        finally:
            os.environ.pop('B4_TRACKING_FILE', None)


# ---------------------------------------------------------------------------
# _run_builtin_patchwork aggregation
# ---------------------------------------------------------------------------

class TestBuiltinPatchwork:
    """Tests for _run_builtin_patchwork status aggregation."""

    def _run(self, pw_checks: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        msg = _make_msg(msgid='test@example.com')
        with mock.patch('b4.LoreMessage.get_patchwork_data_by_msgid',
                        return_value={'id': 42}), \
             mock.patch('b4.review.pw_fetch_checks',
                        return_value=pw_checks):
            return checks._run_builtin_patchwork(msg, 'proj', 'https://pw.example.com')

    def test_all_success(self) -> None:
        pw = [
            {'state': 'success', 'context': 'build', 'description': 'ok', 'url': ''},
            {'state': 'success', 'context': 'test', 'description': 'ok', 'url': ''},
        ]
        results = self._run(pw)
        assert len(results) == 1
        assert results[0]['tool'] == 'patchwork'
        assert results[0]['status'] == 'pass'

    def test_worst_case_fail(self) -> None:
        pw = [
            {'state': 'success', 'context': 'build', 'description': 'ok', 'url': ''},
            {'state': 'fail', 'context': 'test', 'description': 'bad', 'url': ''},
        ]
        results = self._run(pw)
        assert results[0]['status'] == 'fail'

    def test_pending_is_warn(self) -> None:
        pw = [
            {'state': 'pending', 'context': 'ci', 'description': 'running', 'url': ''},
        ]
        results = self._run(pw)
        assert results[0]['status'] == 'warn'

    def test_warning_is_warn(self) -> None:
        pw = [
            {'state': 'warning', 'context': 'ci', 'description': 'iffy', 'url': ''},
        ]
        results = self._run(pw)
        assert results[0]['status'] == 'warn'

    def test_details_are_json(self) -> None:
        pw = [
            {'state': 'success', 'context': 'build', 'description': 'ok', 'url': 'http://x'},
        ]
        results = self._run(pw)
        details = json.loads(results[0]['details'])
        assert isinstance(details, list)
        assert details[0]['context'] == 'build'

    def test_no_msgid_returns_empty(self) -> None:
        msg = EmailMessage()
        msg['Subject'] = 'test'
        result = checks._run_builtin_patchwork(msg, 'proj', 'https://pw.example.com')
        assert result == []

    def test_lookup_failure_returns_empty(self) -> None:
        msg = _make_msg()
        with mock.patch('b4.LoreMessage.get_patchwork_data_by_msgid',
                        side_effect=LookupError('not found')):
            result = checks._run_builtin_patchwork(msg, 'proj', 'https://pw.example.com')
        assert result == []


# ---------------------------------------------------------------------------
# High-level runners
# ---------------------------------------------------------------------------

class TestRunners:
    """Tests for run_perpatch_checks and run_series_checks."""

    def test_perpatch_dispatches_external(self) -> None:
        msg = _make_msg()
        data = json.dumps([{'tool': 'ci', 'status': 'pass', 'summary': 'ok'}])
        with mock.patch('b4._run_command', return_value=(
                0, data.encode(), b'')), \
             mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''):
            results = checks.run_perpatch_checks(
                [('m1@ex', msg)], ['mycheck'], '/fake')
        assert 'm1@ex' in results
        assert results['m1@ex'][0]['tool'] == 'ci'

    def test_perpatch_exception_captured(self) -> None:
        msg = _make_msg()
        with mock.patch('b4._run_command',
                        side_effect=RuntimeError('boom')), \
             mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''):
            results = checks.run_perpatch_checks(
                [('m1@ex', msg)], ['badcmd'], '/fake')
        assert results['m1@ex'][0]['status'] == 'fail'
        assert 'boom' in results['m1@ex'][0]['summary']

    def test_series_dispatches_external(self) -> None:
        msg = _make_msg()
        data = json.dumps([{'tool': 'series-ci', 'status': 'warn'}])
        with mock.patch('b4._run_command', return_value=(
                0, data.encode(), b'')), \
             mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''):
            results = checks.run_series_checks(
                ('cover@ex', msg), ['mycheck'], '/fake')
        assert len(results) == 1
        assert results[0]['tool'] == 'series-ci'

    def test_series_exception_captured(self) -> None:
        msg = _make_msg()
        with mock.patch('b4._run_command',
                        side_effect=RuntimeError('kaboom')), \
             mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''):
            results = checks.run_series_checks(
                ('cover@ex', msg), ['badcmd'], '/fake')
        assert results[0]['status'] == 'fail'
        assert 'kaboom' in results[0]['summary']

    def test_dispatch_builtin_checkpatch(self) -> None:
        msg = _make_msg()
        with mock.patch('os.access', return_value=True), \
             mock.patch('b4._run_command', return_value=(0, b'', b'')), \
             mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''):
            results = checks._dispatch_cmd('_builtin_checkpatch', msg, '/fake')
        assert results[0]['tool'] == 'checkpatch'

    def test_dispatch_builtin_patchwork_without_config(self) -> None:
        msg = _make_msg()
        results = checks._dispatch_cmd('_builtin_patchwork', msg, '/fake')
        assert results == []


# ---------------------------------------------------------------------------
# _STATUS_ORDER module-level constant
# ---------------------------------------------------------------------------

class TestStatusOrder:
    """Verify the module-level status ordering constant."""

    def test_ordering(self) -> None:
        assert checks._STATUS_ORDER['pass'] < checks._STATUS_ORDER['warn']
        assert checks._STATUS_ORDER['warn'] < checks._STATUS_ORDER['fail']
