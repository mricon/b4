import datetime
import importlib.util
import json
import os
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Tuple, cast
from unittest import mock

import pytest
import requests

import liblore
from b4.review import checks

# TestCheckWorkerCancellation imports CheckRunnerMixin from the textual-backed
# review_tui._common; skip it when textual is absent (no-tui install) rather
# than error at call time.
requires_textual = pytest.mark.skipif(
    importlib.util.find_spec('textual') is None,
    reason='requires the [tui] extra (textual)',
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_msg(
    subject: str = 'test patch', msgid: str = 'abc@example.com', body: str = 'dummy'
) -> EmailMessage:
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
            {
                'tool': 'lint',
                'status': 'pass',
                'summary': 'ok',
                'url': '',
                'details': '',
            },
            {
                'tool': 'build',
                'status': 'fail',
                'summary': 'broken',
                'url': 'https://ci.example.com',
                'details': 'error on line 5',
            },
        ]
        checks.store_results(conn, 'msg1@example', results)
        cached = checks.get_cached_results(conn, ['msg1@example'])
        assert 'msg1@example' in cached
        assert len(cached['msg1@example']) == 2
        tools = {r['tool'] for r in cached['msg1@example']}
        assert tools == {'lint', 'build'}
        conn.close()

    @pytest.mark.parametrize(
        'msgids',
        [
            pytest.param(['nonexistent@example'], id='unknown-msgid'),
            pytest.param([], id='empty-list'),
        ],
    )
    def test_retrieve_empty(
        self, tmp_path: pytest.TempPathFactory, msgids: List[str]
    ) -> None:
        conn = checks.get_db()
        cached = checks.get_cached_results(conn, msgids)
        assert cached == {}
        conn.close()

    def test_store_replaces_existing(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = checks.get_db()
        checks.store_results(
            conn, 'msg@ex', [{'tool': 'lint', 'status': 'pass', 'summary': 'v1'}]
        )
        checks.store_results(
            conn, 'msg@ex', [{'tool': 'lint', 'status': 'fail', 'summary': 'v2'}]
        )
        cached = checks.get_cached_results(conn, ['msg@ex'])
        assert cached['msg@ex'][0]['status'] == 'fail'
        assert cached['msg@ex'][0]['summary'] == 'v2'
        conn.close()

    def test_delete_results(self, tmp_path: pytest.TempPathFactory) -> None:
        conn = checks.get_db()
        checks.store_results(conn, 'a@ex', [{'tool': 't1', 'status': 'pass'}])
        checks.store_results(conn, 'b@ex', [{'tool': 't1', 'status': 'pass'}])
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
        checks.store_results(conn, 'recent@ex', [{'tool': 't', 'status': 'pass'}])
        # Manually backdate one row
        old_date = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=200)
        ).isoformat()
        conn.execute(
            'INSERT OR REPLACE INTO check_results'
            ' (msgid, tool, status, checked_at)'
            ' VALUES (?, ?, ?, ?)',
            ('old@ex', 't', 'pass', old_date),
        )
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

    @pytest.mark.parametrize(
        'cmd,expected',
        [
            pytest.param('/usr/bin/check', ['/usr/bin/check'], id='simple'),
            pytest.param(
                'check --verbose -q', ['check', '--verbose', '-q'], id='with-args'
            ),
            pytest.param(
                'check "hello world"', ['check', 'hello world'], id='quoted-arg'
            ),
            pytest.param(
                "check 'hello world'", ['check', 'hello world'], id='single-quotes'
            ),
        ],
    )
    def test_parse_cmd(self, cmd: str, expected: List[str]) -> None:
        assert checks.parse_cmd(cmd) == expected


# ---------------------------------------------------------------------------
# _run_builtin_checkpatch output parsing
# ---------------------------------------------------------------------------


class TestBuiltinCheckpatch:
    """Tests for _run_builtin_checkpatch output parsing."""

    def _run(
        self,
        stdout: str,
        stderr: str = '',
        ecode: int = 0,
        topdir: str = '/fake',
        bdata: bytes = b'',
    ) -> List[Dict[str, str]]:
        msg = _make_msg()
        with (
            mock.patch('os.access', return_value=True),
            mock.patch(
                'b4._run_command',
                return_value=(
                    ecode,
                    stdout.encode() if stdout else b'',
                    stderr.encode() if stderr else b'',
                ),
            ),
            mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=bdata),
        ):
            return checks._run_builtin_checkpatch(msg, topdir)

    @pytest.mark.parametrize(
        'stdout,ecode,status,summary_substr',
        [
            pytest.param('', 0, 'pass', None, id='clean-pass'),
            pytest.param(
                'ERROR: trailing whitespace\n', 0, 'fail', '1 error', id='error-lines'
            ),
            pytest.param(
                'WARNING: missing Signed-off-by\n',
                0,
                'warn',
                '1 warning',
                id='warning-lines',
            ),
            pytest.param(
                'CHECK: braces not needed\n', 0, 'warn', None, id='check-is-a-warning'
            ),
            pytest.param('', 1, 'fail', 'error code', id='nonzero-exit-no-output'),
        ],
    )
    def test_status_and_summary(
        self,
        stdout: str,
        ecode: int,
        status: str,
        summary_substr: Optional[str],
    ) -> None:
        results = self._run(stdout, ecode=ecode)
        assert len(results) == 1
        assert results[0]['tool'] == 'checkpatch'
        assert results[0]['status'] == status
        if summary_substr is not None:
            assert summary_substr in results[0]['summary']

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

    # A small patch email whose line numbers checkpatch would reference:
    #   1 From, 2 Subject, 3 blank, 4 long commit-log line, 5 blank,
    #   6 Signed-off-by, 7 "---", ... diff begins below.
    _SAMPLE_PATCH = (
        'From: Dev <dev@example.com>\n'
        'Subject: [PATCH] foo: do a thing\n'
        '\n'
        'This commit log line is intentionally quite long and well over limits.\n'
        '\n'
        'Signed-off-by: Dev <dev@example.com>\n'
        '---\n'
        ' foo/bar.c | 2 +-\n'
        ' 1 file changed, 1 insertion(+), 1 deletion(-)\n'
        '\n'
        'diff --git a/foo/bar.c b/foo/bar.c\n'
        'index 1111111..2222222 100644\n'
        '--- a/foo/bar.c\n'
        '+++ b/foo/bar.c\n'
        '@@ -1,3 +1,3 @@\n'
        '-old line\n'
        '+new line with trailing whitespace   \n'
    )

    def test_commit_log_finding_gets_srcline(self) -> None:
        out = '-:4: WARNING: Possible unwrapped commit description\n'
        results = self._run(out, bdata=self._SAMPLE_PATCH.encode())
        findings = json.loads(results[0]['details'])
        assert findings[0]['srcline'] == (
            'This commit log line is intentionally quite long and well over limits.'
        )

    @pytest.mark.parametrize(
        'out',
        [
            # A complaint pointing into the diff is left alone -- the reviewer
            # can already see that line in the patch view.
            pytest.param('-:17: ERROR: trailing whitespace\n', id='diff-finding'),
            # A finding with no "-:N:" prefix can't be located, so no srcline.
            pytest.param('WARNING: missing Signed-off-by\n', id='no-line-number'),
        ],
    )
    def test_no_srcline(self, out: str) -> None:
        results = self._run(out, bdata=self._SAMPLE_PATCH.encode())
        findings = json.loads(results[0]['details'])
        assert 'srcline' not in findings[0]


class TestFindCommitLogEnd:
    """Tests for the commit-log boundary helper."""

    @pytest.mark.parametrize(
        'lines',
        [
            pytest.param(
                ['From: x', '', 'body', '---', 'diff --git a b'], id='scissors-wins'
            ),
            pytest.param(
                ['From: x', '', 'body', 'diff --git a b'], id='diff-without-scissors'
            ),
            pytest.param(['just', 'commit', 'message'], id='no-diff-at-all'),
        ],
    )
    def test_commit_log_end(self, lines: List[str]) -> None:
        assert checks._find_commit_log_end(lines) == 4


# ---------------------------------------------------------------------------
# _run_external_cmd JSON protocol
# ---------------------------------------------------------------------------


class TestRunExternalCmd:
    """Tests for _run_external_cmd JSON parsing."""

    def _run(
        self, stdout: str, stderr: str = '', ecode: int = 0
    ) -> List[Dict[str, str]]:
        msg = _make_msg()
        with (
            mock.patch(
                'b4._run_command',
                return_value=(
                    ecode,
                    stdout.encode() if stdout else b'',
                    stderr.encode() if stderr else b'',
                ),
            ),
            mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''),
        ):
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
        results = self._run('', stderr='something broke', ecode=1)
        assert len(results) == 1
        assert results[0]['status'] == 'fail'
        assert 'error code' in results[0]['summary']
        assert 'something broke' in results[0]['details']

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

    def test_extra_env_set_during_run(self) -> None:
        captured_env: Dict[str, str] = {}

        def fake_run(cmdargs: Any, stdin: Any = None, rundir: Any = None) -> Any:
            captured_env['B4_TRACKING_FILE'] = os.environ.get('B4_TRACKING_FILE', '')
            return (0, b'[]', b'')

        msg = _make_msg()
        with (
            mock.patch('b4._run_command', side_effect=fake_run),
            mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''),
        ):
            checks._run_external_cmd(
                ['mycheck'],
                msg,
                '/fake',
                extra_env={'B4_TRACKING_FILE': '/tmp/test.json'},
            )
        assert captured_env['B4_TRACKING_FILE'] == '/tmp/test.json'
        # Env var should be cleaned up after the call
        assert 'B4_TRACKING_FILE' not in os.environ

    def test_extra_env_restored_on_error(self) -> None:
        msg = _make_msg()
        os.environ['B4_TRACKING_FILE'] = 'original'
        try:
            with (
                mock.patch('b4._run_command', side_effect=RuntimeError('boom')),
                mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''),
            ):
                try:
                    checks._run_external_cmd(
                        ['mycheck'],
                        msg,
                        '/fake',
                        extra_env={'B4_TRACKING_FILE': '/tmp/new.json'},
                    )
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
        with (
            mock.patch(
                'b4.LoreMessage.get_patchwork_data_by_msgid', return_value={'id': 42}
            ),
            mock.patch('b4.review.pw_fetch_checks', return_value=pw_checks),
        ):
            return checks._run_builtin_patchwork(msg, 'proj', 'https://pw.example.com')

    @pytest.mark.parametrize(
        'pw_states,expected_status',
        [
            pytest.param(['success', 'success'], 'pass', id='all-success'),
            pytest.param(['success', 'fail'], 'fail', id='worst-case-fail'),
            pytest.param(['pending'], 'warn', id='pending-is-warn'),
            pytest.param(['warning'], 'warn', id='warning-is-warn'),
        ],
    )
    def test_status_aggregation(
        self, pw_states: List[str], expected_status: str
    ) -> None:
        pw = [
            {'state': state, 'context': f'ctx{i}', 'description': 'd', 'url': ''}
            for i, state in enumerate(pw_states)
        ]
        results = self._run(pw)
        assert len(results) == 1
        assert results[0]['tool'] == 'patchwork'
        assert results[0]['status'] == expected_status

    def test_details_are_json(self) -> None:
        pw = [
            {
                'state': 'success',
                'context': 'build',
                'description': 'ok',
                'url': 'http://x',
            },
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
        with mock.patch(
            'b4.LoreMessage.get_patchwork_data_by_msgid',
            side_effect=LookupError('not found'),
        ):
            result = checks._run_builtin_patchwork(
                msg, 'proj', 'https://pw.example.com'
            )
        assert result == []


# ---------------------------------------------------------------------------
# High-level runners
# ---------------------------------------------------------------------------


class TestRunners:
    """Tests for run_perpatch_checks and run_series_checks."""

    def test_perpatch_dispatches_external(self) -> None:
        msg = _make_msg()
        data = json.dumps([{'tool': 'ci', 'status': 'pass', 'summary': 'ok'}])
        with (
            mock.patch('b4._run_command', return_value=(0, data.encode(), b'')),
            mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''),
        ):
            results = checks.run_perpatch_checks([('m1@ex', msg)], ['mycheck'], '/fake')
        assert 'm1@ex' in results
        assert results['m1@ex'][0]['tool'] == 'ci'

    def test_perpatch_exception_captured(self) -> None:
        msg = _make_msg()
        with (
            mock.patch('b4._run_command', side_effect=RuntimeError('boom')),
            mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''),
        ):
            results = checks.run_perpatch_checks([('m1@ex', msg)], ['badcmd'], '/fake')
        assert results['m1@ex'][0]['status'] == 'fail'
        assert 'boom' in results['m1@ex'][0]['summary']

    def test_series_dispatches_external(self) -> None:
        msg = _make_msg()
        data = json.dumps([{'tool': 'series-ci', 'status': 'warn'}])
        with (
            mock.patch('b4._run_command', return_value=(0, data.encode(), b'')),
            mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''),
        ):
            results = checks.run_series_checks(('cover@ex', msg), ['mycheck'], '/fake')
        assert len(results) == 1
        assert results[0]['tool'] == 'series-ci'

    def test_series_exception_captured(self) -> None:
        msg = _make_msg()
        with (
            mock.patch('b4._run_command', side_effect=RuntimeError('kaboom')),
            mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''),
        ):
            results = checks.run_series_checks(('cover@ex', msg), ['badcmd'], '/fake')
        assert results[0]['status'] == 'fail'
        assert 'kaboom' in results[0]['summary']

    def test_dispatch_builtin_checkpatch(self) -> None:
        msg = _make_msg()
        with (
            mock.patch('os.access', return_value=True),
            mock.patch('b4._run_command', return_value=(0, b'', b'')),
            mock.patch('b4.LoreMessage.get_msg_as_bytes', return_value=b''),
        ):
            results = checks._dispatch_cmd('_builtin_checkpatch', msg, '/fake')
        assert results[0]['tool'] == 'checkpatch'

    def test_dispatch_builtin_patchwork_without_config(self) -> None:
        msg = _make_msg()
        results = checks._dispatch_cmd('_builtin_patchwork', msg, '/fake')
        assert results == []


# ---------------------------------------------------------------------------
# Sashiko AI review integration
# ---------------------------------------------------------------------------

# Sample patchset response matching the real sashiko API format.
_SASHIKO_PATCHSET: Dict[str, Any] = {
    'id': 93,
    'message_id': 'cover@example.com',
    'subject': '[PATCH 0/3] Example series',
    'status': 'Reviewed',
    'author': 'Test Author <test@example.com>',
    'patches': [
        {
            'id': 1,
            'message_id': 'patch1@example.com',
            'part_index': 1,
            'subject': '[PATCH 1/3] First patch',
            'status': 'applied',
        },
        {
            'id': 2,
            'message_id': 'patch2@example.com',
            'part_index': 2,
            'subject': '[PATCH 2/3] Second patch',
            'status': 'applied',
        },
        {
            'id': 3,
            'message_id': 'patch3@example.com',
            'part_index': 3,
            'subject': '[PATCH 3/3] Third patch',
            'status': 'applied',
        },
    ],
    'reviews': [
        {
            'id': 100,
            'patch_id': 1,
            'status': 'Reviewed',
            'result': 'Review completed successfully.',
            'summary': '',
            'inline_review': 'looks good',
            'output': json.dumps(
                {
                    'findings': [
                        {'severity': 'Low', 'problem': 'Minor style issue'},
                    ],
                }
            ),
        },
        {
            'id': 101,
            'patch_id': 2,
            'status': 'Reviewed',
            'result': 'Review completed successfully.',
            'summary': '',
            'inline_review': 'has issues',
            'output': json.dumps(
                {
                    'findings': [
                        {
                            'severity': 'Critical',
                            'problem': 'Use-after-free',
                            'severity_explanation': 'Add proper locking',
                        },
                        {'severity': 'High', 'problem': 'Missing error check'},
                    ],
                }
            ),
        },
        {
            'id': 102,
            'patch_id': 3,
            'status': 'Skipped',
            'result': 'Skipped: touches only ignored files',
            'summary': '',
            'inline_review': '',
            'output': '',
        },
    ],
}


class TestSashikoCache:
    """Tests for sashiko in-process patchset cache."""

    def setup_method(self) -> None:
        checks.clear_sashiko_cache()

    def teardown_method(self) -> None:
        checks.clear_sashiko_cache()

    def test_clear_cache(self) -> None:
        checks._sashiko_patchset_cache['test@ex'] = {'id': 1}
        checks.clear_sashiko_cache()
        assert checks._sashiko_patchset_cache == {}

    def test_fetch_caches_all_msgids(self) -> None:
        resp = mock.Mock()
        resp.status_code = 200
        resp.json.return_value = _SASHIKO_PATCHSET

        session = mock.Mock()
        session.get.return_value = resp

        with mock.patch('b4.get_requests_session', return_value=session):
            data = checks._fetch_sashiko_patchset(
                'cover@example.com', 'https://sashiko.dev'
            )

        assert data is not None
        assert data['id'] == 93
        # All msgids should be cached
        assert 'cover@example.com' in checks._sashiko_patchset_cache
        assert 'patch1@example.com' in checks._sashiko_patchset_cache
        assert 'patch2@example.com' in checks._sashiko_patchset_cache
        assert 'patch3@example.com' in checks._sashiko_patchset_cache
        # Second call should use cache, not network
        session.get.reset_mock()
        data2 = checks._fetch_sashiko_patchset(
            'patch2@example.com', 'https://sashiko.dev'
        )
        session.get.assert_not_called()
        assert data2 is not None
        assert data2['id'] == 93

    @pytest.mark.parametrize(
        'get_config',
        [
            pytest.param({'return_value': mock.Mock(status_code=404)}, id='404'),
            pytest.param(
                {'side_effect': requests.ConnectionError('offline')},
                id='network-error',
            ),
        ],
    )
    def test_fetch_failure_caches_none(self, get_config: Dict[str, Any]) -> None:
        session = mock.Mock()
        session.get.configure_mock(**get_config)

        with mock.patch('b4.get_requests_session', return_value=session):
            data = checks._fetch_sashiko_patchset(
                'unknown@example.com', 'https://sashiko.dev'
            )

        assert data is None
        assert checks._sashiko_patchset_cache['unknown@example.com'] is None


class TestParseSashikoFindings:
    """Tests for _parse_sashiko_findings."""

    @pytest.mark.parametrize(
        'review',
        [
            pytest.param({'output': ''}, id='empty-output'),
            pytest.param({'output': None}, id='null-output'),
            pytest.param({}, id='no-output-key'),
            pytest.param({'output': 'not json'}, id='invalid-json'),
            pytest.param({'output': json.dumps({'fixes': []})}, id='no-findings-key'),
        ],
    )
    def test_unusable_output_yields_no_findings(self, review: Dict[str, Any]) -> None:
        assert checks._parse_sashiko_findings(review) == []

    @pytest.mark.parametrize(
        'severity,problem,status,state',
        [
            pytest.param('Critical', 'UAF bug', 'fail', 'critical', id='critical'),
            pytest.param('High', 'Missing check', 'fail', 'high', id='high'),
            pytest.param('Medium', 'Questionable logic', 'warn', 'medium', id='medium'),
            pytest.param('Low', 'Style issue', 'pass', 'low', id='low'),
        ],
    )
    def test_severity_mapping(
        self, severity: str, problem: str, status: str, state: str
    ) -> None:
        review = {
            'output': json.dumps(
                {'findings': [{'severity': severity, 'problem': problem}]}
            )
        }
        findings = checks._parse_sashiko_findings(review)
        assert len(findings) == 1
        assert findings[0]['status'] == status
        assert findings[0]['state'] == state
        assert findings[0]['context'] == f'sashiko/{state}'
        assert problem in findings[0]['description']

    def test_severity_explanation_appended(self) -> None:
        review = {
            'output': json.dumps(
                {
                    'findings': [
                        {
                            'severity': 'High',
                            'problem': 'Bug',
                            'severity_explanation': 'This is dangerous',
                        }
                    ],
                }
            )
        }
        findings = checks._parse_sashiko_findings(review)
        assert 'Bug' in findings[0]['description']
        assert 'This is dangerous' in findings[0]['description']

    def test_legacy_suggestion_ignored(self) -> None:
        """Old 'suggestion' field no longer appears; should not be treated as
        severity_explanation."""
        review = {
            'output': json.dumps(
                {
                    'findings': [
                        {'severity': 'High', 'problem': 'Bug', 'suggestion': 'Fix it'}
                    ],
                }
            )
        }
        findings = checks._parse_sashiko_findings(review)
        assert 'Bug' in findings[0]['description']
        assert 'Fix it' not in findings[0]['description']

    def test_legacy_message_field(self) -> None:
        """Old sashiko data used 'message' instead of 'problem'."""
        review = {
            'output': json.dumps(
                {
                    'findings': [{'severity': 'High', 'message': 'Old style bug'}],
                }
            )
        }
        findings = checks._parse_sashiko_findings(review)
        assert len(findings) == 1
        assert 'Old style bug' in findings[0]['description']

    def test_preexisting_finding_is_pass(self) -> None:
        review = {
            'output': json.dumps(
                {
                    'findings': [
                        {
                            'severity': 'Critical',
                            'problem': 'Pre-existing UAF',
                            'preexisting': True,
                        }
                    ],
                }
            )
        }
        findings = checks._parse_sashiko_findings(review)
        assert len(findings) == 1
        assert findings[0]['status'] == 'pass'
        assert findings[0]['preexisting'] is True
        assert '(pre-existing)' in findings[0]['description']

    def test_multiple_findings(self) -> None:
        review = {
            'output': json.dumps(
                {
                    'findings': [
                        {'severity': 'Critical', 'problem': 'bad'},
                        {'severity': 'Low', 'problem': 'minor'},
                    ],
                }
            )
        }
        findings = checks._parse_sashiko_findings(review)
        assert len(findings) == 2


class TestSashikoFindingsSummary:
    """Tests for _sashiko_findings_summary."""

    def test_no_findings(self) -> None:
        worst, summary = checks._sashiko_findings_summary([])
        assert worst == 'pass'
        assert summary == 'No findings'

    def test_single_critical(self) -> None:
        findings = [
            {
                'status': 'fail',
                'state': 'critical',
                'description': 'bad',
                'preexisting': False,
            }
        ]
        worst, summary = checks._sashiko_findings_summary(findings)
        assert worst == 'fail'
        assert '1 critical' in summary

    def test_mixed_severities(self) -> None:
        findings = [
            {
                'status': 'fail',
                'state': 'critical',
                'description': '',
                'preexisting': False,
            },
            {
                'status': 'fail',
                'state': 'high',
                'description': '',
                'preexisting': False,
            },
            {
                'status': 'warn',
                'state': 'medium',
                'description': '',
                'preexisting': False,
            },
            {'status': 'pass', 'state': 'low', 'description': '', 'preexisting': False},
        ]
        worst, summary = checks._sashiko_findings_summary(findings)
        assert worst == 'fail'
        assert '1 critical' in summary
        assert '1 high' in summary
        assert '1 medium' in summary
        assert '1 low' in summary

    def test_only_low_is_pass(self) -> None:
        findings = [
            {'status': 'pass', 'state': 'low', 'description': '', 'preexisting': False},
            {'status': 'pass', 'state': 'low', 'description': '', 'preexisting': False},
        ]
        worst, summary = checks._sashiko_findings_summary(findings)
        assert worst == 'pass'
        assert '2 low' in summary

    def test_all_preexisting_is_no_new_findings(self) -> None:
        """A series where every finding is pre-existing should report pass."""
        findings = [
            {
                'status': 'pass',
                'state': 'critical',
                'description': '(pre-existing) bad',
                'preexisting': True,
            },
            {
                'status': 'pass',
                'state': 'high',
                'description': '(pre-existing) also bad',
                'preexisting': True,
            },
        ]
        worst, summary = checks._sashiko_findings_summary(findings)
        assert worst == 'pass'
        assert summary == 'No new findings'

    def test_preexisting_not_counted_in_summary(self) -> None:
        """Pre-existing findings should not appear in the count string."""
        findings = [
            {
                'status': 'fail',
                'state': 'critical',
                'description': 'fresh',
                'preexisting': False,
            },
            {
                'status': 'pass',
                'state': 'critical',
                'description': '(pre-existing) old',
                'preexisting': True,
            },
        ]
        worst, summary = checks._sashiko_findings_summary(findings)
        assert worst == 'fail'
        assert '1 critical' in summary  # only the fresh one
        assert '2 critical' not in summary


class TestRunBuiltinSashiko:
    """Tests for _run_builtin_sashiko end-to-end."""

    def setup_method(self) -> None:
        checks.clear_sashiko_cache()

    def teardown_method(self) -> None:
        checks.clear_sashiko_cache()

    def _prefill_cache(self, patchset: Optional[Dict[str, Any]] = None) -> None:
        """Pre-fill the cache so no HTTP calls are made."""
        ps = patchset if patchset is not None else _SASHIKO_PATCHSET
        for key in [
            'cover@example.com',
            'patch1@example.com',
            'patch2@example.com',
            'patch3@example.com',
        ]:
            checks._sashiko_patchset_cache[key] = ps

    def test_no_msgid_returns_empty(self) -> None:
        msg = EmailMessage()
        msg['Subject'] = 'test'
        assert checks._run_builtin_sashiko(msg, 'https://sashiko.dev') == []

    def test_not_found_returns_empty(self) -> None:
        checks._sashiko_patchset_cache['unknown@ex'] = None
        msg = _make_msg(msgid='unknown@ex')
        assert checks._run_builtin_sashiko(msg, 'https://sashiko.dev') == []

    def test_cover_letter_aggregates_all_findings(self) -> None:
        self._prefill_cache()
        msg = _make_msg(msgid='cover@example.com')
        results = checks._run_builtin_sashiko(msg, 'https://sashiko.dev')
        assert len(results) == 1
        assert results[0]['tool'] == 'sashiko'
        assert results[0]['status'] == 'fail'  # critical finding in patch 2
        assert '1 critical' in results[0]['summary']
        assert '1 high' in results[0]['summary']
        assert '1 low' in results[0]['summary']
        assert results[0]['url'] == 'https://sashiko.dev/#/patchset/93'
        # Details should be valid JSON
        details = json.loads(results[0]['details'])
        assert len(details) == 3  # 1 low + 1 critical + 1 high

    @pytest.mark.parametrize(
        'msgid,status,summary_substrs',
        [
            pytest.param(
                'patch2@example.com',
                'fail',
                ('1 critical', '1 high'),
                id='patch-with-critical-finding',
            ),
            pytest.param(
                'patch1@example.com', 'pass', ('1 low',), id='patch-with-low-finding'
            ),
            pytest.param(
                'patch3@example.com', 'pass', ('Skipped',), id='skipped-patch'
            ),
        ],
    )
    def test_patch_findings(
        self, msgid: str, status: str, summary_substrs: Tuple[str, ...]
    ) -> None:
        self._prefill_cache()
        msg = _make_msg(msgid=msgid)
        results = checks._run_builtin_sashiko(msg, 'https://sashiko.dev')
        assert results[0]['status'] == status
        for substr in summary_substrs:
            assert substr in results[0]['summary']

    @pytest.mark.parametrize(
        'ps_status,msgid,status,summary,exact',
        [
            pytest.param(
                'Pending', 'patch1@example.com', 'warn', 'pending', False, id='pending'
            ),
            pytest.param(
                'In Review',
                'cover@example.com',
                'warn',
                'in review',
                False,
                id='in-review',
            ),
            pytest.param(
                'Failed', 'cover@example.com', 'fail', 'Failed', True, id='failed'
            ),
            pytest.param(
                'Failed To Apply',
                'cover@example.com',
                'fail',
                None,
                False,
                id='failed-to-apply',
            ),
            pytest.param(
                'Incomplete',
                'cover@example.com',
                'warn',
                'incomplete',
                False,
                id='incomplete',
            ),
        ],
    )
    def test_patchset_status(
        self,
        ps_status: str,
        msgid: str,
        status: str,
        summary: Optional[str],
        exact: bool,
    ) -> None:
        ps = dict(_SASHIKO_PATCHSET, status=ps_status)
        self._prefill_cache(ps)
        msg = _make_msg(msgid=msgid)
        results = checks._run_builtin_sashiko(msg, 'https://sashiko.dev')
        assert results[0]['status'] == status
        if summary is None:
            return
        if exact:
            assert results[0]['summary'] == summary
        else:
            assert summary in results[0]['summary'].lower()

    @pytest.mark.parametrize(
        'reviews,status,summary,exact',
        [
            pytest.param(
                [
                    {
                        'id': 100,
                        'patch_id': 1,
                        'status': 'Reviewed',
                        'result': 'Review completed successfully.',
                        'output': json.dumps({'findings': []}),
                    }
                ],
                'pass',
                'No findings',
                True,
                id='no-findings-pass',
            ),
            pytest.param(
                [{'id': 100, 'patch_id': 1, 'status': 'Pending', 'output': ''}],
                'warn',
                'in progress',
                False,
                id='pending-review',
            ),
            pytest.param(
                [
                    {
                        'id': 100,
                        'patch_id': 1,
                        'status': 'Failed',
                        'result': 'Token limit exceeded',
                        'output': '',
                    }
                ],
                'fail',
                'Token limit',
                False,
                id='failed-review',
            ),
            # Patchset is reviewed but this specific patch has no review entry
            pytest.param([], 'pass', 'No review', True, id='patch-without-review'),
        ],
    )
    def test_review_for_patch(
        self,
        reviews: List[Dict[str, Any]],
        status: str,
        summary: str,
        exact: bool,
    ) -> None:
        ps = dict(_SASHIKO_PATCHSET, reviews=reviews)
        self._prefill_cache(ps)
        msg = _make_msg(msgid='patch1@example.com')
        results = checks._run_builtin_sashiko(msg, 'https://sashiko.dev')
        assert results[0]['status'] == status
        if exact:
            assert results[0]['summary'] == summary
        else:
            assert summary.lower() in results[0]['summary'].lower()

    def test_url_constructed_correctly(self) -> None:
        self._prefill_cache()
        msg = _make_msg(msgid='patch1@example.com')
        results = checks._run_builtin_sashiko(msg, 'https://sashiko.dev/')
        # Trailing slash should not cause double slash
        assert results[0]['url'] == 'https://sashiko.dev/#/patchset/93?part=1'

    def test_all_preexisting_findings_is_pass(self) -> None:
        """A series whose only findings are pre-existing should report pass."""
        reviews = [
            {
                'id': 100,
                'patch_id': 1,
                'status': 'Reviewed',
                'result': 'Reviewed',
                'summary': '',
                'inline_review': '',
                'output': json.dumps(
                    {
                        'findings': [
                            {
                                'severity': 'Critical',
                                'problem': 'Pre-existing UAF',
                                'preexisting': True,
                            },
                            {
                                'severity': 'High',
                                'problem': 'Pre-existing race',
                                'preexisting': True,
                            },
                        ],
                    }
                ),
            },
        ]
        ps = dict(_SASHIKO_PATCHSET, reviews=reviews)
        self._prefill_cache(ps)
        msg = _make_msg(msgid='patch1@example.com')
        results = checks._run_builtin_sashiko(msg, 'https://sashiko.dev')
        assert results[0]['status'] == 'pass'
        assert results[0]['summary'] == 'No new findings'

    def test_mixed_preexisting_only_fresh_escalates(self) -> None:
        """Only non-preexisting findings should escalate the check status."""
        reviews = [
            {
                'id': 100,
                'patch_id': 1,
                'status': 'Reviewed',
                'result': 'Reviewed',
                'summary': '',
                'inline_review': '',
                'output': json.dumps(
                    {
                        'findings': [
                            {
                                'severity': 'Critical',
                                'problem': 'Pre-existing UAF',
                                'preexisting': True,
                            },
                            {
                                'severity': 'Medium',
                                'problem': 'New style issue',
                                'preexisting': False,
                            },
                        ],
                    }
                ),
            },
        ]
        ps = dict(_SASHIKO_PATCHSET, reviews=reviews)
        self._prefill_cache(ps)
        msg = _make_msg(msgid='patch1@example.com')
        results = checks._run_builtin_sashiko(msg, 'https://sashiko.dev')
        assert results[0]['status'] == 'warn'  # only medium fresh finding
        assert '1 medium' in results[0]['summary']
        assert 'critical' not in results[0]['summary']
        # Both findings are still in details
        details = json.loads(results[0]['details'])
        assert len(details) == 2

    def test_severity_explanation_in_description(self) -> None:
        """severity_explanation should appear in finding descriptions."""
        reviews = [
            {
                'id': 100,
                'patch_id': 1,
                'status': 'Reviewed',
                'result': 'Reviewed',
                'summary': '',
                'inline_review': '',
                'output': json.dumps(
                    {
                        'findings': [
                            {
                                'severity': 'High',
                                'problem': 'Missing null check',
                                'severity_explanation': 'Dereferencing NULL causes a kernel oops.',
                            },
                        ],
                    }
                ),
            },
        ]
        ps = dict(_SASHIKO_PATCHSET, reviews=reviews)
        self._prefill_cache(ps)
        msg = _make_msg(msgid='patch1@example.com')
        results = checks._run_builtin_sashiko(msg, 'https://sashiko.dev')
        details = json.loads(results[0]['details'])
        assert 'Missing null check' in details[0]['description']
        assert 'kernel oops' in details[0]['description']


class TestSashikoAutoWire:
    """Tests for auto-wiring _builtin_sashiko in load_check_cmds."""

    @pytest.mark.parametrize(
        'config,present',
        [
            pytest.param(
                {'sashiko-url': 'https://sashiko.dev'}, True, id='added-when-url-set'
            ),
            pytest.param({}, False, id='not-added-without-url'),
        ],
    )
    def test_sashiko_wired_only_with_url(
        self, config: Dict[str, Any], present: bool
    ) -> None:
        with (
            mock.patch('b4.get_main_config', return_value=config),
            mock.patch('b4.git_get_toplevel', return_value=None),
        ):
            perpatch, series = checks.load_check_cmds()
        assert ('_builtin_sashiko' in perpatch) is present
        assert ('_builtin_sashiko' in series) is present

    def test_sashiko_not_duplicated(self) -> None:
        config = {
            'sashiko-url': 'https://sashiko.dev',
            'review-perpatch-check-cmd': ['_builtin_sashiko'],
            'review-series-check-cmd': ['_builtin_sashiko'],
        }
        with (
            mock.patch('b4.get_main_config', return_value=config),
            mock.patch('b4.git_get_toplevel', return_value=None),
        ):
            perpatch, series = checks.load_check_cmds()
        assert perpatch.count('_builtin_sashiko') == 1
        assert series.count('_builtin_sashiko') == 1


class TestSashikoDispatch:
    """Tests for _dispatch_cmd routing to _builtin_sashiko."""

    def setup_method(self) -> None:
        checks.clear_sashiko_cache()

    def teardown_method(self) -> None:
        checks.clear_sashiko_cache()

    def test_dispatch_routes_to_sashiko(self) -> None:
        msg = _make_msg(msgid='test@ex')
        # Pre-cache so no HTTP call is made
        checks._sashiko_patchset_cache['test@ex'] = dict(
            _SASHIKO_PATCHSET, message_id='test@ex'
        )
        config = {'sashiko-url': 'https://sashiko.dev'}
        with mock.patch('b4.get_main_config', return_value=config):
            results = checks._dispatch_cmd('_builtin_sashiko', msg, '/fake')
        assert results[0]['tool'] == 'sashiko'

    def test_dispatch_without_config(self) -> None:
        msg = _make_msg()
        config: Dict[str, Any] = {}
        with mock.patch('b4.get_main_config', return_value=config):
            results = checks._dispatch_cmd('_builtin_sashiko', msg, '/fake')
        assert results == []


# ---------------------------------------------------------------------------
# Cooperative cancellation of the check worker (_fetch_and_check)
# ---------------------------------------------------------------------------


class _FakeWorker:
    """Minimal stand-in for textual.worker.Worker.

    Only exposes the ``is_cancelled`` attribute that ``_fetch_and_check``
    polls.  ``cancel()`` flips it, mimicking both an Esc/q press on the
    loading overlay and Textual's ``workers.cancel_all()`` on app exit.
    """

    def __init__(self) -> None:
        self.is_cancelled = False

    def cancel(self) -> None:
        self.is_cancelled = True


class _FakeCheckHost:
    """Bare host satisfying what ``_fetch_and_check`` touches on ``self``."""

    def __init__(self) -> None:
        self._check_loading = None
        self.loading_updates: List[str] = []
        self.dismissed: List[Tuple[str, str]] = []
        self.pushed_modal = False
        # call_from_thread runs its callback inline so the final modal-push
        # path is exercised when the run is *not* cancelled.
        self.app = mock.Mock()
        self.app.call_from_thread.side_effect = lambda cb, *a, **k: cb(*a, **k)

    def _update_loading(self, text: str) -> None:
        self.loading_updates.append(text)

    def _dismiss_loading(self, msg: str = '', severity: str = '') -> None:
        self.dismissed.append((msg, severity))

    def push_screen(self, screen: object, callback: object = None) -> None:
        self.pushed_modal = True


def _patch_msg(idx: int, total: int) -> EmailMessage:
    """Build a patch EmailMessage with a ``[PATCH idx/total]`` subject."""
    msg = EmailMessage()
    msg['Subject'] = f'[PATCH {idx}/{total}] change number {idx}'
    msg['Message-Id'] = f'<patch{idx}@example.com>'
    msg.set_content('dummy body')
    return msg


@requires_textual
class TestCheckWorkerCancellation:
    """The per-patch check loop must bail out when the worker is cancelled."""

    def _run(
        self, worker: _FakeWorker, cancel_after: Optional[int]
    ) -> Tuple[_FakeCheckHost, mock.Mock, mock.Mock]:
        from b4.review_tui._common import CheckRunnerMixin

        host = _FakeCheckHost()
        msgs = [_patch_msg(i, 3) for i in (1, 2, 3)]

        call_count = {'n': 0}

        def _fake_perpatch(
            patches: List[Tuple[str, EmailMessage]], *a: Any, **k: Any
        ) -> Dict[str, List[Dict[str, str]]]:
            call_count['n'] += 1
            mid = patches[0][0]
            # Simulate the user cancelling mid-run (or the app exiting) once
            # the requested number of patches have been processed.
            if cancel_after is not None and call_count['n'] >= cancel_after:
                worker.cancel()
            return {mid: [{'tool': 'ci', 'status': 'pass', 'summary': 'ok'}]}

        perpatch = mock.Mock(side_effect=_fake_perpatch)
        store = mock.Mock()

        with (
            mock.patch(
                'b4.review_tui._common.worker_cancelled',
                side_effect=lambda: worker.is_cancelled,
            ),
            mock.patch('b4.review_tui._common.get_thread_msgs', return_value=msgs),
            mock.patch('b4.git_get_toplevel', return_value='/fake'),
            mock.patch('b4.get_main_config', return_value={}),
            mock.patch('b4.review.checks.clear_sashiko_cache'),
            mock.patch(
                'b4.review.checks.load_check_cmds', return_value=(['mycheck'], [])
            ),
            mock.patch('b4.review.checks.get_db', return_value=mock.Mock()),
            mock.patch('b4.review.checks.cleanup_old', return_value=0),
            mock.patch('b4.review.checks.get_cached_results', return_value={}),
            mock.patch('b4.review.checks.run_perpatch_checks', perpatch),
            mock.patch('b4.review.checks.store_results', store),
        ):
            # host is a structural stand-in implementing only the slice of
            # the protocol the worker touches; cast the unbound call past the
            # type checkers, which reject the partial self.
            cast(Any, CheckRunnerMixin)._fetch_and_check(
                host, 'patch1@example.com', 'a series', change_id='', force=False
            )
        return host, perpatch, store

    def test_cancel_stops_remaining_perpatch_checks(self) -> None:
        worker = _FakeWorker()
        host, perpatch, store = self._run(worker, cancel_after=1)
        # Only the first patch ran; the loop broke before patches 2 and 3.
        assert perpatch.call_count == 1
        # Partial results were still cached, so a re-run resumes where this
        # one left off.
        assert store.call_count == 1
        # The results modal must NOT be shown for a cancelled run.
        assert host.pushed_modal is False

    def test_no_cancel_runs_all_and_pushes_modal(self) -> None:
        worker = _FakeWorker()
        host, perpatch, store = self._run(worker, cancel_after=None)
        # All three patches checked, all cached, and the modal is shown.
        assert perpatch.call_count == 3
        assert store.call_count == 3
        assert host.pushed_modal is True


@requires_textual
class TestCheckLoadingScreenCancel:
    """The loading overlay's Esc/q action cancels the worker, not just hides."""

    def test_action_cancel_cancels_worker_and_dismisses(self) -> None:
        from b4.review_tui._modals import CheckLoadingScreen

        screen = CheckLoadingScreen()
        worker = _FakeWorker()
        screen.worker = worker  # type: ignore[assignment]  # ty: ignore[invalid-assignment]
        with mock.patch.object(screen, 'dismiss') as dismiss:
            screen.action_cancel()
        assert worker.is_cancelled is True
        dismiss.assert_called_once_with(None)

    def test_action_cancel_without_worker_just_dismisses(self) -> None:
        from b4.review_tui._modals import CheckLoadingScreen

        screen = CheckLoadingScreen()
        with mock.patch.object(screen, 'dismiss') as dismiss:
            screen.action_cancel()
        dismiss.assert_called_once_with(None)


@requires_textual
class TestWorkerCancelledHelper:
    """The shared worker_cancelled() cooperative-cancellation predicate."""

    def test_returns_false_outside_worker(self) -> None:
        # No active worker (the normal case when called from the test
        # thread or the synchronous CLI) -> False, never raises.
        from b4.tui._common import worker_cancelled

        assert worker_cancelled() is False

    def test_reflects_active_worker_flag(self) -> None:
        from b4.tui import _common

        worker = _FakeWorker()
        with mock.patch.object(_common, 'get_current_worker', return_value=worker):
            assert _common.worker_cancelled() is False
            worker.cancel()
            assert _common.worker_cancelled() is True


@requires_textual
class TestLoreNodeShutdownMixin:
    """The mixin shuts the shared lore node down from its on_unmount hook."""

    def test_on_unmount_shuts_down_lore_node(self) -> None:
        from b4.review_tui._common import LoreNodeShutdownMixin

        class _App(LoreNodeShutdownMixin):
            pass

        node = mock.Mock()
        with mock.patch('b4.get_lore_node', return_value=node):
            _App().on_unmount()
        node.shutdown.assert_called_once_with()

    def test_on_unmount_swallows_errors(self) -> None:
        # Shutdown must never raise out of on_unmount, even if the lore
        # node is unavailable or shutdown() blows up.
        from b4.review_tui._common import LoreNodeShutdownMixin

        class _App(LoreNodeShutdownMixin):
            pass

        with mock.patch('b4.get_lore_node', side_effect=RuntimeError('boom')):
            _App().on_unmount()  # must not raise


@requires_textual
class TestCheckRunnerWorkerContract:
    """Running checks launches the fetch through run_lore_worker().

    Regression coverage for the TUI crash when a check-time fetch failed:
    without exit_on_error=False on the worker, an uncaught fetch error tore
    down the whole app via WorkerFailed.
    """

    def test_run_checks_launches_crash_safe_worker(self) -> None:
        from b4.review_tui._common import CheckRunnerMixin

        host = mock.Mock()
        host._get_check_context.return_value = ('cover@example.com', 'a series', '')

        cast(Any, CheckRunnerMixin)._run_checks(host, force=False)

        host.run_worker.assert_called_once()
        kwargs = host.run_worker.call_args.kwargs
        # In a thread, so the blocking fetch stays off the UI thread; and
        # the worker must not crash the app on a fetch failure.
        assert kwargs.get('thread') is True
        assert kwargs.get('exit_on_error') is False

    def test_fetch_cancellation_dismisses_overlay_quietly(self) -> None:
        from b4.review_tui._common import CheckRunnerMixin

        host = _FakeCheckHost()

        with (
            mock.patch(
                'b4.review_tui._common.get_thread_msgs',
                side_effect=liblore.OperationCancelledError('Request cancelled'),
            ),
            mock.patch('b4.git_get_toplevel', return_value='/fake'),
            mock.patch('b4.get_main_config', return_value={}),
            mock.patch('b4.review.checks.clear_sashiko_cache'),
            mock.patch(
                'b4.review.checks.load_check_cmds', return_value=(['mycheck'], [])
            ),
        ):
            # Must unwind cleanly instead of letting the error escape the worker.
            cast(Any, CheckRunnerMixin)._fetch_and_check(
                host, 'cover@example.com', 'a series', change_id='', force=False
            )

        # Dismissed quietly (no error toast) and no results modal shown.
        assert host.dismissed == [('', '')]
        assert host.pushed_modal is False


@requires_textual
class TestFetchAndCheckTrackingBranch:
    """The optional tracking-data dump must not log-and-exit (which leaks a
    line onto the TUI as a flicker) when the review branch isn't checked out.

    Regression coverage for the screen flicker on 'c' in the tracking app:
    running checks on a tracked series with no local b4/review/<change_id>
    branch (one that isn't under review) called load_tracking(), whose
    `git log` failed and fired a critical log + sys.exit onto the terminal.
    """

    def _run(self, branch_exists: bool) -> Tuple[_FakeCheckHost, mock.Mock]:
        from b4.review_tui._common import CheckRunnerMixin

        host = _FakeCheckHost()
        load_tracking = mock.Mock(
            return_value=('cover', {'series': {'thread-blob': 'deadbeef'}})
        )

        with (
            # Short-circuit right after the tracking block so the test stays
            # focused on the guard: an empty fetch dismisses and returns.
            mock.patch('b4.review_tui._common.get_thread_msgs', return_value=[]),
            mock.patch('b4.git_get_toplevel', return_value='/fake'),
            mock.patch('b4.git_branch_exists', return_value=branch_exists),
            mock.patch('b4.get_main_config', return_value={}),
            mock.patch('b4.review.load_tracking', load_tracking),
            mock.patch('b4.review.checks.clear_sashiko_cache'),
            mock.patch(
                'b4.review.checks.load_check_cmds', return_value=(['mycheck'], [])
            ),
        ):
            cast(Any, CheckRunnerMixin)._fetch_and_check(
                host,
                'cover@example.com',
                'a series',
                change_id='20260609-some-series-deadbeef',
                force=False,
            )
        return host, load_tracking

    def test_missing_review_branch_skips_load_tracking(self) -> None:
        host, load_tracking = self._run(branch_exists=False)
        # The branch isn't present, so load_tracking() (which would log+exit)
        # is never called -- nothing leaks onto the screen.
        load_tracking.assert_not_called()
        # The run still proceeds to the fetch (and dismisses on the empty mock).
        assert host.dismissed == [('Could not fetch thread from lore', 'error')]

    def test_existing_review_branch_loads_tracking(self) -> None:
        host, load_tracking = self._run(branch_exists=True)
        # When the branch exists, the tracking data is read as before.
        load_tracking.assert_called_once()
        assert host.dismissed == [('Could not fetch thread from lore', 'error')]
