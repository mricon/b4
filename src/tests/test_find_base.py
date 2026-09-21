"""Tests for locating the base commit a series applies to.

The repository these tests build looks like this, oldest first::

    c1  2026-01-01  adds a.txt, b.txt, c.txt
    c2  2026-01-05  changes a.txt
    c3  2026-01-10  changes b.txt
    c4  2026-01-15  deletes c.txt   <- master

So a series prepared on top of c2 does not apply cleanly to master, and
finding that out is what the code under test is for.
"""

import datetime
import os
import subprocess
from typing import Dict, List, Optional, Tuple

import pytest

import b4

SUBMITTED = datetime.datetime(2026, 1, 20, 12, 0, 0, tzinfo=datetime.timezone.utc)


def _git(repo: str, *args: str, when: Optional[str] = None) -> str:
    env = dict(os.environ)
    if when:
        env['GIT_AUTHOR_DATE'] = env['GIT_COMMITTER_DATE'] = when
    res = subprocess.run(
        ['git', '-C', repo, *args],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return res.stdout.strip()


def _commit(
    repo: str,
    when: str,
    message: str,
    write: Optional[Dict[str, str]] = None,
    remove: Optional[List[str]] = None,
) -> str:
    for fname, content in (write or {}).items():
        path = os.path.join(repo, fname)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fh:
            fh.write(content)
        _git(repo, 'add', fname)
    for fname in remove or []:
        _git(repo, 'rm', '-q', fname)
    _git(repo, 'commit', '-q', '-m', message, when=when)
    return _git(repo, 'rev-parse', 'HEAD')


@pytest.fixture
def repo(tmp_path: str) -> Dict[str, str]:
    """Build the history described in the module docstring.

    Returns a dict with the repo path under 'repo' and each commit hash under
    its name, so tests can talk about c2 instead of counting backwards.
    """
    path = os.path.join(str(tmp_path), 'findbase')
    os.makedirs(path)
    subprocess.run(
        ['git', 'init', '-q', '-b', 'master', path], check=True, capture_output=True
    )
    _git(path, 'config', 'user.name', 'Test Person')
    _git(path, 'config', 'user.email', 'test@example.com')
    marks = {'repo': path}
    marks['c1'] = _commit(
        path,
        '2026-01-01T12:00:00+0000',
        'one',
        write={'a.txt': 'a one\n', 'b.txt': 'b one\n', 'c.txt': 'c one\n'},
    )
    # git describe only looks at refs reachable from the commit, so without a
    # tag back here it cannot name anything but the branch tips.
    _git(path, 'tag', 'v0', marks['c1'])
    marks['c2'] = _commit(
        path, '2026-01-05T12:00:00+0000', 'two', write={'a.txt': 'a two\n'}
    )
    marks['c3'] = _commit(
        path, '2026-01-10T12:00:00+0000', 'three', write={'b.txt': 'b two\n'}
    )
    marks['c4'] = _commit(path, '2026-01-15T12:00:00+0000', 'four', remove=['c.txt'])
    return marks


def _blob(repo: str, at: str, fname: str, length: int = 12) -> str:
    """The abbreviated blob hash of *fname* at *at*, as a patch would carry it."""
    return _git(repo, 'rev-parse', f'{at}:{fname}')[:length]


def _series(indexes: List[Tuple[str, str]]) -> b4.LoreSeries:
    """A series carrying nothing but the blob indexes we want to look up."""
    lser = b4.LoreSeries(revision=1, expected=1)
    lser._indexes = indexes
    lser._submission_date = SUBMITTED
    return lser


class TestCheckAppliesClean:
    """Tests for LoreSeries.check_applies_clean()."""

    def test_no_indexes(self, repo: Dict[str, str]) -> None:
        checked, mismatches = _series([]).check_applies_clean(repo['repo'])
        assert (checked, mismatches) == (0, [])

    def test_everything_matches(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        lser = _series(
            [
                ('a.txt', _blob(path, 'HEAD', 'a.txt')),
                ('b.txt', _blob(path, 'HEAD', 'b.txt')),
            ]
        )
        assert lser.check_applies_clean(path) == (2, [])

    def test_defaults_to_head(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        lser = _series([('a.txt', _blob(path, 'HEAD', 'a.txt'))])
        assert lser.check_applies_clean(path) == lser.check_applies_clean(path, 'HEAD')

    def test_reports_only_the_files_that_differ(self, repo: Dict[str, str]) -> None:
        # Several files around the odd one out, so a bug that shifted the
        # answers by one would blame the wrong file.
        path = repo['repo']
        stale = _blob(path, repo['c1'], 'b.txt')
        lser = _series(
            [
                ('a.txt', _blob(path, 'HEAD', 'a.txt')),
                ('b.txt', stale),
                ('c.txt', _blob(path, repo['c1'], 'c.txt')),
            ]
        )
        checked, mismatches = lser.check_applies_clean(path, repo['c3'])
        assert checked == 3
        assert mismatches == [('b.txt', stale)]

    def test_deleted_file_is_a_mismatch(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        gone = _blob(path, repo['c1'], 'c.txt')
        checked, mismatches = _series([('c.txt', gone)]).check_applies_clean(path)
        assert (checked, mismatches) == (1, [('c.txt', gone)])

    def test_path_that_is_a_tree_is_a_mismatch(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        _commit(
            path, '2026-01-16T12:00:00+0000', 'five', write={'sub/d.txt': 'd one\n'}
        )
        tree = _git(path, 'rev-parse', 'HEAD:sub')[:12]
        # The hash is right, but it names a directory, not a file.
        checked, mismatches = _series([('sub', tree)]).check_applies_clean(path)
        assert (checked, mismatches) == (1, [('sub', tree)])

    def test_unknown_revision_mismatches_everything(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        indexes = [
            ('a.txt', _blob(path, 'HEAD', 'a.txt')),
            ('b.txt', _blob(path, 'HEAD', 'b.txt')),
        ]
        checked, mismatches = _series(indexes).check_applies_clean(path, 'nosuchref')
        assert checked == 2
        assert mismatches == indexes

    def test_matches_an_older_commit(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        lser = _series(
            [
                ('a.txt', _blob(path, repo['c2'], 'a.txt')),
                ('b.txt', _blob(path, repo['c2'], 'b.txt')),
                ('c.txt', _blob(path, repo['c2'], 'c.txt')),
            ]
        )
        assert lser.check_applies_clean(path, repo['c2']) == (3, [])
        assert len(lser.check_applies_clean(path, 'HEAD')[1]) == 2
