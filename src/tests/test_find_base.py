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


def _series(
    indexes: List[Tuple[str, str]], submitted: datetime.datetime = SUBMITTED
) -> b4.LoreSeries:
    """A series carrying nothing but the blob indexes we want to look up."""
    lser = b4.LoreSeries(revision=1, expected=1)
    lser._indexes = indexes
    lser._submission_date = submitted
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

    def test_answers_stay_with_their_commit(self, repo: Dict[str, str]) -> None:
        # find_base() asks about many commits in one go; a revision git cannot
        # resolve in the middle must not shift the answers for the ones after.
        path = repo['repo']
        indexes = [
            ('a.txt', _blob(path, repo['c2'], 'a.txt')),
            ('b.txt', _blob(path, repo['c2'], 'b.txt')),
            ('c.txt', _blob(path, repo['c2'], 'c.txt')),
        ]
        a, b, c = indexes
        got = _series(indexes)._mismatches_at(
            path, [repo['c1'], repo['c2'], 'nosuchref', repo['c4']]
        )
        assert got == [[a], [], [a, b, c], [b, c]]

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


class TestGitMapBlobsToCommits:
    """Tests for the single-walk blob lookup behind find_base()."""

    since = '2025-12-25'
    until = '2026-01-20'

    def _map(self, repo: str, blobs: List[str]) -> Dict[str, List[str]]:
        return b4.git_map_blobs_to_commits(
            repo, set(blobs), self.since, self.until, ['--all']
        )

    def test_finds_the_commit_that_added_the_blob(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        blob = _blob(path, 'HEAD', 'a.txt')
        assert self._map(path, [blob]) == {blob: [repo['c2']]}

    def test_finds_both_ends_of_the_blob_lifetime(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        # b.txt as it was at c1: added by c1, replaced by c3.
        blob = _blob(path, repo['c1'], 'b.txt')
        assert self._map(path, [blob]) == {blob: [repo['c3'], repo['c1']]}

    def test_same_answer_as_find_object(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        blobs = [
            _blob(path, repo['c1'], 'a.txt'),
            _blob(path, repo['c1'], 'b.txt'),
            _blob(path, repo['c1'], 'c.txt'),
            _blob(path, 'HEAD', 'a.txt'),
        ]
        got = self._map(path, blobs)
        for blob in blobs:
            want = [
                line.split()[0]
                for line in b4.git_get_command_lines(
                    path,
                    [
                        'log',
                        '--pretty=oneline',
                        '--since',
                        self.since,
                        '--until',
                        self.until,
                        '--find-object',
                        blob,
                        '--all',
                    ],
                )
            ]
            assert got.get(blob, []) == want

    def test_a_commit_touching_the_blob_twice_is_listed_once(
        self, repo: Dict[str, str]
    ) -> None:
        path = repo['repo']
        # One commit that writes the same content to two different files.
        dup = _commit(
            path,
            '2026-01-16T12:00:00+0000',
            'five',
            write={'d.txt': 'same\n', 'e.txt': 'same\n'},
        )
        blob = _blob(path, 'HEAD', 'd.txt')
        assert self._map(path, [blob]) == {blob: [dup]}

    def test_respects_the_date_window(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        blob = _blob(path, repo['c1'], 'a.txt')
        # c1 and c2 are the only commits touching it, and both are older.
        assert (
            b4.git_map_blobs_to_commits(
                path, {blob}, '2026-01-08', self.until, ['--all']
            )
            == {}
        )

    def test_paths_still_see_commits_a_merge_discarded(
        self, repo: Dict[str, str]
    ) -> None:
        # A side branch changes a.txt, and the merge keeps master's version.
        # Plain path-limited history hides the side commit behind the merge,
        # but the series may well have been made on top of it.
        path = repo['repo']
        _git(path, 'checkout', '-q', '-b', 'side', repo['c4'])
        side = _commit(
            path, '2026-01-16T12:00:00+0000', 'side', write={'a.txt': 'a side\n'}
        )
        _git(path, 'checkout', '-q', 'master')
        _git(path, 'merge', '-q', '-s', 'ours', '-m', 'merge', 'side')
        _git(path, 'branch', '-q', '-D', 'side')
        blob = _blob(path, side, 'a.txt')
        assert b4.git_map_blobs_to_commits(
            path, {blob}, self.since, self.until, ['--all'], paths=['a.txt']
        ) == {blob: [side]}

    def test_paths_leave_out_other_files(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        blob = _blob(path, 'HEAD', 'b.txt')
        assert (
            b4.git_map_blobs_to_commits(
                path, {blob}, self.since, self.until, ['--all'], paths=['a.txt']
            )
            == {}
        )

    def test_paths_are_taken_literally(self, repo: Dict[str, str]) -> None:
        # A path from a diff is a name, not a pattern: 'a[1].txt' must not
        # also pull in changes to 'a1.txt'.
        path = repo['repo']
        _commit(
            path,
            '2026-01-16T12:00:00+0000',
            'glob',
            write={'a[1].txt': 'bracket\n', 'a1.txt': 'plain\n'},
        )
        blob = _blob(path, 'HEAD', 'a1.txt')
        assert (
            b4.git_map_blobs_to_commits(
                path, {blob}, self.since, self.until, ['--all'], paths=['a[1].txt']
            )
            == {}
        )

    def test_unknown_blob_is_absent(self, repo: Dict[str, str]) -> None:
        assert self._map(repo['repo'], ['0' * 12]) == {}

    def test_mixed_abbreviation_lengths(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        short = _blob(path, 'HEAD', 'a.txt', length=7)
        full = _blob(path, 'HEAD', 'b.txt', length=40)
        assert self._map(path, [short, full]) == {
            short: [repo['c2']],
            full: [repo['c3']],
        }


class TestFindBase:
    """Tests for LoreSeries.find_base()."""

    @pytest.mark.parametrize(
        'indexes',
        [
            pytest.param([], id='no-indexes'),
            pytest.param(
                [('nosuch.txt', '0' * 12), ('alsonot.txt', '1' * 12)],
                id='nothing-matches',
            ),
        ],
    )
    def test_raises_when_no_base_found(
        self, repo: Dict[str, str], indexes: List[Tuple[str, str]]
    ) -> None:
        with pytest.raises(IndexError):
            _series(indexes).find_base(repo['repo'])

    def test_head_when_everything_already_matches(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        lser = _series(
            [
                ('a.txt', _blob(path, 'HEAD', 'a.txt')),
                ('b.txt', _blob(path, 'HEAD', 'b.txt')),
            ]
        )
        describe, checked, fewest = lser.find_base(path)
        assert (checked, fewest) == (2, 0)
        assert _git(path, 'rev-parse', f'{describe}^{{}}') == repo['c4']

    def test_walks_back_to_the_commit_the_series_was_made_on(
        self, repo: Dict[str, str]
    ) -> None:
        path = repo['repo']
        lser = _series(
            [
                ('a.txt', _blob(path, repo['c2'], 'a.txt')),
                ('b.txt', _blob(path, repo['c2'], 'b.txt')),
                ('c.txt', _blob(path, repo['c2'], 'c.txt')),
            ]
        )
        describe, checked, fewest = lser.find_base(path)
        assert (checked, fewest) == (3, 0)
        assert _git(path, 'rev-parse', f'{describe}^{{}}') == repo['c2']

    def test_settles_for_the_best_partial_match(self, repo: Dict[str, str]) -> None:
        path = repo['repo']
        # a.txt and b.txt as of c2, plus a file that never existed: the best we
        # can do is c2, with the invented file still outstanding.
        lser = _series(
            [
                ('a.txt', _blob(path, repo['c2'], 'a.txt')),
                ('b.txt', _blob(path, repo['c2'], 'b.txt')),
                ('nosuch.txt', '0' * 12),
            ]
        )
        describe, checked, fewest = lser.find_base(path)
        assert (checked, fewest) == (3, 1)
        assert _git(path, 'rev-parse', f'{describe}^{{}}') == repo['c2']

    def test_counts_commits_from_the_same_day_as_the_submission(
        self, repo: Dict[str, str]
    ) -> None:
        # Sent a minute after its base was committed, late in the day, with
        # a.txt changing again the next day. Cutting off at the date alone
        # let git fill in the current time of day, which hid the base
        # whenever b4 ran earlier in the day than the patch was sent.
        path = repo['repo']
        base = _commit(
            path, '2026-01-20T23:58:00+0000', 'five', write={'a.txt': 'a three\n'}
        )
        _commit(path, '2026-01-21T12:00:00+0000', 'six', write={'a.txt': 'a four\n'})
        lser = _series(
            [
                ('a.txt', _blob(path, base, 'a.txt')),
                ('b.txt', _blob(path, base, 'b.txt')),
            ],
            submitted=datetime.datetime(
                2026, 1, 20, 23, 59, 0, tzinfo=datetime.timezone.utc
            ),
        )
        describe, checked, fewest = lser.find_base(path)
        assert (checked, fewest) == (2, 0)
        assert _git(path, 'rev-parse', f'{describe}^{{}}') == base

    def test_ignores_refs_that_hold_no_source(self, repo: Dict[str, str]) -> None:
        # git-bug keeps its database in commits under refs/bugs and
        # refs/identities, dated when the bug was touched, and a fetch copies
        # them under refs/remotes/. None of those must stand in for the
        # newest commit before the submission.
        path = repo['repo']
        empty = _git(path, 'mktree')
        env = dict(os.environ)
        env['GIT_AUTHOR_DATE'] = env['GIT_COMMITTER_DATE'] = '2026-01-19T12:00:00+0000'
        bug = subprocess.run(
            ['git', '-C', path, 'commit-tree', '-m', 'bug', empty],
            input='',
            capture_output=True,
            text=True,
            env=env,
            check=True,
        ).stdout.strip()
        for ref in (
            'refs/bugs/1234',
            'refs/identities/5678',
            'refs/remotes/origin/bugs/1234',
            'refs/remotes/origin/identities/5678',
        ):
            _git(path, 'update-ref', ref, bug)
        lser = _series(
            [
                ('a.txt', _blob(path, 'HEAD', 'a.txt')),
                ('b.txt', _blob(path, 'HEAD', 'b.txt')),
            ]
        )
        describe, checked, fewest = lser.find_base(path)
        assert (checked, fewest) == (2, 0)
        # c3 has the same blobs, but only c4 is the newest commit we have.
        assert _git(path, 'rev-parse', f'{describe}^{{}}') == repo['c4']


class TestBaseCommitRe:
    """Tests for the pattern that reads base-commit: out of a cover letter."""

    @pytest.mark.parametrize(
        'body,want',
        [
            pytest.param('base-commit: 1234abcd5678\n', '1234abcd5678', id='short'),
            pytest.param(f'base-commit: {"a" * 40}\n', 'a' * 40, id='sha1'),
            pytest.param(f'base-commit: {"b" * 64}\n', 'b' * 64, id='sha256'),
            pytest.param('Base-Commit: 1234abcd\n', '1234abcd', id='any-case'),
            pytest.param('text\nbase-commit: 1234abcd\n', '1234abcd', id='later'),
            pytest.param('base-commit: next-20260101\n', None, id='ref-name'),
            pytest.param('base-commit: 1234ab\n', None, id='too-short'),
            pytest.param('base-commit: 1234abcdxyz\n', None, id='not-all-hex'),
            pytest.param('> base-commit: 1234abcd\n', None, id='quoted'),
        ],
    )
    def test_parse(self, body: str, want: Optional[str]) -> None:
        matches = b4.BASE_COMMIT_RE.search(body)
        assert (matches.group(1) if matches else None) == want
