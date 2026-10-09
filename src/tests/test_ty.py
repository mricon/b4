import os
import pathlib
from email.message import EmailMessage
from typing import Any, List, Optional, Tuple
from unittest import mock

import pytest

import b4
import b4.ty

from .helpers.tracking import seed_series


def _review_sections() -> List[Tuple[str, List[str]]]:
    return [
        (
            '[PATCH 0/2] Add frobnicator support',
            [
                'From: Foo Bar <foo@example.com>',
                'Sent: Mon, 1 Jan 2026 00:00:00 +0000',
                'Link: https://lore.kernel.org/r/cover-1@example.com',
                '---',
                '[1/2] commit-id: 1a2b3c4d5e6f',
                '[2/2] commit-id: 2b3c4d5e6f70',
                '---',
                'Applied: Wed, 3 Jan 2026 12:00:00 -0500',
            ],
        ),
        (
            '[GIT PULL] frobnicator updates',
            [
                'From: Bar Foo <bar@example.com>',
                'Sent: Tue, 2 Jan 2026 00:00:00 +0000',
                'Link: https://lore.kernel.org/r/pull-2@example.com',
                '---',
                'merge-commit: 9f8e7d6c5b4a',
                '---',
                'Applied: Thu, 4 Jan 2026 09:30:00 -0500',
            ],
        ),
    ]


def test_render_ty_review_layout() -> None:
    """Each item is offered with a leading '+' on its subject line, with its
    From/Date/Link shown as '#' detail comments; a pristine buffer skips none.
    """
    sections = _review_sections()
    buf = b4.ty.render_ty_review(sections)
    text = buf.decode('utf-8')
    assert '+ [PATCH 0/2] Add frobnicator support' in text
    assert '+ [GIT PULL] frobnicator updates' in text
    # Details are '#' comments, not markable item lines.
    assert '    # From: Foo Bar <foo@example.com>' in text
    assert '    # Sent: Mon, 1 Jan 2026 00:00:00 +0000' in text
    assert '    # Link: https://lore.kernel.org/r/cover-1@example.com' in text
    # The resolved commit-ids sit between '---' separators, Applied at the end.
    assert '    # ---' in text
    assert '    # [1/2] commit-id: 1a2b3c4d5e6f' in text
    assert '    # merge-commit: 9f8e7d6c5b4a' in text
    assert '    # Applied: Wed, 3 Jan 2026 12:00:00 -0500' in text
    # A freshly rendered buffer skips nothing.
    assert b4.ty.parse_ty_review(buf, sections) == set()


def test_parse_ty_review_marks_skips() -> None:
    """Flipping '+' to 'x' on an item marks it (by position) skipped."""
    sections = _review_sections()
    text = b4.ty.render_ty_review(sections).decode('utf-8')
    text = text.replace('+ [GIT PULL]', 'x [GIT PULL]')
    skipped = b4.ty.parse_ty_review(text.encode('utf-8'), sections)
    assert skipped == {1}


@pytest.mark.parametrize(
    'old,new',
    [
        # Editing an item subject breaks the positional contract and aborts.
        pytest.param(
            'Add frobnicator support',
            'Add frobnicator SUPPORT',
            id='edited-subject',
        ),
        # Removing an item line entirely also aborts (ambiguous edit).
        pytest.param(
            '+ [GIT PULL] frobnicator updates\n',
            '',
            id='count-mismatch',
        ),
    ],
)
def test_parse_ty_review_rejects_edits(old: str, new: str) -> None:
    sections = _review_sections()
    text = b4.ty.render_ty_review(sections).decode('utf-8')
    assert old in text
    text = text.replace(old, new)
    with pytest.raises(ValueError):
        b4.ty.parse_ty_review(text.encode('utf-8'), sections)


def test_parse_ty_review_rejects_reorder() -> None:
    """Reordering the items aborts: subjects no longer match by position."""
    sections = _review_sections()
    reordered: List[Tuple[str, List[str]]] = [
        sections[1],
        sections[0],
    ]
    buf = b4.ty.render_ty_review(reordered)
    with pytest.raises(ValueError):
        b4.ty.parse_ty_review(buf, sections)


_APPLIED: List[b4.ty.JsonDictT] = [
    {
        'subject': '[PATCH 0/2] Add frobnicator support',
        'fromname': 'Foo Bar',
        'fromemail': 'foo@example.com',
        'sentdate': 'Mon, 1 Jan 2026 00:00:00 +0000',
        'msgid': 'cover-1@example.com',
        'trackfile': 'aaa.am',
    },
    {
        'subject': '[GIT PULL] frobnicator updates',
        'fromname': 'Bar Foo',
        'fromemail': 'bar@example.com',
        'sentdate': 'Tue, 2 Jan 2026 00:00:00 +0000',
        'msgid': 'pull-2@example.com',
        'trackfile': 'bbb.pr',
    },
]


@pytest.mark.parametrize(
    'skip_pull',
    [
        # Marking an item 'x' drops it from the returned list; the kept item
        # survives, in order. Skipped items are simply omitted (no
        # persistence).
        pytest.param(True, id='drops-skipped'),
        # An unedited buffer keeps the full list unchanged, in order.
        pytest.param(False, id='keeps-all-when-pristine'),
    ],
)
def test_interactive_ty_review(
    monkeypatch: pytest.MonkeyPatch, skip_pull: bool
) -> None:
    def fake_edit(
        bdata: bytes, filehint: str = 'COMMIT_EDITMSG', **kwargs: Any
    ) -> bytes:
        if not skip_pull:
            return bdata
        # Maintainer skips the pull request, keeps the patch series.
        text = bdata.decode('utf-8').replace('+ [GIT PULL]', 'x [GIT PULL]')
        return text.encode('utf-8')

    monkeypatch.setattr(b4, 'edit_in_editor', fake_edit)

    kept = b4.ty.interactive_ty_review(_APPLIED, None)
    if skip_pull:
        assert [jd['subject'] for jd in kept] == ['[PATCH 0/2] Add frobnicator support']
    else:
        assert kept == _APPLIED


def test_interactive_ty_review_edits_in_the_named_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """'b4 ty -g' names the tree the thank-yous belong to, so the editor runs
    there: a repository-local core.editor is the one that applies, and the
    scratch file lands inside that tree rather than wherever the process was
    started from."""
    applied: List[b4.ty.JsonDictT] = [
        {
            'subject': '[PATCH] Add frobnicator support',
            'fromname': 'Foo Bar',
            'fromemail': 'foo@example.com',
            'sentdate': 'Mon, 1 Jan 2026 00:00:00 +0000',
            'msgid': 'patch-1@example.com',
            'trackfile': 'aaa.am',
        },
    ]
    seen: List[Optional[str]] = []

    def fake_edit(
        bdata: bytes,
        filehint: str = 'COMMIT_EDITMSG',
        *,
        topdir: Optional[str] = None,
        guard_branch: bool = False,
    ) -> bytes:
        seen.append(topdir)
        return bdata

    monkeypatch.setattr(b4, 'edit_in_editor', fake_edit)

    b4.ty.interactive_ty_review(applied, '/some/other/tree')
    assert seen == ['/some/other/tree']


def test_get_applied_info_picks_latest_and_lists_commits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """For a series: one '[N/total] commit-id' line per matched patch (gaps for
    unmatched ones), and the latest committer date as the applied date.
    """
    by_commit = {
        'aaaaaaaaaaaa': '1750000000\x00Sun, 15 Jun 2026 00:00:00 -0500\x00aaaaaaaaaaaa',
        'cccccccccccc': '1750200000\x00Tue, 17 Jun 2026 12:00:00 -0400\x00cccccccccccc',
    }

    def fake_lines(gitdir: Optional[str], args: List[str]) -> List[str]:
        assert args[:3] == ['show', '-s', '--format=%ct%x00%cD%x00%h']
        return [by_commit[args[3]]]

    monkeypatch.setattr(b4, 'git_get_command_lines', fake_lines)

    # Patch 2/3 did not match (None) -- it should be skipped, leaving a gap.
    jsondata: b4.ty.JsonDictT = {
        'commits': [[1, 'aaaaaaaaaaaa'], [2, None], [3, 'cccccccccccc']],
    }
    applied_date, commit_lines = b4.ty.get_applied_info(None, jsondata)
    assert commit_lines == [
        '[1/3] commit-id: aaaaaaaaaaaa',
        '[3/3] commit-id: cccccccccccc',
    ]
    assert applied_date == 'Tue, 17 Jun 2026 12:00:00 -0400'


def test_get_applied_info_pull_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """For a pull request: a single 'merge-commit' line and its date."""

    def fake_lines(gitdir: Optional[str], args: List[str]) -> List[str]:
        assert args[3] == 'merge1234567'
        return ['1750200000\x00Tue, 17 Jun 2026 12:00:00 -0400\x00merge1234567']

    monkeypatch.setattr(b4, 'git_get_command_lines', fake_lines)

    jsondata: b4.ty.JsonDictT = {'merge_commit_id': 'merge1234567'}
    applied_date, commit_lines = b4.ty.get_applied_info(None, jsondata)
    assert commit_lines == ['merge-commit: merge1234567']
    assert applied_date == 'Tue, 17 Jun 2026 12:00:00 -0400'


def test_get_applied_info_none_without_commits() -> None:
    """No recorded commit-ids means no applied date and no commit lines."""
    assert b4.ty.get_applied_info(None, {'commits': [[1, None]]}) == (None, [])
    assert b4.ty.get_applied_info(None, {}) == (None, [])


@pytest.mark.parametrize(
    'checkurl,repo,commit',
    [
        (
            'https://git.kernel.org/pub/scm/linux/kernel/git/broonie/misc.git/commit/?id=6c2505e185b0',
            'https://git.kernel.org/pub/scm/linux/kernel/git/broonie/misc.git',
            '6c2505e185b0',
        ),
        (
            'https://host.example/repo.git/commit/?h=for-next&id=abcdef123456',
            'https://host.example/repo.git',
            'abcdef123456',
        ),
        (
            'https://github.com/user/repo/commit/0123456789abcdef',
            'https://github.com/user/repo',
            '0123456789abcdef',
        ),
        (
            'https://gitlab.com/group/repo/-/commit/0123456789abcdef',
            'https://gitlab.com/group/repo',
            '0123456789abcdef',
        ),
        # git.kernel.org shortlink: commit recoverable, repo is not
        ('https://git.kernel.org/username/c/abc123def456', None, 'abc123def456'),
        ('https://example.com/whatever', None, None),
    ],
)
def test_parse_checkurl(
    checkurl: str, repo: Optional[str], commit: Optional[str]
) -> None:
    assert b4.ty._parse_checkurl(checkurl) == (repo, commit)


def test_get_check_repo_config_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """b4.thanks-check-repo wins over URL derivation."""
    checkurl = 'https://github.com/user/repo/commit/0123456789abcdef'
    assert b4.ty._get_check_repo(checkurl) == 'https://github.com/user/repo'
    monkeypatch.setitem(
        b4.MAIN_CONFIG, 'thanks-check-repo', 'https://example.com/r.git'
    )
    assert b4.ty._get_check_repo(checkurl) == 'https://example.com/r.git'


def _init_repo(path: str) -> None:
    ecode, out = b4.git_run_command(None, ['init', path])
    assert ecode == 0, out
    b4.git_set_config(path, 'user.name', 'Test')
    b4.git_set_config(path, 'user.email', 'test@example.com')


def _commit_empty(msg: str) -> str:
    ecode, out = b4.git_run_command(None, ['commit', '--allow-empty', '-m', msg])
    assert ecode == 0, out
    ecode, out = b4.git_run_command(None, ['rev-parse', 'HEAD'])
    assert ecode == 0, out
    return out.strip()


def test_commit_reachable_on_remote(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Reachability from an advertised head is what makes a commit
    published; mere presence in the remote odb is not enough."""
    local = str(tmp_path / 'local')
    pub = str(tmp_path / 'pub')
    _init_repo(local)
    ecode, out = b4.git_run_command(None, ['init', '--bare', pub])
    assert ecode == 0, out
    monkeypatch.chdir(local)
    c1 = _commit_empty('c1')
    ecode, out = b4.git_run_command(None, ['push', pub, 'HEAD:refs/heads/master'])
    assert ecode == 0, out
    c2 = _commit_empty('c2')

    # c1 is on the remote's master; c2 exists only locally
    assert b4.ty.commit_reachable_on_remote(c1, pub) is True
    assert b4.ty.commit_reachable_on_remote(c2, pub) is False

    # Emulate shared object storage: c2's object is in the remote odb
    # (push a ref, then delete it) but no head reaches it
    ecode, out = b4.git_run_command(None, ['push', pub, f'{c2}:refs/heads/tmp'])
    assert ecode == 0, out
    ecode, out = b4.git_run_command(None, ['push', pub, ':refs/heads/tmp'])
    assert ecode == 0, out
    assert b4.ty.commit_reachable_on_remote(c2, pub) is False

    # Unreachable remote: undeterminable, not a verdict
    assert b4.ty.commit_reachable_on_remote(c1, str(tmp_path / 'nope')) is None


def test_commit_reachable_unknown_tips(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Advertised tips we have no objects for cannot prove anything, so
    the answer is 'don't know' -- which keeps the message queued, but
    reports a failed check rather than normal waiting."""
    local = str(tmp_path / 'local')
    pub = str(tmp_path / 'pub')
    other = str(tmp_path / 'other')
    _init_repo(local)
    # -b master: the clone below takes its HEAD from this repository, and an
    # init.defaultBranch of 'main' would leave it on an unborn branch, with
    # the "advance the remote" commit landing as an unrelated root commit.
    ecode, out = b4.git_run_command(None, ['init', '--bare', '-b', 'master', pub])
    assert ecode == 0, out
    monkeypatch.chdir(local)
    c1 = _commit_empty('c1')
    ecode, out = b4.git_run_command(None, ['push', pub, 'HEAD:refs/heads/master'])
    assert ecode == 0, out
    # Advance the remote's master from a different clone
    ecode, out = b4.git_run_command(None, ['clone', pub, other])
    assert ecode == 0, out
    b4.git_set_config(other, 'user.name', 'Test')
    b4.git_set_config(other, 'user.email', 'test@example.com')
    monkeypatch.chdir(other)
    _commit_empty('c2-elsewhere')
    ecode, out = b4.git_run_command(None, ['push', 'origin', 'HEAD:refs/heads/master'])
    assert ecode == 0, out
    monkeypatch.chdir(local)
    # c1 is actually published, but the only advertised tip is unknown here
    assert b4.ty.commit_reachable_on_remote(c1, pub) is None


def test_commit_reachable_branch_filter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """With a branch, only that branch qualifies when advertised; an
    unadvertised branch falls back to checking all heads."""
    local = str(tmp_path / 'local')
    pub = str(tmp_path / 'pub')
    _init_repo(local)
    ecode, out = b4.git_run_command(None, ['init', '--bare', pub])
    assert ecode == 0, out
    monkeypatch.chdir(local)
    c1 = _commit_empty('c1')
    ecode, out = b4.git_run_command(None, ['push', pub, 'HEAD:refs/heads/master'])
    assert ecode == 0, out
    c2 = _commit_empty('c2')
    ecode, out = b4.git_run_command(None, ['push', pub, f'{c2}:refs/heads/side'])
    assert ecode == 0, out

    # c2 is only on 'side': published for 'side' and for the branchless
    # check, but not yet for the branch the message claims
    assert b4.ty.commit_reachable_on_remote(c2, pub) is True
    assert b4.ty.commit_reachable_on_remote(c2, pub, branch='side') is True
    assert b4.ty.commit_reachable_on_remote(c2, pub, branch='master') is False
    assert b4.ty.commit_reachable_on_remote(c1, pub, branch='master') is True
    # Unadvertised branch (renamed/deleted): any head counts again
    assert b4.ty.commit_reachable_on_remote(c2, pub, branch='gone') is True


def test_commit_reachable_uses_the_gitdir_it_is_given(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Ancestry is computed in the named repository, not the process cwd.

    'b4 review cron' sweeps several projects from whatever directory the
    scheduler happened to start it in, so the cwd is nobody's repository."""
    local = str(tmp_path / 'local')
    pub = str(tmp_path / 'pub')
    elsewhere = str(tmp_path / 'elsewhere')
    _init_repo(local)
    _init_repo(elsewhere)
    ecode, out = b4.git_run_command(None, ['init', '--bare', pub])
    assert ecode == 0, out
    monkeypatch.chdir(local)
    c1 = _commit_empty('c1')
    ecode, out = b4.git_run_command(None, ['push', pub, 'HEAD:refs/heads/master'])
    assert ecode == 0, out

    # An unrelated cwd knows none of the advertised tips, so on its own it
    # cannot answer -- the objects live in 'local'.
    monkeypatch.chdir(elsewhere)
    assert b4.ty.commit_reachable_on_remote(c1, pub, branch='master') is None
    assert (
        b4.ty.commit_reachable_on_remote(c1, pub, branch='master', gitdir=local) is True
    )


def test_get_thanks_target_check_repo_priority(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Check-repo resolution: per-remote b4-check-repo, then the
    b4.thanks-check-repo config, then the remote URL."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    b4.git_set_config(repo, 'remote.spi.url', 'https://example.com/spi.git')
    b4.git_set_config(repo, 'branch.for-next.remote', 'spi')
    b4.git_set_config(repo, 'branch.for-next.merge', 'refs/heads/for-next')

    def _checkrepo(branch: str) -> Optional[str]:
        return b4.ty.get_thanks_target(repo, branch).checkrepo

    assert _checkrepo('for-next') == 'https://example.com/spi.git'
    # A branch with no remote has nothing to check against
    assert _checkrepo('orphan') is None
    # b4.thanks-check-repo beats the remote URL
    monkeypatch.setitem(
        b4.MAIN_CONFIG, 'thanks-check-repo', 'https://example.com/g.git'
    )
    assert _checkrepo('for-next') == 'https://example.com/g.git'
    assert _checkrepo('orphan') == 'https://example.com/g.git'
    # remote.<name>.b4-check-repo beats everything
    b4.git_set_config(repo, 'remote.spi.b4-check-repo', 'https://example.com/pub.git')
    assert _checkrepo('for-next') == 'https://example.com/pub.git'


def test_get_thanks_target_remote_overrides_global(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """remote.<name>.b4-* settings win over the global b4.thanks-* ones,
    and only for branches tracking that remote."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    b4.git_set_config(repo, 'branch.for-next.remote', 'spi')
    b4.git_set_config(repo, 'branch.for-next.merge', 'refs/heads/spi-next')
    for key, val in (
        ('thanks-commit-url-mask', 'https://example.com/global/c/%s'),
        ('thanks-treename', 'global/tree'),
        ('thanks-am-template', '/global/am'),
    ):
        monkeypatch.setitem(b4.MAIN_CONFIG, key, val)
    for key, val in (
        ('b4-commit-url-mask', 'https://example.com/spi/c/%.12s'),
        ('b4-treename', 'spi/tree'),
        ('b4-am-template', '/spi/am'),
    ):
        b4.git_set_config(repo, f'remote.spi.{key}', val)

    target = b4.ty.get_thanks_target(repo, 'for-next')
    assert target.branch == 'spi-next'
    assert target.cidmask == 'https://example.com/spi/c/%.12s'
    assert target.treename == 'spi/tree'
    assert target.am_template == '/spi/am'

    target = b4.ty.get_thanks_target(repo, 'orphan')
    assert target.branch == 'orphan'
    assert target.cidmask == 'https://example.com/global/c/%s'
    assert target.treename == 'global/tree'
    assert target.am_template == '/global/am'


def test_get_thanks_target_ignores_mask_without_conversion(
    tmp_path: pathlib.Path,
) -> None:
    """A valueless mask key reads back as 'true'; using it as a mask would
    crash the % formatting, so it counts as no mask at all."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    b4.git_set_config(repo, 'branch.for-next.remote', 'spi')
    with open(os.path.join(repo, '.git', 'config'), 'a') as fh:
        fh.write('[remote "spi"]\n\tb4-commit-url-mask\n')
    assert b4.ty.get_thanks_target(repo, 'for-next').cidmask is None


def _am_jsondata(commit: str) -> b4.ty.JsonDictT:
    return {
        'fromname': 'Foo Bar',
        'fromemail': 'foo@example.com',
        'to': 'list@example.com',
        'cc': '',
        'references': '',
        'msgid': 'patch@example.com',
        'sentdate': 'Mon, 1 Jan 2026 00:00:00 +0000',
        'subject': '[PATCH] frobnicate',
        'myname': 'Test',
        'myemail': 'test@example.com',
        'signature': 'Test',
        'quote': '> frobnicate',
        'patches': [('frobnicate', '', 'patch@example.com', '1/1')],
        'commits': [(1, commit)],
    }


def test_generate_am_thanks_does_not_leak_between_branches(
    tmp_path: pathlib.Path,
) -> None:
    """One process (the review TUI) thanking series on two branches must
    not carry the first branch's remote settings into the second message."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    b4.git_set_config(repo, 'branch.for-next.remote', 'spi')
    b4.git_set_config(
        repo, 'remote.spi.b4-commit-url-mask', 'https://example.com/spi/c/%.12s'
    )
    b4.git_set_config(repo, 'remote.spi.b4-treename', 'spi/tree')
    commit = '0123456789abcdef0123456789abcdef01234567'
    cmdargs = mock.Mock(metoo=False, since=None)

    first = _am_jsondata(commit)
    b4.ty.generate_am_thanks(repo, first, 'for-next', cmdargs)
    assert 'https://example.com/spi/c/0123456789ab' in str(first['summary'])

    second = _am_jsondata(commit)
    b4.ty.generate_am_thanks(repo, second, 'orphan', cmdargs)
    assert second['summary'] == f'[1/1] frobnicate\n      commit: {commit}'
    assert second['treename'] == 'local tree'
    assert b4.MAIN_CONFIG['thanks-commit-url-mask'] is None


def test_queue_message_check_headers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Queueing records X-Check-Commit/X-Check-Repo alongside X-Check-URL."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    fullsha = 'ab12' * 10
    checkurl = f'https://git.kernel.org/pub/scm/utils/b4/b4.git/commit/?id={fullsha}'
    msg = EmailMessage()
    msg['Subject'] = 'Re: [PATCH] test'
    msg.set_content('Thanks!')
    b4.ty.queue_message(msg, checkurl, 'test-change-id', 1)
    qdir = b4.ty._get_queue_dir()
    parsed = b4.ty._parse_queue_file(os.path.join(qdir, 'test-change-id-v1.msg'))
    assert parsed is not None
    assert parsed['X-Check-URL'] == checkurl
    assert parsed['X-Check-Commit'] == fullsha
    assert parsed['X-Check-Repo'] == 'https://git.kernel.org/pub/scm/utils/b4/b4.git'


def test_queue_message_shortlink_mask(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """With a shortlink mask the repo comes from b4.thanks-check-repo and
    the commit from the explicit checkcommit argument."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    monkeypatch.setitem(
        b4.MAIN_CONFIG, 'thanks-check-repo', 'https://example.com/r.git'
    )
    fullsha = 'cd34' * 10
    msg = EmailMessage()
    msg['Subject'] = 'Re: [PATCH] test'
    msg.set_content('Thanks!')
    checkurl = f'https://git.kernel.org/username/c/{fullsha[:12]}'
    b4.ty.queue_message(msg, checkurl, 'test-change-id', 2, checkcommit=fullsha)
    qdir = b4.ty._get_queue_dir()
    parsed = b4.ty._parse_queue_file(os.path.join(qdir, 'test-change-id-v2.msg'))
    assert parsed is not None
    assert parsed['X-Check-Commit'] == fullsha
    assert parsed['X-Check-Repo'] == 'https://example.com/r.git'


def test_queue_message_explicit_repo_and_branch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Explicit checkrepo/checkbranch are recorded verbatim, bypassing
    mask derivation entirely."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    fullsha = 'fa11' * 10
    msg = EmailMessage()
    msg['Subject'] = 'Re: [PATCH] test'
    msg.set_content('Thanks!')
    checkurl = f'https://git.kernel.org/username/c/{fullsha[:12]}'
    b4.ty.queue_message(
        msg,
        checkurl,
        'test-change-id',
        3,
        checkcommit=fullsha,
        checkrepo='https://example.com/spi.git',
        checkbranch='for-next',
    )
    qdir = b4.ty._get_queue_dir()
    parsed = b4.ty._parse_queue_file(os.path.join(qdir, 'test-change-id-v3.msg'))
    assert parsed is not None
    assert parsed['X-Check-Commit'] == fullsha
    assert parsed['X-Check-Repo'] == 'https://example.com/spi.git'
    assert parsed['X-Check-Branch'] == 'for-next'


def test_process_queue_passes_branch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Delivery verifies reachability from the exact branch the thanks
    message names, when the queue entry recorded one."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    fullsha = 'ba55' * 10
    msg = EmailMessage()
    msg['Subject'] = 'Re: [PATCH] test'
    msg.set_content('Thanks!')
    b4.ty.queue_message(
        msg,
        f'https://git.kernel.org/username/c/{fullsha[:12]}',
        'test-change-id',
        1,
        checkcommit=fullsha,
        checkrepo='https://example.com/spi.git',
        checkbranch='for-next',
    )

    calls: List[Tuple[str, str, str]] = []

    def fake_reachable(
        commit: str, repo_url: str, branch: str = '', gitdir: Optional[str] = None
    ) -> Optional[bool]:
        calls.append((commit, repo_url, branch))
        return False

    monkeypatch.setattr(b4.ty, 'commit_reachable_on_remote', fake_reachable)
    delivered, pending, dseries = b4.ty.process_queue()
    assert (delivered, pending, dseries) == (0, 1, [])
    assert calls == [(fullsha, 'https://example.com/spi.git', 'for-next')]


def test_process_queue_holds_unpublished(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """A queued message whose commit is not reachable on the public repo
    stays queued, and the reachability check gets the header values."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    fullsha = 'ef56' * 10
    checkurl = f'https://git.kernel.org/pub/scm/utils/b4/b4.git/commit/?id={fullsha}'
    msg = EmailMessage()
    msg['Subject'] = 'Re: [PATCH] test'
    msg.set_content('Thanks!')
    b4.ty.queue_message(msg, checkurl, 'test-change-id', 1)

    calls: List[Tuple[str, str]] = []

    def fake_reachable(
        commit: str, repo_url: str, branch: str = '', gitdir: Optional[str] = None
    ) -> Optional[bool]:
        calls.append((commit, repo_url))
        return False

    monkeypatch.setattr(b4.ty, 'commit_reachable_on_remote', fake_reachable)
    delivered, pending, dseries = b4.ty.process_queue()
    assert (delivered, pending, dseries) == (0, 1, [])
    assert calls == [(fullsha, 'https://git.kernel.org/pub/scm/utils/b4/b4.git')]
    qdir = b4.ty._get_queue_dir()
    assert os.path.exists(os.path.join(qdir, 'test-change-id-v1.msg'))


def test_queue_message_atomic_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Queue files appear atomically: no temp leftovers in the queue dir."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    msg = EmailMessage()
    msg['Subject'] = 'Re: [PATCH] test'
    msg.set_content('Thanks!')
    b4.ty.queue_message(msg, 'https://example.com/c/abcdef123456', 'cid', 1)
    qdir = b4.ty._get_queue_dir()
    entries = os.listdir(qdir)
    assert 'cid-v1.msg' in entries
    assert not [f for f in entries if f.endswith('.tmp')]


def _queue_test_message(
    change_id: str = 'test-change-id',
    revision: int = 1,
    archive_after: bool = False,
) -> str:
    """Queue a minimal thanks message; returns the expected full sha."""
    fullsha = '9a8b' * 10
    checkurl = f'https://git.kernel.org/pub/scm/utils/b4/b4.git/commit/?id={fullsha}'
    msg = EmailMessage()
    msg['Subject'] = 'Re: [PATCH] test'
    msg.set_content('Thanks!')
    b4.ty.queue_message(msg, checkurl, change_id, revision, archive_after=archive_after)
    return fullsha


def test_process_queue_lock_held(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """A second delivery run must fail fast while the lock is held, and
    succeed normally once it is released."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    _queue_test_message()
    monkeypatch.setattr(
        b4.ty,
        'commit_reachable_on_remote',
        lambda commit, repo_url, branch='', gitdir=None: False,
    )
    with b4.lockfile_nb(b4.ty._get_queue_lock_path()):
        with pytest.raises(b4.LockHeldError):
            b4.ty.process_queue()
    # After release, the queue is processable again
    assert b4.ty.process_queue() == (0, 1, [])


def test_process_queue_check_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """check_only reports what would be delivered without sending or
    moving anything."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    _queue_test_message()
    monkeypatch.setattr(
        b4.ty,
        'commit_reachable_on_remote',
        lambda commit, repo_url, branch='', gitdir=None: True,
    )

    def _no_send(dryrun: bool = False) -> Tuple[None, str]:
        raise AssertionError('check_only must not open an smtp connection')

    monkeypatch.setattr(b4, 'get_smtp', _no_send)
    statuses: List[str] = []
    delivered, pending, dseries = b4.ty.process_queue(
        check_only=True, progress_cb=lambda c, t, s: statuses.append(s)
    )
    assert (delivered, pending) == (1, 0)
    assert dseries == [('test-change-id', 1)]
    assert 'Would deliver: Re: [PATCH] test' in statuses
    qdir = b4.ty._get_queue_dir()
    assert os.path.exists(os.path.join(qdir, 'test-change-id-v1.msg'))


def test_process_queue_explicit_topdir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """The queue of an explicitly-given repository is processed even when
    the current directory is not inside it (cron -i __all__)."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    _queue_test_message()
    monkeypatch.setattr(
        b4.ty,
        'commit_reachable_on_remote',
        lambda commit, repo_url, branch='', gitdir=None: True,
    )
    outside = tmp_path / 'elsewhere'
    outside.mkdir()
    monkeypatch.chdir(str(outside))
    assert b4.ty.get_queued_count() == 0
    assert b4.ty.get_queued_count(topdir=repo) == 1
    delivered, pending, _dseries = b4.ty.process_queue(check_only=True, topdir=repo)
    assert (delivered, pending) == (1, 0)


def test_process_queue_finalizes_thanked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Delivering a queued message marks the series 'thanked' in the
    tracking database."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    _add_tracked_series('cronproj')

    _queue_test_message()
    _mock_delivery(monkeypatch)

    delivered, pending, dseries = b4.ty.process_queue(identifier='cronproj')
    assert (delivered, pending) == (1, 0)
    assert dseries == [('test-change-id', 1)]
    assert _series_status('cronproj') == 'thanked'
    qdir = b4.ty._get_queue_dir()
    assert not os.path.exists(os.path.join(qdir, 'test-change-id-v1.msg'))
    assert os.path.exists(os.path.join(qdir, 'sent', 'test-change-id-v1.msg'))


def _add_tracked_series(
    identifier: str,
    change_id: str = 'test-change-id',
    revision: int = 1,
    status: str = 'accepted',
    revisions: Optional[List[int]] = None,
) -> None:
    """Seed a tracking database with one series in the given status."""
    seed_series(
        identifier,
        change_id,
        revision=revision,
        status=status,
        subject='test subject',
        sender_name='Test',
        sender_email='t@example.com',
        sent_at=None,
        message_id='<msg@id>',
        revisions=revisions,
        stamp_activity=True,
    )


def _series_status(identifier: str, change_id: str = 'test-change-id') -> str:
    import b4.review.tracking as tracking

    conn = tracking.get_db(identifier)
    row = conn.execute(
        'SELECT status FROM series WHERE change_id = ?', (change_id,)
    ).fetchone()
    conn.close()
    return str(row[0])


def _mock_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        b4.ty,
        'commit_reachable_on_remote',
        lambda commit, repo_url, branch='', gitdir=None: True,
    )
    monkeypatch.setattr(b4, 'get_smtp', lambda dryrun=False: (None, 't@example.com'))
    monkeypatch.setattr(b4, 'send_mail', lambda *args, **kwargs: 1)


def test_queue_message_archive_after_header(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """archive_after rides on the queued message as an internal header;
    without it the header is absent."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    qdir = b4.ty._get_queue_dir()

    _queue_test_message('plain-cid')
    parsed = b4.ty._parse_queue_file(os.path.join(qdir, 'plain-cid-v1.msg'))
    assert parsed is not None
    assert 'X-B4-Archive-After-Send' not in parsed

    _queue_test_message('archive-cid', archive_after=True)
    parsed = b4.ty._parse_queue_file(os.path.join(qdir, 'archive-cid-v1.msg'))
    assert parsed is not None
    assert parsed['X-B4-Archive-After-Send'] == 'yes'


def test_process_queue_archives_after_send(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """A delivered message with the archive-after flag archives the series,
    and the internal header does not leak into the sent mail."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    _add_tracked_series('cronproj')
    _queue_test_message(archive_after=True)
    _mock_delivery(monkeypatch)
    sent_msgs: List[EmailMessage] = []

    def _capture_send(smtp: object, msgs: List[EmailMessage], **kwargs: object) -> int:
        sent_msgs.extend(msgs)
        return len(msgs)

    monkeypatch.setattr(b4, 'send_mail', _capture_send)

    statuses: List[str] = []
    delivered, pending, _dseries = b4.ty.process_queue(
        identifier='cronproj', progress_cb=lambda c, t, s: statuses.append(s)
    )
    assert (delivered, pending) == (1, 0)
    assert _series_status('cronproj') == 'archived'
    assert 'Re: [PATCH] test + archived' in statuses
    assert len(sent_msgs) == 1
    assert 'X-B4-Archive-After-Send' not in sent_msgs[0]


def test_process_queue_keeps_series_with_newer_revision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """The archive is skipped when a newer revision is known by delivery
    time; the series stays 'thanked' for the maintainer to deal with."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    _add_tracked_series('cronproj', revisions=[1, 2])
    _queue_test_message(archive_after=True)
    _mock_delivery(monkeypatch)

    statuses: List[str] = []
    delivered, _pending, _dseries = b4.ty.process_queue(
        identifier='cronproj', progress_cb=lambda c, t, s: statuses.append(s)
    )
    assert delivered == 1
    assert _series_status('cronproj') == 'thanked'
    assert 'Re: [PATCH] test (not archived: newer revision available)' in statuses


def test_process_queue_keeps_series_after_status_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """The archive is skipped when the series status drifted away from
    'accepted' between queueing and delivery (e.g. back to reviewing)."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    _add_tracked_series('cronproj', status='reviewing')
    _queue_test_message(archive_after=True)
    _mock_delivery(monkeypatch)

    statuses: List[str] = []
    delivered, _pending, _dseries = b4.ty.process_queue(
        identifier='cronproj', progress_cb=lambda c, t, s: statuses.append(s)
    )
    assert delivered == 1
    assert _series_status('cronproj') != 'archived'
    assert (
        'Re: [PATCH] test (not archived: series status changed since queueing)'
        in statuses
    )


def test_process_queue_does_not_resurrect_archived(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Delivering a queued thanks for a series that was manually archived
    in the meantime must not flip it back to 'thanked'."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    _add_tracked_series('cronproj', status='archived')
    _queue_test_message()
    _mock_delivery(monkeypatch)

    delivered, _pending, _dseries = b4.ty.process_queue(identifier='cronproj')
    assert delivered == 1
    assert _series_status('cronproj') == 'archived'


def test_process_queue_skips_archive_when_checked_out(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """A checked-out review branch is left alone by delivery cleanup:
    no tracking-commit write, no archive.  The DB still records
    'thanked' — the fact of the sent thanks."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    _commit_empty('base')
    _add_tracked_series('cronproj')
    review_branch = 'b4/review/test-change-id'
    ecode, out = b4.git_run_command(None, ['checkout', '-b', review_branch])
    assert ecode == 0, out
    _queue_test_message(archive_after=True)
    _mock_delivery(monkeypatch)

    statuses: List[str] = []
    with mock.patch('b4.review.update_tracking_status') as mock_uts:
        delivered, _pending, _dseries = b4.ty.process_queue(
            identifier='cronproj',
            topdir=repo,
            progress_cb=lambda c, t, s: statuses.append(s),
        )
    assert delivered == 1
    mock_uts.assert_not_called()
    assert _series_status('cronproj') == 'thanked'
    assert 'Re: [PATCH] test (not archived: branch is checked out)' in statuses
    assert b4.git_branch_exists(None, review_branch)


def test_process_queue_updates_parked_branch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Control: with the review branch parked, delivery still writes the
    'thanked' status to its tracking commit."""
    repo = str(tmp_path / 'repo')
    _init_repo(repo)
    monkeypatch.chdir(repo)
    _commit_empty('base')
    _add_tracked_series('cronproj')
    review_branch = 'b4/review/test-change-id'
    ecode, out = b4.git_run_command(None, ['branch', review_branch])
    assert ecode == 0, out
    _queue_test_message()
    _mock_delivery(monkeypatch)

    with mock.patch('b4.review.update_tracking_status') as mock_uts:
        delivered, _pending, _dseries = b4.ty.process_queue(
            identifier='cronproj', topdir=repo
        )
    assert delivered == 1
    mock_uts.assert_called_once()
    assert mock_uts.call_args.args[1:] == (review_branch, 'thanked')
