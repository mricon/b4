# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""The contributor workflow on a detached HEAD, without any branch."""

import email.message
import logging
import mailbox
import os
import pathlib
from typing import Any, Dict, Generator, List, Optional
from unittest.mock import patch

import pytest

import b4
import b4.command
import b4.ez


def _run(*args: str) -> None:
    """Drive a b4 subcommand the way the command line would."""
    parser = b4.command.setup_parser()
    cmdargs = parser.parse_args(['--no-stdin', '--no-interactive', *args])
    cmdargs.func(cmdargs)


def _git(*args: str, where: Optional[str] = None) -> str:
    ecode, out = b4.git_run_command(where, list(args), logstderr=True)
    assert ecode == 0, out
    assert isinstance(out, str)
    return out.strip()


def _commit_file(name: str, subject: str) -> None:
    pathlib.Path(name).write_text(f'{subject}\n')
    _git('add', name)
    _git('commit', '-q', '-m', subject)


def _head() -> str:
    return b4.git_revparse_obj('HEAD')


def _tracking() -> Dict[str, Any]:
    _cover, tracking = b4.ez.load_cover()
    return tracking


def _backup_ref() -> str:
    return f'refs/original/b4/{_tracking()["series"]["change-id"]}'


def _assert_no_bogus_branch_config() -> None:
    ecode, out = b4.git_run_command(
        None, ['config', '--get-regexp', r'^branch\.(HEAD|None)\.']
    )
    assert ecode == 1, out


def _cover_from(tmp_path: pathlib.Path, text: str) -> None:
    fpath = tmp_path / 'cover.txt'
    fpath.write_text(text)
    _run('prep', '--cover-from-file', str(fpath))


COVER = 'Add two files\n\nThis series adds two files.\n\nSigned-off-by: Test <t@example.com>'


@pytest.fixture
def detached(gitdir: str) -> Generator[str, None, None]:
    """A commit-strategy series on a detached HEAD, with its branch gone."""
    b4.MAIN_CONFIG['prep-cover-strategy'] = 'commit'
    _run('prep', '-n', 'pytest')
    _commit_file('one.txt', 'Add the first file')
    _commit_file('two.txt', 'Add the second file')
    _git('checkout', '-q', '--detach')
    _git('branch', '-q', '-D', 'b4/pytest')
    assert b4.git_get_current_branch() is None
    yield gitdir


def test_series_is_found_from_head(detached: str) -> None:
    assert b4.ez.is_prep_branch() is True
    assert b4.ez.get_cover_strategy() == 'commit'
    cover = b4.ez.find_cover_commit()
    assert cover is not None
    base, start, end = b4.ez.get_series_range()
    assert start == cover
    assert base == b4.git_revparse_obj(f'{cover}~1')
    assert end == _head()
    info = b4.ez.get_info(usebranch=None)
    assert info['branch'] is None
    assert info['series-range'] == f'{start}..{end}'


def test_cover_update_rewrites_head_in_place(
    detached: str, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    old_head = _head()
    master = b4.git_revparse_obj('master')
    old_tree = b4.git_revparse_obj('HEAD^{tree}')
    _cover_from(tmp_path, COVER)

    assert b4.git_get_current_branch() is None
    assert _head() != old_head
    assert b4.git_revparse_obj('HEAD^{tree}') == old_tree
    assert b4.git_revparse_obj('master') == master
    assert b4.git_revparse_obj(_backup_ref()) == old_head
    assert not b4.git_branch_exists(None, 'refs/original/HEAD')
    _run('prep', '--show-cover')
    assert capsys.readouterr().out.strip() == COVER
    _assert_no_bogus_branch_config()


def test_edit_cover_in_editor(
    detached: str, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    editor = tmp_path / 'editor.sh'
    editor.write_text(
        '#!/bin/sh\nprintf "Edited subject\\n\\nEdited body.\\n" > "$1"\n'
    )
    editor.chmod(0o755)
    monkeypatch.setenv('GIT_EDITOR', str(editor))
    _run('prep', '--edit-cover')
    cover, _tracking = b4.ez.load_cover()
    assert cover == 'Edited subject\n\nEdited body.'
    assert b4.git_get_current_branch() is None


def test_edit_cover_refused_when_head_moves(
    detached: str, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Moving a detached HEAD mid-edit is a series switch; the edit lands
    nowhere and the text is kept for the user."""
    elsewhere = b4.git_revparse_obj('HEAD~1')
    editor = tmp_path / 'editor.sh'
    editor.write_text(
        f'#!/bin/sh\nprintf "Lost subject\\n\\nbody\\n" > "$1"\n'
        f'git -C "{detached}" checkout -q --detach {elsewhere}\n'
    )
    editor.chmod(0o755)
    monkeypatch.setenv('GIT_EDITOR', str(editor))
    with pytest.raises(RuntimeError, match='Detached HEAD moved') as ex:
        b4.ez.edit_cover()
    saved = pathlib.Path(str(ex.value).split(' saved at ')[-1])
    try:
        assert saved.read_text() == 'Lost subject\n\nbody\n'
    finally:
        saved.unlink()
    assert _head() == elsewhere


def test_deps_prefixes_and_revision(
    detached: str, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    deps = tmp_path / 'deps.txt'
    deps.write_text('change-id: 20240101-other-series-0123456789ab:v2\n')
    _run('prep', '--deps-from-file', str(deps))
    _run('prep', '--set-prefixes', 'RFC')
    _run('prep', '--force-revision', '3')
    capsys.readouterr()
    _run('prep', '--show-deps')
    assert capsys.readouterr().out.strip() == (
        'change-id: 20240101-other-series-0123456789ab:v2'
    )
    series = _tracking()['series']
    assert series['prefixes'] == ['RFC']
    assert series['revision'] == 3
    assert b4.git_get_current_branch() is None
    _assert_no_bogus_branch_config()


def test_format_patch_and_check(
    detached: str, tmp_path: pathlib.Path, caplog: pytest.LogCaptureFixture
) -> None:
    _cover_from(tmp_path, COVER)
    outdir = tmp_path / 'out'
    _run('prep', '--format-patch', str(outdir))
    names = sorted(os.listdir(outdir))
    assert len(names) == 3
    assert names[0].startswith('0000-add-two-files')
    assert names[1].startswith('0001-add-the-first-file')

    b4.MAIN_CONFIG['prep-perpatch-check-cmd'] = 'true'
    with caplog.at_level(logging.INFO):
        _run('prep', '--check')
    assert 'Success: 2, Warning: 0, Error: 0' in caplog.text


def _sent_patches() -> List[email.message.EmailMessage]:
    _tos, _ccs, _tag, patches = b4.ez.get_prep_branch_as_patches(movefrom=False)
    return [msg for _commit, msg in patches]


def test_trailers_update(detached: str, tmp_path: pathlib.Path) -> None:
    """Follow-up trailers land on the right commit, and HEAD stays put
    relative to the series: still detached, cover still first."""
    _cover_from(tmp_path, COVER)
    msgs = _sent_patches()
    reply = email.message.EmailMessage()
    reply['From'] = 'Rev Iewer <rev@example.com>'
    reply['Subject'] = 'Re: ' + str(msgs[2]['Subject'])
    reply['Message-Id'] = '<review-1@example.com>'
    reply['In-Reply-To'] = msgs[2]['Message-Id']
    reply['References'] = msgs[2]['Message-Id']
    reply.set_content('> some quote\n\nReviewed-by: Rev Iewer <rev@example.com>\n')
    mbx_path = str(tmp_path / 'thread.mbox')
    mbx = mailbox.mbox(mbx_path)
    for msg in msgs + [reply]:
        mbx.add(msg)
    mbx.close()

    cover = b4.ez.find_cover_commit()
    _run('--offline-mode', 'trailers', '-u', '-m', mbx_path)

    assert b4.git_get_current_branch() is None
    assert b4.ez.find_cover_commit() == cover
    body = _git('log', '-1', '--format=%B', 'HEAD')
    assert 'Reviewed-by: Rev Iewer <rev@example.com>' in body
    first = _git('log', '-1', '--format=%B', 'HEAD~1')
    assert 'Reviewed-by' not in first
    assert b4.git_revparse_obj(_backup_ref())


class _Transport:
    def __init__(self) -> None:
        self.sent: List[email.message.EmailMessage] = []

    def send_mail(self, _smtp: Any, msgs: Any, **kwargs: Any) -> Optional[int]:
        if kwargs.get('dryrun'):
            return None
        self.sent.extend(msgs)
        return len(msgs)


@pytest.fixture
def transport(monkeypatch: pytest.MonkeyPatch) -> _Transport:
    tr = _Transport()
    monkeypatch.setattr(b4, 'send_mail', tr.send_mail)
    monkeypatch.setattr(
        b4, 'get_smtp', lambda dryrun=False: (None, 'test-override@example.com')
    )
    monkeypatch.setattr('builtins.input', lambda _prompt='': '')
    b4.MAIN_CONFIG['prep-pre-flight-checks'] = 'disable-all'
    return tr


def test_send_tags_and_rerolls(
    detached: str, tmp_path: pathlib.Path, transport: _Transport
) -> None:
    _cover_from(tmp_path, COVER)
    master = b4.git_revparse_obj('master')
    series_tree = b4.git_revparse_obj('HEAD^{tree}')
    change_id = _tracking()['series']['change-id']

    _run('send', '--no-sign', '--to', 'list@example.com')

    assert len(transport.sent) == 3
    assert str(transport.sent[0]['Subject']).startswith('[PATCH 0/2] Add two files')
    tagname = f'sent/{change_id}-v1'
    tagged = b4.git_revparse_tag(None, tagname)
    assert tagged is not None
    # The tag holds the two patches and not the cover letter
    assert b4.git_revparse_obj(f'{tagname}^{{tree}}') == series_tree
    assert (
        _git('rev-list', '--count', f'{b4.ez.get_series_range()[0]}..{tagname}') == '2'
    )

    series = _tracking()['series']
    assert series['revision'] == 2
    assert series['history']['v1'] == [
        b4.LoreMessage.get_clean_msgid(transport.sent[0])
    ]
    assert b4.git_get_current_branch() is None
    assert b4.git_revparse_obj('HEAD^{tree}') == series_tree
    assert b4.git_revparse_obj('master') == master
    assert 'Changes in v2' in b4.ez.load_cover()[0]
    _assert_no_bogus_branch_config()

    # The sent revision is there to resend and compare against
    _run('send', '--no-sign', '--resend', 'v1', '--to', 'list@example.com')
    assert len(transport.sent) == 6
    assert '[PATCH RESEND 0/2]' in str(transport.sent[3]['Subject'])
    assert b4.ez.range_diff_compare(1, execvp=False) is not None
    assert _tracking()['series']['revision'] == 2


@pytest.mark.parametrize(
    'sendargs',
    [
        ['--dry-run'],
        ['--preview-to', 'me@example.com'],
        ['--reflect'],
    ],
)
def test_send_without_reroll(
    detached: str,
    tmp_path: pathlib.Path,
    transport: _Transport,
    sendargs: List[str],
) -> None:
    _cover_from(tmp_path, COVER)
    head = _head()
    _run('send', '--no-sign', '--to', 'list@example.com', *sendargs)
    assert _head() == head
    assert _tracking()['series']['revision'] == 1
    assert not b4.git_get_command_lines(None, ['tag', '--list', 'sent/*'])


def test_send_output_dir(
    detached: str, tmp_path: pathlib.Path, transport: _Transport
) -> None:
    _cover_from(tmp_path, COVER)
    head = _head()
    _run('send', '--no-sign', '-o', str(tmp_path / 'out'), '--to', 'list@example.com')
    assert _head() == head
    assert _tracking()['series']['revision'] == 1


def test_claim_after_identity_change(
    detached: str, caplog: pytest.LogCaptureFixture
) -> None:
    newcfg = {'name': 'Changed User', 'email': 'changed@example.com'}
    with patch('b4.get_user_config', return_value=newcfg):
        assert b4.ez.is_prep_branch() is False
        with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit):
            b4.ez.is_prep_branch(mustbe=True)
        assert "This HEAD's b4 cover-letter commit" in caplog.text
        assert 'b4 prep --claim' in caplog.text
        old_head = _head()
        _run('prep', '--claim')
        assert b4.ez.is_prep_branch() is True
        assert b4.git_revparse_obj(_backup_ref()) == old_head
    assert b4.git_get_current_branch() is None
    committers = set(_git('log', '--format=%ce', 'HEAD~3..HEAD').split())
    assert committers == {'changed@example.com'}


def test_new_branch_from_detached_series(
    detached: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """prep -n still creates a branch, and a series at HEAD becomes its
    dependency, as it does from a prep branch."""
    change_id = _tracking()['series']['change-id']
    monkeypatch.setattr('builtins.input', lambda _prompt='': '')
    _run('prep', '-n', 'followup')
    assert b4.git_get_current_branch() == 'b4/followup'
    assert _tracking()['series']['prerequisites'] == [f'change-id: {change_id}:v1']


def test_other_strategies_need_a_branch(
    detached: str, caplog: pytest.LogCaptureFixture
) -> None:
    b4.MAIN_CONFIG['prep-cover-strategy'] = 'branch-description'
    head = _head()
    with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit):
        _run('prep', '--show-cover')
    assert 'b4 supports only the "commit" cover' in caplog.text
    assert 'b4.prep-cover-strategy is branch-description' in caplog.text
    assert _head() == head
    _assert_no_bogus_branch_config()


def test_tip_commit_layout_is_refused(
    gitdir: str, caplog: pytest.LogCaptureFixture
) -> None:
    """A tip-commit cover can look like a commit-strategy cover with an
    empty series; its tracking data tells them apart."""
    b4.MAIN_CONFIG['prep-cover-strategy'] = 'tip-commit'
    _run('prep', '-n', 'pytest')
    _git('checkout', '-q', '--detach')
    b4.MAIN_CONFIG['prep-cover-strategy'] = 'commit'
    with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit):
        _run('prep', '--show-cover')
    assert 'tracks base branch' in caplog.text


def test_merge_in_series_is_refused(
    detached: str, caplog: pytest.LogCaptureFixture
) -> None:
    head = _head()
    _git('checkout', '-q', '-b', 'side', 'master')
    _commit_file('side.txt', 'Side change')
    _git('checkout', '-q', '--detach', head)
    _git('merge', '-q', '--no-edit', 'side')
    with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit):
        _run('prep', '--show-cover')
    assert 'cannot tell which commits belong to it' in caplog.text


def test_linked_worktree_moves_only_its_head(
    detached: str, tmp_path: pathlib.Path
) -> None:
    head = _head()
    linked = str(tmp_path / 'linked')
    _git('worktree', 'add', '-q', '--detach', linked, head)
    _git('checkout', '-q', 'master')
    os.chdir(linked)
    _cover_from(tmp_path, COVER)
    assert b4.git_get_current_branch(linked) is None
    assert b4.git_revparse_obj('HEAD', gitdir=linked) != head
    assert b4.git_get_current_branch(detached) == 'master'
    assert b4.git_revparse_obj(_backup_ref()) == head
