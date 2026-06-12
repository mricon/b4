#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
import json
import os
from email.message import EmailMessage
from typing import Any, Dict, List, Optional, Tuple

import pytest
import requests

import b4
import b4.command
import b4.pr


# ---------------------------------------------------------------------------
# Helpers and fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope='function')
def prremote(gitdir: str, tmp_path: Any, sampledir: str) -> Dict[str, str]:
    """Build a separate "remote" repository with one extra commit on top of
    master, exposed both as a branch (``for-pull``) and a tag (``pull-tag``).

    The ``gitdir`` fixture leaves us cd'd inside a fresh local clone whose
    master does NOT contain the extra commit, so the local tree starts out
    not knowing about the pull request tip.
    """
    remote = os.path.join(str(tmp_path), 'remote')
    bfile = os.path.join(sampledir, 'gitdir.bundle')
    assert os.path.exists(bfile)
    ecode, _out = b4.git_run_command(
        None, ['clone', '--branch', 'master', bfile, remote]
    )
    assert ecode == 0
    b4.git_set_config(remote, 'user.name', 'Pull Author')
    b4.git_set_config(remote, 'user.email', 'pull@example.com')

    def _git(args: List[str]) -> str:
        # Run in the remote worktree (rundir), not via --git-dir, so that
        # working-tree operations like "add"/"commit" see the files we write.
        ecode, out = b4.git_run_command(None, args, rundir=remote)
        assert ecode == 0, f'git {args} failed: {out}'
        return str(out).strip()

    base = _git(['rev-parse', 'HEAD'])
    _git(['checkout', '-b', 'for-pull'])
    fpath = os.path.join(remote, 'pull-file.txt')
    with open(fpath, 'w', encoding='utf-8') as fh:
        fh.write('pull change\n')
    _git(['add', 'pull-file.txt'])
    _git(['commit', '-m', 'Add pull-file'])
    tip = _git(['rev-parse', 'HEAD'])
    assert tip != base
    _git(['tag', 'pull-tag'])

    return {'path': remote, 'base': base, 'tip': tip, 'ref': 'for-pull'}


def _make_msg(
    msgid: str = 'pull-1@example.com',
    subject: str = '[GIT PULL] test changes',
    body: str = 'Please pull the changes.\n',
) -> EmailMessage:
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = 'Pull Author <pull@example.com>'
    msg['Date'] = 'Mon, 01 Jun 2026 10:00:00 +0000'
    msg['Message-Id'] = f'<{msgid}>'
    msg['To'] = 'Maintainer <maint@example.com>'
    msg['Cc'] = 'Some List <list@example.com>'
    msg['References'] = '<prev@example.com>'
    msg.set_payload(body)
    return msg


def _make_lmsg(
    remote: Dict[str, str],
    tip: Optional[str] = None,
    base: Optional[str] = None,
    msgid: str = 'pull-1@example.com',
) -> Tuple[EmailMessage, b4.LoreMessage]:
    msg = _make_msg(msgid=msgid)
    lmsg = b4.LoreMessage(msg)
    lmsg.pr_base_commit = base if base is not None else remote['base']
    lmsg.pr_repo = remote['path']
    lmsg.pr_ref = remote['ref']
    lmsg.pr_tip_commit = tip if tip is not None else remote['tip']
    lmsg.pr_remote_tip_commit = lmsg.pr_tip_commit
    return msg, lmsg


def _parse_main_args(extra: List[str]) -> Any:
    parser = b4.command.setup_parser()
    return parser.parse_args(['--no-stdin', 'pr', 'pull-1@example.com'] + extra)


def _patch_main_lookups(
    monkeypatch: pytest.MonkeyPatch, msg: EmailMessage, lmsg: b4.LoreMessage
) -> None:
    monkeypatch.setattr(b4, 'get_pi_thread_by_msgid', lambda m, **k: [msg])
    monkeypatch.setattr(b4.pr, 'parse_pr_data', lambda m: lmsg)


# ---------------------------------------------------------------------------
# parse_pr_data: extracting repo / ref / base / tip from the message body
# ---------------------------------------------------------------------------
def test_parse_pr_data_extracts_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    base = '1' * 40
    tip = '2' * 40
    body = (
        'Please pull.\n\n'
        f'The following changes since commit {base}:\n\n'
        '  Some commit (2026-01-01)\n\n'
        'are available in the git repository at:\n\n'
        '  git://example.com/repo.git for-pull\n\n'
        f'for you to fetch changes up to {tip}:\n\n'
        '  Tip commit (2026-01-02)\n'
    )
    msg = _make_msg(body=body)
    monkeypatch.setattr(
        b4.pr, 'git_get_commit_id_from_repo_ref', lambda repo, ref: 'deadbeef'
    )
    lmsg = b4.pr.parse_pr_data(msg)
    assert lmsg is not None
    assert lmsg.pr_base_commit == base
    assert lmsg.pr_repo == 'git://example.com/repo.git'
    assert lmsg.pr_ref == 'for-pull'
    assert lmsg.pr_tip_commit == tip
    assert lmsg.pr_remote_tip_commit == 'deadbeef'


def test_parse_pr_data_bare_repo_defaults_to_master(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = 'are available in the git repository at:\n\n  git://example.com/repo.git\n\n'
    msg = _make_msg(body=body)
    captured: Dict[str, str] = {}

    def _fake(repo: str, ref: str) -> str:
        captured['repo'] = repo
        captured['ref'] = ref
        return 'cafe'

    monkeypatch.setattr(b4.pr, 'git_get_commit_id_from_repo_ref', _fake)
    lmsg = b4.pr.parse_pr_data(msg)
    assert lmsg is not None
    assert lmsg.pr_repo == 'git://example.com/repo.git'
    assert lmsg.pr_ref == 'refs/heads/master'
    assert captured['ref'] == 'refs/heads/master'


def test_parse_pr_data_no_repo_leaves_remote_tip_none() -> None:
    msg = _make_msg(body='No pull instructions here at all.\n')
    lmsg = b4.pr.parse_pr_data(msg)
    assert lmsg is not None
    assert lmsg.pr_repo is None
    assert lmsg.pr_remote_tip_commit is None


# ---------------------------------------------------------------------------
# git_get_commit_id_from_repo_ref: protocol handling and ref resolution
# ---------------------------------------------------------------------------
def test_repo_ref_rejects_unsupported_protocol() -> None:
    assert (
        b4.pr.git_get_commit_id_from_repo_ref('/local/path/repo.git', 'master') is None
    )
    assert (
        b4.pr.git_get_commit_id_from_repo_ref('ssh://host/repo.git', 'master') is None
    )


def test_repo_ref_resolves_head(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_lines(gitdir: Optional[str], args: List[str]) -> List[str]:
        if 'refs/heads/for-pull' in args:
            return ['abc123\trefs/heads/for-pull']
        return []

    monkeypatch.setattr(b4, 'git_get_command_lines', _fake_lines)
    cid = b4.pr.git_get_commit_id_from_repo_ref('git://example.com/r.git', 'for-pull')
    assert cid == 'abc123'


def test_repo_ref_returns_none_when_unresolved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(b4, 'git_get_command_lines', lambda gitdir, args: [])
    cid = b4.pr.git_get_commit_id_from_repo_ref('https://example.com/r.git', 'nope')
    assert cid is None


# ---------------------------------------------------------------------------
# fetch_remote: validation and the actual fetch
# ---------------------------------------------------------------------------
def test_fetch_remote_into_fetch_head(prremote: Dict[str, str]) -> None:
    _msg, lmsg = _make_lmsg(prremote)
    ecode = b4.pr.fetch_remote(None, lmsg, check_sig=False)
    assert ecode == 0
    fetched = b4.git_get_command_lines(None, ['rev-parse', 'FETCH_HEAD'])[0]
    assert fetched == prremote['tip']


def test_fetch_remote_into_branch(prremote: Dict[str, str]) -> None:
    _msg, lmsg = _make_lmsg(prremote)
    ecode = b4.pr.fetch_remote(None, lmsg, branch='pulled', check_sig=False)
    assert ecode == 0
    assert b4.git_branch_exists(None, 'pulled')
    head = b4.git_get_command_lines(None, ['rev-parse', 'pulled'])[0]
    assert head == prremote['tip']


def test_fetch_remote_unknown_base(prremote: Dict[str, str]) -> None:
    _msg, lmsg = _make_lmsg(prremote, base='0' * 40)
    ecode = b4.pr.fetch_remote(None, lmsg, check_sig=False)
    assert ecode == 1


def test_fetch_remote_tip_mismatch(prremote: Dict[str, str]) -> None:
    _msg, lmsg = _make_lmsg(prremote)
    lmsg.pr_remote_tip_commit = 'f' * 40
    ecode = b4.pr.fetch_remote(None, lmsg, check_sig=False)
    assert ecode == 1


def test_fetch_remote_missing_repo(prremote: Dict[str, str]) -> None:
    _msg, lmsg = _make_lmsg(prremote)
    lmsg.pr_repo = None
    ecode = b4.pr.fetch_remote(None, lmsg, check_sig=False)
    assert ecode == 1


def test_fetch_remote_records_ty(prremote: Dict[str, str]) -> None:
    _msg, lmsg = _make_lmsg(prremote)
    ecode = b4.pr.fetch_remote(None, lmsg, check_sig=False)
    assert ecode == 0
    prfile = os.path.join(b4.get_data_dir(), f'{prremote["tip"]}.pr')
    assert os.path.exists(prfile)
    with open(prfile, encoding='utf-8') as fh:
        data = json.load(fh)
    assert data['msgid'] == 'pull-1@example.com'
    assert data['remote'] == prremote['path']
    assert data['ref'] == 'for-pull'


def test_fetch_remote_skip_ty(prremote: Dict[str, str]) -> None:
    _msg, lmsg = _make_lmsg(prremote)
    ecode = b4.pr.fetch_remote(None, lmsg, check_sig=False, ty_track=False)
    assert ecode == 0
    prfile = os.path.join(b4.get_data_dir(), f'{prremote["tip"]}.pr')
    assert not os.path.exists(prfile)


# ---------------------------------------------------------------------------
# thanks_record_pr: tracking-record creation and de-duplication
# ---------------------------------------------------------------------------
def test_thanks_record_pr_dedups(prremote: Dict[str, str]) -> None:
    _msg, lmsg = _make_lmsg(prremote)
    b4.pr.thanks_record_pr(lmsg)
    b4.pr.thanks_record_pr(lmsg)
    datadir = b4.get_data_dir()
    prfiles = [f for f in os.listdir(datadir) if f.endswith('.pr')]
    assert prfiles == [f'{prremote["tip"]}.pr']


# ---------------------------------------------------------------------------
# main(): the "already have it" decision (regression coverage for the bug
# where b4 pr refused to fetch and skipped ty tracking)
# ---------------------------------------------------------------------------
def test_main_already_in_current_branch_records_ty(
    prremote: Dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Point the PR tip at the current branch HEAD => genuinely already present.
    head = b4.git_get_command_lines(None, ['rev-parse', 'HEAD'])[0]
    msg, lmsg = _make_lmsg(prremote, tip=head)
    _patch_main_lookups(monkeypatch, msg, lmsg)
    cmdargs = _parse_main_args([])
    with pytest.raises(SystemExit) as e:
        b4.pr.main(cmdargs)
    assert e.value.code == 1
    # Even though we refused to fetch, ty tracking must still be recorded.
    assert os.path.exists(os.path.join(b4.get_data_dir(), f'{head}.pr'))


def test_main_check_already_present_is_readonly(
    prremote: Dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    head = b4.git_get_command_lines(None, ['rev-parse', 'HEAD'])[0]
    msg, lmsg = _make_lmsg(prremote, tip=head)
    _patch_main_lookups(monkeypatch, msg, lmsg)
    cmdargs = _parse_main_args(['--check'])
    with pytest.raises(SystemExit) as e:
        b4.pr.main(cmdargs)
    assert e.value.code == 0
    # --check is a read-only probe: it must not write a ty record.
    assert not os.path.exists(os.path.join(b4.get_data_dir(), f'{head}.pr'))


def test_main_present_only_in_unrelated_branch_still_fetches(
    prremote: Dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Make the tip exist locally, but only on an unrelated branch -- the
    # current branch (master) does not contain it. b4 must NOT refuse.
    b4.git_run_command(None, ['fetch', prremote['path'], prremote['ref']])
    b4.git_run_command(None, ['branch', 'unrelated', 'FETCH_HEAD'])
    assert not b4.git_commit_is_ancestor(None, prremote['tip'], 'master')

    msg, lmsg = _make_lmsg(prremote)
    _patch_main_lookups(monkeypatch, msg, lmsg)
    cmdargs = _parse_main_args([])
    # Should fall through to a successful fetch and return without sys.exit.
    b4.pr.main(cmdargs)
    assert os.path.exists(os.path.join(b4.get_data_dir(), f'{prremote["tip"]}.pr'))


def test_main_not_present_fetches(
    prremote: Dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    msg, lmsg = _make_lmsg(prremote)
    _patch_main_lookups(monkeypatch, msg, lmsg)
    cmdargs = _parse_main_args([])
    b4.pr.main(cmdargs)
    fetched = b4.git_get_command_lines(None, ['rev-parse', 'FETCH_HEAD'])[0]
    assert fetched == prremote['tip']
    assert os.path.exists(os.path.join(b4.get_data_dir(), f'{prremote["tip"]}.pr'))


def test_main_fetch_into_branch(
    prremote: Dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    msg, lmsg = _make_lmsg(prremote)
    _patch_main_lookups(monkeypatch, msg, lmsg)
    cmdargs = _parse_main_args(['--branch', 'mybranch'])
    b4.pr.main(cmdargs)
    assert b4.git_branch_exists(None, 'mybranch')
    head = b4.git_get_command_lines(None, ['rev-parse', 'mybranch'])[0]
    assert head == prremote['tip']


def test_main_check_not_in_tree(
    prremote: Dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    msg, lmsg = _make_lmsg(prremote)
    _patch_main_lookups(monkeypatch, msg, lmsg)
    cmdargs = _parse_main_args(['--check'])
    with pytest.raises(SystemExit) as e:
        b4.pr.main(cmdargs)
    assert e.value.code == 0
    assert not os.path.exists(os.path.join(b4.get_data_dir(), f'{prremote["tip"]}.pr'))


def test_main_no_pr_info_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    msg = _make_msg()
    monkeypatch.setattr(b4, 'get_pi_thread_by_msgid', lambda m, **k: [msg])
    monkeypatch.setattr(b4.pr, 'parse_pr_data', lambda m: None)
    cmdargs = _parse_main_args([])
    with pytest.raises(SystemExit) as e:
        b4.pr.main(cmdargs)
    assert e.value.code == 1


# ---------------------------------------------------------------------------
# explode: turning a pull request into a patch series
# ---------------------------------------------------------------------------
def test_explode_generates_patches(prremote: Dict[str, str]) -> None:
    _msg, lmsg = _make_lmsg(prremote)
    msgs = b4.pr.explode(None, lmsg)
    assert len(msgs) >= 1
    subjects = ' '.join((m.get('Subject') or '') for m in msgs)
    assert 'pull-file' in subjects.lower()


# ---------------------------------------------------------------------------
# get_pr_from_github: building an lmsg from the GitHub API
# ---------------------------------------------------------------------------
class _FakeResp:
    def __init__(self, status: int, data: Dict[str, Any]) -> None:
        self.status_code = status
        self._data = data

    def json(self) -> Dict[str, Any]:
        return self._data


class _FakeSession:
    def __init__(self, responses: List[_FakeResp]) -> None:
        self._responses = list(responses)
        self.headers: Dict[str, str] = {}

    def get(self, url: str) -> _FakeResp:
        return self._responses.pop(0)


def test_get_pr_from_github(monkeypatch: pytest.MonkeyPatch) -> None:
    prdata = {
        'head': {
            'sha': 'tip123',
            'ref': 'feature',
            'repo': {'clone_url': 'https://github.com/u/r.git'},
        },
        'base': {'sha': 'base123'},
        'user': {'login': 'octocat'},
        'title': 'My PR',
        'body': 'Do the thing',
        'created_at': '2026-01-02T03:04:05Z',
    }
    userdata = {'name': 'Octo Cat', 'email': 'octo@example.com'}
    sess = _FakeSession([_FakeResp(200, prdata), _FakeResp(200, userdata)])
    monkeypatch.setattr(requests, 'session', lambda: sess)
    lmsg = b4.pr.get_pr_from_github('https://github.com/u/r/pull/42')
    assert lmsg is not None
    assert lmsg.pr_tip_commit == 'tip123'
    assert lmsg.pr_remote_tip_commit == 'tip123'
    assert lmsg.pr_base_commit == 'base123'
    assert lmsg.pr_repo == 'https://github.com/u/r.git'
    assert lmsg.pr_ref == 'feature'
    assert lmsg.full_subject.endswith('My PR')


def test_get_pr_from_github_error(monkeypatch: pytest.MonkeyPatch) -> None:
    sess = _FakeSession([_FakeResp(404, {})])
    monkeypatch.setattr(requests, 'session', lambda: sess)
    lmsg = b4.pr.get_pr_from_github('https://github.com/u/r/pull/42')
    assert lmsg is None
