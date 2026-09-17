#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Unit tests for the machine-readable "b4 bugs list" output.

Deliberately free of any ``textual`` dependency: the JSON listing is a
plain CLI surface, so an agent must be able to call it on a box that only
has the ``[bugs]`` extra installed.
"""

import argparse
import json
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Set

import pytest

import b4.bugs

# Not importorskip('ezgb'): the ezgb submodule directory in a b4 checkout
# shadows the real package as an empty namespace package, so a bare import
# succeeds even when the optional [bugs] extra is not installed.
if not b4.bugs.has_ezgb():
    pytest.skip('needs the optional [bugs] extra', allow_module_level=True)

from b4.bugs import bug_message_ids, bug_to_dict, cmd_list
from ezgb import Bug, Comment, Identity, Status

_EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)
_IDENTITY = Identity(id='test', name='Test', email='test@test.com', login='')


def _comment(msgid: Optional[str], *, offset: int = 0, body: str = 'Hi') -> Comment:
    """Build a comment whose body carries an RFC 2822 header block."""
    if msgid is None:
        text = body
    else:
        text = f'From: Alice <alice@example.com>\nMessage-ID: <{msgid}>\n\n{body}'
    return Comment(
        id='c0ffee' * 11,
        author=_IDENTITY,
        text=text,
        created_at=_EPOCH + timedelta(hours=offset),
        count=offset,
        attachment_ids=[],
    )


def _bug(
    *,
    bug_id: str = 'deadbeef' * 8,
    title: str = 'Something is broken',
    status: Status = Status.OPEN,
    labels: Optional[Set[str]] = None,
    comments: Optional[List[Comment]] = None,
) -> Bug:
    return Bug(
        id=bug_id,
        title=title,
        status=status,
        creator=_IDENTITY,
        created_at=_EPOCH,
        labels=labels or set(),
        comments=comments or [],
    )


class _FakeRepo:
    """Stands in for GitBugRepo, recording how list_bugs() was called."""

    def __init__(self, bugs: List[Bug]) -> None:
        self.bugs = bugs
        self.calls: List[Any] = []

    def list_bugs(self, status: Any = None, label: Any = None) -> List[Bug]:
        self.calls.append((status, label))
        return self.bugs


def _args(**kwargs: Any) -> argparse.Namespace:
    base = {
        'status': None,
        'label': None,
        'json_output': False,
        'no_interactive': False,
    }
    base.update(kwargs)
    return argparse.Namespace(**base)


def _run(
    monkeypatch: pytest.MonkeyPatch, bugs: List[Bug], **kwargs: Any
) -> '_FakeRepo':
    repo = _FakeRepo(bugs)
    monkeypatch.setattr(b4.bugs, '_get_repo', lambda cmdargs=None: repo)
    cmd_list(_args(**kwargs))
    return repo


class TestBugMessageIds:
    def test_first_comment_is_the_root(self) -> None:
        bug = _bug(comments=[_comment('root@x'), _comment('reply@x', offset=1)])
        root, followups = bug_message_ids(bug)
        assert root == 'root@x'
        assert followups == ['reply@x']

    def test_no_comments_means_no_msgids(self) -> None:
        assert bug_message_ids(_bug()) == (None, [])

    def test_manually_filed_bug_has_no_root(self) -> None:
        # A bug created in the TUI rather than imported has a plain
        # first comment with no header block at all.
        bug = _bug(comments=[_comment(None)])
        assert bug_message_ids(bug) == (None, [])

    def test_headerless_followups_are_dropped(self) -> None:
        bug = _bug(comments=[_comment('root@x'), _comment(None, offset=1)])
        assert bug_message_ids(bug) == ('root@x', [])

    def test_tombstoned_comments_still_count(self) -> None:
        # make_tombstone() keeps the Message-ID, so a redacted comment is
        # still a message we have captured and must not re-propose.
        from b4.bugs._import import make_tombstone

        gone = _comment('gone@x', offset=1)
        bug = _bug(
            comments=[
                _comment('root@x'),
                Comment(
                    id=gone.id,
                    author=gone.author,
                    text=make_tombstone(gone.text, 'test'),
                    created_at=gone.created_at,
                    count=1,
                    attachment_ids=[],
                ),
            ]
        )
        assert bug_message_ids(bug) == ('root@x', ['gone@x'])


class TestBugToDict:
    def test_shape(self) -> None:
        bug = _bug(
            labels={'zebra', 'apple'},
            comments=[_comment('root@x'), _comment('reply@x', offset=5)],
        )
        entry = bug_to_dict(bug)
        assert entry == {
            'id': 'deadbeef' * 8,
            'title': 'Something is broken',
            'status': 'open',
            'labels': ['apple', 'zebra'],
            'root_msgid': 'root@x',
            'comment_msgids': ['reply@x'],
            'last_activity': (_EPOCH + timedelta(hours=5)).isoformat(),
        }

    def test_closed_status(self) -> None:
        assert bug_to_dict(_bug(status=Status.CLOSED))['status'] == 'closed'

    def test_last_activity_falls_back_to_creation(self) -> None:
        assert bug_to_dict(_bug())['last_activity'] == _EPOCH.isoformat()

    def test_is_json_serialisable(self) -> None:
        bug = _bug(labels={'lifecycle:triaged'}, comments=[_comment('root@x')])
        assert json.loads(json.dumps(bug_to_dict(bug)))['labels'] == [
            'lifecycle:triaged'
        ]


class TestCmdListJson:
    def test_emits_an_array(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bugs = [
            _bug(bug_id='aaaa' * 16, comments=[_comment('one@x')]),
            _bug(bug_id='bbbb' * 16, comments=[_comment('two@x')]),
        ]
        _run(monkeypatch, bugs, json_output=True)
        entries = json.loads(capsys.readouterr().out)
        assert [e['root_msgid'] for e in entries] == ['one@x', 'two@x']

    def test_empty_result_is_still_valid_json(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _run(monkeypatch, [], json_output=True)
        assert json.loads(capsys.readouterr().out) == []

    def test_filters_are_passed_through(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        repo = _run(
            monkeypatch, [], json_output=True, status='closed', label='lifecycle:fixed'
        )
        assert repo.calls == [(Status.CLOSED, 'lifecycle:fixed')]
        capsys.readouterr()

    def test_human_output_does_not_go_to_stdout(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # The default listing prints through the logger, which is exactly
        # why the JSON mode had to be added -- guard that split.
        with caplog.at_level('INFO', logger='b4'):
            _run(monkeypatch, [_bug(comments=[_comment('one@x')])])
        assert capsys.readouterr().out == ''
        assert 'Something is broken' in caplog.text
