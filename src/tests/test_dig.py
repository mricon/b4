# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Tests for b4 dig: finding the posted patch behind a commit.

The lore lookups are replaced with canned threads, so these tests pin how
dig picks the right posted patch once lore has answered: a Link: trailer
beats a patch-id match, a patch-id match is tried with every diff
algorithm, and the subject is the last resort.
"""

import argparse
import email
import email.message
import logging
import os
from typing import Dict, List, Optional
from unittest import mock

import pytest

import b4
import b4.dig

# The diff of this change differs between the myers and histogram
# algorithms, so its patch-id does too.
ALGO_OLD = """\
#include <stdio.h>

// Frobs foo heartily
int frobnitz(int foo)
{
    int i;
    for(i = 0; i < 10; i++)
    {
        printf("Your answer is: ");
        printf("%d\\n", foo);
    }
}

int fact(int n)
{
    if(n > 1)
    {
        return fact(n-1) * n;
    }
    return 1;
}

int main(int argc, char **argv)
{
    frobnitz(fact(10));
}
"""

ALGO_NEW = """\
#include <stdio.h>

int fib(int n)
{
    if(n > 2)
    {
        return fib(n-1) + fib(n-2);
    }
    return 1;
}

// Frobs foo heartily
int frobnitz(int foo)
{
    int i;
    for(i = 0; i < 10; i++)
    {
        printf("%d\\n", foo);
    }
}

int main(int argc, char **argv)
{
    frobnitz(fib(10));
}
"""


def _commit(gitdir: str, path: str, content: str, message: str) -> str:
    with open(os.path.join(gitdir, path), 'w') as fh:
        fh.write(content)
    ecode, _out = b4.git_run_command(gitdir, ['add', path])
    assert ecode == 0
    ecode, _out = b4.git_run_command(
        gitdir, ['commit', '-q', '-F', '-'], stdin=message.encode()
    )
    assert ecode == 0
    return b4.git_revparse_obj('HEAD', gitdir)


def _posted(
    gitdir: str, commit: str, msgid: str, prefix: str = 'PATCH', algo: str = 'myers'
) -> email.message.EmailMessage:
    """The patch as its author would have sent it, made with *algo*."""
    ecode, out = b4.git_run_command(
        gitdir,
        [
            'format-patch',
            '-1',
            '--stdout',
            f'--subject-prefix={prefix}',
            f'--diff-algorithm={algo}',
            commit,
        ],
        decode=False,
    )
    assert ecode == 0
    msg = email.message_from_bytes(out, policy=b4.emlpolicy)
    assert isinstance(msg, email.message.EmailMessage)
    msg['Message-Id'] = f'<{msgid}>'
    return msg


def _patch_id(gitdir: str, commit: str, algo: str) -> str:
    ecode, out = b4.git_run_command(
        gitdir,
        ['show', '--format=email', f'--diff-algorithm={algo}', commit],
        decode=False,
    )
    assert ecode == 0
    ecode, pid = b4.git_run_command(gitdir, ['patch-id', '--stable'], stdin=out)
    assert ecode == 0
    return pid.split()[0]


def _serve_threads(
    monkeypatch: pytest.MonkeyPatch,
    threads: Dict[str, List[email.message.EmailMessage]],
) -> None:
    """Make lore answer thread lookups from *threads*, keyed by message-id."""

    def _get_series(msgid: str, nocache: bool = False) -> Optional[b4.LoreMailbox]:
        lmbx = b4.LoreMailbox()
        for msg in threads.get(msgid, []):
            lmbx.add_message(msg)
        return lmbx

    monkeypatch.setattr(b4, 'get_series_by_msgid', _get_series)


def _dig(commit: str, **kwargs: object) -> None:
    args: Dict[str, object] = {
        'commitish': commit,
        'nocache': False,
        'all_series': False,
        'save_mbox': None,
        'who': False,
    }
    args.update(kwargs)
    b4.dig.dig_commitish(argparse.Namespace(**args))


def _link(msgid: str) -> str:
    return str(b4.get_main_config()['linkmask']) % msgid


@pytest.mark.parametrize(
    'trailer',
    ['Link: https://patch.msgid.link/v1@example.com', 'Message-ID: <v1@example.com>'],
)
def test_linked_message_id_beats_newer_patch_id_match(
    gitdir: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    trailer: str,
) -> None:
    """Both revisions carry the same diff; the one the commit names wins.

    Without this preference dig would pick the newest revision, which is
    the wrong one when a maintainer applied an earlier revision. The
    message-id can come from a Link: trailer or, with b4 am -i, from a
    Message-ID: trailer. v2 also adds a patch, because revisions with
    identical patches count as one series and only the newest is kept.
    """
    commit = _commit(
        gitdir, 'file1.txt', 'linked change\n', f'dig: linked change\n\n{trailer}\n'
    )
    extra = _commit(gitdir, 'file2.txt', 'extra change\n', 'dig: extra change\n')
    v1 = _posted(gitdir, commit, 'v1@example.com')
    v2 = [
        _posted(gitdir, sha, f'v2-{at}@example.com', prefix=f'PATCH v2 {at}/2')
        for at, sha in ((1, commit), (2, extra))
    ]
    for msg in v2:
        msg.replace_header('Date', 'Tue, 01 Jan 2030 00:00:00 +0000')
    monkeypatch.setattr(b4, 'get_msgs_by_patch_id', mock.Mock(return_value=[v1, v2[0]]))
    _serve_threads(monkeypatch, {'v1@example.com': [v1], 'v2-1@example.com': v2})

    _dig(commit)

    assert capsys.readouterr().out == _link('v1@example.com') + '\n'


def test_patch_id_is_tried_with_other_diff_algorithms(
    gitdir: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A patch made with histogram is still found from a commit diffed with myers.

    The patch-id depends on the diff algorithm, so a single algorithm would
    miss postings whose author's git used another one. The maintainer
    reworded the subject, so the subject cannot rescue a missed patch-id.
    """
    base = _commit(gitdir, 'algo.c', ALGO_OLD, 'dig: add algo.c\n')
    posted_commit = _commit(
        gitdir, 'algo.c', ALGO_NEW, 'dig: switch to fib, as posted\n'
    )
    posted = _posted(gitdir, posted_commit, 'histo@example.com', algo='histogram')
    ecode, _out = b4.git_run_command(gitdir, ['reset', '-q', '--hard', base])
    assert ecode == 0
    commit = _commit(gitdir, 'algo.c', ALGO_NEW, 'dig: switch to fib\n')
    histogram_id = _patch_id(gitdir, commit, 'histogram')
    assert _patch_id(gitdir, commit, 'myers') != histogram_id
    lookup = mock.Mock(
        side_effect=lambda pid, **kw: [posted] if pid == histogram_id else []
    )
    monkeypatch.setattr(b4, 'get_msgs_by_patch_id', lookup)
    _serve_threads(monkeypatch, {'histo@example.com': [posted]})

    _dig(commit)

    assert capsys.readouterr().out == _link('histo@example.com') + '\n'
    assert [c.args[0] for c in lookup.call_args_list][-1] == histogram_id


@pytest.mark.parametrize('inbody_from', [False, True])
def test_edited_patch_is_found_by_subject(
    gitdir: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    inbody_from: bool,
) -> None:
    """A maintainer edited the diff, so only the subject still matches.

    The second lore query looks for the in-body From: line that git am
    turns into the commit author when the sender differs from the author.
    """
    base = b4.git_revparse_obj('HEAD', gitdir)
    posted_commit = _commit(gitdir, 'file1.txt', 'as posted\n', 'dig: edited change\n')
    posted = _posted(gitdir, posted_commit, 'edited@example.com')
    ecode, _out = b4.git_run_command(gitdir, ['reset', '-q', '--hard', base])
    assert ecode == 0
    commit = _commit(gitdir, 'file1.txt', 'as applied\n', 'dig: edited change\n')
    monkeypatch.setattr(b4, 'get_msgs_by_patch_id', mock.Mock(return_value=[]))
    answers = [[], [posted]] if inbody_from else [[posted]]
    search = mock.Mock(side_effect=answers)
    monkeypatch.setattr(b4, 'get_pi_search_results', search)
    _serve_threads(monkeypatch, {'edited@example.com': [posted]})

    _dig(commit)

    assert capsys.readouterr().out == _link('edited@example.com') + '\n'
    queries = [c.args[0] for c in search.call_args_list]
    assert 's:"dig: edited change"' in queries[0]
    assert f'f:"{b4.USER_CONFIG["email"]}"' in queries[0]
    if inbody_from:
        author = f'From: {b4.USER_CONFIG["name"]} <{b4.USER_CONFIG["email"]}>'
        assert f'nq:"{author}"' in queries[1]


def test_nothing_found_suggests_link_trailers(
    gitdir: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """With no match anywhere, dig fails and points at the commit's links."""
    commit = _commit(
        gitdir,
        'file1.txt',
        'lost change\n',
        'dig: lost change\n\nLink: https://example.org/discussion\n',
    )
    monkeypatch.setattr(b4, 'get_msgs_by_patch_id', mock.Mock(return_value=[]))
    monkeypatch.setattr(b4, 'get_pi_search_results', mock.Mock(return_value=[]))

    with caplog.at_level(logging.INFO, logger='b4'), pytest.raises(SystemExit) as exc:
        _dig(commit)

    assert exc.value.code == 1
    assert 'Link: https://example.org/discussion' in caplog.text


def test_all_series_links_the_matching_patch_of_each_revision(
    gitdir: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """--all-series lists every revision, linking the patch the commit came from.

    The commit is patch 1 of each revision, so a revision where nothing
    matched would link patch 2 instead. The maintainer reworded v1's
    subject, so v1 is matched only by patch-id; v2 changed the diff, so it
    is matched only by subject.
    """
    base = b4.git_revparse_obj('HEAD', gitdir)
    thread: List[email.message.EmailMessage] = []
    posted = (
        (1, 'target\n', 'dig: target patch, as posted\n'),
        (2, 'target, reworked\n', 'dig: target patch\n'),
    )
    for rev, content, subject in posted:
        ecode, _out = b4.git_run_command(gitdir, ['reset', '-q', '--hard', base])
        assert ecode == 0
        target = _commit(gitdir, 'file2.txt', content, subject)
        other = _commit(gitdir, 'file1.txt', 'other\n', 'dig: other patch\n')
        prefix = 'PATCH' if rev == 1 else f'PATCH v{rev}'
        for at, sha in ((1, target), (2, other)):
            msg = _posted(
                gitdir, sha, f'v{rev}-{at}@example.com', prefix=f'{prefix} {at}/2'
            )
            msg.replace_header('Date', f'Mon, 0{rev} Jan 2024 00:00:0{at} +0000')
            thread.append(msg)
    ecode, _out = b4.git_run_command(gitdir, ['reset', '-q', '--hard', base])
    assert ecode == 0
    commit = _commit(gitdir, 'file2.txt', 'target\n', 'dig: target patch\n')
    monkeypatch.setattr(b4, 'get_msgs_by_patch_id', mock.Mock(return_value=thread[:1]))
    _serve_threads(monkeypatch, {'v1-1@example.com': thread})

    with caplog.at_level(logging.INFO, logger='b4'):
        _dig(commit, all_series=True)

    assert _link('v1-1@example.com') in caplog.text
    assert _link('v2-1@example.com') in caplog.text
    assert _link('v1-2@example.com') not in caplog.text
    assert _link('v2-2@example.com') not in caplog.text
