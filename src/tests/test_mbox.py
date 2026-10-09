import argparse
import io
import logging
import mailbox
import os
import sys
from email.message import EmailMessage
from pathlib import Path
from typing import List, Optional
from unittest.mock import patch as mock_patch

import pytest

import b4
import b4.command
import b4.mbox

from .helpers.mail import MINIMAL_DIFF, make_msg


def test_minimize_thread_preserves_reply_separator() -> None:
    body = 'First review comment.\n\n---\n\nSecond review comment.\n'
    msg = make_msg('reply@example.com', 'Re: [PATCH] A change', body=body)

    (minimized,) = b4.mbox.minimize_thread([msg])
    decoded_body, _ = b4.LoreMessage.get_payload(minimized)

    assert decoded_body.strip() == body.strip()


@pytest.mark.parametrize(
    'mboxf, shazamargs, compareargs, compareout',
    [
        (
            'shazam-git1-just-series',
            [],
            ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD~4..'],
            'shazam-git1-just-series-defaults',
        ),
        (
            'shazam-git1-just-series',
            ['-H'],
            ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD..FETCH_HEAD'],
            'shazam-git1-just-series-defaults',
        ),
        (
            'shazam-git1-just-series',
            ['-M'],
            ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD^..'],
            'shazam-git1-just-series-merged',
        ),
        # --add-link: Link: trailers are appended to each patch
        (
            'shazam-git1-just-series',
            ['--add-link'],
            ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD~4..'],
            'shazam-git1-just-series-addlink',
        ),
        # --add-link with pre-existing Link: in patch bodies: no duplicates
        (
            'shazam-git1-with-link',
            ['--add-link'],
            ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD~4..'],
            'shazam-git1-just-series-addlink',
        ),
    ],
)
def test_shazam(
    sampledir: str,
    gitdir: str,
    mboxf: str,
    shazamargs: List[str],
    compareargs: List[str],
    compareout: str,
) -> None:
    mfile = os.path.join(sampledir, f'{mboxf}.mbox')
    cfile = os.path.join(sampledir, f'{compareout}.verify')
    assert os.path.exists(mfile)
    assert os.path.exists(cfile)
    parser = b4.command.setup_parser()
    shazamargs = [
        '--no-stdin',
        '--no-interactive',
        '--offline-mode',
        'shazam',
        '-m',
        mfile,
    ] + shazamargs
    cmdargs = parser.parse_args(shazamargs)
    with pytest.raises(SystemExit) as e:
        b4.mbox.main(cmdargs)
    assert e.value.code == 0
    out, logstr = b4.git_run_command(None, compareargs)
    assert out == 0
    with open(cfile, 'r') as fh:
        cstr = fh.read()
    assert logstr == cstr


def test_shazam_merge_stdin_at_eof(
    sampledir: str, gitdir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # bug bdb9c9b: with the mbox piped in, stdin is at EOF (and not a tty)
    # by the time the -M merge confirmation prompt runs; shazam must fall
    # back to non-interactive behaviour instead of dying with EOFError
    mfile = os.path.join(sampledir, 'shazam-git1-just-series.mbox')
    cfile = os.path.join(sampledir, 'shazam-git1-just-series-merged.verify')
    assert os.path.exists(mfile)
    assert os.path.exists(cfile)
    parser = b4.command.setup_parser()
    cmdargs = parser.parse_args(
        ['--no-stdin', '--offline-mode', 'shazam', '-m', mfile, '-M']
    )
    monkeypatch.setattr(sys, 'stdin', io.StringIO(''))
    with pytest.raises(SystemExit) as e:
        b4.mbox.main(cmdargs)
    assert e.value.code == 0
    out, logstr = b4.git_run_command(
        None, ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD^..']
    )
    assert out == 0
    with open(cfile, 'r') as fh:
        cstr = fh.read()
    assert logstr == cstr


def _make_msg(
    subject: str, from_addr: str, date: str, body: str = '', msgid: str = ''
) -> EmailMessage:
    msgid = msgid.strip('<>') or f'{abs(hash(subject + date))}@example.com'
    return make_msg(msgid, subject, from_addr=from_addr, date=date, body=body)


def test_mbox_all_revisions_from_middle_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(b4, 'can_network', True)
    author = 'Author <author@example.com>'
    v1 = _make_msg(
        '[PATCH] foo: fix bar',
        author,
        'Mon, 21 Sep 2026 10:00:00 +0000',
        msgid='<v1@example.com>',
    )
    v1_reply = _make_msg(
        'Re: [PATCH] foo: fix bar',
        author,
        'Mon, 21 Sep 2026 11:00:00 +0000',
        msgid='<v1-reply@example.com>',
    )
    v2 = _make_msg(
        '[PATCH v2] foo: fix bar',
        author,
        'Tue, 22 Sep 2026 10:00:00 +0000',
        msgid='<v2@example.com>',
    )
    v3 = _make_msg(
        '[PATCH v3] foo: fix bar',
        author,
        'Wed, 23 Sep 2026 10:00:00 +0000',
        msgid='<v3@example.com>',
    )
    v3_reply = _make_msg(
        'Re: [PATCH v3] foo: fix bar',
        author,
        'Wed, 23 Sep 2026 11:00:00 +0000',
        msgid='<v3-reply@example.com>',
    )

    parser = b4.command.setup_parser()
    cmdargs = parser.parse_args(
        [
            '--no-stdin',
            'mbox',
            '-a',
            '-o',
            str(tmp_path),
            '-n',
            'all.mbox',
            'v2@example.com',
        ]
    )
    with (
        mock_patch('b4.retrieve_messages', return_value=('v2@example.com', [v2])),
        mock_patch(
            'b4.get_pi_search_results',
            side_effect=[
                [v3_reply, v3],
                [v1_reply, v1],
            ],
        ),
    ):
        b4.mbox.main(cmdargs)

    output = mailbox.mbox(tmp_path / 'all.mbox')
    assert [msg['Message-Id'] for msg in output] == [
        '<v1@example.com>',
        '<v1-reply@example.com>',
        '<v2@example.com>',
        '<v3@example.com>',
        '<v3-reply@example.com>',
    ]


def test_get_extra_series_rejects_prerequisite_change_id() -> None:
    """Series listing a change-id as prerequisite must not be
    treated as newer revisions of that series."""
    change_id = '20251231-test-fix-abc123def456'

    # Original v1 patch with its own change-id
    original = _make_msg(
        '[PATCH] foo: fix bar syntax',
        'Author <author@example.com>',
        'Wed, 31 Dec 2025 10:00:00 +0000',
        body=(
            'Fix bar.\n\n'
            'Signed-off-by: Author <author@example.com>\n'
            f'change-id: {change_id}\n'
        ),
        msgid='<original-v1@example.com>',
    )

    # Unrelated v2 series that lists the change-id as a prerequisite
    unrelated_cover = _make_msg(
        '[PATCH v2 0/3] baz: add new feature',
        'Other <other@example.com>',
        'Mon, 05 Jan 2026 10:00:00 +0000',
        body=(
            'This series adds a new feature.\n\n'
            'change-id: 20260105-baz-feature-xyz789\n'
            f'prerequisite-change-id: {change_id}:v1\n'
        ),
        msgid='<unrelated-v2-cover@example.com>',
    )
    unrelated_patches = [
        _make_msg(
            f'[PATCH v2 {i}/3] baz: add feature part {i}',
            'Other <other@example.com>',
            'Mon, 05 Jan 2026 10:00:00 +0000',
            body=f'Part {i}.\n\nSigned-off-by: Other <other@example.com>\n',
            msgid=f'<unrelated-v2-{i}@example.com>',
        )
        for i in range(1, 4)
    ]

    search_results = [unrelated_cover] + unrelated_patches

    with mock_patch('b4.get_pi_search_results', return_value=search_results):
        result = b4.mbox.get_extra_series([original], direction=1)

    # Should only contain the original message
    result_msgids = {b4.LoreMessage.get_clean_msgid(m) for m in result}
    assert 'original-v1@example.com' in result_msgids
    assert 'unrelated-v2-cover@example.com' not in result_msgids
    assert len(result) == 1


def test_get_extra_series_accepts_matching_change_id() -> None:
    """Legitimate newer revisions with the same change-id must be included."""
    change_id = '20251231-test-fix-abc123def456'

    # Original v1 patch
    original = _make_msg(
        '[PATCH] foo: fix bar syntax',
        'Author <author@example.com>',
        'Wed, 31 Dec 2025 10:00:00 +0000',
        body=(
            'Fix bar.\n\n'
            'Signed-off-by: Author <author@example.com>\n'
            f'change-id: {change_id}\n'
        ),
        msgid='<original-v1@example.com>',
    )

    # Legitimate v2 with the same change-id
    v2_cover = _make_msg(
        '[PATCH v2 0/2] foo: fix bar syntax',
        'Author <author@example.com>',
        'Fri, 03 Jan 2026 10:00:00 +0000',
        body=(f'v2: split into two patches.\n\nchange-id: {change_id}\n'),
        msgid='<v2-cover@example.com>',
    )
    v2_patches = [
        _make_msg(
            f'[PATCH v2 {i}/2] foo: fix bar part {i}',
            'Author <author@example.com>',
            'Fri, 03 Jan 2026 10:00:00 +0000',
            body=f'Part {i}.\n\nSigned-off-by: Author <author@example.com>\n',
            msgid=f'<v2-{i}@example.com>',
        )
        for i in range(1, 3)
    ]

    search_results = [v2_cover] + v2_patches

    with mock_patch('b4.get_pi_search_results', return_value=search_results):
        result = b4.mbox.get_extra_series([original], direction=1)

    # Should contain the original plus the v2 series
    result_msgids = {b4.LoreMessage.get_clean_msgid(m) for m in result}
    assert 'original-v1@example.com' in result_msgids
    assert 'v2-cover@example.com' in result_msgids
    assert 'v2-1@example.com' in result_msgids
    assert 'v2-2@example.com' in result_msgids
    assert len(result) == 4


@pytest.mark.parametrize(
    'tree,hint',
    [
        (
            'https://git.kernel.org/pub/scm/utils/b4/b4.git master',
            'git fetch https://git.kernel.org/pub/scm/utils/b4/b4.git ',
        ),
        (
            'git://git.kernel.org/pub/scm/utils/b4/b4.git master',
            'git fetch git://git.kernel.org/pub/scm/utils/b4/b4.git ',
        ),
        # Only https:// and git:// are ever suggested
        ('ssh://example.org/b4.git master', None),
        ('ext::sh%20-c%20touch%20pwned', None),
        ('git://example.org/b4.git; rm -rf ~', None),
    ],
)
def test_unknown_base_suggests_base_tree_fetch(
    gitdir: str, caplog: pytest.LogCaptureFixture, tree: str, hint: Optional[str]
) -> None:
    base = 'f' * 40
    body = f'Series\n\n---\nbase-commit: {base}\nbase-tree: {tree}\n'
    lmbx = b4.LoreMailbox()
    lmbx.add_message(make_msg('cover@example.com', '[PATCH 0/1] Series', body=body))
    lmbx.add_message(
        make_msg(
            'patch@example.com',
            '[PATCH 1/1] Patch',
            body=MINIMAL_DIFF,
            in_reply_to='cover@example.com',
        )
    )
    lser = lmbx.get_series(codereview_trailers=False)
    assert lser is not None
    cmdargs = argparse.Namespace(mergebase=False, guessbase=False)
    with caplog.at_level(logging.WARNING):
        assert b4.mbox.get_base_commit(gitdir, body, lser, cmdargs) == 'HEAD'
    assert f'base-commit {base} not known' in caplog.text
    if hint is None:
        assert lser.base_tree is None
        assert 'git fetch' not in caplog.text
    else:
        assert lser.base_tree == tuple(tree.split())
        assert f'{hint}{base}' in caplog.text
