import pytest
import os
import b4
import b4.mbox
import b4.command

from email.message import EmailMessage
from typing import Any, Dict, List
from unittest.mock import patch as mock_patch


@pytest.mark.parametrize('mboxf, shazamargs, compareargs, compareout, b4cfg', [
    ('shazam-git1-just-series', [],
     ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD~4..'], 'shazam-git1-just-series-defaults', {}),
    ('shazam-git1-just-series', ['-H'],
     ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD..FETCH_HEAD'], 'shazam-git1-just-series-defaults', {}),
    ('shazam-git1-just-series', ['-M'],
     ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD^..'], 'shazam-git1-just-series-merged', {}),
    # --add-link: Link: trailers are appended to each patch
    ('shazam-git1-just-series', ['--add-link'],
     ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD~4..'], 'shazam-git1-just-series-addlink', {}),
    # --add-link with pre-existing Link: in patch bodies: no duplicates
    ('shazam-git1-with-link', ['--add-link'],
     ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD~4..'], 'shazam-git1-just-series-addlink', {}),
])
def test_shazam(sampledir: str, gitdir: str, mboxf: str, shazamargs: List[str], compareargs: List[str], compareout: str, b4cfg: Dict[str, Any]) -> None:
    b4.MAIN_CONFIG.update(b4cfg)
    mfile = os.path.join(sampledir, f'{mboxf}.mbox')
    cfile = os.path.join(sampledir, f'{compareout}.verify')
    assert os.path.exists(mfile)
    assert os.path.exists(cfile)
    parser = b4.command.setup_parser()
    shazamargs = ['--no-stdin', '--no-interactive', '--offline-mode', 'shazam', '-m', mfile] + shazamargs
    cmdargs = parser.parse_args(shazamargs)
    with pytest.raises(SystemExit) as e:
        b4.mbox.main(cmdargs)
        assert e.value.code == 0
    out, logstr = b4.git_run_command(None, compareargs)
    assert out == 0
    with open(cfile, 'r') as fh:
        cstr = fh.read()
    assert logstr == cstr


def _make_msg(subject: str, from_addr: str, date: str,
              body: str = '', msgid: str = '') -> EmailMessage:
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['Date'] = date
    msg['Message-Id'] = msgid or f'<{abs(hash(subject + date))}@example.com>'
    msg.set_payload(body)
    return msg


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
        body=(
            'v2: split into two patches.\n\n'
            f'change-id: {change_id}\n'
        ),
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
