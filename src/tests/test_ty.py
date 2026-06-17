from typing import List, Optional, Tuple

import pytest

import b4
import b4.ty


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


def test_parse_ty_review_rejects_edited_subject() -> None:
    """Editing an item subject breaks the positional contract and aborts."""
    sections = _review_sections()
    text = b4.ty.render_ty_review(sections).decode('utf-8')
    text = text.replace('Add frobnicator support', 'Add frobnicator SUPPORT')
    with pytest.raises(ValueError):
        b4.ty.parse_ty_review(text.encode('utf-8'), sections)


def test_parse_ty_review_rejects_count_mismatch() -> None:
    """Removing an item line entirely also aborts (ambiguous edit)."""
    sections = _review_sections()
    text = b4.ty.render_ty_review(sections).decode('utf-8')
    text = text.replace('+ [GIT PULL] frobnicator updates\n', '')
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


def test_interactive_ty_review_drops_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Marking an item 'x' drops it from the returned list; the kept item
    survives, in order. Skipped items are simply omitted (no persistence).
    """
    applied: List[b4.ty.JsonDictT] = [
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

    def fake_edit(bdata: bytes, filehint: str = 'COMMIT_EDITMSG') -> bytes:
        # Maintainer skips the pull request, keeps the patch series.
        text = bdata.decode('utf-8').replace('+ [GIT PULL]', 'x [GIT PULL]')
        return text.encode('utf-8')

    monkeypatch.setattr(b4, 'edit_in_editor', fake_edit)

    kept = b4.ty.interactive_ty_review(applied, None)
    assert [jd['subject'] for jd in kept] == ['[PATCH 0/2] Add frobnicator support']


def test_interactive_ty_review_keeps_all_when_pristine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unedited buffer keeps the full list unchanged, in order."""
    applied: List[b4.ty.JsonDictT] = [
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

    def fake_edit(bdata: bytes, filehint: str = 'COMMIT_EDITMSG') -> bytes:
        return bdata

    monkeypatch.setattr(b4, 'edit_in_editor', fake_edit)

    kept = b4.ty.interactive_ty_review(applied, None)
    assert kept == applied


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
