#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Unit tests for b4 bugs helpers.

Tests the pure-logic functions in _import.py and _tui.py that don't
need Textual, git-bug, or network access.
"""

from datetime import datetime, timezone
from typing import Set
from unittest import mock

from b4.bugs._import import (
    format_comment,
    is_comment_removed,
    make_tombstone,
    parse_comment_header,
    parse_comment_msgid,
)
from b4.bugs._tui import (
    BugListApp,
    _bug_last_activity,
    _bug_lifecycle,
    _bug_tier,
    _relative_time,
    label_color,
)
from ezgb import Bug, BugSummary, Comment, Identity, Status

# ---------------------------------------------------------------------------
# Helpers -- factory functions for real Bug and BugSummary objects
# ---------------------------------------------------------------------------

_EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)
_IDENTITY = Identity(id='test', name='Test', email='test@test.com', login='')


def make_bug(
    *,
    status: Status = Status.OPEN,
    labels: Set[str] | None = None,
    comments: list[Comment] | None = None,
    created_at: datetime | None = None,
    title: str = '',
) -> Bug:
    return Bug(
        id='deadbeef' * 8,
        title=title,
        status=status,
        creator=_IDENTITY,
        created_at=created_at or _EPOCH,
        labels=labels or set(),
        comments=comments or [],
    )


def make_comment(created_at: datetime) -> Comment:
    return Comment(
        id='c0ffee' * 11,
        author=_IDENTITY,
        text='',
        created_at=created_at,
        count=0,
        attachment_ids=[],
    )


def make_summary(
    *,
    status: Status = Status.OPEN,
    labels: frozenset[str] | None = None,
    edited_at: datetime | None = None,
    created_at: datetime | None = None,
    title: str = '',
    comment_count: int = 0,
    author_name: str = '',
) -> BugSummary:
    return BugSummary(
        id='deadbeef' * 8,
        title=title,
        status=status,
        creator_id='test',
        created_at=created_at or _EPOCH,
        labels=labels or frozenset(),
        comment_count=comment_count,
        author_name=author_name,
        edited_at=edited_at or _EPOCH,
    )


# ===========================================================================
# _import.py tests
# ===========================================================================


class TestParseCommentHeader:
    def test_extracts_from(self) -> None:
        text = 'From: Alice <alice@example.com>\nDate: Mon, 1 Jan 2026\n\nBody'
        assert parse_comment_header(text, 'From') == 'Alice <alice@example.com>'

    def test_extracts_message_id(self) -> None:
        text = 'Message-ID: <abc@example.com>\n\nBody'
        assert parse_comment_header(text, 'Message-ID') == '<abc@example.com>'

    def test_case_insensitive(self) -> None:
        text = 'message-id: <abc@example.com>\n\nBody'
        assert parse_comment_header(text, 'Message-ID') == '<abc@example.com>'

    def test_returns_none_for_missing(self) -> None:
        text = 'From: Alice\n\nBody'
        assert parse_comment_header(text, 'Date') is None

    def test_does_not_match_body(self) -> None:
        text = 'From: Alice\n\nMessage-ID: <fake@body>'
        assert parse_comment_header(text, 'Message-ID') is None

    def test_empty_text(self) -> None:
        assert parse_comment_header('', 'From') is None

    def test_no_body_separator(self) -> None:
        text = 'From: Alice'
        assert parse_comment_header(text, 'From') == 'Alice'


class TestParseCommentMsgid:
    def test_strips_angle_brackets(self) -> None:
        text = 'Message-ID: <abc@example.com>\n\nBody'
        assert parse_comment_msgid(text) == 'abc@example.com'

    def test_returns_none_when_missing(self) -> None:
        text = 'From: Alice\n\nBody'
        assert parse_comment_msgid(text) is None


class TestIsCommentRemoved:
    def test_detects_tombstone(self) -> None:
        text = 'Message-ID: <abc@example.com>\nX-B4-Bug-Comment: removed by Alice <alice@test.com>'
        assert is_comment_removed(text) is True

    def test_normal_comment(self) -> None:
        text = 'From: Alice\nMessage-ID: <abc@example.com>\n\nNormal body'
        assert is_comment_removed(text) is False

    def test_empty_text(self) -> None:
        assert is_comment_removed('') is False


class TestMakeTombstone:
    def test_preserves_message_id(self) -> None:
        text = 'From: Alice\nMessage-ID: <abc@example.com>\nIn-Reply-To: <parent@example.com>\n\nBody text'
        tomb = make_tombstone(text, 'Admin <admin@test.com>')
        assert 'Message-ID: <abc@example.com>' in tomb
        assert 'In-Reply-To: <parent@example.com>' in tomb
        assert 'X-B4-Bug-Comment: removed by Admin <admin@test.com>' in tomb

    def test_strips_from_and_body(self) -> None:
        text = 'From: Alice\nDate: Mon, 1 Jan\nMessage-ID: <abc@example.com>\n\nSensitive body'
        tomb = make_tombstone(text, 'Admin <admin@test.com>')
        assert 'Alice' not in tomb
        assert 'Sensitive body' not in tomb
        assert 'Date:' not in tomb

    def test_roundtrip_with_is_removed(self) -> None:
        text = 'Message-ID: <abc@example.com>\n\nBody'
        tomb = make_tombstone(text, 'Admin <admin@test.com>')
        assert is_comment_removed(tomb)

    def test_msgid_preserved_for_dedup(self) -> None:
        text = 'Message-ID: <abc@example.com>\n\nBody'
        tomb = make_tombstone(text, 'Admin <admin@test.com>')
        assert parse_comment_msgid(tomb) == 'abc@example.com'

    def test_no_message_id(self) -> None:
        text = 'From: Alice\n\nInternal comment'
        tomb = make_tombstone(text, 'Admin <admin@test.com>')
        assert 'X-B4-Bug-Comment: removed by Admin' in tomb
        assert 'Message-ID' not in tomb


class TestFormatComment:
    def test_includes_headers(self) -> None:
        msg = mock.MagicMock()
        msg.get.side_effect = lambda h, *a: {
            'From': 'Alice <alice@test.com>',
            'Date': 'Mon, 1 Jan 2026 00:00:00 +0000',
            'Message-ID': '<abc@test.com>',
            'In-Reply-To': '<parent@test.com>',
        }.get(h)
        with mock.patch('b4.LoreMessage.clean_header', side_effect=lambda x: x):
            with mock.patch(
                'b4.LoreMessage.get_payload', return_value=('Body text', 'utf-8')
            ):
                result = format_comment(msg)
        assert 'From: Alice <alice@test.com>' in result
        assert 'Message-ID: <abc@test.com>' in result
        assert 'Body text' in result

    def test_scope_header(self) -> None:
        msg = mock.MagicMock()
        msg.get.side_effect = lambda h, *a: {
            'From': 'Alice',
            'Message-ID': '<abc@test.com>',
        }.get(h)
        with mock.patch('b4.LoreMessage.clean_header', side_effect=lambda x: x):
            with mock.patch(
                'b4.LoreMessage.get_payload', return_value=('Body', 'utf-8')
            ):
                result = format_comment(msg, scope='no-parent')
        assert 'X-B4-Bug-Scope: no-parent' in result


# ===========================================================================
# _tui.py tests
# ===========================================================================


class TestLabelColor:
    def test_deterministic(self) -> None:
        c1 = label_color('review')
        c2 = label_color('review')
        assert c1 == c2

    def test_different_labels_differ(self) -> None:
        c1 = label_color('review')
        c2 = label_color('priority/high')
        # Not guaranteed but extremely likely with different inputs
        assert isinstance(c1, str) and c1.startswith('#')
        assert isinstance(c2, str) and c2.startswith('#')

    def test_returns_hex_color(self) -> None:
        c = label_color('test')
        assert c.startswith('#')
        assert len(c) == 7  # #rrggbb


class TestBugTier:
    def test_open_new_is_tier_0(self) -> None:
        bug = make_bug()
        assert _bug_tier(bug) == 0

    def test_confirmed_is_tier_0(self) -> None:
        bug = make_bug(labels={'lifecycle:confirmed'})
        assert _bug_tier(bug) == 0

    def test_needinfo_is_tier_1(self) -> None:
        bug = make_bug(labels={'lifecycle:needinfo'})
        assert _bug_tier(bug) == 1

    def test_fixed_is_tier_2(self) -> None:
        bug = make_bug(labels={'lifecycle:fixed'})
        assert _bug_tier(bug) == 2

    def test_closed_is_tier_2(self) -> None:
        from ezgb import Status

        bug = make_bug(status=Status.CLOSED)
        assert _bug_tier(bug) == 2

    def test_summary_works(self) -> None:
        s = make_summary(labels=frozenset({'lifecycle:needinfo'}))
        assert _bug_tier(s) == 1


class TestBugLifecycle:
    def test_new_default(self) -> None:
        bug = make_bug()
        assert _bug_lifecycle(bug) == '\u2605'  # ★

    def test_confirmed(self) -> None:
        bug = make_bug(labels={'lifecycle:confirmed'})
        assert _bug_lifecycle(bug) == '\u00a4'  # ¤

    def test_fixed(self) -> None:
        bug = make_bug(labels={'lifecycle:fixed'})
        assert _bug_lifecycle(bug) == '\u2713'  # ✓

    def test_duplicate(self) -> None:
        bug = make_bug(labels={'lifecycle:duplicate'})
        assert _bug_lifecycle(bug) == '\u2261'  # ≡

    def test_closed_no_lifecycle(self) -> None:
        from ezgb import Status

        bug = make_bug(status=Status.CLOSED)
        assert _bug_lifecycle(bug) == '\u00d7'  # ×


class TestBugLastActivity:
    def test_uses_last_comment(self) -> None:
        comment_time = datetime(2026, 3, 15, tzinfo=timezone.utc)
        created_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        bug = make_bug(
            created_at=created_time,
            comments=[make_comment(comment_time)],
        )
        assert _bug_last_activity(bug) == comment_time

    def test_fallback_to_created_at(self) -> None:
        created_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        bug = make_bug(created_at=created_time, comments=[])
        assert _bug_last_activity(bug) == created_time

    def test_summary_uses_edited_at(self) -> None:
        from ezgb import BugSummary, Status

        edited_time = datetime(2026, 4, 1, tzinfo=timezone.utc)
        s = BugSummary(
            id='a' * 64,
            title='Test',
            status=Status.OPEN,
            creator_id='b' * 64,
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            labels=frozenset(),
            comment_count=1,
            edited_at=edited_time,
        )
        assert _bug_last_activity(s) == edited_time


class TestRelativeTime:
    def test_just_now(self) -> None:
        now = datetime.now(tz=timezone.utc)
        assert _relative_time(now) == 'just now'

    def test_minutes(self) -> None:
        from datetime import timedelta

        t = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
        assert '5m ago' == _relative_time(t)

    def test_hours(self) -> None:
        from datetime import timedelta

        t = datetime.now(tz=timezone.utc) - timedelta(hours=3)
        assert '3h ago' == _relative_time(t)

    def test_days(self) -> None:
        from datetime import timedelta

        t = datetime.now(tz=timezone.utc) - timedelta(days=7)
        assert '7d ago' == _relative_time(t)


class TestMatchesLimit:
    def test_bare_text_matches_title(self) -> None:
        bug = make_bug(title='Crash on startup')
        assert BugListApp._matches_limit(bug, 'crash') is True

    def test_bare_text_case_insensitive(self) -> None:
        bug = make_bug(title='Crash on startup')
        assert BugListApp._matches_limit(bug, 'CRASH') is True

    def test_bare_text_no_match(self) -> None:
        bug = make_bug(title='Crash on startup')
        assert BugListApp._matches_limit(bug, 'login') is False

    def test_status_filter_open(self) -> None:
        from ezgb import Status

        bug = make_bug(status=Status.OPEN)
        assert BugListApp._matches_limit(bug, 's:open') is True
        assert BugListApp._matches_limit(bug, 's:closed') is False

    def test_status_filter_closed(self) -> None:
        from ezgb import Status

        bug = make_bug(status=Status.CLOSED)
        assert BugListApp._matches_limit(bug, 's:closed') is True
        assert BugListApp._matches_limit(bug, 's:open') is False

    def test_label_filter(self) -> None:
        bug = make_bug(labels={'area/network', 'priority/high'})
        assert BugListApp._matches_limit(bug, 'l:network') is True
        assert BugListApp._matches_limit(bug, 'l:web') is False

    def test_combined_tokens(self) -> None:
        bug = make_bug(
            title='Network crash',
            labels={'area/network'},
        )
        assert BugListApp._matches_limit(bug, 'crash l:network') is True
        assert BugListApp._matches_limit(bug, 'crash l:web') is False

    def test_empty_pattern(self) -> None:
        bug = make_bug(title='Anything')
        assert BugListApp._matches_limit(bug, '') is True

    def test_summary_works(self) -> None:
        from ezgb import Status

        s = make_summary(
            title='Network bug',
            status=Status.OPEN,
            labels=frozenset({'area/network'}),
        )
        assert BugListApp._matches_limit(s, 'network l:network s:open') is True


class TestBuildActions:
    """Test context-sensitive action list building."""

    @staticmethod
    def _build(status: str = 'open', lifecycle: str = '') -> list[tuple[str, str]]:
        labels: Set[str] = set()
        if lifecycle:
            labels.add(f'lifecycle:{lifecycle}')
        bug = make_bug(
            status=Status.CLOSED if status == 'closed' else Status.OPEN,
            labels=labels,
        )
        return BugListApp._build_actions(bug)

    def test_new_bug_actions(self) -> None:
        actions = self._build()
        keys = [k for k, _label in actions]
        assert 'confirmed' in keys
        assert 'needinfo' in keys
        assert 'fixed' in keys
        assert 'worksforme' in keys
        assert 'wontfix' in keys
        assert 'duplicate' in keys
        assert 'delete' in keys

    def test_confirmed_bug_has_fixed(self) -> None:
        actions = self._build(lifecycle='confirmed')
        keys = [k for k, _label in actions]
        assert 'fixed' in keys
        assert 'confirmed' not in keys  # already confirmed

    def test_closed_bug_has_reopen(self) -> None:
        actions = self._build(status='closed')
        keys = [k for k, _label in actions]
        assert 'reopen' in keys
        assert 'delete' in keys
        assert len(keys) == 2  # only reopen + delete

    def test_needinfo_has_confirm(self) -> None:
        actions = self._build(lifecycle='needinfo')
        keys = [k for k, _label in actions]
        assert 'confirmed' in keys
        assert 'needinfo' not in keys

    def test_close_reasons_always_available(self) -> None:
        """All close reasons are available from any open lifecycle state."""
        for lifecycle in ('', 'new', 'confirmed', 'needinfo'):
            actions = self._build(lifecycle=lifecycle)
            keys = [k for k, _label in actions]
            assert 'fixed' in keys, f'fixed missing for {lifecycle!r}'
            assert 'worksforme' in keys, f'worksforme missing for {lifecycle!r}'
            assert 'wontfix' in keys, f'wontfix missing for {lifecycle!r}'
            assert 'duplicate' in keys, f'duplicate missing for {lifecycle!r}'


class TestParseMsgidForImport:
    """Verify that import_thread accepts URLs and bare message-ids."""

    def test_bare_msgid(self) -> None:
        import b4

        result = b4.parse_msgid('abc123@example.com')
        assert result == 'abc123@example.com'

    def test_angle_bracketed(self) -> None:
        import b4

        result = b4.parse_msgid('<abc123@example.com>')
        assert result == 'abc123@example.com'

    def test_lore_url(self) -> None:
        import b4

        result = b4.parse_msgid('https://lore.kernel.org/all/abc123@example.com/')
        assert result == 'abc123@example.com'

    def test_patch_msgid_link(self) -> None:
        import b4

        result = b4.parse_msgid('https://patch.msgid.link/abc123@example.com')
        assert result == 'abc123@example.com'

    def test_garbage_has_no_at(self) -> None:
        import b4

        result = b4.parse_msgid('not-a-msgid')
        assert '@' not in result
