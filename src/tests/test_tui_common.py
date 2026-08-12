"""Tests for the shared TUI helpers in b4.tui._common."""

from typing import Any, Dict

import pytest

pytest.importorskip('textual')

from b4.tui._common import limit_substring_matcher, matches_limit

# A representative item for engine tests; per-app field semantics are
# pinned by the _matches_limit tests in test_tui_tracking.py,
# test_tui_pw.py, and test_tui_bugs.py.
ITEM: Dict[str, Any] = {
    'subject': 'net: fix widget frobnication',
    'author': 'Alice Author',
    'status': 'reviewing',
    'empty': '',
    'missing_value': None,
}

PREFIXED = {
    's:': limit_substring_matcher('status'),
    'has:': lambda item, needle: bool(item.get(needle)),
}
BARE = limit_substring_matcher('subject', 'author')


class TestMatchesLimit:
    """Tests for the generic matches_limit() engine."""

    @pytest.mark.parametrize(
        'pattern, expected',
        [
            pytest.param('', True, id='empty-pattern-matches-all'),
            pytest.param('   ', True, id='whitespace-only-matches-all'),
            pytest.param('widget', True, id='bare-first-field'),
            pytest.param('alice', True, id='bare-second-field'),
            pytest.param('WIDGET', True, id='bare-case-insensitive'),
            pytest.param('gadget', False, id='bare-no-match'),
            pytest.param('s:review', True, id='prefixed-match'),
            pytest.param('S:REVIEW', True, id='prefixed-case-insensitive'),
            pytest.param('s:done', False, id='prefixed-no-match'),
            pytest.param('s:', True, id='empty-needle-matches'),
            pytest.param('widget alice s:review', True, id='and-all-match'),
            pytest.param('widget s:done', False, id='and-one-fails'),
            pytest.param('has:status', True, id='custom-matcher-true'),
            pytest.param('has:empty', False, id='custom-matcher-false'),
        ],
    )
    def test_engine(self, pattern: str, expected: bool) -> None:
        assert matches_limit(ITEM, pattern, PREFIXED, BARE) is expected

    def test_unknown_prefix_falls_through_to_bare(self) -> None:
        """A token with an unregistered prefix is just a bare token."""
        assert matches_limit(ITEM, 'x:widget', PREFIXED, BARE) is False
        item = dict(ITEM, subject='see x:widget marker')
        assert matches_limit(item, 'x:widget', PREFIXED, BARE) is True


class TestLimitSubstringMatcher:
    """Tests for the dict-field substring matcher factory."""

    def test_any_of_fields(self) -> None:
        match = limit_substring_matcher('subject', 'author')
        assert match(ITEM, 'frobnication') is True
        assert match(ITEM, 'author') is True
        assert match(ITEM, 'reviewing') is False

    def test_missing_and_none_fields_count_as_empty(self) -> None:
        match = limit_substring_matcher('nonexistent', 'missing_value')
        assert match(ITEM, 'anything') is False
        # ...but the empty needle is a substring of the empty string.
        assert match(ITEM, '') is True

    def test_field_values_matched_case_insensitively(self) -> None:
        match = limit_substring_matcher('author')
        # matches_limit lowercases the needle; the matcher must lowercase
        # the field value to meet it.
        assert match(ITEM, 'alice') is True
