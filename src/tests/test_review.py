import argparse
import email.message
import importlib.util
import json
import logging
import os
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union
from unittest import mock

import pytest

import b4
import b4.review.tracking
from b4 import review, review_tui
from b4.review import _review
from b4.review._review import REVIEW_MAGIC_MARKER, check_series_attestation

# The address-helper functions exposed via review_tui live in a module that
# imports textual at load time, so the tests that exercise them need the [tui]
# extra even though the functions themselves are pure. Skip them when textual
# is absent (e.g. a deliberately no-tui install) rather than fail to collect.
requires_textual = pytest.mark.skipif(
    importlib.util.find_spec('textual') is None,
    reason='requires the [tui] extra (textual)',
)

# -- Helper diffs used across tests ------------------------------------------

# A minimal single-file, single-hunk diff
SIMPLE_DIFF = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
+	ptr->field = value;
 	return 0;
"""

# Two files, one hunk each
TWO_FILE_DIFF = """\
diff --git a/src/a.c b/src/a.c
index 1111111..2222222 100644
--- a/src/a.c
+++ b/src/a.c
@@ -5,3 +5,4 @@ void a(void)
 	int x;
+	int y;
 	return;
diff --git a/src/b.c b/src/b.c
index 3333333..4444444 100644
--- a/src/b.c
+++ b/src/b.c
@@ -1,3 +1,4 @@ void b(void)
 	int a;
+	int b;
 	return;
"""


class TestRenderQuotedDiffWithComments:
    """Tests for _render_quoted_diff_with_comments()."""

    def test_no_comments_quotes_diff(self) -> None:
        """Without comments, every diff line gets a '> ' prefix."""
        result = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, {}, 'me@example.com'
        )
        for line in result.splitlines():
            assert line.startswith(('> ', '#')) or line == '', (
                f'Unquoted line: {line!r}'
            )

    def test_own_comment_is_unquoted(self) -> None:
        """Own comments appear as unquoted text between quoted diff."""
        all_reviews: Dict[str, Any] = {
            'me@example.com': {
                'name': 'Me',
                'comments': [
                    {
                        'path': 'b/lib/helpers.c',
                        'line': 12,
                        'text': 'Check NULL return',
                    },
                ],
            },
        }
        result = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, all_reviews, 'me@example.com'
        )
        assert 'Check NULL return' in result
        # Comment should NOT be quoted
        for line in result.splitlines():
            if 'Check NULL return' in line:
                assert not line.startswith('> ')
                assert not line.startswith('| ')

    def test_external_comment_uses_pipe_prefix(self) -> None:
        """External comments are prefixed with '| '."""
        all_reviews: Dict[str, Any] = {
            'other@example.com': {
                'name': 'Other',
                'comments': [
                    {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'Looks wrong.'},
                ],
            },
        }
        result = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, all_reviews, 'me@example.com'
        )
        assert '| Looks wrong.' in result
        assert '| Other <other@example.com>:' in result

    def test_mixed_own_and_external(self) -> None:
        """Own and external comments at the same position."""
        all_reviews: Dict[str, Any] = {
            'me@example.com': {
                'name': 'Me',
                'comments': [
                    {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'My comment'},
                ],
            },
            'ext@example.com': {
                'name': 'Ext',
                'comments': [
                    {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'Ext comment'},
                ],
                'provenance': 'https://lore.kernel.org/test',
            },
        }
        result = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, all_reviews, 'me@example.com'
        )
        assert 'My comment' in result
        assert '| Ext comment' in result

    def test_cross_file_comments(self) -> None:
        """Comments in different files render correctly."""
        all_reviews: Dict[str, Any] = {
            'me@example.com': {
                'name': 'Me',
                'comments': [
                    {'path': 'b/src/a.c', 'line': 6, 'text': 'Comment in a.c'},
                    {'path': 'b/src/b.c', 'line': 2, 'text': 'Comment in b.c'},
                ],
            },
        }
        result = review._render_quoted_diff_with_comments(
            TWO_FILE_DIFF, all_reviews, 'me@example.com'
        )
        assert 'Comment in a.c' in result
        assert 'Comment in b.c' in result

    def test_editor_instructions_at_top(self) -> None:
        """Rendered output starts with # instruction lines."""
        result = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, {}, 'me@example.com'
        )
        lines = result.splitlines()
        # First non-empty line should be an instruction
        assert lines[0].startswith('# ')
        # Instructions end before the first quoted diff line
        instruction_lines = [line for line in lines if line.startswith('#')]
        assert len(instruction_lines) >= 3
        # _extract_editor_comments should strip them
        comments = review._extract_editor_comments(result)
        assert not any(c['text'].startswith('#') for c in comments)

    def test_commit_msg_quoted_before_diff(self) -> None:
        """Commit message body is quoted before the diff when provided."""
        result = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF,
            {},
            'me@example.com',
            commit_msg='Subject line\n\nThis is the body.\nSecond line.',
        )
        lines = result.splitlines()
        # Body lines should appear quoted before the diff
        assert '> This is the body.' in lines
        assert '> Second line.' in lines
        # They should come before the diff
        body_idx = lines.index('> This is the body.')
        diff_idx = next(i for i, line in enumerate(lines) if 'diff --git' in line)
        assert body_idx < diff_idx

    def test_commit_msg_own_comment(self) -> None:
        """Own comments on commit message lines are rendered unquoted."""
        all_reviews: Dict[str, Any] = {
            'me@example.com': {
                'name': 'Me',
                'comments': [
                    {'path': ':message', 'line': 1, 'text': 'Body comment'},
                ],
            },
        }
        result = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF,
            all_reviews,
            'me@example.com',
            commit_msg='Subject\n\nFirst body line.',
        )
        assert 'Body comment' in result
        for line in result.splitlines():
            if 'Body comment' in line:
                assert not line.startswith('> ')
                assert not line.startswith('| ')

    def test_commit_msg_external_comment(self) -> None:
        """External comments on commit message lines use | prefix."""
        all_reviews: Dict[str, Any] = {
            'other@example.com': {
                'name': 'Other',
                'provenance': 'https://lore.kernel.org/test',
                'comments': [
                    {'path': ':message', 'line': 1, 'text': 'Ext msg comment'},
                ],
            },
        }
        result = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF,
            all_reviews,
            'me@example.com',
            commit_msg='Subject\n\nFirst body line.',
        )
        assert '| Ext msg comment' in result
        assert '| Other <other@example.com>:' in result
        assert '| via: https://lore.kernel.org/test' in result

    def test_preamble_comment_rendered(self) -> None:
        """Preamble comments (line 0) are rendered before the commit message."""
        all_reviews: Dict[str, Any] = {
            'me@example.com': {
                'name': 'Me',
                'comments': [
                    {'path': ':message', 'line': 0, 'text': 'General note'},
                ],
            },
        }
        result = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF,
            all_reviews,
            'me@example.com',
            commit_msg='Subject\n\nFirst body line.',
        )
        lines = result.splitlines()
        assert 'General note' in lines
        note_idx = lines.index('General note')
        body_idx = next(i for i, line in enumerate(lines) if 'First body line' in line)
        assert note_idx < body_idx


class TestExtractEditorComments:
    """Tests for _extract_editor_comments()."""

    def test_basic_comment(self) -> None:
        """Unquoted text between quoted diff is extracted as a comment."""
        edited = (
            '> diff --git a/lib/helpers.c b/lib/helpers.c\n'
            '> --- a/lib/helpers.c\n'
            '> +++ b/lib/helpers.c\n'
            '> @@ -10,6 +10,8 @@ void setup(struct ctx *ctx)\n'
            '>  \tint ret;\n'
            '>  \n'
            '> +\tptr = kzalloc(sizeof(*ptr), GFP_KERNEL);\n'
            '\n'
            'Check NULL return.\n'
            '\n'
            '> +\tptr->field = value;\n'
            '>  \treturn 0;\n'
        )
        comments = review._extract_editor_comments(edited)
        assert len(comments) == 1
        assert comments[0]['path'] == 'b/lib/helpers.c'
        assert comments[0]['line'] == 12
        assert comments[0]['text'] == 'Check NULL return.'

    def test_hash_line_in_comment_is_kept(self) -> None:
        """A # line the maintainer wrote is content, not scaffolding."""
        edited = (
            '# Review patch for: test\n'
            '#\n'
            '> diff --git a/lib/helpers.c b/lib/helpers.c\n'
            '> --- a/lib/helpers.c\n'
            '> +++ b/lib/helpers.c\n'
            '> @@ -10,6 +10,8 @@ void setup(struct ctx *ctx)\n'
            '>  \tint ret;\n'
            '>  \n'
            '> +\tptr = kzalloc(sizeof(*ptr), GFP_KERNEL);\n'
            '\n'
            'I had written\n'
            '\n'
            '#define arm_smmu_kdump_is_attach_deferred NULL\n'
            '\n'
            '> +\tptr->field = value;\n'
            '>  \treturn 0;\n'
        )
        comments = review._extract_editor_comments(edited)
        assert len(comments) == 1
        assert '#define arm_smmu_kdump_is_attach_deferred NULL' in comments[0]['text']
        # The leading header is still gone.
        assert '# Review patch for' not in comments[0]['text']

    def test_instruction_lines_stripped(self) -> None:
        """Lines starting with # are ignored."""
        edited = (
            '# Review patch for: test\n'
            '#\n'
            '> diff --git a/lib/helpers.c b/lib/helpers.c\n'
            '> --- a/lib/helpers.c\n'
            '> +++ b/lib/helpers.c\n'
            '> @@ -10,6 +10,8 @@ void setup(struct ctx *ctx)\n'
            '>  \tint ret;\n'
            '>  \n'
            '> +\tptr = kzalloc(sizeof(*ptr), GFP_KERNEL);\n'
            '\n'
            'My comment.\n'
            '\n'
            '> +\tptr->field = value;\n'
            '>  \treturn 0;\n'
        )
        comments = review._extract_editor_comments(edited)
        assert len(comments) == 1
        assert comments[0]['text'] == 'My comment.'

    def test_pipe_prefix_lines_stripped(self) -> None:
        """Lines starting with | are ignored (external comments)."""
        edited = (
            '> diff --git a/lib/helpers.c b/lib/helpers.c\n'
            '> --- a/lib/helpers.c\n'
            '> +++ b/lib/helpers.c\n'
            '> @@ -10,6 +10,8 @@ void setup(struct ctx *ctx)\n'
            '>  \tint ret;\n'
            '>  \n'
            '> +\tptr = kzalloc(sizeof(*ptr), GFP_KERNEL);\n'
            '\n'
            '| Other <other@example.com>:\n'
            '|\n'
            '| This is wrong.\n'
            '\n'
            '> +\tptr->field = value;\n'
            '>  \treturn 0;\n'
        )
        comments = review._extract_editor_comments(edited)
        assert len(comments) == 0

    def test_adopt_external_comment(self) -> None:
        """Removing | prefix adopts an external comment."""
        edited = (
            '> diff --git a/lib/helpers.c b/lib/helpers.c\n'
            '> --- a/lib/helpers.c\n'
            '> +++ b/lib/helpers.c\n'
            '> @@ -10,6 +10,8 @@ void setup(struct ctx *ctx)\n'
            '>  \tint ret;\n'
            '>  \n'
            '> +\tptr = kzalloc(sizeof(*ptr), GFP_KERNEL);\n'
            '\n'
            'This is wrong.\n'
            '\n'
            '> +\tptr->field = value;\n'
            '>  \treturn 0;\n'
        )
        comments = review._extract_editor_comments(edited)
        assert len(comments) == 1
        assert comments[0]['text'] == 'This is wrong.'

    def test_multiple_comments_correct_positions(self) -> None:
        """Multiple comments with blank lines don't shift positions."""
        edited = (
            '> diff --git a/test.rst b/test.rst\n'
            '> new file mode 100644\n'
            '> --- /dev/null\n'
            '> +++ b/test.rst\n'
            '> @@ -0,0 +1,9 @@\n'
            '> +line1\n'
            '> +line2\n'
            '> +line3\n'
            '\n'
            '1st comment\n'
            '\n'
            '> +\n'
            '> +line5\n'
            '> +line6\n'
            '\n'
            '2nd comment\n'
            '\n'
            '> +\n'
            '> +line8\n'
            '> +line9\n'
            '\n'
            '3rd comment\n'
        )
        comments = review._extract_editor_comments(edited)
        assert len(comments) == 3
        assert comments[0]['line'] == 3
        assert comments[0]['text'] == '1st comment'
        assert comments[1]['line'] == 6
        assert comments[1]['text'] == '2nd comment'
        assert comments[2]['line'] == 9
        assert comments[2]['text'] == '3rd comment'

    def test_content_key_set(self) -> None:
        """Extracted comments have 'content' key from the diff line."""
        edited = (
            '> diff --git a/lib/helpers.c b/lib/helpers.c\n'
            '> --- a/lib/helpers.c\n'
            '> +++ b/lib/helpers.c\n'
            '> @@ -10,6 +10,8 @@ void setup(struct ctx *ctx)\n'
            '>  \tint ret;\n'
            '>  \n'
            '> +\tptr = kzalloc(sizeof(*ptr), GFP_KERNEL);\n'
            '\n'
            'My comment.\n'
            '\n'
            '> +\tptr->field = value;\n'
        )
        comments = review._extract_editor_comments(edited)
        assert len(comments) == 1
        assert comments[0]['content'] == '+\tptr = kzalloc(sizeof(*ptr), GFP_KERNEL);'


class TestQuotedEditorRoundTrip:
    """Tests for render → edit → extract round-trip."""

    def test_single_comment_round_trip(self) -> None:
        """A single comment survives render → extract."""
        comments = [{'path': 'b/lib/helpers.c', 'line': 12, 'text': 'Check this'}]
        all_reviews: Dict[str, Any] = {
            'me@example.com': {'name': 'Me', 'comments': comments},
        }
        rendered = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, all_reviews, 'me@example.com'
        )
        extracted = review._extract_editor_comments(rendered)
        assert len(extracted) == 1
        assert extracted[0]['path'] == 'b/lib/helpers.c'
        assert extracted[0]['line'] == 12
        assert extracted[0]['text'] == 'Check this'

    def test_multiple_comments_round_trip(self) -> None:
        """Multiple comments in different files survive round-trip."""
        comments_a = [{'path': 'b/src/a.c', 'line': 6, 'text': 'Note A'}]
        comments_b = [{'path': 'b/src/b.c', 'line': 2, 'text': 'Note B'}]
        all_reviews: Dict[str, Any] = {
            'me@example.com': {
                'name': 'Me',
                'comments': comments_a + comments_b,
            },
        }
        rendered = review._render_quoted_diff_with_comments(
            TWO_FILE_DIFF, all_reviews, 'me@example.com'
        )
        extracted = review._extract_editor_comments(rendered)
        assert len(extracted) == 2
        assert extracted[0]['path'] == 'b/src/a.c'
        assert extracted[0]['text'] == 'Note A'
        assert extracted[1]['path'] == 'b/src/b.c'
        assert extracted[1]['text'] == 'Note B'

    def test_double_round_trip_stable(self) -> None:
        """Two round-trips produce the same comments."""
        comments = [{'path': 'b/lib/helpers.c', 'line': 12, 'text': 'Check this'}]
        all_reviews: Dict[str, Any] = {
            'me@example.com': {'name': 'Me', 'comments': comments},
        }
        rendered1 = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, all_reviews, 'me@example.com'
        )
        extracted1 = review._extract_editor_comments(rendered1)

        all_reviews2: Dict[str, Any] = {
            'me@example.com': {'name': 'Me', 'comments': extracted1},
        }
        rendered2 = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, all_reviews2, 'me@example.com'
        )
        extracted2 = review._extract_editor_comments(rendered2)

        assert len(extracted1) == len(extracted2)
        for c1, c2 in zip(extracted1, extracted2):
            assert c1['path'] == c2['path']
            assert c1['line'] == c2['line']
            assert c1['text'] == c2['text']

    def test_external_comments_preserved_through_round_trip(self) -> None:
        """External | comments don't leak into extracted comments."""
        all_reviews: Dict[str, Any] = {
            'me@example.com': {
                'name': 'Me',
                'comments': [
                    {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'My note'},
                ],
            },
            'ext@example.com': {
                'name': 'Ext',
                'comments': [
                    {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'Ext note'},
                ],
            },
        }
        rendered = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, all_reviews, 'me@example.com'
        )
        extracted = review._extract_editor_comments(rendered)
        assert len(extracted) == 1
        assert extracted[0]['text'] == 'My note'

    def test_commit_message_comment_round_trip(self) -> None:
        """Comments on commit message lines survive render → extract."""
        comments = [{'path': ':message', 'line': 1, 'text': 'Body comment'}]
        all_reviews: Dict[str, Any] = {
            'me@example.com': {'name': 'Me', 'comments': comments},
        }
        rendered = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF,
            all_reviews,
            'me@example.com',
            commit_msg='Subject\n\nFirst body line.\nSecond line.',
        )
        extracted = review._extract_editor_comments(rendered)
        msg_comments = [c for c in extracted if c['path'] == ':message']
        assert len(msg_comments) == 1
        assert msg_comments[0]['text'] == 'Body comment'
        assert msg_comments[0]['line'] == 1

    def test_preamble_comment_round_trip(self) -> None:
        """Preamble comments (line 0) survive render → extract."""
        comments = [{'path': ':message', 'line': 0, 'text': 'General note'}]
        all_reviews: Dict[str, Any] = {
            'me@example.com': {'name': 'Me', 'comments': comments},
        }
        rendered = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF,
            all_reviews,
            'me@example.com',
            commit_msg='Subject\n\nBody line.',
        )
        extracted = review._extract_editor_comments(rendered)
        preamble = [c for c in extracted if c['path'] == ':message' and c['line'] == 0]
        assert len(preamble) == 1
        assert preamble[0]['text'] == 'General note'

    def test_mixed_commit_msg_and_diff_round_trip(self) -> None:
        """Both commit message and diff comments survive round-trip."""
        comments = [
            {'path': ':message', 'line': 1, 'text': 'Msg comment'},
            {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'Diff comment'},
        ]
        all_reviews: Dict[str, Any] = {
            'me@example.com': {'name': 'Me', 'comments': comments},
        }
        rendered = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF,
            all_reviews,
            'me@example.com',
            commit_msg='Subject\n\nFirst body line.',
        )
        extracted = review._extract_editor_comments(rendered)
        msg_c = [c for c in extracted if c['path'] == ':message']
        diff_c = [c for c in extracted if c['path'] != ':message']
        assert len(msg_c) == 1
        assert msg_c[0]['text'] == 'Msg comment'
        assert len(diff_c) == 1
        assert diff_c[0]['text'] == 'Diff comment'


class TestBuildReplyFromComments:
    """Tests for _build_reply_from_comments()."""

    def test_trailing_hunk_lines_truncated(self) -> None:
        """Diff lines after the last comment in a hunk are omitted."""
        comments = [
            {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'Check return value.'},
        ]
        result = review._build_reply_from_comments(SIMPLE_DIFF, comments, [])
        # Everything up to the commented +kzalloc line (line 12) is quoted;
        # the uncommented +ptr->field line (13) and the trailing "return 0"
        # context are truncated.
        assert result == (
            '> diff --git a/lib/helpers.c b/lib/helpers.c\n'
            '> index abc1234..def5678 100644\n'
            '> --- a/lib/helpers.c\n'
            '> +++ b/lib/helpers.c\n'
            '> @@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)\n'
            '>  \tint ret;\n'
            '> \n'
            '> +\tptr = kzalloc(sizeof(*ptr), GFP_KERNEL);\n'
            '\n'
            'Check return value.\n'
        )

    def test_lines_before_comment_preserved(self) -> None:
        """Diff lines before the comment are preserved as quoted context."""
        comments = [
            {'path': 'b/lib/helpers.c', 'line': 13, 'text': 'Check field assignment.'},
        ]
        result = review._build_reply_from_comments(SIMPLE_DIFF, comments, [])
        # The uncommented +kzalloc line (12) is kept as context above the
        # commented +ptr->field line (13); only "return 0" is truncated.
        assert result == (
            '> diff --git a/lib/helpers.c b/lib/helpers.c\n'
            '> index abc1234..def5678 100644\n'
            '> --- a/lib/helpers.c\n'
            '> +++ b/lib/helpers.c\n'
            '> @@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)\n'
            '>  \tint ret;\n'
            '> \n'
            '> +\tptr = kzalloc(sizeof(*ptr), GFP_KERNEL);\n'
            '> +\tptr->field = value;\n'
            '\n'
            'Check field assignment.\n'
        )

    def test_two_comments_middle_lines_preserved(self) -> None:
        """Lines between two comments are kept, trailing lines dropped."""
        comments = [
            {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'First.'},
            {'path': 'b/lib/helpers.c', 'line': 13, 'text': 'Second.'},
        ]
        result = review._build_reply_from_comments(SIMPLE_DIFF, comments, [])
        # Each comment lands directly under its quoted line; the trailing
        # "return 0" after the last comment is truncated.
        assert result == (
            '> diff --git a/lib/helpers.c b/lib/helpers.c\n'
            '> index abc1234..def5678 100644\n'
            '> --- a/lib/helpers.c\n'
            '> +++ b/lib/helpers.c\n'
            '> @@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)\n'
            '>  \tint ret;\n'
            '> \n'
            '> +\tptr = kzalloc(sizeof(*ptr), GFP_KERNEL);\n'
            '\n'
            'First.\n'
            '\n'
            '> +\tptr->field = value;\n'
            '\n'
            'Second.\n'
        )

    def test_no_truncation_when_comment_on_last_line(self) -> None:
        """When the comment is on the last diff line, nothing is lost."""
        diff = """\
diff --git a/f.c b/f.c
index abc..def 100644
--- a/f.c
+++ b/f.c
@@ -1,2 +1,3 @@ void f(void)
 	int x;
+	int y;
+	int z;
"""
        comments = [
            {'path': 'b/f.c', 'line': 3, 'text': 'Why z?'},
        ]
        result = review._build_reply_from_comments(diff, comments, [])
        assert 'int z' in result
        assert 'Why z?' in result

    def test_commit_msg_comment_with_context(self) -> None:
        """Commit message comments include context lines and use windowing."""
        commit_msg = 'Subject\n\nLine one.\nLine two.\nLine three.'
        comments = [
            {'path': ':message', 'line': 3, 'text': 'Comment on line three.'},
        ]
        result = review._build_reply_from_comments(
            SIMPLE_DIFF, comments, [], commit_msg=commit_msg
        )
        assert 'Comment on line three.' in result
        assert '> Line three.' in result

    def test_commit_msg_preamble_comment(self) -> None:
        """Preamble comments (line 0) appear before quoted content."""
        commit_msg = 'Subject\n\nBody line.'
        comments = [
            {'path': ':message', 'line': 0, 'text': 'General feedback.'},
        ]
        result = review._build_reply_from_comments(
            '', comments, [], commit_msg=commit_msg
        )
        lines = result.splitlines()
        assert 'General feedback.' in lines
        # Preamble should come before any quoted line
        feedback_idx = lines.index('General feedback.')
        quoted_lines = [i for i, line in enumerate(lines) if line.startswith('>')]
        if quoted_lines:
            assert feedback_idx < quoted_lines[0]

    def test_commit_msg_no_separator_without_diff(self) -> None:
        """No stray > separator when there is no diff content."""
        commit_msg = 'Subject\n\nBody line.'
        comments = [
            {'path': ':message', 'line': 1, 'text': 'A comment.'},
        ]
        result = review._build_reply_from_comments(
            '', comments, [], commit_msg=commit_msg
        )
        # Should not end with a bare >
        stripped = result.rstrip()
        assert not stripped.endswith('\n>')
        assert '> Body line.' in result
        assert 'A comment.' in result

    def test_commit_msg_skips_uncommented_lines(self) -> None:
        """Only context around commented lines is quoted, rest is skipped."""
        lines = '\n'.join(f'Line {i}' for i in range(1, 31))
        commit_msg = f'Subject\n\n{lines}'
        comments = [
            {'path': ':message', 'line': 25, 'text': 'Comment here.'},
        ]
        result = review._build_reply_from_comments(
            '', comments, [], commit_msg=commit_msg
        )
        # Line 25 and a few lines of context above should be quoted
        assert '> Line 25' in result
        assert 'Comment here.' in result
        # Line 1 is far above — should be skipped
        assert '> Line 1\n' not in result

    def test_comment_on_separator_between_msg_and_diff(self) -> None:
        """A comment placed after the commit message but before diff is kept."""
        commit_msg = 'Subject\n\nBody line 1.\n\nSigned-off-by: A <a@b.c>'
        comments = [
            # Line 4 is beyond _strip_subject's output (3 body lines),
            # simulating a comment on the > separator
            {'path': ':message', 'line': 4, 'text': 'General comment.'},
        ]
        result = review._build_reply_from_comments(
            SIMPLE_DIFF, comments, [], commit_msg=commit_msg
        )
        assert 'General comment.' in result

    def test_comment_above_diff_git_roundtrips(self) -> None:
        """Comment above first diff --git line survives parse and render."""
        commit_msg = 'Subject\n\nBody.\n\nSigned-off-by: A <a@b.c>'
        diff = (
            'diff --git a/f.c b/f.c\n'
            '--- a/f.c\n'
            '+++ b/f.c\n'
            '@@ -1,3 +1,4 @@\n'
            ' ctx\n'
            '+new\n'
            ' more\n'
        )
        # Simulate what the editor would produce: quoted commit message,
        # separator, user comment, then quoted diff
        edited = (
            '> Body.\n'
            '>\n'
            '> Signed-off-by: A <a@b.c>\n'
            '>\n'
            '\n'
            'My general comment.\n'
            '\n'
            '> diff --git a/f.c b/f.c\n'
            '> --- a/f.c\n'
            '> +++ b/f.c\n'
            '> @@ -1,3 +1,4 @@\n'
            '>  ctx\n'
            '> +new\n'
            '>  more\n'
        )
        comments = review._extract_editor_comments(edited, diff_text=diff)
        assert len(comments) == 1
        assert comments[0]['text'] == 'My general comment.'
        # Now rebuild the reply from those comments
        result = review._build_reply_from_comments(
            diff, comments, [], commit_msg=commit_msg
        )
        assert 'My general comment.' in result


class TestTrimQuotedReply:
    """Tests for _trim_quoted_reply().

    The only changes made are stripping b4 scaffolding (# and | lines) and
    dropping the run of quoted diff below the maintainer's last comment.
    """

    def test_strips_scaffolding(self) -> None:
        buf = '# instructions\nMy comment.\n> +code\n| Other <o@x.com>:\n| their note\n'
        out = review._trim_quoted_reply(buf)
        assert '# instructions' not in out
        assert 'Other <o@x.com>' not in out
        assert 'their note' not in out
        assert 'My comment.' in out

    def test_keeps_hash_lines_the_maintainer_wrote(self) -> None:
        # Only the leading instruction header is scaffolding.  A # further
        # down is the maintainer's own text and must be sent verbatim.
        buf = (
            '# instructions\n'
            '# more instructions\n'
            '\n'
            'I had written\n'
            '\n'
            '#define arm_smmu_kdump_is_attach_deferred NULL\n'
            '\n'
            'and it went missing.\n'
        )
        out = review._trim_quoted_reply(buf)
        assert '# instructions' not in out
        assert '# more instructions' not in out
        assert '#define arm_smmu_kdump_is_attach_deferred NULL' in out
        assert out.rstrip().endswith('and it went missing.')

    def test_hash_header_only_stripped_when_leading(self) -> None:
        # With no header at the top, a # first line is the maintainer's own
        # -- but a run below any other text is never treated as a header.
        buf = 'Some prose.\n#define FOO 1\n#define BAR 2\n'
        out = review._trim_quoted_reply(buf)
        assert '#define FOO 1' in out
        assert '#define BAR 2' in out

    def test_drops_trailing_quoted_below_last_comment(self) -> None:
        buf = (
            'Looks good here.\n'
            '> +relevant line\n'
            '\n'
            'Please fix this.\n'
            '\n'
            '> @@ -50,5 +50,5 @@\n'
            '> +trailing\n'
            '> +untouched diff\n'
        )
        out = review._trim_quoted_reply(buf)
        # Everything up to and including the last comment is verbatim.
        assert 'Looks good here.' in out
        assert '> +relevant line' in out  # quoted above a later comment kept
        assert 'Please fix this.' in out
        # The quoted tail after the last comment is gone.
        assert '> +trailing' not in out
        assert '> +untouched diff' not in out
        assert '@@ -50' not in out
        assert out.rstrip().endswith('Please fix this.')

    def test_keeps_quoted_between_comments_verbatim(self) -> None:
        # Quoted code sitting between two comments is NOT trimmed — only the
        # trailing run below the last comment is.
        buf = 'First.\n> a\n> b\n> c\n> d\n> e\n> f\nSecond.\n> g\n'
        out = review._trim_quoted_reply(buf)
        for q in ['> a', '> b', '> c', '> d', '> e', '> f']:
            assert q in out
        assert '> g' not in out  # trailing quoted dropped
        assert out.rstrip().endswith('Second.')

    def test_trailer_at_bottom_keeps_quoted_above(self) -> None:
        # When a trailer is the last line, nothing trails it, so the quoted
        # diff above it is kept verbatim.
        buf = 'Comment.\n> +x\n> +y\nReviewed-by: Me <me@x.com>'
        out = review._trim_quoted_reply(buf)
        assert '> +x' in out and '> +y' in out
        assert out.rstrip().endswith('Reviewed-by: Me <me@x.com>')

    def test_only_quoted_is_all_trailing(self) -> None:
        # No comments at all → the whole quoted body is trailing → dropped.
        buf = '> diff --git a/f b/f\n> @@ -1,2 +1,2 @@\n> +new\n'
        assert review._trim_quoted_reply(buf).strip() == ''

    def test_empty_buffer(self) -> None:
        assert review._trim_quoted_reply('') == ''


class TestParseReplyTrailers:
    """Tests for _parse_reply_trailers() — derived trailer display index."""

    def test_picks_up_inline_trailer(self) -> None:
        buf = 'Looks good.\n\nReviewed-by: Me <me@example.com>\n'
        assert review._parse_reply_trailers(buf) == ['Reviewed-by: Me <me@example.com>']

    def test_prose_colon_not_a_trailer(self) -> None:
        # "stable: ..." is prose, not a trailer — must not be misclassified.
        buf = (
            'You need to Cc\n'
            'stable: without that fix things break.\n'
            '\n'
            'Reviewed-by: Me <me@example.com>\n'
        )
        trailers = review._parse_reply_trailers(buf)
        assert trailers == ['Reviewed-by: Me <me@example.com>']

    def test_ignores_quoted_and_external_lines(self) -> None:
        buf = (
            '> Reviewed-by: NotMe <quoted@example.com>\n'
            '| Acked-by: Other <ext@example.com>\n'
            'Tested-by: Me <me@example.com>\n'
        )
        assert review._parse_reply_trailers(buf) == ['Tested-by: Me <me@example.com>']


class TestReplyTrailerEditing:
    """Tests for _insert_trailer_in_reply() / _remove_trailer_from_reply()."""

    def test_insert_appends_as_block(self) -> None:
        buf = 'Thanks!\n'
        out = review._insert_trailer_in_reply(buf, 'Reviewed-by: Me <me@x.com>')
        assert out == 'Thanks!\n\nReviewed-by: Me <me@x.com>'

    def test_insert_before_signature(self) -> None:
        buf = 'Thanks!\n-- \nmy sig\n'
        out = review._insert_trailer_in_reply(buf, 'Acked-by: Me <me@x.com>')
        lines = out.split('\n')
        assert lines.index('Acked-by: Me <me@x.com>') < lines.index('-- ')

    def test_insert_groups_with_existing_trailers(self) -> None:
        buf = 'Thanks!\n\nReviewed-by: Me <me@x.com>'
        out = review._insert_trailer_in_reply(buf, 'Tested-by: Me <me@x.com>')
        # No blank line inserted between the two trailers.
        assert 'Reviewed-by: Me <me@x.com>\nTested-by: Me <me@x.com>' in out

    def test_remove_drops_matching_bare_line(self) -> None:
        buf = 'Thanks!\n\nReviewed-by: Me <me@x.com>\nAcked-by: Me <me@x.com>'
        out = review._remove_trailer_from_reply(buf, 'reviewed-by')
        assert 'Reviewed-by' not in out
        assert 'Acked-by: Me <me@x.com>' in out

    def test_remove_leaves_quoted_trailer_alone(self) -> None:
        buf = '> Reviewed-by: Quoted <q@x.com>\nReviewed-by: Me <me@x.com>'
        out = review._remove_trailer_from_reply(buf, 'reviewed-by')
        assert '> Reviewed-by: Quoted <q@x.com>' in out
        assert 'Reviewed-by: Me <me@x.com>' not in out.replace(
            '> Reviewed-by: Quoted <q@x.com>', ''
        )

    def test_remove_collapses_blank_gap(self) -> None:
        # A trailer alone between blank lines takes one of the blanks with
        # it, so no doubled gap is left where it used to be.
        buf = 'Intro.\n\nReviewed-by: Me <me@x.com>\n\nMore text.\n'
        out = review._remove_trailer_from_reply(buf, 'reviewed-by')
        assert out == 'Intro.\n\nMore text.\n'

    def test_remove_at_end_leaves_no_trailing_gap(self) -> None:
        buf = 'Thanks!\n\nReviewed-by: Me <me@x.com>\n'
        out = review._remove_trailer_from_reply(buf, 'reviewed-by')
        assert out == 'Thanks!\n'

    def test_insert_normalizes_crlf_buffer(self) -> None:
        # A buffer stored by an older b4 may carry editor CRLF endings;
        # the rebuild canonicalizes them instead of mixing LF into CRLF.
        buf = 'Thanks!\r\n\r\nAcked-by: Me <me@x.com>\r\n'
        out = review._insert_trailer_in_reply(buf, 'Tested-by: Me <me@x.com>')
        assert '\r' not in out
        assert 'Acked-by: Me <me@x.com>\nTested-by: Me <me@x.com>' in out

    def test_remove_normalizes_crlf_buffer(self) -> None:
        buf = 'Thanks!\r\n\r\nReviewed-by: Me <me@x.com>\r\n'
        out = review._remove_trailer_from_reply(buf, 'reviewed-by')
        assert out == 'Thanks!\n'


class TestSyncReplyTrailers:
    """Tests for _sync_reply_trailers() — the trailer-menu buffer sync.

    The menu may only add/remove the trailer names it offers; anything else
    the maintainer typed into the buffer is their content and must survive.
    """

    IDENTITY = 'Me <me@x.com>'

    def test_unmanaged_trailer_survives_menu_toggle(self) -> None:
        # Reported by Matthieu Baerts: a hand-typed Fixes: line was deleted
        # when Reviewed-by was added via the trailer menu.
        buf = (
            'Please add a Fixes tag. Here I guess it should be:\n'
            '\n'
            'Fixes: 1234567890ab ("some patch")\n'
        )
        out = review._sync_reply_trailers(buf, ['Reviewed-by'], self.IDENTITY)
        assert 'Fixes: 1234567890ab ("some patch")' in out
        assert f'Reviewed-by: {self.IDENTITY}' in out

    def test_untoggle_removes_managed_trailer(self) -> None:
        buf = 'Looks good.\n\nReviewed-by: Me <me@x.com>\n'
        out = review._sync_reply_trailers(buf, [], self.IDENTITY)
        assert 'Reviewed-by' not in out
        assert 'Looks good.' in out

    def test_nack_supersedes_managed_keeps_unmanaged(self) -> None:
        buf = (
            'This breaks things.\n'
            '\n'
            'Fixes: 1234567890ab ("some patch")\n'
            'Reviewed-by: Me <me@x.com>\n'
        )
        out = review._sync_reply_trailers(
            buf, ['Reviewed-by', 'NACKed-by'], self.IDENTITY
        )
        assert 'Reviewed-by' not in out
        assert 'Fixes: 1234567890ab ("some patch")' in out
        assert f'NACKed-by: {self.IDENTITY}' in out

    def test_noop_selection_keeps_buffer_verbatim(self) -> None:
        buf = 'Prose here.\n\nFixes: 1234567890ab ("x")\nAcked-by: Me <me@x.com>\n'
        out = review._sync_reply_trailers(buf, ['Acked-by'], self.IDENTITY)
        assert out == buf

    def test_crlf_buffer_healed(self) -> None:
        buf = 'Thanks!\r\n\r\nFixes: 1234567890ab ("x")\r\n'
        out = review._sync_reply_trailers(buf, ['Reviewed-by'], self.IDENTITY)
        assert '\r' not in out
        assert 'Fixes: 1234567890ab ("x")' in out
        assert f'Reviewed-by: {self.IDENTITY}' in out


class TestBuildReviewEmailReplyPath:
    """The verbatim reply path must not relocate or duplicate trailers."""

    @staticmethod
    def _series() -> Dict[str, Any]:
        return {
            'subject': 'Test patch',
            'fromname': 'Author',
            'fromemail': 'author@example.com',
            'header-info': {
                'msgid': 'test-msgid@example.com',
                'to': 'maintainer@example.com',
                'cc': '',
                'references': '',
                'sentdate': 'Mon, 01 Jan 2024 00:00:00 +0000',
            },
        }

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch(
        'b4.get_user_config',
        return_value={'name': 'Reviewer', 'email': 'reviewer@example.com'},
    )
    def test_inline_trailer_not_duplicated(
        self, _cfg: mock.Mock, _sig: mock.Mock
    ) -> None:
        reply = 'Looks good, thanks.\n\nReviewed-by: Me <me@example.com>\n'
        rev = {
            'reply': reply,
            'trailers': ['Reviewed-by: Me <me@example.com>'],
        }
        msg = review._build_review_email(self._series(), None, rev, '', '', None)
        assert msg is not None
        raw = msg.get_payload(decode=True)
        assert isinstance(raw, bytes)
        body = raw.decode()
        assert body.count('Reviewed-by: Me <me@example.com>') == 1

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch(
        'b4.get_user_config',
        return_value={'name': 'Reviewer', 'email': 'reviewer@example.com'},
    )
    def test_prose_colon_not_relocated(self, _cfg: mock.Mock, _sig: mock.Mock) -> None:
        reply = (
            'You need to Cc\n'
            'stable: without that fix things break.\n'
            '\n'
            'Reviewed-by: Me <me@example.com>\n'
        )
        rev = {'reply': reply, 'trailers': ['Reviewed-by: Me <me@example.com>']}
        msg = review._build_review_email(self._series(), None, rev, '', '', None)
        assert msg is not None
        raw = msg.get_payload(decode=True)
        assert isinstance(raw, bytes)
        body = raw.decode()
        # The "stable:" line stays in place, once, right after the Cc line.
        assert body.count('stable: without that fix things break.') == 1
        cc_idx = body.index('You need to Cc')
        stable_idx = body.index('stable: without that fix things break.')
        rvb_idx = body.index('Reviewed-by: Me <me@example.com>')
        assert cc_idx < stable_idx < rvb_idx

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch(
        'b4.get_user_config',
        return_value={'name': 'Reviewer', 'email': 'reviewer@example.com'},
    )
    def test_trailing_quoted_dropped_in_email(
        self, _cfg: mock.Mock, _sig: mock.Mock
    ) -> None:
        # Quoted diff left below the last comment is dropped from the mail.
        reply = 'Please fix.\n\n> @@ -1,3 +1,3 @@\n> +a\n> +b\n'
        rev = {'reply': reply}
        msg = review._build_review_email(self._series(), None, rev, '', '', None)
        assert msg is not None
        raw = msg.get_payload(decode=True)
        assert isinstance(raw, bytes)
        body = raw.decode()
        assert 'Please fix.' in body
        assert '> +a' not in body and '> +b' not in body


@mock.patch('b4.get_email_signature', return_value='sig')
@mock.patch(
    'b4.get_user_config',
    return_value={'name': 'Reviewer', 'email': 'reviewer@example.com'},
)
class TestReviewReplyTemplate:
    """Tests for review-reply-template wrapping in _build_review_email()."""

    @staticmethod
    def _series() -> Dict[str, Any]:
        return {
            'subject': 'Test patch',
            'fromname': 'Jane Developer',
            'fromemail': 'jane@example.com',
            'header-info': {
                'msgid': 'test-msgid@example.com',
                'to': 'maintainer@example.com',
                'cc': '',
                'references': '',
                'sentdate': 'Mon, 01 Jan 2024 00:00:00 +0000',
            },
        }

    @staticmethod
    def _body(rev: Dict[str, Any], tpt_content: Optional[str], tmp_path: Any) -> str:
        """Build a review email with the given template and return its body."""
        config: Dict[str, Any] = {'review-reply-template': None}
        if tpt_content is not None:
            tptfile = tmp_path / 'reply-template'
            tptfile.write_text(tpt_content, encoding='utf-8')
            config['review-reply-template'] = str(tptfile)
        with mock.patch('b4.get_main_config', return_value=config):
            msg = review._build_review_email(
                TestReviewReplyTemplate._series(), None, rev, '', '', None
            )
        assert msg is not None
        raw = msg.get_payload(decode=True)
        assert isinstance(raw, bytes)
        return raw.decode()

    def test_template_wraps_reply(
        self, _cfg: mock.Mock, _sig: mock.Mock, tmp_path: Any
    ) -> None:
        tpt = (
            '# This comment line must be removed\n'
            'Hi ${firstname},\n'
            '\n'
            '${reply}\n'
            '\n'
            'Cheers,\n'
            '${myname}\n'
        )
        body = self._body({'reply': 'Looks good.\n'}, tpt, tmp_path)
        assert body.startswith('Hi Jane,')
        assert 'Looks good.' in body
        assert 'Cheers,\nReviewer' in body
        assert '# This comment line must be removed' not in body
        # Template order: greeting, reply, sign-off, auto-appended signature
        assert (
            body.index('Hi Jane,')
            < body.index('Looks good.')
            < body.index('Cheers,')
            < body.index('\n-- \nsig')
        )

    def test_no_template_configured(
        self, _cfg: mock.Mock, _sig: mock.Mock, tmp_path: Any
    ) -> None:
        body = self._body({'reply': 'Looks good.\n'}, None, tmp_path)
        assert body.startswith('Looks good.')
        assert 'Hi ' not in body

    def test_missing_template_file_ignored(
        self, _cfg: mock.Mock, _sig: mock.Mock, tmp_path: Any
    ) -> None:
        config = {'review-reply-template': str(tmp_path / 'nonexistent')}
        with mock.patch('b4.get_main_config', return_value=config):
            msg = review._build_review_email(
                self._series(), None, {'reply': 'Looks good.\n'}, '', '', None
            )
        assert msg is not None
        raw = msg.get_payload(decode=True)
        assert isinstance(raw, bytes)
        assert raw.decode().startswith('Looks good.')

    def test_template_without_reply_placeholder_ignored(
        self, _cfg: mock.Mock, _sig: mock.Mock, tmp_path: Any
    ) -> None:
        body = self._body({'reply': 'Looks good.\n'}, 'Hi ${firstname},\n', tmp_path)
        assert body.startswith('Looks good.')
        assert 'Hi Jane,' not in body

    def test_firstname_falls_back_to_localpart(
        self, _cfg: mock.Mock, _sig: mock.Mock, tmp_path: Any
    ) -> None:
        tpt = 'Hi ${firstname},\n\n${reply}\n'
        series = self._series()
        series['fromname'] = ''
        tptfile = tmp_path / 'reply-template'
        tptfile.write_text(tpt, encoding='utf-8')
        config = {'review-reply-template': str(tptfile)}
        with mock.patch('b4.get_main_config', return_value=config):
            msg = review._build_review_email(
                series, None, {'reply': 'Looks good.\n'}, '', '', None
            )
        assert msg is not None
        raw = msg.get_payload(decode=True)
        assert isinstance(raw, bytes)
        assert raw.decode().startswith('Hi jane,')

    def test_signature_placeholder_no_double_append(
        self, _cfg: mock.Mock, _sig: mock.Mock, tmp_path: Any
    ) -> None:
        tpt = '${reply}\n\nCheers,\n-- \n${signature}\n'
        body = self._body({'reply': 'Looks good.\n'}, tpt, tmp_path)
        assert body.count('sig') == 1
        assert body.count('-- ') == 1

    def test_trailer_only_reply_wrapped(
        self, _cfg: mock.Mock, _sig: mock.Mock, tmp_path: Any
    ) -> None:
        tpt = 'Hi ${firstname},\n\n${reply}\n\nCheers,\n'
        rev = {'trailers': ['Reviewed-by: Me <me@example.com>']}
        body = self._body(rev, tpt, tmp_path)
        assert body.startswith('Hi Jane,')
        # Auto-composed content (attribution + trailers) lands inside ${reply}
        assert 'wrote:' in body
        assert 'Reviewed-by: Me <me@example.com>' in body
        assert body.index('Hi Jane,') < body.index('wrote:')
        assert body.index('Reviewed-by:') < body.index('Cheers,')


@requires_textual
class TestAddrsToLines:
    """Tests for review_tui._addrs_to_lines()."""

    def test_empty_string(self) -> None:
        assert review_tui._addrs_to_lines('') == ''

    def test_single_bare_email(self) -> None:
        assert review_tui._addrs_to_lines('user@example.com') == 'user@example.com'

    def test_single_named_address(self) -> None:
        result = review_tui._addrs_to_lines('Alice <alice@example.com>')
        assert result == 'Alice <alice@example.com>'

    def test_multiple_addresses(self) -> None:
        header = 'Alice <alice@example.com>, bob@example.com'
        lines = review_tui._addrs_to_lines(header).splitlines()
        assert len(lines) == 2
        assert lines[0] == 'Alice <alice@example.com>'
        assert lines[1] == 'bob@example.com'

    def test_quoted_name(self) -> None:
        header = '"O\'Brien, Alice" <alice@example.com>'
        result = review_tui._addrs_to_lines(header)
        assert 'alice@example.com' in result


@requires_textual
class TestLinesToHeader:
    """Tests for review_tui._lines_to_header()."""

    def test_empty_string(self) -> None:
        assert review_tui._lines_to_header('') == ''

    def test_whitespace_only(self) -> None:
        assert review_tui._lines_to_header('   \n  ') == ''

    def test_single_bare_email(self) -> None:
        result = review_tui._lines_to_header('user@example.com')
        assert 'user@example.com' in result

    def test_single_named_address(self) -> None:
        result = review_tui._lines_to_header('Alice <alice@example.com>')
        assert 'alice@example.com' in result
        assert 'Alice' in result

    def test_multiple_lines(self) -> None:
        text = 'Alice <alice@example.com>\nbob@example.com'
        result = review_tui._lines_to_header(text)
        assert 'alice@example.com' in result
        assert 'bob@example.com' in result
        # Should be comma-separated
        assert ',' in result

    def test_blank_lines_ignored(self) -> None:
        text = 'alice@example.com\n\nbob@example.com\n'
        result = review_tui._lines_to_header(text)
        assert 'alice@example.com' in result
        assert 'bob@example.com' in result


@requires_textual
class TestValidateAddrs:
    """Tests for review_tui._validate_addrs()."""

    def test_empty_is_valid(self) -> None:
        assert review_tui._validate_addrs('') is None

    def test_whitespace_is_valid(self) -> None:
        assert review_tui._validate_addrs('  \n  ') is None

    def test_valid_bare_email(self) -> None:
        assert review_tui._validate_addrs('user@example.com') is None

    def test_valid_named_address(self) -> None:
        assert review_tui._validate_addrs('Alice <alice@example.com>') is None

    def test_valid_multiple_lines(self) -> None:
        text = 'Alice <alice@example.com>\nbob@example.com'
        assert review_tui._validate_addrs(text) is None

    def test_bare_word_rejected(self) -> None:
        result = review_tui._validate_addrs('notanemail')
        assert result is not None
        assert 'Invalid' in result

    def test_missing_at_rejected(self) -> None:
        result = review_tui._validate_addrs('Alice <notanemail>')
        assert result is not None
        assert 'Invalid' in result

    def test_mixed_valid_and_invalid(self) -> None:
        text = 'alice@example.com\nnotanemail'
        result = review_tui._validate_addrs(text)
        assert result is not None

    def test_blank_lines_skipped(self) -> None:
        text = 'alice@example.com\n\nbob@example.com'
        assert review_tui._validate_addrs(text) is None


@requires_textual
class TestAddrsRoundTrip:
    """Round-trip: _addrs_to_lines → _lines_to_header preserves addresses."""

    def test_single_named(self) -> None:
        header = 'Alice <alice@example.com>'
        lines = review_tui._addrs_to_lines(header)
        result = review_tui._lines_to_header(lines)
        assert 'alice@example.com' in result
        assert 'Alice' in result

    def test_multiple(self) -> None:
        header = 'Alice <alice@example.com>, Bob <bob@example.com>'
        lines = review_tui._addrs_to_lines(header)
        result = review_tui._lines_to_header(lines)
        assert 'alice@example.com' in result
        assert 'bob@example.com' in result

    def test_empty(self) -> None:
        assert review_tui._lines_to_header(review_tui._addrs_to_lines('')) == ''


# -- Tests for make_review_magic_json() --------------------------------------


class TestMakeReviewMagicJson:
    """Tests for make_review_magic_json()."""

    def test_starts_with_magic_marker(self) -> None:
        result = review.make_review_magic_json({'key': 'value'})
        assert result.startswith(REVIEW_MAGIC_MARKER + '\n')

    def test_json_payload_parses_back(self) -> None:
        data = {'revision': 3, 'change-id': 'abc-123', 'tags': ['a', 'b']}
        result = review.make_review_magic_json(data)
        # Strip the two header lines to get the JSON
        lines = result.split('\n', 2)
        parsed = json.loads(lines[2])
        assert parsed == data

    def test_empty_dict(self) -> None:
        result = review.make_review_magic_json({})
        lines = result.split('\n', 2)
        assert json.loads(lines[2]) == {}


# -- Tests for _get_my_review() ----------------------------------------------


class TestGetMyReview:
    """Tests for _get_my_review()."""

    def test_returns_matching_entry(self) -> None:
        target = {
            'reviews': {
                'user@example.com': {'name': 'User', 'trailers': ['Reviewed-by: User']},
            }
        }
        result = review._get_my_review(target, {'email': 'user@example.com'})
        assert result == {'name': 'User', 'trailers': ['Reviewed-by: User']}

    def test_returns_empty_dict_when_absent(self) -> None:
        target = {
            'reviews': {
                'other@example.com': {'name': 'Other'},
            }
        }
        result = review._get_my_review(target, {'email': 'user@example.com'})
        assert result == {}

    def test_returns_empty_dict_when_no_reviews_key(self) -> None:
        result = review._get_my_review({}, {'email': 'user@example.com'})
        assert result == {}

    def test_does_not_mutate_target(self) -> None:
        target: Dict[str, Any] = {}
        review._get_my_review(target, {'email': 'user@example.com'})
        assert 'reviews' not in target


# -- Tests for _ensure_my_review() -------------------------------------------


class TestEnsureMyReview:
    """Tests for _ensure_my_review()."""

    def test_creates_entry_when_empty(self) -> None:
        target: Dict[str, Any] = {}
        usercfg: Dict[str, Union[str, List[str], None]] = {
            'email': 'user@example.com',
            'name': 'User',
        }
        entry = review._ensure_my_review(target, usercfg)
        assert entry['name'] == 'User'
        assert target['reviews']['user@example.com'] is entry

    def test_returns_existing_and_updates_name(self) -> None:
        existing = {'name': 'Old Name', 'trailers': ['Reviewed-by: Old']}
        target = {'reviews': {'user@example.com': existing}}
        usercfg: Dict[str, Union[str, List[str], None]] = {
            'email': 'user@example.com',
            'name': 'New Name',
        }
        entry = review._ensure_my_review(target, usercfg)
        assert entry is existing
        assert entry['name'] == 'New Name'
        assert entry['trailers'] == ['Reviewed-by: Old']

    def test_mutates_target_in_place(self) -> None:
        target: Dict[str, Any] = {}
        review._ensure_my_review(target, {'email': 'a@b.com', 'name': 'A'})
        assert 'reviews' in target
        assert 'a@b.com' in target['reviews']


# -- Tests for _cleanup_review() ---------------------------------------------


class TestCleanupReview:
    """Tests for _cleanup_review()."""

    def test_removes_name_only_entry(self) -> None:
        target = {'reviews': {'user@example.com': {'name': 'User'}}}
        review._cleanup_review(target, {'email': 'user@example.com'})
        assert 'reviews' not in target

    def test_keeps_entry_with_content(self) -> None:
        target = {
            'reviews': {
                'user@example.com': {
                    'name': 'User',
                    'trailers': ['Reviewed-by: User <user@example.com>'],
                },
            }
        }
        review._cleanup_review(target, {'email': 'user@example.com'})
        assert 'user@example.com' in target['reviews']

    def test_removes_reviews_key_when_last_entry_deleted(self) -> None:
        target = {'reviews': {'user@example.com': {'name': 'User'}}}
        review._cleanup_review(target, {'email': 'user@example.com'})
        assert 'reviews' not in target

    def test_noop_when_user_not_present(self) -> None:
        target = {'reviews': {'other@example.com': {'name': 'Other'}}}
        review._cleanup_review(target, {'email': 'user@example.com'})
        assert 'other@example.com' in target['reviews']

    def test_removes_empty_entry(self) -> None:
        target: Dict[str, Any] = {'reviews': {'user@example.com': {}}}
        review._cleanup_review(target, {'email': 'user@example.com'})
        assert 'reviews' not in target

    def test_keeps_reviews_dict_when_other_entries_remain(self) -> None:
        target = {
            'reviews': {
                'user@example.com': {'name': 'User'},
                'other@example.com': {'name': 'Other', 'trailers': ['Acked-by: Other']},
            }
        }
        review._cleanup_review(target, {'email': 'user@example.com'})
        assert 'user@example.com' not in target['reviews']
        assert 'other@example.com' in target['reviews']


# -- Tests for _clear_other_comments() ---------------------------------------


class TestClearOtherComments:
    """Tests for _clear_other_comments()."""

    def test_removes_other_comments_keeps_own(self) -> None:
        all_reviews = {
            'me@example.com': {
                'name': 'Me',
                'comments': [{'path': 'a.c', 'line': 1, 'text': 'mine'}],
            },
            'other@example.com': {
                'name': 'Other',
                'comments': [{'path': 'b.c', 'line': 2, 'text': 'theirs'}],
                'trailers': ['Acked-by: Other'],
            },
        }
        result = review._clear_other_comments(all_reviews, 'me@example.com')
        assert result is True
        assert 'comments' in all_reviews['me@example.com']
        assert 'comments' not in all_reviews['other@example.com']
        # Other reviewer still has trailers so entry remains
        assert 'other@example.com' in all_reviews

    def test_returns_false_when_nothing_to_do(self) -> None:
        all_reviews = {
            'me@example.com': {
                'name': 'Me',
                'comments': [{'path': 'a.c', 'line': 1, 'text': 'mine'}],
            },
        }
        result = review._clear_other_comments(all_reviews, 'me@example.com')
        assert result is False

    def test_cleans_up_empty_entry_after_removal(self) -> None:
        all_reviews: Dict[str, Dict[str, Any]] = {
            'me@example.com': {'name': 'Me'},
            'other@example.com': {
                'name': 'Other',
                'comments': [{'path': 'a.c', 'line': 1, 'text': 'note'}],
            },
        }
        review._clear_other_comments(all_reviews, 'me@example.com')
        assert 'other@example.com' not in all_reviews

    def test_leaves_trailers_only_reviewer(self) -> None:
        all_reviews: Dict[str, Dict[str, Any]] = {
            'me@example.com': {'name': 'Me'},
            'other@example.com': {
                'name': 'Other',
                'trailers': ['Reviewed-by: Other'],
            },
        }
        result = review._clear_other_comments(all_reviews, 'me@example.com')
        assert result is False
        assert 'other@example.com' in all_reviews


# -- Tests for _ensure_trailers_in_body() ------------------------------------


class TestEnsureTrailersInBody:
    """Tests for _ensure_trailers_in_body()."""

    def test_empty_trailers_returns_unchanged(self) -> None:
        body = 'Some text.\n\n-- \nsig'
        assert review._ensure_trailers_in_body(body, []) == body

    def test_all_present_returns_unchanged(self) -> None:
        trailer = 'Reviewed-by: Test <test@example.com>'
        body = f'Some text.\n\n{trailer}\n\n-- \nsig'
        assert review._ensure_trailers_in_body(body, [trailer]) == body

    def test_appends_missing_before_signature(self) -> None:
        trailer = 'Reviewed-by: Test <test@example.com>'
        body = 'Some text.\n\n-- \nsig'
        result = review._ensure_trailers_in_body(body, [trailer])
        assert trailer in result
        # Trailer appears before signature
        trailer_pos = result.index(trailer)
        sig_pos = result.index('\n-- \n')
        assert trailer_pos < sig_pos

    def test_appends_missing_at_end_when_no_signature(self) -> None:
        trailer = 'Reviewed-by: Test <test@example.com>'
        body = 'Some text.'
        result = review._ensure_trailers_in_body(body, [trailer])
        assert result.endswith(trailer)

    def test_case_insensitive_match(self) -> None:
        trailer = 'Reviewed-by: Test <test@example.com>'
        body = 'Some text.\n\nreviewed-by: test <test@example.com>\n\n-- \nsig'
        result = review._ensure_trailers_in_body(body, [trailer])
        # Should not duplicate — the existing lowercase version counts
        assert result.count('test@example.com') == 1


# -- Tests for _build_review_email() ------------------------------------------


class TestBuildReviewEmail:
    """Tests for _build_review_email() header and body construction."""

    @pytest.fixture(autouse=True)
    def _reviewer_env(self) -> Iterator[None]:
        """Every test runs as the same reviewer with a stub signature."""
        with (
            mock.patch('b4.get_email_signature', return_value='sig'),
            mock.patch(
                'b4.get_user_config',
                return_value={'name': 'Reviewer', 'email': 'reviewer@example.com'},
            ),
        ):
            yield

    @staticmethod
    def _make_series(**header_overrides: str) -> Dict[str, Any]:
        header_info: Dict[str, str] = {
            'msgid': 'test-msgid@example.com',
            'to': 'maintainer@example.com',
            'cc': '',
            'references': '',
            'sentdate': 'Mon, 01 Jan 2024 00:00:00 +0000',
        }
        header_info.update(header_overrides)
        return {
            'subject': 'Test patch',
            'fromname': 'Author',
            'fromemail': 'author@example.com',
            'header-info': header_info,
        }

    @staticmethod
    def _make_review(**overrides: object) -> Dict[str, Any]:
        base: Dict[str, Any] = {'trailers': ['Reviewed-by: Test <test@example.com>']}
        base.update(overrides)
        return base

    def _build(
        self,
        series: Optional[Dict[str, Any]] = None,
        review_data: Optional[Dict[str, Any]] = None,
    ) -> Optional[email.message.EmailMessage]:
        if series is None:
            series = self._make_series()
        if review_data is None:
            review_data = self._make_review()
        return review._build_review_email(series, None, review_data, 'cover', '', None)

    def test_returns_none_when_empty_review(self) -> None:
        msg = self._build(review_data={'trailers': [], 'reply': '', 'comments': []})
        assert msg is None

    def test_returns_none_when_no_msgid(self) -> None:
        msg = self._build(self._make_series(msgid=''))
        assert msg is None

    @pytest.mark.parametrize(
        'subject,expected',
        [
            ('Test patch', 'Re: Test patch'),
            ('Re: Already prefixed', 'Re: Already prefixed'),
        ],
    )
    def test_subject_gets_single_re_prefix(self, subject: str, expected: str) -> None:
        series = self._make_series()
        series['subject'] = subject
        msg = self._build(series)
        assert msg is not None
        assert msg['Subject'] == expected

    def test_reply_to_used_as_to(self) -> None:
        series = self._make_series(**{'reply-to': 'list@lists.example.com'})
        msg = self._build(series)
        assert msg is not None
        assert 'list@lists.example.com' in msg['To']

    def test_references_without_existing(self) -> None:
        msg = self._build()
        assert msg is not None
        assert msg['References'] == '<test-msgid@example.com>'

    def test_references_appended_to_existing(self) -> None:
        series = self._make_series(references='<prev@example.com>')
        msg = self._build(series)
        assert msg is not None
        assert '<prev@example.com>' in msg['References']
        assert '<test-msgid@example.com>' in msg['References']

    def test_in_reply_to_set(self) -> None:
        msg = self._build()
        assert msg is not None
        assert msg['In-Reply-To'] == '<test-msgid@example.com>'

    def test_from_header_is_reviewer(self) -> None:
        msg = self._build()
        assert msg is not None
        assert 'reviewer@example.com' in msg['From']
        assert 'Reviewer' in msg['From']

    def test_body_contains_trailers(self) -> None:
        msg = self._build()
        assert msg is not None
        payload = msg.get_payload(decode=True)
        assert isinstance(payload, bytes)
        assert 'Reviewed-by: Test <test@example.com>' in payload.decode()

    def test_explicit_reply_text_used(self) -> None:
        rev = self._make_review(reply='This is my explicit reply.')
        msg = self._build(review_data=rev)
        assert msg is not None
        payload = msg.get_payload(decode=True)
        assert isinstance(payload, bytes)
        assert 'This is my explicit reply.' in payload.decode()

    @pytest.mark.parametrize(
        'series_kwargs,expected_bcc',
        [
            pytest.param(
                {'bcc': 'secret@example.com'}, 'secret@example.com', id='present'
            ),
            pytest.param({}, None, id='absent'),
            pytest.param({'bcc': ''}, None, id='empty'),
        ],
    )
    def test_bcc_header(
        self, series_kwargs: Dict[str, str], expected_bcc: Optional[str]
    ) -> None:
        msg = self._build(self._make_series(**series_kwargs))
        assert msg is not None
        assert msg['Bcc'] == expected_bcc

    def test_cc_keeps_original_recipients(self) -> None:
        msg = self._build(self._make_series(cc='other@example.com'))
        assert msg is not None
        assert 'other@example.com' in msg['Cc']
        assert 'maintainer@example.com' in msg['Cc']

    def test_default_to_is_author(self) -> None:
        """Without tocc-edited, To should be the original author."""
        msg = self._build()
        assert msg is not None
        assert 'author@example.com' in msg['To']

    def test_default_demotes_to_header_to_cc(self) -> None:
        """Without tocc-edited, original To gets folded into Cc."""
        series = self._make_series(to='list@lists.example.com')
        msg = self._build(series)
        assert msg is not None
        assert 'author@example.com' in msg['To']
        assert 'list@lists.example.com' in msg['Cc']

    def test_edited_to_is_honoured(self) -> None:
        """With tocc-edited, user's To choice should be used as-is."""
        series = self._make_series(to='custom@example.com')
        series['header-info']['tocc-edited'] = True
        msg = self._build(series)
        assert msg is not None
        assert 'custom@example.com' in msg['To']
        assert 'author@example.com' not in (msg['To'] or '')

    def test_edited_cc_is_honoured(self) -> None:
        """With tocc-edited, user's Cc choice should be used as-is."""
        series = self._make_series(to='custom@example.com', cc='other@example.com')
        series['header-info']['tocc-edited'] = True
        msg = self._build(series)
        assert msg is not None
        assert msg['To'] == 'custom@example.com'
        assert msg['Cc'] == 'other@example.com'

    def test_edited_empty_cc_omitted(self) -> None:
        """With tocc-edited, empty Cc should not produce a Cc header."""
        series = self._make_series(to='custom@example.com', cc='')
        series['header-info']['tocc-edited'] = True
        msg = self._build(series)
        assert msg is not None
        assert msg['Cc'] is None


# -- Tests for get_reference_message() ---------------------------------------


class TestGetReferenceMessage:
    """Tests for get_reference_message()."""

    def test_returns_cover_letter(self) -> None:
        lser = mock.Mock()
        lser.has_cover = True
        cover = mock.Mock(spec=b4.LoreMessage)
        patch1 = mock.Mock(spec=b4.LoreMessage)
        lser.patches = [cover, patch1]
        assert review.get_reference_message(lser) is cover

    def test_returns_first_patch_when_no_cover(self) -> None:
        lser = mock.Mock()
        lser.has_cover = False
        patch1 = mock.Mock(spec=b4.LoreMessage)
        lser.patches = [None, patch1]
        assert review.get_reference_message(lser) is patch1

    def test_raises_when_neither_available(self) -> None:
        lser = mock.Mock()
        lser.has_cover = False
        lser.patches = [None]
        with pytest.raises(LookupError):
            review.get_reference_message(lser)

    def test_raises_when_cover_is_none(self) -> None:
        lser = mock.Mock()
        lser.has_cover = True
        lser.patches = [None]
        with pytest.raises(LookupError):
            review.get_reference_message(lser)


# -- Tests for _collect_reply_headers() --------------------------------------


class TestCollectReplyHeaders:
    """Tests for _collect_reply_headers()."""

    @staticmethod
    def _make_lore_message(**headers: str) -> mock.Mock:
        msg = email.message.EmailMessage()
        for key, val in headers.items():
            # email.message uses '-' in header names, but kwargs use '_'
            msg[key.replace('_', '-')] = val
        lmsg = mock.Mock()
        lmsg.msg = msg
        lmsg.msgid = headers.get('message_id', 'test@example.com')
        return lmsg

    def test_extracts_basic_headers(self) -> None:
        lmsg = self._make_lore_message(
            to='Alice <alice@example.com>',
            cc='Bob <bob@example.com>',
            date='Mon, 01 Jan 2024 00:00:00 +0000',
            references='<ref1@example.com>',
        )
        result = review._collect_reply_headers(lmsg)
        assert result['msgid'] == 'test@example.com'
        assert 'alice@example.com' in result['to']
        assert 'bob@example.com' in result['cc']

    def test_includes_reply_to(self) -> None:
        lmsg = self._make_lore_message(
            to='Alice <alice@example.com>',
            reply_to='list@lists.example.com',
        )
        result = review._collect_reply_headers(lmsg)
        assert 'reply-to' in result
        assert 'list@lists.example.com' in result['reply-to']

    def test_no_reply_to_when_absent(self) -> None:
        lmsg = self._make_lore_message(
            to='Alice <alice@example.com>',
        )
        result = review._collect_reply_headers(lmsg)
        assert 'reply-to' not in result

    def test_handles_empty_headers(self) -> None:
        lmsg = self._make_lore_message()
        result = review._collect_reply_headers(lmsg)
        assert result['msgid'] == 'test@example.com'
        assert result['to'] == ''
        assert result['cc'] == ''


# -- Tests for _collect_followups() ------------------------------------------


class TestCollectFollowups:
    """Tests for _collect_followups()."""

    LINKMASK = 'https://lore.example.com/%s'

    @staticmethod
    def _make_followup_trailer(
        name: str,
        value: str,
        msgid: str = 'reply@example.com',
        fromname: str = 'Reviewer',
        fromemail: str = 'reviewer@example.com',
    ) -> b4.LoreTrailer:
        """Build a LoreTrailer with an attached lmsg for followup testing."""
        lt = b4.LoreTrailer(name=name, value=value)
        lt.lmsg = mock.Mock()
        lt.lmsg.msgid = msgid
        lt.lmsg.fromname = fromname
        lt.lmsg.fromemail = fromemail
        return lt

    def _make_lmsg(
        self,
        body: str,
        followup_trailers: List[Any],
    ) -> mock.Mock:
        """Build a mock LoreMessage with body and followup_trailers."""
        lmsg = mock.Mock()
        lmsg.body = body
        lmsg.followup_trailers = followup_trailers
        return lmsg

    def test_basic_followup(self) -> None:
        """A single follow-up trailer is collected."""
        ft = self._make_followup_trailer(
            'Reviewed-by',
            'Reviewer <reviewer@example.com>',
        )
        lmsg = self._make_lmsg('Some patch body\n', [ft])
        result = review._collect_followups(lmsg, self.LINKMASK)
        assert len(result) == 1
        assert result[0]['fromname'] == 'Reviewer'
        assert result[0]['fromemail'] == 'reviewer@example.com'
        assert 'Reviewed-by: Reviewer <reviewer@example.com>' in result[0]['trailers']
        assert result[0]['link'] == 'https://lore.example.com/reply@example.com'

    def test_skips_trailer_without_lmsg(self) -> None:
        """Follow-up trailers without an lmsg are skipped."""
        ft = b4.LoreTrailer(name='Acked-by', value='Someone <s@example.com>')
        ft.lmsg = None
        lmsg = self._make_lmsg('body\n', [ft])
        result = review._collect_followups(lmsg, self.LINKMASK)
        assert len(result) == 0

    def test_skips_trailer_already_in_body(self) -> None:
        """Follow-up trailers already present in the message body are skipped."""
        body = (
            'Patch description\n'
            '\n'
            'Reviewed-by: Reviewer <reviewer@example.com>\n'
            'Signed-off-by: Author <author@example.com>\n'
        )
        ft = self._make_followup_trailer(
            'Reviewed-by',
            'Reviewer <reviewer@example.com>',
        )
        lmsg = self._make_lmsg(body, [ft])
        result = review._collect_followups(lmsg, self.LINKMASK)
        assert len(result) == 0

    def test_keeps_trailer_not_in_body(self) -> None:
        """Follow-up trailers NOT in the body are kept."""
        body = 'Patch description\n\nSigned-off-by: Author <author@example.com>\n'
        ft = self._make_followup_trailer(
            'Acked-by',
            'Acker <acker@example.com>',
        )
        lmsg = self._make_lmsg(body, [ft])
        result = review._collect_followups(lmsg, self.LINKMASK)
        assert len(result) == 1
        assert 'Acked-by: Acker <acker@example.com>' in result[0]['trailers']

    def test_mixed_body_and_new_trailers(self) -> None:
        """Only trailers not already in body are collected."""
        body = (
            'Description\n'
            '\n'
            'Reviewed-by: Reviewer <reviewer@example.com>\n'
            'Signed-off-by: Author <author@example.com>\n'
        )
        ft_dup = self._make_followup_trailer(
            'Reviewed-by',
            'Reviewer <reviewer@example.com>',
            msgid='reply1@example.com',
        )
        ft_new = self._make_followup_trailer(
            'Tested-by',
            'Tester <tester@example.com>',
            msgid='reply2@example.com',
            fromname='Tester',
            fromemail='tester@example.com',
        )
        lmsg = self._make_lmsg(body, [ft_dup, ft_new])
        result = review._collect_followups(lmsg, self.LINKMASK)
        assert len(result) == 1
        assert result[0]['fromname'] == 'Tester'
        assert 'Tested-by: Tester <tester@example.com>' in result[0]['trailers']

    def test_groups_by_msgid(self) -> None:
        """Multiple trailers from the same reply are grouped together."""
        ft1 = self._make_followup_trailer(
            'Reviewed-by',
            'Reviewer <reviewer@example.com>',
            msgid='reply@example.com',
        )
        ft2 = self._make_followup_trailer(
            'Tested-by',
            'Reviewer <reviewer@example.com>',
            msgid='reply@example.com',
        )
        lmsg = self._make_lmsg('body\n', [ft1, ft2])
        result = review._collect_followups(lmsg, self.LINKMASK)
        assert len(result) == 1
        assert len(result[0]['trailers']) == 2

    def test_empty_followups(self) -> None:
        """No follow-up trailers returns empty list."""
        lmsg = self._make_lmsg('body\n', [])
        result = review._collect_followups(lmsg, self.LINKMASK)
        assert result == []


# -- Tests for _get_art_counts() ---------------------------------------------


@requires_textual
class TestGetArtCounts:
    """Tests for _get_art_counts() in _tracking_app."""

    @staticmethod
    def _make_tracking_json(
        followups: Optional[List[Dict[str, Any]]] = None,
        patches: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """Build a tracking commit message with the given followup data."""
        tracking: Dict[str, Any] = {}
        if followups is not None:
            tracking['followups'] = followups
        if patches is not None:
            tracking['patches'] = patches
        return 'Cover letter text\n\n--- b4-review-tracking ---\n' + json.dumps(
            tracking
        )

    @mock.patch('b4.git_run_command')
    def test_counts_all_trailer_types(self, mock_git: mock.Mock) -> None:
        """Counts Acked-by, Reviewed-by, and Tested-by from followups."""
        commit_msg = self._make_tracking_json(
            followups=[
                {
                    'trailers': [
                        'Acked-by: A <a@example.com>',
                        'Reviewed-by: R <r@example.com>',
                    ]
                },
            ],
            patches=[
                {
                    'followups': [
                        {
                            'trailers': [
                                'Tested-by: T <t@example.com>',
                                'Acked-by: B <b@example.com>',
                            ]
                        },
                    ]
                },
            ],
        )
        mock_git.return_value = (0, commit_msg)
        from b4.review_tui._tracking_app import _get_art_counts

        result = _get_art_counts('/tmp', 'b4/review/test')
        assert result == (2, 1, 1)

    @mock.patch('b4.git_run_command')
    def test_returns_none_on_git_failure(self, mock_git: mock.Mock) -> None:
        mock_git.return_value = (1, '')
        from b4.review_tui._tracking_app import _get_art_counts

        assert _get_art_counts('/tmp', 'b4/review/test') is None

    @mock.patch('b4.git_run_command')
    def test_returns_none_without_marker(self, mock_git: mock.Mock) -> None:
        mock_git.return_value = (0, 'Just a commit message without marker')
        from b4.review_tui._tracking_app import _get_art_counts

        assert _get_art_counts('/tmp', 'b4/review/test') is None

    @mock.patch('b4.git_run_command')
    def test_returns_zeros_without_followups(self, mock_git: mock.Mock) -> None:
        commit_msg = self._make_tracking_json(patches=[{'followups': []}])
        mock_git.return_value = (0, commit_msg)
        from b4.review_tui._tracking_app import _get_art_counts

        assert _get_art_counts('/tmp', 'b4/review/test') == (0, 0, 0)

    @mock.patch('b4.git_run_command')
    def test_ignores_non_art_trailers(self, mock_git: mock.Mock) -> None:
        """Trailers like Signed-off-by are not counted."""
        commit_msg = self._make_tracking_json(
            followups=[
                {
                    'trailers': [
                        'Signed-off-by: S <s@example.com>',
                        'Reviewed-by: R <r@example.com>',
                    ]
                },
            ],
        )
        mock_git.return_value = (0, commit_msg)
        from b4.review_tui._tracking_app import _get_art_counts

        assert _get_art_counts('/tmp', 'b4/review/test') == (0, 1, 0)

    @mock.patch('b4.git_run_command')
    def test_skips_comment_lines_in_json(self, mock_git: mock.Mock) -> None:
        """Lines starting with # in the JSON block are ignored."""
        tracking = json.dumps(
            {'followups': [{'trailers': ['Acked-by: A <a@example.com>']}]}
        )
        commit_msg = 'Cover\n\n--- b4-review-tracking ---\n# comment line\n' + tracking
        mock_git.return_value = (0, commit_msg)
        from b4.review_tui._tracking_app import _get_art_counts

        assert _get_art_counts('/tmp', 'b4/review/test') == (1, 0, 0)


@requires_textual
class TestParseArtFromMessage:
    """Tests for the extracted _parse_art_from_message() helper."""

    @staticmethod
    def _make_msg(
        followups: Optional[List[Dict[str, Any]]] = None,
        patches: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        tracking: Dict[str, Any] = {}
        if followups is not None:
            tracking['followups'] = followups
        if patches is not None:
            tracking['patches'] = patches
        return 'Cover letter text\n\n--- b4-review-tracking ---\n' + json.dumps(
            tracking
        )

    def test_counts_trailers(self) -> None:
        from b4.review_tui._tracking_app import _parse_art_from_message

        msg = self._make_msg(
            followups=[
                {
                    'trailers': [
                        'Acked-by: A <a@example.com>',
                        'Reviewed-by: R <r@example.com>',
                    ]
                }
            ],
            patches=[{'followups': [{'trailers': ['Tested-by: T <t@example.com>']}]}],
        )
        assert _parse_art_from_message(msg) == (1, 1, 1)

    def test_returns_none_without_marker(self) -> None:
        from b4.review_tui._tracking_app import _parse_art_from_message

        assert _parse_art_from_message('no marker here') is None

    def test_returns_none_on_bad_json(self) -> None:
        from b4.review_tui._tracking_app import _parse_art_from_message

        assert (
            _parse_art_from_message('text\n\n--- b4-review-tracking ---\n{bad json')
            is None
        )


# -- Tests for note comment stripping ----------------------------------------


class TestNoteCommentStripping:
    """Tests for _strip_note_footer(), used when saving an edited note."""

    @staticmethod
    def _strip_comments(raw_text: str) -> str:
        from b4.review_tui._review_app import _strip_note_footer

        return _strip_note_footer(raw_text)

    def test_strips_footer(self) -> None:
        raw = (
            'My note here\n'
            '\n'
            '# Add a private note about this patch. It will not be sent in your\n'
            '# email reply, but it will be stored in the tracking commit and\n'
            '# viewable by anyone if you push this branch to any remote.\n'
            '#\n'
            '# This trailing block of # lines will be removed. Any # you write\n'
            '# above it is kept as part of your note.\n'
        )
        assert self._strip_comments(raw) == 'My note here'

    def test_keeps_hash_lines_above_the_footer(self) -> None:
        raw = (
            'I had written\n'
            '#define arm_smmu_kdump_is_attach_deferred NULL\n'
            '\n'
            '# Lines starting with # will be removed.\n'
        )
        assert self._strip_comments(raw) == (
            'I had written\n#define arm_smmu_kdump_is_attach_deferred NULL'
        )

    def test_preserves_non_comment_lines(self) -> None:
        raw = 'Line one\nLine two\nLine three'
        assert self._strip_comments(raw) == 'Line one\nLine two\nLine three'

    def test_empty_after_stripping(self) -> None:
        raw = '# Only comments\n# Nothing else'
        assert self._strip_comments(raw) == ''

    def test_mixed_content(self) -> None:
        raw = '# TODO: revisit\nNeed to check NULL path\n# end'
        assert self._strip_comments(raw) == '# TODO: revisit\nNeed to check NULL path'


# -- Helpers for attestation tests -------------------------------------------


def _make_mock_attestation(status: str, identity: str, passing: bool) -> Dict[str, Any]:
    """Build an attestation dict as returned by LoreMessage.get_attestation_status()."""
    return {'status': status, 'identity': identity, 'passing': passing}


def _make_mock_lmsg(
    attestations: List[Dict[str, Any]], passing: bool = True, critical: bool = False
) -> mock.Mock:
    """Build a mock LoreMessage with a canned get_attestation_status() response."""
    lmsg = mock.Mock()
    lmsg.get_attestation_status = mock.Mock(
        return_value=(attestations, passing, critical)
    )
    return lmsg


# -- Tests for check_series_attestation() ------------------------------------


class TestCheckSeriesAttestation:
    """Tests for check_series_attestation()."""

    def _make_series(self, patch_msgs: List[mock.Mock]) -> mock.Mock:
        """Build a mock LoreSeries with given patch messages (index 0 = cover)."""
        lser = mock.Mock()
        lser.patches = [None] + patch_msgs  # patches[0] is the cover letter
        return lser

    def test_policy_off_returns_none(self) -> None:
        """When attestation-policy is 'off', returns None immediately."""
        lser = self._make_series([_make_mock_lmsg([])])
        with mock.patch(
            'b4.get_main_config', return_value={'attestation-policy': 'off'}
        ):
            assert check_series_attestation(lser) is None

    def test_no_signatures_returns_none_string(self) -> None:
        """When no attestors found on any patch, returns 'none'."""
        lser = self._make_series([_make_mock_lmsg([]), _make_mock_lmsg([])])
        with mock.patch(
            'b4.get_main_config', return_value={'attestation-policy': 'softfail'}
        ):
            assert check_series_attestation(lser) == 'none'

    def test_single_signed_dkim(self) -> None:
        """A single passing DKIM attestor is reported correctly."""
        att = [_make_mock_attestation('signed', 'DKIM/kernel.org', True)]
        lser = self._make_series([_make_mock_lmsg(att)])
        with mock.patch(
            'b4.get_main_config', return_value={'attestation-policy': 'softfail'}
        ):
            result = check_series_attestation(lser)
        assert result == 'signed:DKIM/kernel.org'

    def test_nokey_attestor(self) -> None:
        """A nokey attestor is reported with status 'nokey'."""
        att = [_make_mock_attestation('nokey', 'ed25519/user@example.com', False)]
        lser = self._make_series([_make_mock_lmsg(att)])
        with mock.patch(
            'b4.get_main_config', return_value={'attestation-policy': 'softfail'}
        ):
            result = check_series_attestation(lser)
        assert result == 'nokey:ed25519/user@example.com'

    def test_badsig_attestor(self) -> None:
        """A badsig attestor is reported with status 'badsig'."""
        att = [_make_mock_attestation('badsig', 'ed25519/user@example.com', False)]
        lser = self._make_series([_make_mock_lmsg(att)])
        with mock.patch(
            'b4.get_main_config', return_value={'attestation-policy': 'softfail'}
        ):
            result = check_series_attestation(lser)
        assert result == 'badsig:ed25519/user@example.com'

    def test_mixed_attestors(self) -> None:
        """Mixed signed and nokey attestors are semicolon-separated and sorted."""
        att = [
            _make_mock_attestation('signed', 'DKIM/kernel.org', True),
            _make_mock_attestation('nokey', 'ed25519/user@example.com', False),
        ]
        lser = self._make_series([_make_mock_lmsg(att)])
        with mock.patch(
            'b4.get_main_config', return_value={'attestation-policy': 'softfail'}
        ):
            result = check_series_attestation(lser)
        # Sorted by (status, identity): nokey < signed alphabetically
        assert result is not None
        parts = result.split(';')
        assert len(parts) == 2
        assert 'signed:DKIM/kernel.org' in parts
        assert 'nokey:ed25519/user@example.com' in parts

    def test_deduplicates_across_patches(self) -> None:
        """Same attestor on multiple patches is only reported once."""
        att = [_make_mock_attestation('signed', 'DKIM/kernel.org', True)]
        lser = self._make_series([_make_mock_lmsg(att), _make_mock_lmsg(att)])
        with mock.patch(
            'b4.get_main_config', return_value={'attestation-policy': 'softfail'}
        ):
            result = check_series_attestation(lser)
        assert result == 'signed:DKIM/kernel.org'

    def test_none_patches_skipped(self) -> None:
        """None entries in patches list are skipped gracefully."""
        att = [_make_mock_attestation('signed', 'DKIM/kernel.org', True)]
        lser = mock.Mock()
        lser.patches = [None, None, _make_mock_lmsg(att), None]
        with mock.patch(
            'b4.get_main_config', return_value={'attestation-policy': 'softfail'}
        ):
            result = check_series_attestation(lser)
        assert result == 'signed:DKIM/kernel.org'

    def test_staleness_days_passed_to_attestation(self) -> None:
        """attestation-staleness-days config is passed through correctly."""
        att = [_make_mock_attestation('signed', 'DKIM/kernel.org', True)]
        lmsg = _make_mock_lmsg(att)
        lser = self._make_series([lmsg])
        config = {'attestation-policy': 'softfail', 'attestation-staleness-days': '30'}
        with mock.patch('b4.get_main_config', return_value=config):
            check_series_attestation(lser)
        lmsg.get_attestation_status.assert_called_once_with('softfail', 30)

    def test_invalid_staleness_days_defaults_to_zero(self) -> None:
        """Non-numeric staleness-days falls back to 0."""
        att = [_make_mock_attestation('signed', 'DKIM/kernel.org', True)]
        lmsg = _make_mock_lmsg(att)
        lser = self._make_series([lmsg])
        config = {
            'attestation-policy': 'softfail',
            'attestation-staleness-days': 'garbage',
        }
        with mock.patch('b4.get_main_config', return_value=config):
            check_series_attestation(lser)
        lmsg.get_attestation_status.assert_called_once_with('softfail', 0)

    def test_default_policy_softfail(self) -> None:
        """When no attestation-policy set, defaults to softfail (not off)."""
        att = [_make_mock_attestation('signed', 'DKIM/kernel.org', True)]
        lmsg = _make_mock_lmsg(att)
        lser = self._make_series([lmsg])
        with mock.patch('b4.get_main_config', return_value={}):
            result = check_series_attestation(lser)
        assert result == 'signed:DKIM/kernel.org'


# -- Tests for sashiko inline review conversion and integration ---------------

# A sashiko inline_review with two hunks and two comments
_SASHIKO_INLINE = """\
commit ea336c9a36385d0aabe371a1bcbf38c730add763
Author: Julian Ruess <julianr@linux.ibm.com>

vfio/ism: Implement vfio_pci driver for ISM devices

> diff --git a/drivers/vfio/pci/ism/main.c b/drivers/vfio/pci/ism/main.c
> @@ -83,12 +83,12 @@ static ssize_t ism_vfio_pci_do_io_w(struct vfio_device *core_vdev,
>  	if (((off % PAGE_SIZE) + count) > PAGE_SIZE)
>  		return -EINVAL;

Could an unaligned count here trigger a specification exception?

[ ... ]

> @@ -311,10 +311,10 @@ static void ism_vfio_pci_remove(struct pci_dev *pdev)
>  	vfio_put_device(&ivpcd->core_device.vdev);
>  	kmem_cache_destroy(ivpcd->store_block_cache);

Can this cause a use-after-free of ivpcd?
"""


class TestExtractCommentsFromQuotedReply:
    """Tests for _extract_comments_from_quoted_reply()."""

    def test_sashiko_fixture_produces_two_comments(self) -> None:
        """The _SASHIKO_INLINE fixture (two hunks) produces two comments."""
        comments = review._extract_comments_from_quoted_reply(_SASHIKO_INLINE)
        assert len(comments) == 2
        assert 'unaligned count' in comments[0]['text']
        assert comments[0]['path'] == 'drivers/vfio/pci/ism/main.c'
        assert 'use-after-free' in comments[1]['text']
        assert comments[1]['path'] == 'drivers/vfio/pci/ism/main.c'

    def test_sashiko_fixture_line_numbers(self) -> None:
        """Line numbers track hunk offsets correctly."""
        comments = review._extract_comments_from_quoted_reply(_SASHIKO_INLINE)
        # First hunk: @@ -83,12 +83,12 @@ — two context lines shown (+83, +84)
        # Comment anchors after the second context line
        assert comments[0]['line'] == 84
        # Second hunk: @@ -311,10 +311,10 @@ — two context lines (+311, +312)
        assert comments[1]['line'] == 312

    def test_content_key_set(self) -> None:
        """The content key records the last diff line before each comment."""
        comments = review._extract_comments_from_quoted_reply(_SASHIKO_INLINE)
        assert 'content' in comments[0]
        assert 'EINVAL' in comments[0]['content']
        assert 'content' in comments[1]
        assert 'store_block_cache' in comments[1]['content']

    def test_single_hunk_single_comment(self) -> None:
        """A minimal single-hunk inline review produces one comment."""
        inline = (
            'commit abc123\n'
            'Author: Test <test@test.com>\n'
            '\n'
            'Test patch\n'
            '\n'
            '> diff --git a/fs/file.c b/fs/file.c\n'
            '> @@ -10,4 +10,5 @@ void func(void)\n'
            '>  \tint x;\n'
            '> +\tptr = malloc(sz);\n'
            '\n'
            'Missing NULL check after malloc.\n'
            '\n'
            '>  \treturn 0;\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert 'NULL check' in comments[0]['text']
        assert comments[0]['path'] == 'fs/file.c'
        # +malloc is at +11, comment anchors there
        assert comments[0]['line'] == 11

    def test_no_diff_produces_no_comments(self) -> None:
        """Text with no quoted diff content produces nothing."""
        inline = 'commit abc123\nAuthor: Test\n\nJust text, no diffs.\n'
        comments = review._extract_comments_from_quoted_reply(inline)
        assert comments == []

    def test_truncation_markers_skipped(self) -> None:
        """'[ ... ]' markers don't appear in comment text."""
        inline = (
            '> diff --git a/f.c b/f.c\n'
            '> @@ -1,3 +1,4 @@\n'
            '>  ctx\n'
            '> +new\n'
            '\n'
            'Comment here.\n'
            '\n'
            '[ ... ]\n'
            '\n'
            '> @@ -10,3 +10,4 @@\n'
            '>  ctx2\n'
            '> +new2\n'
            '\n'
            'Another comment.\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 2
        assert '[ ... ]' not in comments[0]['text']
        assert 'Comment here.' == comments[0]['text']
        assert 'Another comment.' == comments[1]['text']

    def test_multiline_comment(self) -> None:
        """Multiple non-quoted lines between diff sections form one comment."""
        inline = (
            '> diff --git a/f.c b/f.c\n'
            '> @@ -5,3 +5,4 @@ void f(void)\n'
            '>  \tint a;\n'
            '> +\tint b;\n'
            '\n'
            'This variable name is confusing.\n'
            'Consider using a more descriptive name.\n'
            '\n'
            '>  \treturn;\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert 'confusing' in comments[0]['text']
        assert 'descriptive' in comments[0]['text']

    def test_multi_paragraph_comment_stays_merged(self) -> None:
        """Two paragraphs separated by a blank line become one comment."""
        inline = (
            '> diff --git a/f.c b/f.c\n'
            '> --- a/f.c\n'
            '> +++ b/f.c\n'
            '> @@ -5,3 +5,5 @@ void f(void)\n'
            '>  \tint a;\n'
            '> +\tint b;\n'
            '> +\tint c;\n'
            '\n'
            'First paragraph of review.\n'
            '\n'
            'Second paragraph of review.\n'
            '\n'
            '>  \treturn;\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert 'First paragraph' in comments[0]['text']
        assert 'Second paragraph' in comments[0]['text']

    def test_comments_in_different_hunks_stay_separate(self) -> None:
        """Comments in different hunks (far apart) stay separate."""
        inline = (
            '> diff --git a/f.c b/f.c\n'
            '> --- a/f.c\n'
            '> +++ b/f.c\n'
            '> @@ -5,3 +5,4 @@\n'
            '>  \tint a;\n'
            '> +\tint b;\n'
            '\n'
            'Comment on hunk 1.\n'
            '\n'
            '>  \treturn;\n'
            '> @@ -100,3 +101,4 @@\n'
            '>  \tvoid x;\n'
            '> +\tvoid y;\n'
            '\n'
            'Comment on hunk 2.\n'
            '\n'
            '>  \treturn;\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 2
        assert 'hunk 1' in comments[0]['text']
        assert 'hunk 2' in comments[1]['text']

    def test_email_reply_with_file_headers(self) -> None:
        """Email follow-ups include --- a/ and +++ b/ lines; parser handles them."""
        email_reply = (
            'On Mon, Jan 1, 2024, Dev <dev@test.com> wrote:\n'
            '> diff --git a/fs/file.c b/fs/file.c\n'
            '> index abc123..def456 100644\n'
            '> --- a/fs/file.c\n'
            '> +++ b/fs/file.c\n'
            '> @@ -10,3 +10,4 @@ void f(void)\n'
            '>  \tint x;\n'
            '> +\tptr = malloc(sz);\n'
            '\n'
            'Missing NULL check.\n'
            '\n'
            '>  \treturn 0;\n'
        )
        comments = review._extract_comments_from_quoted_reply(email_reply)
        assert len(comments) == 1
        assert 'NULL check' in comments[0]['text']
        # With explicit +++ b/ header, path includes the b/ prefix
        assert comments[0]['path'] == 'b/fs/file.c'

    def test_bare_gt_prefix(self) -> None:
        """Lines starting with just '>' (no space) are also parsed."""
        inline = (
            '>diff --git a/f.c b/f.c\n>@@ -1,3 +1,4 @@\n> ctx\n>+new\n\nLooks good.\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert 'Looks good.' == comments[0]['text']

    def test_comments_in_different_files(self) -> None:
        """Comments in different files produce separate entries with correct paths."""
        inline = (
            '> diff --git a/a.c b/a.c\n'
            '> @@ -1,3 +1,4 @@\n'
            '>  ctx\n'
            '> +new_a\n'
            '\n'
            'Comment in a.c.\n'
            '\n'
            '> diff --git a/b.c b/b.c\n'
            '> @@ -1,3 +1,4 @@\n'
            '>  ctx\n'
            '> +new_b\n'
            '\n'
            'Comment in b.c.\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 2
        assert comments[0]['path'] == 'a.c'
        assert 'a.c' in comments[0]['text']
        assert comments[1]['path'] == 'b.c'
        assert 'b.c' in comments[1]['text']

    def test_preamble_before_diff_ignored(self) -> None:
        """Text before the first quoted diff line is not treated as a comment."""
        inline = (
            'Hi, some general feedback below:\n'
            '\n'
            '> diff --git a/f.c b/f.c\n'
            '> @@ -1,3 +1,4 @@\n'
            '>  ctx\n'
            '> +new\n'
            '\n'
            'Actual inline comment.\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert 'Actual inline comment.' == comments[0]['text']

    def test_trailing_comment_flushed(self) -> None:
        """A comment at the very end (no trailing quoted line) is still captured."""
        inline = (
            '> diff --git a/f.c b/f.c\n'
            '> @@ -1,3 +1,4 @@\n'
            '>  ctx\n'
            '> +new\n'
            '\n'
            'Final comment with no trailing diff.\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert 'Final comment' in comments[0]['text']

    def test_deletion_line_anchors_to_a_file(self) -> None:
        """Comment after a deletion line anchors to the a-side file and line."""
        inline = (
            '> diff --git a/old.c b/old.c\n'
            '> @@ -10,4 +10,3 @@\n'
            '>  ctx\n'
            '> -removed_line\n'
            '\n'
            'Why was this removed?\n'
            '\n'
            '>  more ctx\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['path'] == 'old.c'
        # Deletion at a_line=11, so comment anchors to line 11
        assert comments[0]['line'] == 11

    def test_commit_message_comment_extracted(self) -> None:
        """Comments on quoted commit message lines get :message path."""
        inline = (
            '> This is the commit body.\n'
            '> It explains the change.\n'
            '\n'
            'Why is this needed?\n'
            '\n'
            '> diff --git a/f.c b/f.c\n'
            '> @@ -1,3 +1,4 @@\n'
            '>  ctx\n'
            '> +new\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['path'] == ':message'
        assert comments[0]['line'] == 2
        assert comments[0]['text'] == 'Why is this needed?'

    def test_preamble_captured_when_enabled(self) -> None:
        """With capture_preamble=True, text before first quote is a comment."""
        inline = (
            'General feedback on this patch.\n'
            '\n'
            '> Commit body line.\n'
            '\n'
            '> diff --git a/f.c b/f.c\n'
            '> @@ -1,3 +1,4 @@\n'
            '>  ctx\n'
            '> +new\n'
        )
        comments = review._extract_comments_from_quoted_reply(
            inline, capture_preamble=True
        )
        preamble = [c for c in comments if c['line'] == 0]
        assert len(preamble) == 1
        assert preamble[0]['path'] == ':message'
        assert 'General feedback' in preamble[0]['text']

    def test_preamble_not_captured_by_default(self) -> None:
        """Without capture_preamble, text before first quote is ignored."""
        inline = (
            'General feedback on this patch.\n'
            '\n'
            '> diff --git a/f.c b/f.c\n'
            '> @@ -1,3 +1,4 @@\n'
            '>  ctx\n'
            '> +new\n'
            '\n'
            'Actual comment.\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['text'] == 'Actual comment.'

    def test_attribution_line_skipped_in_preamble(self) -> None:
        """The 'On ..., ... wrote:' attribution line is not captured."""
        inline = (
            'On Thu, 12 Mar 2026 15:54:20 +0100, Author <a@b.com> wrote:\n'
            '> Commit body.\n'
            '\n'
            'My comment.\n'
            '\n'
            '> diff --git a/f.c b/f.c\n'
            '> @@ -1,3 +1,4 @@\n'
            '>  ctx\n'
            '> +new\n'
        )
        comments = review._extract_comments_from_quoted_reply(
            inline, capture_preamble=True
        )
        # Attribution line should NOT become a comment
        for c in comments:
            assert 'wrote:' not in c.get('text', '')

    def test_orphan_hunk_header_enters_diff_mode(self) -> None:
        """A @@ hunk header without diff --git still enters diff mode."""
        inline = (
            '> @@ -10,3 +10,4 @@ some_func\n>  ctx\n> +new line\n\nThis needs a test.\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['text'] == 'This needs a test.'
        assert comments[0]['line'] == 11
        assert comments[0].get('content') == '+new line'

    def test_orphan_file_headers_enter_diff_mode(self) -> None:
        """--- a/ and +++ b/ without diff --git still enter diff mode."""
        inline = (
            '> --- a/kernel/sched.c\n'
            '> +++ b/kernel/sched.c\n'
            '> @@ -5,3 +5,4 @@\n'
            '>  existing\n'
            '> +added\n'
            '\n'
            'Why this change?\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['path'] == 'b/kernel/sched.c'
        assert comments[0]['line'] == 6
        assert comments[0]['text'] == 'Why this change?'

    def test_trimmed_diff_with_content_resolution(self) -> None:
        """Trimmed reply resolved against real diff gets correct position."""
        # User trimmed everything except the line they're commenting on
        inline = '> +new line\n\nLooks good.\n'
        comments = review._extract_comments_from_quoted_reply(inline)
        # Comment is captured (even without file path from headers)
        assert len(comments) == 1
        assert comments[0]['text'] == 'Looks good.'
        assert comments[0].get('content') == '+new line'

        # Now resolve against the real diff
        real_diff = (
            'diff --git a/f.c b/f.c\n'
            '--- a/f.c\n'
            '+++ b/f.c\n'
            '@@ -1,3 +1,4 @@\n'
            ' ctx\n'
            '+new line\n'
            ' more\n'
        )
        review._resolve_comment_positions(real_diff, comments)
        assert comments[0]['path'] == 'b/f.c'
        assert comments[0]['line'] == 2

    def test_wrapped_diff_git_line_rejoined(self) -> None:
        """A diff --git line wrapped by the editor is rejoined."""
        # Editor wraps at 72 chars, splitting diff --git into two lines
        inline = (
            '> diff --git a/tools/lib/python/kdoc/xforms_lists.py\n'
            'b/tools/lib/python/kdoc/xforms_lists.py\n'
            '> --- a/tools/lib/python/kdoc/xforms_lists.py\n'
            '> +++ b/tools/lib/python/kdoc/xforms_lists.py\n'
            '> @@ -4,7 +4,8 @@\n'
            '>  existing\n'
            '> +from kdoc.c_lex import CMatch\n'
            '\n'
            'Only editing 2nd file.\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['text'] == 'Only editing 2nd file.'
        assert comments[0]['path'] == 'b/tools/lib/python/kdoc/xforms_lists.py'
        assert comments[0]['line'] == 5

    def test_wrapped_diff_git_line_quoted_continuation(self) -> None:
        """A diff --git line wrapped with quoted continuation is rejoined."""
        inline = (
            '> diff --git a/tools/lib/python/kdoc/xforms_lists.py\n'
            '> b/tools/lib/python/kdoc/xforms_lists.py\n'
            '> --- a/tools/lib/python/kdoc/xforms_lists.py\n'
            '> +++ b/tools/lib/python/kdoc/xforms_lists.py\n'
            '> @@ -1,3 +1,4 @@\n'
            '>  ctx\n'
            '> +new\n'
            '\n'
            'Comment here.\n'
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['text'] == 'Comment here.'
        assert comments[0]['path'] == 'b/tools/lib/python/kdoc/xforms_lists.py'

    def test_extract_editor_comments_with_diff_resolution(self) -> None:
        """_extract_editor_comments resolves positions when diff provided."""
        edited = (
            '# instructions\n> @@ -1,3 +1,4 @@\n>  ctx\n> +new line\n\nMy comment.\n'
        )
        real_diff = (
            'diff --git a/f.c b/f.c\n'
            '--- a/f.c\n'
            '+++ b/f.c\n'
            '@@ -1,3 +1,4 @@\n'
            ' ctx\n'
            '+new line\n'
            ' more\n'
        )
        comments = review._extract_editor_comments(edited, diff_text=real_diff)
        assert len(comments) == 1
        assert comments[0]['path'] == 'b/f.c'
        assert comments[0]['line'] == 2
        assert comments[0]['text'] == 'My comment.'


class TestResolveCommentPositions:
    """Tests for _resolve_comment_positions()."""

    def test_context_content_matches_addition_in_new_file(self) -> None:
        """Content stored as context (space prefix) matches addition (+) in real diff."""
        # Sashiko uses fake context hunks even for new files, so the
        # content key has a space prefix while the real diff has + prefix.
        real_diff = (
            'diff --git a/f.c b/f.c\n'
            'new file mode 100644\n'
            '--- /dev/null\n'
            '+++ b/f.c\n'
            '@@ -0,0 +1,5 @@\n'
            '+int x;\n'
            '+int y;\n'
            '+return -EINVAL;\n'
            '+if (check)\n'
            '+\treturn 0;\n'
        )
        comments = [
            {
                'path': 'f.c',
                'line': 90,
                'text': 'Bug here.',
                'content': ' return -EINVAL;',
            },
        ]
        review._resolve_comment_positions(real_diff, comments)
        assert comments[0]['line'] == 3
        assert comments[0]['path'] == 'b/f.c'

    def test_exact_prefix_match_still_works(self) -> None:
        """Content with matching prefix (both +) still resolves correctly."""
        real_diff = (
            'diff --git a/f.c b/f.c\n'
            '--- a/f.c\n'
            '+++ b/f.c\n'
            '@@ -10,3 +10,4 @@\n'
            ' ctx\n'
            '+new_line\n'
            ' more\n'
        )
        comments = [
            {'path': 'f.c', 'line': 99, 'text': 'Review.', 'content': '+new_line'},
        ]
        review._resolve_comment_positions(real_diff, comments)
        assert comments[0]['line'] == 11

    def test_no_content_key_keeps_original_position(self) -> None:
        """Comments without content key are not touched."""
        real_diff = 'diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n@@ -1,1 +1,1 @@\n-old\n+new\n'
        comments = [{'path': 'f.c', 'line': 42, 'text': 'Note.'}]
        review._resolve_comment_positions(real_diff, comments)
        assert comments[0]['line'] == 42

    def test_duplicate_content_picks_closest_to_source_position(self) -> None:
        """When the same line appears multiple times, pick the closest match."""
        # Simulates a new file with return -EINVAL; at lines 10, 30, and 50
        real_diff = (
            'diff --git a/f.c b/f.c\n'
            'new file mode 100644\n'
            '--- /dev/null\n'
            '+++ b/f.c\n'
            '@@ -0,0 +1,50 @@\n'
            + ''.join(f'+line{i}\n' for i in range(1, 10))
            + '+\treturn -EINVAL;\n'  # line 10
            + ''.join(f'+line{i}\n' for i in range(11, 30))
            + '+\treturn -EINVAL;\n'  # line 30
            + ''.join(f'+line{i}\n' for i in range(31, 50))
            + '+\treturn -EINVAL;\n'  # line 50
        )
        # Sashiko says line 30 with context-prefix content
        comments = [
            {
                'path': 'f.c',
                'line': 30,
                'text': 'Bug here.',
                'content': ' \treturn -EINVAL;',
            },
        ]
        review._resolve_comment_positions(real_diff, comments)
        # Should pick line 30 (closest to source position 30)
        assert comments[0]['line'] == 30
        assert comments[0]['path'] == 'b/f.c'


class TestResolveMessagePositions:
    """Tests for _resolve_message_positions()."""

    # Original cover body, author-wrapped narrow.  When the maintainer
    # replies, the editor (vim mail filetype, textwidth=72) re-flows the
    # quoted lines to a different fill, so the raw line count drifts.
    COVER = (
        'Take: cherry-pick + merge\n'
        '\n'
        "The review TUI's Take dialog can apply a series three ways: merge (a\n"
        'cover-letter merge commit of the whole series), linear (git am onto the\n'
        'target branch), or cherry-pick (pick a subset and git am it).\n'
        '\n'
        'That path was already half-wired. When some patches were marked\n'
        'skipped, the merge method fell through to the patch picker and merged\n'
        'just the non-skipped patches. But with nothing pre-skipped there was\n'
        'no way to ask for it: merge always took the whole series.\n'
        '\n'
        'This series turns it into a first-class choice.\n'
    )

    def test_reanchors_after_editor_rewrap(self) -> None:
        """Re-flowed quote lines get mapped back to the real body line."""
        # Counted positions (3, 7, 8) drift below the true body lines
        # (3, 8, 10) because the editor re-wrapped the quoted paragraphs.
        comments = [
            # last quoted line of para 1 — already correct, must stay put
            {
                'path': review.COMMIT_MESSAGE_PATH,
                'line': 3,
                'text': 'No objections.',
                'content': 'cherry-pick (pick a subset and git am it).',
            },
            # last quoted line of para 2 — re-wrapped tail fragment
            {
                'path': review.COMMIT_MESSAGE_PATH,
                'line': 7,
                'text': 'Skipping happens in the review app.',
                'content': 'whole series.',
            },
            # last quoted line of para 3
            {
                'path': review.COMMIT_MESSAGE_PATH,
                'line': 8,
                'text': 'Familiar phrasing.',
                'content': 'This series turns it into a first-class choice.',
            },
        ]
        review._resolve_message_positions(self.COVER, comments)
        assert [c['line'] for c in comments] == [3, 8, 10]

    def test_keeps_position_without_content(self) -> None:
        """A comment with no content anchor keeps its counted line."""
        comments = [
            {'path': review.COMMIT_MESSAGE_PATH, 'line': 5, 'text': 'x'},
        ]
        review._resolve_message_positions(self.COVER, comments)
        assert comments[0]['line'] == 5

    def test_keeps_position_when_anchor_not_found(self) -> None:
        """An anchor absent from the body leaves the comment untouched."""
        comments = [
            {
                'path': review.COMMIT_MESSAGE_PATH,
                'line': 4,
                'text': 'x',
                'content': 'text that is nowhere in the cover letter',
            },
        ]
        review._resolve_message_positions(self.COVER, comments)
        assert comments[0]['line'] == 4

    def test_ignores_diff_path_comments(self) -> None:
        """Comments anchored to a file path are not message comments."""
        comments = [
            {
                'path': 'b/f.c',
                'line': 2,
                'text': 'x',
                'content': 'merge always took the whole series.',
            },
        ]
        review._resolve_message_positions(self.COVER, comments)
        # Untouched: still pointing at the diff position.
        assert comments[0]['line'] == 2
        assert comments[0]['path'] == 'b/f.c'

    def test_ambiguous_anchor_picks_closest(self) -> None:
        """A repeated anchor resolves to the line nearest the counted one."""
        cover = (
            'Subject\n'
            '\n'
            'apply the patch\n'
            'some other text\n'
            'more filler here\n'
            'apply the patch\n'
        )
        comments = [
            {
                'path': review.COMMIT_MESSAGE_PATH,
                'line': 4,
                'text': 'x',
                'content': 'apply the patch',
            },
        ]
        review._resolve_message_positions(cover, comments)
        # Occurrences at body lines 1 and 4; counted line 4 is closest.
        assert comments[0]['line'] == 4

    def test_extract_editor_comments_message_resolution(self) -> None:
        """_extract_editor_comments re-anchors :message comments when given
        the message body."""
        edited = (
            '# instructions\n'
            "> The review TUI's Take dialog can apply a series three ways: merge"
            ' (a cover-letter\n'
            '> merge commit of the whole series), linear (git am onto the target'
            ' branch), or\n'
            '> cherry-pick (pick a subset and git am it).\n'
            '\n'
            "I don't have any specific objections.\n"
            '\n'
            '> That path was already half-wired. When some patches were marked'
            ' skipped, the merge\n'
            '> method fell through to the patch picker and merged just the'
            ' non-skipped patches.\n'
            '> But with nothing pre-skipped there was no way to ask for it: merge'
            ' always took the\n'
            '> whole series.\n'
            '\n'
            'Skipping happens in the review app.\n'
        )
        comments = review._extract_editor_comments(edited, message_text=self.COVER)
        assert len(comments) == 2
        assert all(c['path'] == review.COMMIT_MESSAGE_PATH for c in comments)
        # Both anchored to the real last line of their quoted paragraph.
        assert comments[0]['line'] == 3
        assert comments[1]['line'] == 8


class TestIntegrateSashikoReviews:
    """Tests for _integrate_sashiko_reviews()."""

    _SASHIKO_RESPONSE = {
        'id': 42,
        'message_id': 'cover@example.com',
        'status': 'Reviewed',
        'patches': [
            {'id': 100, 'message_id': 'patch1@example.com', 'part_index': 1},
            {'id': 101, 'message_id': 'patch2@example.com', 'part_index': 2},
        ],
        'reviews': [
            {
                'id': 200,
                'patch_id': 100,
                'status': 'Reviewed',
                'output': '{}',
                'inline_review': (
                    'commit aaa\n'
                    'Author: Test\n\n'
                    'Test patch 1\n\n'
                    '> diff --git a/f.c b/f.c\n'
                    '> @@ -10,3 +10,4 @@ void f(void)\n'
                    '>  \tint x;\n'
                    '> +\tptr = alloc();\n'
                    '\n'
                    'Missing error check.\n'
                    '\n'
                    '>  \treturn 0;\n'
                ),
            },
            {
                'id': 201,
                'patch_id': 101,
                'status': 'Reviewed',
                'output': '{}',
                'inline_review': '',
            },
        ],
    }

    def test_no_sashiko_url_returns_false(self) -> None:
        """When sashiko-url is not configured, returns False immediately."""
        with mock.patch('b4.get_main_config', return_value={}):
            result = review._integrate_sashiko_reviews(
                '/tmp', '', {'series': {}, 'patches': []}, [], []
            )
        assert result is False

    def test_no_series_msgid_returns_false(self) -> None:
        """When series has no message_id, returns False."""
        with mock.patch(
            'b4.get_main_config', return_value={'sashiko-url': 'https://sashiko.dev'}
        ):
            result = review._integrate_sashiko_reviews(
                '/tmp', '', {'series': {}, 'patches': []}, [], []
            )
        assert result is False

    def test_api_returns_none(self) -> None:
        """When sashiko API returns nothing, returns False."""
        series = {'message_id': 'test@example.com'}
        with mock.patch(
            'b4.get_main_config', return_value={'sashiko-url': 'https://sashiko.dev'}
        ):
            with mock.patch(
                'b4.review.checks._fetch_sashiko_patchset', return_value=None
            ):
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    result = review._integrate_sashiko_reviews(
                        '/tmp', '', {'series': series, 'patches': []}, [], []
                    )
        assert result is False

    def test_integrates_inline_comments(self) -> None:
        """Inline review comments are extracted and stored in tracking."""
        patches: List[Dict[str, Any]] = [
            {'header-info': {'msgid': 'patch1@example.com'}, 'title': 'patch 1'},
            {'header-info': {'msgid': 'patch2@example.com'}, 'title': 'patch 2'},
        ]
        series = {'message_id': 'cover@example.com'}
        tracking = {'series': series, 'patches': patches}
        commit_shas = ['aaaa', 'bbbb']
        # Real diff matching the inline review structure
        real_diff = (
            'diff --git a/f.c b/f.c\n'
            'index 111..222 100644\n'
            '--- a/f.c\n'
            '+++ b/f.c\n'
            '@@ -10,3 +10,4 @@ void f(void)\n'
            ' \tint x;\n'
            '+\tptr = alloc();\n'
            ' \treturn 0;\n'
        )
        with mock.patch(
            'b4.get_main_config', return_value={'sashiko-url': 'https://sashiko.dev'}
        ):
            with mock.patch(
                'b4.review.checks._fetch_sashiko_patchset',
                return_value=self._SASHIKO_RESPONSE,
            ):
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    with mock.patch('b4.git_run_command') as mock_git:
                        mock_git.return_value = (0, real_diff)
                        with mock.patch.object(review, 'save_tracking_ref'):
                            result = review._integrate_sashiko_reviews(
                                '/tmp',
                                'cover',
                                tracking,
                                commit_shas,
                                patches,
                                branch='b4/review/test',
                            )

        assert result is True
        # Patch 1 should have sashiko comments
        assert 'reviews' in patches[0]
        sashiko_review = patches[0]['reviews'].get('sashiko@sashiko.dev')
        assert sashiko_review is not None
        assert sashiko_review['name'] == 'sashiko.dev'
        assert len(sashiko_review['comments']) == 1
        assert 'Missing error check' in sashiko_review['comments'][0]['text']
        # Patch 2 has empty inline_review, should have no sashiko entry
        assert 'reviews' not in patches[1]

    def test_skips_patch_without_msgid(self) -> None:
        """Patches without header-info.msgid are skipped gracefully."""
        patches = [
            {'title': 'no msgid patch'},
        ]
        series = {'message_id': 'cover@example.com'}
        tracking = {'series': series, 'patches': patches}
        with mock.patch(
            'b4.get_main_config', return_value={'sashiko-url': 'https://sashiko.dev'}
        ):
            with mock.patch(
                'b4.review.checks._fetch_sashiko_patchset',
                return_value=self._SASHIKO_RESPONSE,
            ):
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    result = review._integrate_sashiko_reviews(
                        '/tmp', '', tracking, ['aaa'], patches
                    )
        assert result is False

    def test_uses_header_info_msgid_fallback(self) -> None:
        """Falls back to header-info.msgid when message_id is missing."""
        series = {'header-info': {'msgid': 'cover@example.com'}}
        tracking = {'series': series, 'patches': []}
        with mock.patch(
            'b4.get_main_config', return_value={'sashiko-url': 'https://sashiko.dev'}
        ):
            with mock.patch(
                'b4.review.checks._fetch_sashiko_patchset', return_value=None
            ) as mock_fetch:
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    review._integrate_sashiko_reviews('/tmp', '', tracking, [], [])
        # Should have been called with the header-info msgid
        mock_fetch.assert_called_once_with('cover@example.com', 'https://sashiko.dev')

    def test_picks_latest_review_per_patch(self) -> None:
        """When multiple reviews exist for a patch, uses the one with highest id."""
        patchset = {
            'id': 42,
            'message_id': 'cover@example.com',
            'status': 'Reviewed',
            'patches': [
                {'id': 100, 'message_id': 'patch1@example.com', 'part_index': 1},
            ],
            'reviews': [
                {
                    'id': 200,
                    'patch_id': 100,
                    'status': 'Reviewed',
                    'inline_review': (
                        'commit aaa\nAuthor: Test\n\nOld\n\n'
                        '> diff --git a/f.c b/f.c\n'
                        '> @@ -1,3 +1,4 @@\n>  ctx\n> +new\n'
                        '\nOld review comment.\n'
                    ),
                },
                {
                    'id': 300,
                    'patch_id': 100,
                    'status': 'Reviewed',
                    'inline_review': (
                        'commit bbb\nAuthor: Test\n\nNew\n\n'
                        '> diff --git a/f.c b/f.c\n'
                        '> @@ -1,3 +1,4 @@\n>  ctx\n> +new\n'
                        '\nNew review comment.\n'
                    ),
                },
            ],
        }
        patches: List[Dict[str, Any]] = [
            {'header-info': {'msgid': 'patch1@example.com'}}
        ]
        series = {'message_id': 'cover@example.com'}
        tracking = {'series': series, 'patches': patches}
        real_diff = (
            'diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n'
            '@@ -1,3 +1,4 @@\n ctx\n+new\n ctx\n'
        )
        with mock.patch(
            'b4.get_main_config', return_value={'sashiko-url': 'https://sashiko.dev'}
        ):
            with mock.patch(
                'b4.review.checks._fetch_sashiko_patchset', return_value=patchset
            ):
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    with mock.patch('b4.git_run_command', return_value=(0, real_diff)):
                        with mock.patch.object(review, 'save_tracking_ref'):
                            review._integrate_sashiko_reviews(
                                '/tmp',
                                '',
                                tracking,
                                ['aaa'],
                                patches,
                                branch='b4/review/test',
                            )
        comments = patches[0]['reviews']['sashiko@sashiko.dev']['comments']
        # Should have the newer review's comment
        assert any('New review comment' in c['text'] for c in comments)
        assert not any('Old review comment' in c['text'] for c in comments)

    def test_skips_already_integrated_review(self) -> None:
        """When the sashiko-review-id already matches, no re-parsing happens."""
        patches: List[Dict[str, Any]] = [
            {
                'header-info': {'msgid': 'patch1@example.com'},
                'title': 'patch 1',
                'reviews': {
                    'sashiko@sashiko.dev': {
                        'name': 'sashiko.dev',
                        'sashiko-review-id': 200,
                        'comments': [
                            {'path': 'f.c', 'line': 11, 'text': 'Already here.'}
                        ],
                    },
                },
            },
        ]
        series = {'message_id': 'cover@example.com'}
        tracking = {'series': series, 'patches': patches}
        with mock.patch(
            'b4.get_main_config', return_value={'sashiko-url': 'https://sashiko.dev'}
        ):
            with mock.patch(
                'b4.review.checks._fetch_sashiko_patchset',
                return_value=self._SASHIKO_RESPONSE,
            ):
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    with mock.patch('b4.git_run_command') as mock_git:
                        result = review._integrate_sashiko_reviews(
                            '/tmp', '', tracking, ['aaaa'], patches
                        )
        # Should not have called git diff (skipped re-parsing)
        mock_git.assert_not_called()
        assert result is False
        # Original comments untouched
        assert (
            patches[0]['reviews']['sashiko@sashiko.dev']['comments'][0]['text']
            == 'Already here.'
        )


class TestApplyFindingsLocations:
    """Tests for _apply_findings_locations()."""

    def test_noop_when_no_locations(self) -> None:
        """When locations_by_file is empty nothing changes."""
        comments = [{'path': 'f.c', 'line': 0, 'text': 'hello'}]
        review._apply_findings_locations(comments, {})
        assert comments[0]['line'] == 0

    def test_anchors_unpositioned_comment(self) -> None:
        """A comment at line 0 for a file with exactly one location gets updated."""
        comments = [{'path': 'f.c', 'line': 0, 'text': 'needs anchoring'}]
        review._apply_findings_locations(comments, {'f.c': [42]})
        assert comments[0]['line'] == 42

    def test_skips_already_positioned_comment(self) -> None:
        """Comments with a real line number are left untouched."""
        comments = [{'path': 'f.c', 'line': 10, 'text': 'already placed'}]
        review._apply_findings_locations(comments, {'f.c': [99]})
        assert comments[0]['line'] == 10

    def test_skips_ambiguous_file(self) -> None:
        """When multiple lines exist for a file, no fallback is applied."""
        comments = [{'path': 'f.c', 'line': 0, 'text': 'ambiguous'}]
        review._apply_findings_locations(comments, {'f.c': [10, 20]})
        assert comments[0]['line'] == 0

    def test_skips_unmatched_file(self) -> None:
        """Locations for a different file do not affect the comment."""
        comments = [{'path': 'f.c', 'line': 0, 'text': 'wrong file'}]
        review._apply_findings_locations(comments, {'g.c': [5]})
        assert comments[0]['line'] == 0


class TestSashikoLocationsIntegration:
    """Integration: sashiko findings locations used as comment fallback."""

    def test_locations_data_parsed_from_output(self) -> None:
        """Findings with locations in the output JSON flow through without
        error and do not disturb normally-positioned inline comments.

        In current sashiko output every comment is attached to a quoted diff
        line so it always has line > 0 after extraction.  The locations
        fallback (line == 0) is exercised by the unit tests for
        _apply_findings_locations; here we verify end-to-end that locations
        data is silently ignored when the comment is already positioned.
        """
        import json as _json

        patchset = {
            'id': 42,
            'message_id': 'cover@example.com',
            'status': 'Reviewed',
            'patches': [
                {'id': 100, 'message_id': 'patch1@example.com', 'part_index': 1},
            ],
            'reviews': [
                {
                    'id': 200,
                    'patch_id': 100,
                    'status': 'Reviewed',
                    'inline_review': (
                        '> diff --git a/f.c b/f.c\n'
                        '> @@ -1,3 +1,4 @@\n'
                        '>  ctx\n'
                        '> +added\n'
                        '\nLocations-present comment.\n'
                    ),
                    # Finding carries locations in the real sashiko list-of-dicts
                    # format — must be parsed without error but must NOT
                    # override the already-positioned comment.
                    'output': _json.dumps(
                        {
                            'findings': [
                                {
                                    'severity': 'High',
                                    'problem': 'Missing check',
                                    'preexisting': False,
                                    'locations': [
                                        {
                                            'file': 'f.c',
                                            'line': 99,
                                            'function_or_symbol': 'do_thing',
                                            'why_this_location_matters': 'test',
                                            'code_snippet': 'ptr = NULL;',
                                        }
                                    ],
                                }
                            ]
                        }
                    ),
                },
            ],
        }

        patches: List[Dict[str, Any]] = [
            {'header-info': {'msgid': 'patch1@example.com'}}
        ]
        series = {'message_id': 'cover@example.com'}
        tracking = {'series': series, 'patches': patches}
        real_diff = (
            'diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n'
            '@@ -1,3 +1,4 @@\n ctx\n+added\n ctx\n'
        )
        with mock.patch(
            'b4.get_main_config', return_value={'sashiko-url': 'https://sashiko.dev'}
        ):
            with mock.patch(
                'b4.review.checks._fetch_sashiko_patchset', return_value=patchset
            ):
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    with mock.patch('b4.git_run_command', return_value=(0, real_diff)):
                        with mock.patch('b4.review._review.save_tracking'):
                            review._integrate_sashiko_reviews(
                                '/tmp', '', tracking, ['aaa'], patches
                            )

        sashiko_entry = patches[0].get('reviews', {}).get('sashiko@sashiko.dev')
        assert sashiko_entry is not None
        comments = sashiko_entry['comments']
        assert len(comments) == 1
        # _extract_comments_from_quoted_reply stores the b/ path from +++ b/f.c
        assert 'f.c' in comments[0]['path']
        # locations fallback must NOT override an already-positioned comment
        assert comments[0]['line'] != 99
        assert comments[0]['line'] > 0
        assert 'Locations-present' in comments[0]['text']

    def test_no_locations_no_effect(self) -> None:
        """When findings carry no locations, behaviour is unchanged."""
        import json as _json

        patchset = {
            'id': 42,
            'message_id': 'cover@example.com',
            'status': 'Reviewed',
            'patches': [
                {'id': 100, 'message_id': 'patch1@example.com', 'part_index': 1},
            ],
            'reviews': [
                {
                    'id': 200,
                    'patch_id': 100,
                    'status': 'Reviewed',
                    'inline_review': (
                        '> diff --git a/f.c b/f.c\n'
                        '> @@ -1,3 +1,4 @@\n'
                        '>  ctx\n'
                        '> +added\n'
                        '\nNormal comment.\n'
                    ),
                    # No locations in findings
                    'output': _json.dumps(
                        {'findings': [{'severity': 'Low', 'problem': 'style'}]}
                    ),
                },
            ],
        }

        patches: List[Dict[str, Any]] = [
            {'header-info': {'msgid': 'patch1@example.com'}}
        ]
        series = {'message_id': 'cover@example.com'}
        tracking = {'series': series, 'patches': patches}
        real_diff = (
            'diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n'
            '@@ -1,3 +1,4 @@\n ctx\n+added\n ctx\n'
        )
        with mock.patch(
            'b4.get_main_config', return_value={'sashiko-url': 'https://sashiko.dev'}
        ):
            with mock.patch(
                'b4.review.checks._fetch_sashiko_patchset', return_value=patchset
            ):
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    with mock.patch('b4.git_run_command', return_value=(0, real_diff)):
                        with mock.patch('b4.review._review.save_tracking'):
                            review._integrate_sashiko_reviews(
                                '/tmp', '', tracking, ['aaa'], patches
                            )

        sashiko_entry = patches[0].get('reviews', {}).get('sashiko@sashiko.dev')
        assert sashiko_entry is not None
        comments = sashiko_entry['comments']
        assert len(comments) == 1
        assert 'Normal comment' in comments[0]['text']
        # Position was resolved from diff context, not from (absent) locations
        assert comments[0]['line'] > 0


class TestIntegrateFollowupInlineComments:
    """Tests for _integrate_followup_inline_comments()."""

    _FOLLOWUP_BODY_WITH_DIFF = (
        'On Mon, Jan 1, 2024, Dev <dev@test.com> wrote:\n'
        '> diff --git a/fs/file.c b/fs/file.c\n'
        '> index abc123..def456 100644\n'
        '> --- a/fs/file.c\n'
        '> +++ b/fs/file.c\n'
        '> @@ -10,3 +10,4 @@ void f(void)\n'
        '>  \tint x;\n'
        '> +\tptr = malloc(sz);\n'
        '\n'
        'Missing NULL check after malloc.\n'
        '\n'
        '>  \treturn 0;\n'
    )

    _FOLLOWUP_BODY_NO_DIFF = (
        'I think this approach makes sense, but can we also\n'
        'add a test for the error path?\n'
    )

    def _make_followup_comments(
        self, bodies_by_patch: Dict[int, List[str]]
    ) -> Dict[int, List[Dict[str, Any]]]:
        """Build a followup_comments dict like _parse_msgs_to_followup_comments returns."""
        result: Dict[int, List[Dict[str, Any]]] = {}
        for display_idx, body_list in bodies_by_patch.items():
            entries = []
            for i, body in enumerate(body_list):
                entries.append(
                    {
                        'body': body,
                        'fromname': f'Reviewer {i}',
                        'fromemail': f'reviewer{i}@example.com',
                        'date': '2024-01-01',
                        'msgid': f'followup{display_idx}-{i}@example.com',
                        'subject': 'Re: [PATCH]',
                        'depth': 0,
                    }
                )
            result[display_idx] = entries
        return result

    def test_no_thread_blob_returns_false(self) -> None:
        """Without a thread-blob, returns False immediately."""
        tracking: Dict[str, Any] = {'series': {}, 'patches': []}
        result = review._integrate_followup_inline_comments(
            '/tmp', '', tracking, [], []
        )
        assert result is False

    def test_extracts_inline_comments_from_followup(self) -> None:
        """Follow-ups that quote diff content produce inline comments."""
        patches: List[Dict[str, Any]] = [
            {'header-info': {'msgid': 'patch1@example.com'}, 'title': 'patch 1'},
        ]
        series = {
            'header-info': {'msgid': 'cover@example.com'},
            'thread-blob': 'abc123',
        }
        tracking = {'series': series, 'patches': patches}
        commit_shas = ['aaaa']

        # Follow-up body that quotes diff with a comment
        followup_comments = self._make_followup_comments(
            {
                1: [self._FOLLOWUP_BODY_WITH_DIFF],  # display_idx 1 = patch 0
            }
        )

        real_diff = (
            'diff --git a/fs/file.c b/fs/file.c\n'
            'index abc123..def456 100644\n'
            '--- a/fs/file.c\n'
            '+++ b/fs/file.c\n'
            '@@ -10,3 +10,4 @@ void f(void)\n'
            ' \tint x;\n'
            '+\tptr = malloc(sz);\n'
            ' \treturn 0;\n'
        )

        with mock.patch('b4.review.tracking.get_thread_mbox', return_value=b'mbox'):
            with mock.patch('liblore.utils.split_mbox', return_value=[]):
                with mock.patch(
                    'b4.review.tracking._parse_msgs_to_followup_comments',
                    return_value=followup_comments,
                ):
                    with mock.patch('b4.git_run_command', return_value=(0, real_diff)):
                        with mock.patch.object(review, 'save_tracking_ref'):
                            result = review._integrate_followup_inline_comments(
                                '/tmp',
                                'cover',
                                tracking,
                                commit_shas,
                                patches,
                                branch='b4/review/test',
                            )

        assert result is True
        assert 'reviews' in patches[0]
        rev = patches[0]['reviews'].get('reviewer0@example.com')
        assert rev is not None
        assert rev['name'] == 'Reviewer 0'
        assert len(rev['comments']) == 1
        assert 'NULL check' in rev['comments'][0]['text']

    def test_skips_followups_without_diff(self) -> None:
        """Follow-ups that don't quote diff content are ignored."""
        patches = [
            {'header-info': {'msgid': 'patch1@example.com'}, 'title': 'patch 1'},
        ]
        series = {
            'header-info': {'msgid': 'cover@example.com'},
            'thread-blob': 'abc123',
        }
        tracking = {'series': series, 'patches': patches}
        followup_comments = self._make_followup_comments(
            {
                1: [self._FOLLOWUP_BODY_NO_DIFF],
            }
        )

        with mock.patch('b4.review.tracking.get_thread_mbox', return_value=b'mbox'):
            with mock.patch('liblore.utils.split_mbox', return_value=[]):
                with mock.patch(
                    'b4.review.tracking._parse_msgs_to_followup_comments',
                    return_value=followup_comments,
                ):
                    result = review._integrate_followup_inline_comments(
                        '/tmp', '', tracking, ['aaa'], patches
                    )
        assert result is False
        assert 'reviews' not in patches[0]

    def test_skips_cover_letter_followups(self) -> None:
        """Follow-ups to the cover letter (display_idx 0) are skipped."""
        patches = [
            {'header-info': {'msgid': 'patch1@example.com'}, 'title': 'patch 1'},
        ]
        series = {
            'header-info': {'msgid': 'cover@example.com'},
            'thread-blob': 'abc123',
        }
        tracking = {'series': series, 'patches': patches}
        followup_comments = self._make_followup_comments(
            {
                0: [self._FOLLOWUP_BODY_WITH_DIFF],  # cover letter
            }
        )

        with mock.patch('b4.review.tracking.get_thread_mbox', return_value=b'mbox'):
            with mock.patch('liblore.utils.split_mbox', return_value=[]):
                with mock.patch(
                    'b4.review.tracking._parse_msgs_to_followup_comments',
                    return_value=followup_comments,
                ):
                    result = review._integrate_followup_inline_comments(
                        '/tmp', '', tracking, ['aaa'], patches
                    )
        assert result is False

    def test_multiple_reviewers_same_patch(self) -> None:
        """Multiple follow-ups to the same patch create separate review entries."""
        patches = [
            {'header-info': {'msgid': 'patch1@example.com'}, 'title': 'patch 1'},
        ]
        series = {
            'header-info': {'msgid': 'cover@example.com'},
            'thread-blob': 'abc123',
        }
        tracking = {'series': series, 'patches': patches}
        followup_comments = self._make_followup_comments(
            {
                1: [self._FOLLOWUP_BODY_WITH_DIFF, self._FOLLOWUP_BODY_WITH_DIFF],
            }
        )

        real_diff = (
            'diff --git a/fs/file.c b/fs/file.c\n'
            'index abc123..def456 100644\n'
            '--- a/fs/file.c\n'
            '+++ b/fs/file.c\n'
            '@@ -10,3 +10,4 @@ void f(void)\n'
            ' \tint x;\n'
            '+\tptr = malloc(sz);\n'
            ' \treturn 0;\n'
        )

        with mock.patch('b4.review.tracking.get_thread_mbox', return_value=b'mbox'):
            with mock.patch('liblore.utils.split_mbox', return_value=[]):
                with mock.patch(
                    'b4.review.tracking._parse_msgs_to_followup_comments',
                    return_value=followup_comments,
                ):
                    with mock.patch('b4.git_run_command', return_value=(0, real_diff)):
                        with mock.patch.object(review, 'save_tracking_ref'):
                            result = review._integrate_followup_inline_comments(
                                '/tmp',
                                'cover',
                                tracking,
                                ['aaa'],
                                patches,
                                branch='b4/review/test',
                            )

        assert result is True
        reviews = patches[0]['reviews']
        assert 'reviewer0@example.com' in reviews
        assert 'reviewer1@example.com' in reviews

    def test_skips_already_integrated_followup(self) -> None:
        """When the followup-msgid already matches, no re-parsing happens."""
        patches: List[Dict[str, Any]] = [
            {
                'header-info': {'msgid': 'patch1@example.com'},
                'title': 'patch 1',
                'reviews': {
                    'reviewer0@example.com': {
                        'name': 'Reviewer 0',
                        'followup-msgid': 'followup1-0@example.com',
                        'comments': [
                            {'path': 'fs/file.c', 'line': 11, 'text': 'Already here.'}
                        ],
                    },
                },
            },
        ]
        series = {
            'header-info': {'msgid': 'cover@example.com'},
            'thread-blob': 'abc123',
        }
        tracking = {'series': series, 'patches': patches}
        followup_comments = self._make_followup_comments(
            {
                1: [self._FOLLOWUP_BODY_WITH_DIFF],
            }
        )

        with mock.patch('b4.review.tracking.get_thread_mbox', return_value=b'mbox'):
            with mock.patch('liblore.utils.split_mbox', return_value=[]):
                with mock.patch(
                    'b4.review.tracking._parse_msgs_to_followup_comments',
                    return_value=followup_comments,
                ):
                    with mock.patch('b4.git_run_command') as mock_git:
                        result = review._integrate_followup_inline_comments(
                            '/tmp', '', tracking, ['aaa'], patches
                        )
        # Should not have called git diff (skipped re-parsing)
        mock_git.assert_not_called()
        assert result is False
        # Original comments untouched
        assert (
            patches[0]['reviews']['reviewer0@example.com']['comments'][0]['text']
            == 'Already here.'
        )


@requires_textual
class TestFollowupItemPerMessage:
    """Tests for per-message follow-up selection (msgid-based keying)."""

    @staticmethod
    def _make_session() -> Dict[str, Any]:
        return {
            'topdir': '/tmp',
            'cover_text': 'Subject\n',
            'tracking': {},
            'series': {},
            'patches': [{}],
            'base_commit': '',
            'commit_shas': ['deadbeef'],
            'commit_subjects': ['Patch subject'],
            'sha_map': {},
            'abbrev_len': 12,
            'default_identity': 'Tester <tester@example.com>',
            'usercfg': {'name': 'Tester', 'email': 'tester@example.com'},
            'cover_subject_clean': 'Subject',
            'branch': 'b4/review/test-change-id',
        }

    def test_followup_item_keyed_by_msgid(self) -> None:
        """FollowupItem stores msgid, not fromemail."""
        from b4.review_tui._review_app import FollowupItem

        item = FollowupItem('Alice', 1, 'reply-1@example.com')
        assert item.msgid == 'reply-1@example.com'
        assert item.display_idx == 1

    def test_selected_followup_enables_reply_in_preview(self) -> None:
        """check_action returns True for edit_reply when a follow-up is selected."""
        from b4.review_tui._review_app import ReviewApp

        app = ReviewApp(self._make_session())
        app._preview_mode = True
        app._selected_followup_msgid = 'reply@example.com'
        assert app.check_action('edit_reply', ()) is True

    def test_selected_followup_cleared_on_show_content(self) -> None:
        """_selected_followup_msgid is reset when switching patches."""
        from b4.review_tui._review_app import ReviewApp

        app = ReviewApp(self._make_session())
        app._selected_followup_msgid = 'reply@example.com'
        # Verify it was set
        assert app._selected_followup_msgid == 'reply@example.com'
        # The field should be None after init for a fresh app
        app2 = ReviewApp(self._make_session())
        assert app2._selected_followup_msgid is None


# ---------------------------------------------------------------------------
# _get_lore_series version-mismatch tests (cc529aa)
# ---------------------------------------------------------------------------

_MINIMAL_DIFF = """\
Fix bar.

Signed-off-by: Author <author@example.com>
---
 foo.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/foo.c b/foo.c
index aaa..bbb 100644
--- a/foo.c
+++ b/foo.c
@@ -1,3 +1,4 @@
 void foo(void) {
+    bar();
 }
"""


def _make_patch_msg(
    subject: str, from_addr: str, date: str, body: str = '', msgid: str = ''
) -> email.message.EmailMessage:
    """Build a minimal EmailMessage that LoreMailbox can parse as a patch."""
    msg = email.message.EmailMessage()
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['Date'] = date
    msg['Message-Id'] = msgid or f'<{abs(hash(subject + date))}@test.com>'
    msg.set_payload(body or _MINIMAL_DIFF)
    return msg


_AUTHOR = 'Author <author@example.com>'


class TestGetLoreSeriesVersionMismatch:
    """Regression tests for the crash when the stored message-id points
    to a different version's thread than the wanted revision.

    See bug cc529aa: b4 review crashes updating a series.
    """

    @staticmethod
    def _v2_msgs() -> List[email.message.EmailMessage]:
        return [
            _make_patch_msg(
                '[PATCH v2] foo: fix bar',
                _AUTHOR,
                'Thu, 19 Mar 2026 08:51:12 +0530',
                msgid='<v2-patch@example.com>',
            ),
        ]

    @staticmethod
    def _v3_msgs() -> List[email.message.EmailMessage]:
        return [
            _make_patch_msg(
                '[PATCH v3] foo: fix bar',
                _AUTHOR,
                'Fri, 27 Mar 2026 14:51:06 +0530',
                msgid='<v3-patch@example.com>',
            ),
        ]

    def test_correct_version_found(self) -> None:
        """Requesting the version present in messages works."""
        msgs = self._v2_msgs()
        lser = review._get_lore_series(msgs, wantver=2)
        assert lser.revision == 2

    def test_no_preference_picks_highest(self) -> None:
        """wantver=None selects the highest available version."""
        msgs = self._v2_msgs() + self._v3_msgs()
        lser = review._get_lore_series(msgs, wantver=None)
        assert lser.revision == 3

    def test_version_mismatch_shows_found(self) -> None:
        """Error message lists which versions were actually found."""
        msgs = self._v2_msgs()
        with pytest.raises(LookupError, match=r'found: v2'):
            review._get_lore_series(msgs, wantver=3)

    def test_version_mismatch_after_extra_series(self) -> None:
        """Adding the missing version's messages resolves the mismatch."""
        # Start with only v2 — requesting v3 fails
        msgs = list(self._v2_msgs())
        with pytest.raises(LookupError):
            review._get_lore_series(msgs, wantver=3)

        # Simulating get_extra_series adding v3 messages
        msgs.extend(self._v3_msgs())
        lser = review._get_lore_series(msgs, wantver=3)
        assert lser.revision == 3

    def test_no_series_in_messages(self) -> None:
        """Completely empty mailbox raises LookupError."""
        with pytest.raises(LookupError, match='No series found'):
            review._get_lore_series([], wantver=1)


# -- Tests for collect_review_emails() ----------------------------------------


class TestCollectReviewEmails:
    """Tests for collect_review_emails() filtering logic.

    Covers the sent-revision safety-net filter added to fix the bug where
    reviews carried over from a prior revision were re-sent for the new one.
    """

    MY_EMAIL = 'maintainer@example.com'

    @staticmethod
    def _make_series(reviews: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            'revision': 1,
            'header-info': {
                'msgid': 'cover@example.com',
                'to': '',
                'cc': '',
                'references': '',
                'sentdate': '',
            },
            'reviews': reviews or {},
        }

    @staticmethod
    def _make_patch(reviews: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            'header-info': {'msgid': 'patch@example.com'},
            'reviews': reviews or {},
        }

    @staticmethod
    def _review(**extra: Any) -> Dict[str, Any]:
        r: Dict[str, Any] = {
            'name': 'Maintainer',
            'trailers': ['Reviewed-by: Maintainer <maintainer@example.com>'],
        }
        r.update(extra)
        return r

    # Use a sentinel email message so we can count how many were produced.
    _FAKE_MSG = mock.sentinel.email_msg

    @mock.patch('b4.review._review._build_review_email', return_value=_FAKE_MSG)
    @mock.patch(
        'b4.get_user_config', return_value={'name': 'Maintainer', 'email': MY_EMAIL}
    )
    def test_sends_normal_cover_review(
        self, _cfg: mock.Mock, _build: mock.Mock
    ) -> None:
        """A cover review without sent-revision produces one email."""
        series = self._make_series({self.MY_EMAIL: self._review()})
        msgs = review.collect_review_emails(series, [], 'cover', '', [])
        assert len(msgs) == 1

    @mock.patch('b4.review._review._build_review_email', return_value=_FAKE_MSG)
    @mock.patch(
        'b4.get_user_config', return_value={'name': 'Maintainer', 'email': MY_EMAIL}
    )
    def test_skips_cover_with_sent_revision(
        self, _cfg: mock.Mock, _build: mock.Mock
    ) -> None:
        """Cover review stamped with sent-revision is not re-sent."""
        series = self._make_series(
            {self.MY_EMAIL: self._review(**{'sent-revision': 1})}
        )
        msgs = review.collect_review_emails(series, [], 'cover', '', [])
        assert msgs == []

    @mock.patch('b4.review._review._build_review_email', return_value=_FAKE_MSG)
    @mock.patch(
        'b4.get_user_config', return_value={'name': 'Maintainer', 'email': MY_EMAIL}
    )
    def test_sends_normal_patch_review(
        self, _cfg: mock.Mock, _build: mock.Mock
    ) -> None:
        """A patch review without sent-revision produces one email."""
        series = self._make_series()
        patch = self._make_patch({self.MY_EMAIL: self._review()})
        msgs = review.collect_review_emails(series, [patch], 'cover', '', ['sha1'])
        assert len(msgs) == 1

    @mock.patch('b4.review._review._build_review_email', return_value=_FAKE_MSG)
    @mock.patch(
        'b4.get_user_config', return_value={'name': 'Maintainer', 'email': MY_EMAIL}
    )
    def test_skips_patch_with_sent_revision(
        self, _cfg: mock.Mock, _build: mock.Mock
    ) -> None:
        """Patch review stamped with sent-revision is not re-sent."""
        series = self._make_series()
        patch = self._make_patch({self.MY_EMAIL: self._review(**{'sent-revision': 1})})
        msgs = review.collect_review_emails(series, [patch], 'cover', '', ['sha1'])
        assert msgs == []

    @mock.patch('b4.review._review._build_review_email', return_value=_FAKE_MSG)
    @mock.patch(
        'b4.get_user_config', return_value={'name': 'Maintainer', 'email': MY_EMAIL}
    )
    def test_skips_patch_auto_skipped_after_upgrade(
        self, _cfg: mock.Mock, _build: mock.Mock
    ) -> None:
        """Patch auto-marked skip+skip-reason during upgrade is not re-sent.

        This is the combo A+B fix: the upgrade step sets patch-state=skip
        AND skip-reason on unchanged patches whose review was already sent.
        Both the skip filter and the sent-revision filter independently
        prevent re-sending; this test exercises the skip-state path.
        """
        series = self._make_series()
        patch = self._make_patch(
            {
                self.MY_EMAIL: self._review(
                    **{
                        'sent-revision': 1,
                        'patch-state': 'skip',
                        'skip-reason': 'Patch unchanged from v1; review already sent',
                    }
                )
            }
        )
        msgs = review.collect_review_emails(series, [patch], 'cover', '', ['sha1'])
        assert msgs == []

    @mock.patch('b4.review._review._build_review_email', return_value=_FAKE_MSG)
    @mock.patch(
        'b4.get_user_config', return_value={'name': 'Maintainer', 'email': MY_EMAIL}
    )
    def test_only_unsent_patches_included(
        self, _cfg: mock.Mock, _build: mock.Mock
    ) -> None:
        """Mix of sent and unsent patches: only unsent ones produce emails."""
        series = self._make_series()
        sent_patch = self._make_patch(
            {self.MY_EMAIL: self._review(**{'sent-revision': 1})}
        )
        fresh_patch = self._make_patch({self.MY_EMAIL: self._review()})
        msgs = review.collect_review_emails(
            series, [sent_patch, fresh_patch], 'cover', '', ['sha1', 'sha2']
        )
        assert len(msgs) == 1

    @mock.patch('b4.review._review._build_review_email', return_value=_FAKE_MSG)
    @mock.patch(
        'b4.get_user_config', return_value={'name': 'Maintainer', 'email': MY_EMAIL}
    )
    def test_skip_state_without_sent_revision_still_skipped(
        self, _cfg: mock.Mock, _build: mock.Mock
    ) -> None:
        """Explicit skip state (manually set, no sent-revision) is honoured."""
        series = self._make_series()
        patch = self._make_patch(
            {self.MY_EMAIL: self._review(**{'patch-state': 'skip'})}
        )
        msgs = review.collect_review_emails(series, [patch], 'cover', '', ['sha1'])
        assert msgs == []


def _cron_args(**kwargs: Any) -> argparse.Namespace:
    defaults: Dict[str, Any] = {
        'identifier': None,
        'cron_update': False,
        'cron_deliver': False,
        'dryrun': False,
        'sign': False,
        # Global b4 options consulted by setup_config()
        'config': [],
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_cmd_cron_flag_semantics(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bare cron runs all tasks; task flags select; --dry-run skips the
    update and turns delivery into check-only."""
    calls: List[Tuple[Any, ...]] = []
    monkeypatch.setattr(
        _review,
        '_cron_update',
        lambda identifier, topdir: calls.append(('update', identifier)),
    )
    monkeypatch.setattr(
        _review,
        '_cron_deliver',
        lambda identifier, topdir, patatt_sign, check_only: calls.append(
            ('deliver', identifier, patatt_sign, check_only)
        ),
    )
    monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)
    monkeypatch.setattr(b4, 'setup_config', lambda cmdargs, topdir=None: None)
    monkeypatch.setattr(
        b4.review.tracking, 'get_known_projects', lambda: [('proj', '/repo/proj')]
    )

    # Signing is opt-in for cron: timer processes rarely have key access
    _review.cmd_cron(_cron_args())
    assert calls == [('update', 'proj'), ('deliver', 'proj', False, False)]

    calls.clear()
    _review.cmd_cron(_cron_args(cron_deliver=True, sign=True))
    assert calls == [('deliver', 'proj', True, False)]

    calls.clear()
    _review.cmd_cron(_cron_args(cron_update=True))
    assert calls == [('update', 'proj')]

    calls.clear()
    _review.cmd_cron(_cron_args(dryrun=True))
    assert calls == [('deliver', 'proj', False, True)]


def test_cmd_cron_all_projects(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bare cron (no -i) sweeps every known project, reloading
    repository-local configuration per project and skipping queue
    delivery (but not updates) for projects without a recorded
    repository."""
    calls: List[Tuple[str, Optional[str], bool, bool]] = []
    config_reloads: List[Optional[str]] = []
    monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)
    monkeypatch.setattr(
        b4.review.tracking,
        'get_known_projects',
        lambda: [('alpha', '/path/to/alpha'), ('beta', None)],
    )
    monkeypatch.setattr(
        b4,
        'setup_config',
        lambda cmdargs, topdir=None: config_reloads.append(topdir),
    )

    def fake_run_one(
        identifier: str,
        topdir: Optional[str],
        *,
        do_update: bool,
        do_deliver: bool,
        dryrun: bool,
        patatt_sign: bool,
    ) -> None:
        calls.append((identifier, topdir, do_update, do_deliver))

    monkeypatch.setattr(_review, '_cron_run_one', fake_run_one)
    _review.cmd_cron(_cron_args())
    assert calls == [
        ('alpha', '/path/to/alpha', True, True),
        ('beta', None, True, False),
    ]
    # Per-project config reloads, plus the final restore
    assert config_reloads == ['/path/to/alpha', None, None]

    # An explicit -i __all__ means the same thing
    calls.clear()
    config_reloads.clear()
    _review.cmd_cron(_cron_args(identifier=['__all__']))
    assert [c[0] for c in calls] == ['alpha', 'beta']


def test_cmd_cron_cwd_scopes_bare_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bare cron inside an enrolled repository runs on that project
    only (refreshing its recorded path); the all-projects sweep is
    never consulted."""
    calls: List[Tuple[str, Optional[str]]] = []
    recorded: List[Tuple[str, str]] = []
    monkeypatch.setattr(b4, 'git_get_toplevel', lambda: '/repo/alpha')
    monkeypatch.setattr(b4, 'setup_config', lambda cmdargs, topdir=None: None)
    monkeypatch.setattr(
        b4.review.tracking, 'get_repo_identifier', lambda topdir: 'alpha'
    )
    monkeypatch.setattr(b4.review.tracking, 'db_exists', lambda identifier: True)
    monkeypatch.setattr(
        b4.review.tracking,
        'record_repo_path',
        lambda identifier, topdir: recorded.append((identifier, topdir)),
    )

    def fail_known_projects() -> List[Tuple[str, Optional[str]]]:
        raise AssertionError('get_known_projects should not be consulted')

    monkeypatch.setattr(b4.review.tracking, 'get_known_projects', fail_known_projects)

    def fake_run_one(identifier: str, topdir: Optional[str], **kwargs: Any) -> None:
        calls.append((identifier, topdir))

    monkeypatch.setattr(_review, '_cron_run_one', fake_run_one)
    _review.cmd_cron(_cron_args())
    assert calls == [('alpha', '/repo/alpha')]
    assert recorded == [('alpha', '/repo/alpha')]


def test_cmd_cron_selected_identifiers(monkeypatch: pytest.MonkeyPatch) -> None:
    """-i is repeatable and limits the sweep to the named projects,
    finding each repository through the recorded path; an unknown
    identifier aborts before anything runs."""
    calls: List[Tuple[str, Optional[str], bool]] = []
    monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)
    monkeypatch.setattr(b4, 'setup_config', lambda cmdargs, topdir=None: None)
    monkeypatch.setattr(
        b4.review.tracking,
        'db_exists',
        lambda identifier: identifier in ('alpha', 'beta'),
    )
    monkeypatch.setattr(
        b4.review.tracking,
        'get_repo_path',
        lambda identifier: '/path/to/alpha' if identifier == 'alpha' else None,
    )

    def fake_run_one(
        identifier: str,
        topdir: Optional[str],
        *,
        do_update: bool,
        do_deliver: bool,
        dryrun: bool,
        patatt_sign: bool,
    ) -> None:
        calls.append((identifier, topdir, do_deliver))

    monkeypatch.setattr(_review, '_cron_run_one', fake_run_one)
    _review.cmd_cron(_cron_args(identifier=['alpha', 'beta']))
    assert calls == [
        ('alpha', '/path/to/alpha', True),
        ('beta', None, False),
    ]

    calls.clear()
    with pytest.raises(SystemExit):
        _review.cmd_cron(_cron_args(identifier=['alpha', 'nosuch']))
    assert calls == []


def test_cmd_cron_all_isolates_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """One project's failure must not stop the sweep for the others."""
    seen: List[str] = []
    monkeypatch.setattr(b4, 'git_get_toplevel', lambda: None)
    monkeypatch.setattr(
        b4.review.tracking,
        'get_known_projects',
        lambda: [('alpha', '/a'), ('beta', '/b')],
    )

    def fake_run_one(identifier: str, topdir: Optional[str], **kwargs: Any) -> None:
        seen.append(identifier)
        if identifier == 'alpha':
            raise RuntimeError('boom')

    monkeypatch.setattr(_review, '_cron_run_one', fake_run_one)
    _review.cmd_cron(_cron_args())
    assert seen == ['alpha', 'beta']


class _RecordingHandler(logging.Handler):
    def __init__(self, level: int) -> None:
        super().__init__(level)
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


class TestQuietCron:
    """The cron sweep must not spam the maintainer's mailbox with the
    progress narration of the interactive code paths it reuses."""

    @pytest.fixture
    def handler(self) -> Iterator[_RecordingHandler]:
        hdl = _RecordingHandler(logging.INFO)
        old_level = b4.logger.level
        b4.logger.setLevel(logging.DEBUG)
        b4.logger.addHandler(hdl)
        yield hdl
        b4.logger.removeHandler(hdl)
        b4.logger.setLevel(old_level)

    def test_default_suppresses_everything(self, handler: _RecordingHandler) -> None:
        """b4 traditionally narrates at CRITICAL ("always show", it
        survives -q), as mbox.py's 'Checking for newer revisions' did
        until it flipped to INFO, so the default must drop every
        level."""
        with _review._quiet_cron():
            b4.logger.info('Looking up something')
            b4.logger.warning('duplicate messages found')
            b4.logger.critical('Checking for newer revisions')
        assert handler.messages == []

    def test_child_and_liblore_records_suppressed(
        self, handler: _RecordingHandler
    ) -> None:
        """Records propagated from child loggers hit the handler filter."""
        with _review._quiet_cron():
            logging.getLogger('b4.review.tracking').info('Checking for newer')
            logging.getLogger('liblore').info('Grabbing search results')
        assert handler.messages == []

    def test_warning_threshold_keeps_warnings(self, handler: _RecordingHandler) -> None:
        with _review._quiet_cron(logging.WARNING):
            b4.logger.info('Connecting to smtp:465')
            b4.logger.warning('Failed to send queued message')
            b4.logger.critical('CRITICAL: could not parse the thank-you review')
        assert handler.messages == [
            'Failed to send queued message',
            'CRITICAL: could not parse the thank-you review',
        ]

    def test_cron_logger_is_exempt(self, handler: _RecordingHandler) -> None:
        with _review._quiet_cron():
            _review.cron_logger.info('Delivered: some subject')
        assert handler.messages == ['Delivered: some subject']

    def test_filter_removed_after_exit(self, handler: _RecordingHandler) -> None:
        with _review._quiet_cron():
            b4.logger.info('suppressed')
        b4.logger.info('audible again')
        assert handler.messages == ['audible again']

    def test_debug_handler_left_alone(self, handler: _RecordingHandler) -> None:
        """A --debug run must still see the full narration."""
        dbg = _RecordingHandler(logging.DEBUG)
        b4.logger.addHandler(dbg)
        try:
            with _review._quiet_cron():
                b4.logger.info('Looking up something')
        finally:
            b4.logger.removeHandler(dbg)
        assert dbg.messages == ['Looking up something']
        assert handler.messages == []


def test_update_all_tracking_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    """A second update sweep must fail fast while the lock is held."""
    with b4.lockfile_nb(_review._get_update_lock_path('lockproj')):
        with pytest.raises(b4.LockHeldError):
            review.update_all_tracking('lockproj', 'https://lore.example/r/%s')


def test_update_all_tracking_skips_snoozed_and_archived(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default sweep covers active series only, and aggregates
    per-series results into the summary."""
    series = [
        {'change_id': 'a', 'subject': 's-a', 'status': 'new', 'sender_name': 'A'},
        {'change_id': 'b', 'subject': 's-b', 'status': 'snoozed', 'sender_name': 'B'},
        {'change_id': 'c', 'subject': 's-c', 'status': 'archived', 'sender_name': 'C'},
        {'change_id': 'd', 'subject': 's-d', 'status': 'reviewing', 'sender_name': 'D'},
    ]
    monkeypatch.setattr(
        b4.review.tracking, 'get_all_tracked_series', lambda identifier: series
    )
    updated: List[str] = []

    def fake_update(
        one: Dict[str, Any],
        identifier: str,
        linkmask: str,
        topdir: Optional[str] = None,
    ) -> Dict[str, Any]:
        updated.append(one['change_id'])
        if one['change_id'] == 'd':
            return {'new_revisions': 0, 'new_trailers': 0, 'error': 'kaboom'}
        return {'new_revisions': 1, 'new_trailers': 0, 'error': None}

    monkeypatch.setattr(review, 'update_series_tracking', fake_update)
    result = review.update_all_tracking('sweeper', 'https://lore.example/r/%s')
    assert updated == ['a', 'd']
    assert result['series_checked'] == 2
    assert result['series_updated'] == 1
    assert result['errors'] == 1
    assert result['error_details'] == [('D', 'kaboom')]
    assert result['cancelled'] is False


class TestOwnMessageEntries:
    """Tests for _own_message_entries() — the exact-From auto-read match."""

    @staticmethod
    def _make_msg(
        fromhdr: str,
        msgid: str = 'msg@example.com',
        date: Optional[str] = 'Mon, 27 Jul 2026 10:00:00 +0000',
    ) -> email.message.EmailMessage:
        msg = email.message.EmailMessage()
        msg['Subject'] = 'Test'
        if fromhdr:
            msg['From'] = fromhdr
        if msgid:
            msg['Message-Id'] = f'<{msgid}>'
        if date:
            msg['Date'] = date
        return msg

    def test_exact_match(self) -> None:
        msg = self._make_msg('K R <maint@example.com>', 'own@example.com')
        entries = _review._own_message_entries([msg], 'maint@example.com')
        assert len(entries) == 1
        assert entries[0]['msgid'] == 'own@example.com'
        assert entries[0]['msg_date'] == '2026-07-27T10:00:00+00:00'

    def test_match_is_case_insensitive(self) -> None:
        msg = self._make_msg('Maint@Example.COM', 'own@example.com')
        entries = _review._own_message_entries([msg], 'maint@example.com')
        assert len(entries) == 1

    def test_bare_address_matches(self) -> None:
        msg = self._make_msg('maint@example.com', 'own@example.com')
        entries = _review._own_message_entries([msg], 'maint@example.com')
        assert len(entries) == 1

    def test_other_address_no_match(self) -> None:
        msg = self._make_msg('K R <other@example.com>', 'own@example.com')
        assert _review._own_message_entries([msg], 'maint@example.com') == []

    def test_dmarc_munged_from_no_match(self) -> None:
        # A list that rewrites From keeps the name but swaps the address
        msg = self._make_msg(
            'K R via lists.example.com <lists@lists.example.com>',
            'own@example.com',
        )
        assert _review._own_message_entries([msg], 'maint@example.com') == []

    def test_missing_from_no_match(self) -> None:
        msg = self._make_msg('', 'own@example.com')
        assert _review._own_message_entries([msg], 'maint@example.com') == []

    def test_missing_msgid_skipped(self) -> None:
        msg = self._make_msg('maint@example.com', '')
        assert _review._own_message_entries([msg], 'maint@example.com') == []

    def test_missing_date_gives_none(self) -> None:
        msg = self._make_msg('maint@example.com', 'own@example.com', date=None)
        entries = _review._own_message_entries([msg], 'maint@example.com')
        assert len(entries) == 1
        assert entries[0]['msg_date'] is None

    def test_filters_mixed_thread(self) -> None:
        msgs = [
            self._make_msg('Author <author@example.com>', 'a@example.com'),
            self._make_msg('K R <maint@example.com>', 'b@example.com'),
            self._make_msg('Other <other@example.com>', 'c@example.com'),
            self._make_msg('maint@example.com', 'd@example.com'),
        ]
        entries = _review._own_message_entries(msgs, 'maint@example.com')
        assert [e['msgid'] for e in entries] == ['b@example.com', 'd@example.com']


# ---------------------------------------------------------------------------
# archive_series
# ---------------------------------------------------------------------------


class TestArchiveSeries:
    """Tests for b4.review.archive_series() and delete_review_branch()."""

    CHANGE_ID = 'arch-cid'
    IDENTIFIER = 'archproj'

    def _make_repo(self, tmp_path: Any) -> str:
        """Create a repo with a review branch (2 patches + tracking commit)
        and a matching 'accepted' series in the tracking database.

        Returns the repository path; HEAD is left on the base branch.
        """
        repo = str(tmp_path / 'arch-repo')
        ecode, out = b4.git_run_command(None, ['init', '-b', 'main', repo])
        assert ecode == 0, out
        b4.git_set_config(repo, 'user.name', 'Test')
        b4.git_set_config(repo, 'user.email', 'test@example.com')
        ecode, out = b4.git_run_command(
            repo, ['commit', '--allow-empty', '-m', 'base'], rundir=repo
        )
        assert ecode == 0, out
        ecode, base_sha = b4.git_run_command(repo, ['rev-parse', 'HEAD'])
        assert ecode == 0
        base_sha = base_sha.strip()

        branch = f'b4/review/{self.CHANGE_ID}'
        ecode, _out = b4.git_run_command(repo, ['checkout', '-b', branch], rundir=repo)
        assert ecode == 0
        patch_shas: List[str] = []
        for i in (1, 2):
            with open(f'{repo}/file{i}.txt', 'w') as fh:
                fh.write(f'content {i}\n')
            ecode, _out = b4.git_run_command(repo, ['add', f'file{i}.txt'], rundir=repo)
            assert ecode == 0
            ecode, _out = b4.git_run_command(
                repo, ['commit', '-m', f'patch {i}'], rundir=repo
            )
            assert ecode == 0
            ecode, sha = b4.git_run_command(repo, ['rev-parse', 'HEAD'])
            assert ecode == 0
            patch_shas.append(sha.strip())

        trk: Dict[str, Any] = {
            'series': {
                'identifier': self.IDENTIFIER,
                'change-id': self.CHANGE_ID,
                'revision': 1,
                'status': 'accepted',
                'subject': 'Test series',
                'base-commit': base_sha,
                'first-patch-commit': patch_shas[0],
                'header-info': {},
            },
            'followups': [],
            'patches': [{'header-info': {}, 'followups': []} for _ in patch_shas],
        }
        commit_msg = f'Test series\n\n{review.make_review_magic_json(trk)}'
        ecode, _out = b4.git_run_command(
            repo, ['commit', '--allow-empty', '-m', commit_msg], rundir=repo
        )
        assert ecode == 0
        ecode, _out = b4.git_run_command(repo, ['checkout', 'main'], rundir=repo)
        assert ecode == 0

        conn = b4.review.tracking.init_db(self.IDENTIFIER)
        b4.review.tracking.add_series_to_db(
            conn,
            self.CHANGE_ID,
            1,
            'Test series',
            'Test',
            't@example.com',
            None,
            '<msg@id>',
            2,
        )
        b4.review.tracking.update_series_status(
            conn, self.CHANGE_ID, 'accepted', revision=1
        )
        conn.commit()
        conn.close()
        return repo

    def _db_status(self) -> str:
        conn = b4.review.tracking.get_db(self.IDENTIFIER)
        row = conn.execute(
            'SELECT status FROM series WHERE change_id = ?', (self.CHANGE_ID,)
        ).fetchone()
        conn.close()
        return str(row[0])

    def test_archives_branch_and_db(self, tmp_path: Any) -> None:
        """Archiving tars up the branch contents, deletes the branch, and
        marks the series archived in the database."""
        import tarfile

        repo = self._make_repo(tmp_path)
        branch = f'b4/review/{self.CHANGE_ID}'
        ok, detail = review.archive_series(repo, self.IDENTIFIER, self.CHANGE_ID, 1)
        assert ok, detail
        assert detail.endswith(f'{self.CHANGE_ID}.tar.gz')
        with tarfile.open(detail) as tfh:
            names = set(tfh.getnames())
        assert names == {
            f'{self.CHANGE_ID}/cover.txt',
            f'{self.CHANGE_ID}/tracking.js',
            f'{self.CHANGE_ID}/patches.mbx',
        }
        assert not b4.git_branch_exists(repo, branch)
        assert self._db_status() == 'archived'

    def test_idempotent_when_branch_missing(self, tmp_path: Any) -> None:
        """A second archive (branch already gone) is a database-only no-op
        success, so queue delivery can never fail on a manual archive."""
        repo = self._make_repo(tmp_path)
        ok, _detail = review.archive_series(repo, self.IDENTIFIER, self.CHANGE_ID, 1)
        assert ok
        ok, detail = review.archive_series(repo, self.IDENTIFIER, self.CHANGE_ID, 1)
        assert ok
        assert detail == ''
        assert self._db_status() == 'archived'

    def test_refuses_checked_out_branch_without_switch(self, tmp_path: Any) -> None:
        """A non-interactive archive must never yank the checkout out from
        under the user: it refuses and leaves branch and status alone."""
        repo = self._make_repo(tmp_path)
        branch = f'b4/review/{self.CHANGE_ID}'
        ecode, _out = b4.git_run_command(repo, ['checkout', branch], rundir=repo)
        assert ecode == 0
        ok, detail = review.archive_series(
            repo, self.IDENTIFIER, self.CHANGE_ID, 1, allow_switch=False
        )
        assert not ok
        assert 'currently checked out' in detail
        assert b4.git_branch_exists(repo, branch)
        assert self._db_status() == 'accepted'

    def test_allow_switch_archives_checked_out_branch(self, tmp_path: Any) -> None:
        """An interactive archive may switch away from the branch first."""
        repo = self._make_repo(tmp_path)
        branch = f'b4/review/{self.CHANGE_ID}'
        ecode, _out = b4.git_run_command(repo, ['checkout', branch], rundir=repo)
        assert ecode == 0
        ok, detail = review.archive_series(
            repo, self.IDENTIFIER, self.CHANGE_ID, 1, allow_switch=True
        )
        assert ok, detail
        assert not b4.git_branch_exists(repo, branch)
        assert self._db_status() == 'archived'

    def test_unwritable_archive_is_reported_not_raised(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Archiving happens after a thank-you has gone out, so an I/O
        failure must come back as (False, detail).  Raising here would be
        caught upstream and shown as a send failure, telling the maintainer
        to send a note that is already on the list."""
        repo = self._make_repo(tmp_path)
        branch = f'b4/review/{self.CHANGE_ID}'

        def boom(*args: Any, **kwargs: Any) -> None:
            raise OSError(28, 'No space left on device')

        monkeypatch.setattr('b4.ez.write_to_tar', boom)
        ok, detail = review.archive_series(repo, self.IDENTIFIER, self.CHANGE_ID, 1)
        assert not ok
        assert 'No space left on device' in detail
        # Nothing was destroyed, so the maintainer can simply retry
        assert b4.git_branch_exists(repo, branch)
        assert self._db_status() == 'accepted'


class TestCreateReviewBranchCleanup:
    """A branch that cannot be finished is not left checked out."""

    @staticmethod
    def _seed_fetch_head(gitdir: str) -> Tuple[str, str]:
        """Leave a commit for the cherry-pick to land, as FETCH_HEAD.

        Returns (base, tip): the commit to build the review branch on, and
        the one waiting in FETCH_HEAD.
        """
        ecode, base = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        base = base.strip()

        with open(os.path.join(gitdir, 'file1.txt'), 'a') as fh:
            fh.write('review branch cleanup\n')
        b4.git_run_command(gitdir, ['add', 'file1.txt'])
        ecode, _out = b4.git_run_command(gitdir, ['commit', '-m', 'cleanup test'])
        assert ecode == 0
        ecode, tip = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        tip = tip.strip()
        with open(os.path.join(gitdir, '.git', 'FETCH_HEAD'), 'w') as fh:
            fh.write(f'{tip}\t\tbranch\n')
        ecode, _out = b4.git_run_command(gitdir, ['reset', '--hard', base])
        assert ecode == 0
        return base, tip

    @staticmethod
    def _create_with_unreadable_range(gitdir: str, branch: str, base: str) -> None:
        """Run create_review_branch() with the patch range failing to read."""
        real_run = b4.git_run_command

        def _fail_revlist(
            topdir: Any, args: List[str], *a: Any, **kw: Any
        ) -> Tuple[int, Union[str, bytes]]:
            if args[:2] == ['rev-list', '--reverse']:
                return 1, ''
            return real_run(topdir, args, *a, **kw)

        with mock.patch.object(b4, 'git_run_command', side_effect=_fail_revlist):
            with pytest.raises(SystemExit):
                review.create_review_branch(
                    gitdir,
                    branch,
                    base,
                    b4.LoreSeries(1, 1),
                    'https://example.com/x',
                    'https://example.com/%s',
                )

    def test_cleans_up_when_the_patch_range_cannot_be_read(self, gitdir: str) -> None:
        """Everything between the checkout and the tracking commit runs with
        HEAD already on the new branch.  Bailing out there without restoring
        leaves the caller standing on a branch that was never finished, which
        the two neighbouring failures below it already knew to avoid."""
        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', '-b', 'work'])
        assert ecode == 0
        base, _tip = self._seed_fetch_head(gitdir)

        branch = 'b4/review/cleanup-test'
        self._create_with_unreadable_range(gitdir, branch, base)

        assert b4.git_get_current_branch(gitdir) == 'work'
        assert not b4.git_branch_exists(gitdir, branch)

    def test_cleans_up_from_a_detached_head(self, gitdir: str) -> None:
        """A detached HEAD has no branch name to go back to, and skipping the
        restore on that account costs both halves of the cleanup: git refuses
        to delete the branch HEAD is standing on, so the caller keeps the
        stranding *and* the leftover.  The name comes from the change-id, so
        the next attempt at that series then walks into 'already exists'.

        Detached at the FETCH_HEAD tip rather than at the base, so restoring
        to the base the branch was created at does not pass for remembering
        where HEAD actually was.
        """
        base, tip = self._seed_fetch_head(gitdir)
        ecode, _out = b4.git_run_command(gitdir, ['checkout', '-q', '--detach', tip])
        assert ecode == 0

        branch = 'b4/review/cleanup-detached'
        self._create_with_unreadable_range(gitdir, branch, base)

        assert b4.git_get_current_branch(gitdir) is None
        ecode, head = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
        assert ecode == 0
        assert head.strip() == tip
        assert not b4.git_branch_exists(gitdir, branch)
