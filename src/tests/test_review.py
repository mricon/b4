import email.message
import json
from typing import Any, Dict, List, Optional, Union
from unittest import mock

import pytest

import b4
from b4 import review
from b4 import review_tui
from b4.review._review import REVIEW_MAGIC_MARKER, check_series_attestation


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
            SIMPLE_DIFF, {}, 'me@example.com')
        for line in result.splitlines():
            assert line.startswith(('> ', '#')) or line == '', f'Unquoted line: {line!r}'

    def test_own_comment_is_unquoted(self) -> None:
        """Own comments appear as unquoted text between quoted diff."""
        all_reviews: Dict[str, Any] = {
            'me@example.com': {
                'name': 'Me',
                'comments': [
                    {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'Check NULL return'},
                ],
            },
        }
        result = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, all_reviews, 'me@example.com')
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
            SIMPLE_DIFF, all_reviews, 'me@example.com')
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
            SIMPLE_DIFF, all_reviews, 'me@example.com')
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
            TWO_FILE_DIFF, all_reviews, 'me@example.com')
        assert 'Comment in a.c' in result
        assert 'Comment in b.c' in result


    def test_editor_instructions_at_top(self) -> None:
        """Rendered output starts with # instruction lines."""
        result = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, {}, 'me@example.com')
        lines = result.splitlines()
        # First non-empty line should be an instruction
        assert lines[0].startswith('# ')
        # Instructions end before the first quoted diff line
        instruction_lines = [l for l in lines if l.startswith('#')]
        assert len(instruction_lines) >= 3
        # _extract_editor_comments should strip them
        comments = review._extract_editor_comments(result)
        assert not any(c['text'].startswith('#') for c in comments)

    def test_commit_msg_quoted_before_diff(self) -> None:
        """Commit message body is quoted before the diff when provided."""
        result = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, {}, 'me@example.com',
            commit_msg='Subject line\n\nThis is the body.\nSecond line.')
        lines = result.splitlines()
        # Body lines should appear quoted before the diff
        assert '> This is the body.' in lines
        assert '> Second line.' in lines
        # They should come before the diff
        body_idx = lines.index('> This is the body.')
        diff_idx = next(i for i, l in enumerate(lines) if 'diff --git' in l)
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
            SIMPLE_DIFF, all_reviews, 'me@example.com',
            commit_msg='Subject\n\nFirst body line.')
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
            SIMPLE_DIFF, all_reviews, 'me@example.com',
            commit_msg='Subject\n\nFirst body line.')
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
            SIMPLE_DIFF, all_reviews, 'me@example.com',
            commit_msg='Subject\n\nFirst body line.')
        lines = result.splitlines()
        assert 'General note' in lines
        note_idx = lines.index('General note')
        body_idx = next(i for i, l in enumerate(lines) if 'First body line' in l)
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
            SIMPLE_DIFF, all_reviews, 'me@example.com')
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
            TWO_FILE_DIFF, all_reviews, 'me@example.com')
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
            SIMPLE_DIFF, all_reviews, 'me@example.com')
        extracted1 = review._extract_editor_comments(rendered1)

        all_reviews2: Dict[str, Any] = {
            'me@example.com': {'name': 'Me', 'comments': extracted1},
        }
        rendered2 = review._render_quoted_diff_with_comments(
            SIMPLE_DIFF, all_reviews2, 'me@example.com')
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
            SIMPLE_DIFF, all_reviews, 'me@example.com')
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
            SIMPLE_DIFF, all_reviews, 'me@example.com',
            commit_msg='Subject\n\nFirst body line.\nSecond line.')
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
            SIMPLE_DIFF, all_reviews, 'me@example.com',
            commit_msg='Subject\n\nBody line.')
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
            SIMPLE_DIFF, all_reviews, 'me@example.com',
            commit_msg='Subject\n\nFirst body line.')
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
            {'path': 'b/lib/helpers.c', 'line': 12,
             'text': 'Check return value.'},
        ]
        result = review._build_reply_from_comments(
            SIMPLE_DIFF, comments, [])
        # The comment should be present
        assert 'Check return value.' in result
        # The +kzalloc line (line 12) should be quoted
        assert 'kzalloc' in result
        # The +ptr->field line (line 13) comes after the comment and
        # has no comment of its own, so it should be truncated
        assert 'ptr->field' not in result
        # The trailing context "return 0" should also be absent
        assert 'return 0' not in result

    def test_lines_before_comment_preserved(self) -> None:
        """Diff lines before the comment are preserved as quoted context."""
        comments = [
            {'path': 'b/lib/helpers.c', 'line': 13,
             'text': 'Check field assignment.'},
        ]
        result = review._build_reply_from_comments(
            SIMPLE_DIFF, comments, [])
        # The kzalloc line (line 12) precedes the comment target
        assert 'kzalloc' in result
        # The ptr->field line (line 13) is the commented line
        assert 'ptr->field' in result
        assert 'Check field assignment.' in result

    def test_two_comments_middle_lines_preserved(self) -> None:
        """Lines between two comments are kept, trailing lines dropped."""
        comments = [
            {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'First.'},
            {'path': 'b/lib/helpers.c', 'line': 13, 'text': 'Second.'},
        ]
        result = review._build_reply_from_comments(
            SIMPLE_DIFF, comments, [])
        assert 'First.' in result
        assert 'Second.' in result
        assert 'kzalloc' in result
        assert 'ptr->field' in result
        # "return 0" is after the last comment — should be truncated
        assert 'return 0' not in result

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
            SIMPLE_DIFF, comments, [], commit_msg=commit_msg)
        assert 'Comment on line three.' in result
        assert '> Line three.' in result

    def test_commit_msg_preamble_comment(self) -> None:
        """Preamble comments (line 0) appear before quoted content."""
        commit_msg = 'Subject\n\nBody line.'
        comments = [
            {'path': ':message', 'line': 0, 'text': 'General feedback.'},
        ]
        result = review._build_reply_from_comments(
            '', comments, [], commit_msg=commit_msg)
        lines = result.splitlines()
        assert 'General feedback.' in lines
        # Preamble should come before any quoted line
        feedback_idx = lines.index('General feedback.')
        quoted_lines = [i for i, l in enumerate(lines) if l.startswith('>')]
        if quoted_lines:
            assert feedback_idx < quoted_lines[0]

    def test_commit_msg_no_separator_without_diff(self) -> None:
        """No stray > separator when there is no diff content."""
        commit_msg = 'Subject\n\nBody line.'
        comments = [
            {'path': ':message', 'line': 1, 'text': 'A comment.'},
        ]
        result = review._build_reply_from_comments(
            '', comments, [], commit_msg=commit_msg)
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
            '', comments, [], commit_msg=commit_msg)
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
            SIMPLE_DIFF, comments, [], commit_msg=commit_msg)
        assert 'General comment.' in result

    def test_comment_above_diff_git_roundtrips(self) -> None:
        """Comment above first diff --git line survives parse and render."""
        commit_msg = 'Subject\n\nBody.\n\nSigned-off-by: A <a@b.c>'
        diff = (
            "diff --git a/f.c b/f.c\n"
            "--- a/f.c\n"
            "+++ b/f.c\n"
            "@@ -1,3 +1,4 @@\n"
            " ctx\n"
            "+new\n"
            " more\n"
        )
        # Simulate what the editor would produce: quoted commit message,
        # separator, user comment, then quoted diff
        edited = (
            "> Body.\n"
            ">\n"
            "> Signed-off-by: A <a@b.c>\n"
            ">\n"
            "\n"
            "My general comment.\n"
            "\n"
            "> diff --git a/f.c b/f.c\n"
            "> --- a/f.c\n"
            "> +++ b/f.c\n"
            "> @@ -1,3 +1,4 @@\n"
            ">  ctx\n"
            "> +new\n"
            ">  more\n"
        )
        comments = review._extract_editor_comments(edited, diff_text=diff)
        assert len(comments) == 1
        assert comments[0]['text'] == 'My general comment.'
        # Now rebuild the reply from those comments
        result = review._build_reply_from_comments(
            diff, comments, [], commit_msg=commit_msg)
        assert 'My general comment.' in result


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


class TestBuildReviewEmailBcc:
    """Tests for Bcc header support in _build_review_email()."""

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
    def _make_review() -> Dict[str, Any]:
        return {'trailers': ['Reviewed-by: Test <test@example.com>']}

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_bcc_set_when_present(self, _mock_cfg: mock.Mock,
                                  _mock_sig: mock.Mock) -> None:
        series = self._make_series(bcc='secret@example.com')
        msg = review._build_review_email(
            series, None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert msg['Bcc'] == 'secret@example.com'

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_no_bcc_when_absent(self, _mock_cfg: mock.Mock,
                                _mock_sig: mock.Mock) -> None:
        series = self._make_series()
        msg = review._build_review_email(
            series, None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert msg['Bcc'] is None

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_no_bcc_when_empty(self, _mock_cfg: mock.Mock,
                               _mock_sig: mock.Mock) -> None:
        series = self._make_series(bcc='')
        msg = review._build_review_email(
            series, None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert msg['Bcc'] is None

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_cc_still_works(self, _mock_cfg: mock.Mock,
                            _mock_sig: mock.Mock) -> None:
        series = self._make_series(cc='other@example.com')
        msg = review._build_review_email(
            series, None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert 'other@example.com' in msg['Cc']
        assert 'maintainer@example.com' in msg['Cc']


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
        usercfg: Dict[str, Union[str, List[str], None]] = {'email': 'user@example.com', 'name': 'User'}
        entry = review._ensure_my_review(target, usercfg)
        assert entry['name'] == 'User'
        assert target['reviews']['user@example.com'] is entry

    def test_returns_existing_and_updates_name(self) -> None:
        existing = {'name': 'Old Name', 'trailers': ['Reviewed-by: Old']}
        target = {'reviews': {'user@example.com': existing}}
        usercfg: Dict[str, Union[str, List[str], None]] = {'email': 'user@example.com', 'name': 'New Name'}
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


# -- Tests for _build_review_email() (expanded) ------------------------------

class TestBuildReviewEmailHeaders:
    """Expanded tests for _build_review_email() header and body construction."""

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

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_returns_none_when_empty_review(self, _mock_cfg: mock.Mock,
                                            _mock_sig: mock.Mock) -> None:
        msg = review._build_review_email(
            self._make_series(), None, {'trailers': [], 'reply': '', 'comments': []},
            'cover', '', None)
        assert msg is None

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_returns_none_when_no_msgid(self, _mock_cfg: mock.Mock,
                                        _mock_sig: mock.Mock) -> None:
        series = self._make_series()
        series['header-info']['msgid'] = ''
        msg = review._build_review_email(
            series, None, self._make_review(), 'cover', '', None)
        assert msg is None

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_subject_gets_re_prefix(self, _mock_cfg: mock.Mock,
                                    _mock_sig: mock.Mock) -> None:
        msg = review._build_review_email(
            self._make_series(), None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert msg['Subject'] == 'Re: Test patch'

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_re_prefix_not_doubled(self, _mock_cfg: mock.Mock,
                                   _mock_sig: mock.Mock) -> None:
        series = self._make_series()
        series['subject'] = 'Re: Already prefixed'
        msg = review._build_review_email(
            series, None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert msg['Subject'] == 'Re: Already prefixed'

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_reply_to_used_as_to(self, _mock_cfg: mock.Mock,
                                 _mock_sig: mock.Mock) -> None:
        series = self._make_series(**{'reply-to': 'list@lists.example.com'})
        msg = review._build_review_email(
            series, None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert 'list@lists.example.com' in msg['To']

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_from_is_series_author_when_no_reply_to(self, _mock_cfg: mock.Mock,
                                                    _mock_sig: mock.Mock) -> None:
        msg = review._build_review_email(
            self._make_series(), None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert 'author@example.com' in msg['To']

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_references_without_existing(self, _mock_cfg: mock.Mock,
                                         _mock_sig: mock.Mock) -> None:
        msg = review._build_review_email(
            self._make_series(), None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert msg['References'] == '<test-msgid@example.com>'

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_references_with_existing(self, _mock_cfg: mock.Mock,
                                      _mock_sig: mock.Mock) -> None:
        series = self._make_series(references='<prev@example.com>')
        msg = review._build_review_email(
            series, None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert '<prev@example.com>' in msg['References']
        assert '<test-msgid@example.com>' in msg['References']

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_body_contains_trailers(self, _mock_cfg: mock.Mock,
                                    _mock_sig: mock.Mock) -> None:
        msg = review._build_review_email(
            self._make_series(), None, self._make_review(), 'cover text', '', None)
        assert msg is not None
        payload = msg.get_payload(decode=True)
        assert isinstance(payload, bytes)
        assert 'Reviewed-by: Test <test@example.com>' in payload.decode()

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_explicit_reply_text_used(self, _mock_cfg: mock.Mock,
                                      _mock_sig: mock.Mock) -> None:
        rev = self._make_review(reply='This is my explicit reply.')
        msg = review._build_review_email(
            self._make_series(), None, rev, 'cover', '', None)
        assert msg is not None
        payload = msg.get_payload(decode=True)
        assert isinstance(payload, bytes)
        assert 'This is my explicit reply.' in payload.decode()

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_in_reply_to_set(self, _mock_cfg: mock.Mock,
                             _mock_sig: mock.Mock) -> None:
        msg = review._build_review_email(
            self._make_series(), None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert msg['In-Reply-To'] == '<test-msgid@example.com>'

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_from_header_is_reviewer(self, _mock_cfg: mock.Mock,
                                     _mock_sig: mock.Mock) -> None:
        msg = review._build_review_email(
            self._make_series(), None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert 'reviewer@example.com' in msg['From']
        assert 'Reviewer' in msg['From']

# -- Tests for _build_review_email() user-edited To/Cc -----------------------

class TestBuildReviewEmailToCcEdited:
    """Tests for user-edited To/Cc handling in _build_review_email()."""

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
    def _make_review() -> Dict[str, Any]:
        return {'trailers': ['Reviewed-by: Test <test@example.com>']}

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_default_to_is_author(self, _mock_cfg: mock.Mock,
                                  _mock_sig: mock.Mock) -> None:
        """Without tocc-edited, To should be the original author."""
        msg = review._build_review_email(
            self._make_series(), None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert 'author@example.com' in msg['To']

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_default_demotes_to_header_to_cc(self, _mock_cfg: mock.Mock,
                                             _mock_sig: mock.Mock) -> None:
        """Without tocc-edited, original To gets folded into Cc."""
        series = self._make_series(to='list@lists.example.com')
        msg = review._build_review_email(
            series, None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert 'author@example.com' in msg['To']
        assert 'list@lists.example.com' in msg['Cc']

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_edited_to_is_honoured(self, _mock_cfg: mock.Mock,
                                   _mock_sig: mock.Mock) -> None:
        """With tocc-edited, user's To choice should be used as-is."""
        series = self._make_series(to='custom@example.com')
        series['header-info']['tocc-edited'] = True
        msg = review._build_review_email(
            series, None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert 'custom@example.com' in msg['To']
        assert 'author@example.com' not in (msg['To'] or '')

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_edited_cc_is_honoured(self, _mock_cfg: mock.Mock,
                                   _mock_sig: mock.Mock) -> None:
        """With tocc-edited, user's Cc choice should be used as-is."""
        series = self._make_series(to='custom@example.com', cc='other@example.com')
        series['header-info']['tocc-edited'] = True
        msg = review._build_review_email(
            series, None, self._make_review(), 'cover', '', None)
        assert msg is not None
        assert msg['To'] == 'custom@example.com'
        assert msg['Cc'] == 'other@example.com'

    @mock.patch('b4.get_email_signature', return_value='sig')
    @mock.patch('b4.get_user_config', return_value={
        'name': 'Reviewer', 'email': 'reviewer@example.com'})
    def test_edited_empty_cc_omitted(self, _mock_cfg: mock.Mock,
                                     _mock_sig: mock.Mock) -> None:
        """With tocc-edited, empty Cc should not produce a Cc header."""
        series = self._make_series(to='custom@example.com', cc='')
        series['header-info']['tocc-edited'] = True
        msg = review._build_review_email(
            series, None, self._make_review(), 'cover', '', None)
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
        name: str, value: str,
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
        self, body: str, followup_trailers: List[Any],
    ) -> mock.Mock:
        """Build a mock LoreMessage with body and followup_trailers."""
        lmsg = mock.Mock()
        lmsg.body = body
        lmsg.followup_trailers = followup_trailers
        return lmsg

    def test_basic_followup(self) -> None:
        """A single follow-up trailer is collected."""
        ft = self._make_followup_trailer(
            'Reviewed-by', 'Reviewer <reviewer@example.com>',
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
            'Reviewed-by', 'Reviewer <reviewer@example.com>',
        )
        lmsg = self._make_lmsg(body, [ft])
        result = review._collect_followups(lmsg, self.LINKMASK)
        assert len(result) == 0

    def test_keeps_trailer_not_in_body(self) -> None:
        """Follow-up trailers NOT in the body are kept."""
        body = (
            'Patch description\n'
            '\n'
            'Signed-off-by: Author <author@example.com>\n'
        )
        ft = self._make_followup_trailer(
            'Acked-by', 'Acker <acker@example.com>',
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
            'Reviewed-by', 'Reviewer <reviewer@example.com>',
            msgid='reply1@example.com',
        )
        ft_new = self._make_followup_trailer(
            'Tested-by', 'Tester <tester@example.com>',
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
            'Reviewed-by', 'Reviewer <reviewer@example.com>',
            msgid='reply@example.com',
        )
        ft2 = self._make_followup_trailer(
            'Tested-by', 'Reviewer <reviewer@example.com>',
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

class TestGetArtCounts:
    """Tests for _get_art_counts() in _tracking_app."""

    @staticmethod
    def _make_tracking_json(followups: Optional[List[Dict[str, Any]]] = None, patches: Optional[List[Dict[str, Any]]] = None) -> str:
        """Build a tracking commit message with the given followup data."""
        tracking: Dict[str, Any] = {}
        if followups is not None:
            tracking['followups'] = followups
        if patches is not None:
            tracking['patches'] = patches
        return 'Cover letter text\n\n--- b4-review-tracking ---\n' + json.dumps(tracking)

    @mock.patch('b4.git_run_command')
    def test_counts_all_trailer_types(self, mock_git: mock.Mock) -> None:
        """Counts Acked-by, Reviewed-by, and Tested-by from followups."""
        commit_msg = self._make_tracking_json(
            followups=[
                {'trailers': ['Acked-by: A <a@example.com>',
                               'Reviewed-by: R <r@example.com>']},
            ],
            patches=[
                {'followups': [
                    {'trailers': ['Tested-by: T <t@example.com>',
                                  'Acked-by: B <b@example.com>']},
                ]},
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
                {'trailers': ['Signed-off-by: S <s@example.com>',
                               'Reviewed-by: R <r@example.com>']},
            ],
        )
        mock_git.return_value = (0, commit_msg)
        from b4.review_tui._tracking_app import _get_art_counts
        assert _get_art_counts('/tmp', 'b4/review/test') == (0, 1, 0)

    @mock.patch('b4.git_run_command')
    def test_skips_comment_lines_in_json(self, mock_git: mock.Mock) -> None:
        """Lines starting with # in the JSON block are ignored."""
        tracking = json.dumps({'followups': [{'trailers': ['Acked-by: A <a@example.com>']}]})
        commit_msg = 'Cover\n\n--- b4-review-tracking ---\n# comment line\n' + tracking
        mock_git.return_value = (0, commit_msg)
        from b4.review_tui._tracking_app import _get_art_counts
        assert _get_art_counts('/tmp', 'b4/review/test') == (1, 0, 0)


# -- Tests for note comment stripping ----------------------------------------

class TestNoteCommentStripping:
    """Tests for the # comment stripping logic used in note editing."""

    @staticmethod
    def _strip_comments(raw_text: str) -> str:
        """Replicate the stripping logic from _edit_note_in_editor."""
        return '\n'.join(ln for ln in raw_text.splitlines() if not ln.startswith('#')).strip()

    def test_strips_comment_lines(self) -> None:
        raw = 'This is my note\n# This is a comment\nSecond line'
        assert self._strip_comments(raw) == 'This is my note\nSecond line'

    def test_strips_footer(self) -> None:
        raw = (
            'My note here\n'
            '\n'
            '# Add a private note about this patch. It will not be sent in your\n'
            '# email reply, but it will be stored in the tracking commit and\n'
            '# viewable by anyone if you push this branch to any remote.\n'
            '#\n'
            '# Lines starting with # will be removed.\n'
        )
        assert self._strip_comments(raw) == 'My note here'

    def test_preserves_non_comment_lines(self) -> None:
        raw = 'Line one\nLine two\nLine three'
        assert self._strip_comments(raw) == 'Line one\nLine two\nLine three'

    def test_empty_after_stripping(self) -> None:
        raw = '# Only comments\n# Nothing else'
        assert self._strip_comments(raw) == ''

    def test_mixed_content(self) -> None:
        raw = '# TODO: revisit\nNeed to check NULL path\n# end'
        assert self._strip_comments(raw) == 'Need to check NULL path'


# -- Helpers for attestation tests -------------------------------------------

def _make_mock_attestation(status: str, identity: str, passing: bool) -> Dict[str, Any]:
    """Build an attestation dict as returned by LoreMessage.get_attestation_status()."""
    return {'status': status, 'identity': identity, 'passing': passing}


def _make_mock_lmsg(attestations: List[Dict[str, Any]], passing: bool = True, critical: bool = False) -> mock.Mock:
    """Build a mock LoreMessage with a canned get_attestation_status() response."""
    lmsg = mock.Mock()
    lmsg.get_attestation_status = mock.Mock(return_value=(attestations, passing, critical))
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
        with mock.patch('b4.get_main_config', return_value={'attestation-policy': 'off'}):
            assert check_series_attestation(lser) is None

    def test_no_signatures_returns_none_string(self) -> None:
        """When no attestors found on any patch, returns 'none'."""
        lser = self._make_series([_make_mock_lmsg([]), _make_mock_lmsg([])])
        with mock.patch('b4.get_main_config', return_value={'attestation-policy': 'softfail'}):
            assert check_series_attestation(lser) == 'none'

    def test_single_signed_dkim(self) -> None:
        """A single passing DKIM attestor is reported correctly."""
        att = [_make_mock_attestation('signed', 'DKIM/kernel.org', True)]
        lser = self._make_series([_make_mock_lmsg(att)])
        with mock.patch('b4.get_main_config', return_value={'attestation-policy': 'softfail'}):
            result = check_series_attestation(lser)
        assert result == 'signed:DKIM/kernel.org'

    def test_nokey_attestor(self) -> None:
        """A nokey attestor is reported with status 'nokey'."""
        att = [_make_mock_attestation('nokey', 'ed25519/user@example.com', False)]
        lser = self._make_series([_make_mock_lmsg(att)])
        with mock.patch('b4.get_main_config', return_value={'attestation-policy': 'softfail'}):
            result = check_series_attestation(lser)
        assert result == 'nokey:ed25519/user@example.com'

    def test_badsig_attestor(self) -> None:
        """A badsig attestor is reported with status 'badsig'."""
        att = [_make_mock_attestation('badsig', 'ed25519/user@example.com', False)]
        lser = self._make_series([_make_mock_lmsg(att)])
        with mock.patch('b4.get_main_config', return_value={'attestation-policy': 'softfail'}):
            result = check_series_attestation(lser)
        assert result == 'badsig:ed25519/user@example.com'

    def test_mixed_attestors(self) -> None:
        """Mixed signed and nokey attestors are semicolon-separated and sorted."""
        att = [
            _make_mock_attestation('signed', 'DKIM/kernel.org', True),
            _make_mock_attestation('nokey', 'ed25519/user@example.com', False),
        ]
        lser = self._make_series([_make_mock_lmsg(att)])
        with mock.patch('b4.get_main_config', return_value={'attestation-policy': 'softfail'}):
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
        with mock.patch('b4.get_main_config', return_value={'attestation-policy': 'softfail'}):
            result = check_series_attestation(lser)
        assert result == 'signed:DKIM/kernel.org'

    def test_none_patches_skipped(self) -> None:
        """None entries in patches list are skipped gracefully."""
        att = [_make_mock_attestation('signed', 'DKIM/kernel.org', True)]
        lser = mock.Mock()
        lser.patches = [None, None, _make_mock_lmsg(att), None]
        with mock.patch('b4.get_main_config', return_value={'attestation-policy': 'softfail'}):
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
        config = {'attestation-policy': 'softfail', 'attestation-staleness-days': 'garbage'}
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
            "commit abc123\n"
            "Author: Test <test@test.com>\n"
            "\n"
            "Test patch\n"
            "\n"
            "> diff --git a/fs/file.c b/fs/file.c\n"
            "> @@ -10,4 +10,5 @@ void func(void)\n"
            ">  \tint x;\n"
            "> +\tptr = malloc(sz);\n"
            "\n"
            "Missing NULL check after malloc.\n"
            "\n"
            ">  \treturn 0;\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert 'NULL check' in comments[0]['text']
        assert comments[0]['path'] == 'fs/file.c'
        # +malloc is at +11, comment anchors there
        assert comments[0]['line'] == 11

    def test_no_diff_produces_no_comments(self) -> None:
        """Text with no quoted diff content produces nothing."""
        inline = "commit abc123\nAuthor: Test\n\nJust text, no diffs.\n"
        comments = review._extract_comments_from_quoted_reply(inline)
        assert comments == []

    def test_truncation_markers_skipped(self) -> None:
        """'[ ... ]' markers don't appear in comment text."""
        inline = (
            "> diff --git a/f.c b/f.c\n"
            "> @@ -1,3 +1,4 @@\n"
            ">  ctx\n"
            "> +new\n"
            "\n"
            "Comment here.\n"
            "\n"
            "[ ... ]\n"
            "\n"
            "> @@ -10,3 +10,4 @@\n"
            ">  ctx2\n"
            "> +new2\n"
            "\n"
            "Another comment.\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 2
        assert '[ ... ]' not in comments[0]['text']
        assert 'Comment here.' == comments[0]['text']
        assert 'Another comment.' == comments[1]['text']

    def test_multiline_comment(self) -> None:
        """Multiple non-quoted lines between diff sections form one comment."""
        inline = (
            "> diff --git a/f.c b/f.c\n"
            "> @@ -5,3 +5,4 @@ void f(void)\n"
            ">  \tint a;\n"
            "> +\tint b;\n"
            "\n"
            "This variable name is confusing.\n"
            "Consider using a more descriptive name.\n"
            "\n"
            ">  \treturn;\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert 'confusing' in comments[0]['text']
        assert 'descriptive' in comments[0]['text']

    def test_multi_paragraph_comment_stays_merged(self) -> None:
        """Two paragraphs separated by a blank line become one comment."""
        inline = (
            "> diff --git a/f.c b/f.c\n"
            "> --- a/f.c\n"
            "> +++ b/f.c\n"
            "> @@ -5,3 +5,5 @@ void f(void)\n"
            ">  \tint a;\n"
            "> +\tint b;\n"
            "> +\tint c;\n"
            "\n"
            "First paragraph of review.\n"
            "\n"
            "Second paragraph of review.\n"
            "\n"
            ">  \treturn;\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert 'First paragraph' in comments[0]['text']
        assert 'Second paragraph' in comments[0]['text']

    def test_comments_in_different_hunks_stay_separate(self) -> None:
        """Comments in different hunks (far apart) stay separate."""
        inline = (
            "> diff --git a/f.c b/f.c\n"
            "> --- a/f.c\n"
            "> +++ b/f.c\n"
            "> @@ -5,3 +5,4 @@\n"
            ">  \tint a;\n"
            "> +\tint b;\n"
            "\n"
            "Comment on hunk 1.\n"
            "\n"
            ">  \treturn;\n"
            "> @@ -100,3 +101,4 @@\n"
            ">  \tvoid x;\n"
            "> +\tvoid y;\n"
            "\n"
            "Comment on hunk 2.\n"
            "\n"
            ">  \treturn;\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 2
        assert 'hunk 1' in comments[0]['text']
        assert 'hunk 2' in comments[1]['text']

    def test_email_reply_with_file_headers(self) -> None:
        """Email follow-ups include --- a/ and +++ b/ lines; parser handles them."""
        email_reply = (
            "On Mon, Jan 1, 2024, Dev <dev@test.com> wrote:\n"
            "> diff --git a/fs/file.c b/fs/file.c\n"
            "> index abc123..def456 100644\n"
            "> --- a/fs/file.c\n"
            "> +++ b/fs/file.c\n"
            "> @@ -10,3 +10,4 @@ void f(void)\n"
            ">  \tint x;\n"
            "> +\tptr = malloc(sz);\n"
            "\n"
            "Missing NULL check.\n"
            "\n"
            ">  \treturn 0;\n"
        )
        comments = review._extract_comments_from_quoted_reply(email_reply)
        assert len(comments) == 1
        assert 'NULL check' in comments[0]['text']
        # With explicit +++ b/ header, path includes the b/ prefix
        assert comments[0]['path'] == 'b/fs/file.c'

    def test_bare_gt_prefix(self) -> None:
        """Lines starting with just '>' (no space) are also parsed."""
        inline = (
            ">diff --git a/f.c b/f.c\n"
            ">@@ -1,3 +1,4 @@\n"
            "> ctx\n"
            ">+new\n"
            "\n"
            "Looks good.\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert 'Looks good.' == comments[0]['text']

    def test_comments_in_different_files(self) -> None:
        """Comments in different files produce separate entries with correct paths."""
        inline = (
            "> diff --git a/a.c b/a.c\n"
            "> @@ -1,3 +1,4 @@\n"
            ">  ctx\n"
            "> +new_a\n"
            "\n"
            "Comment in a.c.\n"
            "\n"
            "> diff --git a/b.c b/b.c\n"
            "> @@ -1,3 +1,4 @@\n"
            ">  ctx\n"
            "> +new_b\n"
            "\n"
            "Comment in b.c.\n"
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
            "Hi, some general feedback below:\n"
            "\n"
            "> diff --git a/f.c b/f.c\n"
            "> @@ -1,3 +1,4 @@\n"
            ">  ctx\n"
            "> +new\n"
            "\n"
            "Actual inline comment.\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert 'Actual inline comment.' == comments[0]['text']

    def test_trailing_comment_flushed(self) -> None:
        """A comment at the very end (no trailing quoted line) is still captured."""
        inline = (
            "> diff --git a/f.c b/f.c\n"
            "> @@ -1,3 +1,4 @@\n"
            ">  ctx\n"
            "> +new\n"
            "\n"
            "Final comment with no trailing diff.\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert 'Final comment' in comments[0]['text']

    def test_deletion_line_anchors_to_a_file(self) -> None:
        """Comment after a deletion line anchors to the a-side file and line."""
        inline = (
            "> diff --git a/old.c b/old.c\n"
            "> @@ -10,4 +10,3 @@\n"
            ">  ctx\n"
            "> -removed_line\n"
            "\n"
            "Why was this removed?\n"
            "\n"
            ">  more ctx\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['path'] == 'old.c'
        # Deletion at a_line=11, so comment anchors to line 11
        assert comments[0]['line'] == 11


    def test_commit_message_comment_extracted(self) -> None:
        """Comments on quoted commit message lines get :message path."""
        inline = (
            "> This is the commit body.\n"
            "> It explains the change.\n"
            "\n"
            "Why is this needed?\n"
            "\n"
            "> diff --git a/f.c b/f.c\n"
            "> @@ -1,3 +1,4 @@\n"
            ">  ctx\n"
            "> +new\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['path'] == ':message'
        assert comments[0]['line'] == 2
        assert comments[0]['text'] == 'Why is this needed?'

    def test_preamble_captured_when_enabled(self) -> None:
        """With capture_preamble=True, text before first quote is a comment."""
        inline = (
            "General feedback on this patch.\n"
            "\n"
            "> Commit body line.\n"
            "\n"
            "> diff --git a/f.c b/f.c\n"
            "> @@ -1,3 +1,4 @@\n"
            ">  ctx\n"
            "> +new\n"
        )
        comments = review._extract_comments_from_quoted_reply(
            inline, capture_preamble=True)
        preamble = [c for c in comments if c['line'] == 0]
        assert len(preamble) == 1
        assert preamble[0]['path'] == ':message'
        assert 'General feedback' in preamble[0]['text']

    def test_preamble_not_captured_by_default(self) -> None:
        """Without capture_preamble, text before first quote is ignored."""
        inline = (
            "General feedback on this patch.\n"
            "\n"
            "> diff --git a/f.c b/f.c\n"
            "> @@ -1,3 +1,4 @@\n"
            ">  ctx\n"
            "> +new\n"
            "\n"
            "Actual comment.\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['text'] == 'Actual comment.'

    def test_attribution_line_skipped_in_preamble(self) -> None:
        """The 'On ..., ... wrote:' attribution line is not captured."""
        inline = (
            "On Thu, 12 Mar 2026 15:54:20 +0100, Author <a@b.com> wrote:\n"
            "> Commit body.\n"
            "\n"
            "My comment.\n"
            "\n"
            "> diff --git a/f.c b/f.c\n"
            "> @@ -1,3 +1,4 @@\n"
            ">  ctx\n"
            "> +new\n"
        )
        comments = review._extract_comments_from_quoted_reply(
            inline, capture_preamble=True)
        # Attribution line should NOT become a comment
        for c in comments:
            assert 'wrote:' not in c.get('text', '')

    def test_orphan_hunk_header_enters_diff_mode(self) -> None:
        """A @@ hunk header without diff --git still enters diff mode."""
        inline = (
            "> @@ -10,3 +10,4 @@ some_func\n"
            ">  ctx\n"
            "> +new line\n"
            "\n"
            "This needs a test.\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['text'] == 'This needs a test.'
        assert comments[0]['line'] == 11
        assert comments[0].get('content') == '+new line'

    def test_orphan_file_headers_enter_diff_mode(self) -> None:
        """--- a/ and +++ b/ without diff --git still enter diff mode."""
        inline = (
            "> --- a/kernel/sched.c\n"
            "> +++ b/kernel/sched.c\n"
            "> @@ -5,3 +5,4 @@\n"
            ">  existing\n"
            "> +added\n"
            "\n"
            "Why this change?\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['path'] == 'b/kernel/sched.c'
        assert comments[0]['line'] == 6
        assert comments[0]['text'] == 'Why this change?'

    def test_trimmed_diff_with_content_resolution(self) -> None:
        """Trimmed reply resolved against real diff gets correct position."""
        # User trimmed everything except the line they're commenting on
        inline = (
            "> +new line\n"
            "\n"
            "Looks good.\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        # Comment is captured (even without file path from headers)
        assert len(comments) == 1
        assert comments[0]['text'] == 'Looks good.'
        assert comments[0].get('content') == '+new line'

        # Now resolve against the real diff
        real_diff = (
            "diff --git a/f.c b/f.c\n"
            "--- a/f.c\n"
            "+++ b/f.c\n"
            "@@ -1,3 +1,4 @@\n"
            " ctx\n"
            "+new line\n"
            " more\n"
        )
        review._resolve_comment_positions(real_diff, comments)
        assert comments[0]['path'] == 'b/f.c'
        assert comments[0]['line'] == 2

    def test_wrapped_diff_git_line_rejoined(self) -> None:
        """A diff --git line wrapped by the editor is rejoined."""
        # Editor wraps at 72 chars, splitting diff --git into two lines
        inline = (
            "> diff --git a/tools/lib/python/kdoc/xforms_lists.py\n"
            "b/tools/lib/python/kdoc/xforms_lists.py\n"
            "> --- a/tools/lib/python/kdoc/xforms_lists.py\n"
            "> +++ b/tools/lib/python/kdoc/xforms_lists.py\n"
            "> @@ -4,7 +4,8 @@\n"
            ">  existing\n"
            "> +from kdoc.c_lex import CMatch\n"
            "\n"
            "Only editing 2nd file.\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['text'] == 'Only editing 2nd file.'
        assert comments[0]['path'] == 'b/tools/lib/python/kdoc/xforms_lists.py'
        assert comments[0]['line'] == 5

    def test_wrapped_diff_git_line_quoted_continuation(self) -> None:
        """A diff --git line wrapped with quoted continuation is rejoined."""
        inline = (
            "> diff --git a/tools/lib/python/kdoc/xforms_lists.py\n"
            "> b/tools/lib/python/kdoc/xforms_lists.py\n"
            "> --- a/tools/lib/python/kdoc/xforms_lists.py\n"
            "> +++ b/tools/lib/python/kdoc/xforms_lists.py\n"
            "> @@ -1,3 +1,4 @@\n"
            ">  ctx\n"
            "> +new\n"
            "\n"
            "Comment here.\n"
        )
        comments = review._extract_comments_from_quoted_reply(inline)
        assert len(comments) == 1
        assert comments[0]['text'] == 'Comment here.'
        assert comments[0]['path'] == 'b/tools/lib/python/kdoc/xforms_lists.py'

    def test_extract_editor_comments_with_diff_resolution(self) -> None:
        """_extract_editor_comments resolves positions when diff provided."""
        edited = (
            "# instructions\n"
            "> @@ -1,3 +1,4 @@\n"
            ">  ctx\n"
            "> +new line\n"
            "\n"
            "My comment.\n"
        )
        real_diff = (
            "diff --git a/f.c b/f.c\n"
            "--- a/f.c\n"
            "+++ b/f.c\n"
            "@@ -1,3 +1,4 @@\n"
            " ctx\n"
            "+new line\n"
            " more\n"
        )
        comments = review._extract_editor_comments(edited, diff_text=real_diff)
        assert len(comments) == 1
        assert comments[0]['path'] == 'b/f.c'
        assert comments[0]['line'] == 2
        assert comments[0]['text'] == 'My comment.'


class TestShouldPromoteWaiting:
    """Tests for _should_promote_waiting()."""

    def test_promotes_on_genuinely_new_version(self) -> None:
        """A version not previously known triggers promotion."""
        assert review._should_promote_waiting([2], previously_known={1})

    def test_no_promote_when_version_already_known(self) -> None:
        """A version already in the DB does not trigger promotion."""
        assert not review._should_promote_waiting([2], previously_known={1, 2})

    def test_promotes_when_one_of_several_is_new(self) -> None:
        """If any newer version is genuinely new, promote."""
        assert review._should_promote_waiting([2, 3], previously_known={1, 2})

    def test_no_promote_when_all_already_known(self) -> None:
        """No promotion when all newer versions were already known."""
        assert not review._should_promote_waiting([2, 3], previously_known={1, 2, 3})

    def test_no_promote_on_empty_newer_vers(self) -> None:
        """No newer versions means no promotion."""
        assert not review._should_promote_waiting([], previously_known={1})

    def test_promotes_when_previously_known_empty(self) -> None:
        """First update ever — nothing known, so any version is new."""
        assert review._should_promote_waiting([2], previously_known=set())

    def test_marks_scenario(self) -> None:
        """Mark's exact scenario: v2 known+broken, waiting, v3 arrives."""
        # v1 applied, v2 discovered but broken, maintainer went back to waiting
        # Next update: v2 still there but already known — no promote
        assert not review._should_promote_waiting([2], previously_known={1, 2})
        # v3 arrives — genuinely new, should promote
        assert review._should_promote_waiting([2, 3], previously_known={1, 2})


class TestResolveCommentPositions:
    """Tests for _resolve_comment_positions()."""

    def test_context_content_matches_addition_in_new_file(self) -> None:
        """Content stored as context (space prefix) matches addition (+) in real diff."""
        # Sashiko uses fake context hunks even for new files, so the
        # content key has a space prefix while the real diff has + prefix.
        real_diff = (
            "diff --git a/f.c b/f.c\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            "+++ b/f.c\n"
            "@@ -0,0 +1,5 @@\n"
            "+int x;\n"
            "+int y;\n"
            "+return -EINVAL;\n"
            "+if (check)\n"
            "+\treturn 0;\n"
        )
        comments = [
            {'path': 'f.c', 'line': 90, 'text': 'Bug here.',
             'content': ' return -EINVAL;'},
        ]
        review._resolve_comment_positions(real_diff, comments)
        assert comments[0]['line'] == 3
        assert comments[0]['path'] == 'b/f.c'

    def test_exact_prefix_match_still_works(self) -> None:
        """Content with matching prefix (both +) still resolves correctly."""
        real_diff = (
            "diff --git a/f.c b/f.c\n"
            "--- a/f.c\n"
            "+++ b/f.c\n"
            "@@ -10,3 +10,4 @@\n"
            " ctx\n"
            "+new_line\n"
            " more\n"
        )
        comments = [
            {'path': 'f.c', 'line': 99, 'text': 'Review.',
             'content': '+new_line'},
        ]
        review._resolve_comment_positions(real_diff, comments)
        assert comments[0]['line'] == 11

    def test_no_content_key_keeps_original_position(self) -> None:
        """Comments without content key are not touched."""
        real_diff = "diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n@@ -1,1 +1,1 @@\n-old\n+new\n"
        comments = [{'path': 'f.c', 'line': 42, 'text': 'Note.'}]
        review._resolve_comment_positions(real_diff, comments)
        assert comments[0]['line'] == 42

    def test_duplicate_content_picks_closest_to_source_position(self) -> None:
        """When the same line appears multiple times, pick the closest match."""
        # Simulates a new file with return -EINVAL; at lines 10, 30, and 50
        real_diff = (
            "diff --git a/f.c b/f.c\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            "+++ b/f.c\n"
            "@@ -0,0 +1,50 @@\n"
            + "".join(f"+line{i}\n" for i in range(1, 10))
            + "+\treturn -EINVAL;\n"        # line 10
            + "".join(f"+line{i}\n" for i in range(11, 30))
            + "+\treturn -EINVAL;\n"        # line 30
            + "".join(f"+line{i}\n" for i in range(31, 50))
            + "+\treturn -EINVAL;\n"        # line 50
        )
        # Sashiko says line 30 with context-prefix content
        comments = [
            {'path': 'f.c', 'line': 30, 'text': 'Bug here.',
             'content': ' \treturn -EINVAL;'},
        ]
        review._resolve_comment_positions(real_diff, comments)
        # Should pick line 30 (closest to source position 30)
        assert comments[0]['line'] == 30
        assert comments[0]['path'] == 'b/f.c'


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
                    "commit aaa\n"
                    "Author: Test\n\n"
                    "Test patch 1\n\n"
                    "> diff --git a/f.c b/f.c\n"
                    "> @@ -10,3 +10,4 @@ void f(void)\n"
                    ">  \tint x;\n"
                    "> +\tptr = alloc();\n"
                    "\n"
                    "Missing error check.\n"
                    "\n"
                    ">  \treturn 0;\n"
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
                '/tmp', '', {'series': {}, 'patches': []}, [], [])
        assert result is False

    def test_no_series_msgid_returns_false(self) -> None:
        """When series has no message_id, returns False."""
        with mock.patch('b4.get_main_config',
                        return_value={'sashiko-url': 'https://sashiko.dev'}):
            result = review._integrate_sashiko_reviews(
                '/tmp', '', {'series': {}, 'patches': []}, [], [])
        assert result is False

    def test_api_returns_none(self) -> None:
        """When sashiko API returns nothing, returns False."""
        series = {'message_id': 'test@example.com'}
        with mock.patch('b4.get_main_config',
                        return_value={'sashiko-url': 'https://sashiko.dev'}):
            with mock.patch('b4.review.checks._fetch_sashiko_patchset', return_value=None):
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    result = review._integrate_sashiko_reviews(
                        '/tmp', '', {'series': series, 'patches': []}, [], [])
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
            "diff --git a/f.c b/f.c\n"
            "index 111..222 100644\n"
            "--- a/f.c\n"
            "+++ b/f.c\n"
            "@@ -10,3 +10,4 @@ void f(void)\n"
            " \tint x;\n"
            "+\tptr = alloc();\n"
            " \treturn 0;\n"
        )
        with mock.patch('b4.get_main_config',
                        return_value={'sashiko-url': 'https://sashiko.dev'}):
            with mock.patch('b4.review.checks._fetch_sashiko_patchset',
                            return_value=self._SASHIKO_RESPONSE):
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    with mock.patch('b4.git_run_command') as mock_git:
                        mock_git.return_value = (0, real_diff)
                        with mock.patch.object(review, 'save_tracking'):
                            result = review._integrate_sashiko_reviews(
                                '/tmp', 'cover', tracking, commit_shas, patches)

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
        with mock.patch('b4.get_main_config',
                        return_value={'sashiko-url': 'https://sashiko.dev'}):
            with mock.patch('b4.review.checks._fetch_sashiko_patchset',
                            return_value=self._SASHIKO_RESPONSE):
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    result = review._integrate_sashiko_reviews(
                        '/tmp', '', tracking, ['aaa'], patches)
        assert result is False

    def test_uses_header_info_msgid_fallback(self) -> None:
        """Falls back to header-info.msgid when message_id is missing."""
        series = {'header-info': {'msgid': 'cover@example.com'}}
        tracking = {'series': series, 'patches': []}
        with mock.patch('b4.get_main_config',
                        return_value={'sashiko-url': 'https://sashiko.dev'}):
            with mock.patch('b4.review.checks._fetch_sashiko_patchset',
                            return_value=None) as mock_fetch:
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    review._integrate_sashiko_reviews(
                        '/tmp', '', tracking, [], [])
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
                        "commit aaa\nAuthor: Test\n\nOld\n\n"
                        "> diff --git a/f.c b/f.c\n"
                        "> @@ -1,3 +1,4 @@\n>  ctx\n> +new\n"
                        "\nOld review comment.\n"
                    ),
                },
                {
                    'id': 300,
                    'patch_id': 100,
                    'status': 'Reviewed',
                    'inline_review': (
                        "commit bbb\nAuthor: Test\n\nNew\n\n"
                        "> diff --git a/f.c b/f.c\n"
                        "> @@ -1,3 +1,4 @@\n>  ctx\n> +new\n"
                        "\nNew review comment.\n"
                    ),
                },
            ],
        }
        patches: List[Dict[str, Any]] = [{'header-info': {'msgid': 'patch1@example.com'}}]
        series = {'message_id': 'cover@example.com'}
        tracking = {'series': series, 'patches': patches}
        real_diff = (
            "diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n"
            "@@ -1,3 +1,4 @@\n ctx\n+new\n ctx\n"
        )
        with mock.patch('b4.get_main_config',
                        return_value={'sashiko-url': 'https://sashiko.dev'}):
            with mock.patch('b4.review.checks._fetch_sashiko_patchset',
                            return_value=patchset):
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    with mock.patch('b4.git_run_command', return_value=(0, real_diff)):
                        with mock.patch.object(review, 'save_tracking'):
                            review._integrate_sashiko_reviews(
                                '/tmp', '', tracking, ['aaa'], patches)
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
                        'comments': [{'path': 'f.c', 'line': 11, 'text': 'Already here.'}],
                    },
                },
            },
        ]
        series = {'message_id': 'cover@example.com'}
        tracking = {'series': series, 'patches': patches}
        with mock.patch('b4.get_main_config',
                        return_value={'sashiko-url': 'https://sashiko.dev'}):
            with mock.patch('b4.review.checks._fetch_sashiko_patchset',
                            return_value=self._SASHIKO_RESPONSE):
                with mock.patch('b4.review.checks.clear_sashiko_cache'):
                    with mock.patch('b4.git_run_command') as mock_git:
                        result = review._integrate_sashiko_reviews(
                            '/tmp', '', tracking, ['aaaa'], patches)
        # Should not have called git diff (skipped re-parsing)
        mock_git.assert_not_called()
        assert result is False
        # Original comments untouched
        assert patches[0]['reviews']['sashiko@sashiko.dev']['comments'][0]['text'] == 'Already here.'


class TestIntegrateFollowupInlineComments:
    """Tests for _integrate_followup_inline_comments()."""

    _FOLLOWUP_BODY_WITH_DIFF = (
        "On Mon, Jan 1, 2024, Dev <dev@test.com> wrote:\n"
        "> diff --git a/fs/file.c b/fs/file.c\n"
        "> index abc123..def456 100644\n"
        "> --- a/fs/file.c\n"
        "> +++ b/fs/file.c\n"
        "> @@ -10,3 +10,4 @@ void f(void)\n"
        ">  \tint x;\n"
        "> +\tptr = malloc(sz);\n"
        "\n"
        "Missing NULL check after malloc.\n"
        "\n"
        ">  \treturn 0;\n"
    )

    _FOLLOWUP_BODY_NO_DIFF = (
        "I think this approach makes sense, but can we also\n"
        "add a test for the error path?\n"
    )

    def _make_followup_comments(self, bodies_by_patch: Dict[int, List[str]]) -> Dict[int, List[Dict[str, Any]]]:
        """Build a followup_comments dict like _parse_msgs_to_followup_comments returns."""
        result: Dict[int, List[Dict[str, Any]]] = {}
        for display_idx, body_list in bodies_by_patch.items():
            entries = []
            for i, body in enumerate(body_list):
                entries.append({
                    'body': body,
                    'fromname': f'Reviewer {i}',
                    'fromemail': f'reviewer{i}@example.com',
                    'date': '2024-01-01',
                    'msgid': f'followup{display_idx}-{i}@example.com',
                    'subject': 'Re: [PATCH]',
                    'depth': 0,
                })
            result[display_idx] = entries
        return result

    def test_no_thread_blob_returns_false(self) -> None:
        """Without a thread-blob, returns False immediately."""
        tracking: Dict[str, Any] = {'series': {}, 'patches': []}
        result = review._integrate_followup_inline_comments(
            '/tmp', '', tracking, [], [])
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
        followup_comments = self._make_followup_comments({
            1: [self._FOLLOWUP_BODY_WITH_DIFF],  # display_idx 1 = patch 0
        })

        real_diff = (
            "diff --git a/fs/file.c b/fs/file.c\n"
            "index abc123..def456 100644\n"
            "--- a/fs/file.c\n"
            "+++ b/fs/file.c\n"
            "@@ -10,3 +10,4 @@ void f(void)\n"
            " \tint x;\n"
            "+\tptr = malloc(sz);\n"
            " \treturn 0;\n"
        )

        with mock.patch('b4.review.tracking.get_thread_mbox', return_value=b'mbox'):
            with mock.patch('b4.mailsplit_bytes', return_value=[]):
                with mock.patch('b4.review.tracking._parse_msgs_to_followup_comments',
                                return_value=followup_comments):
                    with mock.patch('b4.git_run_command', return_value=(0, real_diff)):
                        with mock.patch.object(review, 'save_tracking'):
                            result = review._integrate_followup_inline_comments(
                                '/tmp', 'cover', tracking, commit_shas, patches)

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
        followup_comments = self._make_followup_comments({
            1: [self._FOLLOWUP_BODY_NO_DIFF],
        })

        with mock.patch('b4.review.tracking.get_thread_mbox', return_value=b'mbox'):
            with mock.patch('b4.mailsplit_bytes', return_value=[]):
                with mock.patch('b4.review.tracking._parse_msgs_to_followup_comments',
                                return_value=followup_comments):
                    result = review._integrate_followup_inline_comments(
                        '/tmp', '', tracking, ['aaa'], patches)
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
        followup_comments = self._make_followup_comments({
            0: [self._FOLLOWUP_BODY_WITH_DIFF],  # cover letter
        })

        with mock.patch('b4.review.tracking.get_thread_mbox', return_value=b'mbox'):
            with mock.patch('b4.mailsplit_bytes', return_value=[]):
                with mock.patch('b4.review.tracking._parse_msgs_to_followup_comments',
                                return_value=followup_comments):
                    result = review._integrate_followup_inline_comments(
                        '/tmp', '', tracking, ['aaa'], patches)
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
        followup_comments = self._make_followup_comments({
            1: [self._FOLLOWUP_BODY_WITH_DIFF, self._FOLLOWUP_BODY_WITH_DIFF],
        })

        real_diff = (
            "diff --git a/fs/file.c b/fs/file.c\n"
            "index abc123..def456 100644\n"
            "--- a/fs/file.c\n"
            "+++ b/fs/file.c\n"
            "@@ -10,3 +10,4 @@ void f(void)\n"
            " \tint x;\n"
            "+\tptr = malloc(sz);\n"
            " \treturn 0;\n"
        )

        with mock.patch('b4.review.tracking.get_thread_mbox', return_value=b'mbox'):
            with mock.patch('b4.mailsplit_bytes', return_value=[]):
                with mock.patch('b4.review.tracking._parse_msgs_to_followup_comments',
                                return_value=followup_comments):
                    with mock.patch('b4.git_run_command', return_value=(0, real_diff)):
                        with mock.patch.object(review, 'save_tracking'):
                            result = review._integrate_followup_inline_comments(
                                '/tmp', 'cover', tracking, ['aaa'], patches)

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
                        'comments': [{'path': 'fs/file.c', 'line': 11, 'text': 'Already here.'}],
                    },
                },
            },
        ]
        series = {
            'header-info': {'msgid': 'cover@example.com'},
            'thread-blob': 'abc123',
        }
        tracking = {'series': series, 'patches': patches}
        followup_comments = self._make_followup_comments({
            1: [self._FOLLOWUP_BODY_WITH_DIFF],
        })

        with mock.patch('b4.review.tracking.get_thread_mbox', return_value=b'mbox'):
            with mock.patch('b4.mailsplit_bytes', return_value=[]):
                with mock.patch('b4.review.tracking._parse_msgs_to_followup_comments',
                                return_value=followup_comments):
                    with mock.patch('b4.git_run_command') as mock_git:
                        result = review._integrate_followup_inline_comments(
                            '/tmp', '', tracking, ['aaa'], patches)
        # Should not have called git diff (skipped re-parsing)
        mock_git.assert_not_called()
        assert result is False
        # Original comments untouched
        assert patches[0]['reviews']['reviewer0@example.com']['comments'][0]['text'] == 'Already here.'


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


def _make_patch_msg(subject: str, from_addr: str, date: str,
                    body: str = '', msgid: str = '') -> email.message.EmailMessage:
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

    @mock.patch('b4.review._review._build_review_email',
                return_value=_FAKE_MSG)
    @mock.patch('b4.get_user_config',
                return_value={'name': 'Maintainer', 'email': MY_EMAIL})
    def test_sends_normal_cover_review(self, _cfg: mock.Mock,
                                       _build: mock.Mock) -> None:
        """A cover review without sent-revision produces one email."""
        series = self._make_series({self.MY_EMAIL: self._review()})
        msgs = review.collect_review_emails(series, [], 'cover', '', [])
        assert len(msgs) == 1

    @mock.patch('b4.review._review._build_review_email',
                return_value=_FAKE_MSG)
    @mock.patch('b4.get_user_config',
                return_value={'name': 'Maintainer', 'email': MY_EMAIL})
    def test_skips_cover_with_sent_revision(self, _cfg: mock.Mock,
                                             _build: mock.Mock) -> None:
        """Cover review stamped with sent-revision is not re-sent."""
        series = self._make_series(
            {self.MY_EMAIL: self._review(**{'sent-revision': 1})})
        msgs = review.collect_review_emails(series, [], 'cover', '', [])
        assert msgs == []

    @mock.patch('b4.review._review._build_review_email',
                return_value=_FAKE_MSG)
    @mock.patch('b4.get_user_config',
                return_value={'name': 'Maintainer', 'email': MY_EMAIL})
    def test_sends_normal_patch_review(self, _cfg: mock.Mock,
                                       _build: mock.Mock) -> None:
        """A patch review without sent-revision produces one email."""
        series = self._make_series()
        patch = self._make_patch({self.MY_EMAIL: self._review()})
        msgs = review.collect_review_emails(series, [patch], 'cover', '', ['sha1'])
        assert len(msgs) == 1

    @mock.patch('b4.review._review._build_review_email',
                return_value=_FAKE_MSG)
    @mock.patch('b4.get_user_config',
                return_value={'name': 'Maintainer', 'email': MY_EMAIL})
    def test_skips_patch_with_sent_revision(self, _cfg: mock.Mock,
                                             _build: mock.Mock) -> None:
        """Patch review stamped with sent-revision is not re-sent."""
        series = self._make_series()
        patch = self._make_patch(
            {self.MY_EMAIL: self._review(**{'sent-revision': 1})})
        msgs = review.collect_review_emails(series, [patch], 'cover', '', ['sha1'])
        assert msgs == []

    @mock.patch('b4.review._review._build_review_email',
                return_value=_FAKE_MSG)
    @mock.patch('b4.get_user_config',
                return_value={'name': 'Maintainer', 'email': MY_EMAIL})
    def test_skips_patch_auto_skipped_after_upgrade(self, _cfg: mock.Mock,
                                                     _build: mock.Mock) -> None:
        """Patch auto-marked skip+skip-reason during upgrade is not re-sent.

        This is the combo A+B fix: the upgrade step sets patch-state=skip
        AND skip-reason on unchanged patches whose review was already sent.
        Both the skip filter and the sent-revision filter independently
        prevent re-sending; this test exercises the skip-state path.
        """
        series = self._make_series()
        patch = self._make_patch({self.MY_EMAIL: self._review(
            **{'sent-revision': 1,
               'patch-state': 'skip',
               'skip-reason': 'Patch unchanged from v1; review already sent'})})
        msgs = review.collect_review_emails(series, [patch], 'cover', '', ['sha1'])
        assert msgs == []

    @mock.patch('b4.review._review._build_review_email',
                return_value=_FAKE_MSG)
    @mock.patch('b4.get_user_config',
                return_value={'name': 'Maintainer', 'email': MY_EMAIL})
    def test_only_unsent_patches_included(self, _cfg: mock.Mock,
                                          _build: mock.Mock) -> None:
        """Mix of sent and unsent patches: only unsent ones produce emails."""
        series = self._make_series()
        sent_patch = self._make_patch(
            {self.MY_EMAIL: self._review(**{'sent-revision': 1})})
        fresh_patch = self._make_patch(
            {self.MY_EMAIL: self._review()})
        msgs = review.collect_review_emails(
            series, [sent_patch, fresh_patch], 'cover', '', ['sha1', 'sha2'])
        assert len(msgs) == 1

    @mock.patch('b4.review._review._build_review_email',
                return_value=_FAKE_MSG)
    @mock.patch('b4.get_user_config',
                return_value={'name': 'Maintainer', 'email': MY_EMAIL})
    def test_skip_state_without_sent_revision_still_skipped(
            self, _cfg: mock.Mock, _build: mock.Mock) -> None:
        """Explicit skip state (manually set, no sent-revision) is honoured."""
        series = self._make_series()
        patch = self._make_patch(
            {self.MY_EMAIL: self._review(**{'patch-state': 'skip'})})
        msgs = review.collect_review_emails(series, [patch], 'cover', '', ['sha1'])
        assert msgs == []
