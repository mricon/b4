import argparse
import email.message
import json
from typing import Any, Dict
from unittest import mock

import pytest

import b4
from b4 import review
from b4 import review_tui
from b4.review._review import REVIEW_MAGIC_MARKER


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


class TestExtractPatchComments:
    """Tests for _extract_patch_comments()."""

    def test_no_comments(self) -> None:
        """A clean diff with no comments returns an empty list."""
        assert review._extract_patch_comments(SIMPLE_DIFF) == []

    def test_bare_comment_after_addition(self) -> None:
        """A bare line (no diff prefix) after a '+' line is a comment."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
This can return NULL.
+	ptr->field = value;
 	return 0;
"""
        comments = review._extract_patch_comments(edited)
        assert len(comments) == 1
        assert comments[0]['path'] == 'b/lib/helpers.c'
        assert comments[0]['line'] == 12
        assert comments[0]['text'] == 'This can return NULL.'

    def test_bare_comment_after_context(self) -> None:
        """A bare comment line after a context line tracks the b-side."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;
Comment on ret declaration.

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
+	ptr->field = value;
 	return 0;
"""
        comments = review._extract_patch_comments(edited)
        assert len(comments) == 1
        assert comments[0]['path'] == 'b/lib/helpers.c'
        assert comments[0]['line'] == 10

    def test_bare_comment_after_deletion(self) -> None:
        """A bare comment after a '-' line tracks the a-side."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,4 +10,3 @@ void setup_helper(struct ctx *ctx)
 	int ret;
-	old_call();
Comment on removed line.
 	return 0;
"""
        comments = review._extract_patch_comments(edited)
        assert len(comments) == 1
        assert comments[0]['path'] == 'a/lib/helpers.c'
        assert comments[0]['line'] == 11

    def test_delimited_comment(self) -> None:
        """A >>> / <<< block is collected as a single comment."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
>>>
kzalloc() can return NULL here.
Check the return value.
<<<
+	ptr->field = value;
 	return 0;
"""
        comments = review._extract_patch_comments(edited)
        assert len(comments) == 1
        assert 'kzalloc() can return NULL here.' in comments[0]['text']
        assert 'Check the return value.' in comments[0]['text']
        assert comments[0]['line'] == 12

    def test_delimited_comment_with_marker_padding(self) -> None:
        """> / < markers with blank-line padding inside do not shift positions."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
>
>>>

Check return value.

<<<
<
+	ptr->field = value;
 	return 0;
"""
        comments = review._extract_patch_comments(edited)
        assert len(comments) == 1
        assert comments[0]['line'] == 12
        assert comments[0]['text'] == 'Check return value.'

    def test_multiple_comments_same_hunk(self) -> None:
        """Multiple comments in the same hunk are all collected."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
>>>
First comment.
<<<
+	ptr->field = value;
>>>
Second comment.
<<<
 	return 0;
"""
        comments = review._extract_patch_comments(edited)
        assert len(comments) == 2
        assert comments[0]['text'] == 'First comment.'
        assert comments[0]['line'] == 12
        assert comments[1]['text'] == 'Second comment.'
        assert comments[1]['line'] == 13

    def test_comments_across_two_files(self) -> None:
        """Comments on different files are tracked separately."""
        edited = """\
diff --git a/src/a.c b/src/a.c
index 1111111..2222222 100644
--- a/src/a.c
+++ b/src/a.c
@@ -5,3 +5,4 @@ void a(void)
 	int x;
+	int y;
>>>
Comment on a.c
<<<
 	return;
diff --git a/src/b.c b/src/b.c
index 3333333..4444444 100644
--- a/src/b.c
+++ b/src/b.c
@@ -1,3 +1,4 @@ void b(void)
 	int a;
+	int b;
>>>
Comment on b.c
<<<
 	return;
"""
        comments = review._extract_patch_comments(edited)
        assert len(comments) == 2
        assert comments[0]['path'] == 'b/src/a.c'
        assert comments[0]['text'] == 'Comment on a.c'
        assert comments[1]['path'] == 'b/src/b.c'
        assert comments[1]['text'] == 'Comment on b.c'

    def test_preamble_before_diff_ignored(self) -> None:
        """Text before the first 'diff --git' line is ignored."""
        edited = """\
# Review instructions
# You may delete hunks you are not interested in.
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
        assert review._extract_patch_comments(edited) == []

    def test_delimited_only_ignores_bare_comments(self) -> None:
        """With delimited_only=True, bare lines are not comments."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
This would be a comment normally.
+	ptr->field = value;
 	return 0;
"""
        comments = review._extract_patch_comments(edited, delimited_only=True)
        assert len(comments) == 0

    def test_delimited_only_collects_delimited(self) -> None:
        """With delimited_only=True, >>> / <<< blocks are still collected."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
>>>
Delimited comment.
<<<
+	ptr->field = value;
 	return 0;
"""
        comments = review._extract_patch_comments(edited, delimited_only=True)
        assert len(comments) == 1
        assert comments[0]['text'] == 'Delimited comment.'

    def test_track_content(self) -> None:
        """With track_content=True, comments include a 'content' key."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
>>>
Check return value.
<<<
+	ptr->field = value;
 	return 0;
"""
        comments = review._extract_patch_comments(edited, track_content=True)
        assert len(comments) == 1
        assert comments[0]['content'] == '+\tptr = kzalloc(sizeof(*ptr), GFP_KERNEL);'

    def test_agent_plus_delimiters(self) -> None:
        """Agent-produced +>>> / +<<< and +comment lines are handled."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
+>>>
+Check return value.
+<<<
+	ptr->field = value;
 	return 0;
"""
        comments = review._extract_patch_comments(
            edited, delimited_only=True)
        assert len(comments) == 1
        assert comments[0]['text'] == 'Check return value.'

    def test_multiline_bare_comment(self) -> None:
        """Consecutive bare lines form a single multiline comment."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
Line one of comment.
Line two of comment.
+	ptr->field = value;
 	return 0;
"""
        comments = review._extract_patch_comments(edited)
        assert len(comments) == 1
        assert 'Line one of comment.' in comments[0]['text']
        assert 'Line two of comment.' in comments[0]['text']

    def test_deleted_hunk_does_not_break_tracking(self) -> None:
        """Removing a hunk entirely still parses the remaining one."""
        edited = """\
diff --git a/src/a.c b/src/a.c
index 1111111..2222222 100644
--- a/src/a.c
+++ b/src/a.c
@@ -5,3 +5,4 @@ void a(void)
 	int x;
+	int y;
>>>
Comment here.
<<<
 	return;
"""
        comments = review._extract_patch_comments(edited)
        assert len(comments) == 1
        assert comments[0]['path'] == 'b/src/a.c'
        assert comments[0]['text'] == 'Comment here.'

    def test_empty_delimited_block_ignored(self) -> None:
        """An empty >>> / <<< block produces no comment."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
>>>
<<<
+	ptr->field = value;
 	return 0;
"""
        comments = review._extract_patch_comments(edited)
        assert len(comments) == 0

    def test_new_file_diff(self) -> None:
        """/dev/null source is handled for new files."""
        edited = """\
diff --git a/src/new.c b/src/new.c
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/src/new.c
@@ -0,0 +1,3 @@
+#include <stdio.h>
>>>
Missing license header.
<<<
+int main(void) { return 0; }
"""
        comments = review._extract_patch_comments(edited)
        assert len(comments) == 1
        assert comments[0]['path'] == 'b/src/new.c'
        assert comments[0]['line'] == 1


    def test_agent_bare_delimiters(self) -> None:
        """Agent-produced >>> / <<< (no +) are parsed by the unified parser."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
>>>
This is the agent comment.
<<<
+	ptr->field = value;
 	return 0;
"""
        comments = review._extract_patch_comments(
            edited, delimited_only=True)
        assert len(comments) == 1
        assert comments[0]['text'] == 'This is the agent comment.'
        assert comments[0]['line'] == 12

    def test_single_gt_lt_markers(self) -> None:
        """Single > / < markers open and close a comment block."""
        edited = """\
diff --git a/lib/helpers.c b/lib/helpers.c
index abc1234..def5678 100644
--- a/lib/helpers.c
+++ b/lib/helpers.c
@@ -10,6 +10,8 @@ void setup_helper(struct ctx *ctx)
 	int ret;

+	ptr = kzalloc(sizeof(*ptr), GFP_KERNEL);
>
Check the return value.
<
+	ptr->field = value;
 	return 0;
"""
        comments = review._extract_patch_comments(edited)
        assert len(comments) == 1
        assert comments[0]['text'] == 'Check the return value.'
        assert comments[0]['line'] == 12


class TestReinsertComments:
    """Tests for _reinsert_comments()."""

    def test_no_comments_returns_diff_unchanged(self) -> None:
        result = review._reinsert_comments(SIMPLE_DIFF, [])
        assert result == SIMPLE_DIFF

    def test_comment_inserted_at_correct_position(self) -> None:
        comments = [
            {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'Check NULL.'},
        ]
        result = review._reinsert_comments(SIMPLE_DIFF, comments)
        lines = result.splitlines()
        # Find the > open marker
        idx = lines.index('>')
        assert lines[idx + 1] == '>>>'
        assert lines[idx + 2] == ''
        assert lines[idx + 3] == 'Check NULL.'
        assert lines[idx + 4] == ''
        assert lines[idx + 5] == '<<<'
        assert lines[idx + 6] == '<'
        # The line before the > marker should be the +kzalloc line
        assert 'kzalloc' in lines[idx - 1]

    def test_multiple_comments_inserted_in_order(self) -> None:
        comments = [
            {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'First.'},
            {'path': 'b/lib/helpers.c', 'line': 13, 'text': 'Second.'},
        ]
        result = review._reinsert_comments(SIMPLE_DIFF, comments)
        lines = result.splitlines()
        first_idx = lines.index('First.')
        second_idx = lines.index('Second.')
        assert first_idx < second_idx
        # Both comments use the > / >>> ... <<< / < format
        assert '>' in lines
        assert '>>>' in lines
        assert '<<<' in lines
        assert '<' in lines

    def test_comments_across_files(self) -> None:
        comments = [
            {'path': 'b/src/a.c', 'line': 6, 'text': 'Comment A.'},
            {'path': 'b/src/b.c', 'line': 2, 'text': 'Comment B.'},
        ]
        result = review._reinsert_comments(TWO_FILE_DIFF, comments)
        assert 'Comment A.' in result
        assert 'Comment B.' in result


class TestRoundTrip:
    """Verify that extract(reinsert(comments)) reproduces the same comments."""

    def test_single_comment_round_trip(self) -> None:
        comments = [
            {'path': 'b/lib/helpers.c', 'line': 12,
             'text': 'Check the return value.'},
        ]
        with_comments = review._reinsert_comments(SIMPLE_DIFF, comments)
        extracted = review._extract_patch_comments(with_comments)
        assert len(extracted) == 1
        assert extracted[0]['path'] == comments[0]['path']
        assert extracted[0]['line'] == comments[0]['line']
        assert extracted[0]['text'] == comments[0]['text']

    def test_multiple_comments_round_trip(self) -> None:
        comments = [
            {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'First note.'},
            {'path': 'b/lib/helpers.c', 'line': 13, 'text': 'Second note.'},
        ]
        with_comments = review._reinsert_comments(SIMPLE_DIFF, comments)
        extracted = review._extract_patch_comments(with_comments)
        assert len(extracted) == 2
        for orig, ext in zip(comments, extracted):
            assert ext['path'] == orig['path']
            assert ext['line'] == orig['line']
            assert ext['text'] == orig['text']

    def test_cross_file_round_trip(self) -> None:
        comments = [
            {'path': 'b/src/a.c', 'line': 6, 'text': 'Note on a.c'},
            {'path': 'b/src/b.c', 'line': 2, 'text': 'Note on b.c'},
        ]
        with_comments = review._reinsert_comments(TWO_FILE_DIFF, comments)
        extracted = review._extract_patch_comments(with_comments)
        assert len(extracted) == 2
        for orig, ext in zip(comments, extracted):
            assert ext['path'] == orig['path']
            assert ext['line'] == orig['line']
            assert ext['text'] == orig['text']

    def test_double_round_trip_stable(self) -> None:
        """Two consecutive round-trips produce the same positions."""
        comments = [
            {'path': 'b/lib/helpers.c', 'line': 12,
             'text': 'Check return value.'},
        ]
        # First round-trip
        rt1 = review._reinsert_comments(SIMPLE_DIFF, comments)
        ext1 = review._extract_patch_comments(rt1)
        # Second round-trip
        rt2 = review._reinsert_comments(SIMPLE_DIFF, ext1)
        ext2 = review._extract_patch_comments(rt2)
        assert len(ext1) == len(ext2) == 1
        assert ext1[0]['line'] == ext2[0]['line']
        assert ext1[0]['path'] == ext2[0]['path']
        assert ext1[0]['text'] == ext2[0]['text']

    def test_triple_round_trip_stable(self) -> None:
        """Three consecutive round-trips still produce the same positions."""
        comments = [
            {'path': 'b/lib/helpers.c', 'line': 12, 'text': 'Note A.'},
            {'path': 'b/lib/helpers.c', 'line': 13, 'text': 'Note B.'},
        ]
        prev = comments
        for _ in range(3):
            text = review._reinsert_comments(SIMPLE_DIFF, prev)
            prev = review._extract_patch_comments(text)
        assert len(prev) == 2
        for orig, ext in zip(comments, prev):
            assert ext['path'] == orig['path']
            assert ext['line'] == orig['line']
            assert ext['text'] == orig['text']

    def test_round_trip_with_multiline_comment(self) -> None:
        """Multiline comment text survives a round-trip."""
        comments = [
            {'path': 'b/lib/helpers.c', 'line': 12,
             'text': 'Line one.\nLine two.\nLine three.'},
        ]
        with_comments = review._reinsert_comments(SIMPLE_DIFF, comments)
        extracted = review._extract_patch_comments(with_comments)
        assert len(extracted) == 1
        assert extracted[0]['text'] == comments[0]['text']
        assert extracted[0]['line'] == comments[0]['line']


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
        usercfg = {'email': 'user@example.com', 'name': 'User'}
        entry = review._ensure_my_review(target, usercfg)
        assert entry['name'] == 'User'
        assert target['reviews']['user@example.com'] is entry

    def test_returns_existing_and_updates_name(self) -> None:
        existing = {'name': 'Old Name', 'trailers': ['Reviewed-by: Old']}
        target = {'reviews': {'user@example.com': existing}}
        usercfg = {'email': 'user@example.com', 'name': 'New Name'}
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
        body = f'Some text.\n\nreviewed-by: test <test@example.com>\n\n-- \nsig'
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


# -- Tests for determine_review_branch() ------------------------------------

class TestDetermineReviewBranch:
    """Tests for determine_review_branch()."""

    def test_uses_change_id(self) -> None:
        lser = mock.Mock()
        lser.change_id = 'my-change-id-123'
        cmdargs = argparse.Namespace()
        result = review.determine_review_branch(lser, cmdargs)
        assert result == 'b4/review/my-change-id-123'

    def test_generates_fallback_without_change_id(self) -> None:
        lser = mock.Mock()
        lser.change_id = None
        lser.get_slug.return_value = 'test-series'
        cmdargs = argparse.Namespace()
        result = review.determine_review_branch(lser, cmdargs)
        assert result.startswith('b4/review/')
        # Should contain date, slug, and hex
        parts = result[len('b4/review/'):].split('-')
        # First part is YYYYMMDD date
        assert len(parts[0]) == 8
        assert parts[0].isdigit()
        # Slug is in the middle
        assert 'test' in result
        assert 'series' in result


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
        self, body: str, followup_trailers: list,
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
    def _make_tracking_json(followups=None, patches=None) -> str:
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
