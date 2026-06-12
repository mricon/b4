#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Tests for the editor integration files under ``misc/vim`` and ``misc/emacs``.

The vim ftplugin and the emacs major mode reimplement the *same* review-reply
behaviour twice -- hunk trimming, skip-marker coalescing and "adopt comment" --
and all of it rides on a format contract with the Python code that generates the
buffer (:func:`b4.review._review._render_quoted_diff_with_comments`).  Two
things can quietly break: the Python side could emit a line shape the plugins do
not recognise, or the two plugins could drift apart from each other.

This module guards both, in two layers:

1. **Format-contract tests** (pure Python, no editors).  They assert that a
   generated review buffer only uses the line prefixes the plugins know about,
   that the skip markers the plugins insert stay invisible to b4's parser, and
   that both plugins write the marker with one identical template.

2. **Behavioural tests** that drive the *real* vim and emacs over a shared set
   of fixtures and check both produce the expected buffer -- so the two ports
   cannot diverge.  vim is driven through keystroke replay (``-s``) with a full
   editor, because its auto-marker hangs off the ``TextChanged`` autocommand,
   which does not fire in silent-ex (``-es``) mode; emacs runs ``-batch`` with a
   generated driver script.  Each editor is skipped individually when its binary
   is not installed, so a minimal CI box still passes.
"""

import pathlib
import shutil
import subprocess
from typing import Dict, List, NamedTuple

import pytest

from b4.review._review import (
    _extract_editor_comments,
    _render_quoted_diff_with_comments,
)

# --------------------------------------------------------------------------
# Locations of the plugin files under test.
# --------------------------------------------------------------------------

_MISC = pathlib.Path(__file__).resolve().parents[2] / 'misc'
_VIM_RTP = _MISC / 'vim'
_VIM_FTPLUGIN = _VIM_RTP / 'ftplugin' / 'b4review.vim'
_EL_MODE = _MISC / 'emacs' / 'b4-review-mode.el'

# The single template both plugins use to write a skip marker.  The behavioural
# tests confirm both also *recognise* it; this constant pins the spelling.
_MARKER_TEMPLATE = '> [ ... %d lines skipped ... ]'


# --------------------------------------------------------------------------
# Layer 1: format-contract tests (no editor required).
# --------------------------------------------------------------------------

# A small diff and a review set exercising every rendered line category: an
# own (unquoted) comment and an external reviewer comment with attribution,
# a multi-line body and a "via:" provenance line.
_CONTRACT_DIFF = """\
diff --git a/f.c b/f.c
--- a/f.c
+++ b/f.c
@@ -1,3 +1,4 @@
 int x;
+int y;
 int z;
"""

_CONTRACT_REVIEWS: Dict[str, Dict[str, object]] = {
    'me@example.com': {
        'comments': [{'path': 'b/f.c', 'line': 2, 'text': 'looks good'}],
    },
    'rev@example.com': {
        'name': 'Rev Iewer',
        'provenance': 'agent-foo',
        'comments': [
            {'path': 'b/f.c', 'line': 2, 'text': 'are you sure?\nmaybe not'},
        ],
    },
}


def _contract_buffer() -> str:
    return _render_quoted_diff_with_comments(
        _CONTRACT_DIFF, _CONTRACT_REVIEWS, 'me@example.com'
    )


def test_external_comment_lines_follow_plugin_contract() -> None:
    """Every ``|`` line is ``"| "``-prefixed or bare ``"|"``.

    The plugins' "adopt comment" and highlighting both key off exactly this
    shape, including a ``| Name <addr>:`` header and a ``| via:`` line.
    """
    buf = _contract_buffer()
    pipe_lines = [ln for ln in buf.splitlines() if ln.startswith('|')]
    assert pipe_lines, 'expected the external review to render | lines'
    for ln in pipe_lines:
        assert ln == '|' or ln.startswith('| '), f'bad external line: {ln!r}'
    # The attribution header and provenance lines the adopt command drops.
    assert any(ln.endswith('>:') for ln in pipe_lines), 'no attribution header'
    assert any(ln.startswith('| via: ') for ln in pipe_lines), 'no via: line'


def test_quoted_and_instruction_prefixes() -> None:
    """Quoted lines are ``"> "`` or bare ``">"``; instructions start with ``#``."""
    buf = _contract_buffer()
    for ln in buf.splitlines():
        if ln.startswith('>'):
            assert ln == '>' or ln.startswith('> '), f'bad quoted line: {ln!r}'
        if ln.startswith('#'):
            # Instruction lines are a comment to the reader, never "# " only.
            assert ln.startswith('#')


def test_skip_markers_are_inert_to_parser() -> None:
    """A plugin-inserted skip marker is quoted, so b4's parser ignores it.

    The marker is a reading aid the plugins drop into the ``> ``-quoted diff;
    it must never come back out as one of the reviewer's own comments.
    """
    buf = _contract_buffer()
    # Splice a marker in among the quoted diff, as the plugins would.
    lines = buf.splitlines()
    spliced = []
    for ln in lines:
        spliced.append(ln)
        if ln == '> +int y;':
            spliced.append(_MARKER_TEMPLATE % 7)
    comments = _extract_editor_comments('\n'.join(spliced) + '\n')
    texts = [c['text'] for c in comments]
    assert any('looks good' in t for t in texts), 'own comment should survive'
    assert not any('lines skipped' in t for t in texts), 'marker leaked into a comment'


def test_skip_marker_template_consistent_across_plugins() -> None:
    """Both plugins write the marker with the one identical template."""
    vim_src = _VIM_FTPLUGIN.read_text()
    el_src = _EL_MODE.read_text()
    assert _MARKER_TEMPLATE in vim_src, 'vim ftplugin lost the marker template'
    assert _MARKER_TEMPLATE in el_src, 'emacs mode lost the marker template'


# --------------------------------------------------------------------------
# Layer 2: behavioural tests driving the real editors.
# --------------------------------------------------------------------------

_VIM = shutil.which('vim')
_EMACS = shutil.which('emacs')

# Logical operation -> how to perform it in each editor.  vim ops are appended
# with ":wq\r" by the driver; the command ops are ex commands, "delete3" is the
# raw normal-mode keystrokes for a three-line delete (exercising the auto
# marker, which only fires through the real normal-mode loop).
_VIM_KEYS: Dict[str, str] = {
    'adopt': ':B4Adopt\r',
    'delhunk': ':B4DelHunk\r',
    'delbefore': ':B4DelHunksBefore\r',
    'delete3': '3dd',
}
_EL_OPS: Dict[str, str] = {
    'adopt': '(b4-review-adopt-comment)',
    'delhunk': '(b4-review-delete-hunk)',
    'delbefore': '(b4-review-delete-hunks-before)',
    'delete3': (
        '(let ((b (line-beginning-position)))'
        ' (forward-line 3) (delete-region b (point)))'
    ),
}


class Case(NamedTuple):
    cid: str
    text: str
    line: int  # 1-based line to place the cursor on before the op
    op: str
    auto: bool  # enable the opt-in auto-marker (only meaningful for delete3)
    expected: str


def _norm(text: str) -> str:
    """Collapse trailing blank lines to a single newline.

    vim leaves one extra empty line when a delete reduces the buffer entirely
    to a marker (an emptied buffer still holds vim's mandatory single line);
    emacs does not.  The reply format treats trailing blanks as insignificant
    -- b4 strips them on send -- so the comparison ignores them rather than
    baking a cosmetic quirk into the expected output.
    """
    return text.rstrip('\n') + '\n' if text.strip() else ''


_ADOPT = """\
> @@ -1,3 +1,3 @@
> -old line
> +new line
| Reviewer Name <rev@example.com>:
|
| This looks wrong to me.
| Second line.
|
| via: agent-foo
"""

_DELHUNK = """\
> diff --git a/f b/f
> --- a/f
> +++ b/f
> @@ -1,2 +1,2 @@
> -a
> +b
> ctx
"""

# A hunk whose last quoted line is already a skip marker: trimming the hunk
# must fold the marker's 5 into the 3 newly removed quoted lines -> 8.
_COALESCE = """\
> @@ -1,2 +1,2 @@
> -a
> +b
> [ ... 5 lines skipped ... ]
"""

_TWOHUNK = """\
> diff --git a/f b/f
> --- a/f
> +++ b/f
> @@ -1,2 +1,2 @@
> -a
> +b
> @@ -10,2 +10,2 @@
> -c
> +d
"""

_AUTO = """\
> @@ -1,4 +1,4 @@
> -a
> -b
> -c
> +d
"""

CASES: List[Case] = [
    # Adopt strips "| ", drops the attribution + via lines, trims the blank
    # "|" lines around the body.
    Case(
        cid='adopt',
        text=_ADOPT,
        line=6,
        op='adopt',
        auto=False,
        expected=(
            '> @@ -1,3 +1,3 @@\n> -old line\n> +new line\n'
            'This looks wrong to me.\nSecond line.\n'
        ),
    ),
    # Adopt on a quoted "> " line is a no-op (not on a | comment).
    Case(
        cid='adopt-noop',
        text=_TWOHUNK,
        line=5,
        op='adopt',
        auto=False,
        expected=_norm(_TWOHUNK),
    ),
    # Delete the hunk under the cursor: header + 3 quoted lines -> one marker.
    Case(
        cid='delhunk',
        text=_DELHUNK,
        line=5,
        op='delhunk',
        auto=False,
        expected=(
            '> diff --git a/f b/f\n> --- a/f\n> +++ b/f\n'
            '> [ ... 4 lines skipped ... ]\n'
        ),
    ),
    # Adjacent markers coalesce: 3 trimmed + the existing 5 -> 8.
    Case(
        cid='coalesce',
        text=_COALESCE,
        line=2,
        op='delhunk',
        auto=False,
        expected='> [ ... 8 lines skipped ... ]\n',
    ),
    # Trim the hunk(s) above the current one; the file header is preserved and
    # the second hunk is left intact.
    Case(
        cid='delbefore',
        text=_TWOHUNK,
        line=8,
        op='delbefore',
        auto=False,
        expected=(
            '> diff --git a/f b/f\n> --- a/f\n> +++ b/f\n'
            '> [ ... 3 lines skipped ... ]\n'
            '> @@ -10,2 +10,2 @@\n> -c\n> +d\n'
        ),
    ),
    # Opt-in auto-marker: a plain 3-line delete of quoted lines leaves a marker
    # counting only the quoted (>) lines removed.
    Case(
        cid='auto-marker',
        text=_AUTO,
        line=2,
        op='delete3',
        auto=True,
        expected='> @@ -1,4 +1,4 @@\n> [ ... 3 lines skipped ... ]\n> +d\n',
    ),
]

_CASE_IDS = [c.cid for c in CASES]


def _run_vim(tmp_path: pathlib.Path, case: Case) -> str:
    target = tmp_path / 't.b4-review.eml'
    keys = tmp_path / 'keys'
    target.write_text(case.text)
    keys.write_text(_VIM_KEYS[case.op] + ':wq\r')
    cmd = [
        'vim',
        '-N',
        '-u',
        'NONE',
        '-T',
        'dumb',
        '--not-a-term',
        '-c',
        f'set runtimepath^={_VIM_RTP}',
    ]
    if case.auto:
        cmd += ['-c', 'let g:b4review_auto_marker=1']
    cmd += [
        '-c',
        'filetype plugin on',
        '-c',
        f'edit {target}',
        '-c',
        'setlocal filetype=b4review',
        '-c',
        str(case.line),
        '-s',
        str(keys),
    ]
    subprocess.run(
        cmd,
        cwd=str(tmp_path),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    return target.read_text()


def _run_emacs(tmp_path: pathlib.Path, case: Case) -> str:
    infile = tmp_path / 'in.eml'
    outfile = tmp_path / 'out.eml'
    driver = tmp_path / 'drv.el'
    infile.write_text(case.text)
    setvar = '(setq b4-review-auto-marker t)' if case.auto else ''
    driver.write_text(
        f'(load "{_EL_MODE}" nil t)\n'
        f'{setvar}\n'
        '(with-temp-buffer\n'
        f'  (insert-file-contents "{infile}")\n'
        '  (b4-review-mode)\n'
        '  (goto-char (point-min))\n'
        f'  (forward-line {case.line - 1})\n'
        f'  {_EL_OPS[case.op]}\n'
        f'  (write-region (point-min) (point-max) "{outfile}"))\n'
    )
    subprocess.run(
        ['emacs', '-Q', '-batch', '-l', str(driver)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )
    return outfile.read_text()


@pytest.mark.skipif(not _VIM, reason='vim not installed')
@pytest.mark.parametrize('case', CASES, ids=_CASE_IDS)
def test_vim_plugin_behaviour(case: Case, tmp_path: pathlib.Path) -> None:
    assert _norm(_run_vim(tmp_path, case)) == case.expected


@pytest.mark.skipif(not _EMACS, reason='emacs not installed')
@pytest.mark.parametrize('case', CASES, ids=_CASE_IDS)
def test_emacs_plugin_behaviour(case: Case, tmp_path: pathlib.Path) -> None:
    assert _norm(_run_emacs(tmp_path, case)) == case.expected
