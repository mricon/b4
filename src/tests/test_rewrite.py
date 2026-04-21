# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
"""Tests for b4._rewrite.rewrite_commit_messages() and notes migration."""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, List, Optional, Tuple, Union, cast
from unittest.mock import patch

import pygit2
import pytest

import b4
import b4._rewrite


def _commit(repo: pygit2.Repository, oid: Union[pygit2.Oid, str]) -> pygit2.Commit:
    """Helper: look up a commit and return it typed as Commit for mypy."""
    return cast(pygit2.Commit, repo[oid])


SIG = pygit2.Signature('Test Author', 'test@example.com', 1700000000, 0)
BRANCH = 'refs/heads/master'


# -- Fixtures ----------------------------------------------------------------


@pytest.fixture()
def bare_repo(tmp_path: Path) -> pygit2.Repository:
    """A bare repo with HEAD symbolically pointing at refs/heads/master.

    ``core.logAllRefUpdates = always`` is enabled so ref updates write
    reflog entries, matching the default behavior of non-bare user repos
    where b4 is actually run.
    """
    repo_dir = tmp_path / 'repo'
    pygit2.init_repository(str(repo_dir), bare=True)
    repo = pygit2.Repository(str(repo_dir))
    repo.config['core.logAllRefUpdates'] = 'always'
    return repo


def _mkcommit(
    repo: pygit2.Repository,
    message: str,
    parent_oid: Optional[pygit2.Oid] = None,
    file_content: bytes = b'hello\n',
) -> pygit2.Oid:
    """Create a one-file commit and return its OID.

    Tree is a single blob at path ``file``; callers override ``file_content``
    when they want different trees across a chain.
    """
    blob_oid = repo.create_blob(file_content)
    tb = repo.TreeBuilder()
    tb.insert('file', blob_oid, pygit2.GIT_FILEMODE_BLOB)
    tree_oid = tb.write()
    parents = [parent_oid] if parent_oid is not None else []
    return repo.create_commit(None, SIG, SIG, message, tree_oid, parents)


def _seed(repo: pygit2.Repository, messages: List[str]) -> List[pygit2.Oid]:
    """Seed a linear chain of commits with distinct trees; return OIDs."""
    oids: List[pygit2.Oid] = []
    parent: Optional[pygit2.Oid] = None
    for i, msg in enumerate(messages):
        oid = _mkcommit(repo, msg, parent_oid=parent, file_content=f'v{i}\n'.encode())
        oids.append(oid)
        parent = oid
    repo.references.create(BRANCH, oids[-1])
    repo.references['HEAD'].set_target(BRANCH) if 'HEAD' in repo.references else None
    # A fresh bare repo already has HEAD -> refs/heads/master symbolically;
    # creating refs/heads/master above makes it resolvable.
    return oids


def _patch_gitdir(repo: pygit2.Repository) -> AbstractContextManager[Any]:
    """Patch b4.git_get_gitdir to return this repo's path."""
    return patch('b4.git_get_gitdir', return_value=repo.path.rstrip('/'))


# -- rewrite_commit_messages core tests --------------------------------------


class TestRewriteCore:
    def test_empty_edit_map_shortcircuits(self, bare_repo: pygit2.Repository) -> None:
        oids = _seed(bare_repo, ['a\n', 'b\n', 'c\n'])
        tip_before = bare_repo.references[BRANCH].target
        with _patch_gitdir(bare_repo), patch('b4.ez.run_rewrite_hook') as mock_hook:
            result = b4._rewrite.rewrite_commit_messages(
                edit_map={},
                start=str(oids[0]),
                end='HEAD',
            )
        assert result == {}
        assert bare_repo.references[BRANCH].target == tip_before
        mock_hook.assert_not_called()

    def test_rewrite_single_commit_preserves_tree_and_sigs(
        self, bare_repo: pygit2.Repository
    ) -> None:
        oids = _seed(bare_repo, ['a\n', 'b\n', 'c\n'])
        middle_hex = str(oids[1])
        with _patch_gitdir(bare_repo), patch('b4.ez.run_rewrite_hook'):
            result = b4._rewrite.rewrite_commit_messages(
                edit_map={middle_hex: 'b (edited)\n'},
                start=str(oids[0]),
                end='HEAD',
            )
        new_middle = _commit(bare_repo, result[middle_hex])
        old_middle = _commit(bare_repo, oids[1])
        assert new_middle.tree_id == old_middle.tree_id
        assert new_middle.author.name == old_middle.author.name
        assert new_middle.author.email == old_middle.author.email
        assert new_middle.author.time == old_middle.author.time
        assert new_middle.committer.name == old_middle.committer.name
        assert new_middle.committer.email == old_middle.committer.email
        assert new_middle.committer.time == old_middle.committer.time
        assert new_middle.message == 'b (edited)\n'

    def test_rewrite_descendants_reparented(self, bare_repo: pygit2.Repository) -> None:
        oids = _seed(bare_repo, ['a\n', 'b\n', 'c\n', 'd\n'])
        second_hex = str(oids[1])
        with _patch_gitdir(bare_repo), patch('b4.ez.run_rewrite_hook'):
            result = b4._rewrite.rewrite_commit_messages(
                edit_map={second_hex: 'b!\n'},
                start=str(oids[0]),
                end='HEAD',
            )
        # Every commit after the first should have been re-emitted.
        for old in oids[1:]:
            assert str(old) in result
        # Chain should be walk-able from the new tip.
        new_tip = _commit(bare_repo, result[str(oids[3])])
        assert str(new_tip.parents[0].id) == result[str(oids[2])]
        assert str(new_tip.parents[0].parents[0].id) == result[str(oids[1])]

    def test_branch_backup_created(self, bare_repo: pygit2.Repository) -> None:
        oids = _seed(bare_repo, ['a\n', 'b\n'])
        pre_tip = bare_repo.references[BRANCH].target
        with _patch_gitdir(bare_repo), patch('b4.ez.run_rewrite_hook'):
            b4._rewrite.rewrite_commit_messages(
                edit_map={str(oids[1]): 'b!\n'},
                start=str(oids[0]),
                end='HEAD',
            )
        assert 'refs/original/master' in bare_repo.references
        assert bare_repo.references['refs/original/master'].target == pre_tip

    def test_reflog_entry_written(self, bare_repo: pygit2.Repository) -> None:
        oids = _seed(bare_repo, ['a\n', 'b\n'])
        reflog_msg = 'b4: custom reflog message'
        with _patch_gitdir(bare_repo), patch('b4.ez.run_rewrite_hook'):
            b4._rewrite.rewrite_commit_messages(
                edit_map={str(oids[1]): 'b!\n'},
                start=str(oids[0]),
                end='HEAD',
                reflog_msg=reflog_msg,
            )
        entries = list(bare_repo.references[BRANCH].log())
        assert any(e.message == reflog_msg for e in entries)

    def test_commit_not_in_edit_map_passes_message_through(
        self, bare_repo: pygit2.Repository
    ) -> None:
        oids = _seed(bare_repo, ['a\n', 'b\n', 'c\n'])
        with _patch_gitdir(bare_repo), patch('b4.ez.run_rewrite_hook'):
            result = b4._rewrite.rewrite_commit_messages(
                edit_map={str(oids[1]): 'b!\n'},
                start=str(oids[0]),
                end='HEAD',
            )
        # Third commit had its parent remapped but its message untouched.
        new_third = _commit(bare_repo, result[str(oids[2])])
        old_third = _commit(bare_repo, oids[2])
        assert new_third.message == old_third.message

    def test_trailing_newline_normalized(self, bare_repo: pygit2.Repository) -> None:
        oids = _seed(bare_repo, ['a\n', 'b\n'])
        with _patch_gitdir(bare_repo), patch('b4.ez.run_rewrite_hook'):
            result = b4._rewrite.rewrite_commit_messages(
                edit_map={str(oids[1]): 'no trailing newline'},
                start=str(oids[0]),
                end='HEAD',
            )
        assert (
            _commit(bare_repo, result[str(oids[1])]).message == 'no trailing newline\n'
        )


# -- Notes migration ---------------------------------------------------------


class TestNotesMigration:
    def test_notes_migrated_default_ref(self, bare_repo: pygit2.Repository) -> None:
        oids = _seed(bare_repo, ['a\n', 'b\n', 'c\n'])
        bare_repo.create_note('the note body', SIG, SIG, str(oids[1]))
        with _patch_gitdir(bare_repo), patch('b4.ez.run_rewrite_hook'):
            result = b4._rewrite.rewrite_commit_messages(
                edit_map={str(oids[1]): 'b (edited)\n'},
                start=str(oids[0]),
                end='HEAD',
            )
        new_hex = result[str(oids[1])]
        migrated = bare_repo.lookup_note(new_hex)
        assert migrated.message == 'the note body'
        # Old-OID note is still reachable (we don't delete).
        original = bare_repo.lookup_note(str(oids[1]))
        assert original.message == 'the note body'

    def test_notes_migrated_custom_ref(self, bare_repo: pygit2.Repository) -> None:
        oids = _seed(bare_repo, ['a\n', 'b\n'])
        bare_repo.create_note(
            'review note',
            SIG,
            SIG,
            str(oids[1]),
            'refs/notes/review',
        )
        with _patch_gitdir(bare_repo), patch('b4.ez.run_rewrite_hook'):
            result = b4._rewrite.rewrite_commit_messages(
                edit_map={str(oids[1]): 'b!\n'},
                start=str(oids[0]),
                end='HEAD',
            )
        new_hex = result[str(oids[1])]
        migrated = bare_repo.lookup_note(new_hex, 'refs/notes/review')
        assert migrated.message == 'review note'

    def test_notes_migrated_multiple_refs(self, bare_repo: pygit2.Repository) -> None:
        oids = _seed(bare_repo, ['a\n', 'b\n'])
        bare_repo.create_note('default', SIG, SIG, str(oids[1]))
        bare_repo.create_note(
            'review',
            SIG,
            SIG,
            str(oids[1]),
            'refs/notes/review',
        )
        with _patch_gitdir(bare_repo), patch('b4.ez.run_rewrite_hook'):
            result = b4._rewrite.rewrite_commit_messages(
                edit_map={str(oids[1]): 'b!\n'},
                start=str(oids[0]),
                end='HEAD',
            )
        new_hex = result[str(oids[1])]
        assert bare_repo.lookup_note(new_hex).message == 'default'
        assert bare_repo.lookup_note(new_hex, 'refs/notes/review').message == 'review'

    def test_no_notes_no_work(self, bare_repo: pygit2.Repository) -> None:
        oids = _seed(bare_repo, ['a\n', 'b\n'])
        # No notes created.
        with _patch_gitdir(bare_repo), patch('b4.ez.run_rewrite_hook'):
            result = b4._rewrite.rewrite_commit_messages(
                edit_map={str(oids[1]): 'b!\n'},
                start=str(oids[0]),
                end='HEAD',
            )
        # Rewrite still succeeds and no refs/notes/* were created.
        new_hex = result[str(oids[1])]
        assert new_hex  # sanity
        notes_refs = [r for r in bare_repo.references if r.startswith('refs/notes/')]
        assert notes_refs == []


# -- Hook integration (moved from test_ez.py) -------------------------------


class TestHookIntegration:
    def test_pre_hook_blocks_rewrite(self, bare_repo: pygit2.Repository) -> None:
        """A failing pre-hook prevents any rewrite work from happening."""
        oids = _seed(bare_repo, ['a\n', 'b\n'])
        pre_tip = bare_repo.references[BRANCH].target
        b4.MAIN_CONFIG['prep-pre-rewrite-hook'] = 'false'
        try:
            with (
                patch('b4.ez.b4._run_command', return_value=(1, b'', b'hook failed\n')),
                patch('b4.ez.b4.git_get_toplevel', return_value='/tmp'),
                _patch_gitdir(bare_repo),
            ):
                with pytest.raises(RuntimeError, match='Pre-rewrite hook'):
                    b4._rewrite.rewrite_commit_messages(
                        edit_map={str(oids[1]): 'b!\n'},
                        start=str(oids[0]),
                        end='HEAD',
                    )
            # Branch must not have moved.
            assert bare_repo.references[BRANCH].target == pre_tip
            # No backup ref should have been created.
            assert 'refs/original/master' not in bare_repo.references
        finally:
            b4.MAIN_CONFIG.pop('prep-pre-rewrite-hook', None)

    def test_hooks_bracket_rewrite(self, bare_repo: pygit2.Repository) -> None:
        """Both hooks run around a successful rewrite, in the right order."""
        oids = _seed(bare_repo, ['a\n', 'b\n'])
        b4.MAIN_CONFIG['prep-pre-rewrite-hook'] = 'pre-cmd'
        b4.MAIN_CONFIG['prep-post-rewrite-hook'] = 'post-cmd'
        try:
            call_order: List[str] = []

            def _track_run(
                cmdargs: List[str], **kwargs: Any
            ) -> Tuple[int, bytes, bytes]:
                call_order.append(cmdargs[0])
                return (0, b'', b'')

            with (
                patch('b4.ez.b4._run_command', side_effect=_track_run),
                patch('b4.ez.b4.git_get_toplevel', return_value='/tmp'),
                _patch_gitdir(bare_repo),
            ):
                b4._rewrite.rewrite_commit_messages(
                    edit_map={str(oids[1]): 'b!\n'},
                    start=str(oids[0]),
                    end='HEAD',
                )

            # pre-cmd must run before the rewrite; post-cmd after. We don't
            # have a direct "rewrite happened" marker in call_order, but if
            # both are present in order and the branch moved, that's the
            # guarantee we care about.
            assert call_order == ['pre-cmd', 'post-cmd']
            assert bare_repo.references[BRANCH].target != oids[1]
        finally:
            b4.MAIN_CONFIG.pop('prep-pre-rewrite-hook', None)
            b4.MAIN_CONFIG.pop('prep-post-rewrite-hook', None)
