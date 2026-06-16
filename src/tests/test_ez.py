import os
from email.message import EmailMessage
from typing import Any, Dict, Generator, List, Optional, Tuple
from unittest.mock import patch

import pytest

import b4
import b4.command
import b4.ez
import b4.mbox


@pytest.fixture(scope='function')
def prepdir(gitdir: str) -> Generator[str, None, None]:
    b4.MAIN_CONFIG.update({'prep-cover-strategy': 'branch-description'})
    parser = b4.command.setup_parser()
    b4args = [
        '--no-stdin',
        '--no-interactive',
        '--offline-mode',
        'prep',
        '-n',
        'pytest',
    ]
    cmdargs = parser.parse_args(b4args)
    b4.ez.cmd_prep(cmdargs)
    yield gitdir


@pytest.fixture(scope='function')
def prepdir_commit(gitdir: str) -> Generator[str, None, None]:
    """Like prepdir but with prep-cover-strategy=commit, so the cover lives
    in an actual git commit (and `store_cover` exercises the rewrite path).
    """
    b4.MAIN_CONFIG.update({'prep-cover-strategy': 'commit'})
    parser = b4.command.setup_parser()
    b4args = [
        '--no-stdin',
        '--no-interactive',
        '--offline-mode',
        'prep',
        '-n',
        'pytest',
    ]
    cmdargs = parser.parse_args(b4args)
    b4.ez.cmd_prep(cmdargs)
    yield gitdir


@pytest.mark.parametrize(
    'mboxf, bundlef, rep, trargs, compareargs, compareout, b4cfg',
    [
        (
            'trailers-thread-with-followups',
            None,
            None,
            [],
            ['log', '--format=%ae%n%s%n%b---', 'HEAD~4..'],
            'trailers-thread-with-followups',
            {'shazam-am-flags': '--signoff'},
        ),
        (
            'trailers-thread-with-cover-followup',
            None,
            None,
            [],
            ['log', '--format=%ae%n%s%n%b---', 'HEAD~4..'],
            'trailers-thread-with-cover-followup',
            {'shazam-am-flags': '--signoff'},
        ),
        # Test matching trailer updates by subject when patch-id changes
        (
            'trailers-thread-with-followups',
            None,
            (b'vivendum', b'addendum'),
            [],
            ['log', '--format=%ae%n%s%n%b---', 'HEAD~4..'],
            'trailers-thread-with-followups-no-match',
            {'shazam-am-flags': '--signoff'},
        ),
        # Test that we properly perserve commits with --- in them
        (
            'trailers-thread-with-followups',
            'trailers-with-tripledash',
            None,
            [],
            ['log', '--format=%ae%n%s%n%b---', 'HEAD~4..'],
            'trailers-thread-with-followups-and-tripledash',
            None,
        ),
    ],
)
def test_trailers(
    sampledir: str,
    prepdir: str,
    mboxf: str,
    bundlef: Optional[str],
    rep: Optional[Tuple[bytes, bytes]],
    trargs: List[str],
    compareargs: List[str],
    compareout: str,
    b4cfg: Dict[str, Any],
) -> None:
    if b4cfg:
        b4.MAIN_CONFIG.update(b4cfg)
    config = b4.get_main_config()
    mfile = os.path.join(sampledir, f'{mboxf}.mbox')
    assert os.path.exists(mfile)
    if bundlef:
        bfile = os.path.join(sampledir, f'{bundlef}.bundle')
        assert os.path.exists(bfile)
        gitargs = ['pull', '--rebase', bfile]
        out, logstr = b4.git_run_command(None, gitargs)
        assert out == 0
    else:
        assert config.get('shazam-am-flags') == '--signoff'
        if rep:
            with open(mfile, 'rb') as fh:
                contents = fh.read()
            contents = contents.replace(rep[0], rep[1])
            tfile = os.path.join(prepdir, '.git', 'modified.mbox')
            with open(tfile, 'wb') as fh:
                fh.write(contents)
        else:
            tfile = mfile
        b4args = [
            '--no-stdin',
            '--no-interactive',
            '--offline-mode',
            'shazam',
            '--no-add-trailers',
            '-m',
            tfile,
        ]
        parser = b4.command.setup_parser()

        cmdargs = parser.parse_args(b4args)
        with pytest.raises(SystemExit) as e:
            b4.mbox.main(cmdargs)
            assert e.value.code == 0

    cfile = os.path.join(sampledir, f'{compareout}.verify')
    assert os.path.exists(cfile)

    parser = b4.command.setup_parser()
    b4args = [
        '--no-stdin',
        '--no-interactive',
        '--offline-mode',
        'trailers',
        '--update',
        '-m',
        mfile,
    ] + trargs
    cmdargs = parser.parse_args(b4args)
    b4.ez.cmd_trailers(cmdargs)

    out, logstr = b4.git_run_command(None, compareargs)
    assert out == 0
    with open(cfile, 'r') as fh:
        cstr = fh.read()
    assert logstr == cstr


# ---------------------------------------------------------------------------
# Tests for pre/post-rewrite hooks
# ---------------------------------------------------------------------------


class TestRunRewriteHook:
    """Tests for run_rewrite_hook().

    Tests that exercise hook integration with the full history-rewrite path
    (rewrite_commit_messages) live in test_rewrite.py since they need a
    real pygit2 repository fixture.
    """

    def test_no_hooks_configured(self) -> None:
        """When no hook is configured, nothing is executed."""
        with patch('b4.ez.b4._run_command') as mock_run:
            b4.ez.run_rewrite_hook('pre')
            b4.ez.run_rewrite_hook('post')
            mock_run.assert_not_called()

    def test_pre_hook_success(self) -> None:
        """A pre-hook that exits 0 should not raise."""
        b4.MAIN_CONFIG['prep-pre-rewrite-hook'] = 'true'
        try:
            with (
                patch('b4.ez.b4._run_command', return_value=(0, b'', b'')) as mock_run,
                patch('b4.ez.b4.git_get_toplevel', return_value='/tmp'),
            ):
                b4.ez.run_rewrite_hook('pre')
                mock_run.assert_called_once_with(['true'], rundir='/tmp')
        finally:
            b4.MAIN_CONFIG.pop('prep-pre-rewrite-hook', None)

    def test_pre_hook_failure_raises(self) -> None:
        """A pre-hook that exits non-zero should raise RuntimeError."""
        b4.MAIN_CONFIG['prep-pre-rewrite-hook'] = 'stg commit --all'
        try:
            with (
                patch(
                    'b4.ez.b4._run_command',
                    return_value=(1, b'', b'stg: not initialized\n'),
                ),
                patch('b4.ez.b4.git_get_toplevel', return_value='/tmp'),
            ):
                with pytest.raises(RuntimeError, match='Pre-rewrite hook'):
                    b4.ez.run_rewrite_hook('pre')
        finally:
            b4.MAIN_CONFIG.pop('prep-pre-rewrite-hook', None)

    def test_post_hook_failure_warns(self) -> None:
        """A post-hook that exits non-zero should warn, not raise."""
        b4.MAIN_CONFIG['prep-post-rewrite-hook'] = 'false'
        try:
            with (
                patch('b4.ez.b4._run_command', return_value=(1, b'', b'error\n')),
                patch('b4.ez.b4.git_get_toplevel', return_value='/tmp'),
            ):
                # Should not raise
                b4.ez.run_rewrite_hook('post')
        finally:
            b4.MAIN_CONFIG.pop('prep-post-rewrite-hook', None)


# ---------------------------------------------------------------------------
# End-to-end tests: git-notes survive history rewrites
# ---------------------------------------------------------------------------
#
# The unit tests in test_rewrite.py exercise rewrite_commit_messages() against
# synthetic bare repos. These tests drive notes through the *real* b4 entry
# points (shazam → trailers --update, and store_cover) and assert that notes
# attached pre-rewrite are reachable at the new OIDs post-rewrite.


def _add_note(commit: str, msg: str, *, ref: str = 'refs/notes/commits') -> None:
    """Attach a note to commit on the given notes ref."""
    ecode, out = b4.git_run_command(
        None,
        ['notes', f'--ref={ref}', 'add', '-m', msg, commit],
        logstderr=True,
    )
    assert ecode == 0, f'git notes add failed: {out}'


def _read_note(commit: str, *, ref: str = 'refs/notes/commits') -> str:
    """Return the note attached to commit on the given notes ref, stripped."""
    ecode, out = b4.git_run_command(
        None,
        ['notes', f'--ref={ref}', 'show', commit],
        logstderr=True,
    )
    assert ecode == 0, f'git notes show failed: {out}'
    return out.strip()


def _series_oids(depth: int = 4) -> List[str]:
    """Return the SHAs of the last *depth* commits, newest-first."""
    ecode, out = b4.git_run_command(None, ['log', '--format=%H', f'-{depth}'])
    assert ecode == 0
    oids = out.strip().split('\n')
    assert len(oids) == depth
    return oids


@pytest.mark.parametrize(
    'notes_ref',
    [
        'refs/notes/commits',
        'refs/notes/review',
    ],
)
def test_trailers_update_preserves_notes(
    sampledir: str, prepdir: str, notes_ref: str
) -> None:
    """`b4 trailers --update` must migrate refs/notes/* entries to new OIDs.

    Uses the cover-followup mbox because it adds a Reviewed-by to the cover,
    which propagates to every patch in the series — this guarantees all four
    commit OIDs change, so every note attachment is exercised by the
    migration path (not just trivially preserved by an unchanged OID).
    """
    b4.MAIN_CONFIG.update({'shazam-am-flags': '--signoff'})
    mfile = os.path.join(sampledir, 'trailers-thread-with-cover-followup.mbox')
    assert os.path.exists(mfile)

    parser = b4.command.setup_parser()
    b4args = [
        '--no-stdin',
        '--no-interactive',
        '--offline-mode',
        'shazam',
        '--no-add-trailers',
        '-m',
        mfile,
    ]
    cmdargs = parser.parse_args(b4args)
    with pytest.raises(SystemExit) as e:
        b4.mbox.main(cmdargs)
        assert e.value.code == 0

    pre_oids = _series_oids(4)
    expected_notes: Dict[int, str] = {}
    for i, oid in enumerate(pre_oids):
        msg = f'note-{i}-on-{notes_ref}'
        _add_note(oid, msg, ref=notes_ref)
        expected_notes[i] = msg
        # Sanity check the attach landed.
        assert _read_note(oid, ref=notes_ref) == msg

    parser = b4.command.setup_parser()
    b4args = [
        '--no-stdin',
        '--no-interactive',
        '--offline-mode',
        'trailers',
        '--update',
        '-m',
        mfile,
    ]
    cmdargs = parser.parse_args(b4args)
    b4.ez.cmd_trailers(cmdargs)

    post_oids = _series_oids(4)
    # The cover-followup variant rewrites every series commit; if not, the
    # test's premise (exercising migration on every position) is broken.
    assert post_oids != pre_oids
    for i, pre_oid in enumerate(pre_oids):
        assert post_oids[i] != pre_oid, f'commit at position ~{i} did not get a new OID'

    # Each positional commit's note must be retrievable at the NEW OID.
    for i, post_oid in enumerate(post_oids):
        assert _read_note(post_oid, ref=notes_ref) == expected_notes[i]

    # The pre-rewrite OIDs are still reachable through refs/original/<branch>;
    # their notes were never deleted, so they should still resolve too.
    for i, pre_oid in enumerate(pre_oids):
        assert _read_note(pre_oid, ref=notes_ref) == expected_notes[i]

    # refs/original/<branch> backup must point at the pre-rewrite tip.
    cb = b4.git_get_current_branch()
    assert cb is not None
    ecode, backup_oid = b4.git_run_command(None, ['rev-parse', f'refs/original/{cb}'])
    assert ecode == 0
    assert backup_oid.strip() == pre_oids[0]


def test_store_cover_preserves_series_notes(prepdir_commit: str) -> None:
    """`store_cover` (cover-letter edit) must migrate notes on series commits.

    The cover lives at the START of the series under the `commit` strategy,
    so editing it forces every descendant patch to be re-emitted with a new
    OID. Any notes attached to those patches must follow the new OIDs.
    """
    # prepdir_commit gave us a fresh prep branch with a single cover commit
    # at HEAD. Stack two empty patches on top so we have something to migrate.
    for subj in ('series patch one', 'series patch two'):
        ecode, out = b4.git_run_command(
            None,
            ['commit', '--allow-empty', '-m', subj],
            logstderr=True,
        )
        assert ecode == 0, f'git commit failed: {out}'

    # Layout now: HEAD = "series patch two", HEAD~1 = "series patch one",
    # HEAD~2 = cover commit.
    pre_head = _series_oids(1)[0]
    pre_patch1 = b4.git_revparse_obj('HEAD~1')
    pre_cover = b4.git_revparse_obj('HEAD~2')

    # Attach notes to BOTH series patches; the cover gets one too, on a
    # custom ref, just to prove multi-ref migration works through this path.
    _add_note(pre_head, 'note-on-tip')
    _add_note(pre_patch1, 'note-on-patch1')
    _add_note(pre_cover, 'cover-side-note', ref='refs/notes/review')

    # Drive the actual cover-letter edit path: load the current cover +
    # tracking, mutate the cover text, store it back. store_cover() routes
    # through rewrite_commit_messages() under the `commit` strategy.
    cover, tracking = b4.ez.load_cover(strip_comments=False)
    new_cover = cover + '\n\nEdited by test_store_cover_preserves_series_notes.\n'
    b4.ez.store_cover(new_cover, tracking)

    # Every commit in the series should have a new OID after the rewrite.
    post_head = _series_oids(1)[0]
    post_patch1 = b4.git_revparse_obj('HEAD~1')
    post_cover = b4.git_revparse_obj('HEAD~2')
    assert post_head != pre_head
    assert post_patch1 != pre_patch1
    assert post_cover != pre_cover

    # Notes on the series patches must be reachable on the new OIDs.
    assert _read_note(post_head) == 'note-on-tip'
    assert _read_note(post_patch1) == 'note-on-patch1'
    # Custom-ref note on the cover commit must follow its new OID too.
    assert _read_note(post_cover, ref='refs/notes/review') == 'cover-side-note'

    # The new cover commit's message reflects the edit.
    ecode, msg = b4.git_run_command(None, ['show', '-s', '--format=%B', post_cover])
    assert ecode == 0
    assert 'Edited by test_store_cover_preserves_series_notes.' in msg

    # refs/original/<branch> backup must point at the pre-rewrite tip.
    cb = b4.git_get_current_branch()
    assert cb is not None
    ecode, backup_oid = b4.git_run_command(None, ['rev-parse', f'refs/original/{cb}'])
    assert ecode == 0
    assert backup_oid.strip() == pre_head


# A minimal but realistic single-patch body: commit message, the '---'
# separator, a diffstat, and a diff. mixin_cover() folds a cover into this
# when a series has exactly one patch.
_SINGLE_PATCH_BODY = (
    'feat: add a feature\n'
    '\n'
    'This adds a feature.\n'
    '\n'
    'Signed-off-by: Test User <test@example.com>\n'
    '---\n'
    ' feature.txt | 1 +\n'
    ' 1 file changed, 1 insertion(+)\n'
    '\n'
    'diff --git a/feature.txt b/feature.txt\n'
    'new file mode 100644\n'
    'index 0000000..cc628cc\n'
    '--- /dev/null\n'
    '+++ b/feature.txt\n'
    '@@ -0,0 +1 @@\n'
    '+world\n'
)


def _make_patch_msg(body: str) -> EmailMessage:
    msg = EmailMessage()
    msg.set_payload(body, charset='utf-8')
    return msg


def test_mixin_cover_relocates_basement_without_change_id() -> None:
    """A cover whose basement omits `change-id:` must still relocate the
    basement (base-commit, prerequisites) to the very bottom of a lone patch.

    Regression: mixin_cover() used to detect the relocatable basement section
    purely by its `change-id:` line. A custom prep-cover-template that dropped
    that line (but kept base-commit) left mixin_cover unable to recognize the
    section, so base-commit was emitted as cover notes *above* the diffstat and
    the real bottom basement was truncated entirely.
    """
    patch = _make_patch_msg(_SINGLE_PATCH_BODY)
    # Rendering of a custom prep-cover-template that drops `change-id:`.
    cbody = (
        'Cover title\n'
        '\n'
        'Cover body text.\n'
        '---\n'
        'feat: add a feature\n'
        '\n'
        ' feature.txt | 1 +\n'
        ' 1 file changed, 1 insertion(+)\n'
        '---\n'
        'base-commit: 1234abcd5678\n'
    )

    b4.ez.mixin_cover(cbody, [('', patch)])
    body, _charset = b4.LoreMessage.get_payload(patch)

    # base-commit belongs in the bottom basement, after the diff -- not
    # injected as cover notes above the diffstat.
    assert body.count('base-commit:') == 1
    assert body.index('base-commit:') > body.index('diff --git')


def test_mixin_cover_relocates_basement_with_change_id() -> None:
    """The default-template path (basement keyed by change-id) keeps working:
    both base-commit and change-id land in the bottom basement after the diff.
    """
    patch = _make_patch_msg(_SINGLE_PATCH_BODY)
    cbody = (
        'Cover title\n'
        '\n'
        'Cover body text.\n'
        '---\n'
        'feat: add a feature\n'
        '\n'
        ' feature.txt | 1 +\n'
        ' 1 file changed, 1 insertion(+)\n'
        '---\n'
        'base-commit: 1234abcd5678\n'
        'change-id: 20260101-test-change-id\n'
    )

    b4.ez.mixin_cover(cbody, [('', patch)])
    body, _charset = b4.LoreMessage.get_payload(patch)

    assert body.count('base-commit:') == 1
    assert body.count('change-id:') == 1
    assert body.index('base-commit:') > body.index('diff --git')
    assert body.index('change-id:') > body.index('diff --git')


def test_mixin_cover_uses_last_basement_section() -> None:
    """When more than one section looks like a basement, the LAST one wins.

    A cover may carry an earlier trailer-shaped section (stale or quoted
    metadata) above the genuine basement. Only the final trailer section is
    the real basement and gets relocated below the diff; earlier look-alikes
    stay where the cover put them.
    """
    patch = _make_patch_msg(_SINGLE_PATCH_BODY)
    cbody = (
        'Cover title\n'
        '\n'
        'Cover body text.\n'
        '---\n'
        'base-commit: 0000stale0000\n'  # earlier look-alike -> stays put
        '---\n'
        ' feature.txt | 1 +\n'
        ' 1 file changed, 1 insertion(+)\n'
        '---\n'
        'base-commit: 1234abcd5678\n'  # genuine basement -> bottom
        'change-id: 20260101-test-change-id\n'
    )

    b4.ez.mixin_cover(cbody, [('', patch)])
    body, _charset = b4.LoreMessage.get_payload(patch)

    assert body.index('base-commit: 0000stale0000') < body.index('diff --git')
    assert body.index('base-commit: 1234abcd5678') > body.index('diff --git')
    assert body.index('change-id: 20260101-test-change-id') > body.index('diff --git')


def test_mixin_cover_keeps_notes_that_mention_trailers() -> None:
    """Prose that merely *mentions* a basement trailer must stay put.

    A cover-letter section can contain free-form text that happens to talk
    about base-commit/change-id/prerequisite-* trailers (e.g. a changelog
    noting that obsolete dependencies were dropped). The genuine basement
    comes later, so this earlier prose section is left in place rather than
    yanked below the diff.
    """
    patch = _make_patch_msg(_SINGLE_PATCH_BODY)
    # The cover body uses a '---' rule, so everything after it lands in the
    # cover "basement" and goes through section classification.
    cbody = (
        'Cover title\n'
        '\n'
        'Cover body text.\n'
        '---\n'
        'Deleted some obsolete series dependencies, so the new series no\n'
        'longer has\n'
        'prerequisite-change-id: or similar sections.\n'
        '---\n'
        'feat: add a feature\n'
        '\n'
        ' feature.txt | 1 +\n'
        ' 1 file changed, 1 insertion(+)\n'
        '---\n'
        'base-commit: 1234abcd5678\n'
        'change-id: 20260101-test-change-id\n'
    )

    b4.ez.mixin_cover(cbody, [('', patch)])
    body, _charset = b4.LoreMessage.get_payload(patch)

    # The prose -- including its "prerequisite-change-id:" mention -- stays
    # above the diff, exactly where the cover put it...
    assert body.index('Deleted some obsolete') < body.index('diff --git')
    assert body.index('prerequisite-change-id: or similar sections.') < body.index(
        'diff --git'
    )
    # ...while the genuine basement is relocated to the bottom.
    assert body.index('base-commit: 1234abcd5678') > body.index('diff --git')
    assert body.index('change-id: 20260101-test-change-id') > body.index('diff --git')


def test_mixin_cover_keeps_notes_with_midsection_trailer_line() -> None:
    """A prose section whose interior line *begins* with a trailer token
    (colon and all) still stays put, because the genuine basement is the
    later trailer section, not this one.
    """
    patch = _make_patch_msg(_SINGLE_PATCH_BODY)
    cbody = (
        'Cover title\n'
        '\n'
        'Cover body text.\n'
        '---\n'
        'Notes about this revision:\n'
        'change-id: handling was simplified in this round.\n'
        '---\n'
        ' feature.txt | 1 +\n'
        ' 1 file changed, 1 insertion(+)\n'
        '---\n'
        'base-commit: 1234abcd5678\n'
        'change-id: 20260101-test-change-id\n'
    )

    b4.ez.mixin_cover(cbody, [('', patch)])
    body, _charset = b4.LoreMessage.get_payload(patch)

    # The prose section (including its trailer-shaped line) stays above the diff.
    assert body.index('Notes about this revision') < body.index('diff --git')
    assert body.index('change-id: handling was simplified') < body.index('diff --git')
    # The genuine basement is relocated below the diff.
    assert body.index('base-commit:') > body.index('diff --git')


# A single patch whose commit message body is empty: the payload jumps straight
# from the (header-borne) subject to the '---' cutline. This is what b4 emits
# when the author leaves the commit message blank.
_EMPTY_BODY_PATCH = (
    '---\n'
    ' feature.txt | 1 +\n'
    ' 1 file changed, 1 insertion(+)\n'
    '\n'
    'diff --git a/feature.txt b/feature.txt\n'
    'new file mode 100644\n'
    'index 0000000..cc628cc\n'
    '--- /dev/null\n'
    '+++ b/feature.txt\n'
    '@@ -0,0 +1 @@\n'
    '+world\n'
)


def test_misplaced_body_flags_empty_commit_with_cover_prose() -> None:
    """The real-world case: the author left the commit message empty and wrote
    the description into the cover letter. On a single-patch series mixin_cover()
    folds that prose below the '---' cutline, where `git am` discards it. The
    empty body plus leftover prose is the high-confidence signal we warn on.
    """
    patch = _make_patch_msg(_EMPTY_BODY_PATCH)
    cbody = (
        'Cover title\n'
        '\n'
        'This is the real description that should have been the commit message.\n'
        '\n'
        'Signed-off-by: Test User <test@example.com>\n'
        '---\n'
        'base-commit: 1234abcd5678\n'
        'change-id: 20260101-test-change-id\n'
    )
    b4.ez.mixin_cover(cbody, [('', patch)])

    assert b4.ez.patch_body_is_misplaced(patch) is True


def test_misplaced_body_allows_populated_commit() -> None:
    """A commit that carries a real message body is never flagged, even after a
    cover with its own notes is mixed in.
    """
    patch = _make_patch_msg(_SINGLE_PATCH_BODY)
    cbody = (
        'Cover title\n'
        '\n'
        'Cover body text.\n'
        '---\n'
        'base-commit: 1234abcd5678\n'
        'change-id: 20260101-test-change-id\n'
    )
    b4.ez.mixin_cover(cbody, [('', patch)])

    assert b4.ez.patch_body_is_misplaced(patch) is False


def test_misplaced_body_allows_trivial_empty_commit() -> None:
    """An empty commit body with nothing below the cut but the auto-generated
    diffstat, diff, and base-commit/change-id utility must NOT be flagged -- a
    trivial one-liner patch is a legitimate workflow we don't nag about.
    """
    body = _EMPTY_BODY_PATCH + (
        '\nbase-commit: 1234abcd5678\nchange-id: 20260101-test-change-id\n'
    )
    patch = _make_patch_msg(body)

    assert b4.ez.patch_body_is_misplaced(patch) is False


def test_misplaced_body_ignores_lone_signoff_below_cut() -> None:
    """An empty commit body with only a Signed-off-by (no prose) folded below
    the cut is not a misplaced *description*, so it stays quiet.
    """
    patch = _make_patch_msg(_EMPTY_BODY_PATCH)
    cbody = (
        'Signed-off-by: Test User <test@example.com>\n'
        '---\n'
        'base-commit: 1234abcd5678\n'
        'change-id: 20260101-test-change-id\n'
    )
    b4.ez.mixin_cover(cbody, [('', patch)])

    assert b4.ez.patch_body_is_misplaced(patch) is False
