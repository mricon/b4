import io
import logging
import os
import pathlib
from email.message import EmailMessage
from types import SimpleNamespace
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple, cast
from unittest.mock import patch

import pytest

import b4
import b4._rewrite
import b4.command
import b4.ez
import b4.mbox


def _prep_branch(gitdir: str, strategy: str) -> str:
    """Run `b4 prep -n pytest` in gitdir with the given prep-cover-strategy."""
    b4.MAIN_CONFIG.update({'prep-cover-strategy': strategy})
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
    return gitdir


@pytest.fixture(scope='function')
def prepdir(gitdir: str) -> Generator[str, None, None]:
    yield _prep_branch(gitdir, 'branch-description')


@pytest.fixture(scope='function')
def prepdir_commit(gitdir: str) -> Generator[str, None, None]:
    """Like prepdir but with prep-cover-strategy=commit, so the cover lives
    in an actual git commit (and `store_cover` exercises the rewrite path).
    """
    yield _prep_branch(gitdir, 'commit')


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
        # When the patch-id changes (here the diff is altered but the commit
        # subject is not), the trailer is dropped unless we ask for fuzzy
        # matching.
        (
            'trailers-thread-with-followups',
            None,
            (b'vivendum', b'addendum'),
            [],
            ['log', '--format=%ae%n%s%n%b---', 'HEAD~4..'],
            'trailers-thread-with-followups-no-match',
            {'shazam-am-flags': '--signoff'},
        ),
        # ...and with --fuzzy the same altered series recovers the trailer by
        # matching on the (unchanged) subject.
        (
            'trailers-thread-with-followups',
            None,
            (b'vivendum', b'addendum'),
            ['--fuzzy'],
            ['log', '--format=%ae%n%s%n%b---', 'HEAD~4..'],
            'trailers-thread-with-followups',
            {'shazam-am-flags': '--signoff'},
        ),
        # Test that we properly preserve commits with --- in them
        (
            'trailers-thread-with-followups',
            'trailers-with-tripledash',
            None,
            [],
            ['log', '--format=%ae%n%s%n%b---', 'HEAD~4..'],
            'trailers-thread-with-followups-and-tripledash',
            {},
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
        # The bundled series was committed by its original author. b4 now
        # refuses to rewrite commits committed by someone else (that would
        # misrepresent who committed them). Re-stamp the pulled commits under
        # the current identity -- exactly what happens when you build the
        # series yourself -- so the trailer updater may touch them. Authorship
        # is preserved, so the comparison below (which keys on %ae) is
        # unaffected.
        _ec, _mb = b4.git_run_command(None, ['merge-base', 'HEAD', 'master'])
        _ec2, _out2 = b4.git_run_command(
            None, ['rebase', '--no-ff', _mb.strip()], logstderr=True
        )
        assert _ec2 == 0, _out2
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
    (rewrite_commits) live in test_rewrite.py since they need a
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
# The unit tests in test_rewrite.py exercise rewrite_commits() against
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
    # through rewrite_commits() under the `commit` strategy.
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


def test_get_cover_dests_without_diffstat() -> None:
    cbody = (
        'Describe the series.\n\n'
        'To: Project List <list@example.com>\n'
        'Cc: Maintainer <maintainer@example.com>\n'
        'Signed-off-by: Test Override <test-override@example.com>\n'
        '---\nChanges in v2:\n- Update the implementation.\n'
    )

    tos, ccs, body = b4.ez.get_cover_dests(cbody)

    assert tos == [('Project List', 'list@example.com')]
    assert ccs == [('Maintainer', 'maintainer@example.com')]
    assert body == (
        'Describe the series.\n\n'
        'Signed-off-by: Test Override <test-override@example.com>\n'
        '---\nChanges in v2:\n- Update the implementation.\n'
    )


@pytest.mark.parametrize('with_diffstat', [False, True])
def test_mixin_cover_relocates_basement_without_change_id(with_diffstat: bool) -> None:
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
    if not with_diffstat:
        cbody = cbody.replace(
            ' feature.txt | 1 +\n 1 file changed, 1 insertion(+)\n', ''
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


@pytest.mark.parametrize('strategy', ['branch-description', 'commit'])
@pytest.mark.parametrize('location', ['above-cut', 'below-cut', 'both'])
def test_auto_to_cc_preserves_cover_recipients(
    gitdir: str, strategy: str, location: str, tmp_path: pathlib.Path
) -> None:
    template = tmp_path / 'cover.txt'
    template.write_text('${cover}\n---\nbase-commit: ${base_commit}\n')
    b4.MAIN_CONFIG.update(
        {
            'prep-cover-strategy': strategy,
            'prep-cover-template': str(template),
            'send-series-to': 'Project List <list@example.com>',
            'send-series-cc': 'Maintainer <maintainer@example.com>',
        }
    )
    _run_prep('-n', 'recipients')
    pathlib.Path(gitdir, 'recipient-test.txt').write_text('A series change.\n')
    ecode, out = b4.git_run_command(None, ['add', 'recipient-test.txt'])
    assert ecode == 0, out
    ecode, out = b4.git_run_command(None, ['commit', '-m', 'Add a file'])
    assert ecode == 0, out

    changelog = (
        'Changes in v2:\n- Keep recipient updates separate from the notes.\n'
        '\n---\nChanges in v1:\n- Initial version.'
    )
    recipients = (
        'To: Project List <list@example.com>\nCc: Maintainer <maintainer@example.com>\n'
    )
    cover = 'A series with recipients\n\nDescribe the series.\n\n'
    if location != 'below-cut':
        cover += recipients
    cover += 'Signed-off-by: Test Override <test-override@example.com>\n'
    cover += f'---\n{changelog}'
    if location != 'above-cut':
        cover += f'\n\n{recipients}'
    cover = cover.rstrip()
    _, tracking = b4.ez.load_cover()
    b4.ez.store_cover(cover, tracking)

    # Old b4 versions put recipients below the changelog, sometimes
    # duplicating those above it. Discover each destination once without
    # adding another copy to the cover.
    _run_prep('--auto-to-cc')
    assert b4.ez.load_cover() == (cover, tracking)
    tos, ccs, _tag, _patches = b4.ez.get_prep_branch_as_patches()
    assert tos == [('Project List', 'list@example.com')]
    assert ccs == [('Maintainer', 'maintainer@example.com')]
    branch = b4.git_get_current_branch()
    assert branch is not None
    info = b4.ez.get_info(branch)
    assert (info['needs-recipients'], info['needs-auto-to-cc']) == (False, False)

    b4.MAIN_CONFIG.update(
        {
            'send-series-to': (
                'Project List <list@example.com>, Additional List <additional@example.com>'
            ),
            'send-series-cc': (
                'Maintainer <maintainer@example.com>, Reviewer <reviewer@example.com>'
            ),
        }
    )
    _run_prep('--auto-to-cc')
    updated, updated_tracking = b4.ez.load_cover()
    if location == 'below-cut':
        expected = cover.replace(
            'Signed-off-by:',
            'To: Additional List <additional@example.com>\n'
            'Cc: Reviewer <reviewer@example.com>\nSigned-off-by:',
        )
    else:
        expected = cover.replace(
            'Cc: Maintainer',
            'To: Additional List <additional@example.com>\nCc: Maintainer',
            1,
        ).replace(
            'Signed-off-by:', 'Cc: Reviewer <reviewer@example.com>\nSigned-off-by:'
        )
    assert updated == expected
    assert updated_tracking == tracking

    pre_head = b4.git_revparse_obj('HEAD')
    _run_prep('--auto-to-cc')
    assert b4.git_revparse_obj('HEAD') == pre_head
    assert b4.ez.load_cover() == (updated, tracking)
    tos, ccs, _tag, patches = b4.ez.get_prep_branch_as_patches()
    assert sorted(tos) == [
        ('Additional List', 'additional@example.com'),
        ('Project List', 'list@example.com'),
    ]
    assert sorted(ccs) == [
        ('Maintainer', 'maintainer@example.com'),
        ('Reviewer', 'reviewer@example.com'),
    ]
    ((_commit, patch),) = patches
    body, _charset = b4.LoreMessage.get_payload(patch)
    assert body.index('base-commit:') > body.index('diff --git')
    info = b4.ez.get_info(branch)
    assert (info['needs-recipients'], info['needs-auto-to-cc']) == (False, False)


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


# ---------------------------------------------------------------------------
# Tests for interactive trailer review (b4 trailers -u -i)
# ---------------------------------------------------------------------------


def _review_sections() -> List[Tuple[str, List[Tuple[str, str]]]]:
    return [
        (
            '[PATCH 1/2] add a feature',
            [
                (
                    'Reviewed-by: Foo Bar <foo@example.com>',
                    'https://lore.kernel.org/r/msgid-1%40example.com',
                ),
                (
                    'Acked-by: Bar Foo <bar@example.com>',
                    'https://lore.kernel.org/r/msgid-2%40example.com',
                ),
            ],
        ),
        (
            '[PATCH 2/2] wire it up',
            [
                (
                    'Tested-by: Quux Dev <quux@example.com>',
                    'https://lore.kernel.org/r/msgid-3%40example.com',
                ),
            ],
        ),
    ]


def test_render_trailer_review_layout() -> None:
    """The buffer names each patch with a load-bearing "- <subject>" header and
    offers each trailer with a leading '+' plus its 'via:' source; a pristine
    buffer round-trips clean.
    """
    sections = _review_sections()
    buf = b4.ez.render_trailer_review(sections)
    text = buf.decode('utf-8')
    # Patch headers use '-' (not '#'): they scope trailers to a patch and are
    # verified on parse, not ignored as comments.
    assert '- [PATCH 1/2] add a feature' in text
    assert '- [PATCH 2/2] wire it up' in text
    # Each trailer is offered with a '+' marker and its via: source line.
    assert '  + Reviewed-by: Foo Bar <foo@example.com>' in text
    assert '    # via: https://lore.kernel.org/r/msgid-1%40example.com' in text
    # A freshly rendered buffer rejects nothing.
    assert b4.ez.parse_trailer_review(buf, sections) == set()


def test_parse_trailer_review_marks_rejections() -> None:
    """Flipping '+' to 'x' on a line marks that trailer (by position) rejected."""
    sections = _review_sections()
    text = b4.ez.render_trailer_review(sections).decode('utf-8')
    text = text.replace('  + Reviewed-by:', '  x Reviewed-by:')
    text = text.replace('  + Tested-by:', '  x Tested-by:')
    rejected = b4.ez.parse_trailer_review(text.encode('utf-8'), sections)
    assert rejected == {0, 2}


@pytest.mark.parametrize(
    'old,new',
    [
        # Editing the trailer text breaks the positional contract and aborts.
        pytest.param('Foo Bar', 'Foo Baz', id='edited-text'),
        # Adding or removing trailer lines entirely also aborts (ambiguous
        # edit).
        pytest.param(
            '  + Acked-by: Bar Foo <bar@example.com>\n', '', id='count-mismatch'
        ),
        # The patch header is load-bearing: tampering with it aborts the run.
        pytest.param(
            '- [PATCH 2/2] wire it up',
            '- [PATCH 2/2] WIRED up',
            id='edited-patch-header',
        ),
    ],
)
def test_parse_trailer_review_rejects_edits(old: str, new: str) -> None:
    sections = _review_sections()
    text = b4.ez.render_trailer_review(sections).decode('utf-8')
    assert old in text
    text = text.replace(old, new)
    with pytest.raises(ValueError):
        b4.ez.parse_trailer_review(text.encode('utf-8'), sections)


def test_parse_trailer_review_scopes_identical_trailer_per_patch() -> None:
    """An identical trailer under two patches is tracked per patch: rejecting
    the one under the first patch leaves the second patch's copy untouched.
    """
    same = 'Reviewed-by: Foo Bar <foo@example.com>'
    sections: List[Tuple[str, List[Tuple[str, str]]]] = [
        ('[PATCH 1/2] first', [(same, 'https://lore.kernel.org/r/a%40x.com')]),
        ('[PATCH 2/2] second', [(same, 'https://lore.kernel.org/r/b%40x.com')]),
    ]
    text = b4.ez.render_trailer_review(sections).decode('utf-8')
    # Reject only the first occurrence (the one under PATCH 1/2).
    text = text.replace('  + ', '  x ', 1)
    rejected = b4.ez.parse_trailer_review(text.encode('utf-8'), sections)
    assert rejected == {0}


def test_trailer_ignore_key_keys_off_provenance() -> None:
    """The ignore key is (trailer, provenance-msgid) -- no patch-id. An
    identical trailer from a different message is a different key, so a fresh
    re-send by the reviewer is offered again rather than silently suppressed.
    """
    trailer = 'Reviewed-by: Foo Bar <foo@example.com>'
    assert b4.ez._trailer_ignore_key(trailer, 'm@example.com') == (
        trailer,
        'm@example.com',
    )
    assert b4.ez._trailer_ignore_key(
        trailer, 'dead-series@example.com'
    ) != b4.ez._trailer_ignore_key(trailer, 'fresh-review@example.com')


def test_trailer_ignores_roundtrip(gitdir: str) -> None:
    """The ignore file survives a save/load cycle with identical key set."""
    keys = {
        ('Reviewed-by: Foo <foo@example.com>', 'm1@example.com'),
        ('Acked-by: Bar <bar@example.com>', 'm2@example.com'),
    }
    b4.ez.save_trailer_ignores(keys)
    assert b4.ez.load_trailer_ignores() == keys


@pytest.mark.parametrize(
    'content',
    [
        # A repo with no ignore file yet yields an empty set (not an error).
        pytest.param(None, id='missing-file'),
        # A corrupt ignore file degrades to an empty set instead of crashing.
        pytest.param('this is not json{{', id='corrupt-file'),
    ],
)
def test_trailer_ignores_unusable_file_is_empty(
    gitdir: str, content: Optional[str]
) -> None:
    if content is not None:
        path = b4.ez._trailer_ignore_path()
        assert path is not None
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(content)
    assert b4.ez.load_trailer_ignores() == set()


class _Src:
    """Stand-in for the LoreMessage a trailer was harvested from."""

    def __init__(self, msgid: str) -> None:
        self.msgid = msgid


class _Commit:
    """Stand-in for the LoreMessage of a patch in the series."""

    def __init__(self, subject: str, patchid: str) -> None:
        self.subject = subject
        self.git_patch_id = patchid


def test_interactive_trailer_review_drops_and_remembers(
    gitdir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rejecting a trailer in the editor drops it from the updates and records
    it (keyed by trailer + via msgid) for future runs.
    """
    config = b4.get_main_config()

    rev = b4.LoreTrailer(name='Reviewed-by', value='Foo Bar <foo@example.com>')
    rev.lmsg = cast(b4.LoreMessage, _Src('rev-msgid@example.com'))
    ack = b4.LoreTrailer(name='Acked-by', value='Bar Foo <bar@example.com>')
    ack.lmsg = cast(b4.LoreMessage, _Src('ack-msgid@example.com'))

    updates = {'commitA': [rev, ack]}
    commit_map = {
        'commitA': cast(b4.LoreMessage, _Commit('[PATCH 1/1] do a thing', 'patchid-A'))
    }

    def fake_edit(
        bdata: bytes, filehint: str = 'COMMIT_EDITMSG', **kwargs: Any
    ) -> bytes:
        # Maintainer rejects the Reviewed-by, keeps the Acked-by.
        text = bdata.decode('utf-8')
        text = text.replace('  + Reviewed-by:', '  x Reviewed-by:')
        return text.encode('utf-8')

    monkeypatch.setattr(b4, 'edit_in_editor', fake_edit)

    ignored: Set[Tuple[str, str]] = set()
    new_updates = b4.ez.interactive_trailer_review(updates, commit_map, config, ignored)

    # The kept Acked-by survives; the rejected Reviewed-by is gone.
    assert new_updates == {'commitA': [ack]}
    # The rejection is persisted, keyed by trailer + provenance msgid.
    key = ('Reviewed-by: Foo Bar <foo@example.com>', 'rev-msgid@example.com')
    assert key in b4.ez.load_trailer_ignores()


def test_interactive_trailer_review_same_trailer_two_patches(
    gitdir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same trailer offered on two different patches is scoped per patch:
    rejecting it under the first patch keeps it on the second, and only the
    first patch's key is remembered.
    """
    config = b4.get_main_config()

    tr_a = b4.LoreTrailer(name='Reviewed-by', value='Foo Bar <foo@example.com>')
    tr_a.lmsg = cast(b4.LoreMessage, _Src('via-a@example.com'))
    tr_b = b4.LoreTrailer(name='Reviewed-by', value='Foo Bar <foo@example.com>')
    tr_b.lmsg = cast(b4.LoreMessage, _Src('via-b@example.com'))

    updates = {'commitA': [tr_a], 'commitB': [tr_b]}
    commit_map = {
        'commitA': cast(b4.LoreMessage, _Commit('[PATCH 1/2] first', 'patchid-A')),
        'commitB': cast(b4.LoreMessage, _Commit('[PATCH 2/2] second', 'patchid-B')),
    }

    def fake_edit(
        bdata: bytes, filehint: str = 'COMMIT_EDITMSG', **kwargs: Any
    ) -> bytes:
        # Reject only the first occurrence -- the copy under PATCH 1/2.
        return bdata.decode('utf-8').replace('  + ', '  x ', 1).encode('utf-8')

    monkeypatch.setattr(b4, 'edit_in_editor', fake_edit)

    ignored: Set[Tuple[str, str]] = set()
    new_updates = b4.ez.interactive_trailer_review(updates, commit_map, config, ignored)

    # Patch 2 keeps its copy; patch 1's is gone. The two copies are
    # distinguished by their provenance message, not the patch-id.
    assert new_updates == {'commitB': [tr_b]}
    stored = b4.ez.load_trailer_ignores()
    trailer = 'Reviewed-by: Foo Bar <foo@example.com>'
    assert (trailer, 'via-a@example.com') in stored
    assert (trailer, 'via-b@example.com') not in stored


def test_trailers_interactive_reject_persists_across_runs(
    sampledir: str, prepdir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end: rejecting the lone follow-up trailer via -i keeps it off the
    commit, records it, and a later plain `-u` run honours the rejection.
    """
    b4.MAIN_CONFIG.update({'shazam-am-flags': '--signoff'})
    mfile = os.path.join(sampledir, 'trailers-thread-with-followups.mbox')
    assert os.path.exists(mfile)

    # Apply the series first (mirrors test_trailers' setup).
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

    def fake_edit(
        bdata: bytes, filehint: str = 'COMMIT_EDITMSG', **kwargs: Any
    ) -> bytes:
        # Reject the only follow-up trailer (Reviewed-by: Follow Upper).
        text = bdata.decode('utf-8')
        text = text.replace('  + Reviewed-by:', '  x Reviewed-by:')
        return text.encode('utf-8')

    monkeypatch.setattr(b4, 'edit_in_editor', fake_edit)

    # `-i` implies `-u`; run the interactive update.
    parser = b4.command.setup_parser()
    b4args = [
        '--no-stdin',
        '--no-interactive',
        '--offline-mode',
        'trailers',
        '-i',
        '-m',
        mfile,
    ]
    cmdargs = parser.parse_args(b4args)
    b4.ez.cmd_trailers(cmdargs)

    # The rejected trailer never landed on the commit.
    _ec, logstr = b4.git_run_command(None, ['log', '--format=%b', 'HEAD~4..'])
    assert 'Follow Upper' not in logstr
    # ...and it was remembered.
    assert b4.ez.load_trailer_ignores()

    # A subsequent *plain* update must keep honouring the rejection.
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

    _ec, logstr = b4.git_run_command(None, ['log', '--format=%b', 'HEAD~4..'])
    assert 'Follow Upper' not in logstr


def test_trailers_fuzzy_composes_with_interactive(
    sampledir: str, prepdir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--fuzzy` and `-i` must compose: a fuzzy (subject) match is offered in
    the interactive editor just like an exact match, and accepting it lands the
    trailer on the locally-modified commit.
    """
    b4.MAIN_CONFIG.update({'shazam-am-flags': '--signoff'})
    mfile = os.path.join(sampledir, 'trailers-thread-with-followups.mbox')
    assert os.path.exists(mfile)

    # Apply the series with the diff altered so the patch-id no longer matches
    # the posting (the subject stays the same, so only fuzzy matching recovers
    # the follow-up trailer).
    with open(mfile, 'rb') as rfh:
        contents = rfh.read()
    tfile = os.path.join(prepdir, '.git', 'modified.mbox')
    with open(tfile, 'wb') as wfh:
        wfh.write(contents.replace(b'vivendum', b'addendum'))

    parser = b4.command.setup_parser()
    b4args = [
        '--no-stdin',
        '--no-interactive',
        '--offline-mode',
        'shazam',
        '--no-add-trailers',
        '-m',
        tfile,
    ]
    cmdargs = parser.parse_args(b4args)
    with pytest.raises(SystemExit) as e:
        b4.mbox.main(cmdargs)
    assert e.value.code == 0

    seen = {'offered': False}

    def fake_edit(
        bdata: bytes, filehint: str = 'COMMIT_EDITMSG', **kwargs: Any
    ) -> bytes:
        # The fuzzy-matched Reviewed-by must be presented for review; accept it
        # by leaving the text unchanged.
        if b'Reviewed-by: Follow Upper' in bdata:
            seen['offered'] = True
        return bdata

    monkeypatch.setattr(b4, 'edit_in_editor', fake_edit)

    parser = b4.command.setup_parser()
    b4args = [
        '--no-stdin',
        '--no-interactive',
        '--offline-mode',
        'trailers',
        '-i',
        '--fuzzy',
        '-m',
        mfile,
    ]
    cmdargs = parser.parse_args(b4args)
    b4.ez.cmd_trailers(cmdargs)

    # The fuzzy match was routed through the interactive review...
    assert seen['offered']
    # ...and, having been accepted there, it landed on the commit.
    _ec, logstr = b4.git_run_command(None, ['log', '--format=%b', 'HEAD~4..'])
    assert 'Follow Upper' in logstr


# -- prep --claim / committer-email gotcha (bug f97673d) ---------------------


def _stack_empty_patches(subjects: List[str]) -> None:
    """Add empty commits on top of HEAD under the ambient git identity."""
    for subj in subjects:
        ecode, out = b4.git_run_command(
            None, ['commit', '--allow-empty', '-m', subj], logstderr=True
        )
        assert ecode == 0, f'git commit failed: {out}'


def _idents(revrange: str) -> List[Tuple[str, str]]:
    """Return [(author_email, committer_email), ...] over revrange."""
    lines = b4.git_get_command_lines(None, ['log', '--format=%ae %ce', revrange])
    out: List[Tuple[str, str]] = []
    for line in lines:
        a, c = line.split()
        out.append((a, c))
    return out


def test_is_prep_branch_diagnoses_email_change(
    prepdir_commit: str, caplog: pytest.LogCaptureFixture
) -> None:
    """After a user.email change, the missing-cover error should explain the
    real cause (committer mismatch) and point at `b4 prep --claim`."""
    _stack_empty_patches(['series patch one'])
    orig_email = b4.USER_CONFIG['email']
    assert isinstance(orig_email, str)
    # Sanity: recognized as a prep branch under the original identity.
    assert b4.ez.is_prep_branch() is True

    newcfg = {'name': 'Changed User', 'email': 'changed@example.com'}
    with patch('b4.get_user_config', return_value=newcfg):
        # No longer recognized once the committer no longer matches.
        assert b4.ez.is_prep_branch() is False
        with caplog.at_level(logging.CRITICAL, logger='b4'):
            with pytest.raises(SystemExit):
                b4.ez.is_prep_branch(mustbe=True)
    assert orig_email in caplog.text
    assert 'changed@example.com' in caplog.text
    assert 'b4 prep --claim' in caplog.text


def test_claim_restamps_committer_preserves_author(prepdir_commit: str) -> None:
    """`prep --claim` re-stamps the series committer to the current identity
    while preserving authorship, and the branch is recognized again."""
    _stack_empty_patches(['series patch one', 'series patch two'])
    orig_email = b4.USER_CONFIG['email']
    assert isinstance(orig_email, str)

    cover = b4.ez.find_cover_commit()
    assert cover is not None
    revrange = f'{cover}~1..HEAD'
    pre = _idents(revrange)
    pre_shas = b4.git_get_command_lines(None, ['rev-list', revrange])
    # Every commit currently authored AND committed by the original identity.
    assert pre and all(a == orig_email and c == orig_email for a, c in pre)

    newcfg = {'name': 'Changed User', 'email': 'changed@example.com'}
    with patch('b4.get_user_config', return_value=newcfg):
        # Branch is unrecognized under the new identity...
        assert b4.ez.is_prep_branch() is False
        parser = b4.command.setup_parser()
        cmdargs = parser.parse_args(
            ['--no-stdin', '--no-interactive', '--offline-mode', 'prep', '--claim']
        )
        b4.ez.cmd_prep(cmdargs)
        # ...and recognized again after claiming it.
        assert b4.ez.is_prep_branch() is True

    post = _idents(revrange)
    post_shas = b4.git_get_command_lines(None, ['rev-list', revrange])
    assert len(post) == len(pre)
    # Authorship is credit -> preserved. Committer is provenance -> re-stamped.
    assert all(a == orig_email for a, _c in post)
    assert all(c == 'changed@example.com' for _a, c in post)
    # The rewrite changed every commit's OID.
    assert post_shas != pre_shas
    # A backup of the pre-rewrite tip was recorded.
    cb = b4.git_get_current_branch()
    assert cb is not None
    ecode, _out = b4.git_run_command(None, ['rev-parse', f'refs/original/{cb}'])
    assert ecode == 0


def test_claim_refuses_multiple_cover_commits(
    prepdir_commit: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Two cover-letter commits on one branch is a wreck b4 won't untangle:
    both the diagnostic and `prep --claim` must hard-refuse."""
    # Plant a second magic-marker commit alongside the real cover.
    second = f'bogus second cover\n\n{b4.ez.MAGIC_MARKER}\n{{}}\n'
    ecode, out = b4.git_run_command(
        None, ['commit', '--allow-empty', '-m', second], logstderr=True
    )
    assert ecode == 0, f'git commit failed: {out}'
    assert len(b4.ez.find_cover_commits()) == 2

    newcfg = {'name': 'Changed User', 'email': 'changed@example.com'}
    with patch('b4.get_user_config', return_value=newcfg):
        with caplog.at_level(logging.CRITICAL, logger='b4'):
            parser = b4.command.setup_parser()
            cmdargs = parser.parse_args(
                ['--no-stdin', '--no-interactive', '--offline-mode', 'prep', '--claim']
            )
            with pytest.raises(SystemExit):
                b4.ez.cmd_prep(cmdargs)
    assert 'different identities' in caplog.text


def test_rewrite_series_commits_explains_thirdparty(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The cover/trailers rewrite wrapper turns the engine's third-party
    refusal into a clear message pointing at `b4 prep --claim`."""
    err = b4._rewrite.ThirdpartyCommitterError([('deadbeefcafe', 'other@example.com')])
    with patch('b4.ez.rewrite_commits', side_effect=err):
        with caplog.at_level(logging.CRITICAL, logger='b4'):
            with pytest.raises(SystemExit):
                b4.ez._rewrite_series_commits(
                    {'deadbeefcafe': 'msg'}, 'start', reflog_msg='b4: test'
                )
    assert 'other@example.com' in caplog.text
    assert 'b4 prep --claim' in caplog.text


def test_claim_branch_description_restamps_series(prepdir: str) -> None:
    """branch-description keeps no cover commit, but --claim still re-stamps
    the series patches (fork-point..HEAD) under the current identity."""
    _stack_empty_patches(['bd patch one', 'bd patch two'])
    orig_email = b4.USER_CONFIG['email']
    assert isinstance(orig_email, str)
    start = b4.ez.get_series_start()
    assert start is not None
    revrange = f'{start}..HEAD'
    pre = _idents(revrange)
    assert pre and all(c == orig_email for _a, c in pre)

    newcfg = {'name': 'Changed User', 'email': 'changed@example.com'}
    with patch('b4.get_user_config', return_value=newcfg):
        # Config-based detection still recognizes the branch under any identity...
        assert b4.ez.is_prep_branch() is True
        # ...and there is no cover *commit* to find.
        assert b4.ez.find_cover_commits() == []
        parser = b4.command.setup_parser()
        cmdargs = parser.parse_args(
            ['--no-stdin', '--no-interactive', '--offline-mode', 'prep', '--claim']
        )
        b4.ez.cmd_prep(cmdargs)

    post = _idents(revrange)
    assert len(post) == len(pre)
    # Authorship preserved; committer re-stamped to the current identity.
    assert all(a == orig_email for a, _c in post)
    assert all(c == 'changed@example.com' for _a, c in post)


def test_reroll_ignores_submodule_recurse(
    gitdir: str, add_unpopulated_submodule: Callable[..., str]
) -> None:
    """reroll()'s sent-tag worktree is one of b4's scratch worktrees too.

    Under prep-cover-strategy=commit the series is cherry-picked into a fresh
    sparse worktree whose ``checkout -f`` dies on the user's submodule.recurse
    -- and the sent tag goes with it, swallowed as "Error tagging the
    revision".
    """
    add_unpopulated_submodule(gitdir)

    b4.MAIN_CONFIG.update({'prep-cover-strategy': 'commit'})
    parser = b4.command.setup_parser()
    cmdargs = parser.parse_args(
        ['--no-stdin', '--no-interactive', '--offline-mode', 'prep', '-n', 'pytest']
    )
    b4.ez.cmd_prep(cmdargs)

    with open(os.path.join(gitdir, 'file1.txt'), 'a') as fh:
        fh.write('reroll tweak\n')
    b4.git_run_command(gitdir, ['add', 'file1.txt'])
    ecode, _ = b4.git_run_command(gitdir, ['commit', '-m', 'reroll: tweak file1'])
    assert ecode == 0

    _cover, tracking = b4.ez.load_cover(strip_comments=True)
    tagname, _rev = b4.ez.get_sent_tagname(
        tracking['series']['change-id'], b4.ez.SENT_TAG_PREFIX, 1
    )

    # Only now flip the config the bug needs, so the fixture setup above never
    # ran under recursion itself.
    b4.git_set_config(gitdir, 'submodule.recurse', 'true')

    mybranch = b4.git_get_current_branch()
    assert mybranch is not None
    b4.ez.reroll(mybranch, 'sent tag message\n', 'reroll-recurse@test.local')

    assert b4.git_revparse_tag(None, tagname), (
        f'reroll did not tag {tagname}: the scratch worktree recursed'
    )


def _run_prep(*args: str) -> None:
    """Drive `b4 prep` the way the command line would."""
    parser = b4.command.setup_parser()
    cmdargs = parser.parse_args(
        ['--no-stdin', '--no-interactive', '--offline-mode', 'prep', *args]
    )
    b4.ez.cmd_prep(cmdargs)


def _write(tmp_path: pathlib.Path, name: str, content: str) -> str:
    fpath = tmp_path / name
    fpath.write_text(content)
    return str(fpath)


def _as_stdin(bdata: bytes) -> Any:
    """A stand-in for sys.stdin that only needs to satisfy .buffer.read()."""
    return SimpleNamespace(buffer=io.BytesIO(bdata))


NEW_COVER = 'A brand new subject\n\nAnd a brand new body.'


def test_prep_cover_from_file_round_trip(
    prepdir: str, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--cover-from-file stores what --show-cover prints back."""
    fpath = _write(tmp_path, 'cover.txt', NEW_COVER + '\n')
    _run_prep('--cover-from-file', fpath)

    _run_prep('--show-cover')
    assert capsys.readouterr().out.strip() == NEW_COVER

    # And what we printed can be fed straight back in.
    fpath = _write(tmp_path, 'again.txt', NEW_COVER + '\n')
    _run_prep('--cover-from-file', fpath)
    _run_prep('--show-cover')
    assert capsys.readouterr().out.strip() == NEW_COVER


def test_prep_cover_from_stdin(
    prepdir: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """A dash means stdin, which is the whole point of the feature."""
    with patch('sys.stdin', _as_stdin(NEW_COVER.encode() + b'\n')):
        _run_prep('--cover-from-file', '-')

    _run_prep('--show-cover')
    assert capsys.readouterr().out.strip() == NEW_COVER


def test_prep_cover_from_file_normalizes_crlf(
    prepdir: str, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """CRLF input is canonicalized, same as the editor path does."""
    fpath = _write(tmp_path, 'cover.txt', NEW_COVER.replace('\n', '\r\n') + '\r\n')
    _run_prep('--cover-from-file', fpath)

    _run_prep('--show-cover')
    out = capsys.readouterr().out
    assert '\r' not in out
    assert out.strip() == NEW_COVER


def test_prep_cover_from_file_rejects_blank(
    prepdir: str, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Nobody is watching a pipe, so a blank cover is a failure, not a no-op.

    (--edit-cover treats it as "user changed their mind", which is right for
    a human who quit the editor and wrong for a generator that produced
    nothing.)
    """
    before, _tracking = b4.ez.load_cover()
    fpath = _write(tmp_path, 'blank.txt', '\n   \n')
    with pytest.raises(SystemExit) as ex:
        _run_prep('--cover-from-file', fpath)
    assert ex.value.code == 1

    after, _tracking = b4.ez.load_cover()
    assert after == before


def test_prep_cover_from_file_missing_file_is_fatal(
    prepdir: str, tmp_path: pathlib.Path
) -> None:
    with pytest.raises(SystemExit) as ex:
        _run_prep('--cover-from-file', str(tmp_path / 'does-not-exist.txt'))
    assert ex.value.code == 1


def test_prep_cover_from_file_unchanged_skips_rewrite(
    prepdir_commit: str, tmp_path: pathlib.Path
) -> None:
    """Identical content must not churn the tracking commit.

    Under the `commit` strategy, storing the cover rewrites the whole
    series, so a no-op write is expensive as well as pointless.
    """
    cover, _tracking = b4.ez.load_cover()
    pre_head = b4.git_revparse_obj('HEAD')

    fpath = _write(tmp_path, 'same.txt', cover + '\n')
    _run_prep('--cover-from-file', fpath)

    assert b4.git_revparse_obj('HEAD') == pre_head


def test_prep_cover_from_file_refuses_non_prep_branch(
    gitdir: str, tmp_path: pathlib.Path
) -> None:
    fpath = _write(tmp_path, 'cover.txt', NEW_COVER)
    with pytest.raises(SystemExit) as ex:
        _run_prep('--cover-from-file', fpath)
    assert ex.value.code == 1


def test_prep_deps_from_file_round_trip(
    prepdir: str,
    tmp_path: pathlib.Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Comments and blanks are dropped; unknown entries warn but are kept."""
    deps = (
        '# this is a comment\n'
        '\n'
        'change-id: some-change-id:v2\n'
        '  base-commit: abcdef1234  \n'
        'bogus: entry\n'
    )
    fpath = _write(tmp_path, 'deps.txt', deps)
    with caplog.at_level(logging.WARNING):
        _run_prep('--deps-from-file', fpath)
    assert 'Unrecognized entry: bogus: entry' in caplog.text

    _run_prep('--show-deps')
    # No DEPS_HELP banner in the output: it must be pipe-able back in.
    assert capsys.readouterr().out == (
        'change-id: some-change-id:v2\nbase-commit: abcdef1234\nbogus: entry\n'
    )

    _cover, tracking = b4.ez.load_cover()
    assert tracking['series']['prerequisites'] == [
        'change-id: some-change-id:v2',
        'base-commit: abcdef1234',
        'bogus: entry',
    ]


def test_prep_deps_from_stdin_blank_clears(
    prepdir: str, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Blank deps input clears the list, matching --edit-deps semantics.

    This is the one place blank input is meaningful, and it's the only way
    to drop all dependencies without an editor.
    """
    fpath = _write(tmp_path, 'deps.txt', 'change-id: some-change-id:v2\n')
    _run_prep('--deps-from-file', fpath)
    _cover, tracking = b4.ez.load_cover()
    assert tracking['series']['prerequisites']

    with patch('sys.stdin', _as_stdin(b'\n# only a comment\n')):
        _run_prep('--deps-from-file', '-')

    _cover, tracking = b4.ez.load_cover()
    assert tracking['series']['prerequisites'] == []
    _run_prep('--show-deps')
    assert capsys.readouterr().out == ''


def test_prep_cover_and_deps_flags_are_mutually_exclusive() -> None:
    parser = b4.command.setup_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(['prep', '--edit-cover', '--cover-from-file', '-'])
    with pytest.raises(SystemExit):
        parser.parse_args(['prep', '--show-deps', '--deps-from-file', '-'])
