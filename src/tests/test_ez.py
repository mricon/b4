import os
from typing import Any, Dict, Generator, List, Optional, Tuple
from unittest.mock import MagicMock, patch

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
    """Tests for run_rewrite_hook() and its integration with run_frf()."""

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

    def test_pre_hook_blocks_frf(self) -> None:
        """A failing pre-hook should prevent git-filter-repo from running."""
        b4.MAIN_CONFIG['prep-pre-rewrite-hook'] = 'false'
        try:
            mock_frf = MagicMock()
            with (
                patch('b4.ez.b4._run_command', return_value=(1, b'', b'hook failed\n')),
                patch('b4.ez.b4.git_get_toplevel', return_value='/tmp'),
            ):
                with pytest.raises(RuntimeError):
                    b4.ez.run_frf(mock_frf)
            # frf.run() should never have been called
            mock_frf.run.assert_not_called()
        finally:
            b4.MAIN_CONFIG.pop('prep-pre-rewrite-hook', None)

    def test_hooks_bracket_frf(self) -> None:
        """Both hooks should run around a successful git-filter-repo."""
        b4.MAIN_CONFIG['prep-pre-rewrite-hook'] = 'pre-cmd'
        b4.MAIN_CONFIG['prep-post-rewrite-hook'] = 'post-cmd'
        try:
            mock_frf = MagicMock()
            call_order: List[str] = []
            mock_frf.run.side_effect = lambda: call_order.append('frf')

            def _track_run(cmdargs: Any, **kwargs: Any) -> Tuple[int, bytes, bytes]:
                call_order.append(cmdargs[0])
                return (0, b'', b'')

            with (
                patch('b4.ez.b4._run_command', side_effect=_track_run),
                patch('b4.ez.b4.git_get_toplevel', return_value='/tmp'),
                patch('b4.ez.b4.git_get_gitdir', return_value='/tmp'),
            ):
                b4.ez.run_frf(mock_frf)

            assert call_order == ['pre-cmd', 'frf', 'post-cmd']
        finally:
            b4.MAIN_CONFIG.pop('prep-pre-rewrite-hook', None)
            b4.MAIN_CONFIG.pop('prep-post-rewrite-hook', None)
