import pytest
import os
import b4
import b4.mbox
import b4.command

from typing import Any, Dict, List


@pytest.mark.parametrize('mboxf, shazamargs, compareargs, compareout, b4cfg', [
    ('shazam-git1-just-series', [],
     ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD~4..'], 'shazam-git1-just-series-defaults', {}),
    ('shazam-git1-just-series', ['-H'],
     ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD..FETCH_HEAD'], 'shazam-git1-just-series-defaults', {}),
    ('shazam-git1-just-series', ['-M'],
     ['log', '--format=%ae%n%ce%n%s%n%b---', 'HEAD^..'], 'shazam-git1-just-series-merged', {}),
])
def test_shazam(sampledir: str, gitdir: str, mboxf: str, shazamargs: List[str], compareargs: List[str], compareout: str, b4cfg: Dict[str, Any]) -> None:
    b4.MAIN_CONFIG.update(b4cfg)
    mfile = os.path.join(sampledir, f'{mboxf}.mbox')
    cfile = os.path.join(sampledir, f'{compareout}.verify')
    assert os.path.exists(mfile)
    assert os.path.exists(cfile)
    parser = b4.command.setup_parser()
    shazamargs = ['--no-stdin', '--no-interactive', '--offline-mode', 'shazam', '-m', mfile] + shazamargs
    cmdargs = parser.parse_args(shazamargs)
    with pytest.raises(SystemExit) as e:
        b4.mbox.main(cmdargs)
        assert e.value.code == 0
    out, logstr = b4.git_run_command(None, compareargs)
    assert out == 0
    with open(cfile, 'r') as fh:
        cstr = fh.read()
    assert logstr == cstr
