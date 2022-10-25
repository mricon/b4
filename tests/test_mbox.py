import pytest  # noqa
import os
import b4
import b4.mbox
import b4.command


def _setup_bundle(tmpdir, bundle, chdir=False):
    dest = os.path.join(tmpdir, 'bundle')
    args = ['clone', bundle, dest]
    b4.git_run_command(None, args)
    if chdir:
        os.chdir(dest)
    return dest


@pytest.mark.parametrize('bundle,mboxf,msgid', [
    ('git1', 'shazam-git1-just-series', '20221025-test1-v1-0-e4f28f57990c@linuxfoundation.org'),
])
def test_shazam(tmpdir, bundle, mboxf, msgid):
    bfile = f'tests/samples/{bundle}.bundle'
    assert os.path.exists(bfile)
    mfile = os.path.abspath(f'tests/samples/{mboxf}.mbox')
    assert os.path.exists(mfile)
    gitdir = _setup_bundle(tmpdir, bfile, chdir=True)
    parser = b4.command.setup_parser()
    cmdargs = parser.parse_args(['shazam', '-m', mfile, msgid])
    b4.can_patatt = False
    b4.can_dkim = False
    with pytest.raises(SystemExit) as e:
        b4.mbox.main(cmdargs)
        assert e.type == SystemExit
        assert e.value.code == 0
