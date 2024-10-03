import pytest  # noqa
import os
import b4
import b4.ez
import b4.mbox
import b4.command


@pytest.fixture(scope="function")
def prepdir(gitdir):
    b4.MAIN_CONFIG.update({'prep-cover-strategy': 'branch-description'})
    parser = b4.command.setup_parser()
    b4args = ['--no-stdin', '--no-interactive', '--offline-mode', 'prep', '-n', 'pytest']
    cmdargs = parser.parse_args(b4args)
    b4.ez.cmd_prep(cmdargs)
    yield gitdir


@pytest.mark.parametrize('mboxf, bundlef, rep, trargs, compareargs, compareout, b4cfg', [
    ('trailers-thread-with-followups', None, None, [],
     ['log', '--format=%ae%n%s%n%b---', 'HEAD~4..'], 'trailers-thread-with-followups',
     {'shazam-am-flags': '--signoff'}),
    ('trailers-thread-with-cover-followup', None, None, [],
     ['log', '--format=%ae%n%s%n%b---', 'HEAD~4..'], 'trailers-thread-with-cover-followup',
     {'shazam-am-flags': '--signoff'}),
    # Test matching trailer updates by subject when patch-id changes
    ('trailers-thread-with-followups', None, (b'vivendum', b'addendum'), [],
     ['log', '--format=%ae%n%s%n%b---', 'HEAD~4..'], 'trailers-thread-with-followups-no-match',
     {'shazam-am-flags': '--signoff'}),
    # Test that we properly perserve commits with --- in them
    ('trailers-thread-with-followups', 'trailers-with-tripledash', None, [],
     ['log', '--format=%ae%n%s%n%b---', 'HEAD~4..'], 'trailers-thread-with-followups-and-tripledash',
     None),
])
def test_trailers(sampledir, prepdir, mboxf, bundlef, rep, trargs, compareargs, compareout, b4cfg):
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
        b4args = ['--no-stdin', '--no-interactive', '--offline-mode', 'shazam', '--no-add-trailers', '-m', tfile]
        parser = b4.command.setup_parser()

        cmdargs = parser.parse_args(b4args)
        with pytest.raises(SystemExit) as e:
            b4.mbox.main(cmdargs)
            assert e.type == SystemExit
            assert e.value.code == 0

    cfile = os.path.join(sampledir, f'{compareout}.verify')
    assert os.path.exists(cfile)

    parser = b4.command.setup_parser()
    b4args = ['--no-stdin', '--no-interactive', '--offline-mode', 'trailers', '--update', '-m', mfile] + trargs
    cmdargs = parser.parse_args(b4args)
    b4.ez.cmd_trailers(cmdargs)

    out, logstr = b4.git_run_command(None, compareargs)
    assert out == 0
    with open(cfile, 'r') as fh:
        cstr = fh.read()
    assert logstr == cstr

