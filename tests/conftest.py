import pytest  # noqa
import b4
import os


@pytest.fixture(scope="function", autouse=True)
def settestdefaults(tmp_path):
    topdir = b4.git_get_toplevel()
    if topdir != os.getcwd():
        os.chdir(topdir)
    b4.can_patatt = False
    b4.can_network = False
    b4.MAIN_CONFIG = dict(b4.DEFAULT_CONFIG)
    b4.USER_CONFIG = {
        'name': 'Test Override',
        'email': 'test-override@example.com',
    }
    os.environ['XDG_DATA_HOME'] = str(tmp_path)
    os.environ['XDG_CACHE_HOME'] = str(tmp_path)


@pytest.fixture(scope="function")
def sampledir(request):
    return os.path.join(request.fspath.dirname, 'samples')


@pytest.fixture(scope="function")
def gitdir(request, tmp_path):
    sampledir = os.path.join(request.fspath.dirname, 'samples')
    # look for bundle file specific to the calling fspath
    bname = request.fspath.basename[5:-3]
    bfile = os.path.join(sampledir, f'{bname}-gitdir.bundle')
    if not os.path.exists(bfile):
        # Fall back to the default
        bfile = os.path.join(sampledir, 'gitdir.bundle')
    assert os.path.exists(bfile)
    dest = os.path.join(tmp_path, 'repo')
    args = ['clone', bfile, dest]
    b4.git_run_command(None, args)
    olddir = os.getcwd()
    os.chdir(dest)
    yield dest
    os.chdir(olddir)
