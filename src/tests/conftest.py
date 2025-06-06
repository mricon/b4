import pytest
import b4
import os
import pathlib
import sys

from typing import Generator


@pytest.fixture(scope="function", autouse=True)
def settestdefaults(tmp_path: pathlib.Path) -> None:
    topdir = b4.git_get_toplevel()
    if topdir and topdir != os.getcwd():
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
    # This lets us avoid execvp-ing from inside b4 when testing
    sys._running_in_pytest = True


@pytest.fixture(scope="function")
def sampledir(request: pytest.FixtureRequest) -> str:
    return os.path.join(request.path.parent, 'samples')


@pytest.fixture(scope="function")
def gitdir(request: pytest.FixtureRequest, tmp_path: pathlib.Path) -> Generator[str, None, None]:
    sampledir = os.path.join(request.path.parent, 'samples')
    # look for bundle file specific to the calling fspath
    bname = request.path.name[5:-3]
    bfile = os.path.join(sampledir, f'{bname}-gitdir.bundle')
    if not os.path.exists(bfile):
        # Fall back to the default
        bfile = os.path.join(sampledir, 'gitdir.bundle')
    assert os.path.exists(bfile)
    dest = os.path.join(tmp_path, 'repo')
    args = ['clone', '--branch', 'master', bfile, dest]
    out, logstr = b4.git_run_command(None, args)
    assert out == 0
    b4.git_set_config(dest, 'user.name', b4.USER_CONFIG['name'])
    b4.git_set_config(dest, 'user.email', b4.USER_CONFIG['email'])
    olddir = os.getcwd()
    os.chdir(dest)
    yield dest
    os.chdir(olddir)
