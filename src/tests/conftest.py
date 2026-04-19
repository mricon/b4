import copy
import os
import pathlib
import sys
from typing import Generator

import pytest

import b4


@pytest.fixture(scope='function', autouse=True)
def settestdefaults(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    topdir = b4.git_get_toplevel()
    if topdir and topdir != os.getcwd():
        os.chdir(topdir)
    monkeypatch.setattr(b4, 'can_network', False)
    monkeypatch.setattr(
        b4,
        'MAIN_CONFIG',
        {
            **copy.deepcopy(b4.DEFAULT_CONFIG),
            'attestation-policy': 'off',
        },
    )
    monkeypatch.setattr(
        b4,
        'USER_CONFIG',
        {
            'name': 'Test Override',
            'email': 'test-override@example.com',
        },
    )
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path))
    monkeypatch.setenv('XDG_CACHE_HOME', str(tmp_path))
    git_config_count = int(os.environ.get('GIT_CONFIG_COUNT', '0'))
    monkeypatch.setenv('GIT_CONFIG_COUNT', str(git_config_count + 1))
    monkeypatch.setenv(f'GIT_CONFIG_KEY_{git_config_count}', 'commit.gpgsign')
    monkeypatch.setenv(f'GIT_CONFIG_VALUE_{git_config_count}', 'false')
    # This lets us avoid execvp-ing from inside b4 when testing
    monkeypatch.setattr(sys, '_running_in_pytest', True, raising=False)


@pytest.fixture(scope='function')
def sampledir(request: pytest.FixtureRequest) -> str:
    return os.path.join(request.path.parent, 'samples')


@pytest.fixture(scope='function')
def gitdir(
    request: pytest.FixtureRequest, tmp_path: pathlib.Path
) -> Generator[str, None, None]:
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
    out, _logstr = b4.git_run_command(None, args)
    assert out == 0
    assert isinstance(b4.USER_CONFIG['name'], str)
    assert isinstance(b4.USER_CONFIG['email'], str)
    b4.git_set_config(dest, 'user.name', b4.USER_CONFIG['name'])
    b4.git_set_config(dest, 'user.email', b4.USER_CONFIG['email'])
    olddir = os.getcwd()
    os.chdir(dest)
    yield dest
    os.chdir(olddir)
