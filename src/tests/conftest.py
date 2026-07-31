import copy
import os
import pathlib
import sys
from typing import Callable, Generator

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
def add_unpopulated_submodule() -> Callable[..., str]:
    """Factory: advance master with an active but unpopulated submodule.

    A gitlink and .gitmodules in the tree plus a configured url is all it
    takes: no clone exists anywhere, which is exactly what any fresh linked
    worktree sees, and a git command recursing into submodules there dies with
    "fatal: not a git repository: .../worktrees/<wt>/modules/<name>". Built
    with plumbing so nothing is signed and master can be advanced in place.
    Callers flip submodule.recurse on only once their own fixtures are built --
    this setup would trip over it too. Returns the sha the gitlink points at.
    """

    def _add(gitdir: str, name: str = 'sub') -> str:
        ecode, head = b4.git_run_command(gitdir, ['rev-parse', 'master'])
        assert ecode == 0
        gitlink = head.strip()
        gm = pathlib.Path(gitdir) / '.gitmodules'
        gm.write_text(f'[submodule "{name}"]\n\tpath = {name}\n\turl = ./{name}\n')
        ecode, _ = b4.git_run_command(gitdir, ['add', '.gitmodules'])
        assert ecode == 0
        ecode, _ = b4.git_run_command(
            gitdir,
            ['update-index', '--add', '--cacheinfo', f'160000,{gitlink},{name}'],
        )
        assert ecode == 0
        ecode, tree = b4.git_run_command(gitdir, ['write-tree'])
        assert ecode == 0
        ecode, commit = b4.git_run_command(
            gitdir,
            ['commit-tree', tree.strip(), '-p', 'master'],
            stdin=f'add {name} gitlink\n'.encode(),
        )
        assert ecode == 0
        ecode, _ = b4.git_run_command(
            gitdir, ['update-ref', 'refs/heads/master', commit.strip()]
        )
        assert ecode == 0
        ecode, _ = b4.git_run_command(gitdir, ['reset', '--hard', 'master'])
        assert ecode == 0
        ecode, entry = b4.git_run_command(gitdir, ['ls-tree', 'master', name])
        assert ecode == 0 and entry.startswith('160000 commit'), (
            f'gitlink did not land in master: {entry!r}'
        )
        b4.git_set_config(gitdir, f'submodule.{name}.url', f'./{name}')
        return gitlink

    return _add


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
