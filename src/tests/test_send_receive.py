"""Tests for misc/send-receive.py.

The endpoint is a standalone script with a hyphen in its name, so it is
loaded from its file. It reads CONFIG when it loads, which is why
every test gets its own copy of the module.
"""

import base64
import email.message
import importlib.util
import pathlib
import re
import sqlite3
import types
from contextlib import closing
from typing import Any, Dict, List, Sequence, Tuple

import pytest

pytest.importorskip('falcon')
pytest.importorskip('ezpi')
pytest.importorskip('nacl')

from falcon import testing
from nacl.signing import SigningKey

import b4
import patatt

MISC = pathlib.Path(__file__).resolve().parents[2] / 'misc'
IDENTITY = 'dev@example.com'

ENDPOINT_CONF = """\
[main]
  myname = Test Endpoint
  myurl = http://localhost/_b4_submit
  dbpath = {dbpath}
[sendemail]
  from = Test Endpoint <devnull@example.org>
[templates]
verify-subject = Verify $${{identity}}
verify-body = Your challenge: $${{challenge}}
signature = bot
"""


def load_script(filename: str) -> types.ModuleType:
    modname = filename.removesuffix('.py').replace('-', '_')
    spec = importlib.util.spec_from_file_location(modname, MISC / filename)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def query(dbpath: pathlib.Path, sql: str, params: Sequence[Any] = ()) -> List[Any]:
    with closing(sqlite3.connect(dbpath)) as conn:
        return conn.execute(sql, params).fetchall()


class Key:
    """A throwaway ed25519 key, as b4 would send it to the endpoint."""

    def __init__(self, tmp_path: pathlib.Path, name: str) -> None:
        sk = SigningKey.generate()
        self.pubkey = base64.b64encode(sk.verify_key.encode()).decode()
        self.keyfile = tmp_path / f'{name}.key'
        self.keyfile.write_text(base64.b64encode(sk.encode()).decode())

    def sign(self, body: str) -> str:
        """Build and sign a message the way b4's ez.auth_verify() does."""
        msg = email.message.EmailMessage()
        msg.add_header('From', IDENTITY)
        msg.add_header('Subject', 'b4-send-verify')
        msg.add_header('Message-ID', b4.make_msgid())
        msg.set_payload(body, charset='utf-8')
        # patatt caches signing keys by identity, and tests swap keys
        patatt.KEYCACHE.pop(IDENTITY, None)
        config: Dict[str, Any] = {
            'identity': IDENTITY,
            'selector': 'default',
            'signingkey': f'ed25519:{self.keyfile}',
        }
        return patatt.rfc2822_sign(
            msg.as_bytes(policy=b4.emlpolicy), config=config
        ).decode()


class Endpoint:
    def __init__(
        self,
        tmp_path: pathlib.Path,
        monkeypatch: pytest.MonkeyPatch,
        dbpath: pathlib.Path,
    ) -> None:
        conf = tmp_path / 'endpoint.conf'
        conf.write_text(ENDPOINT_CONF.format(dbpath=dbpath))
        monkeypatch.setenv('CONFIG', str(conf))
        self.dbpath = dbpath
        self.mod = load_script('send-receive.py')
        self.client = testing.TestClient(self.mod.app)
        self.mailed: List[bytes] = []
        mailed = self.mailed

        class FakeSMTP:
            def sendmail(self, fromaddr: str, toaddrs: List[str], msg: bytes) -> None:
                mailed.append(msg)

            def close(self) -> None:
                pass

        monkeypatch.setattr(
            self.mod.SendReceiveListener,
            'get_smtp',
            lambda _self: (FakeSMTP(), ('Test Endpoint', 'devnull@example.org')),
        )

    def post(self, **req: Any) -> Dict[str, Any]:
        return self.client.simulate_post('/_b4_submit', json=req).json

    def auth_new(self, key: Key) -> Dict[str, Any]:
        return self.post(
            action='auth-new', identity=IDENTITY, selector='default', pubkey=key.pubkey
        )

    def last_challenge(self) -> str:
        found = re.search(rb'challenge: (\S+)', self.mailed[-1])
        assert found is not None
        return found.group(1).decode()

    def rows(self) -> List[Tuple[Any, ...]]:
        return query(
            self.dbpath,
            'SELECT auth_id, pubkey, challenge, verified FROM auth ORDER BY auth_id',
        )


@pytest.fixture
def endpoint(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Endpoint:
    # The directory doesn't exist yet: the endpoint has to create it
    return Endpoint(tmp_path, monkeypatch, tmp_path / 'db' / 'auth.sqlite3')


def test_auth_lifecycle(endpoint: Endpoint, tmp_path: pathlib.Path) -> None:
    key = Key(tmp_path, 'key')
    assert endpoint.auth_new(key)['result'] == 'success'
    challenge = endpoint.last_challenge()
    assert endpoint.rows() == [(1, key.pubkey, challenge, 0)]
    assert query(endpoint.dbpath, 'PRAGMA journal_mode') == [('wal',)]
    assert query(endpoint.dbpath, 'PRAGMA user_version') == [(1,)]

    res = endpoint.post(action='auth-verify', msg=key.sign(f'verify:{challenge}\n'))
    assert res['result'] == 'success', res
    assert endpoint.rows() == [(1, key.pubkey, None, 1)]

    # A verified key is never replaced through auth-new
    res = endpoint.auth_new(Key(tmp_path, 'other'))
    assert res['result'] == 'error'
    assert 'already authorized' in res['message']
    assert endpoint.rows() == [(1, key.pubkey, None, 1)]

    res = endpoint.post(action='auth-delete', msg=key.sign('auth-delete\n'))
    assert res['result'] == 'success', res
    assert endpoint.rows() == []

    # auth_id is never reused, because it shows up in published headers
    endpoint.auth_new(key)
    assert endpoint.rows()[0][0] > 1


def test_auth_new_replaces_pending_challenge(
    endpoint: Endpoint, tmp_path: pathlib.Path
) -> None:
    first, second = Key(tmp_path, 'first'), Key(tmp_path, 'second')
    endpoint.auth_new(first)
    old_challenge = endpoint.last_challenge()
    endpoint.auth_new(second)
    new_challenge = endpoint.last_challenge()
    assert endpoint.rows() == [(1, second.pubkey, new_challenge, 0)]

    res = endpoint.post(
        action='auth-verify', msg=second.sign(f'verify:{old_challenge}\n')
    )
    assert res['result'] == 'error'
    res = endpoint.post(
        action='auth-verify', msg=second.sign(f'verify:{new_challenge}\n')
    )
    assert res['result'] == 'success', res


def test_auth_verify_ignores_key_swapped_in_meanwhile(
    endpoint: Endpoint, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    victim, attacker = Key(tmp_path, 'victim'), Key(tmp_path, 'attacker')
    endpoint.auth_new(victim)
    challenge = endpoint.last_challenge()

    # Another worker handles auth-new for the same pair right after the
    # victim's signature was checked against the old key
    validate = endpoint.mod.SendReceiveListener.validate_message

    def racing_validate(self: Any, bdata: bytes, verified: int = 1) -> Any:
        found = validate(self, bdata, verified)
        endpoint.auth_new(attacker)
        return found

    monkeypatch.setattr(
        endpoint.mod.SendReceiveListener, 'validate_message', racing_validate
    )
    res = endpoint.post(action='auth-verify', msg=victim.sign(f'verify:{challenge}\n'))
    assert res['result'] == 'error'
    assert endpoint.rows()[0][1:] == (attacker.pubkey, endpoint.last_challenge(), 0)


@pytest.mark.parametrize(
    'main, expected',
    [
        ('dburl = sqlite:///old.db', 'send-receive-migrate.py'),
        ('dbpath = :memory:', 'must be a file'),
        ('', 'main.dbpath is not set'),
    ],
)
def test_endpoint_refuses_bad_db_config(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    main: str,
    expected: str,
) -> None:
    conf = tmp_path / 'endpoint.conf'
    conf.write_text(f'[main]\n  {main}\n')
    monkeypatch.setenv('CONFIG', str(conf))
    with pytest.raises(SystemExit):
        load_script('send-receive.py')
    assert expected in capsys.readouterr().err
