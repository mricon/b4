"""Tests for misc/send-receive.py and its database migration tool.

Both are standalone scripts with hyphens in their names, so they are
loaded from their files. The endpoint reads CONFIG when it loads, which
is why every test gets its own copy of the module.
"""

import base64
import datetime
import email.charset
import email.message
import importlib.util
import pathlib
import re
import smtplib
import sqlite3
import subprocess
import types
from contextlib import closing
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pytest

# ezpi re-registers utf-8 for its own headers when imported, and this
# runs at collection, before every other test module's tests
_charsets = dict(email.charset.CHARSETS)
pytest.importorskip('falcon')
pytest.importorskip('ezpi')
pytest.importorskip('pymysql')
pytest.importorskip('nacl')
email.charset.CHARSETS.clear()
email.charset.CHARSETS.update(_charsets)

import ezpi
from falcon import testing
from nacl.signing import SigningKey

import b4
import patatt

from .helpers.mail import MINIMAL_DIFF, make_msg

# patatt deprecated get_field(), and the endpoint must keep up
pytestmark = pytest.mark.filterwarnings(
    r'error:get_field\(\) is deprecated:DeprecationWarning'
)

MISC = pathlib.Path(__file__).resolve().parents[2] / 'misc'
IDENTITY = 'dev@example.com'

ENDPOINT_CONF = """\
[main]
  myname = Test Endpoint
  myurl = http://localhost/_b4_submit
  dbpath = {dbpath}
  {extra}
[sendemail]
  from = Test Endpoint <devnull@example.org>
[templates]
verify-subject = Verify $${{identity}}
verify-body = Your challenge: $${{challenge}}
signature = bot
{sections}
"""

# What SQLAlchemy's create_all() made in sqlite, in the old send-receive.py
OLD_SCHEMA = """
CREATE TABLE meta (version INTEGER);
CREATE TABLE auth (
    auth_id INTEGER NOT NULL,
    created DATETIME DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
    identity TEXT NOT NULL,
    selector TEXT NOT NULL,
    pubkey TEXT NOT NULL,
    challenge TEXT,
    verified INTEGER NOT NULL,
    PRIMARY KEY (auth_id)
);
CREATE UNIQUE INDEX idx_identity_selector ON auth (identity, selector);
INSERT INTO meta (version) VALUES (1);
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


def schema(dbpath: pathlib.Path) -> List[Any]:
    return query(
        dbpath,
        "SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
        ' ORDER BY name',
    )


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
        return self.sign_message(msg)

    def sign_message(self, msg: email.message.EmailMessage) -> str:
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
        extra: str = '',
        sections: str = '',
    ) -> None:
        conf = tmp_path / 'endpoint.conf'
        conf.write_text(
            ENDPOINT_CONF.format(dbpath=dbpath, extra=extra, sections=sections)
        )
        monkeypatch.setenv('CONFIG', str(conf))
        self.dbpath = dbpath
        self.mod = load_script('send-receive.py')
        self.client = testing.TestClient(self.mod.app)
        # (recipients, message) for every message handed to SMTP
        self.mailed: List[Tuple[List[str], bytes]] = []
        # Set to make sendmail() fail with it, once smtp_fail_at messages
        # have gone through
        self.smtp_error: Optional[Exception] = None
        self.smtp_fail_at = 0
        endpoint = self

        class FakeSMTP:
            def sendmail(self, fromaddr: str, toaddrs: List[str], msg: bytes) -> None:
                if (
                    endpoint.smtp_error is not None
                    and len(endpoint.mailed) >= endpoint.smtp_fail_at
                ):
                    raise endpoint.smtp_error
                endpoint.mailed.append((list(toaddrs), msg))

            def close(self) -> None:
                pass

        monkeypatch.setattr(
            self.mod.SendReceiveListener,
            'get_smtp',
            lambda _self: FakeSMTP(),
        )

    def post(self, **req: Any) -> Dict[str, Any]:
        result = self.client.simulate_post('/_b4_submit', json=req).json
        assert isinstance(result, dict)
        return result

    def add_verified_key(self, key: Key) -> None:
        """Store a key as if it had gone through auth-new and auth-verify."""
        with closing(sqlite3.connect(self.dbpath)) as conn, conn:
            conn.execute(
                'INSERT INTO auth (identity, selector, pubkey, verified)'
                " VALUES (?, 'default', ?, 1)",
                (IDENTITY, key.pubkey),
            )

    def auth_new(self, key: Key) -> Dict[str, Any]:
        return self.post(
            action='auth-new', identity=IDENTITY, selector='default', pubkey=key.pubkey
        )

    def last_challenge(self) -> str:
        found = re.search(rb'challenge: (\S+)', self.mailed[-1][1])
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


@pytest.fixture
def dev_key(tmp_path: pathlib.Path) -> Key:
    return Key(tmp_path, 'dev')


def patch_message(
    key: Key,
    body: str = MINIMAL_DIFF,
    charset: str = 'utf-8',
    subject: str = '[PATCH] Fix bar',
) -> str:
    msg = make_msg(
        b4.make_msgid().strip('<>'),
        subject,
        from_addr=f'Dev <{IDENTITY}>',
        to='list@example.org',
        body=body,
        charset=charset,
    )
    return key.sign_message(msg)


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


def test_auth_new_never_bccs_alwaysbcc(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, dev_key: Key
) -> None:
    endpoint = Endpoint(
        tmp_path,
        monkeypatch,
        tmp_path / 'auth.sqlite3',
        extra='alwaysbcc = Audit <audit@example.org>',
    )
    assert endpoint.auth_new(dev_key)['result'] == 'success'
    assert endpoint.mailed[-1][0] == [IDENTITY]


@pytest.mark.parametrize('payload', [{}, ['receive']])
def test_post_without_action_is_an_error(endpoint: Endpoint, payload: Any) -> None:
    res = endpoint.client.simulate_post('/_b4_submit', json=payload)
    assert res.status_code == 500
    # b4 parses the body as JSON, like every other error
    assert res.json == {'result': 'error', 'message': 'Action not set'}


def test_receive_reencodes_rewritten_body(endpoint: Endpoint, dev_key: Key) -> None:
    # b4 always sends 8-bit UTF-8, but any client can sign and post a
    # quoted-printable Latin-1 patch
    endpoint.add_verified_key(dev_key)
    # =FF must survive too, so the rewrite can't keep the old QP encoding
    body = MINIMAL_DIFF.replace('Author <', 'José Author <').replace(
        'bar();', 'bar(mask=FF);'
    )
    msg = patch_message(dev_key, body=body, charset='iso-8859-1')
    res = endpoint.post(action='receive', messages=[msg])
    assert res['result'] == 'success', res

    # The sender's domain isn't ours, so the From: moved into the body
    sent = email.message_from_bytes(endpoint.mailed[-1][1], policy=b4.emlpolicy)
    assert isinstance(sent, email.message.EmailMessage)
    text = sent.get_content().replace('\r\n', '\n')
    assert text.startswith(f'From: Dev <{IDENTITY}>\n')
    assert body in text


@pytest.mark.parametrize('action', ['auth-new', 'receive'])
def test_smtp_failure_returns_json_error(
    endpoint: Endpoint, dev_key: Key, action: str
) -> None:
    endpoint.smtp_error = smtplib.SMTPRecipientsRefused(
        {IDENTITY: (550, b'No such user')}
    )
    if action == 'auth-new':
        res = endpoint.auth_new(dev_key)
    else:
        endpoint.add_verified_key(dev_key)
        res = endpoint.post(action='receive', messages=[patch_message(dev_key)])
    assert res['result'] == 'error', res
    if action == 'auth-new':
        # Harmless: the next auth-new replaces the unsent challenge
        assert [row[3] for row in endpoint.rows()] == [0]


def test_endpoint_refuses_newer_database(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dbpath = tmp_path / 'auth.sqlite3'
    with closing(sqlite3.connect(dbpath)) as conn:
        conn.execute('PRAGMA user_version = 2')
    with pytest.raises(RuntimeError, match='version 2'):
        Endpoint(tmp_path, monkeypatch, dbpath)


def test_dryrun_does_not_connect_to_smtp(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, dev_key: Key
) -> None:
    endpoint = Endpoint(
        tmp_path, monkeypatch, tmp_path / 'auth.sqlite3', extra='dryrun = true'
    )
    endpoint.add_verified_key(dev_key)

    def no_smtp(_self: Any) -> None:
        raise AssertionError('Connected to SMTP during a dry run')

    monkeypatch.setattr(endpoint.mod.SendReceiveListener, 'get_smtp', no_smtp)
    res = endpoint.post(action='receive', messages=[patch_message(dev_key)])
    assert res['result'] == 'success', res


LISTID = 'Test <test.example.org>'


def make_inbox(path: pathlib.Path, how: str = 'epoch-only') -> pathlib.Path:
    if how == 'ezpi-made':
        ezpi.init_v2_inbox(str(path))
    else:
        # What moves over from lkml-1: one epoch, no inbox.lock or all.git
        subprocess.run(
            ['git', 'init', '-q', '--bare', str(path / 'git' / '0.git')], check=True
        )
    return path


def archived(inbox: pathlib.Path) -> List[Tuple[int, str, str]]:
    """(epoch, Subject, List-Id) of every message in a v2 inbox."""
    found = []
    for epoch, _commit, raw in ezpi.iter_messages(str(inbox)):
        msg = email.message_from_bytes(raw, policy=b4.emlpolicy)
        found.append((epoch, str(msg['Subject']), str(msg['List-Id'])))
    return found


def archiving_endpoint(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    inbox: pathlib.Path,
    extra: str = '',
    notify: Optional[pathlib.Path] = None,
) -> Endpoint:
    notify = notify or tmp_path / '.updated'
    return Endpoint(
        tmp_path,
        monkeypatch,
        tmp_path / 'auth.sqlite3',
        extra=extra,
        sections=f'[public-inbox]\n  inbox = {inbox}\n  listid = {LISTID}\n'
        f'  notify_file = {notify}',
    )


@pytest.mark.parametrize('how', ['epoch-only', 'ezpi-made'])
def test_receive_archives_to_v2_inbox(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, dev_key: Key, how: str
) -> None:
    inbox = make_inbox(tmp_path / 'inbox', how)
    endpoint = archiving_endpoint(tmp_path, monkeypatch, inbox)
    endpoint.add_verified_key(dev_key)
    res = endpoint.post(action='receive', messages=[patch_message(dev_key)])
    assert res['result'] == 'success', res
    # Taken under public-inbox's lock, and still in the epoch we moved over
    assert (inbox / 'inbox.lock').exists()
    assert archived(inbox) == [(0, '[PATCH] Fix bar', LISTID)]
    assert (tmp_path / '.updated').exists()


def test_receive_archives_only_what_was_sent(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, dev_key: Key
) -> None:
    inbox = make_inbox(tmp_path / 'inbox')
    endpoint = archiving_endpoint(tmp_path, monkeypatch, inbox)
    endpoint.add_verified_key(dev_key)
    endpoint.smtp_error = smtplib.SMTPServerDisconnected('Connection closed')
    endpoint.smtp_fail_at = 1

    msgs = [patch_message(dev_key, subject=f'[PATCH {n}/2] Fix bar') for n in (1, 2)]
    res = endpoint.post(action='receive', messages=msgs)
    assert res['result'] == 'error', res
    assert 'Sent 1 of 2 messages' in res['message']
    assert archived(inbox) == [(0, '[PATCH 1/2] Fix bar', LISTID)]
    # The indexer still has to pick up what made it into the archive
    assert (tmp_path / '.updated').exists()


@pytest.mark.parametrize(
    'extra, action', [('dryrun = true', 'receive'), ('', 'reflect')]
)
def test_nothing_archived_without_a_real_send(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    dev_key: Key,
    extra: str,
    action: str,
) -> None:
    inbox = make_inbox(tmp_path / 'inbox')
    endpoint = archiving_endpoint(tmp_path, monkeypatch, inbox, extra=extra)
    endpoint.add_verified_key(dev_key)
    res = endpoint.post(action=action, messages=[patch_message(dev_key)])
    assert res['result'] == 'success', res
    assert archived(inbox) == []
    assert not (tmp_path / '.updated').exists()


def test_failed_notify_touch_still_succeeds(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, dev_key: Key
) -> None:
    inbox = make_inbox(tmp_path / 'inbox')
    rundir = tmp_path / 'run'
    rundir.mkdir()
    endpoint = archiving_endpoint(
        tmp_path, monkeypatch, inbox, notify=rundir / '.updated'
    )
    endpoint.add_verified_key(dev_key)
    rundir.rmdir()
    res = endpoint.post(action='receive', messages=[patch_message(dev_key)])
    assert res['result'] == 'success', res
    assert archived(inbox) == [(0, '[PATCH] Fix bar', LISTID)]


@pytest.mark.parametrize(
    'section, expected',
    [
        ('repo = {inbox}/git/0.git\n  listid = x', 'public-inbox.repo'),
        ('listid = x', 'public-inbox.inbox is not set'),
        ('inbox = {tmp}/typo\n  listid = x', 'not a public-inbox v2 inbox'),
        ('inbox = {inbox}', 'public-inbox.listid is not set'),
        (
            'inbox = {inbox}\n  listid = x\n  notify_file = {tmp}/typo/.updated',
            'public-inbox.notify_file',
        ),
    ],
)
def test_endpoint_refuses_broken_public_inbox(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    section: str,
    expected: str,
) -> None:
    # A typo at cutover must not leave patches going out unarchived
    inbox = make_inbox(tmp_path / 'inbox')
    section = section.format(inbox=inbox, tmp=tmp_path)
    with pytest.raises(SystemExit):
        Endpoint(
            tmp_path,
            monkeypatch,
            tmp_path / 'auth.sqlite3',
            sections=f'[public-inbox]\n  {section}',
        )
    assert expected in capsys.readouterr().err
    assert not (tmp_path / 'typo').exists()


def write_migrate_conf(tmp_path: pathlib.Path, dburl: str) -> pathlib.Path:
    conf = tmp_path / 'old.conf'
    conf.write_text(f'[main]\n  dburl = {dburl}\n')
    return conf


def test_migrate_from_sqlite(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = Key(tmp_path, 'key')
    olddb = tmp_path / 'old.db'
    with closing(sqlite3.connect(olddb)) as conn, conn:
        conn.executescript(OLD_SCHEMA)
        conn.executemany(
            'INSERT INTO auth VALUES (?, ?, ?, ?, ?, ?, ?)',
            [
                (3, '2024-01-02 03:04:05', IDENTITY, 'default', key.pubkey, None, 1),
                (7, '2025-01-01 00:00:00', 'new@example.com', 'default', 'pk', 'c', 0),
            ],
        )
    migrate = load_script('send-receive-migrate.py')
    conf = write_migrate_conf(tmp_path, f'sqlite:///{olddb}')
    newdb = tmp_path / 'auth.sqlite3'
    assert migrate.main(['-c', str(conf), '-o', str(newdb)]) == 0
    assert query(newdb, 'SELECT * FROM auth ORDER BY auth_id') == query(
        olddb, 'SELECT * FROM auth ORDER BY auth_id'
    )

    # Never clobber a database that is already there
    before = newdb.read_bytes()
    assert migrate.main(['-c', str(conf), '-o', str(newdb)]) == 1
    assert newdb.read_bytes() == before
    assert list(tmp_path.glob('*.tmp')) == []

    # Same schema as a database the endpoint creates itself
    fresh = Endpoint(tmp_path, monkeypatch, tmp_path / 'fresh.sqlite3')
    assert schema(newdb) == schema(fresh.dbpath)

    # The endpoint takes the file as is, and the migrated key works
    endpoint = Endpoint(tmp_path, monkeypatch, newdb)
    res = endpoint.post(action='auth-delete', msg=key.sign('auth-delete\n'))
    assert res['result'] == 'success', res
    assert [row[0] for row in endpoint.rows()] == [7]


class FakeMySQL:
    """Stands in for pymysql.connect() and records what the tool asked."""

    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        migrate: types.ModuleType,
        rows: List[Tuple[Any, ...]],
        auto_increment: int,
    ) -> None:
        self.rows = rows
        self.auto_increment = auto_increment
        self.connected: Dict[str, Any] = {}
        self.executed: List[str] = []
        monkeypatch.setattr(migrate.pymysql, 'connect', self.connect)

    def connect(self, **kwargs: Any) -> 'FakeMySQL':
        self.connected.update(kwargs)
        return self

    def __enter__(self) -> 'FakeMySQL':
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def cursor(self) -> 'FakeMySQL':
        return self

    def execute(self, sql: str) -> None:
        self.executed.append(sql)

    def fetchall(self) -> List[Tuple[Any, ...]]:
        return self.rows

    def fetchone(self) -> Tuple[int]:
        return (self.auto_increment,)


# PyMySQL hands DATETIME columns over without a timezone
CREATED = datetime.datetime.fromisoformat('2024-01-02 03:04:05')


# The counter (12) is ahead of the data either way, and the ids in
# between are in published headers
@pytest.mark.parametrize(
    'rows,migrated',
    [
        ([(4, CREATED, 'old@example.org', 'default', 'pk', None, 1)], [4]),
        ([], []),
    ],
    ids=['newest-deleted', 'all-deleted'],
)
def test_migrate_from_mysql(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    rows: List[Tuple[Any, ...]],
    migrated: List[int],
) -> None:
    migrate = load_script('send-receive-migrate.py')
    mysql = FakeMySQL(monkeypatch, migrate, rows, 12)
    conf = write_migrate_conf(
        tmp_path, 'mysql+pymysql://b4:p%40ss@db.example.org/b4_web?charset=utf8mb4'
    )
    newdb = tmp_path / 'auth.sqlite3'
    assert migrate.main(['-c', str(conf), '-o', str(newdb)]) == 0

    assert mysql.connected == {
        'host': 'db.example.org',
        'port': 3306,
        'user': 'b4',
        'password': 'p@ss',
        'database': 'b4_web',
        'charset': 'utf8mb4',
    }
    assert any('information_schema_stats_expiry' in sql for sql in mysql.executed)
    assert query(newdb, 'SELECT created FROM auth') == [
        ('2024-01-02 03:04:05',) for _ in migrated
    ]
    endpoint = Endpoint(tmp_path, monkeypatch, newdb)
    endpoint.auth_new(Key(tmp_path, 'key'))
    assert [row[0] for row in endpoint.rows()] == [*migrated, 12]
