#!/usr/bin/env python3
# noinspection PyUnresolvedReferences
import falcon
import os
import logging
import json
import sqlalchemy as sa

from nacl.signing import VerifyKey
from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError

DB_VERSION = 1

logger = logging.getLogger('b4-send-receive')


# noinspection PyBroadException, PyMethodMayBeStatic
class SendReceiveListener(object):

    def __init__(self, _engine):
        self._engine = _engine
        # You shouldn't use this in production
        if self._engine.driver == 'pysqlite':
            self._init_sa_db()

    def _init_sa_db(self):
        logger.info('Creating tables')
        conn = self._engine.connect()
        md = sa.MetaData()
        meta = sa.Table('meta', md,
                        sa.Column('version', sa.Integer())
                        )
        auth = sa.Table('auth', md,
                        sa.Column('auth_id', sa.Integer(), primary_key=True),
                        sa.Column('created', sa.DateTime(), nullable=False, server_default=sa.sql.func.now()),
                        sa.Column('email', sa.Text(), nullable=False),
                        sa.Column('name', sa.Text(), nullable=False),
                        sa.Column('pubkey', sa.Text(), nullable=False),
                        )
        sa.Index('idx_email_pubkey', auth.c.pubkey, auth.c.email, unique=True)
        challenge = sa.Table('challenge', md,
                             sa.Column('challenge_id', sa.Integer(), primary_key=True),
                             sa.Column('created', sa.DateTime(), nullable=False, server_default=sa.sql.func.now()),
                             sa.Column('pubkey', sa.Text(), nullable=False),
                             sa.Column('email', sa.Text(), nullable=False),
                             sa.Column('challenge', sa.Text(), nullable=False),
                             )
        sa.Index('idx_uniq_challenge', challenge.c.pubkey, challenge.c.email, challenge.c.challenge, unique=True)
        md.create_all(self._engine)
        q = sa.insert(meta).values(version=DB_VERSION)
        conn.execute(q)

    def on_get(self, req, resp):  # noqa
        resp.status = falcon.HTTP_200
        resp.content_type = falcon.MEDIA_TEXT
        resp.text = "We don't serve GETs here\n"

    def send_error(self, resp, message):
        resp.status = falcon.HTTP_500
        resp.text = json.dumps({'result': 'error', 'message': message})

    def send_success(self, resp, message):
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({'result': 'success', 'message': message})

    def auth_new(self, jdata, resp):
        # Is it already authorized?
        conn = self._engine.connect()
        md = sa.MetaData()
        t_auth = sa.Table('auth', md, autoload=True, autoload_with=self._engine)
        email = jdata.get('email')
        pubkey = jdata.get('key')
        q = sa.select([t_auth.c.auth_id]).where(t_auth.c.email == email, t_auth.c.pubkey == pubkey)
        rp = conn.execute(q)
        if len(rp.fetchall()):
            self.send_error(resp, message='%s:%s is already authorized' % (email, pubkey))
            return
        # delete any existing challenges for this and create a new one
        t_challenge = sa.Table('challenge', md, autoload=True, autoload_with=self._engine)
        q = sa.delete(t_challenge).where(t_challenge.c.email == email, t_challenge.c.pubkey == pubkey)
        conn.execute(q)
        # create new challenge
        import uuid
        cstr = str(uuid.uuid4())
        q = sa.insert(t_challenge).values(pubkey=pubkey, email=email, challenge=cstr)
        conn.execute(q)
        # TODO: Actual mail sending
        logger.info('Challenge: %s', cstr)
        self.send_success(resp, message='Challenge generated')

    def auth_verify(self, jdata, resp):
        # Do we have a record for this email/challenge?
        conn = self._engine.connect()
        md = sa.MetaData()
        t_challenge = sa.Table('challenge', md, autoload=True, autoload_with=self._engine)
        email = jdata.get('email', '')
        challenge = jdata.get('challenge', '')
        sigdata = jdata.get('sigdata', '')
        q = sa.select([t_challenge.c.pubkey]).where(t_challenge.c.email == email, t_challenge.c.challenge == challenge)
        rp = conn.execute(q)
        qres = rp.fetchall()
        if not len(qres):
            self.send_error(resp, message='No such challenge for %s' % email)
            return
        pubkey = qres[0][0]
        vk = VerifyKey(pubkey.encode(), encoder=Base64Encoder)
        try:
            vk.verify(sigdata.encode(), encoder=Base64Encoder)
        except BadSignatureError:
            self.send_error(resp, message='Could not validate signature for %s' % email)
            return
        # validated at this point, so record this as valid auth
        name = jdata.get('name')
        t_auth = sa.Table('auth', md, autoload=True, autoload_with=self._engine)
        q = sa.insert(t_auth).values(pubkey=pubkey, name=name, email=email)
        conn.execute(q)
        q = sa.delete(t_challenge).where(t_challenge.c.email == email, t_challenge.c.challenge == challenge)
        conn.execute(q)
        self.send_success(resp, message='Challenge verified')

    def on_post(self, req, resp):
        if not req.content_length:
            resp.status = falcon.HTTP_500
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = 'Payload required\n'
            return
        raw = req.bounded_stream.read()
        try:
            jdata = json.loads(raw)
        except:
            resp.status = falcon.HTTP_500
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = 'Failed to parse the request\n'
            return
        logger.info(jdata)
        action = jdata.get('action')
        if action == 'auth-new':
            self.auth_new(jdata, resp)
        if action == 'auth-verify':
            self.auth_verify(jdata, resp)
        else:
            resp.status = falcon.HTTP_500
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = 'Unknown action: %s\n' % action
            return


app = falcon.App()
dburl = os.getenv('DB_URL', 'sqlite:///:memory:')
engine = sa.create_engine(dburl)
srl = SendReceiveListener(engine)
mp = os.getenv('MOUNTPOINT', '/_b4_submit')
app.add_route(mp, srl)


if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    with make_server('', 8000, app) as httpd:
        logger.info('Serving on port 8000...')

        # Serve until process is killed
        httpd.serve_forever()
