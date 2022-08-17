#!/usr/bin/env python3
# noinspection PyUnresolvedReferences
import falcon
import os
import logging
import json
import sqlalchemy as sa
import patatt

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
                        sa.Column('identity', sa.Text(), nullable=False),
                        sa.Column('selector', sa.Text(), nullable=False),
                        sa.Column('pubkey', sa.Text(), nullable=False),
                        sa.Column('challenge', sa.Text(), nullable=True),
                        sa.Column('verified', sa.Integer(), nullable=False),
                        )
        sa.Index('idx_identity_selector', auth.c.identity, auth.c.selector, unique=True)
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
        identity = jdata.get('identity')
        selector = jdata.get('selector')
        pubkey = jdata.get('pubkey')
        t_auth = sa.Table('auth', md, autoload=True, autoload_with=self._engine)
        q = sa.select([t_auth.c.auth_id]).where(t_auth.c.identity == identity, t_auth.c.selector == selector,
                                                t_auth.c.verified == 1)
        rp = conn.execute(q)
        if len(rp.fetchall()):
            self.send_error(resp, message='i=%s;s=%s is already authorized' % (identity, selector))
            return
        # delete any existing challenges for this and create a new one
        q = sa.delete(t_auth).where(t_auth.c.identity == identity, t_auth.c.selector == selector,
                                    t_auth.c.verified == 0)
        conn.execute(q)
        # create new challenge
        import uuid
        cstr = str(uuid.uuid4())
        q = sa.insert(t_auth).values(identity=identity, selector=selector, pubkey=pubkey, challenge=cstr,
                                     verified=0)
        conn.execute(q)
        # TODO: Actual mail sending
        logger.info('Challenge: %s', cstr)
        self.send_success(resp, message='Challenge generated')

    def validate_message(self, conn, t_auth, bdata, verified=1):
        # Returns auth_id of the matching record
        pm = patatt.PatattMessage(bdata)
        if not pm.signed:
            return None
        auth_id = identity = pubkey = None
        for ds in pm.get_sigs():
            selector = 'default'
            identity = ''
            i = ds.get_field('i')
            if i:
                identity = i.decode()
            s = ds.get_field('s')
            if s:
                selector = s.decode()
            logger.debug('i=%s; s=%s', identity, selector)
            q = sa.select([t_auth.c.auth_id, t_auth.c.pubkey]).where(t_auth.c.identity == identity,
                                                                     t_auth.c.selector == selector,
                                                                     t_auth.c.verified == verified)
            rp = conn.execute(q)
            res = rp.fetchall()
            if res:
                auth_id, pubkey = res[0]
                break

        logger.debug('auth_id=%s', auth_id)
        if not auth_id:
            return None
        try:
            pm.validate(identity, pubkey.encode())
        except Exception as ex:
            logger.debug('Validation failed: %s', ex)
            return None

        return auth_id

    def auth_verify(self, jdata, resp):
        msg = jdata.get('msg')
        if msg.find('\nverify:') < 0:
            self.send_error(resp, message='Invalid verification message')
            return
        conn = self._engine.connect()
        md = sa.MetaData()
        t_auth = sa.Table('auth', md, autoload=True, autoload_with=self._engine)
        bdata = msg.encode()
        auth_id = self.validate_message(conn, t_auth, bdata, verified=0)
        if auth_id is None:
            self.send_error(resp, message='Signature validation failed')
            return
        # Now compare the challenge to what we received
        q = sa.select([t_auth.c.challenge]).where(t_auth.c.auth_id == auth_id)
        rp = conn.execute(q)
        res = rp.fetchall()
        challenge = res[0][0]
        if msg.find(f'\nverify:{challenge}') < 0:
            self.send_error(resp, message='Invalid verification string')
            return
        q = sa.update(t_auth).where(t_auth.c.auth_id == auth_id).values(challenge=None, verified=1)
        conn.execute(q)
        self.send_success(resp, message='Challenge verified')

    def auth_delete(self, jdata, resp):
        msg = jdata.get('msg')
        if msg.find('\nauth-delete') < 0:
            self.send_error(resp, message='Invalid key delete message')
            return
        conn = self._engine.connect()
        md = sa.MetaData()
        t_auth = sa.Table('auth', md, autoload=True, autoload_with=self._engine)
        bdata = msg.encode()
        auth_id = self.validate_message(conn, t_auth, bdata)
        if auth_id is None:
            self.send_error(resp, message='Signature validation failed')
            return
        q = sa.delete(t_auth).where(t_auth.c.auth_id == auth_id)
        conn.execute(q)
        self.send_success(resp, message='Authentication deleted')

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
        action = jdata.get('action')
        if action == 'auth-new':
            self.auth_new(jdata, resp)
            return
        if action == 'auth-verify':
            self.auth_verify(jdata, resp)
            return
        if action == 'auth-delete':
            self.auth_delete(jdata, resp)
            return

        resp.status = falcon.HTTP_500
        resp.content_type = falcon.MEDIA_TEXT
        resp.text = 'Unknown action: %s\n' % action


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
