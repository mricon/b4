#!/usr/bin/env python3
# noinspection PyUnresolvedReferences
import falcon
import os
import logging
import json
import sqlalchemy as sa
import patatt
import smtplib
import email
import email.header
import email.policy
import re
import ezpi
import copy

from configparser import ConfigParser, ExtendedInterpolation
from string import Template
from email import utils
from typing import Tuple, Union

from email import charset
charset.add_charset('utf-8', None)
emlpolicy = email.policy.EmailPolicy(utf8=True, cte_type='8bit', max_line_length=None)

DB_VERSION = 1

# We'll make this configurable later
TPT_VERIFY_SUBJECT = 'Web endpoint verification for ${identity}'
TPT_VERIFY_BODY = '''Dear ${name}:

Somebody, probably you, initiated a web endpoint verification routine
for patch submissions at: ${myurl}

If you have no idea what is going on, please ignore this message. 
Otherwise, please follow instructions provided by your tool and paste
the following string:

${challenge}

Happy patching!
-- 
Deet-doot-dot, I'm a bot
https://korg.docs.kernel.org/
'''

DEFAULT_CFG = r'''
[main]
  myname = Web Endpoint
  myurl = http://localhost:8000/_b4_submit
  dburl = sqlite:///:memory:
  mydomains = kernel.org, linux.dev
  # One of the To: or Cc: addrs must match this regex
  # (to ensure that the message was intended to go to mailing lists)
  mustdest = .*@(vger\.kernel\.org|lists\.linux\.dev|lists\.infradead\.org)
  dryrun = false
[sendemail]
  smtpserver = localhost
  from = devnull@kernel.org
[public-inbox]
  repo = 
  listid = patches.feeds.kernel.org
'''

logger = logging.getLogger('b4-send-receive')


# noinspection PyBroadException, PyMethodMayBeStatic
class SendReceiveListener(object):

    def __init__(self, _engine, _config):
        self._engine = _engine
        self._config = _config
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

    def send_error(self, resp, message: str):
        resp.status = falcon.HTTP_500
        resp.text = json.dumps({'result': 'error', 'message': message})

    def send_success(self, resp, message: str):
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({'result': 'success', 'message': message})

    def get_smtp(self) -> Tuple[Union[smtplib.SMTP, smtplib.SMTP_SSL, None], Tuple[str, str]]:
        sconfig = self._config['sendemail']
        server = sconfig.get('smtpserver', 'localhost')
        port = sconfig.get('smtpserverport', 0)
        encryption = sconfig.get('smtpencryption')

        logger.debug('Connecting to %s:%s', server, port)
        # We only authenticate if we have encryption
        if encryption:
            if encryption in ('tls', 'starttls'):
                # We do startssl
                smtp = smtplib.SMTP(server, port)
                # Introduce ourselves
                smtp.ehlo()
                # Start encryption
                smtp.starttls()
                # Introduce ourselves again to get new criteria
                smtp.ehlo()
            elif encryption in ('ssl', 'smtps'):
                # We do TLS from the get-go
                smtp = smtplib.SMTP_SSL(server, port)
            else:
                raise smtplib.SMTPException('Unclear what to do with smtpencryption=%s' % encryption)

            # If we got to this point, we should do authentication.
            auser = sconfig.get('smtpuser')
            apass = sconfig.get('smtppass')
            if auser and apass:
                # Let any exceptions bubble up
                smtp.login(auser, apass)
        else:
            # We assume you know what you're doing if you don't need encryption
            smtp = smtplib.SMTP(server, port)

        frompair = utils.getaddresses([sconfig.get('from')])[0]
        return smtp, frompair

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
        logger.info('Challenge: %s', cstr)
        smtp, frompair = self.get_smtp()
        cmsg = email.message.EmailMessage()
        fromname, fromaddr = frompair
        if len(fromname):
            cmsg.add_header('From', f'{fromname} <{fromaddr}>')
        else:
            cmsg.add_header('From', fromaddr)
        subject = Template(TPT_VERIFY_SUBJECT).safe_substitute({'identity': jdata.get('identity')})
        cmsg.add_header('Subject', subject)
        name = jdata.get('name', 'Anonymous Llama')
        cmsg.add_header('To', f'{name} <{identity}>')
        cmsg.add_header('Message-Id', utils.make_msgid('b4-verify'))
        vals = {
            'name': name,
            'myurl': self._config['main'].get('myurl'),
            'challenge': cstr,
        }
        body = Template(TPT_VERIFY_BODY).safe_substitute(vals)
        cmsg.set_payload(body, charset='utf-8')
        bdata = cmsg.as_bytes(policy=emlpolicy)
        destaddrs = [identity]
        alwaysbcc = self._config['main'].get('alwayscc')
        if alwaysbcc:
            destaddrs += [x[1] for x in utils.getaddresses(alwaysbcc)]
        smtp.sendmail(fromaddr, [identity], bdata)
        self.send_success(resp, message=f'Challenge generated and sent to {identity}')

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

    def clean_header(self, hdrval):
        if hdrval is None:
            return ''

        decoded = ''
        for hstr, hcs in email.header.decode_header(hdrval):
            if hcs is None:
                hcs = 'utf-8'
            try:
                decoded += hstr.decode(hcs, errors='replace')
            except LookupError:
                # Try as utf-u
                decoded += hstr.decode('utf-8', errors='replace')
            except (UnicodeDecodeError, AttributeError):
                decoded += hstr
        new_hdrval = re.sub(r'\n?\s+', ' ', decoded)
        return new_hdrval.strip()

    def receive(self, jdata, resp):
        servicename = self._config['main'].get('myname')
        if not servicename:
            servicename = 'Web Endpoint'
        umsgs = jdata.get('messages')
        if not umsgs:
            self.send_error(resp, message='Missing the messages array')
            return

        diffre = re.compile(r'^(---.*\n\+\+\+|GIT binary patch|diff --git \w/\S+ \w/\S+)', flags=re.M | re.I)
        diffstatre = re.compile(r'^\s*\d+ file.*\d+ (insertion|deletion)', flags=re.M | re.I)

        msgs = list()
        conn = self._engine.connect()
        md = sa.MetaData()
        t_auth = sa.Table('auth', md, autoload=True, autoload_with=self._engine)
        # First, validate all signatures
        at = 0
        mustdest = self._config['main'].get('mustdest')
        for umsg in umsgs:
            at += 1
            auth_id = self.validate_message(conn, t_auth, umsg.encode())
            if auth_id is None:
                self.send_error(resp, message=f'Signature validation failed for message {at}')
                return
            msg = email.message_from_string(umsg)
            # Some quick sanity checking:
            # - Subject has to start with [PATCH
            # - Content-type may ONLY be text/plain
            # - Has to include a diff or a diffstat
            passes = True
            if not msg.get('Subject', '').startswith('[PATCH '):
                passes = False
            if passes:
                cte = msg.get_content_type()
                if cte.lower() != 'text/plain':
                    passes = False
            if passes:
                payload = msg.get_payload()
                if not (diffre.search(payload) or diffstatre.search(payload)):
                    passes = False

            if not passes:
                self.send_error(resp, message='This service only accepts patches')
                return

            # Make sure that From, Date, Subject, and Message-Id headers exist
            if not msg.get('From') or not msg.get('Date') or not msg.get('Subject') or not msg.get('Message-Id'):
                self.send_error(resp, message='Message is missing some required headers.')
                return

            # Check that To/Cc have a mailing list we recognize
            alldests = utils.getaddresses([str(x) for x in msg.get_all('to', [])])
            alldests += utils.getaddresses([str(x) for x in msg.get_all('cc', [])])
            destaddrs = {x[1] for x in alldests}
            if mustdest:
                matched = False
                for destaddr in destaddrs:
                    if re.search(mustdest, destaddr, flags=re.I):
                        matched = True
                        break
                if not matched:
                    self.send_error(resp, message='Destinations must include a mailing list we recognize.')
                    return
            msg.add_header('X-Endpoint-Received', f'by {servicename} with auth_id={auth_id}')
            msgs.append((msg, destaddrs))

        # All signatures verified. Prepare messages for sending.
        cfgdomains = self._config['main'].get('mydomains')
        if cfgdomains is not None:
            mydomains = [x.strip() for x in cfgdomains.split(',')]
        else:
            mydomains = list()

        smtp, frompair = self.get_smtp()
        bccaddrs = set()
        _bcc = self._config['main'].get('alwaysbcc')
        if _bcc:
            bccaddrs.update([x[1] for x in utils.getaddresses([_bcc])])

        repo = listid = None
        if 'public-inbox' in self._config and self._config['public-inbox'].get('repo'):
            repo = self._config['public-inbox'].get('repo')
            listid = self._config['public-inbox'].get('listid')
            if not os.path.isdir(repo):
                repo = None

        for msg, destaddrs in msgs:
            if repo:
                pmsg = copy.deepcopy(msg)
                if pmsg.get('List-Id'):
                    pmsg.replace_header('List-Id', listid)
                else:
                    pmsg.add_header('List-Id', listid)
                ezpi.add_rfc822(repo, pmsg)

            subject = self.clean_header(msg.get('Subject'))
            origfrom = self.clean_header(msg.get('From'))
            origpair = utils.getaddresses([origfrom])[0]
            origaddr = origpair[1]
            # Does it match one of our domains
            mydomain = False
            for _domain in mydomains:
                if origaddr.endswith(f'@{_domain}'):
                    mydomain = True
                    break
            if mydomain:
                fromaddr = origaddr
            else:
                fromaddr = frompair[1]
                # We can't just send this as-is due to DMARC policies. Therefore, we set
                # Reply-To and X-Original-From.
                origname = origpair[0]
                if not origname:
                    origname = origpair[1]
                msg.replace_header('From', f'{origname} via {servicename} <{fromaddr}>')

                if msg.get('X-Original-From'):
                    msg.replace_header('X-Original-From', origfrom)
                else:
                    msg.add_header('X-Original-From', origfrom)
                if msg.get('Reply-To'):
                    msg.replace_header('Reply-To', f'<{origpair[1]}>')
                else:
                    msg.add_header('Reply-To', f'<{origpair[1]}>')

                body = msg.get_payload()
                # Parse it as a message and see if we get a From: header
                cmsg = email.message_from_string(body)
                if cmsg.get('From') is None:
                    cmsg.add_header('From', origfrom)
                    msg.set_payload(cmsg.as_string(policy=emlpolicy, maxheaderlen=0), charset='utf-8')

            if bccaddrs:
                destaddrs.update(bccaddrs)

            bdata = msg.as_string(policy=emlpolicy).encode()

            if not self._config['main'].getboolean('dryrun'):
                smtp.sendmail(fromaddr, list(destaddrs), bdata)
                logger.info('Sent %s', subject)
            else:
                logger.info('---DRYRUN MSG START---')
                logger.info(msg)
                logger.info('---DRYRUN MSG END---')

        if repo:
            # run it once after writing all messages
            ezpi.run_hook(repo)
        self.send_success(resp, message=f'Sent {len(msgs)} messages')

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
        if action == 'receive':
            self.receive(jdata, resp)
            return

        resp.status = falcon.HTTP_500
        resp.content_type = falcon.MEDIA_TEXT
        resp.text = 'Unknown action: %s\n' % action


parser = ConfigParser(interpolation=ExtendedInterpolation())
cfgfile = os.getenv('CONFIG')
if cfgfile:
    parser.read(cfgfile)
else:
    parser.read_string(DEFAULT_CFG)

gpgbin = parser['main'].get('gpgbin')
if gpgbin:
    patatt.GPGBIN = gpgbin
dburl = parser['main'].get('dburl')
engine = sa.create_engine(dburl)
srl = SendReceiveListener(engine, parser)
app = falcon.App()
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
