#!/usr/bin/env python3
# noinspection PyUnresolvedReferences
import falcon
import os
import sys
import logging
import logging.handlers
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

logger = logging.getLogger('b4-send-receive')
logger.setLevel(logging.DEBUG)


# noinspection PyBroadException, PyMethodMayBeStatic
class SendReceiveListener(object):

    def __init__(self, _engine, _config) -> None:
        self._engine = _engine
        self._config = _config
        # You shouldn't use this in production
        if self._engine.driver == 'pysqlite':
            self._init_sa_db()
        logfile = _config['main'].get('logfile')
        loglevel = _config['main'].get('loglevel', 'info')
        if logfile:
            self._init_logger(logfile, loglevel)

    def _init_logger(self, logfile: str, loglevel: str) -> None:
        global logger
        lch = logging.handlers.WatchedFileHandler(os.path.expanduser(logfile))
        lfmt = logging.Formatter('[%(process)d] %(asctime)s - %(levelname)s - %(message)s')
        lch.setFormatter(lfmt)
        if loglevel == 'critical':
            lch.setLevel(logging.CRITICAL)
        elif loglevel == 'debug':
            lch.setLevel(logging.DEBUG)
        else:
            lch.setLevel(logging.INFO)
        logger.addHandler(lch)

    def _init_sa_db(self) -> None:
        logger.info('Setting up SQLite database')
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
        conn.close()

    def on_get(self, req, resp):  # noqa
        resp.status = falcon.HTTP_200
        resp.content_type = falcon.MEDIA_TEXT
        resp.text = "We don't serve GETs here\n"

    def send_error(self, resp, message: str) -> None:
        resp.status = falcon.HTTP_500
        logger.critical('Returning error: %s', message)
        resp.text = json.dumps({'result': 'error', 'message': message})

    def send_success(self, resp, message: str) -> None:
        resp.status = falcon.HTTP_200
        logger.debug('Returning success: %s', message)
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

    def auth_new(self, jdata, resp) -> None:
        # Is it already authorized?
        conn = self._engine.connect()
        md = sa.MetaData()
        identity = jdata.get('identity')
        selector = jdata.get('selector')
        logger.info('New authentication request for %s/%s', identity, selector)
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
        logger.info('Created new challenge for %s/%s: %s', identity, selector, cstr)
        conn.close()
        smtp, frompair = self.get_smtp()
        cmsg = email.message.EmailMessage()
        fromname, fromaddr = frompair
        if len(fromname):
            cmsg.add_header('From', f'{fromname} <{fromaddr}>')
        else:
            cmsg.add_header('From', fromaddr)
        tpt_subject = self._config['templates']['verify-subject'].strip()
        tpt_body = self._config['templates']['verify-body'].strip()
        signature = self._config['templates']['signature'].strip()
        subject = Template(tpt_subject).safe_substitute({'identity': jdata.get('identity')})
        cmsg.add_header('Subject', subject)
        name = jdata.get('name', 'Anonymous Llama')
        cmsg.add_header('To', f'{name} <{identity}>')
        cmsg.add_header('Message-Id', utils.make_msgid('b4-verify'))
        vals = {
            'name': name,
            'myurl': self._config['main'].get('myurl'),
            'challenge': cstr,
        }
        body = Template(tpt_body).safe_substitute(vals)
        body += '\n-- \n'
        body += Template(signature).safe_substitute(vals)
        body += '\n'
        cmsg.set_payload(body, charset='utf-8')
        cmsg.set_charset('utf-8')
        bdata = cmsg.as_bytes(policy=email.policy.SMTP)
        destaddrs = [identity]
        alwaysbcc = self._config['main'].get('alwayscc')
        if alwaysbcc:
            destaddrs += [x[1] for x in utils.getaddresses(alwaysbcc)]
        logger.info('Sending challenge to %s', identity)
        smtp.sendmail(fromaddr, [identity], bdata)
        smtp.close()
        self.send_success(resp, message=f'Challenge generated and sent to {identity}')

    def validate_message(self, conn, t_auth, bdata, verified=1) -> Tuple[str, str, int]:
        # Returns auth_id of the matching record
        pm = patatt.PatattMessage(bdata)
        if not pm.signed:
            raise patatt.ValidationError('Message is not signed')

        auth_id = identity = selector = pubkey = None
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

        if not auth_id:
            logger.debug('Did not find a matching identity!')
            raise patatt.NoKeyError('No match for this identity')

        logger.debug('Found matching %s/%s with auth_id=%s', identity, selector, auth_id)
        pm.validate(identity, pubkey.encode())

        return identity, selector, auth_id

    def auth_verify(self, jdata, resp) -> None:
        msg = jdata.get('msg')
        if msg.find('\nverify:') < 0:
            self.send_error(resp, message='Invalid verification message')
            return
        conn = self._engine.connect()
        md = sa.MetaData()
        t_auth = sa.Table('auth', md, autoload=True, autoload_with=self._engine)
        bdata = msg.encode()
        try:
            identity, selector, auth_id = self.validate_message(conn, t_auth, bdata, verified=0)
        except Exception as ex:
            self.send_error(resp, message='Signature validation failed: %s' % ex)
            return
        logger.debug('Message validation passed for %s/%s with auth_id=%s', identity, selector, auth_id)

        # Now compare the challenge to what we received
        q = sa.select([t_auth.c.challenge]).where(t_auth.c.auth_id == auth_id)
        rp = conn.execute(q)
        res = rp.fetchall()
        challenge = res[0][0]
        if msg.find(f'\nverify:{challenge}') < 0:
            self.send_error(resp, message='Challenge verification for %s/%s did not match' % (identity, selector))
            return
        logger.info('Successfully verified challenge for %s/%s with auth_id=%s', identity, selector, auth_id)
        q = sa.update(t_auth).where(t_auth.c.auth_id == auth_id).values(challenge=None, verified=1)
        conn.execute(q)
        conn.close()
        self.send_success(resp, message='Challenge verified for %s/%s' % (identity, selector))

    def auth_delete(self, jdata, resp) -> None:
        msg = jdata.get('msg')
        if msg.find('\nauth-delete') < 0:
            self.send_error(resp, message='Invalid key delete message')
            return
        conn = self._engine.connect()
        md = sa.MetaData()
        t_auth = sa.Table('auth', md, autoload=True, autoload_with=self._engine)
        bdata = msg.encode()
        try:
            identity, selector, auth_id = self.validate_message(conn, t_auth, bdata)
        except Exception as ex:
            self.send_error(resp, message='Signature validation failed: %s' % ex)
            return

        logger.info('Deleting record for %s/%s with auth_id=%s', identity, selector, auth_id)
        q = sa.delete(t_auth).where(t_auth.c.auth_id == auth_id)
        conn.execute(q)
        conn.close()
        self.send_success(resp, message='Record deleted for %s/%s' % (identity, selector))

    def clean_header(self, hdrval: str) -> str:
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

    def receive(self, jdata, resp, reflect: bool = False) -> None:
        servicename = self._config['main'].get('myname')
        if not servicename:
            servicename = 'Web Endpoint'
        umsgs = jdata.get('messages')
        if not umsgs:
            self.send_error(resp, message='Missing the messages array')
            return
        logger.debug('Received a request for %s messages', len(umsgs))

        diffre = re.compile(rb'^(---.*\n\+\+\+|GIT binary patch|diff --git \w/\S+ \w/\S+)', flags=re.M | re.I)
        diffstatre = re.compile(rb'^\s*\d+ file.*\d+ (insertion|deletion)', flags=re.M | re.I)

        msgs = list()
        conn = self._engine.connect()
        md = sa.MetaData()
        t_auth = sa.Table('auth', md, autoload=True, autoload_with=self._engine)
        mustdest = self._config['main'].get('mustdest')
        # First, validate all messages
        seenid = identity = selector = validfrom = None
        for umsg in umsgs:
            bdata = umsg.encode()
            try:
                identity, selector, auth_id = self.validate_message(conn, t_auth, bdata)
            except patatt.NoKeyError as ex:  # noqa
                self.send_error(resp, message='No matching record found, maybe you need to auth-verify first?')
                return
            except Exception as ex:
                self.send_error(resp, message='Signature validation failed: %s' % ex)
                return

            # Make sure only a single auth_id is used within a receive session
            if seenid is None:
                seenid = auth_id
            elif seenid != auth_id:
                self.send_error(resp, message='We only support a single signing identity across patch series.')
                return

            msg = email.message_from_bytes(bdata, policy=email.policy.SMTP)
            logger.debug('Checking sanity on message: %s', msg.get('Subject'))
            # Some quick sanity checking:
            # - Subject has to start with [PATCH
            # - Content-type may ONLY be text/plain
            # - Has to include a diff or a diffstat
            passes = True
            subject = self.clean_header(msg.get('Subject', ''))
            if not subject.startswith('[PATCH'):
                passes = False
            if passes:
                cte = msg.get_content_type()
                if cte.lower() != 'text/plain':
                    passes = False
            if passes:
                payload = msg.get_payload(decode=True)
                if not (diffre.search(payload) or diffstatre.search(payload)):
                    passes = False

            if not passes:
                self.send_error(resp, message='This service only accepts patches')
                return

            # Make sure that From, Date, Subject, and Message-Id headers exist
            if not msg.get('From') or not msg.get('Date') or not msg.get('Subject') or not msg.get('Message-Id'):
                self.send_error(resp, message='Message is missing some required headers.')
                return

            # Make sure that From: matches the validated identity. We allow + expansion,
            # such that foo+listname@example.com is allowed for foo@example.com
            allfroms = utils.getaddresses([str(x) for x in msg.get_all('from')])
            # Allow only a single From: address
            if len(allfroms) > 1:
                self.send_error(resp, message='Message may only contain a single From: address.')
                return

            fromaddr = allfroms[0][1]
            if validfrom != fromaddr:
                ldparts = fromaddr.split('@')
                if len(ldparts) != 2:
                    self.send_error(resp, message=f'Invalid address in From: {fromaddr}')
                    return
                lparts = ldparts[0].split('+', maxsplit=1)
                toval = f'{lparts[0]}@{ldparts[1]}'
                if toval != identity:
                    self.send_error(resp, message=f'From header invalid for identity {identity}: {fromaddr}')
                    return
                # usually, all From: addresses will be the same, so use validfrom as a quick bypass
                if validfrom is None:
                    validfrom = fromaddr

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
            msg.add_header('X-Endpoint-Received', f'by {servicename} for {identity}/{selector} with auth_id={auth_id}')
            msgs.append((msg, destaddrs))

        conn.close()
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

        if reflect:
            logger.info('Reflecting %s messages back to %s', len(msgs), identity, selector)
            sentaction = 'Reflected'
        else:
            logger.info('Sending %s messages for %s/%s', len(msgs), identity, selector)
            sentaction = 'Sent'

        for msg, destaddrs in msgs:
            subject = self.clean_header(msg.get('Subject'))
            if repo:
                pmsg = copy.deepcopy(msg)
                if pmsg.get('List-Id'):
                    pmsg.replace_header('List-Id', listid)
                else:
                    pmsg.add_header('List-Id', listid)
                ezpi.add_rfc822(repo, pmsg)
                logger.debug('Wrote %s to public-inbox at %s', subject, repo)

            origfrom = msg.get('From')
            origpair = utils.getaddresses([origfrom])[0]
            origaddr = origpair[1]
            # Does it match one of our domains
            mydomain = False
            for _domain in mydomains:
                if origaddr.endswith(f'@{_domain}'):
                    mydomain = True
                    break
            if mydomain:
                logger.debug('%s matches mydomain, no substitution required', origaddr)
                fromaddr = origaddr
            else:
                logger.debug('%s does not match mydomain, substitution required', origaddr)
                # We can't just send this as-is due to DMARC policies. Therefore, we set
                # Reply-To and X-Original-From.
                fromaddr = frompair[1]
                origname = origpair[0]
                if not origname:
                    origname = origpair[1]
                delim = self._config['main'].get('from-recipient-delimiter', '+')
                if delim and '@' in fromaddr:
                    _flocal, _fdomain = fromaddr.split('@', maxsplit=1)
                    _forig = origaddr.replace('@', '.')
                    fromaddr = f'{_flocal}{delim}{_forig}@{_fdomain}'
                msg.replace_header('From', f'{origname} via {servicename} <{fromaddr}>')

                if msg.get('X-Original-From'):
                    msg.replace_header('X-Original-From', origfrom)
                else:
                    msg.add_header('X-Original-From', origfrom)
                if msg.get('Reply-To'):
                    msg.replace_header('Reply-To', f'<{origpair[1]}>')
                else:
                    msg.add_header('Reply-To', f'<{origpair[1]}>')

                body = msg.get_payload(decode=True)
                # Add a From: header (if there isn't already one), but only if it's a patch
                if diffre.search(body):
                    # Parse it as a message and see if we get a From: header
                    cmsg = email.message_from_bytes(body, policy=emlpolicy)
                    if cmsg.get('From') is None:
                        newbody = 'From: ' + self.clean_header(origfrom) + '\n'
                        if cmsg.get('Subject'):
                            newbody += 'Subject: ' + self.clean_header(cmsg.get('Subject')) + '\n'
                        if cmsg.get('Date'):
                            newbody += 'Date: ' + self.clean_header(cmsg.get('Date')) + '\n'
                        newbody += '\n' + body.decode()
                        msg.set_payload(newbody, charset='utf-8')
                        # If we have non-ascii content in the new body, force CTE to 8bit
                        if msg['Content-Transfer-Encoding'] == '7bit' and not all(ord(char) < 128 for char in newbody):
                            msg.set_charset('utf-8')
                            msg.replace_header('Content-Transfer-Encoding', '8bit')

            if bccaddrs:
                destaddrs.update(bccaddrs)

            if not self._config['main'].getboolean('dryrun'):
                bdata = msg.as_bytes(policy=email.policy.SMTP)
                if reflect:
                    smtp.sendmail(fromaddr, [identity], bdata)
                else:
                    smtp.sendmail(fromaddr, list(destaddrs), bdata)
                logger.info('%s: %s', sentaction, subject)
            else:
                logger.info('---DRYRUN MSG START---')
                logger.info(msg)
                logger.info('---DRYRUN MSG END---')

        smtp.close()
        if repo and not reflect:
            # run it once after writing all messages
            logger.debug('Running public-inbox repo hook (if present)')
            ezpi.run_hook(repo)
        logger.info('%s %s messages for %s/%s', sentaction, len(msgs), identity, selector)
        self.send_success(resp, message=f'{sentaction} {len(msgs)} messages for {identity}/{selector}')

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
        if not action:
            logger.critical('Action not set from %s', req.remote_addr)

        logger.info('Action: %s; from: %s', action, req.remote_addr)
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
        if action == 'reflect':
            self.receive(jdata, resp, reflect=True)
            return

        resp.status = falcon.HTTP_500
        resp.content_type = falcon.MEDIA_TEXT
        resp.text = 'Unknown action: %s\n' % action


parser = ConfigParser(interpolation=ExtendedInterpolation())
cfgfile = os.getenv('CONFIG')
if not cfgfile or not os.path.exists(cfgfile):
    sys.stderr.write('CONFIG env var is not set or is not valid')
    sys.exit(1)

parser.read(cfgfile)

gpgbin = parser['main'].get('gpgbin')
if gpgbin:
    patatt.GPGBIN = gpgbin

dburl = parser['main'].get('dburl')
# By default, recycle db connections after 5 min
db_pool_recycle = parser['main'].getint('dbpoolrecycle', 300)
engine = sa.create_engine(dburl, pool_recycle=db_pool_recycle)
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
