#!/usr/bin/env python3

import contextlib
import copy
import email
import email.header
import email.message
import email.policy
import email.quoprimime
import email.utils
import json
import logging
import logging.handlers
import os
import re
import smtplib
import sqlite3
import sys
import textwrap
import uuid
from configparser import ConfigParser, ExtendedInterpolation
from email import charset, utils
from string import Template
from typing import Generator, List, Mapping, Optional, Sequence, Tuple, Union

import ezpi
import falcon

import patatt

charset.add_charset('utf-8', None)
emlpolicy = email.policy.EmailPolicy(utf8=True, cte_type='8bit', max_line_length=None)

qspecials = re.compile(r'[()<>@,:;.\"\[\]]')

DB_VERSION = 1

# IF NOT EXISTS lets several uwsgi workers initialize a new file at the
# same time. AUTOINCREMENT never reuses an auth_id, because published
# X-Endpoint-Received headers refer to it. send-receive-migrate.py
# creates the same schema.
SCHEMA = """
CREATE TABLE IF NOT EXISTS auth (
    auth_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    identity TEXT NOT NULL,
    selector TEXT NOT NULL,
    pubkey TEXT NOT NULL,
    challenge TEXT,
    verified INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_selector ON auth (identity, selector);
"""

logger = logging.getLogger('b4-send-receive')
logger.setLevel(logging.DEBUG)

JSON = Union[str, int, float, bool, Sequence['JSON'], Mapping[str, 'JSON']]


class SendReceiveListener(object):
    def __init__(self, _dbpath: str, _config: ConfigParser) -> None:
        self._dbpath = _dbpath
        self._config = _config
        logfile = _config['main'].get('logfile')
        loglevel = _config['main'].get('loglevel', 'info')
        if logfile:
            self._init_logger(logfile, loglevel)
        self._init_db()

    def _init_logger(self, logfile: str, loglevel: str) -> None:
        global logger
        lch = logging.handlers.WatchedFileHandler(os.path.expanduser(logfile))
        lfmt = logging.Formatter(
            '[%(process)d] %(asctime)s - %(levelname)s - %(message)s'
        )
        lch.setFormatter(lfmt)
        if loglevel == 'critical':
            lch.setLevel(logging.CRITICAL)
        elif loglevel == 'debug':
            lch.setLevel(logging.DEBUG)
        else:
            lch.setLevel(logging.INFO)
        logger.addHandler(lch)

    @contextlib.contextmanager
    def _db(self) -> Generator[sqlite3.Connection, None, None]:
        # One connection per request, because uwsgi runs several processes
        # and threads against the same file. The timeout makes a worker
        # wait for a lock instead of failing at once.
        conn = sqlite3.connect(self._dbpath, timeout=30)
        try:
            # sqlite3's own context manager commits or rolls back, but
            # does not close
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._db() as conn:
            # WAL lets readers work while another worker writes. The mode
            # is stored in the file, so this only does work the first time.
            conn.execute('PRAGMA journal_mode = WAL')
            dbver = conn.execute('PRAGMA user_version').fetchone()[0]
            if dbver > DB_VERSION:
                raise RuntimeError(
                    f'Database {self._dbpath} is version {dbver}, '
                    f'we only know version {DB_VERSION}'
                )
            if dbver < DB_VERSION:
                logger.info('Setting up SQLite database at %s', self._dbpath)
                conn.executescript(SCHEMA)
                conn.execute(f'PRAGMA user_version = {DB_VERSION}')

    def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        resp.status = falcon.HTTP_200
        resp.content_type = falcon.MEDIA_TEXT
        resp.text = "We don't serve GETs here\n"

    def send_error(self, resp: falcon.Response, message: str) -> None:
        resp.status = falcon.HTTP_500
        logger.critical('Returning error: %s', message)
        resp.text = json.dumps({'result': 'error', 'message': message})

    def send_success(self, resp: falcon.Response, message: str) -> None:
        resp.status = falcon.HTTP_200
        logger.debug('Returning success: %s', message)
        resp.text = json.dumps({'result': 'success', 'message': message})

    def get_frompair(self) -> Tuple[str, str]:
        afrom = self._config['sendemail'].get('from')
        assert afrom is not None
        return utils.getaddresses([afrom])[0]

    def get_smtp(self) -> smtplib.SMTP:
        sconfig = self._config['sendemail']
        server = sconfig.get('smtpserver', 'localhost')
        port = sconfig.getint('smtpserverport', 0)
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
                raise smtplib.SMTPException(
                    'Unclear what to do with smtpencryption=%s' % encryption
                )

            # If we got to this point, we should do authentication.
            auser = sconfig.get('smtpuser')
            apass = sconfig.get('smtppass')
            if auser and apass:
                # Let any exceptions bubble up
                smtp.login(auser, apass)
        else:
            # We assume you know what you're doing if you don't need encryption
            smtp = smtplib.SMTP(server, port)

        return smtp

    def auth_new(self, jdata: Mapping[str, JSON], resp: falcon.Response) -> None:
        identity: Optional[JSON] = jdata.get('identity')
        selector: Optional[JSON] = jdata.get('selector')
        pubkey: Optional[JSON] = jdata.get('pubkey')
        if (
            not isinstance(identity, str)
            or not isinstance(selector, str)
            or not isinstance(pubkey, str)
        ):
            self.send_error(resp, message='Invalid authentication request')
            return
        logger.info('New authentication request for %s/%s', identity, selector)
        cstr = str(uuid.uuid4())
        with self._db() as conn:
            # Replace a pending challenge, but never a verified key. A single
            # statement means concurrent requests for the same pair can't race.
            cur = conn.execute(
                'INSERT INTO auth (identity, selector, pubkey, challenge, verified)'
                ' VALUES (?, ?, ?, ?, 0)'
                ' ON CONFLICT (identity, selector) DO UPDATE'
                ' SET created = CURRENT_TIMESTAMP, pubkey = excluded.pubkey,'
                ' challenge = excluded.challenge'
                ' WHERE verified = 0',
                (identity, selector, pubkey, cstr),
            )
            created = cur.rowcount > 0
        if not created:
            self.send_error(
                resp, message='i=%s;s=%s is already authorized' % (identity, selector)
            )
            return
        logger.info('Created new challenge for %s/%s: %s', identity, selector, cstr)
        smtp = self.get_smtp()
        cmsg = email.message.EmailMessage()
        fromname, fromaddr = self.get_frompair()
        if len(fromname):
            cmsg.add_header('From', f'{fromname} <{fromaddr}>')
        else:
            cmsg.add_header('From', fromaddr)
        tpt_subject = self._config['templates']['verify-subject'].strip()
        tpt_body = self._config['templates']['verify-body'].strip()
        signature = self._config['templates']['signature'].strip()
        subject = Template(tpt_subject).safe_substitute(
            {'identity': jdata.get('identity')}
        )
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
        bdata = self.get_msg_as_bytes(cmsg, headers='encode')
        destaddrs = [identity]
        alwaysbcc = self._config['main'].get('alwayscc')
        if alwaysbcc:
            destaddrs += [x[1] for x in utils.getaddresses([alwaysbcc])]
        logger.info('Sending challenge to %s', identity)
        smtp.sendmail(fromaddr, [identity], bdata)
        smtp.close()
        self.send_success(resp, message=f'Challenge generated and sent to {identity}')

    def validate_message(self, bdata: bytes, verified: int = 1) -> Tuple[str, str, int]:
        # Returns auth_id of the matching record
        pm = patatt.PatattMessage(bdata)
        if not pm.signed:
            raise patatt.ValidationError('Message is not signed')

        identity_selector_pairs = [
            (
                ''
                if (i := ds.get_field('i')) is None
                else i.decode()
                if isinstance(i, bytes)
                else i,
                'default'
                if (s := ds.get_field('s')) is None
                else s.decode()
                if isinstance(s, bytes)
                else s,
            )
            for ds in pm.get_sigs()
        ]
        logger.debug('is_pairs=%s', identity_selector_pairs)
        placeholders = ', '.join(['(?, ?)'] * len(identity_selector_pairs))
        params = [x for pair in identity_selector_pairs for x in pair]
        with self._db() as conn:
            rows = conn.execute(
                'SELECT identity, selector, auth_id, pubkey FROM auth'
                f' WHERE (identity, selector) IN (VALUES {placeholders})'
                ' AND verified = ?',
                (*params, verified),
            ).fetchall()
        if not rows:
            logger.debug('Did not find a matching identity!')
            raise patatt.NoKeyError('No match for this identity')

        identity, selector, auth_id, pubkey = rows[0]

        logger.debug(
            'Found matching %s/%s with auth_id=%s', identity, selector, auth_id
        )
        pm.validate(identity, pubkey.encode())

        return identity, selector, auth_id

    def auth_verify(self, jdata: Mapping[str, JSON], resp: falcon.Response) -> None:
        msg = jdata.get('msg')
        if not isinstance(msg, str) or msg.find('\nverify:') < 0:
            self.send_error(resp, message='Invalid verification message')
            return
        bdata = msg.encode()
        try:
            identity, selector, auth_id = self.validate_message(bdata, verified=0)
        except Exception as ex:
            self.send_error(resp, message='Signature validation failed: %s' % ex)
            return
        logger.debug(
            'Message validation passed for %s/%s with auth_id=%s',
            identity,
            selector,
            auth_id,
        )

        with self._db() as conn:
            # Now compare the challenge to what we received
            challenge = conn.execute(
                'SELECT challenge FROM auth WHERE auth_id = ?', (auth_id,)
            ).fetchone()[0]
            verified = False
            if msg.find(f'\nverify:{challenge}') >= 0:
                # A new auth-new for this pair replaces the pubkey and the
                # challenge but keeps the auth_id, so match on the challenge
                # to never verify a key that was swapped in meanwhile.
                cur = conn.execute(
                    'UPDATE auth SET challenge = NULL, verified = 1'
                    ' WHERE auth_id = ? AND challenge = ?',
                    (auth_id, challenge),
                )
                verified = cur.rowcount > 0
        if not verified:
            self.send_error(
                resp,
                message='Challenge verification for %s/%s did not match'
                % (identity, selector),
            )
            return
        logger.info(
            'Successfully verified challenge for %s/%s with auth_id=%s',
            identity,
            selector,
            auth_id,
        )
        self.send_success(
            resp, message='Challenge verified for %s/%s' % (identity, selector)
        )

    def auth_delete(self, jdata: Mapping[str, JSON], resp: falcon.Response) -> None:
        msg = jdata.get('msg')
        if not isinstance(msg, str) or msg.find('\nauth-delete') < 0:
            self.send_error(resp, message='Invalid key delete message')
            return
        bdata = msg.encode()
        try:
            identity, selector, auth_id = self.validate_message(bdata)
        except Exception as ex:
            self.send_error(resp, message='Signature validation failed: %s' % ex)
            return

        logger.info(
            'Deleting record for %s/%s with auth_id=%s', identity, selector, auth_id
        )
        with self._db() as conn:
            conn.execute('DELETE FROM auth WHERE auth_id = ?', (auth_id,))
        self.send_success(
            resp, message='Record deleted for %s/%s' % (identity, selector)
        )

    def clean_header(self, hdrval: Optional[str]) -> str:
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

    def format_addrs(self, pairs: List[Tuple[str, str]], clean: bool = True) -> str:
        addrs = list()
        for pair in pairs:
            if pair[0] == pair[1]:
                addrs.append(pair[1])
                continue
            if clean:
                # Remove any quoted-printable header junk from the name
                pair = (self.clean_header(pair[0]), pair[1])
            # Work around https://github.com/python/cpython/issues/100900
            if (
                not pair[0].startswith('=?')
                and not pair[0].startswith('"')
                and qspecials.search(pair[0])
            ):
                quoted = email.utils.quote(pair[0])
                addrs.append(f'"{quoted}" <{pair[1]}>')
                continue
            addrs.append(email.utils.formataddr(pair))
        return ', '.join(addrs)

    def isascii(self, strval: str) -> bool:
        try:
            return strval.isascii()
        except AttributeError:
            return all([ord(c) < 128 for c in strval])

    def wrap_header(
        self,
        hdr: Tuple[str, str],
        width: int = 75,
        nl: str = '\r\n',
        transform: str = 'preserve',
    ) -> bytes:
        hname, hval = hdr
        if hname.lower() in ('to', 'cc', 'from', 'x-original-from'):
            _parts = [f'{hname}: ']
            first = True
            for addr in email.utils.getaddresses([hval]):
                if transform == 'encode' and not self.isascii(addr[0]):
                    addr = (
                        email.quoprimime.header_encode(
                            addr[0].encode(), charset='utf-8'
                        ),
                        addr[1],
                    )
                    qp = self.format_addrs([addr], clean=False)
                elif transform == 'decode':
                    qp = self.format_addrs([addr], clean=True)
                else:
                    qp = self.format_addrs([addr], clean=False)
                # See if there is enough room on the existing line
                if first:
                    _parts[-1] += qp
                    first = False
                    continue
                if len(_parts[-1] + ', ' + qp) > width:
                    _parts[-1] += ', '
                    _parts.append(qp)
                    continue
                _parts[-1] += ', ' + qp
        else:
            if transform == 'decode' and hval.find('?=') >= 0:
                hdata = f'{hname}: ' + self.clean_header(hval)
            else:
                hdata = f'{hname}: {hval}'
            if transform != 'encode' or self.isascii(hval):
                if len(hdata) <= width:
                    return hdata.encode()
                # Use simple textwrap, with a small trick that ensures that long non-breakable
                # strings don't show up on the next line from the bare header
                hdata = hdata.replace(': ', ':_', 1)
                wrapped = textwrap.wrap(
                    hdata,
                    break_long_words=False,
                    break_on_hyphens=False,
                    subsequent_indent=' ',
                    width=width,
                )
                return nl.join(wrapped).replace(':_', ': ', 1).encode()

            qp = f'{hname}: ' + email.quoprimime.header_encode(
                hval.encode(), charset='utf-8'
            )
            # is it longer than width?
            if len(qp) <= width:
                return qp.encode()

            _parts = list()
            while len(qp) > width:
                wrapat = width - 2
                if len(_parts):
                    # Also allow for the ' ' at the front on continuation lines
                    wrapat -= 1
                # Make sure we don't break on a =XX escape sequence
                while '=' in qp[wrapat - 2 : wrapat]:
                    wrapat -= 1
                _parts.append(qp[:wrapat] + '?=')
                qp = '=?utf-8?q?' + qp[wrapat:]
            _parts.append(qp)
        return f'{nl} '.join(_parts).encode()

    def get_msg_as_bytes(
        self, msg: email.message.Message, nl: str = '\r\n', headers: str = 'preserve'
    ) -> bytes:
        bdata = b''
        for hname, hval in msg.items():
            bdata += (
                self.wrap_header((hname, str(hval)), nl=nl, transform=headers)
                + nl.encode()
            )
        bdata += nl.encode()
        payload = msg.get_payload(decode=True)
        assert isinstance(payload, bytes)
        for bline in payload.split(b'\n'):
            bdata += re.sub(rb'[\r\n]*$', b'', bline) + nl.encode()
        return bdata

    def receive(
        self,
        jdata: Mapping[str, JSON],
        resp: falcon.Response,
        reflect: bool = False,
    ) -> None:
        servicename = self._config['main'].get('myname')
        if not servicename:
            servicename = 'Web Endpoint'
        umsgs = jdata.get('messages')
        if not umsgs:
            self.send_error(resp, message='Missing the messages array')
            return
        if not isinstance(umsgs, Sequence):
            self.send_error(resp, message='Invalid messages array')
            return
        logger.debug('Received a request for %s messages', len(umsgs))

        diffre = re.compile(
            rb'^(---.*\n\+\+\+|GIT binary patch|diff --git \w/\S+ \w/\S+)',
            flags=re.M | re.I,
        )
        diffstatre = re.compile(
            rb'^\s*\d+ file.*\d+ (insertion|deletion)', flags=re.M | re.I
        )

        msgs = list()
        mustdest = self._config['main'].get('mustdest')
        # First, validate all messages
        seenid = identity = selector = validfrom = None
        for umsg in umsgs:
            if not isinstance(umsg, str):
                self.send_error(resp, message='Invalid message payload')
                return
            bdata = umsg.encode()
            try:
                identity, selector, auth_id = self.validate_message(bdata)
            except patatt.NoKeyError:
                self.send_error(
                    resp, message='No matching key, please complete web auth first.'
                )
                return
            except Exception as ex:
                self.send_error(resp, message='Signature validation failed: %s' % ex)
                return

            # Make sure only a single auth_id is used within a receive session
            if seenid is None:
                seenid = auth_id
            elif seenid != auth_id:
                self.send_error(
                    resp,
                    message='We only support a single signing identity across patch series.',
                )
                return

            msg = email.message_from_bytes(bdata, policy=emlpolicy)
            logger.debug('Checking sanity on message: %s', msg.get('Subject'))
            # Some quick sanity checking:
            # - Subject must include [PATCH and have only bracketed prefixes before
            # - Content-type may ONLY be text/plain
            # - Has to include a diff or a diffstat
            passes = True
            subject = self.clean_header(msg.get('Subject', ''))
            if not re.match(r'(\[[^]]+\])*\[PATCH', subject):
                passes = False
            if passes:
                cte = msg.get_content_type()
                if cte.lower() != 'text/plain':
                    passes = False
            if passes:
                payload = msg.get_payload(decode=True)
                assert isinstance(payload, bytes)
                if not (diffre.search(payload) or diffstatre.search(payload)):
                    passes = False

            if not passes:
                self.send_error(resp, message='This service only accepts patches')
                return

            # Make sure that From, Date, Subject, and Message-Id headers exist
            if (
                not msg.get('From')
                or not msg.get('Date')
                or not msg.get('Subject')
                or not msg.get('Message-Id')
            ):
                self.send_error(
                    resp, message='Message is missing some required headers.'
                )
                return

            # Make sure that From: matches the validated identity. We allow + expansion,
            # such that foo+listname@example.com is allowed for foo@example.com
            froms = msg.get_all('from')
            assert froms is not None
            allfroms = utils.getaddresses(froms)
            # Allow only a single From: address
            if len(allfroms) > 1:
                self.send_error(
                    resp, message='Message may only contain a single From: address.'
                )
                return

            fromaddr = allfroms[0][1]
            if validfrom != fromaddr:
                ldparts = fromaddr.split('@')
                if len(ldparts) != 2:
                    self.send_error(
                        resp, message=f'Invalid address in From: {fromaddr}'
                    )
                    return
                lparts = ldparts[0].split('+', maxsplit=1)
                toval = f'{lparts[0]}@{ldparts[1]}'
                if toval != identity:
                    self.send_error(
                        resp,
                        message=f'From header invalid for identity {identity}: {fromaddr}',
                    )
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
                    self.send_error(
                        resp,
                        message='Destinations must include a mailing list we recognize.',
                    )
                    return
            msg.add_header(
                'X-Endpoint-Received',
                f'by {servicename} for {identity}/{selector} with auth_id={auth_id}',
            )
            msgs.append((msg, destaddrs))

        # Must be the case if the loop above runs at least once, and we check
        # that umsgs is truthy (not empty).
        assert identity is not None

        # All signatures verified. Prepare messages for sending.
        cfgdomains = self._config['main'].get('mydomains')
        if cfgdomains is not None:
            mydomains = [x.strip() for x in cfgdomains.split(',')]
        else:
            mydomains = list()

        smtp = self.get_smtp()
        frompair = self.get_frompair()
        bccaddrs = set()
        _bcc = self._config['main'].get('alwaysbcc')
        if _bcc:
            bccaddrs.update([x[1] for x in utils.getaddresses([_bcc])])

        repo_and_listid = None
        if 'public-inbox' in self._config and not reflect:
            public_inbox = self._config['public-inbox']
            if (repo := public_inbox.get('repo')) is not None and os.path.isdir(repo):
                if (listid := public_inbox.get('listid')) is not None:
                    repo_and_listid = (repo, listid)

        if reflect:
            logger.info('Reflecting %s messages back to %s', len(msgs), identity)
            sentaction = 'Reflected'
        else:
            logger.info('Sending %s messages for %s/%s', len(msgs), identity, selector)
            sentaction = 'Sent'

        for msg, destaddrs in msgs:
            subject = self.clean_header(msg.get('Subject'))
            if repo_and_listid is not None:
                repo, listid = repo_and_listid
                pmsg = copy.deepcopy(msg)
                if pmsg.get('List-Id'):
                    pmsg.replace_header('List-Id', listid)
                else:
                    pmsg.add_header('List-Id', listid)
                ezpi.add_rfc822(repo, pmsg)
                logger.debug('Wrote %s to public-inbox at %s', subject, repo)

            origfrom = msg.get('From')
            assert origfrom is not None
            origpair = utils.getaddresses([origfrom])[0]
            assert origpair is not None
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
                logger.debug(
                    '%s does not match mydomain, substitution required', origaddr
                )
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
                assert isinstance(body, bytes)
                # Add a From: header (if there isn't already one), but only if it's a patch
                if diffre.search(body):
                    # Parse it as a message and see if we get a From: header
                    cmsg = email.message_from_bytes(body, policy=emlpolicy)
                    if cmsg.get('From') is None:
                        newbody = 'From: ' + self.clean_header(origfrom) + '\n'
                        if cmsg.get('Subject'):
                            newbody += (
                                'Subject: '
                                + self.clean_header(cmsg.get('Subject'))
                                + '\n'
                            )
                        if cmsg.get('Date'):
                            newbody += (
                                'Date: ' + self.clean_header(cmsg.get('Date')) + '\n'
                            )
                        newbody += '\n' + body.decode()
                        msg.set_payload(newbody, charset='utf-8')
                        # If we have non-ascii content in the new body, force CTE to 8bit
                        if msg['Content-Transfer-Encoding'] == '7bit' and not all(
                            ord(char) < 128 for char in newbody
                        ):
                            msg.set_charset('utf-8')
                            msg.replace_header('Content-Transfer-Encoding', '8bit')

            if bccaddrs:
                destaddrs.update(bccaddrs)

            if not self._config['main'].getboolean('dryrun'):
                bdata = self.get_msg_as_bytes(msg, headers='encode')
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
        if repo_and_listid is not None:
            repo, _ = repo_and_listid
            # run it once after writing all messages
            logger.debug('Running public-inbox repo hook (if present)')
            ezpi.run_hook(repo)
        logger.info(
            '%s %s messages for %s/%s', sentaction, len(msgs), identity, selector
        )
        self.send_success(
            resp, message=f'{sentaction} {len(msgs)} messages for {identity}/{selector}'
        )

    def on_post(self, req: falcon.Request, resp: falcon.Response) -> None:
        if not req.content_length:
            resp.status = falcon.HTTP_500
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = 'Payload required\n'
            return
        raw = req.bounded_stream.read()
        try:
            jdata: JSON = json.loads(raw)
        except Exception:
            resp.status = falcon.HTTP_500
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = 'Failed to parse the request\n'
            return
        # TODO(https://github.com/astral-sh/ruff/pull/24458): remove this when ty understands conditional walrus.
        action = None
        if not isinstance(jdata, Mapping) or (action := jdata.get('action')) is None:
            logger.critical('Action not set from %s', req.remote_addr)
            return

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

dbpath = parser['main'].get('dbpath')
if not dbpath:
    if parser['main'].get('dburl'):
        sys.stderr.write(
            'main.dburl is no longer supported, convert the database with '
            'send-receive-migrate.py and set main.dbpath\n'
        )
    else:
        sys.stderr.write('main.dbpath is not set in CONFIG\n')
    sys.exit(1)
if dbpath == ':memory:':
    # Every request opens its own connection, and so would get its own
    # empty database
    sys.stderr.write('main.dbpath must be a file, not :memory:\n')
    sys.exit(1)
dbpath = os.path.expanduser(dbpath)
os.makedirs(os.path.dirname(os.path.abspath(dbpath)), exist_ok=True)
srl = SendReceiveListener(dbpath, parser)
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
