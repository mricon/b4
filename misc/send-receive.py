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
import pathlib
import re
import smtplib
import sqlite3
import sys
import textwrap
import uuid
from configparser import ConfigParser, ExtendedInterpolation
from email import charset, utils
from string import Template
from typing import (
    Generator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Union,
)

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

JSON = Union[None, str, int, float, bool, Sequence['JSON'], Mapping[str, 'JSON']]


class PublicInbox(NamedTuple):
    inbox: str
    listid: str
    notify_file: Optional[str]


def get_public_inbox(config: ConfigParser) -> Optional[PublicInbox]:
    """Read [public-inbox], refusing anything that would quietly not archive."""
    if 'public-inbox' not in config:
        return None
    section = config['public-inbox']
    if section.get('repo'):
        raise ValueError(
            'public-inbox.repo is no longer supported, set public-inbox.inbox '
            'to the v2 inbox directory instead'
        )
    inbox = section.get('inbox')
    if not inbox:
        raise ValueError('public-inbox.inbox is not set')
    inbox = os.path.expanduser(inbox)
    # ezpi creates a missing inbox, so a typo would start a new, empty one
    if not os.path.isdir(os.path.join(inbox, 'git')):
        raise ValueError(f'public-inbox.inbox: {inbox} is not a public-inbox v2 inbox')
    listid = section.get('listid')
    if not listid:
        raise ValueError('public-inbox.listid is not set')
    notify_file = section.get('notify_file')
    if notify_file:
        notify_file = os.path.expanduser(notify_file)
        # Otherwise indexing would quietly stop while archiving goes on
        if not os.path.isdir(os.path.dirname(os.path.abspath(notify_file))):
            raise ValueError(
                f'public-inbox.notify_file: no directory for {notify_file}'
            )
    return PublicInbox(inbox, listid, notify_file or None)


class SendReceiveListener(object):
    def __init__(
        self,
        _dbpath: str,
        _config: ConfigParser,
        _public_inbox: Optional[PublicInbox] = None,
    ) -> None:
        self._dbpath = _dbpath
        self._config = _config
        self._public_inbox = _public_inbox
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
        # Only the identity gets the challenge: alwaysbcc is for patch
        # series, and a copy here would let that mailbox verify any key
        logger.info('Sending challenge to %s', identity)
        try:
            smtp = self.get_smtp()
            try:
                smtp.sendmail(fromaddr, [identity], bdata)
            finally:
                smtp.close()
        except OSError as ex:  # SMTPException is an OSError too
            self.send_error(resp, message=f'Could not send the challenge: {ex}')
            return
        self.send_success(resp, message=f'Challenge generated and sent to {identity}')

    def validate_message(self, bdata: bytes, verified: int = 1) -> Tuple[str, str, int]:
        # Returns auth_id of the matching record
        pm = patatt.PatattMessage(bdata)
        if not pm.signed:
            raise patatt.ValidationError('Message is not signed')

        identity_selector_pairs = [
            (ds.get_field_as_str('i') or '', ds.get_field_as_str('s') or 'default')
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
                if transform == 'encode' and not addr[0].isascii():
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
            if transform != 'encode' or hval.isascii():
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

        # All signatures verified. Prepare every message before any network
        # I/O, so that a message we can't rewrite fails the whole request
        # with nothing sent.
        cfgdomains = self._config['main'].get('mydomains')
        if cfgdomains is not None:
            mydomains = [x.strip() for x in cfgdomains.split(',')]
        else:
            mydomains = list()

        frompair = self.get_frompair()
        bccaddrs = set()
        _bcc = self._config['main'].get('alwaysbcc')
        if _bcc:
            bccaddrs.update([x[1] for x in utils.getaddresses([_bcc])])

        # Reflected messages only go back to the sender
        pi = None if reflect else self._public_inbox

        if reflect:
            logger.info('Reflecting %s messages back to %s', len(msgs), identity)
            sentaction = 'Reflected'
        else:
            logger.info('Sending %s messages for %s/%s', len(msgs), identity, selector)
            sentaction = 'Sent'

        # (subject, envelope from, recipients, data, archive copy)
        tosend: List[Tuple[str, str, List[str], bytes, Optional[bytes]]] = []
        for msg, destaddrs in msgs:
            subject = self.clean_header(msg.get('Subject'))
            # Archive the message as signed, before we rewrite it for SMTP
            pdata = None
            if pi is not None:
                pmsg = copy.deepcopy(msg)
                if pmsg.get('List-Id'):
                    pmsg.replace_header('List-Id', pi.listid)
                else:
                    pmsg.add_header('List-Id', pi.listid)
                pdata = pmsg.as_bytes(policy=emlpolicy)

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
                        bodycs = msg.get_content_charset('utf-8')
                        try:
                            newbody += '\n' + body.decode(bodycs, errors='replace')
                        except LookupError:
                            newbody += '\n' + body.decode('utf-8', errors='replace')
                        # The body is UTF-8 text now, so the old transfer
                        # encoding no longer applies; set_payload() picks
                        # 7bit or 8bit when there is none
                        del msg['Content-Transfer-Encoding']
                        msg.set_payload(newbody, charset='utf-8')

            if reflect:
                recipients = [identity]
            else:
                recipients = list(destaddrs | bccaddrs)
            bdata = self.get_msg_as_bytes(msg, headers='encode')
            tosend.append((subject, fromaddr, recipients, bdata, pdata))

        if self._config['main'].getboolean('dryrun'):
            for _, _, _, bdata, _ in tosend:
                logger.info('---DRYRUN MSG START---')
                logger.info(bdata.decode(errors='replace'))
                logger.info('---DRYRUN MSG END---')
            self.send_success(
                resp, message=f'Dry run of {len(tosend)} messages for {identity}'
            )
            return

        sent = archived = 0
        error = None
        try:
            smtp = self.get_smtp()
            try:
                for subject, fromaddr, recipients, bdata, pdata in tosend:
                    smtp.sendmail(fromaddr, recipients, bdata)
                    sent += 1
                    logger.info('%s: %s', sentaction, subject)
                    # Only archive what actually went out
                    if pi is not None and pdata is not None:
                        archived += self.archive(pi, subject, pdata)
            finally:
                smtp.close()
        except OSError as ex:  # SMTPException is an OSError too
            error = ex

        if pi is not None and archived:
            # Once per batch, after all messages are written
            self.notify(pi)
        if error is not None:
            self.send_error(
                resp,
                message=f'{sentaction} {sent} of {len(tosend)} messages for'
                f' {identity}/{selector} before failing: {error}',
            )
            return
        logger.info(
            '%s %s messages for %s/%s', sentaction, len(msgs), identity, selector
        )
        self.send_success(
            resp, message=f'{sentaction} {len(msgs)} messages for {identity}/{selector}'
        )

    def archive(self, pi: PublicInbox, subject: str, pdata: bytes) -> bool:
        try:
            # The v2 writer takes inbox.lock, so public-inbox-index and
            # -purge never run at the same time, and it rotates epochs
            ezpi.add_rfc822_v2(pi.inbox, pdata)
        except (RuntimeError, OSError, ValueError) as ex:
            # The message already went out, so a missing archive copy must
            # not stop the rest of the series
            logger.critical('Could not archive %s: %s', subject, ex)
            return False
        logger.debug('Wrote %s to public-inbox at %s', subject, pi.inbox)
        return True

    def notify(self, pi: PublicInbox) -> None:
        if not pi.notify_file:
            return
        try:
            # Updating the timestamps is enough for systemd's PathChanged=
            pathlib.Path(pi.notify_file).touch()
        except OSError as ex:
            # Not an error for the client: everything is sent and archived,
            # and it must not send the series again
            logger.critical('Could not touch %s: %s', pi.notify_file, ex)

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
            logger.info('Action not set from %s', req.remote_addr)
            self.send_error(resp, message='Action not set')
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
try:
    public_inbox = get_public_inbox(parser)
except ValueError as ex:
    sys.stderr.write(f'{ex}\n')
    sys.exit(1)
srl = SendReceiveListener(dbpath, parser, public_inbox)
app = falcon.App()
mp = os.getenv('MOUNTPOINT', '/_b4_submit')
app.add_route(mp, srl)


if __name__ == '__main__':
    from wsgiref.simple_server import make_server

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(message)s')
    ch.setFormatter(formatter)
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)

    with make_server('', 8000, app) as httpd:
        logger.info('Serving on port 8000...')

        # Serve until process is killed
        httpd.serve_forever()
