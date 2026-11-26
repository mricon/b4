#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Durable SMTP submissions. Callers hold the series lock through rerolling.

Messages are stored after signing and are never rendered again on resume.
An in-flight marker reaches disk before SMTP DATA can be accepted. If the
outcome cannot be recorded, another invocation must reconcile it explicitly.
"""

import hashlib
import json
import os
import re
import shutil
import smtplib
import tempfile
from dataclasses import asdict, dataclass, field
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import b4


class RetryableSendError(RuntimeError):
    """A transport failure with durably recorded, unambiguous progress."""


def _sync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write(path: Path, data: bytes) -> None:
    """Replace a snapshot durably; a failed update leaves the old one usable."""
    fd, temporary = tempfile.mkstemp(prefix='.tmp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_dir(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def series_directory(change_id: str) -> Path:
    common = b4.git_get_common_dir(b4.git_get_toplevel())
    if common is None:
        raise RuntimeError('Cannot locate the repository for send state')
    # Neither a branch name nor an imported change-id is a pathname.
    key = hashlib.sha256(change_id.encode()).hexdigest()
    return Path(common) / 'b4-send' / key


def _check_text(value: object) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError('Invalid send metadata')


def _check_addresses(value: object) -> None:
    if (
        not isinstance(value, list)
        or any(
            not isinstance(addr, str) or not addr or any(c in addr for c in '\r\n')
            for addr in value
        )
        or len(set(value)) != len(value)
    ):
        raise ValueError('Invalid recipient list')


@dataclass
class Message:
    message_id: str
    subject: str
    recipients: List[str]
    sha256: str
    accepted: List[str] = field(default_factory=list)
    # Refused for good (5xx) while others accepted; asking again is pointless.
    refused: List[str] = field(default_factory=list)

    def pending(self) -> List[str]:
        done = set(self.accepted) | set(self.refused)
        return [addr for addr in self.recipients if addr not in done]


@dataclass
class State:
    change_id: str
    revision: int
    branch: str
    head: str
    tree: str
    cover_hash: str
    tag_message: str
    cover_message_id: str
    fromaddr: str
    messages: List[Message]
    schema: int = 1
    in_flight: Optional[int] = None
    finished: bool = False
    next_cover: Optional[str] = None
    next_tracking: Optional[Dict[str, Any]] = None
    partial_reroll_hash: Optional[str] = None
    # Explicit Bcc destinations can override email-exclude at submission.
    bcc_overrides: Dict[str, List[str]] = field(default_factory=dict)


class SendSession:
    def __init__(self, directory: Path, state: State) -> None:
        self.directory = directory
        self.state = state

    @classmethod
    def prepare(
        cls,
        directory: Path,
        state: State,
        messages: Sequence[Tuple[Set[str], bytes, b4.LoreSubject]],
    ) -> 'SendSession':
        if (directory / 'state.json').exists():
            if not cls.load(directory).state.finished:
                raise RuntimeError(f'A send is already recorded in {directory}')
            cls.load(directory).discard()
        # Keep signed mail and recipient lists private, including in shared repos.
        for path in (directory.parent.parent, directory.parent, directory):
            path.mkdir(mode=0o700, exist_ok=True)
            _sync_dir(path.parent)
        session = cls(directory, state)
        for index, (recipients, data, subject) in enumerate(messages):
            data = re.sub(rb'\r\n|\n|\r(?!\n)', b'\r\n', data)
            msg = BytesParser(policy=b4.emlpolicy).parsebytes(data, headersonly=True)
            message_id = b4.LoreMessage.get_clean_msgid(msg)
            if not message_id or not recipients or msg.get('Bcc'):
                raise RuntimeError(
                    'Cannot save a message without an ID/recipients or with Bcc'
                )
            state.messages.append(
                Message(
                    message_id=message_id,
                    subject=subject.full_subject,
                    recipients=sorted(recipients),
                    sha256=hashlib.sha256(data).hexdigest(),
                )
            )
            _write(session.message_path(index), data)
        session.validate()
        session.save()
        return session

    @classmethod
    def load(cls, directory: Path) -> 'SendSession':
        try:
            data = json.loads((directory / 'state.json').read_text())
            data['messages'] = [Message(**entry) for entry in data['messages']]
            session = cls(directory, State(**data))
            session.validate()
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise RuntimeError(f'Cannot read send state in {directory}: {exc}') from exc
        return session

    def validate(self) -> None:
        state = self.state
        if state.schema != 1 or not state.messages or type(state.revision) is not int:
            raise ValueError('Invalid send state version or message list')
        if state.revision < 1 or type(state.finished) is not bool:
            raise ValueError('Invalid send revision/status')
        if type(state.bcc_overrides) is not dict:
            raise ValueError('Invalid Bcc exclusion overrides')
        _check_addresses(list(state.bcc_overrides))
        for patterns in state.bcc_overrides.values():
            _check_addresses(patterns)
        for value in (
            state.change_id,
            state.branch,
            state.head,
            state.tree,
            state.cover_hash,
            state.tag_message,
            state.cover_message_id,
            state.fromaddr,
        ):
            _check_text(value)
        seen: Set[str] = set()
        for index, message in enumerate(state.messages):
            for value in (message.subject, message.sha256, message.message_id):
                _check_text(value)
            if message.message_id in seen:
                raise ValueError('Invalid or repeated Message-ID')
            seen.add(message.message_id)
            for addresses in (message.recipients, message.accepted, message.refused):
                _check_addresses(addresses)
            answered = message.accepted + message.refused
            if (
                not message.recipients
                or not set(answered) <= set(message.recipients)
                or len(set(answered)) != len(answered)
            ):
                raise ValueError('Recipient results do not match the submission')
            msg = BytesParser(policy=b4.emlpolicy).parsebytes(
                self.message_bytes(index), headersonly=True
            )
            if b4.LoreMessage.get_clean_msgid(msg) != message.message_id:
                raise ValueError('Saved Message-ID differs from the wire message')
        if state.cover_message_id != state.messages[0].message_id:
            raise ValueError('Submission root differs from the saved first message')
        if state.in_flight is not None:
            if (
                type(state.in_flight) is not int
                or not 0 <= state.in_flight < len(state.messages)
                or not state.messages[state.in_flight].pending()
            ):
                raise ValueError('Invalid in-flight delivery')
        if state.finished and (not self.delivered() or state.in_flight is not None):
            raise ValueError('Unfinished delivery marked complete')
        if any(
            value is not None
            for value in (
                state.next_cover,
                state.next_tracking,
                state.partial_reroll_hash,
            )
        ):
            _check_text(state.next_cover)
            _check_text(state.partial_reroll_hash)
            if not isinstance(state.next_tracking, dict) or not self.delivered():
                raise ValueError('Invalid saved reroll')

    def message_path(self, index: int) -> Path:
        return self.directory / f'{index:04d}.eml'

    def message_bytes(self, index: int) -> bytes:
        data = self.message_path(index).read_bytes()
        if hashlib.sha256(data).hexdigest() != self.state.messages[index].sha256:
            raise ValueError(f'Saved message changed: {self.message_path(index)}')
        return data

    def save(self) -> None:
        _write(
            self.directory / 'state.json',
            (json.dumps(asdict(self.state), indent=2) + '\n').encode(),
        )

    def discard(self) -> None:
        """Remove the record once nothing in it can be needed again."""
        # Without state.json, a half-removed directory is no longer a record.
        (self.directory / 'state.json').unlink(missing_ok=True)
        shutil.rmtree(self.directory)

    def delivered(self) -> bool:
        return all(not message.pending() for message in self.state.messages)

    def untouched(self) -> bool:
        """Whether no recipient can have received anything yet."""
        return self.state.in_flight is None and not any(
            message.accepted or message.refused for message in self.state.messages
        )

    def resolve(self, outcome: str) -> None:
        index = self.state.in_flight
        if index is None:
            raise RuntimeError('There is no uncertain delivery to resolve')
        if outcome not in ('sent', 'unsent'):
            raise ValueError('Invalid delivery outcome')
        if outcome == 'sent':
            message = self.state.messages[index]
            message.accepted = [
                addr for addr in message.recipients if addr not in message.refused
            ]
        self.state.in_flight = None
        self.save()

    def send(self, smtp: b4.SMTPConnector) -> None:
        if self.state.in_flight is not None:
            message = self.state.messages[self.state.in_flight]
            raise RuntimeError(
                f'Delivery of <{message.message_id}> is uncertain. Check the server/list, '
                'then use --resume --resolve-uncertain=sent or =unsent.'
            )
        # Recheck every saved payload before connecting, not halfway through sending.
        self.validate()
        if self.delivered():
            return
        try:
            conn = smtp()
        except Exception as exc:
            raise RetryableSendError(
                f'Failed to connect to the smtp server: {exc}'
            ) from exc
        # Recipients to ask again later; they do not hold up other messages.
        deferred: Set[str] = set()
        try:
            for index, message in enumerate(self.state.messages):
                remaining = message.pending()
                if not remaining:
                    continue
                data = self.message_bytes(index)
                b4.logger.info(
                    '  %s (%d pending recipients)', message.subject, len(remaining)
                )
                self.state.in_flight = index
                self.save()
                try:
                    refused = conn.sendmail(self.state.fromaddr, remaining, data)
                except smtplib.SMTPRecipientsRefused as exc:
                    refused = exc.recipients
                    if not _can_defer_refusal(refused, remaining, message.accepted):
                        self.state.in_flight = None
                        self.save()
                        raise RetryableSendError(
                            f'SMTP rejected the message: {exc}'
                        ) from exc
                except (
                    smtplib.SMTPSenderRefused,
                    # Both are raised before the sender is even named.
                    smtplib.SMTPHeloError,
                    smtplib.SMTPNotSupportedError,
                ) as exc:
                    self.state.in_flight = None
                    self.save()
                    raise RetryableSendError(
                        f'SMTP rejected the message: {exc}'
                    ) from exc
                except smtplib.SMTPDataError as exc:
                    # smtplib reports an unparseable final reply as -1, and
                    # the server may have queued the message before sending it.
                    if 400 <= exc.smtp_code < 600:
                        self.state.in_flight = None
                        self.save()
                        raise RetryableSendError(f'SMTP rejected DATA: {exc}') from exc
                    raise RuntimeError(f'SMTP rejected DATA: {exc}') from exc
                except (OSError, smtplib.SMTPException) as exc:
                    raise RuntimeError(
                        f'SMTP outcome for <{message.message_id}> is uncertain: {exc}'
                    ) from exc
                if not set(refused) <= set(remaining):
                    raise RuntimeError(
                        'SMTP returned an unexpected recipient; outcome is uncertain'
                    )
                gone = [addr for addr in remaining if _is_permanent(refused.get(addr))]
                message.accepted.extend(
                    addr for addr in remaining if addr not in refused
                )
                message.refused.extend(gone)
                self.state.in_flight = None
                self.save()
                if gone:
                    b4.logger.warning(
                        '    SMTP permanently refused: %s', ', '.join(gone)
                    )
                deferred.update(set(refused) - set(gone))
        finally:
            try:
                conn.quit()
            except (OSError, smtplib.SMTPException):
                conn.close()
        if deferred:
            raise RetryableSendError(
                'SMTP refused recipients: ' + ', '.join(sorted(deferred))
            )


def _is_permanent(reply: Optional[Tuple[int, bytes]]) -> bool:
    return reply is not None and 500 <= reply[0] < 600


def _can_defer_refusal(
    refused: Dict[str, Tuple[int, bytes]], remaining: List[str], accepted: List[str]
) -> bool:
    """Whether a message that all its recipients refused can wait for a retry.

    If not, the whole envelope counts as rejected: no recipient is
    recorded and the send stops instead of moving to later messages.
    """
    # smtplib stops at a 421 and reports only the RCPTs tried so far.
    if set(refused) != set(remaining):
        return False
    for code, _reply in refused.values():
        # A 421 closes the connection, so later messages cannot go out on it.
        # A code outside 4xx/5xx says nothing about the recipient.
        if code == 421 or not 400 <= code < 600:
            return False
        # Until someone takes the message, a 5xx is more likely our own
        # setup (relay denied) than a dead address.
        if code >= 500 and not accepted:
            return False
    return True


def pending_session(directory: Path) -> Optional[SendSession]:
    pending = []
    for path in sorted(directory.glob('v*/state.json')):
        session = SendSession.load(path.parent)
        if not session.state.finished:
            pending.append(session)
    if len(pending) > 1:
        raise RuntimeError(f'Multiple unfinished submissions in {directory}')
    return pending[0] if pending else None
