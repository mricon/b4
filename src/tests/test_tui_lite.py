#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Tests for the lite (mutt-style) thread viewer."""

import contextlib
import email.message
import email.utils
import threading
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

import pytest

pytest.importorskip('textual')

from textual.app import App
from textual.screen import ModalScreen
from textual.widgets import ListView, Static

import b4
from b4.review_tui._lite_app import (
    LiteThreadScreen,
    MessageViewScreen,
    ThreadNode,
    build_thread_tree,
    check_attestation,
)


class TestLiteSendReply:
    """The lite view sends the same trimmed body the preview showed."""

    BUFFER = (
        'On today, Reviewer wrote:\n'
        '> old context one\n'
        '> old context two\n'
        '>--cut--\n'
        '> context kept below the marker\n'
        'My reply.\n'
        '> trailing untouched quote\n'
    )
    TRIMMED = (
        'On today, Reviewer wrote:\n'
        '> [ ... 2 lines skipped ... ]\n'
        '> context kept below the marker\n'
        'My reply.'
    )

    def test_send_trims_like_the_review_panel(self) -> None:
        """A trailing quoted run and a >--cut-- marker are resolved on the
        lite send path too, not just in the review panel."""
        screen = LiteThreadScreen('thread@example.com', email_dryrun=True)
        lmsg = mock.Mock()
        lmsg.fromemail = 'reviewer@example.com'
        outgoing = email.message.EmailMessage()
        lmsg.make_reply.return_value = outgoing
        node = mock.Mock()
        node.lmsg = lmsg

        host = mock.Mock()
        host.suspend.side_effect = lambda: contextlib.nullcontext()

        with (
            mock.patch.object(
                type(screen), 'app', mock.PropertyMock(return_value=host)
            ),
            mock.patch.object(screen, '_mark_answered'),
            mock.patch('b4.get_smtp', return_value=(None, 'me@example.com')),
            mock.patch('b4.send_mail', return_value=0) as send_mail,
        ):
            screen._send_reply(node, self.BUFFER)

        body = lmsg.make_reply.call_args.args[0]
        assert body.startswith(self.TRIMMED)
        assert '>--cut--\n' not in body
        assert '> old context one' not in body
        assert '> trailing untouched quote' not in body
        assert body.endswith('\n\n-- \n' + b4.get_email_signature())
        assert send_mail.call_args.args[1] == [outgoing]


def _static_text(widget: Any) -> str:
    """Return the text content of a Static widget across Textual versions."""
    if hasattr(widget, 'content'):
        return str(widget.content)
    return str(widget.renderable)


def _make_lmsg(
    msgid: str, subject: str, signed: bool, reply_to: Optional[str] = None
) -> b4.LoreMessage:
    msg = email.message.EmailMessage()
    msg['From'] = 'Dev <dev@example.com>'
    msg['Subject'] = subject
    msg['Date'] = email.utils.formatdate(1_700_000_000 + len(msgid))
    msg['Message-Id'] = f'<{msgid}>'
    if reply_to:
        msg['In-Reply-To'] = f'<{reply_to}>'
    if signed:
        msg['DKIM-Signature'] = 'v=1; a=rsa-sha256; d=example.com; s=sel; b=AAAA'
    msg.set_content('Body.\n')
    return b4.LoreMessage(msg)


def _make_tree() -> List[ThreadNode]:
    lmbx = b4.LoreMailbox()
    lmbx.add_message(_make_lmsg('top@example.com', '[PATCH] top', True).msg)
    lmbx.add_message(
        _make_lmsg('reply@example.com', 'Re: [PATCH] top', True, 'top@example.com').msg
    )
    lmbx.add_message(
        _make_lmsg(
            'plain@example.com', 'Re: [PATCH] top', False, 'reply@example.com'
        ).msg
    )
    return build_thread_tree(lmbx)


PASSED = [{'status': 'signed', 'identity': 'DKIM/example.com', 'passing': True}]


class _FakeChecks:
    """Stands in for get_attestation_status, one held-back answer per message."""

    def __init__(self) -> None:
        self.gates: Dict[str, threading.Event] = {}
        self.calls: List[str] = []
        self.fail: Optional[Exception] = None

    def release(self, msgid: str) -> None:
        self.gates.setdefault(msgid, threading.Event()).set()

    def __call__(
        self, lmsg: b4.LoreMessage, attpolicy: str, maxdays: int = 0
    ) -> Tuple[List[Dict[str, Any]], bool, bool]:
        self.calls.append(lmsg.msgid)
        assert self.gates.setdefault(lmsg.msgid, threading.Event()).wait(10)
        if self.fail is not None:
            raise self.fail
        return list(PASSED), True, False


class _CannedThreadScreen(LiteThreadScreen):
    """A thread screen that shows a ready-made thread instead of fetching."""

    def __init__(self, nodes: List[ThreadNode]) -> None:
        super().__init__('top@example.com')
        self._canned = nodes

    def _fetch_thread(self) -> List[ThreadNode]:
        return self._canned


class _LiteHost(App[None]):
    def __init__(self, nodes: List[ThreadNode]) -> None:
        super().__init__()
        self._thread = nodes

    def on_mount(self) -> None:
        self.push_screen(_CannedThreadScreen(self._thread))


class TestLazyAttestation:
    """The thread opens without waiting for attestation checks."""

    @pytest.fixture
    def checks(self, monkeypatch: pytest.MonkeyPatch) -> _FakeChecks:
        # conftest turns attestation off for every test
        monkeypatch.setitem(b4.MAIN_CONFIG, 'attestation-policy', 'softfail')
        fake = _FakeChecks()

        # A plain function, so it binds as a method and gets the message
        def _status(
            lmsg: b4.LoreMessage, attpolicy: str, maxdays: int = 0
        ) -> Tuple[List[Dict[str, Any]], bool, bool]:
            return fake(lmsg, attpolicy, maxdays)

        monkeypatch.setattr(b4.LoreMessage, 'get_attestation_status', _status)
        return fake

    def test_tree_does_not_check_attestation(self, checks: _FakeChecks) -> None:
        nodes = _make_tree()
        assert [n.lmsg.msgid for n in nodes] == [
            'top@example.com',
            'reply@example.com',
            'plain@example.com',
        ]
        assert checks.calls == []
        assert all(n.attestation is None for n in nodes)

    def test_check_remembers_result(self, checks: _FakeChecks) -> None:
        node = _make_tree()[0]
        checks.release('top@example.com')
        assert check_attestation(node) == PASSED
        assert node.attestation == PASSED

    @staticmethod
    async def _open(app: _LiteHost, pilot: Any) -> MessageViewScreen:
        for _ in range(20):
            await pilot.pause()
            if app.screen.query(ListView):
                break
        await pilot.press('enter')
        await pilot.pause()
        assert isinstance(app.screen, MessageViewScreen)
        return app.screen

    @staticmethod
    async def _settle(app: _LiteHost, pilot: Any) -> None:
        await app.workers.wait_for_complete()
        await pilot.pause()
        await pilot.pause()

    @staticmethod
    def _line(screen: MessageViewScreen) -> Static:
        return screen.query_one('#msg-attestation', Static)

    @pytest.mark.asyncio
    async def test_message_shows_checking_then_result(
        self, checks: _FakeChecks
    ) -> None:
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await self._open(app, pilot)
            line = self._line(screen)
            assert line.display
            assert _static_text(line) == 'Attestation: checking\u2026'

            checks.release('top@example.com')
            await self._settle(app, pilot)
            assert _static_text(line) == 'Attestation: \u2713 DKIM/example.com'
        assert checks.calls == ['top@example.com']

    @pytest.mark.asyncio
    async def test_unsigned_message_skips_check(self, checks: _FakeChecks) -> None:
        nodes = _make_tree()
        for gate in ('top@example.com', 'reply@example.com'):
            checks.release(gate)
        app = _LiteHost(nodes)
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await self._open(app, pilot)
            await pilot.press('j', 'j')
            await self._settle(app, pilot)
            assert screen.node.lmsg.msgid == 'plain@example.com'
            assert not self._line(screen).display
        assert 'plain@example.com' not in checks.calls
        assert nodes[2].attestation == []

    @pytest.mark.asyncio
    async def test_check_survives_moving_away(self, checks: _FakeChecks) -> None:
        """A check started on one message finishes while the user reads
        another, and is not run twice when they come back."""
        nodes = _make_tree()
        app = _LiteHost(nodes)
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await self._open(app, pilot)
            await pilot.press('j')
            await pilot.pause()
            assert screen.node is nodes[1]
            assert _static_text(self._line(screen)) == 'Attestation: checking\u2026'

            # The first message's answer lands while the second is shown
            checks.release('top@example.com')
            await pilot.pause()
            for _ in range(20):
                if nodes[0].attestation is not None:
                    break
                await pilot.pause(0.05)
            assert nodes[0].attestation == PASSED
            assert _static_text(self._line(screen)) == 'Attestation: checking\u2026'

            await pilot.press('k')
            await pilot.pause()
            assert _static_text(self._line(screen)) == (
                'Attestation: \u2713 DKIM/example.com'
            )
            checks.release('reply@example.com')
            await self._settle(app, pilot)
        assert sorted(checks.calls) == ['reply@example.com', 'top@example.com']

    @pytest.mark.asyncio
    async def test_reopened_message_reuses_running_check(
        self, checks: _FakeChecks
    ) -> None:
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            await self._open(app, pilot)
            await pilot.press('q')
            await pilot.pause()
            screen = await self._open(app, pilot)
            checks.release('top@example.com')
            await self._settle(app, pilot)
            assert _static_text(self._line(screen)) == (
                'Attestation: \u2713 DKIM/example.com'
            )
        assert checks.calls == ['top@example.com']

    @pytest.mark.asyncio
    async def test_result_lands_under_another_screen(self, checks: _FakeChecks) -> None:
        """A check that finishes while a screen covers the message view
        (the reply preview, say) still shows up when it is uncovered."""
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await self._open(app, pilot)
            await app.push_screen(ModalScreen[None]())
            checks.release('top@example.com')
            await self._settle(app, pilot)
            app.pop_screen()
            await pilot.pause()
            assert app.screen is screen
            assert _static_text(self._line(screen)) == (
                'Attestation: \u2713 DKIM/example.com'
            )

    @pytest.mark.asyncio
    async def test_broken_check_says_so(self, checks: _FakeChecks) -> None:
        checks.fail = RuntimeError('kaboom')
        checks.release('top@example.com')
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await self._open(app, pilot)
            await self._settle(app, pilot)
            assert _static_text(self._line(screen)) == (
                'Attestation: \u2717 check failed: kaboom'
            )
