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
from textual.widgets import ListView, RichLog, Static

import b4
from b4.review_tui._lite_app import (
    LiteThreadScreen,
    MessageViewScreen,
    ThreadNode,
    _build_attestation_text,
    build_thread_tree,
    check_attestation,
)

from .helpers.tui import CUT_BUFFER, CUT_TRIMMED, static_text


class TestLiteSendReply:
    """The lite view sends the same trimmed body the preview showed."""

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
            screen._send_reply(node, CUT_BUFFER)

        body = lmsg.make_reply.call_args.args[0]
        assert body.startswith(CUT_TRIMMED)
        assert '>--cut--\n' not in body
        assert '> old context one' not in body
        assert '> trailing untouched quote' not in body
        assert body.endswith('\n\n-- \n' + b4.get_email_signature())
        assert send_mail.call_args.args[1] == [outgoing]


def _make_lmsg(
    msgid: str,
    subject: str,
    signed: bool,
    reply_to: Optional[str] = None,
    sender: str = 'Dev <dev@example.com>',
) -> b4.LoreMessage:
    msg = email.message.EmailMessage()
    msg['From'] = sender
    msg['To'] = 'Maintainer <maint@example.com>'
    msg['Cc'] = 'list@example.com, Other <other@example.com>'
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
            'plain@example.com',
            'Re: [PATCH] top',
            False,
            'reply@example.com',
            sender='Reviewer <reviewer@example.com>',
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


async def _open(app: _LiteHost, pilot: Any) -> MessageViewScreen:
    """Wait for the thread index, then open its first message."""
    for _ in range(20):
        await pilot.pause()
        if app.screen.query(ListView):
            break
    await pilot.press('enter')
    await pilot.pause()
    assert isinstance(app.screen, MessageViewScreen)
    return app.screen


async def _settle(app: _LiteHost, pilot: Any) -> None:
    await app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()


def _attestation_line(screen: MessageViewScreen) -> Static:
    return screen.query_one('#msg-attestation', Static)


@pytest.fixture
def checks(monkeypatch: pytest.MonkeyPatch) -> _FakeChecks:
    # conftest turns attestation off for every test
    monkeypatch.setitem(b4.MAIN_CONFIG, 'attestation-policy', 'softfail')
    fake = _FakeChecks()

    # A plain function, so it binds as a method and gets the message
    def _status(
        lmsg: b4.LoreMessage, attpolicy: str, maxdays: int = 0, tofu: bool = False
    ) -> Tuple[List[Dict[str, Any]], bool, bool]:
        # The message view must see keys trusted on first use
        assert tofu
        return fake(lmsg, attpolicy, maxdays)

    monkeypatch.setattr(b4.LoreMessage, 'get_attestation_status', _status)
    return fake


class TestLazyAttestation:
    """The thread opens without waiting for attestation checks."""

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

    @pytest.mark.asyncio
    async def test_message_shows_checking_then_result(
        self, checks: _FakeChecks
    ) -> None:
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await _open(app, pilot)
            line = _attestation_line(screen)
            assert line.display
            assert static_text(line) == 'Attestation: checking\u2026'

            checks.release('top@example.com')
            await _settle(app, pilot)
            assert static_text(line) == 'Attestation: \u2713 DKIM/example.com'
        assert checks.calls == ['top@example.com']

    @pytest.mark.asyncio
    async def test_unsigned_message_skips_check(self, checks: _FakeChecks) -> None:
        nodes = _make_tree()
        for gate in ('top@example.com', 'reply@example.com'):
            checks.release(gate)
        app = _LiteHost(nodes)
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await _open(app, pilot)
            await pilot.press('j', 'j')
            await _settle(app, pilot)
            assert screen.node.lmsg.msgid == 'plain@example.com'
            assert not _attestation_line(screen).display
        assert 'plain@example.com' not in checks.calls
        assert nodes[2].attestation == []

    @pytest.mark.asyncio
    async def test_check_survives_moving_away(self, checks: _FakeChecks) -> None:
        """A check started on one message finishes while the user reads
        another, and is not run twice when they come back."""
        nodes = _make_tree()
        app = _LiteHost(nodes)
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await _open(app, pilot)
            await pilot.press('j')
            await pilot.pause()
            assert screen.node is nodes[1]
            assert (
                static_text(_attestation_line(screen)) == 'Attestation: checking\u2026'
            )

            # The first message's answer lands while the second is shown
            checks.release('top@example.com')
            await pilot.pause()
            for _ in range(20):
                if nodes[0].attestation is not None:
                    break
                await pilot.pause(0.05)
            assert nodes[0].attestation == PASSED
            assert (
                static_text(_attestation_line(screen)) == 'Attestation: checking\u2026'
            )

            await pilot.press('k')
            await pilot.pause()
            assert static_text(_attestation_line(screen)) == (
                'Attestation: \u2713 DKIM/example.com'
            )
            checks.release('reply@example.com')
            await _settle(app, pilot)
        assert sorted(checks.calls) == ['reply@example.com', 'top@example.com']

    @pytest.mark.asyncio
    async def test_reopened_message_reuses_running_check(
        self, checks: _FakeChecks
    ) -> None:
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            await _open(app, pilot)
            await pilot.press('q')
            await pilot.pause()
            screen = await _open(app, pilot)
            checks.release('top@example.com')
            await _settle(app, pilot)
            assert static_text(_attestation_line(screen)) == (
                'Attestation: \u2713 DKIM/example.com'
            )
        assert checks.calls == ['top@example.com']

    @pytest.mark.asyncio
    async def test_result_lands_under_another_screen(self, checks: _FakeChecks) -> None:
        """A check that finishes while a screen covers the message view
        (the reply preview, say) still shows up when it is uncovered."""
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await _open(app, pilot)
            await app.push_screen(ModalScreen[None]())
            checks.release('top@example.com')
            await _settle(app, pilot)
            app.pop_screen()
            await pilot.pause()
            assert app.screen is screen
            assert static_text(_attestation_line(screen)) == (
                'Attestation: \u2713 DKIM/example.com'
            )

    @pytest.mark.asyncio
    async def test_broken_check_says_so(self, checks: _FakeChecks) -> None:
        checks.fail = RuntimeError('kaboom')
        checks.release('top@example.com')
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await _open(app, pilot)
            await _settle(app, pilot)
            assert static_text(_attestation_line(screen)) == (
                'Attestation: \u2717 check failed: kaboom'
            )


class TestAttestationText:
    """The Attestation line of the message view."""

    TS = {'success': 'green', 'warning': 'yellow', 'error': 'red'}

    @pytest.mark.parametrize(
        'status,passing,expected',
        [
            pytest.param('tofu', True, '\u2713 ed25519/a@example.org', id='tofu'),
            pytest.param(
                'tofu-new', True, '? ed25519/a@example.org (new key)', id='new'
            ),
            pytest.param(
                'tofu-changed',
                False,
                '\u2717 Key changed: ed25519/a@example.org',
                id='changed',
            ),
            pytest.param(
                'tofu-retired',
                False,
                '\u2717 Retired key: ed25519/a@example.org',
                id='retired',
            ),
            pytest.param(
                'tofu-rejected',
                False,
                '\u2717 Rejected key: ed25519/a@example.org',
                id='rejected',
            ),
        ],
    )
    def test_tofu_statuses(self, status: str, passing: bool, expected: str) -> None:
        att = [
            {'status': status, 'identity': 'ed25519/a@example.org', 'passing': passing}
        ]
        text = _build_attestation_text(att, self.TS)
        assert text.plain == f'Attestation: {expected}'


class TestFixedHeader:
    """From, Subject and Attestation stay above the scrolling message."""

    @staticmethod
    def _viewer_text(screen: MessageViewScreen) -> List[str]:
        viewer = screen.query_one('#msg-viewer', RichLog)
        return [line.text for line in viewer.lines]

    @pytest.mark.asyncio
    async def test_order_and_switching(self, checks: _FakeChecks) -> None:
        for gate in ('top@example.com', 'reply@example.com'):
            checks.release(gate)
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await _open(app, pilot)
            await _settle(app, pilot)
            header = screen.query_one('#msg-header')
            ids = [w.id for w in header.children if w.display]
            assert ids == ['msg-from', 'msg-title', 'msg-attestation']
            # A blank row, not a line, sets the fixed block apart from the body
            assert header.styles.margin.bottom == 1
            assert header.styles.border_bottom[0] == ''
            dialog = screen.query_one('#msg-dialog')
            assert [w.id for w in dialog.children][:2] == ['msg-header', 'msg-viewer']
            assert static_text(screen.query_one('#msg-from', Static)) == (
                'From: Dev <dev@example.com>'
            )
            assert static_text(screen.query_one('#msg-title', Static)) == (
                'Subject: [PATCH] top'
            )
            # Shown once, in the fixed lines only
            assert not any(t.startswith('From:') for t in self._viewer_text(screen))

            await pilot.press('j', 'j')
            await _settle(app, pilot)
            assert static_text(screen.query_one('#msg-from', Static)) == (
                'From: Reviewer <reviewer@example.com>'
            )


# The brief set; Link comes from the default b4.linkmask
BRIEF = ['Date', 'To', 'Cc', 'Link']


class TestHeaderToggle:
    """h shows the useful headers, H shows them all, and neither by default."""

    @staticmethod
    def _names(screen: MessageViewScreen) -> List[str]:
        """Header names at the top of the viewer, up to the blank line."""
        viewer = screen.query_one('#msg-viewer', RichLog)
        names = []
        for line in viewer.lines:
            text = line.text
            if not text.strip():
                break
            if ': ' not in text or text.startswith(' '):
                break
            names.append(text.split(':', 1)[0])
        return names

    @staticmethod
    def _first_line(screen: MessageViewScreen) -> str:
        return screen.query_one('#msg-viewer', RichLog).lines[0].text

    @pytest.mark.asyncio
    async def test_h_toggles_brief_headers(self) -> None:
        """No headers by default; h shows the brief set, h again hides it."""
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await _open(app, pilot)
            assert self._first_line(screen) == 'Body.'
            await pilot.press('h')
            await pilot.pause()
            assert self._names(screen) == BRIEF
            await pilot.press('h')
            await pilot.pause()
            assert self._first_line(screen) == 'Body.'

    @pytest.mark.asyncio
    async def test_no_link_without_linkmask(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(b4.MAIN_CONFIG, 'linkmask', '')
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await _open(app, pilot)
            await pilot.press('h')
            await pilot.pause()
            assert self._names(screen) == ['Date', 'To', 'Cc']

    @pytest.mark.asyncio
    async def test_H_shows_every_header_in_order(self) -> None:
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await _open(app, pilot)
            await pilot.press('H')
            await pilot.pause()
            names = self._names(screen)
            assert names == list(screen.node.lmsg.msg.keys())
            assert 'Message-Id' in names and 'DKIM-Signature' in names

            # h from the full set goes to the brief one, not to none
            await pilot.press('h')
            await pilot.pause()
            assert self._names(screen) == BRIEF
            await pilot.press('H')
            await pilot.pause()
            assert 'Message-Id' in self._names(screen)
            await pilot.press('H')
            await pilot.pause()
            assert self._first_line(screen) == 'Body.'

    @pytest.mark.asyncio
    async def test_choice_holds_for_the_thread(self) -> None:
        app = _LiteHost(_make_tree())
        async with app.run_test(size=(120, 30)) as pilot:
            screen = await _open(app, pilot)
            await pilot.press('h', 'j')
            await pilot.pause()
            assert screen.node.lmsg.msgid == 'reply@example.com'
            assert self._names(screen) == BRIEF

            # Leaving the message and opening another one keeps it too
            await pilot.press('q')
            await pilot.pause()
            screen = await _open(app, pilot)
            assert self._names(screen) == BRIEF
