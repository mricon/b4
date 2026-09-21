#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 by the Linux Foundation
#
"""Tests for the lite (mutt-style) thread viewer."""

import contextlib
import email.message
from unittest import mock

import pytest

pytest.importorskip('textual')

import b4
from b4.review_tui._lite_app import LiteThreadScreen
from b4.review_tui._patchwork import PatchworkStateMixin


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
class TestPatchworkStateFlow:
    """A screen may have only one Patchwork state update in flight."""

    def test_rejects_overlapping_requests(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Host(PatchworkStateMixin):
            def __init__(self) -> None:
                self.app = mock.Mock()
                self.run_worker = mock.Mock()

        monkeypatch.setattr(
            b4,
            'get_main_config',
            lambda: {
                'pw-key': 'key',
                'pw-url': 'https://pw.example.com',
                'pw-project': 'project',
            },
        )
        host = Host()

        host.begin_patchwork_state(['first@example.com'])
        host.begin_patchwork_state(['second@example.com'])

        assert host.run_worker.call_count == 1
        host.app.notify.assert_called_once_with(
            'Patchwork state update already in progress', severity='warning'
        )
