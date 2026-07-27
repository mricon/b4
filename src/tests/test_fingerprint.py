# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
"""Tests for LoreSeries.fingerprint content identity.

Regression coverage for the fingerprint collapse behind bug 78c0fa1: distinct
same-author series whose patches lack ``diff --git`` headers (plain ``diff -u``,
as some senders produce) yield no ``git patch-id``, and the fingerprint used to
degenerate to ``sha256(fromemail:revision)`` -- collapsing every rev-1 series
from one author onto a single identity.
"""

import email.message

import b4


def _plain_diff_patch(
    msgid: str,
    subject: str,
    path: str,
    old: str,
    new: str,
    from_addr: str = 'Randy Dunlap <rdunlap@infradead.org>',
) -> email.message.EmailMessage:
    """Build a one-patch message whose diff has NO ``diff --git`` header.

    ``git patch-id --stable`` emits nothing for such a diff, so
    ``LoreMessage.git_patch_id`` is None -- the condition that triggered the
    fingerprint collapse.
    """
    body = (
        f'{subject}\n\n'
        'Signed-off-by: Randy Dunlap <rdunlap@infradead.org>\n'
        '---\n'
        f' {path} | 2 +-\n'
        ' 1 file changed, 1 insertion(+), 1 deletion(-)\n\n'
        f'--- a/{path}\n'
        f'+++ b/{path}\n'
        '@@ -1,1 +1,1 @@\n'
        f'-{old}\n'
        f'+{new}\n'
    )
    msg = email.message.EmailMessage()
    msg['Message-ID'] = f'<{msgid}>'
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['Date'] = 'Mon, 13 Jul 2026 17:55:10 +0000'
    msg.set_payload(body, 'utf-8')
    return msg


def _series_for(msg: email.message.EmailMessage) -> b4.LoreSeries:
    lmbx = b4.LoreMailbox()
    lmbx.add_message(msg)
    revs = sorted(lmbx.series.keys())
    assert revs, 'expected at least one revision in the mailbox'
    return lmbx.series[revs[0]]


class TestFingerprintPlainDiff:
    def test_distinct_series_without_git_patch_id_differ(self) -> None:
        """Two unrelated same-author rev-1 series must not share a fingerprint.

        Redline for 78c0fa1: both patches are plain ``diff -u`` (no
        ``diff --git``), so ``git_patch_id`` is None for both. The fingerprint
        must fall back to diff content and stay distinct.
        """
        sof = _plain_diff_patch(
            '20260713175510.524728-1-rdunlap@infradead.org',
            '[PATCH] ASoC: SOF: don\'t use "/**" for non-kernel-doc comments',
            'sound/soc/sof/core.c',
            'old sof line',
            'new sof line',
        )
        regmap = _plain_diff_patch(
            '20260723181215.419984-1-rdunlap@infradead.org',
            '[PATCH] regmap: clean up kernel-doc comments',
            'drivers/base/regmap/regmap.c',
            'old regmap line',
            'new regmap line',
        )
        sof_ser = _series_for(sof)
        regmap_ser = _series_for(regmap)

        # Precondition that makes this bug possible: no git patch-id available.
        assert sof_ser.patches[1] is not None
        assert regmap_ser.patches[1] is not None
        assert sof_ser.patches[1].has_diff
        assert regmap_ser.patches[1].has_diff
        assert sof_ser.patches[1].git_patch_id is None
        assert regmap_ser.patches[1].git_patch_id is None

        assert sof_ser.fingerprint != regmap_ser.fingerprint

    def test_same_series_is_stable(self) -> None:
        """Identical content must produce an identical fingerprint (matching still works)."""
        a = _plain_diff_patch(
            '20260713175510.524728-1-rdunlap@infradead.org',
            '[PATCH] regmap: clean up kernel-doc comments',
            'drivers/base/regmap/regmap.c',
            'old regmap line',
            'new regmap line',
        )
        b = _plain_diff_patch(
            'resend-20260713175510.524728-1-rdunlap@infradead.org',
            '[PATCH] regmap: clean up kernel-doc comments',
            'drivers/base/regmap/regmap.c',
            'old regmap line',
            'new regmap line',
        )
        assert _series_for(a).fingerprint == _series_for(b).fingerprint
