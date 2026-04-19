# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2020 by the Linux Foundation
import email.message
from typing import List, Optional, Tuple
from unittest import mock

import b4


# ---------------------------------------------------------------------------
# Helpers for building synthetic EmailMessage objects
# ---------------------------------------------------------------------------
def _make_msg(msgid: str, subject: str, from_addr: str = 'Test Author <test@example.com>',
              date: str = 'Mon, 23 Mar 2026 12:00:00 +0000',
              in_reply_to: Optional[str] = None,
              references: Optional[str] = None,
              body: str = 'Hello\n') -> email.message.EmailMessage:
    msg = email.message.EmailMessage()
    msg['Message-ID'] = f'<{msgid}>'
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['Date'] = date
    if in_reply_to:
        msg['In-Reply-To'] = f'<{in_reply_to}>'
    if references:
        msg['References'] = references
    msg.set_payload(body, 'utf-8')
    return msg


# ===========================================================================
# parse_msgid tests
# ===========================================================================
class TestParseMsgid:
    def test_bare_msgid(self) -> None:
        assert b4.parse_msgid('20260323041505.2088-1-user@example.com') == \
            '20260323041505.2088-1-user@example.com'

    def test_angle_brackets(self) -> None:
        assert b4.parse_msgid('<20260323041505.2088-1-user@example.com>') == \
            '20260323041505.2088-1-user@example.com'

    def test_lore_url(self) -> None:
        result = b4.parse_msgid(
            'https://lore.kernel.org/all/20260323041505.2088-1-user@example.com/')
        assert result == '20260323041505.2088-1-user@example.com'

    def test_lore_url_with_r_shorthand(self) -> None:
        result = b4.parse_msgid(
            'https://lore.kernel.org/r/20260323041505.2088-1-user@example.com')
        assert result == '20260323041505.2088-1-user@example.com'

    def test_lore_url_percent_encoded(self) -> None:
        result = b4.parse_msgid(
            'https://lore.kernel.org/all/abc%2Bdef@example.com/')
        assert result == 'abc+def@example.com'

    def test_patchwork_url(self) -> None:
        result = b4.parse_msgid(
            'https://patchwork.kernel.org/project/linux-mm/patch/20260323041505.2088-1-user@example.com/')
        assert result == '20260323041505.2088-1-user@example.com'

    def test_id_prefix(self) -> None:
        assert b4.parse_msgid('id:20260323041505.2088-1-user@example.com') == \
            '20260323041505.2088-1-user@example.com'

    def test_rfc822msgid_prefix(self) -> None:
        assert b4.parse_msgid('rfc822msgid:20260323041505.2088-1-user@example.com') == \
            '20260323041505.2088-1-user@example.com'

    def test_whitespace_stripped(self) -> None:
        assert b4.parse_msgid('  <foo@bar.com>  ') == 'foo@bar.com'

    def test_generic_http_url_with_at_sign(self) -> None:
        result = b4.parse_msgid('https://some.archive.org/msg/20260323.abc@example.com')
        assert result == '20260323.abc@example.com'

    def test_non_url_passthrough(self) -> None:
        """A bare msgid without special prefixes passes through unchanged."""
        assert b4.parse_msgid('simple-msgid@host') == 'simple-msgid@host'

    def test_midmask_override_for_foreign_server(self) -> None:
        """When a URL points to a different server, midmask is overridden."""
        old_midmask = b4.MAIN_CONFIG.get('midmask')
        b4.parse_msgid('https://other.archive.org/linux-mm/foo@bar.com/')
        assert b4.MAIN_CONFIG['midmask'] == 'https://other.archive.org/linux-mm/%s'
        # Restore
        b4.MAIN_CONFIG['midmask'] = old_midmask


# ===========================================================================
# LoreSeries.rewrite_subject_counter tests
# ===========================================================================
class TestRewriteSubjectCounter:
    def test_basic_rewrite(self) -> None:
        msg = _make_msg('a@b', '[PATCH 1/1] Fix the frobnicator')
        b4.LoreSeries.rewrite_subject_counter(msg, 2, 5)
        assert msg['Subject'] == '[PATCH 2/5] Fix the frobnicator'

    def test_preserves_rfc_prefix(self) -> None:
        msg = _make_msg('a@b', '[PATCH RFC 1/1] Add new feature')
        b4.LoreSeries.rewrite_subject_counter(msg, 3, 7)
        assert msg['Subject'] == '[PATCH RFC 3/7] Add new feature'

    def test_preserves_version(self) -> None:
        msg = _make_msg('a@b', '[PATCH v3 1/2] Refactor widgets')
        b4.LoreSeries.rewrite_subject_counter(msg, 1, 4)
        assert msg['Subject'] == '[PATCH v3 1/4] Refactor widgets'

    def test_zero_pads_counter(self) -> None:
        msg = _make_msg('a@b', '[PATCH 1/1] Something')
        b4.LoreSeries.rewrite_subject_counter(msg, 2, 15)
        assert msg['Subject'] == '[PATCH 02/15] Something'

    def test_cover_letter(self) -> None:
        msg = _make_msg('a@b', '[PATCH 0/3] Cover letter subject')
        b4.LoreSeries.rewrite_subject_counter(msg, 0, 5)
        assert msg['Subject'] == '[PATCH 0/5] Cover letter subject'

    def test_bare_subject_gets_patch_prefix(self) -> None:
        msg = _make_msg('a@b', 'Fix the thing')
        b4.LoreSeries.rewrite_subject_counter(msg, 1, 3)
        assert msg['Subject'] == '[PATCH 1/3] Fix the thing'


# ===========================================================================
# LoreSeries.identify_cover_letter tests
# ===========================================================================
class TestIdentifyCoverLetter:
    def test_cover_detected(self) -> None:
        cover = _make_msg('cover@x', '[PATCH 0/2] Series title')
        p1 = _make_msg('p1@x', '[PATCH 1/2] First')
        p2 = _make_msg('p2@x', '[PATCH 2/2] Second')
        all_msgs = [cover, p1, p2]
        msgids = ['cover@x', 'p1@x', 'p2@x']

        cover_msgid, patch_msgs = b4.LoreSeries.identify_cover_letter(all_msgs, msgids)
        assert cover_msgid == 'cover@x'
        assert len(patch_msgs) == 2
        assert b4.LoreMessage.get_clean_msgid(patch_msgs[0]) == 'p1@x'
        assert b4.LoreMessage.get_clean_msgid(patch_msgs[1]) == 'p2@x'

    def test_no_cover(self) -> None:
        p1 = _make_msg('p1@x', '[PATCH 1/2] First')
        p2 = _make_msg('p2@x', '[PATCH 2/2] Second')
        all_msgs = [p1, p2]
        msgids = ['p1@x', 'p2@x']

        cover_msgid, patch_msgs = b4.LoreSeries.identify_cover_letter(all_msgs, msgids)
        assert cover_msgid is None
        assert len(patch_msgs) == 2

    def test_preserves_cli_order(self) -> None:
        p1 = _make_msg('p1@x', '[PATCH 1/3] First')
        p2 = _make_msg('p2@x', '[PATCH 2/3] Second')
        p3 = _make_msg('p3@x', '[PATCH 3/3] Third')
        all_msgs = [p1, p2, p3]
        # Pass in reverse order
        msgids = ['p3@x', 'p1@x', 'p2@x']

        _, patch_msgs = b4.LoreSeries.identify_cover_letter(all_msgs, msgids)
        result_ids = [b4.LoreMessage.get_clean_msgid(m) for m in patch_msgs]
        assert result_ids == ['p3@x', 'p1@x', 'p2@x']

    def test_child_messages_ignored(self) -> None:
        """Messages present in all_msgs but not in msgids should not appear in patch_msgs."""
        p1 = _make_msg('p1@x', '[PATCH 1/2] First')
        reply = _make_msg('reply@x', 'Re: [PATCH 1/2] First', in_reply_to='p1@x')
        p2 = _make_msg('p2@x', '[PATCH 2/2] Second')
        all_msgs = [p1, reply, p2]
        msgids = ['p1@x', 'p2@x']

        cover_msgid, patch_msgs = b4.LoreSeries.identify_cover_letter(all_msgs, msgids)
        assert cover_msgid is None
        assert len(patch_msgs) == 2

    def test_inferred_counter_zero_not_cover(self) -> None:
        """A message with inferred counter 0 (e.g. just [PATCH]) should not be treated as cover."""
        # A bare [PATCH] message gets counter=1, expected=1, counters_inferred=True
        # but a message that somehow parses as counter=0 with inferred counters should not
        # be treated as a cover letter
        p1 = _make_msg('p1@x', '[PATCH] Single patch fix')
        p2 = _make_msg('p2@x', '[PATCH] Another fix')
        all_msgs = [p1, p2]
        msgids = ['p1@x', 'p2@x']

        cover_msgid, patch_msgs = b4.LoreSeries.identify_cover_letter(all_msgs, msgids)
        assert cover_msgid is None
        assert len(patch_msgs) == 2


# ===========================================================================
# LoreSeries.renumber_patches tests
# ===========================================================================
class TestRenumberPatches:
    def test_all_explicit_correct_expected(self) -> None:
        """When all counters are explicit and expected is correct, nothing changes."""
        msgs = [
            _make_msg('a@x', '[PATCH 1/2] First'),
            _make_msg('b@x', '[PATCH 2/2] Second'),
        ]
        b4.LoreSeries.renumber_patches(msgs)
        assert b4.LoreSubject(msgs[0]['Subject']).counter == 1
        assert b4.LoreSubject(msgs[0]['Subject']).expected == 2
        assert b4.LoreSubject(msgs[1]['Subject']).counter == 2
        assert b4.LoreSubject(msgs[1]['Subject']).expected == 2

    def test_all_explicit_wrong_expected(self) -> None:
        """When all counters are explicit but expected is wrong, fix expected only."""
        msgs = [
            _make_msg('a@x', '[PATCH 1/1] First'),
            _make_msg('b@x', '[PATCH 2/2] Second'),
            _make_msg('c@x', '[PATCH 3/3] Third'),
        ]
        b4.LoreSeries.renumber_patches(msgs)
        for msg in msgs:
            assert b4.LoreSubject(msg['Subject']).expected == 3
        # Counters preserved
        assert b4.LoreSubject(msgs[0]['Subject']).counter == 1
        assert b4.LoreSubject(msgs[1]['Subject']).counter == 2
        assert b4.LoreSubject(msgs[2]['Subject']).counter == 3

    def test_inferred_counters_renumbered(self) -> None:
        """When counters are inferred, renumber based on list order."""
        msgs = [
            _make_msg('a@x', '[PATCH] Alpha fix'),
            _make_msg('b@x', '[PATCH] Beta fix'),
            _make_msg('c@x', '[PATCH] Gamma fix'),
        ]
        b4.LoreSeries.renumber_patches(msgs)
        for i, msg in enumerate(msgs, 1):
            subj = b4.LoreSubject(msg['Subject'])
            assert subj.counter == i
            assert subj.expected == 3

    def test_mixed_explicit_and_inferred(self) -> None:
        """When some counters are inferred, renumber everything based on order."""
        msgs = [
            _make_msg('a@x', '[PATCH 1/2] Has counter'),
            _make_msg('b@x', '[PATCH] No counter'),
        ]
        b4.LoreSeries.renumber_patches(msgs)
        assert b4.LoreSubject(msgs[0]['Subject']).counter == 1
        assert b4.LoreSubject(msgs[0]['Subject']).expected == 2
        assert b4.LoreSubject(msgs[1]['Subject']).counter == 2
        assert b4.LoreSubject(msgs[1]['Subject']).expected == 2

    def test_empty_list(self) -> None:
        """Empty list should be a no-op."""
        b4.LoreSeries.renumber_patches([])

    def test_preserves_version_during_renumber(self) -> None:
        msgs = [
            _make_msg('a@x', '[PATCH v2] First fix'),
            _make_msg('b@x', '[PATCH v2] Second fix'),
        ]
        b4.LoreSeries.renumber_patches(msgs)
        for msg in msgs:
            subj = b4.LoreSubject(msg['Subject'])
            assert subj.revision == 2
            assert subj.expected == 2


# ===========================================================================
# LoreSeries.rethread_messages tests
# ===========================================================================
class TestRethreadMessages:
    def test_patches_threaded_to_cover(self) -> None:
        cover = _make_msg('cover@x', '[PATCH 0/2] Cover')
        p1 = _make_msg('p1@x', '[PATCH 1/2] First')
        p2 = _make_msg('p2@x', '[PATCH 2/2] Second')
        all_msgs = [cover, p1, p2]

        b4.LoreSeries.rethread_messages(all_msgs, 'cover@x', {'p1@x', 'p2@x'})

        # Cover has no threading headers
        assert cover.get('In-Reply-To') is None
        assert cover.get('References') is None
        # Patches thread to cover
        assert p1['In-Reply-To'] == '<cover@x>'
        assert p1['References'] == '<cover@x>'
        assert p2['In-Reply-To'] == '<cover@x>'
        assert p2['References'] == '<cover@x>'

    def test_child_messages_untouched(self) -> None:
        cover = _make_msg('cover@x', '[PATCH 0/2] Cover')
        p1 = _make_msg('p1@x', '[PATCH 1/2] First')
        reply = _make_msg('reply@x', 'Re: [PATCH 1/2] First',
                          in_reply_to='p1@x',
                          references='<p1@x>')
        all_msgs = [cover, p1, reply]

        b4.LoreSeries.rethread_messages(all_msgs, 'cover@x', {'p1@x'})

        # Reply should keep its original threading
        assert reply['In-Reply-To'] == '<p1@x>'
        assert reply['References'] == '<p1@x>'

    def test_strips_old_threading_from_cover(self) -> None:
        """If the cover had pre-existing threading, it should be stripped."""
        cover = _make_msg('cover@x', '[PATCH 0/2] Cover',
                          in_reply_to='old-parent@x',
                          references='<old-parent@x>')
        p1 = _make_msg('p1@x', '[PATCH 1/2] First')
        all_msgs = [cover, p1]

        b4.LoreSeries.rethread_messages(all_msgs, 'cover@x', {'p1@x'})

        assert cover.get('In-Reply-To') is None
        assert cover.get('References') is None

    def test_replaces_old_threading_on_patches(self) -> None:
        """Patches should lose their old threading and get cover as parent."""
        cover = _make_msg('cover@x', '[PATCH 0/1] Cover')
        p1 = _make_msg('p1@x', '[PATCH 1/1] Fix',
                        in_reply_to='unrelated@x',
                        references='<unrelated@x> <other@x>')
        all_msgs = [cover, p1]

        b4.LoreSeries.rethread_messages(all_msgs, 'cover@x', {'p1@x'})

        assert p1['In-Reply-To'] == '<cover@x>'
        assert p1['References'] == '<cover@x>'

    def test_threads_under_first_patch_when_no_cover(self) -> None:
        """Without a cover, patches 2+ should thread under patch 1."""
        p1 = _make_msg('p1@x', '[PATCH 1/2] First')
        p2 = _make_msg('p2@x', '[PATCH 2/2] Second')
        all_msgs = [p1, p2]

        # p1 is the root, only p2 needs rethreading
        b4.LoreSeries.rethread_messages(all_msgs, 'p1@x', {'p2@x'})

        # p1 (root) has no threading headers
        assert p1.get('In-Reply-To') is None
        assert p1.get('References') is None
        # p2 threads to p1
        assert p2['In-Reply-To'] == '<p1@x>'
        assert p2['References'] == '<p1@x>'


# ===========================================================================
# Integration: full rethread pipeline with LoreMailbox
# ===========================================================================
class TestRethreadIntegration:
    @staticmethod
    def _run_pipeline(msgids: List[str],
                      all_msgs: List[email.message.EmailMessage]
                      ) -> Tuple[str, b4.LoreSeries]:
        """Run the rethread pipeline and feed into LoreMailbox."""
        cover_msgid, all_msgs = b4.LoreSeries.rethread_series(msgids, all_msgs)

        lmbx = b4.LoreMailbox()
        for msg in all_msgs:
            lmbx.add_message(msg)
        lser = lmbx.get_series(codereview_trailers=False)
        assert lser is not None
        return cover_msgid, lser

    def test_numbered_patches_with_cover(self) -> None:
        """Properly numbered patches with a cover letter should produce a complete series."""
        cover = _make_msg('cover@x', '[PATCH 0/2] Widget overhaul',
                          body='This series overhauls widgets.\n')
        p1 = _make_msg('p1@x', '[PATCH 1/2] Refactor widget core',
                        body='---\n widget.c | 10 +\n 1 file changed\n\ndiff --git a/widget.c b/widget.c\n--- a/widget.c\n+++ b/widget.c\n@@ -1 +1 @@\n-old\n+new\n')
        p2 = _make_msg('p2@x', '[PATCH 2/2] Add widget tests',
                        body='---\n test.c | 5 +\n 1 file changed\n\ndiff --git a/test.c b/test.c\n--- a/test.c\n+++ b/test.c\n@@ -1 +1 @@\n-old\n+new\n')
        all_msgs = [cover, p1, p2]
        msgids = ['cover@x', 'p1@x', 'p2@x']

        cover_msgid, lser = self._run_pipeline(msgids, all_msgs)
        assert cover_msgid == 'cover@x'
        assert lser.complete
        assert lser.has_cover
        assert lser.expected == 2

    def test_unnumbered_patches_no_cover(self) -> None:
        """Unnumbered patches without a cover should get renumbered and threaded under patch 1."""
        p1 = _make_msg('p1@x', '[PATCH] Add alpha feature',
                        body='---\n a.c | 1 +\n 1 file changed\n\ndiff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-old\n+new\n')
        p2 = _make_msg('p2@x', '[PATCH] Add beta feature',
                        body='---\n b.c | 1 +\n 1 file changed\n\ndiff --git a/b.c b/b.c\n--- a/b.c\n+++ b/b.c\n@@ -1 +1 @@\n-old\n+new\n')
        all_msgs = [p1, p2]
        msgids = ['p1@x', 'p2@x']

        root_msgid, lser = self._run_pipeline(msgids, all_msgs)
        assert root_msgid == 'p1@x'
        assert lser.complete
        assert not lser.has_cover
        assert lser.expected == 2

    def test_followup_trailers_preserved(self) -> None:
        """Review replies should be associated with the correct patch after rethreading."""
        p1 = _make_msg('p1@x', '[PATCH 1/2] First patch',
                        body='---\n a.c | 1 +\n 1 file changed\n\ndiff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-old\n+new\n')
        review = _make_msg('rev@x', 'Re: [PATCH 1/2] First patch',
                           in_reply_to='p1@x',
                           references='<p1@x>',
                           from_addr='Reviewer <rev@example.com>',
                           body='Looks good.\n\nReviewed-by: Reviewer <rev@example.com>\n')
        p2 = _make_msg('p2@x', '[PATCH 2/2] Second patch',
                        body='---\n b.c | 1 +\n 1 file changed\n\ndiff --git a/b.c b/b.c\n--- a/b.c\n+++ b/b.c\n@@ -1 +1 @@\n-old\n+new\n')
        all_msgs = [p1, review, p2]
        msgids = ['p1@x', 'p2@x']

        _, lser = self._run_pipeline(msgids, all_msgs)
        assert lser.complete
        # The review trailer should have landed on patch 1
        assert lser.patches[1] is not None
        has_reviewed_by = any(
            t.name == 'Reviewed-by' for t in lser.patches[1].followup_trailers
        )
        assert has_reviewed_by

    def test_wrong_expected_fixed(self) -> None:
        """Patches claiming 1/1 each should have expected fixed to match actual count."""
        p1 = _make_msg('p1@x', '[PATCH 1/1] First',
                        body='---\n a.c | 1 +\n 1 file changed\n\ndiff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-old\n+new\n')
        p2 = _make_msg('p2@x', '[PATCH 1/1] Second',
                        body='---\n b.c | 1 +\n 1 file changed\n\ndiff --git a/b.c b/b.c\n--- a/b.c\n+++ b/b.c\n@@ -1 +1 @@\n-old\n+new\n')
        all_msgs = [p1, p2]
        msgids = ['p1@x', 'p2@x']

        # Both say 1/1 but there are 2 patches. After renumber_series,
        # expected should be 2 for both.
        _, patch_msgs = b4.LoreSeries.identify_cover_letter(all_msgs, msgids)
        b4.LoreSeries.renumber_patches(patch_msgs)
        for msg in patch_msgs:
            subj = b4.LoreSubject(msg['Subject'])
            assert subj.expected == 2


# ===========================================================================
# discover_rethread_series tests (mock network calls)
# ===========================================================================
class TestDiscoverRethreadSeries:
    @staticmethod
    def _mock_discover(seed_msg: email.message.EmailMessage,
                       search_results: List[email.message.EmailMessage]) -> List[str]:
        """Run discover_rethread_series with mocked network calls."""
        seed_msgid = b4.LoreMessage.get_clean_msgid(seed_msg)
        assert seed_msgid is not None
        with mock.patch('b4.get_pi_thread_by_msgid', return_value=[seed_msg]), \
             mock.patch('b4.get_pi_search_results', return_value=search_results):
            return b4.discover_rethread_series(seed_msgid)

    def test_discovers_numbered_series(self) -> None:
        """From a single [PATCH 1/3], discover the full series."""
        seed = _make_msg('p1@x', '[PATCH 1/3] First fix')
        p2 = _make_msg('p2@x', '[PATCH 2/3] Second fix')
        p3 = _make_msg('p3@x', '[PATCH 3/3] Third fix')

        result = self._mock_discover(seed, [seed, p2, p3])
        assert result == ['p1@x', 'p2@x', 'p3@x']

    def test_discovers_cover_letter(self) -> None:
        """If a cover letter exists, it should be found and listed first."""
        seed = _make_msg('p1@x', '[PATCH 1/2] First fix')
        cover = _make_msg('c@x', '[PATCH 0/2] Series title')
        p2 = _make_msg('p2@x', '[PATCH 2/2] Second fix')

        result = self._mock_discover(seed, [cover, seed, p2])
        assert result == ['c@x', 'p1@x', 'p2@x']

    def test_filters_different_expected(self) -> None:
        """Patches with a different expected count should be excluded."""
        seed = _make_msg('p1@x', '[PATCH 1/3] My fix')
        match = _make_msg('p2@x', '[PATCH 2/3] My fix part 2')
        other = _make_msg('o@x', '[PATCH 1/5] Unrelated series')

        result = self._mock_discover(seed, [seed, match, other])
        assert 'o@x' not in result
        assert result == ['p1@x', 'p2@x']

    def test_filters_different_revision(self) -> None:
        """Patches with a different version should be excluded."""
        seed = _make_msg('p1@x', '[PATCH v2 1/2] Fix widget')
        match = _make_msg('p2@x', '[PATCH v2 2/2] Fix gadget')
        v1 = _make_msg('old@x', '[PATCH v1 1/2] Fix widget')

        result = self._mock_discover(seed, [seed, match, v1])
        assert 'old@x' not in result
        assert result == ['p1@x', 'p2@x']

    def test_filters_replies(self) -> None:
        """Reply messages should be excluded."""
        seed = _make_msg('p1@x', '[PATCH 1/2] First fix')
        p2 = _make_msg('p2@x', '[PATCH 2/2] Second fix')
        reply = _make_msg('r@x', 'Re: [PATCH 1/2] First fix')

        result = self._mock_discover(seed, [seed, p2, reply])
        assert 'r@x' not in result
        assert result == ['p1@x', 'p2@x']

    def test_bare_patch_discovery(self) -> None:
        """Bare [PATCH] messages should discover other bare [PATCH] messages."""
        seed = _make_msg('p1@x', '[PATCH] Alpha fix')
        p2 = _make_msg('p2@x', '[PATCH] Beta fix')
        numbered = _make_msg('n@x', '[PATCH 1/3] Numbered patch')

        result = self._mock_discover(seed, [seed, p2, numbered])
        assert 'n@x' not in result
        assert set(result) == {'p1@x', 'p2@x'}

    def test_no_results_returns_seed_only(self) -> None:
        """If search returns nothing, return only the seed msgid."""
        seed = _make_msg('p1@x', '[PATCH 1/2] Fix')
        seed_msgid = b4.LoreMessage.get_clean_msgid(seed)
        assert seed_msgid is not None
        with mock.patch('b4.get_pi_thread_by_msgid', return_value=[seed]), \
             mock.patch('b4.get_pi_search_results', return_value=None):
            result = b4.discover_rethread_series(seed_msgid)
        assert result == ['p1@x']
