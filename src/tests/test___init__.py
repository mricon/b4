import copy
import email
import email.message
import email.parser
import email.policy
import email.utils
import io
import logging
import os
import pathlib
import smtplib
import socket
import sys
from typing import Any, Callable, Dict, List, Literal, Optional, Set, Tuple, Union

import dkim  # type: ignore[import-untyped]
import dkim.dnsplug  # type: ignore[import-untyped]
import dns.message
import dns.query
import dns.resolver
import dns.rrset
import pytest

import b4


@pytest.mark.parametrize(
    'source,expected',
    [
        ('good-valid-trusted', (True, True, True, 'B6C41CE35664996C', '1623274836')),
        ('good-valid-notrust', (True, True, False, 'B6C41CE35664996C', '1623274836')),
        ('good-invalid-notrust', (True, False, False, 'B6C41CE35664996C', None)),
        ('badsig', (False, False, False, 'B6C41CE35664996C', None)),
        ('no-pubkey', (False, False, False, None, None)),
    ],
)
def test_check_gpg_status(
    sampledir: str,
    source: str,
    expected: Tuple[bool, bool, bool, Optional[str], Optional[str]],
) -> None:
    with open(f'{sampledir}/gpg-{source}.txt', 'r') as fh:
        status = fh.read()
    assert b4.check_gpg_status(status) == expected


@pytest.mark.parametrize(
    'source,regex,ismbox',
    [
        (None, r'^From git@z ', False),
        (None, r'\n\nFrom git@z ', False),
        ('save-7bit-clean', r'From: Unicôdé', True),
        # mailbox.mbox does not properly handle 8bit-clean headers
        ('save-8bit-clean', r'From: Unicôdé', False),
    ],
)
def test_save_git_am_mbox(
    sampledir: Optional[str],
    tmp_path: pathlib.Path,
    source: Optional[str],
    regex: str,
    ismbox: bool,
) -> None:
    import re

    msgs: List[email.message.EmailMessage]
    if source is not None:
        if ismbox:
            msgs = b4.get_msgs_from_mailbox_or_maildir(f'{sampledir}/{source}.txt')
        else:
            with open(f'{sampledir}/{source}.txt', 'rb') as fh:
                msg = email.parser.BytesParser(
                    policy=b4.emlpolicy, _class=email.message.EmailMessage
                ).parse(fh)
            msgs = [msg]
    else:
        msgs = list()
        for x in range(0, 3):
            msg = email.message.EmailMessage()
            msg.set_payload(f'Hello world {x}\n')
            msg['Subject'] = f'Hello world {x}'
            msg['From'] = f'Me{x} <me{x}@foo.bar>'
            msgs.append(msg)
    dest = os.path.join(tmp_path, 'out')
    with open(dest, 'wb') as fh:
        b4.save_git_am_mbox(msgs, fh)
    with open(dest, 'r') as fh:
        res = fh.read()
    assert re.search(regex, res)


# A body line that git and liblore both take for an mbox separator
_SEPARATOR_LINE = (
    'From 008046b33ef4b476048e3ddb2c679a453254e535 Mon Sep 17 00:00:00 2001'
)


class TestSaveMboxrdMbox:
    """save_mboxrd_mbox() must write real mboxrd, so that reading it back
    gives the same messages with the same bodies."""

    @pytest.mark.parametrize(
        'line,escaped',
        [
            (_SEPARATOR_LINE, '>' + _SEPARATOR_LINE),
            ('From here on', '>From here on'),
            ('>From x', '>>From x'),
            ('>>From x', '>>>From x'),
            ('From: not a separator', 'From: not a separator'),
            ('> From x', '> From x'),
        ],
    )
    def test_round_trip(self, line: str, escaped: str) -> None:
        msgs = []
        for x in range(3):
            msg = email.message.EmailMessage()
            msg['From'] = f'Me{x} <me{x}@foo.bar>'
            msg['Subject'] = f'Re: hello {x}'
            msg['Message-Id'] = f'<msg{x}@foo.bar>'
            msg.set_payload(f'before\n\n{line}\nafter\n')
            msgs.append(msg)

        buf = io.BytesIO()
        b4.save_mboxrd_mbox(msgs, buf)
        out = buf.getvalue().decode()
        assert out.count(f'\n{escaped}\n') == 3

        back = b4.mailsplit_bytes(buf.getvalue())
        assert [b4.LoreMessage.get_clean_msgid(m) for m in back] == [
            'msg0@foo.bar',
            'msg1@foo.bar',
            'msg2@foo.bar',
        ]
        for orig, got in zip(msgs, back):
            # The splitter adds a newline to the last message; ignore it.
            got_payload = got.get_payload(decode=True)
            orig_payload = orig.get_payload(decode=True)
            assert isinstance(got_payload, bytes)
            assert isinstance(orig_payload, bytes)
            assert got_payload.rstrip(b'\n') == orig_payload.rstrip(b'\n')

    def test_headers_are_not_escaped(self) -> None:
        msg = email.message.EmailMessage()
        msg['From'] = 'Me <me@foo.bar>'
        msg['Subject'] = 'hello'
        msg.set_payload('From here on\n')
        buf = io.BytesIO()
        b4.save_mboxrd_mbox([msg], buf)
        assert buf.getvalue() == (
            b'From mboxrd@z Thu Jan  1 00:00:00 1970\n'
            b'From: Me <me@foo.bar>\n'
            b'Subject: hello\n'
            b'\n'
            b'>From here on\n'
        )


def _msgid_domain(msgid: str) -> str:
    return msgid.strip('<>').rsplit('@', maxsplit=1)[1]


def test_make_msgid_avoids_host_domain_by_default() -> None:
    stdlib_msgid = email.utils.make_msgid()
    b4_msgid = b4.make_msgid(idstring='b4-test')

    assert _msgid_domain(stdlib_msgid) == socket.getfqdn()
    assert _msgid_domain(b4_msgid) == 'b4'
    assert _msgid_domain(b4_msgid) != socket.getfqdn()


@pytest.mark.parametrize(
    'cmd,expected,check_opt_out',
    [
        # The custom command is only consulted when explicitly allowed.
        pytest.param(
            'echo custom-1234@example.com',
            '<custom-1234@example.com>',
            True,
            id='opt-in',
        ),
        pytest.param(
            'echo <wrapped-5678@example.com>',
            '<wrapped-5678@example.com>',
            False,
            id='preserves-brackets',
        ),
        # Config options defined multiple times arrive as a list; use the
        # first.
        pytest.param(
            ['echo first@example.com', 'echo second@example.com'],
            '<first@example.com>',
            False,
            id='list-uses-first',
        ),
    ],
)
def test_make_msgid_custom_cmd(
    monkeypatch: pytest.MonkeyPatch,
    cmd: Union[str, List[str]],
    expected: str,
    check_opt_out: bool,
) -> None:
    monkeypatch.setitem(b4.MAIN_CONFIG, 'custom-msgid-cmd', cmd)
    assert b4.make_msgid(allow_custom_msgid_cmd=True) == expected
    if check_opt_out:
        # Without the opt-in, the built-in id is used and the command is
        # ignored.
        assert _msgid_domain(b4.make_msgid(idstring='b4-review')) == 'b4'


@pytest.mark.parametrize(
    'cmdstr',
    [
        None,  # unset
        'false',  # command fails
        'true',  # command succeeds but produces no output
    ],
)
def test_make_msgid_custom_cmd_falls_back(
    monkeypatch: pytest.MonkeyPatch, cmdstr: Optional[str]
) -> None:
    monkeypatch.setitem(b4.MAIN_CONFIG, 'custom-msgid-cmd', cmdstr)
    msgid = b4.make_msgid(idstring='b4-ty', allow_custom_msgid_cmd=True)
    assert _msgid_domain(msgid) == 'b4'
    assert msgid.endswith('.b4-ty@b4>')


@pytest.mark.parametrize(
    'source,expected',
    [
        (
            'trailers-test-simple',
            [
                ('person', 'Reported-by', '"Doe, Jane" <jane@example.com>', None),
                ('person', 'Reviewed-by', 'Bogus Bupkes <bogus@example.com>', None),
                ('utility', 'Fixes', 'abcdef01234567890', None),
                ('utility', 'Link', 'https://msgid.link/some@msgid.here', None),
            ],
        ),
        (
            'trailers-test-extinfo',
            [
                ('person', 'Reported-by', 'Some, One <somewhere@example.com>', None),
                (
                    'person',
                    'Reviewed-by',
                    'Bogus Bupkes <bogus@example.com>',
                    '[for the parts that are bogus]',
                ),
                ('utility', 'Fixes', 'abcdef01234567890', None),
                (
                    'person',
                    'Tested-by',
                    'Some Person <bogus2@example.com>',
                    '           [this person visually indented theirs]',
                ),
                (
                    'utility',
                    'Link',
                    'https://msgid.link/some@msgid.here',
                    '  # initial submission',
                ),
                (
                    'person',
                    'Signed-off-by',
                    'Wrapped Persontrailer <broken@example.com>',
                    None,
                ),
            ],
        ),
    ],
)
def test_parse_trailers(
    sampledir: str, source: str, expected: List[Tuple[str, str, str, Optional[str]]]
) -> None:
    msgs = b4.get_msgs_from_mailbox_or_maildir(f'{sampledir}/{source}.txt')
    for msg in msgs:
        lmsg = b4.LoreMessage(msg)
        _, _, trs, _, _ = b4.LoreMessage.get_body_parts(lmsg.body)
        assert len(expected) == len(trs)
        for tr in trs:
            mytype, myname, myvalue, myextinfo = expected.pop(0)
            assert tr.name == myname
            assert tr.value == myvalue
            assert tr.extinfo == myextinfo
            assert tr.type == mytype

            mytr = b4.LoreTrailer(name=myname, value=myvalue, extinfo=myextinfo)
            assert tr == mytr
            assert tr.extinfo == mytr.extinfo


@pytest.mark.parametrize(
    'body,expected_fixes_values',
    [
        # Valid Fixes: trailer (SHA-1 style)
        (
            'Reviewed-by: Foo Bar <foo@example.com>\nFixes: abcdef012345 ("This is the commit subject")\n',
            ['abcdef012345 ("This is the commit subject")'],
        ),
        # Valid Fixes: trailer (SHA-256 style, 64 hex chars)
        (
            'Fixes: ' + 'a' * 64 + ' ("SHA-256 commit subject")\n',
            ['a' * 64 + ' ("SHA-256 commit subject")'],
        ),
        # Malformed: reviewer wrote "Fixes: ?" as a question — must be rejected
        (
            'Reviewed-by: Foo Bar <foo@example.com>\nFixes: ?\n',
            [],
        ),
        # Malformed: plain text value — must be rejected
        (
            'Fixes: some description with no hash\n',
            [],
        ),
        # Bare hash without parenthesised subject — also valid
        (
            'Fixes: abcdef012345\n',
            ['abcdef012345'],
        ),
    ],
)
def test_fixes_trailer_format_validation(
    body: str, expected_fixes_values: List[str]
) -> None:
    trailers, _ = b4.LoreMessage.find_trailers(body, followup=True)
    fixes = [t.value for t in trailers if t.name.lower() == 'fixes']
    assert fixes == expected_fixes_values


def test_mismatched_trailer_already_on_patch_is_not_flagged(
    sampledir: str,
) -> None:
    # A follow-up message can restate a trailer the patch already carries
    # (e.g. while quoting it for context, or suggesting a different order).
    # Since it's already on the patch, restating it isn't new information
    # from the replier, so it must not be flagged as a from/email mismatch
    # just because the replier isn't the trailer's original author.  A
    # genuinely new trailer from an unrelated address (the Mismatched
    # Reviewer message) must still be flagged.
    lmbx = b4.LoreMailbox()
    for msg in b4.get_msgs_from_mailbox_or_maildir(
        f'{sampledir}/trailers-followup-already-present.mbox'
    ):
        lmbx.add_message(msg)
    lser = lmbx.get_series()
    assert lser is not None
    mismatched_names = {tname for tname, _, _, _ in lser.trailer_mismatches}
    assert mismatched_names == {'Tested-by'}


@pytest.mark.parametrize(
    'name,value,exp_type,exp_addr,exp_value',
    [
        # Simple name
        (
            'Signed-off-by',
            'Simple Name <simple@example.com>',
            'person',
            ('Simple Name', 'simple@example.com'),
            'Simple Name <simple@example.com>',
        ),
        # Double quotes in display name must be preserved
        (
            'Signed-off-by',
            'Jane "JD" Doe <jd@example.com>',
            'person',
            ('Jane "JD" Doe', 'jd@example.com'),
            'Jane "JD" Doe <jd@example.com>',
        ),
        # Outer RFC 2822 quotes around a name with comma
        (
            'Reported-by',
            '"Doe, Jane" <jane@example.com>',
            'person',
            ('"Doe, Jane"', 'jane@example.com'),
            '"Doe, Jane" <jane@example.com>',
        ),
        # Comma in name without quotes
        (
            'Reported-by',
            'Some, One <somewhere@example.com>',
            'person',
            ('Some, One', 'somewhere@example.com'),
            'Some, One <somewhere@example.com>',
        ),
        # Parentheses in display name
        (
            'Tested-by',
            'Developer Foo (EXAMPLECORP) <dev@example.com>',
            'person',
            ('Developer Foo (EXAMPLECORP)', 'dev@example.com'),
            'Developer Foo (EXAMPLECORP) <dev@example.com>',
        ),
        # Bare angle-bracket email
        (
            'Cc',
            '<bare@example.com>',
            'person',
            ('', 'bare@example.com'),
            'bare@example.com',
        ),
        # Bare email without angle brackets
        (
            'Cc',
            'bare@example.com',
            'person',
            ('', 'bare@example.com'),
            'bare@example.com',
        ),
    ],
)
def test_trailer_addr_parsing(
    name: str, value: str, exp_type: str, exp_addr: Tuple[str, str], exp_value: str
) -> None:
    tr = b4.LoreTrailer(name=name, value=value)
    assert tr.type == exp_type
    assert tr.addr == exp_addr
    assert tr.value == exp_value


@pytest.mark.parametrize(
    'source,serargs,amargs,reference,b4cfg',
    [
        ('single', {}, {}, 'defaults', {}),
        ('single', {}, {'noaddtrailers': True}, 'noadd', {}),
        ('single', {}, {'addmysob': True}, 'addmysob', {}),
        ('single', {}, {'addmysob': True, 'copyccs': True}, 'copyccs', {}),
        ('single', {}, {'addmysob': True, 'addlink': True}, 'addlink', {}),
        (
            'single',
            {},
            {'addmysob': True, 'addlink': True},
            'addmsgid',
            {'linktrailermask': 'Message-ID: <%s>'},
        ),
        (
            'single',
            {},
            {'addmysob': True, 'copyccs': True},
            'ordered',
            {'trailer-order': 'Cc,Tested*,Reviewed*,*'},
        ),
        ('single', {'sloppytrailers': True}, {'addmysob': True}, 'sloppy', {}),
        ('with-cover', {}, {'addmysob': True}, 'defaults', {}),
        ('with-cover', {}, {'addmysob': True, 'addlink': True}, 'addlink', {}),
        ('custody', {}, {'addmysob': True, 'copyccs': True}, 'unordered', {}),
        (
            'custody',
            {},
            {'addmysob': True, 'copyccs': True},
            'ordered',
            {'trailer-order': 'Cc,Fixes*,Link*,Suggested*,Reviewed*,Tested*,*'},
        ),
        (
            'custody',
            {},
            {'addmysob': True, 'copyccs': True},
            'with-ignored',
            {'trailers-ignore-from': 'followup-reviewer1@example.com'},
        ),
        ('partial-reroll', {}, {'addmysob': True}, 'defaults', {}),
        ('nore', {}, {}, 'defaults', {}),
        ('non-git-patch', {}, {}, 'defaults', {}),
        ('non-git-patch-with-comments', {}, {}, 'defaults', {}),
        ('with-diffstat', {}, {}, 'defaults', {}),
        ('name-parens', {}, {}, 'defaults', {}),
        ('bare-address', {}, {}, 'defaults', {}),
        ('stripped-lines', {}, {}, 'defaults', {}),
        ('htmljunk', {}, {}, 'defaults', {}),
    ],
)
def test_followup_trailers(
    sampledir: str,
    source: str,
    serargs: Dict[str, Any],
    amargs: Dict[str, Any],
    reference: str,
    b4cfg: Dict[str, Any],
) -> None:
    b4.MAIN_CONFIG.update(b4cfg)
    lmbx = b4.LoreMailbox()
    for msg in b4.get_msgs_from_mailbox_or_maildir(
        f'{sampledir}/trailers-followup-{source}.mbox'
    ):
        lmbx.add_message(msg)
    lser = lmbx.get_series(**serargs)
    assert lser is not None
    amsgs = lser.get_am_ready(**amargs)
    ifh = io.BytesIO()
    b4.save_git_am_mbox(amsgs, ifh)
    with open(f'{sampledir}/trailers-followup-{source}-ref-{reference}.txt', 'r') as fh:
        assert ifh.getvalue().decode() == fh.read()


def _followup_trailer_keys(lser: b4.LoreSeries) -> List[List[Tuple[str, str, str]]]:
    """Each patch's follow-up trailers, with the message each came from."""
    return [
        [
            (t.name, t.value, t.lmsg.msgid if t.lmsg else '')
            for t in lmsg.followup_trailers
        ]
        for lmsg in lser.patches
        if lmsg is not None
    ]


@pytest.mark.parametrize(
    'source', ['single', 'with-cover', 'nore', 'name-parens', 'bare-address', 'custody']
)
def test_get_series_twice_adds_no_duplicate_trailers(
    sampledir: str, source: str
) -> None:
    """Asking a mailbox for the same series again gives the same series."""
    lmbx = b4.LoreMailbox()
    for msg in b4.get_msgs_from_mailbox_or_maildir(
        f'{sampledir}/trailers-followup-{source}.mbox'
    ):
        lmbx.add_message(msg)
    first = lmbx.get_series()
    assert first is not None
    before = _followup_trailer_keys(first)
    assert any(before), 'the sample should have follow-up trailers'
    slots = [p.msgid if p else None for p in first.patches]
    again = lmbx.get_series()
    assert again is not None
    # The cover letter is added again, and must not push out patch 1
    assert [p.msgid if p else None for p in again.patches] == slots
    assert _followup_trailer_keys(again) == before


def test_same_trailer_in_two_replies_is_kept_twice(sampledir: str) -> None:
    """Only a repeat from the same message is a duplicate, not a second reply."""
    msgs = b4.get_msgs_from_mailbox_or_maildir(
        f'{sampledir}/trailers-followup-nore.mbox'
    )
    lmbx = b4.LoreMailbox()
    for msg in msgs:
        lmbx.add_message(msg)
    lser = lmbx.get_series()
    assert lser is not None
    counted = [t for p in _followup_trailer_keys(lser) for t in p]
    name, value, src_msgid = counted[0]

    lmbx = b4.LoreMailbox()
    for msg in msgs:
        lmbx.add_message(msg)
        if b4.LoreMessage.get_clean_msgid(msg) == src_msgid:
            resend = copy.deepcopy(msg)
            del resend['Message-Id']
            resend['Message-Id'] = '<second-reply@example.com>'
            lmbx.add_message(resend)
    lser = lmbx.get_series()
    assert lser is not None
    # Deliberately called twice: get_series() must be able to run more than
    # once on the same mailbox (ab1a0d3) without adding each follow-up
    # trailer to its patch again.
    lser = lmbx.get_series()
    assert lser is not None
    sources = [
        m
        for p in _followup_trailer_keys(lser)
        for n, v, m in p
        if (n, v) == (name, value)
    ]
    assert sorted(sources) == sorted([src_msgid, 'second-reply@example.com'])


@pytest.mark.parametrize(
    'source,expect_cover,expect_subject',
    [
        # A cover with neither a [PATCH 0/N] prefix nor a diffstat is still
        # recognized when it is the same-author thread root of the series.
        ('single', True, 'do a thing to the widget subsystem'),
        # A patch sent in-reply-to someone else's bug report must not mistake
        # that report for a cover letter.
        ('bugreport', False, None),
    ],
)
def test_naked_cover_letter_detection(
    sampledir: str,
    source: str,
    expect_cover: bool,
    expect_subject: Optional[str],
) -> None:
    lmbx = b4.LoreMailbox()
    for msg in b4.get_msgs_from_mailbox_or_maildir(
        f'{sampledir}/naked-cover-{source}.mbox'
    ):
        lmbx.add_message(msg)
    lser = lmbx.get_series(codereview_trailers=False)
    assert lser is not None
    assert lser.has_cover is expect_cover
    if expect_subject is None:
        assert lser.patches[0] is None
    else:
        assert lser.patches[0] is not None
        assert lser.patches[0].subject == expect_subject


@pytest.mark.parametrize(
    'hval,verify,tr',
    [
        ('short-ascii', 'short-ascii', 'encode'),
        ('short-unicôde', '=?utf-8?q?short-unic=C3=B4de?=', 'encode'),
        # Long ascii
        (
            (
                'Lorem ipsum dolor sit amet consectetur adipiscing elit '
                'sed do eiusmod tempor incididunt ut labore et dolore magna aliqua'
            ),
            (
                'Lorem ipsum dolor sit amet consectetur adipiscing elit sed do\n'
                ' eiusmod tempor incididunt ut labore et dolore magna aliqua'
            ),
            'encode',
        ),
        # Long unicode
        (
            (
                'Lorem îpsum dolor sit amet consectetur adipiscing elît '
                'sed do eiusmod tempôr incididunt ut labore et dolôre magna aliqua'
            ),
            (
                '=?utf-8?q?Lorem_=C3=AEpsum_dolor_sit_amet_consectetur_adipiscin?=\n'
                ' =?utf-8?q?g_el=C3=AEt_sed_do_eiusmod_temp=C3=B4r_incididunt_ut_labore_et?=\n'
                ' =?utf-8?q?_dol=C3=B4re_magna_aliqua?='
            ),
            'encode',
        ),
        # Exactly 75 long
        (
            'Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiu',
            'Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiu',
            'encode',
        ),
        # Unicode that breaks on escape boundary
        (
            'Lorem ipsum dolor sit amet consectetur adipiscin elît',
            '=?utf-8?q?Lorem_ipsum_dolor_sit_amet_consectetur_adipiscin_el?=\n =?utf-8?q?=C3=AEt?=',
            'encode',
        ),
        # Unicode that's just 1 too long
        (
            'Lorem ipsum dolor sit amet consectetur adipi elît',
            '=?utf-8?q?Lorem_ipsum_dolor_sit_amet_consectetur_adipi_el=C3=AE?=\n =?utf-8?q?t?=',
            'encode',
        ),
        # A single address
        ('foo@example.com', 'foo@example.com', 'encode'),
        # Two addresses
        (
            'foo@example.com, bar@example.com',
            'foo@example.com, bar@example.com',
            'encode',
        ),
        # Mixed addresses
        (
            'foo@example.com, Foo Bar <bar@example.com>',
            'foo@example.com, Foo Bar <bar@example.com>',
            'encode',
        ),
        # Mixed Unicode
        (
            'foo@example.com, Foo Bar <bar@example.com>, Fôo Baz <baz@example.com>',
            'foo@example.com, Foo Bar <bar@example.com>, \n =?utf-8?q?F=C3=B4o_Baz?= <baz@example.com>',
            'encode',
        ),
        (
            'foo@example.com, Foo Bar <bar@example.com>, Fôo Baz <baz@example.com>, "Quux, Foo" <quux@example.com>',
            (
                'foo@example.com, Foo Bar <bar@example.com>, \n'
                ' =?utf-8?q?F=C3=B4o_Baz?= <baz@example.com>, "Quux, Foo" <quux@example.com>'
            ),
            'encode',
        ),
        (
            '01234567890123456789012345678901234567890123456789012345678901@example.org, ä <foo@example.org>',
            (
                '01234567890123456789012345678901234567890123456789012345678901@example.org, \n'
                ' =?utf-8?q?=C3=A4?= <foo@example.org>'
            ),
            'encode',
        ),
        # Test for https://github.com/python/cpython/issues/100900
        (
            'foo@example.com, Foo Bar <bar@example.com>, Fôo Baz <baz@example.com>, "Quûx, Foo" <quux@example.com>',
            (
                'foo@example.com, Foo Bar <bar@example.com>, \n'
                ' =?utf-8?q?F=C3=B4o_Baz?= <baz@example.com>, \n =?utf-8?q?Qu=C3=BBx=2C_Foo?= <quux@example.com>'
            ),
            'encode',
        ),
        # Test preserve
        (
            'foo@example.com, Foo Bar <bar@example.com>, Fôo Baz <baz@example.com>, "Quûx, Foo" <quux@example.com>',
            'foo@example.com, Foo Bar <bar@example.com>, Fôo Baz <baz@example.com>, \n "Quûx, Foo" <quux@example.com>',
            'preserve',
        ),
        # Test decode
        (
            'foo@example.com, Foo Bar <bar@example.com>, =?utf-8?q?Qu=C3=BBx=2C_Foo?= <quux@example.com>',
            'foo@example.com, Foo Bar <bar@example.com>, \n "Quûx, Foo" <quux@example.com>',
            'decode',
        ),
        # Test short message-id
        (
            'Message-ID: <20240319-short-message-id@example.com>',
            '<20240319-short-message-id@example.com>',
            'encode',
        ),
        # Test long message-id
        (
            'Message-ID: <20240319-very-long-message-id-that-spans-multiple-lines-for-sure-because-longer-than-75-characters-abcde123456@longdomain.example.com>',
            '<20240319-very-long-message-id-that-spans-multiple-lines-for-sure-because-longer-than-75-characters-abcde123456@longdomain.example.com>',
            'encode',
        ),
    ],
)
def test_header_wrapping(
    sampledir: str, hval: str, verify: str, tr: Literal['encode', 'decode', 'preserve']
) -> None:
    if ':' in hval:
        chunks = hval.split(':', maxsplit=1)
        hname = chunks[0].strip()
        hval = chunks[1].strip()
    else:
        hname = 'To' if '@' in hval else 'X-Header'
    wrapped = b4.LoreMessage.wrap_header((hname, hval), transform=tr)
    assert wrapped.decode() == f'{hname}: {verify}'
    _wname, wval = wrapped.split(b':', maxsplit=1)
    if tr != 'decode':
        cval = b4.LoreMessage.clean_header(wval.decode())
        assert cval == hval


@pytest.mark.parametrize(
    'pairs,verify,clean',
    [
        (
            [('', 'foo@example.com'), ('Foo Bar', 'bar@example.com')],
            'foo@example.com, Foo Bar <bar@example.com>',
            True,
        ),
        (
            [('', 'foo@example.com'), ('Foo, Bar', 'bar@example.com')],
            'foo@example.com, "Foo, Bar" <bar@example.com>',
            True,
        ),
        (
            [('', 'foo@example.com'), ('Fôo, Bar', 'bar@example.com')],
            'foo@example.com, "Fôo, Bar" <bar@example.com>',
            True,
        ),
        (
            [
                ('', 'foo@example.com'),
                ('=?utf-8?q?Qu=C3=BBx_Foo?=', 'quux@example.com'),
            ],
            'foo@example.com, Quûx Foo <quux@example.com>',
            True,
        ),
        (
            [
                ('', 'foo@example.com'),
                ('=?utf-8?q?Qu=C3=BBx=2C_Foo?=', 'quux@example.com'),
            ],
            'foo@example.com, "Quûx, Foo" <quux@example.com>',
            True,
        ),
        (
            [
                ('', 'foo@example.com'),
                ('=?utf-8?q?Qu=C3=BBx=2C_Foo?=', 'quux@example.com'),
            ],
            'foo@example.com, =?utf-8?q?Qu=C3=BBx=2C_Foo?= <quux@example.com>',
            False,
        ),
        # Pre-quoted display name with special chars must not be double-quoted
        (
            [('', 'foo@example.com'), ('"Example.org Tools"', 'tools@example.org')],
            'foo@example.com, "Example.org Tools" <tools@example.org>',
            True,
        ),
        (
            [('', 'foo@example.com'), ('"Doe, Jane"', 'jane@example.com')],
            'foo@example.com, "Doe, Jane" <jane@example.com>',
            True,
        ),
        # Unquoted name with internal quotes
        (
            [('', 'foo@example.com'), ('Jane "JD" Doe', 'jd@example.com')],
            'foo@example.com, "Jane \\"JD\\" Doe" <jd@example.com>',
            True,
        ),
        # Name starting with quote but not fully quoted
        (
            [('', 'foo@example.com'), ('"JD" Doe', 'jd@example.com')],
            'foo@example.com, "\\"JD\\" Doe" <jd@example.com>',
            True,
        ),
        # Pre-quoted name with internal quotes
        (
            [('', 'foo@example.com'), ('"Jane "JD" Doe"', 'jd@example.com')],
            'foo@example.com, "Jane \\"JD\\" Doe" <jd@example.com>',
            True,
        ),
    ],
)
def test_format_addrs(pairs: List[Tuple[str, str]], verify: str, clean: bool) -> None:
    formatted = b4.format_addrs(pairs, clean)
    assert formatted == verify


@pytest.mark.parametrize(
    'intrange,upper,expected',
    [
        ('1-3', 5, [1, 2, 3]),
        ('-1', 5, [5]),
        ('1,3-5', 5, [1, 3, 4, 5]),
        ('5', 5, [5]),
        # '<N' means everything below N
        ('<4', 5, [1, 2, 3]),
        ('<1', 5, []),
        ('1,3,4-', 6, [1, 3, 4, 5, 6]),
        ('1-3,5,-1', 7, [1, 2, 3, 5, 7]),
        ('-7', 5, []),
        ('1-8', 3, [1, 2, 3]),
    ],
)
def test_parse_int_range(intrange: str, upper: int, expected: List[int]) -> None:
    assert list(b4.parse_int_range(intrange, upper)) == expected


@pytest.mark.parametrize(
    'body_link,extra_link,expect_count',
    [
        # Exact same URL — should dedup to one
        (
            'https://patch.msgid.link/20240101-test-v1-1-abc123@example.com',
            'https://patch.msgid.link/20240101-test-v1-1-abc123@example.com',
            1,
        ),
        # Same URL, different case — should still dedup
        (
            'https://patch.msgid.link/20240101-TEST-V1-1-ABC123@example.com',
            'https://patch.msgid.link/20240101-test-v1-1-abc123@example.com',
            1,
        ),
        # Different domains, same message-id — should dedup to one
        (
            'https://lore.kernel.org/r/20240101-test-v1-1-abc123@example.com',
            'https://patch.msgid.link/20240101-test-v1-1-abc123@example.com',
            1,
        ),
        # URL-encoded message-id — should match decoded form
        (
            'https://lore.kernel.org/r/20240101-test-v1-1-abc123%40example.com',
            'https://patch.msgid.link/20240101-test-v1-1-abc123@example.com',
            1,
        ),
        # Different message-ids — both should survive
        (
            'https://lore.kernel.org/r/20240101-foo-v1-1-aaa@example.com',
            'https://patch.msgid.link/20240101-bar-v1-1-bbb@example.com',
            2,
        ),
    ],
)
def test_link_trailer_dedup(body_link: str, extra_link: str, expect_count: int) -> None:
    """Link: trailers already in the body should not be duplicated by extras."""
    raw = (
        f'From: Test Author <test@example.com>\n'
        f'Subject: [PATCH] test link dedup\n'
        f'Date: Mon, 1 Jan 2024 00:00:00 +0000\n'
        f'Message-Id: <20240101-test-v1-1-abc123@example.com>\n'
        f'\n'
        f'Commit body here.\n'
        f'\n'
        f'Signed-off-by: Test Author <test@example.com>\n'
        f'Link: {body_link}\n'
    )
    msg = email.message_from_string(raw, policy=email.policy.EmailPolicy(utf8=True))
    lmsg = b4.LoreMessage(msg)
    extra = b4.LoreTrailer(name='Link', value=extra_link)
    lmsg.fix_trailers(extras=[extra])
    # Count Link: trailers in the result
    _, _, trailers, _, _ = b4.LoreMessage.get_body_parts(lmsg.body)
    link_trailers = [t for t in trailers if t.lname == 'link']
    assert len(link_trailers) == expect_count


class TestTakeFlow:
    """Simulate the 'take' flow using the actual code path: build email
    messages (as if fetched from lore), feed through LoreMailbox →
    LoreSeries → get_am_ready(addlink=True) → git am.

    No network access — messages are constructed in-memory.
    """

    @staticmethod
    def _make_patch_msg(
        msgid: str,
        subject: str,
        body: str,
        diff: str,
        counter: int = 1,
        expected: int = 1,
        in_reply_to: Optional[str] = None,
    ) -> email.message.EmailMessage:
        """Build a realistic patch email like what lore returns.

        The *body* should contain the full commit message including
        trailers (Signed-off-by, Link, etc.) — just like a real patch
        email from a mailing list.
        """
        if expected > 1:
            prefix = f'[PATCH {counter}/{expected}]'
        else:
            prefix = '[PATCH]'
        raw = (
            f'From: Test Author <test@example.com>\n'
            f'Subject: {prefix} {subject}\n'
            f'Date: Mon, 1 Jan 2024 00:00:00 +0000\n'
            f'Message-Id: <{msgid}>\n'
        )
        if in_reply_to:
            raw += f'In-Reply-To: <{in_reply_to}>\n'
            raw += f'References: <{in_reply_to}>\n'
        raw += f'\n{body}\n---\n{diff}\n'
        return email.message_from_string(
            raw, policy=email.policy.EmailPolicy(utf8=True)
        )

    @staticmethod
    def _make_reply_msg(
        msgid: str,
        in_reply_to: str,
        from_name: str,
        from_email: str,
        trailer_lines: List[str],
    ) -> email.message.EmailMessage:
        """Build a followup reply with trailers."""
        trailers = '\n'.join(trailer_lines)
        raw = (
            f'From: {from_name} <{from_email}>\n'
            f'Subject: Re: [PATCH] test\n'
            f'Date: Mon, 1 Jan 2024 01:00:00 +0000\n'
            f'Message-Id: <{msgid}>\n'
            f'In-Reply-To: <{in_reply_to}>\n'
            f'References: <{in_reply_to}>\n'
            f'\n'
            f'> Some quoted text\n'
            f'\n'
            f'{trailers}\n'
        )
        return email.message_from_string(
            raw, policy=email.policy.EmailPolicy(utf8=True)
        )

    def test_link_dedup_with_followups(self, gitdir: str) -> None:
        """Patch already has Link: in body, get_am_ready(addlink=True)
        should not duplicate it.  Followup trailers should be added."""
        patch_msgid = '20240101-widget-v1-1-abc123@example.com'
        link_url = f'https://patch.msgid.link/{patch_msgid}'

        patch_msg = self._make_patch_msg(
            msgid=patch_msgid,
            subject='Add widget support',
            body=(
                'This adds a fancy widget.\n'
                '\n'
                'Signed-off-by: Test Author <test@example.com>\n'
                f'Link: {link_url}\n'
            ),
            diff=(
                ' file1.txt | 1 +\n'
                ' 1 file changed, 1 insertion(+)\n'
                '\n'
                'diff --git a/file1.txt b/file1.txt\n'
                'index b352682..6713e9f 100644\n'
                '--- a/file1.txt\n'
                '+++ b/file1.txt\n'
                '@@ -1,3 +1,4 @@\n'
                ' This is file 1.\n'
                ' It has a single line.\n'
                ' This is a second line I added.\n'
                '+widget\n'
            ),
        )

        reply_msg = self._make_reply_msg(
            msgid='reply-1@example.com',
            in_reply_to=patch_msgid,
            from_name='Reviewer One',
            from_email='reviewer@example.com',
            trailer_lines=[
                'Reviewed-by: Reviewer One <reviewer@example.com>',
            ],
        )

        reply_msg2 = self._make_reply_msg(
            msgid='reply-2@example.com',
            in_reply_to=patch_msgid,
            from_name='Acker Two',
            from_email='acker@example.com',
            trailer_lines=[
                'Acked-by: Acker Two <acker@example.com>',
            ],
        )

        # Feed through LoreMailbox → LoreSeries (actual take code path)
        lmbx = b4.LoreMailbox()
        for msg in [patch_msg, reply_msg, reply_msg2]:
            lmbx.add_message(msg)

        lser = lmbx.get_series()
        assert lser is not None

        am_msgs = lser.get_am_ready(addlink=True)
        assert len(am_msgs) == 1

        # Apply to master via git am
        ifh = io.BytesIO()
        b4.save_git_am_mbox(am_msgs, ifh)
        ecode, out = b4.git_run_command(gitdir, ['am'], stdin=ifh.getvalue())
        assert ecode == 0, f'git am failed: {out}'

        ecode, result = b4.git_run_command(gitdir, ['log', '-1', '--format=%B'])
        assert ecode == 0

        # Exactly one Link: trailer, not two
        assert result.count(f'Link: {link_url}') == 1, (
            f'Duplicate Link: found:\n{result}'
        )
        # Followup trailers applied
        assert 'Reviewed-by: Reviewer One <reviewer@example.com>' in result
        assert 'Acked-by: Acker Two <acker@example.com>' in result

    def test_link_added_when_not_present(self, gitdir: str) -> None:
        """Patch without Link: should get one added by addlink=True."""
        patch_msgid = '20240101-cursor-v1-1-def456@example.com'

        patch_msg = self._make_patch_msg(
            msgid=patch_msgid,
            subject='Fix cursor rendering',
            body=(
                'This fixes a cursor bug.\n'
                '\n'
                'Signed-off-by: Test Author <test@example.com>\n'
            ),
            diff=(
                ' file1.txt | 1 +\n'
                ' 1 file changed, 1 insertion(+)\n'
                '\n'
                'diff --git a/file1.txt b/file1.txt\n'
                'index b352682..e147dad 100644\n'
                '--- a/file1.txt\n'
                '+++ b/file1.txt\n'
                '@@ -1,3 +1,4 @@\n'
                ' This is file 1.\n'
                ' It has a single line.\n'
                ' This is a second line I added.\n'
                '+cursor fix\n'
            ),
        )

        lmbx = b4.LoreMailbox()
        lmbx.add_message(patch_msg)
        lser = lmbx.get_series()
        assert lser is not None

        am_msgs = lser.get_am_ready(addlink=True)
        assert len(am_msgs) == 1

        ifh = io.BytesIO()
        b4.save_git_am_mbox(am_msgs, ifh)
        ecode, out = b4.git_run_command(gitdir, ['am'], stdin=ifh.getvalue())
        assert ecode == 0, f'git am failed: {out}'

        ecode, result = b4.git_run_command(gitdir, ['log', '-1', '--format=%B'])
        assert ecode == 0

        expected_link = f'https://patch.msgid.link/{patch_msgid}'
        assert f'Link: {expected_link}' in result
        assert result.count('Link:') == 1

    def test_followup_trailers_without_addlink(self, gitdir: str) -> None:
        """Followups should be applied even with addlink=False."""
        patch_msgid = '20240101-verifier-v1-1-789abc@example.com'

        patch_msg = self._make_patch_msg(
            msgid=patch_msgid,
            subject='Refactor verifier',
            body=(
                'Clean up the verifier logic.\n'
                '\n'
                'Signed-off-by: Test Author <test@example.com>\n'
            ),
            diff=(
                ' file1.txt | 1 +\n'
                ' 1 file changed, 1 insertion(+)\n'
                '\n'
                'diff --git a/file1.txt b/file1.txt\n'
                'index b352682..6a8b771 100644\n'
                '--- a/file1.txt\n'
                '+++ b/file1.txt\n'
                '@@ -1,3 +1,4 @@\n'
                ' This is file 1.\n'
                ' It has a single line.\n'
                ' This is a second line I added.\n'
                '+verifier\n'
            ),
        )

        reply_msg = self._make_reply_msg(
            msgid='reply-v-1@example.com',
            in_reply_to=patch_msgid,
            from_name='Alice Author',
            from_email='alice@example.com',
            trailer_lines=[
                'Reviewed-by: Alice Author <alice@example.com>',
                'Tested-by: Alice Author <alice@example.com>',
            ],
        )

        lmbx = b4.LoreMailbox()
        for msg in [patch_msg, reply_msg]:
            lmbx.add_message(msg)
        lser = lmbx.get_series()
        assert lser is not None

        am_msgs = lser.get_am_ready(addlink=False)
        assert len(am_msgs) == 1

        ifh = io.BytesIO()
        b4.save_git_am_mbox(am_msgs, ifh)
        ecode, out = b4.git_run_command(gitdir, ['am'], stdin=ifh.getvalue())
        assert ecode == 0, f'git am failed: {out}'

        ecode, result = b4.git_run_command(gitdir, ['log', '-1', '--format=%B'])
        assert ecode == 0

        assert 'Reviewed-by: Alice Author <alice@example.com>' in result
        assert 'Tested-by: Alice Author <alice@example.com>' in result
        assert 'Link:' not in result

    def test_different_link_domains_same_msgid_deduped(self, gitdir: str) -> None:
        """If the patch body has a lore.kernel.org Link: and addlink
        generates a patch.msgid.link one for the same message-id,
        only the original should survive (dedup by message-id)."""
        patch_msgid = '20240101-drm-v1-1-aabbcc@example.com'
        lore_link = f'https://lore.kernel.org/r/{patch_msgid}'

        patch_msg = self._make_patch_msg(
            msgid=patch_msgid,
            subject='Fix DRM issue',
            body=(
                'Fix the DRM subsystem.\n'
                '\n'
                'Signed-off-by: Test Author <test@example.com>\n'
                f'Link: {lore_link}\n'
            ),
            diff=(
                ' file1.txt | 1 +\n'
                ' 1 file changed, 1 insertion(+)\n'
                '\n'
                'diff --git a/file1.txt b/file1.txt\n'
                'index b352682..4a2161b 100644\n'
                '--- a/file1.txt\n'
                '+++ b/file1.txt\n'
                '@@ -1,3 +1,4 @@\n'
                ' This is file 1.\n'
                ' It has a single line.\n'
                ' This is a second line I added.\n'
                '+drm fix\n'
            ),
        )

        lmbx = b4.LoreMailbox()
        lmbx.add_message(patch_msg)
        lser = lmbx.get_series()
        assert lser is not None

        am_msgs = lser.get_am_ready(addlink=True)
        assert len(am_msgs) == 1

        ifh = io.BytesIO()
        b4.save_git_am_mbox(am_msgs, ifh)
        ecode, out = b4.git_run_command(gitdir, ['am'], stdin=ifh.getvalue())
        assert ecode == 0, f'git am failed: {out}'

        ecode, result = b4.git_run_command(gitdir, ['log', '-1', '--format=%B'])
        assert ecode == 0

        # Same message-id in both URLs, so deduped to one Link:
        assert lore_link in result
        assert result.count('Link:') == 1


@pytest.mark.parametrize(
    'subject,extras,expected',
    [
        ('[PATCH] This is a patch', None, '[PATCH] This is a patch'),
        ('[PATCH v3] This is a patch', None, '[PATCH v3] This is a patch'),
        ('[PATCH RFC v3] This is a patch', None, '[PATCH RFC v3] This is a patch'),
        (
            '[RFC PATCH v3 1/3] This is a patch',
            None,
            '[RFC PATCH v3 1/3] This is a patch',
        ),
        (
            '[RESEND PATCH v3 1/3] This is a patch',
            None,
            '[RESEND PATCH v3 1/3] This is a patch',
        ),
        (
            '[PATCH RFC v3 2/3] This is a patch',
            ['RFC'],
            '[PATCH RFC v3 2/3] This is a patch',
        ),
        (
            '[PATCH RFC v3 3/12] This is a patch',
            None,
            '[PATCH RFC v3 03/12] This is a patch',
        ),
        (
            '[PATCH RFC v3] This is a [patch]',
            ['RFC'],
            '[PATCH RFC v3] This is a [patch]',
        ),
        (
            '[PATCH RFC v3 2/3] This is a patch',
            ['netdev', 'bpf'],
            '[PATCH RFC netdev bpf v3 2/3] This is a patch',
        ),
    ],
)
def test_lore_subject_prefixes(
    subject: str, extras: Optional[List[str]], expected: str
) -> None:
    lsubj = b4.LoreSubject(subject)
    assert lsubj.get_rebuilt_subject(eprefixes=extras) == expected


class TestGetLoreNode:
    """Tests for get_lore_node() liblore integration."""

    def setup_method(self) -> None:
        b4.LORENODE = None

    def test_uses_from_git_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_lore_node() constructs via LoreNode.from_git_config()."""
        from unittest.mock import MagicMock

        import liblore

        mock_node = MagicMock()
        mock_from_gc = MagicMock(return_value=mock_node)
        monkeypatch.setattr(liblore.LoreNode, 'from_git_config', mock_from_gc)
        node = b4.get_lore_node()
        mock_from_gc.assert_called_once()
        assert node is mock_node

    def test_sets_user_agent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_lore_node() calls set_user_agent with b4's identity."""
        from unittest.mock import MagicMock

        import liblore

        mock_node = MagicMock()
        monkeypatch.setattr(
            liblore.LoreNode, 'from_git_config', MagicMock(return_value=mock_node)
        )
        b4.get_lore_node()
        mock_node.set_user_agent.assert_called_once_with('b4', b4.__VERSION__)

    def test_passes_cache_settings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """cache_dir and cache_ttl from b4 config are passed through."""
        from unittest.mock import MagicMock

        import liblore

        b4.MAIN_CONFIG['cache-expire'] = '5'
        mock_node = MagicMock()
        mock_from_gc = MagicMock(return_value=mock_node)
        monkeypatch.setattr(liblore.LoreNode, 'from_git_config', mock_from_gc)
        b4.get_lore_node()
        call_kwargs = mock_from_gc.call_args.kwargs
        assert call_kwargs['cache_ttl'] == 300
        assert 'lore' in call_kwargs['cache_dir']

    def test_singleton(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Repeated calls return the same LoreNode instance."""
        from unittest.mock import MagicMock

        import liblore

        mock_node = MagicMock()
        mock_node.is_shutdown = False
        mock_from_gc = MagicMock(return_value=mock_node)
        monkeypatch.setattr(liblore.LoreNode, 'from_git_config', mock_from_gc)
        n1 = b4.get_lore_node()
        n2 = b4.get_lore_node()
        assert n1 is n2
        assert mock_from_gc.call_count == 1

    def test_rebuilds_after_shutdown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A shut-down node is replaced, not handed out again.

        LoreNodeShutdownMixin calls shutdown() whenever a TUI app exits,
        and shutdown() is terminal for the node.  When the process keeps
        going (a sibling app is starting), get_lore_node() must build a
        fresh node instead of returning one that refuses every request.
        """
        from unittest.mock import MagicMock

        import liblore

        dead_node = MagicMock()
        dead_node.is_shutdown = True
        fresh_node = MagicMock()
        fresh_node.is_shutdown = False
        mock_from_gc = MagicMock(side_effect=[dead_node, fresh_node])
        monkeypatch.setattr(liblore.LoreNode, 'from_git_config', mock_from_gc)

        n1 = b4.get_lore_node()
        assert n1 is dead_node
        n2 = b4.get_lore_node()
        assert n2 is fresh_node
        assert mock_from_gc.call_count == 2
        # The fresh node stays the singleton from here on.
        assert b4.get_lore_node() is fresh_node
        assert mock_from_gc.call_count == 2

    @staticmethod
    def _set_git_config(monkeypatch: pytest.MonkeyPatch, key: str, value: str) -> None:
        """Add *key* = *value* to the git config every git command sees."""
        count = int(os.environ.get('GIT_CONFIG_COUNT', '0'))
        monkeypatch.setenv('GIT_CONFIG_COUNT', str(count + 1))
        monkeypatch.setenv(f'GIT_CONFIG_KEY_{count}', key)
        monkeypatch.setenv(f'GIT_CONFIG_VALUE_{count}', value)

    def test_bad_allowupstream_is_config_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A value liblore rejects gives a LoreConfigError naming the section.

        liblore raises LibloreError for an allowupstream value that is not
        scheme://host, and without this every command that talks to lore
        would die with a traceback.
        """
        self._set_git_config(
            monkeypatch, 'liblore.https://lore.kernel.org.allowupstream', 'bogus'
        )
        with pytest.raises(b4.LoreConfigError) as exc:
            b4.get_lore_node()
        msg = str(exc.value)
        assert "'bogus'" in msg
        assert '[liblore "https://lore.kernel.org"] section (or [lore])' in msg
        # Nothing half-built is kept: the next call tries again.
        assert b4.LORENODE is None

    def test_config_error_names_mirror_section(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """For a local mirror the message names its own section, not [lore]."""
        b4.MAIN_CONFIG['midmask'] = 'http://127.0.0.1:11043/lore/all/%s'
        self._set_git_config(
            monkeypatch, 'liblore.http://127.0.0.1:11043.fallback', 'bogus'
        )
        with pytest.raises(b4.LoreConfigError) as exc:
            b4.get_lore_node()
        msg = str(exc.value)
        assert '[liblore "http://127.0.0.1:11043"] section of' in msg
        assert '[lore]' not in msg

    def test_cmd_exits_cleanly_on_config_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """b4 prints the config error and exits 1, with no traceback."""
        import b4.command
        import b4.mbox

        def needs_node(_cmdargs: object) -> None:
            raise b4.LoreConfigError('Bad liblore setting\nFix it here.')

        # Stand in for any command that talks to lore, and keep cmd()
        # from loading the real git config of whoever runs the tests.
        monkeypatch.setattr(b4.mbox, 'main', needs_node)
        monkeypatch.setattr(b4, 'setup_config', lambda _cmdargs: None)
        monkeypatch.setattr(sys, 'argv', ['b4', 'mbox', 'x@example.com'])
        handlers = list(b4.logger.handlers)
        try:
            with caplog.at_level(logging.CRITICAL, logger='b4'):
                with pytest.raises(SystemExit) as exc:
                    b4.command.cmd()
        finally:
            b4.logger.handlers[:] = handlers
        assert exc.value.code == 1
        crit = [r.getMessage() for r in caplog.records if r.levelno == logging.CRITICAL]
        assert crit[-2:] == ['Bad liblore setting', 'Fix it here.']


class TestLoreFetchMessages:
    """What get_pi_thread_by_msgid() and get_pi_search_results() tell the user."""

    MBOX = (
        b'From mboxrd@z Thu Jan  1 00:00:00 1970\n'
        b'From: Dev <dev@example.com>\n'
        b'Subject: [PATCH] thing\n'
        b'Message-Id: <thing@example.com>\n'
        b'\n'
        b'Body.\n'
    )

    @pytest.fixture
    def node(self, monkeypatch: pytest.MonkeyPatch) -> Any:
        from unittest.mock import MagicMock

        import liblore

        node = MagicMock()
        node.is_shutdown = False
        node.hostname = 'mirror.example.org'
        node.upstream_url = 'https://lore.kernel.org/all'
        node.last_source = liblore.Source.LOCAL
        monkeypatch.setattr(b4, 'LORENODE', node)
        return node

    @staticmethod
    def _messages(caplog: pytest.LogCaptureFixture, level: int) -> List[str]:
        return [r.getMessage() for r in caplog.records if r.levelno == level]

    @pytest.mark.parametrize(
        'make_exc,msgid,expected_critical',
        [
            pytest.param(
                lambda ll: ll.RemoteError(
                    'Server returned an error: 404', status_code=404
                ),
                'gone@example.com',
                'Thread not found on mirror.example.org: gone@example.com',
                id='404-says-not-found',
            ),
            pytest.param(
                lambda ll: ll.RemoteError(
                    'Server returned an error: 503', status_code=503
                ),
                'x@example.com',
                'Could not retrieve thread: Server returned an error: 503',
                id='server-error-keeps-detail',
            ),
            # liblore's message already names both the mirror and upstream.
            pytest.param(
                lambda ll: ll.NotOnMirrorError(
                    'mirror.example.org does not have it, '
                    'and lore.kernel.org did not answer'
                ),
                'x@example.com',
                'mirror.example.org does not have it, '
                'and lore.kernel.org did not answer',
                id='not-on-mirror-uses-liblore-message',
            ),
        ],
    )
    def test_thread_errors(
        self,
        node: Any,
        caplog: pytest.LogCaptureFixture,
        make_exc: Callable[[Any], Exception],
        msgid: str,
        expected_critical: str,
    ) -> None:
        import liblore

        node.get_mbox_by_msgid.side_effect = make_exc(liblore)
        with caplog.at_level(logging.INFO, logger='b4'):
            assert b4.get_pi_thread_by_msgid(msgid) is None
        assert self._messages(caplog, logging.CRITICAL) == [expected_critical]

    def test_thread_quiet_logs_nothing_on_error(
        self, node: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        import liblore

        node.get_mbox_by_msgid.side_effect = liblore.RemoteError(
            'Server returned an error: 404', status_code=404
        )
        with caplog.at_level(logging.DEBUG, logger='b4'):
            assert b4.get_pi_thread_by_msgid('x@example.com', quiet=True) is None
        assert caplog.records == []

    def test_thread_from_upstream_says_so(
        self, node: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        import liblore

        node.get_mbox_by_msgid.return_value = self.MBOX
        node.last_source = liblore.Source.UPSTREAM
        with caplog.at_level(logging.INFO, logger='b4'):
            msgs = b4.get_pi_thread_by_msgid('thing@example.com')
        assert msgs is not None and len(msgs) == 1
        assert (
            'Fetched from lore.kernel.org instead of mirror.example.org'
            in self._messages(caplog, logging.INFO)
        )

    def test_thread_from_mirror_is_silent_about_source(
        self, node: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        node.get_mbox_by_msgid.return_value = self.MBOX
        with caplog.at_level(logging.DEBUG, logger='b4'):
            assert b4.get_pi_thread_by_msgid('thing@example.com') is not None
        assert not any('Fetched from' in r.getMessage() for r in caplog.records)

    def test_thread_from_upstream_quiet(
        self, node: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        import liblore

        node.get_mbox_by_msgid.return_value = self.MBOX
        node.last_source = liblore.Source.UPSTREAM
        with caplog.at_level(logging.DEBUG, logger='b4'):
            assert (
                b4.get_pi_thread_by_msgid('thing@example.com', quiet=True) is not None
            )
        # Quiet keeps it out of the user's way, but --debug still shows it
        line = 'Fetched from lore.kernel.org instead of mirror.example.org'
        assert line in self._messages(caplog, logging.DEBUG)
        assert not any(
            'Fetched from' in r.getMessage()
            for r in caplog.records
            if r.levelno > logging.DEBUG
        )

    @pytest.mark.parametrize(
        'make_exc,query,expected_info',
        [
            pytest.param(
                lambda ll: ll.RemoteError(
                    'Server returned an error: 404', status_code=404
                ),
                's:nothing',
                'No messages found for that query',
                id='404-is-no-results',
            ),
            pytest.param(
                lambda ll: ll.RemoteError('Request failed: connection refused'),
                's:thing',
                'Could not search mirror.example.org: '
                'Request failed: connection refused',
                id='server-error-keeps-detail',
            ),
            pytest.param(
                lambda ll: ll.NotOnMirrorError(
                    'No results for the query on mirror.example.org, '
                    'and lore.kernel.org did not answer'
                ),
                's:thing',
                'No results for the query on mirror.example.org, '
                'and lore.kernel.org did not answer',
                id='not-on-mirror-uses-liblore-message',
            ),
        ],
    )
    def test_search_errors(
        self,
        node: Any,
        caplog: pytest.LogCaptureFixture,
        make_exc: Callable[[Any], Exception],
        query: str,
        expected_info: str,
    ) -> None:
        import liblore

        node.get_mbox_by_query.side_effect = make_exc(liblore)
        with caplog.at_level(logging.INFO, logger='b4'):
            assert b4.get_pi_search_results(query) is None
        assert self._messages(caplog, logging.INFO)[-1] == expected_info

    def test_search_from_upstream_is_debug(
        self, node: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        import liblore

        node.get_mbox_by_query.return_value = self.MBOX
        node.last_source = liblore.Source.UPSTREAM
        with caplog.at_level(logging.DEBUG, logger='b4'):
            msgs = b4.get_pi_search_results('s:thing')
        assert msgs is not None and len(msgs) == 1
        line = 'Fetched from lore.kernel.org instead of mirror.example.org'
        assert line in self._messages(caplog, logging.DEBUG)
        assert line not in self._messages(caplog, logging.INFO)

    @pytest.mark.parametrize('quiet', [False, True], ids=['loud', 'quiet'])
    def test_tracker_sees_upstream_thread(self, node: Any, quiet: bool) -> None:
        import liblore

        node.get_mbox_by_msgid.return_value = self.MBOX
        node.last_source = liblore.Source.UPSTREAM
        with b4.track_lore_sources() as sources:
            b4.get_pi_thread_by_msgid('thing@example.com', quiet=quiet)
        assert sources == {liblore.Source.UPSTREAM}

    def test_tracker_sees_every_source(self, node: Any) -> None:
        import liblore

        node.get_mbox_by_msgid.return_value = self.MBOX
        node.get_mbox_by_query.return_value = self.MBOX
        with b4.track_lore_sources() as sources:
            b4.get_pi_thread_by_msgid('thing@example.com')
            node.last_source = liblore.Source.UPSTREAM
            b4.get_pi_search_results('s:thing')
        assert sources == {liblore.Source.LOCAL, liblore.Source.UPSTREAM}

    def test_tracker_ignores_failed_fetch(self, node: Any) -> None:
        import liblore

        node.get_mbox_by_query.side_effect = liblore.RemoteError(
            'Server returned an error: 404', status_code=404
        )
        node.last_source = None
        with b4.track_lore_sources() as sources:
            b4.get_pi_search_results('s:nothing')
        assert sources == set()

    def test_tracker_nested_block_adds_to_outer(self, node: Any) -> None:
        import liblore

        node.get_mbox_by_msgid.return_value = self.MBOX
        with b4.track_lore_sources() as outer:
            with b4.track_lore_sources() as inner:
                node.last_source = liblore.Source.UPSTREAM
                b4.get_pi_thread_by_msgid('thing@example.com')
            node.last_source = liblore.Source.LOCAL
            b4.get_pi_thread_by_msgid('thing@example.com')
        assert inner == {liblore.Source.UPSTREAM}
        assert outer == {liblore.Source.LOCAL, liblore.Source.UPSTREAM}

    def test_tracker_off_outside_block(self, node: Any) -> None:
        import liblore

        node.get_mbox_by_msgid.return_value = self.MBOX
        with b4.track_lore_sources() as sources:
            pass
        node.last_source = liblore.Source.UPSTREAM
        b4.get_pi_thread_by_msgid('thing@example.com')
        assert sources == set()

    def test_tracker_is_per_thread(self, node: Any) -> None:
        import threading

        import liblore

        node.get_mbox_by_msgid.return_value = self.MBOX
        node.last_source = liblore.Source.UPSTREAM
        with b4.track_lore_sources() as sources:
            t = threading.Thread(
                target=b4.get_pi_thread_by_msgid, args=('thing@example.com',)
            )
            t.start()
            t.join()
        assert sources == set()


class TestHasAttestationHeaders:
    """LoreMessage.has_attestation_headers looks at headers only."""

    @staticmethod
    def _lmsg(*headers: Tuple[str, str]) -> b4.LoreMessage:
        msg = email.message.EmailMessage()
        msg['From'] = 'Dev <dev@example.com>'
        msg['Subject'] = '[PATCH] thing'
        msg['Message-Id'] = '<thing@example.com>'
        for name, value in headers:
            msg[name] = value
        msg.set_content('Body.\n')
        return b4.LoreMessage(msg)

    @pytest.fixture
    def config(self, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Any]:
        config = dict(b4.get_main_config())
        config['attestation-policy'] = 'softfail'
        config['attestation-check-dkim'] = 'yes'
        monkeypatch.setattr(b4, 'get_main_config', lambda: config)
        return config

    @pytest.mark.parametrize(
        'headers,overrides,expected',
        [
            pytest.param([], {}, False, id='unsigned'),
            pytest.param(
                [(b4.DEVSIG_HDR, 'v=1; a=ed25519; b=AAAA')], {}, True, id='patatt'
            ),
            pytest.param(
                [('DKIM-Signature', 'v=1; d=example.com')], {}, True, id='dkim'
            ),
            pytest.param(
                [('DKIM-Signature', 'v=1; d=example.com')],
                {'attestation-check-dkim': 'no'},
                False,
                id='dkim-check-off',
            ),
            pytest.param(
                [(b4.DEVSIG_HDR, 'v=1; a=ed25519; b=AAAA')],
                {'attestation-policy': 'off'},
                False,
                id='policy-off',
            ),
        ],
    )
    def test_has_attestation_headers(
        self,
        config: Dict[str, Any],
        headers: List[Tuple[str, str]],
        overrides: Dict[str, str],
        expected: bool,
    ) -> None:
        config.update(overrides)
        lmsg = self._lmsg(*headers)
        assert bool(lmsg.has_attestation_headers) is expected
        if overrides:
            # Disabled by config: nothing is collected either.
            assert lmsg.attestors == []


class TestDeprecatedConfig:
    """Tests for the b4.searchmask deprecation notice."""

    def test_warns_when_set_in_git_config(
        self, gitdir: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Someone who still has the setting in git-config gets told."""
        b4.git_set_config(gitdir, 'b4.searchmask', 'https://example.com/?q=%s')
        with caplog.at_level(logging.WARNING, logger='b4'):
            b4._setup_main_config(topdir=gitdir)
        assert 'b4.searchmask is deprecated' in caplog.text

    def test_silent_when_unset(
        self, gitdir: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """No setting, no nagging."""
        with caplog.at_level(logging.WARNING, logger='b4'):
            b4._setup_main_config(topdir=gitdir)
        assert 'searchmask' not in caplog.text

    def test_silent_when_only_in_worktree_config(
        self, gitdir: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A series' own .b4-config must not nag about someone else's config.

        Deprecated *mask settings match one of the wtglobs, so they are
        loaded from a project's .b4-config, too. The warning is advice for
        the person running b4, and they cannot act on a setting that arrived
        with a series they just applied.
        """
        wtcfg = pathlib.Path(gitdir) / '.b4-config'
        wtcfg.write_text('[b4]\n\tsearchmask = https://example.com/?q=%s\n')
        with caplog.at_level(logging.WARNING, logger='b4'):
            b4._setup_main_config(topdir=gitdir)
        # Sanity: the value really did make it into the merged config, so
        # checking git-config is what keeps this quiet.
        assert b4.MAIN_CONFIG.get('searchmask') == 'https://example.com/?q=%s'
        assert 'searchmask' not in caplog.text


class _FakeClock:
    """Stands in for the time module inside dns.resolver."""

    def __init__(self) -> None:
        self.now = 1_000_000.0

    def time(self) -> float:
        return self.now

    def sleep(self, secs: float) -> None:
        self.now += secs


class TestDnsCache:
    """DKIM key lookups are cached, so a series doesn't ask DNS per patch."""

    TEST_NS = '192.0.2.53'

    @pytest.fixture(autouse=True)
    def fake_dns(self, monkeypatch: pytest.MonkeyPatch) -> List[Tuple[str, str]]:
        """Answer every query with a TXT record, and log each one asked."""
        monkeypatch.setattr(dns.resolver, 'default_resolver', None)
        monkeypatch.setattr(b4, '_DNS_CACHE', dns.resolver.LRUCache())
        self.clock = _FakeClock()
        monkeypatch.setattr(dns.resolver, 'time', self.clock)
        self.asked: List[Tuple[str, str]] = []

        def fake_udp(
            q: dns.message.Message, where: str, *args: Any, **kwargs: Any
        ) -> dns.message.Message:
            qname = q.question[0].name
            self.asked.append((qname.to_text(), where))
            resp = dns.message.make_response(q)
            resp.answer.append(
                dns.rrset.from_text(qname, 300, 'IN', 'TXT', '"v=DKIM1; p=AAAA"')
            )
            # Through the wire format, like a real answer: the resolver
            # only matches the answer to the question (and so only takes
            # its TTL) in a parsed message.
            return dns.message.from_wire(resp.to_wire())

        monkeypatch.setattr(dns.query, 'udp', fake_udp)
        return self.asked

    def _setup(self) -> None:
        b4._setup_dns_resolver({'attestation-dns-resolvers': self.TEST_NS})

    def test_repeated_lookups_ask_once(self) -> None:
        """Ten patches signed with one key cost one DNS query."""
        self._setup()
        name = b'sel._domainkey.example.org'
        answers = {dkim.dnsplug.get_txt(name) for _ in range(10)}
        assert answers == {b'v=DKIM1; p=AAAA'}
        assert self.asked == [('sel._domainkey.example.org.', self.TEST_NS)]

    def test_different_keys_are_asked_separately(self) -> None:
        """The cache is per name: other signers still get their own key."""
        self._setup()
        for _ in range(3):
            dkim.dnsplug.get_txt(b'a._domainkey.example.org')
            dkim.dnsplug.get_txt(b'b._domainkey.example.net')
        assert sorted(n for n, _ in self.asked) == [
            'a._domainkey.example.org.',
            'b._domainkey.example.net.',
        ]

    def test_expired_answer_is_asked_again(self) -> None:
        """An answer past its TTL is not used, so a rotated key is seen."""
        self._setup()
        name = b'sel._domainkey.example.org'
        dkim.dnsplug.get_txt(name)
        self.clock.now += 299
        dkim.dnsplug.get_txt(name)
        assert len(self.asked) == 1
        self.clock.now += 2
        dkim.dnsplug.get_txt(name)
        assert len(self.asked) == 2

    def test_cache_survives_config_reload(self) -> None:
        """Reloading the config (cron does it per project) keeps answers."""
        self._setup()
        name = b'sel._domainkey.example.org'
        dkim.dnsplug.get_txt(name)
        self._setup()
        dkim.dnsplug.get_txt(name)
        assert len(self.asked) == 1

    def test_system_resolver_gets_cache(self) -> None:
        """Without configured resolvers, the system resolver is cached too."""
        system = dns.resolver.Resolver(configure=False)
        system.nameservers = ['198.51.100.53']
        dns.resolver.default_resolver = system
        b4._setup_dns_resolver({'attestation-dns-resolvers': None})
        assert dns.resolver.get_default_resolver() is system
        dkim.dnsplug.get_txt(b'sel._domainkey.example.org')
        dkim.dnsplug.get_txt(b'sel._domainkey.example.org')
        assert self.asked == [('sel._domainkey.example.org.', '198.51.100.53')]

    def test_blank_resolver_list_keeps_system_resolver(self) -> None:
        """A setting with only commas and spaces names no servers."""
        system = dns.resolver.Resolver(configure=False)
        system.nameservers = ['198.51.100.53']
        dns.resolver.default_resolver = system
        b4._setup_dns_resolver({'attestation-dns-resolvers': ' , '})
        assert dns.resolver.get_default_resolver() is system
        assert system.cache is b4._DNS_CACHE


class _ExpiringDKIM(dkim.DKIM):  # type: ignore[misc]
    """Signs with an expiry time (x=), like Gmail does.

    dkimpy can verify x= but has no option to sign with it.
    """

    def __init__(self, message: bytes, expire: int) -> None:
        super().__init__(message)
        self._expire = expire

    def gen_header(
        self,
        fields: List[Tuple[bytes, bytes]],
        include_headers: Any,
        canon_policy: Any,
        header_name: bytes,
        pk: Any,
        standardize: bool = False,
    ) -> bytes:
        # b= must stay last: it is filled in after the rest is signed
        fields = [f for f in fields if f[0] != b'b']
        fields += [(b'x', str(self._expire).encode()), (b'b', b'0' * 60)]
        return bytes(
            super().gen_header(
                fields, include_headers, canon_policy, header_name, pk, standardize
            )
        )


class TestDkimStore:
    """A DKIM signature that passed once keeps passing."""

    DAY = 86400
    MSG = (
        b'From: Dev Eloper <dev@example.org>\r\n'
        b'To: list@example.com\r\n'
        b'Subject: [PATCH] foo: fix the bar\r\n'
        b'Date: Sat, 03 Oct 2026 12:00:00 +0000\r\n'
        b'Message-ID: <dkim-test@example.org>\r\n'
        b'\r\n'
        b'Just a test.\r\n'
    )

    @pytest.fixture(autouse=True)
    def fake_dkim_dns(self, monkeypatch: pytest.MonkeyPatch, sampledir: str) -> None:
        """Serve the test key from fake DNS, on a clock the test controls."""
        samples = pathlib.Path(sampledir)
        self.privkey = (samples / 'dkim-test.key').read_bytes()
        self.pubkey = (samples / 'dkim-test.pub').read_text().strip()
        monkeypatch.setattr(b4, 'can_network', True)
        monkeypatch.setitem(b4.MAIN_CONFIG, 'attestation-policy', 'softfail')
        self.clock = _FakeClock()
        self.clock.now = 1_790_000_000.0
        monkeypatch.setattr(dkim, 'time', self.clock)
        self.lookups = 0
        self.dns_works = True

        def fake_get_txt(name: str, timeout: int = 5) -> Optional[str]:
            self.lookups += 1
            if not self.dns_works or name != 'test._domainkey.example.org.':
                return None
            return f'v=DKIM1; k=rsa; p={self.pubkey}'

        monkeypatch.setattr(dkim.dnsplug, '_get_txt', fake_get_txt)

    def _sign(self, expire_in: int = 0, body: bytes = b'') -> bytes:
        msg = self.MSG + body
        if expire_in:
            signer = _ExpiringDKIM(msg, int(self.clock.now) + expire_in)
        else:
            signer = dkim.DKIM(msg)
        sig = signer.sign(
            b'test',
            b'example.org',
            self.privkey,
            include_headers=[b'from', b'to', b'subject', b'date', b'message-id'],
        )
        return bytes(sig) + msg

    @staticmethod
    def _check(raw: bytes) -> List[Any]:
        """The DKIM attestors of a freshly parsed copy of *raw*."""
        msg = email.parser.BytesParser(
            policy=b4.emlpolicy, _class=email.message.EmailMessage
        ).parsebytes(raw)
        return [a for a in b4.LoreMessage(msg).attestors if a.mode == 'DKIM']

    def _passes(self, raw: bytes) -> bool:
        atts = self._check(raw)
        assert len(atts) == 1
        assert atts[0].identity == 'example.org'
        return bool(atts[0].passing)

    def test_pass_is_not_checked_again(self) -> None:
        """The second look at a verified message needs no DNS at all."""
        raw = self._sign()
        assert self._passes(raw)
        assert self.lookups == 1
        assert self._passes(raw)
        assert self.lookups == 1

    def test_expired_signature_passes_once_verified(self) -> None:
        """A Gmail-style x= expiry doesn't undo a pass from before it."""
        raw = self._sign(expire_in=3 * self.DAY)
        assert self._passes(raw)
        self.clock.now += 7 * self.DAY
        assert self._passes(raw)

    def test_expired_signature_fails_if_never_verified(self) -> None:
        """The store vouches only for what b4 really verified."""
        raw = self._sign(expire_in=3 * self.DAY)
        self.clock.now += 7 * self.DAY
        assert not self._passes(raw)

    def test_removed_key_passes_once_verified(self) -> None:
        """A key rotated out of DNS doesn't undo an earlier pass."""
        raw = self._sign()
        assert self._passes(raw)
        self.dns_works = False
        assert self._passes(raw)

    def test_failure_is_not_remembered(self) -> None:
        """A DNS hiccup is checked again next time, not stored as a fail."""
        raw = self._sign()
        self.dns_works = False
        assert not self._passes(raw)
        self.dns_works = True
        assert self._passes(raw)
        assert self.lookups == 2

    def test_changed_message_is_checked_again(self) -> None:
        """A pass is for the exact bytes, so an edited copy is not trusted."""
        raw = self._sign()
        assert self._passes(raw)
        tampered = raw.replace(b'Just a test.', b'Just a trap.')
        assert not self._passes(tampered)
        assert self.lookups == 2

    def test_offline_uses_remembered_pass(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without network, a message verified before still shows its pass."""
        raw = self._sign()
        assert self._passes(raw)
        monkeypatch.setattr(b4, 'can_network', False)
        assert self._passes(raw)
        assert self.lookups == 1

    def test_offline_skips_unverified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without network, a message never verified gets no DKIM result."""
        monkeypatch.setattr(b4, 'can_network', False)
        assert self._check(self._sign()) == []
        assert self.lookups == 0

    def test_unusable_store_still_verifies(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
    ) -> None:
        """If the store can't be opened, b4 checks every time, as before."""
        blocker = tmp_path / 'not-a-dir'
        blocker.write_text('')
        monkeypatch.setattr(
            b4, '_dkim_store_path', lambda: str(blocker / 'dkim.sqlite3')
        )
        raw = self._sign()
        assert self._passes(raw)
        assert self._passes(raw)
        assert self.lookups == 2


@pytest.mark.parametrize(
    'urls,expected',
    [
        # lore /r/ style and patch.msgid.link both yield the bare msgid
        (
            {'https://lore.kernel.org/r/20240101-foo-1-aaa@example.com'},
            {'20240101-foo-1-aaa@example.com'},
        ),
        (
            {'https://patch.msgid.link/20240101-foo-1-aaa@example.com'},
            {'20240101-foo-1-aaa@example.com'},
        ),
        # URL-encoded @ is decoded
        (
            {'https://lore.kernel.org/r/20240101-foo-1-aaa%40example.com'},
            {'20240101-foo-1-aaa@example.com'},
        ),
        # A URL with no message-id (no @) yields nothing
        ({'https://bugs.example.com/show_bug.cgi?id=123'}, set()),
    ],
)
def test_get_all_msgids_from_urls(urls: Set[str], expected: Set[str]) -> None:
    assert b4.get_all_msgids_from_urls(urls) == expected


def test_get_link_msgids_from_lmsg() -> None:
    """Only Link:-type trailers that resolve to a message-id are returned."""
    raw = (
        'From: Test Author <test@example.com>\n'
        'Subject: [PATCH] does a thing\n'
        'Date: Mon, 1 Jan 2024 00:00:00 +0000\n'
        'Message-Id: <local-commit@example.com>\n'
        '\n'
        'Commit body here.\n'
        '\n'
        'Signed-off-by: Test Author <test@example.com>\n'
        'Link: https://lore.kernel.org/r/20240101-orig-1-abc@example.com\n'
        'Closes: https://bugs.example.com/show_bug.cgi?id=123\n'
    )
    msg = email.message_from_string(raw, policy=email.policy.EmailPolicy(utf8=True))
    lmsg = b4.LoreMessage(msg)
    # The Link: resolves to a msgid; the Closes: bug URL has no msgid, and the
    # Signed-off-by is not a link trailer at all.
    assert b4.get_link_msgids_from_lmsg(lmsg) == {'20240101-orig-1-abc@example.com'}


def test_map_codereview_trailers_exposes_parent_patches(sampledir: str) -> None:
    """The optional parent_patches out-param is populated with the parent
    patch's identity (subject + msgid) so callers can fuzzy-match when the
    patch-id no longer lines up with a local commit."""
    mfile = os.path.join(sampledir, 'trailers-thread-with-followups.mbox')
    msgs = b4.get_msgs_from_mailbox_or_maildir(mfile)
    parent_patches: Dict[str, b4.LoreMessage] = dict()
    patchid_map = b4.map_codereview_trailers(msgs, parent_patches=parent_patches)
    # The only follow-up (fwup1) replied to patch 4/4, so exactly that patch's
    # patch-id should carry a follow-up and a recorded parent identity.
    assert patchid_map
    assert set(parent_patches.keys()) == set(patchid_map.keys())
    (patchid,) = patchid_map.keys()
    parent = parent_patches[patchid]
    assert parent.subject == 'Minor typo changes imitation'
    assert parent.msgid == '20221025-test1-v1-4-e4f28f57990c@linuxfoundation.org'


def test_edit_in_editor_normalizes_crlf(
    gitdir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The edited buffer comes back with unix line endings even when the
    editor saved it with CRLF (e.g. mail-oriented configs forcing
    fileformat=dos on .eml files)."""
    # 'true' leaves the buffer untouched, so the CRLF input stands in for an
    # editor that saved the file with dos line endings.
    monkeypatch.setenv('GIT_EDITOR', 'true')
    out = b4.edit_in_editor(b'line one\r\nline two\r\rlast\r\n', filehint='reply.eml')
    assert out == b'line one\nline two\n\nlast\n'


def test_git_run_command_log_fixup_looks_past_option_prefix(gitdir: str) -> None:
    """``--no-abbrev-commit`` must survive a leading ``-c`` override.

    git_run_command counteracts log.abbrevCommit by injecting the flag after
    the subcommand -- which it can only find by skipping the ``-c key=value``
    pairs callers prefix (see SCRATCH_GIT_OPTS).
    """
    b4.git_set_config(gitdir, 'log.abbrevCommit', 'true')
    ecode, out = b4.git_run_command(gitdir, ['-c', 'gc.auto=0', 'log', '-1'])
    assert ecode == 0
    assert out.startswith('commit '), out
    sha = out.split('\n', 1)[0].split()[1]
    assert len(sha) == 40, f'log abbreviated the sha despite the fixup: {sha}'


class TestGitBranchCheckedOut:
    """Tests for git_branch_checked_out()."""

    @pytest.mark.parametrize(
        'branch,create,expected',
        [
            # The branch checked out in the main worktree is detected.
            pytest.param(None, False, True, id='current-branch'),
            # An existing but not checked-out branch is not flagged.
            pytest.param('parked-branch', True, False, id='other-branch'),
            pytest.param('no-such-branch', False, False, id='nonexistent-branch'),
        ],
    )
    def test_branch_checked_out(
        self, gitdir: str, branch: Optional[str], create: bool, expected: bool
    ) -> None:
        if branch is None:
            ecode, out = b4.git_run_command(gitdir, ['branch', '--show-current'])
            assert ecode == 0
            branch = out.strip()
        if create:
            ecode, _ = b4.git_run_command(gitdir, ['branch', branch])
            assert ecode == 0
        assert b4.git_branch_checked_out(gitdir, branch) is expected

    def test_linked_worktree_branch(self, gitdir: str, tmp_path: pathlib.Path) -> None:
        """A branch checked out in a linked worktree is detected too."""
        wtpath = str(tmp_path / 'linked-wt')
        ecode, out = b4.git_run_command(
            gitdir, ['worktree', 'add', '-b', 'wt-branch', wtpath], logstderr=True
        )
        assert ecode == 0, out
        try:
            assert b4.git_branch_checked_out(gitdir, 'wt-branch') is True
            assert b4.git_branch_checked_out(gitdir, 'refs/heads/wt-branch') is True
        finally:
            b4.git_run_command(gitdir, ['worktree', 'remove', '--force', wtpath])


class TestSendemailLocalcmd:
    """Tests for get_sendemail_localcmd() and the local-command path of get_smtp()."""

    @pytest.mark.parametrize(
        'sendemail_cfg,expected',
        [
            # sendmailCmd wins over smtpServer, matching git behavior.
            pytest.param(
                {'sendmailcmd': 'msmtp', 'smtpserver': 'smtp.example.org'},
                'msmtp',
                id='sendmailcmd-takes-precedence',
            ),
            # The historical spelling: a path as the smtpServer value.
            pytest.param(
                {'smtpserver': '/usr/bin/msmtp'},
                '/usr/bin/msmtp',
                id='pathlike-smtpserver',
            ),
            pytest.param(
                {'smtpserver': 'smtp.example.org'}, None, id='smtp-host-is-not-localcmd'
            ),
            pytest.param({}, None, id='no-transport-configured'),
        ],
    )
    def test_get_sendemail_localcmd(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sendemail_cfg: Dict[str, str],
        expected: Optional[str],
    ) -> None:
        monkeypatch.setattr(b4, 'SENDEMAIL_CONFIG', sendemail_cfg)
        assert b4.get_sendemail_localcmd() == expected

    @pytest.mark.parametrize(
        'sendemail_cfg,expected_cmd',
        [
            # A bare command without slashes must work, like git's
            # sendmailCmd.
            pytest.param(
                {
                    'sendmailcmd': 'msmtp --account=work',
                    'from': 'Alice Developer <alice@example.org>',
                    'envelopesender': 'auto',
                },
                ['msmtp', '--account=work', '-i', '-f', 'alice@example.org'],
                id='uses-sendmailcmd',
            ),
            pytest.param(
                {
                    'smtpserver': '/usr/bin/msmtp',
                    'from': 'Alice Developer <alice@example.org>',
                },
                ['/usr/bin/msmtp', '-i'],
                id='pathlike-smtpserver',
            ),
        ],
    )
    def test_get_smtp_local_command(
        self,
        monkeypatch: pytest.MonkeyPatch,
        sendemail_cfg: Dict[str, str],
        expected_cmd: List[str],
    ) -> None:
        monkeypatch.setattr(b4, 'SENDEMAIL_CONFIG', sendemail_cfg)
        smtp, fromaddr = b4.get_smtp()
        assert smtp == expected_cmd
        assert fromaddr == 'Alice Developer <alice@example.org>'


def _plain_msg(subject: str) -> email.message.EmailMessage:
    msg = email.message.EmailMessage()
    msg['Subject'] = subject
    msg['From'] = 'alice@example.org'
    msg['To'] = 'bob@example.org'
    msg.set_content('body')
    return msg


class _FakeSMTP:
    """Just enough of smtplib.SMTP to satisfy send_mail()."""

    def __init__(self, log: List[str]) -> None:
        self._log = log

    def sendmail(self, fromaddr: str, destaddrs: List[str], bdata: bytes) -> None:
        self._log.append('send')


class TestSignBeforeConnect:
    """Signing must finish before we open the SMTP connection.

    patatt shells out to gpg for PGP keys, which can block indefinitely on a
    pinentry passphrase prompt.  Connecting first holds an idle socket open for
    the duration and makes a stuck signature look like a stuck network.
    """

    def test_get_smtp_does_not_connect(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_smtp() hands back a connector without touching the network."""
        monkeypatch.setattr(
            b4,
            'SENDEMAIL_CONFIG',
            {
                'smtpserver': 'smtp.example.org',
                'smtpserverport': '465',
                'smtpencryption': 'ssl',
                'smtpauth': 'none',
                'from': 'alice@example.org',
            },
        )

        monkeypatch.setattr(b4, 'get_main_config', dict)

        def _boom(*args: Any, **kwargs: Any) -> None:
            raise AssertionError('get_smtp() must not connect')

        monkeypatch.setattr(smtplib, 'SMTP_SSL', _boom)
        monkeypatch.setattr(smtplib, 'SMTP', _boom)

        smtp, fromaddr = b4.get_smtp()
        assert isinstance(smtp, b4.SMTPConnector)
        assert fromaddr == 'alice@example.org'

    def test_signing_happens_before_connect(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: List[str] = list()

        class _FakePatatt:
            NoKeyError = type('NoKeyError', (Exception,), {})
            SigningError = type('SigningError', (Exception,), {})

            @staticmethod
            def rfc2822_sign(bdata: bytes) -> bytes:
                calls.append('sign')
                return bdata

        monkeypatch.setitem(sys.modules, 'patatt', _FakePatatt)

        def _connect() -> Any:
            calls.append('connect')
            return _FakeSMTP(calls)

        conn = b4.SMTPConnector(_connect)
        sent = b4.send_mail(
            conn,
            [_plain_msg('one'), _plain_msg('two')],
            fromaddr='alice@example.org',
            patatt_sign=True,
        )
        assert sent == 2
        # Both signatures land before the connection is made
        assert calls == ['sign', 'sign', 'connect', 'send', 'send']

    def test_connector_is_reused(self) -> None:
        """b4 ty sends one message per send_mail() call, in a loop."""
        calls: List[str] = list()

        def _connect() -> Any:
            calls.append('connect')
            return _FakeSMTP(calls)

        conn = b4.SMTPConnector(_connect)
        for num in range(3):
            b4.send_mail(conn, [_plain_msg(f'msg {num}')], fromaddr='alice@example.org')
        assert calls.count('connect') == 1
        assert calls.count('send') == 3

    def test_connect_failure_is_runtimeerror(self) -> None:
        """Callers catch RuntimeError to report a broken smtp setup."""

        def _connect() -> Any:
            raise smtplib.SMTPException('server unreachable')

        conn = b4.SMTPConnector(_connect)
        with pytest.raises(RuntimeError, match='server unreachable'):
            b4.send_mail(conn, [_plain_msg('one')], fromaddr='alice@example.org')

    def _capture_timeout(
        self, monkeypatch: pytest.MonkeyPatch, timeout_cfg: Optional[str]
    ) -> Any:
        """Connect through get_smtp() and report the timeout it asked for."""
        sendemail: Dict[str, Any] = {
            'smtpserver': 'smtp.example.org',
            'smtpserverport': '465',
            'smtpencryption': 'ssl',
            'smtpauth': 'none',
            'from': 'alice@example.org',
        }
        monkeypatch.setattr(b4, 'SENDEMAIL_CONFIG', sendemail)
        main: Dict[str, Any] = dict()
        if timeout_cfg is not None:
            main['smtp-timeout'] = timeout_cfg
        monkeypatch.setattr(b4, 'get_main_config', lambda: main)

        seen: Dict[str, Any] = dict()

        def _fake_ssl(host: str, port: int, timeout: Any = None) -> Any:
            seen['timeout'] = timeout
            return _FakeSMTP(list())

        monkeypatch.setattr(smtplib, 'SMTP_SSL', _fake_ssl)
        smtp, _fromaddr = b4.get_smtp()
        assert isinstance(smtp, b4.SMTPConnector)
        smtp()
        return seen['timeout']

    @pytest.mark.parametrize(
        'timeout_cfg,expected',
        [
            # git-send-email gets 120s from Net::SMTP; b4 should not wait
            # forever.
            pytest.param(None, 120.0, id='default-matches-git'),
            pytest.param('30', 30.0, id='configurable'),
            # 0 must omit the argument, not pass a non-blocking zero through.
            pytest.param('0', None, id='zero-means-wait-forever'),
        ],
    )
    def test_timeout(
        self,
        monkeypatch: pytest.MonkeyPatch,
        timeout_cfg: Optional[str],
        expected: Optional[float],
    ) -> None:
        assert self._capture_timeout(monkeypatch, timeout_cfg) == expected

    def test_bad_timeout_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            b4,
            'SENDEMAIL_CONFIG',
            {'smtpserver': 'smtp.example.org', 'from': 'alice@example.org'},
        )
        monkeypatch.setattr(b4, 'get_main_config', lambda: {'smtp-timeout': 'soon'})
        with pytest.raises(smtplib.SMTPException, match='smtp-timeout'):
            b4.get_smtp()

    def test_dryrun_never_connects(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            b4,
            'SENDEMAIL_CONFIG',
            {'smtpserver': 'smtp.example.org', 'from': 'alice@example.org'},
        )
        monkeypatch.setattr(b4, 'get_main_config', dict)
        smtp, _fromaddr = b4.get_smtp(dryrun=True)
        assert smtp is None


def _fake_editor(tmp_path: pathlib.Path, body: str) -> str:
    """A stand-in $EDITOR that runs *body* and leaves the buffer alone."""
    script = tmp_path / 'fake-editor.sh'
    script.write_text(f'#!/bin/sh\n{body}\n')
    script.chmod(0o755)
    return str(script)


def test_edit_in_editor_without_guard_survives_branch_switch(
    gitdir: str, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Callers that write to an explicit ref get their text back even if HEAD
    moved while the editor was open.

    The review TUI stores replies on the review branch and reads the patch it
    is replying to by SHA, so a branch switch -- its own, or the user's in
    another terminal sharing the worktree -- is none of its business."""
    monkeypatch.setenv(
        'GIT_EDITOR', _fake_editor(tmp_path, f'git -C "{gitdir}" checkout -q -b side')
    )
    assert b4.edit_in_editor(b'my reply\n', filehint='reply.eml') == b'my reply\n'
    assert b4.git_get_current_branch(gitdir) == 'side'


def test_edit_in_editor_guard_refuses_branch_switch(
    gitdir: str, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A caller that opts in is refused when HEAD has moved on, and its text
    is preserved in a temporary file."""
    monkeypatch.setenv(
        'GIT_EDITOR', _fake_editor(tmp_path, f'git -C "{gitdir}" checkout -q -b side')
    )
    with pytest.raises(RuntimeError, match='Branch changed during file editing') as ex:
        b4.edit_in_editor(b'my cover\n', guard_branch=True)

    saved = pathlib.Path(str(ex.value).split(' saved at ')[-1])
    try:
        assert saved.read_bytes() == b'my cover\n'
    finally:
        saved.unlink()


def test_edit_in_editor_guard_covers_a_detached_head(
    gitdir: str, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Starting detached is still a starting point worth guarding.

    'b4 trailers -u' does not require a prep branch, so it can run with HEAD
    detached and rewrite whatever branch is current when it applies."""
    ecode, out = b4.git_run_command(gitdir, ['checkout', '-q', '--detach'])
    assert ecode == 0, out
    monkeypatch.setenv(
        'GIT_EDITOR', _fake_editor(tmp_path, f'git -C "{gitdir}" checkout -q -b side')
    )
    with pytest.raises(RuntimeError, match='Branch changed during file editing') as ex:
        b4.edit_in_editor(b'my trailers\n', guard_branch=True)

    saved = pathlib.Path(str(ex.value).split(' saved at ')[-1])
    try:
        assert saved.read_bytes() == b'my trailers\n'
    finally:
        saved.unlink()


def test_edit_in_editor_follows_the_topdir_it_is_given(
    gitdir: str, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """topdir, not the process cwd, decides where the scratch file lands and
    which HEAD the guard reads.

    The TUIs may be driven from a different worktree than the one holding the
    branch they operate on, so cwd is the wrong repository to ask."""
    linked = str(tmp_path / 'linked')
    ecode, out = b4.git_run_command(
        gitdir, ['worktree', 'add', '-b', 'elsewhere', linked], logstderr=True
    )
    assert ecode == 0, out
    seen = tmp_path / 'editor-argv1'
    # Move the *cwd* repository's HEAD while the editor is open. The guard is
    # on, so if it were reading cwd rather than topdir this would refuse.
    monkeypatch.setenv(
        'GIT_EDITOR',
        _fake_editor(
            tmp_path, f'printf %s "$1" > {seen}; git -C "{gitdir}" checkout -q -b side'
        ),
    )

    # cwd is still on master; only the linked worktree is on 'elsewhere'.
    assert b4.git_get_current_branch(gitdir) == 'master'
    edited = b4.edit_in_editor(
        b'note\n', filehint='note.txt', topdir=linked, guard_branch=True
    )
    assert edited == b'note\n'
    assert seen.read_text().startswith(linked + os.sep)
    assert b4.git_get_current_branch(gitdir) == 'side'
    assert b4.git_get_current_branch(linked) == 'elsewhere'


def test_edit_in_editor_reads_core_editor_from_topdir(
    gitdir: str, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """core.editor is read from the named tree too, so a repository-local
    setting is the one belonging to the branch being edited."""
    other = str(tmp_path / 'other')
    ecode, out = b4.git_run_command(None, ['init', '-b', 'master', other])
    assert ecode == 0, out
    seen = tmp_path / 'which-editor'
    b4.git_set_config(
        other, 'core.editor', _fake_editor(tmp_path, f'printf topdir > {seen}')
    )
    b4.git_set_config(gitdir, 'core.editor', 'false')
    for var in ('GIT_EDITOR', 'VISUAL', 'EDITOR'):
        monkeypatch.delenv(var, raising=False)

    assert b4.edit_in_editor(b'note\n', filehint='note.txt', topdir=other) == b'note\n'
    assert seen.read_text() == 'topdir'


def test_git_head_restore_args_names_the_branch(gitdir: str) -> None:
    assert b4.git_head_restore_args(gitdir) == ['checkout', 'master']


def test_git_head_restore_args_names_the_commit_when_detached(gitdir: str) -> None:
    """A detached HEAD is a starting point too, and the only thing that can
    be named for it is the commit."""
    ecode, out = b4.git_run_command(gitdir, ['rev-parse', 'HEAD'])
    assert ecode == 0, out
    sha = out.strip()
    ecode, out = b4.git_run_command(gitdir, ['checkout', '-q', '--detach'])
    assert ecode == 0, out
    assert b4.git_head_restore_args(gitdir) == ['checkout', '--detach', sha]


def test_git_head_restore_args_round_trip(gitdir: str) -> None:
    """Running what it returns puts HEAD back exactly where it was read."""
    ecode, out = b4.git_run_command(gitdir, ['checkout', '-q', '--detach'])
    assert ecode == 0, out
    restore = b4.git_head_restore_args(gitdir)

    ecode, out = b4.git_run_command(gitdir, ['checkout', '-q', '-b', 'elsewhere'])
    assert ecode == 0, out
    ecode, out = b4.git_run_command(gitdir, restore)
    assert ecode == 0, out

    assert b4.git_get_current_branch(gitdir) is None
    assert b4.git_head_restore_args(gitdir) == restore


class TestUnicodeControlChars:
    """The Cf-character guard in get_am_message() must raise BadCharsError
    instead of calling sys.exit(), so that interactive front-ends (the
    review TUI) can report it without tearing down the whole process.
    """

    ZWNJ = '\u200c'  # ZERO WIDTH NON-JOINER, category Cf

    @staticmethod
    def _make_msg(body: str) -> email.message.EmailMessage:
        raw = (
            'From: Test Author <test@example.com>\n'
            'Subject: [PATCH] Add widget support\n'
            'Date: Mon, 1 Jan 2024 00:00:00 +0000\n'
            'Message-Id: <20240101-widget-v1-1-abc123@example.com>\n'
            'MIME-Version: 1.0\n'
            'Content-Type: text/plain; charset="utf-8"\n'
            'Content-Transfer-Encoding: 8bit\n'
            '\n'
            f'{body}\n'
            'Signed-off-by: Test Author <test@example.com>\n'
            '---\n'
            ' file1.txt | 1 +\n'
            ' 1 file changed, 1 insertion(+)\n'
            '\n'
            'diff --git a/file1.txt b/file1.txt\n'
            'index b352682..6713e9f 100644\n'
            '--- a/file1.txt\n'
            '+++ b/file1.txt\n'
            '@@ -1 +1,2 @@\n'
            ' hello\n'
            '+widget\n'
        )
        # Parse from bytes like b4 does when reading an mbox: parsing from
        # str runs non-ascii through raw-unicode-escape and would turn the
        # very characters under test into literal backslash sequences.
        return email.message_from_bytes(
            raw.encode(), policy=email.policy.EmailPolicy(utf8=True)
        )

    def _get_lmsg(self, body: str) -> b4.LoreMessage:
        lmbx = b4.LoreMailbox()
        lmbx.add_message(self._make_msg(body))
        lser = lmbx.get_series()
        assert lser is not None
        lmsg = lser.patches[1]
        assert lmsg is not None
        return lmsg

    def test_zwnj_raises_badchars(self) -> None:
        """A zero-width non-joiner is Cf with no Lo chars on the line."""
        lmsg = self._get_lmsg(f'This adds a {self.ZWNJ}fancy widget.')
        with pytest.raises(b4.BadCharsError) as excinfo:
            lmsg.get_am_message(add_trailers=False)

        ex = excinfo.value
        assert ex.char == self.ZWNJ
        assert ex.charname == 'ZERO WIDTH NON-JOINER'
        assert ex.at == len('This adds a ')
        assert 'ZERO WIDTH NON-JOINER' in str(ex)
        # The caret must line up under the offending character.
        details = ex.details()
        line_row = next(x for x in details if x.lstrip().startswith('Line: '))
        caret_row = next(x for x in details if x.lstrip().startswith('---'))
        assert line_row.index(self.ZWNJ) == caret_row.index('^')

    def test_allowbadchars_lets_it_through(self) -> None:
        lmsg = self._get_lmsg(f'This adds a {self.ZWNJ}fancy widget.')
        am_msg = lmsg.get_am_message(add_trailers=False, allowbadchars=True)
        payload = am_msg.get_payload(decode=True)
        assert isinstance(payload, bytes)
        assert self.ZWNJ in payload.decode()

    @pytest.mark.parametrize(
        'body',
        [
            # Cf chars alongside Lo chars are legitimate (e.g. Arabic, Indic),
            # so a body with letters from a non-latin script must pass.
            pytest.param(
                f'\u0627\u0644\u0648\u064a\u062c{ZWNJ}\u062a', id='non-latin-body'
            ),
            pytest.param('This adds a fancy widget.', id='plain-ascii-body'),
        ],
    )
    def test_body_is_not_flagged(self, body: str) -> None:
        lmsg = self._get_lmsg(body)
        lmsg.get_am_message(add_trailers=False)


class TestGetIndexesPerFileModes:
    """A mode belongs to the file whose diff header carried it.

    make_fake_am_range() binds every preimage by (hash, mode), so a mode
    read off the file before it binds a gitlink or a symlink as a regular
    blob, and the series stops fake-am'ing at all.
    """

    def test_a_mode_does_not_leak_onto_the_next_file(self) -> None:
        """A gitlink and a symlink after a regular file keep their own.

        The deleted file states its mode nowhere but on its own
        "deleted file mode" line, which the index line does not repeat.
        """
        diff = (
            'diff --git a/README b/README\n'
            'index 1111111..2222222 100644\n'
            '--- a/README\n'
            '+++ b/README\n'
            '@@ -1 +1 @@\n'
            '-readme\n'
            '+readme v2\n'
            'diff --git a/sub b/sub\n'
            'index 3333333..4444444 160000\n'
            '--- a/sub\n'
            '+++ b/sub\n'
            '@@ -1 +1 @@\n'
            '-Subproject commit 3333333333333333333333333333333333333333\n'
            '+Subproject commit 4444444444444444444444444444444444444444\n'
            'diff --git a/link b/link\n'
            'index 5555555..6666666 120000\n'
            '--- a/link\n'
            '+++ b/link\n'
            '@@ -1 +1 @@\n'
            '-README\n'
            '+sub\n'
            'diff --git a/gone b/gone\n'
            'deleted file mode 100755\n'
            'index 7777777..0000000\n'
            '--- a/gone\n'
            '+++ /dev/null\n'
            '@@ -1 +0,0 @@\n'
            '-#!/bin/sh\n'
        )
        assert b4.LoreMessage.get_indexes(diff) == {
            ('README', '1111111', 'README', '100644'),
            ('sub', '3333333', 'sub', '160000'),
            ('link', '5555555', 'link', '120000'),
            ('gone', '7777777', 'gone', '100755'),
        }

    def test_a_mode_change_names_the_preimage_mode(self) -> None:
        """A chmod alongside an edit: the index line carries no mode.

        get_indexes describes the preimage, so "old mode" is the answer --
        and nothing anywhere is mode 10644.
        """
        diff = (
            'diff --git a/run.sh b/run.sh\n'
            'old mode 100644\n'
            'new mode 100755\n'
            'index 8888888..9999999\n'
            '--- a/run.sh\n'
            '+++ b/run.sh\n'
            '@@ -1 +1 @@\n'
            '-echo old\n'
            '+echo new\n'
        )
        assert b4.LoreMessage.get_indexes(diff) == {
            ('run.sh', '8888888', 'run.sh', '100644')
        }


class TestFakeAmGitlinkPreimage:
    """A series bumping a submodule has to fake-am in either hash format.

    The preimage of a gitlink is a commit in the submodule's object store,
    which the superproject cannot resolve, so the only copy of it anywhere
    on this side is the one written out in the diff -- as 64 hex digits in a
    sha256 repository.
    """

    @staticmethod
    def _bump_repo(
        tmp_path: pathlib.Path, object_format: str
    ) -> Tuple[str, str, int, b4.LoreSeries]:
        """Build a repo whose gitlink bump names objects nobody has.

        Returns (repo, base commit, hash length, series).  master keeps no
        gitlink at all, so the index lookup make_fake_am_range falls back to
        has nothing to find either -- exactly like a submodule that was never
        cloned here.  The bump edits README as well, so the gitlink is not
        the first file in the diff: a mode is per-file state, and one left
        over from the file before would bind this one as a regular blob.
        """
        repo = str(tmp_path / f'gitlink-{object_format}')
        ecode, out = b4.git_run_command(
            None, ['init', f'--object-format={object_format}', '-b', 'master', repo]
        )
        assert ecode == 0, out
        assert b4.git_set_config(repo, 'user.name', 'Gitlink Tester') == 0
        assert b4.git_set_config(repo, 'user.email', 'gitlink@example.com') == 0
        (pathlib.Path(repo) / 'README').write_text('readme\n')
        for args in (['add', 'README'], ['commit', '-q', '-m', 'initial']):
            assert b4.git_run_command(repo, args, rundir=repo)[0] == 0, args

        hexlen = 64 if object_format == 'sha256' else 40
        old, new = '1' * hexlen, '2' * hexlen
        parent = 'master'
        commits = list()
        for idx, gitlink in enumerate((old, new)):
            ecode, _out = b4.git_run_command(
                repo,
                ['update-index', '--add', '--cacheinfo', f'160000,{gitlink},sub'],
                rundir=repo,
            )
            assert ecode == 0
            if idx:
                (pathlib.Path(repo) / 'README').write_text('readme v2\n')
                assert b4.git_run_command(repo, ['add', 'README'], rundir=repo)[0] == 0
            ecode, tree = b4.git_run_command(repo, ['write-tree'], rundir=repo)
            assert ecode == 0
            ecode, commit = b4.git_run_command(
                repo,
                ['commit-tree', tree.strip(), '-p', parent],
                stdin=f'point sub at {gitlink[:7]}\n'.encode(),
            )
            assert ecode == 0
            parent = commit.strip()
            commits.append(parent)
        base, bump = commits

        ecode, mbox = b4.git_run_command(
            repo, ['format-patch', '-1', '--stdout', bump], decode=False
        )
        assert ecode == 0
        assert f'-Subproject commit {old}'.encode() in mbox
        assert mbox.index(b'diff --git a/README') < mbox.index(b'diff --git a/sub')
        # Back to a master that never heard of the submodule.
        assert (
            b4.git_run_command(repo, ['reset', '--hard', 'master'], rundir=repo)[0] == 0
        )

        lmbx = b4.LoreMailbox()
        for idx, msg in enumerate(b4.mailsplit_bytes(mbox)):
            if not msg['Message-Id']:
                msg['Message-Id'] = f'<{object_format}-gitlink-{idx}@test.local>'
            lmbx.add_message(msg)
        lser = lmbx.get_series()
        assert lser is not None
        return repo, base, hexlen, lser

    @pytest.mark.parametrize('object_format', ['sha1', 'sha256'])
    def test_gitlink_preimage_is_bound_without_the_object(
        self,
        tmp_path: pathlib.Path,
        monkeypatch: pytest.MonkeyPatch,
        object_format: str,
    ) -> None:
        """Both ends of the range carry the gitlink the diff named."""
        repo, base, hexlen, lser = self._bump_repo(tmp_path, object_format)
        monkeypatch.chdir(repo)

        start, end = lser.make_fake_am_range(gitdir=repo, at_base=base)

        assert start, 'the gitlink preimage did not make it into a fake-am range'
        assert end
        for commit, gitlink in ((start, '1' * hexlen), (end, '2' * hexlen)):
            ecode, entry = b4.git_run_command(repo, ['ls-tree', commit, 'sub'])
            assert ecode == 0
            assert entry.split()[:3] == ['160000', 'commit', gitlink]


class TestGetAmMessageFromLines:
    """git mailinfo never undoes ">From " escaping, so get_am_message()
    must not escape the commit message it hands to mailinfo."""

    def test_from_lines_survive(self) -> None:
        body = (
            'Fix bar.\n'
            '\n'
            'From the manual, bar() must be called here.\n'
            '>From an old thread.\n'
            '\n'
            'Signed-off-by: Test Author <test@example.com>\n'
            '---\n'
            ' foo.c | 1 +\n'
            ' 1 file changed, 1 insertion(+)\n'
            '\n'
            'diff --git a/foo.c b/foo.c\n'
            'index aaa..bbb 100644\n'
            '--- a/foo.c\n'
            '+++ b/foo.c\n'
            '@@ -1,3 +1,4 @@\n'
            ' void foo(void) {\n'
            '+    bar();\n'
            ' }\n'
        )
        msg = email.message.EmailMessage()
        msg['From'] = 'Test Author <test@example.com>'
        msg['Subject'] = '[PATCH] Fix bar'
        msg['Date'] = 'Mon, 1 Jan 2024 00:00:00 +0000'
        msg['Message-Id'] = '<20240101-bar-v1-1@example.com>'
        msg.set_payload(body)
        lmbx = b4.LoreMailbox()
        lmbx.add_message(msg)
        lser = lmbx.get_series()
        assert lser is not None
        lmsg = lser.patches[1]
        assert lmsg is not None

        am_msg = lmsg.get_am_message(add_trailers=False)
        payload = am_msg.get_payload(decode=True)
        assert isinstance(payload, bytes)
        lines = payload.decode().splitlines()
        assert 'From the manual, bar() must be called here.' in lines
        assert '>From an old thread.' in lines
