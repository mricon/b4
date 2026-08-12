import email
import email.message
import email.parser
import email.policy
import email.utils
import io
import os
import pathlib
import smtplib
import socket
import sys
from typing import Any, Dict, List, Literal, Optional, Set, Tuple

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
    'source,regex,flags,ismbox',
    [
        (None, r'^From git@z ', 0, False),
        (None, r'\n\nFrom git@z ', 0, False),
        ('save-7bit-clean', r'From: Unicôdé', 0, True),
        # mailbox.mbox does not properly handle 8bit-clean headers
        ('save-8bit-clean', r'From: Unicôdé', 0, False),
    ],
)
def test_save_git_am_mbox(
    sampledir: Optional[str],
    tmp_path: pathlib.Path,
    source: Optional[str],
    regex: str,
    flags: int,
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
    assert re.search(regex, res, flags=flags)


def _msgid_domain(msgid: str) -> str:
    return msgid.strip('<>').rsplit('@', maxsplit=1)[1]


def test_make_msgid_avoids_host_domain_by_default() -> None:
    stdlib_msgid = email.utils.make_msgid()
    b4_msgid = b4.make_msgid(idstring='b4-test')

    assert _msgid_domain(stdlib_msgid) == socket.getfqdn()
    assert _msgid_domain(b4_msgid) == 'b4'
    assert _msgid_domain(b4_msgid) != socket.getfqdn()


def test_make_msgid_custom_cmd_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(
        b4.MAIN_CONFIG, 'custom-msgid-cmd', 'echo custom-1234@example.com'
    )
    # The custom command is only consulted when explicitly allowed.
    assert b4.make_msgid(allow_custom_msgid_cmd=True) == '<custom-1234@example.com>'
    # Without the opt-in, the built-in id is used and the command is ignored.
    assert _msgid_domain(b4.make_msgid(idstring='b4-review')) == 'b4'


def test_make_msgid_custom_cmd_preserves_brackets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        b4.MAIN_CONFIG, 'custom-msgid-cmd', 'echo <wrapped-5678@example.com>'
    )
    assert b4.make_msgid(allow_custom_msgid_cmd=True) == '<wrapped-5678@example.com>'


def test_make_msgid_custom_cmd_list_uses_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Config options defined multiple times arrive as a list; use the first.
    monkeypatch.setitem(
        b4.MAIN_CONFIG,
        'custom-msgid-cmd',
        ['echo first@example.com', 'echo second@example.com'],
    )
    assert b4.make_msgid(allow_custom_msgid_cmd=True) == '<first@example.com>'


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
    'body,followup,expected_fixes_values',
    [
        # Valid Fixes: trailer (SHA-1 style)
        (
            'Reviewed-by: Foo Bar <foo@example.com>\nFixes: abcdef012345 ("This is the commit subject")\n',
            True,
            ['abcdef012345 ("This is the commit subject")'],
        ),
        # Valid Fixes: trailer (SHA-256 style, 64 hex chars)
        (
            'Fixes: ' + 'a' * 64 + ' ("SHA-256 commit subject")\n',
            True,
            ['a' * 64 + ' ("SHA-256 commit subject")'],
        ),
        # Malformed: reviewer wrote "Fixes: ?" as a question — must be rejected
        (
            'Reviewed-by: Foo Bar <foo@example.com>\nFixes: ?\n',
            True,
            [],
        ),
        # Malformed: plain text value — must be rejected
        (
            'Fixes: some description with no hash\n',
            True,
            [],
        ),
        # Bare hash without parenthesised subject — also valid
        (
            'Fixes: abcdef012345\n',
            True,
            ['abcdef012345'],
        ),
    ],
)
def test_fixes_trailer_format_validation(
    body: str, followup: bool, expected_fixes_values: List[str]
) -> None:
    trailers, _ = b4.LoreMessage.find_trailers(body, followup=followup)
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
        ('1', 5, [1]),
        ('3', 5, [3]),
        ('5', 5, [5]),
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

    def test_current_branch(self, gitdir: str) -> None:
        """The branch checked out in the main worktree is detected."""
        ecode, out = b4.git_run_command(gitdir, ['branch', '--show-current'])
        assert ecode == 0
        current = out.strip()
        assert b4.git_branch_checked_out(gitdir, current) is True

    def test_other_branch(self, gitdir: str) -> None:
        """An existing but not checked-out branch is not flagged."""
        ecode, _ = b4.git_run_command(gitdir, ['branch', 'parked-branch'])
        assert ecode == 0
        assert b4.git_branch_checked_out(gitdir, 'parked-branch') is False

    def test_nonexistent_branch(self, gitdir: str) -> None:
        assert b4.git_branch_checked_out(gitdir, 'no-such-branch') is False

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

    def test_sendmailcmd_takes_precedence(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """sendmailCmd wins over smtpServer, matching git behavior."""
        monkeypatch.setattr(
            b4,
            'SENDEMAIL_CONFIG',
            {'sendmailcmd': 'msmtp', 'smtpserver': 'smtp.example.org'},
        )
        assert b4.get_sendemail_localcmd() == 'msmtp'

    def test_pathlike_smtpserver(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The historical spelling: a path as the smtpServer value."""
        monkeypatch.setattr(b4, 'SENDEMAIL_CONFIG', {'smtpserver': '/usr/bin/msmtp'})
        assert b4.get_sendemail_localcmd() == '/usr/bin/msmtp'

    def test_smtp_host_is_not_localcmd(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(b4, 'SENDEMAIL_CONFIG', {'smtpserver': 'smtp.example.org'})
        assert b4.get_sendemail_localcmd() is None

    def test_no_transport_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(b4, 'SENDEMAIL_CONFIG', dict())
        assert b4.get_sendemail_localcmd() is None

    def test_get_smtp_uses_sendmailcmd(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A bare command without slashes must work, like git's sendmailCmd."""
        monkeypatch.setattr(
            b4,
            'SENDEMAIL_CONFIG',
            {
                'sendmailcmd': 'msmtp --account=work',
                'from': 'Alice Developer <alice@example.org>',
                'envelopesender': 'auto',
            },
        )
        smtp, fromaddr = b4.get_smtp()
        assert smtp == ['msmtp', '--account=work', '-i', '-f', 'alice@example.org']
        assert fromaddr == 'Alice Developer <alice@example.org>'

    def test_get_smtp_pathlike_smtpserver(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            b4,
            'SENDEMAIL_CONFIG',
            {
                'smtpserver': '/usr/bin/msmtp',
                'from': 'Alice Developer <alice@example.org>',
            },
        )
        smtp, fromaddr = b4.get_smtp()
        assert smtp == ['/usr/bin/msmtp', '-i']
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

    def test_default_timeout_matches_git(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """git-send-email gets 120s from Net::SMTP; b4 should not wait forever."""
        assert self._capture_timeout(monkeypatch, None) == 120.0

    def test_timeout_is_configurable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert self._capture_timeout(monkeypatch, '30') == 30.0

    def test_zero_timeout_means_wait_forever(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """0 must omit the argument, not pass a non-blocking zero through."""
        assert self._capture_timeout(monkeypatch, '0') is None

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
