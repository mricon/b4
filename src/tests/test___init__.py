import pytest
import b4
import os
import email
import email.parser
import io
import pathlib

from typing import Any, Dict, List, Literal, Optional, Tuple


@pytest.mark.parametrize('source,expected', [
    ('good-valid-trusted', (True, True, True, 'B6C41CE35664996C', '1623274836')),
    ('good-valid-notrust', (True, True, False, 'B6C41CE35664996C', '1623274836')),
    ('good-invalid-notrust', (True, False, False, 'B6C41CE35664996C', None)),
    ('badsig', (False, False, False, 'B6C41CE35664996C', None)),
    ('no-pubkey', (False, False, False, None, None)),
])
def test_check_gpg_status(sampledir: str, source: str, expected: Tuple[bool, bool, bool, Optional[str], Optional[str]]) -> None:
    with open(f'{sampledir}/gpg-{source}.txt', 'r') as fh:
        status = fh.read()
    assert b4.check_gpg_status(status) == expected


@pytest.mark.parametrize('source,regex,flags,ismbox', [
    (None, r'^From git@z ', 0, False),
    (None, r'\n\nFrom git@z ', 0, False),
    ('save-7bit-clean', r'From: Unicôdé', 0, True),
    # mailbox.mbox does not properly handle 8bit-clean headers
    ('save-8bit-clean', r'From: Unicôdé', 0, False),
])
def test_save_git_am_mbox(sampledir: Optional[str], tmp_path: pathlib.Path, source: Optional[str], regex: str, flags: int, ismbox: bool) -> None:
    import re
    msgs: List[email.message.EmailMessage]
    if source is not None:
        if ismbox:
            msgs = b4.get_msgs_from_mailbox_or_maildir(f'{sampledir}/{source}.txt')
        else:
            import email
            import email.parser
            with open(f'{sampledir}/{source}.txt', 'rb') as fh:
                msg = email.parser.BytesParser(policy=b4.emlpolicy, _class=email.message.EmailMessage).parse(fh)
            msgs = [msg]
    else:
        import email.message
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


@pytest.mark.parametrize('source,expected', [
    ('trailers-test-simple',
     [('person', 'Reported-by', '"Doe, Jane" <jane@example.com>', None),
      ('person', 'Reviewed-by', 'Bogus Bupkes <bogus@example.com>', None),
      ('utility', 'Fixes', 'abcdef01234567890', None),
      ('utility', 'Link', 'https://msgid.link/some@msgid.here', None),
      ]),
    ('trailers-test-extinfo',
     [('person', 'Reported-by', 'Some, One <somewhere@example.com>', None),
      ('person', 'Reviewed-by', 'Bogus Bupkes <bogus@example.com>', '[for the parts that are bogus]'),
      ('utility', 'Fixes', 'abcdef01234567890', None),
      ('person', 'Tested-by', 'Some Person <bogus2@example.com>', '           [this person visually indented theirs]'),
      ('utility', 'Link', 'https://msgid.link/some@msgid.here', '  # initial submission'),
      ('person', 'Signed-off-by', 'Wrapped Persontrailer <broken@example.com>', None),
      ]),
])
def test_parse_trailers(sampledir: str, source: str, expected: List[Tuple[str, str, str, Optional[str]]]) -> None:
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


@pytest.mark.parametrize('name,value,exp_type,exp_addr,exp_value', [
    # Simple name
    ('Signed-off-by', 'Simple Name <simple@example.com>',
     'person', ('Simple Name', 'simple@example.com'),
     'Simple Name <simple@example.com>'),
    # Double quotes in display name must be preserved
    ('Signed-off-by', 'Jane "JD" Doe <jd@example.com>',
     'person', ('Jane "JD" Doe', 'jd@example.com'),
     'Jane "JD" Doe <jd@example.com>'),
    # Outer RFC 2822 quotes around a name with comma
    ('Reported-by', '"Doe, Jane" <jane@example.com>',
     'person', ('"Doe, Jane"', 'jane@example.com'),
     '"Doe, Jane" <jane@example.com>'),
    # Comma in name without quotes
    ('Reported-by', 'Some, One <somewhere@example.com>',
     'person', ('Some, One', 'somewhere@example.com'),
     'Some, One <somewhere@example.com>'),
    # Parentheses in display name
    ('Tested-by', 'Developer Foo (EXAMPLECORP) <dev@example.com>',
     'person', ('Developer Foo (EXAMPLECORP)', 'dev@example.com'),
     'Developer Foo (EXAMPLECORP) <dev@example.com>'),
    # Bare angle-bracket email
    ('Cc', '<bare@example.com>',
     'person', ('', 'bare@example.com'),
     'bare@example.com'),
    # Bare email without angle brackets
    ('Cc', 'bare@example.com',
     'person', ('', 'bare@example.com'),
     'bare@example.com'),
])
def test_trailer_addr_parsing(name: str, value: str, exp_type: str,
                              exp_addr: Tuple[str, str], exp_value: str) -> None:
    tr = b4.LoreTrailer(name=name, value=value)
    assert tr.type == exp_type
    assert tr.addr == exp_addr
    assert tr.value == exp_value


@pytest.mark.parametrize('source,serargs,amargs,reference,b4cfg', [
    ('single', {}, {}, 'defaults', {}),
    ('single', {}, {'noaddtrailers': True}, 'noadd', {}),
    ('single', {}, {'addmysob': True}, 'addmysob', {}),
    ('single', {}, {'addmysob': True, 'copyccs': True}, 'copyccs', {}),
    ('single', {}, {'addmysob': True, 'addlink': True}, 'addlink', {}),
    ('single', {}, {'addmysob': True, 'addlink': True}, 'addmsgid', {'linktrailermask': 'Message-ID: <%s>'}),
    ('single', {}, {'addmysob': True, 'copyccs': True}, 'ordered',
     {'trailer-order': 'Cc,Tested*,Reviewed*,*'}),
    ('single', {'sloppytrailers': True}, {'addmysob': True}, 'sloppy', {}),
    ('with-cover', {}, {'addmysob': True}, 'defaults', {}),
    ('with-cover', {}, {'addmysob': True, 'addlink': True}, 'addlink', {}),
    ('custody', {}, {'addmysob': True, 'copyccs': True}, 'unordered', {}),
    ('custody', {}, {'addmysob': True, 'copyccs': True}, 'ordered',
     {'trailer-order': 'Cc,Fixes*,Link*,Suggested*,Reviewed*,Tested*,*'}),
    ('custody', {}, {'addmysob': True, 'copyccs': True}, 'with-ignored',
     {'trailers-ignore-from': 'followup-reviewer1@example.com'}),
    ('partial-reroll', {}, {'addmysob': True}, 'defaults', {}),
    ('nore', {}, {}, 'defaults', {}),
    ('non-git-patch', {}, {}, 'defaults', {}),
    ('non-git-patch-with-comments', {}, {}, 'defaults', {}),
    ('with-diffstat', {}, {}, 'defaults', {}),
    ('name-parens', {}, {}, 'defaults', {}),
    ('bare-address', {}, {}, 'defaults', {}),
    ('stripped-lines', {}, {}, 'defaults', {}),
    ('htmljunk', {}, {}, 'defaults', {}),
])
def test_followup_trailers(sampledir: str, source: str, serargs: Dict[str, Any], amargs: Dict[str, Any],
                           reference: str, b4cfg: Dict[str, Any]) -> None:
    b4.MAIN_CONFIG.update(b4cfg)
    lmbx = b4.LoreMailbox()
    for msg in b4.get_msgs_from_mailbox_or_maildir(f'{sampledir}/trailers-followup-{source}.mbox'):
        lmbx.add_message(msg)
    lser = lmbx.get_series(**serargs)
    assert lser is not None
    amsgs = lser.get_am_ready(**amargs)
    ifh = io.BytesIO()
    b4.save_git_am_mbox(amsgs, ifh)
    with open(f'{sampledir}/trailers-followup-{source}-ref-{reference}.txt', 'r') as fh:
        assert ifh.getvalue().decode() == fh.read()


@pytest.mark.parametrize('hval,verify,tr', [
    ('short-ascii', 'short-ascii', 'encode'),
    ('short-unicôde', '=?utf-8?q?short-unic=C3=B4de?=', 'encode'),
    # Long ascii
    (('Lorem ipsum dolor sit amet consectetur adipiscing elit '
      'sed do eiusmod tempor incididunt ut labore et dolore magna aliqua'),
     ('Lorem ipsum dolor sit amet consectetur adipiscing elit sed do\n'
      ' eiusmod tempor incididunt ut labore et dolore magna aliqua'), 'encode'),
    # Long unicode
    (('Lorem îpsum dolor sit amet consectetur adipiscing elît '
      'sed do eiusmod tempôr incididunt ut labore et dolôre magna aliqua'),
     ('=?utf-8?q?Lorem_=C3=AEpsum_dolor_sit_amet_consectetur_adipiscin?=\n'
      ' =?utf-8?q?g_el=C3=AEt_sed_do_eiusmod_temp=C3=B4r_incididunt_ut_labore_et?=\n'
      ' =?utf-8?q?_dol=C3=B4re_magna_aliqua?='), 'encode'),
    # Exactly 75 long
    ('Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiu',
     'Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiu', 'encode'),
    # Unicode that breaks on escape boundary
    ('Lorem ipsum dolor sit amet consectetur adipiscin elît',
     '=?utf-8?q?Lorem_ipsum_dolor_sit_amet_consectetur_adipiscin_el?=\n =?utf-8?q?=C3=AEt?=', 'encode'),
    # Unicode that's just 1 too long
    ('Lorem ipsum dolor sit amet consectetur adipi elît',
     '=?utf-8?q?Lorem_ipsum_dolor_sit_amet_consectetur_adipi_el=C3=AE?=\n =?utf-8?q?t?=', 'encode'),
    # A single address
    ('foo@example.com', 'foo@example.com', 'encode'),
    # Two addresses
    ('foo@example.com, bar@example.com', 'foo@example.com, bar@example.com', 'encode'),
    # Mixed addresses
    ('foo@example.com, Foo Bar <bar@example.com>', 'foo@example.com, Foo Bar <bar@example.com>', 'encode'),
    # Mixed Unicode
    ('foo@example.com, Foo Bar <bar@example.com>, Fôo Baz <baz@example.com>',
     'foo@example.com, Foo Bar <bar@example.com>, \n =?utf-8?q?F=C3=B4o_Baz?= <baz@example.com>', 'encode'),
    ('foo@example.com, Foo Bar <bar@example.com>, Fôo Baz <baz@example.com>, "Quux, Foo" <quux@example.com>',
     ('foo@example.com, Foo Bar <bar@example.com>, \n'
      ' =?utf-8?q?F=C3=B4o_Baz?= <baz@example.com>, "Quux, Foo" <quux@example.com>'), 'encode'),
    ('01234567890123456789012345678901234567890123456789012345678901@example.org, ä <foo@example.org>',
     ('01234567890123456789012345678901234567890123456789012345678901@example.org, \n'
      ' =?utf-8?q?=C3=A4?= <foo@example.org>'), 'encode'),
    # Test for https://github.com/python/cpython/issues/100900
    ('foo@example.com, Foo Bar <bar@example.com>, Fôo Baz <baz@example.com>, "Quûx, Foo" <quux@example.com>',
     ('foo@example.com, Foo Bar <bar@example.com>, \n'
      ' =?utf-8?q?F=C3=B4o_Baz?= <baz@example.com>, \n =?utf-8?q?Qu=C3=BBx=2C_Foo?= <quux@example.com>'), 'encode'),
    # Test preserve
    ('foo@example.com, Foo Bar <bar@example.com>, Fôo Baz <baz@example.com>, "Quûx, Foo" <quux@example.com>',
     'foo@example.com, Foo Bar <bar@example.com>, Fôo Baz <baz@example.com>, \n "Quûx, Foo" <quux@example.com>',
     'preserve'),
    # Test decode
    ('foo@example.com, Foo Bar <bar@example.com>, =?utf-8?q?Qu=C3=BBx=2C_Foo?= <quux@example.com>',
     'foo@example.com, Foo Bar <bar@example.com>, \n "Quûx, Foo" <quux@example.com>',
     'decode'),
    # Test short message-id
    ('Message-ID: <20240319-short-message-id@example.com>', '<20240319-short-message-id@example.com>', 'encode'),
    # Test long message-id
    ('Message-ID: <20240319-very-long-message-id-that-spans-multiple-lines-for-sure-because-longer-than-75-characters-abcde123456@longdomain.example.com>',
     '<20240319-very-long-message-id-that-spans-multiple-lines-for-sure-because-longer-than-75-characters-abcde123456@longdomain.example.com>',
     'encode'),
])
def test_header_wrapping(sampledir: str, hval: str, verify: str, tr: Literal['encode', 'decode', 'preserve']) -> None:
    if ':' in hval:
        chunks = hval.split(':', maxsplit=1)
        hname = chunks[0].strip()
        hval = chunks[1].strip()
    else:
        hname = 'To' if '@' in hval else "X-Header"
    wrapped = b4.LoreMessage.wrap_header((hname, hval), transform=tr)
    assert wrapped.decode() == f'{hname}: {verify}'
    wname, wval = wrapped.split(b':', maxsplit=1)
    if tr != 'decode':
        cval = b4.LoreMessage.clean_header(wval.decode())
        assert cval == hval


@pytest.mark.parametrize('pairs,verify,clean', [
    ([('', 'foo@example.com'), ('Foo Bar', 'bar@example.com')],
     'foo@example.com, Foo Bar <bar@example.com>', True),
    ([('', 'foo@example.com'), ('Foo, Bar', 'bar@example.com')],
     'foo@example.com, "Foo, Bar" <bar@example.com>', True),
    ([('', 'foo@example.com'), ('Fôo, Bar', 'bar@example.com')],
     'foo@example.com, "Fôo, Bar" <bar@example.com>', True),
    ([('', 'foo@example.com'), ('=?utf-8?q?Qu=C3=BBx_Foo?=', 'quux@example.com')],
     'foo@example.com, Quûx Foo <quux@example.com>', True),
    ([('', 'foo@example.com'), ('=?utf-8?q?Qu=C3=BBx=2C_Foo?=', 'quux@example.com')],
     'foo@example.com, "Quûx, Foo" <quux@example.com>', True),
    ([('', 'foo@example.com'), ('=?utf-8?q?Qu=C3=BBx=2C_Foo?=', 'quux@example.com')],
     'foo@example.com, =?utf-8?q?Qu=C3=BBx=2C_Foo?= <quux@example.com>', False),
])
def test_format_addrs(pairs: List[Tuple[str, str]], verify: str, clean: bool) -> None:
    formatted = b4.format_addrs(pairs, clean)
    assert formatted == verify


@pytest.mark.parametrize('intrange,upper,expected', [
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
])
def test_parse_int_range(intrange: str, upper: int, expected: List[int]) -> None:
    assert list(b4.parse_int_range(intrange, upper)) == expected


@pytest.mark.parametrize('body_link,extra_link,expect_count', [
    # Exact same URL — should dedup to one
    ('https://patch.msgid.link/20240101-test-v1-1-abc123@example.com',
     'https://patch.msgid.link/20240101-test-v1-1-abc123@example.com', 1),
    # Same URL, different case — should still dedup
    ('https://patch.msgid.link/20240101-TEST-V1-1-ABC123@example.com',
     'https://patch.msgid.link/20240101-test-v1-1-abc123@example.com', 1),
    # Different URLs — both should survive
    ('https://lore.kernel.org/r/20240101-test-v1-1-abc123@example.com',
     'https://patch.msgid.link/20240101-test-v1-1-abc123@example.com', 2),
])
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
    def _make_patch_msg(msgid: str, subject: str, body: str,
                        diff: str, counter: int = 1, expected: int = 1,
                        in_reply_to: Optional[str] = None) -> email.message.EmailMessage:
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
        raw += (
            f'\n'
            f'{body}\n'
            f'---\n'
            f'{diff}\n'
        )
        return email.message_from_string(
            raw, policy=email.policy.EmailPolicy(utf8=True))

    @staticmethod
    def _make_reply_msg(msgid: str, in_reply_to: str,
                        from_name: str, from_email: str,
                        trailer_lines: List[str]) -> email.message.EmailMessage:
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
            raw, policy=email.policy.EmailPolicy(utf8=True))

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
        ecode, out = b4.git_run_command(
            gitdir, ['am'], stdin=ifh.getvalue())
        assert ecode == 0, f'git am failed: {out}'

        ecode, result = b4.git_run_command(
            gitdir, ['log', '-1', '--format=%B'])
        assert ecode == 0

        # Exactly one Link: trailer, not two
        assert result.count(f'Link: {link_url}') == 1, \
            f'Duplicate Link: found:\n{result}'
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
        ecode, out = b4.git_run_command(
            gitdir, ['am'], stdin=ifh.getvalue())
        assert ecode == 0, f'git am failed: {out}'

        ecode, result = b4.git_run_command(
            gitdir, ['log', '-1', '--format=%B'])
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
        ecode, out = b4.git_run_command(
            gitdir, ['am'], stdin=ifh.getvalue())
        assert ecode == 0, f'git am failed: {out}'

        ecode, result = b4.git_run_command(
            gitdir, ['log', '-1', '--format=%B'])
        assert ecode == 0

        assert 'Reviewed-by: Alice Author <alice@example.com>' in result
        assert 'Tested-by: Alice Author <alice@example.com>' in result
        assert 'Link:' not in result

    def test_different_link_domains_both_kept(self, gitdir: str) -> None:
        """If the patch body has a lore.kernel.org Link: and addlink
        generates a patch.msgid.link one, both should be kept."""
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
        ecode, out = b4.git_run_command(
            gitdir, ['am'], stdin=ifh.getvalue())
        assert ecode == 0, f'git am failed: {out}'

        ecode, result = b4.git_run_command(
            gitdir, ['log', '-1', '--format=%B'])
        assert ecode == 0

        expected_patch_link = f'https://patch.msgid.link/{patch_msgid}'
        assert lore_link in result
        assert expected_patch_link in result
        assert result.count('Link:') == 2


@pytest.mark.parametrize('subject,extras,expected', [
    ('[PATCH] This is a patch', None, '[PATCH] This is a patch'),
    ('[PATCH v3] This is a patch', None, '[PATCH v3] This is a patch'),
    ('[PATCH RFC v3] This is a patch', None, '[PATCH RFC v3] This is a patch'),
    ('[RFC PATCH v3 1/3] This is a patch', None, '[RFC PATCH v3 1/3] This is a patch'),
    ('[RESEND PATCH v3 1/3] This is a patch', None, '[RESEND PATCH v3 1/3] This is a patch'),
    ('[PATCH RFC v3 2/3] This is a patch', ['RFC'], '[PATCH RFC v3 2/3] This is a patch'),
    ('[PATCH RFC v3 3/12] This is a patch', None, '[PATCH RFC v3 03/12] This is a patch'),
    ('[PATCH RFC v3] This is a [patch]', ['RFC'], '[PATCH RFC v3] This is a [patch]'),
    ('[PATCH RFC v3 2/3] This is a patch', ['netdev', 'bpf'], '[PATCH RFC netdev bpf v3 2/3] This is a patch'),
])
def test_lore_subject_prefixes(subject: str, extras: Optional[List[str]], expected: str) -> None:
    lsubj = b4.LoreSubject(subject)
    assert lsubj.get_rebuilt_subject(eprefixes=extras) == expected
