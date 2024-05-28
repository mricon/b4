import pytest  # noqa
import b4
import os
import email
import mailbox
import io


@pytest.mark.parametrize('source,expected', [
    ('good-valid-trusted', (True, True, True, 'B6C41CE35664996C', '1623274836')),
    ('good-valid-notrust', (True, True, False, 'B6C41CE35664996C', '1623274836')),
    ('good-invalid-notrust', (True, False, False, 'B6C41CE35664996C', None)),
    ('badsig', (False, False, False, 'B6C41CE35664996C', None)),
    ('no-pubkey', (False, False, False, None, None)),
])
def test_check_gpg_status(sampledir, source, expected):
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
def test_save_git_am_mbox(sampledir, tmp_path, source, regex, flags, ismbox):
    import re
    if source is not None:
        if ismbox:
            mbx = mailbox.mbox(f'{sampledir}/{source}.txt')
            msgs = list(mbx)
        else:
            import email
            with open(f'{sampledir}/{source}.txt', 'rb') as fh:
                msg = email.message_from_binary_file(fh, policy=b4.emlpolicy)
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
     [('person', 'Reviewed-By', 'Bogus Bupkes <bogus@example.com>', None),
      ('utility', 'Fixes', 'abcdef01234567890', None),
      ('utility', 'Link', 'https://msgid.link/some@msgid.here', None),
      ]),
    ('trailers-test-extinfo',
     [('person', 'Reviewed-by', 'Bogus Bupkes <bogus@example.com>', '[for the parts that are bogus]'),
      ('utility', 'Fixes', 'abcdef01234567890', None),
      ('person', 'Tested-by', 'Some Person <bogus2@example.com>', '           [this person visually indented theirs]'),
      ('utility', 'Link', 'https://msgid.link/some@msgid.here', '  # initial submission'),
      ('person', 'Signed-off-by', 'Wrapped Persontrailer <broken@example.com>', None),
      ]),
])
def test_parse_trailers(sampledir, source, expected):
    with open(f'{sampledir}/{source}.txt', 'r') as fh:
        msg = email.message_from_file(fh)
        lmsg = b4.LoreMessage(msg)
        gh, m, trs, bas, sig = b4.LoreMessage.get_body_parts(lmsg.body)
        assert len(expected) == len(trs)
        for tr in trs:
            mytype, myname, myvalue, myextinfo = expected.pop(0)
            mytr = b4.LoreTrailer(name=myname, value=myvalue, extinfo=myextinfo)
            assert tr == mytr
            assert tr.type == mytype


@pytest.mark.parametrize('source,serargs,amargs,reference,b4cfg', [
    ('single', {}, {}, 'defaults', {}),
    ('single', {}, {'noaddtrailers': True}, 'noadd', {}),
    ('single', {}, {'addmysob': True}, 'addmysob', {}),
    ('single', {}, {'addmysob': True, 'copyccs': True}, 'copyccs', {}),
    ('single', {}, {'addmysob': True, 'addlink': True}, 'addlink', {}),
    ('single', {}, {'addmysob': True, 'addlink': True}, 'addmsgid', {'linktrailermask': 'Message-Id: <%s>'}),
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
])
def test_followup_trailers(sampledir, source, serargs, amargs, reference, b4cfg):
    b4.MAIN_CONFIG.update(b4cfg)
    lmbx = b4.LoreMailbox()
    for msg in mailbox.mbox(f'{sampledir}/trailers-followup-{source}.mbox'):
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
    ('Message-ID: <20240319-very-long-message-id-that-spans-multiple-lines-for-sure-because-longer-than-75-characters-abcde123456@longdomain.example.com>',  # noqa
     '<20240319-very-long-message-id-that-spans-multiple-lines-for-sure-because-longer-than-75-characters-abcde123456@longdomain.example.com>',  # noqa
     'encode'),
])
def test_header_wrapping(sampledir, hval, verify, tr):
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
def test_format_addrs(pairs, verify, clean):
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
def test_parse_int_range(intrange, upper, expected):
    assert list(b4.parse_int_range(intrange, upper)) == expected
