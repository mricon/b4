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
def test_check_gpg_status(source, expected):
    with open(f'tests/samples/gpg-{source}.txt', 'r') as fh:
        status = fh.read()
    assert b4.check_gpg_status(status) == expected


@pytest.mark.parametrize('source,regex,flags,ismbox', [
    (None, r'^From git@z ', 0, False),
    (None, r'\n\nFrom git@z ', 0, False),
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
                msg = email.message_from_binary_file(fh)
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
    with open(dest, 'w') as fh:
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
    ('single', {}, {'addmysob': True, 'copyccs': True}, 'ordered',
     {'trailer-order': 'Cc,Tested*,Reviewed*,*'}),
    ('single', {'sloppytrailers': True}, {'addmysob': True}, 'sloppy', {}),
    ('with-cover', {}, {'addmysob': True}, 'defaults', {}),
    ('with-cover', {}, {'covertrailers': True, 'addmysob': True}, 'covertrailers', {}),
    ('custody', {}, {'addmysob': True, 'copyccs': True}, 'unordered', {}),
    ('custody', {}, {'addmysob': True, 'copyccs': True}, 'ordered',
     {'trailer-order': 'Cc,Fixes*,Link*,Suggested*,Reviewed*,Tested*,*'}),
    ('custody', {}, {'addmysob': True, 'copyccs': True}, 'with-ignored',
     {'trailers-ignore-from': 'followup-reviewer1@example.com'}),
    ('partial-reroll', {}, {'addmysob': True}, 'defaults', {}),
])
def test_followup_trailers(sampledir, source, serargs, amargs, reference, b4cfg):
    b4.MAIN_CONFIG.update(b4cfg)
    lmbx = b4.LoreMailbox()
    for msg in mailbox.mbox(f'{sampledir}/trailers-followup-{source}.mbox'):
        lmbx.add_message(msg)
    lser = lmbx.get_series(**serargs)
    assert lser is not None
    amsgs = lser.get_am_ready(**amargs)
    ifh = io.StringIO()
    b4.save_git_am_mbox(amsgs, ifh)
    with open(f'{sampledir}/trailers-followup-{source}-ref-{reference}.txt', 'r') as fh:
        assert ifh.getvalue() == fh.read()
