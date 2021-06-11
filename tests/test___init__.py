import pytest  # noqa
import b4
import re
import os


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
def test_save_git_am_mbox(tmpdir, source, regex, flags, ismbox):
    import re
    if source is not None:
        if ismbox:
            import mailbox
            mbx = mailbox.mbox(f'tests/samples/{source}.txt')
            msgs = list(mbx)
        else:
            import email
            with open(f'tests/samples/{source}.txt', 'rb') as fh:
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
    dest = os.path.join(tmpdir, 'out')
    with open(dest, 'w') as fh:
        b4.save_git_am_mbox(msgs, fh)
    with open(dest, 'r') as fh:
        res = fh.read()
    assert re.search(regex, res, flags=flags)
