import pytest  # noqa
import b4


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
