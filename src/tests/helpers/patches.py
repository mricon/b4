# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Builders for real commits and the patch emails posted for them."""

import email
import email.message
import os

import b4


def commit_file(gitdir: str, path: str, content: str, message: str) -> str:
    """Write *content* to *path*, commit it with *message*, return the SHA."""
    with open(os.path.join(gitdir, path), 'w') as fh:
        fh.write(content)
    ecode, _out = b4.git_run_command(gitdir, ['add', path])
    assert ecode == 0
    ecode, _out = b4.git_run_command(
        gitdir, ['commit', '-q', '-F', '-'], stdin=message.encode()
    )
    assert ecode == 0
    return b4.git_revparse_obj('HEAD', gitdir)


def post_patch(
    gitdir: str, commit: str, msgid: str, prefix: str = 'PATCH', algo: str = 'myers'
) -> email.message.EmailMessage:
    """The patch for *commit* as its author would have sent it, diffed with *algo*."""
    ecode, out = b4.git_run_command(
        gitdir,
        [
            'format-patch',
            '-1',
            '--stdout',
            f'--subject-prefix={prefix}',
            f'--diff-algorithm={algo}',
            commit,
        ],
        decode=False,
    )
    assert ecode == 0
    msg = email.message_from_bytes(out, policy=b4.emlpolicy)
    assert isinstance(msg, email.message.EmailMessage)
    msg['Message-Id'] = f'<{msgid}>'
    return msg


def commit_patch_id(gitdir: str, commit: str, algo: str) -> str:
    """The stable patch-id of *commit* when diffed with *algo*."""
    ecode, out = b4.git_run_command(
        gitdir,
        ['show', '--format=email', f'--diff-algorithm={algo}', commit],
        decode=False,
    )
    assert ecode == 0
    ecode, pid = b4.git_run_command(gitdir, ['patch-id', '--stable'], stdin=out)
    assert ecode == 0
    return pid.split()[0]


# The diff of this change differs between the myers and histogram
# algorithms, so its patch-id does too.
ALGO_OLD = """\
#include <stdio.h>

// Frobs foo heartily
int frobnitz(int foo)
{
    int i;
    for(i = 0; i < 10; i++)
    {
        printf("Your answer is: ");
        printf("%d\\n", foo);
    }
}

int fact(int n)
{
    if(n > 1)
    {
        return fact(n-1) * n;
    }
    return 1;
}

int main(int argc, char **argv)
{
    frobnitz(fact(10));
}
"""

ALGO_NEW = """\
#include <stdio.h>

int fib(int n)
{
    if(n > 2)
    {
        return fib(n-1) + fib(n-2);
    }
    return 1;
}

// Frobs foo heartily
int frobnitz(int foo)
{
    int i;
    for(i = 0; i < 10; i++)
    {
        printf("%d\\n", foo);
    }
}

int main(int argc, char **argv)
{
    frobnitz(fib(10));
}
"""
