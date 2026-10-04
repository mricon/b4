# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Builders for synthetic email messages."""

import email.message
from typing import Optional

AUTHOR = 'Author <author@example.com>'

#: The smallest body LoreMailbox accepts as a real patch.
MINIMAL_DIFF = """\
Fix bar.

Signed-off-by: Author <author@example.com>
---
 foo.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/foo.c b/foo.c
index aaa..bbb 100644
--- a/foo.c
+++ b/foo.c
@@ -1,3 +1,4 @@
 void foo(void) {
+    bar();
 }
"""


def make_msg(
    msgid: Optional[str],
    subject: str,
    *,
    from_addr: Optional[str] = 'Test Author <test@example.com>',
    date: Optional[str] = 'Mon, 23 Mar 2026 12:00:00 +0000',
    body: str = 'Hello\n',
    in_reply_to: Optional[str] = None,
    references: Optional[str] = None,
    to: Optional[str] = None,
    cc: Optional[str] = None,
    charset: Optional[str] = None,
) -> email.message.EmailMessage:
    """Build an EmailMessage with the usual headers.

    *msgid* and *in_reply_to* are bare ids and get their angle brackets
    here; *references* is used verbatim.  Any header passed as ``None``
    (or an empty string) is left out, so tests can exercise missing-header
    paths.
    """
    msg = email.message.EmailMessage()
    msg['Subject'] = subject
    if from_addr:
        msg['From'] = from_addr
    if date:
        msg['Date'] = date
    if msgid:
        msg['Message-Id'] = f'<{msgid}>'
    if to:
        msg['To'] = to
    if cc:
        msg['Cc'] = cc
    if in_reply_to:
        msg['In-Reply-To'] = f'<{in_reply_to}>'
    if references:
        msg['References'] = references
    if charset:
        msg.set_payload(body, charset)
    else:
        msg.set_payload(body)
    return msg
