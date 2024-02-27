import sys

from instructor import OpenAISchema
from pydantic import Field

# This is needed for now while the minimization bits aren't released
sys.path.insert(0, '/home/user/work/git/korg/b4/src')
import b4
import b4.mbox


class Function(OpenAISchema):
    """
    Accepts a message-id, retrieves a mailing list discussion thread from lore.kernel.org, and returns a mailbox with all messages in the tread.
    """

    message_id: str = Field(
        ...,
        example='20240228-foo-bar-baz@localhost',
        descriptions='Message-ID of the thread to retrieve from lore.kernel.org',
    )

    class Config:
        title = "retrieve_lore_thread"

    @classmethod
    def execute(cls, message_id: str) -> str:
        b4._setup_main_config()
        msgs = b4.get_pi_thread_by_msgid(message_id, with_thread=True)
        if not msgs:
            return f'No messages matching this message-id: {message_id}'
        minmsgs = b4.mbox.minimize_thread(msgs)
        out = ''
        for minmsg in minmsgs:
            out += minmsg.as_string(policy=b4.emlpolicy) + '\n'
        return out
