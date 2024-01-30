mbox: retrieving threads
========================
.. note::

   If you are looking for a way to continuously retrieve full threads
   (or even full search results) from a public-inbox server, the ``lei``
   tool provides a much more robust way of doing that.

Retrieving full discussion threads is the most basic use of b4. All you
need to know is the message-id of any message in the thread::

    b4 mbox 20200313231252.64999-1-keescook@chromium.org

Alternatively, if you have found a thread on lore.kernel.org and you
want to retrieve it in full, you can just use the full URL::

    b4 mbox https://lore.kernel.org/lkml/20200313231252.64999-1-keescook@chromium.org/#t

By default, b4 will save the thread in a mailbox format using the
message-id of the message as the filename base::

    $ b4 mbox 20200313231252.64999-1-keescook@chromium.org
    Grabbing thread from lore.kernel.org/all/20200313231252.64999-1-keescook%40chromium.org/t.mbox.gz
    5 messages in the thread
    Saved ./20200313231252.64999-1-keescook@chromium.org.mbx

Option flags
------------
``-m LOCALMBOX, --use-local-mbox LOCALMBOX``
  By default, b4 will retrieve threads from remote public-inbox servers,
  but it can also use a local mailbox/maildir. This is useful if you
  have a tool like ``mbsync`` or ``lei`` copying remote messages locally
  and you need to do some work while offline. You can pass ``-`` to read
  messages from stdin.

``--stdin-pipe-sep STDIN_PIPE_SEP`` **(0.11+)**
  When reading input from stdin, split messages using the string passed
  as parameter. Otherwise, b4 expects stdin to be a single message or a
  valid mbox.

  This is most useful when piping threads directly from mutt. In your
  ``.muttrc`` add the following configuration parameter::

      set pipe_sep = "\n---randomstr---\n"

  Then invoke b4 with ``-m - --stdin-pipe-sep='\n---randomstr---\n'``

``-C, --no-cache``
  By default, b4 will cache the retrieved threads for about 10 minutes.
  This lets you force b4 to ignore cache and retrieve the latest
  results.

``--single-message`` **(0.13+)**
  By default, b4 will retrieve the entire thread, but sometimes you
  really just want a single message. This helps when someone posts a
  patch in the middle of a long thread and you just want that patch and
  ignore the rest of what is going on.

``-o OUTDIR, --outdir OUTDIR``
  Instead of writing the .mbox file to the current directory, write it
  to this location instead. You can also pass a path to an existing
  mbox or maildir location to have the results appended to that mailbox
  instead (see also the ``-f`` flag below).

``-c, --check-newer-revisions``
  When retrieving patch series, check if a newer revision is available.
  For example, if you are trying to retrieve a series titled ``[PATCH v2
  0/3]``, b4 will use a number of mechanisms to check if a ``v3`` or
  later revision is also available and will add these results to the
  retrieved thread.

``-n WANTNAME, --mbox-name WANTNAME``
  By default, the resulting mailbox file will use the message-id as the
  basis for its filename. This option lets you override this behaviour.

``-M, --save-as-maildir``
  By default, the retrieved thread will be saved as an mbox file.
  However, due to subtle incompatibilities between various mbox formats
  ("mboxo" vs "mboxrd", etc), you may want to instead save the results
  as a Maildir directory.

``-f, --filter-dupes``
  When adding messages to existing mailbox or maildir (with ``-o``),
  this will check all existing messages and will only add those messages
  that aren't already present. Note, that this uses simple message-id
  matching and no other checks for correctness are performed.

``-r MBOX, --refetch MBOX`` **(v0.12+)**
  This allows you to refetch all messages in the provided mailbox from
  the upstream public-inbox server. For example, this is useful when you
  have a .mbx file prepared by ``b4 am`` and you want to send a
  response to one of the patches. Performing a refetch will restore the
  original message headers that may have been dropped or modified by
  ``b4 am``.

Using with mutt
---------------
If you are a mutt or neomutt user and your mail is stored locally, you
can define a quick macro that would let you quickly retrieve full
threads and add them to your inbox. This is handy if you are cc'd in the
middle of a conversation and you want to retrieve the rest of the thread
for context.

Add something like the following to your ``~/.muttrc``::

    macro index 4 "<pipe-message>b4 mbox -fo ~/Mail<return>"

Now selecting a message in the message index and pressing "4" will
retrieve the rest of the thread from the public-inbox server and add
them to the local maildir (``~/Mail`` in the example above).
