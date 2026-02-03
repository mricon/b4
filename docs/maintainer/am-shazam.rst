am,shazam: retrieving and applying patches
==========================================
The most common use of b4 is to retrieve, prepare, and apply patches
sent via distribution lists. For example, you can use it to retrieve a
set of patches using the ``Message-ID``::

    b4 am 20200313231252.64999-1-keescook@chromium.org

This does the following:

1. Looks up that Message-ID on the specified public-inbox server, using
   lore.kernel.org by default.
2. Retrieves the full thread containing that message-id.
3. Processes all replies to collect code review trailers and apply them
   to the corresponding commit messages.
4. Performs attestation checks on patches and follow-ups containing
   code-review trailers.
5. Puts all patches in the correct order and prepares them for "git am"
6. Writes out the resulting mailbox so it is ready to be applied to a
   git tree.

For example::

    $ b4 am 20200313231252.64999-1-keescook@chromium.org
    Analyzing 5 messages in the thread
    Checking attestation on all messages, may take a moment...
    ---
      ✓ [PATCH v2 1/2] selftests/harness: Move test child waiting logic
      ✓ [PATCH v2 2/2] selftests/harness: Handle timeouts cleanly
      ---
      ✓ Signed: DKIM/chromium.org
    ---
    Total patches: 2
    ---
    Cover: ./v2_20200313_keescook_selftests_harness_handle_timeouts_cleanly.cover
     Link: https://lore.kernel.org/r/20200313231252.64999-1-keescook@chromium.org
     Base: not specified
           git am ./v2_20200313_keescook_selftests_harness_handle_timeouts_cleanly.mbx

b4 am vs. b4 shazam
-------------------
The two commands are similar -- the main distinction is that ``b4 am``
prepares the patch series so you can ``git am`` the resulting mbox file,
but it doesn't make any actual modifications to your current branch.

The ``b4 shazam`` command does the same as ``b4 am`` *and* actually
applies the patch series to the current branch (if it's possible to do
so cleanly).

Common flags
------------
The following flags are common to both commands:

``-m LOCALMBOX, --use-local-mbox LOCALMBOX``
  By default, b4 retrieves threads from remote public-inbox servers, but
  it can also use a local mailbox/maildir. This is useful if you have a
  tool like ``mbsync`` or ``lei`` copying remote messages locally and
  you need to do some work while offline. You can pass ``-`` to read
  messages from stdin.

``--stdin-pipe-sep STDIN_PIPE_SEP``
  When reading input from stdin, split messages using the string passed
  as parameter. Otherwise, b4 expects stdin to be a single message or a
  valid mbox.

  This is most useful when piping threads directly from mutt. In your
  ``.muttrc`` add the following configuration parameter::

      set pipe_sep = "\n---randomstr---\n"

  Then invoke b4 with ``-m - --stdin-pipe-sep='\n---randomstr---\n'``

``-C, --no-cache``
  By default, b4 caches the retrieved threads for about 10 minutes.
  This lets you force b4 to ignore cache and retrieve the latest
  results.

``--single-message``
  By default, b4 retrieves the entire thread, but sometimes you really
  just want a single message. This helps when someone posts a patch in
  the middle of a long thread and you just want that patch and ignore
  the rest of the messages.

  .. versionadded:: v0.13

``-v WANTVER, --use-version WANTVER``
  If a thread (or threads, when used with ``-c``) contains multiple
  patch series revisions, b4 automatically picks the highest numbered
  version. This switch lets you pick a different revision.

``-S, --sloppy-trailers``
  B4 tries to be careful when collecting code review trailers and
  refuses to consider the trailers where the email address in the
  ``From:`` header doesn't match the address in the trailer itself.

  For example, this follow-up trailer doesn't match and b4 ignores it by
  default::

      From: Alice Maintainer <alice@personalemail.org>
      Subject: Re: [PATCH v3 3/3] Some patch title

      > [...]
      Reviewed-by: Alice Maintainer <alice.maintainer@workemail.com>

  When b4 encounters such situations, it prints a warning and refuses to
  apply the trailer due to the email address mismatch. You can override
  this behavior by passing the ``-S`` flag.

``-T, --no-add-trailers``
  This tells b4 to ignore any follow-up trailers and just save the
  patches as sent by the contributor.

``-s, --add-my-sob``
  Applies your own ``Signed-off-by:`` trailer to every commit.

``-l, --add-link``
  Adds a ``Link:`` trailer with the URL of the retrieved message using
  the :term:`b4.linkmask` template.

``-i, --add-message-id``
  Adds a ``Message-ID:`` trailer with the Message-ID of the retrieved
  message. Cannot be used together with the ``-l`` switch.

``-P CHERRYPICK, --cherry-pick CHERRYPICK``
  This allows you to select a subset of patches from a larger series.
  Here are a few examples.

  This picks patches 1, 3, 5, 6, 7, 9, and any others that follow::

      b4 am -P 1,3,5-7,9- <msgid>

  This picks just the patch that matches the exact message-id
  provided::

      b4 am -P _ <msgid>

  This picks just the last patch from a series::

      b4 am -P -1 <msgid>

  This picks all patches where the subject matches "iscsi"::

      b4 am -P *iscsi*

``--cc-trailers``
  Copies all addresses found in the message ``Cc`` headers into ``Cc:``
  commit trailers.

``--no-parent``
  Break thread at the message-id specified and ignore any parent
  messages. This is handy with long convoluted threads, for example when
  someone replies with a different patch series in the middle of a
  larger conversation and b4 gets confused about which patch series you
  are requesting.

``--allow-unicode-control-chars``
  There are malicious tricks that someone can do with unicode control
  chars that make the code as printed on the screen and reviewed by a
  human do something totally different when processed by a compiler.
  Such unicode control chars are almost never legitimately useful in the
  code, so b4 prints a warning and bails out when it finds them.
  However, just in case there are legitimate reasons for these
  characters to be in the code, for example, as part of documentation
  translated into left-to-right languages), you can override the default
  behavior with this switch.

``--check``
  Tells b4 to run a series of local checks on each patch of the series
  and display any problems. When b4 finds a valid patchwork project
  definition in the configuration settings, it also looks up the CI
  status of each patch.

  For the Linux kernel tree, b4 runs the following checkpatch command::

      ./scripts/checkpatch.pl -q --terse --no-summary --mailback

  You can specify a different command to run by setting the
  :term:`b4.am-perpatch-check-cmd` configuration setting, e.g.::

      [b4]
      am-perpatch-check-cmd = ./scripts/checkpatch.pl -q --terse --no-summary --mailback --strict

  .. versionadded:: v0.14

Flags only valid for ``b4 am``
------------------------------
The following flags only make sense for ``b4 am``:

``-o OUTDIR, --outdir OUTDIR``
  Instead of writing the .mbox file to the current directory, write it
  to this location instead. You can also pass a path to an existing
  mbox or maildir location to have the results appended to that mailbox
  instead (see also the ``-f`` flag below).

  When ``-`` is specified, the output goes to stdout.

``-c, --check-newer-revisions``
  When retrieving a patch series, perform a lookup to see if a newer
  revision is available. For example, if you are trying to retrieve a
  series titled ``[PATCH v2 0/3]``, b4 tries a number of mechanisms to
  look up if a ``v3`` or later revision exists and adds these results to
  the retrieved thread.

``-n WANTNAME, --mbox-name WANTNAME``
  By default, the resulting mailbox file uses the message-id as the
  basis for its filename. This option lets you override this behaviour.

``-M, --save-as-maildir``
  By default, b4 saves the retrieved thread as an mbox file. However,
  due to subtle incompatibilities between various mbox formats ("mboxo"
  vs "mboxrd", etc), you may instead want to save the results as a
  Maildir directory.

``-Q, --quilt-ready``
  Saves the patches as a folder that you can pass directly to quilt. If
  you don't know what quilt is, you don't really need to worry about
  this option.

``-b GUESSBRANCH [...], --guess-branch GUESSBRANCH [...]``
  When using ``--guess-base``, you can restrict which branch(es) b4 uses
  to find the match. If not specified, b4 uses the entire tree history.

``--guess-lookback GUESSDAYS``
  When using ``--guess-base``, you can specify how far back b4 should
  look *from the date of the patch* to find the base commit. By default,
  b4 only considers the last 14 days prior to the date of the patch,
  but you can expand or shrink this range as necessary.

``-3, --prep-3way``
  This tries to prepare your tree for a 3-way merge by doing some
  behind-the-scenes git magic and preparing some fake loose commits.

``--no-cover``
  By default, b4 saves the cover letter as a separate file in the output
  directory specified. This flag turns it off. This is also the default
  when used with ``-o -``.

``--no-partial-reroll``
  For minor changes, it's common practice for contributors to send
  follow-ups to just the patches they have modified. For example::

      [PATCH v1 1/3] foo: add foo to bar
      [PATCH v1 2/3] bar: add bar to baz
       \- [PATCH v2 2/3] bar: add bar to baz
      [PATCH v1 3/3] baz: add baz to quux

  When b4 encounters this situation, it properly creates a v2 of the
  entire series by reusing ``[PATCH v1 1/3]`` and ``[PATCH v1 3/3]``.
  However, sometimes that isn't the right thing to do, so you can turn
  off this feature using ``--no-partial-reroll``.


Flags only valid for ``b4 shazam``
----------------------------------
By default, ``b4 shazam`` applies the patch series directly to the
current git tree and the current branch in the directory where you run
it. However, instead of just running ``git am`` and applying the patches
directly, it can also treat the series as if it were a git pull request
and either prepare a ``FETCH_HEAD`` that you can merge manually, or even
automatically merge the series using the cover letter as the basis for
the merge commit.

``-H, --make-fetch-head``
  This prepares the series and places it into the ``FETCH_HEAD`` that
  you can merge just as if it were a pull request:

  1. b4 prepares a temporary sparse worktree
  2. b4 applies the series to that worktree
  3. if ``git am`` completes successfully, b4 fetches that tree into
     your current tree's ``FETCH_HEAD``, and then gets rid of the
     temporary tree
  4. b4 places the cover letter into ``.git/b4-cover``
  5. b4 suggests the command you can run to merge the change into your
     current branch, e.g.::

         git merge --no-ff -F .git/b4-cover --edit FETCH_HEAD --signoff

  Generally, this command is also a good test to see if a patch series
  is going to apply cleanly to a tree. You can perform any actions with
  the ``FETCH_HEAD`` as you normally would, such as run ``git diff``,
  make a new branch out of it using ``git checkout``, etc.

``-M, --merge``
  Exactly the same as ``--make-fetch-head``, but will actually execute
  the suggested ``git merge`` command.

Please also see the :ref:`shazam_settings` section for some
configuration file options that affect some of ``b4 shazam`` behaviour.
