am,shazam: retrieving and applying patches
==========================================
Most commonly, b4 is used to retrieve, prepare, and apply patches sent
via distribution lists. The base functionality is similar to that of
``b4 mbox``::

    b4 am 20200313231252.64999-1-keescook@chromium.org

This will do the following:

1. look up if that message-id is known on the specified public-inbox
   server (e.g. lore.kernel.org)
2. retrieve the full thread containing that message-id
3. process all replies to collect code review trailers and apply them to
   the relevant patch commit messages
4. perform attestation checks on patches and code review follow-ups
5. put all patches in the correct order and prepare for "git am"
6. write out the resulting mailbox so it is ready to be applied to a git
   tree

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
.. note::

   ``b4 shazam`` was added in version v0.9.

The two commands are very similar -- the main distinction is that ``b4
am`` will prepare the patch series for application to the git tree, but
will not make any modifications to your current branch.

The ``b4 shazam`` command will do the same as ``b4 am`` *and* will apply
the patch series to the current branch (if it is possible to do so
cleanly).

Common flags
------------
The following flags are common to both commands:

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

``-v WANTVER, --use-version WANTVER``
  If a thread (or threads, when used with ``-c``) contains multiple
  patch series revisions, b4 will automatically pick the highest
  numbered version. This switch lets you pick a different revision.

``-t, --apply-cover-trailers``
  By default, b4 will not apply any code review trailers sent to the
  cover letter (but will let you know when it finds those). This lets
  you automatically apply these trailers to all commits in the series.
  **This will become the default in a future version of b4.**

``-S, --sloppy-trailers``
  B4 tries to be careful when collecting code review trailers and will
  refuse to consider the trailers where the email address in the From:
  header does not patch the address in the trailer itself.

  For example, the following message will not be processed::

      From: Alice Maintainer <alice@personalemail.org>
      Subject: Re: [PATCH v3 3/3] Some patch title

      > [...]
      Reviewed-by: Alice Maintainer <alice.maintainer@workemail.com>

  In such situations, b4 will print a warning and refuse to apply the
  trailer due to the email address mismatch. You can override this by
  passing the ``-S`` flag.

``-T, --no-add-trailers``
  This tells b4 to ignore any follow-up trailers and just save the
  patches as sent by the contributor.

``-s, --add-my-sob``
  Applies your own ``Signed-off-by:`` trailer to every commit.

``-l, --add-link``
  Adds a ``Link:`` trailer with the URL of the retrieved message using
  the ``linkmask`` template. Note, that such trailers may be considered
  redundant by the upstream maintainer.

``-P CHERRYPICK, --cherry-pick CHERRYPICK``
  This allows you to select a subset of patches from a larger series.
  Here are a few examples.

  This will pick patches 1, 3, 5, 6, 7, 9 and any others that follow::

      b4 am -P 1,3,5-7,9- <msgid>

  This will pick just the patch that matches the exact message-id
  provided::

      b4 am -P _ <msgid>

  This will pick all patches where the subject matches "iscsi"::

      b4 am -P *iscsi*

``--cc-trailers``
  Copies all addresses found in the message Cc's into ``Cc:`` commit
  trailers.

``--no-parent``
  Break thread at the msgid specified and ignore any parent messages.
  This is handy with very convoluted threads, for example when someone
  replies with a different patch series in the middle of a larger
  conversation and b4 gets confused about which patch series is being
  requested.

``--allow-unicode-control-chars``
  There are some clever tricks that can be accomplished with unicode
  control chars that make the code as printed on the screen (and
  reviewed by a human) to actually do something totally different when
  processed by a compiler. Such unicode control chars are almost never
  legitimately useful in the code, so b4 will print a warning and bail
  out when it finds them. However, just in case there are legitimate
  reasons for these characters to be in the code (e.g. as part of
  documentation translated into LTR languages), this behaviour can be
  overridden.

Flags only valid for ``b4 am``
------------------------------
The following flags only make sense for ``b4 am``:

``-o OUTDIR, --outdir OUTDIR``
  Instead of writing the .mbox file to the current directory, write it
  to this location instead. You can also pass a path to an existing
  mbox or maildir location to have the results appended to that mailbox
  instead (see also the ``-f`` flag below).

  When ``-`` is specified, the output is dumped to stdout.

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

``-Q, --quilt-ready``
  Saves the patches as a folder that can be fed directly to quilt. If
  you don't know what quilt is, you don't really need to worry about
  this option.

``-b GUESSBRANCH [...], --guess-branch GUESSBRANCH [...]``
  When using ``--guess-base``, you can restrict which branch(es) b4 will
  use to find the match. If not specified, b4 will use the entire tree
  history.

``--guess-lookback GUESSDAYS``
  When using ``--guess-base``, you can specify how far back b4 should
  look *from the date of the patch* to find the base commit. By default,
  b4 will only consider the last 14 days prior to the date of the patch,
  but you can expand or shrink it as necessary.

``-3, --prep-3way``
  This will try to prepare your tree for a 3-way merge by doing some
  behind the scenes git magic and preparing some fake loose commits.

``--no-cover``
  By default, b4 will save the cover letter as a separate file in the
  output directory specified. This flag turns it off (this is also the
  default when used with ``-o -``).

``--no-partial-reroll``
  For minor changes, it is common practice for contributors to send
  follow-ups to just the patches they have modified. For example::

      [PATCH v1 1/3] foo: add foo to bar
      [PATCH v1 2/3] bar: add bar to baz
       \- [PATCH v2 2/3] bar: add bar to baz
      [PATCH v1 3/3] baz: add baz to quux

  In this case, b4 will properly create a v2 of the entire series by
  reusing ``[PATCH v1 1/3]`` and ``[PATCH v1 3/3]``. However, sometimes
  that is not the right thing to do, so you can turn off this feature
  using ``--no-partial-reroll``.


Flags only valid for ``b4 shazam``
----------------------------------
By default, ``b4 shazam`` will apply the patch series directly to the
git tree where the command is being executed. However, instead of
just running ``git am`` and applying the patches directly on top of the
current branch, it can also treat the series similar to a git pull
request and either prepare a ``FETCH_HEAD`` that you can merge manually,
or even automatically merge the series using the series cover letter as
the basis for the merge commit.

``-H, --make-fetch-head``
  This will prepare the series and place it into the ``FETCH_HEAD`` that
  can then be merged just as if it were a pull request:

  1. b4 will prepare a temporary sparse worktree
  2. b4 will apply the series to that worktree
  3. if ``git am`` completed successfully, b4 will fetch that tree into
     your current tree's ``FETCH_HEAD`` (and get rid of the temporary
     tree)
  4. b4 will place the cover letter into ``.git/b4-cover``
  5. b4 will offer the command you can run to merge the change into your
     current branch, e.g.::

         git merge --no-ff -F .git/b4-cover --edit FETCH_HEAD --signoff

  Generally, this command is also a good test for "will this patch
  series apply cleanly to my tree." You can perform any actions with the
  ``FETCH_HEAD`` as you normally would, e.g. run ``git diff``, make a
  new branch out of it using ``git checkout``, etc.

``-M, --merge``
  Exactly the same as ``--make-fetch-head``, but will actually execute
  the suggested ``git merge`` command.

Please also see the :ref:`shazam_settings` section for some
configuration file options that affect some of ``b4 shazam`` behaviour.
