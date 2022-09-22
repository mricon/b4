prep: preparing your patch series
=================================
The first stage of contributor workflow is to prepare your patch series
for submission upstream. It generally consists of the following stages:

1. start a new topical branch using ``b4 prep -n topical-name``
2. add commits as usual and work with them using ``git rebase -i``
3. prepare the cover letter using ``b4 prep --edit-cover``
4. prepare the list of recipients using ``b4 prep --auto-to-cc``

Starting a new topical branch
-----------------------------
When you are ready to start working on a new submission, the first step
is to create a topical branch::

    b4 prep -n descriptive-name [-f tagname]

It is important to give your branch a short descriptive name, because it
will become part of the unique ``change-id`` that will be used to track
your proposal across revisions. In other words, don't call it "stuff" or
"foo".

This command will do the following:

1. Create a new branch called ``b4/descriptive-name`` and switch to it.
2. Create an empty commit with a cover letter template.

.. note::

   Generally, you will want to fork from some known point in the
   history, not from some random HEAD commit. You can use ``-f`` to
   specify a fork-point for b4 to use, such as a recent tag name.

You can then edit the cover letter using::

    b4 prep --edit-cover

This will fire up a text editor using your defined ``$EDITOR`` or
``core.editor`` and automatically update the cover letter commit when
you are done.

.. _prep_cover_strategies:

Cover letter strategies
~~~~~~~~~~~~~~~~~~~~~~~
By default, b4 will keep the cover letter in an empty commit at the
start of your series. This has the following benefits:

* it is easy to keep track where your series starts without needing to
  keep a "tracking base branch" around
* you can view and edit the cover letter using regular git commands
  (``git log``, ``git rebase -i``)
* you can push the entire branch to a remote and pull it from a
  different location to continue working on your series from a different
  system

However, keeping an empty commit in your history can have some
disadvantages in some less-common situations:

* it complicates merging between branches
* some non-native git tools may drop empty commits
* editing the cover letter rewrites the commit history of the entire
  branch

For this reason, b4 supports alternative strategies for storing the
cover letter, which can be set using the ``b4.prep-cover-strategy``
configuration variable.

``commit`` strategy (default)
  This is the default strategy that keeps the cover letter and all
  tracking information in an empty commit at the start of your series.
  See above for upsides and downsides.

  This strategy is recommended for developers who mostly send out patch
  series and do not handle actual subsystem tree management (merging
  submissions from sub-maintainers, cherry-picking, etc).

``branch-description`` strategy
  This keeps the cover letter and all tracking information outside of
  the git commits by using the branch description configuration value
  (stored locally in ``.git/config``).

  Upsides:

  * this is how git expects you to handle cover letters (see
    ``git format-patch --cover-from-description``)
  * editing the cover letter does not rewrite commit history
  * merging between branches is easiest

  Downsides:

  * the cover letter cannot be pushed to a remote and only exists local
    to your tree
  * you have to rely on the base branch for keeping track of where your
    series starts

``tip-commit`` strategy
  This is similar to the default ``commit`` strategy, but instead of
  keeping the cover letter and all tracking information in an empty
  commit at the start of your series, it keeps it at the end ("tip") of
  your series.

  Upsides:

  * allows you to push the series to a remote and pull it from a
    different location to continue working on a series
  * editing the cover letter does not rewrite commit history, which may
    be easier when working in teams

  Downsides:

  * adding new commits is a bit more complicated, because you have to
    immediately rebase them to be in front of the cover letter
  * you have to rely on the base branch for keeping track of where your
    series starts

.. note::

   At this time, you cannot easily switch from one strategy to the other
   once you have created the branch with ``b4 prep -n``. This may be
   supported in the future.

Enrolling an existing branch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If you've already started working on a set of commits without first
running ``b4 prep -n``, you can enroll your existing branch to make it
"prep-tracked."

For example, if you have a branch called ``my-topical-branch`` that was
forked from ``master``, you can enroll it with b4::

    b4 prep -e master

Once that completes, you should be able to edit the cover letter and use
all other b4 contributor-oriented commands.

Creating a branch from a sent series
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If you have previously sent a patch series, you can create your new
topical branch from that submission by passing the ``--from-thread``
parameter to ``b4 prep -n``. All you need is the msgid of the series,
e.g.::

    b4 prep -n my-topical-branch -F some-msgid@localhost

If the series was submitted using ``b4 send`` it will even contain all
the preserved tracking information, but it's not a requirement and
should work reasonably well with most patch series.

Working with commits
--------------------
All your commits in a prep-tracked branch are just regular git commits
and you can work with them using any regular git tooling:

* you can rebase them on a different (or an updated) branch using ``git
  rebase``
* you can amend (reword, split, squash, etc) commits interactively using
  ``git rebase -i``; there are many excellent tutorials available online
  on how to use interactive rebase

Unless you are using a very old version of git, your empty cover letter
commit should be preserved through all rebase operations.

.. note::

   You can edit the cover letter using regular git operations, though it
   is not recommended (best to do it with ``b4 prep --edit-cover``). If
   you do want to edit it directly using ``git rebase -i``, remember to
   use ``git commit --allow-empty`` to commit it back into the tree.

What if I only have a single patch?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When you only have a single patch, the contents of the cover letter will
be mixed into the "under-the-cut" portion of the patch. You can just use
the cover letter for extra To/Cc trailers and changelog entries as your
patch goes through revisions. If you add more commits in the future
version, you can fill in the cover letter content with additional
information about the intent of your entire series.

.. _prep_recipients:

Prepare the list of recipients
------------------------------
When you are getting ready to submit your work, you need to figure out
who the recipients of your series should be. By default, b4 will send
the series to any address mentioned in the trailers (and to any other
addresses you tell it to use).

For the Linux kernel, a required step is to gather the recipients from
the output of ``get_maintainer.pl``, which b4 will do for you
automatically when you run the ``auto-to-cc`` command::

    b4 prep --auto-to-cc

The recipients will be added to the cover letter as extra ``To:`` and
``Cc:`` trailers. It is normal for this list to be very large if your
change is touching a lot of files. You can add or remove recipients by
adding or removing the recipient trailers from the cover letter using
``b4 prep --edit-cover``.

For projects that are not using the MAINTAINERS file, there is usually a
single list where you should send your changes. You can set that in the
repository's ``.git/config`` file as follows::

    [b4]
      send-series-to = some@list.name

This may also be already set by the project, if they have a
``.b4-config`` file in the root of their git repository.

.. _prep_flags:

Prep command flags
------------------
Please also see :ref:`contributor_settings`, which allow setting
or modifying defaults for some of these flags.

``-c, --auto-to-cc``
  Automatically populate the cover letter with addresses collected from
  commit trailers. If a ``MAINTAINERS`` file is found, together with
  ``scripts/get_maintainer.pl``, b4 will automatically perform the query
  to collect the maintainers and lists that should be notified of the
  change.

``-p OUTPUT_DIR, --format-patch OUTPUT_DIR``
  This will output your tracked series as patches similar to what
  ``git-format-patch`` would do.

``--edit-cover``
  Lets you edit the cover letter using whatever editor is defined in
  git-config for ``core.editor``, ``$EDITOR`` if that is not found, or
  ``vim`` because we're pretty sure that if you don't like vim, you
  would have already set your ``$EDITOR`` to not be vim.

``--show-revision``
  Shows the current series revision.

``--force-revision N``
  Forces the revision to a different integer number. This modifies your
  cover letter and tracking information and makes this change permanent.

``--manual-reroll MSGID``
  Normally, your patch series will be automatically rerolled to the next
  version after a successful ``b4 send`` (see :doc:`send`). However, if
  you sent it in using some other mechanism, such as ``git-send-email``,
  you can trigger a manual reroll using this command. It requires a
  message-id that can be retrieved from the public-inbox server, so we
  can properly add the reference to the previously sent series to the
  cover letter changelog.

``-n NEW_SERIES_NAME, --new NEW_SERIES_NAME``
  Creates a new branch to start work on a new patch series.

``-f FORK_POINT, --fork-point FORK_POINT``
  When creating a new branch, use a specific fork-point instead of
  whatever commit happens to be at the current ``HEAD``.

``-F MSGID, --from-thread MSGID``
  After creating a new branch, populate it with patches from this
  pre-existing patch series. Requires a message-id that can be retrieved
  from the public-inbox server.

``-e ENROLL_BASE, --enroll ENROLL_BASE``
  Enrolls your current branch to be b4-prep managed. Requires the name
  of the branch to use as the fork-point tracking base.
