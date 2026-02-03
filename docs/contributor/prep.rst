prep: preparing your patch series
=================================
The first stage of contributor workflow is to prepare your patch series
for submission upstream. It generally consists of the following stages:

1. start a new topical branch using ``b4 prep -n topical-name``
2. add commits as usual and work with them using ``git rebase -i``
3. prepare the cover letter using ``b4 prep --edit-cover``
4. prepare the list of recipients using ``b4 prep --auto-to-cc``
5. run basic checks using ``b4 prep --check``

Starting a new topical branch
-----------------------------
When you are ready to start working on a new submission, the first step
is to create a topical branch::

    b4 prep -n descriptive-name [-f tagname]

It's important to give your branch a short descriptive name, because it
becomes part of the unique ``change-id`` that is used to track your
proposal across revisions. In other words, don't call it "stuff" or
"foo".

This command performs the following operations:

1. Creates a new branch called ``b4/descriptive-name`` and switches to it.
2. Creates an empty commit with a cover letter template.

.. note::

   Generally, you should fork from some well-defined point in the
   project history, not from some random tip commit. You can use ``-f``
   to specify a fork-point for b4 to use, such as a recent tag name.

You can then edit the cover letter using::

    b4 prep --edit-cover

This should start a text editor using your defined ``$EDITOR`` or
``core.editor`` and automatically update the cover letter commit when
you save and exit.

.. _prep_cover_strategies:

Cover letter strategies
~~~~~~~~~~~~~~~~~~~~~~~
By default, b4 keeps the cover letter in an empty commit at the start of
your series. This has the following benefits:

* it's easy to keep track where your series starts without needing to
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
cover letter. You can tell ``b4`` which strategy to use using the
:term:`b4.prep-cover-strategy` configuration variable.

``commit`` strategy (default)
  This is the default strategy that keeps the cover letter and all
  tracking information in an empty commit at the start of your series.
  See the preceding section for upsides and downsides.

  This is the recommended strategy for developers who mostly send out
  patch series and don't perform actual subsystem tree management tasks,
  such as merging submissions from sub-maintainers, cherry-picking
  commits, etc.

``branch-description`` strategy
  This keeps the cover letter and all tracking information outside of
  the git commits by using the branch description configuration value,
  stored locally in ``.git/config``.

  Upsides:

  * this is how git expects you to handle cover letters, see
    ``git format-patch --cover-from-description``
  * editing the cover letter doesn't rewrite commit history
  * merging between branches is easiest

  Downsides:

  * the cover letter only exists local to your tree -- you won't be
    able to commit it to the repository and push it remotely
  * you have to rely on the base branch for keeping track of where your
    series starts

``tip-commit`` strategy
  This is similar to the default ``commit`` strategy, but instead of
  keeping the cover letter and all tracking information in an empty
  commit at the start of your series, it keeps it at the tip of your
  series.

  Upsides:

  * allows you to push the series to a remote and pull it from a
    different location to continue working on a series
  * editing the cover letter doesn't rewrite commit history, which may
    be easier when working in teams

  Downsides:

  * adding new commits is a bit more complicated, because you have to
    immediately rebase them to be in front of the cover letter
  * you have to rely on the base branch for keeping track of where your
    series starts

.. note::

   At this time, you can't easily switch from one strategy to the other
   once you have created the branch with ``b4 prep -n``. This may be
   supported in the future.

Enrolling an existing branch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If you've already started working on a set of commits without first
running ``b4 prep -n``, you can enroll your existing branch to make it
"prep-tracked".

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

If you sent the series using ``b4 send`` it should even contain all the
preserved tracking information, but it works reasonably well with any
patch series.

Working with commits
--------------------
All your commits in a prep-tracked branch are just regular git commits
and you can work with them using any regular git tooling:

* you can rebase them using ``git rebase``
* you can amend, reword, split, squash commits interactively using ``git
  rebase -i``; there are many excellent tutorials available online on
  how to use interactive rebase

Unless you are using an old version of git, your empty cover letter
commit should remain preserved through all rebase operations.

.. note::

   You can edit the cover letter using regular git operations, though it
   isn't recommended and it's best to always do it with ``b4 prep
   --edit-cover``. If you do want to edit it directly using ``git rebase
   -i``, remember to use ``git commit --allow-empty`` to commit it back
   into the tree.

What if the series only has a single patch?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When you only have a single patch, b4 should "mix-in" the contents of
the cover letter into the "under-the-cut" portion of the patch itself,
where it serves as a source of additional information for the reviewers,
but never makes it into the actual commit.

You can just use the cover letter for extra To/Cc trailers and changelog
entries as your patch goes through revisions. If you add more commits at
some point in the future, you can fill in the cover letter content with
additional information about the intent of your entire series.

.. _prep_deps:

Working with series dependencies
--------------------------------

.. versionadded:: v0.14

.. warning::

   This is an experimental set of features introduced in v0.14. It may
   have rough edges or unexpected bugs.

If your series depends on another set of patches that aren't yet merged
into the repository, you can specify these patches as *prerequisites*.

There are multiple ways to indicate a dependency:

- by the ``change-id`` of the series
- by the ``message-id`` of its first patch or cover letter
- by the ``patch-id`` of individual patches

Using ``change-id`` is easiest, because this allows an easy way to
identify when a newer version of the prerequisite series is available.
The ``change-id`` is usually included in series created and sent with b4
itself.

To find the ``change-id`` of a series, look at the first patch or the
cover letter and see if it has a ``change-id:`` entry at the bottom.

Here is one such example:

- https://lore.kernel.org/lkml/20240425-b4-dts_dxl_audio-v5-0-46397f23ce35@nxp.com/

To specify this series as a dependency, run ``b4 prep --edit-deps`` and
add the following line in the editor that opens::

    change-id: 20240402-b4-dts_dxl_audio-74ba02030a72:v5

In addition to the change-id itself, it's also necessary to add ``:v5``
to the end of that line, to indicate the specific revision of that
series. This allows checking if a newer version of the series is
available when running ``b4 prep --check-deps`` during the next step.

In addition to the ``change-id``, you must also specify the
``base-commit`` to use for your combined series. Most of the time it is
sufficient to copy-paste the ``base-commit:`` line from the same series
where you copy-pasted the ``change-id`` line, but you can also use a
specific tag.

Using the message-id
~~~~~~~~~~~~~~~~~~~~
If a series doesn't specify a ``change-id``, you can also refer to it
using the ``message-id`` of the cover letter or the first patch in the
series. Enclose the message-id in the brackets, e.g. you can refer to
the same series mentioned above by its ``message-id``::

    message-id: <20240425-b4-dts_dxl_audio-v5-0-46397f23ce35@nxp.com>

If you specify a series by its message-id, running ``--check-deps``
won't show if there is a newer version of the series available. For this
reason, it is better to always use the series ``change-id``, if it's
available.

.. note::

   Specifying the message-id always pulls in the entire series, not
   individual patches. To specify individual patches, use the patch-id
   mechanism described below.

Using the patch-id
~~~~~~~~~~~~~~~~~~
If you really want to, you can specify individual patches using their
patch-ids, generated with ``git patch-id --stable``. For example, to
obtain the patch-id of just the 3rd patch in the example series above,
run::

    $ curl -sL https://lore.kernel.org/lkml/20240425-b4-dts_dxl_audio-v5-3-46397f23ce35@nxp.com/raw \
    > | git patch-id --stable
    29e16de21ac5396e1475bbfe2798ac1ab2c7b7a1 0000000000000000000000000000000000000000

You can now specify the dependency using that patch-id hash::

    patch-id: 29e16de21ac5396e1475bbfe2798ac1ab2c7b7a1

Running ``--check-deps``
~~~~~~~~~~~~~~~~~~~~~~~~
After you have finished specifying dependencies using ``b4 prep
--edit-deps``, you should run ``--check-deps``, which does the following
verifications:

- ensures that it can find all specified series on the server
- checks if newer versions of the series are available
- checks that the specified base-commit is present in the tree
- checks if prerequisite series plus your patches cleanly apply

You should run ``--check-deps`` right after editing them, and right
before submitting your series for review.

.. _prep_recipients:

Prepare the list of recipients
------------------------------
When you are getting ready to submit your work, you need to figure out
who the recipients of your series should be. By default, b4 should send
the series to any address mentioned in the trailers, plus to any other
addresses you tell it to use.

For the Linux kernel, a required step is to gather the recipients from
the output of ``get_maintainer.pl``, which b4 does for you automatically
when you run the ``auto-to-cc`` command::

    b4 prep --auto-to-cc

B4 should append any discovered recipients to the cover letter as extra
``To:`` and ``Cc:`` trailers. It's normal for this list to be pretty
large if your change is touching a lot of files. You can add or remove
recipients by adding or removing the recipient trailers from the cover
letter using ``b4 prep --edit-cover``.

For projects that aren't using the MAINTAINERS file, there is usually a
single list where you should send your changes. You can set that in the
repository's ``.git/config`` file as follows::

    [b4]
      send-series-to = some@list.name

This may also be already set by the project, if they have a
``.b4-config`` file in the root of their git repository.


.. _prep_check:

Checking your work
------------------

.. versionadded:: v0.14

.. warning::

   This is a new feature in version 0.14 and you should consider it
   experimental.

Once you are getting close to submitting your series, you should run
``b4 prep --check``. This should run a suite of recommended local checks
to make sure that your patches do not have some of the more common
problems, such as spelling errors, missing Signed-off-by trailers, etc.

For the Linux kernel, this automatically runs ``scripts/checkpatch.pl``,
while other projects may define their own checks as part of the default
``.b4-config``.

.. _prep_cleanup:

Cleaning up old work
--------------------
Once project maintainers accept your series, you can archive and clean
up the prep-managed branch, together with all of its sent tags::

    b4 prep --cleanup

This command lists all prep-managed branches in your repository. Pick a
branch to clean up, make sure it's not currently checked out, and run
the command again::

    b4 prep --cleanup b4/my-topical-branch

After you confirm your action, this should create a tarball with all the
patches, cover letters, and tracking information from your series.
Afterwards, b4 deletes the branch and all related tags from your local
repository.

.. _prep_flags:

Prep command flags
------------------
Please also see :ref:`contributor_settings`, which allows setting or
modifying defaults for some of these flags.

``-c, --auto-to-cc``
  Automatically populate the cover letter with addresses collected from
  commit trailers. If b4 finds a ``MAINTAINERS`` file, together with
  ``scripts/get_maintainer.pl``, it runs the recommended query to
  collect the maintainers and mailing lists where to send your series.

``-p OUTPUT_DIR, --format-patch OUTPUT_DIR``
  This outputs your tracked series as patches similar to what
  ``git-format-patch`` would do.

``--edit-cover``
  Lets you edit the cover letter using the editor command defined in
  git-config as ``core.editor``, the ``$EDITOR`` environment var if that
  isn't found, or ``vim`` -- because it's safe to assume that if you
  don't like vim, you would have already set your ``$EDITOR`` to use
  some other command.

``--edit-deps``
  Lets you edit the series dependencies using the editor command defined
  in git-config as ``core.editor``, the ``$EDITOR`` environment var if
  that isn't found, or ``vim``.

  .. versionadded:: v0.14

``--check-deps``
  Verifies that b4 can resolve all specified dependencies and that
  everything cleanly applies to the base-commit specified.

  .. versionadded:: v0.14

``--check``
  Runs a set of checks on your series to identify some of the more
  common problems.

  For the Linux kernel, this runs the following command for each of your
  commits:

  ``./scripts/checkpatch.pl --terse --no-summary --mailback --showfile``

  You can specify your own command by setting the
  :term:`b4.prep-perpatch-check-cmd` configuration parameter. For example
  you can make it more strict::

      [b4]
      prep-perpatch-check-cmd = ./scripts/checkpatch.pl --terse --no-summary --mailback --strict --showfile

  If you want to see a more detailed checkpatch report, you can always
  run it separately::

      ./scripts/checkpatch.pl --strict --git $(b4 prep --show-info series-range)

  .. versionadded:: v0.14

``--show-revision``
  Shows the current series revision.

``--force-revision N``
  Forces the revision to a different integer number. This modifies your
  cover letter and tracking information and makes this change permanent.

``--compare-to vN``
  This executes a ``git range-diff`` command that lets you compare the
  previously sent version of the series to what is currently in your
  working branch. This is very useful right before sending off a new
  revision to make sure that you didn't forget to include anything into
  changelogs.

  .. versionadded:: v0.11

``--manual-reroll MSGID``
  Normally, your patch series should be automatically rerolled to the
  next version after a successful ``b4 send`` operation (see
  :doc:`send`).  However, if you sent it in using some other mechanism,
  such as ``git-send-email``, you can trigger a manual version reroll
  using this command. It requires a message-id that can be retrieved
  from the public-inbox server, so we can properly add the reference to
  the previously sent series to the cover letter changelog.

``--set-prefixes PREFIX [PREFIX ...]``
  If you want to mark your patch as ``RFC``, ``WIP``, or add any other
  subsystem identifiers, you can define them via this command. Do
  **not** add ``PATCH`` or ``v1`` here, as these are already
  automatically added to the subject lines. To remove any extra prefixes
  you previously set, you can run ``--set-prefixes ''``.

  Alternatively, you can add any extra prefixes to the cover letter
  subject line, using the usual square brackets notation, e.g.::

      [RFC] Cover letter subject

  When b4 sends the message, it should add ``PATCH``, ``vN``, to the
  subject as necessary.

  .. versionadded:: v0.11

``--add-prefixes PREFIX [PREFIX ...]``
  Similar to ``--set-prefixes``, but will add prefixes to any ones
  currently defined, as opposed to completely replacing them.

  .. versionadded:: v0.14

``--show-info [PARAM]``
  Dumps information about the current series in a format suitable for
  parsing by other tools. Starting with v0.13, the parameter can be one
  of the following:

  - **key name** to show just a specific value from the current branch
  - **branch name** to show all info about a specific branch
  - **branch name:key name** to show a specific value from a specific
    branch

  For example, if you have a branch called ``b4/foodrv-bar`` and you
  want to display the ``series-range`` value, run::

      b4 prep --show-info b4/foodrv-bar:series-range

  Or, to show all values for branch ``b4/foodrv-bar``::

      b4 prep --show-info b4/foodrv-bar

  Or, to show ``series-range`` for the current branch::

      b4 prep --show-info series-range

  And, to show all values for the current branch::

      b4 prep --show-info

  .. versionadded:: v0.13

``--cleanup [BRANCHNAME]``
  Archive and delete obsolete prep-managed branches and all git objects
  related to them, such as sent tags. Run without parameters to list
  all known prep-managed branches in the repository. Rerun with the
  branch name to create an archival tarball with all patches, covers,
  and tracking information, and then delete all git objects related to
  that series from the local repository.

  .. versionadded:: v0.13

``-n NEW_SERIES_NAME, --new NEW_SERIES_NAME``
  Creates a new branch to start work on a new patch series.

``-f FORK_POINT, --fork-point FORK_POINT``
  When creating a new branch, use a specific fork-point instead of
  whatever commit happens to be at the current ``HEAD``.

``-F MSGID, --from-thread MSGID``
  After creating a new branch, populate it with patches from this
  pre-existing patch series. Requires a message-id to retrieve from the
  public-inbox server.

``-e ENROLL_BASE, --enroll ENROLL_BASE``
  Enrolls your current branch to be b4-prep managed. Requires the name
  of the branch to use as the fork-point tracking base.

``--range-diff-opts RANGE_DIFF_OPTS``
  Additional arguments passed to ``git range-diff`` when comparing series with
  ``--compare-to``. For example::

      b4 prep --compare-to v1 --range-diff-opts "--creation-factor=80 --no-dual-color"

  .. versionadded:: v0.15
