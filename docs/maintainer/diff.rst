b4 diff: comparing patch series
===============================
The ``diff`` subcommand allows comparing two different revisions of the
same patch series using ``git range-diff``. Note, that in order to
perform the ``range-diff`` comparison, both revisions need to cleanly
apply to the current tree, which may not always be easy to achieve.

The easiest way to use it is to prepare two mbox files of the series you
would like to compare first::

    $ b4 am --no-cover -n ver1 msgid-of-ver-1
    $ b4 am --no-cover -n ver2 msgid-of-ver-2
    $ b4 diff -m ver1.mbx ver2.mbx

Optional flags
--------------
``-g GITDIR, --gitdir GITDIR``
  Specify a path to the git tree to use, if not running the command
  inside a git tree.

``-p USEPROJECT, --use-project USEPROJECT``
  **(DEPRECATED)**: This is a legacy option that made sense before
  public-inbox supported collating and retrieving threads from across
  multiple lists. This flag will probably go away in the future.

``-C, --no-cache``
  By default, b4 will cache the retrieved threads for about 10 minutes.
  This lets you force b4 to ignore cache and retrieve the latest
  results.

``-v WANTVERS [WANTVERS ...], --compare-versions WANTVERS [WANTVERS ...]``
  To properly work, this requires that both versions being compared are
  part of the same thread, which is rarely the case. In the future, this
  may work better as more series use the ``change-id`` trailer to keep
  track of revisions across discussion threads.

  Example: ``b4 diff <msgid> -v 2 3``

``-n, --no-diff``
  By default, ``b4 diff`` will output the results of the range-diff
  command. However, this can be a wall of text, so instead you may want
  to just view the command that you can run yourself with the ranges
  prepared by b4. This additionally allows you to tweak the
  ``git-range`` flags to use.

``-m AMBOX AMBOX, --compare-am-mboxes AMBOX AMBOX``
  Compares two mbox files prepared by ``git am`` instead of querying
  the public-inbox server directly.

``-o OUTDIFF, --output-diff OUTDIFF``
  **(DEPRECATED)** Sends ``range-diff`` output into a file. You should use
  ``-n`` instead and redirect output from there.

``-c, --color``
  **(DEPRECATED)** Show colour output even when outputting into a file.
  You should use ``-n`` instead and modify flags to ``range-diff``.
