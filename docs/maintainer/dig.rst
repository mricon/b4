dig: finding commit origins
===========================
The ``dig`` subcommand helps you trace a commit in your local git
repository back to the original mailing list submission on a
public-inbox instance such as lore.kernel.org.

This is useful when you need to find the discussion thread for an
already-applied commit, identify the original recipients, or retrieve
the full thread for reference.

Basic usage
-----------
Pass a commit-ish object to ``b4 dig``::

    $ b4 dig -c HEAD
    $ b4 dig -c abc123
    $ b4 dig -c v6.14-rc2~10

B4 will try several strategies to find the original submission, in
order of reliability:

1. **Patch-id matching**: computes a stable patch-id from the commit
   diff and searches for it on lore, trying multiple diff algorithms.
2. **Author email + subject**: searches for the commit subject combined
   with the author's email address.
3. **In-body From: line**: when a patch was sent from a different email
   address than the commit author (common with contributors who have
   both personal and corporate addresses), git records the author
   identity in an in-body ``From:`` line. B4 searches for that exact
   string.

If the commit already contains ``Link:`` trailers pointing to
public-inbox URLs, b4 will use those as well.

.. versionadded:: v0.15

Option flags
------------
``-c COMMITISH, --commitish COMMITISH``
  The commit to look up. Can be a SHA, tag, branch, or any valid
  git commit-ish expression.

``-C, --no-cache``
  Bypass the local cache and fetch fresh results from the server.

``-a, --all-series``
  Instead of showing only the best matching patch, show all revisions
  of the series that b4 can find. Useful for seeing the full history
  of a patch set.

``-m DEST, --save-mbox DEST``
  Save the matched thread to the specified mbox file instead of just
  printing the link.

``-w, --who``
  Show the list of people who were originally included in To and Cc
  of the matched patch. Useful for finding out who was involved in
  the original review.

.. note::

   The ``-a``, ``-m``, and ``-w`` flags are mutually exclusive.

Examples
--------
Find the mailing list link for a commit::

    $ b4 dig -c e48e16f3e37f
    ---
    [PATCH v3] f2fs: support non-4KB block size without packed_ssa feature
    https://patch.msgid.link/20260110235405.2783424-1-daeho43@gmail.com

Show all revisions of the series containing a commit::

    $ b4 dig -c e48e16f3e37f -a
    ---
    This patch belongs in the following series:
    ---
      v1: [PATCH] f2fs: support non-4KB block size ...
      v2: [PATCH v2] f2fs: support non-4KB block size ...
      v3: [PATCH v3] f2fs: support non-4KB block size ...

Find who was on the original thread::

    $ b4 dig -c abc123 -w
    ---
    People originally included in this patch:
    maintainer@example.org, reviewer@example.org, dev-list@example.org

Save the matched thread for offline review::

    $ b4 dig -c abc123 -m /tmp/thread.mbx
    Saved matched thread to /tmp/thread.mbx
