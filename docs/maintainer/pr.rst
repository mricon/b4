pr: working with pull requests
==============================
In addition to working with patches and patch series, b4 is also able to
work with pull requests. It provides the following benefits as opposed
to using git directly:

* it can check if the pull request has already been applied before
  performing a git fetch
* it will check the signature on the tag (or tip commit)
* it can track applied pull requests and send replies to submitters
  (using ``b4 ty``)
* it can explode a pull request into a series of patches for code review
  purposes

Basic usage is very similar to ``b4 am``::

    b4 pr <msgid>

By default, this will fetch the pull request into ``FETCH_HEAD``.

Optional flags
--------------

``-g GITDIR, --gitdir GITDIR``
  This specifies (or overrides) the git directory where the pull request
  should be applied.

``-b BRANCH, --branch BRANCH``
  After fetching the pull request into ``FETCH_HEAD``, check it out as a
  new branch with the name specified.

``-c, --check``
  Check if the specified pull request has already been applied.

Exploding pull requests
-----------------------
Pull requests are useful, but if the maintainer needs to do more than
just accept or reject it, providing code review commentary on a PR can
be difficult. For this reason, b4 can convert a pull request into a
mailbox full of patches, as if the pull request was sent as a patch
series. The exploded pull request will retain the correct author and
To/Cc headers.

``-e, --explode``
  Instructs b4 to convert a pull request to a series of patches and save
  them as a mailbox file.

``-o OUTMBOX, --output-mbox OUTMBOX``
  If ``-o`` is not provided, the mailbox name will be based on the
  message-id of the pull request and saved in the local directory. This
  allows overriding that with a different path and name.

Explode archival features
~~~~~~~~~~~~~~~~~~~~~~~~~
.. note::

   These are experimental features that were developed for internal
   kernel.org use.

The following flags are mostly useful when b4 is used
for archival purposes. One of the goals of this feature was to make it
possible to save pull requests, which are transient by nature, into an
archival public-inbox so they can be analyzed by archivists at a later
date if necessary.

``-f MAILFROM, --from-addr MAILFROM``
  When exploding pull requests, use this email address
  in the From header, instead of reusing the same From as in the pull
  request.

  .. deprecated:: v0.10

``-s SENDIDENTITY, --send-as-identity SENDIDENTITY``
  When resending pull requests as patch series, use
  this sendemail identity.

  .. deprecated:: v0.10

``--dry-run``
  Force a --dry-run on ``git-send-email`` invocation.

  .. deprecated:: v0.10
