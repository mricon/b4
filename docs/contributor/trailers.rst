trailers: retrieving code-review trailers
=========================================
This commands allows you to easily retrieve code-review trailers sent in
reply to your work and apply them to the matching commits. It should
locate code-review trailers sent in response to any previously submitted
versions of your series, as long as:

* either the patch-id of the commit still matches what was sent, or
* the title of the commit is exactly the same

You can always edit the trailers after they are applied by using ``git
rebase -i`` and choosing ``reword`` as rebase action.

Most commonly, you just need to run::

    b4 trailers -u

Command flags
-------------
``-u, --update``
  Update branch commits with latest received trailers.

``-S, --sloppy-trailers``
  Accept trailers where the email address of the sender differs from the
  email address found in the trailer itself.

``-F MSGID, --trailers-from MSGID``
  Look for trailer updates in an arbitrary tread found on the
  public-inbox server. Note, that this is generally only useful in the
  following two cases:

  * for branches not already managed by ``b4 prep``
  * when a single larger series is broken up into multiple smaller
    series (or vice-versa)

``--since GITLOGDATE``
  Only useful with ``-F``. By default, b4 will only look for your own
  commits as far as 1 month ago. With this flag, you can instruct it to
  look further back.

``--since-commit COMMITISH``
  Looks at all commits that happened since the specified commit (or tag,
  or branch HEAD) where you are the committer, and then queries the
  public-inbox server for matching patch-ids. Pulls in any code-review
  trailers received for the matching patches.
