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

Reviewing trailers before applying them
---------------------------------------

.. versionadded:: v0.16

Because trailers are matched by patch-id, b4 may occasionally pull in a
trailer that you did not expect -- for example, a ``Reviewed-by:`` that was
given to an identical patch in an older series that was never actually
applied. If you would like to review and selectively reject incoming
trailers, run::

    b4 trailers -u -i

This opens your editor with the list of trailers about to be applied,
grouped per commit, each shown with the message it came from::

    - [PATCH 1/2] Add frobnicator support
      + Reviewed-by: Foo Bar <foobar@example.com>
        # via: https://lore.kernel.org/r/msgid@example.com

The ``- <patch>`` lines say which patch each trailer belongs to, so the same
trailer can be kept on one patch and rejected on another. To **reject** a
trailer, change its leading ``+`` to an ``x`` and save. The rejection is
remembered in ``.git/b4-trailers-ignore.json``, keyed by the trailer and the
message it came from (its provenance), so the same trailer from that message
will not be offered again on later ``b4 trailers -u`` runs -- including after
you reroll the series. Because the key is the provenance message and not the
patch-id, a rejection survives rebases and rewording; and if the reviewer
later re-sends the same trailer directly for your current series, that fresh
message is offered as new rather than silently dropped. Editing, adding,
removing, or reordering the ``- <patch>`` or trailer lines aborts the run
without making any changes.

Command flags
-------------
``-u, --update``
  Update branch commits with latest received trailers.

``-i, --interactive``
  Review the trailers in your editor before applying them, rejecting any you
  don't want by marking them with an ``x``. Implies ``-u``.

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
