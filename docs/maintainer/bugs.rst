bugs: bug tracking with git-bug (alpha)
========================================

.. warning::

   ``b4 bugs`` is a **technology preview** (alpha). Commands, keybindings,
   and features may change in incompatible ways between releases. Bug
   reports and feedback are welcome at tools@kernel.org.

The ``b4 bugs`` command provides a TUI and CLI for tracking bug reports
alongside your git repository using `git-bug`_. Bugs are stored as git
objects inside the repo, so they travel with the code and can be shared
via ``git push``/``git pull`` without any external service.

.. _`git-bug`: https://github.com/git-bug/git-bug

Prerequisites
-------------
Bug tracking is an optional feature, so install b4 with the ``bugs``
extra to pull in the ``ezgb`` library that drives git-bug::

    pipx install b4[bugs]

Then install `git-bug`_ v0.10.1 or later. It is a Go binary rather than a
Python package, so it cannot come from PyPI and has to be installed
separately (most distributions package it). b4 will automatically create and
adopt a git-bug identity the first time you run ``b4 bugs`` in a
repository, using your ``user.name`` and ``user.email`` from git config.

TUI overview
------------
Launch with::

    b4 bugs tui

The TUI shows a list of all tracked bugs with their submitter, comment
count, lifecycle status, and subject. A detail panel at the bottom
shows metadata for the highlighted bug.

Bug list keybindings
~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :widths: 10 40

   * - ``j``/``k``
     - Move cursor up/down
   * - ``Enter``
     - Open bug detail view
   * - ``N``
     - New bug (import from lore or create manually)
   * - ``L``
     - Edit labels on the selected bug
   * - ``a``
     - Triage action (confirm, need info, close, duplicate, etc.)
   * - ``u``
     - Update selected bug from lore (fetch new messages)
   * - ``U``
     - Update all bugs from lore
   * - ``p``
     - Pull bugs from remote
   * - ``P``
     - Push bugs to remote
   * - ``l``
     - Limit (filter) the bug list
   * - ``s``
     - Toggle showing closed bugs
   * - ``Q``
     - Quit (bare ``q`` only shows a reminder)

Bug detail keybindings
~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :widths: 10 40

   * - ``j``/``k``
     - Scroll right pane / move between comments (when left pane focused)
   * - ``,``/``.``
     - Previous/next comment
   * - ``r``
     - Reply to selected comment via email
   * - ``c``
     - Add an internal comment (not emailed)
   * - ``T``
     - Edit the bug title
   * - ``X``
     - Remove (tombstone) the selected comment
   * - ``Space``/``Backspace``
     - Page down/up
   * - ``Escape``
     - Return to bug list

Creating bugs
-------------
Press ``N`` in the bug list to create a new bug. You can choose between:

**Import from lore**
    Enter a Message-ID from a lore.kernel.org thread. b4 fetches the
    full thread, uses the oldest message as the bug title and body, and
    adds follow-up messages as comments. Importing the same thread twice
    is detected and prevented.

**Create manually**
    Opens your editor with a template. The first line becomes the bug
    title; the rest becomes the description.

Lifecycle states
----------------
Bugs move through lifecycle states tracked via ``lifecycle:`` labels:

.. list-table::
   :widths: 5 15 30

   * - ★
     - ``new``
     - Newly reported, needs triage
   * - ¤
     - ``confirmed``
     - Triaged and accepted
   * - ‽
     - ``needinfo``
     - Waiting for more information
   * - ø
     - ``worksforme``
     - Cannot reproduce (closes the bug)
   * - ≠
     - ``wontfix``
     - Will not be fixed (closes the bug)
   * - ✓
     - ``fixed``
     - Fixed (closes the bug)
   * - ≡
     - ``duplicate``
     - Duplicate of another bug (closes the bug)

Comment removal
---------------
Press ``X`` on a comment to tombstone it. The comment body is replaced
with a minimal header preserving the Message-ID (so thread refresh does
not re-import it), but all personal data is removed. This supports data
removal requests for content visible via cgit or other public interfaces.

CLI commands
------------
For scripting and non-interactive use:

.. code-block:: none

    b4 bugs import <message-id>    Import a lore thread as a new bug
    b4 bugs import --no-parent <message-id>
                                   Import only the sub-thread
    b4 bugs list                   List all bugs
    b4 bugs list --status open     List only open bugs
    b4 bugs list --label <label>   Filter by label
    b4 bugs list -j                Same, as JSON (see below)
    b4 bugs refresh [bug-id]       Fetch new messages from lore
    b4 bugs delete <bug-id>        Permanently delete a bug

.. _bugs_list_json:

Machine-readable listings
-------------------------
``b4 bugs list`` normally prints a short human-readable line per bug.
Add ``-j`` (``--json``) and it prints an array of objects on stdout
instead, one per bug:

.. code-block:: none

    id              The full bug id (the short form is just its prefix)
    title           The bug title
    status          Either "open" or "closed"
    labels          The bug's labels, sorted
    root_msgid      Message-ID of the thread the bug was imported from
    comment_msgids  Message-IDs of every later message captured as a comment
    last_activity   ISO 8601 timestamp of the most recent activity

The two message-id fields are what make the listing useful to a tool
that searches the archives for new reports. ``root_msgid`` is the same
dedup key ``b4 bugs import`` checks against, so a candidate whose
message-id appears there is a bug you already filed. ``comment_msgids``
covers the rest of the thread, so a follow-up that was already pulled in
by ``b4 bugs refresh`` does not come back as a fresh report either.
Both are bare message-ids, without the angle brackets.

``root_msgid`` is ``null`` for a bug that was filed by hand rather than
imported from a thread. Tombstoned comments keep their Message-ID, so
they still appear in ``comment_msgids`` -- the message was captured, even
though its content has since been removed.

To build an exclusion set for every bug you are already tracking:

.. code-block:: shell

    b4 bugs list -j \
        | jq -r '.root_msgid, .comment_msgids[] | select(. != null)' \
        | sort -u > known-bugs.txt

Running unattended
------------------
``b4 bugs`` needs two things before it can do anything: a git repository
to store the bugs in, and an adopted git-bug identity to attribute
changes to. If no identity exists it normally offers to create one from
your ``user.name`` and ``user.email`` -- which means a prompt, and a
prompt means a hang when nothing is there to answer it.

Pass the global ``-n`` (``--no-interactive``) flag and no prompt is ever
issued; the command fails instead. Being a global flag, it goes *before*
the subcommand:

.. code-block:: shell

    b4 -n bugs list -j      # correct
    b4 bugs list -n -j      # error: unrecognized arguments: -n

Combined with ``-j`` the failure is reported as a JSON object on stdout
rather than as log lines, so a caller always has something to parse:

.. code-block:: none

    {
      "error": "no-identity",
      "message": "No usable git-bug identity"
    }

The ``error`` slug is stable and is one of ``no-repo`` (not in a git
repository), ``no-identity`` (no git-bug identity could be adopted), or
``no-git-bug`` (the optional ``[bugs]`` extra or the ``git-bug`` binary
is not installed). The exit code is 1 in every case.

``b4 review list`` reports its own precondition failures the same way, so
a caller driving both commands only has to know one error shape; see
:ref:`review_list_json`.
