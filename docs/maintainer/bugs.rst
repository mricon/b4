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
Install `git-bug`_ v0.10.1 or later. b4 will automatically create and
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
   * - ``q``
     - Quit

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
    b4 bugs refresh [bug-id]       Fetch new messages from lore
    b4 bugs delete <bug-id>        Permanently delete a bug
