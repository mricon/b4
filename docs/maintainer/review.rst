review: TUI-based patch review workflow (alpha)
================================================

.. warning::

   ``b4 review`` is a **technology preview** (alpha). Commands, keybindings,
   configuration options, and on-disk formats may change in incompatible ways
   between releases. Bug reports and feedback are welcome at tools@kernel.org.

The ``b4 review`` command provides a TUI-based workflow for maintainers
who receive patches on mailing lists. It lets you track incoming patch
series, review diffs with inline commenting, add code-review trailers,
send review emails, and accept (apply) patches — all from a single
terminal interface.

The workflow is built around a lightweight SQLite tracking database that
records every series you are interested in, together with a per-series
review branch in your git repository where comments, trailers, and
review state are persisted between sessions.

Getting started
---------------

Enrolling a repository
~~~~~~~~~~~~~~~~~~~~~~
Before you can track series, you need to enrol the repository::

    b4 review enroll [path] [-i identifier]

This creates metadata under ``.git/b4-review/`` and a SQLite database in
``$XDG_DATA_HOME/b4/review/``. The ``-i`` flag sets the project
identifier (defaults to the repository directory name). You only need to
do this once per repository.

The ``-i`` flag lets you work with multiple checkouts of the same git
repository, for example if you manage multiple subsystems. This way you
can have ``~/work/linux-subsystemA`` with identifier "subsystemA" and
``~/work/linux-subsystemB`` with identifier "subsystemB".

Tracking a series
~~~~~~~~~~~~~~~~~
Once enrolled, add a series to the tracking database::

    b4 review track <msgid|url|change-id> [-i identifier]

You can also pipe a message on stdin::

    cat message.eml | b4 review track

This makes it easy to integrate with mail clients. For example, to
track a series directly from mutt with a single keypress, add the
following to your ``~/.muttrc``::

    macro index 8 "<pipe-message>~/bin/b4 review track -i linux-subsystemA<return>"

Pressing ``8`` on any message in the series will pipe it to b4 and
start tracking.

B4 fetches the series from lore, discovers all available revisions
(older and newer), and stores everything in the tracking database.

Using the TUI
-------------
Launch the TUI inside the repository with::

    b4 review tui [-i identifier]

If you are already on a review branch (``b4/review/<change-id>``), the
TUI opens the review interface directly and shows a notification
suggesting you switch to your target branch (configured via
:term:`b4.review-target-branch`, or ``master``/``main`` by default)
if you want to see the full tracking list instead. Otherwise it starts
in the tracking list.

You can leave the tui running. Any series added in another terminal will
be automatically recognized and displayed.

Tracking list
~~~~~~~~~~~~~
The tracking list shows all series you are following, with their current
status.

**Series lifecycle**

Every tracked series passes through these statuses:

=============  =========================================================
Status         Meaning
=============  =========================================================
``new``        Freshly tracked, not yet reviewed
``reviewing``  Review branch created, review in progress
``replied``    Review comments sent to the mailing list
``waiting``    Waiting for a new revision from the submitter
``snoozed``    Deferred until a date, duration, or git tag
``accepted``   Patches applied to the target branch
``thanked``    Thank-you note sent to the contributor
``archived``   Review completed and archived
``gone``       Review branch deleted or missing (e.g. after a sync)
=============  =========================================================

Series are grouped by lifecycle stage — Active (reviewing/replied/
accepted/thanked), New, Waiting, Snoozed, and Gone — and sorted within
each group by the most recent activity, whether that is a new mailing
list reply or a local status change.

**Listing columns**

Each row in the tracking list shows:

* **Submitter** — patch author name (truncated if necessary)
* **A·R·T** — Acked-by · Reviewed-by · Tested-by trailer counts
  collected from the review branch
* **Fups** — total follow-up reply count for the thread, with any
  unseen replies shown as ``+N`` in yellow (populated after pressing
  ``u``)
* **S** — single-character status symbol; ``*`` suffix means the
  tracking data needs a refresh
* **Subject** — compact ``[subsystem,vN,0/M]`` prefix followed by the
  series subject

**Status symbols**

=======  =============
Symbol   Status
=======  =============
``★``    new
``✎``    reviewing
``↩``    replied
``↻``    waiting
``⏸``    snoozed
``∈``    accepted
``✓``    thanked
``∅``    gone
=======  =============

**Keybindings**

============  ===========================================================
Key           Action
============  ===========================================================
``Enter``     View thread — open the lite thread viewer (see below)
``r``         Review — open the review interface for the selected series
``d``         Range-diff between revisions
``a``         Action menu — context-sensitive actions (see below)
``u``         Update — fetch latest trailers, check for newer revisions,
              and refresh follow-up reply counts
``l``         Limit — filter the list of displayed series
``s``         Shell — suspend to an interactive sub-shell
``p``         Patchwork — switch to the Patchwork browser (if configured)
``j``/``k``   Move cursor down/up
``?``         Help — show keybinding reference
``q``         Quit
============  ===========================================================

The ``a`` key opens a context-sensitive action menu. Each action has a
single-keypress shortcut shown in square brackets so you can act
quickly — for example, ``a`` then ``T`` to take a series. Available
actions depend on the series status:

**Reviewing / replied:**

* ``[T]`` **Take** — apply patches to the target branch
* ``[R]`` **Rebase** — rebase review branch onto HEAD
* ``[w]`` **Mark as waiting** — waiting on new revision
* ``[s]`` **Snooze** — defer until a date, duration, or git tag
* ``[U]`` **Upgrade** — switch to a newer revision (when available)
* ``[A]`` **Abandon** / ``[x]`` **Archive**

**New / gone:**

* ``[r]`` **Review** — create or re-enter the review branch
* ``[s]`` **Snooze** — defer until later (new only)
* ``[A]`` **Abandon**

**Waiting:**

* ``[r]`` **Review** — return to reviewing
* ``[A]`` **Abandon** / ``[x]`` **Archive**

**Snoozed:**

* ``[u]`` **Unsnooze** — wake up and restore previous status
* ``[A]`` **Abandon** / ``[x]`` **Archive**

**Accepted:**

* ``[t]`` **Thank** — send a thank-you note
* ``[A]`` **Abandon** / ``[x]`` **Archive**

The details panel at the bottom shows the full original subject, sender,
send date, status, change-ID, lore link, known revisions, and the
review branch name for active and snoozed series.

Lite thread viewer
~~~~~~~~~~~~~~~~~~
Pressing ``Enter`` on any series opens a mutt-style thread viewer that
fetches the full mailing list thread from lore and displays it in two
levels:

**Thread index** — a flat list of all messages (patches and follow-ups)
with date, author, mutt-style threading tree art, and subject. Reply
messages are dimmed to make patches stand out.

**Message view** — full headers (Date, From, To, Cc, Subject, Link,
Attestation) and message body with diff syntax highlighting and
quoted-line dimming. Addresses are packed horizontally to make good use
of available terminal width.

The thread viewer is available from both the tracking list and the
Patchwork browser, providing a quick way to read a thread and fire off
a reply without creating a review branch.

*Thread index keybindings*

===============  =========================================================
Key              Action
===============  =========================================================
``Enter``        Open the selected message in the message viewer
``j``/``k``      Move cursor down/up
``q``            Close the thread viewer
===============  =========================================================

*Message view keybindings*

================  ========================================================
Key               Action
================  ========================================================
``j``/``k``       Next/previous message in thread
``Enter``         Scroll down one line
``Backspace``     Scroll up one line
``Space``         Page down
``-``             Page up
``S``             Skip past the next block of quoted text
``^``             Jump to top of message
``$``             Jump to bottom of message
``r``             Reply to the current message
``q``/``Escape``  Return to the thread index
================  ========================================================

The ``S`` key works like mutt's skip-quoted: it scans forward from the
current scroll position, finds the next block of quoted lines (``>``
prefixed), skips past it, and scrolls to the first non-quoted line with
a couple of trailing quote lines visible for context.

Review interface
~~~~~~~~~~~~~~~~
The review interface presents a split-pane view: the left pane lists
patches in the series, and the right pane shows the diff for the
selected patch.

**Review mode keybindings**

=========================  =============================================
Key                        Action
=========================  =============================================
``[``/``]``                Previous/next patch
``j``/``k``                Scroll down/up
``h``/``l``                Scroll left/right
``Space``/``Backspace``    Page down/up
``.``/``,``                Jump to next/previous review comment
``Tab``                    Switch focus between panels
``t``                      Trailers — quickly add Reviewed-by, Acked-by, etc.
``c``                      Comment — open ``$EDITOR`` for inline comment
``n``                      Notes — view or edit review notes
``r``                      Reply — open ``$EDITOR`` for a general reply
``f``                      Followups — toggle follow-up messages from lore
``a``                      Agent — run review LLM agent (if configured)
``d``                      Done — toggle "done" state on the current patch
``x``                      Skip — toggle "skip" state on the current patch
``C``                      Check — run configured per-patch check command
``e``                      Toggle email mode
``s``                      Shell — suspend to an interactive sub-shell
``?``                      Help — show keybinding reference
``q``                      Quit
=========================  =============================================

**Email preview mode keybindings**

======  ================================================================
Key     Action
======  ================================================================
``T``   Edit To/Cc/Bcc recipients
``S``   Send review emails
``e``   Toggle email mode
======  ================================================================

**Inline diff comments**

Press ``c`` on a patch to open ``$EDITOR`` with the full diff. B4
prepends instruction comments at the top and sets the filehint to
``review.diff``, so editors with filetype detection will apply diff
syntax highlighting.

To leave a comment, write it on a new line inside the hunk, directly
below the diff line you want to comment on. Any line that does not
start with ``" "``, ``+``, ``-``, or ``\`` is treated as a comment.
You may delete hunks you are not interested in reviewing, but leave
all hunks you are commenting on intact.

For longer comments that span multiple lines, wrap them in ``>`` / ``<``
delimiters::

    @@ -10,3 +10,4 @@
     context line
    +new_function();
    >
    >>>
    This function needs a NULL check on the return value,
    otherwise we risk a dereference on the error path.
    <<<
    <
     another context line

Single-line comments can be written without delimiters::

    @@ -10,3 +10,4 @@
     context line
    +new_function();
    Needs a NULL check here.
     another context line

On save, b4 extracts each comment and associates it with the nearest
preceding diff line (file path and line number). Comments from all
reviewers are displayed in the diff view as coloured bordered panels,
with the reviewer's initials shown in the panel title. Use ``.`` and
``,`` to jump between comments.

When you send review emails, b4 automatically builds a standard
quoted-reply for each patch: only hunks that contain comments are
included, diff lines are quoted with ``>``, and your comments appear
unquoted after the relevant line — matching the format expected on
mailing lists. To keep replies concise, b4 shows at most 5 lines of
diff context above each comment and collapses larger gaps with a
``[ ... skip N lines ... ]`` marker.

The left pane summarises the review state per reviewer using a trailer
overlay.

**Per-patch states**

Each patch in the series can be marked with a state to help you track
your review progress:

==========  ======  =======================================================
State       Key     Meaning
==========  ======  =======================================================
*(none)*    —       Not yet reviewed
Done        ``d``   Review complete, include in outgoing emails
Skip        ``x``   Intentionally skipped, exclude from outgoing emails
==========  ======  =======================================================

Pressing ``d`` or ``x`` toggles the state for the current patch. The
patch list on the left shows the state visually: done patches appear in
bold, skipped patches appear dimmed.

Skipped patches are automatically excluded when sending review emails.
When taking patches via cherry-pick, skipped patches are pre-deselected
in the patch selection dialog.

**Follow-up messages**

Press ``f`` to fetch and display follow-up messages from lore for the
series being reviewed. The ``f`` key is a toggle — pressing it again
clears the follow-up display.

Follow-up messages appear as coloured panels in the diff view, showing
threading depth (replies indented visually), along with From, Date, and
Message-ID headers for easy cross-referencing with your mail client.

You can click a follow-up panel header (marked with ↩) to compose a
quick reply directly from the review interface. B4 opens ``$EDITOR``
with the quoted message and constructs a proper reply-to-all email with
correct threading headers.

Patchwork integration
~~~~~~~~~~~~~~~~~~~~~
If your project uses a Patchwork server (see :ref:`patchwork_settings`),
press ``p`` in the tracking list to open the Patchwork browser. From
there you can:

* Browse series from your Patchwork project
* View a series thread (``Enter``)
* View CI check details for a series (``c``)
* Track a series directly from the Patchwork list (``t``)
* Set or change the Patchwork state for a series (``s``)
* Hide and unhide series (``h``/``u``)
* Toggle display of hidden series (``H``)
* Refresh the series list from Patchwork (``r``)
* Filter the list with a mutt-style pattern (``l``)
* Show keybinding help (``?``)

Each series in the listing shows a coloured CI status indicator when
Patchwork has check results: green for pass, red for fail or warning,
and dim for pending. Press ``c`` to open a detailed view of all CI
checks grouped by patch, showing the check context, description, and a
link to the full CI results.

Taking action
-------------

Upgrading to a newer revision
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When a submitter sends a new revision of a series you are reviewing, the
Revisions line in the details panel is highlighted to let you know.
Press ``u`` to fetch the latest thread and discover new revisions, then
use the action menu (``a``) and select **Upgrade** to switch the review
branch. B4 will:

1. Save your review comments on each patch, keyed by stable patch-id.
2. Archive the current revision (creating a ``.tar.gz`` backup).
3. Fetch and check out the new revision.
4. Restore your comments onto patches whose content did not change.

Comments on patches that were modified between revisions are not carried
over, since those patches need fresh review. Cover letter reviews are
also not carried over, as they are specific to the previous revision.

Applying patches (take)
~~~~~~~~~~~~~~~~~~~~~~~
Open the action menu (``a``) and select **Take** to apply a reviewed series.
B4 offers three methods:

* **Merge** — creates a merge commit using the cover letter as the
  commit message template. Per-commit ``Signed-off-by`` and ``Link:``
  trailers are applied to each patch individually.
* **Linear** (git-am) — applies patches linearly with ``git am``.
* **Cherry-pick** — cherry-picks individual patches (you can select
  which ones). Skipped patches are pre-deselected.

The Take dialog suggests recently used target branches, with the
configured :term:`b4.review-target-branch` always included. You can
also type a branch name directly.

Optionally toggle the ``Signed-off-by`` and ``Link:`` checkboxes to
add those trailers to each commit, and the ``Mark as accepted``
checkbox to update the series status. Press ``Ctrl-y`` to confirm,
or ``Escape`` to cancel.

Rebasing
~~~~~~~~
Open the action menu (``a``) and select **Rebase** to rebase the review
branch onto a target branch. The dialog suggests recently used branches
(same as the Take dialog). Press ``y`` to confirm, or ``Escape`` to
cancel. B4 first tests applicability in a temporary worktree before
performing the actual rebase.

Range-diff
~~~~~~~~~~
Press ``d`` to compare two revisions of the series using ``git
range-diff``. B4 fetches the comparison revision from lore if needed.

Thank-you
~~~~~~~~~
Open the action menu (``a``) on an accepted series and select **Thank**
to compose and send a thank-you note to the contributor.

Archive and abandon
~~~~~~~~~~~~~~~~~~~
Open the action menu (``a``) and select **Archive** to archive a
completed series (creates a ``.tar.gz`` in
``$XDG_DATA_HOME/b4/review-archived/``). Select **Abandon** to delete
the series and review branch entirely.

.. _snooze_details:

Snoozing a series
~~~~~~~~~~~~~~~~~
When you want to defer a series — perhaps waiting for a release
candidate or simply clearing your queue — open the action menu (``a``)
and select **Snooze**. The snooze dialog offers three modes:

* **Duration** — relative time like ``2w`` (2 weeks), ``30d`` (30 days),
  or ``3m`` (3 months).
* **Date** — an absolute date in ``YYYY-MM-DD`` format.
* **Tag** — a git tag name such as ``v6.15-rc3``. The series wakes up
  when that tag appears in the repository.

Snoozed series move to a separate **Snoozed** group in the tracking
list and are skipped during ``u`` (update-all). The review branch is
preserved so you can pick up exactly where you left off.

When the snooze condition is met — the date passes or the tag appears
— the series automatically wakes up and returns to its previous status
the next time the TUI loads. You can also wake a series manually via
the action menu (**Unsnooze**).

The snooze dialog remembers your last choice within a session, so if
you are snoozing several series with the same settings the fields are
pre-populated.

Working across multiple machines
--------------------------------

Because review state is stored in ``b4/review/*`` git branches, it can
be synchronised between machines using any git remote. This makes it
straightforward to start reviewing a series on one machine and continue
on another, or to keep a laptop and a workstation in sync.

Setting up a sync remote
~~~~~~~~~~~~~~~~~~~~~~~~~

Configure a dedicated remote pointing to a repository accessible from
all your machines::

    git remote add review-sync git@example.com:linux-review.git

Then configure push and fetch refspecs so that only ``b4/review/*``
branches are transferred::

    git config --add remote.review-sync.push  '+refs/heads/b4/review/*:refs/heads/b4/review/*'
    git config --add remote.review-sync.fetch  'refs/heads/b4/review/*:refs/heads/b4/review/*'

The ``+`` prefix in the push refspec enables force-push, which is
required because the tracking commit at the tip of each review branch is
replaced in-place whenever the series status changes.

.. warning::

   Review branches may contain unpublished comments, draft responses, or
   early-stage review notes that you would not want to share publicly.
   Make sure the remote repository is not publicly accessible if you want
   to keep your in-progress review work private.

Syncing your review branches
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After a review session, push all your review branches in one command::

    git push review-sync

Add ``--prune`` to also remove remote branches that you have abandoned
or archived locally::

    git push --prune review-sync

On another machine, fetch the latest branches::

    git fetch review-sync

Then launch the TUI as normal — a rescan runs automatically in the
background and detects any branches whose HEAD commit changed since the
last fetch, updating the tracking database to reflect their current
state::

    b4 review tui

.. note::

   The TUI compares the HEAD commit SHA of each ``b4/review/*`` branch
   against a cached value in the database. Only branches that have
   actually changed are re-read, so the background rescan adds no
   perceptible delay even in large repositories.

Optional flags
--------------

``b4 review enroll``
~~~~~~~~~~~~~~~~~~~~
``repo_path``
  Path to the git repository to enrol (default: current directory).

``-i IDENTIFIER, --identifier IDENTIFIER``
  Project identifier (default: repository directory name).

``b4 review track``
~~~~~~~~~~~~~~~~~~~
``series_id``
  Series identifier: a message-id, URL, or change-id. Alternatively,
  pipe a message on stdin.

``-i IDENTIFIER, --identifier IDENTIFIER``
  Project identifier (required if not in an enrolled repository).

``b4 review tui``
~~~~~~~~~~~~~~~~~
``-i IDENTIFIER, --identifier IDENTIFIER``
  Project identifier (required if not in an enrolled repository).

``--email-dry-run``
  Show all email dialogs and perform status transitions as normal, but
  print messages to stdout instead of sending them. Useful for testing
  the full review workflow without actually delivering emails.

``--no-sign``
  Do not patatt-sign outgoing review emails. By default, review replies,
  follow-up replies, and thank-you messages are signed with your
  configured attestation key (same as ``b4 send``). This flag disables
  signing for the current session. Can also be set permanently via
  :term:`b4.review-no-patatt-sign` (see :ref:`review_settings`).

Configuration
-------------
The following configuration options are specific to ``b4 review``. Set
them in your git config under the ``[b4]`` section.

See :ref:`review_settings` for the full reference.

Patchwork integration reuses the standard patchwork settings
(:term:`b4.pw-url`, :term:`b4.pw-key`, :term:`b4.pw-project`). See
:ref:`patchwork_settings` for details.

Configuring the review agent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The ``a`` keybinding in the review interface invokes an external command
that can perform AI-assisted review of the current patch. To enable it,
set both :term:`b4.review-agent-command` and
:term:`b4.review-agent-prompt-path` in your git config. For example,
to use Claude Code with access to the repository::

    [b4]
      review-agent-command = claude --add-dir .git --allowedTools 'Bash(git:*) Read Glob Grep Write(.git/b4-review/**) Edit(.git/b4-review/**)'
      review-agent-prompt-path = .git/agent-reviewer.md

To use Gemini CLI instead::

    [b4]
      review-agent-command = gemini --sandbox --allowed-tools 'Bash(git:*) Read Glob Grep Write(.git/b4-review/**) Edit(.git/b4-review/**)'
      review-agent-prompt-path = .git/agent-reviewer.md

To use OpenAI Codex CLI::

    [b4]
      review-agent-command = codex --sandbox workspace-write
      review-agent-prompt-path = .git/agent-reviewer.md

To use GitHub Copilot CLI::

    [b4]
      review-agent-command = copilot --autopilot --yolo
      review-agent-prompt-path = .git/agent-reviewer.md

.. note::

   Only **Claude Code** and **OpenAI Codex CLI** have been directly
   tested. The command-line examples for Gemini CLI and GitHub Copilot
   CLI are best-effort suggestions. If you get another tool working
   (or find corrections for the above), please send your findings to
   tools@kernel.org.

The command is run from the repository top-level directory. The prompt
file should contain instructions telling the agent how to review patches
for your project. A sample prompt is included in
``misc/agent-reviewer.md`` in the b4 source tree — copy it into your
repository and adapt it to your project's coding standards and review
guidelines.

Customising the colour theme
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The review TUI uses Textual's built-in theming system. By default it
picks colours from the active Textual theme. You can switch themes by
setting the ``TEXTUAL_THEME`` environment variable before launching the
TUI. For example, to use a dark theme::

    TEXTUAL_THEME=textual-dark b4 review tui

To use a 16-colour theme that works well on basic terminals::

    TEXTUAL_THEME=textual-ansi b4 review tui

The ``textual-ansi`` theme restricts rendering to the standard 16 ANSI
colours, which makes it suitable for terminals that do not support 256
or true-colour output. All UI elements — diff highlighting, reviewer
badges, CI indicators, and comment panels — adapt automatically to the
active theme.

Disabling colour entirely
~~~~~~~~~~~~~~~~~~~~~~~~~~
If you prefer no colour at all — for example, when piping output to a file
or when colours interfere with a screen reader — you can set the
``NO_COLOR`` environment variable (see `no-color.org <https://no-color.org>`_
for the broader convention)::

    NO_COLOR=1 b4 review tui

This tells Textual to strip all colour information from the rendered
output while keeping the layout intact.
