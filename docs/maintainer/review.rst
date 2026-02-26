review: TUI-based patch review workflow (alpha)
================================================

.. warning::

   ``b4 review`` is a **technology preview** (alpha). Commands, keybindings,
   configuration options, and on-disk formats may change in incompatible ways
   between releases. Bug reports and feedback are welcome at tools@kernel.org.

The ``b4 review`` command provides a TUI-based workflow for maintainers
who receive patches on mailing lists. It lets you track incoming patch
series, review diffs with inline commenting, add code-review trailers,
send review emails, and take (apply) patches — all from a single
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
TUI opens the review interface directly. Otherwise it starts in the
tracking list.

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
``taken``      Patches applied to the target branch
``thanked``    Thank-you note sent to the contributor
``archived``   Review completed and archived
=============  =========================================================

**Keybindings**

============  ===========================================================
Key           Action
============  ===========================================================
``r``         Review — open the review interface for the selected series
``v``         View series in a modal (fetches from lore)
``d``         Range-diff between revisions
``a``         Action menu — context-sensitive actions (see below)
``u``         Update — fetch latest trailers and check for newer revisions
``l``         Limit — filter the list of displayed series
``s``         Shell — suspend to an interactive sub-shell
``p``         Patchwork — switch to the Patchwork browser (if configured)
``j``/``k``   Move cursor down/up
``?``         Help — show keybinding reference
``q``         Quit
============  ===========================================================

The ``a`` key opens a context-sensitive action menu. Available actions
depend on the series status:

* **Take** — apply patches to the target branch (reviewing/replied)
* **Rebase** — rebase review branch onto HEAD (reviewing/replied)
* **Mark as waiting** — mark series as waiting on new revision
  (reviewing/replied)
* **Upgrade** — switch review branch to a newer revision (when
  available)
* **Thank** — send a thank-you note (taken)
* **Abandon** — delete series and review branch
* **Archive** — archive a completed series

The details panel at the bottom shows an **A/R/T** row (Acked-by /
Reviewed-by / Tested-by) for series with review branches, tallying
follow-up trailers that are not already present in the commit messages.

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
``f``                      Followups — fetch and display follow-up messages from lore
``a``                      Agent — run review LLM agent (if configured)
``x``                      Check — run configured per-patch check command
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
mailing lists.

The left pane summarises the review state per reviewer using a trailer
overlay.

Patchwork integration
~~~~~~~~~~~~~~~~~~~~~
If your project uses a Patchwork server (see :ref:`patchwork_settings`),
press ``p`` in the tracking list to open the Patchwork browser. From
there you can:

* Browse series from your Patchwork project
* View a series in a modal (``v``)
* View CI check details for a series (``c``)
* Track a series directly from the Patchwork list (``t``)
* Set or change the Patchwork state for a series (``s``)
* Hide and unhide series (``h``/``u``)
* Toggle display of hidden series (``H``)
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
  commit message template.
* **Linear** (git-am) — applies patches linearly with ``git am``.
* **Cherry-pick** — cherry-picks individual patches (you can select
  which ones).

You can also choose the target branch, and optionally add a
``Signed-off-by`` trailer or a ``Link:`` trailer to each commit.
Press ``Ctrl-y`` to confirm, or ``Escape`` to cancel.

After taking, the series moves to ``taken`` status.

Rebasing
~~~~~~~~
Open the action menu (``a``) and select **Rebase** to rebase the review
branch onto the current HEAD. Press ``y`` to confirm, or ``Escape`` to
cancel. B4 first tests applicability in a temporary worktree before
performing the actual rebase.

Range-diff
~~~~~~~~~~
Press ``d`` to compare two revisions of the series using ``git
range-diff``. B4 fetches the comparison revision from lore if needed.

Thank-you
~~~~~~~~~
Open the action menu (``a``) on a taken series and select **Thank** to
compose and send a thank-you note to the contributor.

Archive and abandon
~~~~~~~~~~~~~~~~~~~
Open the action menu (``a``) and select **Archive** to archive a
completed series (creates a ``.tar.gz`` in
``$XDG_DATA_HOME/b4/review-archived/``). Select **Abandon** to delete
the series and review branch entirely.

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
