Getting started with b4 review
==============================

.. warning::

   ``b4 review`` is a **technology preview** (alpha). Commands, keybindings,
   configuration options, and on-disk formats may change in incompatible ways
   between releases. Bug reports and feedback are welcome — please send
   plaintext email to tools@kernel.org.

This guide walks you through the ``b4 review`` TUI workflow using a
series of short screencasts. Each section builds on the previous one,
so it is best to follow them in order.

For a complete reference of all commands, keybindings, and configuration
options, see :doc:`/maintainer/review`.

.. contents:: In this guide
   :local:
   :depth: 1


Enrolling and tracking a series
-------------------------------

.. raw:: html

   <script src="https://asciinema.org/a/802140.js" id="asciicast-802140"
    async data-speed="1.5" data-theme="monokai" data-fit="width"></script>

Before you can use the review TUI, you need to enrol your repository.
Run this once per checkout::

    b4 review enroll

This creates a SQLite tracking database in
``$XDG_DATA_HOME/b4/review/`` and metadata under ``.git/b4-review/``.
If you manage several subsystems from separate checkouts of the same
repository, use ``-i`` to give each one a distinct identifier::

    b4 review enroll -i my-subsystem

Once enrolled, launch the TUI::

    b4 review tui

The tracking list starts empty. To add a series, you need to pass a
series identifier to ``b4 review track``. The UI will automatically
display any newly added series. You can do it from another terminal even
if the UI is running::

    b4 review track <msgid-or-lore-url>

You can also pipe a message from your mail client. For example, you can
configure mutt to track a series when you press "8"::

    macro index 8 "<pipe-message>b4 review track<return>"

B4 fetches the series from lore, discovers all available revisions
(older and newer), and stores everything in the tracking database.

**Quick actions in the tracking list:**

- ``v`` — view the series (cover letter + patches) in a modal
- ``u`` — update: fetch latest trailers and check for newer revisions
- ``a`` — open the action menu (context-sensitive)
- ``q`` — quit

If you are no longer interested in a series, press ``a`` and select
**Abandon** to remove it from the tracking list.


Reviewing a series
------------------

.. raw:: html

   <script src="https://asciinema.org/a/802142.js" id="asciicast-802142"
    async data-speed="1.5" data-theme="monokai" data-fit="width"></script>

Select a series in the tracking list and press ``r`` to start
reviewing. B4 fetches the thread, checks attestation on all messages,
and creates a review branch (``b4/review/<change-id>``). The review
interface then opens in a split-pane view: the patch list on the left,
the diff for the selected patch on the right.

Navigate between patches with ``[`` and ``]``, scroll with ``j``/``k``,
and page with ``Space``/``Backspace``. You can also use arrows and tab
between panes if you're less familiar with vim keybindings.

Adding trailers
~~~~~~~~~~~~~~~
Press ``t`` to add a code-review trailer to the current patch. A
pop-up lets you select the trailer type — Reviewed-by, Acked-by,
Tested-by, etc. The trailer is recorded in the review branch and will
be included when you send the review.

For trailers that require additional explanation, press ``r`` instead to
compose a full reply in ``$EDITOR``.

Inline diff comments
~~~~~~~~~~~~~~~~~~~~
Press ``c`` to open ``$EDITOR`` with the full diff for the current
patch. Write your comment on a new line inside the hunk, directly
below the diff line you want to comment on. Any line that does not
start with ``" "``, ``+``, ``-``, or ``\`` is treated as a comment.

For multi-line comments, use ``>>>`` / ``<<<`` delimiters::

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

You may delete hunks you are not interested in reviewing, but leave
all hunks you are commenting on intact.

Previewing and sending the review
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Press ``e`` to toggle email preview mode. The right pane switches to
show the exact email that will be sent for each patch, including your
trailers and inline comments formatted as quoted replies. Navigate
between patches with ``[`` and ``]`` to inspect each outgoing message.

When you are satisfied, press ``S`` (capital S) to send. B4 composes
proper ``In-Reply-To`` / ``References`` headers so your review appears
in the correct thread on the mailing list.

.. tip::

   Use ``--email-dry-run`` when launching the TUI to see exactly what
   would be sent without delivering any email::

       b4 review tui --email-dry-run

After sending, the series status changes to **replied**.

Waiting for a new revision
~~~~~~~~~~~~~~~~~~~~~~~~~~
If your review requested changes, open the action menu (``a``) and
select **Mark as waiting on new revision**. The series moves to
**waiting** status and sorts to the bottom of the tracking list.

When you press ``u`` to update all tracked series, b4 checks lore for
newer revisions. If one is found, the series is highlighted and you
can **Upgrade** to the new revision via the action menu.

Range-diff between revisions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Press ``d`` in the tracking list to compare two revisions of the
series using ``git range-diff``. B4 fetches the comparison revision
from lore if needed and displays the result in a scrollable view.


Taking a series and sending thank-yous
---------------------------------------

.. raw:: html

   <script src="https://asciinema.org/a/802143.js" id="asciicast-802143"
    async data-speed="1.5" data-theme="monokai" data-fit="width"></script>

Fetching follow-ups
~~~~~~~~~~~~~~~~~~~~
Before applying a series, you may want to check what other reviewers
have said. Press ``f`` in the review interface to fetch follow-up
messages from lore. They are displayed as coloured panels in the diff
view, attributed by the reviewer's initials.

Applying patches (take)
~~~~~~~~~~~~~~~~~~~~~~~~
Go back to the tracking list (``q`` from the review interface) and
open the action menu (``a``). Select **Take** to apply the series.

B4 presents a dialog where you choose:

* **Merge strategy** — merge (creates a merge commit using the cover
  letter as the message template), linear (``git am``), or cherry-pick
  (select individual patches).
* **Target branch** — the branch to apply to (defaults to ``master``
  or ``main``).
* **Optional trailers** — toggle adding a ``Signed-off-by`` or
  ``Link:`` trailer to each commit.

For the merge strategy, ``$EDITOR`` opens with the merge commit
message for you to review and edit. Press ``Ctrl-y`` to confirm, or
``Escape`` to cancel.

After taking, the series status changes to **taken**.

Sending a thank-you note
~~~~~~~~~~~~~~~~~~~~~~~~~~
Open the action menu (``a``) on a taken series and select **Thank**.
B4 composes a thank-you email listing each applied commit with its
hash, and sends it to the submitter and relevant lists.

After sending, the series status changes to **thanked**.

Archiving a completed series
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Once a series is fully handled, open the action menu (``a``) and
select **Archive**. This creates a ``.tar.gz`` backup in
``$XDG_DATA_HOME/b4/review-archived/`` and removes the series from
the tracking list.


AI-assisted review
------------------

.. raw:: html

   <script src="https://asciinema.org/a/802144.js" id="asciicast-802144"
    async data-speed="1.5" data-theme="monokai" data-fit="width"></script>

The review interface can invoke an external AI agent to help you
review patches. The agent runs in a sandboxed environment with
read-only access to the repository and writes its findings into the
review branch. This is entirely optional and requires configuration.

.. note::

   Agent output is meant to assist the maintainer — it is **not** sent
   to the submitter by default. You decide which findings, if any, to
   include in your review.

Configuring the agent
~~~~~~~~~~~~~~~~~~~~~~
Set two keys in your git config::

    [b4]
      review-agent-command = claude --add-dir .git --allowedTools 'Bash(git:*) Read Glob Grep Write(.git/b4-review/**) Edit(.git/b4-review/**)'
      review-agent-prompt-path = .git/agent-reviewer.md

A sample prompt is included in ``misc/agent-reviewer.md`` in the b4
source tree — copy it into your repository and adapt it to your
project's review guidelines.

See :ref:`review_settings` for the full list of supported agents
(Claude Code, Gemini CLI, OpenAI Codex CLI, GitHub Copilot CLI).

Running the agent
~~~~~~~~~~~~~~~~~~
In the review interface, press ``a`` to invoke the agent on the
current series. B4 passes the patch information to the configured
command and waits for it to finish. When the agent completes, b4
integrates its findings into the review branch and displays a summary
(e.g. "Integrated agent review data from 4 file(s)").

Agent comments appear in the diff view as coloured panels, attributed
by the agent's initials (e.g. "CO4" for Claude Opus 4). Use ``.``
and ``,`` to jump between comments. Press ``n`` to view the agent's
per-patch review notes.

Incorporating agent feedback
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Agent comments are private to you by default — toggling email preview
(``e``) shows that no replies will be sent for patches with only agent
comments.

To include an agent finding in your review, press ``c`` to open the
diff editor for that patch. The agent's comments are already present
in the diff; edit them to add your own judgement, rephrase, or remove
findings you disagree with. On save, the comments are re-attributed
to you (your initials) and will be included when you send the review.


Patchwork integration
---------------------

.. raw:: html

   <script src="https://asciinema.org/a/802145.js" id="asciicast-802145"
    async data-speed="1.5" data-theme="monokai" data-fit="width"></script>

If your project uses a Patchwork server, you can browse and track
series directly from the Patchwork listing without leaving the TUI.

.. note::

   Patchwork integration requires the standard patchwork settings
   (:term:`b4.pw-url`, :term:`b4.pw-key`, :term:`b4.pw-project`).
   See :ref:`patchwork_settings` for details.

Browsing series
~~~~~~~~~~~~~~~~
Press ``p`` in the tracking list to switch to the Patchwork browser.
The listing shows series from your Patchwork project with coloured CI
status indicators: green for pass, red for fail or warning, and dim
for pending.

Viewing CI results
~~~~~~~~~~~~~~~~~~~
Press ``c`` on a series to open a detailed view of all CI checks,
grouped by patch. Each entry shows the check context, description, and
a link to the full CI results.

Tracking from Patchwork
~~~~~~~~~~~~~~~~~~~~~~~~
Press ``t`` to track the selected series. B4 fetches it from lore and
adds it to your local tracking database, just as if you had run
``b4 review track`` from the command line. Press ``q`` to return to
the tracking list, where the newly tracked series is ready for review.

Patchwork state synchronisation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When you have write access to the Patchwork instance, b4 automatically
updates the remote series state as you work. For example, starting a
review sets the Patchwork state to "under-review", and taking a series
sets it to "accepted".


Where to go from here
---------------------

* :doc:`/maintainer/review` — full reference for ``b4 review``
  (commands, keybindings, configuration)
* :doc:`/config` — b4 configuration options
* ``b4 review --help`` — command-line help
