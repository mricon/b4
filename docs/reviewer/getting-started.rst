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

   <script src="https://asciinema.org/a/850261.js" id="asciicast-850261"
    async data-speed="1.5" data-theme="monokai" data-fit="width"></script>

Before you can use the review TUI, you need to enroll your repository.
Run this once per checkout::

    b4 review enroll

This creates a SQLite tracking database in
``$XDG_DATA_HOME/b4/review/`` and metadata under ``.git/b4-review/``.
If you manage several subsystems from separate checkouts of the same
repository, use ``-i`` to give each one a distinct identifier::

    b4 review enroll -i my-subsystem

Once enrolled, launch the TUI::

    b4 review tui

.. tip::

   By default, the TUI captures mouse events for scrolling and
   clicking. This prevents your terminal from handling text selection
   and copy/paste normally. If you prefer to select and copy text
   with the mouse, launch with ``--no-mouse``::

       b4 review tui --no-mouse

   To make this permanent, set it in your git config::

       git config --global b4.review-no-mouse true

The tracking list starts empty. To add a series, run
``b4 review track`` from another terminal (it works even while the TUI
is running)::

    b4 review track <msgid-or-lore-url>

You can also pipe a message from your mail client. For example, you can
configure mutt to track a series when you press "8"::

    macro index 8 "<pipe-message>b4 review track<return>"

B4 fetches the series from lore, discovers all available revisions
(older and newer), and stores everything in the tracking database.
The TUI updates automatically to show the newly added series.

**Quick actions in the tracking list:**

- ``e`` — view the email thread in a lightweight reader
- ``u`` — update: fetch latest trailers, check for newer revisions,
  and refresh message counts
- ``a`` — open the action menu (context-sensitive)
- ``q`` — quit

If you are no longer interested in a series, press ``a`` and select
**Abandon** to remove it from the tracking list.


Reviewing a series
------------------

.. raw:: html

   <script src="https://asciinema.org/a/850549.js" id="asciicast-850549"
    async data-speed="1.5" data-theme="monokai" data-fit="width"></script>

Select a series in the tracking list and press ``r`` to start
reviewing. B4 fetches the thread, checks attestation on all messages,
and creates a review branch (``b4/review/<change-id>``). The review
interface opens in a split-pane view: the patch list on the left, the
diff for the selected patch on the right.

Navigate between patches with ``[`` and ``]``, scroll with ``j``/``k``,
and page with ``Space``/``Backspace``. The status bar at the bottom
shows the available keybindings at all times.

Viewing follow-up comments
~~~~~~~~~~~~~~~~~~~~~~~~~~
Press ``f`` to fetch follow-up messages from lore. These are inline
review comments and trailers left by other reviewers. Once loaded,
they appear as coloured panels in the diff view, attributed by
reviewer name.

Follow-up trailers (such as ``Reviewed-by`` or ``Tested-by`` from other
reviewers) are shown in a green bar above the diff, so you can quickly
see who has already reviewed each patch.

Use ``.`` and ``,`` to jump between comments in the current patch.

AI agent notes
~~~~~~~~~~~~~~
If you have run an AI agent review on the series (see
:ref:`ai_assisted_review` below), agent comments also appear as
coloured panels in the diff view. Press ``n`` to view the agent's
per-patch review notes, or ``N`` to view the full note in a scrollable
modal.


Adding comments and previewing emails
--------------------------------------

.. raw:: html

   <script src="https://asciinema.org/a/850602.js" id="asciicast-850602"
    async data-speed="1.5" data-theme="monokai" data-fit="width"></script>

Adding inline comments
~~~~~~~~~~~~~~~~~~~~~~
Press ``r`` on a patch to compose a reply in ``$EDITOR``. The editor
opens with the full diff quoted (``> `` prefix), along with any
external comments from other reviewers (``| `` prefix) and agent
comments. Write your comments on blank lines directly below the diff
line you want to comment on. You can trim quoted content you are not
interested in — b4 will match your comments to the right location.

.. tip::

   If an AI agent has already left a useful comment, you can edit it
   in-place to make it your own. On save, the comment is re-attributed
   to you and will be included in your review email.

Adding trailers
~~~~~~~~~~~~~~~
Press ``t`` to add a code-review trailer to the current patch. A
pop-up lets you select the trailer type — Reviewed-by, Acked-by,
Tested-by, etc. The trailer is recorded in the review branch and will
be included when you send the review.

Previewing outgoing email
~~~~~~~~~~~~~~~~~~~~~~~~~
Press ``e`` to toggle email preview mode. The right pane switches to
show the exact email that will be sent for each patch, including your
trailers and inline comments formatted as quoted replies. Navigate
between patches with ``[`` and ``]`` to inspect each outgoing message.

B4 automatically trims quoted context and leaves only your own comments
in the outgoing email, saving you the effort of manually cleaning up
the reply.

Sending the review
~~~~~~~~~~~~~~~~~~
When you are satisfied, press ``S`` (capital S) to send. B4 composes
proper ``In-Reply-To`` / ``References`` headers so your review appears
in the correct thread on the mailing list.

.. tip::

   Use ``--email-dry-run`` when launching the TUI to see exactly what
   would be sent without delivering any email::

       b4 review tui --email-dry-run

   To skip patatt signing (for example, if you do not have a key
   configured), add ``--no-sign``::

       b4 review tui --no-sign

After sending, the series status changes to **replied**.

Series lifecycle
~~~~~~~~~~~~~~~~
Once you have reviewed a series:

- **Waiting** — if your review requested changes, open the action menu
  (``a``) and select **Mark as waiting on new revision**. The series
  moves to a lower-priority group. When you press ``u`` to update, b4
  checks lore for newer revisions and brings the series back to active
  status.
- **Snooze** — to defer a series until a specific date, duration, or
  git tag, select **Snooze** from the action menu. See
  :ref:`snooze_details` in the reference for full details.
- **Range-diff** — press ``d`` in the tracking list to compare two
  revisions of the series side-by-side.


Taking a series and sending thank-yous
---------------------------------------

.. raw:: html

   <script src="https://asciinema.org/a/850603.js" id="asciicast-850603"
    async data-speed="1.5" data-theme="monokai" data-fit="width"></script>

Applying patches (take)
~~~~~~~~~~~~~~~~~~~~~~~~
When you are ready to accept a series, open the action menu (``a``)
and select **Take**. B4 presents a dialog where you choose:

* **Merge strategy** — merge (creates a merge commit using the cover
  letter as the message template), linear (``git am``), or cherry-pick
  (select individual patches).
* **Target branch** — recently used branches are suggested, with the
  configured :term:`b4.review-target-branch` always included. You can
  also type a branch name directly.
* **Optional trailers** — toggle adding a ``Signed-off-by`` or
  ``Link:`` trailer to each commit.
* **Mark as accepted** — update the series status after applying.

After taking, the series status changes to **accepted**.

Sending a thank-you note
~~~~~~~~~~~~~~~~~~~~~~~~~~
Open the action menu (``a``) on an accepted series and select
**Thank**. B4 composes a thank-you email listing each applied commit
with its hash, and sends it to the submitter and relevant lists.

You can send the thank-you right away with ``S``, or press ``W`` to
queue it — the message will be held until the specified git ref becomes
publicly available, ensuring the commit hashes in the thank-you are
reachable before anyone receives the email.

After sending (or queuing), the series status changes to **thanked**.

Archiving a completed series
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Once a series is fully handled, open the action menu (``a``) and
select **Archive**. This creates a ``.tar.gz`` backup in
``$XDG_DATA_HOME/b4/review-archived/`` and removes the series from
the tracking list.


.. _ai_assisted_review:

AI-assisted review
------------------

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
      review-agent-command = claude --add-dir .git --allowedTools 'Bash(git:*) Read Glob Grep Write(.git/b4-review/**) Edit(.git/b4-review/**)' --
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
by the agent's name. Use ``.`` and ``,`` to jump between comments.
Press ``n`` to view the agent's per-patch review notes.

Incorporating agent feedback
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Agent comments are private to you by default — toggling email preview
(``e``) shows that no replies will be sent for patches with only agent
comments.

To include an agent finding in your review, press ``r`` to open the
reply editor for that patch. The agent's comments are already present;
edit them to add your own judgement, rephrase, or remove findings you
disagree with. On save, the comments are re-attributed to you and will
be included when you send the review.


Patchwork integration
---------------------

.. raw:: html

   <script src="https://asciinema.org/a/850545.js" id="asciicast-850545"
    async data-speed="1.5" data-theme="monokai" data-fit="width"></script>

If your project uses a Patchwork server, b4 automatically enables
Patchwork integration when it detects the relevant configuration.

.. note::

   Patchwork integration requires the standard patchwork settings
   (:term:`b4.pw-url`, :term:`b4.pw-key`, :term:`b4.pw-project`).
   See :ref:`patchwork_settings` for details.

Browsing series
~~~~~~~~~~~~~~~~
Press ``p`` in the tracking list to switch to the Patchwork browser.
The listing shows series from your Patchwork project with coloured CI
status indicators.

Tracking from Patchwork
~~~~~~~~~~~~~~~~~~~~~~~~
If you see a series worth reviewing, press ``t`` to track it. B4
fetches the series from lore and adds it to your local tracking
database. Press ``q`` to return to the tracking list, where the newly
tracked series is ready for review.

You can also view the email thread directly from the Patchwork browser
using the lightweight thread viewer, without having to track the series
first.

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
