Release notes
=============

.. _release-unreleased:

Unreleased
----------

``b4 bugs`` — bug tracking with git-bug (technology preview)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The new ``b4 bugs`` command integrates with `git-bug`_ to let you track
bug reports alongside your git repository. Bugs are stored as git objects
inside the repo, so they travel with the code and can be shared via
``git push``/``git pull`` without any external service.

.. _`git-bug`: https://github.com/git-bug/git-bug

A full-featured TUI (``b4 bugs tui``) lets you browse, triage, and
update bugs; a lightweight CLI covers scripting and non-interactive use.
Key capabilities:

- **Import from lore** — enter a Message-ID and b4 fetches the full thread,
  uses the oldest message as the bug report, and adds follow-ups as
  comments. Importing the same thread twice is detected and prevented.
- **Lifecycle states** — triage bugs through ``new`` → ``confirmed`` →
  ``fixed`` (and ``needinfo``, ``wontfix``, ``duplicate``, ``worksforme``).
  State is tracked via internal ``lifecycle:`` labels.
- **Comment tombstoning** — remove personal data from a comment while
  preserving the Message-ID, so thread refresh does not re-import it.
- **Label editing** — add and remove arbitrary labels from the TUI or CLI.

``b4 bugs`` is a **technology preview** (alpha): commands, keybindings,
and formats may change between releases. See :doc:`maintainer/bugs` for
the full reference.

``b4 review`` — tracking and review improvements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Several notable improvements to the ``b4 review`` workflow shipped this
cycle, building on the v0.15 foundation.

**Manual revision linking**

When automatic revision discovery fails — for example, a submitter sent
v2 to a different mailing list or without proper in-reply-to threading —
you can now link a revision by hand. Open the action menu (``a``) on a
new or actively reviewed series and select **Link a revision** (``l``).
B4 prompts for a message-id or lore URL, fetches the posting in the
background, and shows a confirmation preview before recording the link.
See :ref:`review_link_revision` for details.

**Partial-series state**

When you cherry-pick only a subset of a series' patches, b4 now sets the
series status to ``partial`` (◐) rather than ``accepted``. The review
branch stays alive, new revisions are ingested as normal, and a **Thank**
action is available so you can acknowledge the patches already applied
without closing the review. When subsequent takes complete coverage, b4
automatically promotes the status to ``accepted``.

**Unchanged-patch marker on revision upgrade**

After upgrading to a new revision, patches whose content did not change
from the previous revision are automatically marked with the ``≡``
(unchanged) indicator in the patch list. This lets you focus your review
on what actually changed between revisions.

**Auto-detection of prior reviewer trailers**

If you already replied to one or more patches in a series with a
``Reviewed-by`` or ``Acked-by`` trailer before tracking it in
``b4 review``, those patches are now detected from the thread and marked
``✓`` Done automatically. Any subsequent action (a new comment, a
``Nacked-by``, or a manual ``x`` skip) takes precedence.

**Network operation cancellation**

Long-running network operations — fetching threads from lore, running
attestation checks, tracking a new series — can now be interrupted at
any time by pressing ``Escape`` or ``q``. B4 exits cleanly from any
cancellation point without leaving dangling state.

**Patchwork backlog gate**

Opening the Patchwork browser against a project with a large number of
outstanding patches no longer hangs. B4 now probes the outstanding patch
count first; if it exceeds 1000, the fetch is automatically restricted
to the last 30 days. A self-dismissing notice informs you when the window
is active, and the title bar shows "· last 30 days" so the absence of
older series does not look like data loss.

``b4 trailers`` — interactive review and fuzzy matching
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two new flags make trailer recovery more controlled.

``b4 trailers -u -i``
  Opens your editor with the list of trailers about to be applied,
  grouped per commit and annotated with their source message. Change a
  leading ``+`` to ``x`` to reject a trailer; the rejection is persisted
  in ``.git/b4-trailers-ignore.json`` and honoured on future runs, even
  after a reroll.

``b4 trailers -u --fuzzy``
  When a commit's patch-id no longer matches what was posted (after a
  rebase or amend), additionally try to match by ``Link:`` message-id
  and then by subject instead of skipping it. Best combined with ``-i``
  so you can review each recovered trailer before it is applied.

See :doc:`contributor/trailers` for details.

``b4 ty`` — interactive review before sending
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``b4 ty -i`` opens your editor with the list of thank-you messages the
auto-thankanator detected, each pre-marked to send. Change a ``+`` to
``x`` to skip an individual entry — it stays pending for the next run.
Editing, adding, removing, or reordering the entry lines aborts the run
without sending anything.

``b4 review track --rethread``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Submitters who send patches without threading (each patch as a separate,
unrelated message) can now be accommodated with ``--rethread``. Pass any
single patch from the series; b4 auto-discovers the rest by searching
lore for other patches from the same author sent within a 1-hour window,
matching by ``[PATCH n/m]`` counters and version. You can also supply
all message-ids explicitly or read them from stdin.

If the submitter also posted a correctly threaded re-send of the same
version, b4 prefers that copy instead of stitching. ``--rethread`` also
records an unthreaded new version of an already-tracked series as a new
revision rather than a duplicate.

Vim and Emacs editor plugins
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``misc/`` directory now includes syntax highlighting and editing
helpers for both Vim and Emacs. Both plugins provide:

- **Diff-aware syntax highlighting** — quoted additions in green,
  removals in red, hunk headers in cyan, external ``|`` comments
  visually bracketed, your own comments in the default foreground, with
  spell checking limited to your comment lines.
- **Hunk trimming** — delete a hunk or all uncommented hunks above the
  cursor, leaving a ``[ ... NN lines skipped ... ]`` breadcrumb so
  recipients can see that context was intentionally omitted. An opt-in
  ``auto_marker`` mode extends this to ordinary delete commands.
- **Adopt-comment** — strip the ``|`` prefix from an external reviewer
  comment (from a follow-up or AI agent) to claim it as your own,
  ready to edit and send.

See :ref:`Editor syntax highlighting <review_editor_plugins>` in the
reference for setup instructions.

New configuration options
~~~~~~~~~~~~~~~~~~~~~~~~~~

``b4.custom-msgid-cmd``
  An optional command whose stdout is used as the ``Message-Id`` for
  review replies, follow-up replies, and ``b4 ty`` thank-you notes.
  Useful for maintainers who rely on a custom message-id scheme and
  whose SMTP path does not run a ``sendemail-validate`` hook. Falls
  back to b4's built-in id on unset, failure, or empty output.

``b4.send-me-too``
  Set to ``no`` to suppress including your own address in the ``Cc``
  when sending patches with ``b4 send``. Defaults to ``yes`` (include
  yourself).

Native history rewriting (replaces ``git-filter-repo``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

b4 no longer depends on ``git-filter-repo`` for the two operations that
rewrite commit history on a prep branch (cover-letter updates and
trailer application via ``b4 trailers -u``). The rewrite is now
implemented natively using ``pygit2``, which b4 already pulls in
through the ``ezgb`` dependency. Existing safety backups continue to
live at ``refs/original/<branch>``.

The migration also fixes a long-standing issue where git notes
attached to rewritten commits were silently orphaned on the old commit
OIDs (upstream ``git-filter-repo`` issue #22). b4 now migrates entries
under any ``refs/notes/*`` ref onto the new commit OIDs after a
rewrite, preserving note message bytes verbatim.

GPG signatures on rewritten commits continue to be stripped, as they
were previously with ``git-filter-repo``. Re-sign from
``refs/original/<branch>`` if needed — for example::

    git rebase --exec 'git commit --amend -S --no-edit' \
        refs/original/<branch>

.. _release-0.15:

v0.15
-----

``b4 review`` — TUI-based patch review workflow (technology preview)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This release introduces ``b4 review``, a new terminal-based workflow
for maintainers who receive, review, and accept patches from mailing
lists. It ships as a **technology preview** (alpha): the
commands, keybindings, configuration options, and on-disk formats may
change in incompatible ways between releases. Bug reports and
feedback are welcome at tools@kernel.org.

.. note::

   The TUI requires the optional ``tui`` dependency group. Install
   with ``pipx install b4[tui]`` or ``uv tool install b4[tui]``.

The workflow is built around a lightweight SQLite tracking database and
per-series review branches. It comprises three cooperating TUI apps:

Tracking TUI (``b4 review tui``)
  Browse and manage tracked series with status indicators, take
  (apply) series using merge, linear, or cherry-pick strategies,
  compare revisions with range-diff, send thank-you messages, and
  archive completed series. The app groups series by lifecycle state
  (active, new, waiting, gone) and sorts by most-recent activity.

Review TUI (``b4 review <branch>``)
  Split-pane interface with a patch list and scrollable diff viewer.
  Add inline comments and code-review trailers, preview outgoing
  emails, invoke an external AI agent for automated review assistance,
  and send review replies — all without leaving the terminal.

Patchwork TUI (``b4 review pw``)
  Browse outstanding series from a Patchwork server, set state and
  archived flags, and track series into the local database for review.

Highlights:

- **Series tracking and lifecycle management** — track series from the
  CLI (``b4 review track <msgid>``), from your mail client, or from
  Patchwork. Series progress through new → reviewing → replied →
  accepted → thanked states.
- **Revision discovery and upgrades** — b4 automatically discovers
  older and newer revisions of a tracked series using change-id and
  in-reply-to chains. Upgrading to a newer revision preserves your
  review state and prior context.
- **Inline commenting** — press ``r`` in the review view to open
  ``$EDITOR`` with the full diff quoted. Write your comments below
  the relevant lines and b4 will format them as proper email replies.
  The diff view shows community follow-up comments from the mailing
  list alongside your own.
- **AI agent integration** — optionally invoke an external AI agent
  (Claude Code, Gemini CLI, OpenAI Codex CLI, or GitHub Copilot CLI)
  to produce a first-pass review. Agent findings remain private to
  you; you decide what, if anything, to include in your reply.
- **Per-patch state machine** — mark individual patches as done (✓),
  skip (✕), or draft (✎) to track your progress through large series.
  B4 automatically excludes skipped patches from cherry-pick
  selection and outgoing emails.
- **Three take strategies** — merge (creates a merge commit from the
  cover letter), linear (``git am``), or cherry-pick (select
  individual patches). B4 adds per-commit ``Signed-off-by`` and
  ``Link`` trailers on request.
- **Snooze** — defer a series until a specific date, duration, or git
  tag. B4 skips snoozed series during bulk updates and automatically
  wakes them when the snooze expires.
- **Cross-machine synchronisation** — push ``b4/review/*`` branches to
  a private remote and ``rescan`` on another machine to rebuild the
  tracking database from branch metadata.
- **Mutt-style thread viewer** — press ``e`` to browse the full email
  thread with tree art, attestation status display, and reply support.
  B4 tracks per-message flags (seen, flagged, answered) across
  sessions.
- **Worktree support** — enrolled repositories work correctly from
  worktrees; a configurable ``review-target-branch`` sets the default
  branch for take operations.
- **Patchwork state synchronisation** — when you have write access to a
  Patchwork instance, b4 automatically updates the remote series state
  as you progress through the review lifecycle.
- **Prior review context** — when upgrading to a new revision, b4
  carries forward your previous review comments and notes so you can
  see what you said last time.
- **Quick-reply** — reply to follow-up messages directly from the
  review TUI or thread viewer without switching to your email client.

See :doc:`reviewer/getting-started` for a walkthrough with
screencasts, and :doc:`maintainer/review` for the full reference.

``b4 dig`` — trace applied commits back to mailing list submissions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The new ``b4 dig`` command searches for the original mailing list
submission of a commit that has already been applied to a git tree.
It matches by patch-id, author, and subject to locate the original
thread on lore.kernel.org.

::

    b4 dig -c <commitish>
    b4 dig -c <commitish> --all-series
    b4 dig -c <commitish> --who
    b4 dig -c <commitish> --save-mbox /tmp/thread.mbx

The ``--all-series`` flag shows all revisions of the series containing
the commit. The ``--who`` flag shows who was originally included on
the thread (To/Cc recipients), and ``--save-mbox`` saves the matched
thread to a local mbox file. See :doc:`maintainer/dig` for details.

``b4 shazam`` — three-way merge and conflict resolution
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``b4 shazam -H`` now performs a three-way merge when applying patches,
which significantly improves the success rate for series that do not
apply cleanly with a simple ``git am``. When conflicts do occur, the
new ``--resolve`` flag drops you into an interactive conflict
resolution session instead of aborting::

    b4 shazam -H --resolve <msgid>

``b4 prep`` — pre/post history-rewrite hooks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two new configuration keys let you run commands before and after b4
rewrites history on a prep branch (for example, when updating the
cover letter or applying trailers):

``b4.prep-pre-rewrite-hook``
  Command to run before the rewrite. A non-zero exit aborts the
  operation, which is useful for tools like StGit that need to commit
  their internal state first.

``b4.prep-post-rewrite-hook``
  Command to run after a successful rewrite. A non-zero exit logs
  a warning but does not undo the rewrite.

Example for StGit users::

    [b4]
        prep-pre-rewrite-hook = stg commit --all
        prep-post-rewrite-hook = stg repair

Other notable changes
~~~~~~~~~~~~~~~~~~~~~

New features and enhancements:

- **XOAUTH2 and bearer-token SMTP authentication** — b4 can now use
  XOAUTH2 or bearer tokens to authenticate to SMTP servers, for
  environments that do not support basic authentication.
- **Presubject support** — set ``b4.send-presubject`` or use
  ``--set-presubject`` to add a prefix before the standard ``[PATCH]``
  subject tag.
- **Send-email aliases** — b4 now reads ``sendemail.aliasesfile`` and
  ``sendemail.aliasfiletype`` to expand aliases in To/Cc fields, the
  same way ``git send-email`` does.
- **Codespell integration** — ``b4 prep --check`` now runs codespell
  as a spellcheck pass when the ``codespell`` tool is installed.
- **Shallow same-thread support** — ``b4.send-same-thread = shallow``
  sends follow-up versions as a reply to the cover letter of the
  previous version rather than the entire thread.
- **Force cover letter for single-patch series** — use
  ``b4 send --force-cover-letter`` to generate a separate cover letter
  even when the series has only one patch.
- **Default Link domain** — the default ``linkmask`` now uses
  ``patch.msgid.link`` instead of ``lore.kernel.org``.
- **Full-index binary diffs** — b4 now creates patches with
  ``--full-index --binary`` for more reliable application.
- **Clean multiple prep branches** — ``b4 prep --cleanup`` now accepts
  multiple branch names at once.
- **Thank-you self-copy** — ``b4 ty --me-too`` sends a copy of the
  thank-you message to yourself.
- **Range-diff arguments** — ``b4 prep --compare-to`` and ``b4 diff``
  now accept ``--range-diff-opts`` to pass additional flags to
  ``git range-diff``.
- **Trailer provenance** — ``b4 trailers`` now shows the message-id
  and source of each trailer it discovers.
- **Pre-flight check improvements** — check output now includes the
  exit code and stderr from check commands for easier debugging.

Thanks
~~~~~~

Thanks to the following people for reporting bugs, suggesting features,
reviewing patches, testing, and contributing code:

- Alexey Minnekhanov
- Andrew Cooper
- Andy Shevchenko
- Christian Heusel
- Conor Dooley
- Dave Marquardt
- Geert Uytterhoeven
- Jonathan Corbet
- Junio C Hamano
- Juri Lelli
- Kevin Hilman
- Krzysztof Kozlowski
- Lee Jones
- Linus Torvalds
- Louis Chauvet
- Luca Ceresoli
- Manos Pitsidianakis
- Marc Kleine-Budde
- Mark Brown
- Matthieu Baerts
- Maxime Ripard
- Michael S. Tsirkin
- Miguel Ojeda
- Nathan Chancellor
- Panagiotis Vasilopoulos
- Ricardo Ribalda
- Rob Herring
- Tamir Duberstein
- Toke Høiland-Jørgensen

