Release notes
=============

.. _release-0.15.2:

v0.15.2
-------

Bug fixes for the review TUI and mbox parsing, plus a new visual
indicator for unchanged patches during series upgrades.

Review TUI fixes
~~~~~~~~~~~~~~~~

- **Unchanged-patch visual cue** — when upgrading a series to a newer
  revision, patches whose content is identical between revisions now
  display a ``≡`` marker and are rendered dim in the patch list, giving
  the maintainer an at-a-glance signal to focus on patches that actually
  changed.  The ``≡`` state is automatically superseded by any review
  action (adding a trailer, reply, or comment).
- **Prevent double-sending of carried-over reviews** — after a
  successful send, each review is stamped with a ``sent-revision``
  field so ``collect_review_emails()`` skips reviews that have already
  been sent for a previous revision.
- **Crash fix: stored message-id pointing to wrong version thread** —
  after upgrading a series, the stored message-id could still reference
  the old version's thread, causing a ``LookupError``.  B4 now retries
  with ``get_extra_series()`` to discover the correct version.
- **Crash fix: IndexError when toggling followups** — a race between
  Textual's ``ListView.clear()`` and DOM removal could leave the cursor
  past the end of the list.  Fixed by tracking the new-item count
  directly and deferring index restoration.
- **Crash fix: modal screen blocking _refresh_list** — the background
  rescan finishing while a modal screen was active caused a
  ``NoMatches`` crash.  Added guards to return early when the default
  screen's widgets are unreachable.
- **Replies to additional patches no longer treated as inline reviews**
  — when a follow-up message contains its own diff, replies to it are
  no longer injected as code reviews on the wrong patch.
- **Range-diff finds previous series revision** — pressing ``d``
  previously passed the current revision's blob SHA when fetching the
  older one, causing a version mismatch.
- **Upgrade branches no longer pollute tracking DB** — temporary
  upgrade branches now use a ``_tmp-`` prefix and are skipped during
  rescan, preventing ghost entries with garbled change-ids.
- **Per-series error details after update-all** — the "Update all"
  action now reports which series failed and why, instead of only
  showing a total error count.

Mbox parsing fix
~~~~~~~~~~~~~~~~

- **Free-form replies no longer split on** ``---`` — reply messages
  that use ``---`` as a visual separator (e.g. AI-assisted reviews) no
  longer have their body content silently discarded.  The ``---``/diff
  split is now only applied to messages that contain actual diff content.

Thanks
~~~~~~

Thanks to the following people for reporting bugs and testing:

- Mark Brown
- Miroslav Benes


.. _release-0.15.1:

v0.15.1
-------

Bug fixes for the review TUI and documentation corrections.

- **Patch list scrolling** — the patch list in the review TUI now
  scrolls properly on large series instead of expanding beyond its
  container.  Keyboard navigation keeps the selected patch visible.
  (Reported by Chris Samuel)
- **CI results list scrolling** — the check results matrix no longer
  resets to the top on every re-render, so keyboard navigation works
  correctly.  (Reported by Chris Samuel)
- **TUI tests outside a git repository** — tests no longer fail when
  run from a release tarball with no ``.git`` directory.
  (Reported by Jiri Slaby)
- **Documentation** — fixed incorrect ``b4 dig`` examples in the v0.15
  release notes.

Thanks
~~~~~~

Thanks to the following people for reporting bugs:

- Chris Samuel
- Jiri Slaby


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
cover letter or applying trailers via ``git-filter-repo``):

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

