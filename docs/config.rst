Configuration options
=====================
B4 doesn't have a separate configuration file but will use
``git-config`` to retrieve a set of b4-specific settings. This means
that you can have three levels of b4 configuration:

- system-wide, in ``/etc/gitconfig``
- per-user, in ``$HOME/.gitconfig``
- per-repo, in ``somerepo/.git/config``

Since the purpose of b4 is to work with git repositories, this allows
the usual fall-through configuration that can be overridden by more
local settings on the repository level.

.. note:: Per-project defaults

   A project may ship their own b4 config with some defaults, placed in
   the toplevel of the git tree. If you're not sure where a
   configuration option is coming from, check if there is a
   ``.b4-config`` file in the repository you're currently using.

Configuration options
---------------------
All settings are under the ``b4`` section.

Core options
~~~~~~~~~~~~
These options control many of the core features of b4.

``b4.midmask``
  When retrieving threads by message-id, b4 will use ``midmask`` to
  figure out from which server they should be retrieved.

  Default: ``https://lore.kernel.org/%s``

``b4.linkmask``
  When automatically generating ``Link:`` trailers, b4 will use this
  setting to derive the destination URL. If you want a shorter option,
  you can also use ``https://msgid.link/%s``, which is an alias for
  lore.kernel.org.

  Default: ``https://lore.kernel.org/%s``

``b4.searchmask``
  If the public-inbox server provides a global searchable index (usually
  in ``/all/``, this setting can be used to query and retrieve matching
  discussion threads based on specific search terms -- for example, to
  retrieve trailer updates using a series ``change-id`` identifier.

  Default: ``https://lore.kernel.org/all/?x=m&t=1&q=%s``

``b4.listid-preference``
  Messages are frequently sent to multiple distribution lists, and some
  servers may apply content munging to modify the headers or the message
  content. B4 will deduplicate the results and this configuration option
  defines the priority given to the ``List-Id`` header. It is a simple
  comma-separated string with shell-style globbing.

  Default: ``*.feeds.kernel.org, *.linux.dev,*.kernel.org,*``

``b4.save-maildirs``
  The "mbox" file format is actually several incompatible formats
  ("mboxo" vs "mboxrd", for example). If you want to avoid dealing with
  this problem, you can choose to always save retrieved messages as a
  Maildir instead.

  Default: ``no``

``b4.trailer-order``
  This lets you control the order of trailers that get added to your own
  custody section of the commit message. By default, b4 will apply these
  trailers in the order they were received (because this is mostly
  consumed by tooling and the order does not matter). However, if you
  wanted to list things in a specific order, you could try something
  like::

      trailer-order = link*,fixes*,acked*,reviewed*,tested*,*

  The "chain of custody" is an important concept in patch-based code
  review process, with each "Signed-off-by" trailer indicating where the
  custody section of previous reviewer ends and the new one starts. Your
  own custody section is anything between the previous-to-last
  "Signed-off-by" trailer (if any) and the bottom of the trailer
  section. E.g.::

      Fixes: abcde (Commit info)
      Suggested-by: Alex Reporter <alex.reporter@example.com>
      Signed-off-by: Betty Developer <betty.developer@example.com>
      Acked-by: Chandra Acker <chandra.acker@example.com>
      Reviewed-by: Debby Reviewer <debby.reviewer@example.com>
      Signed-off-by: Ezri Submaintainer <ezri.submaintainer@example.com>
      Link: https://msgid.link/some@thing.foo
      Tested-by: Finn Tester <finn.tester@example.com>
      Signed-off-by: Your Name <your.name@example.com>

  Your custody section is beneath "Ezri Submaintainer", so the only
  trailers considered for reordering are "Link" and "Tested-by" (your
  own Signed-off-by trailer is always at the bottom of your own custody
  section).

  Default: ``*``

``b4.cache-expire``
  B4 will cache retrieved threads by default, and this allows tweaking
  the time (in minutes) before cache is invalidated. Many commands also
  allow the ``--no-cache`` flag to force remote lookups.

  Default: ``10``

.. _shazam_settings:

shazam settings
~~~~~~~~~~~~~~~
These settings control how ``b4 shazam`` applies patches to your tree.

``b4.shazam-am-flags``
  Additional flags to pass to ``git am`` when applying patches.

  Default: ``None``

``b4.shazam-merge-flags``
  Additional flags to pass to ``git merge`` when performing a merge with
  ``b4 shazam -M``

  Default: ``--signoff``

``b4.shazam-merge-template``
  Path to a template to use when creating a merge commit. See
  ``shazam-merge-template.example`` for some info on how to tweak one.

  Default: ``None``


Attestation settings
~~~~~~~~~~~~~~~~~~~~
These settings control patch attestation.

``b4.attestation-policy``
  B4 supports domain-level and end-to-end attestation of patches using
  the `patatt`_ library. There are four different operation modes:

  * ``off``: do not bother checking attestation at all
  * ``check``: print green checkmarks when attestation is passing, but
    nothing if attestation is failing (DEPRECATED, use ``softfail``)
  * ``softfail``: print green checkmarks when attestation is passing and
    red x-marks when it is failing
  * ``hardfail``: exit with an error when any attestation checks fail

  Default: ``softfail``

``b4.attestation-checkmarks``
  When reporting attestation results, b4 can output fancy unicode
  checkmarks, or plain old ascii ones:

  * ``fancy``: uses ✓/✗ checkmarks and colours
  * ``plain``: uses x/v checkmarks and no colours

  Default: ``fancy``

``b4.attestation-check-dkim``
  Controls whether to perform DKIM attestation checks.

  Default: ``yes``

``b4.attestation-staleness-days``
  This setting controls how long in the past attestation signatures can
  be made before we stop considering them valid. This helps avoid an
  attack where someone resends valid old patches that contain a known
  vulnerability.

  Default: ``30``

``b4.attestation-gnupghome``
  This allows setting ``GNUPGHOME`` before running PGP attestation
  checks using GnuPG.

  Default: ``None``

``b4.gpgbin``
  If you don't want to use the default ``gpg`` command, you can specify
  a path to a different binary. B4 will also use git's ``gpg.program``
  setting, if found.

  Default: ``None``

``b4.keyringsrc``
  See ``patatt`` for details on how to configure keyring lookups. For
  example, you can clone the kernel.org pgpkeys.git repository and use
  it for attestation without needing to import any keys into your GnuPG
  keyring::

      git clone https://git.kernel.org/pub/scm/docs/kernel/pgpkeys.git

  Then set the following in your ``~/.gitconfig``::

      [b4]
        keyringsrc = ~/path/to/pgpkeys/.keyring

  Default: ``None``

.. _ty_settings:

Thank-you (ty) settings
~~~~~~~~~~~~~~~~~~~~~~~
These settings control the behaviour of ``b4 ty`` command.

``b4.thanks-pr-template``, ``b4.thanks-am-template``
  These settings take a full path to the template to use when generating
  thank-you messages for contributors. See example templates provided
  with the project.

  Default: ``None``


``b4.thanks-commit-url-mask``
  Used when creating summaries for ``b4 ty``, and can be set to a value like::

      thanks-commit-url-mask = https://git.kernel.org/username/c/%.12s

  If not set, b4 will just specify the commit hashes.

  See this page for more info on convenient git.kernel.org shorterners:
  https://korg.docs.kernel.org/git-url-shorteners.html

  Default: ``None``

``b4.email-exclude``
  A comma-separated list of shell-style globbing patterns with addresses
  that should always be excluded from the recipient list.

``b4.sendemail-identity``
  Sendemail identity to use when sending mail directly from b4 (applies
  to ``b4 send`` and ``b4 ty``). See ``man git-send-email`` for info
  about sendemail identities.


.. _patchwork_settings:

Patchwork integration settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If your project uses a patchwork server, these settings allow you to
integrate your b4 workflow with patchwork.

``b4.pw-url``
  The URL of your patchwork server. Note, that this should point at the
  toplevel of your patchwork installation and NOT at the project patch
  listing. E.g.: ``https://patchwork.kernel.org/``.

  Default: ``None``

``b4.pw-key``
  You should be able to obtain an API key from your patchwork user
  profile. This API key will be used to perform actions on your behalf.

  Default: ``None``

``b4.pw-project``
  This should contain the name of your patchwork project, as seen in the
  URL subpath to it (e.g. ``linux-usb``).

  Default: ``None``


``b4.pw-review-state``:
  When patchwork integration is enabled, every time you run ``b4 am`` or
  ``b4 shazam``, b4 will mark those patches as with this state (e.g.
  "under review").

  Default: ``under-review``

``b4.pw-accept-state``:
  After you run ``b4 ty`` to thank the contributor, b4 will move the
  matching patches into this state.

  Default: ``accepted``

``b4.pw-discard-state``
  If you run ``b4 ty -d`` to delete the tracking information for a patch
  series, it will also be set on the patchwork server with this state.

  Default: ``deferred``

.. _contributor_settings:

Contributor-oriented settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``b4.send-endpoint-web``
  The web submission endpoint to use (see :ref:`web_endpoint`).

``b4.send-series-to``
  Address or comma-separated addresses to always add to the To: header
  (see :ref:`prep_recipients`).

``b4.send-series-cc``
  Address or comma-separated addresses to always add to the To: header
  (see :ref:`prep_recipients`).

``b4.send-no-patatt-sign``
  Do not sign patches with patatt before sending them (ignored when
  using the web submission endpoint).

``b4.send-hide-cover-to-cc``
  Always hide To: and Cc: trailers from the cover letter, just include
  them into the corresponding message recipient headers.

``b4.send-auto-to-cmd``
  Alternative command to use to generate the list of To: recipients.

``b4.send-auto-cc-cmd``
  Alternative command to use to generate the list of Cc: recipients.

``b4.prep-cover-strategy``
  Alternative cover letter storage strategy to use (see
  :ref:`prep_cover_strategies`).

``b4.prep-cover-template``
  Path to the template to use for the cover letter.

``b4.gh-api-key``
  Deliberately undocumented because the feature is incomplete and poorly
  tested.

.. _`patatt`: https://pypi.org/project/patatt/
