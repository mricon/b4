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

Additionally, you can set and override configuration options on the command-line
using the ``--config`` (or ``-c``) option, for example::

    b4 --config b4.midmask=https://some.host/%s

Per-project defaults
~~~~~~~~~~~~~~~~~~~~
.. note::

   This feature is new in v0.10.

A project may ship their own b4 config with some defaults, placed in the
toplevel of the git tree. If you're not sure where a configuration
option is coming from, check if there is a ``.b4-config`` file in the
repository you're currently using.

Configuration options
---------------------
All settings are under the ``b4`` section. E.g to set a ``b4.midmask``
option, you can just edit your ``~/.gitconfig`` or ``.git/config`` file
and add the following section::

    [b4]
      midmask = https://some.host/%s

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

``b4.searchmask`` (v0.9+)
  If the public-inbox server provides a global searchable index (usually
  in ``/all/``, this setting can be used to query and retrieve matching
  discussion threads based on specific search terms -- for example, to
  retrieve trailer updates using a series ``change-id`` identifier.

  Default: ``https://lore.kernel.org/all/?x=m&t=1&q=%s``

``b4.linktrailermask`` (v0.13+)
  This allows overriding the format of the Link: trailer, in case you
  want to call it something other thank "Link". For example, some
  projects require "Message-Id" trailers, so you can make b4 behave the
  way you like by setting::

      linktrailermask = Message-Id: <%s>

  The ``%s`` will be replaced by the message-id.

  Default: ``Link: https://lore.kernel.org/%s``

``b4.listid-preference`` (v0.8+)
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

  Note: versions prior to v0.10 did not properly respect the chain of
  custody.

  Default: ``*``

``b4.trailers-ignore-from`` (v0.10+)
  A comma-separated list of addresses that should never be considered
  for follow-up trailers. This is useful when dealing with reports
  generated by automated bots that may insert trailer suggestions, such
  as the "kernel test robot." E.g.::

      [b4]
        trailers-ignore-from = lkp@intel.com, someotherbot@example.org

  Default: ``None``

``b4.cache-expire``
  B4 will cache retrieved threads by default, and this allows tweaking
  the time (in minutes) before cache is invalidated. Many commands also
  allow the ``--no-cache`` flag to force remote lookups.

  Default: ``10``

.. _shazam_settings:

shazam settings
~~~~~~~~~~~~~~~
These settings control how ``b4 shazam`` applies patches to your tree.

``b4.shazam-am-flags`` (v0.9+)
  Additional flags to pass to ``git am`` when applying patches.

  Default: ``None``

``b4.shazam-merge-flags`` (v0.9+)
  Additional flags to pass to ``git merge`` when performing a merge with
  ``b4 shazam -M``

  Default: ``--signoff``

``b4.shazam-merge-template`` (v0.9+)
  Path to a template to use when creating a merge commit. See
  ``shazam-merge-template.example`` for some info on how to tweak one.

  Default: ``None``


Attestation settings
~~~~~~~~~~~~~~~~~~~~

``b4.attestation-policy``
  B4 supports domain-level and end-to-end attestation of patches using
  the `patatt`_ library. There are four different operation modes:

  * ``off``: do not bother checking attestation at all
  * ``check``: print green checkmarks when attestation is passing, but
    nothing if attestation is failing (**DEPRECATED**, use ``softfail``)
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

``b4.thanks-from-name`` (v0.13+)
  An custom from name for sending thanks, eg::

      thanks-from-name = Project Foo Thanks Bot

  Default: ``None`` - falls back to user name.

``b4.thanks-from-email`` (v0.13+)
  An custom from email for sending thanks, eg::

      thanks-from-email = thanks-bot@foo.org

  Default: ``None`` - falls back to user email.

``b4.thanks-treename``
  Name of the tree which can be used in thanks templates.

  Default: ``None``

``b4.email-exclude`` (v0.9+)
  A comma-separated list of shell-style globbing patterns with addresses
  that should always be excluded from the recipient list.

  Default: ``None``

``b4.sendemail-identity`` (v0.8+)
  Sendemail identity to use when sending mail directly from b4 (applies
  to ``b4 send`` and ``b4 ty``). See ``man git-send-email`` for info
  about sendemail identities.

  Default: ``None``

``b4.ty-send-email`` (v0.11+)
  When set to ``yes``, will instruct ``b4 ty`` to send email directly
  instead of generating .thanks files.

  Default: ``no``


.. _patchwork_settings:

Patchwork integration settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If your project uses a patchwork server, these settings allow you to
integrate your b4 workflow with patchwork.

``b4.pw-url`` (v0.10+)
  The URL of your patchwork server. Note, that this should point at the
  toplevel of your patchwork installation and NOT at the project patch
  listing. E.g.: ``https://patchwork.kernel.org/``.

  Default: ``None``

``b4.pw-key`` (v0.10+)
  You should be able to obtain an API key from your patchwork user
  profile. This API key will be used to perform actions on your behalf.

  Default: ``None``

``b4.pw-project`` (v0.10+)
  This should contain the name of your patchwork project, as seen in the
  URL subpath to it (e.g. ``linux-usb``).

  Default: ``None``

``b4.pw-review-state`` (v0.10+)
  When patchwork integration is enabled, every time you run ``b4 am`` or
  ``b4 shazam``, b4 will mark those patches as with this state. E.g.:
  ``under-review``).

  Default: ``None``

``b4.pw-accept-state`` (v0.10+)
  After you run ``b4 ty`` to thank the contributor, b4 will move the
  matching patches into this state. E.g.: ``accepted``.

  Default: ``None``

``b4.pw-discard-state`` (v0.10+)
  If you run ``b4 ty -d`` to delete the tracking information for a patch
  series, it will also be set on the patchwork server with this state.
  E.g.: ``deferred`` (or ``rejected``).

  Default: ``None``

.. _contributor_settings:

Contributor-oriented settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``b4.send-endpoint-web`` (v0.10+)
  The web submission endpoint to use (see :ref:`web_endpoint`).

  Default: ``None``

``b4.send-series-to`` (v0.10+)
  Address or comma-separated addresses to always add to the To: header
  (see :ref:`prep_recipients`).

  Default: ``None``

``b4.send-series-cc`` (v0.10+)
  Address or comma-separated addresses to always add to the Cc: header
  (see :ref:`prep_recipients`).

  Default: ``None``

``b4.send-no-patatt-sign`` (v0.10+)
  Do not sign patches with patatt before sending them (unless using the
  web submission endpoint where signing is required).

  Default: ``no``

``b4.send-auto-to-cmd`` (v0.10+)
  Command to use to generate the list of To: recipients. Has no effect
  if the specified script is not found in the repository.

  Default: ``scripts/get_maintainer.pl --nogit --nogit-fallback --nogit-chief-penguins --norolestats --nol``

``b4.send-auto-cc-cmd`` (v0.10+)
  Command to use to generate the list of Cc: recipients. Has no effect
  if the specified script is not found in the repository.

  Default:: ``scripts/get_maintainer.pl --nogit --nogit-fallback --nogit-chief-penguins --norolestats --nom``

``b4.send-same-thread`` (v0.13+)
  When sending a new version of a series, make it part of the same
  thread as the previous one. The first mail will be sent as a reply
  to the previous version's cover letter.

  Default: ``no``

``b4.prep-cover-strategy`` (v0.10+)
  Alternative cover letter storage strategy to use (see :ref:`prep_cover_strategies`).

  Default: ``commit``

``b4.prep-cover-template`` (v0.10+)
  Path to the template to use for the cover letter.

  Default: ``None``


To document
-----------
``b4.gh-api-key``
  Deliberately undocumented because the feature is incomplete and poorly
  tested.

.. _`patatt`: https://pypi.org/project/patatt/
