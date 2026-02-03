Configuration options
=====================
B4 doesn't have a separate configuration file but uses
`git-config <https://git-scm.com/docs/git-config#_configuration_file>`__ to
retrieve a set of b4-specific settings. This means that you can have three
levels of b4 configuration:

- system-wide, in ``/etc/gitconfig``
- per-user, in ``$HOME/.gitconfig``
- per-repo, in ``somerepo/.git/config``

Since the purpose of b4 is to work with git repositories, this allows
the usual fall-through configuration, with local settings specified in
``.git/config`` overriding the global defaults.

You can also use the command-line switch ``-c/--config`` to override
specific options, for example::

    b4 --config b4.midmask=https://some.host/%s

Per-project defaults
~~~~~~~~~~~~~~~~~~~~
A project may ship their own b4 configuration file with some defaults,
located at the top-level of the git tree. If you're not sure where a
configuration option is coming from, see if there is a ``.b4-config``
file in the repository you're currently using.

Configuration options
---------------------
All settings are under the ``b4`` section. For example, to set the
``b4.midmask`` option, add the following section to the relevant git
config file::

    [b4]
      midmask = https://some.host/%s

Core options
~~~~~~~~~~~~
These options control many of the core features of b4.

.. glossary::
   :sorted:

   :term:`b4.cache-expire`
     B4 caches retrieved threads for 10 minutes. This option allows
     tweaking the time that the cache remains valid. Many commands also
     allow a ``--no-cache`` flag to force b4 to perform remote lookups.

     Default: ``10``

   :term:`b4.linkmask`
     B4 uses this setting to construct the URL in the ``Link:`` trailers.
     If you want a shorter option, you can also use
     ``https://msgid.link/%s``, which is an alias for lore.kernel.org.

     Default: ``https://lore.kernel.org/%s``

   :term:`b4.linktrailermask`
     Overrides the format of the ``Link:`` trailer, in case you want to
     call it something other than "Link". For example, some projects
     use "Message-ID" trailers instead::

         linktrailermask = Message-ID: <%s>

     The ``%s`` is the placeholder for the message-id.

     Default: ``Link: https://lore.kernel.org/%s``

     .. versionadded:: v0.13

     .. versionchanged:: v0.14
        You can now pass the ``-i`` command-line switch instead of ``-l`` to
        automatically insert the ``Message-ID`` trailer.

   :term:`b4.listid-preference`
     Sometimes messages with the same message-id can have different
     contents, because some servers modify message bodies to inject list
     subscription information. B4 attempts to de-duplicate the results
     using the ``List-Id`` header. You may use this parameter to specify
     the order of preference, using comma-separated strings with shell-style
     wildcard globbing.

     Default: ``*.feeds.kernel.org, *.linux.dev,*.kernel.org,*``

   :term:`b4.midmask`
     Specifies the server from where to retrieve the messages specified by
     their message-id.

     Default: ``https://lore.kernel.org/%s``

   :term:`b4.save-maildirs`
     The "mbox" file format is actually several incompatible standards,
     such as "mboxo" vs. "mboxrd". Setting this option can avoid potential
     problems by saving retrieved threads as Maildirs.

     Default: ``no``

   :term:`b4.searchmask`
     B4 uses this setting to query and retrieve threads matching specific
     search terms. For example, it can retrieve trailer updates using the
     series ``change-id`` identifier.

     Default: ``https://lore.kernel.org/all/?x=m&t=1&q=%s``

   :term:`b4.trailer-order`
     This lets you control the order of trailers that get added to your own
     custody section of the commit message. By default, b4 applies these
     trailers in the order received. However, if you want to list trailers
     in a specific order, you can try something like::

         trailer-order = link*,fixes*,acked*,reviewed*,tested*,*

     The "chain of custody" is an important concept in patch-based code
     review process. Each "Signed-off-by" trailer indicates where the
     custody section of previous reviewer ends and the new one starts. Your
     own custody section is always between the previous-to-last
     "Signed-off-by" trailer, if any, and the bottom of the trailer
     section. For example::

         Fixes: abcde (Commit info)
         Suggested-by: Alex Reporter <alex.reporter@example.com>
         Signed-off-by: Betty Developer <betty.developer@example.com>
         Acked-by: Chandra Acker <chandra.acker@example.com>
         Reviewed-by: Debby Reviewer <debby.reviewer@example.com>
         Signed-off-by: Ezri Submaintainer <ezri.submaintainer@example.com>
         Link: https://msgid.link/some@thing.foo
         Tested-by: Finn Tester <finn.tester@example.com>
         Signed-off-by: Your Name <your.name@example.com>

     Your custody section is beneath "Ezri Submaintainer," so the only
     trailers considered for reordering are "Link" and "Tested-by". Your
     own Signed-off-by trailer is always at the bottom of your own custody
     section.

     Default: ``*``

   :term:`b4.trailers-ignore-from`
     A comma-separated list of addresses that b4 should always ignore
     when applying follow-up trailers. This is useful when dealing with
     reports generated by some automated bots. For example::

         trailers-ignore-from = lkp@intel.com, someotherbot@example.org

     Default: ``None``

.. _shazam_settings:

``am`` and ``shazam`` settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
These settings control ``b4 am`` and ``b4 shazam`` behavior.

.. glossary::
   :sorted:

   :term:`b4.am-perpatch-check-cmd`
     The command to use when running ``--check``. The command is run once for each
     patch to check. The patch file to check is piped through stdin. If this
     config is defined multiple times, all commands will be run. If this config is
     not defined and b4 finds ``scripts/checkpatch.pl`` at the top of your git
     tree, it uses the command shown below by default.

     Default: ``./scripts/checkpatch.pl -q --terse --no-summary --mailback``

     .. versionadded:: v0.14

   :term:`b4.shazam-am-flags`
     Additional flags to pass to ``git am`` when applying patches.

     Default: ``None``

   :term:`b4.shazam-merge-flags`
     Additional flags to pass to ``git merge`` when performing a merge with
     ``b4 shazam -M``.

     Default: ``--signoff``

   :term:`b4.shazam-merge-template`
     Path to a template to use when creating a merge commit. Take the following
     as example content for this file:

     .. literalinclude:: ../src/b4/templates/shazam-merge-template.example

     Default: ``None``

.. _attestation_settings:

Attestation settings
~~~~~~~~~~~~~~~~~~~~

.. glossary::
   :sorted:

   :term:`b4.attestation-check-dkim`
     Controls whether to perform DKIM attestation checks.

     Default: ``yes``

   :term:`b4.attestation-dns-resolvers`
     You can specify your own DNS servers if you are on a company network
     and your OS-provided resolvers aren't able to perform domain key
     lookups. For example, to use Google DNS servers::

         attestation-dns-resolvers = 8.8.8.8, 8.8.4.4

     Default: ``None``

     .. versionadded:: v0.14

   :term:`b4.attestation-gnupghome`
     Sets ``GNUPGHOME`` before running PGP attestation checks that rely on
     GnuPG.

     Default: ``None``

   :term:`b4.attestation-policy`
     B4 supports domain-level and end-to-end attestation of patches using
     the `patatt`_ library. There are four different operation modes:

     * ``off``: don't bother checking attestation at all
     * ``softfail``: print green marks when attestation is passing and
       red marks when it's failing
     * ``hardfail``: exit with an error when any attestation checks fail

     Default: ``softfail``

   :term:`b4.attestation-staleness-days`
     Ignore attestation signatures that are more than this many days
     old. This helps avoid a class of attacks when someone re-sends old
     patches that contain known security bugs.

     Default: ``30``

   :term:`b4.gpgbin`
     Full path to a different binary to use for ``gpg``. B4 also checks the
     ``gpg.program`` setting, and uses that value, if found.

     Default: ``None``

   :term:`b4.keyringsrc`
     See `patatt`_ for details on how to configure keyrings. For example,
     you can clone the kernel.org pgp keys repository and use it for
     attestation::

         git clone https://git.kernel.org/pub/scm/docs/kernel/pgpkeys.git

     Then set the following in your ``~/.gitconfig``::

         [b4]
           keyringsrc = ~/path/to/pgpkeys/.keyring

     Default: ``None``

.. _ty_settings:

``ty`` settings
~~~~~~~~~~~~~~~

.. glossary::
   :sorted:

   :term:`b4.email-exclude`
     A list of addresses to always exclude from the message recipients.
     Expects a comma-separated list with shell-style globbing. E.g.::

         email-exclude = *@codeaurora.org, *@obsolete.example.com

     Default: ``None``

   :term:`b4.sendemail-identity`
     The ``sendemail`` identity to use when sending mail directly with b4.
     This setting applies to ``b4 send`` and ``b4 ty``. See `man
     git-send-email <https://git-scm.com/docs/git-send-email>`__ for info about
     sendemail identities.

     Default: ``None``

   :term:`b4.thanks-am-template`
     Full paths to the templates to use when generating thank-you messages
     for contributors. Take the following as example content for this file:

     .. literalinclude:: ../src/b4/templates/thanks-am-template.example

     Default: ``None``

   :term:`b4.thanks-commit-url-mask`
     Used when creating summaries for ``b4 ty``, and can be a value like::

         thanks-commit-url-mask = https://git.kernel.org/username/c/%.12s

     If not set, b4 falls back to using commit hashes.

     .. note::

        See this page for more info on convenient git.kernel.org short URLs:
        https://korg.docs.kernel.org/git-url-shorteners.html

     Default: ``None``

   :term:`b4.thanks-from-email`
     The email to use in the ``From:`` header when sending thank-you notes.
     By default, b4 uses ``user.email``. For example::

         thanks-from-email = thanks-bot@example.com

     Default: ``None``

     .. versionadded:: v0.13

   :term:`b4.thanks-from-name`
     The name to use in the ``From:`` header when sending thank-you notes.
     By default, b4 uses ``user.name``. For example::

         thanks-from-name = Project Foo Thanks Bot

     Default: ``None``

     .. versionadded:: v0.13

   :term:`b4.thanks-pr-template`
     Full paths to the templates to use when generating thank-you messages
     for contributors. Take the following as example content for this file:

     .. literalinclude:: ../src/b4/templates/thanks-pr-template.example

     Default: ``None``

   :term:`b4.thanks-treename`
     Name of the tree to use in the thank-you templates.

     Default: ``None``

   :term:`b4.ty-send-email`
     When set, tells ``b4 ty`` to send email directly instead of writing
     out ``.thanks`` files.

     Default: ``no``

     .. versionadded:: v0.11

.. _patchwork_settings:

Patchwork integration settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If your project uses a patchwork server, setting these allows you to
integrate your b4 workflow with patchwork.

.. glossary::
   :sorted:

   :term:`b4.pw-accept-state`
     Enabling this option makes ``b4 ty`` set the status of any applied patches
     to the specified state. For example::

         pw-accept-state = accepted

     Default: ``None``

   :term:`b4.pw-discard-state`
     Enabling this option makes ``b4 ty -d`` set the status of any matching
     patches to the specified state. For example::

         pw-discard-state = rejected

     Default: ``None``

   :term:`b4.pw-key`
     The API key from your user profile to use when authenticating with the
     patchwork server.

     Default: ``None``

   :term:`b4.pw-project`
     The name of the patchwork project, exactly as seen in the URL
     sub-path. For example::

         pw-project = linux-usb

     Default: ``None``

   :term:`b4.pw-review-state`
     Enabling this option makes ``b4 am`` or ``b4 shazam`` automatically set
     the review status of the retrieved patches. For example::

         pw-review-state = under-review

     Default: ``None``

   :term:`b4.pw-url`
     The URL of your patchwork server. Note, that this should point at the
     top-level of your patchwork installation and **not** at the project patch
     listing. For example::

         pw-url = https://patchwork.kernel.org/

     Default: ``None``

.. _contributor_settings:

Contributor-oriented settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. glossary::
   :sorted:

   :term:`b4.prep-cover-strategy`
     Alternative cover letter storage strategy to use, in case you don't
     want to use the default ``commit`` strategy. See
     :ref:`prep_cover_strategies`.

     Default: ``commit``

   :term:`b4.prep-cover-template`
     Path to the template to use for the cover letter. The template supports the
     following tokens:

     * ``${cover}``: the content of the cover letter itself
     * ``${shortlog}``: the ``git shortlog`` output for the series
     * ``${diffstat}``: the ``git diff --stat`` output for the series
     * ``${range_diff}``: the ``git range-diff`` output against the previous revision of the series
     * ``${base_commit}``: the base commit of the series
     * ``${change_id}``: the change-id of the series
     * ``${signature}``: your signature, either from ``~/.signature`` if found, or from your Git config

     Default: ``None``

   :term:`b4.prep-perpatch-check-cmd`
     The command to use when running ``--check``. The command is run once for each
     patch to check. The patch file to check is piped through stdin. If this
     config is defined multiple times, all commands will be run. If this config is
     not defined and b4 finds ``scripts/checkpatch.pl`` at the top of your git
     tree, it uses the command shown below by default.

     Default: ``./scripts/checkpatch.pl -q --terse --no-summary --mailback --showfile``

     .. versionadded:: v0.14

   :term:`b4.prep-pre-flight-checks`
     You can use this to turn off some or all pre-flight checks that b4 runs
     prior to sending out patches. To cancel all checks::

         [b4]
         prep-pre-flight-checks = disable-all

     To turn off specific checks, list each one of them, separated by
     comma::

         [b4]
         prep-pre-flight-checks = disable-needs-auto-to-cc, needs-checking

     .. versionadded:: v0.14

   :term:`b4.send-auto-cc-cmd`
     The command to use for obtaining the list of "Cc:" recipients. The command is
     run once for each patch in the series. Each patch file is piped through
     stdin. If b4 finds ``scripts/get_maintainer.pl`` at the top of your git tree,
     it uses the command shown below by default.

     Default: ``scripts/get_maintainer.pl --nogit --nogit-fallback --nogit-chief-penguins --norolestats --nom``

   :term:`b4.send-auto-to-cmd`
     The command to use for obtaining the list of "To:" recipients. The command is
     run once for each patch in the series. Each patch file is piped through
     stdin. If b4 finds ``scripts/get_maintainer.pl`` at the top of your git tree,
     it uses the command shown below by default.

     Default: ``scripts/get_maintainer.pl --nogit --nogit-fallback --nogit-chief-penguins --norolestats --nol``

   :term:`b4.send-endpoint-web`
     The web submission endpoint to use. See :ref:`web_endpoint`.

     Default: ``None``

   :term:`b4.send-no-patatt-sign`
     Instructs b4 not to sign patches with patatt before sending them. Note, that
     using the web submission endpoint requires using signed patches.

     Default: ``no``

   :term:`b4.send-prefixes`
     Extra prefixes to add to ``[PATCH]`` (e.g. ``RFC mydrv``).

     This setting can be replaced for a series with ``b4 prep --set-prefixes``.

     Default: ``None``

     .. versionadded:: v0.11

   :term:`b4.send-same-thread`
     When sending a new version of a series, send it in the same thread as
     the previous version. The config supports the following values:

     * ``yes``, ``true``, ``y``: B4 sends the first message of the new series as a
       reply to the previous version's cover letter.
     * ``shallow``: B4 sends the first message of the new series as a reply to the
       first version's cover letter.
     * ``no``: B4 does not send the new version of the series in the same thread
       as any previous version.

     Default: ``no``

     .. versionadded:: v0.13

     .. versionchanged:: v0.15
        Added ``shallow`` config value.

   :term:`b4.send-series-cc`
     A comma-separated list of addresses to always add to the "Cc:" header.
     See :ref:`prep_recipients`.

     Default: ``None``

   :term:`b4.send-series-to`
     A comma-separated list of addresses to always add to the "To:" header.
     See :ref:`prep_recipients`.

     Default: ``None``

To document
-----------

.. glossary::
   :sorted:

   :term:`b4.gh-api-key`
     Deliberately undocumented because the feature is incomplete and poorly
     tested.

.. _`patatt`: https://pypi.org/project/patatt/
