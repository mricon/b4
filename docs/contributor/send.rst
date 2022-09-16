send: sending in your work
==========================
B4 supports sending your series either via your own SMTP server, or via
a web submission endpoint.

Upsides of using your own SMTP server:

* it is part of decentralized infrastructure not dependent on a single
  point of failure
* it adds domain-level attestation to your messages via DKIM signatures
* it avoids the need to munge the From: headers in patches, which is
  required for email delivery that originates at a different domain

However, using your own SMTP server may not always be a valid option:

* your mail provider may not offer an SMTP compliant server for sending
  mail (e.g. if it only uses a webmail/exchange client)
* there may be limits on the number of messages you can send through
  your SMTP server in a short period of time (which is normal for large
  patch series)
* your company SMTP server may modify the message bodies by adding huge
  legal disclaimers to all outgoing mail

The web submission endpoint helps with such cases, plus offers several
other upsides:

* the messages are written to a public-inbox feed, which is then
  immediately available for others to follow and query
* all patches are end-to-end attested with the developer signature
* messages are less likely to get lost or delayed

.. note::

   Even if you opt to use the web submission endpoint, you still need a
   valid email account for participating in decentralized development --
   you will need it to take part in discussions and for sending and
   receiving code review feedback.

.. _web_endpoint:

Authenticating with the web submission endpoint
-----------------------------------------------
Before you start, you will need to configure your attestation mechanism.
If you already have a PGP key configured for use with git, you can just
use that and skip the next section. If you don't already have a PGP key,
you can create a separate ed25519 key just for web submission purposes.

Creating a new ed25519 key
~~~~~~~~~~~~~~~~~~~~~~~~~~
.. note::

   Creating a new ed25519 key is not required if you already have a PGP
   key configured with git using the ``user.signingKey`` git-config
   setting.

Installing b4 should have already pulled in the patatt patch attestation
library. You can use the command line tool to create your ed25519 key::

    $ patatt genkey
    Generating a new ed25519 keypair
    Wrote: /home/user/.local/share/patatt/private/20220915.key
    Wrote: /home/user/.local/share/patatt/public/20220915.pub
    Wrote: /home/user/.local/share/patatt/public/ed25519/example.org/alice.developer/20220915
    Add the following to your .git/config (or global ~/.gitconfig):
    ---
    [patatt]
        signingkey = ed25519:20220915
        selector = 20220915
    ---
    Next, communicate the contents of the following file to the
    repository keyring maintainers for inclusion into the project:
    /home/user/.local/share/patatt/public/20220915.pub

Copy the ``[patatt]`` section and add it to your ``~/.gitconfig`` or to
your ``.git/config`` in the repository that you want to enable for ``b4
send``.

Configuring the web endpoint
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The web endpoint you will use is going to be dependent on the project.
For the Linux kernel and associated tools (like Git, B4, patatt, etc),
the kernel.org endpoint can be enabled by adding the following to your
``~/.gitconfig``::

    [b4]
      send-endpoint-web = https://lkml.kernel.org/_b4_submit

.. note::

   The kernel.org endpoint can only be used for kernel.org-hosted
   projects. If there are no recognized mailing lists in the to/cc
   headers, then the submission will be rejected.

Once that is added, you can request authentication, as in the example
below::

    $ b4 send --web-auth-new
    Will submit a new email authorization request to:
      Endpoint: https://lkml.kernel.org/_b4_submit
          Name: Alice Developer
      Identity: alice.developer@example.org
      Selector: 20220915
        Pubkey: ed25519:ABCDE1lNXHvHOTuHV+Cf1eK9SuRNZZYrQmcJ44IkE8Q=
    ---
    Press Enter to confirm or Ctrl-C to abort
    Submitting new auth request to https://lkml.kernel.org/_b4_submit
    ---
    Challenge generated and sent to alice.developer@example.org
    Once you receive it, run b4 send --web-auth-verify [challenge-string]

As the instructions say, you should receive a verification email to the
address you specified in your ``user.email``. Once you have received it,
run the verification command by copy-pasting the UUID from the
confirmation message::

    $ b4 send --web-auth-verify abcd9b34-2ecf-4d25-946a-0631c414227e
    Signing challenge
    Submitting verification to https://lkml.kernel.org/_b4_submit
    ---
    Challenge successfully verified for alice.developer@example.org
    You may now use this endpoint for submitting patches.

You should now be able to send patches via this web submission endpoint.

Using your own SMTP server
--------------------------
B4 will use the ``sendemail`` section from your git configuration, but
it only supports the most common subset of options. The vast majority of
servers will only need the following settings::

    [sendemail]
       smtpServer = smtp.example.org
       smtpPort = 465
       smtpEncryption = ssl
       smtpUser = alice.developer@example.org
       smtpPass = [omitted]

You can also set up msmtp or a similar tool and specify the path to the
``sendmail``-compliant binary as the value for ``smtpServer``.

Sending your patches
--------------------
Once your web endpoint or SMTP server are configured, you can start
sending your work.

.. note::

  At this time, only series prepared with ``b4 prep`` are supported, but
  future versions may support sending arbitrary patches generated with
  ``git format-patch``.

Checking things over with ``-o``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
It is a good idea to first check that everything is looking good by
running the send command with ``-o somedir``, e.g.::

    b4 send -o /tmp/presend

This will write out the messages just as they would be sent out, giving
you a way to check that everything is looking as it should.

Please check the command flag summary below to see what other flags are
available.

What happens after you send
---------------------------
The following happens after you send your patches:

* b4 will automatically create a detached head containing the commits
  from your sent series and tag it with the contents of the cover
  letter; this creates a historical record of your submission, as well
  as adds a way to easily resend a previously sent series
* b4 will reroll your series to the next version, so that if you just
  sent off a ``v1`` of the series, the working version will be marked as
  ``v2``
* b4 will automatically edit the cover letter to add templated changelog
  entries containing a pre-populated link to the just-sent series

Resending your series
~~~~~~~~~~~~~~~~~~~~~
If something went wrong, or if you need to resend the series because
nobody paid attention to it the first time, it is easy to do this with
``--resend vN``. B4 will automatically generate the series from the
tagged historical version created during the previous sending attempt.

Command line flags
------------------
``-d, --dry-run``
  Don't send any mail, just output the raw messages that would be sent.
  Normally, this is a wall of text, so you'd want to use ``-o`` instead.

``-o OUTPUT_DIR, --output-dir OUTPUT_DIR``
  Prepares everything for sending, but writes out the messages into the
  folder specified instead. This is usually a good last check before
  actually sending things out and lets you verify that all patches are
  looking good and all recipients are correctly set.

``--prefixes PREFIXES [PREFIXES ...]``
  If you want to mark your patch as ``RFC``, ``WIP``, or add any
  other subsystem identifiers, you can pass them as parameters. Do
  **not** add ``PATCH`` or ``v1`` here, as they will already be
  automatically added to the series.

``--no-trailer-to-cc``
  Do not add any addresses found in the cover or patch trailers to To:
  or Cc:. This is usually handy for testing purposes, in case you want
  to send a set of patches to yourself. 

``--hide-cover-to-cc``
  It is common for the ``To:`` and ``Cc:`` sections in cover letters to
  be pretty large on large patch sets. Passing this flag will remove
  these trailers from the cover letter, but still add the addresses to
  the corresponding To: and Cc: headers. This can be made permanent in
  the configuration file using the ``b4.send-hide-cover-to-cc`` option
  (see :ref:`contributor_settings`).

``--to``
  Add any more email addresses to include into the To: header here
  (comma-separated). Can be set in the configuration file using the
  ``b4.send-series-to`` option (see :ref:`contributor_settings`).

``--cc``
  Add any more email addresses to include into the Cc: header here
  (comma-separated). Can be set in the configuration file using the
  ``b4.send-series-cc`` option (see :ref:`contributor_settings`).

``--not-me-too``
  Removes your own email address from the recipients.

``--no-sign``
  Don't sign your patches with your configured attestation mechanism.
  Note, that patch signing is required for the web submission endpoint,
  so this is only a valid option to use with ``-o`` or when using your
  own SMTP server. This can be set in the configuration using the
  ``b4.send-no-patatt-sign`` (see :ref:`contributor_settings`).

``--resend V``
  Resend a previously sent version (see above for more info).

