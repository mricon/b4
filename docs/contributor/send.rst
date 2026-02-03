send: sending in your work
==========================
B4 supports sending your series either via your own SMTP-compliant mail
server, or via a web submission endpoint.

Upsides of using your own mail server:

* it's part of decentralized infrastructure not dependent on a single
  point of failure
* it adds domain-level attestation to your messages via DKIM signatures
* it avoids the need to rewrite the From: headers in patches, which is
  required for email delivery that originates at a different domain

However, using your own mail server may not always be a valid option:

* your provider may not offer an SMTP-compliant endpoint for sending
  mail; for example it may only provide a webmail/exchange interface
* there may be limits on the number of messages you can send through
  your mail server in a short period of time, which makes it hard to
  send large patch series
* your company mail server may modify the message bodies by adding huge
  legal disclaimers to all outgoing mail

The web submission endpoint helps with such cases, plus offers several
other upsides:

* the endpoint writes all messages to a public-inbox feed and makes them
  immediately available for others to follow and query
* all patches are end-to-end attested with the developer signature
* messages are less likely to get lost or delayed by mail relays

.. note::

   Even if you opt to use the web submission endpoint, you still need a
   valid email account for participating in decentralized development --
   it's required for taking part in discussions and for sending and
   receiving code review feedback.

.. _web_endpoint:

Authenticating with the web submission endpoint
-----------------------------------------------
Before you start, you need to configure your attestation mechanism. If
you already have a PGP key configured for use with git, you can just use
that and skip the next section. If you don't already have a PGP key, you
can create a separate ed25519 key just for web submission purposes.

Creating a new ed25519 key
~~~~~~~~~~~~~~~~~~~~~~~~~~
.. note::

   Creating a new ed25519 key isn't required if you already have a PGP
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
Which web endpoint to use is going to be dependent on the project. For
the Linux kernel and associated tools (like Git, B4, patatt, etc), you
can use the kernel.org endpoint by adding the following to your
``~/.gitconfig``::

    [b4]
      send-endpoint-web = https://lkml.kernel.org/_b4_submit

.. note::

   You can only use the kernel.org endpoint for kernel.org-hosted
   projects. If there are no recognized mailing lists in the to/cc
   headers, the endpoint refuses to accept the submission.

After updating your git configuration file, you can request
authentication, as in the example below::

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
run the verification command by copy-pasting the confirmation string
from the message::

    $ b4 send --web-auth-verify abcd9b34-2ecf-4d25-946a-0631c414227e
    Signing challenge
    Submitting verification to https://lkml.kernel.org/_b4_submit
    ---
    Challenge successfully verified for alice.developer@example.org
    You may now use this endpoint for submitting patches.

You should now be able to send patches via this web submission endpoint.

Changing your attestation key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If you change your attestation key without changing your email address (e.g.
switch from a ``patatt`` generated key to a PGP key or change your PGP keys),
your previous authorization will stop working. Trying to reauthorize will also
result in an error as changing the attestation key is `currently unsupported
<https://lore.kernel.org/tools/4608818.LvFx2qVVIh@radijator/T/#m9aa19999463864341ed8be929f470e5439513256>`_.
Instead, you can change the key selector to something other than ``default``
with the following setting::

    [patatt]
       selector = something

.. note::
   The selector can be anything besides default or any previously used selector.
   For example, you could use the creation date of your PGP key.

Using your own SMTP server
--------------------------
If there is a ``sendemail`` section in your git configuration, B4 tries
to use that by default instead of going via the web endpoint. At this
time, b4 only recognizes a subset of ``sendemail`` options supported by
git itself. The vast majority of servers should only need the following
settings::

    [sendemail]
       smtpServer = smtp.example.org
       smtpServerPort = 465
       smtpEncryption = ssl
       smtpUser = alice.developer@example.org
       smtpPass = [omitted]

You can also set up ``msmtp`` or a similar tool and specify the path to
the ``sendmail``-compliant binary as the value for ``smtpServer``. To
force B4 to use the web endpoint even when a ``sendemail`` option is
present, use the ``--use-web-endpoint`` switch.

Sending your patches
--------------------
Once your web endpoint or SMTP server is configured, you can start
sending your work.

.. note::

  At this time, the endpoint only accepts the series prepared with ``b4
  prep``, but future versions may support sending arbitrary patches
  generated with ``git format-patch``.

Passing pre-flight checks
~~~~~~~~~~~~~~~~~~~~~~~~~

.. versionadded:: v0.14

B4 defines some pre-flight checks that should be passing, or the command
generates a warning:

- ``needs-editing``: there is an "EDITME" string in the patches
  generated, which usually indicates that the cover letter needs to be
  edited with ``b4 prep --edit-cover``
- ``needs-checking``: you need to run ``b4 prep --check`` to make sure
  that there are no common errors in your submission
- ``needs-checking-deps``: your series defines dependencies, and you
  need to run ``b4 prep --check-deps`` to verify that they are valid
  (see :doc:`prep`)
- ``needs-auto-to-cc``: you need to run ``b4 prep --auto-to-cc`` to
  populate the list of addresses that should receive your patch series

If you find that some of these pre-flight checks aren't relevant to you,
you can either turn them all off, or only the ones that you don't like.
To do so, use the ``prep-pre-flight-checks`` configuration option, for
example::

    [b4]
    prep-pre-flight-checks = disable-all

or::

    [b4]
    prep-pre-flight-checks = disable-needs-auto-to-cc, disable-needs-checking

B4 automatically recognizes when your commits have changed and triggers
the pre-flight checks warning when it thinks that you should re-run
them.

Checking things over with ``-o``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Before you send things out, it's a good idea to verify that everything
is looking good by running the send command with ``-o somedir``, e.g.::

    b4 send -o /tmp/presend

This generates the messages and writes them out into the directory
provided, giving you a way to verify that everything is looking as it
should before sending.

Checking things over with ``--reflect``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
One final test you can do before you submit your series is to send
everything to yourself. This is especially useful when using the web
endpoint, because this allows you to see what the messages are going to
look like after being potentially post-processed on the remote end.

When ``--reflect`` is on:

* b4 still populates the To:/Cc: headers with all the addresses, because
  this allows to identify any encoding problems
* b4 **only sends the series to the address in the From: field**
* when using the web endpoint, the messages aren't added to the
  public-inbox feed
* your branch is **not** automatically rerolled to the next revision

Checking things over with ``--preview-to``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. versionadded:: v0.13

Sometimes you want to ask your friend, colleague, boss, or mentor to
give your submission a quick review. You can send them your series using
``--preview-to boss@example.com`` before you send things out to the
actual maintainers.

When ``--preview-to`` is on:

* b4 **only sends to the addresses you specify on the command line**
* your branch is **not** automatically rerolled to the next revision

(NB: the web submission endpoint can't currently be used with this
feature.)

What happens after you send
---------------------------
The following happens after you send your patches:

* b4 automatically creates a detached head containing the commits from
  your sent series and tags it with the contents of the cover letter;
  this creates a historical record of your submission, as well as adds a
  way to easily resend a previously sent series, should you decide to do
  so in the future
* b4 rerolls your series to the next version, so that a ``v1`` of the
  series becomes ``v2``, etc
* b4 automatically edits the cover letter to add changelog entries
  containing a pre-populated link to the just-sent series

Resending your series
~~~~~~~~~~~~~~~~~~~~~
If something went wrong, or if you need to resend the series because
nobody paid attention to it the first time, it's easy to do this with
``--resend vN``. B4 automatically generates the series from the tagged
historical version created during the previous sending attempt and sends
it out.

Command line flags
------------------
``-d, --dry-run``
  Don't send any mail, just output the raw pre-rendered messages.
  Normally, this is a wall of text, so you'd want to use ``-o`` instead.

``-o OUTPUT_DIR, --output-dir OUTPUT_DIR``
  Prepares everything for sending, but writes out the messages into the
  folder specified instead. This is usually a good last step before
  actually sending things out and lets you verify that all patches are
  looking good and all recipients are correctly set.

``--preview-to``
  Sometimes it's useful to send your series for a pre-review to a
  colleague, mentor, boss, etc. Using this option sends out the prepared
  patches to the addresses specified on the command line, but doesn't
  reroll your series, allowing you to send the actual submission at some
  later point.

  .. versionadded:: v0.13

``--reflect``
  Prepares everything for sending, but only emails yourself (the address
  in the ``From:`` header). Useful as a last step to make sure that
  everything is looking good, and especially useful when using the web
  endpoint, because it may rewrite your From: header for DMARC reasons.

  .. versionadded:: v0.11

``--no-trailer-to-cc``
  Tells b4 not to add any addresses found in the cover or patch trailers
  to To: or Cc:. This is usually handy for testing purposes, in case you
  want to send a set of patches to a test address (also see
  ``--reflect``).

``--to``
  Additional email addresses to include into the To: header. Separate
  multiple entries with a comma. You can also set this in the
  configuration file using the :term:`b4.send-series-to` option (see
  :ref:`contributor_settings`).

``--cc``
  Additional email addresses to include into the Cc: header. Separate
  multiple entries with a comma. You can also set this in the
  configuration file using the :term:`b4.send-series-cc` option (see
  :ref:`contributor_settings`).

``--not-me-too``
  Removes your own email address from the recipients.

``--no-sign``
  Don't sign your patches with your configured attestation mechanism.
  Note, that sending via the web submission endpoint requires
  cryptographic signatures at all times, so this is only a valid option
  to use with ``-o`` or when using your own SMTP server. This can be set
  in the configuration using the :term:`b4.send-no-patatt-sign` (see
  :ref:`contributor_settings`).

``--resend V``
  Resend the specified previously sent version.

