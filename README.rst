B4 tools
========
This is a helper utility to work with patches made available via a
public-inbox archive like lore.kernel.org. It is written to make it
easier to participate in a patch-based workflows, like those used in
the Linux kernel development.

The name "b4" was chosen for ease of typing and because B-4 was the
precursor to Lore and Data in the Star Trek universe.

See man/b4.5.rst for more information.

Installing
----------
To install from pypi::

    python3 -m pip install --user b4

Upgrading
---------
If you previously installed from pypi::

    python3 -m pip install --user --upgrade b4

Running from the checkout dir
-----------------------------
If you want to run from the checkout dir without installing the python
package, you can use the included ``b4.sh`` wrapper. You can set it as
an alias in your .bash_profile::

    alias b4="$HOME/path/to/b4/b4.sh"

Setting up a symlink should also be possible.

Patch attestation (EXPERIMENTAL)
--------------------------------
Starting with version 0.6, b4 implements in-header patch attestation,
following the approach proposed here:

https://git.kernel.org/pub/scm/linux/kernel/git/mricon/patch-attestation-poc.git/tree/README.rst

At this time, only PGP mode is implemented, but further work is expected
in future versions of b4.

Attesting your own patches
~~~~~~~~~~~~~~~~~~~~~~~~~~
Patch attestation is done via message headers and stays out of the way
of usual code submission and review workflow. At this time, only
maintainers using b4 to retrieve patches and patch series will benefit
from patch attestation, but everyone is encouraged to submit
cryptographic patch attestation with their work anyway, in hopes that it
becomes a common and widely used procedure.

To start attesting your own patches:

1. Make sure you have b4 version 0.6.0 or above:
   ``b4 --version``
2. If you don't already have a PGP key, you can follow the following
   guide on how to generate it:
   https://www.kernel.org/doc/html/latest/process/maintainer-pgp-guide.html
3. It is strongly recommended to use ed25519 as your signing key
   algorithm, as it will result in much smaller signatures, preventing
   unnecessary email header bloat.
4. Make sure your ``user.email`` and ``user.signingkey`` are set either
   globally, or in the repository you will be using for attestation.
5. Add the ``sendemail-validate`` hook to each repository you want
   enabled for attestation, with the following single line of content as
   the hook body:
   ``b4 attest $1``.

If you are using b4 from git checkout, you can use a symlink instead::

    ln -s path/to/b4/hooks/sendemail-validate-attestation-hook \
        .git/hooks/sendemail-validate

(Note, that there's a second "E" in send*E*mail.)

Next time you run ``git send-email``, b4 will automatically add
attestation headers to all patches before they go out.

Verifying attestation on received patches
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
There are three attestation verification policies in b4:

- check (default)
- softfail
- hardfail

The default "check" policy is look for any available attestation and try
to verify it. If verification fails, b4 will not output any errors, but
will not show verification checkmarks either.

In "softfail" mode, any verification errors will be prominently
displayed, but b4 will still generate the .mbx file with patches.

The "hardfail" mode will show verification errors and exit without
generating the .mbox file with patches.

You can set the preferred policy via the git configuration file::

    [b4]
      attestation-policy = softfail

Using with mutt
~~~~~~~~~~~~~~~
You can show patch attestation data with mutt, using the following
configuration parameters::

    set display_filter="b4 -q attest -m"
    ignore *
    unignore from date subject to cc list-id:
    unignore x-patch-hashes: x-patch-sig:
    unignore attested-by: attestation-failed:

When displaying a message containing in-header PGP attestation
signatures, mutt will display either the "Attested-By" or the
"Attestation-Failed" headers, e.g.::

    Date: Mon, 23 Nov 2020 13:38:50 -0500
    From: Konstantin Ryabitsev <konstantin@linuxfoundation.org>
    To: mricon@kernel.org
    Subject: [PATCH 3/5] Fix in-header attestation code
    Attested-By: Konstantin Ryabitsev <konstantin@linuxfoundation.org> (pgp: B6C41CE35664996C)

or::

    Date: Mon, 23 Nov 2020 13:38:48 -0500
    From: Konstantin Ryabitsev <konstantin@linuxfoundation.org>
    To: mricon@kernel.org
    Subject: [PATCH 1/5] Add not very simple dkim key caching
    Attestation-Failed: signature failed (commit message, patch metadata)


Support
-------
For support or with any other questions, please email
tools@linux.kernel.org, or browse the list archive at
https://linux.kernel.org/g/tools.
