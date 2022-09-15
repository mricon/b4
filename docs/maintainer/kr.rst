kr: working with contributor keys
=================================
This subcommand allows maintaining a local keyring of contributor keys.

.. note::

  This functionality is under active development and the set of
  available features will be expanded in the near future.

Patatt keyrings
---------------
B4 uses the patatt patch attestation library for its purposes, and it
uses patatt-style keyrings. You can read more information about managing
patatt keyrings at the following page:

* https://pypi.org/project/patatt/#getting-started-as-a-project-maintainer

b4 kr --show-keys
-----------------
At this stage, b4 has limited support for keyring management, but there
are plans to expand this functionality in one of the future versions. At
most, you can view what keys were used to sign a set of patches in a
thread, e.g.::

    $ b4 kr --show-keys <msgid>
    Grabbing thread from lore.kernel.org/all/<msgid>/t.mbox.gz
    ---
    alice.developer@example.org: (unknown)
        keytype: ed25519
         pubkey: AbCdzUj91asvincQGOFx6+ZF5AoUuP9GdOtQChs7Mm0=
         krpath: ed25519/example.org/alice.developer/20211009
       fullpath: /home/user/.local/share/b4/keyring/ed25519/example.org/alice.developer/20211009
    ---
    For ed25519 keys:
        echo [pubkey] > [fullpath]

At this time, if you want to store this public key in your local
keyring, you can run the command suggested above::

    echo AbCdzUj91asvincQGOFx6+ZF5AoUuP9GdOtQChs7Mm0= > \
        /home/user/.local/share/b4/keyring/ed25519/example.org/alice.developer/20211009

Now if you come across a signed set of patches from alice.developer, you
should be able to view the attestation status in the ``b4 am`` output.

