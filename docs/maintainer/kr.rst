kr: working with contributor keys
=================================
B4 checks patch signatures made with the `patatt`_ library. It can check
a signature with a key from two places:

* **Your keyring**: keys you add yourself (see :term:`b4.keyringsrc`).
  These always win.
* **Trust on first use (TOFU)**: every patatt ed25519 signature carries
  the full public key. When your keyring has no key for the sender, b4
  checks the signature with that key and remembers it.

The ``b4 kr`` subcommands show and manage both.

.. versionadded:: v0.17
   Trust on first use and the ``list``, ``show``, ``accept``,
   ``reject``, ``forget`` and ``promote`` subcommands.

How trust on first use works
----------------------------
* The first key b4 sees for an address is pinned for that address.
* Every new series (each revision counts) signed with the same key
  makes the key more trusted.
* A series signed with a **different** key for the same address gets a
  loud warning. B4 never switches keys on its own: you decide with
  ``b4 kr accept`` or ``b4 kr reject``.
* Only cover letters and patches can pin a key or add to its count.
  Follow-ups (review replies and similar) are checked against the pinned
  key, but never change it.
* A key belongs to one address. The same key used with another address
  starts over as a new key.

.. important::

   TOFU protects you from a key that **changes** later. It cannot tell
   you whether the first key was real. For a key that matters, check it
   with the developer and promote it into your keyring.

Attestation results
-------------------
``b4 am`` and ``b4 shazam`` show these results (for ``b4 review``, see
:doc:`review`):

============================================= ========================================
Result                                        Meaning
============================================= ========================================
``✓ Signed: … (TOFU: 3 series)``              Known key, seen in 3 other series
``? Signed: … (TOFU: new key)``               First series with this key. Not a pass:
                                              anyone can make up a key
``✗ KEY CHANGED: …``                          Signed with a different key than the one
                                              pinned (or the one in your keyring)
``✗ REJECTED KEY: …``                         Signed with a key you rejected
``✗ RETIRED KEY: …``                          Signed with a key you replaced. Messages
                                              seen before you replaced it still pass
============================================= ========================================

With :term:`b4.attestation-policy` set to ``hardfail``, a changed or
rejected key stops b4. A first-seen key never does.

Commands
--------
=============================================== ==========================================
Command                                         What it does
=============================================== ==========================================
``b4 kr list``                                  All addresses with TOFU keys
``b4 kr show <addr>``                           Keys and recent series of one address
``b4 kr accept <addr> <key> --add``             Trust a key next to the trusted one
``b4 kr accept <addr> <key> --replace``         Trust a key, retire the old one
``b4 kr reject <addr> <key>``                   Never accept messages with this key
``b4 kr forget <addr>``                         Erase everything known about an address
``b4 kr promote <addr> [<key>]``                Write the key into your b4 keyring
``b4 kr show-keys <msgid>``                     Show all keys used in a thread
=============================================== ==========================================

Where ``<key>`` is needed, the first few characters of a known key are
enough.

When a key changes
------------------
B4 prints a warning box with the new key and the keys it knows. To
decide::

    $ b4 kr show alice@example.org
    alice@example.org
    ---
      Key: AbCdzUj91asvincQGOFx6+ZF5AoUuP9GdOtQChs7Mm0=
        Status: trusted (tofu)
        First seen: 2026-03-02, last seen: 2026-09-14
        Counted series: 12
    ---
      Key: XyZ0p8yGQ2Ffk3vMHf9qWZ1ZsL2ZSmS6vN2w5p6tU1A=
        Status: pending (tofu)
        First seen: 2026-10-01, last seen: 2026-10-01
        Counted series: 1
    ---
    Check with the developer through a channel you trust, then:
      b4 kr accept alice@example.org XyZ0p8yGQ2 --add      (an extra key)
      b4 kr accept alice@example.org XyZ0p8yGQ2 --replace  (a new key)
      b4 kr reject alice@example.org XyZ0p8yGQ2

* ``--add``: the developer uses both keys (for example, two machines).
* ``--replace``: the developer moved to a new key.
* ``reject``: you do not trust this key.

Your decision applies right away, also to series you already track.

.. warning::

   Do not accept a new key only because the email asks you to. Check it
   with the developer in another way: chat, phone, or in person.

In ``b4 review``, a series with a changed or rejected key shows a red
``!`` in the **A** column. Open the action menu (``a``) and press ``K``
to see the key and decide.

Promoting a key to your keyring
-------------------------------
Once you have checked a key with the developer, store it in your
keyring::

    $ b4 kr promote alice@example.org
    Wrote /home/user/.local/share/b4/keyring/ed25519/example.org/alice/default
    Signatures from alice@example.org are now checked against your keyring.

From now on, the keyring key is used for this address and TOFU is
skipped. Use ``-s`` to pick a selector other than ``default``.

Showing keys in a thread
------------------------
``show-keys`` lists every key used to sign messages in a thread, and
the command to promote each ed25519 key::

    $ b4 kr show-keys <msgid>
    ---
    alice@example.org: (trusted on first use, 12 series)
        keytype: ed25519
         pubkey: AbCdzUj91asvincQGOFx6+ZF5AoUuP9GdOtQChs7Mm0=
       selector: default
       fullpath: /home/user/.local/share/b4/keyring/ed25519/example.org/alice/default
    ---
    After checking with the developer, add ed25519 keys with:
        b4 kr promote alice@example.org AbCdzUj91asvincQGOFx6+ZF5AoUuP9GdOtQChs7Mm0=

.. note::

   ``b4 kr --show-keys`` still works, but is deprecated.

Where TOFU data lives
---------------------
B4 stores keys and sightings in ``~/.local/share/b4/tofu.sqlite3``.
This file is **not** a cache: if you delete it, all trust history is
gone and the next key b4 sees for each address is pinned again. Back it
up with the rest of your data.

To turn TOFU off, set :term:`b4.attestation-tofu` to ``no``.

.. _`patatt`: https://pypi.org/project/patatt/
