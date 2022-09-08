Configuration file
==================
B4 doesn't have a separate configuration file but will use
``git-config`` to retrieve a set of b4-specific settings. This means
that you can have three levels of b4 configuration:

- system-wide, in ``/etc/gitconfig``
- per-user, in ``$HOME/.gitconfig``
- per-repo, in ``somerepo/.git/config``

Since the purpose of b4 is to work with git repositories, this allows
the usual fall-through configuration that can be overridden by more
local settings on the repository level.

Configuration options
---------------------
All settings are under the ``b4`` section.

``b4.midmask``
  Default: ``https://lore.kernel.org/%s``

  When retrieving threads by message-id, b4 will use ``midmask`` to
  figure out from which server they should be retrieved.

``b4.linkmask``
  Default: ``https://lore.kernel.org/%s``

  When automatically generating ``Link:`` trailers, b4 will use this
  setting to derive the destination URL. If you want a shorter option,
  you can also use ``https://msgid.link/%s``, which is an alias for
  lore.kernel.org.

``b4.listid-preference``
  Default: ``*.feeds.kernel.org, *.linux.dev,*.kernel.org,*``

  Messages are frequently sent to multiple distribution lists, and some
  servers may apply content munging to modify the headers or the message
  content. B4 will deduplicate the results and this configuration option
  defines the priority given to the ``List-Id`` header. It is a simple
  comma-separated string with shell-style globbing.

``b4.save-maildirs``
  Default: ``no``

  The "mbox" file format is actually several incompatible formats
  ("mboxo" vs "mboxrd", for example). If you want to avoid dealing with
  this problem, you can choose to always save retrieved messages as a
  Maildir instead.

``b4.trailer-order``
  Default: ``*``

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
