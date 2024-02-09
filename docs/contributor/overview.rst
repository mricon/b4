Contributor overview
====================
.. note::

   ``b4 prep``, ``b4 send`` and ``b4 trailers`` are available starting
   with version 0.10.

Even though b4 started out as a tool to help maintainers, beginning with
the version ``0.10`` there is also a set of features aimed at making it
easier for contributors to submit patch series:

* ``b4 prep`` allows to get your patch series ready for sending to the
  maintainer for review
* ``b4 send`` simplifies the process of submitting your patches to the
  upstream maintainer even if you don't have access to a compliant SMTP
  server
* ``b4 trailers`` simplifies the process of retrieving code-review
  trailers received on the distribution lists and applying them to your
  tree

.. warning::

  This is a fairly new set of features and can still be buggy or do
  something unexpected. While a lot of work has gone into making sure
  that your git tree is not harmed in any way, it is best to have
  backups and to always check things with ``--dry-run`` when that option
  is available.

  If you come across a bug or unexpected behaviour, please report the
  problem to the Tools mailing list.

Do I still need to be able to send email?
-----------------------------------------
While ``b4 send`` makes it possible to submit patches without having
access to an SMTP server, you still need a reasonable mail server for
participating in conversations and code review.

The main benefit of ``b4 send`` is that you no longer have to really
care if your mail server performs some kind of content mangling that
causes patches to become corrupted, or if it doesn't provide a way to
send mail via SMTP.

What is the b4 contributor workflow?
------------------------------------
The workflow is very much git-oriented, so you should expect to need to
know a lot about such git commands like ``git commit --amend`` and ``git rebase
-i``. In general, the process goes like this:

1. Prepare your patch series by using ``b4 prep`` and queueing your
   commits. Use ``git rebase -i`` to arrange the commits in the right
   order and to write good commit messages.

2. Prepare your cover letter using ``b4 prep --edit-cover``. You should
   provide a good overview of what your series does and why you think it
   will improve the current code.

3. When you are almost ready to send, use ``b4 prep --auto-to-cc``
   to collect the relevant addresses from your commits. If your project
   uses a ``MAINTAINERS`` file, this will also perform the required
   query to figure out who should be included on your patch series
   submission.

4. Review the list of addresses that were added to the cover letter and,
   if you know what you're doing, remove any that you think are
   unnecessary.

5. Send your series using ``b4 send``. This will automatically reroll
   your series to the next version and add changelog entries to the
   cover letter.

6. Await code review and feedback from maintainers.

7. Apply any received code-review trailers using ``b4 trailers -u``.

8. Use ``git rebase -i`` to make any changes to the code based on the
   feedback you receive. Remember to record these changes in the cover
   letter's changelog.

9. Unless series is accepted upstream, GOTO 3.

10. Clean up obsolete prep-managed branches using ``b4 prep --cleanup``

Please read the rest of these docs for details on the ``prep``,
``send``, and ``trailers`` subcommands.
