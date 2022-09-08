Maintainer overview
===================
The primary goal of b4 is to make it easier for maintainers to retrieve
patch series, verify their authenticity, apply any follow-up code review
trailers, and apply the patches to their maintained git trees.

This functionality works best when coupled with a `public-inbox`_
aggregator service, such as the one running on lore.kernel.org, but can
be used with local mailboxes and maildirs, thus providing fully
decentralized, experience with robust end-to-end attestation.

.. _`public-inbox`: https://public-inbox.org/README.html

Working with patches sent to distribution lists
-----------------------------------------------
Patches sent to distribution lists remains the only widely used
decentralized code review framework. RFC2822-conformant ("email")
messages adhere to an established standard that ensures high level of
interoperability between systems, and it remains one of the remaining
few truly decentralized communication platforms.

Note, that "distribution lists" may not necessarily mean "patches sent
via email". In addition to SMTP, RFC2822 messages can be also delivered
via any number of push and pull mechanisms, such as NNTP, web archives,
public-inbox repositories, etc. In the case of lore.kernel.org, the
messages are collated from a large number of sources then replicated
across multiple frontends.
