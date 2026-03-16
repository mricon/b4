Contributing to b4
==================

Thank you for your interest in contributing to b4!

Source code
-----------
The current b4 source code can be found at::

  git clone https://git.kernel.org/pub/scm/utils/b4/b4.git/

Submitting contributions
------------------------
Contributions should be sent as patches via email to **tools@kernel.org**.
Please include a clear description of your changes and the reasoning
behind them.

You can use ``b4`` itself to prepare and send your patches::

  b4 prep
  b4 send

Licensing
---------
This project is licensed under the `GNU General Public License, version 2
or later (GPL-2.0+) <COPYING>`_. By submitting a contribution, you agree
to license your work under this license.

Developer Certificate of Origin
--------------------------------
All contributions must include a ``Signed-off-by:`` trailer in each
commit message, certifying that you wrote or otherwise have the right to
submit the code under the project's open source license. This follows the
`Developer Certificate of Origin (DCO) <DCO>`_ process used by the Linux
kernel and many other open source projects.

To add your sign-off, use ``git commit -s`` or manually append the
following line to your commit message::

  Signed-off-by: Your Name <your.email@example.com>

AI-assisted contributions
~~~~~~~~~~~~~~~~~~~~~~~~~
AI agents (LLMs, coding assistants, etc.) are NOT permitted to use
``Signed-off-by:`` or ``Co-developed-by:`` trailers, as they cannot
certify the DCO. Additionally, ``Co-developed-by:`` trailer format
requires an email address and AI agents typically use bogus addresses
that interfere with patch-based workflows where valid contact
information is expected.

When a contribution is made with AI assistance, the AI tool MUST be
credited with an ``Assisted-by:`` trailer that includes the full model
version identifier. For example::

  Signed-off-by: Your Name <your.email@example.com>
  Assisted-by: claude-opus-4-6-20250925

The human contributor remains responsible for reviewing all AI-generated
changes, ensuring correctness, and certifying the DCO via their own
``Signed-off-by:`` trailer. The machine does not have any agency and
therefore you, the human, are the sole entity responsible for all
decisions.
