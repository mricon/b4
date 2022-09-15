B4 tools
========
This is a helper utility to work with patches made available via a
public-inbox archive like lore.kernel.org. It is written to make it
easier to participate in a patch-based workflows, like those used in
the Linux kernel development.

The name "b4" was chosen for ease of typing and because B-4 was the
precursor to Lore and Data in the Star Trek universe.

See https://b4.docs.kernel.org/ for online documentation.

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

Setting up a symlink should also be possible. Remember to run the
following command after the initial clone in order to pull in the
dependencies that are tracked via submodules::

    git submodule update --init

Support
-------
For support or with any other questions, please email
tools@linux.kernel.org, or browse the list archive at
https://lore.kernel.org/tools.
