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
To install the latest released version with pip::

    python3 -m pip install b4

Or to install the latest master (warning, maybe broken!)::

    python3 -m pip install git+https://git.kernel.org/pub/scm/utils/b4/b4.git@master

Upgrading
---------
If you previously installed from pypi::

    python3 -m pip install --upgrade b4

Or to get the latest stuff from git::

    python3 -m pip install --upgrade git+https://git.kernel.org/pub/scm/utils/b4/b4.git@master

Running from the checkout dir
-----------------------------
If you want to run from the checkout dir without installing the python
package, you can use the included ``b4.sh`` wrapper. You can set it as
an alias in your .bash_profile::

    alias b4="$HOME/path/to/b4/b4.sh"

Setting up a symlink should also be possible. Remember to run the
following commands after the initial clone::

    git submodule update --init
    python3 -m pip install -r requirements.txt

Support
-------
For support or with any other questions, please email tools@kernel.org,
or browse the list archive at https://lore.kernel.org/tools.
