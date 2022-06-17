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

Setting up a symlink should also be possible. Remember to run the
following command after the initial clone in order to pull in the
dependencies that are tracked via submodules::

    git submodule update --init

Patch attestation
-----------------
B4 implements two attestation verification mechanisms:

- DKIM attestation using the dkimpy library
- X-Developer-Signature attestation using the patatt library

If you installed from pip, you should have pulled both of these
dependencies in automatically. Alternatively, you can install dkimpy
from your OS packaging and then run "git submodule update --init" to
clone patatt as a submodule of b4.

For attesting your outgoing patches, see patatt documentation.
https://git.kernel.org/pub/scm/utils/patatt/patatt.git/about/

Display attestation results on received patches
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
There are four attestation verification modes in b4:

- off
- check
- softfail (default)
- hardfail

The "check" policy is look for any available attestation and try to
verify it. If verification fails, b4 will not output any errors, but
will not show verification checkmarks either.

In the "softfail" mode, any verification errors will be prominently
displayed, but b4 will still produce the resulting file with patches.

The "hardfail" mode will show verification errors and exit without
generating the .mbx file with patches.

You can set the preferred policy via the git configuration file::

    [b4]
      attestation-policy = hardfail

Support
-------
For support or with any other questions, please email
tools@linux.kernel.org, or browse the list archive at
https://lore.kernel.org/tools.
