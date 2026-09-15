Installing b4
=============
B4 is packaged for many distributions, so chances are that you will be
able to install it using your regular package installation commands,
e.g.::

    # dnf install b4

or::

    # apt install b4

Note, that b4 is under heavy development, so it is possible that the
version packaged for your distribution is not as recent as you'd like.
If that is the case, you can install it from other sources.

Installing with pipx
--------------------
The recommended way to install b4 from PyPI is with `pipx`_, which
installs CLI tools into isolated environments::

    pipx install b4

Some features live behind optional extras, so that you only pull in the
dependencies for the parts of b4 you actually use:

``tui``
    The TUI dependencies needed for ``b4 review tui``.

``bugs``
    Bug tracking with ``b4 bugs``. This also needs the `git-bug`_ binary,
    which is not installable from PyPI -- see :doc:`maintainer/bugs`.

Install them by naming them in brackets, separated by commas::

    pipx install b4[tui]
    pipx install b4[tui,bugs]

If you do not have pipx, it is available in most distribution
repositories (``dnf install pipx``, ``apt install pipx``).

Upgrading
~~~~~~~~~
::

    pipx upgrade b4

Using uv
~~~~~~~~
`uv`_ is a fast alternative to pipx::

    uv tool install b4
    uv tool install b4[tui]

.. _`pipx`: https://pipx.pypa.io/
.. _`uv`: https://docs.astral.sh/uv/
.. _`git-bug`: https://github.com/git-bug/git-bug

Installing from a git checkout
------------------------------
If you want to run the latest development version of b4, you can
install it from a local git clone using pipx::

    git clone https://git.kernel.org/pub/scm/utils/b4/b4.git
    cd b4
    git submodule update --init
    pipx install .

Or with the optional extras::

    pipx install .[tui,bugs]

After pulling new changes, reinstall to pick them up::

    git pull origin master
    git submodule update
    pipx install --force .

Running directly with b4.sh
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Alternatively, you can run b4 directly from the checkout without
installing. Symlink the ``b4.sh`` script to your user-bin directory::

    ln -sf $HOME/path/to/b4/b4.sh ~/bin/b4

or add an alias to your shell's RC file::

    alias b4="$HOME/path/to/b4/b4.sh"

To update, just pull::

    git pull origin master
    git submodule update

Using a stable branch
~~~~~~~~~~~~~~~~~~~~~
If you don't want to use the master branch (which may not be stable),
you can switch to a stable branch instead, e.g.::

    git switch stable-0.9.y
