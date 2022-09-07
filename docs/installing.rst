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

Installing with pip
-------------------
To install from pypi::

    python3 -m pip install --user b4

This will install b4 locally and pull in any required dependencies. If
you are not able to execute ``b4 --version`` after pip completes, check
that your ``~/.local/bin/`` is in your ``$PATH``.

Upgrading
~~~~~~~~~
If you have previously installed from pypi, you can upgrade using pip as
well::

    python3 -m pip install --user --upgrade b4

Running from the checkout dir
-----------------------------
If you want to run the latest development version of b4, you can run it
directly from the git repository::

    git clone https://git.kernel.org/pub/scm/utils/b4/b4.git
    cd b4
    git submodule update --init
    pip install --user -r requirements.txt

You can then either symlink the ``b4.sh`` script to your user-bin
directory::

    ln -sf $HOME/path/to/b4.sh ~/bin/b4

or you can add an alias to your shell's RC file::

    alias b4="$HOME/path/to/b4/b4.sh"

Using a stable branch
~~~~~~~~~~~~~~~~~~~~~
If you don't want to use the master branch (which may not be stable),
you can switch to a stable branch instead, e.g.::

    git switch stable-0.9.y

Updating the git checkout
~~~~~~~~~~~~~~~~~~~~~~~~~
It should be sufficient to just turn ``git pull``::

    git pull origin master
    git submodule update

If you notice that ``requirements.txt`` has been updated, you may wish
to run the pip command again::

    pip install --user -r requirements.txt
