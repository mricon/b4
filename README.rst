This is a helper utility to work with patches made available via a
public-inbox archive like lore.kernel.org. It is written to make it
easier to participate in a patch-based workflows, like those used in
the Linux kernel development.

The name "b4" was chosen for ease of typing and because B-4 was the
precursor to Lore and Data in the Start Trek universe.

See man/b4.5.rst for more information.

Installing
----------
```
python3 -m pip install --user b4
```

Upgrading
---------
```
python3 -m pip install --user --upgrade b4
```

Running from the checkout dir
-----------------------------
If you want to run from the checkout dir without installing the python package,
just create the following wrapper command and put it in your path::

    #!/bin/bash
    B4DIR=$HOME/your/path/to/b4-git-repo
    PYTHONPATH=$B4DIR env python3 $B4DIR/b4/command.py $@

Support
-------
For support or with any other questions, please email
tools@linux.kernel.org.
