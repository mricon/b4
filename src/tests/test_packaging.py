#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Regression tests for the packaged module surface.

Downstream packagers (e.g. Fedora's ``import_all_modules.py`` script)
probe importability of every public module after install.  The
``[tui]``-only modules must not break that check when the optional
``textual`` dependency is absent.
"""

import subprocess
import sys
import textwrap

_PROBE_SCRIPT = textwrap.dedent("""
    import importlib
    import pkgutil
    import sys

    # Simulate `textual` not being installed by blocking the import.
    class _Blocker:
        def find_spec(self, name, path, target=None):
            if name == 'textual' or name.startswith('textual.'):
                raise ModuleNotFoundError(f"No module named {name!r}")
            return None

    sys.meta_path.insert(0, _Blocker())

    import b4

    failures = []
    for info in pkgutil.walk_packages(b4.__path__, prefix='b4.'):
        name = info.name
        # Mirror what Fedora's import-all check does: only public modules.
        if any(part.startswith('_') for part in name.split('.')[1:]):
            continue
        try:
            importlib.import_module(name)
        except Exception as e:
            failures.append(f'{name}: {type(e).__name__}: {e}')

    if failures:
        for line in failures:
            print(line)
        sys.exit(1)
""")


def test_public_modules_import_without_textual() -> None:
    """Every public ``b4.*`` submodule must import without ``textual``.

    Runs in a subprocess so that ``textual`` is not already cached in
    ``sys.modules`` from earlier TUI tests in the same session.
    """
    result = subprocess.run(
        [sys.executable, '-c', _PROBE_SCRIPT],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        'Some public b4 modules failed to import without textual:\n'
        f'stdout:\n{result.stdout}\n'
        f'stderr:\n{result.stderr}'
    )
