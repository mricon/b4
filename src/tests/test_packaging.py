#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 by the Linux Foundation
#
"""Regression tests for the packaged module surface.

Downstream packagers (e.g. Fedora's ``import_all_modules.py`` script)
probe importability of every public module after install.  Modules that
belong to an optional extra must not break that check when that extra's
dependency is absent.
"""

import subprocess
import sys
import textwrap

import pytest

# Every optional runtime dependency, keyed by the extra that provides it.
OPTIONAL_DEPS = {
    'tui': 'textual',
    'bugs': 'ezgb',
}

_PROBE_SCRIPT = textwrap.dedent("""
    import importlib
    import pkgutil
    import sys

    blocked = sys.argv[1].split(',')

    # Simulate the optional dependencies not being installed.
    class _Blocker:
        def find_spec(self, name, path, target=None):
            root = name.split('.')[0]
            if root in blocked:
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


@pytest.mark.parametrize(
    'blocked',
    [pytest.param([mod], id=extra) for extra, mod in OPTIONAL_DEPS.items()]
    + [pytest.param(sorted(OPTIONAL_DEPS.values()), id='all')],
)
def test_public_modules_import_without_optional_deps(blocked: list[str]) -> None:
    """Every public ``b4.*`` submodule must import without the optional deps.

    Runs in a subprocess so that the blocked modules are not already cached
    in ``sys.modules`` from earlier tests in the same session.
    """
    result = subprocess.run(
        [sys.executable, '-c', _PROBE_SCRIPT, ','.join(blocked)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f'Some public b4 modules failed to import without {", ".join(blocked)}:\n'
        f'stdout:\n{result.stdout}\n'
        f'stderr:\n{result.stderr}'
    )


_BUGS_GUARD_SCRIPT = textwrap.dedent("""
    import argparse
    import logging
    import sys

    # Simulate `ezgb` not being installed by blocking the import.
    class _Blocker:
        def find_spec(self, name, path, target=None):
            if name.split('.')[0] == 'ezgb':
                raise ModuleNotFoundError(f"No module named {name!r}")
            return None

    sys.meta_path.insert(0, _Blocker())

    logging.basicConfig(format='%(message)s', level=logging.DEBUG)

    import b4.bugs

    b4.bugs.main(argparse.Namespace(bugs_subcmd='list', status=None, label=None))
""")


def test_bugs_without_ezgb_hints_at_the_extra() -> None:
    """``b4 bugs`` must explain how to get bug support, not traceback.

    Bug tracking lives behind the ``[bugs]`` extra, so a b4 installed
    without it has to fail with an actionable message.
    """
    result = subprocess.run(
        [sys.executable, '-c', _BUGS_GUARD_SCRIPT],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1, f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}'
    assert 'Traceback' not in result.stderr
    assert 'pip install b4[bugs]' in result.stdout + result.stderr
