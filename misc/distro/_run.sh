#!/usr/bin/env bash

# Shared in-container runner, sourced by each distro/<lane>.sh after it has
# installed the distro's own packages. It builds a venv that can see those
# distro site-packages, layers the first-party libraries and b4 on top with
# --no-deps (so pip never quietly upgrades the distro-provided third-party
# deps out from under the test), reports where every dependency came from,
# and runs the suite.
#
# No-tui lanes (e.g. AlmaLinux, which packages no textual) need no special
# handling here: the suite guards its optional-dependency imports with
# pytest.importorskip(), so tests that need textual/rich/nacl skip cleanly
# when those are absent.

set -eu

# The bind mount is read-only; copy to a writable tree so pytest and the
# editable install can write.
cp -r /src /build
cd /build

python3 -m venv --system-site-packages /venv
# shellcheck disable=SC1091
. /venv/bin/activate

# First-party libraries we maintain: pull the released versions b4 ships
# against, with --no-deps so they cannot drag in newer copies of textual,
# pygit2, etc. that would defeat the point of testing distro versions.
pip install -q --no-deps patatt liblore ezgb
# b4 itself (editable, no deps -- everything is already present).
pip install -q --no-deps -e .

echo '=== dependency provenance (distro vs pip) ==='
python - <<'PY'
import importlib

# dkim is the import name provided by the dkimpy package.
for name in ('textual', 'pygit2', 'dkim', 'requests', 'shtab',
             'patatt', 'liblore', 'ezgb', 'pytest'):
    try:
        mod = importlib.import_module(name)
    except Exception as exc:  # noqa: BLE001 -- report, don't fail
        print(f'  {name:10} absent  [{exc.__class__.__name__}]')
        continue
    ver = getattr(mod, '__version__', '?')
    path = getattr(mod, '__file__', '') or ''
    if path.startswith('/usr/'):
        origin = 'distro'
    elif '/venv/' in path:
        origin = 'pip'
    else:
        origin = '?'
    print(f'  {name:10} {str(ver):14} [{origin}]')
PY

echo '=== pytest ==='
python -m pytest src/tests -q -p no:cacheprovider
