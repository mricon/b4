#!/usr/bin/env bash

# Shared in-container runner, sourced by each distro/<lane>.sh after it has
# installed the distro's own packages. It builds a venv that can see those
# distro site-packages, layers the first-party libraries and b4 on top with
# --no-deps (so pip never quietly upgrades the distro-provided third-party
# deps out from under the test), reports where every dependency came from,
# and runs the suite.
#
# Contract from the caller (distro/<lane>.sh):
#   WITH_TUI=1|0   -- whether textual (and thus the review TUI) is installed.
#                     A no-tui lane deselects every test module that imports
#                     textual/rich so collection still succeeds.

set -eu

: "${WITH_TUI:=1}"

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

# Assemble the pytest ignore set.
IG=""
# test_patatt.py exercises patatt's own signing via PyNaCl, which is not part
# of b4's dependency surface; skip it rather than pull nacl into every image.
IG="$IG --ignore=src/tests/test_patatt.py"
echo '>>> skipping src/tests/test_patatt.py (needs PyNaCl, tangential to b4)'

if [ "$WITH_TUI" = 0 ]; then
    # No textual/rich installed. Deselect every test module that imports them,
    # derived by grep so the list cannot rot as tests are added. (The proper
    # fix is pytest.importorskip guards in the suite itself; deferred.)
    # `_tui` catches both b4.review_tui and b4.bugs._tui (the latter pulls in
    # rich transitively), plus direct textual/rich imports.
    for f in src/tests/test_*.py; do
        if grep -qE 'import textual|from textual|_tui|import rich|from rich' "$f"; then
            IG="$IG --ignore=$f"
            echo ">>> no-tui: skipping $f"
        fi
    done
fi

echo "=== pytest (WITH_TUI=$WITH_TUI) ==="
# IG must word-split into separate --ignore args, so it stays unquoted.
# shellcheck disable=SC2086
python -m pytest src/tests $IG -q -p no:cacheprovider
