#!/usr/bin/env sh

set -eu

# Run an import smoke check and pytest under every interpreter version in the
# supported range (see `requires-python` in pyproject.toml). This is not part
# of ci.sh because materialising a venv per version is slow; invoke this
# before releases and after changes that could depend on version-specific
# runtime behaviour (import-time annotations, stdlib APIs, etc.).
#
# Missing interpreters are pulled automatically from uv's managed Python
# cache (python-build-standalone), so no system packages or sudo are needed.
#
# Override the version list: PYTHONS="3.11 3.14" ./ci-matrix.sh
#
# After the interpreter sweep it runs one "floor" lane: the project plus its
# runtime extras resolved to the *minimum* versions our metadata allows
# (uv --resolution lowest-direct), then the suite. This is what catches a
# dependency floor that is declared but does not actually work -- e.g. textual
# was pinned >=1.0 while the review TUI needed >=7.0.1 (github #80), invisible
# to every other lane because they all resolve the newest compatible version.
# It runs on the lowest supported interpreter, where the old dependency
# releases are likeliest to still publish wheels. Override or skip it:
# FLOOR_PY=3.12 ./ci-matrix.sh  (or FLOOR_PY= ./ci-matrix.sh to skip)
#
# After the floor lane it runs one advisory "prerelease" lane, on the newest
# CPython not yet in PYTHONS (a beta ahead of its final release, say), so we
# get an early signal without waiting on a relock. It resolves fresh against
# PyPI instead of uv.lock, and never fails the run -- see the lane itself for
# why. Override or skip it: PRERELEASE_PY=3.16 ./ci-matrix.sh (or
# PRERELEASE_PY= ./ci-matrix.sh to skip)

# ${VAR-default} rather than ${VAR:-default}: the latter also substitutes for
# an explicitly empty value, which would make "PYTHONS= ./ci-matrix.sh" run
# the full sweep instead of skipping it.
PYTHONS="${PYTHONS-3.11 3.12 3.13 3.14}"

# Install any requested interpreters that are missing. This is an explicit
# step because a dev may have set UV_PYTHON_DOWNLOADS=manual globally to
# prevent `uv sync` from reaching out to the network mid-workflow; running
# it once up front scopes the network access to this script.
if [ -n "$PYTHONS" ]; then
    # shellcheck disable=SC2086
    uv python install $PYTHONS
fi

# Collect failures so the run reports a complete matrix instead of bailing on
# the first broken interpreter.
failed=""

for py in $PYTHONS; do
    printf '\n=== Python %s ===\n' "$py"
    # Each version gets its own project environment so switching interpreters
    # does not thrash the default .venv and each sync is incremental.
    UV_PROJECT_ENVIRONMENT=".venv-$py"
    export UV_PROJECT_ENVIRONMENT
    if ! uv sync --all-extras --all-groups --python "$py"; then
        failed="$failed $py(sync)"
        continue
    fi
    if ! uv run python -c 'import b4, sys; print("import b4 OK on", sys.version.split()[0])'; then
        failed="$failed $py(import)"
        continue
    fi
    if ! uv run pytest --durations=20; then
        failed="$failed $py(pytest)"
        continue
    fi
done

# Floor lane: install the project + runtime extras at the minimum versions our
# metadata allows, then run the suite. Dependency groups (pytest, mypy, ...)
# carry no lower bounds, so `uv sync --resolution lowest-direct` would drag
# them to unbuildable ancient releases; installing just the project with
# `uv pip install` keeps the flooring to b4's own runtime dependencies, and a
# current test runner is layered on afterwards.
FLOOR_PY="${FLOOR_PY-3.11}"
if [ -n "$FLOOR_PY" ]; then
    printf '\n=== Floors (lowest-direct) on Python %s ===\n' "$FLOOR_PY"
    # --python targets the venv explicitly, so the loop's UV_PROJECT_ENVIRONMENT
    # must not leak in and redirect these commands.
    unset UV_PROJECT_ENVIRONMENT
    uv python install "$FLOOR_PY"
    floorenv='.venv-floor'
    rm -rf "$floorenv"
    if ! uv venv "$floorenv" --python "$FLOOR_PY"; then
        failed="$failed floors(venv)"
    elif ! uv pip install --python "$floorenv" --resolution lowest-direct '.[tui,completion]'; then
        failed="$failed floors(install)"
    elif ! uv pip install --python "$floorenv" pytest pytest-asyncio; then
        failed="$failed floors(pytest-install)"
    elif ! "$floorenv/bin/python" -c 'import b4, sys; print("import b4 OK on", sys.version.split()[0])'; then
        failed="$failed floors(import)"
    elif ! "$floorenv/bin/python" -m pytest --durations=20; then
        failed="$failed floors(pytest)"
    fi

    # Report what the floors actually resolved to. A green lane says the
    # declared minimums install and pass; this says which versions that was,
    # so a bound that has drifted above what PyPI still offers is visible.
    # Anchored to the start of the line so we match package names in the
    # `uv pip list` table and not substrings of other packages' names.
    printf '\n--- resolved floors ---\n'
    uv pip list --python "$floorenv" 2>/dev/null | grep -Ei \
        '^(argcomplete|dkimpy|ezgb|liblore|patatt|pygit2|requests|rich|shtab|textual)' || true
fi

# Prerelease lane: try the newest CPython not yet in PYTHONS, such as a beta
# ahead of its final release. This resolves fresh against PyPI instead of
# the committed uv.lock, which only targets our declared requires-python
# range and would otherwise need relocking (and could fail to resolve at
# all) just to humor an interpreter we don't support yet.
#
# Ecosystem wheels typically lag a new CPython release by weeks to months,
# and our compiled dependencies are the ones that bite: with no cp315 wheel
# for pygit2, uv falls back to its sdist and the build wants libgit2 headers
# that are not installed. So failures here are expected and this lane is
# advisory: it never fails the run, only reports what broke, so it does not
# block CI while giving a heads-up for when to move the interpreter into
# PYTHONS for real.
# Override or skip: PRERELEASE_PY=3.16 ./ci-matrix.sh (or PRERELEASE_PY= to skip)
PRERELEASE_PY="${PRERELEASE_PY-3.15}"
if [ -n "$PRERELEASE_PY" ]; then
    printf '\n=== Prerelease (advisory) on Python %s ===\n' "$PRERELEASE_PY"
    unset UV_PROJECT_ENVIRONMENT
    prereleaseenv='.venv-prerelease'
    rm -rf "$prereleaseenv"
    prerelease_failed=""
    if ! uv python install "$PRERELEASE_PY"; then
        prerelease_failed="install"
    elif ! uv venv "$prereleaseenv" --python "$PRERELEASE_PY"; then
        prerelease_failed="venv"
    elif ! uv pip install --python "$prereleaseenv" '.[tui,completion]'; then
        prerelease_failed="install-project"
    elif ! uv pip install --python "$prereleaseenv" pytest pytest-asyncio; then
        prerelease_failed="pytest-install"
    elif ! "$prereleaseenv/bin/python" -c 'import b4, sys; print("import b4 OK on", sys.version.split()[0])'; then
        prerelease_failed="import"
    elif ! "$prereleaseenv/bin/b4" --version; then
        prerelease_failed="cli"
    elif ! "$prereleaseenv/bin/python" -m pytest --durations=20; then
        prerelease_failed="pytest"
    fi

    if [ -n "$prerelease_failed" ]; then
        printf '\nPrerelease lane failed (advisory, not fatal): %s\n' "$prerelease_failed"
    else
        printf '\nPrerelease lane passed on Python %s\n' "$PRERELEASE_PY"
    fi
fi

if [ -n "$failed" ]; then
    printf '\nFAILURES:%s\n' "$failed"
    exit 1
fi

if [ -n "$PYTHONS" ]; then
    printf '\nAll interpreters passed: %s\n' "$PYTHONS"
fi
if [ -n "$FLOOR_PY" ]; then
    printf 'Floor lane passed on Python %s\n' "$FLOOR_PY"
fi
