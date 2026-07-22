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

PYTHONS="${PYTHONS:-3.11 3.12 3.13 3.14}"

# Install any requested interpreters that are missing. This is an explicit
# step because a dev may have set UV_PYTHON_DOWNLOADS=manual globally to
# prevent `uv sync` from reaching out to the network mid-workflow; running
# it once up front scopes the network access to this script.
# shellcheck disable=SC2086
uv python install $PYTHONS

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
FLOOR_PY="${FLOOR_PY:-3.11}"
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
fi

if [ -n "$failed" ]; then
    printf '\nFAILURES:%s\n' "$failed"
    exit 1
fi

printf '\nAll interpreters passed: %s\n' "$PYTHONS"
if [ -n "$FLOOR_PY" ]; then
    printf 'Floor lane passed on Python %s\n' "$FLOOR_PY"
fi
