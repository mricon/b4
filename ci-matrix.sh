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

if [ -n "$failed" ]; then
    printf '\nFAILURES:%s\n' "$failed"
    exit 1
fi

printf '\nAll interpreters passed: %s\n' "$PYTHONS"
