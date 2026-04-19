#!/usr/bin/env sh

set -eu

uv run ruff format --check
uv run ruff check
uv run mypy .
uv run pytest --durations=20
