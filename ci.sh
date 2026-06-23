#!/usr/bin/env sh

set -eu

# Install every extra and dependency group so the type checkers below can
# resolve imports in src/b4/review_tui (textual), src/b4/command (shtab),
# and misc/ (ezpi, falcon, instructor, pydantic, sqlalchemy).
uv sync --all-extras --all-groups

uv run ruff format --check
uv run ruff check
uv run ty check
uv run mypy .
uv run pyright
uv run pytest --durations=20
