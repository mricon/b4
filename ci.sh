#!/usr/bin/env sh

set -eu

uv run ruff check
uv run mypy .
