#!/usr/bin/env bash

# Arch lane: full TUI, bleeding edge. Ships the newest of everything
# (textual 8.x, pytest 9.x), so it catches breakage from dependencies moving
# ahead of us. dkimpy is packaged as python-dkim; rich arrives as a
# dependency of python-textual.

set -eu

pacman -Sy --noconfirm --needed \
    git python python-pip \
    python-textual python-pygit2 python-dkim python-requests python-shtab \
    python-pytest python-pytest-asyncio \
    >/dev/null

# shellcheck disable=SC1091
. /src/misc/distro/_run.sh
