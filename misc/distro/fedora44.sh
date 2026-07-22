#!/usr/bin/env bash

# Fedora 44 lane: full TUI. Ships textual 4.0.0 (< 7.0.1), so this lane
# exercises the old-textual path alongside Debian. rich arrives automatically
# as a dependency of python3-textual.

set -eu

dnf -q -y install \
    git python3 python3-pip \
    python3-textual python3-pygit2 python3-dkimpy python3-requests python3-shtab \
    python3-pytest python3-pytest-asyncio \
    >/dev/null

export WITH_TUI=1
# shellcheck disable=SC1091
. /src/misc/distro/_run.sh
