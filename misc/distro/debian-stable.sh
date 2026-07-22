#!/usr/bin/env bash

# Debian stable lane: full TUI. This is the primary old-textual guardian --
# trixie ships textual 2.1.2, which reproduces github #80. dkimpy is packaged
# as python3-dkim; rich arrives as a dependency of python3-textual.

set -eu

export DEBIAN_FRONTEND=noninteractive
apt-get -qq update >/dev/null
apt-get -qq install -y --no-install-recommends \
    git python3 python3-pip python3-venv \
    python3-textual python3-pygit2 python3-dkim python3-requests python3-shtab \
    python3-pytest python3-pytest-asyncio \
    >/dev/null

# shellcheck disable=SC1091
. /src/misc/distro/_run.sh
