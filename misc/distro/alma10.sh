#!/usr/bin/env bash

# AlmaLinux 10 lane: the no-tui / enterprise-Linux case. EL10 does not package
# textual anywhere (base, AppStream, EPEL, CRB), so this lane deliberately runs
# the core CLI without it -- verifying b4 degrades gracefully when
# python3-textual is absent, which is exactly what an EL packager faces.
#
# It also ships pygit2 1.14.0, below b4's declared `pygit2>=1.15` floor; a probe
# confirmed the rewrite engine passes on 1.14.0, so this lane doubles as the
# canary for that floor (installing b4 --no-deps means we run against 1.14.0
# rather than pip-upgrading it).
#
# EPEL + CRB are needed for shtab and pytest-asyncio.

set -eu

dnf -q -y install \
    "https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm" \
    >/dev/null 2>&1 || true
dnf -q -y install dnf-plugins-core >/dev/null 2>&1 || true
dnf config-manager --set-enabled crb >/dev/null 2>&1 || true

dnf -q -y install \
    git python3 python3-pip \
    python3-pygit2 python3-dkimpy python3-requests python3-shtab \
    python3-pytest python3-pytest-asyncio \
    >/dev/null

# shellcheck disable=SC1091
. /src/misc/distro/_run.sh
