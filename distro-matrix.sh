#!/usr/bin/env sh

set -eu

# Run the test suite inside real distro containers, installing b4's
# third-party dependencies from each distro's *own* package manager. This
# catches "the distro ships an older dependency than we pin" bugs that the
# interpreter-only ci-matrix.sh cannot see: every uv-resolved lane there
# always gets the newest compatible dependency, whereas distros lag.
# (The motivating case: textual is declared `>=1.0`, but the review TUI
# needs `>=7.0.1`, and Debian stable ships 2.1.2 -- see github #80.)
#
# This is a heavy, network-dependent, pre-release check -- it pulls OS
# images and hits distro mirrors -- so it is deliberately separate from
# both ci.sh (fast local gate) and ci-matrix.sh (interpreter sweep).
#
# Requires rootless podman. Override the lane list or the runtime:
#   DISTROS="debian-stable arch" ./distro-matrix.sh
#   PODMAN=docker ./distro-matrix.sh
#
# Each lane runs misc/distro/<lane>.sh inside its container; that recipe
# installs the distro packages, then hands off to misc/distro/_run.sh (shared)
# which builds
# a venv over the distro site-packages, adds the first-party trio
# (patatt/liblore/ezgb) + b4 with `--no-deps`, prints a provenance report,
# and runs pytest. IMPORTANT: a green matrix does not mean every lane tested
# an old dependency -- read the per-lane "dependency provenance" report to see
# which libs came from the distro vs. pip. AlmaLinux, for instance, does not
# package textual at all and runs as a deliberate no-tui lane.

PODMAN="${PODMAN:-podman}"
DISTROS="${DISTROS:-fedora44 alma10 debian-stable arch}"

if ! command -v "$PODMAN" >/dev/null 2>&1; then
    printf 'error: %s not found; install podman (rootless) or set PODMAN=\n' "$PODMAN" >&2
    exit 2
fi

# Base image per lane. Pinned to major versions we care about; bump
# deliberately (a newer image may ship newer deps and change coverage).
image_for() {
    case "$1" in
        fedora44)      echo 'registry.fedoraproject.org/fedora:44' ;;
        alma10)        echo 'quay.io/almalinuxorg/almalinux:10' ;;
        debian-stable) echo 'docker.io/debian:stable-slim' ;;
        arch)          echo 'docker.io/archlinux:latest' ;;
        *) printf 'error: unknown distro lane: %s\n' "$1" >&2; return 1 ;;
    esac
}

# The source tree is bind-mounted read-only; --security-opt label=disable
# avoids relabelling the host checkout under SELinux (rootless podman would
# otherwise fail to read it, or rewrite its labels with :z/:Z).
run_lane() {
    _d="$1"
    _img=$(image_for "$_d") || return 1
    printf '\n============================ %s (%s) ============================\n' \
        "$_d" "$_img"
    "$PODMAN" run --rm --security-opt label=disable \
        -v "$PWD:/src:ro" "$_img" bash "/src/misc/distro/$_d.sh"
}

# Collect failures so the run reports the whole matrix instead of bailing on
# the first red lane.
failed=""
for d in $DISTROS; do
    if ! run_lane "$d"; then
        failed="$failed $d"
    fi
done

if [ -n "$failed" ]; then
    printf '\nFAILURES:%s\n' "$failed"
    exit 1
fi

printf '\nAll distro lanes passed: %s\n' "$DISTROS"
