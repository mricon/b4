#!/usr/bin/env bash
#
# Run b4 from a git checkout.
#

SCRIPT_TOP="${SCRIPT_TOP:-$(cd "${BASH_SOURCE%/*}" && pwd)}"

exec env PYTHONPATH="${SCRIPT_TOP}" python3 "${SCRIPT_TOP}/b4/command.py" "${@}"
