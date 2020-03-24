#!/usr/bin/env bash
#
# Run b4 from a git checkout.
#

REAL_SCRIPT=$(realpath -e ${BASH_SOURCE[0]})
SCRIPT_TOP="${SCRIPT_TOP:-$(dirname ${REAL_SCRIPT})}"

exec env PYTHONPATH="${SCRIPT_TOP}" python3 "${SCRIPT_TOP}/b4/command.py" "${@}"
