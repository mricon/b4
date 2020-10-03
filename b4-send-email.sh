#!/usr/bin/env bash
#
# Wrapper for running b4-send-email from checkout
#

REAL_SCRIPT=$(realpath -e ${BASH_SOURCE[0]})
SCRIPT_TOP="${SCRIPT_TOP:-$(dirname ${REAL_SCRIPT})}"

exec env PYTHONPATH="${SCRIPT_TOP}" python3 "${SCRIPT_TOP}/b4/attest.py" "${@}"
