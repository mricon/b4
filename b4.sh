#!/usr/bin/env bash
#
# Run b4 from a git checkout.
#

REAL_SCRIPT=$(realpath -e ${BASH_SOURCE[0]})
SCRIPT_TOP="${SCRIPT_TOP:-$(dirname ${REAL_SCRIPT})}"

PYTHONPATH="${SCRIPT_TOP}/src:${SCRIPT_TOP}/patatt${PYTHONPATH:+:$PYTHONPATH}" \
	exec python3 "${SCRIPT_TOP}/src/b4/command.py" "${@}"
