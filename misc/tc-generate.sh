#!/usr/bin/env bash
# Generate tab-complete files for use with bash, zsh, tcsh
# E.g.:
#    ./misc/tc-generate.sh bash > /tmp/b4
#    sudo cp /tmp/b4 /usr/share/bash-completion/completions/b4
#
# Requires shtab (python3-shtab)
#
if [[ -z $1 ]]; then
    echo "Specify the shell type as parameter (bash, zsh, tcsh)"
    exit 1
fi

REAL_PATH=$(realpath -e ${BASH_SOURCE[0]})
PROJ_TOP="${PROJ_TOP:-$(dirname ${REAL_PATH})}"
while [[ ${PROJ_TOP} != "/" ]]; do
    if [[ -d ${PROJ_TOP}/src/b4 ]]; then
        break
    fi
    PROJ_TOP=$(dirname ${PROJ_TOP})
done
if [[ $PROJ_TOP == "/" ]]; then
    echo "Please run me from the b4 project directory."
    exit 1
fi

if which shtab >/dev/null 2>&1; then
    PYTHONPATH="${PROJ_TOP}/src${PYTHONPATH:+:$PYTHONPATH}" \
        shtab --shell=$1 -u b4.command.setup_parser
else
    echo "Install shtab to generate tab-completion files."
    exit 1
fi