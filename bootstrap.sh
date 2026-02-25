#!/usr/bin/env bash
set -euo pipefail

# Optional mode argument:
# --autorestore-only: run workspace autorestore once and exit quickly.
MODE_ARG="${1:-}"
AUTORESTORE_ONLY=0
if [ "$MODE_ARG" = "--autorestore-only" ]; then
  AUTORESTORE_ONLY=1
  shift || true
fi

# Expected env vars (auto injected by: happycapy_ops.py bootstrap-via-tmate --script-url):
# - HAPPYCAPY_ACCESS_TOKEN
# - HAPPYCAPY_ALIAS
# - HAPPYCAPY_SSH_USER
# - HAPPYCAPY_SSH_PASSWORD
# - HAPPYCAPY_SSH_PORT
# - HAPPYCAPY_LOCAL_PORT
# - HAPPYCAPY_CHISEL_AUTH
# - HAPPYCAPY_REGISTRY_FILE
# - HAPPYCAPY_REGISTRY_UPLOAD_API
# - HAPPYCAPY_REGISTRY_BASE

ACCESS_TOKEN="${HAPPYCAPY_ACCESS_TOKEN:-}"
ALIAS="${HAPPYCAPY_ALIAS:-acc001}"
SSH_USER="${HAPPYCAPY_SSH_USER:-node}"
SSH_PASSWORD="${HAPPYCAPY_SSH_PASSWORD:-zd19861111}"
SSH_PORT="${HAPPYCAPY_SSH_PORT:-2222}"
LOCAL_PORT="${HAPPYCAPY_LOCAL_PORT:-2233}"
CHISEL_AUTH="${HAPPYCAPY_CHISEL_AUTH:-user:ChiselPass2026}"
REGISTRY_FILE="${HAPPYCAPY_REGISTRY_FILE:-happycapy_${ALIAS}.txt}"
UPLOAD_API="${HAPPYCAPY_REGISTRY_UPLOAD_API:-https://file.zmkk.fun/api/upload}"
REGISTRY_BASE="${HAPPYCAPY_REGISTRY_BASE:-https://file.zmkk.fun}"
OHMYZSH_INSTALL_URL="${HAPPYCAPY_OHMYZSH_INSTALL_URL:-https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh}"
P10K_REPO_URL="${HAPPYCAPY_P10K_REPO_URL:-https://github.com/romkatv/powerlevel10k.git}"
DOTFILE_BASHRC_URL="${HAPPYCAPY_DOTFILE_BASHRC_URL:-https://raw.githubusercontent.com/hhsw2015/bin/refs/heads/main/.bashrc}"
DOTFILE_ZSHRC_URL="${HAPPYCAPY_DOTFILE_ZSHRC_URL:-https://raw.githubusercontent.com/hhsw2015/bin/refs/heads/main/.zshrc}"
DOTFILE_P10K_URL="${HAPPYCAPY_DOTFILE_P10K_URL:-https://raw.githubusercontent.com/hhsw2015/bin/refs/heads/main/.p10k.zsh}"
PERSIST_ROOT="${HAPPYCAPY_PERSIST_ROOT:-}"
# Normalize transient workspace-style roots to a stable persisted root.
# Example: /home/node/a0/workspace/<session>/workspace -> /home/node/a0/workspace
if [ -n "$PERSIST_ROOT" ]; then
  PERSIST_ROOT="$(printf '%s' "$PERSIST_ROOT" | sed -E 's#^(/home/node/[^/]+/workspace)/.+/workspace/?$#\1#')"
fi
if [ -z "$PERSIST_ROOT" ] || [ ! -d "$PERSIST_ROOT" ]; then
  if [ -d /home/node/a0/workspace ]; then
    PERSIST_ROOT="/home/node/a0/workspace"
  else
    for d in /home/node/*/workspace /home/node/workspace; do
      if [ -d "$d" ]; then
        PERSIST_ROOT="$d"
        break
      fi
    done
  fi
  if [ -z "$PERSIST_ROOT" ]; then
    PERSIST_ROOT="$HOME"
  fi
fi
PERSIST_DIR="${PERSIST_ROOT}/.happycapy"
SHELL_PROFILE_MARKER="${PERSIST_DIR}/shell-profile-ohmyzsh-v1.ready"
SHELL_PROFILE_VERSION="2026-02-25-ohmyzsh-p10k-v1"
PERSIST_BOOTSTRAP="${PERSIST_DIR}/bootstrap.sh"
RECOVER_SCRIPT_PATH="${HAPPYCAPY_RECOVER_SCRIPT:-${PERSIST_DIR}/happycapy-recover.sh}"
WORKSPACE_RECOVER_GLOB="/home/node/*/workspace/.happycapy/happycapy-recover.sh"
REGISTRY_URL_PATH="${HAPPYCAPY_REGISTRY_URL_PATH:-${PERSIST_DIR}/registry_url.txt}"
CONTROL_PORT="${HAPPYCAPY_CONTROL_PORT:-18080}"
CONTROL_API_SCRIPT="${PERSIST_DIR}/happycapy-control-api.js"
CONTROL_API_SCRIPT_VERSION_MARKER="happycapy-control-api-version: 2026-02-24-observability-v1"
CONTROL_API_PID_FILE="${PERSIST_DIR}/happycapy-control-api.pid"
CONTROL_API_URL_PATH="${HAPPYCAPY_CONTROL_API_URL_PATH:-${PERSIST_DIR}/control_api_url.txt}"
HEARTBEAT_URL_PATH="${HAPPYCAPY_HEARTBEAT_URL_PATH:-${PERSIST_DIR}/heartbeat_url.txt}"
KEEPALIVE_PID_FILE="${HAPPYCAPY_KEEPALIVE_PID_FILE:-${PERSIST_DIR}/vnc-keeper-browser.pid}"
KEEPALIVE_URL_PATH="${HAPPYCAPY_KEEPALIVE_URL_PATH:-${PERSIST_DIR}/vnc-keeper-url.txt}"
KEEPALIVE_VISIBLE_PATH="${HAPPYCAPY_KEEPALIVE_VISIBLE_PATH:-${PERSIST_DIR}/vnc-keeper-visible.txt}"
KEEPALIVE_PAGE_PATH="${HAPPYCAPY_KEEPALIVE_PAGE_PATH:-${PERSIST_DIR}/vnc-keeper-page.txt}"
KEEPALIVE_TRIGGER_PATH="${HAPPYCAPY_KEEPALIVE_TRIGGER_PATH:-${PERSIST_DIR}/vnc-keeper-trigger.txt}"
KEEPALIVE_BROWSER_LOG="${HAPPYCAPY_KEEPALIVE_BROWSER_LOG:-/tmp/happycapy-vnc-browser.log}"
KEEPALIVE_LOG_PATH="${HAPPYCAPY_KEEPALIVE_LOG_PATH:-/tmp/happycapy-vnc-keepalive.log}"
INSTALL_AUDIT_LOG_PATH="${HAPPYCAPY_INSTALL_AUDIT_LOG_PATH:-/tmp/happycapy-install-audit.log}"
PROCESS_AUDIT_LOG_PATH="${HAPPYCAPY_PROCESS_AUDIT_LOG_PATH:-/tmp/happycapy-process-audit.log}"
KEEPALIVE_STATE_PATH="${HAPPYCAPY_KEEPALIVE_STATE_PATH:-${PERSIST_DIR}/vnc-keeper-state.env}"
AUTORESTORE_ENV_FILE="${HAPPYCAPY_AUTORESTORE_ENV_FILE:-${PERSIST_DIR}/autorestore.env}"
EXTERNAL_RECOVER_URL="${HAPPYCAPY_EXTERNAL_RECOVER_URL:-}"
EXTERNAL_RECOVER_STATE_FILE="${PERSIST_DIR}/external-recover.state"
EXTERNAL_RECOVER_LOG="${HAPPYCAPY_EXTERNAL_RECOVER_LOG:-/tmp/happycapy-external-recover.log}"
AUTORESTORE_WORKER_PID_FILE="${PERSIST_DIR}/autorestore-worker.pid"
AUTORESTORE_WORKER_LOG="${HAPPYCAPY_AUTORESTORE_LOG:-/tmp/happycapy-autorestore.log}"
AUTORESTORE_DEPS_BOOTID_FILE="${PERSIST_DIR}/autorestore-deps.bootid"
BOOTSTRAP_LOOP_PID_FILE="${PERSIST_DIR}/bootstrap-loop.pid"
BOOTSTRAP_LOOP_LOG="${HAPPYCAPY_BOOTSTRAP_LOG:-/tmp/hc-bootstrap-loop.log}"
BOOTSTRAP_LOCK_DIR="${PERSIST_DIR}/bootstrap.lock"
BOOTSTRAP_LOCK_PID_FILE="${BOOTSTRAP_LOCK_DIR}/pid"
OUTPUT_MODE="${HAPPYCAPY_OUTPUT_MODE:-}"
if [ -z "$OUTPUT_MODE" ]; then
  if [ "${HAPPYCAPY_RECOVER_CHAIN:-0}" = "1" ]; then
    OUTPUT_MODE="short"
  else
    OUTPUT_MODE="full"
  fi
fi
WATCHDOG_MODE_RAW="$(printf '%s' "${HAPPYCAPY_WATCHDOG_MODE:-0}" | tr '[:upper:]' '[:lower:]')"
WATCHDOG_MODE=0
case "$WATCHDOG_MODE_RAW" in
  1|true|yes|on) WATCHDOG_MODE=1 ;;
esac
SKIP_CORE_INSTALL_RAW="$(printf '%s' "${HAPPYCAPY_SKIP_CORE_INSTALL:-}" | tr '[:upper:]' '[:lower:]')"
SKIP_CORE_INSTALL=0
case "$SKIP_CORE_INSTALL_RAW" in
  1|true|yes|on) SKIP_CORE_INSTALL=1 ;;
  0|false|no|off) SKIP_CORE_INSTALL=0 ;;
esac
# Watchdog worker is a steady-state maintainer. Core dependency install should
# happen in normal bootstrap/autorestore paths to avoid apt/dpkg lock races.
if [ "$WATCHDOG_MODE" -eq 1 ] && [ -z "${HAPPYCAPY_SKIP_CORE_INSTALL:-}" ]; then
  SKIP_CORE_INSTALL=1
fi
WATCHDOG_INTERVAL_RAW="${HAPPYCAPY_WATCHDOG_INTERVAL_SEC:-8}"
case "$WATCHDOG_INTERVAL_RAW" in
  ''|*[!0-9.]*)
    WATCHDOG_INTERVAL_SEC=8
    ;;
  *)
    WATCHDOG_INTERVAL_SEC="$WATCHDOG_INTERVAL_RAW"
    ;;
esac
HEARTBEAT_INTERVAL_RAW="${HAPPYCAPY_HEARTBEAT_INTERVAL_SEC:-300}"
case "$HEARTBEAT_INTERVAL_RAW" in
  ''|*[!0-9]*)
    HEARTBEAT_INTERVAL_SEC=300
    ;;
  *)
    HEARTBEAT_INTERVAL_SEC="$HEARTBEAT_INTERVAL_RAW"
    ;;
esac
if [ "$HEARTBEAT_INTERVAL_SEC" -lt 5 ] 2>/dev/null; then
  HEARTBEAT_INTERVAL_SEC=5
fi
HEARTBEAT_TIMEOUT_RAW="${HAPPYCAPY_HEARTBEAT_TIMEOUT_SEC:-4}"
case "$HEARTBEAT_TIMEOUT_RAW" in
  ''|*[!0-9]*)
    HEARTBEAT_TIMEOUT_SEC=4
    ;;
  *)
    HEARTBEAT_TIMEOUT_SEC="$HEARTBEAT_TIMEOUT_RAW"
    ;;
esac
if [ "$HEARTBEAT_TIMEOUT_SEC" -lt 2 ] 2>/dev/null; then
  HEARTBEAT_TIMEOUT_SEC=2
fi
WEBSOCKIFY_HEARTBEAT_RAW="${HAPPYCAPY_WEBSOCKIFY_HEARTBEAT_SEC:-25}"
case "$WEBSOCKIFY_HEARTBEAT_RAW" in
  ''|*[!0-9]*)
    WEBSOCKIFY_HEARTBEAT_SEC=25
    ;;
  *)
    WEBSOCKIFY_HEARTBEAT_SEC="$WEBSOCKIFY_HEARTBEAT_RAW"
    ;;
esac
if [ "$WEBSOCKIFY_HEARTBEAT_SEC" -lt 0 ] 2>/dev/null; then
  WEBSOCKIFY_HEARTBEAT_SEC=25
fi
if [ "$WEBSOCKIFY_HEARTBEAT_SEC" -gt 0 ] 2>/dev/null && [ "$WEBSOCKIFY_HEARTBEAT_SEC" -lt 5 ] 2>/dev/null; then
  WEBSOCKIFY_HEARTBEAT_SEC=5
fi
if [ "$WEBSOCKIFY_HEARTBEAT_SEC" -gt 300 ] 2>/dev/null; then
  WEBSOCKIFY_HEARTBEAT_SEC=300
fi
BOOTSTRAP_LOCK_WAIT_RAW="${HAPPYCAPY_BOOTSTRAP_LOCK_WAIT_SEC:-45}"
case "$BOOTSTRAP_LOCK_WAIT_RAW" in
  ''|*[!0-9]*)
    BOOTSTRAP_LOCK_WAIT_SEC=45
    ;;
  *)
    BOOTSTRAP_LOCK_WAIT_SEC="$BOOTSTRAP_LOCK_WAIT_RAW"
    ;;
esac
if [ "$BOOTSTRAP_LOCK_WAIT_SEC" -lt 5 ] 2>/dev/null; then
  BOOTSTRAP_LOCK_WAIT_SEC=5
fi
if [ "$BOOTSTRAP_LOCK_WAIT_SEC" -gt 240 ] 2>/dev/null; then
  BOOTSTRAP_LOCK_WAIT_SEC=240
fi
HEARTBEAT_LOG_PATH="${HAPPYCAPY_HEARTBEAT_LOG_PATH:-/tmp/happycapy-heartbeat.log}"
HEARTBEAT_EXTERNAL_KEEPALIVE_RAW="$(printf '%s' "${HAPPYCAPY_HEARTBEAT_EXTERNAL_KEEPALIVE:-1}" | tr '[:upper:]' '[:lower:]')"
HEARTBEAT_EXTERNAL_KEEPALIVE=0
case "$HEARTBEAT_EXTERNAL_KEEPALIVE_RAW" in
  1|true|yes|on) HEARTBEAT_EXTERNAL_KEEPALIVE=1 ;;
esac
AUTORESTORE_FORCE_REINSTALL_RAW="$(printf '%s' "${HAPPYCAPY_AUTORESTORE_FORCE_REINSTALL:-0}" | tr '[:upper:]' '[:lower:]')"
AUTORESTORE_FORCE_REINSTALL=0
case "$AUTORESTORE_FORCE_REINSTALL_RAW" in
  1|true|yes|on) AUTORESTORE_FORCE_REINSTALL=1 ;;
esac
AUTORESTORE_FORCE_INSTALL_ROUND=0
AUTORESTORE_FORCE_INSTALL_BOOT_ID=""
KEEPALIVE_MODE_RAW="$(printf '%s' "${HAPPYCAPY_KEEPALIVE_MODE:-vnc-browser}" | tr '[:upper:]' '[:lower:]')"
KEEPALIVE_MODE="vnc-browser"
case "$KEEPALIVE_MODE_RAW" in
  vnc-browser|vnc_browser|browser|vncbrowser) KEEPALIVE_MODE="vnc-browser" ;;
  *) KEEPALIVE_MODE="vnc-browser" ;;
esac
KEEPALIVE_INTERVAL_RAW="${HAPPYCAPY_KEEPALIVE_INTERVAL_SEC:-${HEARTBEAT_INTERVAL_SEC}}"
case "$KEEPALIVE_INTERVAL_RAW" in
  ''|*[!0-9]*)
    KEEPALIVE_INTERVAL_SEC="$HEARTBEAT_INTERVAL_SEC"
    ;;
  *)
    KEEPALIVE_INTERVAL_SEC="$KEEPALIVE_INTERVAL_RAW"
    ;;
esac
if [ "$KEEPALIVE_INTERVAL_SEC" -lt 30 ] 2>/dev/null; then
  KEEPALIVE_INTERVAL_SEC=30
fi
if [ "$KEEPALIVE_MODE" = "vnc-browser" ] && [ "$KEEPALIVE_INTERVAL_SEC" -lt 300 ] 2>/dev/null; then
  KEEPALIVE_INTERVAL_SEC=300
fi
KEEPALIVE_RECOVERY_INTERVAL_RAW="${HAPPYCAPY_KEEPALIVE_RECOVERY_INTERVAL_SEC:-30}"
case "$KEEPALIVE_RECOVERY_INTERVAL_RAW" in
  ''|*[!0-9]*)
    KEEPALIVE_RECOVERY_INTERVAL_SEC=30
    ;;
  *)
    KEEPALIVE_RECOVERY_INTERVAL_SEC="$KEEPALIVE_RECOVERY_INTERVAL_RAW"
    ;;
esac
if [ "$KEEPALIVE_RECOVERY_INTERVAL_SEC" -lt 5 ] 2>/dev/null; then
  KEEPALIVE_RECOVERY_INTERVAL_SEC=5
fi
if [ "$KEEPALIVE_RECOVERY_INTERVAL_SEC" -gt "$KEEPALIVE_INTERVAL_SEC" ] 2>/dev/null; then
  KEEPALIVE_RECOVERY_INTERVAL_SEC="$KEEPALIVE_INTERVAL_SEC"
fi
KEEPALIVE_HEALTH_CHECK_INTERVAL_RAW="${HAPPYCAPY_KEEPALIVE_HEALTH_CHECK_INTERVAL_SEC:-45}"
case "$KEEPALIVE_HEALTH_CHECK_INTERVAL_RAW" in
  ''|*[!0-9]*)
    KEEPALIVE_HEALTH_CHECK_INTERVAL_SEC=45
    ;;
  *)
    KEEPALIVE_HEALTH_CHECK_INTERVAL_SEC="$KEEPALIVE_HEALTH_CHECK_INTERVAL_RAW"
    ;;
esac
if [ "$KEEPALIVE_HEALTH_CHECK_INTERVAL_SEC" -lt 10 ] 2>/dev/null; then
  KEEPALIVE_HEALTH_CHECK_INTERVAL_SEC=10
fi
KEEPALIVE_UNHEALTHY_COOLDOWN_RAW="${HAPPYCAPY_KEEPALIVE_UNHEALTHY_COOLDOWN_SEC:-90}"
case "$KEEPALIVE_UNHEALTHY_COOLDOWN_RAW" in
  ''|*[!0-9]*)
    KEEPALIVE_UNHEALTHY_COOLDOWN_SEC=90
    ;;
  *)
    KEEPALIVE_UNHEALTHY_COOLDOWN_SEC="$KEEPALIVE_UNHEALTHY_COOLDOWN_RAW"
    ;;
esac
if [ "$KEEPALIVE_UNHEALTHY_COOLDOWN_SEC" -lt 20 ] 2>/dev/null; then
  KEEPALIVE_UNHEALTHY_COOLDOWN_SEC=20
fi
KEEPALIVE_BROWSER_RAW="$(printf '%s' "${HAPPYCAPY_KEEPALIVE_BROWSER:-chromium}" | tr '[:upper:]' '[:lower:]')"
KEEPALIVE_BROWSER="chromium"
case "$KEEPALIVE_BROWSER_RAW" in
  chromium|chromium-browser|chrome|google-chrome|google-chrome-stable) KEEPALIVE_BROWSER="chromium" ;;
  firefox) KEEPALIVE_BROWSER="firefox" ;;
esac
KEEPALIVE_BROWSER_VISIBLE_RAW="$(printf '%s' "${HAPPYCAPY_KEEPALIVE_BROWSER_VISIBLE:-1}" | tr '[:upper:]' '[:lower:]')"
KEEPALIVE_BROWSER_VISIBLE=0
case "$KEEPALIVE_BROWSER_VISIBLE_RAW" in
  1|true|yes|on) KEEPALIVE_BROWSER_VISIBLE=1 ;;
esac
KEEPALIVE_FORCE_REFRESH_RAW="$(printf '%s' "${HAPPYCAPY_KEEPALIVE_FORCE_REFRESH:-0}" | tr '[:upper:]' '[:lower:]')"
KEEPALIVE_FORCE_REFRESH=0
case "$KEEPALIVE_FORCE_REFRESH_RAW" in
  1|true|yes|on) KEEPALIVE_FORCE_REFRESH=1 ;;
esac
KEEPALIVE_FORCE_REFRESH_MODE_RAW="$(printf '%s' "${HAPPYCAPY_KEEPALIVE_FORCE_REFRESH_MODE:-http_touch}" | tr '[:upper:]' '[:lower:]')"
KEEPALIVE_FORCE_REFRESH_MODE="http_touch"
case "$KEEPALIVE_FORCE_REFRESH_MODE_RAW" in
  cdp_reload|visible_reload|tab_reload|reload)
    KEEPALIVE_FORCE_REFRESH_MODE="cdp_reload"
    ;;
  *)
    KEEPALIVE_FORCE_REFRESH_MODE="http_touch"
    ;;
esac
KEEPALIVE_VNC_PAGE_RAW="$(printf '%s' "${HAPPYCAPY_KEEPALIVE_VNC_PAGE:-vnc.html}" | tr '[:upper:]' '[:lower:]')"
KEEPALIVE_VNC_PAGE="vnc.html"
case "$KEEPALIVE_VNC_PAGE_RAW" in
  vnc.html|vnc|full|classic)
    KEEPALIVE_VNC_PAGE="vnc.html"
    ;;
  *)
    KEEPALIVE_VNC_PAGE="vnc_lite.html"
    ;;
esac
# Auto-detect active desktop display when not explicitly provided.
# Prefer x11vnc display (the one user actually sees via noVNC), then Xvfb.
KEEPALIVE_DISPLAY_AUTO=""
X11VNC_CMDLINE="$(ps -eo args= 2>/dev/null | grep -E '[x]11vnc' | head -n1 || true)"
if [ -n "$X11VNC_CMDLINE" ]; then
  KEEPALIVE_DISPLAY_AUTO="$(printf '%s\n' "$X11VNC_CMDLINE" | sed -n 's/.*-display[[:space:]]\+\(:[0-9][0-9]*\).*/\1/p' | head -n1)"
fi
if [ -z "$KEEPALIVE_DISPLAY_AUTO" ]; then
  XVFB_DISPLAYS="$(ps -eo args= 2>/dev/null | grep -E '[X]vfb[[:space:]]+:[0-9]+' | sed -n 's/.*[[:space:]]\(:[0-9][0-9]*\)\([[:space:]].*\|$\)/\1/p' || true)"
  if [ -n "$XVFB_DISPLAYS" ]; then
    if printf '%s\n' "$XVFB_DISPLAYS" | grep -qx ':99'; then
      KEEPALIVE_DISPLAY_AUTO=":99"
    else
      KEEPALIVE_DISPLAY_AUTO="$(printf '%s\n' "$XVFB_DISPLAYS" | head -n1)"
    fi
  fi
fi
KEEPALIVE_DISPLAY="${HAPPYCAPY_KEEPALIVE_DISPLAY:-${KEEPALIVE_DISPLAY_AUTO:-:1}}"
KEEPALIVE_WORKSPACE_RAW="${HAPPYCAPY_KEEPALIVE_WORKSPACE:-1}"
case "$KEEPALIVE_WORKSPACE_RAW" in
  -1)
    KEEPALIVE_WORKSPACE=-1
    ;;
  ''|*[!0-9]*)
    KEEPALIVE_WORKSPACE=1
    ;;
  *)
    KEEPALIVE_WORKSPACE="$KEEPALIVE_WORKSPACE_RAW"
    ;;
esac
WORK_WORKSPACE_RAW="${HAPPYCAPY_WORK_WORKSPACE:-0}"
case "$WORK_WORKSPACE_RAW" in
  ''|*[!0-9]*)
    WORK_WORKSPACE=0
    ;;
  *)
    WORK_WORKSPACE="$WORK_WORKSPACE_RAW"
    ;;
esac
if [ "$KEEPALIVE_WORKSPACE" -ge 0 ] 2>/dev/null && [ "$KEEPALIVE_WORKSPACE" -eq "$WORK_WORKSPACE" ] 2>/dev/null; then
  KEEPALIVE_WORKSPACE=$((WORK_WORKSPACE + 1))
fi
KEEPALIVE_CDP_PORT_RAW="${HAPPYCAPY_KEEPALIVE_CDP_PORT:-19222}"
case "$KEEPALIVE_CDP_PORT_RAW" in
  ''|*[!0-9]*)
    KEEPALIVE_CDP_PORT=19222
    ;;
  *)
    KEEPALIVE_CDP_PORT="$KEEPALIVE_CDP_PORT_RAW"
    ;;
esac
if [ "$KEEPALIVE_CDP_PORT" -lt 1024 ] 2>/dev/null || [ "$KEEPALIVE_CDP_PORT" -gt 65535 ] 2>/dev/null; then
  KEEPALIVE_CDP_PORT=19222
fi
DESKTOP_RESOLUTION="${HAPPYCAPY_DESKTOP_RESOLUTION:-1366x768x24}"
KEEPALIVE_PROFILE_DIR="${HAPPYCAPY_KEEPALIVE_PROFILE_DIR:-${PERSIST_DIR}/apps/keepalive/browser/profile}"
KEEPALIVE_REFRESH_MODE_PATH="${HAPPYCAPY_KEEPALIVE_REFRESH_MODE_PATH:-${PERSIST_DIR}/vnc-keeper-refresh-mode.txt}"
mkdir -p "$(dirname "$KEEPALIVE_VISIBLE_PATH")" >/dev/null 2>&1 || true
if [ ! -s "$KEEPALIVE_VISIBLE_PATH" ]; then
  printf '%s\n' "$KEEPALIVE_BROWSER_VISIBLE" > "$KEEPALIVE_VISIBLE_PATH" 2>/dev/null || true
fi
mkdir -p "$(dirname "$KEEPALIVE_PAGE_PATH")" >/dev/null 2>&1 || true
# Keep page target deterministic across restarts: default to vnc.html unless explicitly overridden.
printf '%s\n' "$KEEPALIVE_VNC_PAGE" > "$KEEPALIVE_PAGE_PATH" 2>/dev/null || true
mkdir -p "$(dirname "$KEEPALIVE_REFRESH_MODE_PATH")" >/dev/null 2>&1 || true
if [ ! -s "$KEEPALIVE_REFRESH_MODE_PATH" ]; then
  printf '%s\n' "$KEEPALIVE_FORCE_REFRESH_MODE" > "$KEEPALIVE_REFRESH_MODE_PATH" 2>/dev/null || true
fi
EXPORT_PORT_TIMEOUT_RAW="${HAPPYCAPY_EXPORT_PORT_TIMEOUT_SEC:-8}"
case "$EXPORT_PORT_TIMEOUT_RAW" in
  ''|*[!0-9.]*)
    EXPORT_PORT_TIMEOUT_SEC=8
    ;;
  *)
    EXPORT_PORT_TIMEOUT_SEC="$EXPORT_PORT_TIMEOUT_RAW"
    ;;
esac
if [ "${EXPORT_PORT_TIMEOUT_SEC%.*}" -lt 4 ] 2>/dev/null; then
  EXPORT_PORT_TIMEOUT_SEC=4
fi
UPLOAD_TIMEOUT_RAW="${HAPPYCAPY_UPLOAD_TIMEOUT_SEC:-8}"
case "$UPLOAD_TIMEOUT_RAW" in
  ''|*[!0-9.]*)
    UPLOAD_TIMEOUT_SEC=8
    ;;
  *)
    UPLOAD_TIMEOUT_SEC="$UPLOAD_TIMEOUT_RAW"
    ;;
esac
if [ "${UPLOAD_TIMEOUT_SEC%.*}" -lt 4 ] 2>/dev/null; then
  UPLOAD_TIMEOUT_SEC=4
fi

SUPERVISOR_MANAGED=0
CHISEL_OK=0
SSHD_OK=0
CONTROL_API_OK=0
CONTROL_API_REQUIRED=0
CONTROL_API_BIN=""
CONTROL_API_SCRIPT_UPDATED=0
AUTORESTORE_DOCKER=0
AUTORESTORE_BROWSER=""
AUTORESTORE_DESKTOP=0
AUTORESTORE_DESKTOP_ENV=0
# Default policy: restore app prerequisites/data only; persisted services are start-on-demand.
AUTORESTORE_START_SERVICES=0

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

emit_error() {
  local msg="$1"
  printf '{"status":"error","message":"%s"}\n' "$(json_escape "$msg")"
}

can_root() {
  if [ "$(id -u)" -eq 0 ]; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

run_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

is_port_listening() {
  local port="$1"
  ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$"
}

control_api_http_ready() {
  local body
  body="$(curl -sS -m 5 "http://127.0.0.1:${CONTROL_PORT}/status" 2>/dev/null || true)"
  if [ -z "$body" ]; then
    return 1
  fi
  printf '%s' "$body" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'
}

control_api_heartbeat() {
  local source="${1:-watchdog-local}"
  local body
  body="$(curl -sS -m "$HEARTBEAT_TIMEOUT_SEC" "http://127.0.0.1:${CONTROL_PORT}/heartbeat?source=${source}" 2>/dev/null || true)"
  if [ -z "$body" ]; then
    return 1
  fi
  printf '%s' "$body" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'
}

heartbeat_log() {
  local msg="$1"
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$msg" >> "$HEARTBEAT_LOG_PATH" 2>/dev/null || true
}

install_log() {
  local msg="$1"
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$msg" >> "$INSTALL_AUDIT_LOG_PATH" 2>/dev/null || true
}

process_log() {
  local msg="$1"
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$msg" >> "$PROCESS_AUDIT_LOG_PATH" 2>/dev/null || true
}

control_api_external_heartbeat() {
  local source="${1:-watchdog-external}"
  local control_url body
  if [ "$HEARTBEAT_EXTERNAL_KEEPALIVE" -ne 1 ]; then
    return 2
  fi
  control_url=""
  if [ -f "$CONTROL_API_URL_PATH" ]; then
    control_url="$(head -n1 "$CONTROL_API_URL_PATH" | tr -d '\r')"
  fi
  if [ -z "$control_url" ]; then
    return 2
  fi
  body="$(curl -sS -m "$HEARTBEAT_TIMEOUT_SEC" "${control_url%/}/heartbeat?source=${source}" 2>/dev/null || true)"
  if [ -z "$body" ]; then
    return 1
  fi
  if ! printf '%s' "$body" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
    return 1
  fi
  return 0
}

keepalive_log() {
  local msg="$1"
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$msg" >> "$KEEPALIVE_LOG_PATH" 2>/dev/null || true
}

process_count_by_pattern() {
  local pattern="$1"
  ps -eo args= 2>/dev/null | grep -E "$pattern" | grep -Ev 'grep -E' | wc -l | tr -d ' '
}

short_cmdline_for_pid() {
  local pid="$1"
  local cmdline
  case "$pid" in
    ''|*[!0-9]*)
      printf '%s\n' ""
      return 0
      ;;
  esac
  if [ "$pid" -le 0 ] 2>/dev/null; then
    printf '%s\n' ""
    return 0
  fi
  cmdline="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  cmdline="$(printf '%s' "$cmdline" | tr '\r\n' ' ' | sed -E 's/[[:space:]]+/ /g' | sed -E 's/^ //; s/ $//')"
  printf '%s\n' "$(printf '%s' "$cmdline" | cut -c1-320)"
}

keepalive_process_snapshot() {
  local stage="$1"
  local detail="${2:-}"
  local browser_pid browser_alive browser_cmd
  local p_ssh p_8080 p_ctl p_6080 p_5901
  local sshd_count chisel_count ctl_count browser_count
  local display_now visible_now
  browser_pid=0
  if [ -f "$KEEPALIVE_PID_FILE" ]; then
    browser_pid="$(cat "$KEEPALIVE_PID_FILE" 2>/dev/null | tr -dc '0-9')"
  fi
  [ -z "$browser_pid" ] && browser_pid=0
  browser_alive=0
  if [ "$browser_pid" -gt 0 ] 2>/dev/null && kill -0 "$browser_pid" >/dev/null 2>&1; then
    browser_alive=1
  fi
  browser_cmd="$(short_cmdline_for_pid "$browser_pid")"
  p_ssh=0
  p_8080=0
  p_ctl=0
  p_6080=0
  p_5901=0
  if is_port_listening "$SSH_PORT"; then p_ssh=1; fi
  if is_port_listening 8080; then p_8080=1; fi
  if is_port_listening "$CONTROL_PORT"; then p_ctl=1; fi
  if is_port_listening 6080; then p_6080=1; fi
  if is_port_listening 5901; then p_5901=1; fi
  sshd_count="$(process_count_by_pattern "[s]shd( |$|.*-p ${SSH_PORT})")"
  chisel_count="$(process_count_by_pattern "[c]hisel server .*--port 8080")"
  ctl_count="$(process_count_by_pattern "[n]ode .*happycapy-control-api.js")"
  browser_count="$(process_count_by_pattern "chromium|chromium-browser|google-chrome|google-chrome-stable|firefox")"
  display_now="$KEEPALIVE_DISPLAY"
  visible_now="$(keepalive_desired_visible)"
  keepalive_state_set last_process_snapshot_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  keepalive_state_set last_process_snapshot_stage "$stage"
  keepalive_state_set last_process_snapshot_detail "$detail"
  keepalive_state_set last_process_snapshot_browser_pid "$browser_pid"
  keepalive_state_set last_process_snapshot_browser_alive "$browser_alive"
  keepalive_state_set last_process_snapshot_browser_cmd "$browser_cmd"
  process_log "stage=${stage} detail=${detail} ssh_port=${SSH_PORT} ports{ssh=${p_ssh},chisel=${p_8080},control=${p_ctl},novnc=${p_6080},vnc=${p_5901}} procs{sshd=${sshd_count},chisel=${chisel_count},control=${ctl_count},browser=${browser_count}} keepalive{pid=${browser_pid},alive=${browser_alive},display=${display_now},visible_desired=${visible_now}} cmd=\"${browser_cmd}\""
}

keepalive_state_set() {
  local key="$1"
  local value="$2"
  local safe_key safe_value tmp
  safe_key="$(printf '%s' "$key" | tr -cd 'A-Za-z0-9_')"
  [ -n "$safe_key" ] || return 0
  safe_value="$(printf '%s' "$value" | tr '\r\n' ' ' | cut -c1-4096)"
  mkdir -p "$(dirname "$KEEPALIVE_STATE_PATH")" >/dev/null 2>&1 || true
  tmp="${KEEPALIVE_STATE_PATH}.tmp.$$"
  if [ -f "$KEEPALIVE_STATE_PATH" ]; then
    grep -Ev "^${safe_key}=" "$KEEPALIVE_STATE_PATH" > "$tmp" 2>/dev/null || true
  else
    : > "$tmp"
  fi
  printf '%s=%s\n' "$safe_key" "$safe_value" >> "$tmp"
  mv "$tmp" "$KEEPALIVE_STATE_PATH" >/dev/null 2>&1 || true
}

keepalive_state_get() {
  local key="$1"
  local default_value="${2:-}"
  local safe_key out
  safe_key="$(printf '%s' "$key" | tr -cd 'A-Za-z0-9_')"
  [ -n "$safe_key" ] || { printf '%s\n' "$default_value"; return 0; }
  out=""
  if [ -f "$KEEPALIVE_STATE_PATH" ]; then
    out="$(grep -E "^${safe_key}=" "$KEEPALIVE_STATE_PATH" 2>/dev/null | tail -n1 | cut -d= -f2- || true)"
  fi
  if [ -z "$out" ]; then
    printf '%s\n' "$default_value"
  else
    printf '%s\n' "$out"
  fi
}

keepalive_visible_parse() {
  local raw="${1:-}"
  case "$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) printf '1\n' ;;
    *) printf '0\n' ;;
  esac
}

keepalive_desired_visible() {
  if [ "$KEEPALIVE_MODE" = "vnc-browser" ]; then
    printf '1\n'
    return 0
  fi
  local raw default_v
  default_v="$KEEPALIVE_BROWSER_VISIBLE"
  raw=""
  if [ -f "$KEEPALIVE_VISIBLE_PATH" ]; then
    raw="$(cat "$KEEPALIVE_VISIBLE_PATH" 2>/dev/null | head -n1 || true)"
  fi
  if [ -z "$raw" ]; then
    raw="$default_v"
  fi
  keepalive_visible_parse "$raw"
}

keepalive_refresh_mode_parse() {
  local raw="${1:-}"
  case "$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')" in
    cdp_reload|visible_reload|tab_reload|reload) printf 'cdp_reload\n' ;;
    *) printf 'http_touch\n' ;;
  esac
}

keepalive_vnc_page_parse() {
  local raw="${1:-}"
  case "$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')" in
    vnc.html|vnc|full|classic) printf 'vnc.html\n' ;;
    *) printf 'vnc_lite.html\n' ;;
  esac
}

keepalive_vnc_page() {
  local raw
  raw=""
  if [ -f "$KEEPALIVE_PAGE_PATH" ]; then
    raw="$(cat "$KEEPALIVE_PAGE_PATH" 2>/dev/null | head -n1 || true)"
  fi
  if [ -z "$raw" ]; then
    raw="$KEEPALIVE_VNC_PAGE"
  fi
  keepalive_vnc_page_parse "$raw"
}

keepalive_vnc_url_with_params() {
  local vnc_base="$1"
  local vnc_page="$2"
  local root
  root="${vnc_base%/}"
  if [ -z "$root" ]; then
    return 1
  fi
  printf '%s/%s?autoconnect=1&reconnect=1&resize=remote&path=websockify\n' "$root" "$vnc_page"
}

keepalive_target_url() {
  local current_url current_base fresh_base vnc_base vnc_page
  current_url=""
  if [ -f "$KEEPALIVE_URL_PATH" ]; then
    current_url="$(cat "$KEEPALIVE_URL_PATH" 2>/dev/null | head -n1 || true)"
  fi
  current_base=""
  if [ -n "$current_url" ]; then
    current_base="${current_url%%\?*}"
    current_base="${current_base%/vnc.html}"
    current_base="${current_base%/vnc_lite.html}"
  fi
  fresh_base="$(query_preview_url_for_port 6080 || true)"
  if [ -n "$fresh_base" ]; then
    vnc_base="$fresh_base"
  else
    vnc_base="$current_base"
  fi
  if [ -z "$vnc_base" ]; then
    return 1
  fi
  vnc_page="$(keepalive_vnc_page)"
  keepalive_vnc_url_with_params "$vnc_base" "$vnc_page"
}

keepalive_force_refresh_mode() {
  local raw
  raw=""
  if [ -f "$KEEPALIVE_REFRESH_MODE_PATH" ]; then
    raw="$(cat "$KEEPALIVE_REFRESH_MODE_PATH" 2>/dev/null | head -n1 || true)"
  fi
  if [ -z "$raw" ]; then
    raw="$KEEPALIVE_FORCE_REFRESH_MODE"
  fi
  keepalive_refresh_mode_parse "$raw"
}

keepalive_request_tick() {
  mkdir -p "$(dirname "$KEEPALIVE_TRIGGER_PATH")" >/dev/null 2>&1 || true
  printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$KEEPALIVE_TRIGGER_PATH" 2>/dev/null || true
}

keepalive_state_mark_refresh() {
  local action="$1"
  local url="$2"
  local ok="${3:-1}"
  local count now url_b64 visible_now
  count="$(keepalive_state_get refresh_count 0)"
  case "$count" in
    ''|*[!0-9]*) count=0 ;;
  esac
  count=$((count + 1))
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  url_b64="$(printf '%s' "$url" | base64 | tr -d '\n' 2>/dev/null || true)"
  keepalive_state_set refresh_count "$count"
  keepalive_state_set last_refresh_at "$now"
  keepalive_state_set last_refresh_action "$action"
  keepalive_state_set last_refresh_ok "$ok"
  keepalive_state_set current_url_b64 "$url_b64"
  keepalive_state_set force_refresh_enabled "$KEEPALIVE_FORCE_REFRESH"
  keepalive_state_set force_refresh_mode "$(keepalive_force_refresh_mode)"
  keepalive_state_set vnc_page "$(keepalive_vnc_page)"
  visible_now="$(keepalive_desired_visible)"
  keepalive_state_set browser_visible "$visible_now"
  keepalive_state_set display "$KEEPALIVE_DISPLAY"
  keepalive_state_set workspace "$KEEPALIVE_WORKSPACE"
  keepalive_state_set last_refresh_url "$url"
  keepalive_log "vnc_browser_refresh_record action=${action} ok=${ok} url=${url}"
  keepalive_process_snapshot "refresh_${action}" "ok=${ok} url=${url}" || true
}

keepalive_state_mark_tick() {
  local url="$1"
  local now url_b64 visible_now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  url_b64="$(printf '%s' "$url" | base64 | tr -d '\n' 2>/dev/null || true)"
  keepalive_state_set last_tick_at "$now"
  keepalive_state_set current_url_b64 "$url_b64"
  keepalive_state_set mode "$KEEPALIVE_MODE"
  keepalive_state_set force_refresh_enabled "$KEEPALIVE_FORCE_REFRESH"
  keepalive_state_set force_refresh_mode "$(keepalive_force_refresh_mode)"
  keepalive_state_set vnc_page "$(keepalive_vnc_page)"
  visible_now="$(keepalive_desired_visible)"
  keepalive_state_set browser_visible "$visible_now"
  keepalive_state_set workspace "$KEEPALIVE_WORKSPACE"
}

keepalive_pick_window_for_pid() {
  local pid="$1"
  local candidate first_win win_name
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$pid" -gt 0 ] 2>/dev/null || return 1
  first_win=""
  while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    if [ -z "$first_win" ]; then
      first_win="$candidate"
    fi
    win_name="$(DISPLAY="$KEEPALIVE_DISPLAY" xdotool getwindowname "$candidate" 2>/dev/null || true)"
    if printf '%s' "$win_name" | grep -Ei 'novnc' >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done < <(DISPLAY="$KEEPALIVE_DISPLAY" xdotool search --pid "$pid" 2>/dev/null || true)
  if [ -n "$first_win" ]; then
    printf '%s\n' "$first_win"
    return 0
  fi
  return 1
}

ensure_keepalive_window_workspace() {
  local pid="$1"
  local target="$KEEPALIVE_WORKSPACE"
  local win_id current_ws desktop_count moved_any
  if [ "$target" -lt 0 ] 2>/dev/null; then
    return 0
  fi
  if ! command -v xdotool >/dev/null 2>&1 || ! command -v wmctrl >/dev/null 2>&1; then
    return 0
  fi
  moved_any=0
  if command -v xdotool >/dev/null 2>&1; then
    DISPLAY="$KEEPALIVE_DISPLAY" xdotool set_num_desktops $((target + 1)) >/dev/null 2>&1 || true
  fi
  desktop_count="$(DISPLAY="$KEEPALIVE_DISPLAY" wmctrl -d 2>/dev/null | wc -l | tr -d ' ' || true)"
  case "$desktop_count" in
    ''|*[!0-9]*) desktop_count=0 ;;
  esac
  if [ "$desktop_count" -le 0 ] 2>/dev/null; then
    desktop_count="$(DISPLAY="$KEEPALIVE_DISPLAY" xdotool get_num_desktops 2>/dev/null | head -n1 || true)"
    case "$desktop_count" in
      ''|*[!0-9]*) desktop_count=0 ;;
    esac
  fi
  if [ "$desktop_count" -le "$target" ] 2>/dev/null; then
    DISPLAY="$KEEPALIVE_DISPLAY" wmctrl -n $((target + 1)) >/dev/null 2>&1 || true
  fi
  while IFS= read -r win_id; do
    [ -n "$win_id" ] || continue
    moved_any=1
    current_ws="$(DISPLAY="$KEEPALIVE_DISPLAY" xdotool get_desktop_for_window "$win_id" 2>/dev/null || true)"
    case "$current_ws" in
      ''|*[!0-9-]*) current_ws=-1 ;;
    esac
    if [ "$current_ws" -ne "$target" ] 2>/dev/null; then
      DISPLAY="$KEEPALIVE_DISPLAY" wmctrl -i -r "$win_id" -t "$target" >/dev/null 2>&1 || true
      keepalive_log "vnc_browser_workspace_set pid=${pid} win=${win_id} from=${current_ws} to=${target}"
    fi
  done < <(DISPLAY="$KEEPALIVE_DISPLAY" xdotool search --pid "$pid" 2>/dev/null || true)
  if [ "$moved_any" -eq 1 ]; then
    return 0
  fi
  win_id="$(keepalive_pick_window_for_pid "$pid" || true)"
  [ -n "$win_id" ] || return 1
  current_ws="$(DISPLAY="$KEEPALIVE_DISPLAY" xdotool get_desktop_for_window "$win_id" 2>/dev/null || true)"
  case "$current_ws" in
    ''|*[!0-9-]*) current_ws=-1 ;;
  esac
  if [ "$current_ws" -ne "$target" ] 2>/dev/null; then
    DISPLAY="$KEEPALIVE_DISPLAY" wmctrl -i -r "$win_id" -t "$target" >/dev/null 2>&1 || true
    keepalive_log "vnc_browser_workspace_set pid=${pid} win=${win_id} from=${current_ws} to=${target}"
  fi
  return 0
}

keepalive_windows_on_target_workspace() {
  local pid="$1"
  local target="$2"
  local win_id current_ws found_any mapped_any
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  case "$target" in
    ''|*[!0-9-]*) return 1 ;;
  esac
  [ "$pid" -gt 0 ] 2>/dev/null || return 1
  found_any=0
  mapped_any=0
  while IFS= read -r win_id; do
    [ -n "$win_id" ] || continue
    found_any=1
    current_ws="$(DISPLAY="$KEEPALIVE_DISPLAY" xdotool get_desktop_for_window "$win_id" 2>/dev/null || true)"
    case "$current_ws" in
      ''|*[!0-9-]*) continue ;;
    esac
    if [ "$current_ws" -lt 0 ] 2>/dev/null; then
      continue
    fi
    mapped_any=1
    if [ "$current_ws" -ne "$target" ] 2>/dev/null; then
      return 1
    fi
  done < <(DISPLAY="$KEEPALIVE_DISPLAY" xdotool search --pid "$pid" 2>/dev/null || true)
  [ "$found_any" -eq 1 ] || return 1
  [ "$mapped_any" -eq 1 ] || return 1
  return 0
}

ensure_keepalive_window_workspace_retry() {
  local pid="$1"
  local max_try="${2:-40}"
  local sleep_sec="${3:-0.15}"
  local target="$KEEPALIVE_WORKSPACE"
  local n
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  case "$max_try" in
    ''|*[!0-9]*) max_try=40 ;;
  esac
  if [ "$max_try" -lt 1 ] 2>/dev/null; then
    max_try=1
  fi
  if [ "$target" -lt 0 ] 2>/dev/null; then
    return 0
  fi
  if ! command -v xdotool >/dev/null 2>&1 || ! command -v wmctrl >/dev/null 2>&1; then
    return 0
  fi
  n=1
  while [ "$n" -le "$max_try" ]; do
    ensure_keepalive_window_workspace "$pid" >/dev/null 2>&1 || true
    if keepalive_windows_on_target_workspace "$pid" "$target"; then
      if [ "$n" -gt 1 ] 2>/dev/null; then
        keepalive_log "vnc_browser_workspace_retry_ok pid=${pid} target=${target} try=${n}"
      fi
      return 0
    fi
    if [ "$n" -lt "$max_try" ] 2>/dev/null; then
      sleep "$sleep_sec"
    fi
    n=$((n + 1))
  done
  keepalive_log "vnc_browser_workspace_retry_timeout pid=${pid} target=${target} tries=${max_try}"
  return 1
}

find_sshd_bin() {
  if command -v sshd >/dev/null 2>&1; then
    command -v sshd
    return 0
  fi
  if [ -x /usr/sbin/sshd ]; then
    printf '%s\n' /usr/sbin/sshd
    return 0
  fi
  if [ -x /sbin/sshd ]; then
    printf '%s\n' /sbin/sshd
    return 0
  fi
  return 1
}

find_chisel_bin() {
  if command -v chisel >/dev/null 2>&1; then
    command -v chisel
    return 0
  fi
  if [ -x /home/node/bin/chisel ]; then
    printf '%s\n' /home/node/bin/chisel
    return 0
  fi
  if [ -x /usr/local/bin/chisel ]; then
    printf '%s\n' /usr/local/bin/chisel
    return 0
  fi
  if [ -x "$HOME/.local/bin/chisel" ]; then
    printf '%s\n' "$HOME/.local/bin/chisel"
    return 0
  fi
  return 1
}

find_browser_bin() {
  local preferred="$KEEPALIVE_BROWSER"
  local c
  for c in "$preferred" chromium chromium-browser google-chrome google-chrome-stable firefox; do
    [ -n "$c" ] || continue
    if command -v "$c" >/dev/null 2>&1; then
      command -v "$c"
      return 0
    fi
  done
  return 1
}

stop_keepalive_browser() {
  local pid
  pid=0
  if [ -f "$KEEPALIVE_PID_FILE" ]; then
    pid="$(cat "$KEEPALIVE_PID_FILE" 2>/dev/null | tr -dc '0-9')"
  fi
  [ -z "$pid" ] && pid=0
  if [ "$pid" -gt 0 ] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    sleep 0.2
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$KEEPALIVE_PID_FILE" >/dev/null 2>&1 || true
}

keepalive_browser_pid_running() {
  local pid
  pid=0
  if [ -f "$KEEPALIVE_PID_FILE" ]; then
    pid="$(cat "$KEEPALIVE_PID_FILE" 2>/dev/null | tr -dc '0-9')"
  fi
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$pid" -gt 0 ] 2>/dev/null || return 1
  kill -0 "$pid" >/dev/null 2>&1
}

kill_keepalive_profile_processes() {
  local line pid cmdline killed
  killed=0
  [ -n "$KEEPALIVE_PROFILE_DIR" ] || return 0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    pid="$(printf '%s' "$line" | awk '{print $1}')"
    case "$pid" in
      ''|*[!0-9]*) continue ;;
    esac
    cmdline="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')"
    case "$cmdline" in
      *"--user-data-dir=${KEEPALIVE_PROFILE_DIR}"*|*"${KEEPALIVE_PROFILE_DIR}"*)
        kill "$pid" >/dev/null 2>&1 || true
        killed=1
        ;;
    esac
  done < <(ps -eo pid=,args= 2>/dev/null || true)

  if [ "$killed" -eq 1 ]; then
    sleep 0.5
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      pid="$(printf '%s' "$line" | awk '{print $1}')"
      case "$pid" in
        ''|*[!0-9]*) continue ;;
      esac
      cmdline="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')"
      case "$cmdline" in
        *"--user-data-dir=${KEEPALIVE_PROFILE_DIR}"*|*"${KEEPALIVE_PROFILE_DIR}"*)
          if kill -0 "$pid" >/dev/null 2>&1; then
            kill -9 "$pid" >/dev/null 2>&1 || true
          fi
          ;;
      esac
    done < <(ps -eo pid=,args= 2>/dev/null || true)
  fi
}

kill_legacy_keepalive_profile_processes() {
  local legacy_profile line pid cmdline
  legacy_profile="${PERSIST_DIR}/apps/browser-keepalive/browser/profile"
  [ -n "$legacy_profile" ] || return 0
  if [ "$legacy_profile" = "$KEEPALIVE_PROFILE_DIR" ]; then
    return 0
  fi
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    pid="$(printf '%s' "$line" | awk '{print $1}')"
    case "$pid" in
      ''|*[!0-9]*) continue ;;
    esac
    cmdline="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')"
    case "$cmdline" in
      *"--user-data-dir=${legacy_profile}"*|*"${legacy_profile}"*)
        kill_pid_gracefully "$pid"
        ;;
    esac
  done < <(ps -eo pid=,args= 2>/dev/null || true)
}

cleanup_keepalive_profile_lock_files() {
  [ -n "$KEEPALIVE_PROFILE_DIR" ] || return 0
  rm -f \
    "$KEEPALIVE_PROFILE_DIR/SingletonLock" \
    "$KEEPALIVE_PROFILE_DIR/SingletonSocket" \
    "$KEEPALIVE_PROFILE_DIR/SingletonCookie" >/dev/null 2>&1 || true
}

cleanup_keepalive_runtime_conflicts() {
  kill_keepalive_profile_processes
  kill_legacy_keepalive_profile_processes
  cleanup_keepalive_profile_lock_files
}

kill_pid_gracefully() {
  local pid="$1"
  case "$pid" in
    ''|*[!0-9]*) return 0 ;;
  esac
  if [ "$pid" -le 1 ] 2>/dev/null; then
    return 0
  fi
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    return 0
  fi
  kill "$pid" >/dev/null 2>&1 || true
  sleep 0.2
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill -9 "$pid" >/dev/null 2>&1 || true
  fi
}

prune_keepalive_browser_duplicates() {
  local keep_pid="$1"
  local line pid cmdline pruned
  pruned=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    pid="$(printf '%s' "$line" | awk '{print $1}')"
    case "$pid" in
      ''|*[!0-9]*) continue ;;
    esac
    [ "$pid" -eq "$keep_pid" ] && continue
    cmdline="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')"
    case "$cmdline" in
      *"--remote-debugging-port=${KEEPALIVE_CDP_PORT}"* )
        case "$cmdline" in
          *"--user-data-dir=${KEEPALIVE_PROFILE_DIR}"*|*"${KEEPALIVE_PROFILE_DIR}"*)
            kill_pid_gracefully "$pid"
            pruned=1
            ;;
        esac
        ;;
    esac
  done < <(ps -eo pid=,args= 2>/dev/null || true)
  if [ "$pruned" -eq 1 ]; then
    keepalive_log "vnc_browser_prune_duplicates keep_pid=${keep_pid} profile=${KEEPALIVE_PROFILE_DIR}"
  fi
}

cleanup_legacy_desktop_duplicates() {
  local line pid cmdline pruned
  pruned=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    pid="$(printf '%s' "$line" | awk '{print $1}')"
    case "$pid" in
      ''|*[!0-9]*) continue ;;
    esac
    cmdline="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')"
    case "$cmdline" in
      *x11vnc*rfbport*5991*|*x11vnc*rfbport*5921*|*x11vnc*rfbport*5900*)
        kill_pid_gracefully "$pid"
        pruned=1
        ;;
      *websockify*6191*|*websockify*6366*|*websockify*localhost:5991*|*websockify*localhost:5921*)
        kill_pid_gracefully "$pid"
        pruned=1
        ;;
    esac
  done < <(ps -eo pid=,args= 2>/dev/null || true)
  if [ "$pruned" -eq 1 ]; then
    heartbeat_log "desktop_duplicate_pruned"
  fi
}

start_vnc_browser_keepalive() {
  local browser_bin="$1"
  local vnc_url="$2"
  local pid browser_name visible_try_ok desired_visible
  browser_name="$(basename "$browser_bin")"
  visible_try_ok=0
  desired_visible="$(keepalive_desired_visible)"
  mkdir -p "$(dirname "$KEEPALIVE_PID_FILE")" "$(dirname "$KEEPALIVE_URL_PATH")" "$KEEPALIVE_PROFILE_DIR"
  if [ "$desired_visible" -eq 1 ]; then
    cleanup_keepalive_runtime_conflicts
    if [ "$browser_name" = "firefox" ]; then
      nohup env DISPLAY="$KEEPALIVE_DISPLAY" "$browser_bin" --new-window "$vnc_url" >>"$KEEPALIVE_BROWSER_LOG" 2>&1 &
    else
      nohup env DISPLAY="$KEEPALIVE_DISPLAY" "$browser_bin" \
        --disable-gpu \
        --disable-dev-shm-usage \
        --disable-background-networking \
        --disable-renderer-backgrounding \
        --no-first-run \
        --no-default-browser-check \
        --window-size=1366,768 \
        --remote-debugging-port="$KEEPALIVE_CDP_PORT" \
        --user-data-dir="$KEEPALIVE_PROFILE_DIR" \
        --new-window \
        "$vnc_url" >>"$KEEPALIVE_BROWSER_LOG" 2>&1 &
    fi
    pid="$!"
    sleep 0.5
    if kill -0 "$pid" >/dev/null 2>&1; then
      visible_try_ok=1
      printf '%s\n' "$pid" > "$KEEPALIVE_PID_FILE"
      printf '%s\n' "$vnc_url" > "$KEEPALIVE_URL_PATH"
      ensure_keepalive_window_workspace_retry "$pid" 60 0.15 || true
      keepalive_state_mark_refresh "launch_visible" "$vnc_url" 1
      keepalive_log "vnc_browser_ok pid=${pid} browser=${browser_name} mode=visible display=${KEEPALIVE_DISPLAY} url=${vnc_url}"
      return 0
    fi
    cleanup_keepalive_runtime_conflicts
    if [ "$browser_name" = "firefox" ]; then
      nohup env DISPLAY="$KEEPALIVE_DISPLAY" "$browser_bin" --new-window "$vnc_url" >>"$KEEPALIVE_BROWSER_LOG" 2>&1 &
    else
      nohup env DISPLAY="$KEEPALIVE_DISPLAY" "$browser_bin" \
        --disable-gpu \
        --disable-dev-shm-usage \
        --disable-background-networking \
        --disable-renderer-backgrounding \
        --no-first-run \
        --no-default-browser-check \
        --window-size=1366,768 \
        --remote-debugging-port="$KEEPALIVE_CDP_PORT" \
        --user-data-dir="$KEEPALIVE_PROFILE_DIR" \
        --new-window \
        "$vnc_url" >>"$KEEPALIVE_BROWSER_LOG" 2>&1 &
    fi
    pid="$!"
    sleep 0.5
    if kill -0 "$pid" >/dev/null 2>&1; then
      visible_try_ok=1
      printf '%s\n' "$pid" > "$KEEPALIVE_PID_FILE"
      printf '%s\n' "$vnc_url" > "$KEEPALIVE_URL_PATH"
      ensure_keepalive_window_workspace_retry "$pid" 60 0.15 || true
      keepalive_state_mark_refresh "launch_visible_retry" "$vnc_url" 1
      keepalive_log "vnc_browser_ok pid=${pid} browser=${browser_name} mode=visible-retry display=${KEEPALIVE_DISPLAY} url=${vnc_url}"
      return 0
    fi
  fi
  if [ "$visible_try_ok" -eq 0 ]; then
    keepalive_state_mark_refresh "launch_visible_failed" "$vnc_url" 0
    keepalive_log "vnc_browser_visible_fail browser=${browser_name} display=${KEEPALIVE_DISPLAY} url=${vnc_url}"
    return 1
  fi
  keepalive_state_mark_refresh "launch_failed" "$vnc_url" 0
  keepalive_log "vnc_browser_fail browser=${browser_name} url=${vnc_url}"
  return 1
}

reload_vnc_browser_keepalive_url() {
  local browser_bin="$1"
  local vnc_url="$2"
  local browser_name enc_url
  browser_name="$(basename "$browser_bin")"
  if [ "$browser_name" = "firefox" ]; then
    nohup env DISPLAY="$KEEPALIVE_DISPLAY" "$browser_bin" --new-window "$vnc_url" >>"$KEEPALIVE_BROWSER_LOG" 2>&1 &
    printf '%s\n' "$vnc_url" > "$KEEPALIVE_URL_PATH"
    keepalive_state_mark_refresh "reload_firefox_cli" "$vnc_url" 1
    keepalive_log "vnc_browser_reload_ok browser=${browser_name} mode=firefox_cli url=${vnc_url}"
    dedupe_vnc_browser_tabs "$vnc_url" || true
    return 0
  fi
  enc_url=""
  close_vnc_browser_tabs "$vnc_url" || true
  if command -v python3 >/dev/null 2>&1; then
    enc_url="$(python3 - "$vnc_url" <<'PY'
import sys, urllib.parse
u = sys.argv[1] if len(sys.argv) > 1 else ""
print(urllib.parse.quote(u, safe=":/?&=%#"))
PY
)"
  fi
  [ -z "$enc_url" ] && enc_url="$vnc_url"
  if curl -fsS -m 4 -X PUT "http://127.0.0.1:${KEEPALIVE_CDP_PORT}/json/new?${enc_url}" >/dev/null 2>&1; then
    printf '%s\n' "$vnc_url" > "$KEEPALIVE_URL_PATH"
    keepalive_state_mark_refresh "reload_cdp_new_tab" "$vnc_url" 1
    keepalive_log "vnc_browser_reload_ok browser=${browser_name} mode=cdp_new_tab url=${vnc_url}"
    dedupe_vnc_browser_tabs "$vnc_url" || true
    return 0
  fi
  nohup env DISPLAY="$KEEPALIVE_DISPLAY" "$browser_bin" --new-window "$vnc_url" >>"$KEEPALIVE_BROWSER_LOG" 2>&1 &
  sleep 0.3
  printf '%s\n' "$vnc_url" > "$KEEPALIVE_URL_PATH"
  keepalive_state_mark_refresh "reload_cli_fallback" "$vnc_url" 1
  keepalive_log "vnc_browser_reload_ok browser=${browser_name} mode=cli_fallback url=${vnc_url}"
  dedupe_vnc_browser_tabs "$vnc_url" || true
  return 0
}

close_vnc_browser_tabs() {
  local vnc_url="$1"
  local vnc_base list ids id
  vnc_base="${vnc_url%%\?*}"
  [ -n "$vnc_base" ] || return 0
  list="$(curl -fsS -m 4 "http://127.0.0.1:${KEEPALIVE_CDP_PORT}/json/list" 2>/dev/null || true)"
  [ -n "$list" ] || return 0
  if command -v python3 >/dev/null 2>&1; then
    ids="$(
      printf '%s' "$list" | python3 - "$vnc_base" <<'PY'
import json
import sys

base = sys.argv[1] if len(sys.argv) > 1 else ""
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except Exception:
    data = []
if isinstance(data, dict):
    data = [data]
for item in data:
    if not isinstance(item, dict):
        continue
    item_id = str(item.get("id", "") or "").strip()
    item_type = str(item.get("type", "") or "").strip().lower()
    item_url = str(item.get("url", "") or "").strip()
    if item_type and item_type != "page":
        continue
    # Keepalive browser uses dedicated profile. Enforce single-tab model:
    # collect every page/typeless tab id and close all of them before opening target URL.
    if item_id:
        print(item_id)
PY
    )"
  else
    ids=""
  fi
  for id in $ids; do
    curl -fsS -m 2 "http://127.0.0.1:${KEEPALIVE_CDP_PORT}/json/close/${id}" >/dev/null 2>&1 || true
  done
  return 0
}

dedupe_vnc_browser_tabs() {
  local vnc_url="$1"
  local result closed
  [ -n "$vnc_url" ] || return 0
  if ! command -v python3 >/dev/null 2>&1; then
    return 0
  fi
  result="$(
    python3 - "$vnc_url" "$KEEPALIVE_CDP_PORT" <<'PY'
import json
import sys
import urllib.request

target_url = sys.argv[1] if len(sys.argv) > 1 else ""
port = sys.argv[2] if len(sys.argv) > 2 else "19222"
base = target_url.split("?", 1)[0] if target_url else ""
out = {"before": 0, "after": 0, "closed": 0, "kept": ""}
if not base:
    print(json.dumps(out, ensure_ascii=False))
    raise SystemExit(0)
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=4) as resp:
        raw = resp.read().decode("utf-8", "ignore")
    data = json.loads(raw)
except Exception:
    print(json.dumps(out, ensure_ascii=False))
    raise SystemExit(0)
if isinstance(data, dict):
    data = [data]
tabs = []
for item in data:
    if not isinstance(item, dict):
        continue
    tid = str(item.get("id", "") or "").strip()
    ttype = str(item.get("type", "") or "").strip().lower()
    url = str(item.get("url", "") or "").strip()
    if ttype and ttype != "page":
        continue
    # Keepalive browser uses dedicated profile. Consider every page/typeless tab
    # as dedupe candidate so stale Google/new-tab/error tabs cannot accumulate.
    if tid:
        tabs.append((tid, url))
out["before"] = len(tabs)
if len(tabs) <= 1:
    out["after"] = len(tabs)
    out["kept"] = tabs[0][0] if tabs else ""
    print(json.dumps(out, ensure_ascii=False))
    raise SystemExit(0)
keep = ""
for tid, url in tabs:
    if url == target_url:
        keep = tid
        break
if not keep:
    for tid, url in tabs:
        if "reconnect=1" in url and "path=websockify" in url:
            keep = tid
            break
if not keep:
    for tid, url in tabs:
        if not (
            url.startswith("chrome-error://")
            or url in ("about:blank", "chrome://newtab/", "chrome://new-tab-page/")
        ):
            keep = tid
            break
if not keep:
    keep = tabs[-1][0]
closed = 0
for tid, _ in tabs:
    if tid == keep:
        continue
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/json/close/{tid}", timeout=3).read()
        closed += 1
    except Exception:
        pass
out["closed"] = closed
out["after"] = max(0, len(tabs) - closed)
out["kept"] = keep
print(json.dumps(out, ensure_ascii=False))
PY
  )"
  closed="$(printf '%s' "$result" | sed -n 's/.*"closed":[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1)"
  case "$closed" in
    ''|*[!0-9]*) closed=0 ;;
  esac
  if [ "$closed" -gt 0 ] 2>/dev/null; then
    keepalive_log "vnc_browser_tab_dedup ${result}"
  fi
  return 0
}

visible_vnc_window_reload() {
  local vnc_url="$1"
  local win_id pid_now reload_url browser_bin
  pid_now="$(cat "$KEEPALIVE_PID_FILE" 2>/dev/null | tr -dc '0-9' || true)"
  [ -n "$pid_now" ] || pid_now=0
  if ! command -v xdotool >/dev/null 2>&1; then
    keepalive_log "vnc_browser_force_refresh_skip reason=xdotool_missing mode=visible_ctrl_r url=${vnc_url}"
    return 1
  fi
  activate_vnc_browser_tab "$vnc_url" || true
  ensure_keepalive_window_workspace_retry "$pid_now" 24 0.12 || true
  win_id="$(keepalive_pick_window_for_pid "$pid_now" || true)"
  if [ -z "$win_id" ]; then
    # Do not fallback to generic noVNC/chromium windows; that can touch user's work browser.
    keepalive_log "vnc_browser_force_refresh_skip reason=no_window_for_keepalive_pid mode=visible_ctrl_r pid=${pid_now} display=${KEEPALIVE_DISPLAY} url=${vnc_url}"
    return 1
  fi
  reload_url="$vnc_url"
  # Prefer CDP URL navigation first (deterministic exact URL, avoids omnibox search redirects).
  browser_bin="$(find_browser_bin || true)"
  if [ -n "$browser_bin" ] \
    && reload_vnc_browser_keepalive_url "$browser_bin" "$vnc_url" \
    && activate_vnc_browser_tab "$vnc_url"; then
    if verify_vnc_browser_refresh_health "$vnc_url"; then
      keepalive_state_mark_refresh "visible_cdp_new_tab" "$vnc_url" 1
      dedupe_vnc_browser_tabs "$vnc_url" || true
      keepalive_log "vnc_browser_force_refresh_ok pid=${pid_now} browser=$(basename "$browser_bin") mode=visible_cdp_new_tab win=${win_id} url=${vnc_url}"
      return 0
    fi
    keepalive_log "vnc_browser_force_refresh_unhealthy pid=${pid_now} browser=$(basename "$browser_bin") mode=visible_cdp_new_tab win=${win_id} url=${vnc_url}"
  fi
  # Fallback to explicit omnibox URL entry when CDP path is unavailable.
  # Use Ctrl+A + Backspace to avoid partial text causing Google search.
  if DISPLAY="$KEEPALIVE_DISPLAY" xdotool key --window "$win_id" --clearmodifiers ctrl+1 >/dev/null 2>&1 \
    && DISPLAY="$KEEPALIVE_DISPLAY" xdotool key --window "$win_id" --clearmodifiers ctrl+l >/dev/null 2>&1 \
    && DISPLAY="$KEEPALIVE_DISPLAY" xdotool key --window "$win_id" --clearmodifiers ctrl+a >/dev/null 2>&1 \
    && DISPLAY="$KEEPALIVE_DISPLAY" xdotool key --window "$win_id" BackSpace >/dev/null 2>&1 \
    && DISPLAY="$KEEPALIVE_DISPLAY" xdotool type --window "$win_id" --delay 1 -- "$reload_url" >/dev/null 2>&1 \
    && DISPLAY="$KEEPALIVE_DISPLAY" xdotool key --window "$win_id" Return >/dev/null 2>&1; then
    if verify_vnc_browser_refresh_health "$vnc_url"; then
      keepalive_state_mark_refresh "visible_first_tab_url_enter" "$vnc_url" 1
      dedupe_vnc_browser_tabs "$vnc_url" || true
      keepalive_log "vnc_browser_force_refresh_ok pid=${pid_now} browser=chromium mode=visible_first_tab_url_enter win=${win_id} url=${vnc_url}"
      return 0
    fi
    keepalive_log "vnc_browser_force_refresh_unhealthy pid=${pid_now} browser=chromium mode=visible_first_tab_url_enter win=${win_id} url=${vnc_url}"
  fi
  if DISPLAY="$KEEPALIVE_DISPLAY" xdotool key --window "$win_id" --clearmodifiers ctrl+1 >/dev/null 2>&1 \
    && DISPLAY="$KEEPALIVE_DISPLAY" xdotool key --window "$win_id" --clearmodifiers ctrl+r >/dev/null 2>&1; then
    if verify_vnc_browser_refresh_health "$vnc_url"; then
      keepalive_state_mark_refresh "visible_first_tab_ctrl_r_fallback" "$vnc_url" 1
      dedupe_vnc_browser_tabs "$vnc_url" || true
      keepalive_log "vnc_browser_force_refresh_ok pid=${pid_now} browser=chromium mode=visible_first_tab_ctrl_r_fallback win=${win_id} url=${vnc_url}"
      return 0
    fi
    keepalive_log "vnc_browser_force_refresh_unhealthy pid=${pid_now} browser=chromium mode=visible_first_tab_ctrl_r_fallback win=${win_id} url=${vnc_url}"
  fi
  keepalive_state_mark_refresh "visible_refresh_failed" "$vnc_url" 0
  keepalive_log "vnc_browser_force_refresh_failed pid=${pid_now} browser=chromium mode=visible_refresh_failed win=${win_id} display=${KEEPALIVE_DISPLAY} url=${vnc_url}"
  return 1
}

verify_vnc_browser_refresh_health() {
  local vnc_url="$1"
  local browser_bin tab_rc content_rc now url_b64
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  url_b64="$(printf '%s' "$vnc_url" | base64 | tr -d '\n' 2>/dev/null || true)"
  keepalive_state_set last_health_probe_at "$now"
  keepalive_state_set last_health_probe_url_b64 "$url_b64"
  keepalive_state_set last_health_probe_url "$vnc_url"
  browser_bin="$(find_browser_bin || true)"
  if [ -n "$browser_bin" ]; then
    vnc_browser_tab_state "$browser_bin" "$vnc_url"
    tab_rc=$?
    case "$tab_rc" in
      0)
        keepalive_state_set last_health_probe_ok 1
        keepalive_state_set last_health_probe_mode tab_state
        keepalive_state_set last_health_probe_reason healthy_tab
        keepalive_log "vnc_browser_health_ok mode=tab_state browser=$(basename "$browser_bin") url=${vnc_url}"
        return 0
        ;;
      2)
        # CDP tab metadata unavailable: inspect real DOM content via DevTools Runtime.
        vnc_browser_content_state "$vnc_url"
        content_rc=$?
        if [ "$content_rc" -eq 0 ]; then
          keepalive_state_set last_health_probe_ok 1
          keepalive_state_set last_health_probe_mode dom_content
          keepalive_state_set last_health_probe_reason healthy_dom
          keepalive_log "vnc_browser_health_ok mode=dom_content browser=$(basename "$browser_bin") url=${vnc_url}"
          return 0
        fi
        if [ "$content_rc" -eq 1 ]; then
          keepalive_state_set last_health_probe_ok 0
          keepalive_state_set last_health_probe_mode dom_content
          keepalive_state_set last_health_probe_reason crash_or_error_page
          keepalive_log "vnc_browser_dom_unhealthy url=${vnc_url}"
          keepalive_process_snapshot "health_dom_unhealthy" "url=${vnc_url}" || true
          return 1
        fi
        keepalive_state_set last_health_probe_ok 0
        keepalive_state_set last_health_probe_mode dom_content
        keepalive_state_set last_health_probe_reason dom_probe_unavailable
        keepalive_log "vnc_browser_dom_probe_unavailable url=${vnc_url}"
        return 1
        ;;
      1)
        keepalive_state_set last_health_probe_ok 0
        keepalive_state_set last_health_probe_mode tab_state
        keepalive_state_set last_health_probe_reason error_tab_detected
        keepalive_log "vnc_browser_health_bad mode=tab_state browser=$(basename "$browser_bin") url=${vnc_url}"
        keepalive_process_snapshot "health_tab_bad" "url=${vnc_url}" || true
        return 1
        ;;
    esac
  else
    keepalive_state_set last_health_probe_ok 0
    keepalive_state_set last_health_probe_mode none
    keepalive_state_set last_health_probe_reason no_browser_bin
    keepalive_log "vnc_browser_health_skip reason=no_browser_bin url=${vnc_url}"
  fi
  keepalive_state_set last_health_probe_ok 0
  keepalive_state_set last_health_probe_mode unknown
  keepalive_state_set last_health_probe_reason wait_next_tick
  if [ "$KEEPALIVE_INTERVAL_SEC" -gt 0 ]; then
    keepalive_log "vnc_browser_health_unready action=wait_next_tick interval_sec=${KEEPALIVE_INTERVAL_SEC} url=${vnc_url}"
  else
    keepalive_log "vnc_browser_health_unready action=wait_next_tick url=${vnc_url}"
  fi
  return 1
}

vnc_browser_content_state() {
  local vnc_url="$1"
  local vnc_base rc
  [ -n "$vnc_url" ] || return 2
  vnc_base="${vnc_url%%\?*}"
  [ -n "$vnc_base" ] || return 2
  if ! command -v node >/dev/null 2>&1; then
    return 2
  fi
  rc="$(
    node - "$KEEPALIVE_CDP_PORT" "$vnc_base" <<'NODE' 2>/dev/null || true
const port = String(process.argv[2] || "").trim();
const base = String(process.argv[3] || "").trim().toLowerCase();
if (!port || !base || typeof fetch !== "function" || typeof WebSocket !== "function") {
  console.log("2");
  process.exit(0);
}
const BAD_WORDS = [
  "something went wrong while displaying this webpage",
  "aw, snap",
  "site can’t be reached",
  "site can't be reached",
  "this page isn’t working",
  "this page isn't working",
  "err_",
  "chrome-error://",
  "页面崩溃",
  "无法显示此网页",
  "出错了",
];
function isBad(text) {
  const t = String(text || "").toLowerCase();
  if (!t) return false;
  return BAD_WORDS.some((w) => t.includes(w));
}
function done(code) {
  console.log(String(code));
  process.exit(0);
}
(async () => {
  let tabs = [];
  try {
    const r = await fetch(`http://127.0.0.1:${port}/json/list`, { method: "GET" });
    tabs = await r.json();
  } catch {
    done(2);
    return;
  }
  if (!Array.isArray(tabs)) tabs = [tabs];
  let tab = null;
  for (const t of tabs) {
    if (!t || typeof t !== "object") continue;
    const u = String(t.url || "").toLowerCase();
    if (u.startsWith(base) && t.webSocketDebuggerUrl) {
      tab = t;
      break;
    }
  }
  if (!tab || !tab.webSocketDebuggerUrl) {
    done(2);
    return;
  }
  let resolved = false;
  const ws = new WebSocket(String(tab.webSocketDebuggerUrl));
  const timer = setTimeout(() => {
    if (resolved) return;
    resolved = true;
    try { ws.close(); } catch {}
    done(2);
  }, 4500);
  ws.onopen = () => {
    const expression = `(() => {
      const body = (document && document.body && document.body.innerText) ? document.body.innerText : "";
      return JSON.stringify({
        title: document && document.title ? document.title : "",
        url: (typeof location !== "undefined" && location && location.href) ? location.href : "",
        body: String(body || "").slice(0, 3000)
      });
    })()`;
    ws.send(JSON.stringify({
      id: 1,
      method: "Runtime.evaluate",
      params: { expression, returnByValue: true },
    }));
  };
  ws.onmessage = (ev) => {
    if (resolved) return;
    let msg = null;
    try { msg = JSON.parse(String(ev.data || "")); } catch {}
    if (!msg || msg.id !== 1) return;
    resolved = true;
    clearTimeout(timer);
    try { ws.close(); } catch {}
    let payload = {};
    try {
      const value = (((msg || {}).result || {}).result || {}).value;
      payload = JSON.parse(String(value || "{}"));
    } catch {
      done(2);
      return;
    }
    const title = String(payload.title || "");
    const url = String(payload.url || "");
    const body = String(payload.body || "");
    if (String(url).toLowerCase().startsWith("chrome-error://")) {
      done(1);
      return;
    }
    if (isBad(title) || isBad(body)) {
      done(1);
      return;
    }
    // Require noVNC markers in DOM/title for positive success.
    const comb = `${title}\n${body}`.toLowerCase();
    if (comb.includes("novnc") || comb.includes("websockify")) {
      done(0);
      return;
    }
    done(2);
  };
  ws.onerror = () => {
    if (resolved) return;
    resolved = true;
    clearTimeout(timer);
    try { ws.close(); } catch {}
    done(2);
  };
  ws.onclose = () => {
    if (resolved) return;
    resolved = true;
    clearTimeout(timer);
    done(2);
  };
})().catch(() => done(2));
NODE
  )"
  case "$rc" in
    0) return 0 ;;
    1) return 1 ;;
    *) return 2 ;;
  esac
}

activate_vnc_browser_tab() {
  local vnc_url="$1"
  local vnc_base list tab_id
  [ -n "$vnc_url" ] || return 1
  vnc_base="${vnc_url%%\?*}"
  [ -n "$vnc_base" ] || return 1
  if ! command -v python3 >/dev/null 2>&1; then
    return 1
  fi
  list="$(curl -fsS -m 4 "http://127.0.0.1:${KEEPALIVE_CDP_PORT}/json/list" 2>/dev/null || true)"
  [ -n "$list" ] || return 1
  tab_id="$(
    printf '%s' "$list" | python3 - "$vnc_url" "$vnc_base" <<'PY'
import json
import sys

target_url = sys.argv[1] if len(sys.argv) > 1 else ""
target_base = sys.argv[2] if len(sys.argv) > 2 else ""
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except Exception:
    data = []
if isinstance(data, dict):
    data = [data]
tabs = []
for item in data:
    if not isinstance(item, dict):
        continue
    tid = str(item.get("id", "") or "").strip()
    url = str(item.get("url", "") or "").strip()
    if not tid or not url:
        continue
    if target_base and url.startswith(target_base):
        tabs.append((tid, url))
if not tabs:
    raise SystemExit(0)
for tid, url in tabs:
    if url == target_url:
        print(tid)
        raise SystemExit(0)
for tid, url in tabs:
    if "reconnect=1" in url and "path=websockify" in url:
        print(tid)
        raise SystemExit(0)
print(tabs[-1][0])
PY
  )"
  [ -n "$tab_id" ] || return 1
  curl -fsS -m 3 "http://127.0.0.1:${KEEPALIVE_CDP_PORT}/json/activate/${tab_id}" >/dev/null 2>&1 || return 1
  return 0
}

vnc_browser_tab_state() {
  local browser_bin="$1"
  local vnc_url="$2"
  local browser_name vnc_base list rc
  browser_name="$(basename "$browser_bin")"
  vnc_base="${vnc_url%%\?*}"
  if [ -z "$vnc_base" ]; then
    return 2
  fi
  case "$browser_name" in
    firefox)
      return 2
      ;;
  esac
  list="$(curl -fsS -m 4 "http://127.0.0.1:${KEEPALIVE_CDP_PORT}/json/list" 2>/dev/null || true)"
  if [ -z "$list" ]; then
    return 2
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    if printf '%s' "$list" | grep -F "$vnc_base" >/dev/null 2>&1; then
      return 0
    fi
    return 1
  fi
  rc="$(printf '%s' "$list" | python3 - "$vnc_base" <<'PY'
import json
import sys

base = (sys.argv[1] if len(sys.argv) > 1 else "").strip()
if not base:
    print("2")
    raise SystemExit(0)
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except Exception:
    print("2")
    raise SystemExit(0)
if isinstance(data, dict):
    data = [data]
if not isinstance(data, list):
    print("2")
    raise SystemExit(0)

error_words = (
    "something went wrong while displaying this webpage",
    "aw, snap",
    "site can’t be reached",
    "site can't be reached",
    "this page isn’t working",
    "this page isn't working",
    "err_",
    "chrome-error://",
)

matched = 0
bad = 0
for item in data:
    if not isinstance(item, dict):
        continue
    url = str(item.get("url", "") or "").strip()
    title = str(item.get("title", "") or "").strip()
    if not url.startswith(base):
        continue
    matched += 1
    low_url = url.lower()
    low_title = title.lower()
    if low_url.startswith("chrome-error://"):
        bad += 1
        continue
    if any(word in low_title for word in error_words):
        bad += 1
        continue
    print("0")
    raise SystemExit(0)

if matched == 0:
    print("1")
elif bad >= matched:
    print("1")
else:
    # Mixed state: at least one non-error candidate exists.
    print("0")
PY
  )"
  case "$rc" in
    0) return 0 ;;
    1) return 1 ;;
    *) return 2 ;;
  esac
}

ensure_vnc_browser_tab() {
  local browser_bin="$1"
  local vnc_url="$2"
  local browser_name tab_rc content_rc
  browser_name="$(basename "$browser_bin")"
  vnc_browser_tab_state "$browser_bin" "$vnc_url"
  tab_rc=$?
  if [ "$tab_rc" -eq 0 ]; then
    return 0
  fi
  if [ "$tab_rc" -eq 2 ]; then
    vnc_browser_content_state "$vnc_url"
    content_rc=$?
    if [ "$content_rc" -eq 0 ]; then
      keepalive_log "vnc_browser_tab_unknown_dom_ok browser=${browser_name} reason=cdp_list_unknown"
      return 0
    fi
    if reload_vnc_browser_keepalive_url "$browser_bin" "$vnc_url"; then
      keepalive_log "vnc_browser_tab_unknown_rehydrated browser=${browser_name} reason=dom_unhealthy_or_unknown url=${vnc_url}"
      return 0
    fi
    keepalive_log "vnc_browser_tab_unknown_restore_failed browser=${browser_name} reason=dom_unhealthy_or_unknown url=${vnc_url}"
    return 1
  fi
  if reload_vnc_browser_keepalive_url "$browser_bin" "$vnc_url"; then
    keepalive_log "vnc_browser_tab_restored browser=${browser_name} url=${vnc_url}"
    return 0
  fi
  keepalive_log "vnc_browser_tab_restore_failed browser=${browser_name} url=${vnc_url}"
  return 1
}

keepalive_pid_is_headless() {
  local pid="$1"
  local args
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  if [ "$pid" -le 0 ] 2>/dev/null; then
    return 1
  fi
  args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  if [ -z "$args" ]; then
    return 1
  fi
  if printf '%s' "$args" | grep -Eq -- '(^|[[:space:]])--headless(=new)?([[:space:]]|$)'; then
    return 0
  fi
  return 1
}

keepalive_pid_display() {
  local pid="$1"
  local display_val
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  if [ "$pid" -le 0 ] 2>/dev/null; then
    return 1
  fi
  display_val=""
  if [ -r "/proc/$pid/environ" ]; then
    display_val="$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed -n 's/^DISPLAY=//p' | head -n1 || true)"
  fi
  if [ -n "$display_val" ]; then
    printf '%s\n' "$display_val"
    return 0
  fi
  return 1
}

vnc_browser_keepalive_tick() {
  local force_refresh_now vnc_base vnc_url vnc_page browser_bin current_pid current_url desired_visible pid_display current_base fresh_base current_headless
  force_refresh_now=0
  case "${1:-0}" in
    1|true|yes|on) force_refresh_now=1 ;;
  esac
  current_pid=0
  if [ -f "$KEEPALIVE_PID_FILE" ]; then
    current_pid="$(cat "$KEEPALIVE_PID_FILE" 2>/dev/null | tr -dc '0-9')"
  fi
  [ -z "$current_pid" ] && current_pid=0
  current_url=""
  if [ -f "$KEEPALIVE_URL_PATH" ]; then
    current_url="$(cat "$KEEPALIVE_URL_PATH" 2>/dev/null | head -n1 || true)"
  fi
  vnc_base=""
  current_base=""
  if [ -n "$current_url" ]; then
    current_base="${current_url%%\?*}"
    current_base="${current_base%/vnc.html}"
    current_base="${current_base%/vnc_lite.html}"
  fi
  fresh_base="$(query_preview_url_for_port 6080 || true)"
  if [ -n "$fresh_base" ]; then
    vnc_base="$fresh_base"
    if [ -n "$current_base" ] && [ "$current_base" != "$fresh_base" ]; then
      keepalive_log "vnc_browser_url_rotated old=${current_base} new=${fresh_base}"
    fi
  elif [ -n "$current_base" ]; then
    vnc_base="$current_base"
  fi
  if [ -z "$vnc_base" ]; then
    keepalive_log "vnc_browser_skip reason=no_vnc_url"
    keepalive_process_snapshot "tick_skip_no_vnc_url" "current_url=${current_url}" || true
    return 1
  fi
  vnc_page="$(keepalive_vnc_page)"
  vnc_url="$(keepalive_vnc_url_with_params "$vnc_base" "$vnc_page" || true)"
  if [ -z "$vnc_url" ]; then
    vnc_url="${vnc_base%/}/${vnc_page}?autoconnect=1&reconnect=1&resize=remote&path=websockify"
  fi
  browser_bin="$(find_browser_bin || true)"
  if [ -z "$browser_bin" ]; then
    keepalive_log "vnc_browser_skip reason=no_browser_bin"
    keepalive_process_snapshot "tick_skip_no_browser" "url=${vnc_url}" || true
    return 1
  fi
  keepalive_process_snapshot "tick_enter" "pid=${current_pid} url=${vnc_url}" || true
  keepalive_state_mark_tick "$vnc_url"
  desired_visible="$(keepalive_desired_visible)"
  current_headless=0
  if [ "$current_pid" -gt 0 ] && kill -0 "$current_pid" >/dev/null 2>&1; then
    prune_keepalive_browser_duplicates "$current_pid"
    if keepalive_pid_is_headless "$current_pid"; then
      current_headless=1
    fi
    pid_display="$(keepalive_pid_display "$current_pid" || true)"
    if [ -n "$pid_display" ] && [ "$pid_display" != "$KEEPALIVE_DISPLAY" ]; then
      keepalive_log "vnc_browser_display_mismatch pid=${current_pid} pid_display=${pid_display} target_display=${KEEPALIVE_DISPLAY} action=no_restart_keep_running"
    fi
    if [ -n "$current_url" ] && [ "$current_url" = "$vnc_url" ]; then
      if [ "$desired_visible" -eq 1 ] && [ "$current_headless" -eq 1 ]; then
        keepalive_log "vnc_browser_visibility_mismatch pid=${current_pid} target=visible action=no_restart_keep_running"
      fi
      if ! ensure_vnc_browser_tab "$browser_bin" "$vnc_url"; then
        if [ "$KEEPALIVE_FORCE_REFRESH" -eq 1 ] || [ "$force_refresh_now" -eq 1 ]; then
          if [ "$current_headless" -eq 1 ]; then
            if reload_vnc_browser_keepalive_url "$browser_bin" "$vnc_url" && verify_vnc_browser_refresh_health "$vnc_url"; then
              keepalive_state_mark_refresh "tab_ensure_failed_headless_cdp_reload" "$vnc_url" 1
              keepalive_log "vnc_browser_tab_ensure_recovered pid=${current_pid} browser=$(basename "$browser_bin") mode=headless_cdp_reload url=${vnc_url}"
              keepalive_process_snapshot "tick_tab_ensure_recovered_headless" "pid=${current_pid} url=${vnc_url}" || true
              return 0
            fi
          else
            if visible_vnc_window_reload "$vnc_url"; then
              keepalive_state_mark_refresh "tab_ensure_failed_visible_reload" "$vnc_url" 1
              keepalive_log "vnc_browser_tab_ensure_recovered pid=${current_pid} browser=$(basename "$browser_bin") mode=visible_reload url=${vnc_url}"
              keepalive_process_snapshot "tick_tab_ensure_recovered_visible" "pid=${current_pid} url=${vnc_url}" || true
              return 0
            fi
          fi
        fi
        keepalive_log "vnc_browser_tab_ensure_failed pid=${current_pid} browser=$(basename "$browser_bin") action=no_restart_wait_next_tick url=${vnc_url}"
        return 1
      fi
      dedupe_vnc_browser_tabs "$vnc_url" || true
      if [ "$desired_visible" -eq 1 ]; then
        ensure_keepalive_window_workspace_retry "$current_pid" 24 0.12 || true
      fi
        if [ "$KEEPALIVE_FORCE_REFRESH" -eq 1 ] || [ "$force_refresh_now" -eq 1 ]; then
        if [ "$current_headless" -eq 1 ]; then
          if reload_vnc_browser_keepalive_url "$browser_bin" "$vnc_url" && verify_vnc_browser_refresh_health "$vnc_url"; then
            keepalive_state_mark_refresh "headless_cdp_reload" "$vnc_url" 1
            keepalive_log "vnc_browser_force_refresh_ok pid=${current_pid} browser=$(basename "$browser_bin") mode=headless_cdp_reload url=${vnc_url}"
            keepalive_process_snapshot "tick_force_refresh_ok_headless" "pid=${current_pid} url=${vnc_url}" || true
            return 0
          fi
          keepalive_state_mark_refresh "headless_refresh_failed" "$vnc_url" 0
          keepalive_log "vnc_browser_force_refresh_failed pid=${current_pid} browser=$(basename "$browser_bin") mode=headless_cdp_reload url=${vnc_url}"
          stop_keepalive_browser || true
          if start_vnc_browser_keepalive "$browser_bin" "$vnc_url"; then
            keepalive_state_mark_refresh "headless_restart_browser" "$vnc_url" 1
            keepalive_log "vnc_browser_force_refresh_recovered pid=${current_pid} browser=$(basename "$browser_bin") mode=headless_restart url=${vnc_url}"
            keepalive_process_snapshot "tick_force_refresh_recovered_headless" "pid=${current_pid} url=${vnc_url}" || true
            return 0
          fi
          keepalive_process_snapshot "tick_force_refresh_fail_headless" "pid=${current_pid} url=${vnc_url}" || true
          return 1
        fi
        if visible_vnc_window_reload "$vnc_url"; then
          keepalive_process_snapshot "tick_force_refresh_ok_visible" "pid=${current_pid} url=${vnc_url}" || true
          return 0
        fi
        # Try one tab/url rehydrate before declaring failure.
        if reload_vnc_browser_keepalive_url "$browser_bin" "$vnc_url"; then
          if visible_vnc_window_reload "$vnc_url"; then
            keepalive_log "vnc_browser_force_refresh_recovered pid=${current_pid} browser=$(basename "$browser_bin") mode=visible_only url=${vnc_url}"
            keepalive_process_snapshot "tick_force_refresh_recovered_visible" "pid=${current_pid} url=${vnc_url}" || true
            return 0
          fi
        fi
        keepalive_state_mark_refresh "visible_refresh_failed" "$vnc_url" 0
        keepalive_log "vnc_browser_force_refresh_failed pid=${current_pid} browser=$(basename "$browser_bin") mode=visible_only url=${vnc_url}"
        stop_keepalive_browser || true
        if start_vnc_browser_keepalive "$browser_bin" "$vnc_url"; then
          keepalive_state_mark_refresh "visible_restart_browser" "$vnc_url" 1
          keepalive_log "vnc_browser_force_refresh_recovered pid=${current_pid} browser=$(basename "$browser_bin") mode=visible_restart url=${vnc_url}"
          keepalive_process_snapshot "tick_force_refresh_recovered_visible_restart" "pid=${current_pid} url=${vnc_url}" || true
          return 0
        fi
        keepalive_process_snapshot "tick_force_refresh_fail_visible" "pid=${current_pid} url=${vnc_url}" || true
        return 1
      fi
      keepalive_log "vnc_browser_alive pid=${current_pid} browser=$(basename "$browser_bin") url=${vnc_url}"
      keepalive_process_snapshot "tick_alive" "pid=${current_pid} url=${vnc_url}" || true
      return 0
    fi
    if reload_vnc_browser_keepalive_url "$browser_bin" "$vnc_url"; then
      dedupe_vnc_browser_tabs "$vnc_url" || true
      if [ "$desired_visible" -eq 1 ]; then
        visible_vnc_window_reload "$vnc_url" || true
      fi
      keepalive_log "vnc_browser_reload_applied pid=${current_pid} browser=$(basename "$browser_bin") url=${vnc_url}"
      keepalive_process_snapshot "tick_reload_applied" "pid=${current_pid} url=${vnc_url}" || true
      return 0
    fi
    keepalive_log "vnc_browser_reload_failed pid=${current_pid} browser=$(basename "$browser_bin") action=no_restart_wait_next_tick url=${vnc_url}"
    keepalive_process_snapshot "tick_reload_failed" "pid=${current_pid} url=${vnc_url}" || true
    return 1
  fi
  stop_keepalive_browser
  if start_vnc_browser_keepalive "$browser_bin" "$vnc_url"; then
    keepalive_process_snapshot "tick_launch_ok" "url=${vnc_url}" || true
    return 0
  fi
  keepalive_process_snapshot "tick_launch_failed" "url=${vnc_url}" || true
  return 1
}

with_retry() {
  local max_try="$1"
  shift
  local attempt=1
  while true; do
    if "$@"; then
      return 0
    fi
    if [ "$attempt" -ge "$max_try" ]; then
      return 1
    fi
    sleep $((attempt * 2))
    attempt=$((attempt + 1))
  done
}

detect_supervisor_conf_dir() {
  if [ -d /etc/supervisor/conf.d ]; then
    printf '%s\n' /etc/supervisor/conf.d
    return 0
  fi
  if [ -d /etc/supervisord.d ]; then
    printf '%s\n' /etc/supervisord.d
    return 0
  fi
  return 1
}

set_sshd_option() {
  local key="$1"
  local value="$2"
  local conf="/etc/ssh/sshd_config"
  if [ ! -f "$conf" ]; then
    return 1
  fi
  if run_root grep -Eq "^[#[:space:]]*${key}[[:space:]]+" "$conf"; then
    run_root sed -i -E "s|^[#[:space:]]*${key}[[:space:]].*|${key} ${value}|g" "$conf"
  else
    printf '%s %s\n' "$key" "$value" | run_root tee -a "$conf" >/dev/null
  fi
}

chisel_state() {
  local line found
  found=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    found=1
    if [[ "$line" == *"chisel server"* ]] \
      && [[ "$line" == *"--port 8080"* ]] \
      && [[ "$line" == *"--auth ${CHISEL_AUTH}"* ]]; then
      echo "desired"
      return 0
    fi
  done < <(pgrep -af "chisel server" || true)
  if [ "$found" -eq 1 ]; then
    echo "other"
  else
    echo "none"
  fi
}

install_packages() {
  local rc_update rc_install
  if ! can_root; then
    install_log "core_install_skip reason=no_root"
    return 0
  fi

  if command -v apt-get >/dev/null 2>&1; then
    install_log "core_install_start manager=apt"
    set +e
    with_retry 3 run_root apt-get -o DPkg::Lock::Timeout=180 update -y >/tmp/hc-apt-update.log 2>&1
    rc_update=$?
    with_retry 3 run_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y \
      curl ca-certificates gzip openssh-server supervisor nodejs git zsh >/tmp/hc-apt-install.log 2>&1
    rc_install=$?
    set -e
    install_log "core_install_end manager=apt rc_update=${rc_update} rc_install=${rc_install} update_log=/tmp/hc-apt-update.log install_log=/tmp/hc-apt-install.log"
  elif command -v apk >/dev/null 2>&1; then
    install_log "core_install_start manager=apk"
    set +e
    with_retry 2 run_root apk add --no-cache curl gzip openssh supervisor nodejs git zsh >/tmp/hc-apk-install.log 2>&1
    rc_install=$?
    set -e
    install_log "core_install_end manager=apk rc_install=${rc_install} install_log=/tmp/hc-apk-install.log"
  elif command -v yum >/dev/null 2>&1; then
    install_log "core_install_start manager=yum"
    set +e
    with_retry 2 run_root yum install -y curl gzip openssh-server supervisor nodejs git zsh >/tmp/hc-yum-install.log 2>&1
    rc_install=$?
    set -e
    install_log "core_install_end manager=yum rc_install=${rc_install} install_log=/tmp/hc-yum-install.log"
  else
    install_log "core_install_skip reason=unsupported_package_manager"
  fi
}

read_boot_id() {
  local boot_id
  boot_id="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
  if [ -z "$boot_id" ]; then
    boot_id="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
  fi
  printf '%s\n' "$boot_id"
}

prepare_autorestore_install_round() {
  AUTORESTORE_FORCE_INSTALL_ROUND=0
  AUTORESTORE_FORCE_INSTALL_BOOT_ID=""
  if [ "$KEEPALIVE_MODE" != "vnc-browser" ]; then
    return 0
  fi
  if [ "$AUTORESTORE_FORCE_REINSTALL" -eq 1 ]; then
    AUTORESTORE_FORCE_INSTALL_ROUND=1
    AUTORESTORE_FORCE_INSTALL_BOOT_ID="$(read_boot_id)"
    return 0
  fi
  local boot_id last_boot
  boot_id="$(read_boot_id)"
  [ -n "$boot_id" ] || return 0
  last_boot="$(cat "$AUTORESTORE_DEPS_BOOTID_FILE" 2>/dev/null | head -n1 || true)"
  if [ "$last_boot" != "$boot_id" ]; then
    AUTORESTORE_FORCE_INSTALL_ROUND=1
    AUTORESTORE_FORCE_INSTALL_BOOT_ID="$boot_id"
  fi
  return 0
}

mark_autorestore_install_round_done() {
  if [ "$AUTORESTORE_FORCE_INSTALL_ROUND" -ne 1 ] 2>/dev/null; then
    return 0
  fi
  local boot_id
  boot_id="${AUTORESTORE_FORCE_INSTALL_BOOT_ID:-}"
  [ -n "$boot_id" ] || boot_id="$(read_boot_id)"
  [ -n "$boot_id" ] || return 0
  mkdir -p "$(dirname "$AUTORESTORE_DEPS_BOOTID_FILE")" >/dev/null 2>&1 || true
  printf '%s\n' "$boot_id" > "$AUTORESTORE_DEPS_BOOTID_FILE" 2>/dev/null || true
  return 0
}

load_autorestore_preferences() {
  AUTORESTORE_DOCKER=0
  AUTORESTORE_BROWSER=""
  AUTORESTORE_DESKTOP=0
  AUTORESTORE_DESKTOP_ENV=0
  AUTORESTORE_START_SERVICES=0
  if [ -f "$AUTORESTORE_ENV_FILE" ]; then
    while IFS='=' read -r key value; do
      key="$(printf '%s' "${key:-}" | tr -d '[:space:]')"
      value="$(printf '%s' "${value:-}" | tr -d '\r')"
      case "$key" in
        HAPPYCAPY_AUTORESTORE_DOCKER)
          case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
            1|true|yes|on) AUTORESTORE_DOCKER=1 ;;
          esac
          ;;
        HAPPYCAPY_AUTORESTORE_BROWSER)
          value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
          case "$value" in
            chromium|firefox|chrome|auto) AUTORESTORE_BROWSER="$value" ;;
          esac
          ;;
        HAPPYCAPY_AUTORESTORE_DESKTOP)
          case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
            1|true|yes|on) AUTORESTORE_DESKTOP=1 ;;
          esac
          ;;
        HAPPYCAPY_AUTORESTORE_DESKTOP_ENV)
          case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
            1|true|yes|on) AUTORESTORE_DESKTOP_ENV=1 ;;
            *) AUTORESTORE_DESKTOP_ENV=0 ;;
          esac
          ;;
        HAPPYCAPY_AUTORESTORE_START_SERVICES)
          case "$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')" in
            1|true|yes|on) AUTORESTORE_START_SERVICES=1 ;;
            *) AUTORESTORE_START_SERVICES=0 ;;
          esac
          ;;
        HAPPYCAPY_EXTERNAL_RECOVER_URL)
          if [ -z "$EXTERNAL_RECOVER_URL" ]; then
            EXTERNAL_RECOVER_URL="$value"
          fi
          ;;
      esac
    done < "$AUTORESTORE_ENV_FILE"
  else
    install_log "autorestore_env_missing path=${AUTORESTORE_ENV_FILE}"
  fi
  # Extension-only behavior: vnc-browser keepalive requires desktop + browser.
  # For cold-start/new machines, also force lightweight desktop env install
  # (openbox/xterm) so keepalive/UI can work without manual intervention.
  if [ "$KEEPALIVE_MODE" = "vnc-browser" ]; then
    AUTORESTORE_DESKTOP=1
    AUTORESTORE_DESKTOP_ENV=1
    AUTORESTORE_START_SERVICES=1
    if [ -z "$AUTORESTORE_BROWSER" ]; then
      AUTORESTORE_BROWSER="$KEEPALIVE_BROWSER"
    fi
  fi
}

ensure_autorestore_docker() {
  [ "$AUTORESTORE_DOCKER" -eq 1 ] || return 0
  can_root || return 0
  if ! command -v docker >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      with_retry 3 run_root apt-get -o DPkg::Lock::Timeout=180 update -y >/tmp/hc-autorestore-docker-install.log 2>&1 || true
      with_retry 3 run_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y docker.io >>/tmp/hc-autorestore-docker-install.log 2>&1 || true
    elif command -v apk >/dev/null 2>&1; then
      run_root apk add --no-cache docker >/tmp/hc-autorestore-docker-install.log 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then
      run_root yum install -y docker >/tmp/hc-autorestore-docker-install.log 2>&1 || true
    fi
  fi
  if command -v docker >/dev/null 2>&1; then
    run_root service docker start >/tmp/hc-autorestore-docker-service.log 2>&1 || run_root systemctl start docker >/tmp/hc-autorestore-docker-service.log 2>&1 || true
  fi
}

ensure_autorestore_browser() {
  local browser="$AUTORESTORE_BROWSER"
  local force_install
  local rc_update rc_install
  force_install=0
  if [ "$AUTORESTORE_FORCE_INSTALL_ROUND" -eq 1 ] 2>/dev/null; then
    force_install=1
  fi
  rc_update=0
  rc_install=0
  [ -n "$browser" ] || return 0
  [ "$browser" != "auto" ] || browser="chromium"
  case "$browser" in
    chromium)
      if command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1; then
        if [ "$force_install" -eq 0 ]; then
          install_log "browser_dep_check rc=0 browser=chromium reason=already_present"
          return 0
        fi
        install_log "browser_dep_check rc=0 browser=chromium reason=present_but_forced_reinstall"
      fi
      ;;
    firefox)
      if command -v firefox >/dev/null 2>&1; then
        if [ "$force_install" -eq 0 ]; then
          install_log "browser_dep_check rc=0 browser=firefox reason=already_present"
          return 0
        fi
        install_log "browser_dep_check rc=0 browser=firefox reason=present_but_forced_reinstall"
      fi
      ;;
    chrome)
      if command -v google-chrome >/dev/null 2>&1 || command -v google-chrome-stable >/dev/null 2>&1; then
        if [ "$force_install" -eq 0 ]; then
          install_log "browser_dep_check rc=0 browser=chrome reason=already_present"
          return 0
        fi
        install_log "browser_dep_check rc=0 browser=chrome reason=present_but_forced_reinstall"
      fi
      ;;
  esac
  if [ "$force_install" -eq 1 ]; then
    install_log "browser_dep_check rc=1 browser=${browser} reason=forced_install keepalive_mode=${KEEPALIVE_MODE}"
  else
    install_log "browser_dep_check rc=1 browser=${browser} reason=missing_binary"
  fi
  if ! can_root; then
    keepalive_log "autorestore_browser_missing reason=no_root browser=${browser}"
    install_log "browser_dep_install_skip browser=${browser} reason=no_root force_install=${force_install}"
    return 1
  fi

  case "$browser" in
    chromium)
      if command -v apt-get >/dev/null 2>&1; then
        install_log "browser_dep_install_start browser=chromium manager=apt log=/tmp/hc-autorestore-browser-install.log"
        set +e
        with_retry 3 run_root apt-get -o DPkg::Lock::Timeout=180 update -y >/tmp/hc-autorestore-browser-install.log 2>&1
        rc_update=$?
        with_retry 3 run_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y chromium >>/tmp/hc-autorestore-browser-install.log 2>&1
        rc_install=$?
        if [ "$rc_install" -ne 0 ]; then
          with_retry 3 run_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y chromium-browser >>/tmp/hc-autorestore-browser-install.log 2>&1
          rc_install=$?
        fi
        set -e
        install_log "browser_dep_install_end browser=chromium manager=apt rc_update=${rc_update} rc_install=${rc_install} log=/tmp/hc-autorestore-browser-install.log"
      elif command -v apk >/dev/null 2>&1; then
        install_log "browser_dep_install_start browser=chromium manager=apk log=/tmp/hc-autorestore-browser-install.log"
        set +e
        run_root apk add --no-cache chromium >/tmp/hc-autorestore-browser-install.log 2>&1
        rc_install=$?
        set -e
        install_log "browser_dep_install_end browser=chromium manager=apk rc_install=${rc_install} log=/tmp/hc-autorestore-browser-install.log"
      elif command -v yum >/dev/null 2>&1; then
        install_log "browser_dep_install_start browser=chromium manager=yum log=/tmp/hc-autorestore-browser-install.log"
        set +e
        run_root yum install -y chromium >/tmp/hc-autorestore-browser-install.log 2>&1
        rc_install=$?
        set -e
        install_log "browser_dep_install_end browser=chromium manager=yum rc_install=${rc_install} log=/tmp/hc-autorestore-browser-install.log"
      fi
      ;;
    firefox)
      if command -v apt-get >/dev/null 2>&1; then
        install_log "browser_dep_install_start browser=firefox manager=apt log=/tmp/hc-autorestore-browser-install.log"
        set +e
        with_retry 3 run_root apt-get -o DPkg::Lock::Timeout=180 update -y >/tmp/hc-autorestore-browser-install.log 2>&1
        rc_update=$?
        with_retry 3 run_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y firefox-esr >>/tmp/hc-autorestore-browser-install.log 2>&1
        rc_install=$?
        if [ "$rc_install" -ne 0 ]; then
          with_retry 3 run_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y firefox >>/tmp/hc-autorestore-browser-install.log 2>&1
          rc_install=$?
        fi
        set -e
        install_log "browser_dep_install_end browser=firefox manager=apt rc_update=${rc_update} rc_install=${rc_install} log=/tmp/hc-autorestore-browser-install.log"
      elif command -v apk >/dev/null 2>&1; then
        install_log "browser_dep_install_start browser=firefox manager=apk log=/tmp/hc-autorestore-browser-install.log"
        set +e
        run_root apk add --no-cache firefox >/tmp/hc-autorestore-browser-install.log 2>&1
        rc_install=$?
        set -e
        install_log "browser_dep_install_end browser=firefox manager=apk rc_install=${rc_install} log=/tmp/hc-autorestore-browser-install.log"
      elif command -v yum >/dev/null 2>&1; then
        install_log "browser_dep_install_start browser=firefox manager=yum log=/tmp/hc-autorestore-browser-install.log"
        set +e
        run_root yum install -y firefox >/tmp/hc-autorestore-browser-install.log 2>&1
        rc_install=$?
        set -e
        install_log "browser_dep_install_end browser=firefox manager=yum rc_install=${rc_install} log=/tmp/hc-autorestore-browser-install.log"
      fi
      ;;
    chrome)
      if command -v apt-get >/dev/null 2>&1; then
        install_log "browser_dep_install_start browser=chrome manager=apt log=/tmp/hc-autorestore-browser-install.log"
        set +e
        with_retry 3 run_root apt-get -o DPkg::Lock::Timeout=180 update -y >/tmp/hc-autorestore-browser-install.log 2>&1
        rc_update=$?
        with_retry 3 run_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y google-chrome-stable >>/tmp/hc-autorestore-browser-install.log 2>&1
        rc_install=$?
        set -e
        install_log "browser_dep_install_end browser=chrome manager=apt rc_update=${rc_update} rc_install=${rc_install} log=/tmp/hc-autorestore-browser-install.log"
      elif command -v yum >/dev/null 2>&1; then
        install_log "browser_dep_install_start browser=chrome manager=yum log=/tmp/hc-autorestore-browser-install.log"
        set +e
        run_root yum install -y google-chrome-stable >/tmp/hc-autorestore-browser-install.log 2>&1
        rc_install=$?
        set -e
        install_log "browser_dep_install_end browser=chrome manager=yum rc_install=${rc_install} log=/tmp/hc-autorestore-browser-install.log"
      fi
      ;;
  esac

  case "$browser" in
    chromium)
      if ! command -v chromium >/dev/null 2>&1 && ! command -v chromium-browser >/dev/null 2>&1; then
        keepalive_log "autorestore_browser_missing browser=chromium"
        install_log "browser_dep_install_verify rc=1 browser=chromium"
        return 1
      fi
      ;;
    firefox)
      if ! command -v firefox >/dev/null 2>&1; then
        keepalive_log "autorestore_browser_missing browser=firefox"
        install_log "browser_dep_install_verify rc=1 browser=firefox"
        return 1
      fi
      ;;
    chrome)
      if ! command -v google-chrome >/dev/null 2>&1 && ! command -v google-chrome-stable >/dev/null 2>&1; then
        keepalive_log "autorestore_browser_missing browser=chrome"
        install_log "browser_dep_install_verify rc=1 browser=chrome"
        return 1
      fi
      ;;
  esac
  install_log "browser_dep_install_verify rc=0 browser=${browser}"
  return 0
}

ensure_autorestore_desktop_packages() {
  local missing need_window_tools force_install rc
  [ "$AUTORESTORE_DESKTOP" -eq 1 ] || return 0
  missing=""
  need_window_tools=0
  force_install=0
  if [ "$KEEPALIVE_MODE" = "vnc-browser" ]; then
    need_window_tools=1
  fi
  if [ "$AUTORESTORE_FORCE_INSTALL_ROUND" -eq 1 ] 2>/dev/null; then
    force_install=1
  fi
  if ! command -v Xvfb >/dev/null 2>&1; then missing="${missing} Xvfb"; fi
  if ! command -v x11vnc >/dev/null 2>&1; then missing="${missing} x11vnc"; fi
  if ! command -v websockify >/dev/null 2>&1 && ! command -v novnc_proxy >/dev/null 2>&1; then
    missing="${missing} websockify_or_novnc_proxy"
  fi
  if [ "$need_window_tools" -eq 1 ]; then
    if ! command -v xdotool >/dev/null 2>&1; then missing="${missing} xdotool"; fi
    if ! command -v wmctrl >/dev/null 2>&1; then missing="${missing} wmctrl"; fi
  fi
  missing="$(printf '%s' "$missing" | sed -E 's/^ +//; s/ +/ /g')"
  if [ -z "$missing" ] && [ "$force_install" -eq 0 ]; then
    install_log "desktop_dep_check rc=0 keepalive_mode=${KEEPALIVE_MODE} missing=none"
    return 0
  fi
  if [ -z "$missing" ] && [ "$force_install" -eq 1 ]; then
    install_log "desktop_dep_check rc=0 keepalive_mode=${KEEPALIVE_MODE} missing=none reason=forced_reinstall"
  else
    install_log "desktop_dep_check rc=1 keepalive_mode=${KEEPALIVE_MODE} missing=${missing}"
  fi
  if ! can_root; then
    keepalive_log "autorestore_desktop_missing reason=no_root missing=${missing}"
    install_log "desktop_dep_install_skip reason=no_root missing=${missing} force_install=${force_install}"
    return 1
  fi
  rc=0
  if command -v apt-get >/dev/null 2>&1; then
    install_log "desktop_dep_install_start manager=apt missing=${missing} log=/tmp/hc-autorestore-desktop-install.log"
    set +e
    with_retry 3 run_root apt-get -o DPkg::Lock::Timeout=180 update -y >/tmp/hc-autorestore-desktop-install.log 2>&1
    rc=$?
    with_retry 3 run_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y xvfb x11vnc novnc websockify xdotool wmctrl >>/tmp/hc-autorestore-desktop-install.log 2>&1
    rc=$((rc + $?))
    set -e
    install_log "desktop_dep_install_end manager=apt rc=${rc} log=/tmp/hc-autorestore-desktop-install.log"
    if [ "$AUTORESTORE_DESKTOP_ENV" -eq 1 ]; then
      set +e
      with_retry 3 run_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y openbox xterm >>/tmp/hc-autorestore-desktop-install.log 2>&1
      rc=$?
      set -e
      install_log "desktop_env_install_end manager=apt rc=${rc} log=/tmp/hc-autorestore-desktop-install.log"
    fi
  elif command -v apk >/dev/null 2>&1; then
    install_log "desktop_dep_install_start manager=apk missing=${missing} log=/tmp/hc-autorestore-desktop-install.log"
    set +e
    run_root apk add --no-cache xvfb x11vnc novnc websockify xdotool wmctrl >/tmp/hc-autorestore-desktop-install.log 2>&1
    rc=$?
    set -e
    install_log "desktop_dep_install_end manager=apk rc=${rc} log=/tmp/hc-autorestore-desktop-install.log"
    if [ "$AUTORESTORE_DESKTOP_ENV" -eq 1 ]; then
      set +e
      run_root apk add --no-cache openbox xterm >>/tmp/hc-autorestore-desktop-install.log 2>&1
      rc=$?
      set -e
      install_log "desktop_env_install_end manager=apk rc=${rc} log=/tmp/hc-autorestore-desktop-install.log"
    fi
  elif command -v yum >/dev/null 2>&1; then
    install_log "desktop_dep_install_start manager=yum missing=${missing} log=/tmp/hc-autorestore-desktop-install.log"
    set +e
    run_root yum install -y xorg-x11-server-Xvfb x11vnc novnc python3-websockify xdotool wmctrl >/tmp/hc-autorestore-desktop-install.log 2>&1
    rc=$?
    set -e
    install_log "desktop_dep_install_end manager=yum rc=${rc} log=/tmp/hc-autorestore-desktop-install.log"
    if [ "$AUTORESTORE_DESKTOP_ENV" -eq 1 ]; then
      set +e
      run_root yum install -y openbox xterm >>/tmp/hc-autorestore-desktop-install.log 2>&1
      rc=$?
      set -e
      install_log "desktop_env_install_end manager=yum rc=${rc} log=/tmp/hc-autorestore-desktop-install.log"
    fi
  fi
  missing=""
  if ! command -v Xvfb >/dev/null 2>&1; then missing="${missing} Xvfb"; fi
  if ! command -v x11vnc >/dev/null 2>&1; then missing="${missing} x11vnc"; fi
  if ! command -v websockify >/dev/null 2>&1 && ! command -v novnc_proxy >/dev/null 2>&1; then
    missing="${missing} websockify_or_novnc_proxy"
  fi
  if [ "$need_window_tools" -eq 1 ]; then
    if ! command -v xdotool >/dev/null 2>&1; then missing="${missing} xdotool"; fi
    if ! command -v wmctrl >/dev/null 2>&1; then missing="${missing} wmctrl"; fi
  fi
  if [ "$AUTORESTORE_DESKTOP_ENV" -eq 1 ]; then
    if ! command -v openbox >/dev/null 2>&1; then missing="${missing} openbox"; fi
    if ! command -v xterm >/dev/null 2>&1; then missing="${missing} xterm"; fi
  fi
  missing="$(printf '%s' "$missing" | sed -E 's/^ +//; s/ +/ /g')"
  if [ -n "$missing" ]; then
    keepalive_log "autorestore_desktop_missing reason=missing_desktop_tools missing=${missing}"
    install_log "desktop_dep_install_verify rc=1 missing=${missing}"
    return 1
  fi
  install_log "desktop_dep_install_verify rc=0 missing=none keepalive_mode=${KEEPALIVE_MODE}"
  return 0
}

desktop_gateway_stack_healthy() {
  if ! is_port_listening 5901; then
    return 1
  fi
  if ! is_port_listening 6080; then
    return 1
  fi
  if ! pgrep -af "Xvfb .*:99" >/dev/null 2>&1; then
    return 1
  fi
  if ! pgrep -af "websockify .* 6080 " >/dev/null 2>&1 && ! pgrep -af "websockify .* 6080$" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

restore_persisted_services() {
  local svc_dir="$PERSIST_DIR/services"
  [ -d "$svc_dir" ] || return 0
  local cmdf pidf logf pid cmd svc_sub name

  # New layout: .happycapy/services/<service>/start.cmd
  for svc_sub in "$svc_dir"/*; do
    [ -d "$svc_sub" ] || continue
    name="$(basename "$svc_sub")"
    cmdf="$svc_sub/start.cmd"
    pidf="$svc_sub/service.pid"
    logf="$svc_sub/service.log"
    [ -f "$cmdf" ] || continue
    pid=0
    if [ -f "$pidf" ]; then
      pid="$(cat "$pidf" 2>/dev/null | tr -dc '0-9')"
    fi
    [ -z "$pid" ] && pid=0
    if [ "$pid" -gt 0 ] && kill -0 "$pid" >/dev/null 2>&1; then
      continue
    fi
    cmd="$(cat "$cmdf" 2>/dev/null || true)"
    [ -n "$cmd" ] || continue
    if [ "$name" = "desktop-gateway" ] || printf '%s' "$cmd" | grep -q "start-desktop.sh"; then
      if desktop_gateway_stack_healthy; then
        continue
      fi
    fi
    nohup bash -lc "$cmd" >>"$logf" 2>&1 &
    printf '%s' "$!" > "$pidf"
    sleep 0.2
  done

  # Legacy layout compatibility: .happycapy/services/<name>.cmd
  for cmdf in "$svc_dir"/*.cmd; do
    [ -f "$cmdf" ] || continue
    name="$(basename "$cmdf" .cmd)"
    [ -n "$name" ] || continue
    pidf="$svc_dir/$name.pid"
    logf="$svc_dir/$name.log"
    pid=0
    if [ -f "$pidf" ]; then
      pid="$(cat "$pidf" 2>/dev/null | tr -dc '0-9')"
    fi
    [ -z "$pid" ] && pid=0
    if [ "$pid" -gt 0 ] && kill -0 "$pid" >/dev/null 2>&1; then
      continue
    fi
    cmd="$(cat "$cmdf" 2>/dev/null || true)"
    [ -n "$cmd" ] || continue
    if [ "$name" = "desktop-gateway" ] || printf '%s' "$cmd" | grep -q "start-desktop.sh"; then
      if desktop_gateway_stack_healthy; then
        continue
      fi
    fi
    nohup bash -lc "$cmd" >>"$logf" 2>&1 &
    printf '%s' "$!" > "$pidf"
    sleep 0.2
  done
}

restore_custom_recover_tasks() {
  local task_dir="$PERSIST_DIR/recover-tasks"
  [ -d "$task_dir" ] || return 0
  local cmdf name pidf logf pid cmd
  for cmdf in "$task_dir"/*.cmd; do
    [ -f "$cmdf" ] || continue
    name="$(basename "$cmdf" .cmd)"
    [ -n "$name" ] || continue
    pidf="$task_dir/$name.pid"
    logf="$task_dir/$name.log"
    pid=0
    if [ -f "$pidf" ]; then
      pid="$(cat "$pidf" 2>/dev/null | tr -dc '0-9')"
    fi
    [ -z "$pid" ] && pid=0
    if [ "$pid" -gt 0 ] && kill -0 "$pid" >/dev/null 2>&1; then
      continue
    fi
    cmd="$(cat "$cmdf" 2>/dev/null || true)"
    [ -n "$cmd" ] || continue
    nohup bash -lc "$cmd" >>"$logf" 2>&1 &
    printf '%s' "$!" > "$pidf"
    sleep 0.2
  done
}

ensure_keepalive_desktop_service_registration() {
  local desktop_dir launcher service_dir service_cmdf
  local launcher_tmp service_cmdf_tmp
  local keepalive_display_cfg keepalive_workspace_cfg work_workspace_cfg desktop_resolution_cfg
  local websockify_heartbeat_cfg
  [ "$KEEPALIVE_MODE" = "vnc-browser" ] || return 0

  desktop_dir="$PERSIST_DIR/desktop"
  launcher="$desktop_dir/start-desktop.sh"
  service_dir="$PERSIST_DIR/services/desktop-gateway"
  service_cmdf="$service_dir/start.cmd"
  launcher_tmp="${launcher}.tmp.$$"
  service_cmdf_tmp="${service_cmdf}.tmp.$$"
  keepalive_display_cfg="${KEEPALIVE_DISPLAY:-:99}"
  keepalive_workspace_cfg="${KEEPALIVE_WORKSPACE:-1}"
  work_workspace_cfg="${WORK_WORKSPACE:-0}"
  desktop_resolution_cfg="${DESKTOP_RESOLUTION:-1366x768x24}"
  websockify_heartbeat_cfg="${WEBSOCKIFY_HEARTBEAT_SEC:-25}"

  mkdir -p "$desktop_dir" "$service_dir"

  cat > "$launcher_tmp" <<'EOF2'
#!/usr/bin/env bash
set -euo pipefail

PERSIST_ROOT="${HAPPYCAPY_PERSIST_ROOT:-}"
if [ -z "$PERSIST_ROOT" ]; then
  PERSIST_ROOT="$(ls -d /home/node/*/workspace 2>/dev/null | head -n1 || true)"
fi
if [ -z "$PERSIST_ROOT" ]; then
  PERSIST_ROOT="$HOME"
fi
HC_ROOT="${PERSIST_ROOT%/}/.happycapy"
DROOT="$HC_ROOT/desktop"
APP_ROOT="$HC_ROOT/apps/desktop"
NOVNC_ROOT="$APP_ROOT/novnc-web"
WORK_TERM_PID_FILE="$DROOT/work-terminal.pid"
mkdir -p "$DROOT"

DISPLAY_NAME="${HAPPYCAPY_KEEPALIVE_DISPLAY:-:99}"
case "$DISPLAY_NAME" in
  :*) ;;
  *) DISPLAY_NAME=":${DISPLAY_NAME}" ;;
esac
KEEPALIVE_WORKSPACE_RAW="${HAPPYCAPY_KEEPALIVE_WORKSPACE:-1}"
case "$KEEPALIVE_WORKSPACE_RAW" in
  -1)
    KEEPALIVE_WORKSPACE=-1
    ;;
  ''|*[!0-9]*)
    KEEPALIVE_WORKSPACE=1
    ;;
  *)
    KEEPALIVE_WORKSPACE="$KEEPALIVE_WORKSPACE_RAW"
    ;;
esac
WORK_WORKSPACE_RAW="${HAPPYCAPY_WORK_WORKSPACE:-0}"
case "$WORK_WORKSPACE_RAW" in
  ''|*[!0-9]*)
    WORK_WORKSPACE=0
    ;;
  *)
    WORK_WORKSPACE="$WORK_WORKSPACE_RAW"
    ;;
esac
if [ "$KEEPALIVE_WORKSPACE" -ge 0 ] 2>/dev/null && [ "$KEEPALIVE_WORKSPACE" -eq "$WORK_WORKSPACE" ] 2>/dev/null; then
  KEEPALIVE_WORKSPACE=$((WORK_WORKSPACE + 1))
fi
RESOLUTION="${HAPPYCAPY_DESKTOP_RESOLUTION:-1366x768x24}"
WEBSOCKIFY_HEARTBEAT_RAW="${HAPPYCAPY_WEBSOCKIFY_HEARTBEAT_SEC:-25}"
case "$WEBSOCKIFY_HEARTBEAT_RAW" in
  ''|*[!0-9]*)
    WEBSOCKIFY_HEARTBEAT_SEC=25
    ;;
  *)
    WEBSOCKIFY_HEARTBEAT_SEC="$WEBSOCKIFY_HEARTBEAT_RAW"
    ;;
esac
if [ "$WEBSOCKIFY_HEARTBEAT_SEC" -lt 0 ] 2>/dev/null; then
  WEBSOCKIFY_HEARTBEAT_SEC=25
fi
if [ "$WEBSOCKIFY_HEARTBEAT_SEC" -gt 0 ] 2>/dev/null && [ "$WEBSOCKIFY_HEARTBEAT_SEC" -lt 5 ] 2>/dev/null; then
  WEBSOCKIFY_HEARTBEAT_SEC=5
fi
if [ "$WEBSOCKIFY_HEARTBEAT_SEC" -gt 300 ] 2>/dev/null; then
  WEBSOCKIFY_HEARTBEAT_SEC=300
fi

ensure_desktop_count() {
  local target="$1"
  local desktop_count
  if [ "$target" -lt 0 ] 2>/dev/null; then
    return 0
  fi
  command -v wmctrl >/dev/null 2>&1 || return 0
  desktop_count="$(DISPLAY="$DISPLAY_NAME" wmctrl -d 2>/dev/null | wc -l | tr -d ' ' || true)"
  case "$desktop_count" in
    ''|*[!0-9]*) desktop_count=0 ;;
  esac
  if [ "$desktop_count" -le "$target" ] 2>/dev/null; then
    DISPLAY="$DISPLAY_NAME" wmctrl -n $((target + 1)) >/dev/null 2>&1 || true
  fi
}

move_window_to_workspace_by_pid() {
  local pid="$1"
  local target="$2"
  local win_id wins
  case "$pid" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$pid" -gt 0 ] 2>/dev/null || return 1
  if [ "$target" -lt 0 ] 2>/dev/null; then
    return 0
  fi
  command -v xdotool >/dev/null 2>&1 || return 0
  command -v wmctrl >/dev/null 2>&1 || return 0
  ensure_desktop_count "$target"
  wins=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    wins="$(DISPLAY="$DISPLAY_NAME" xdotool search --pid "$pid" 2>/dev/null || true)"
    [ -n "$wins" ] && break
    sleep 0.2
  done
  [ -n "$wins" ] || return 1
  while IFS= read -r win_id; do
    [ -n "$win_id" ] || continue
    DISPLAY="$DISPLAY_NAME" wmctrl -i -r "$win_id" -t "$target" >/dev/null 2>&1 || true
  done <<< "$wins"
  return 0
}

if ! command -v Xvfb >/dev/null 2>&1 || ! command -v x11vnc >/dev/null 2>&1; then
  echo "missing desktop deps (Xvfb/x11vnc)" >>"$DROOT/desktop-health.log"
  exit 1
fi
if ! command -v websockify >/dev/null 2>&1 && ! command -v novnc_proxy >/dev/null 2>&1; then
  echo "missing desktop deps (websockify/novnc_proxy)" >>"$DROOT/desktop-health.log"
  exit 1
fi

if ! pgrep -af "Xvfb .*${DISPLAY_NAME}" >/dev/null 2>&1; then
  nohup Xvfb "$DISPLAY_NAME" -screen 0 "$RESOLUTION" -ac +extension RANDR >"$DROOT/xvfb.log" 2>&1 &
fi
sleep 0.3

if ! pgrep -af "x11vnc .*rfbport 5901" >/dev/null 2>&1; then
  nohup x11vnc -display "$DISPLAY_NAME" -rfbport 5901 -forever -shared -nopw -xkb >"$DROOT/x11vnc.log" 2>&1 &
fi
sleep 0.3

resolve_web_root() {
  local src
  if [ -d "$NOVNC_ROOT" ] && { [ -f "$NOVNC_ROOT/vnc_lite.html" ] || [ -f "$NOVNC_ROOT/vnc.html" ]; }; then
    printf '%s\n' "$NOVNC_ROOT"
    return 0
  fi
  for src in /opt/novnc /usr/share/novnc /usr/share/noVNC /usr/local/share/novnc /usr/local/share/noVNC; do
    if [ -d "$src" ] && { [ -f "$src/vnc_lite.html" ] || [ -f "$src/vnc.html" ]; }; then
      mkdir -p "$NOVNC_ROOT" >/dev/null 2>&1 || true
      if [ ! -f "$NOVNC_ROOT/vnc_lite.html" ] && [ ! -f "$NOVNC_ROOT/vnc.html" ]; then
        cp -a "$src"/. "$NOVNC_ROOT"/ >/dev/null 2>&1 || true
      fi
      if [ -f "$NOVNC_ROOT/vnc_lite.html" ] || [ -f "$NOVNC_ROOT/vnc.html" ]; then
        printf '%s\n' "$NOVNC_ROOT"
        return 0
      fi
      printf '%s\n' "$src"
      return 0
    fi
  done
  return 1
}

websockify_6080_cmdline() {
  ps -eo args= 2>/dev/null | awk '/[w]ebsockify/ && ($0 ~ / 6080 / || $0 ~ / 6080$/ || $0 ~ /:6080 / || $0 ~ /:6080$/) {print; exit}'
}

kill_websockify_6080() {
  ps -eo pid=,args= 2>/dev/null | \
    awk '/[w]ebsockify/ && ($0 ~ / 6080 / || $0 ~ / 6080$/ || $0 ~ /:6080 / || $0 ~ /:6080$/) {print $1}' | \
    while read -r pid; do
      [ -n "$pid" ] || continue
      kill "$pid" >/dev/null 2>&1 || true
    done
  sleep 0.2
  ps -eo pid=,args= 2>/dev/null | \
    awk '/[w]ebsockify/ && ($0 ~ / 6080 / || $0 ~ / 6080$/ || $0 ~ /:6080 / || $0 ~ /:6080$/) {print $1}' | \
    while read -r pid; do
      [ -n "$pid" ] || continue
      kill -9 "$pid" >/dev/null 2>&1 || true
    done
}

prune_websockify_6080_duplicates() {
  local keep_pid pid
  keep_pid=""
  while read -r pid; do
    [ -n "$pid" ] || continue
    if [ -z "$keep_pid" ]; then
      keep_pid="$pid"
      continue
    fi
    kill "$pid" >/dev/null 2>&1 || true
  done < <(ps -eo pid=,args= 2>/dev/null | awk '/[w]ebsockify/ && ($0 ~ / 6080 / || $0 ~ / 6080$/ || $0 ~ /:6080 / || $0 ~ /:6080$/) {print $1}')
}

WEB_ROOT="$(resolve_web_root || true)"
WSK_CMDLINE="$(websockify_6080_cmdline || true)"
websockify_restart_needed=0
if [ -z "$WSK_CMDLINE" ]; then
  websockify_restart_needed=1
elif [ -n "$WEB_ROOT" ] && ! printf '%s' "$WSK_CMDLINE" | grep -F -- "$WEB_ROOT" >/dev/null 2>&1; then
  websockify_restart_needed=1
elif [ "$WEBSOCKIFY_HEARTBEAT_SEC" -gt 0 ] 2>/dev/null && ! printf '%s' "$WSK_CMDLINE" | grep -E -- "--heartbeat[[:space:]]+${WEBSOCKIFY_HEARTBEAT_SEC}([[:space:]]|$)" >/dev/null 2>&1; then
  websockify_restart_needed=1
elif [ "$WEBSOCKIFY_HEARTBEAT_SEC" -eq 0 ] 2>/dev/null && printf '%s' "$WSK_CMDLINE" | grep -E -- "--heartbeat[[:space:]]+[0-9]+" >/dev/null 2>&1; then
  websockify_restart_needed=1
fi

if [ "$websockify_restart_needed" -eq 1 ]; then
  kill_websockify_6080
  if command -v websockify >/dev/null 2>&1; then
    WS_HB_ARGS=()
    if [ "$WEBSOCKIFY_HEARTBEAT_SEC" -gt 0 ] 2>/dev/null; then
      WS_HB_ARGS=(--heartbeat "$WEBSOCKIFY_HEARTBEAT_SEC")
    fi
    if [ -n "$WEB_ROOT" ]; then
      nohup websockify "${WS_HB_ARGS[@]}" --web "$WEB_ROOT" 0.0.0.0:6080 localhost:5901 >"$DROOT/websockify.log" 2>&1 &
    else
      nohup websockify "${WS_HB_ARGS[@]}" 0.0.0.0:6080 localhost:5901 >"$DROOT/websockify.log" 2>&1 &
    fi
  else
    nohup novnc_proxy --listen 6080 --vnc localhost:5901 >"$DROOT/websockify.log" 2>&1 &
  fi
else
  prune_websockify_6080_duplicates || true
fi

if command -v openbox >/dev/null 2>&1; then
  if ! pgrep -f "openbox.*${DISPLAY_NAME}" >/dev/null 2>&1; then
    nohup env DISPLAY="$DISPLAY_NAME" openbox >"$DROOT/openbox.log" 2>&1 &
  fi
fi
XTERM_PID=""
XTERM_NEW=0
WORK_TERM_PID=0
if [ -f "$WORK_TERM_PID_FILE" ]; then
  WORK_TERM_PID="$(cat "$WORK_TERM_PID_FILE" 2>/dev/null | tr -dc '0-9')"
fi
case "$WORK_TERM_PID" in ''|*[!0-9]*) WORK_TERM_PID=0 ;; esac
if [ "$WORK_TERM_PID" -gt 0 ] 2>/dev/null && kill -0 "$WORK_TERM_PID" >/dev/null 2>&1; then
  XTERM_PID="$WORK_TERM_PID"
else
  TERM_CMD=""
  if command -v xterm >/dev/null 2>&1; then
    TERM_CMD="xterm -geometry 100x30+40+40"
  elif command -v x-terminal-emulator >/dev/null 2>&1; then
    TERM_CMD="x-terminal-emulator"
  elif command -v lxterminal >/dev/null 2>&1; then
    TERM_CMD="lxterminal"
  elif command -v xfce4-terminal >/dev/null 2>&1; then
    TERM_CMD="xfce4-terminal"
  fi
  if [ -n "$TERM_CMD" ]; then
    nohup env DISPLAY="$DISPLAY_NAME" bash -lc "$TERM_CMD" >"$DROOT/xterm.log" 2>&1 &
    XTERM_PID="$!"
    XTERM_NEW=1
    printf '%s\n' "$XTERM_PID" > "$WORK_TERM_PID_FILE"
  fi
fi
if [ -n "$XTERM_PID" ]; then
  move_window_to_workspace_by_pid "$XTERM_PID" "$WORK_WORKSPACE" || true
fi
ensure_desktop_count "$WORK_WORKSPACE"
if command -v xdotool >/dev/null 2>&1; then
  DISPLAY="$DISPLAY_NAME" xdotool set_desktop "$WORK_WORKSPACE" >/dev/null 2>&1 || true
elif command -v wmctrl >/dev/null 2>&1; then
  DISPLAY="$DISPLAY_NAME" wmctrl -s "$WORK_WORKSPACE" >/dev/null 2>&1 || true
fi

printf '{"ok":true,"action":"desktop_start","display":"%s","work_workspace":%s,"keepalive_workspace":%s}\n' "$DISPLAY_NAME" "$WORK_WORKSPACE" "$KEEPALIVE_WORKSPACE"
EOF2
  if [ ! -s "$launcher_tmp" ]; then
    rm -f "$launcher_tmp" >/dev/null 2>&1 || true
    return 1
  fi
  mv -f "$launcher_tmp" "$launcher"
  chmod 700 "$launcher" || true

  cat > "$service_cmdf_tmp" <<EOF2
PERSIST_ROOT="\$(ls -d /home/node/*/workspace 2>/dev/null | head -n1 || true)"; PERSIST_ROOT="\$(printf '%s' "\$PERSIST_ROOT" | sed -E 's#^(/home/node/[^/]+/workspace)/.+/workspace/?$#\\1#')"; if [ -d /home/node/a0/workspace ]; then PERSIST_ROOT="/home/node/a0/workspace"; fi; [ -z "\$PERSIST_ROOT" ] && PERSIST_ROOT="\$HOME"; HAPPYCAPY_PERSIST_ROOT="\$PERSIST_ROOT" HAPPYCAPY_KEEPALIVE_DISPLAY="${keepalive_display_cfg}" HAPPYCAPY_KEEPALIVE_WORKSPACE="${keepalive_workspace_cfg}" HAPPYCAPY_WORK_WORKSPACE="${work_workspace_cfg}" HAPPYCAPY_DESKTOP_RESOLUTION="${desktop_resolution_cfg}" HAPPYCAPY_WEBSOCKIFY_HEARTBEAT_SEC="${websockify_heartbeat_cfg}" bash "\$PERSIST_ROOT/.happycapy/desktop/start-desktop.sh"
EOF2
  if [ ! -s "$service_cmdf_tmp" ]; then
    rm -f "$service_cmdf_tmp" >/dev/null 2>&1 || true
    return 1
  fi
  mv -f "$service_cmdf_tmp" "$service_cmdf"
  chmod 600 "$service_cmdf" || true
}

run_external_recover_url_once() {
  local url boot_id stamp current target rc
  url="$(printf '%s' "$EXTERNAL_RECOVER_URL" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -n "$url" ] || return 0
  case "$url" in
    http://*|https://*) ;;
    *) return 0 ;;
  esac
  boot_id="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
  [ -z "$boot_id" ] && boot_id="boot-unknown"
  current="${url}|${boot_id}"
  stamp="$(cat "$EXTERNAL_RECOVER_STATE_FILE" 2>/dev/null || true)"
  if [ "$stamp" = "$current" ]; then
    return 0
  fi

  target="${PERSIST_DIR}/external-recover.sh"
  rc=0
  curl -fsSL --retry 2 --retry-delay 1 --retry-connrefused "$url" -o "$target" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    return 0
  fi
  chmod 700 "$target" >/dev/null 2>&1 || true
  set +e
  HAPPYCAPY_RECOVER_CHAIN=1 bash "$target" >>"$EXTERNAL_RECOVER_LOG" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ]; then
    printf '%s\n' "$current" > "$EXTERNAL_RECOVER_STATE_FILE"
  fi
}

run_workspace_autorestore() {
  local browser_rc desktop_rc
  install_log "autorestore_begin mode=${KEEPALIVE_MODE}"
  load_autorestore_preferences
  prepare_autorestore_install_round
  ensure_autorestore_docker || true
  browser_rc=0
  ensure_autorestore_browser || {
    browser_rc=$?
    keepalive_log "autorestore_browser_prepare_failed target=${AUTORESTORE_BROWSER:-none}"
  }
  desktop_rc=0
  ensure_autorestore_desktop_packages || {
    desktop_rc=$?
    keepalive_log "autorestore_desktop_prepare_failed"
  }
  if [ "$browser_rc" -eq 0 ] && [ "$desktop_rc" -eq 0 ]; then
    mark_autorestore_install_round_done
  fi
  ensure_keepalive_desktop_service_registration || keepalive_log "keepalive_desktop_service_registration_failed"
  if [ "$AUTORESTORE_START_SERVICES" -eq 1 ]; then
    restore_persisted_services || true
  fi
  restore_custom_recover_tasks || true
  run_external_recover_url_once || true
  keepalive_process_snapshot "autorestore_end" "mode=${KEEPALIVE_MODE}" || true
  install_log "autorestore_end mode=${KEEPALIVE_MODE}"
}

autorestore_worker_running() {
  local worker_pid
  if [ ! -f "$AUTORESTORE_WORKER_PID_FILE" ]; then
    return 1
  fi
  worker_pid="$(cat "$AUTORESTORE_WORKER_PID_FILE" 2>/dev/null | tr -dc '0-9')"
  [ -n "$worker_pid" ] || return 1
  if [ "$worker_pid" -gt 0 ] 2>/dev/null && kill -0 "$worker_pid" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

start_autorestore_worker_detached() {
  mkdir -p "$PERSIST_DIR"
  local boot_bin
  if autorestore_worker_running; then
    return 0
  fi

  boot_bin="$PERSIST_BOOTSTRAP"
  if [ ! -x "$boot_bin" ]; then
    if [ -x "$0" ]; then
      boot_bin="$0"
    else
      return 1
    fi
  fi

  nohup env \
    HAPPYCAPY_PERSIST_ROOT="$PERSIST_ROOT" \
    HAPPYCAPY_AUTORESTORE_ENV_FILE="$AUTORESTORE_ENV_FILE" \
    HAPPYCAPY_EXTERNAL_RECOVER_URL="$EXTERNAL_RECOVER_URL" \
    HAPPYCAPY_OUTPUT_MODE=short \
    HAPPYCAPY_WATCHDOG_MODE=0 \
    HAPPYCAPY_RECOVER_CHAIN=0 \
    bash "$boot_bin" --autorestore-only >>"$AUTORESTORE_WORKER_LOG" 2>&1 &
  printf '%s\n' "$!" > "$AUTORESTORE_WORKER_PID_FILE"
}

start_watchdog_worker_detached() {
  mkdir -p "$PERSIST_DIR"
  local old_pid boot_bin wait_sec wait_left
  old_pid=0
  if [ -f "$BOOTSTRAP_LOOP_PID_FILE" ]; then
    old_pid="$(cat "$BOOTSTRAP_LOOP_PID_FILE" 2>/dev/null | tr -dc '0-9')"
  fi
  [ -z "$old_pid" ] && old_pid=0
  if [ "$old_pid" -gt 0 ] && kill -0 "$old_pid" >/dev/null 2>&1; then
    return 0
  fi

  # Optional grace window for autorestore worker; default is 0 to avoid
  # delaying bootstrap exit and holding orchestration locks.
  wait_sec="${HAPPYCAPY_AUTORESTORE_START_WAIT_SEC:-0}"
  case "$wait_sec" in
    ''|*[!0-9]*) wait_sec=0 ;;
  esac
  wait_left="$wait_sec"
  if autorestore_worker_running; then
    install_log "watchdog_start_wait_autorestore wait_sec=${wait_sec}"
  fi
  while [ "$wait_left" -gt 0 ] && autorestore_worker_running; do
    sleep 1
    wait_left=$((wait_left - 1))
  done
  if autorestore_worker_running; then
    install_log "watchdog_start_wait_autorestore_timeout waited=${wait_sec}"
  fi

  boot_bin="$PERSIST_BOOTSTRAP"
  if [ ! -x "$boot_bin" ]; then
    if [ -x "$0" ]; then
      boot_bin="$0"
    else
      return 1
    fi
  fi

  nohup env \
    HAPPYCAPY_ACCESS_TOKEN="$ACCESS_TOKEN" \
    HAPPYCAPY_ALIAS="$ALIAS" \
    HAPPYCAPY_SSH_USER="$SSH_USER" \
    HAPPYCAPY_SSH_PASSWORD="$SSH_PASSWORD" \
    HAPPYCAPY_SSH_PORT="$SSH_PORT" \
    HAPPYCAPY_LOCAL_PORT="$LOCAL_PORT" \
    HAPPYCAPY_CHISEL_AUTH="$CHISEL_AUTH" \
    HAPPYCAPY_REGISTRY_FILE="$REGISTRY_FILE" \
    HAPPYCAPY_REGISTRY_UPLOAD_API="$UPLOAD_API" \
    HAPPYCAPY_REGISTRY_BASE="$REGISTRY_BASE" \
    HAPPYCAPY_PERSIST_ROOT="$PERSIST_ROOT" \
    HAPPYCAPY_RECOVER_SCRIPT="$RECOVER_SCRIPT_PATH" \
    HAPPYCAPY_REGISTRY_URL_PATH="$REGISTRY_URL_PATH" \
    HAPPYCAPY_CONTROL_PORT="$CONTROL_PORT" \
    HAPPYCAPY_CONTROL_API_URL_PATH="$CONTROL_API_URL_PATH" \
    HAPPYCAPY_HEARTBEAT_URL_PATH="$HEARTBEAT_URL_PATH" \
    HAPPYCAPY_HEARTBEAT_INTERVAL_SEC="$HEARTBEAT_INTERVAL_SEC" \
    HAPPYCAPY_HEARTBEAT_EXTERNAL_KEEPALIVE="$HEARTBEAT_EXTERNAL_KEEPALIVE" \
    HAPPYCAPY_KEEPALIVE_MODE="$KEEPALIVE_MODE" \
    HAPPYCAPY_KEEPALIVE_INTERVAL_SEC="$KEEPALIVE_INTERVAL_SEC" \
    HAPPYCAPY_KEEPALIVE_RECOVERY_INTERVAL_SEC="$KEEPALIVE_RECOVERY_INTERVAL_SEC" \
    HAPPYCAPY_KEEPALIVE_BROWSER_VISIBLE="$KEEPALIVE_BROWSER_VISIBLE" \
    HAPPYCAPY_KEEPALIVE_VISIBLE_PATH="$KEEPALIVE_VISIBLE_PATH" \
    HAPPYCAPY_KEEPALIVE_VNC_PAGE="$KEEPALIVE_VNC_PAGE" \
    HAPPYCAPY_KEEPALIVE_PAGE_PATH="$KEEPALIVE_PAGE_PATH" \
    HAPPYCAPY_KEEPALIVE_TRIGGER_PATH="$KEEPALIVE_TRIGGER_PATH" \
    HAPPYCAPY_KEEPALIVE_FORCE_REFRESH="$KEEPALIVE_FORCE_REFRESH" \
    HAPPYCAPY_KEEPALIVE_FORCE_REFRESH_MODE="$KEEPALIVE_FORCE_REFRESH_MODE" \
    HAPPYCAPY_KEEPALIVE_REFRESH_MODE_PATH="$KEEPALIVE_REFRESH_MODE_PATH" \
    HAPPYCAPY_KEEPALIVE_DISPLAY="$KEEPALIVE_DISPLAY" \
    HAPPYCAPY_KEEPALIVE_WORKSPACE="$KEEPALIVE_WORKSPACE" \
    HAPPYCAPY_WORK_WORKSPACE="$WORK_WORKSPACE" \
    HAPPYCAPY_KEEPALIVE_PID_FILE="$KEEPALIVE_PID_FILE" \
    HAPPYCAPY_KEEPALIVE_URL_PATH="$KEEPALIVE_URL_PATH" \
    HAPPYCAPY_KEEPALIVE_PROFILE_DIR="$KEEPALIVE_PROFILE_DIR" \
    HAPPYCAPY_KEEPALIVE_STATE_PATH="$KEEPALIVE_STATE_PATH" \
    HAPPYCAPY_KEEPALIVE_LOG_PATH="$KEEPALIVE_LOG_PATH" \
    HAPPYCAPY_KEEPALIVE_BROWSER_LOG="$KEEPALIVE_BROWSER_LOG" \
    HAPPYCAPY_AUTORESTORE_ENV_FILE="$AUTORESTORE_ENV_FILE" \
    HAPPYCAPY_EXTERNAL_RECOVER_URL="$EXTERNAL_RECOVER_URL" \
    HAPPYCAPY_OUTPUT_MODE=short \
    HAPPYCAPY_WATCHDOG_MODE=1 \
    HAPPYCAPY_RECOVER_CHAIN=0 \
    HAPPYCAPY_BOOT_BIN="$boot_bin" \
    bash -lc 'sleep 2; exec bash "$HAPPYCAPY_BOOT_BIN"' >>"$BOOTSTRAP_LOOP_LOG" 2>&1 &
  printf '%s\n' "$!" > "$BOOTSTRAP_LOOP_PID_FILE"
}

install_chisel() {
  local chisel_bin
  chisel_bin="$(find_chisel_bin || true)"
  if [ -n "$chisel_bin" ]; then
    echo "$chisel_bin"
    return 0
  fi

  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) return 1 ;;
  esac

  local url tmp_gz tmp_bin ok rel_json
  rel_json="$(curl -fsSL --retry 2 --retry-delay 1 https://api.github.com/repos/jpillora/chisel/releases/latest 2>/dev/null || true)"
  url="$(printf '%s' "$rel_json" | sed 's/,/\n/g' | sed -n "s|.*\"browser_download_url\"[[:space:]]*:[[:space:]]*\"\\([^\"]*chisel_[^\"]*_linux_${arch}\\.gz\\)\".*|\\1|p" | head -n1)"
  if [ -z "$url" ]; then
    url="https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_${arch}.gz"
  fi
  tmp_gz="$(mktemp /tmp/chisel.XXXXXX.gz)"
  tmp_bin="$(mktemp /tmp/chisel.XXXXXX)"
  ok=0

  for attempt in 1 2 3; do
    rm -f "$tmp_gz" "$tmp_bin"
    tmp_gz="$(mktemp /tmp/chisel.XXXXXX.gz)"
    tmp_bin="$(mktemp /tmp/chisel.XXXXXX)"
    if curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused "$url" -o "$tmp_gz" \
      && gzip -t "$tmp_gz" \
      && gzip -dc "$tmp_gz" > "$tmp_bin" \
      && [ -s "$tmp_bin" ]; then
      ok=1
      break
    fi
    sleep $((attempt * 2))
  done

  if [ "$ok" -ne 1 ]; then
    rm -f "$tmp_gz" "$tmp_bin"
    return 1
  fi

  chmod +x "$tmp_bin"
  if can_root; then
    run_root install -m 755 "$tmp_bin" /usr/local/bin/chisel
    chisel_bin="/usr/local/bin/chisel"
  else
    mkdir -p "$HOME/.local/bin"
    install -m 755 "$tmp_bin" "$HOME/.local/bin/chisel"
    chisel_bin="$HOME/.local/bin/chisel"
    export PATH="$HOME/.local/bin:$PATH"
  fi

  rm -f "$tmp_gz" "$tmp_bin"
  echo "$chisel_bin"
}

configure_sshd() {
  local sshd_bin
  sshd_bin="$(find_sshd_bin || true)"

  if [ -z "$sshd_bin" ] && can_root && command -v apt-get >/dev/null 2>&1; then
    with_retry 2 run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server >/tmp/hc-sshd-install.log 2>&1 || true
    sshd_bin="$(find_sshd_bin || true)"
  fi

  if [ -z "$sshd_bin" ]; then
    return 1
  fi

  if ! can_root; then
    return 0
  fi

  run_root ssh-keygen -A >/dev/null 2>&1 || true
  run_root mkdir -p /var/run/sshd
  set_sshd_option "PasswordAuthentication" "yes" || true
  set_sshd_option "PermitRootLogin" "yes" || true
  set_sshd_option "KbdInteractiveAuthentication" "yes" || true

  if id -u "$SSH_USER" >/dev/null 2>&1; then
    printf '%s:%s\n' "$SSH_USER" "$SSH_PASSWORD" | run_root chpasswd || true
  fi
  return 0
}

resolve_user_home_dir() {
  local user_name="$1"
  local home_dir
  home_dir=""
  if [ -n "$user_name" ] && command -v getent >/dev/null 2>&1; then
    home_dir="$(getent passwd "$user_name" 2>/dev/null | awk -F: '{print $6}' | head -n1 || true)"
  fi
  if [ -z "$home_dir" ] && [ -n "$user_name" ]; then
    home_dir="$(eval "printf '%s' ~${user_name}" 2>/dev/null || true)"
  fi
  if [ -z "$home_dir" ]; then
    home_dir="$HOME"
  fi
  printf '%s\n' "$home_dir"
}

download_file_atomic() {
  local url="$1"
  local dest="$2"
  local tmpf
  [ -n "$url" ] || return 1
  [ -n "$dest" ] || return 1
  mkdir -p "$(dirname "$dest")" >/dev/null 2>&1 || true
  tmpf="$(mktemp "/tmp/hc-fetch.XXXXXX")"
  if with_retry 3 curl -fsSL --retry 2 --retry-delay 1 --retry-connrefused "$url" -o "$tmpf" >/dev/null 2>&1; then
    mv -f "$tmpf" "$dest"
    return 0
  fi
  rm -f "$tmpf" >/dev/null 2>&1 || true
  return 1
}

ensure_git_zsh_installed() {
  local rc_update rc_install
  if command -v git >/dev/null 2>&1 && command -v zsh >/dev/null 2>&1; then
    return 0
  fi
  if ! can_root; then
    install_log "shell_deps_skip reason=no_root has_git=$([ -x "$(command -v git || true)" ] && echo 1 || echo 0) has_zsh=$([ -x "$(command -v zsh || true)" ] && echo 1 || echo 0)"
    return 1
  fi
  if command -v apt-get >/dev/null 2>&1; then
    set +e
    with_retry 2 run_root apt-get -o DPkg::Lock::Timeout=180 update -y >/tmp/hc-shell-deps-update.log 2>&1
    rc_update=$?
    with_retry 2 run_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=180 install -y git zsh >/tmp/hc-shell-deps-install.log 2>&1
    rc_install=$?
    set -e
    install_log "shell_deps_install manager=apt rc_update=${rc_update} rc_install=${rc_install} update_log=/tmp/hc-shell-deps-update.log install_log=/tmp/hc-shell-deps-install.log"
  elif command -v apk >/dev/null 2>&1; then
    set +e
    with_retry 2 run_root apk add --no-cache git zsh >/tmp/hc-shell-deps-install.log 2>&1
    rc_install=$?
    set -e
    install_log "shell_deps_install manager=apk rc_install=${rc_install} install_log=/tmp/hc-shell-deps-install.log"
  elif command -v yum >/dev/null 2>&1; then
    set +e
    with_retry 2 run_root yum install -y git zsh >/tmp/hc-shell-deps-install.log 2>&1
    rc_install=$?
    set -e
    install_log "shell_deps_install manager=yum rc_install=${rc_install} install_log=/tmp/hc-shell-deps-install.log"
  fi
  command -v git >/dev/null 2>&1 && command -v zsh >/dev/null 2>&1
}

shell_profile_is_ready() {
  local home_dir="$1"
  local marker_ver
  [ -n "$home_dir" ] || return 1
  [ -s "${home_dir}/.bashrc" ] || return 1
  [ -s "${home_dir}/.zshrc" ] || return 1
  [ -s "${home_dir}/.p10k.zsh" ] || return 1
  [ -d "${home_dir}/.oh-my-zsh" ] || return 1
  [ -d "${home_dir}/.oh-my-zsh/custom/themes/powerlevel10k" ] || return 1
  marker_ver="$(cat "$SHELL_PROFILE_MARKER" 2>/dev/null | head -n1 | tr -d '\r' || true)"
  [ "$marker_ver" = "$SHELL_PROFILE_VERSION" ]
}

mark_shell_profile_ready() {
  mkdir -p "$(dirname "$SHELL_PROFILE_MARKER")" >/dev/null 2>&1 || true
  printf '%s\n' "$SHELL_PROFILE_VERSION" > "$SHELL_PROFILE_MARKER" 2>/dev/null || true
}

bootstrap_shell_profile_for_user() {
  local home_dir="$1"
  local user_name="${2:-}"
  local installer p10k_dir bashrc zshrc p10krc rc
  [ -n "$home_dir" ] || return 1
  bashrc="${home_dir}/.bashrc"
  zshrc="${home_dir}/.zshrc"
  p10krc="${home_dir}/.p10k.zsh"
  install_log "shell_profile_setup_begin home=${home_dir}"

  installer="/tmp/hc-ohmyzsh-install.sh"
  if ! download_file_atomic "$OHMYZSH_INSTALL_URL" "$installer"; then
    install_log "shell_profile_setup_fail step=download_ohmyzsh_installer url=${OHMYZSH_INSTALL_URL}"
    return 1
  fi

  rm -rf "${home_dir}/.oh-my-zsh" >/dev/null 2>&1 || true
  set +e
  unset REPO REMOTE BRANCH
  printf 'y\n' | env HOME="$home_dir" ZSH="${home_dir}/.oh-my-zsh" RUNZSH=no CHSH=no KEEP_ZSHRC=yes sh "$installer" >/tmp/hc-ohmyzsh-install.log 2>&1
  rc=$?
  set -e
  rm -f "$installer" >/dev/null 2>&1 || true
  if [ "$rc" -ne 0 ]; then
    install_log "shell_profile_setup_fail step=install_ohmyzsh rc=${rc} log=/tmp/hc-ohmyzsh-install.log"
    return 1
  fi

  p10k_dir="${home_dir}/.oh-my-zsh/custom/themes/powerlevel10k"
  rm -rf "$p10k_dir" >/dev/null 2>&1 || true
  set +e
  git clone --depth=1 "$P10K_REPO_URL" "$p10k_dir" >/tmp/hc-p10k-install.log 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    install_log "shell_profile_setup_fail step=install_p10k rc=${rc} repo=${P10K_REPO_URL} log=/tmp/hc-p10k-install.log"
    return 1
  fi

  if ! download_file_atomic "$DOTFILE_BASHRC_URL" "$bashrc"; then
    install_log "shell_profile_setup_fail step=download_dotfile name=.bashrc url=${DOTFILE_BASHRC_URL}"
    return 1
  fi
  if ! download_file_atomic "$DOTFILE_ZSHRC_URL" "$zshrc"; then
    install_log "shell_profile_setup_fail step=download_dotfile name=.zshrc url=${DOTFILE_ZSHRC_URL}"
    return 1
  fi
  if ! download_file_atomic "$DOTFILE_P10K_URL" "$p10krc"; then
    install_log "shell_profile_setup_fail step=download_dotfile name=.p10k.zsh url=${DOTFILE_P10K_URL}"
    return 1
  fi

  if [ -n "$user_name" ] && id -u "$user_name" >/dev/null 2>&1 && can_root; then
    run_root chown -R "$user_name":"$user_name" "${home_dir}/.oh-my-zsh" >/dev/null 2>&1 || true
    run_root chown "$user_name":"$user_name" "$bashrc" "$zshrc" "$p10krc" >/dev/null 2>&1 || true
  fi

  mark_shell_profile_ready
  install_log "shell_profile_setup_end home=${home_dir} ohmyzsh=1 p10k=1"
  return 0
}

upsert_shell_defaults_block() {
  local rc_file="$1"
  local begin_marker end_marker tmpf
  [ -n "$rc_file" ] || return 1
  begin_marker="# >>> happycapy-term-defaults >>>"
  end_marker="# <<< happycapy-term-defaults <<<"
  mkdir -p "$(dirname "$rc_file")" >/dev/null 2>&1 || true
  [ -f "$rc_file" ] || : > "$rc_file"
  tmpf="$(mktemp "/tmp/hc-shell-defaults.XXXXXX")"
  awk -v b="$begin_marker" -v e="$end_marker" '
    $0 == b {skip=1; next}
    $0 == e {skip=0; next}
    !skip {print}
  ' "$rc_file" > "$tmpf" 2>/dev/null || cp -f "$rc_file" "$tmpf"
  cat >> "$tmpf" <<'EOF'
# >>> happycapy-term-defaults >>>
if [ -t 1 ]; then
  export COLUMNS="${COLUMNS:-240}"
  export LINES="${LINES:-60}"
  if command -v stty >/dev/null 2>&1; then
    _hc_sz="$(stty size 2>/dev/null || true)"
    _hc_rows="$(printf '%s' "$_hc_sz" | awk '{print $1}')"
    _hc_cols="$(printf '%s' "$_hc_sz" | awk '{print $2}')"
    case "${_hc_rows:-0}" in ''|*[!0-9]*) _hc_rows=0 ;; esac
    case "${_hc_cols:-0}" in ''|*[!0-9]*) _hc_cols=0 ;; esac
    if [ "$_hc_cols" -gt 0 ] && [ "$_hc_cols" -lt 200 ]; then
      stty cols 220 >/dev/null 2>&1 || true
    fi
    if [ "$_hc_rows" -gt 0 ] && [ "$_hc_rows" -lt 45 ]; then
      stty rows 55 >/dev/null 2>&1 || true
    fi
    unset _hc_sz _hc_rows _hc_cols
  fi
  alias ps='ps -ww'
fi
# <<< happycapy-term-defaults <<<
EOF
  mv -f "$tmpf" "$rc_file"
  return 0
}

ensure_shell_defaults_for_user() {
  local user_name="$1"
  local home_dir bashrc zshrc p10krc bash_profile
  home_dir="$(resolve_user_home_dir "$user_name")"
  [ -n "$home_dir" ] || return 1

  ensure_git_zsh_installed || true
  if command -v git >/dev/null 2>&1 && command -v zsh >/dev/null 2>&1; then
    if ! shell_profile_is_ready "$home_dir"; then
      bootstrap_shell_profile_for_user "$home_dir" "$user_name" || true
    fi
  fi

  bashrc="${home_dir}/.bashrc"
  zshrc="${home_dir}/.zshrc"
  p10krc="${home_dir}/.p10k.zsh"
  bash_profile="${home_dir}/.bash_profile"
  upsert_shell_defaults_block "$bashrc" || true
  upsert_shell_defaults_block "$zshrc" || true
  printf '%s\n' '[ -f ~/.bashrc ] && source ~/.bashrc' > "$bash_profile" 2>/dev/null || true
  if id -u "$user_name" >/dev/null 2>&1; then
    if can_root; then
      run_root chown "$user_name":"$user_name" "$bashrc" "$zshrc" "$p10krc" "$bash_profile" >/dev/null 2>&1 || true
    fi
  fi
  return 0
}

write_reporter() {
  local writer tmp_writer
  tmp_writer="$(mktemp /tmp/hc-registry-writer.XXXXXX)"
  cat > "$tmp_writer" <<EOF2
#!/usr/bin/env bash
set -euo pipefail
ACCESS_TOKEN="${ACCESS_TOKEN}"
ALIAS="${ALIAS}"
CHISEL_AUTH="${CHISEL_AUTH}"
SSH_USER="${SSH_USER}"
SSH_PASSWORD="${SSH_PASSWORD}"
SSH_PORT="${SSH_PORT}"
LOCAL_PORT="${LOCAL_PORT}"
REGISTRY_FILE="${REGISTRY_FILE}"
UPLOAD_API="${UPLOAD_API}"
REGISTRY_BASE="${REGISTRY_BASE}"
REGISTRY_URL_PATH="${REGISTRY_URL_PATH}"
CONTROL_PORT="${CONTROL_PORT}"
CONTROL_API_URL_PATH="${CONTROL_API_URL_PATH}"
HEARTBEAT_URL_PATH="${HEARTBEAT_URL_PATH}"
EXPORT_PORT_TIMEOUT_SEC="${EXPORT_PORT_TIMEOUT_SEC}"
UPLOAD_TIMEOUT_SEC="${UPLOAD_TIMEOUT_SEC}"

server="\${HAPPYCAPY_CHISEL_SERVER:-}"
if [ -z "\$server" ]; then
  resp="\$(curl -sS -m "\$EXPORT_PORT_TIMEOUT_SEC" -X POST "https://happycapy.ai/api/export-port" \\
    -H "Authorization: Bearer \$ACCESS_TOKEN" \\
    -H "Cookie: authToken=\$ACCESS_TOKEN" \\
    -H "Content-Type: application/json" \\
    --data '{"port":8080}' || true)"
  preview="\$(printf '%s' "\$resp" | sed -n 's/.*"previewUrl"[[:space:]]*:[[:space:]]*"\\([^\"]*\\)".*/\\1/p' | head -n1)"
  if [ -z "\$preview" ]; then
    exit 1
  fi
  server="https://\${preview#https://}"
fi
control_url="\${HAPPYCAPY_CONTROL_API_URL:-}"
if [ -z "\$control_url" ]; then
  resp2="\$(curl -sS -m "\$EXPORT_PORT_TIMEOUT_SEC" -X POST "https://happycapy.ai/api/export-port" \\
    -H "Authorization: Bearer \$ACCESS_TOKEN" \\
    -H "Cookie: authToken=\$ACCESS_TOKEN" \\
    -H "Content-Type: application/json" \\
    --data "{\\"port\\":\${CONTROL_PORT}}" || true)"
  preview2="\$(printf '%s' "\$resp2" | sed -n 's/.*"previewUrl"[[:space:]]*:[[:space:]]*"\\([^\"]*\\)".*/\\1/p' | head -n1)"
  if [ -n "\$preview2" ]; then
    control_url="https://\${preview2#https://}"
  fi
fi
heartbeat_url=""
if [ -n "\$control_url" ]; then
  heartbeat_url="\${control_url%/}/heartbeat"
fi
now="\$(date -u +%Y-%m-%dT%H:%M:%SZ)"
tmpf="/tmp/\${REGISTRY_FILE}"
cat > "\$tmpf" <<JSON
{"schema":"happycapy-registry-v1","happycapy_username":"\$ALIAS","alias":"\$ALIAS","chisel_server":"\$server","chisel_auth":"\$CHISEL_AUTH","ssh_user":"\$SSH_USER","ssh_password":"\$SSH_PASSWORD","ssh_port":\$SSH_PORT,"local_port":\$LOCAL_PORT,"remote_port":\$SSH_PORT,"control_api_port":\$CONTROL_PORT,"control_api_url":"\$control_url","heartbeat_url":"\$heartbeat_url","updated_at":"\$now","service_count":0,"services":[]}
JSON

attempt=1
while [ "\$attempt" -le 2 ]; do
  up="\$(curl -sS -m "\$UPLOAD_TIMEOUT_SEC" -F "file=@\${tmpf};filename=\${REGISTRY_FILE};type=text/plain" "\$UPLOAD_API" || true)"
  rel="\$(printf '%s' "\$up" | sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\\([^\"]*\\)".*/\\1/p' | head -n1)"
  if [ -n "\$rel" ]; then
    mkdir -p "\$(dirname "\$REGISTRY_URL_PATH")" 2>/dev/null || true
    printf '%s\n' "\${REGISTRY_BASE}/\${rel#/}" > "\$REGISTRY_URL_PATH"
    if [ -n "\$control_url" ]; then
      mkdir -p "\$(dirname "\$CONTROL_API_URL_PATH")" 2>/dev/null || true
      printf '%s\n' "\$control_url" > "\$CONTROL_API_URL_PATH"
    fi
    if [ -n "\$heartbeat_url" ]; then
      mkdir -p "\$(dirname "\$HEARTBEAT_URL_PATH")" 2>/dev/null || true
      printf '%s\n' "\$heartbeat_url" > "\$HEARTBEAT_URL_PATH"
    fi
    exit 0
  fi
  attempt=\$((attempt + 1))
  sleep 1
done

exit 1
EOF2

  mkdir -p "$PERSIST_DIR"
  writer="$PERSIST_DIR/happycapy-report-registry.sh"
  install -m 700 "$tmp_writer" "$writer"

  rm -f "$tmp_writer"
  echo "$writer"
}

write_control_api_server() {
  mkdir -p "$PERSIST_DIR"
  cat > "$CONTROL_API_SCRIPT" <<'EOF2'
#!/usr/bin/env node
// happycapy-control-api-version: 2026-02-24-observability-v1
const http = require("http");
const fs = require("fs");
const { spawnSync, spawn } = require("child_process");
const { URL } = require("url");

const cfg = {
  alias: process.env.HAPPYCAPY_ALIAS || "acc001",
  token: process.env.HAPPYCAPY_ACCESS_TOKEN || "",
  sshPort: Number(process.env.HAPPYCAPY_SSH_PORT || "2222"),
  controlPort: Number(process.env.HAPPYCAPY_CONTROL_PORT || "18080"),
  recoverScript: process.env.HAPPYCAPY_RECOVER_SCRIPT || "",
  writer: process.env.HAPPYCAPY_REGISTRY_WRITER || "",
  registryUrlPath: process.env.HAPPYCAPY_REGISTRY_URL_PATH || "",
  controlApiUrlPath: process.env.HAPPYCAPY_CONTROL_API_URL_PATH || "",
  heartbeatUrlPath: process.env.HAPPYCAPY_HEARTBEAT_URL_PATH || "",
  heartbeatIntervalSec: Number(process.env.HAPPYCAPY_HEARTBEAT_INTERVAL_SEC || "300"),
  heartbeatExternalKeepalive: ["1", "true", "yes", "on"].includes(
    String(process.env.HAPPYCAPY_HEARTBEAT_EXTERNAL_KEEPALIVE || "1").toLowerCase()
  ),
  keepaliveMode: String(process.env.HAPPYCAPY_KEEPALIVE_MODE || "vnc-browser"),
  keepaliveIntervalSec: Number(process.env.HAPPYCAPY_KEEPALIVE_INTERVAL_SEC || "300"),
  keepaliveBrowserVisible: ["1", "true", "yes", "on"].includes(
    String(process.env.HAPPYCAPY_KEEPALIVE_BROWSER_VISIBLE || "0").toLowerCase()
  ),
  keepaliveVisiblePath: process.env.HAPPYCAPY_KEEPALIVE_VISIBLE_PATH || "",
  keepaliveTriggerPath: process.env.HAPPYCAPY_KEEPALIVE_TRIGGER_PATH || "",
  keepaliveDisplay: String(process.env.HAPPYCAPY_KEEPALIVE_DISPLAY || ":1"),
  keepaliveWorkspace: Number(process.env.HAPPYCAPY_KEEPALIVE_WORKSPACE || "1"),
  workWorkspace: Number(process.env.HAPPYCAPY_WORK_WORKSPACE || "0"),
  keepalivePidFile: process.env.HAPPYCAPY_KEEPALIVE_PID_FILE || "",
  keepaliveUrlPath: process.env.HAPPYCAPY_KEEPALIVE_URL_PATH || "",
  keepaliveProfileDir: process.env.HAPPYCAPY_KEEPALIVE_PROFILE_DIR || "",
  keepaliveLogPath: process.env.HAPPYCAPY_KEEPALIVE_LOG_PATH || "",
  keepaliveBrowserLogPath: process.env.HAPPYCAPY_KEEPALIVE_BROWSER_LOG || "",
  keepaliveStatePath: process.env.HAPPYCAPY_KEEPALIVE_STATE_PATH || "",
  installAuditLogPath: process.env.HAPPYCAPY_INSTALL_AUDIT_LOG_PATH || "/tmp/happycapy-install-audit.log",
  processAuditLogPath: process.env.HAPPYCAPY_PROCESS_AUDIT_LOG_PATH || "/tmp/happycapy-process-audit.log",
  keepaliveForceRefresh: ["1", "true", "yes", "on"].includes(
    String(process.env.HAPPYCAPY_KEEPALIVE_FORCE_REFRESH || "0").toLowerCase()
  ),
  keepaliveForceRefreshMode: String(process.env.HAPPYCAPY_KEEPALIVE_FORCE_REFRESH_MODE || "http_touch"),
  keepaliveVncPage: String(process.env.HAPPYCAPY_KEEPALIVE_VNC_PAGE || "vnc.html"),
  keepalivePagePath: process.env.HAPPYCAPY_KEEPALIVE_PAGE_PATH || "",
  keepaliveRefreshModePath: process.env.HAPPYCAPY_KEEPALIVE_REFRESH_MODE_PATH || "",
  exportTimeout: Number(process.env.HAPPYCAPY_EXPORT_PORT_TIMEOUT_SEC || "8"),
  hardRestartSshd: ["1", "true", "yes", "on"].includes(
    String(process.env.HAPPYCAPY_HARD_RECOVER_RESTART_SSHD || "0").toLowerCase()
  ),
};
const RECOVER_LOG_PATH = "/tmp/hc-recover-only.log";
let recoverInProgress = false;
let lastRecoverAt = 0;
let lastRecoverOk = null;
let lastRecoverRc = null;
let lastRecoverOutput = "";
let heartbeatCount = 0;
let lastHeartbeatAt = 0;
let lastHeartbeatSource = "";
let lastHeartbeatVia = "";
const controlApiStartedAtMs = Date.now();

function formatUptimeHuman(elapsedMs) {
  const minuteMs = 60 * 1000;
  const hourMinutes = 60;
  const dayMinutes = 24 * hourMinutes;
  const monthMinutes = 30 * dayMinutes;
  const totalMinutes = Math.max(0, Math.floor(Number(elapsedMs || 0) / minuteMs));

  if (totalMinutes >= monthMinutes) {
    const months = Math.floor(totalMinutes / monthMinutes);
    const remMinutes = totalMinutes % monthMinutes;
    const days = Math.floor(remMinutes / dayMinutes);
    return `${months}月${days}天`;
  }

  if (totalMinutes >= dayMinutes) {
    const days = Math.floor(totalMinutes / dayMinutes);
    const remMinutes = totalMinutes % dayMinutes;
    const hours = Math.floor(remMinutes / hourMinutes);
    return `${days}天${hours}小时`;
  }

  const hours = Math.floor(totalMinutes / hourMinutes);
  const minutes = totalMinutes % hourMinutes;
  return `${hours}小时${minutes}分钟`;
}

function controlApiUptimeHuman() {
  return formatUptimeHuman(Date.now() - controlApiStartedAtMs);
}

function readMachineUptimeMs() {
  try {
    const raw = String(fs.readFileSync("/proc/uptime", "utf8") || "").trim();
    const first = raw.split(/\s+/)[0] || "";
    const sec = Number.parseFloat(first);
    if (Number.isFinite(sec) && sec >= 0) {
      return Math.floor(sec * 1000);
    }
  } catch {}
  return null;
}

function machineUptimeHuman() {
  const ms = readMachineUptimeMs();
  if (ms === null) return "";
  return formatUptimeHuman(ms);
}

function normalizeHeartbeatSource(raw, fallback = "unknown") {
  const src = String(raw || "").trim();
  if (!src) return fallback;
  return src.replace(/[^a-zA-Z0-9_.:-]/g, "_").slice(0, 64) || fallback;
}

function touchHeartbeat(source, via) {
  heartbeatCount += 1;
  lastHeartbeatAt = Date.now();
  lastHeartbeatSource = normalizeHeartbeatSource(source, "unknown");
  lastHeartbeatVia = normalizeHeartbeatSource(via, "unknown");
}

function runBash(script, timeoutMs = 15000, envExtra = {}) {
  const ret = spawnSync("bash", ["-lc", script], {
    encoding: "utf8",
    timeout: timeoutMs,
    maxBuffer: 8 * 1024 * 1024,
    env: { ...process.env, ...envExtra },
  });
  const out = `${ret.stdout || ""}${ret.stderr || ""}`;
  return { ok: ret.status === 0, code: ret.status ?? -1, out };
}

function readText(path) {
  if (!path) return "";
  try {
    return String(fs.readFileSync(path, "utf8")).trim();
  } catch {
    return "";
  }
}

function parseKeyValueFile(path) {
  const out = {};
  const raw = readText(path);
  if (!raw) return out;
  for (const line of raw.split(/\r?\n/)) {
    const text = String(line || "").trim();
    if (!text || text.startsWith("#")) continue;
    const idx = text.indexOf("=");
    if (idx <= 0) continue;
    const key = text.slice(0, idx).trim();
    const val = text.slice(idx + 1).trim();
    if (!key) continue;
    out[key] = val;
  }
  return out;
}

function decodeB64(text) {
  try {
    return Buffer.from(String(text || ""), "base64").toString("utf8");
  } catch {
    return "";
  }
}

function parseBool(raw, fallback = false) {
  const text = String(raw || "").trim().toLowerCase();
  if (!text) return Boolean(fallback);
  if (["1", "true", "yes", "on"].includes(text)) return true;
  if (["0", "false", "no", "off"].includes(text)) return false;
  return Boolean(fallback);
}

function parseKeepaliveRefreshMode(raw, fallback = "http_touch") {
  const text = String(raw || "").trim().toLowerCase();
  if (["cdp_reload", "visible_reload", "tab_reload", "reload"].includes(text)) return "cdp_reload";
  if (["http_touch", "touch", "http"].includes(text)) return "http_touch";
  return String(fallback || "http_touch") === "cdp_reload" ? "cdp_reload" : "http_touch";
}

function parseKeepalivePage(raw, fallback = "vnc.html") {
  const text = String(raw || "").trim().toLowerCase();
  if (["vnc.html", "vnc", "full", "classic"].includes(text)) return "vnc.html";
  if (["vnc_lite.html", "vnc-lite", "vnc_lite", "lite"].includes(text)) return "vnc_lite.html";
  return String(fallback || "vnc.html").trim().toLowerCase() === "vnc_lite.html" ? "vnc_lite.html" : "vnc.html";
}

function readKeepaliveVisibleDesired() {
  const raw = readText(cfg.keepaliveVisiblePath || "");
  if (!raw) return Boolean(cfg.keepaliveBrowserVisible);
  return parseBool(raw, cfg.keepaliveBrowserVisible);
}

function writeKeepaliveVisibleDesired(visible) {
  const want = Boolean(visible);
  const current = readKeepaliveVisibleDesired();
  const changed = current !== want;
  if (!cfg.keepaliveVisiblePath) {
    return { ok: false, changed: false, path: "", error: "keepalive_visible_path_missing" };
  }
  try {
    const p = String(cfg.keepaliveVisiblePath || "");
    const dir = require("path").dirname(p);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(p, want ? "1\n" : "0\n", "utf8");
    return { ok: true, changed, path: p };
  } catch (e) {
    return { ok: false, changed: false, path: String(cfg.keepaliveVisiblePath || ""), error: String(e || "write_failed") };
  }
}

function requestKeepaliveTick(reason) {
  if (!cfg.keepaliveTriggerPath) return { ok: false, path: "", error: "keepalive_trigger_path_missing" };
  try {
    const p = String(cfg.keepaliveTriggerPath || "");
    const dir = require("path").dirname(p);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(p, `${new Date().toISOString()} ${String(reason || "manual")}\n`, "utf8");
    return { ok: true, path: p };
  } catch (e) {
    return { ok: false, path: String(cfg.keepaliveTriggerPath || ""), error: String(e || "trigger_write_failed") };
  }
}

function readKeepaliveRefreshModeDesired() {
  const fallback = parseKeepaliveRefreshMode(cfg.keepaliveForceRefreshMode || "http_touch", "http_touch");
  const raw = readText(cfg.keepaliveRefreshModePath || "");
  if (!raw) return fallback;
  return parseKeepaliveRefreshMode(raw, fallback);
}

function writeKeepaliveRefreshModeDesired(mode) {
  const want = parseKeepaliveRefreshMode(mode, readKeepaliveRefreshModeDesired());
  const current = readKeepaliveRefreshModeDesired();
  const changed = current !== want;
  if (!cfg.keepaliveRefreshModePath) {
    return { ok: false, changed: false, path: "", mode: want, error: "keepalive_refresh_mode_path_missing" };
  }
  try {
    const p = String(cfg.keepaliveRefreshModePath || "");
    const dir = require("path").dirname(p);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(p, `${want}\n`, "utf8");
    return { ok: true, changed, path: p, mode: want };
  } catch (e) {
    return {
      ok: false,
      changed: false,
      path: String(cfg.keepaliveRefreshModePath || ""),
      mode: want,
      error: String(e || "write_failed"),
    };
  }
}

function readKeepalivePageDesired() {
  const fallback = parseKeepalivePage(cfg.keepaliveVncPage || "vnc.html", "vnc.html");
  const raw = readText(cfg.keepalivePagePath || "");
  if (!raw) return fallback;
  return parseKeepalivePage(raw, fallback);
}

function writeKeepalivePageDesired(page) {
  const want = parseKeepalivePage(page, readKeepalivePageDesired());
  const current = readKeepalivePageDesired();
  const changed = current !== want;
  if (!cfg.keepalivePagePath) {
    return { ok: false, changed: false, path: "", page: want, error: "keepalive_page_path_missing" };
  }
  try {
    const p = String(cfg.keepalivePagePath || "");
    const dir = require("path").dirname(p);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(p, `${want}\n`, "utf8");
    return { ok: true, changed, path: p, page: want };
  } catch (e) {
    return {
      ok: false,
      changed: false,
      path: String(cfg.keepalivePagePath || ""),
      page: want,
      error: String(e || "write_failed"),
    };
  }
}

function readPid(path) {
  const raw = readText(path);
  const n = Number.parseInt(raw || "0", 10);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n;
}

function pidAlive(pid) {
  const n = Number(pid || 0);
  if (!Number.isFinite(n) || n <= 0) return false;
  try {
    process.kill(n, 0);
    return true;
  } catch {
    return false;
  }
}

function pidCommandLine(pid) {
  const n = Number(pid || 0);
  if (!Number.isFinite(n) || n <= 0) return "";
  const res = runBash(`tr '\\0' ' ' </proc/"$PID"/cmdline 2>/dev/null || ps -p "$PID" -o args= 2>/dev/null || true`, 4000, {
    PID: String(n),
  });
  return String(res.out || "").trim();
}

function pidIsHeadless(pid) {
  const cmd = pidCommandLine(pid).toLowerCase();
  if (!cmd) return false;
  return /(^|\\s)--headless(=new)?(\\s|$)/.test(cmd);
}

function pidEnvDisplay(pid) {
  const n = Number(pid || 0);
  if (!Number.isFinite(n) || n <= 0) return "";
  const res = runBash(`tr '\\0' '\\n' </proc/"$PID"/environ 2>/dev/null | sed -n 's/^DISPLAY=//p' | head -n1 || true`, 4000, {
    PID: String(n),
  });
  return String(res.out || "").trim();
}

function discoverKeepalivePid(profileDir) {
  const profile = String(profileDir || "").trim();
  if (!profile) return 0;
  const script = `
PROFILE="$PROFILE_DIR"
ps -eo pid=,args= 2>/dev/null | while read -r pid rest; do
  [ -n "$pid" ] || continue
  case "$rest" in
    *"--user-data-dir=$PROFILE"*|*"$PROFILE"*)
      case "$rest" in
        *" --type="*) ;;
        *) printf '%s\\n' "$pid" ;;
      esac
      ;;
  esac
done | tail -n1
`;
  const res = runBash(script, 4000, { PROFILE_DIR: profile });
  const n = Number.parseInt(String(res.out || "").trim(), 10);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n;
}

function syncKeepalivePidFile(pid) {
  const n = Number.parseInt(String(pid || "0"), 10);
  if (!Number.isFinite(n) || n <= 0) return;
  const path = String(cfg.keepalivePidFile || "").trim();
  if (!path) return;
  try {
    fs.mkdirSync(require("path").dirname(path), { recursive: true });
    fs.writeFileSync(path, `${n}\n`, "utf8");
  } catch {}
}

function detectDesktopDisplay() {
  const x11 = runBash("ps -eo args= 2>/dev/null | grep -E '[x]11vnc' | head -n1 || true", 4000);
  const x11Line = String(x11.out || "").trim();
  if (x11Line) {
    const m = x11Line.match(/-display\\s+(:\\d+)/);
    if (m && m[1]) return m[1];
  }
  const xvfb = runBash("ps -eo args= 2>/dev/null | grep -E '[X]vfb\\s+:[0-9]+' | head -n1 || true", 4000);
  const xvfbLine = String(xvfb.out || "").trim();
  if (xvfbLine) {
    const m = xvfbLine.match(/\\s(:\\d+)(\\s|$)/);
    if (m && m[1]) return m[1];
  }
  return "";
}

function effectiveKeepaliveProfileDir() {
  const explicit = String(cfg.keepaliveProfileDir || "").trim();
  if (explicit) return explicit;
  const pidFile = String(cfg.keepalivePidFile || "").trim();
  if (!pidFile) return "";
  try {
    const path = require("path");
    const base = path.dirname(pidFile);
    return path.join(base, "apps", "keepalive", "browser", "profile");
  } catch {
    return "";
  }
}

function keepaliveStatus() {
  const mode = String(cfg.keepaliveMode || "vnc-browser").trim() || "vnc-browser";
  const intervalSec = Math.max(30, Number(cfg.keepaliveIntervalSec || 300));
  const workspaceIndexRaw = Number(cfg.keepaliveWorkspace);
  const workspaceIndex = Number.isFinite(workspaceIndexRaw) ? Math.max(-1, Math.floor(workspaceIndexRaw)) : 1;
  const workWorkspaceIndexRaw = Number(cfg.workWorkspace);
  const workWorkspaceIndex = Number.isFinite(workWorkspaceIndexRaw) ? Math.max(0, Math.floor(workWorkspaceIndexRaw)) : 0;
  let pid = readPid(cfg.keepalivePidFile);
  let running = pidAlive(pid);
  if (!running && mode === "vnc-browser") {
    const discovered = discoverKeepalivePid(effectiveKeepaliveProfileDir());
    if (discovered > 0 && pidAlive(discovered)) {
      pid = discovered;
      running = true;
      syncKeepalivePidFile(discovered);
    }
  }
  const state = parseKeyValueFile(cfg.keepaliveStatePath || "");
  const desktopDisplay = detectDesktopDisplay();
  const keepaliveDisplay = String(cfg.keepaliveDisplay || ":1");
  const displayMatchesDesktop = desktopDisplay ? (desktopDisplay === keepaliveDisplay) : true;
  const browserVisibleDesired = readKeepaliveVisibleDesired();
  const browserVisibleRuntime = parseBool(state.browser_visible, browserVisibleDesired);
  const browserHeadless = running ? pidIsHeadless(pid) : false;
  const pidDisplay = running ? pidEnvDisplay(pid) : "";
  const displayMatchesPid = pidDisplay ? (pidDisplay === keepaliveDisplay) : true;
  const browserVisibleActual = running ? (!browserHeadless && displayMatchesDesktop && displayMatchesPid) : false;
  const refreshCount = Number.parseInt(String(state.refresh_count || "0"), 10);
  const forceRefreshEnabled =
    String(state.force_refresh_enabled || (cfg.keepaliveForceRefresh ? "1" : "0")).toLowerCase() === "1";
  const forceRefreshMode = parseKeepaliveRefreshMode(
    readKeepaliveRefreshModeDesired() || state.force_refresh_mode,
    parseKeepaliveRefreshMode(cfg.keepaliveForceRefreshMode || "http_touch", "http_touch")
  );
  const keepalivePage = parseKeepalivePage(
    readKeepalivePageDesired() || state.vnc_page,
    parseKeepalivePage(cfg.keepaliveVncPage || "vnc.html", "vnc.html")
  );
  const lastTickAt = String(state.last_tick_at || "").trim();
  const lastTickMs = Date.parse(lastTickAt || "");
  const tickAgeMs = Number.isFinite(lastTickMs) ? (Date.now() - lastTickMs) : Number.POSITIVE_INFINITY;
  const lastRefreshAt = String(state.last_refresh_at || "").trim();
  const lastRefreshMs = Date.parse(lastRefreshAt || "");
  const refreshAgeMs = Number.isFinite(lastRefreshMs) ? (Date.now() - lastRefreshMs) : Number.POSITIVE_INFINITY;
  const lastHealthProbeAt = String(state.last_health_probe_at || "").trim();
  const processSnapshotAt = String(state.last_process_snapshot_at || "").trim();
  const activeWindowMs = Math.max(60, intervalSec * 2) * 1000;
  const recentTick = Number.isFinite(lastTickMs) && tickAgeMs <= activeWindowMs;
  const recentRefresh = Number.isFinite(lastRefreshMs) && refreshAgeMs <= activeWindowMs;
  const refreshing =
    mode === "vnc-browser" &&
    running &&
    (recentTick || (forceRefreshEnabled && recentRefresh));
  const currentPage =
    decodeB64(state.current_url_b64 || "") ||
    String(state.current_url || "").trim() ||
    readText(cfg.keepaliveUrlPath);
  return {
    mode,
    interval_sec: intervalSec,
    browser_visible: browserVisibleActual,
    browser_visible_desired: browserVisibleDesired,
    browser_visible_runtime: browserVisibleRuntime,
    browser_headless: browserHeadless,
    display: keepaliveDisplay,
    workspace: workspaceIndex,
    work_workspace: workWorkspaceIndex,
    desktop_display: desktopDisplay,
    display_matches_desktop: displayMatchesDesktop,
    pid_display: pidDisplay,
    display_matches_pid: displayMatchesPid,
    force_refresh_enabled: forceRefreshEnabled,
    force_refresh_mode: forceRefreshMode,
    vnc_page: keepalivePage,
    refreshing,
    pid,
    running,
    url: readText(cfg.keepaliveUrlPath),
    current_page: currentPage,
    last_tick_at: lastTickAt,
    last_refresh_at: lastRefreshAt,
    last_refresh_action: String(state.last_refresh_action || "").trim(),
    last_refresh_ok: String(state.last_refresh_ok || "").trim() === "1",
    refresh_count: Number.isFinite(refreshCount) ? Math.max(0, refreshCount) : 0,
    last_health_probe_at: lastHealthProbeAt,
    last_health_probe_ok: String(state.last_health_probe_ok || "").trim() === "1",
    last_health_probe_mode: String(state.last_health_probe_mode || "").trim(),
    last_health_probe_reason: String(state.last_health_probe_reason || "").trim(),
    last_process_snapshot_at: processSnapshotAt,
    last_process_snapshot_stage: String(state.last_process_snapshot_stage || "").trim(),
    last_process_snapshot_detail: String(state.last_process_snapshot_detail || "").trim(),
    last_process_snapshot_browser_pid: Number.parseInt(String(state.last_process_snapshot_browser_pid || "0"), 10) || 0,
    last_process_snapshot_browser_alive: String(state.last_process_snapshot_browser_alive || "").trim() === "1",
    last_process_snapshot_browser_cmd: String(state.last_process_snapshot_browser_cmd || "").trim(),
    state_path: cfg.keepaliveStatePath || "",
    pid_file: cfg.keepalivePidFile || "",
    log_path: cfg.keepaliveLogPath || "",
    browser_log_path: cfg.keepaliveBrowserLogPath || "",
  };
}

function exportPortUrl(port) {
  if (!cfg.token || !port) return "";
  const script = `
resp="$(curl -sS -m "$EXPORT_TIMEOUT" -X POST "https://happycapy.ai/api/export-port" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Cookie: authToken=$TOKEN" \
  -H "Content-Type: application/json" \
  --data "{\\"port\\":$PORT}" || true)"
preview="$(printf '%s' "$resp" | sed -n 's/.*"previewUrl"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p' | head -n1)"
if [ -n "$preview" ]; then
  printf 'https://%s' "\${preview#https://}"
fi
`;
  const res = runBash(script, 20000, {
    TOKEN: cfg.token,
    PORT: String(port),
    EXPORT_TIMEOUT: String(Math.max(4, cfg.exportTimeout)),
  });
  return (res.out || "").trim().split(/\n/).filter(Boolean).pop() || "";
}

function runtimeState() {
  const script = `
r=0; rs="";
if [ -x "$RECOVER_SCRIPT" ]; then r=1; rs="$RECOVER_SCRIPT"; fi
if [ "$r" -eq 0 ]; then
  for f in /home/node/*/workspace/.happycapy/happycapy-recover.sh; do
    if [ -x "$f" ]; then r=1; rs="$f"; break; fi
  done
fi
p2222=0; ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$SSH_PORT$" && p2222=1
p8080=0; ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)8080$" && p8080=1
pctl=0; ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$CONTROL_PORT$" && pctl=1
sshd=$(ps -ef | grep -E "[s]shd.*-p $SSH_PORT|[s]shd$" | wc -l | tr -d " ")
chisel=$(ps -ef | grep -E "[c]hisel server .*8080" | wc -l | tr -d " ")
ctl=$(ps -ef | grep -E "[n]ode .*happycapy-control-api.js" | wc -l | tr -d " ")
printf '{"recover_exists":%s,"recover_script":"%s","p2222":%s,"p8080":%s,"pcontrol":%s,"sshd_proc":%s,"chisel_proc":%s,"control_proc":%s}\n' "$r" "$rs" "$p2222" "$p8080" "$pctl" "$sshd" "$chisel" "$ctl"
`;
  const res = runBash(script, 12000, {
    RECOVER_SCRIPT: cfg.recoverScript,
    SSH_PORT: String(cfg.sshPort),
    CONTROL_PORT: String(cfg.controlPort),
  });
  const text = (res.out || "").trim();
  let parsed = {};
  try {
    parsed = JSON.parse(text.split(/\n/).filter(Boolean).pop() || "{}");
  } catch {
    parsed = {};
  }
  return parsed;
}

function tailFile(path, n) {
  if (!path) return "";
  const res = runBash(`tail -n "$N" "$P" 2>/dev/null || true`, 8000, {
    N: String(Math.max(1, Math.min(500, n))),
    P: path,
  });
  return (res.out || "").trim();
}

function writeRegistry(chiselServer, controlApiUrl) {
  if (!cfg.writer) return { ok: false, error: "writer_missing" };
  const res = runBash(`"$WRITER"`, 30000, {
    WRITER: cfg.writer,
    HAPPYCAPY_CHISEL_SERVER: chiselServer || "",
    HAPPYCAPY_CONTROL_API_URL: controlApiUrl || "",
  });
  return { ok: res.ok, code: res.code, output: (res.out || "").trim() };
}

function recoverLog(line) {
  try {
    fs.appendFileSync(RECOVER_LOG_PATH, `[${new Date().toISOString()}] ${line}\n`);
  } catch {}
}

function doRecover(mode) {
  const script = `
R="$RECOVER_SCRIPT"
if [ ! -x "$R" ]; then
  R="$(ls -1 /home/node/*/workspace/.happycapy/happycapy-recover.sh 2>/dev/null | head -n1 || true)"
fi
if [ -z "$R" ] || [ ! -x "$R" ]; then
  echo '{"status":"error","message":"no_recover_script"}'
  exit 2
fi
if [ "$MODE" = "hard" ]; then
  ps -eo pid=,args= | awk '/[c]hisel server .*--port 8080/ {print $1}' | while read -r pid; do
    [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true
  done
  if [ "\${HARD_RESTART_SSHD:-0}" = "1" ]; then
    ps -eo pid=,args= | awk -v p="$SSH_PORT" '$0 ~ /[s]shd/ && $0 ~ ("-p " p) {print $1}' | while read -r pid; do
      [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true
    done
  fi
  sleep 1
fi
HAPPYCAPY_RECOVER_CHAIN=1 bash "$R"
`;
  const res = runBash(script, 180000, {
    RECOVER_SCRIPT: cfg.recoverScript,
    MODE: mode || "soft",
    SSH_PORT: String(cfg.sshPort),
    HARD_RESTART_SSHD: cfg.hardRestartSshd ? "1" : "0",
  });
  return res;
}

function startRecoverAsync(mode) {
  const script = `
R="$RECOVER_SCRIPT"
if [ ! -x "$R" ]; then
  R="$(ls -1 /home/node/*/workspace/.happycapy/happycapy-recover.sh 2>/dev/null | head -n1 || true)"
fi
if [ -z "$R" ] || [ ! -x "$R" ]; then
  echo '{"status":"error","message":"no_recover_script"}'
  exit 2
fi
if [ "$MODE" = "hard" ]; then
  ps -eo pid=,args= | awk '/[c]hisel server .*--port 8080/ {print $1}' | while read -r pid; do
    [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true
  done
  if [ "\${HARD_RESTART_SSHD:-0}" = "1" ]; then
    ps -eo pid=,args= | awk -v p="$SSH_PORT" '$0 ~ /[s]shd/ && $0 ~ ("-p " p) {print $1}' | while read -r pid; do
      [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true
    done
  fi
  sleep 1
fi
HAPPYCAPY_RECOVER_CHAIN=1 bash "$R"
`;
  const startedAt = Date.now();
  recoverLog(`recover_start mode=${mode || "soft"}`);
  const child = spawn("bash", ["-lc", script], {
    env: {
      ...process.env,
      RECOVER_SCRIPT: cfg.recoverScript,
      MODE: mode || "soft",
      SSH_PORT: String(cfg.sshPort),
      HARD_RESTART_SSHD: cfg.hardRestartSshd ? "1" : "0",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  const pushOut = (chunk) => {
    if (!chunk) return;
    out += chunk.toString("utf8");
    if (out.length > 8 * 1024 * 1024) {
      out = out.slice(-8 * 1024 * 1024);
    }
  };
  if (child.stdout) child.stdout.on("data", pushOut);
  if (child.stderr) child.stderr.on("data", pushOut);
  const timeoutId = setTimeout(() => {
    try {
      child.kill("SIGKILL");
    } catch {}
  }, 180000);
  child.on("error", (err) => {
    clearTimeout(timeoutId);
    recoverInProgress = false;
    lastRecoverOk = false;
    lastRecoverRc = -1;
    lastRecoverOutput = String(err || "recover_spawn_error");
    recoverLog(`recover_error mode=${mode || "soft"} rc=-1 detail=${lastRecoverOutput}`);
  });
  child.on("close", (code, signal) => {
    clearTimeout(timeoutId);
    recoverInProgress = false;
    lastRecoverRc = Number.isInteger(code) ? code : -1;
    lastRecoverOk = code === 0 && !signal;
    const outTail = (out || "").trim().split(/\n/).slice(-40).join("\n");
    if (outTail) {
      lastRecoverOutput = outTail;
    } else if (signal) {
      lastRecoverOutput = `recover_terminated signal=${signal}`;
    } else {
      lastRecoverOutput = "";
    }
    const durationMs = Date.now() - startedAt;
    recoverLog(
      `recover_end mode=${mode || "soft"} ok=${lastRecoverOk} rc=${lastRecoverRc} signal=${signal || ""} duration_ms=${durationMs}`
    );
    if (lastRecoverOutput) {
      recoverLog(`recover_output_tail ${lastRecoverOutput.replace(/\n/g, "\\n").slice(0, 1500)}`);
    }
    const chiselServer = exportPortUrl(8080);
    const controlApiUrl = exportPortUrl(cfg.controlPort);
    writeRegistry(chiselServer, controlApiUrl);
  });
}

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Access-Control-Allow-Origin": "*",
  });
  res.end(body);
}

function collectStatus(refresh) {
  const state = runtimeState();
  const keepalive = keepaliveStatus();
  let chiselServer = "";
  let controlApiUrl = readText(cfg.controlApiUrlPath);
  let heartbeatUrl = readText(cfg.heartbeatUrlPath);
  if (refresh) {
    chiselServer = exportPortUrl(8080);
    controlApiUrl = exportPortUrl(cfg.controlPort) || controlApiUrl;
    if (!heartbeatUrl && controlApiUrl) {
      heartbeatUrl = `${controlApiUrl.replace(/\/+$/, "")}/heartbeat`;
    }
  }
  if (!heartbeatUrl && controlApiUrl) {
    heartbeatUrl = `${controlApiUrl.replace(/\/+$/, "")}/heartbeat`;
  }
  if (!chiselServer) {
    chiselServer = "";
  }
  const p2222 = Number(state.p2222 || 0) > 0;
  const p8080 = Number(state.p8080 || 0) > 0;
  const sshdProc = Number(state.sshd_proc || 0) > 0;
  const chiselProc = Number(state.chisel_proc || 0) > 0;
  let runtimeStateValue = "down";
  if (recoverInProgress) {
    runtimeStateValue = "recovering";
  } else if (p2222 && p8080 && sshdProc && chiselProc) {
    runtimeStateValue = "ready";
  } else if (p2222 || p8080 || sshdProc || chiselProc) {
    runtimeStateValue = "starting";
  }
  const recommendedAction =
    runtimeStateValue === "ready" ? "connect" : (runtimeStateValue === "down" ? "recover" : "wait");
  return {
    ok: true,
    alias: cfg.alias,
    control_port: cfg.controlPort,
    control_api_url: controlApiUrl,
    heartbeat_url: heartbeatUrl,
    chisel_server: chiselServer,
    registry_url: readText(cfg.registryUrlPath),
    runtime_state: runtimeStateValue,
    recommended_action: recommendedAction,
    recover_in_progress: recoverInProgress,
    last_recover_at: lastRecoverAt ? new Date(lastRecoverAt).toISOString() : "",
    last_recover_ok: lastRecoverOk,
    last_recover_rc: lastRecoverRc,
    last_recover_output: (lastRecoverOutput || "").split(/\n/).slice(-8).join("\n"),
    heartbeat_count: heartbeatCount,
    heartbeat_interval_sec: Math.max(5, Number(cfg.heartbeatIntervalSec || 300)),
    heartbeat_external_keepalive: Boolean(cfg.heartbeatExternalKeepalive),
    last_heartbeat_at: lastHeartbeatAt ? new Date(lastHeartbeatAt).toISOString() : "",
    last_heartbeat_source: lastHeartbeatSource,
    last_heartbeat_via: lastHeartbeatVia,
    keepalive,
    diagnostics: {
      install_audit_log: cfg.installAuditLogPath || "",
      process_audit_log: cfg.processAuditLogPath || "",
      keepalive_log: cfg.keepaliveLogPath || "",
      keepalive_browser_log: cfg.keepaliveBrowserLogPath || "",
    },
    machine_uptime: machineUptimeHuman(),
    control_api_uptime: controlApiUptimeHuman(),
    ...state,
    checked_at: new Date().toISOString(),
  };
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url || "/", `http://127.0.0.1:${cfg.controlPort}`);
  if (req.method === "GET" && u.pathname === "/heartbeat") {
    const source = u.searchParams.get("source") || "external";
    touchHeartbeat(source, "get");
    return sendJson(res, 200, {
      ok: true,
      action: "heartbeat",
      alias: cfg.alias,
      alive: true,
      heartbeat_count: heartbeatCount,
      last_heartbeat_at: new Date(lastHeartbeatAt).toISOString(),
      last_heartbeat_source: lastHeartbeatSource,
      machine_uptime: machineUptimeHuman(),
      uptime: controlApiUptimeHuman(),
      checked_at: new Date().toISOString(),
    });
  }

  if (req.method === "POST" && u.pathname === "/heartbeat") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
      if (body.length > 256 * 1024) req.destroy();
    });
    req.on("end", () => {
      let payload = {};
      try {
        payload = body ? JSON.parse(body) : {};
      } catch {
        payload = {};
      }
      const source = payload.source || u.searchParams.get("source") || "external";
      touchHeartbeat(source, "post");
      return sendJson(res, 200, {
        ok: true,
        action: "heartbeat",
        alias: cfg.alias,
        alive: true,
        heartbeat_count: heartbeatCount,
        last_heartbeat_at: new Date(lastHeartbeatAt).toISOString(),
        last_heartbeat_source: lastHeartbeatSource,
        machine_uptime: machineUptimeHuman(),
        uptime: controlApiUptimeHuman(),
        checked_at: new Date().toISOString(),
      });
    });
    return;
  }

  if (req.method === "GET" && u.pathname === "/status") {
    const refresh = u.searchParams.get("refresh") === "1";
    return sendJson(res, 200, collectStatus(refresh));
  }

  if (req.method === "GET" && u.pathname === "/logs") {
    const n = Number(u.searchParams.get("tail") || "120");
    return sendJson(res, 200, {
      ok: true,
      alias: cfg.alias,
      tail: Math.max(1, Math.min(500, n)),
      logs: {
        bootstrap_loop: tailFile("/tmp/hc-bootstrap-loop.log", n),
        bootstrap: tailFile("/tmp/hc-bootstrap.log", n),
        recover: tailFile("/tmp/hc-recover-only.log", n),
        keepalive: tailFile(cfg.keepaliveLogPath, n),
        keepalive_browser: tailFile(cfg.keepaliveBrowserLogPath, n),
        install_audit: tailFile(cfg.installAuditLogPath, n),
        process_audit: tailFile(cfg.processAuditLogPath, n),
        apt_update: tailFile("/tmp/hc-apt-update.log", n),
        apt_install: tailFile("/tmp/hc-apt-install.log", n),
        autorestore_browser_install: tailFile("/tmp/hc-autorestore-browser-install.log", n),
        autorestore_desktop_install: tailFile("/tmp/hc-autorestore-desktop-install.log", n),
        chisel: tailFile("/tmp/happycapy-chisel.log", n),
        chisel_err: tailFile("/tmp/happycapy-chisel.err.log", n),
        sshd: tailFile("/tmp/happycapy-sshd.log", n),
        sshd_err: tailFile("/tmp/happycapy-sshd.err.log", n),
        registry: tailFile("/tmp/happycapy-registry-report.log", n),
        registry_err: tailFile("/tmp/happycapy-registry-report.err.log", n),
      },
      checked_at: new Date().toISOString(),
    });
  }

  if (req.method === "POST" && u.pathname === "/keepalive/visibility") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
      if (body.length > 256 * 1024) req.destroy();
    });
    req.on("end", () => {
      let payload = {};
      try {
        payload = body ? JSON.parse(body) : {};
      } catch {
        payload = {};
      }
      const visible = parseBool(payload.visible, true);
      const writeRes = writeKeepaliveVisibleDesired(visible);
      const pid = readPid(cfg.keepalivePidFile);
      const hadRunningPid = pidAlive(pid);
      // Keep recovery lightweight: do not restart browser process here.
      // Runtime loop will apply visibility/workspace on next tick.
      const tickRes = requestKeepaliveTick("visibility");
      return sendJson(res, writeRes.ok ? 200 : 500, {
        ok: Boolean(writeRes.ok),
        action: "keepalive_visibility",
        visible,
        changed: Boolean(writeRes.changed),
        write: writeRes,
        requested_tick: tickRes,
        previous_pid: hadRunningPid ? pid : 0,
        restart_requested: false,
        status: collectStatus(false),
      });
    });
    return;
  }

  if (req.method === "POST" && u.pathname === "/keepalive/refresh-mode") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
      if (body.length > 256 * 1024) req.destroy();
    });
    req.on("end", () => {
      let payload = {};
      try {
        payload = body ? JSON.parse(body) : {};
      } catch {
        payload = {};
      }
      const mode = parseKeepaliveRefreshMode(payload.mode, readKeepaliveRefreshModeDesired());
      const writeRes = writeKeepaliveRefreshModeDesired(mode);
      const tickRes = requestKeepaliveTick("refresh_mode");
      return sendJson(res, writeRes.ok ? 200 : 500, {
        ok: Boolean(writeRes.ok),
        action: "keepalive_refresh_mode",
        mode: writeRes.mode || mode,
        changed: Boolean(writeRes.changed),
        write: writeRes,
        requested_tick: tickRes,
        status: collectStatus(false),
      });
    });
    return;
  }

  if (req.method === "POST" && u.pathname === "/keepalive/page") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
      if (body.length > 256 * 1024) req.destroy();
    });
    req.on("end", () => {
      let payload = {};
      try {
        payload = body ? JSON.parse(body) : {};
      } catch {
        payload = {};
      }
      const page = parseKeepalivePage(payload.page, readKeepalivePageDesired());
      const writeRes = writeKeepalivePageDesired(page);
      const tickRes = requestKeepaliveTick("page");
      return sendJson(res, writeRes.ok ? 200 : 500, {
        ok: Boolean(writeRes.ok),
        action: "keepalive_page",
        page: writeRes.page || page,
        changed: Boolean(writeRes.changed),
        write: writeRes,
        requested_tick: tickRes,
        status: collectStatus(false),
      });
    });
    return;
  }

  if (req.method === "POST" && (u.pathname === "/recover" || u.pathname === "/export-refresh")) {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString("utf8");
      if (body.length > 1024 * 1024) req.destroy();
    });
    req.on("end", () => {
      let payload = {};
      try {
        payload = body ? JSON.parse(body) : {};
      } catch {
        payload = {};
      }

      if (u.pathname === "/recover") {
        if (recoverInProgress) {
          return sendJson(res, 200, {
            ok: true,
            action: "recover",
            already_running: true,
            status: collectStatus(false),
          });
        }
        const mode = (payload.mode || u.searchParams.get("mode") || "soft").toString().toLowerCase() === "hard" ? "hard" : "soft";
        recoverInProgress = true;
        lastRecoverAt = Date.now();
        lastRecoverOk = null;
        lastRecoverRc = null;
        lastRecoverOutput = "";
        recoverLog(`recover_accept mode=${mode}`);
        try {
          startRecoverAsync(mode);
        } catch (e) {
          recoverInProgress = false;
          lastRecoverOk = false;
          lastRecoverRc = -1;
          lastRecoverOutput = String(e || "recover_exception");
          recoverLog(`recover_exception mode=${mode} detail=${lastRecoverOutput}`);
          return sendJson(res, 500, {
            ok: false,
            action: "recover",
            accepted: false,
            mode,
            rc: -1,
            output: lastRecoverOutput,
            status: collectStatus(false),
          });
        }
        return sendJson(res, 200, {
          ok: true,
          action: "recover",
          accepted: true,
          mode,
          status: collectStatus(false),
        });
      }

      const chiselServer = exportPortUrl(8080);
      const controlApiUrl = exportPortUrl(cfg.controlPort);
      const wr = writeRegistry(chiselServer, controlApiUrl);
      return sendJson(res, wr.ok ? 200 : 500, {
        ok: wr.ok,
        action: "export-refresh",
        chisel_server: chiselServer,
        control_api_url: controlApiUrl,
        registry_write: wr,
        status: collectStatus(false),
      });
    });
    return;
  }

  sendJson(res, 404, { ok: false, error: "not_found", path: u.pathname });
});

server.listen(cfg.controlPort, "0.0.0.0", () => {
  touchHeartbeat("control-api-startup", "startup");
  process.stdout.write(`{"status":"ok","control_port":${cfg.controlPort}}\n`);
});
EOF2
  chmod 700 "$CONTROL_API_SCRIPT"
  echo "$CONTROL_API_SCRIPT"
}

ensure_control_api_script() {
  local need_write
  need_write=0
  if [ -z "$CONTROL_API_BIN" ]; then
    return 1
  fi
  if [ ! -x "$CONTROL_API_SCRIPT" ]; then
    need_write=1
  elif ! grep -Fq "$CONTROL_API_SCRIPT_VERSION_MARKER" "$CONTROL_API_SCRIPT" 2>/dev/null; then
    need_write=1
  fi
  if [ "$need_write" -eq 1 ]; then
    if ! write_control_api_server >/dev/null 2>&1; then
      return 1
    fi
    CONTROL_API_SCRIPT_UPDATED=1
  fi
  if [ ! -x "$CONTROL_API_SCRIPT" ]; then
    return 1
  fi
  if ! "$CONTROL_API_BIN" --check "$CONTROL_API_SCRIPT" >/tmp/happycapy-control-api.check.log 2>&1; then
    if ! write_control_api_server >/dev/null 2>&1; then
      return 1
    fi
    CONTROL_API_SCRIPT_UPDATED=1
    if ! "$CONTROL_API_BIN" --check "$CONTROL_API_SCRIPT" >/tmp/happycapy-control-api.check.log 2>&1; then
      return 1
    fi
  fi
  return 0
}

setup_supervisor() {
  local chisel_bin="$1"
  local writer="$2"
  local sshd_bin conf_dir

  sshd_bin="$(find_sshd_bin || true)"
  if ! can_root || ! command -v supervisorctl >/dev/null 2>&1; then
    return 0
  fi
  conf_dir="$(detect_supervisor_conf_dir || true)"
  if [ -z "$conf_dir" ]; then
    return 0
  fi
  if ! run_root supervisorctl status >/dev/null 2>&1; then
    return 0
  fi

  cat > /tmp/happycapy-chisel.conf <<EOF2
[program:happycapy-chisel]
command=${chisel_bin} server --host 0.0.0.0 --port 8080 --auth ${CHISEL_AUTH} --keepalive 30s
autostart=true
autorestart=true
startsecs=2
stdout_logfile=/tmp/happycapy-chisel.log
stderr_logfile=/tmp/happycapy-chisel.err.log
EOF2
  run_root install -m 644 /tmp/happycapy-chisel.conf "${conf_dir}/happycapy-chisel.conf"

  if [ -n "$sshd_bin" ]; then
    cat > /tmp/happycapy-sshd.conf <<EOF2
[program:happycapy-sshd]
command=${sshd_bin} -D -p ${SSH_PORT}
autostart=true
autorestart=true
startsecs=2
stdout_logfile=/tmp/happycapy-sshd.log
stderr_logfile=/tmp/happycapy-sshd.err.log
EOF2
    run_root install -m 644 /tmp/happycapy-sshd.conf "${conf_dir}/happycapy-sshd.conf"
  fi

  if [ -n "$CONTROL_API_BIN" ] && [ -x "$CONTROL_API_SCRIPT" ]; then
    cat > /tmp/happycapy-control-api.conf <<EOF2
[program:happycapy-control-api]
command=/usr/bin/env HAPPYCAPY_ALIAS=${ALIAS} HAPPYCAPY_ACCESS_TOKEN=${ACCESS_TOKEN} HAPPYCAPY_SSH_PORT=${SSH_PORT} HAPPYCAPY_CONTROL_PORT=${CONTROL_PORT} HAPPYCAPY_RECOVER_SCRIPT=${RECOVER_SCRIPT_PATH} HAPPYCAPY_REGISTRY_WRITER=${writer} HAPPYCAPY_REGISTRY_URL_PATH=${REGISTRY_URL_PATH} HAPPYCAPY_CONTROL_API_URL_PATH=${CONTROL_API_URL_PATH} HAPPYCAPY_HEARTBEAT_URL_PATH=${HEARTBEAT_URL_PATH} HAPPYCAPY_HEARTBEAT_INTERVAL_SEC=${HEARTBEAT_INTERVAL_SEC} HAPPYCAPY_HEARTBEAT_EXTERNAL_KEEPALIVE=${HEARTBEAT_EXTERNAL_KEEPALIVE} HAPPYCAPY_KEEPALIVE_MODE=${KEEPALIVE_MODE} HAPPYCAPY_KEEPALIVE_INTERVAL_SEC=${KEEPALIVE_INTERVAL_SEC} HAPPYCAPY_KEEPALIVE_BROWSER_VISIBLE=${KEEPALIVE_BROWSER_VISIBLE} HAPPYCAPY_KEEPALIVE_VISIBLE_PATH=${KEEPALIVE_VISIBLE_PATH} HAPPYCAPY_KEEPALIVE_VNC_PAGE=${KEEPALIVE_VNC_PAGE} HAPPYCAPY_KEEPALIVE_PAGE_PATH=${KEEPALIVE_PAGE_PATH} HAPPYCAPY_KEEPALIVE_TRIGGER_PATH=${KEEPALIVE_TRIGGER_PATH} HAPPYCAPY_KEEPALIVE_FORCE_REFRESH=${KEEPALIVE_FORCE_REFRESH} HAPPYCAPY_KEEPALIVE_FORCE_REFRESH_MODE=${KEEPALIVE_FORCE_REFRESH_MODE} HAPPYCAPY_KEEPALIVE_REFRESH_MODE_PATH=${KEEPALIVE_REFRESH_MODE_PATH} HAPPYCAPY_KEEPALIVE_DISPLAY=${KEEPALIVE_DISPLAY} HAPPYCAPY_KEEPALIVE_WORKSPACE=${KEEPALIVE_WORKSPACE} HAPPYCAPY_WORK_WORKSPACE=${WORK_WORKSPACE} HAPPYCAPY_KEEPALIVE_PID_FILE=${KEEPALIVE_PID_FILE} HAPPYCAPY_KEEPALIVE_URL_PATH=${KEEPALIVE_URL_PATH} HAPPYCAPY_KEEPALIVE_PROFILE_DIR=${KEEPALIVE_PROFILE_DIR} HAPPYCAPY_KEEPALIVE_STATE_PATH=${KEEPALIVE_STATE_PATH} HAPPYCAPY_KEEPALIVE_LOG_PATH=${KEEPALIVE_LOG_PATH} HAPPYCAPY_KEEPALIVE_BROWSER_LOG=${KEEPALIVE_BROWSER_LOG} HAPPYCAPY_INSTALL_AUDIT_LOG_PATH=${INSTALL_AUDIT_LOG_PATH} HAPPYCAPY_PROCESS_AUDIT_LOG_PATH=${PROCESS_AUDIT_LOG_PATH} HAPPYCAPY_EXPORT_PORT_TIMEOUT_SEC=${EXPORT_PORT_TIMEOUT_SEC} ${CONTROL_API_BIN} ${CONTROL_API_SCRIPT}
autostart=true
autorestart=true
startsecs=2
stdout_logfile=/tmp/happycapy-control-api.log
stderr_logfile=/tmp/happycapy-control-api.err.log
EOF2
    run_root install -m 644 /tmp/happycapy-control-api.conf "${conf_dir}/happycapy-control-api.conf"
  fi

  cat > /tmp/happycapy-registry-report.conf <<EOF2
[program:happycapy-registry-report]
command=${writer}
autostart=true
autorestart=false
startsecs=0
stdout_logfile=/tmp/happycapy-registry-report.log
stderr_logfile=/tmp/happycapy-registry-report.err.log
EOF2
  run_root install -m 644 /tmp/happycapy-registry-report.conf "${conf_dir}/happycapy-registry-report.conf"

  run_root supervisorctl reread >/dev/null 2>&1 || true
  run_root supervisorctl update >/dev/null 2>&1 || true
  if ! run_root supervisorctl status happycapy-chisel 2>/dev/null | grep -q RUNNING; then
    run_root supervisorctl start happycapy-chisel >/dev/null 2>&1 || run_root supervisorctl restart happycapy-chisel >/dev/null 2>&1 || true
  fi
  if [ -n "$sshd_bin" ]; then
    if ! run_root supervisorctl status happycapy-sshd 2>/dev/null | grep -q RUNNING; then
      run_root supervisorctl start happycapy-sshd >/dev/null 2>&1 || run_root supervisorctl restart happycapy-sshd >/dev/null 2>&1 || true
    fi
  fi
  if [ -n "$CONTROL_API_BIN" ] && [ -x "$CONTROL_API_SCRIPT" ]; then
    run_root supervisorctl start happycapy-control-api >/dev/null 2>&1 || run_root supervisorctl restart happycapy-control-api >/dev/null 2>&1 || true
  fi
  run_root supervisorctl start happycapy-registry-report >/dev/null 2>&1 || true
  if run_root supervisorctl status happycapy-chisel >/dev/null 2>&1; then
    SUPERVISOR_MANAGED=1
  else
    SUPERVISOR_MANAGED=0
  fi
}

start_control_api_fallback() {
  local old_pid
  if [ "$CONTROL_API_REQUIRED" -eq 1 ]; then
    ensure_control_api_script >/dev/null 2>&1 || true
  fi
  if [ "$SUPERVISOR_MANAGED" -eq 1 ]; then
    if [ "$CONTROL_API_REQUIRED" -eq 1 ] && [ "$CONTROL_API_SCRIPT_UPDATED" -eq 1 ]; then
      run_root supervisorctl restart happycapy-control-api >/dev/null 2>&1 || true
      sleep 1
      CONTROL_API_SCRIPT_UPDATED=0
    fi
    if is_port_listening "$CONTROL_PORT" && control_api_http_ready; then
      CONTROL_API_OK=1
    else
      if [ "$CONTROL_API_REQUIRED" -eq 1 ]; then
        run_root supervisorctl start happycapy-control-api >/dev/null 2>&1 || run_root supervisorctl restart happycapy-control-api >/dev/null 2>&1 || true
        sleep 1
      fi
      if is_port_listening "$CONTROL_PORT" && control_api_http_ready; then
        CONTROL_API_OK=1
      else
        CONTROL_API_OK=0
      fi
    fi
    if [ "$CONTROL_API_OK" -eq 1 ]; then
      CONTROL_API_SCRIPT_UPDATED=0
    fi
    return 0
  fi

  if [ -z "$CONTROL_API_BIN" ] || [ ! -x "$CONTROL_API_SCRIPT" ]; then
    CONTROL_API_OK=0
    return 1
  fi

  if [ "$CONTROL_API_SCRIPT_UPDATED" -eq 0 ] && is_port_listening "$CONTROL_PORT" && control_api_http_ready; then
    CONTROL_API_OK=1
    return 0
  fi

  ensure_control_api_script >/dev/null 2>&1 || true

  if [ -f "$CONTROL_API_PID_FILE" ]; then
    old_pid="$(cat "$CONTROL_API_PID_FILE" 2>/dev/null || true)"
    if [ -n "${old_pid:-}" ] && kill -0 "$old_pid" 2>/dev/null; then
      kill "$old_pid" >/dev/null 2>&1 || true
      sleep 1
    fi
  fi
  pkill -f "happycapy-control-api.js" >/dev/null 2>&1 || true
  sleep 1

  HAPPYCAPY_ALIAS="$ALIAS" \
  HAPPYCAPY_ACCESS_TOKEN="$ACCESS_TOKEN" \
  HAPPYCAPY_SSH_PORT="$SSH_PORT" \
  HAPPYCAPY_CONTROL_PORT="$CONTROL_PORT" \
  HAPPYCAPY_RECOVER_SCRIPT="$RECOVER_SCRIPT_PATH" \
  HAPPYCAPY_REGISTRY_WRITER="$BOOT_WRITER" \
  HAPPYCAPY_REGISTRY_URL_PATH="$REGISTRY_URL_PATH" \
  HAPPYCAPY_CONTROL_API_URL_PATH="$CONTROL_API_URL_PATH" \
  HAPPYCAPY_HEARTBEAT_URL_PATH="$HEARTBEAT_URL_PATH" \
  HAPPYCAPY_HEARTBEAT_INTERVAL_SEC="$HEARTBEAT_INTERVAL_SEC" \
  HAPPYCAPY_HEARTBEAT_EXTERNAL_KEEPALIVE="$HEARTBEAT_EXTERNAL_KEEPALIVE" \
  HAPPYCAPY_KEEPALIVE_MODE="$KEEPALIVE_MODE" \
  HAPPYCAPY_KEEPALIVE_INTERVAL_SEC="$KEEPALIVE_INTERVAL_SEC" \
  HAPPYCAPY_KEEPALIVE_RECOVERY_INTERVAL_SEC="$KEEPALIVE_RECOVERY_INTERVAL_SEC" \
  HAPPYCAPY_KEEPALIVE_BROWSER_VISIBLE="$KEEPALIVE_BROWSER_VISIBLE" \
  HAPPYCAPY_KEEPALIVE_VISIBLE_PATH="$KEEPALIVE_VISIBLE_PATH" \
  HAPPYCAPY_KEEPALIVE_VNC_PAGE="$KEEPALIVE_VNC_PAGE" \
  HAPPYCAPY_KEEPALIVE_PAGE_PATH="$KEEPALIVE_PAGE_PATH" \
  HAPPYCAPY_KEEPALIVE_TRIGGER_PATH="$KEEPALIVE_TRIGGER_PATH" \
  HAPPYCAPY_KEEPALIVE_FORCE_REFRESH="$KEEPALIVE_FORCE_REFRESH" \
  HAPPYCAPY_KEEPALIVE_FORCE_REFRESH_MODE="$KEEPALIVE_FORCE_REFRESH_MODE" \
  HAPPYCAPY_KEEPALIVE_REFRESH_MODE_PATH="$KEEPALIVE_REFRESH_MODE_PATH" \
  HAPPYCAPY_KEEPALIVE_DISPLAY="$KEEPALIVE_DISPLAY" \
  HAPPYCAPY_KEEPALIVE_WORKSPACE="$KEEPALIVE_WORKSPACE" \
  HAPPYCAPY_WORK_WORKSPACE="$WORK_WORKSPACE" \
  HAPPYCAPY_KEEPALIVE_PID_FILE="$KEEPALIVE_PID_FILE" \
  HAPPYCAPY_KEEPALIVE_URL_PATH="$KEEPALIVE_URL_PATH" \
  HAPPYCAPY_KEEPALIVE_PROFILE_DIR="$KEEPALIVE_PROFILE_DIR" \
  HAPPYCAPY_KEEPALIVE_STATE_PATH="$KEEPALIVE_STATE_PATH" \
  HAPPYCAPY_KEEPALIVE_LOG_PATH="$KEEPALIVE_LOG_PATH" \
  HAPPYCAPY_KEEPALIVE_BROWSER_LOG="$KEEPALIVE_BROWSER_LOG" \
  HAPPYCAPY_INSTALL_AUDIT_LOG_PATH="$INSTALL_AUDIT_LOG_PATH" \
  HAPPYCAPY_PROCESS_AUDIT_LOG_PATH="$PROCESS_AUDIT_LOG_PATH" \
  HAPPYCAPY_EXPORT_PORT_TIMEOUT_SEC="$EXPORT_PORT_TIMEOUT_SEC" \
  nohup "$CONTROL_API_BIN" "$CONTROL_API_SCRIPT" >/tmp/happycapy-control-api.log 2>/tmp/happycapy-control-api.err.log &
  printf '%s\n' "$!" > "$CONTROL_API_PID_FILE"
  for _ in 1 2 3; do
    sleep 1
    if is_port_listening "$CONTROL_PORT" && control_api_http_ready; then
      CONTROL_API_OK=1
      CONTROL_API_SCRIPT_UPDATED=0
      return 0
    fi
  done
  CONTROL_API_OK=0
  return 1
}

start_fallback_processes() {
  local chisel_bin="$1"
  local sshd_bin

  sshd_bin="$(find_sshd_bin || true)"
  cleanup_legacy_desktop_duplicates || true

  if [ "$SUPERVISOR_MANAGED" -eq 1 ]; then
    start_control_api_fallback || true
    return 0
  fi

  if [ -n "$sshd_bin" ] && can_root; then
    if ! is_port_listening "$SSH_PORT"; then
      run_root sh -c "nohup '$sshd_bin' -D -p '$SSH_PORT' >/tmp/happycapy-sshd.log 2>&1 &"
      sleep 1
    fi
  fi

  case "$(chisel_state)" in
    desired)
      if ! is_port_listening 8080; then
        pkill -f "chisel server.*--port 8080" >/dev/null 2>&1 || true
        sleep 1
        nohup "$chisel_bin" server --host 0.0.0.0 --port 8080 --auth "$CHISEL_AUTH" --keepalive 30s >/tmp/happycapy-chisel.log 2>&1 &
      fi
      ;;
    other)
      pkill -f "chisel server.*--port 8080" >/dev/null 2>&1 || true
      sleep 1
      nohup "$chisel_bin" server --host 0.0.0.0 --port 8080 --auth "$CHISEL_AUTH" --keepalive 30s >/tmp/happycapy-chisel.log 2>&1 &
      ;;
    none)
      nohup "$chisel_bin" server --host 0.0.0.0 --port 8080 --auth "$CHISEL_AUTH" --keepalive 30s >/tmp/happycapy-chisel.log 2>&1 &
      ;;
  esac

  start_control_api_fallback || true
  keepalive_process_snapshot "fallback_processes" "chisel_state=$(chisel_state)" || true
}

query_preview_url_for_port_once() {
  local port="$1"
  local resp preview
  resp="$(curl -sS -m "$EXPORT_PORT_TIMEOUT_SEC" -X POST "https://happycapy.ai/api/export-port" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "Cookie: authToken=${ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{\"port\":${port}}" || true)"
  preview="$(printf '%s' "$resp" | sed -n 's/.*"previewUrl"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  if [ -n "$preview" ]; then
    printf 'https://%s' "${preview#https://}"
  fi
}

query_preview_url_for_port() {
  local port="$1"
  local url
  for _ in 1 2; do
    url="$(query_preview_url_for_port_once "$port" || true)"
    if [ -n "$url" ]; then
      printf '%s\n' "$url"
      return 0
    fi
    sleep 1
  done
  return 1
}

query_preview_url() {
  query_preview_url_for_port 8080
}

install_recover_script() {
  mkdir -p "$PERSIST_DIR" "$(dirname "$RECOVER_SCRIPT_PATH")"

  if [ -f "$0" ] && [ -r "$0" ]; then
    if [ "$0" != "$PERSIST_BOOTSTRAP" ]; then
      install -m 700 "$0" "$PERSIST_BOOTSTRAP" || true
    fi
  elif [ -f /tmp/hc-remote-bootstrap.sh ] && [ -r /tmp/hc-remote-bootstrap.sh ]; then
    install -m 700 /tmp/hc-remote-bootstrap.sh "$PERSIST_BOOTSTRAP" || true
  fi

  if [ ! -f "$PERSIST_BOOTSTRAP" ]; then
    return 1
  fi

  cat > "$RECOVER_SCRIPT_PATH" <<EOF2
#!/usr/bin/env bash
set -euo pipefail

export HAPPYCAPY_ACCESS_TOKEN="\${HAPPYCAPY_ACCESS_TOKEN:-${ACCESS_TOKEN}}"
export HAPPYCAPY_ALIAS="\${HAPPYCAPY_ALIAS:-${ALIAS}}"
export HAPPYCAPY_SSH_USER="\${HAPPYCAPY_SSH_USER:-${SSH_USER}}"
export HAPPYCAPY_SSH_PASSWORD="\${HAPPYCAPY_SSH_PASSWORD:-${SSH_PASSWORD}}"
export HAPPYCAPY_SSH_PORT="\${HAPPYCAPY_SSH_PORT:-${SSH_PORT}}"
export HAPPYCAPY_LOCAL_PORT="\${HAPPYCAPY_LOCAL_PORT:-${LOCAL_PORT}}"
export HAPPYCAPY_CHISEL_AUTH="\${HAPPYCAPY_CHISEL_AUTH:-${CHISEL_AUTH}}"
export HAPPYCAPY_REGISTRY_FILE="\${HAPPYCAPY_REGISTRY_FILE:-${REGISTRY_FILE}}"
export HAPPYCAPY_REGISTRY_UPLOAD_API="\${HAPPYCAPY_REGISTRY_UPLOAD_API:-${UPLOAD_API}}"
export HAPPYCAPY_REGISTRY_BASE="\${HAPPYCAPY_REGISTRY_BASE:-${REGISTRY_BASE}}"
export HAPPYCAPY_REGISTRY_URL_PATH="\${HAPPYCAPY_REGISTRY_URL_PATH:-${REGISTRY_URL_PATH}}"
export HAPPYCAPY_CONTROL_PORT="\${HAPPYCAPY_CONTROL_PORT:-${CONTROL_PORT}}"
export HAPPYCAPY_CONTROL_API_URL_PATH="\${HAPPYCAPY_CONTROL_API_URL_PATH:-${CONTROL_API_URL_PATH}}"
export HAPPYCAPY_HEARTBEAT_URL_PATH="\${HAPPYCAPY_HEARTBEAT_URL_PATH:-${HEARTBEAT_URL_PATH}}"
export HAPPYCAPY_KEEPALIVE_MODE="\${HAPPYCAPY_KEEPALIVE_MODE:-${KEEPALIVE_MODE}}"
export HAPPYCAPY_KEEPALIVE_INTERVAL_SEC="\${HAPPYCAPY_KEEPALIVE_INTERVAL_SEC:-${KEEPALIVE_INTERVAL_SEC}}"
export HAPPYCAPY_KEEPALIVE_RECOVERY_INTERVAL_SEC="\${HAPPYCAPY_KEEPALIVE_RECOVERY_INTERVAL_SEC:-${KEEPALIVE_RECOVERY_INTERVAL_SEC}}"
export HAPPYCAPY_KEEPALIVE_BROWSER="\${HAPPYCAPY_KEEPALIVE_BROWSER:-${KEEPALIVE_BROWSER}}"
export HAPPYCAPY_KEEPALIVE_BROWSER_VISIBLE="\${HAPPYCAPY_KEEPALIVE_BROWSER_VISIBLE:-${KEEPALIVE_BROWSER_VISIBLE}}"
export HAPPYCAPY_KEEPALIVE_FORCE_REFRESH="\${HAPPYCAPY_KEEPALIVE_FORCE_REFRESH:-${KEEPALIVE_FORCE_REFRESH}}"
export HAPPYCAPY_KEEPALIVE_FORCE_REFRESH_MODE="\${HAPPYCAPY_KEEPALIVE_FORCE_REFRESH_MODE:-${KEEPALIVE_FORCE_REFRESH_MODE}}"
export HAPPYCAPY_KEEPALIVE_VNC_PAGE="\${HAPPYCAPY_KEEPALIVE_VNC_PAGE:-${KEEPALIVE_VNC_PAGE}}"
export HAPPYCAPY_KEEPALIVE_DISPLAY="\${HAPPYCAPY_KEEPALIVE_DISPLAY:-${KEEPALIVE_DISPLAY}}"
export HAPPYCAPY_KEEPALIVE_WORKSPACE="\${HAPPYCAPY_KEEPALIVE_WORKSPACE:-${KEEPALIVE_WORKSPACE}}"
export HAPPYCAPY_WORK_WORKSPACE="\${HAPPYCAPY_WORK_WORKSPACE:-${WORK_WORKSPACE}}"
export HAPPYCAPY_KEEPALIVE_CDP_PORT="\${HAPPYCAPY_KEEPALIVE_CDP_PORT:-${KEEPALIVE_CDP_PORT}}"
export HAPPYCAPY_KEEPALIVE_PROFILE_DIR="\${HAPPYCAPY_KEEPALIVE_PROFILE_DIR:-${KEEPALIVE_PROFILE_DIR}}"
export HAPPYCAPY_KEEPALIVE_PID_FILE="\${HAPPYCAPY_KEEPALIVE_PID_FILE:-${KEEPALIVE_PID_FILE}}"
export HAPPYCAPY_KEEPALIVE_URL_PATH="\${HAPPYCAPY_KEEPALIVE_URL_PATH:-${KEEPALIVE_URL_PATH}}"
export HAPPYCAPY_KEEPALIVE_VISIBLE_PATH="\${HAPPYCAPY_KEEPALIVE_VISIBLE_PATH:-${KEEPALIVE_VISIBLE_PATH}}"
export HAPPYCAPY_KEEPALIVE_PAGE_PATH="\${HAPPYCAPY_KEEPALIVE_PAGE_PATH:-${KEEPALIVE_PAGE_PATH}}"
export HAPPYCAPY_KEEPALIVE_REFRESH_MODE_PATH="\${HAPPYCAPY_KEEPALIVE_REFRESH_MODE_PATH:-${KEEPALIVE_REFRESH_MODE_PATH}}"
export HAPPYCAPY_KEEPALIVE_TRIGGER_PATH="\${HAPPYCAPY_KEEPALIVE_TRIGGER_PATH:-${KEEPALIVE_TRIGGER_PATH}}"
export HAPPYCAPY_KEEPALIVE_STATE_PATH="\${HAPPYCAPY_KEEPALIVE_STATE_PATH:-${KEEPALIVE_STATE_PATH}}"
export HAPPYCAPY_KEEPALIVE_LOG_PATH="\${HAPPYCAPY_KEEPALIVE_LOG_PATH:-${KEEPALIVE_LOG_PATH}}"
export HAPPYCAPY_KEEPALIVE_BROWSER_LOG="\${HAPPYCAPY_KEEPALIVE_BROWSER_LOG:-${KEEPALIVE_BROWSER_LOG}}"
export HAPPYCAPY_INSTALL_AUDIT_LOG_PATH="\${HAPPYCAPY_INSTALL_AUDIT_LOG_PATH:-${INSTALL_AUDIT_LOG_PATH}}"
export HAPPYCAPY_PROCESS_AUDIT_LOG_PATH="\${HAPPYCAPY_PROCESS_AUDIT_LOG_PATH:-${PROCESS_AUDIT_LOG_PATH}}"
export HAPPYCAPY_RECOVER_SCRIPT="\${HAPPYCAPY_RECOVER_SCRIPT:-${RECOVER_SCRIPT_PATH}}"
export HAPPYCAPY_RECOVER_CHAIN=1

if [ -x "${PERSIST_BOOTSTRAP}" ]; then
  exec bash "${PERSIST_BOOTSTRAP}"
fi
if [ -x /tmp/hc-remote-bootstrap.sh ]; then
  exec bash /tmp/hc-remote-bootstrap.sh
fi
echo '{"status":"error","message":"bootstrap cache missing for recover"}'
exit 1
EOF2

  chmod 700 "$RECOVER_SCRIPT_PATH"
  echo "$RECOVER_SCRIPT_PATH"
}

verify_services() {
  if [ "$(chisel_state)" = "desired" ] && is_port_listening 8080; then
    CHISEL_OK=1
  else
    CHISEL_OK=0
  fi

  if find_sshd_bin >/dev/null 2>&1; then
    if is_port_listening "$SSH_PORT"; then
      SSHD_OK=1
    else
      SSHD_OK=0
    fi
  fi

  if [ "$CONTROL_API_REQUIRED" -eq 1 ]; then
    if is_port_listening "$CONTROL_PORT" && control_api_http_ready; then
      CONTROL_API_OK=1
    else
      CONTROL_API_OK=0
    fi
  else
    CONTROL_API_OK=0
  fi

  if [ "$CHISEL_OK" -ne 1 ] || [ "$SSHD_OK" -ne 1 ]; then
    return 1
  fi
  if [ "$CONTROL_API_REQUIRED" -eq 1 ] && [ "$CONTROL_API_OK" -ne 1 ]; then
    return 1
  fi
  return 0
}

watchdog_loop() {
  local interval="$1"
  local heartbeat_last_ts=0
  local keepalive_last_ts=0
  local keepalive_recover_last_ts=0
  local keepalive_health_last_ts=0
  local keepalive_unhealthy_last_ts=0
  local autorestore_skip_logged=0
  local now_ts=0
  local hb_ext_rc=0
  local keepalive_triggered=0
  local keepalive_due=0
  local keepalive_recover_due=0
  local keepalive_health_due=0
  local keepalive_unhealthy_due=0
  local keepalive_pid_alive=0
  local keepalive_health_url=""
  if [ "$KEEPALIVE_MODE" != "vnc-browser" ]; then
    stop_keepalive_browser || true
  fi
  while true; do
    setup_supervisor "$CHISEL_BIN" "$BOOT_WRITER" || true
    start_fallback_processes "$CHISEL_BIN" || true
    now_ts="$(date +%s 2>/dev/null || echo 0)"
    if [ "$HEARTBEAT_INTERVAL_SEC" -gt 0 ] && [ "$now_ts" -gt 0 ]; then
      if [ "$heartbeat_last_ts" -eq 0 ] || [ $((now_ts - heartbeat_last_ts)) -ge "$HEARTBEAT_INTERVAL_SEC" ]; then
        if ! control_api_heartbeat "watchdog-local"; then
          heartbeat_log "heartbeat_fail: control_api_unreachable, restarting control api"
          start_control_api_fallback || true
          if control_api_heartbeat "watchdog-retry"; then
            heartbeat_log "heartbeat_recovered"
          else
            heartbeat_log "heartbeat_still_fail"
          fi
        fi
        control_api_external_heartbeat "watchdog-external"
        hb_ext_rc=$?
        if [ "$hb_ext_rc" -eq 1 ]; then
          heartbeat_log "external_heartbeat_fail: control_api_url_unreachable"
        fi
        heartbeat_last_ts="$now_ts"
      fi
    fi
    if verify_services; then
      local server_now control_now
      server_now="$(query_preview_url_for_port 8080 || true)"
      control_now="$(query_preview_url_for_port "$CONTROL_PORT" || true)"
      if [ -n "$server_now" ]; then
        HAPPYCAPY_CHISEL_SERVER="$server_now" HAPPYCAPY_CONTROL_API_URL="$control_now" "$BOOT_WRITER" >/tmp/happycapy-registry-report.log 2>&1 || true
      fi
      # Keep workspace restore behind core connectivity:
      # SSH/chisel/control must be healthy first, then run restore tasks.
      if autorestore_worker_running; then
        if [ "$autorestore_skip_logged" -eq 0 ]; then
          install_log "watchdog_autorestore_skip reason=worker_running"
          autorestore_skip_logged=1
        fi
      else
        autorestore_skip_logged=0
        run_workspace_autorestore
      fi
      keepalive_triggered=0
      if [ -f "$KEEPALIVE_TRIGGER_PATH" ]; then
        rm -f "$KEEPALIVE_TRIGGER_PATH" >/dev/null 2>&1 || true
        keepalive_triggered=1
      fi
      if [ "$KEEPALIVE_MODE" = "vnc-browser" ] && [ "$KEEPALIVE_INTERVAL_SEC" -gt 0 ] && [ "$now_ts" -gt 0 ]; then
        keepalive_due=0
        # Health-driven policy for vnc-browser:
        # - first tick (boot) or explicit trigger runs one keepalive tick
        # - routine refresh is driven by health probe (unhealthy -> force refresh)
        # This avoids blind periodic reload every KEEPALIVE_INTERVAL_SEC.
        if [ "$keepalive_triggered" -eq 1 ] || [ "$keepalive_last_ts" -eq 0 ]; then
          keepalive_due=1
        fi
        keepalive_pid_alive=0
        if keepalive_browser_pid_running; then
          keepalive_pid_alive=1
        fi
        keepalive_recover_due=0
        if [ "$keepalive_pid_alive" -ne 1 ]; then
          if [ "$keepalive_recover_last_ts" -eq 0 ] || [ $((now_ts - keepalive_recover_last_ts)) -ge "$KEEPALIVE_RECOVERY_INTERVAL_SEC" ]; then
            keepalive_recover_due=1
          fi
        fi
        keepalive_health_due=0
        keepalive_unhealthy_due=0
        keepalive_health_url=""
        if [ "$keepalive_pid_alive" -eq 1 ] && [ "$KEEPALIVE_HEALTH_CHECK_INTERVAL_SEC" -gt 0 ] && [ "$now_ts" -gt 0 ]; then
          if [ "$keepalive_health_last_ts" -eq 0 ] || [ $((now_ts - keepalive_health_last_ts)) -ge "$KEEPALIVE_HEALTH_CHECK_INTERVAL_SEC" ]; then
            keepalive_health_due=1
          fi
        fi
        if [ "$keepalive_health_due" -eq 1 ]; then
          keepalive_health_url="$(keepalive_target_url || true)"
          if [ -n "$keepalive_health_url" ] && verify_vnc_browser_refresh_health "$keepalive_health_url"; then
            keepalive_health_last_ts="$now_ts"
          else
            keepalive_health_last_ts="$now_ts"
            if [ "$keepalive_unhealthy_last_ts" -eq 0 ] || [ $((now_ts - keepalive_unhealthy_last_ts)) -ge "$KEEPALIVE_UNHEALTHY_COOLDOWN_SEC" ]; then
              keepalive_unhealthy_due=1
            fi
          fi
        fi
        if [ "$keepalive_due" -eq 1 ] || [ "$keepalive_recover_due" -eq 1 ] || [ "$keepalive_unhealthy_due" -eq 1 ]; then
          local keepalive_force_refresh_now
          keepalive_force_refresh_now=0
          if [ "$keepalive_unhealthy_due" -eq 1 ]; then
            keepalive_force_refresh_now=1
          fi
          vnc_browser_keepalive_tick "$keepalive_force_refresh_now" || true
          if [ "$keepalive_unhealthy_due" -eq 1 ]; then
            keepalive_unhealthy_last_ts="$now_ts"
          fi
          if [ "$keepalive_due" -eq 1 ]; then
            keepalive_last_ts="$now_ts"
          fi
          if [ "$keepalive_recover_due" -eq 1 ]; then
            keepalive_recover_last_ts="$now_ts"
          fi
        fi
      fi
    fi
    sleep "$interval"
  done
}

bootstrap_cmdline_like() {
  local cmdline="$1"
  case "$cmdline" in
    *"/.happycapy/bootstrap.sh"*|*"/tmp/hc-remote-bootstrap.sh"*|*" bootstrap.sh"*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

bootstrap_lock_owner_alive() {
  local owner_pid="$1"
  local cmdline
  case "$owner_pid" in
    ''|*[!0-9]*)
      return 1
      ;;
  esac
  if [ "$owner_pid" -le 1 ] 2>/dev/null; then
    return 1
  fi
  if ! kill -0 "$owner_pid" >/dev/null 2>&1; then
    return 1
  fi
  cmdline="$(ps -p "$owner_pid" -o args= 2>/dev/null || true)"
  [ -n "$cmdline" ] || return 1
  bootstrap_cmdline_like "$cmdline"
}

converge_bootstrap_singleton() {
  local line pid cmdline killed_pids
  killed_pids=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    pid="$(printf '%s' "$line" | awk '{print $1}')"
    case "$pid" in
      ''|*[!0-9]*) continue ;;
    esac
    [ "$pid" -eq "$$" ] && continue
    cmdline="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*[0-9]+[[:space:]]+//')"
    bootstrap_cmdline_like "$cmdline" || continue
    case "$cmdline" in
      *"--autorestore-only"*) continue ;;
    esac
    kill "$pid" >/dev/null 2>&1 || true
    killed_pids="${killed_pids} ${pid}"
  done < <(ps -eo pid=,args= 2>/dev/null || true)

  if [ -n "$killed_pids" ]; then
    sleep 0.4
    for pid in $killed_pids; do
      if kill -0 "$pid" >/dev/null 2>&1; then
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
    done
  fi
}

acquire_bootstrap_lock() {
  mkdir -p "$PERSIST_DIR"
  local owner_pid
  if mkdir "$BOOTSTRAP_LOCK_DIR" 2>/dev/null; then
    printf '%s\n' "$$" > "$BOOTSTRAP_LOCK_PID_FILE"
    return 0
  fi

  owner_pid="$(cat "$BOOTSTRAP_LOCK_PID_FILE" 2>/dev/null | tr -dc '0-9' || true)"
  if bootstrap_lock_owner_alive "$owner_pid"; then
    return 1
  fi

  rm -rf "$BOOTSTRAP_LOCK_DIR" >/dev/null 2>&1 || true
  sleep 0.2
  if mkdir "$BOOTSTRAP_LOCK_DIR" 2>/dev/null; then
    printf '%s\n' "$$" > "$BOOTSTRAP_LOCK_PID_FILE"
    return 0
  fi

  owner_pid="$(cat "$BOOTSTRAP_LOCK_PID_FILE" 2>/dev/null | tr -dc '0-9' || true)"
  if bootstrap_lock_owner_alive "$owner_pid"; then
    return 1
  fi
  rm -rf "$BOOTSTRAP_LOCK_DIR" >/dev/null 2>&1 || true
  return 1
}

release_bootstrap_lock() {
  local owner_pid
  owner_pid="$(cat "$BOOTSTRAP_LOCK_PID_FILE" 2>/dev/null || true)"
  if [ -n "$owner_pid" ] && [ "$owner_pid" != "$$" ]; then
    return 0
  fi
  rm -rf "$BOOTSTRAP_LOCK_DIR" >/dev/null 2>&1 || true
}

if [ "$AUTORESTORE_ONLY" -eq 1 ]; then
  mkdir -p "$PERSIST_DIR"
  run_workspace_autorestore || true
  printf '{"status":"ok","mode":"autorestore_only"}\n'
  exit 0
fi

if [ -z "$ACCESS_TOKEN" ]; then
  emit_error "HAPPYCAPY_ACCESS_TOKEN is empty"
  exit 1
fi

RECOVER_EXISTING=""
if [ -x "$RECOVER_SCRIPT_PATH" ]; then
  RECOVER_EXISTING="$RECOVER_SCRIPT_PATH"
else
  R0="$(ls -1 $WORKSPACE_RECOVER_GLOB 2>/dev/null | head -n1 || true)"
  if [ -n "$R0" ] && [ -x "$R0" ]; then
    RECOVER_EXISTING="$R0"
  fi
fi

# Apply interactive shell defaults even on fast pre-recover path.
ensure_shell_defaults_for_user "$SSH_USER" || true

if [ "$WATCHDOG_MODE" -ne 1 ] && [ "${HAPPYCAPY_RECOVER_CHAIN:-0}" != "1" ] && [ -n "$RECOVER_EXISTING" ]; then
  set +e
  HAPPYCAPY_RECOVER_CHAIN=1 bash "$RECOVER_EXISTING"
  pre_recover_rc=$?
  set -e
  if [ "$pre_recover_rc" -eq 0 ]; then
    exit 0
  fi
fi

LOCK_ACQUIRED=0
if acquire_bootstrap_lock; then
  LOCK_ACQUIRED=1
else
  lock_deadline="$(( $(date +%s) + BOOTSTRAP_LOCK_WAIT_SEC ))"
  while [ "$(date +%s)" -lt "$lock_deadline" ]; do
    p2222=0
    if is_port_listening "$SSH_PORT"; then p2222=1; fi
    p8080=0
    if is_port_listening 8080; then p8080=1; fi
    pcontrol=0
    if [ "$CONTROL_API_REQUIRED" -eq 1 ] && is_port_listening "$CONTROL_PORT"; then
      pcontrol=1
    fi
    if [ "$CONTROL_API_REQUIRED" -eq 0 ]; then
      pcontrol=1
    fi
    if [ "$p2222" -eq 1 ] && [ "$p8080" -eq 1 ] && [ "$pcontrol" -eq 1 ]; then
      printf '{"status":"ok","message":"bootstrap_lock_busy","p2222":%s,"p8080":%s,"pcontrol":%s}\n' "$p2222" "$p8080" "$pcontrol"
      exit 0
    fi
    if acquire_bootstrap_lock; then
      LOCK_ACQUIRED=1
      break
    fi
    sleep 1
  done
fi
if [ "$LOCK_ACQUIRED" -ne 1 ]; then
  emit_error "bootstrap lock busy"
  exit 1
fi
trap 'release_bootstrap_lock' EXIT INT TERM
converge_bootstrap_singleton || true
install_log "bootstrap_begin alias=${ALIAS} persist_root=${PERSIST_ROOT} watchdog_mode=${WATCHDOG_MODE} keepalive_mode=${KEEPALIVE_MODE}"

RECOVER_SCRIPT="$(install_recover_script || true)"
if [ -z "$RECOVER_SCRIPT" ] || [ ! -x "$RECOVER_SCRIPT" ]; then
  install_log "bootstrap_fail step=install_recover_script"
  emit_error "failed to create recover script"
  exit 1
fi

if [ "$SKIP_CORE_INSTALL" -eq 1 ]; then
  install_log "core_install_skip reason=skip_core_install watchdog_mode=${WATCHDOG_MODE}"
else
  install_packages
fi

if ! command -v curl >/dev/null 2>&1; then
  emit_error "curl not found"
  exit 1
fi

CONTROL_API_BIN="$(command -v node || true)"
if [ -z "$CONTROL_API_BIN" ]; then
  install_log "bootstrap_fail step=detect_node reason=node_not_found"
  emit_error "node not found (control api unavailable)"
  exit 1
fi

CHISEL_BIN="$(install_chisel || true)"
if [ -z "$CHISEL_BIN" ]; then
  install_log "bootstrap_fail step=install_chisel"
  emit_error "failed to install/find chisel"
  exit 1
fi

if ! configure_sshd; then
  install_log "bootstrap_fail step=configure_sshd"
  emit_error "failed to install/configure sshd"
  exit 1
fi
ensure_shell_defaults_for_user "$SSH_USER" || true

BOOT_WRITER="$(write_reporter || true)"
if [ -z "$BOOT_WRITER" ] || [ ! -x "$BOOT_WRITER" ]; then
  install_log "bootstrap_fail step=write_reporter"
  emit_error "failed to create registry writer"
  exit 1
fi

if [ -n "$CONTROL_API_BIN" ]; then
  write_control_api_server >/dev/null 2>&1 || true
  if ! ensure_control_api_script; then
    install_log "bootstrap_fail step=ensure_control_api_script"
    emit_error "failed to build/validate control api script"
    exit 1
  fi
fi
if [ -x "$CONTROL_API_SCRIPT" ]; then
  CONTROL_API_REQUIRED=1
else
  install_log "bootstrap_fail step=write_control_api_server"
  emit_error "failed to create control api server script"
  exit 1
fi

# Watchdog worker should not block on export-port/registry roundtrips.
# It only needs local core services up, then enters steady keepalive loop.
if [ "$WATCHDOG_MODE" -eq 1 ]; then
  setup_supervisor "$CHISEL_BIN" "$BOOT_WRITER" || true
  start_fallback_processes "$CHISEL_BIN" || true
  verify_services || true
  # Watchdog is long-running. Do not hold bootstrap lock for the whole loop,
  # otherwise subsequent bootstrap/recover calls will be permanently blocked.
  release_bootstrap_lock || true
  trap - EXIT INT TERM
  watchdog_loop "$WATCHDOG_INTERVAL_SEC"
  exit 0
fi

HEAL_MAX_ROUNDS_RAW="${HAPPYCAPY_HEAL_MAX_ROUNDS:-8}"
case "$HEAL_MAX_ROUNDS_RAW" in
  ''|*[!0-9]*) HEAL_MAX_ROUNDS=8 ;;
  *) HEAL_MAX_ROUNDS="$HEAL_MAX_ROUNDS_RAW" ;;
esac
if [ "$HEAL_MAX_ROUNDS" -lt 1 ]; then
  HEAL_MAX_ROUNDS=1
fi
HEAL_SLEEP_SEC_RAW="${HAPPYCAPY_HEAL_SLEEP_SEC:-1.5}"
case "$HEAL_SLEEP_SEC_RAW" in
  ''|*[!0-9.]*)
    HEAL_SLEEP_SEC=1.5
    ;;
  *)
    HEAL_SLEEP_SEC="$HEAL_SLEEP_SEC_RAW"
    ;;
esac

CHISEL_SERVER=""
CONTROL_API_URL=""
HEARTBEAT_URL=""
REGISTRY_URL=""
HEAL_OK=0
HEAL_LAST_ERR=""
HEAL_LAST_STEP=""
HEAL_ROUND=1
while [ "$HEAL_ROUND" -le "$HEAL_MAX_ROUNDS" ]; do
  setup_supervisor "$CHISEL_BIN" "$BOOT_WRITER"
  start_fallback_processes "$CHISEL_BIN"

  if ! verify_services; then
    HEAL_LAST_STEP="verify_services"
    HEAL_LAST_ERR="services not healthy (chisel_ok=${CHISEL_OK}, sshd_ok=${SSHD_OK}, control_api_ok=${CONTROL_API_OK}, control_api_required=${CONTROL_API_REQUIRED})"
    sleep "$HEAL_SLEEP_SEC"
    HEAL_ROUND=$((HEAL_ROUND + 1))
    continue
  fi

  CHISEL_SERVER="$(query_preview_url_for_port 8080 || true)"
  if [ -z "$CHISEL_SERVER" ]; then
    HEAL_LAST_STEP="query_preview_url"
    HEAL_LAST_ERR="preview_url_empty"
    sleep "$HEAL_SLEEP_SEC"
    HEAL_ROUND=$((HEAL_ROUND + 1))
    continue
  fi
  CONTROL_API_URL="$(query_preview_url_for_port "$CONTROL_PORT" || true)"

  if ! HAPPYCAPY_CHISEL_SERVER="$CHISEL_SERVER" HAPPYCAPY_CONTROL_API_URL="$CONTROL_API_URL" "$BOOT_WRITER" >/tmp/happycapy-registry-report.log 2>&1; then
    HEAL_LAST_STEP="write_registry"
    HEAL_LAST_ERR="registry_write_failed"
    sleep "$HEAL_SLEEP_SEC"
    HEAL_ROUND=$((HEAL_ROUND + 1))
    continue
  fi

  REGISTRY_URL=""
  if [ -f "$REGISTRY_URL_PATH" ]; then
    REGISTRY_URL="$(head -n1 "$REGISTRY_URL_PATH" | tr -d '\r')"
  fi
  if [ -z "$CONTROL_API_URL" ] && [ -f "$CONTROL_API_URL_PATH" ]; then
    CONTROL_API_URL="$(head -n1 "$CONTROL_API_URL_PATH" | tr -d '\r')"
  fi
  if [ -z "$HEARTBEAT_URL" ] && [ -f "$HEARTBEAT_URL_PATH" ]; then
    HEARTBEAT_URL="$(head -n1 "$HEARTBEAT_URL_PATH" | tr -d '\r')"
  fi
  if [ -z "$HEARTBEAT_URL" ] && [ -n "$CONTROL_API_URL" ]; then
    HEARTBEAT_URL="${CONTROL_API_URL%/}/heartbeat"
  fi
  if [ -z "$REGISTRY_URL" ]; then
    HEAL_LAST_STEP="read_registry_url"
    HEAL_LAST_ERR="registry_url_missing"
    sleep "$HEAL_SLEEP_SEC"
    HEAL_ROUND=$((HEAL_ROUND + 1))
    continue
  fi

  HEAL_OK=1
  break
done

if [ "$HEAL_OK" -ne 1 ]; then
  install_log "bootstrap_fail step=${HEAL_LAST_STEP} detail=${HEAL_LAST_ERR}"
  emit_error "heal_loop_exhausted step=${HEAL_LAST_STEP} detail=${HEAL_LAST_ERR}"
  exit 1
fi
install_log "bootstrap_core_ready round=${HEAL_ROUND} chisel_server=${CHISEL_SERVER}"

if [ "$OUTPUT_MODE" = "short" ]; then
  printf '{"status":"ok","chisel_server":"%s","control_api_url":"%s","heartbeat_url":"%s","recover_script":"%s","round":%s}\n' \
    "$(json_escape "${CHISEL_SERVER}")" \
    "$(json_escape "${CONTROL_API_URL}")" \
    "$(json_escape "${HEARTBEAT_URL}")" \
    "$(json_escape "${RECOVER_SCRIPT_PATH}")" \
    "$HEAL_ROUND"
else
  printf '{"status":"ok","alias":"%s","chisel_server":"%s","control_api_url":"%s","heartbeat_url":"%s","control_port":%s,"chisel_auth":"%s","ssh_user":"%s","ssh_password":"%s","ssh_port":%s,"local_port":%s,"registry_file":"%s","registry_url":"%s","recover_script":"%s","bootstrap_cache":"%s","supervisor_managed":%s,"chisel_ok":%s,"sshd_ok":%s,"control_api_ok":%s,"control_api_required":%s,"heal_round":%s}\n' \
    "$(json_escape "$ALIAS")" \
    "$(json_escape "${CHISEL_SERVER}")" \
    "$(json_escape "${CONTROL_API_URL}")" \
    "$(json_escape "${HEARTBEAT_URL}")" \
    "$CONTROL_PORT" \
    "$(json_escape "$CHISEL_AUTH")" \
    "$(json_escape "$SSH_USER")" \
    "$(json_escape "$SSH_PASSWORD")" \
    "$SSH_PORT" \
    "$LOCAL_PORT" \
    "$(json_escape "$REGISTRY_FILE")" \
    "$(json_escape "$REGISTRY_URL")" \
    "$(json_escape "${RECOVER_SCRIPT_PATH}")" \
    "$(json_escape "${PERSIST_BOOTSTRAP}")" \
    "$SUPERVISOR_MANAGED" \
    "$CHISEL_OK" \
    "$SSHD_OK" \
    "$CONTROL_API_OK" \
    "$CONTROL_API_REQUIRED" \
    "$HEAL_ROUND"
fi

if [ "$WATCHDOG_MODE" -eq 1 ]; then
  watchdog_loop "$WATCHDOG_INTERVAL_SEC"
else
  # Worker startup may wait; release lock early so recover/bootstrap calls are
  # not blocked by detached worker orchestration.
  release_bootstrap_lock || true
  trap - EXIT INT TERM
  # Run restore first in background, then let watchdog maintain steady-state.
  # Watchdog will skip restore while worker is alive to avoid apt/dpkg lock races.
  start_autorestore_worker_detached || true
  # Keep watchdog running in background for heartbeat/keepalive self-heal.
  start_watchdog_worker_detached || true
fi
