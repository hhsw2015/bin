#!/usr/bin/env bash
set -euo pipefail

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
PERSIST_ROOT="${HAPPYCAPY_PERSIST_ROOT:-}"
if [ -z "$PERSIST_ROOT" ]; then
  if [ -d /home/node/a0/workspace ]; then
    PERSIST_ROOT="/home/node/a0/workspace"
  else
    PERSIST_ROOT="$HOME"
  fi
fi
PERSIST_DIR="${PERSIST_ROOT}/.happycapy"
PERSIST_BOOTSTRAP="${PERSIST_DIR}/bootstrap.sh"
RECOVER_SCRIPT_PATH="${HAPPYCAPY_RECOVER_SCRIPT:-${PERSIST_DIR}/happycapy-recover.sh}"
LEGACY_RECOVER_SCRIPT="${HOME}/.local/bin/happycapy-recover.sh"
OUTPUT_MODE="${HAPPYCAPY_OUTPUT_MODE:-}"
if [ -z "$OUTPUT_MODE" ]; then
  if [ "${HAPPYCAPY_RECOVER_CHAIN:-0}" = "1" ]; then
    OUTPUT_MODE="short"
  else
    OUTPUT_MODE="full"
  fi
fi

SUPERVISOR_MANAGED=0
CHISEL_OK=0
SSHD_OK=0

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
  if ! can_root; then
    return 0
  fi

  if command -v apt-get >/dev/null 2>&1; then
    with_retry 2 run_root apt-get update -y >/tmp/hc-apt-update.log 2>&1 || true
    with_retry 2 run_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      curl ca-certificates gzip openssh-server supervisor >/tmp/hc-apt-install.log 2>&1 || true
  elif command -v apk >/dev/null 2>&1; then
    with_retry 2 run_root apk add --no-cache curl gzip openssh supervisor >/tmp/hc-apk-install.log 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    with_retry 2 run_root yum install -y curl gzip openssh-server supervisor >/tmp/hc-yum-install.log 2>&1 || true
  fi
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

resp="\$(curl -sS -m 20 -X POST "https://happycapy.ai/api/export-port" \\
  -H "Authorization: Bearer \$ACCESS_TOKEN" \\
  -H "Cookie: authToken=\$ACCESS_TOKEN" \\
  -H "Content-Type: application/json" \\
  --data '{"port":8080}' || true)"
preview="\$(printf '%s' "\$resp" | sed -n 's/.*"previewUrl"[[:space:]]*:[[:space:]]*"\\([^\"]*\\)".*/\\1/p' | head -n1)"
if [ -z "\$preview" ]; then
  exit 0
fi

server="https://\${preview#https://}"
now="\$(date -u +%Y-%m-%dT%H:%M:%SZ)"
tmpf="/tmp/\${REGISTRY_FILE}"
cat > "\$tmpf" <<JSON
{"schema":"happycapy-registry-v1","happycapy_username":"\$ALIAS","alias":"\$ALIAS","chisel_server":"\$server","chisel_auth":"\$CHISEL_AUTH","ssh_user":"\$SSH_USER","ssh_password":"\$SSH_PASSWORD","ssh_port":\$SSH_PORT,"local_port":\$LOCAL_PORT,"remote_port":\$SSH_PORT,"updated_at":"\$now","service_count":0,"services":[]}
JSON

attempt=1
while [ "\$attempt" -le 3 ]; do
  up="\$(curl -sS -m 20 -F "file=@\${tmpf};filename=\${REGISTRY_FILE};type=text/plain" "\$UPLOAD_API" || true)"
  rel="\$(printf '%s' "\$up" | sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\\([^\"]*\\)".*/\\1/p' | head -n1)"
  if [ -n "\$rel" ]; then
    printf '%s\n' "\${REGISTRY_BASE}/\${rel#/}" > "\$HOME/.happycapy_registry_url"
    exit 0
  fi
  attempt=\$((attempt + 1))
  sleep 2
done

exit 0
EOF2

  mkdir -p "$HOME/.local/bin"
  writer="$HOME/.local/bin/happycapy-report-registry.sh"
  install -m 700 "$tmp_writer" "$writer"

  rm -f "$tmp_writer"
  echo "$writer"
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
command=${chisel_bin} server --port 8080 --auth ${CHISEL_AUTH} --keepalive 30s
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
  run_root supervisorctl restart happycapy-chisel >/dev/null 2>&1 || run_root supervisorctl start happycapy-chisel >/dev/null 2>&1 || true
  if [ -n "$sshd_bin" ]; then
    run_root supervisorctl restart happycapy-sshd >/dev/null 2>&1 || run_root supervisorctl start happycapy-sshd >/dev/null 2>&1 || true
  fi
  run_root supervisorctl start happycapy-registry-report >/dev/null 2>&1 || true
  if run_root supervisorctl status happycapy-chisel >/dev/null 2>&1; then
    SUPERVISOR_MANAGED=1
  else
    SUPERVISOR_MANAGED=0
  fi
}

start_fallback_processes() {
  local chisel_bin="$1"
  local writer="$2"
  local sshd_bin

  sshd_bin="$(find_sshd_bin || true)"

  if [ "$SUPERVISOR_MANAGED" -eq 1 ]; then
    "$writer" >/tmp/happycapy-registry-report.log 2>&1 || true
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
        nohup "$chisel_bin" server --port 8080 --auth "$CHISEL_AUTH" --keepalive 30s >/tmp/happycapy-chisel.log 2>&1 &
      fi
      ;;
    other)
      pkill -f "chisel server.*--port 8080" >/dev/null 2>&1 || true
      sleep 1
      nohup "$chisel_bin" server --port 8080 --auth "$CHISEL_AUTH" --keepalive 30s >/tmp/happycapy-chisel.log 2>&1 &
      ;;
    none)
      nohup "$chisel_bin" server --port 8080 --auth "$CHISEL_AUTH" --keepalive 30s >/tmp/happycapy-chisel.log 2>&1 &
      ;;
  esac

  "$writer" >/tmp/happycapy-registry-report.log 2>&1 || true
}

query_preview_url_once() {
  local resp preview
  resp="$(curl -sS -m 20 -X POST "https://happycapy.ai/api/export-port" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "Cookie: authToken=${ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    --data '{"port":8080}' || true)"
  preview="$(printf '%s' "$resp" | sed -n 's/.*"previewUrl"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  if [ -n "$preview" ]; then
    printf 'https://%s' "${preview#https://}"
  fi
}

query_preview_url() {
  local url
  for _ in 1 2 3; do
    url="$(query_preview_url_once || true)"
    if [ -n "$url" ]; then
      printf '%s\n' "$url"
      return 0
    fi
    sleep 2
  done
  return 1
}

install_recover_script() {
  mkdir -p "$PERSIST_DIR" "$(dirname "$RECOVER_SCRIPT_PATH")" "$HOME/.local/bin"

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
  if [ "$RECOVER_SCRIPT_PATH" != "$LEGACY_RECOVER_SCRIPT" ]; then
    install -m 700 "$RECOVER_SCRIPT_PATH" "$LEGACY_RECOVER_SCRIPT" 2>/dev/null || true
  fi
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

  if [ "$CHISEL_OK" -ne 1 ] || [ "$SSHD_OK" -ne 1 ]; then
    return 1
  fi
  return 0
}

if [ -z "$ACCESS_TOKEN" ]; then
  emit_error "HAPPYCAPY_ACCESS_TOKEN is empty"
  exit 1
fi

RECOVER_EXISTING=""
if [ -x "$RECOVER_SCRIPT_PATH" ]; then
  RECOVER_EXISTING="$RECOVER_SCRIPT_PATH"
elif [ -x "$LEGACY_RECOVER_SCRIPT" ]; then
  RECOVER_EXISTING="$LEGACY_RECOVER_SCRIPT"
fi

if [ "${HAPPYCAPY_RECOVER_CHAIN:-0}" != "1" ] && [ -n "$RECOVER_EXISTING" ]; then
  set +e
  HAPPYCAPY_RECOVER_CHAIN=1 bash "$RECOVER_EXISTING"
  pre_recover_rc=$?
  set -e
  if [ "$pre_recover_rc" -eq 0 ]; then
    exit 0
  fi
fi

RECOVER_SCRIPT="$(install_recover_script || true)"
if [ -z "$RECOVER_SCRIPT" ] || [ ! -x "$RECOVER_SCRIPT" ]; then
  emit_error "failed to create recover script"
  exit 1
fi

install_packages

if ! command -v curl >/dev/null 2>&1; then
  emit_error "curl not found"
  exit 1
fi

CHISEL_BIN="$(install_chisel || true)"
if [ -z "$CHISEL_BIN" ]; then
  emit_error "failed to install/find chisel"
  exit 1
fi

if ! configure_sshd; then
  emit_error "failed to install/configure sshd"
  exit 1
fi

BOOT_WRITER="$(write_reporter || true)"
if [ -z "$BOOT_WRITER" ] || [ ! -x "$BOOT_WRITER" ]; then
  emit_error "failed to create registry writer"
  exit 1
fi

setup_supervisor "$CHISEL_BIN" "$BOOT_WRITER"
start_fallback_processes "$CHISEL_BIN" "$BOOT_WRITER"

if ! verify_services; then
  emit_error "services not healthy (chisel_ok=${CHISEL_OK}, sshd_ok=${SSHD_OK})"
  exit 1
fi

CHISEL_SERVER="$(query_preview_url || true)"
"$BOOT_WRITER" >/tmp/happycapy-registry-report.log 2>&1 || true

REGISTRY_URL=""
if [ -f "$HOME/.happycapy_registry_url" ]; then
  REGISTRY_URL="$(head -n1 "$HOME/.happycapy_registry_url" | tr -d '\r')"
fi

if [ "$OUTPUT_MODE" = "short" ]; then
  printf '{"status":"ok","chisel_server":"%s","recover_script":"%s"}\n' \
    "$(json_escape "${CHISEL_SERVER}")" \
    "$(json_escape "${RECOVER_SCRIPT_PATH}")"
else
  printf '{"status":"ok","alias":"%s","chisel_server":"%s","chisel_auth":"%s","ssh_user":"%s","ssh_password":"%s","ssh_port":%s,"local_port":%s,"registry_file":"%s","registry_url":"%s","recover_script":"%s","bootstrap_cache":"%s","supervisor_managed":%s,"chisel_ok":%s,"sshd_ok":%s}\n' \
    "$(json_escape "$ALIAS")" \
    "$(json_escape "${CHISEL_SERVER}")" \
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
    "$SSHD_OK"
fi
