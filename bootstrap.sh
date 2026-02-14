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

if [ -z "$ACCESS_TOKEN" ]; then
  echo "{\"status\":\"error\",\"message\":\"HAPPYCAPY_ACCESS_TOKEN is empty\"}"
  exit 1
fi

SUPERVISOR_MANAGED=0

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

has_cmdline_substr() {
  local needle="$1"
  ps -eo command= | grep -F -- "$needle" >/dev/null 2>&1
}

install_packages() {
  if ! can_root; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    run_root apt-get update -y >/dev/null 2>&1 || true
    run_root apt-get install -y curl gzip openssh-server supervisor >/dev/null 2>&1 || true
  elif command -v apk >/dev/null 2>&1; then
    run_root apk add --no-cache curl gzip openssh supervisor >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    run_root yum install -y curl gzip openssh-server supervisor >/dev/null 2>&1 || true
  fi
}

install_chisel() {
  local chisel_bin
  chisel_bin="$(command -v chisel || true)"
  if [ -n "$chisel_bin" ]; then
    echo "$chisel_bin"
    return 0
  fi

  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)
      echo ""
      return 1
      ;;
  esac

  local tmp_gz tmp_bin url
  tmp_gz="$(mktemp /tmp/chisel.XXXXXX.gz)"
  tmp_bin="$(mktemp /tmp/chisel.XXXXXX)"
  url="https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_${arch}.gz"
  curl -fsSL "$url" -o "$tmp_gz"
  gzip -dc "$tmp_gz" > "$tmp_bin"
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
  sshd_bin="$(command -v sshd || true)"
  if [ -z "$sshd_bin" ]; then
    return 0
  fi
  if ! can_root; then
    return 0
  fi

  run_root mkdir -p /var/run/sshd || true
  if [ -f /etc/ssh/sshd_config ]; then
    run_root sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
    run_root sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config || true
    run_root sed -i 's/^#\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config || true
  fi
  if id -u "$SSH_USER" >/dev/null 2>&1; then
    printf '%s:%s\n' "$SSH_USER" "$SSH_PASSWORD" | run_root chpasswd || true
  fi
}

write_reporter() {
  local writer_dir writer
  if can_root; then
    writer_dir="/usr/local/bin"
  else
    writer_dir="$HOME/.local/bin"
    mkdir -p "$writer_dir"
  fi
  writer="$writer_dir/happycapy-report-registry.sh"
  cat > "$writer" <<EOF
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
preview="\$(printf '%s' "\$resp" | sed -n 's/.*"previewUrl"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p' | head -n1)"
if [ -z "\$preview" ]; then
  exit 0
fi
server="https://\${preview#https://}"
now="\$(date -u +%Y-%m-%dT%H:%M:%SZ)"
tmpf="/tmp/\${REGISTRY_FILE}"
cat > "\$tmpf" <<JSON
{"schema":"happycapy-registry-v1","happycapy_username":"\$ALIAS","alias":"\$ALIAS","chisel_server":"\$server","chisel_auth":"\$CHISEL_AUTH","ssh_user":"\$SSH_USER","ssh_password":"\$SSH_PASSWORD","ssh_port":\$SSH_PORT,"local_port":\$LOCAL_PORT,"remote_port":\$SSH_PORT,"updated_at":"\$now","service_count":0,"services":[]}
JSON
up="\$(curl -sS -m 20 -F "file=@\${tmpf};filename=\${REGISTRY_FILE};type=text/plain" "\$UPLOAD_API" || true)"
rel="\$(printf '%s' "\$up" | sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p' | head -n1)"
if [ -n "\$rel" ]; then
  printf '%s\n' "\${REGISTRY_BASE}/\${rel#/}" > "\$HOME/.happycapy_registry_url"
fi
EOF
  chmod +x "$writer"
  echo "$writer"
}

setup_supervisor() {
  local chisel_bin="$1"
  local writer="$2"
  local sshd_bin
  sshd_bin="$(command -v sshd || true)"
  if ! can_root || ! command -v supervisorctl >/dev/null 2>&1; then
    return 0
  fi

  local conf_dir
  conf_dir="/etc/supervisor/conf.d"
  if [ ! -d "$conf_dir" ]; then
    conf_dir="/etc/supervisord.d"
  fi
  if [ ! -d "$conf_dir" ]; then
    return 0
  fi
  if ! run_root supervisorctl status >/dev/null 2>&1; then
    return 0
  fi

  cat > /tmp/happycapy-chisel.conf <<EOF
[program:happycapy-chisel]
command=${chisel_bin} server --port 8080 --auth ${CHISEL_AUTH} --reverse --keepalive 30s
autostart=true
autorestart=true
startsecs=2
stdout_logfile=/tmp/happycapy-chisel.log
stderr_logfile=/tmp/happycapy-chisel.err.log
EOF
  run_root cp /tmp/happycapy-chisel.conf "${conf_dir}/happycapy-chisel.conf"

  if [ -n "$sshd_bin" ]; then
    cat > /tmp/happycapy-sshd.conf <<EOF
[program:happycapy-sshd]
command=${sshd_bin} -D -p ${SSH_PORT}
autostart=true
autorestart=true
startsecs=2
stdout_logfile=/tmp/happycapy-sshd.log
stderr_logfile=/tmp/happycapy-sshd.err.log
EOF
    run_root cp /tmp/happycapy-sshd.conf "${conf_dir}/happycapy-sshd.conf"
  fi

  cat > /tmp/happycapy-registry-report.conf <<EOF
[program:happycapy-registry-report]
command=/bin/bash -lc '${writer}'
autostart=true
autorestart=false
startsecs=0
stdout_logfile=/tmp/happycapy-registry-report.log
stderr_logfile=/tmp/happycapy-registry-report.err.log
EOF
  run_root cp /tmp/happycapy-registry-report.conf "${conf_dir}/happycapy-registry-report.conf"

  run_root supervisorctl reread || true
  run_root supervisorctl update || true
  run_root supervisorctl restart happycapy-chisel || run_root supervisorctl start happycapy-chisel || true
  if [ -n "$sshd_bin" ]; then
    run_root supervisorctl restart happycapy-sshd || run_root supervisorctl start happycapy-sshd || true
  fi
  run_root supervisorctl start happycapy-registry-report || true
  SUPERVISOR_MANAGED=1
}

start_fallback_processes() {
  local chisel_bin="$1"
  local writer="$2"
  local sshd_bin
  sshd_bin="$(command -v sshd || true)"
  if [ "$SUPERVISOR_MANAGED" -eq 1 ]; then
    bash "$writer" >/tmp/happycapy-registry-report.log 2>&1 || true
    return 0
  fi

  if [ -n "$sshd_bin" ] && can_root; then
    if ! has_cmdline_substr "sshd -D -p ${SSH_PORT}"; then
      nohup "$sshd_bin" -D -p "$SSH_PORT" >/tmp/happycapy-sshd.log 2>&1 &
    fi
  fi

  if has_cmdline_substr "chisel server --port 8080 --auth ${CHISEL_AUTH} --reverse"; then
    :
  else
    if has_cmdline_substr "chisel server --port 8080"; then
      pkill -f "chisel server --port 8080" >/dev/null 2>&1 || true
      sleep 1
    fi
    nohup "$chisel_bin" server --port 8080 --auth "$CHISEL_AUTH" --reverse --keepalive 30s >/tmp/happycapy-chisel.log 2>&1 &
  fi

  bash "$writer" >/tmp/happycapy-registry-report.log 2>&1 || true
}

query_preview_url() {
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

install_packages
if ! command -v curl >/dev/null 2>&1; then
  echo "{\"status\":\"error\",\"message\":\"curl not found\"}"
  exit 1
fi

CHISEL_BIN="$(install_chisel || true)"
if [ -z "$CHISEL_BIN" ]; then
  echo "{\"status\":\"error\",\"message\":\"failed to install/find chisel\"}"
  exit 1
fi

configure_sshd
BOOT_WRITER="$(write_reporter)"
setup_supervisor "$CHISEL_BIN" "$BOOT_WRITER"
start_fallback_processes "$CHISEL_BIN" "$BOOT_WRITER"

CHISEL_SERVER="$(query_preview_url || true)"
if [ -z "$CHISEL_SERVER" ]; then
  CHISEL_SERVER=""
fi

echo "{\"status\":\"ok\",\"alias\":\"${ALIAS}\",\"chisel_server\":\"${CHISEL_SERVER}\",\"chisel_auth\":\"${CHISEL_AUTH}\",\"ssh_user\":\"${SSH_USER}\",\"ssh_password\":\"${SSH_PASSWORD}\",\"ssh_port\":${SSH_PORT},\"local_port\":${LOCAL_PORT},\"registry_file\":\"${REGISTRY_FILE}\",\"supervisor_managed\":${SUPERVISOR_MANAGED}}"
