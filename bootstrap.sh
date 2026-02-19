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
PERSIST_BOOTSTRAP="${PERSIST_DIR}/bootstrap.sh"
RECOVER_SCRIPT_PATH="${HAPPYCAPY_RECOVER_SCRIPT:-${PERSIST_DIR}/happycapy-recover.sh}"
WORKSPACE_RECOVER_GLOB="/home/node/*/workspace/.happycapy/happycapy-recover.sh"
REGISTRY_URL_PATH="${HAPPYCAPY_REGISTRY_URL_PATH:-${PERSIST_DIR}/registry_url.txt}"
CONTROL_PORT="${HAPPYCAPY_CONTROL_PORT:-18080}"
CONTROL_API_SCRIPT="${PERSIST_DIR}/happycapy-control-api.js"
CONTROL_API_PID_FILE="${PERSIST_DIR}/happycapy-control-api.pid"
CONTROL_API_URL_PATH="${HAPPYCAPY_CONTROL_API_URL_PATH:-${PERSIST_DIR}/control_api_url.txt}"
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
WATCHDOG_INTERVAL_RAW="${HAPPYCAPY_WATCHDOG_INTERVAL_SEC:-8}"
case "$WATCHDOG_INTERVAL_RAW" in
  ''|*[!0-9.]*)
    WATCHDOG_INTERVAL_SEC=8
    ;;
  *)
    WATCHDOG_INTERVAL_SEC="$WATCHDOG_INTERVAL_RAW"
    ;;
esac
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
      curl ca-certificates gzip openssh-server supervisor nodejs >/tmp/hc-apt-install.log 2>&1 || true
  elif command -v apk >/dev/null 2>&1; then
    with_retry 2 run_root apk add --no-cache curl gzip openssh supervisor nodejs >/tmp/hc-apk-install.log 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    with_retry 2 run_root yum install -y curl gzip openssh-server supervisor nodejs >/tmp/hc-yum-install.log 2>&1 || true
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
REGISTRY_URL_PATH="${REGISTRY_URL_PATH}"
CONTROL_PORT="${CONTROL_PORT}"
CONTROL_API_URL_PATH="${CONTROL_API_URL_PATH}"
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
now="\$(date -u +%Y-%m-%dT%H:%M:%SZ)"
tmpf="/tmp/\${REGISTRY_FILE}"
cat > "\$tmpf" <<JSON
{"schema":"happycapy-registry-v1","happycapy_username":"\$ALIAS","alias":"\$ALIAS","chisel_server":"\$server","chisel_auth":"\$CHISEL_AUTH","ssh_user":"\$SSH_USER","ssh_password":"\$SSH_PASSWORD","ssh_port":\$SSH_PORT,"local_port":\$LOCAL_PORT,"remote_port":\$SSH_PORT,"control_api_port":\$CONTROL_PORT,"control_api_url":"\$control_url","updated_at":"\$now","service_count":0,"services":[]}
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
const http = require("http");
const fs = require("fs");
const { spawnSync } = require("child_process");
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
  exportTimeout: Number(process.env.HAPPYCAPY_EXPORT_PORT_TIMEOUT_SEC || "8"),
};
let recoverInProgress = false;
let lastRecoverAt = 0;
let lastRecoverOk = null;

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
  pkill -f "chisel server.*--port 8080" >/dev/null 2>&1 || true
  pkill -f "sshd.*-p $SSH_PORT" >/dev/null 2>&1 || true
  sleep 1
fi
HAPPYCAPY_RECOVER_CHAIN=1 bash "$R"
`;
  const res = runBash(script, 180000, {
    RECOVER_SCRIPT: cfg.recoverScript,
    MODE: mode || "soft",
    SSH_PORT: String(cfg.sshPort),
  });
  return res;
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
  let chiselServer = "";
  let controlApiUrl = readText(cfg.controlApiUrlPath);
  if (refresh) {
    chiselServer = exportPortUrl(8080);
    controlApiUrl = exportPortUrl(cfg.controlPort) || controlApiUrl;
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
    chisel_server: chiselServer,
    registry_url: readText(cfg.registryUrlPath),
    runtime_state: runtimeStateValue,
    recommended_action: recommendedAction,
    recover_in_progress: recoverInProgress,
    last_recover_at: lastRecoverAt ? new Date(lastRecoverAt).toISOString() : "",
    last_recover_ok: lastRecoverOk,
    ...state,
    checked_at: new Date().toISOString(),
  };
}

const server = http.createServer((req, res) => {
  const u = new URL(req.url || "/", `http://127.0.0.1:${cfg.controlPort}`);
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
        let rec = { ok: false, code: -1, out: "recover_not_started" };
        try {
          rec = doRecover(mode);
        } catch (e) {
          rec = { ok: false, code: -1, out: String(e || "recover_exception") };
        }
        recoverInProgress = false;
        lastRecoverOk = !!rec.ok;
        const chiselServer = exportPortUrl(8080);
        const controlApiUrl = exportPortUrl(cfg.controlPort);
        const wr = writeRegistry(chiselServer, controlApiUrl);
        return sendJson(res, rec.ok ? 200 : 500, {
          ok: rec.ok,
          action: "recover",
          mode,
          rc: rec.code,
          chisel_server: chiselServer,
          control_api_url: controlApiUrl,
          registry_write: wr,
          output: (rec.out || "").trim().split(/\n/).slice(-20).join("\n"),
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
  process.stdout.write(`{"status":"ok","control_port":${cfg.controlPort}}\n`);
});
EOF2
  chmod 700 "$CONTROL_API_SCRIPT"
  echo "$CONTROL_API_SCRIPT"
}

ensure_control_api_script() {
  if [ -z "$CONTROL_API_BIN" ]; then
    return 1
  fi
  if [ ! -x "$CONTROL_API_SCRIPT" ]; then
    write_control_api_server >/dev/null 2>&1 || true
  fi
  if [ ! -x "$CONTROL_API_SCRIPT" ]; then
    return 1
  fi
  if ! "$CONTROL_API_BIN" --check "$CONTROL_API_SCRIPT" >/tmp/happycapy-control-api.check.log 2>&1; then
    write_control_api_server >/dev/null 2>&1 || true
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
command=/usr/bin/env HAPPYCAPY_ALIAS=${ALIAS} HAPPYCAPY_ACCESS_TOKEN=${ACCESS_TOKEN} HAPPYCAPY_SSH_PORT=${SSH_PORT} HAPPYCAPY_CONTROL_PORT=${CONTROL_PORT} HAPPYCAPY_RECOVER_SCRIPT=${RECOVER_SCRIPT_PATH} HAPPYCAPY_REGISTRY_WRITER=${writer} HAPPYCAPY_REGISTRY_URL_PATH=${REGISTRY_URL_PATH} HAPPYCAPY_CONTROL_API_URL_PATH=${CONTROL_API_URL_PATH} HAPPYCAPY_EXPORT_PORT_TIMEOUT_SEC=${EXPORT_PORT_TIMEOUT_SEC} ${CONTROL_API_BIN} ${CONTROL_API_SCRIPT}
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
  if [ "$SUPERVISOR_MANAGED" -eq 1 ]; then
    if is_port_listening "$CONTROL_PORT" && control_api_http_ready; then
      CONTROL_API_OK=1
    else
      if [ "$CONTROL_API_REQUIRED" -eq 1 ]; then
        ensure_control_api_script >/dev/null 2>&1 || true
        run_root supervisorctl start happycapy-control-api >/dev/null 2>&1 || run_root supervisorctl restart happycapy-control-api >/dev/null 2>&1 || true
        sleep 1
      fi
      if is_port_listening "$CONTROL_PORT" && control_api_http_ready; then
        CONTROL_API_OK=1
      else
        CONTROL_API_OK=0
      fi
    fi
    return 0
  fi

  if [ -z "$CONTROL_API_BIN" ] || [ ! -x "$CONTROL_API_SCRIPT" ]; then
    CONTROL_API_OK=0
    return 1
  fi

  if is_port_listening "$CONTROL_PORT" && control_api_http_ready; then
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
  HAPPYCAPY_EXPORT_PORT_TIMEOUT_SEC="$EXPORT_PORT_TIMEOUT_SEC" \
  nohup "$CONTROL_API_BIN" "$CONTROL_API_SCRIPT" >/tmp/happycapy-control-api.log 2>/tmp/happycapy-control-api.err.log &
  printf '%s\n' "$!" > "$CONTROL_API_PID_FILE"
  for _ in 1 2 3; do
    sleep 1
    if is_port_listening "$CONTROL_PORT" && control_api_http_ready; then
      CONTROL_API_OK=1
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
  while true; do
    setup_supervisor "$CHISEL_BIN" "$BOOT_WRITER"
    start_fallback_processes "$CHISEL_BIN"
    if verify_services; then
      local server_now control_now
      server_now="$(query_preview_url_for_port 8080 || true)"
      control_now="$(query_preview_url_for_port "$CONTROL_PORT" || true)"
      if [ -n "$server_now" ]; then
        HAPPYCAPY_CHISEL_SERVER="$server_now" HAPPYCAPY_CONTROL_API_URL="$control_now" "$BOOT_WRITER" >/tmp/happycapy-registry-report.log 2>&1 || true
      fi
    fi
    sleep "$interval"
  done
}

acquire_bootstrap_lock() {
  mkdir -p "$PERSIST_DIR"
  local tries=0
  local max_tries=12
  while true; do
    if mkdir "$BOOTSTRAP_LOCK_DIR" 2>/dev/null; then
      printf '%s\n' "$$" > "$BOOTSTRAP_LOCK_PID_FILE"
      return 0
    fi
    local owner_pid
    owner_pid="$(cat "$BOOTSTRAP_LOCK_PID_FILE" 2>/dev/null || true)"
    if [ -n "$owner_pid" ] && kill -0 "$owner_pid" 2>/dev/null; then
      tries=$((tries + 1))
      if [ "$tries" -ge "$max_tries" ]; then
        return 1
      fi
      sleep 1
      continue
    fi
    rm -rf "$BOOTSTRAP_LOCK_DIR" >/dev/null 2>&1 || true
    sleep 0.2
  done
}

release_bootstrap_lock() {
  local owner_pid
  owner_pid="$(cat "$BOOTSTRAP_LOCK_PID_FILE" 2>/dev/null || true)"
  if [ -n "$owner_pid" ] && [ "$owner_pid" != "$$" ]; then
    return 0
  fi
  rm -rf "$BOOTSTRAP_LOCK_DIR" >/dev/null 2>&1 || true
}

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

if [ "${HAPPYCAPY_RECOVER_CHAIN:-0}" != "1" ] && [ -n "$RECOVER_EXISTING" ]; then
  set +e
  HAPPYCAPY_RECOVER_CHAIN=1 bash "$RECOVER_EXISTING"
  pre_recover_rc=$?
  set -e
  if [ "$pre_recover_rc" -eq 0 ]; then
    exit 0
  fi
fi

if ! acquire_bootstrap_lock; then
  p2222=0
  if is_port_listening "$SSH_PORT"; then p2222=1; fi
  p8080=0
  if is_port_listening 8080; then p8080=1; fi
  if [ "$p2222" -eq 1 ] && [ "$p8080" -eq 1 ]; then
    printf '{"status":"ok","message":"bootstrap_lock_busy","p2222":%s,"p8080":%s}\n' "$p2222" "$p8080"
    exit 0
  fi
  emit_error "bootstrap lock busy"
  exit 1
fi
trap 'release_bootstrap_lock' EXIT INT TERM

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

CONTROL_API_BIN="$(command -v node || true)"
if [ -z "$CONTROL_API_BIN" ]; then
  emit_error "node not found (control api unavailable)"
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

if [ -n "$CONTROL_API_BIN" ]; then
  write_control_api_server >/dev/null 2>&1 || true
  if ! ensure_control_api_script; then
    emit_error "failed to build/validate control api script"
    exit 1
  fi
fi
if [ -x "$CONTROL_API_SCRIPT" ]; then
  CONTROL_API_REQUIRED=1
else
  emit_error "failed to create control api server script"
  exit 1
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
  emit_error "heal_loop_exhausted step=${HEAL_LAST_STEP} detail=${HEAL_LAST_ERR}"
  exit 1
fi

if [ "$OUTPUT_MODE" = "short" ]; then
  printf '{"status":"ok","chisel_server":"%s","recover_script":"%s","round":%s}\n' \
    "$(json_escape "${CHISEL_SERVER}")" \
    "$(json_escape "${RECOVER_SCRIPT_PATH}")" \
    "$HEAL_ROUND"
else
  printf '{"status":"ok","alias":"%s","chisel_server":"%s","control_api_url":"%s","control_port":%s,"chisel_auth":"%s","ssh_user":"%s","ssh_password":"%s","ssh_port":%s,"local_port":%s,"registry_file":"%s","registry_url":"%s","recover_script":"%s","bootstrap_cache":"%s","supervisor_managed":%s,"chisel_ok":%s,"sshd_ok":%s,"control_api_ok":%s,"control_api_required":%s,"heal_round":%s}\n' \
    "$(json_escape "$ALIAS")" \
    "$(json_escape "${CHISEL_SERVER}")" \
    "$(json_escape "${CONTROL_API_URL}")" \
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

if [ "$WATCHDOG_MODE" -eq 1 ] && [ "${HAPPYCAPY_RECOVER_CHAIN:-0}" != "1" ]; then
  watchdog_loop "$WATCHDOG_INTERVAL_SEC"
fi
