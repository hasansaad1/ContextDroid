#!/usr/bin/env bash
# Phase 4 Option C — host network sink lifecycle (DNS + HTTP/HTTPS).
# Fail-closed: vault must be mounted before bind; logs only under vault logs/sink/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

DNS_PORT="${ABRG_SINK_DNS_PORT:-15353}"
HTTP_PORT="${ABRG_SINK_HTTP_PORT:-8080}"
HTTPS_PORT="${ABRG_SINK_HTTPS_PORT:-8443}"
UDP_CATCHALL_PORT="${ABRG_SINK_UDP_CATCHALL_PORT:-8053}"
BIND_HOST="${ABRG_SINK_BIND:-0.0.0.0}"

log() { printf '[network_sink] %s\n' "$*" >&2; }

vault_python() {
  python3 - "$@" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety import vault_paths as vp

cmd = sys.argv[1]
if cmd == "assert":
    vp.assert_mounted()
    vp.ensure_layout()
    print(vp.MOUNT_ROOT / "logs" / "sink")
elif cmd == "sink_dir":
    vp.assert_mounted()
    print(vp.MOUNT_ROOT / "logs" / "sink")
else:
    raise SystemExit(f"unknown: {cmd}")
PY
}

require_run_id() {
  local run_id="${1:-}"
  if [[ -z "${run_id}" ]]; then
    log "missing --run-id (or ABRG_RUN_ID)"
    exit 2
  fi
  if [[ ! "${run_id}" =~ ^[A-Za-z0-9._-]{1,128}$ ]]; then
    log "invalid run-id: ${run_id}"
    exit 2
  fi
}

parse_run_id() {
  RUN_ID="${ABRG_RUN_ID:-}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --run-id)
        RUN_ID="${2:-}"
        shift 2
        ;;
      --run-id=*)
        RUN_ID="${1#*=}"
        shift
        ;;
      *)
        shift
        ;;
    esac
  done
  # CLI already consumed by caller for subcommand; keep env fallback.
  require_run_id "${RUN_ID}"
}

paths_for_run() {
  SINK_DIR="$(vault_python assert)"
  ENV_FILE="${SINK_DIR}/${RUN_ID}.env"
  JSONL_FILE="${SINK_DIR}/${RUN_ID}.jsonl"
  PID_FILE="${SINK_DIR}/${RUN_ID}.pid"
  GATE_A_FLAG="${SINK_DIR}/${RUN_ID}.gate_a_ok"
}

cmd_start() {
  parse_run_id "$@"
  paths_for_run

  if [[ -f "${PID_FILE}" ]]; then
    local old
    old="$(tr -d '[:space:]' < "${PID_FILE}" || true)"
    if [[ -n "${old}" ]] && kill -0 "${old}" 2>/dev/null; then
      log "sink already running for run_id=${RUN_ID} pid=${old}"
      exit 1
    fi
    rm -f "${PID_FILE}"
  fi

  NONCE="$(openssl rand -hex 16)"
  umask 077
  cat > "${ENV_FILE}" <<EOF
ABRG_RUN_ID=${RUN_ID}
ABRG_SINK_NONCE=${NONCE}
ABRG_SINK_DNS_PORT=${DNS_PORT}
ABRG_SINK_HTTP_PORT=${HTTP_PORT}
ABRG_SINK_HTTPS_PORT=${HTTPS_PORT}
ABRG_SINK_UDP_CATCHALL_PORT=${UDP_CATCHALL_PORT}
ABRG_SINK_BIND=${BIND_HOST}
ABRG_SINK_JSONL=${JSONL_FILE}
EOF

  # Bind only after vault paths proved writable.
  : >> "${JSONL_FILE}"

  nohup python3 "${ROOT}/scripts/safety/network_sink_server.py" \
    --run-id "${RUN_ID}" \
    --nonce "${NONCE}" \
    --jsonl "${JSONL_FILE}" \
    --pidfile "${PID_FILE}" \
    --bind "${BIND_HOST}" \
    --dns-port "${DNS_PORT}" \
    --http-port "${HTTP_PORT}" \
    --https-port "${HTTPS_PORT}" \
    --udp-catchall-port "${UDP_CATCHALL_PORT}" \
    --enable-https \
    --cert-dir "${SINK_DIR}/.certs-${RUN_ID}" \
    >"${SINK_DIR}/${RUN_ID}.server.log" 2>&1 &

  # Wait for listen + Gate A
  local i
  for i in $(seq 1 50); do
    if [[ -f "${PID_FILE}" ]] && kill -0 "$(tr -d '[:space:]' < "${PID_FILE}")" 2>/dev/null; then
      if cmd_gate_a_internal; then
        log "started run_id=${RUN_ID} dns=${DNS_PORT} http=${HTTP_PORT} https=${HTTPS_PORT} udp_catchall=${UDP_CATCHALL_PORT}"
        printf '%s\n' "${RUN_ID}"
        return 0
      fi
    fi
    sleep 0.1
  done
  log "sink failed to become healthy; tearing down"
  cmd_stop --run-id "${RUN_ID}" || true
  exit 1
}

cmd_gate_a_internal() {
  paths_for_run
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  local body headers
  headers="$(mktemp)"
  body="$(curl -fsS --max-time 2 -D "${headers}" \
    "http://127.0.0.1:${ABRG_SINK_HTTP_PORT}/__abrg_health?nonce=${ABRG_SINK_NONCE}" || true)"
  if [[ -z "${body}" ]]; then
    rm -f "${headers}"
    return 1
  fi
  if ! grep -qiE '^X-CONTEXTDROID-SINK:[[:space:]]*1' "${headers}"; then
    rm -f "${headers}"
    return 1
  fi
  rm -f "${headers}"
  if [[ "${body}" != *CONTEXTDROID_SINK_HTTP_MARKER* ]]; then
    return 1
  fi
  if [[ "${body}" != *"${ABRG_SINK_NONCE}"* ]]; then
    return 1
  fi
  date -u +'%Y-%m-%dT%H:%M:%SZ' > "${GATE_A_FLAG}"
  return 0
}

cmd_gate_a() {
  parse_run_id "$@"
  paths_for_run
  if [[ ! -f "${ENV_FILE}" ]]; then
    log "missing env file for ${RUN_ID}"
    exit 1
  fi
  if cmd_gate_a_internal; then
    log "Gate A PASS run_id=${RUN_ID}"
    exit 0
  fi
  log "Gate A FAIL run_id=${RUN_ID}"
  exit 1
}

cmd_stop() {
  parse_run_id "$@"
  paths_for_run || true
  if [[ -f "${PID_FILE:-/dev/null}" ]]; then
    local pid
    pid="$(tr -d '[:space:]' < "${PID_FILE}" || true)"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      sleep 0.3
      kill -9 "${pid}" 2>/dev/null || true
    fi
    rm -f "${PID_FILE}"
  fi
  rm -f "${GATE_A_FLAG:-}"
  log "stopped run_id=${RUN_ID}"
}

cmd_status() {
  parse_run_id "$@"
  paths_for_run
  if [[ -f "${PID_FILE}" ]] && kill -0 "$(tr -d '[:space:]' < "${PID_FILE}")" 2>/dev/null; then
    echo "running run_id=${RUN_ID} pid=$(tr -d '[:space:]' < "${PID_FILE}")"
    if [[ -f "${GATE_A_FLAG}" ]]; then
      echo "gate_a_ok=$(cat "${GATE_A_FLAG}")"
    else
      echo "gate_a_ok=missing"
    fi
    exit 0
  fi
  echo "stopped run_id=${RUN_ID}"
  exit 1
}

usage() {
  cat <<EOF
Usage: $0 {start|stop|status|gate-a} --run-id <ID>

Host ports (defaults; guest DNATs onto these):
  DNS  ${DNS_PORT}   (5353 is taken by adb mDNS on this host)
  HTTP ${HTTP_PORT}
  HTTPS ${HTTPS_PORT}
  UDP catch-all ${UDP_CATCHALL_PORT}  (guest any non-53 UDP → this port)

Vault must be mounted at the path from vault_paths.MOUNT_ROOT before start.
EOF
}

main() {
  local cmd="${1:-}"
  shift || true
  case "${cmd}" in
    start) cmd_start "$@" ;;
    stop) cmd_stop "$@" ;;
    status) cmd_status "$@" ;;
    gate-a) cmd_gate_a "$@" ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
