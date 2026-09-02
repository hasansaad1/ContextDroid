#!/usr/bin/env bash
# Phase 4 — guest sink rule watchdog (15s cadence).
# Fail closed on drift: abort flag + exit. NO silent heal / rewrite.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

ADB_BIN="${ADB_BIN:-${ROOT}/tools/platform-tools/adb}"
[[ -x "${ADB_BIN}" ]] || ADB_BIN="${HOME}/Library/Android/sdk/platform-tools/adb"
export ADB_BIN
SERIAL="${ANDROID_SERIAL:-emulator-5556}"
INTERVAL_SEC="${ABRG_SINK_WATCHDOG_INTERVAL:-15}"

log() { printf '[sink_rule_watchdog] %s\n' "$*" >&2; }

vault_sink_dir() {
  python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety.vault_paths import assert_mounted, ensure_layout, MOUNT_ROOT
assert_mounted()
ensure_layout()
print(MOUNT_ROOT / "logs" / "sink")
PY
}

require_run_id() {
  local run_id="${1:-}"
  if [[ -z "${run_id}" || ! "${run_id}" =~ ^[A-Za-z0-9._-]{1,128}$ ]]; then
    log "invalid/missing --run-id"
    exit 2
  fi
}

parse_args() {
  RUN_ID="${ABRG_RUN_ID:-}"
  INTERVAL_SEC="${ABRG_SINK_WATCHDOG_INTERVAL:-15}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --run-id) RUN_ID="${2:-}"; shift 2 ;;
      --run-id=*) RUN_ID="${1#*=}"; shift ;;
      --interval) INTERVAL_SEC="${2:-}"; shift 2 ;;
      --interval=*) INTERVAL_SEC="${1#*=}"; shift ;;
      *) shift ;;
    esac
  done
  require_run_id "${RUN_ID}"
}

paths_for_run() {
  SINK_DIR="$(vault_sink_dir)"
  JSONL="${SINK_DIR}/${RUN_ID}.jsonl"
  WD_JSONL="${SINK_DIR}/${RUN_ID}.watchdog.jsonl"
  PID_FILE="${SINK_DIR}/${RUN_ID}.watchdog.pid"
  ABORT_FLAG="${SINK_DIR}/${RUN_ID}.abort"
}

emit_jsonl() {
  # Append one event to run jsonl + sibling watchdog jsonl.
  local event="$1"
  shift
  python3 - "$JSONL" "$WD_JSONL" "$RUN_ID" "$event" "$@" <<'PY'
import json, sys, time
jsonl, wd_jsonl, run_id, event = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
extra = {}
for a in sys.argv[5:]:
    if "=" in a:
        k, v = a.split("=", 1)
        extra[k] = v
rec = {"ts": time.time(), "event": event, "run_id": run_id, **extra}
line = json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n"
for path in (jsonl, wd_jsonl):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)
        fh.flush()
PY
}

# Single verification tick. Exit 0 if pins match; on drift write abort + exit 1.
# Never rewrites guest rules.
cmd_once() {
  parse_args "$@"
  paths_for_run
  : >> "${JSONL}"
  : >> "${WD_JSONL}"

  local verify_out rc=0
  set +e
  verify_out="$(ANDROID_SERIAL="${SERIAL}" bash "${ROOT}/scripts/safety/guest_sink_rules.sh" verify 2>&1)"
  rc=$?
  set -e

  if [[ "${rc}" -eq 0 ]]; then
    emit_jsonl "watchdog_tick" "result=ok" "interval_sec=${INTERVAL_SEC}"
    log "tick ok run_id=${RUN_ID}"
    return 0
  fi

  # Fail closed — abort flag, no heal.
  umask 077
  {
    echo "ts=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    echo "reason=sink_rule_drift"
    echo "run_id=${RUN_ID}"
    echo "serial=${SERIAL}"
    echo "verify_rc=${rc}"
    echo "----- verify output -----"
    printf '%s\n' "${verify_out}"
  } > "${ABORT_FLAG}"

  emit_jsonl "watchdog_drift" "result=abort" "reason=sink_rule_drift" "verify_rc=${rc}"
  log "DRIFT DETECTED — fail-closed abort flag written: ${ABORT_FLAG}"
  printf '%s\n' "${verify_out}" >&2
  return 1
}

cmd_loop() {
  parse_args "$@"
  paths_for_run
  umask 077
  echo $$ > "${PID_FILE}"
  emit_jsonl "watchdog_start" "interval_sec=${INTERVAL_SEC}" "pid=$$"

  # First check immediately (caller also may invoke once right after Gate B).
  if ! cmd_once --run-id "${RUN_ID}" --interval "${INTERVAL_SEC}"; then
    rm -f "${PID_FILE}"
    exit 1
  fi

  while true; do
    sleep "${INTERVAL_SEC}"
    if [[ -f "${ABORT_FLAG}" ]]; then
      log "abort flag already present — exiting"
      rm -f "${PID_FILE}"
      exit 1
    fi
    if ! cmd_once --run-id "${RUN_ID}" --interval "${INTERVAL_SEC}"; then
      rm -f "${PID_FILE}"
      exit 1
    fi
  done
}

cmd_start() {
  parse_args "$@"
  paths_for_run
  if [[ -f "${PID_FILE}" ]]; then
    local old
    old="$(tr -d '[:space:]' < "${PID_FILE}" || true)"
    if [[ -n "${old}" ]] && kill -0 "${old}" 2>/dev/null; then
      log "watchdog already running pid=${old}"
      exit 1
    fi
    rm -f "${PID_FILE}"
  fi
  rm -f "${ABORT_FLAG}"
  nohup bash "${ROOT}/scripts/safety/sink_rule_watchdog.sh" loop \
    --run-id "${RUN_ID}" --interval "${INTERVAL_SEC}" \
    >"${SINK_DIR}/${RUN_ID}.watchdog.log" 2>&1 &
  local i
  for i in $(seq 1 30); do
    if [[ -f "${PID_FILE}" ]] && kill -0 "$(tr -d '[:space:]' < "${PID_FILE}")" 2>/dev/null; then
      log "started pid=$(tr -d '[:space:]' < "${PID_FILE}") interval=${INTERVAL_SEC}s"
      echo "$(tr -d '[:space:]' < "${PID_FILE}")"
      return 0
    fi
    if [[ -f "${ABORT_FLAG}" ]]; then
      log "watchdog aborted on first tick"
      exit 1
    fi
    sleep 0.1
  done
  log "watchdog failed to start"
  exit 1
}

cmd_stop() {
  parse_args "$@"
  paths_for_run || true
  if [[ -f "${PID_FILE:-/dev/null}" ]]; then
    local pid
    pid="$(tr -d '[:space:]' < "${PID_FILE}" || true)"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      sleep 0.2
      kill -9 "${pid}" 2>/dev/null || true
    fi
    rm -f "${PID_FILE}"
  fi
  log "stopped run_id=${RUN_ID}"
}

cmd_status() {
  parse_args "$@"
  paths_for_run
  if [[ -f "${ABORT_FLAG}" ]]; then
    echo "abort run_id=${RUN_ID} flag=${ABORT_FLAG}"
    exit 1
  fi
  if [[ -f "${PID_FILE}" ]] && kill -0 "$(tr -d '[:space:]' < "${PID_FILE}")" 2>/dev/null; then
    echo "running run_id=${RUN_ID} pid=$(tr -d '[:space:]' < "${PID_FILE}")"
    exit 0
  fi
  echo "stopped run_id=${RUN_ID}"
  exit 1
}

usage() {
  cat <<EOF
Usage: ANDROID_SERIAL=emulator-5556 $0 {start|stop|status|once|loop} --run-id <ID> [--interval 15]

Re-checks exact nat pin + filter ICMP + v6 egress + OUTPUT jumps via guest_sink_rules.sh verify.
On drift: writes vault logs/sink/<run_id>.abort and exits — never heals rules.
EOF
}

main() {
  local cmd="${1:-}"
  shift || true
  case "${cmd}" in
    start) cmd_start "$@" ;;
    stop) cmd_stop "$@" ;;
    status) cmd_status "$@" ;;
    once) cmd_once "$@" ;;
    loop) cmd_loop "$@" ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
