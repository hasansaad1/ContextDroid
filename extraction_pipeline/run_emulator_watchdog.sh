#!/usr/bin/env bash
# Background watchdog: keep the analysis emulator online between bulk runs.
#
# Usage:
#   bash extraction_pipeline/run_emulator_watchdog.sh &
#
# Environment:
#   WATCHDOG_INTERVAL_SEC   default 30
#   Same vars as ensure_emulator.sh (ANDROID_SERIAL, AVD_NAME, ...)
#
# Writes PID to ${LOG_DIR:-logs}/emulator_watchdog.pid and logs to emulator_watchdog.log

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_DIR="${LOG_DIR:-${REPO_ROOT}/logs/bulk_llm_dataset}"
WATCH_LOG="${LOG_DIR}/emulator_watchdog.log"
PID_FILE="${LOG_DIR}/emulator_watchdog.pid"
INTERVAL="${WATCHDOG_INTERVAL_SEC:-30}"

mkdir -p "${LOG_DIR}"
echo "$$" >"${PID_FILE}"

log() {
  printf '[%s] [emulator-watchdog] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >>"${WATCH_LOG}"
}

analysis_active() {
  pgrep -f "analyze_apk\\.py" >/dev/null 2>&1
}

device_ready() {
  local adb_bin="${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}/platform-tools/adb"
  [[ -x "${adb_bin}" ]] || adb_bin="$(command -v adb 2>/dev/null || true)"
  [[ -n "${adb_bin}" ]] || return 1
  local serial="${ANDROID_SERIAL:-emulator-5554}"
  [[ "$("${adb_bin}" -s "${serial}" get-state 2>/dev/null | tr -d '\r')" == "device" ]] || return 1
  [[ "$("${adb_bin}" -s "${serial}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]
}

cleanup() {
  rm -f "${PID_FILE}"
  exit 0
}
trap cleanup INT TERM EXIT

log "started pid=$$ interval=${INTERVAL}s serial=${ANDROID_SERIAL:-emulator-5554}"

while true; do
  if analysis_active; then
    # Snapshot restore / brief adb offline during analyze_apk — wait, do not spawn a second emulator.
    if device_ready; then
      sleep "${INTERVAL}"
      continue
    fi
    log "device offline during analyze_apk; waiting for reconnect (no restart)"
    recovered=0
    for _ in $(seq 1 45); do
      sleep 2
      if device_ready; then
        recovered=1
        break
      fi
    done
    if [[ "${recovered}" == "1" ]]; then
      sleep "${INTERVAL}"
      continue
    fi
    log "device still offline after analyze grace window; calling ensure_emulator"
  fi
  if ! LOG_DIR="${LOG_DIR}" bash "${SCRIPT_DIR}/ensure_emulator.sh" >>"${WATCH_LOG}" 2>&1; then
    log "ensure_emulator failed; will retry in ${INTERVAL}s"
  fi
  sleep "${INTERVAL}"
done
