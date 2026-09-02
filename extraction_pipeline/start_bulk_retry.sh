#!/usr/bin/env bash
# Boot a stable headless emulator, verify root frida-server, then retry failed bulk APKs.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"

export ANDROID_SERIAL="${ANDROID_SERIAL:-emulator-5554}"
export AVD_NAME="${AVD_NAME:-abrg_benign}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}"
export PATH="${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/emulator:${PATH}"
export LOG_DIR="${LOG_DIR:-${REPO}/logs/bulk_llm_dataset}"
export FRIDA_USE_DOCKER="${FRIDA_USE_DOCKER:-0}"
export SKIP_DOCKER_AUTO_START=1
export CONTEXTDROID_SKIP_SNAPSHOT_LOAD=1
export BULK_RETRY_FAILED=1
export BULK_EMULATOR_WATCHDOG=0
export EMULATOR_BOOT_TIMEOUT_SEC="${EMULATOR_BOOT_TIMEOUT_SEC:-300}"
export EMULATOR_GPU="${EMULATOR_GPU:-swiftshader_indirect}"
export EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW:-1}"
export EMULATOR_NO_SNAPSHOT_LOAD=1
export EMULATOR_SAVE_SNAPSHOT=0

ADB=(adb -s "${ANDROID_SERIAL}")

booted() {
  [[ "$("${ADB[@]}" get-state 2>/dev/null | tr -d '\r')" == "device" ]] \
    && [[ "$("${ADB[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]
}

pkill -f "run_emulator_watchdog.sh" 2>/dev/null || true
rm -rf /tmp/contextdroid_ensure_emulator.lock.d 2>/dev/null || true

# One persistent emulator process — bulk must not spawn a second instance.
bash "${REPO}/extraction_pipeline/run_emulator_daemon.sh" --detach
export SKIP_EMULATOR_AUTO_START=1

wait_booted() {
  local i max="${1:-120}"
  for i in $(seq 1 "${max}"); do
    if booted; then
      return 0
    fi
    sleep 1
  done
  return 1
}

if ! wait_booted 120; then
  echo "[start] ERROR: emulator daemon did not bring device online (see logs/bulk_llm_dataset/emulator_daemon.log)" >&2
  exit 1
fi

# Daemon roots device on its next loop; wait for adb root + frida before analyze starts.
for _ in $(seq 1 90); do
  uid="$("${ADB[@]}" shell id -u 2>/dev/null | tr -d '\r' || true)"
  frida="$("${ADB[@]}" shell "ps -A -o USER,NAME | grep frida-server" 2>/dev/null | tr -d '\r' || true)"
  if [[ "${uid}" == "0" ]] && grep -qE '^root[[:space:]]' <<<"${frida}"; then
    break
  fi
  sleep 2
done

echo "[start] emulator online uid=$("${ADB[@]}" shell id -u 2>/dev/null | tr -d '\r')"
echo "[start] frida=$("${ADB[@]}" shell "ps -A -o USER,PID,NAME | grep frida" 2>/dev/null | tr -d '\r' || echo missing)"
if [[ "$("${ADB[@]}" shell id -u 2>/dev/null | tr -d '\r')" != "0" ]]; then
  echo "[start] WARN: adb not root yet; bulk may fail Frida attach" >&2
fi
echo "[start] starting bulk retry (272 failed APKs)"
DAEMON_LOG="${LOG_DIR}/bulk_daemon.log"
PID_FILE="${LOG_DIR}/bulk_runner.pid"
if [[ "${BULK_FOREGROUND:-0}" == "1" ]]; then
  exec bash extraction_pipeline/run_bulk_llm_dataset_resumable.sh data/apks/benign 1200
fi
nohup bash extraction_pipeline/run_bulk_llm_dataset_resumable.sh data/apks/benign 1200 \
  >>"${DAEMON_LOG}" 2>&1 &
echo $! >"${PID_FILE}"
disown -h $! 2>/dev/null || true
echo "[start] bulk running in background pid=$(cat "${PID_FILE}") log=${DAEMON_LOG}"
echo "[start] tail -f ${LOG_DIR}/batch.log ${DAEMON_LOG}"
