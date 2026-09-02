#!/usr/bin/env bash
# Keep one headless abrg_benign emulator online (boot + root frida-server).
# Start once before bulk runs; survives bulk/analyze restarts.
#
#   bash extraction_pipeline/run_emulator_daemon.sh          # foreground
#   bash extraction_pipeline/run_emulator_daemon.sh --detach # background

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${SCRIPT_DIR}/.." && pwd)"
AVD_NAME="${AVD_NAME:-abrg_benign}"
ANDROID_SERIAL="${ANDROID_SERIAL:-emulator-5554}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${HOME}/Library/Android/sdk}"
export PATH="${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/emulator:${PATH}"
EMULATOR_LOG="${EMULATOR_LOG:-/tmp/${AVD_NAME}_emulator.log}"
EMULATOR_GPU="${EMULATOR_GPU:-swiftshader_indirect}"
EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW:-1}"
PID_FILE="${EMULATOR_DAEMON_PID_FILE:-/tmp/${AVD_NAME}_emulator_daemon.pid}"
EMU_PID_FILE="${EMULATOR_PID_FILE:-/tmp/${AVD_NAME}_emulator.pid}"
INTERVAL="${EMULATOR_DAEMON_INTERVAL_SEC:-20}"
BOOT_TIMEOUT_SEC="${EMULATOR_BOOT_TIMEOUT_SEC:-300}"

ADB=(adb -s "${ANDROID_SERIAL}")

log() { printf '[emulator-daemon] %s\n' "$1"; }

booted() {
  [[ "$("${ADB[@]}" get-state 2>/dev/null | tr -d '\r')" == "device" ]] \
    && [[ "$("${ADB[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]
}

qemu_running() {
  pgrep -f "qemu-system.*${AVD_NAME}" >/dev/null 2>&1
}

start_emulator() {
  if qemu_running; then
    return 0
  fi
  log "starting ${AVD_NAME} (gpu=${EMULATOR_GPU}, window=$([[ "${EMULATOR_SHOW_WINDOW}" == "1" ]] && echo on || echo off), log=${EMULATOR_LOG})"
  local -a emu_args=(-avd "${AVD_NAME}" -writable-system -no-boot-anim -no-audio \
    -no-snapshot-load -no-snapshot-save -gpu "${EMULATOR_GPU}")
  if [[ "${EMULATOR_SHOW_WINDOW}" != "1" ]]; then
    emu_args+=(-no-window)
  fi
  nohup emulator "${emu_args[@]}" \
    >>"${EMULATOR_LOG}" 2>&1 &
  echo $! >"${EMU_PID_FILE}"
  local i
  for i in $(seq 1 "${BOOT_TIMEOUT_SEC}"); do
    if booted; then
      log "boot completed (${i}s)"
      return 0
    fi
    sleep 1
  done
  log "boot timed out after ${BOOT_TIMEOUT_SEC}s"
  return 1
}

ensure_root_frida() {
  booted || return 1
  "${ADB[@]}" root >/dev/null 2>&1 || true
  sleep 3
  "${ADB[@]}" wait-for-device >/dev/null 2>&1 || true
  "${ADB[@]}" remount >/dev/null 2>&1 || true
  local pid owner
  pid="$("${ADB[@]}" shell pidof frida-server 2>/dev/null | tr -d '\r' | awk '{print $1}')"
  if [[ -n "${pid}" ]]; then
    owner="$("${ADB[@]}" shell ps -o USER= -p "${pid}" 2>/dev/null | tr -d '\r')"
    [[ "${owner}" == "root" ]] && return 0
    "${ADB[@]}" shell "pkill -9 frida-server" >/dev/null 2>&1 || true
    sleep 1
  fi
  if [[ "$("${ADB[@]}" shell id -u 2>/dev/null | tr -d '\r')" == "0" ]]; then
    "${ADB[@]}" shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &" >/dev/null 2>&1 || true
  else
    "${ADB[@]}" shell "su 0 sh -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &'" >/dev/null 2>&1 || true
  fi
  sleep 2
  pid="$("${ADB[@]}" shell pidof frida-server 2>/dev/null | tr -d '\r' | awk '{print $1}')"
  [[ -n "${pid}" ]] || return 1
  owner="$("${ADB[@]}" shell ps -o USER= -p "${pid}" 2>/dev/null | tr -d '\r')"
  [[ "${owner}" == "root" ]]
}

daemon_loop() {
  echo $$ >"${PID_FILE}"
  trap 'rm -f "${PID_FILE}"; exit 0' INT TERM EXIT
  log "daemon pid=$$ serial=${ANDROID_SERIAL}"
  while true; do
    if ! qemu_running; then
      log "qemu not running; restarting"
      start_emulator || true
    elif ! booted; then
      log "qemu up but not booted; waiting"
      local i
      for i in $(seq 1 60); do
        booted && break
        sleep 2
      done
    fi
    if booted; then
      ensure_root_frida || log "frida-server not root yet; will retry"
    fi
    sleep "${INTERVAL}"
  done
}

if [[ "${1:-}" == "--detach" ]]; then
  if [[ -f "${PID_FILE}" ]]; then
    old="$(cat "${PID_FILE}" 2>/dev/null || true)"
    if [[ -n "${old}" ]] && kill -0 "${old}" 2>/dev/null; then
      log "already running pid=${old}"
      exit 0
    fi
  fi
  nohup bash "${SCRIPT_DIR}/run_emulator_daemon.sh" >>"${REPO}/logs/bulk_llm_dataset/emulator_daemon.log" 2>&1 &
  disown -h $! 2>/dev/null || true
  log "detached pid=$!"
  exit 0
fi

daemon_loop
