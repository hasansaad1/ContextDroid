#!/usr/bin/env bash
# Ensure Android emulator is online, booted, rooted, and frida-server is running.
#
# Environment:
#   ANDROID_SERIAL      default emulator-5554
#   AVD_NAME            default abrg_benign (renamed from malware_sandbox)
#   ANDROID_SDK_ROOT    auto-detected on macOS/Linux
#   SKIP_EMULATOR_AUTO_START  set to 1 to only check (no start)
#   EMULATOR_LOG        default /tmp/${AVD_NAME}_emulator.log
#
# Exit 0 when emulator is ready; non-zero on failure.

set -euo pipefail

AVD_NAME="${AVD_NAME:-abrg_benign}"
EMULATOR_SERIAL="${ANDROID_SERIAL:-emulator-5554}"
EMULATOR_LOG="${EMULATOR_LOG:-/tmp/${AVD_NAME}_emulator.log}"
BOOT_TIMEOUT_SEC="${EMULATOR_BOOT_TIMEOUT_SEC:-180}"
LOCK_FILE="${EMULATOR_LOCK_FILE:-/tmp/contextdroid_ensure_emulator.lock}"
ADB_TIMEOUT_SEC="${ADB_TIMEOUT_SEC:-20}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVICE_GUARD_SH="${ROOT_DIR}/scripts/safety/device_guard.sh"
# Stable headless-ish defaults: avoid broken default_boot snapshot (GLES renderer drift) and gfxstream save crashes.
EMULATOR_GPU="${EMULATOR_GPU:-swiftshader_indirect}"
EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW:-1}"
EMULATOR_NO_SNAPSHOT_LOAD="${EMULATOR_NO_SNAPSHOT_LOAD:-1}"
EMULATOR_SAVE_SNAPSHOT="${EMULATOR_SAVE_SNAPSHOT:-0}"

if [[ -z "${ANDROID_SDK_ROOT:-}" ]]; then
  if [[ -d "${HOME}/Library/Android/sdk" ]]; then
    export ANDROID_SDK_ROOT="${HOME}/Library/Android/sdk"
  elif [[ -d "${HOME}/Android/Sdk" ]]; then
    export ANDROID_SDK_ROOT="${HOME}/Android/Sdk"
  fi
fi

if [[ -n "${ANDROID_SDK_ROOT:-}" ]]; then
  export PATH="${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/emulator:${PATH}"
fi

ADB_BIN="${ADB_BIN:-}"
if [[ -z "${ADB_BIN}" ]]; then
  if command -v adb >/dev/null 2>&1; then
    ADB_BIN="$(command -v adb)"
  elif [[ -n "${ANDROID_SDK_ROOT:-}" && -x "${ANDROID_SDK_ROOT}/platform-tools/adb" ]]; then
    ADB_BIN="${ANDROID_SDK_ROOT}/platform-tools/adb"
  else
    echo "[emulator-ensure] adb not found" >&2
    exit 1
  fi
fi

log() { printf '[emulator-ensure] %s\n' "$1" >&2; }

adb_serial() {
  "${ADB_BIN}" -s "${EMULATOR_SERIAL}" "$@"
}

adb_with_timeout() {
  if command -v gtimeout >/dev/null 2>&1; then
    gtimeout "${ADB_TIMEOUT_SEC}" adb_serial "$@"
  elif command -v timeout >/dev/null 2>&1; then
    timeout "${ADB_TIMEOUT_SEC}" adb_serial "$@"
  else
    adb_serial "$@"
  fi
}

emulator_booted() {
  local state boot
  state="$(adb_serial get-state 2>/dev/null | tr -d '\r' || true)"
  [[ "${state}" == "device" ]] || return 1
  boot="$(adb_serial shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
  [[ "${boot}" == "1" ]]
}

frida_server_running() {
  adb_serial shell pidof frida-server >/dev/null 2>&1
}

qemu_running() {
  pgrep -f "qemu-system.*${AVD_NAME}" >/dev/null 2>&1
}

analysis_active() {
  pgrep -f "analyze_apk\\.py" >/dev/null 2>&1
}

wait_for_boot() {
  local i
  for i in $(seq 1 "${BOOT_TIMEOUT_SEC}"); do
    if emulator_booted; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_reconnect() {
  local i
  for i in $(seq 1 90); do
    if emulator_booted; then
      return 0
    fi
    sleep 2
  done
  return 1
}

frida_server_is_root() {
  local pid owner
  pid="$(adb_serial shell pidof frida-server 2>/dev/null | tr -d '\r' | awk '{print $1}')"
  [[ -n "${pid}" ]] || return 1
  owner="$(adb_serial shell ps -o USER= -p "${pid}" 2>/dev/null | tr -d '\r')"
  [[ "${owner}" == "root" ]]
}

ensure_frida_server() {
  adb_with_timeout root >/dev/null 2>&1 || true
  adb_with_timeout wait-for-device >/dev/null 2>&1 || true
  if frida_server_running && frida_server_is_root; then
    return 0
  fi
  if frida_server_running; then
    log "frida-server not root-owned; restarting"
    adb_serial shell "pkill -9 frida-server" >/dev/null 2>&1 || true
    sleep 1
  fi
  if adb_serial shell "test -x /data/local/tmp/frida-server" 2>/dev/null; then
    if [[ "$("${ADB_BIN}" -s "${EMULATOR_SERIAL}" shell id -u 2>/dev/null | tr -d '\r')" == "0" ]]; then
      adb_serial shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &" >/dev/null 2>&1 || true
    else
      adb_serial shell "su 0 sh -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &'" >/dev/null 2>&1 || true
    fi
    sleep 2
    frida_server_running && frida_server_is_root
    return $?
  fi
  log "warn: /data/local/tmp/frida-server missing on device"
  return 0
}

full_post_boot_setup() {
  adb_with_timeout root >/dev/null 2>&1 || true
  adb_with_timeout wait-for-device >/dev/null 2>&1 || true
  sleep 2
  adb_with_timeout remount >/dev/null 2>&1 || true
  ensure_frida_server || true
  if [[ "${EMULATOR_SAVE_SNAPSHOT}" == "1" ]] && emulator_booted; then
    adb_serial emu avd snapshot save default_boot >/dev/null 2>&1 || true
  fi
}

light_ready() {
  if ! emulator_booted; then
    return 1
  fi
  adb_with_timeout root >/dev/null 2>&1 || true
  adb_with_timeout wait-for-device >/dev/null 2>&1 || true
  ensure_frida_server || true
  return 0
}

start_emulator() {
  if [[ -x "${DEVICE_GUARD_SH}" ]]; then
    # Hard seam before emulator launch: if any device is attached, it must match expected identity.
    ADB_BIN="${ADB_BIN}" AVD_NAME="${AVD_NAME}" ANDROID_SERIAL="${EMULATOR_SERIAL}" \
      bash "${DEVICE_GUARD_SH}" hard-prelaunch >/dev/null
  fi
  if ! command -v emulator >/dev/null 2>&1; then
    log "emulator binary not found (set ANDROID_SDK_ROOT)"
    return 1
  fi
  if qemu_running; then
    log "qemu for ${AVD_NAME} already running; waiting for boot"
    wait_for_boot
    return $?
  fi
  log "starting AVD ${AVD_NAME} (log: ${EMULATOR_LOG}, gpu=${EMULATOR_GPU})"
  local -a emu_args=(-avd "${AVD_NAME}" -writable-system -no-boot-anim -no-audio -gpu "${EMULATOR_GPU}" -no-snapshot-load -no-snapshot-save)
  if [[ "${EMULATOR_SHOW_WINDOW}" != "1" ]]; then
    emu_args+=(-no-window)
  fi
  if [[ "${EMULATOR_NO_SNAPSHOT_LOAD}" != "1" ]]; then
    emu_args=(-avd "${AVD_NAME}" -writable-system -no-boot-anim -no-audio -gpu "${EMULATOR_GPU}" -no-snapshot-save)
    if [[ "${EMULATOR_SHOW_WINDOW}" != "1" ]]; then
      emu_args+=(-no-window)
    fi
  fi
  nohup emulator "${emu_args[@]}" >>"${EMULATOR_LOG}" 2>&1 &
  wait_for_boot
}

with_lock() {
  local i=0
  while ! mkdir "${LOCK_FILE}.d" 2>/dev/null; do
    i=$((i + 1))
    if [[ ${i} -ge 120 ]]; then
      log "could not acquire emulator lock (${LOCK_FILE}.d)"
      return 1
    fi
    sleep 1
  done
  trap 'rmdir "${LOCK_FILE}.d" 2>/dev/null || true' RETURN
  "$@"
}

if light_ready; then
  log "ready ${EMULATOR_SERIAL}"
  exit 0
fi

if qemu_running; then
  log "qemu present but not ready; waiting for boot"
  if wait_for_boot; then
    full_post_boot_setup
    log "ready ${EMULATOR_SERIAL}"
    exit 0
  fi
  log "qemu running but boot timed out (see ${EMULATOR_LOG})"
  exit 1
fi

if [[ "${SKIP_EMULATOR_AUTO_START:-0}" == "1" ]]; then
  log "${EMULATOR_SERIAL} not booted and SKIP_EMULATOR_AUTO_START=1"
  exit 1
fi

if analysis_active; then
  log "analyze_apk active; waiting for ${EMULATOR_SERIAL} to reconnect"
  if wait_for_reconnect; then
    light_ready || full_post_boot_setup
    log "ready ${EMULATOR_SERIAL}"
    exit 0
  fi
  log "analyze_apk active but device did not reconnect in time"
fi

with_lock start_emulator
full_post_boot_setup

if ! emulator_booted; then
  log "emulator failed to boot (see ${EMULATOR_LOG})"
  exit 1
fi

log "ready ${EMULATOR_SERIAL}"
exit 0
