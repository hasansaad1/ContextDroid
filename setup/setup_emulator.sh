#!/usr/bin/env bash
set -euo pipefail

AVD_NAME="${AVD_NAME:-abrg_benign}"
EMULATOR_LOG="${EMULATOR_LOG:-/tmp/${AVD_NAME}_emulator.log}"
ADB_BIN="${ADB_BIN:-}"
EMULATOR_SERIAL="${EMULATOR_SERIAL:-emulator-5554}"

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

if [[ -z "${ADB_BIN}" ]]; then
  if command -v adb >/dev/null 2>&1; then
    ADB_BIN="$(command -v adb)"
  elif [[ -n "${ANDROID_SDK_ROOT:-}" && -x "${ANDROID_SDK_ROOT}/platform-tools/adb" ]]; then
    ADB_BIN="${ANDROID_SDK_ROOT}/platform-tools/adb"
  else
    echo "[error] adb not found. Set ANDROID_SDK_ROOT or ADB_BIN."
    exit 1
  fi
fi

echo "[emulator] starting ${AVD_NAME}"
emulator -avd "${AVD_NAME}" -writable-system -no-snapshot -no-boot-anim >"${EMULATOR_LOG}" 2>&1 &

echo "[emulator] waiting for ${EMULATOR_SERIAL}"
"${ADB_BIN}" -s "${EMULATOR_SERIAL}" wait-for-device

boot_done=""
for _ in $(seq 1 120); do
  boot_done="$("${ADB_BIN}" -s "${EMULATOR_SERIAL}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
  if [[ "${boot_done}" == "1" ]]; then
    break
  fi
  sleep 1
done

if [[ "${boot_done}" != "1" ]]; then
  echo "[error] emulator did not reach boot_completed=1 (see ${EMULATOR_LOG})"
  exit 1
fi

"${ADB_BIN}" -s "${EMULATOR_SERIAL}" root || true
"${ADB_BIN}" -s "${EMULATOR_SERIAL}" wait-for-device
"${ADB_BIN}" -s "${EMULATOR_SERIAL}" remount || true

device_abi="$("${ADB_BIN}" -s "${EMULATOR_SERIAL}" shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r' || true)"
if [[ -n "${device_abi}" ]]; then
  echo "[emulator] device ABI: ${device_abi}"
fi

state="$("${ADB_BIN}" -s "${EMULATOR_SERIAL}" get-state 2>/dev/null | tr -d '\r' || true)"
if [[ "${state}" != "device" ]]; then
  echo "[error] emulator state is '${state:-unknown}' (expected 'device')."
  exit 1
fi

if "${ADB_BIN}" -s "${EMULATOR_SERIAL}" shell "test -x /data/local/tmp/frida-server"; then
  "${ADB_BIN}" -s "${EMULATOR_SERIAL}" shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 </dev/null &"
  echo "[emulator] frida-server started (requires adb root above)"
  echo "[emulator] ensure frida-server binary matches device ABI (${device_abi:-unknown})"
else
  echo "[warn] /data/local/tmp/frida-server not found; push it before running analysis"
fi

echo "[emulator] ready"
