#!/usr/bin/env bash
set -euo pipefail

ANDROID_API_LEVEL="${ANDROID_API_LEVEL:-29}"
AVD_NAME="${AVD_NAME:-abrg_benign}"
AVD_DEVICE="${AVD_DEVICE:-pixel_2}"
TARGET_ABI="${TARGET_ABI:-}"
VENV_DIR="${VENV_DIR:-.venv}"

log() { printf '[install] %s\n' "$1"; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

detect_host_abi() {
  local host_os host_arch
  host_os="$(uname -s)"
  host_arch="$(uname -m)"

  case "${host_arch}" in
    arm64|aarch64)
      echo "arm64-v8a"
      ;;
    x86_64|amd64)
      echo "x86_64"
      ;;
    *)
      # Conservative fallback for unknown hosts.
      echo "x86_64"
      ;;
  esac
}

if [[ -z "${ANDROID_SDK_ROOT:-}" ]]; then
  if [[ -d "${HOME}/Library/Android/sdk" ]]; then
    export ANDROID_SDK_ROOT="${HOME}/Library/Android/sdk"
  elif [[ -d "${HOME}/Android/Sdk" ]]; then
    export ANDROID_SDK_ROOT="${HOME}/Android/Sdk"
  fi
fi

if [[ -z "${ANDROID_SDK_ROOT:-}" ]]; then
  log "ANDROID_SDK_ROOT is not set and SDK was not auto-detected."
  exit 1
fi

export PATH="${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/emulator:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${PATH}"

for cmd in python3 adb emulator sdkmanager avdmanager; do
  if ! have_cmd "${cmd}"; then
    log "Missing required command: ${cmd}"
    exit 1
  fi
done

if [[ -z "${TARGET_ABI}" ]]; then
  TARGET_ABI="$(detect_host_abi)"
  log "Auto-selected TARGET_ABI=${TARGET_ABI} from host architecture ($(uname -m))."
else
  log "Using user-provided TARGET_ABI=${TARGET_ABI}."
fi

python3 -m venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

yes | sdkmanager --licenses >/dev/null || true
IMAGE="system-images;android-${ANDROID_API_LEVEL};google_apis;${TARGET_ABI}"
log "Installing emulator image: ${IMAGE}"
sdkmanager "platform-tools" "emulator" "${IMAGE}"

if ! avdmanager list avd | grep -q "Name: ${AVD_NAME}$"; then
  printf "no\n" | avdmanager create avd -n "${AVD_NAME}" -k "${IMAGE}" -d "${AVD_DEVICE}"
fi

log "Setup completed."
