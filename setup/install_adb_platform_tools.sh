#!/usr/bin/env bash
# Install Android SDK platform-tools (adb, fastboot, etc.) without the full SDK.
# Default install dir: <repo>/tools/platform-tools/
# Override: CONTEXTDROID_PLATFORM_TOOLS_PARENT=/path/to/parent (extracts platform-tools under it)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT="${CONTEXTDROID_PLATFORM_TOOLS_PARENT:-${ROOT}/tools}"

log() { printf '[adb-setup] %s\n' "$1"; }

detect_zip_url() {
  local os_kind arch
  os_kind="$(uname -s)"
  arch="$(uname -m)"
  case "${os_kind}" in
    Darwin)
      echo "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip"
      ;;
    Linux)
      echo "https://dl.google.com/android/repository/platform-tools-latest-linux.zip"
      ;;
    *)
      log "Unsupported OS: ${os_kind}"
      exit 1
      ;;
  esac
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

for cmd in curl unzip; do
  if ! have_cmd "${cmd}"; then
    log "Missing required command: ${cmd}"
    exit 1
  fi
done

mkdir -p "${PARENT}"
ZIP_URL="$(detect_zip_url)"
ZIP_TMP="$(mktemp -t platform-tools.XXXXXX.zip)"

cleanup() { rm -f "${ZIP_TMP}"; }
trap cleanup EXIT

log "Downloading platform-tools from ${ZIP_URL}"
curl -fsSL -o "${ZIP_TMP}" "${ZIP_URL}"

log "Extracting into ${PARENT}"
rm -rf "${PARENT}/platform-tools"
unzip -q -o "${ZIP_TMP}" -d "${PARENT}"

ADB_BIN="${PARENT}/platform-tools/adb"
if [[ ! -x "${ADB_BIN}" ]]; then
  chmod +x "${ADB_BIN}" || true
fi

if [[ ! -x "${ADB_BIN}" ]]; then
  log "adb not executable at ${ADB_BIN}"
  exit 1
fi

log "Installed: ${ADB_BIN}"
"${ADB_BIN}" version
