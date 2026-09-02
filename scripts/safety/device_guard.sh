#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${1:-hard}"
shift || true

ADB_BIN="${ADB_BIN:-adb}"
AVD_NAME="${AVD_NAME:-}"
ANDROID_SERIAL="${ANDROID_SERIAL:-}"
EXPECTED_FP="${CONTEXTDROID_EXPECTED_FINGERPRINT:-}"

case "${MODE}" in
  hard-prelaunch)
    python3 "${ROOT}/extraction_pipeline/safety/device_guard.py" hard \
      --adb-bin "${ADB_BIN}" \
      --expected-avd "${AVD_NAME}" \
      --expected-serial "${ANDROID_SERIAL}" \
      --expected-fingerprint "${EXPECTED_FP}" \
      --allow-no-device "$@"
    ;;
  hard)
    python3 "${ROOT}/extraction_pipeline/safety/device_guard.py" hard \
      --adb-bin "${ADB_BIN}" \
      --expected-avd "${AVD_NAME}" \
      --expected-serial "${ANDROID_SERIAL}" \
      --expected-fingerprint "${EXPECTED_FP}" "$@"
    ;;
  single)
    python3 "${ROOT}/extraction_pipeline/safety/device_guard.py" single \
      --adb-bin "${ADB_BIN}" \
      --expected-serial "${ANDROID_SERIAL}" "$@"
    ;;
  *)
    echo "usage: $0 {hard-prelaunch|hard|single}" >&2
    exit 2
    ;;
esac
