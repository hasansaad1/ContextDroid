#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ANDROID_SERIAL="${ANDROID_SERIAL:-emulator-5554}"
export SESSIONS_PER_APP=1
export PATH="${BASE_DIR}/tools/platform-tools:${PATH}"

DURATION="${1:-420}"
LOG_DIR="${BASE_DIR}/logs/pilot_regression"
mkdir -p "${LOG_DIR}"

run_one() {
  local label="$1"
  local apk="$2"
  local log="${LOG_DIR}/${label}_post_fix.log"
  echo "[regression] START ${label} (${DURATION}s) -> ${log}"
  if bash "${BASE_DIR}/extraction_pipeline/run_llm_audit_session.sh" "${apk}" "${DURATION}" >"${log}" 2>&1; then
    echo "[regression] PASS ${label}"
  else
    echo "[regression] FAIL ${label} (see ${log})"
  fi
}

run_one "app.michaelwuensch.bitbanana" "${BASE_DIR}/data/apks/benign/app.michaelwuensch.bitbanana_78.apk"
run_one "com.aefyr.sai.fdroid" "${BASE_DIR}/data/apks/benign/com.aefyr.sai.fdroid_60.apk"
echo "[regression] DONE"
