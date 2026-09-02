#!/usr/bin/env bash
# Run 7-minute LLM regression on pilot apps (Pilfer, SAI, BitBanana).
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ANDROID_SERIAL="${ANDROID_SERIAL:-emulator-5554}"
export SESSIONS_PER_APP=1
export PATH="${BASE_DIR}/tools/platform-tools:${PATH}"

DURATION="${1:-420}"
LOG_DIR="${BASE_DIR}/logs/pilot_regression"
mkdir -p "${LOG_DIR}"

APPS=(
  "cityfreqs.com.pilfershushjammer:${BASE_DIR}/data/apks/benign/cityfreqs.com.pilfershushjammer_43.apk"
  "com.aefyr.sai.fdroid:${BASE_DIR}/data/apks/benign/com.aefyr.sai.fdroid_60.apk"
  "app.michaelwuensch.bitbanana:${BASE_DIR}/data/apks/benign/app.michaelwuensch.bitbanana_78.apk"
)

for entry in "${APPS[@]}"; do
  pkg="${entry%%:*}"
  apk="${entry#*:}"
  log="${LOG_DIR}/${pkg}_regression.log"
  echo "[regression] START ${pkg} (${DURATION}s) -> ${log}"
  if bash "${BASE_DIR}/extraction_pipeline/run_llm_audit_session.sh" "${apk}" "${DURATION}" \
    >"${log}" 2>&1; then
    echo "[regression] PASS ${pkg}"
  else
    echo "[regression] FAIL ${pkg} (see ${log})"
  fi
done

echo "[regression] DONE"
