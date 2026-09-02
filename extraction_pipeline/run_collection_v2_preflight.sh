#!/usr/bin/env bash
# Single-app collection v2 preflight (Step 9 preflight gate) — ch.protonvpn.android only.
# Does NOT start the overnight batch.

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION="${1:-600}"
APK="${APK:-${BASE_DIR}/data/apks/benign/ch.protonvpn.android_605177200.apk}"
LOG_DIR="${PREFLIGHT_LOG_ROOT:-${BASE_DIR}/logs/collection_v2_preflight/protonvpn_fresh3}"
MANIFEST="${LOG_DIR}/preflight_manifest.txt"

# shellcheck source=collection_v2.env
source "${BASE_DIR}/extraction_pipeline/collection_v2.env"
export SESSIONS_PER_APP="${SESSIONS_PER_APP:-3}"
export CONTEXTDROID_RUN_LOG_DIR="${LOG_DIR}"
export DATASET_INDEX_CSV="${LOG_DIR}/dataset_index.csv"
export PREFLIGHT_LOG_ROOT="${LOG_DIR}"
export EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW:-0}"
export APK_ROOT="${BASE_DIR}/data/apks/benign"

mkdir -p "${LOG_DIR}/state"
# Fresh run: no completed APK state from prior preflight attempts.
: >"${LOG_DIR}/state/completed_apks.sha256"
: >"${LOG_DIR}/state/failed_apks.sha256"
rm -f "${LOG_DIR}/state/current.json"
echo "${APK}" >"${MANIFEST}"

echo "[preflight] collection_config=${CONTEXTDROID_COLLECTION_CONFIG}"
echo "[preflight] SESSIONS_PER_APP=${SESSIONS_PER_APP} schedule=${SESSION_MODE_SCHEDULE}"
echo "[preflight] explore_floor=${CONTEXTDROID_LLM_EXPLORE_UNTIL_SEC_FLOOR}s ratio=${CONTEXTDROID_LLM_EXPLORE_RATIO}"
echo "[preflight] FRIDA_USE_DOCKER=${FRIDA_USE_DOCKER} duration=${DURATION}s"
echo "[preflight] log_dir=${LOG_DIR}"

exec bash "${BASE_DIR}/extraction_pipeline/run_bulk_llm_manifest_resumable.sh" \
  "${MANIFEST}" \
  "${DURATION}"
