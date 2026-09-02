#!/usr/bin/env bash
# Full benign v2 reference corpus collection (Step 9) — DO NOT run until preflight passes.

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION="${1:-420}"
APK_ROOT="${BASE_DIR}/data/apks/benign"
LOG_DIR="${BASE_DIR}/logs/bulk_llm_benign_v2"

# shellcheck source=collection_v2.env
source "${BASE_DIR}/extraction_pipeline/collection_v2.env"
export CONTEXTDROID_RUN_LOG_DIR="${LOG_DIR}"
export DATASET_INDEX_CSV="${LOG_DIR}/dataset_index.csv"
export AVD_NAME="${AVD_NAME:-abrg_benign}"
export EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW:-0}"

mkdir -p "${LOG_DIR}/state"

exec bash "${BASE_DIR}/extraction_pipeline/run_bulk_llm_dataset_resumable.sh" \
  "${APK_ROOT}" \
  "${DURATION}"
