#!/usr/bin/env bash
# Controlled experiment: bulk_llm_benign_v6 settings with ONE change:
#   CONTEXTDROID_LLM_EXECUTE_ENGINE_ONLY=0
#
# Runs only APKs listed in experiment/engineoff_test_manifest.txt
# Logs: logs/exp_engineoff_v6/ (does not touch bulk_llm_benign_v6)

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION="${1:-600}"
LOG_DIR="${BASE_DIR}/logs/exp_engineoff_v6"
MANIFEST="${BASE_DIR}/experiment/engineoff_test_manifest.txt"
APK_ROOT="${BASE_DIR}/data/apks/benign"

export CONTEXTDROID_RUN_LOG_DIR="${LOG_DIR}"
export DATASET_INDEX_CSV="${LOG_DIR}/dataset_index.csv"
export EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW:-0}"
export BULK_EMULATOR_WATCHDOG="${BULK_EMULATOR_WATCHDOG:-1}"
export CONTEXTDROID_ISOLATE_EMULATOR="${CONTEXTDROID_ISOLATE_EMULATOR:-1}"
export CONTEXTDROID_STRICT_FOREGROUND="${CONTEXTDROID_STRICT_FOREGROUND:-1}"
export CONTEXTDROID_FOREGROUND_MISMATCH_LIMIT="${CONTEXTDROID_FOREGROUND_MISMATCH_LIMIT:-3}"
export CONTEXTDROID_SKIP_SNAPSHOT_LOAD="${CONTEXTDROID_SKIP_SNAPSHOT_LOAD:-1}"
export FRIDA_EVENTS_STALE_SEC="${FRIDA_EVENTS_STALE_SEC:-30}"
export FRIDA_ATTACH_GRACE_SEC="${FRIDA_ATTACH_GRACE_SEC:-30}"
export FRIDA_POST_HOOK_SILENCE_SEC="${FRIDA_POST_HOOK_SILENCE_SEC:-20}"
export FRIDA_HEALTHCHECK_INTERVAL_SEC="${FRIDA_HEALTHCHECK_INTERVAL_SEC:-8}"
export FRIDA_CLI_TIMEOUT="${FRIDA_CLI_TIMEOUT:-inf}"
export FRIDA_USE_DOCKER="${FRIDA_USE_DOCKER:-0}"
export CONTEXTDROID_ROOT_CAPTURE_DEADLINE_SEC="${CONTEXTDROID_ROOT_CAPTURE_DEADLINE_SEC:-30}"
export CONTEXTDROID_PRE_SETUP_MAX_SEC="${CONTEXTDROID_PRE_SETUP_MAX_SEC:-120}"
export CONTEXTDROID_LLM_UI_DUMP_TIMEOUT_SEC="${CONTEXTDROID_LLM_UI_DUMP_TIMEOUT_SEC:-15}"
export BULK_EMULATOR_REBOOT_EVERY_N="${BULK_EMULATOR_REBOOT_EVERY_N:-5}"
# SINGLE VARIABLE CHANGE (v6 default is 1):
export CONTEXTDROID_LLM_EXECUTE_ENGINE_ONLY="${CONTEXTDROID_LLM_EXECUTE_ENGINE_ONLY:-0}"

export OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2}"
export OLLAMA_ENDPOINT="${OLLAMA_ENDPOINT:-http://127.0.0.1:11434}"
export CONTEXTDROID_LLM_EXPLORE_RATIO="${CONTEXTDROID_LLM_EXPLORE_RATIO:-0.30}"

mkdir -p "${LOG_DIR}/state"

if [[ ! -f "${MANIFEST}" ]]; then
  echo "Missing manifest: ${MANIFEST} — run: python3 extraction_pipeline/experiment_engineoff.py baseline" >&2
  exit 1
fi

# Proof of effective env (first app only)
echo "=== exp_engineoff_v6 effective env (single-variable check) ==="
env | grep -E '^(CONTEXTDROID_LLM_EXECUTE_ENGINE_ONLY|OLLAMA_MODEL|OLLAMA_ENDPOINT|CONTEXTDROID_LLM_EXPLORE_RATIO|CONTEXTDROID_RUN_LOG_DIR)=' | sort
echo "DURATION=${DURATION}"
echo "MANIFEST=${MANIFEST} ($(wc -l <"${MANIFEST}" | tr -d ' ') APKs)"
echo "=============================================================="

exec bash "${BASE_DIR}/extraction_pipeline/run_bulk_llm_manifest_resumable.sh" \
  "${MANIFEST}" \
  "${DURATION}"
