#!/usr/bin/env bash
# Pilot bulk re-run (25 apps) with hardened Frida / foreground / isolation pipeline.
#
# Usage (repo root):
#   bash extraction_pipeline/run_bulk_llm_pilot_v2.sh [duration_sec]
#
# Logs: logs/bulk_llm_pilot_v2/
# APK set: data/apks/pilot_v2/ (symlinks; see state/pilot_manifest.txt)

set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION="${1:-600}"
PILOT_APK_ROOT="${BASE_DIR}/data/apks/pilot_v2"
LOG_DIR="${BASE_DIR}/logs/bulk_llm_pilot_v2"

export CONTEXTDROID_RUN_LOG_DIR="${LOG_DIR}"
export DATASET_INDEX_CSV="${LOG_DIR}/dataset_index.csv"
export AVD_NAME="${AVD_NAME:-abrg_benign}"
export EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW:-0}"
export BULK_EMULATOR_WATCHDOG="${BULK_EMULATOR_WATCHDOG:-1}"
export CONTEXTDROID_ISOLATE_EMULATOR="${CONTEXTDROID_ISOLATE_EMULATOR:-1}"
export CONTEXTDROID_STRICT_FOREGROUND="${CONTEXTDROID_STRICT_FOREGROUND:-1}"
export CONTEXTDROID_FOREGROUND_MISMATCH_LIMIT="${CONTEXTDROID_FOREGROUND_MISMATCH_LIMIT:-3}"
export CONTEXTDROID_SKIP_SNAPSHOT_LOAD="${CONTEXTDROID_SKIP_SNAPSHOT_LOAD:-1}"
export FRIDA_EVENTS_STALE_SEC="${FRIDA_EVENTS_STALE_SEC:-45}"
export FRIDA_ATTACH_GRACE_SEC="${FRIDA_ATTACH_GRACE_SEC:-30}"
export FRIDA_USE_DOCKER="${FRIDA_USE_DOCKER:-0}"
export CONTEXTDROID_ROOT_CAPTURE_DEADLINE_SEC="${CONTEXTDROID_ROOT_CAPTURE_DEADLINE_SEC:-30}"
export CONTEXTDROID_PRE_SETUP_MAX_SEC="${CONTEXTDROID_PRE_SETUP_MAX_SEC:-120}"
export CONTEXTDROID_LLM_UI_DUMP_TIMEOUT_SEC="${CONTEXTDROID_LLM_UI_DUMP_TIMEOUT_SEC:-15}"
export BULK_EMULATOR_REBOOT_EVERY_N="${BULK_EMULATOR_REBOOT_EVERY_N:-5}"

exec bash "${BASE_DIR}/extraction_pipeline/run_bulk_llm_dataset_resumable.sh" \
  "${PILOT_APK_ROOT}" \
  "${DURATION}"
