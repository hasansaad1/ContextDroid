#!/usr/bin/env bash
# Fair single-app comparison: one LLM session + one monkey session (same duration each).
# Default duration is 600s (10 minutes per arm → ~20+ minutes wall clock plus setup).
#
# Usage (from repo root):
#   bash extraction_pipeline/run_llm_vs_monkey_compare_one_app.sh /path/to/App.apk [duration_seconds_per_arm]
#
# Environment (optional):
#   CONTEXTDROID_* LLM knobs, ANDROID_SERIAL, MONKEY_SEED, OLLAMA_MODEL, OLLAMA_ENDPOINT
#   MIN_VALID_EVENTS, MIN_CATEGORY_COUNT (passed through to run_dynamic_dataset.sh)
#
# Outputs under logs/llm_vs_monkey_<apk_slug>_<timestamp>/ :
#   dataset_index.csv, run artifacts, comparison_metrics/, final_comparison_report.md

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <path_to_one.apk_or_folder> [duration_seconds_per_arm]" >&2
  exit 1
fi

SRC="$1"
DURATION_PER_ARM="${2:-600}"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
  if [[ -x "${BASE_DIR}/.venv/bin/python" ]]; then
    PYTHON_BIN="${BASE_DIR}/.venv/bin/python"
  else
    PYTHON_BIN="$(command -v python3)"
  fi
fi

STAGING="${LLM_VS_MONKEY_STAGING_DIR:-${BASE_DIR}/logs/llm_vs_monkey_staging}"
rm -rf "${STAGING}"
mkdir -p "${STAGING}"

if [[ -f "${SRC}" ]]; then
  cp "${SRC}" "${STAGING}/"
  apk_basename="$(basename "${SRC}" .apk)"
elif [[ -d "${SRC}" ]]; then
  shopt -s nullglob
  found=( "${SRC}"/*.apk )
  shopt -u nullglob
  if [[ ${#found[@]} -ne 1 ]]; then
    echo "Directory must contain exactly one .apk file; found ${#found[@]}: ${SRC}" >&2
    exit 1
  fi
  cp "${found[0]}" "${STAGING}/"
  apk_basename="$(basename "${found[0]}" .apk)"
else
  echo "Not a file or directory: ${SRC}" >&2
  exit 1
fi

slug="$(echo "${apk_basename}" | tr '/: ' '___' | tr -cd '[:alnum:]_.-' | head -c 48)"
slug="${slug:-app}"
ts="$(date -u '+%Y%m%dT%H%M%SZ')"
RUN_ROOT="${BASE_DIR}/logs/llm_vs_monkey_${slug}_${ts}"
mkdir -p "${RUN_ROOT}"

export CONTEXTDROID_RUN_LOG_DIR="${RUN_ROOT}"
export DATASET_INDEX_CSV="${RUN_ROOT}/dataset_index.csv"
export ENABLE_COMPARISON=1
export RUN_MODE=llm_plus_monkey
export SESSIONS_PER_APP=1

echo "[llm-vs-monkey] run_root=${RUN_ROOT}"
echo "[llm-vs-monkey] staging=${STAGING}"
echo "[llm-vs-monkey] duration_per_arm=${DURATION_PER_ARM}s  sessions_per_arm=1"
echo "[llm-vs-monkey] OLLAMA_ENDPOINT=${OLLAMA_ENDPOINT:-http://127.0.0.1:11434} OLLAMA_MODEL=${OLLAMA_MODEL:-llama3.2}"

bash "${BASE_DIR}/extraction_pipeline/run_dynamic_dataset.sh" "${STAGING}" "${DURATION_PER_ARM}"

METRICS_DIR="${RUN_ROOT}/comparison_metrics"
"${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/compute_comparison_metrics.py" \
  --index "${RUN_ROOT}/dataset_index.csv" \
  --output-dir "${METRICS_DIR}"
"${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/generate_comparison_report.py" \
  --metrics-dir "${METRICS_DIR}" \
  --output "${METRICS_DIR}/final_comparison_report.md"

echo "[llm-vs-monkey] metrics: ${METRICS_DIR}"
echo "[llm-vs-monkey] report: ${METRICS_DIR}/final_comparison_report.md"
