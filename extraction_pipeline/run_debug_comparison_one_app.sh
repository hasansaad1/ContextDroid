#!/usr/bin/env bash
# Single-app comparison debug run: LLM + Monkey, 3 sessions per arm (6 runs total).
#
# Usage (from repo root):
#   bash extraction_pipeline/run_debug_comparison_one_app.sh /path/to/App.apk [duration_sec]
#   bash extraction_pipeline/run_debug_comparison_one_app.sh /path/to/folder_with_one_apk [duration_sec]
#
# Environment (optional):
#   OLLAMA_MODEL, OLLAMA_ENDPOINT, ANDROID_SERIAL, MONKEY_SEED
#   Relaxed quality gate for debugging (defaults below):
#   DEBUG_MIN_VALID_EVENTS (default 1), DEBUG_MIN_CATEGORY_COUNT (default 1)
#
# Ensure Ollama is up: ollama serve && ollama pull "${OLLAMA_MODEL:-llama3.2}"

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <path_to_one.apk_or_folder> [duration_seconds]" >&2
  exit 1
fi

SRC="$1"
DURATION="${2:-180}"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGING="${DEBUG_COMPARISON_STAGING_DIR:-${BASE_DIR}/logs/debug_comparison_one_app}"
PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
  if [[ -x "${BASE_DIR}/.venv/bin/python" ]]; then
    PYTHON_BIN="${BASE_DIR}/.venv/bin/python"
  else
    PYTHON_BIN="$(command -v python3)"
  fi
fi

rm -rf "${STAGING}"
mkdir -p "${STAGING}"

if [[ -f "${SRC}" ]]; then
  cp "${SRC}" "${STAGING}/"
elif [[ -d "${SRC}" ]]; then
  shopt -s nullglob
  found=( "${SRC}"/*.apk )
  shopt -u nullglob
  if [[ ${#found[@]} -ne 1 ]]; then
    echo "Directory must contain exactly one .apk file; found ${#found[@]}: ${SRC}" >&2
    exit 1
  fi
  cp "${found[0]}" "${STAGING}/"
else
  echo "Not a file or directory: ${SRC}" >&2
  exit 1
fi

export ENABLE_COMPARISON=1
export RUN_MODE=llm_plus_monkey
export SESSIONS_PER_APP=3
export MIN_VALID_EVENTS="${DEBUG_MIN_VALID_EVENTS:-1}"
export MIN_CATEGORY_COUNT="${DEBUG_MIN_CATEGORY_COUNT:-1}"

echo "[debug-comparison] staging=${STAGING}"
echo "[debug-comparison] duration=${DURATION}s  sessions/arm=3  MIN_VALID_EVENTS=${MIN_VALID_EVENTS} MIN_CATEGORY_COUNT=${MIN_CATEGORY_COUNT}"
echo "[debug-comparison] OLLAMA_ENDPOINT=${OLLAMA_ENDPOINT:-http://127.0.0.1:11434} OLLAMA_MODEL=${OLLAMA_MODEL:-llama3.2}"

exec bash "${BASE_DIR}/extraction_pipeline/run_dynamic_dataset.sh" "${STAGING}" "${DURATION}"
