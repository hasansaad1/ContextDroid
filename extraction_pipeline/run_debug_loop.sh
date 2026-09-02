#!/usr/bin/env bash
# Run N x 7-min F-Droid LLM audits and record per-iteration summaries.
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${BASE_DIR}"

ITERATIONS="${1:-10}"
DURATION="${2:-420}"
export ANDROID_SERIAL="${ANDROID_SERIAL:-emulator-5554}"
export PATH="${BASE_DIR}/tools/platform-tools:${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}/platform-tools:${PATH}"
export SESSIONS_PER_APP=1

RESULTS="${BASE_DIR}/logs/debug_loop_10/results.jsonl"
mkdir -p "${BASE_DIR}/logs/debug_loop_10"

# Ensure frida-server (non-blocking)
adb -s "${ANDROID_SERIAL}" shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &" || true
sleep 1

PYTHON_BIN="${BASE_DIR}/.venv/bin/python"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="$(command -v python3)"
fi

for i in $(seq 1 "${ITERATIONS}"); do
  echo "[loop] === iteration ${i}/${ITERATIONS} ==="
  LOG="${BASE_DIR}/logs/debug_loop_10/iter_${i}_$(date +%Y%m%d_%H%M%S).log"
  if ! bash extraction_pipeline/run_llm_audit_session.sh tools/pilot/F-Droid.apk "${DURATION}" >"${LOG}" 2>&1; then
    rc=$?
    echo "[loop] iteration ${i} exit_code=${rc}" | tee -a "${LOG}"
  fi
  SUMMARY="$("${PYTHON_BIN}" extraction_pipeline/analyze_run_iteration.py "${BASE_DIR}")"
  echo "${SUMMARY}" | "${PYTHON_BIN}" -c "
import json,sys
row=json.load(sys.stdin)
row['iteration']=${i}
row['log']='${LOG}'
print(json.dumps(row))
" >>"${RESULTS}"
  echo "[loop] iteration ${i} summary:"
  echo "${SUMMARY}"
done

echo "[loop] complete: ${RESULTS}"
