#!/usr/bin/env bash
# Run LLM audit session while streaming *_llm_step_audit.jsonl as lines appear.
#
# Usage (repo root):
#   SESSIONS_PER_APP=1 CONTEXTDROID_LLM_GOAL_PLAN=1 \
#     bash extraction_pipeline/run_llm_audit_session_live.sh /path/to/App.apk [duration_sec]
#
# Env: same as run_llm_audit_session.sh / run_llm_best_effort_one_app.sh

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <apk_or_folder_with_one_apk> [duration_seconds]" >&2
  exit 1
fi

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${BASE_DIR}"

export CONTEXTDROID_LLM_AUDIT_SESSION=1
export CONTEXTDROID_LLM_STEP_DEBUG="${CONTEXTDROID_LLM_STEP_DEBUG:-1}"

SESSION_NUM="${AUDIT_SESSION_NUM:-1}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if [[ -x "${BASE_DIR}/.venv/bin/python" ]]; then
  PYTHON_BIN="${BASE_DIR}/.venv/bin/python"
fi

# Only tail audit files touched after this instant (avoid stale logs from older runs).
export CONTEXTDROID_AUDIT_LIVE_SINCE="$("${PYTHON_BIN}" -c 'import time; print(time.time())')"

_audit_newest_mtime() {
  "${PYTHON_BIN}" - <<'PY'
import os
import pathlib

logs = pathlib.Path("logs")
try:
    start_ts = float(os.environ.get("CONTEXTDROID_AUDIT_LIVE_SINCE", "0")) - 2.0
except ValueError:
    start_ts = 0.0

best = None
mt = -1.0
try:
    for p in logs.rglob("*_llm_step_audit.jsonl"):
        try:
            m = p.stat().st_mtime
            if m < start_ts:
                continue
            if m > mt:
                mt, best = m, p
        except OSError:
            pass
except (OSError, RuntimeError):
    pass
print(best.resolve() if best else "", end="")
PY
}

AUDIT_TAIL_PID=""
cleanup() {
  if [[ -n "${AUDIT_TAIL_PID}" ]] && kill -0 "${AUDIT_TAIL_PID}" 2>/dev/null; then
    kill "${AUDIT_TAIL_PID}" 2>/dev/null || true
    wait "${AUDIT_TAIL_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "[live-audit] Watching logs/**/*_llm_step_audit.jsonl (newest by mtime); main run logs below." >&2
echo "[live-audit] Hint: SESSIONS_PER_APP=1 speeds iteration." >&2

(
  tracked=""
  while true; do
    cur="$(_audit_newest_mtime)"
    if [[ -n "${cur}" && "${cur}" != "${tracked}" ]]; then
      tracked="${cur}"
      echo "" >&2
      echo "[live-audit] ===== tail -f ${tracked} =====" >&2
      tail -n 3 -f "${tracked}" >&2
      exit 0
    fi
    sleep 1
  done
) &
AUDIT_TAIL_PID=$!

set +e
bash "${BASE_DIR}/extraction_pipeline/run_llm_best_effort_one_app.sh" "$@"
RUN_EXIT=$?
set -e

cleanup
trap - EXIT

AUDIT="$(find "${BASE_DIR}/logs" -path "*/dynamic/llm/session_${SESSION_NUM}/*_llm_step_audit.jsonl" 2>/dev/null | head -n 1 || true)"
echo "" >&2
echo "[live-audit] run_llm_best_effort_one_app exit=${RUN_EXIT}" >&2
if [[ -z "${AUDIT}" ]]; then
  echo "[live-audit] No *_llm_step_audit.jsonl for session_${SESSION_NUM}; see logs/ tree." >&2
  exit "${RUN_EXIT}"
fi

echo "[live-audit] report: ${AUDIT}" >&2
"${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/report_llm_audit.py" "${AUDIT}"
exit "${RUN_EXIT}"
