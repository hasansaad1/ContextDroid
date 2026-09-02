#!/usr/bin/env bash
# Run N consecutive LLM-only sessions (same APK) for tuning; each writes to its own output dir + eval JSON.
#
# Usage (repo root):
#   bash extraction_pipeline/run_llm_tune_loop.sh /path/to/App.apk [iterations] [duration_sec]
#
# Env: ANDROID_SERIAL, OLLAMA_MODEL, OLLAMA_ENDPOINT, PYTHON_BIN
# Default: 10 iterations × 300s (50 min LLM time + install overhead each).

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <apk_path> [iterations=10] [duration_sec=300]" >&2
  exit 1
fi

APK="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
ITERS="${2:-10}"
DURATION="${3:-300}"
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ROOT="${BASE_DIR}/logs/llm_tune_loop_$(date -u '+%Y%m%dT%H%M%SZ')"
mkdir -p "${RUN_ROOT}"

PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "${PYTHON_BIN}" ]]; then
  if [[ -x "${BASE_DIR}/.venv/bin/python" ]]; then
    PYTHON_BIN="${BASE_DIR}/.venv/bin/python"
  else
    PYTHON_BIN="$(command -v python3)"
  fi
fi

export TUNE_APK="${APK}"
PKG="$("${PYTHON_BIN}" - <<'PY'
from pathlib import Path
import os, subprocess, shutil, sys

apk = Path(os.environ["TUNE_APK"])
aapt = shutil.which("aapt")
if not aapt:
    for base in (
        Path(os.environ.get("ANDROID_SDK_ROOT", "") or ""),
        Path(os.environ.get("ANDROID_HOME", "") or ""),
        Path.home() / "Library/Android/sdk",
        Path.home() / "Android/Sdk",
    ):
        if not base or not base.is_dir():
            continue
        cands = sorted((base / "build-tools").glob("*/aapt"), key=lambda p: str(p), reverse=True)
        if cands:
            aapt = str(cands[0])
            break
if not aapt:
    sys.exit("no aapt")
out = subprocess.run([aapt, "dump", "badging", str(apk)], capture_output=True, text=True)
for line in (out.stdout or "").splitlines():
    if line.startswith("package: name="):
        print(line.split("'", 2)[1])
        sys.exit(0)
sys.exit("no package")
PY
)"

MASTER="${RUN_ROOT}/master_summary.jsonl"
echo "[]" >"${RUN_ROOT}/aggregate.json"
export CONTEXTDROID_LLM_NAV_FIRST_PIPELINE="${CONTEXTDROID_LLM_NAV_FIRST_PIPELINE:-1}"
echo "[llm-tune-loop] run_root=${RUN_ROOT} apk=${APK} pkg=${PKG} iters=${ITERS} duration=${DURATION}s NAV_FIRST=${CONTEXTDROID_LLM_NAV_FIRST_PIPELINE}" | tee "${RUN_ROOT}/README.txt"

for ((i = 1; i <= ITERS; i++)); do
  OUT="${RUN_ROOT}/iter_${i}"
  mkdir -p "${OUT}"
  echo "[llm-tune-loop] === iteration ${i}/${ITERS} output=${OUT} ===" | tee -a "${RUN_ROOT}/run.log"
  set +e
  "${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/analyze_apk.py" \
    --apk "${APK}" \
    --pkg "${PKG}" \
    --duration "${DURATION}" \
    --output-dir "${OUT}" \
    --arm llm \
    --session-id "tune_${i}" \
    --ollama-model "${OLLAMA_MODEL:-llama3.2}" \
    --ollama-endpoint "${OLLAMA_ENDPOINT:-http://127.0.0.1:11434}"
  rc=$?
  set -e
  EVAL_OUT="${OUT}/llm_eval_report.json"
  "${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/evaluate_llm_session.py" "${OUT}" --out "${EVAL_OUT}" || true
  "${PYTHON_BIN}" - <<PY
import json, pathlib, subprocess, os
out = pathlib.Path("${OUT}")
evalp = pathlib.Path("${EVAL_OUT}")
meta = {}
mp = next(out.rglob("*_dynamic_metadata.json"), None)
if mp and mp.exists():
    try:
        meta = json.loads(mp.read_text(encoding="utf-8"))
    except Exception:
        pass
ev = {}
if evalp.exists():
    try:
        ev = json.loads(evalp.read_text(encoding="utf-8"))
    except Exception:
        pass
row = {
  "iter": int("${i}"),
  "analyze_exit": int("${rc}"),
  "llm_status": meta.get("llm_status"),
  "analysis_status": meta.get("analysis_status"),
  "elapsed_sec": meta.get("elapsed_sec"),
  "llm_actions_count": meta.get("llm_actions_count"),
  "aggregates": (ev.get("aggregates") or {}),
}
pathlib.Path("${MASTER}").open("a", encoding="utf-8").write(json.dumps(row, ensure_ascii=False) + "\\n")
PY
done

echo "[llm-tune-loop] done. Summary lines: ${MASTER}" | tee -a "${RUN_ROOT}/run.log"
