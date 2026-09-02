#!/usr/bin/env bash
# Golden-set validation after Frida liveness / foreground / isolation fixes.
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-${BASE_DIR}/.venv/bin/python}"
ADB_BIN="${ADB_BIN:-${BASE_DIR}/tools/platform-tools/adb}"
APK_ROOT="${BASE_DIR}/data/apks/benign"
LOG_ROOT="${LOG_ROOT:-${BASE_DIR}/logs/controlled_golden_fix_v1}"
DURATION="${DURATION:-300}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2}"
OLLAMA_ENDPOINT="${OLLAMA_ENDPOINT:-http://127.0.0.1:11434}"

export ANDROID_SERIAL="${ANDROID_SERIAL:-emulator-5554}"
export CONTEXTDROID_ISOLATE_EMULATOR=1
export CONTEXTDROID_STRICT_FOREGROUND=1
export CONTEXTDROID_FOREGROUND_MISMATCH_LIMIT=3
export CONTEXTDROID_SKIP_SNAPSHOT_LOAD=1
export FRIDA_EVENTS_STALE_SEC="${FRIDA_EVENTS_STALE_SEC:-45}"
export FRIDA_ATTACH_GRACE_SEC="${FRIDA_ATTACH_GRACE_SEC:-30}"
export FRIDA_USE_DOCKER=0
export EMULATOR_SHOW_WINDOW=0
export CONTEXTDROID_ROOT_CAPTURE_DEADLINE_SEC="${CONTEXTDROID_ROOT_CAPTURE_DEADLINE_SEC:-30}"
export CONTEXTDROID_PRE_SETUP_MAX_SEC="${CONTEXTDROID_PRE_SETUP_MAX_SEC:-120}"
export CONTEXTDROID_LLM_UI_DUMP_TIMEOUT_SEC="${CONTEXTDROID_LLM_UI_DUMP_TIMEOUT_SEC:-15}"

APPS=(
  "app.michaelwuensch.bitbanana:app.michaelwuensch.bitbanana_78.apk"
  "app.fedilab.mobilizon:app.fedilab.mobilizon_3.apk"
  "com.absinthe.libchecker:com.absinthe.libchecker_2515.apk"
)

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

mkdir -p "${LOG_ROOT}"
LOG_ROOT="${LOG_ROOT}" ANDROID_SERIAL="${ANDROID_SERIAL}" \
  bash "${BASE_DIR}/extraction_pipeline/ensure_emulator.sh"
LOG_DIR="${BASE_DIR}/logs" OLLAMA_ENDPOINT="${OLLAMA_ENDPOINT}" \
  bash "${BASE_DIR}/extraction_pipeline/ensure_ollama.sh"
"${ADB_BIN}" -s "${ANDROID_SERIAL}" root >/dev/null 2>&1 || true
"${ADB_BIN}" -s "${ANDROID_SERIAL}" wait-for-device

for entry in "${APPS[@]}"; do
  pkg="${entry%%:*}"
  apk_name="${entry##*:}"
  apk_path="${APK_ROOT}/${apk_name}"
  out_dir="${LOG_ROOT}/${pkg}/dynamic/llm/session_1"
  mkdir -p "${out_dir}"
  log "=== START ${pkg} (${DURATION}s) ==="
  set +e
  "${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/analyze_apk.py" \
    --apk "${apk_path}" \
    --pkg "${pkg}" \
    --duration "${DURATION}" \
    --output-dir "${out_dir}" \
    --arm llm \
    --session-id "golden_fix_${pkg}" \
    --ollama-model "${OLLAMA_MODEL}" \
    --ollama-endpoint "${OLLAMA_ENDPOINT}" \
    --strict-clean-start \
    --fairness-protocol \
    </dev/null
  rc=$?
  set -e
  frida_log="${out_dir}/${pkg}_frida.jsonl"
  "${PYTHON_BIN}" "${BASE_DIR}/extraction_pipeline/parse_logs.py" \
    --frida-log "${frida_log}" \
    --output "${out_dir}/${pkg}_frida.csv" \
    --quality-output "${out_dir}/${pkg}_frida.quality.json" \
    </dev/null 2>/dev/null || true
  log "=== END ${pkg} rc=${rc} ==="
done

"${PYTHON_BIN}" - <<'PY' "${LOG_ROOT}"
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
print("\n=== GOLDEN SET SUMMARY ===")
for d in sorted(root.iterdir()):
    if not d.is_dir():
        continue
    pkg = d.name
    sess = d / "dynamic/llm/session_1"
    mf = next(sess.glob("*_dynamic_metadata.json"), None)
    af = next(sess.glob("*_llm_actions.jsonl"), None)
    ff = next(sess.glob("*_frida.jsonl"), None)
    if not mf:
        print(f"{pkg}: no metadata")
        continue
    m = json.loads(mf.read_text())
    actions = []
    if af and af.exists():
        for line in af.read_text().splitlines():
            if line.strip():
                actions.append(json.loads(line))
    ev_ts = []
    if ff and ff.exists():
        for line in ff.read_text().splitlines():
            try:
                o = json.loads(line)
                if o.get("type") == "event" and o.get("timestamp") is not None:
                    ev_ts.append(int(o["timestamp"]))
            except Exception:
                pass
    wrong = sum(
        1
        for a in actions
        if (a.get("app_state") or {}).get("foreground_package") not in ("", pkg, None)
    )
    overlap = 0
    if ev_ts and actions:
        t0, t1 = min(ev_ts), max(ev_ts)
        overlap = sum(1 for a in actions if t0 <= a.get("ts_epoch_ms", 0) <= t1)
    print(
        f"{pkg}: status={m.get('analysis_status')} sim={m.get('llm_simulation_status')} "
        f"reattach={m.get('frida_reattach_successes',0)}/{m.get('frida_reattach_attempts',0)} "
        f"actions={len(actions)} wrong_fg={wrong} frida_overlap={overlap}/{len(actions)} "
        f"frida_span_ms={(max(ev_ts)-min(ev_ts)) if ev_ts else 0}"
    )
PY

log "Golden validation complete: ${LOG_ROOT}"
