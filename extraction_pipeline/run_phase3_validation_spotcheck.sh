#!/usr/bin/env bash
# Phase 3 validation: libchecker (regression) + vpnhotspot/traced_it (v4 foreground_mismatch).
set -euo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-${BASE_DIR}/.venv/bin/python}"
ADB_BIN="${ADB_BIN:-${BASE_DIR}/tools/platform-tools/adb}"
APK_ROOT="${APK_ROOT:-${BASE_DIR}/data/apks/pilot_v2}"
LOG_ROOT="${LOG_ROOT:-${BASE_DIR}/logs/phase3_validation_spotcheck}"
DURATION="${DURATION:-400}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.2}"
OLLAMA_ENDPOINT="${OLLAMA_ENDPOINT:-http://127.0.0.1:11434}"

export ANDROID_SERIAL="${ANDROID_SERIAL:-emulator-5554}"
export CONTEXTDROID_ISOLATE_EMULATOR=1
export CONTEXTDROID_STRICT_FOREGROUND=1
export CONTEXTDROID_FOREGROUND_MISMATCH_LIMIT=3
export CONTEXTDROID_SKIP_SNAPSHOT_LOAD=1
export FRIDA_EVENTS_STALE_SEC="${FRIDA_EVENTS_STALE_SEC:-30}"
export FRIDA_ATTACH_GRACE_SEC="${FRIDA_ATTACH_GRACE_SEC:-30}"
export FRIDA_POST_HOOK_SILENCE_SEC="${FRIDA_POST_HOOK_SILENCE_SEC:-20}"
export FRIDA_HEALTHCHECK_INTERVAL_SEC="${FRIDA_HEALTHCHECK_INTERVAL_SEC:-8}"
export FRIDA_CLI_TIMEOUT="${FRIDA_CLI_TIMEOUT:-inf}"
export FRIDA_USE_DOCKER=0
export EMULATOR_SHOW_WINDOW="${EMULATOR_SHOW_WINDOW:-0}"
export CONTEXTDROID_ROOT_CAPTURE_DEADLINE_SEC="${CONTEXTDROID_ROOT_CAPTURE_DEADLINE_SEC:-30}"
export CONTEXTDROID_PRE_SETUP_MAX_SEC="${CONTEXTDROID_PRE_SETUP_MAX_SEC:-120}"
export CONTEXTDROID_LLM_UI_DUMP_TIMEOUT_SEC="${CONTEXTDROID_LLM_UI_DUMP_TIMEOUT_SEC:-15}"

APPS=(
  "com.absinthe.libchecker:com.absinthe.libchecker_2515.apk"
  "be.mygod.vpnhotspot_foss:be.mygod.vpnhotspot_foss_1035.apk"
  "app.traced_it:app.traced_it_15.apk"
)

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

mkdir -p "${LOG_ROOT}"
LOG_ROOT="${LOG_ROOT}" ANDROID_SERIAL="${ANDROID_SERIAL}" ADB_BIN="${ADB_BIN}" \
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
    --session-id "phase3_val_${pkg}" \
    --ollama-model "${OLLAMA_MODEL}" \
    --ollama-endpoint "${OLLAMA_ENDPOINT}" \
    --strict-clean-start \
    --fairness-protocol \
    </dev/null
  rc=$?
  set -e
  log "=== END ${pkg} rc=${rc} ==="
done

"${PYTHON_BIN}" - <<'PY' "${LOG_ROOT}"
import json, sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
print("\n=== PHASE 3 VALIDATION SPOT-CHECK SUMMARY ===")
for d in sorted(root.iterdir()):
    if not d.is_dir():
        continue
    pkg = d.name
    sess = d / "dynamic/llm/session_1"
    mf = next(sess.glob("*_dynamic_metadata.json"), None)
    af = next(sess.glob("*_llm_actions.jsonl"), None)
    pf = next(sess.glob("*_llm_ux_plan.json"), None)
    if not mf:
        print(f"{pkg}: no metadata")
        continue
    m = json.loads(mf.read_text())
    goals = []
    if pf and pf.exists():
        goals = json.loads(pf.read_text()).get("goals") or []
    actions = []
    if af and af.exists():
        for line in af.read_text().splitlines():
            if line.strip():
                actions.append(json.loads(line))
    types = Counter()
    backs = 0
    for a in actions:
        pa = a.get("parsed_action") or {}
        rsn = str(pa.get("reason") or "")
        types[pa.get("action_type", "?")] += 1
        if rsn.startswith("engine_route_back"):
            backs += 1
    forward_goals = sum(
        1
        for g in goals
        if g and not str(g).lower().startswith(("press back", "back ", "wait "))
    )
    print(f"\n{pkg}:")
    print(f"  sim={m.get('llm_simulation_status')} detail={m.get('llm_simulation_status_detail')}")
    print(f"  primary_ux={m.get('llm_primary_ux_fallback_reason','')}")
    print(f"  goals={len(goals)} forward_goals={forward_goals}")
    for g in goals[:12]:
        print(f"    - {g}")
    print(f"  actions={len(actions)} back_goal_steps={backs} types={dict(types)}")
PY

log "Validation spot-check complete: ${LOG_ROOT}"
