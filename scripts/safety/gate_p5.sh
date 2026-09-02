#!/usr/bin/env bash
# Gate P5 — config parity, activation validator, canary dry-run path, failure-injection.
# No real malware. Fail closed. Prefer working proofs over stubs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

PASS=0
FAIL=0
SKIP=0
note() { printf '%s\n' "$*"; }
pass() { note "[PASS] $*"; PASS=$((PASS + 1)); }
fail() { note "[FAIL] $*"; FAIL=$((FAIL + 1)); }
skip() { note "[SKIP] $*"; SKIP=$((SKIP + 1)); }

ADB_BIN="${ADB_BIN:-${ROOT}/tools/platform-tools/adb}"
[[ -x "${ADB_BIN}" ]] || ADB_BIN="${HOME}/Library/Android/sdk/platform-tools/adb"
export ADB_BIN
MW_SERIAL="${MW_SERIAL:-emulator-5556}"
export ANDROID_SERIAL="${MW_SERIAL}"
export AVD_NAME="${AVD_NAME:-abrg_mw}"

CANARY_APK="${CANARY_APK:-${ROOT}/data/apks/benign/ademar.textlauncher_10.apk}"
CANARY_PKG="${CANARY_PKG:-ademar.textlauncher}"
CANARY_DURATION="${CANARY_DURATION:-45}"
RUN_ID="${ABRG_RUN_ID:-gatep5-$(date -u +%Y%m%dT%H%M%SZ)}"

# Host Frida CLI (analyze_apk resolves .venv) + no Docker hang.
export PATH="${ROOT}/.venv/bin:${PATH}"
export FRIDA_USE_DOCKER="${FRIDA_USE_DOCKER:-0}"

note "=== gate_p5 start ==="
note "ROOT=${ROOT}"
note "date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
note "run_id=${RUN_ID}"
note "canary_apk=${CANARY_APK}"
note "NO real malware; canary = benign sealed-as-sample"

# --- 5.1 config parity ---
note "--- 5.1 config_parity_check selftest ---"
PARITY_OUT="$(python3 "${ROOT}/scripts/safety/config_parity_check.py" selftest --out-dir "${ROOT}/logs/p5_config_parity" 2>&1)" || true
note "${PARITY_OUT}"
if printf '%s\n' "${PARITY_OUT}" | grep -q 'CONFIG_PARITY_MUTATION_DETECTED_OK' \
  && printf '%s\n' "${PARITY_OUT}" | grep -q 'CONFIG_PARITY_OK'; then
  pass "config parity OK; deliberate mutation fails"
else
  fail "config parity selftest"
fi

# --- 5.4 validate_activation on existing benign traces ---
note "--- 5.4 validate_activation calibration (benign traces) ---"
TRACE1="experiment/v2_dataset_bundle/sessions/497e019dc8a1_llm_s2__ac.robinson.mediaphone/ac.robinson.mediaphone_frida.jsonl"
TRACE2="experiment/v2_dataset_bundle/sessions/f54d6d05f299_llm_s3__ca.andries.portknocker/ca.andries.portknocker_frida.jsonl"
ACT_OK=1
for tr in "${TRACE1}" "${TRACE2}"; do
  if [[ ! -f "${tr}" ]]; then
    fail "missing calibration trace ${tr}"
    ACT_OK=0
    continue
  fi
  ACT_OUT="$(python3 "${ROOT}/scripts/corpus/validate_activation.py" --trace "${tr}" --expect-malware-axis not_activated 2>&1)" || {
    note "${ACT_OUT}"
    fail "validate_activation on ${tr}"
    ACT_OK=0
    continue
  }
  note "${ACT_OUT}"
done
if [[ "${ACT_OK}" -eq 1 ]]; then
  pass "validate_activation: benign traces not_activated on malware-signal axis"
fi

# --- 5.5 failure-injection (safe subset) ---
note "--- 5.5 failure-injection (safe subset) ---"
FI_OUT="$(python3 "${ROOT}/scripts/corpus/tests/test_p5_failure_injection.py" 2>&1)" || true
note "${FI_OUT}"
if printf '%s\n' "${FI_OUT}" | grep -q 'FAILINJ_SUMMARY PASS'; then
  pass "failure-injection safe subset"
else
  fail "failure-injection safe subset"
fi
if [[ -f "${ROOT}/scripts/corpus/tests/FAILURE_INJECTION_DEFERRED.md" ]]; then
  pass "failure-injection status doc present"
else
  fail "FAILURE_INJECTION_DEFERRED.md missing"
fi

# Live mid-run suite (plan 5.5) — require GATE_P5_MIDRUN=1 (long; needs abrg_mw)
note "--- 5.5 mid-run failure-injection (live) ---"
if [[ "${GATE_P5_MIDRUN:-0}" == "1" ]]; then
  MID_OUT="$(python3 "${ROOT}/scripts/corpus/tests/test_p5_midrun_failure_injection.py" 2>&1)" || true
  note "${MID_OUT}"
  if printf '%s\n' "${MID_OUT}" | grep -q 'FAILINJ_SUMMARY PASS'; then
    pass "failure-injection mid-run live suite"
  else
    fail "failure-injection mid-run live suite"
  fi
else
  skip "mid-run failure-injection (set GATE_P5_MIDRUN=1)"
fi

# --- refuse guard disable on malware path (Safety residual) ---
note "--- refuse CONTEXTDROID_DEVICE_GUARD_DISABLE on canary/malware path ---"
GD_OUT="$(CONTEXTDROID_DEVICE_GUARD_DISABLE=1 python3 "${ROOT}/scripts/corpus/run_sample.py" \
  --tier canary --sha256 "$(printf '0%.0s' {1..64})" --pkg "${CANARY_PKG}" --no-boot-if-needed 2>&1)" || true
note "${GD_OUT}"
if printf '%s\n' "${GD_OUT}" | grep -q 'CONTEXTDROID_DEVICE_GUARD_DISABLE'; then
  pass "run_sample refuses DEVICE_GUARD_DISABLE on canary path"
else
  fail "run_sample did not refuse DEVICE_GUARD_DISABLE"
fi

# --- refuse --tier malware without CONTEXTDROID_MALWARE_GO=1 (code go/no-go) ---
note "--- refuse --tier malware without CONTEXTDROID_MALWARE_GO=1 ---"
unset CONTEXTDROID_MALWARE_GO || true
MW_REFUSE_OUT="$(env -u CONTEXTDROID_MALWARE_GO python3 "${ROOT}/scripts/corpus/run_sample.py" \
  --tier malware --sha256 "$(printf '0%.0s' {1..64})" --pkg "${CANARY_PKG}" --no-boot-if-needed 2>&1)" || true
note "${MW_REFUSE_OUT}"
if printf '%s\n' "${MW_REFUSE_OUT}" | grep -q 'CONTEXTDROID_MALWARE_GO=1'; then
  pass "run_sample refuses --tier malware without CONTEXTDROID_MALWARE_GO"
else
  fail "run_sample did not refuse malware tier without CONTEXTDROID_MALWARE_GO"
fi

# With flag set but no real sample: still fail closed (no download/install of malware).
note "--- CONTEXTDROID_MALWARE_GO=1 still fail-closed (missing archive / no install) ---"
MW_GO_OUT="$(CONTEXTDROID_MALWARE_GO=1 python3 "${ROOT}/scripts/corpus/run_sample.py" \
  --tier malware --sha256 "$(printf '0%.0s' {1..64})" --pkg "${CANARY_PKG}" --no-boot-if-needed 2>&1)" || true
note "${MW_GO_OUT}"
if printf '%s\n' "${MW_GO_OUT}" | grep -qE 'CONTEXTDROID_MALWARE_GO=1'; then
  fail "malware path still refused GO with flag set (unexpected)"
elif printf '%s\n' "${MW_GO_OUT}" | grep -qE 'quarantine archive missing|vault not mounted|REFUSE: vault'; then
  pass "CONTEXTDROID_MALWARE_GO=1 still fail-closed without real sample (no install)"
elif printf '%s\n' "${MW_GO_OUT}" | grep -qiE 'install|analyze_apk starting|unsealed'; then
  fail "malware path progressed toward install without a real sealed sample"
else
  # Any other early fail-closed is acceptable; must not look like success.
  if printf '%s\n' "${MW_GO_OUT}" | grep -q 'run_sample: OK'; then
    fail "malware path reported OK without real sample"
  else
    pass "CONTEXTDROID_MALWARE_GO=1 still fail-closed (early refuse, no install)"
  fi
fi

# --seal-from refused on malware tier (even with GO)
note "--- refuse --seal-from on --tier malware ---"
SEAL_REFUSE_OUT="$(CONTEXTDROID_MALWARE_GO=1 python3 "${ROOT}/scripts/corpus/run_sample.py" \
  --tier malware --seal-from "${CANARY_APK}" --pkg "${CANARY_PKG}" --no-boot-if-needed 2>&1)" || true
note "${SEAL_REFUSE_OUT}"
if printf '%s\n' "${SEAL_REFUSE_OUT}" | grep -q 'seal-from is only allowed for --tier canary'; then
  pass "run_sample refuses --seal-from on malware tier"
else
  fail "run_sample did not refuse --seal-from on malware tier"
fi

# --- Vault for canary ---
note "--- vault for canary ---"
if ! bash "${ROOT}/scripts/safety/vault.sh" status 2>/dev/null | grep -q '^mounted'; then
  if bash "${ROOT}/scripts/safety/vault.sh" mount; then
    pass "vault mounted"
  else
    fail "vault mount"
    note "=== gate_p5 summary: PASS=${PASS} FAIL=${FAIL} SKIP=${SKIP} ==="
    exit 1
  fi
else
  pass "vault already mounted"
fi

# Staging must be empty before canary
STAGING_EMPTY="$(python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety.vault_paths import STAGING_DIR, assert_mounted, ensure_layout
assert_mounted(); ensure_layout()
left = list(STAGING_DIR.iterdir()) if STAGING_DIR.is_dir() else []
print("empty" if not left else "dirty:" + ",".join(p.name for p in left))
PY
)"
if [[ "${STAGING_EMPTY}" == "empty" ]]; then
  pass "staging empty pre-canary"
else
  note "clearing staging residue: ${STAGING_EMPTY}"
  python3 - <<'PY'
import sys, shutil
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety.vault_paths import STAGING_DIR, assert_mounted
assert_mounted()
for p in STAGING_DIR.iterdir():
    if p.is_dir(): shutil.rmtree(p)
    else: p.unlink(missing_ok=True)
print("cleared")
PY
  pass "staging cleared pre-canary"
fi

if [[ ! -f "${CANARY_APK}" ]]; then
  fail "canary APK missing: ${CANARY_APK}"
  note "=== gate_p5 summary: PASS=${PASS} FAIL=${FAIL} SKIP=${SKIP} ==="
  exit 1
fi

# --- 5.3 canary: full path if emulator available / bootable ---
note "--- 5.3 canary dry run via run_sample.py ---"
CANARY_EXTRA=()
if "${ADB_BIN}" -s "${MW_SERIAL}" get-state 2>/dev/null | grep -q device; then
  note "abrg_mw online — canary uses --no-wipe-boot (frida re-push if missing)"
  CANARY_EXTRA+=(--no-wipe-boot)
else
  note "abrg_mw not online — will attempt wipe-boot via run_sample (may take several minutes)"
fi
if [[ ! -f "${ROOT}/tools/frida-server-android-arm64" ]]; then
  fail "tools/frida-server-android-arm64 missing (required for post-wipe push; match .venv frida version)"
  note "=== gate_p5 summary: PASS=${PASS} FAIL=${FAIL} SKIP=${SKIP} ==="
  exit 1
fi
pass "host frida-server binary present for provisioning"

unset CONTEXTDROID_DEVICE_GUARD_DISABLE || true
CANARY_LOG="${ROOT}/logs/p5_canary_${RUN_ID}.log"
mkdir -p "${ROOT}/logs"
set +e
# shellcheck disable=SC2086
python3 "${ROOT}/scripts/corpus/run_sample.py" \
  --tier canary \
  --seal-from "${CANARY_APK}" \
  --pkg "${CANARY_PKG}" \
  --duration "${CANARY_DURATION}" \
  --arm monkey \
  --run-id "${RUN_ID}" \
  --monkey-seed 424242 \
  "${CANARY_EXTRA[@]}" \
  >"${CANARY_LOG}" 2>&1
CANARY_RC=$?
set -e
note "--- canary log tail ---"
tail -n 80 "${CANARY_LOG}" || true

if [[ "${CANARY_RC}" -eq 0 ]]; then
  pass "canary run_sample completed rc=0"
  # staging empty
  POST="$(python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety.vault_paths import STAGING_DIR
left = list(STAGING_DIR.iterdir()) if STAGING_DIR.is_dir() else []
print("empty" if not left else "dirty")
PY
)"
  if [[ "${POST}" == "empty" ]]; then
    pass "post-canary staging empty"
  else
    fail "post-canary staging not empty"
  fi
  # trace present under vault
  TRACE_CHECK="$(python3 - <<PY
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety.vault_paths import TRACES_DIR
d = TRACES_DIR / "${RUN_ID}"
fridas = list(d.glob("*_frida.jsonl")) if d.is_dir() else []
print(str(fridas[0]) if fridas else "missing")
PY
)"
  if [[ "${TRACE_CHECK}" != "missing" ]]; then
    pass "canary trace present: ${TRACE_CHECK}"
    ACT_C="$(python3 "${ROOT}/scripts/corpus/validate_activation.py" --trace "${TRACE_CHECK}" --expect-malware-axis not_activated 2>&1)" || true
    note "${ACT_C}"
    if printf '%s\n' "${ACT_C}" | grep -q 'malware_signal_axis=not_activated'; then
      pass "canary malware-signal axis not_activated"
    else
      fail "canary activation axis unexpected"
    fi
  else
    fail "canary trace missing under vault traces/${RUN_ID}"
  fi
  # ledger last line
  LEDGER="${ROOT}/logs/ledger/run_ledger.jsonl"
  if [[ -f "${LEDGER}" ]] && tail -n 1 "${LEDGER}" | python3 -c "import sys,json; r=json.load(sys.stdin); assert r.get('run_id'); assert r.get('outcome') in ('executed','failed'); print('ledger_ok', r.get('outcome'), r.get('run_id'))"; then
    pass "ledger record schema-valid for canary"
  else
    fail "ledger record missing/invalid"
  fi
else
  fail "canary run_sample rc=${CANARY_RC} (see ${CANARY_LOG})"
  # Still require staging empty after failure
  POST="$(python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety.vault_paths import STAGING_DIR, is_mounted
if not is_mounted():
    print("unmounted")
else:
    left = list(STAGING_DIR.iterdir()) if STAGING_DIR.is_dir() else []
    print("empty" if not left else "dirty")
PY
)"
  if [[ "${POST}" == "empty" ]]; then
    pass "staging empty after failed canary (fail-closed cleanup)"
  elif [[ "${POST}" == "unmounted" ]]; then
    skip "staging check skipped (vault unmounted)"
  else
    fail "staging residue after failed canary"
  fi
  note "BLOCKER: full canary needs abrg_mw + sink + frida; offline proofs above may still be green"
fi

# Three consecutive canaries — only if first succeeded; else document skip
if [[ "${CANARY_RC}" -eq 0 ]]; then
  note "--- three consecutive canaries (independence) ---"
  note "[SKIP deferred in gate_p5 default] three consecutive full canaries are long; first canary green. Re-run with GATE_P5_TRIPLE=1 to force."
  if [[ "${GATE_P5_TRIPLE:-0}" == "1" ]]; then
    for i in 1 2 3; do
      RID="${RUN_ID}-t${i}"
      set +e
      python3 "${ROOT}/scripts/corpus/run_sample.py" \
        --tier canary --seal-from "${CANARY_APK}" --pkg "${CANARY_PKG}" \
        --duration "${CANARY_DURATION}" --arm monkey --run-id "${RID}" --no-wipe-boot \
        >"${ROOT}/logs/p5_canary_${RID}.log" 2>&1
      rc=$?
      set -e
      if [[ "${rc}" -eq 0 ]]; then
        pass "triple canary ${i}/3"
      else
        fail "triple canary ${i}/3 rc=${rc}"
      fi
    done
  else
    skip "triple canary (set GATE_P5_TRIPLE=1)"
  fi
else
  skip "triple canary (first canary failed)"
fi

note "=== gate_p5 summary: PASS=${PASS} FAIL=${FAIL} SKIP=${SKIP} ==="
[[ "${FAIL}" -eq 0 ]] || exit 1
exit 0
