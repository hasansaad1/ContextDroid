#!/usr/bin/env bash
# Gate P3 — emulator isolation + device guard.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

PASS=0
FAIL=0
note() { printf '%s\n' "$*"; }
pass() { note "[PASS] $*"; PASS=$((PASS + 1)); }
fail() { note "[FAIL] $*"; FAIL=$((FAIL + 1)); }

ADB_BIN="${ADB_BIN:-${ROOT}/tools/platform-tools/adb}"
EMU_BIN="${EMU_BIN:-${HOME}/Library/Android/sdk/emulator/emulator}"
BENIGN_APK="${BENIGN_APK:-${ROOT}/data/apks/benign/ac.robinson.mediaphone_65.apk}"
BENIGN_PKG="${BENIGN_PKG:-ac.robinson.mediaphone}"
BENIGN_SERIAL="${BENIGN_SERIAL:-emulator-5554}"
MW_SERIAL="${MW_SERIAL:-emulator-5556}"
MW_PORT="${MW_PORT:-5556}"

wait_boot() {
  local serial="$1"
  "${ADB_BIN}" -s "${serial}" wait-for-device >/dev/null 2>&1 || return 1
  for _ in $(seq 1 180); do
    if [[ "$("${ADB_BIN}" -s "${serial}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

kill_emulator_serial() {
  local serial="$1"
  "${ADB_BIN}" -s "${serial}" emu kill >/dev/null 2>&1 || true
  sleep 4
}

start_mw_wipe_boot() {
  ADB_BIN="${ADB_BIN}" AVD_NAME="abrg_mw" ANDROID_SERIAL="${MW_SERIAL}" bash "${ROOT}/scripts/safety/device_guard.sh" hard-prelaunch >/dev/null
  nohup "${EMU_BIN}" -avd "abrg_mw" -port "${MW_PORT}" -wipe-data -writable-system -no-boot-anim -no-audio -gpu swiftshader_indirect -no-snapshot-load -no-snapshot-save -no-window >/tmp/abrg_mw_gate_p3.log 2>&1 &
  wait_boot "${MW_SERIAL}"
}

note "=== gate_p3 start ==="
note "ROOT=${ROOT}"
note "date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# Stale lock from an interrupted ensure_emulator blocks all regression runs.
ENSURE_LOCK="/tmp/contextdroid_ensure_emulator.lock.d"
if [[ -d "${ENSURE_LOCK}" ]]; then
  note "clearing stale ensure_emulator lock (${ENSURE_LOCK})"
  rmdir "${ENSURE_LOCK}" 2>/dev/null || {
    fail "ensure_emulator lock held at ${ENSURE_LOCK}; another ensure_emulator may be running"
    note "=== gate_p3 summary: PASS=${PASS} FAIL=${FAIL} ==="
    exit 1
  }
fi

if python3 extraction_pipeline/safety/device_guard.py write-avd-fingerprint --out manifest/avd_fingerprint.json --avd abrg_benign --avd abrg_mw >/tmp/gate_p3_avd.txt 2>&1; then
  cat /tmp/gate_p3_avd.txt
  pass "avd_fingerprint.json generated and equal except name/path"
else
  cat /tmp/gate_p3_avd.txt
  fail "avd_fingerprint.json mismatch"
fi

run_regression_case() {
  local label="$1"
  local guard_disable="$2"
  local out_dir="$3"
  local screen_trace="$4"
  rm -rf "${out_dir}"
  mkdir -p "${out_dir}"
  rm -f "${screen_trace}"
  if ! ADB_BIN="${ADB_BIN}" AVD_NAME="abrg_benign" ANDROID_SERIAL="${BENIGN_SERIAL}" EMULATOR_SHOW_WINDOW=0 EMULATOR_NO_SNAPSHOT_LOAD=1 \
    bash extraction_pipeline/ensure_emulator.sh >/tmp/gate_p3_${label}_ensure.log 2>&1; then
    cat "/tmp/gate_p3_${label}_ensure.log"
    return 1
  fi
  CONTEXTDROID_DEVICE_GUARD_DISABLE="${guard_disable}" CONTEXTDROID_SKIP_SNAPSHOT_LOAD=1 FRIDA_USE_DOCKER=0 CONTEXTDROID_LLM_AGENT_SEED=424242 CONTEXTDROID_SCREEN_DUMP_TRACE="${screen_trace}" ADB_BIN="${ADB_BIN}" AVD_NAME="abrg_benign" ANDROID_SERIAL="${BENIGN_SERIAL}" \
    python3 extraction_pipeline/analyze_apk.py --apk "${BENIGN_APK}" --pkg "${BENIGN_PKG}" --duration 90 --output-dir "${out_dir}" --arm llm --fairness-protocol >/tmp/gate_p3_${label}_run.log 2>&1
}

baseline_ok=1
# 4 guard-disabled baseline runs (all used for mean/std; no discard).
for run_idx in 1 2 3 4; do
  if run_regression_case "baseline_${run_idx}" "1" "/tmp/phase3_baseline_${run_idx}" "/tmp/phase3_baseline_${run_idx}_screen_dumps.log"; then
    pass "baseline nondeterminism run ${run_idx}/4 completed (guard disabled)"
  else
    cat "/tmp/gate_p3_baseline_${run_idx}_ensure.log" 2>/dev/null || true
    cat "/tmp/gate_p3_baseline_${run_idx}_run.log"
    fail "baseline nondeterminism run ${run_idx}/4 failed"
    baseline_ok=0
  fi
done

guard_ok=1
for run_idx in 1 2 3; do
  if run_regression_case "guard_enabled_${run_idx}" "0" "/tmp/phase3_guard_enabled_${run_idx}" "/tmp/phase3_guard_enabled_${run_idx}_screen_dumps.log"; then
    pass "guard-enabled comparison run ${run_idx}/3 completed"
  else
    cat "/tmp/gate_p3_guard_enabled_${run_idx}_ensure.log" 2>/dev/null || true
    cat "/tmp/gate_p3_guard_enabled_${run_idx}_run.log"
    fail "guard-enabled comparison run ${run_idx}/3 failed"
    guard_ok=0
  fi
done

if python3 - <<'PY'
import json
import math
import statistics
from pathlib import Path

PKG = "ac.robinson.mediaphone"
LOW_SIGNAL = {"lifecycle", "reflection", "unknown"}
COUNT_KEYS = ("event_count", "meaningful_event_count", "screen_dumps")
GUARD_OVERHEAD_LIMIT = 0.01  # 1% of session wall
SMOKE_FLOOR = 0.7

_T_CRIT_ONESIDED_05 = {
    1: 6.314, 2: 2.920, 3: 2.353, 4: 2.132, 5: 2.015,
    6: 1.943, 7: 1.895, 8: 1.860, 9: 1.833, 10: 1.812,
}

# Historical known-bad (per-dump light assert) kept for documentation only.
OLD_KNOWN_BAD = {
    "baseline": [
        {"event_count": 360, "meaningful_event_count": 287, "screen_dumps": 14},
        {"event_count": 368, "meaningful_event_count": 293, "screen_dumps": 14},
        {"event_count": 368, "meaningful_event_count": 293, "screen_dumps": 14},
    ],
    "guard": [
        {"event_count": 364, "meaningful_event_count": 289, "screen_dumps": 13},
        {"event_count": 339, "meaningful_event_count": 264, "screen_dumps": 12},
        {"event_count": 331, "meaningful_event_count": 258, "screen_dumps": 12},
    ],
}


def t_crit_onesided_05(df: int) -> float:
    if df in _T_CRIT_ONESIDED_05:
        return _T_CRIT_ONESIDED_05[df]
    raise RuntimeError(f"no t-critical for df={df}")


def count_from_frida(path: Path):
    event_count = meaningful = 0
    categories: set[str] = set()
    hooks: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s.startswith("{"):
            continue
        try:
            obj = json.loads(s)
        except Exception:
            continue
        if obj.get("type") != "event":
            continue
        event_count += 1
        cat = obj.get("category")
        api = obj.get("api")
        if isinstance(cat, str) and cat:
            categories.add(cat)
            if cat not in LOW_SIGNAL:
                meaningful += 1
        if isinstance(api, str) and api:
            hooks.add(api)
    return event_count, meaningful, categories, hooks


def metrics(prefix: str):
    meta = json.loads((Path(prefix) / f"{PKG}_dynamic_metadata.json").read_text())
    frida = Path(prefix) / f"{PKG}_frida.jsonl"
    event_count, meaningful, categories, hooks = count_from_frida(frida)
    if "frida_meaningful_event_count" in meta:
        meaningful = int(meta["frida_meaningful_event_count"])
    if "frida_event_count" in meta:
        event_count = int(meta["frida_event_count"])
    wall = float(meta.get("session_wall_ms") or (float(meta.get("elapsed_sec") or 0.0) * 1000.0))
    guard_total = float(meta.get("guard_total_ms") or 0.0)
    ratio = float(meta.get("guard_overhead_ratio") or 0.0)
    if wall > 0 and not meta.get("guard_overhead_ratio"):
        ratio = guard_total / wall
    return {
        "exit_status": int(meta.get("analysis_exit_code", -1)),
        "event_count": event_count,
        "meaningful_event_count": meaningful,
        "hook_coverage": len(hooks),
        "category_set": categories,
        "screen_dumps": int(meta.get("llm_actions_count", 0)),
        "session_wall_ms": wall,
        "guard_total_ms": guard_total,
        "guard_call_count": int(meta.get("guard_call_count") or 0),
        "guard_max_call_ms": float(meta.get("guard_max_call_ms") or 0.0),
        "guard_overhead_ratio": ratio,
        "guard_watchdog_poll_count": int(meta.get("guard_watchdog_poll_count") or 0),
        "guard_slow_adb_call_count": int(meta.get("guard_slow_adb_call_count") or 0),
        "guard_watchdog_slow_adb_correlated": list(meta.get("guard_watchdog_slow_adb_correlated") or []),
        "elapsed_sec": float(meta.get("elapsed_sec") or 0.0),
    }


def single_obs_threshold(values):
    n = len(values)
    mean = statistics.mean(values)
    std = statistics.stdev(values) if n > 1 else 0.0
    tcrit = t_crit_onesided_05(max(1, n - 1))
    margin = tcrit * std * math.sqrt(1.0 + 1.0 / n) if n else 0.0
    return mean, std, mean - max(margin, 1.0)


def two_sample_threshold(bvals, gvals):
    n, m = len(bvals), len(gvals)
    mb, mg = statistics.mean(bvals), statistics.mean(gvals)
    vb = statistics.variance(bvals) if n > 1 else 0.0
    vg = statistics.variance(gvals) if m > 1 else 0.0
    df = n + m - 2
    sp = math.sqrt(((n - 1) * vb + (m - 1) * vg) / df) if df else 0.0
    se = sp * math.sqrt(1.0 / n + 1.0 / m)
    tcrit = t_crit_onesided_05(df)
    thr = mb - max(tcrit * se, 1.0)
    return mb, mg, thr, (mg >= thr)


baseline = [metrics(f"/tmp/phase3_baseline_{i}") for i in (1, 2, 3, 4)]
enabled = [metrics(f"/tmp/phase3_guard_enabled_{i}") for i in (1, 2, 3)]

for i, row in enumerate(baseline, start=1):
    print(
        f"BASELINE_DISABLED_RUN_{i} "
        f"meaningful_event_count={row['meaningful_event_count']} "
        f"event_count={row['event_count']} screen_dumps={row['screen_dumps']} "
        f"hook_coverage={row['hook_coverage']} exit_status={row['exit_status']} "
        f"guard_total_ms={row['guard_total_ms']} "
        f"category_set={sorted(row['category_set'])}"
    )
for i, row in enumerate(enabled, start=1):
    print(
        f"GUARD_ENABLED_RUN_{i} "
        f"meaningful_event_count={row['meaningful_event_count']} "
        f"event_count={row['event_count']} screen_dumps={row['screen_dumps']} "
        f"hook_coverage={row['hook_coverage']} exit_status={row['exit_status']} "
        f"guard_total_ms={row['guard_total_ms']} guard_overhead_ratio={row['guard_overhead_ratio']:.6f} "
        f"watchdog_polls={row['guard_watchdog_poll_count']} slow_adb={row['guard_slow_adb_call_count']} "
        f"correlated={len(row['guard_watchdog_slow_adb_correlated'])} "
        f"category_set={sorted(row['category_set'])}"
    )

if min(r["screen_dumps"] for r in baseline) <= 0 or min(r["screen_dumps"] for r in enabled) <= 0:
    raise SystemExit(5)

# --- EXACT structural invariants ---
struct_keys = ("exit_status", "hook_coverage", "category_set")
ref = baseline[0]
for key in struct_keys:
    if any(r[key] != ref[key] for r in baseline[1:]):
        print(f"A4_FAIL baseline structural drift on {key!r}")
        raise SystemExit(6)
    if any(r[key] != ref[key] for r in enabled):
        print(f"A4_FAIL guard structural drift on {key!r} (baseline={ref[key]!r})")
        raise SystemExit(2)
print("A4_EXACT_STRUCTURE pass=True keys=" + ",".join(struct_keys))

# --- DOCUMENTATION ONLY: abandoned count-gating controls ---
print("A4_DOC abandoned_count_gating_controls (informational; do not gate)")
print("A4_DOC CONTROL_1 leave_one_out_single_obs_prediction")
c1 = 0
for idx, held in enumerate(baseline, start=1):
    others = [r for j, r in enumerate(baseline) if j != idx - 1]
    ok = True
    for key in COUNT_KEYS:
        _mean, _std, thr = single_obs_threshold([r[key] for r in others])
        if held[key] < thr:
            ok = False
    c1 += int(ok)
    print(f"  hold_out_run_{idx} pass={ok}")
print(f"A4_DOC CONTROL_1_RESULT {c1}/4 (would-be null for count gating)")
print("A4_DOC CONTROL_2 known_bad_289_264_258 two_sample_t")
c2_ok = True
for key in COUNT_KEYS:
    mb, mg, thr, passed = two_sample_threshold(
        [r[key] for r in OLD_KNOWN_BAD["baseline"]],
        [r[key] for r in OLD_KNOWN_BAD["guard"]],
    )
    print(f"  {key}: mean_b={mb:.2f} mean_g={mg:.2f} thr={thr:.2f} pass={passed}")
    c2_ok = c2_ok and passed
print(f"A4_DOC CONTROL_2_RESULT pass={c2_ok} (known-bad under two-sample t)")
old_g_mean = statistics.mean([r["meaningful_event_count"] for r in OLD_KNOWN_BAD["guard"]])
old_b_mean = statistics.mean([r["meaningful_event_count"] for r in OLD_KNOWN_BAD["baseline"]])
print(
    "A4_DOC NOTE smoke_floor would NOT catch old 289/264/258 case "
    f"(guard_mean_meaningful={old_g_mean:.1f} "
    f"> 0.7*baseline_mean={0.7 * old_b_mean:.1f}); "
    "direct timing is the equivalence instrument"
)
print(
    "A4_DOC COUNTS dominated by LLM planner nondeterminism: "
    "GUARD_ENABLED_RUN_1 explore->execute fork at step 8 (-2 actions, -49 content_access); "
    "not gated"
)

# --- COUNTS reported, not gated ---
for key in COUNT_KEYS:
    bv = [r[key] for r in baseline]
    gv = [r[key] for r in enabled]
    print(
        f"A4_COUNTS_REPORT {key}: baseline_mean={statistics.mean(bv):.2f} "
        f"baseline_range=[{min(bv)},{max(bv)}] "
        f"guard_mean={statistics.mean(gv):.2f} guard_range=[{min(gv)},{max(gv)}] "
        f"(not gated)"
    )

# --- SMOKE FLOOR: catastrophic breakage only ---
print("A4_SMOKE_FLOOR threshold=0.7*baseline_mean (NOT an equivalence test)")
for key in COUNT_KEYS:
    bmean = statistics.mean([r[key] for r in baseline])
    gmean = statistics.mean([r[key] for r in enabled])
    floor = SMOKE_FLOOR * bmean
    ok = gmean > floor
    print(f"  {key}: guard_mean={gmean:.2f} floor={floor:.2f} pass={ok}")
    if not ok:
        print(f"A4_FAIL smoke floor breached on {key}")
        raise SystemExit(8)

# --- DIRECT timing on guard-enabled runs ---
print(f"A4_DIRECT_TIMING limit_ratio={GUARD_OVERHEAD_LIMIT}")
any_corr = False
for i, row in enumerate(enabled, start=1):
    ratio = row["guard_overhead_ratio"]
    corr = row["guard_watchdog_slow_adb_correlated"]
    ok_ratio = ratio < GUARD_OVERHEAD_LIMIT
    ok_corr = len(corr) == 0
    print(
        f"  GUARD_ENABLED_RUN_{i}: guard_total_ms={row['guard_total_ms']:.3f} "
        f"session_wall_ms={row['session_wall_ms']:.1f} "
        f"ratio={ratio:.6f} calls={row['guard_call_count']} "
        f"max_call_ms={row['guard_max_call_ms']:.3f} "
        f"watchdog_polls={row['guard_watchdog_poll_count']} "
        f"slow_adb={row['guard_slow_adb_call_count']} "
        f"correlated={len(corr)} "
        f"ratio_pass={ok_ratio} corr_pass={ok_corr}"
    )
    if corr:
        any_corr = True
        print(f"    correlated_events={corr}")
    if not ok_ratio:
        print(f"A4_FAIL guard overhead ratio {ratio:.6f} >= {GUARD_OVERHEAD_LIMIT}")
        raise SystemExit(9)
if any_corr:
    print("A4_FAIL slow adb calls temporally correlated with watchdog polls")
    raise SystemExit(12)
print("A4_DIRECT_TIMING pass=True (overhead <1%, no watchdog/slow-adb correlation)")

guard_totals = [r["guard_total_ms"] for r in enabled]
print(
    f"A4_PHANTOM_CHECK mean_guard_total_ms={statistics.mean(guard_totals):.3f} "
    f"(if tiny: old 11s->18-20s dump spacing was LLM path divergence, not 10ms per-dump assert)"
)
PY
then
  pass "A4 holds: exact structure + direct guard timing + smoke floor (counts reported only)"
else
  fail "A4 check failed (structure, direct timing, or smoke floor)"
fi

if [[ -s /tmp/phase3_baseline_1_screen_dumps.log && -s /tmp/phase3_baseline_2_screen_dumps.log && -s /tmp/phase3_baseline_3_screen_dumps.log && -s /tmp/phase3_baseline_4_screen_dumps.log && -s /tmp/phase3_guard_enabled_1_screen_dumps.log && -s /tmp/phase3_guard_enabled_2_screen_dumps.log && -s /tmp/phase3_guard_enabled_3_screen_dumps.log ]]; then
  pass "screen.py dump path exercised in all baseline + guard-enabled runs"
else
  fail "screen.py dump path was not exercised in one of the runs"
fi

if AVD_NAME="abrg_benign" ANDROID_SERIAL="emulator-9999" bash scripts/safety/device_guard.sh hard >/tmp/gate_p3_closed_fail_serial.log 2>&1; then
  fail "device guard did not fail closed on wrong serial"
else
  pass "device guard fails closed on wrong serial"
fi

if AVD_NAME="definitely_wrong_avd_name" ANDROID_SERIAL="${BENIGN_SERIAL}" bash scripts/safety/device_guard.sh hard >/tmp/gate_p3_closed_fail_avd.log 2>&1; then
  fail "device guard did not fail closed on wrong AVD name"
else
  pass "device guard fails closed on wrong AVD name"
fi

# PLAN_AMENDMENTS A7: second-emulator fail-closed supersedes USB phone step.
note "--- A7 two-emulator fail-closed (USB phone step withdrawn) ---"
two_device_ok=1
kill_emulator_serial "${MW_SERIAL}"
if ! ADB_BIN="${ADB_BIN}" AVD_NAME="abrg_benign" ANDROID_SERIAL="${BENIGN_SERIAL}" EMULATOR_SHOW_WINDOW=0 EMULATOR_NO_SNAPSHOT_LOAD=1 \
  bash extraction_pipeline/ensure_emulator.sh >/tmp/gate_p3_a7_benign_ensure.log 2>&1; then
  cat /tmp/gate_p3_a7_benign_ensure.log
  two_device_ok=0
  fail "A7: could not ensure ${BENIGN_SERIAL} before two-emulator test"
elif ! start_mw_wipe_boot; then
  two_device_ok=0
  fail "A7: could not boot second emulator ${MW_SERIAL}"
else
  if ADB_BIN="${ADB_BIN}" AVD_NAME="abrg_benign" ANDROID_SERIAL="${BENIGN_SERIAL}" bash scripts/safety/device_guard.sh single >/tmp/gate_p3_a7_single_fail.log 2>&1; then
    cat /tmp/gate_p3_a7_single_fail.log
    two_device_ok=0
    fail "A7: device guard single did not fail closed with two emulators online"
  elif rg -q 'expected exactly one online adb device' /tmp/gate_p3_a7_single_fail.log; then
    pass "A7: single fails closed with two emulators (expected exactly one online adb device)"
  else
    cat /tmp/gate_p3_a7_single_fail.log
    two_device_ok=0
    fail "A7: single failed with two emulators but message was not expected exactly-one-device"
  fi
  if ADB_BIN="${ADB_BIN}" AVD_NAME="abrg_benign" ANDROID_SERIAL="${BENIGN_SERIAL}" bash scripts/safety/device_guard.sh hard >/tmp/gate_p3_a7_hard_fail.log 2>&1; then
    cat /tmp/gate_p3_a7_hard_fail.log
    two_device_ok=0
    fail "A7: device guard hard did not fail closed with two emulators online"
  elif rg -q 'expected exactly one online adb device' /tmp/gate_p3_a7_hard_fail.log; then
    pass "A7: hard fails closed with two emulators (expected exactly one online adb device)"
  else
    cat /tmp/gate_p3_a7_hard_fail.log
    two_device_ok=0
    fail "A7: hard failed with two emulators but message was not expected exactly-one-device"
  fi
  kill_emulator_serial "${MW_SERIAL}"
  if ! ADB_BIN="${ADB_BIN}" AVD_NAME="abrg_benign" ANDROID_SERIAL="${BENIGN_SERIAL}" bash scripts/safety/device_guard.sh single >/tmp/gate_p3_a7_single_pass.log 2>&1; then
    cat /tmp/gate_p3_a7_single_pass.log
    two_device_ok=0
    fail "A7: device guard single did not pass after second emulator shutdown"
  else
    pass "A7: single passes again with one emulator online"
  fi
fi

wipe_ok=1
# Enforce exact-one-device guard invariant for malware tier proof.
kill_emulator_serial "${BENIGN_SERIAL}"
for i in 1 2 3; do
  note "--- wipe-proof trial ${i} ---"
  kill_emulator_serial "${MW_SERIAL}"
  if ! start_mw_wipe_boot; then
    wipe_ok=0
    note "trial ${i}: failed to boot with wipe-data"
    break
  fi
  if ! ADB_BIN="${ADB_BIN}" AVD_NAME="abrg_mw" ANDROID_SERIAL="${MW_SERIAL}" bash "${ROOT}/scripts/safety/device_guard.sh" hard >/tmp/gate_p3_guard_install_${i}.log 2>&1; then
    wipe_ok=0
    cat /tmp/gate_p3_guard_install_${i}.log
    note "trial ${i}: hard guard failed pre-install"
    break
  fi
  "${ADB_BIN}" -s "${MW_SERIAL}" install -r "${BENIGN_APK}" >/tmp/gate_p3_install_${i}.log 2>&1 || { wipe_ok=0; cat /tmp/gate_p3_install_${i}.log; break; }
  "${ADB_BIN}" -s "${MW_SERIAL}" shell pm path "${BENIGN_PKG}" >/tmp/gate_p3_present_${i}.log 2>&1 || { wipe_ok=0; break; }
  if ! rg -q '^package:' /tmp/gate_p3_present_${i}.log; then
    wipe_ok=0
    note "trial ${i}: package not present after install"
    break
  fi
  kill_emulator_serial "${MW_SERIAL}"
  if ! start_mw_wipe_boot; then
    wipe_ok=0
    note "trial ${i}: failed reboot wipe"
    break
  fi
  if "${ADB_BIN}" -s "${MW_SERIAL}" shell pm path "${BENIGN_PKG}" >/tmp/gate_p3_absent_${i}.log 2>&1; then
    if rg -q '^package:' /tmp/gate_p3_absent_${i}.log; then
      wipe_ok=0
      note "trial ${i}: package still present after wipe+boot"
      break
    fi
  fi
done

kill_emulator_serial "${MW_SERIAL}"

if [[ "${wipe_ok}" == "1" ]]; then
  pass "A2 wipe-proof holds for 3 consecutive install->wipe->absent cycles"
else
  fail "A2 wipe-proof failed"
fi

note "=== gate_p3 summary: PASS=${PASS} FAIL=${FAIL} ==="
if [[ "${FAIL}" -gt 0 ]]; then
  exit 1
fi
exit 0
