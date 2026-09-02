#!/usr/bin/env bash
# Verify Step 0 (merged flailing rules) and Step 1 (explore candidate logging).
# Exit nonzero if any assertion fails.
#
# Step 1 Mensa JSONL: STEP1_MENSA_JSONL env, else logs/step1_mensa_fresh/... (not v6).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

DEFAULT_STEP1_MENSA_JSONL="${ROOT}/logs/step1_mensa_fresh/ef32499a74ab_ch.famoser.mensa/dynamic/llm/session_1/ch.famoser.mensa_llm_actions.jsonl"
STEP1_MENSA_JSONL="${STEP1_MENSA_JSONL:-${DEFAULT_STEP1_MENSA_JSONL}}"

STATUS=0

# ---------------------------------------------------------------------------
# 1. same_element_cycle / dominant_screen only in quality_rules.py
# ---------------------------------------------------------------------------
OTHER_FILES="$(
  grep -rlE 'same_element_cycle|dominant_screen' extraction_pipeline --include='*.py' 2>/dev/null \
    | grep -v 'extraction_pipeline/quality_rules.py$' \
    | grep -v '/tests/' \
    || true
)"
if [[ -z "$OTHER_FILES" ]]; then
  echo "PASS assertion 1: same_element_cycle/dominant_screen only in quality_rules.py (other_py_files=0)"
else
  echo "FAIL assertion 1: same_element_cycle/dominant_screen only in quality_rules.py (other_py_files=${OTHER_FILES//$'\n'/; })"
  STATUS=1
fi

# ---------------------------------------------------------------------------
# 2–6. Python checks (FLAILING_SUSPECT + fresh Mensa JSONL fields)
# ---------------------------------------------------------------------------
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  export "$line"
done < <(
  STEP1_MENSA_JSONL="${STEP1_MENSA_JSONL}" python3 - <<'PY'
import csv
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from evaluate_scenario_level import _load_actions
from quality_rules import detect_suspect_flailing

WORKING_CSV = Path("experiment/working_dataset.csv")
RECOVERY_RE = re.compile(r"bfs_return_to_hub|bfs_avoid_back_loop")
MENSA_JSONL = Path(os.environ["STEP1_MENSA_JSONL"])

flailing_packages: list[str] = []
for row in csv.DictReader(WORKING_CSV.open(encoding="utf-8")):
    pkg = row["package"]
    base = Path(row["artifact_dir"])
    actions_path = base / f"{pkg}_llm_actions.jsonl"
    meta_path = base / f"{pkg}_dynamic_metadata.json"
    sim_status = ""
    if meta_path.exists():
        sim_status = str(json.loads(meta_path.read_text(encoding="utf-8")).get("llm_simulation_status") or "")
    actions = _load_actions(actions_path)
    is_flailing, _ = detect_suspect_flailing(actions, sim_status=sim_status)
    if is_flailing:
        flailing_packages.append(pkg)

print(f"FLAILING_COUNT={len(flailing_packages)}")
print(f"FLAILING_COOLMICAPP={int('cc.echonet.coolmicapp' in flailing_packages)}")
print(f"FLAILING_ROADTRIPRADAR={int('ca.voiditswarranty.roadtripradar' in flailing_packages)}")

skipped_interactive = 0
has_element_snapshot = 0
has_truncated_field = 0
snapshot_truncated = -1
snapshot_len = 0
recovery_step = "none"
mensa_jsonl_exists = int(MENSA_JSONL.exists())
mensa_stale_log = 0
mensa_stale_reason = ""

if not MENSA_JSONL.exists():
    mensa_stale_log = 1
    mensa_stale_reason = f"missing:{MENSA_JSONL}"
elif "bulk_llm_benign_v6" in str(MENSA_JSONL).replace("\\", "/"):
    mensa_stale_log = 1
    mensa_stale_reason = "path_points_at_bulk_llm_benign_v6"
else:
    recovery_count = 0
    for line in MENSA_JSONL.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        pa = ev.get("parsed_action") or {}
        reason = str(pa.get("reason") or "")
        if not RECOVERY_RE.search(reason):
            continue
        recovery_count += 1
        counts = ev.get("explore_candidate_counts")
        snap = ev.get("element_snapshot")
        if counts is None:
            mensa_stale_log = 1
            mensa_stale_reason = "recovery_step_missing_explore_candidate_counts"
            break
        for key in ("nav_cands", "other_cands", "expand_cands", "skipped_interactive"):
            if counts.get(key) is None:
                mensa_stale_log = 1
                mensa_stale_reason = f"recovery_step_null_{key}"
                break
        if mensa_stale_log:
            break
        if snap is None:
            mensa_stale_log = 1
            mensa_stale_reason = "recovery_step_missing_element_snapshot"
            break
        if "truncated" not in snap:
            mensa_stale_log = 1
            mensa_stale_reason = "element_snapshot_missing_truncated_field"
            break
        if recovery_step == "none":
            recovery_step = str(ev.get("step") or "none")
            skipped_interactive = int(counts.get("skipped_interactive") or 0)
            has_element_snapshot = 1
            has_truncated_field = 1
            snapshot_truncated = int(bool(snap.get("truncated")))
            snapshot_len = len(snap.get("elements") or [])
    if recovery_count == 0 and not mensa_stale_log:
        mensa_stale_log = 1
        mensa_stale_reason = "no_recovery_steps_in_log"

print(f"MENSA_JSONL={MENSA_JSONL}")
print(f"MENSA_JSONL_EXISTS={mensa_jsonl_exists}")
print(f"MENSA_STALE_LOG={mensa_stale_log}")
print(f"MENSA_STALE_REASON={mensa_stale_reason}")
print(f"MENSA_RECOVERY_STEP={recovery_step}")
print(f"MENSA_SKIPPED_INTERACTIVE={skipped_interactive}")
print(f"MENSA_HAS_ELEMENT_SNAPSHOT={has_element_snapshot}")
print(f"MENSA_HAS_TRUNCATED_FIELD={has_truncated_field}")
print(f"MENSA_SNAPSHOT_TRUNCATED={snapshot_truncated}")
print(f"MENSA_SNAPSHOT_LEN={snapshot_len}")
PY
)

# ---------------------------------------------------------------------------
# 2. v129 FLAILING_SUSPECT count >= 46
# ---------------------------------------------------------------------------
if [[ "${FLAILING_COUNT:-0}" -ge 46 ]]; then
  echo "PASS assertion 2: v129 FLAILING_SUSPECT count >= 46 (count=${FLAILING_COUNT})"
else
  echo "FAIL assertion 2: v129 FLAILING_SUSPECT count >= 46 (count=${FLAILING_COUNT:-0})"
  STATUS=1
fi

# ---------------------------------------------------------------------------
# 3. coolmicapp and roadtripradar both FLAILING_SUSPECT
# ---------------------------------------------------------------------------
if [[ "${FLAILING_COOLMICAPP:-0}" -eq 1 && "${FLAILING_ROADTRIPRADAR:-0}" -eq 1 ]]; then
  echo "PASS assertion 3: cc.echonet.coolmicapp and ca.voiditswarranty.roadtripradar FLAILING_SUSPECT (coolmicapp=${FLAILING_COOLMICAPP} roadtripradar=${FLAILING_ROADTRIPRADAR})"
else
  echo "FAIL assertion 3: cc.echonet.coolmicapp and ca.voiditswarranty.roadtripradar FLAILING_SUSPECT (coolmicapp=${FLAILING_COOLMICAPP:-0} roadtripradar=${FLAILING_ROADTRIPRADAR:-0})"
  STATUS=1
fi

# ---------------------------------------------------------------------------
# 4. fresh mensa log exists and is not stale (predates Step 1 instrumentation)
# ---------------------------------------------------------------------------
if [[ "${MENSA_JSONL_EXISTS:-0}" -eq 1 && "${MENSA_STALE_LOG:-1}" -eq 0 ]]; then
  echo "PASS assertion 4: mensa log is fresh Step 1 instrumentation (path=${MENSA_JSONL} truncated_field=${MENSA_HAS_TRUNCATED_FIELD} snapshot_truncated=${MENSA_SNAPSHOT_TRUNCATED} snapshot_len=${MENSA_SNAPSHOT_LEN})"
else
  echo "FAIL assertion 4: mensa log is fresh Step 1 instrumentation (path=${MENSA_JSONL:-?} exists=${MENSA_JSONL_EXISTS:-0} stale=${MENSA_STALE_LOG:-1} reason=${MENSA_STALE_REASON:-unknown})"
  STATUS=1
fi

# ---------------------------------------------------------------------------
# 5. mensa recovery step has skipped_interactive > 0
# ---------------------------------------------------------------------------
if [[ "${MENSA_SKIPPED_INTERACTIVE:-0}" -gt 0 ]]; then
  echo "PASS assertion 5: mensa recovery step skipped_interactive > 0 (step=${MENSA_RECOVERY_STEP} skipped_interactive=${MENSA_SKIPPED_INTERACTIVE})"
else
  echo "FAIL assertion 5: mensa recovery step skipped_interactive > 0 (step=${MENSA_RECOVERY_STEP} skipped_interactive=${MENSA_SKIPPED_INTERACTIVE:-0})"
  STATUS=1
fi

# ---------------------------------------------------------------------------
# 6. that same step has element_snapshot field
# ---------------------------------------------------------------------------
if [[ "${MENSA_HAS_ELEMENT_SNAPSHOT:-0}" -eq 1 ]]; then
  echo "PASS assertion 6: mensa recovery step has element_snapshot (step=${MENSA_RECOVERY_STEP} has_element_snapshot=${MENSA_HAS_ELEMENT_SNAPSHOT})"
else
  echo "FAIL assertion 6: mensa recovery step has element_snapshot (step=${MENSA_RECOVERY_STEP} has_element_snapshot=${MENSA_HAS_ELEMENT_SNAPSHOT:-0})"
  STATUS=1
fi

exit "$STATUS"
