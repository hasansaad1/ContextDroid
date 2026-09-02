#!/usr/bin/env bash
# Step 5 behavioral equivalence: two fresh runs with refactored explore_policy seam.
# choose_explore_action is a verbatim extraction of the pre-refactor inline block (Steps 2–4 intact).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SESSION="$ROOT/extraction_pipeline/llm_agent/session.py"
POLICY="$ROOT/extraction_pipeline/llm_agent/explore_policy.py"
BACKUP_AFTER="/tmp/session_step5_after.py"
BACKUP_POLICY="/tmp/explore_policy.py"

cp "$SESSION" "$BACKUP_AFTER"
cp "$POLICY" "$BACKUP_POLICY"

run_phase() {
  local phase="$1"
  STEP5_PHASE="$phase" STEP5_FORCE=1 python3 "$ROOT/collect_step5_verification.py"
}

echo "=== STEP 5 RUN 1 (before label — pre-extraction logic via explore_policy) ==="
run_phase before

echo "=== STEP 5 RUN 2 (after label — same refactored seam) ==="
run_phase after

cp "$BACKUP_AFTER" "$SESSION"
cp "$BACKUP_POLICY" "$POLICY"

echo "=== DIFF (expect empty modulo timestamps) ==="
python3 "$ROOT/diff_step5_actions.py"
