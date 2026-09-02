#!/usr/bin/env bash
# Gate P2 (offline): fixture-only determinism and labelling correctness.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

PASS=0
FAIL=0
note() { printf '%s\n' "$*"; }
pass() { note "[PASS] $*"; PASS=$((PASS + 1)); }
fail() { note "[FAIL] $*"; FAIL=$((FAIL + 1)); }

note "=== gate_p2 offline fixture start ==="
note "ROOT=${ROOT}"
note "date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

OUT1="$(python3 scripts/corpus/tests/test_selector_fixture.py 2>&1)" || true
note "${OUT1}"
if echo "${OUT1}" | rg -q "^SELECTOR_FIXTURE_OK$"; then
  pass "selector determinism + expected fixture output"
else
  fail "selector fixture test failed"
fi

OUT2="$(python3 scripts/corpus/tests/test_labeler_fixture.py 2>&1)" || true
note "${OUT2}"
if echo "${OUT2}" | rg -q "^LABELER_FIXTURE_OK$"; then
  pass "labeler assigns expected families + unmatched->none"
else
  fail "labeler fixture test failed"
fi

note "=== gate_p2 summary: PASS=${PASS} FAIL=${FAIL} ==="
if [[ "${FAIL}" -ne 0 ]]; then
  exit 1
fi
exit 0
