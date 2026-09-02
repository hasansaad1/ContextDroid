#!/usr/bin/env bash
# Gate P0 — repo hygiene, ledger, SAFETY.md, pre-commit sample rejection.
# Cold-start: run from repo root with a clean invocation (no reliance on prior shell state).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

PASS=0
FAIL=0
note() { printf '%s\n' "$*"; }
pass() { note "[PASS] $*"; PASS=$((PASS + 1)); }
fail() { note "[FAIL] $*"; FAIL=$((FAIL + 1)); }

note "=== gate_p0 cold start ==="
note "ROOT=${ROOT}"
note "date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# --- 0. SAFETY.md ---
if [[ -f SAFETY.md ]]; then
  if awk '
    BEGIN { in_pol=0; in_inc=0; bad=0 }
    /^## Handling policy/ { in_pol=1; in_inc=0; next }
    /^## Incident procedure/ { in_inc=1; in_pol=0; next }
    /^## / { in_pol=0; in_inc=0 }
    (in_pol || in_inc) && /TODO/ { bad=1 }
    END { exit bad }
  ' SAFETY.md; then
    pass "SAFETY.md exists; no TODO in policy or incident sections"
  else
    fail "SAFETY.md contains TODO in policy or incident sections"
  fi
else
  fail "SAFETY.md missing"
fi

# --- 1. git check-ignore ---
for path in test.apk malware/x Volumes/ABRG_MW/quarantine/sample; do
  if out="$(git check-ignore -v "${path}" 2>/dev/null)"; then
    pass "git check-ignore matches ${path}: ${out}"
  else
    fail "git check-ignore did not match ${path}"
  fi
done

# --- 2. A6: no >2MB tracked file at HEAD without allowlist ---
note "--- HEAD tree size scan (pre-commit 2MB rule) ---"
OVERSIZE=0
while IFS= read -r -d '' f; do
  [[ -f "${f}" ]] || continue
  sz="$(wc -c <"${f}" | tr -d ' ')"
  if [[ "${sz}" -gt $((2 * 1024 * 1024)) ]]; then
    note "OVERSIZE_TRACKED ${sz} ${f}"
    OVERSIZE=$((OVERSIZE + 1))
  fi
done < <(git ls-files -z)
if [[ "${OVERSIZE}" -eq 0 ]]; then
  pass "no tracked HEAD file exceeds 2 MB (pre-commit size rule clean on HEAD)"
else
  fail "${OVERSIZE} tracked HEAD file(s) exceed 2 MB — update allowlist before relying on the hook"
fi

# --- 3. Install hook ---
make install-hooks
HOOK=".git/hooks/pre-commit"
if [[ -x "${HOOK}" ]]; then
  pass "pre-commit hook installed at ${HOOK}"
else
  fail "pre-commit hook missing or not executable"
fi

# --- 4. Ledger validate_ledger ---
note "--- ledger validation ---"
LEDGER_OUT="$(python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety.ledger import validate_ledger, LedgerValidationError

good = {
    "run_id": "gate_p0_test",
    "utc_start": "2026-07-27T00:00:00Z",
    "utc_end": "2026-07-27T00:01:00Z",
    "sample_sha256": "a" * 64,
    "tier": "canary",
    "avd_name": "abrg_benign",
    "avd_fingerprint": "test",
    "snapshot_id": None,
    "config_hash": "deadbeef",
    "hooks_version": "3",
    "network_mode": "open",
    "adb_device_serial": "emulator-5554",
    "adb_device_count": 1,
    "outcome": "success",
    "trace_path": None,
    "notes": "gate_p0",
}
try:
    validate_ledger(good)
    print("GOOD_OK")
except Exception as exc:
    print(f"GOOD_FAIL {exc}")
    sys.exit(2)

bad = dict(good)
del bad["sample_sha256"]
try:
    validate_ledger(bad)
    print("BAD_ACCEPTED")
    sys.exit(3)
except LedgerValidationError as exc:
    print(f"BAD_REJECTED {exc}")
PY
)" || true
note "${LEDGER_OUT}"
if echo "${LEDGER_OUT}" | grep -q '^GOOD_OK$' && echo "${LEDGER_OUT}" | grep -q '^BAD_REJECTED'; then
  pass "validate_ledger accepts well-formed record and rejects missing sample_sha256"
else
  fail "validate_ledger behavior incorrect"
fi

# Run pre-commit against a temp index only — never creates a real commit.
run_precommit_on_staged() {
  local relpath="$1"
  local tmp_index
  tmp_index="$(mktemp "${TMPDIR:-/tmp}/gate_p0_index_XXXXXX")"
  export GIT_INDEX_FILE="${tmp_index}"
  git read-tree HEAD
  git add -f "${relpath}"
  set +e
  HOOK_OUT="$("${HOOK}" 2>&1)"
  HOOK_RC=$?
  set -e
  unset GIT_INDEX_FILE
  rm -f "${tmp_index}"
  return 0
}

# --- 5. Pre-commit rejects synthetic APK zip ---
note "--- pre-commit reject synthetic APK zip ---"
TMPDIR_GATE="$(mktemp -d /tmp/gate_p0_XXXXXX)"
SYNTH="${TMPDIR_GATE}/synthetic_payload.bin"
python3 - <<PY
import zipfile
from pathlib import Path
p = Path("${SYNTH}")
with zipfile.ZipFile(p, "w") as zf:
    zf.writestr("AndroidManifest.xml", "<manifest/>")
    zf.writestr("classes.dex", b"dex\n")
print(p, p.stat().st_size)
PY

STAGE_REL="scripts/safety/.gate_p0_synthetic.zip"
cp "${SYNTH}" "${ROOT}/${STAGE_REL}"
run_precommit_on_staged "${STAGE_REL}"
note "reject_hook_rc=${HOOK_RC}"
note "${HOOK_OUT}"
rm -f "${STAGE_REL}"
if [[ "${HOOK_RC}" -ne 0 ]] && echo "${HOOK_OUT}" | grep -qi 'REJECT\|AndroidManifest\|APK\|precommit_no_samples'; then
  pass "pre-commit rejects staged synthetic APK zip"
else
  fail "pre-commit did not reject synthetic APK zip (rc=${HOOK_RC})"
fi

# --- 6. Pre-commit accepts normal source file (hook only; no commit) ---
note "--- pre-commit accept normal source file ---"
ACCEPT_REL="scripts/safety/.gate_p0_accept.txt"
echo "gate_p0 accept probe $(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "${ACCEPT_REL}"
run_precommit_on_staged "${ACCEPT_REL}"
note "accept_hook_rc=${HOOK_RC}"
note "${HOOK_OUT}"
rm -f "${ACCEPT_REL}"
rm -rf "${TMPDIR_GATE}"
if [[ "${HOOK_RC}" -eq 0 ]]; then
  pass "pre-commit accepts a normal source-file commit"
else
  fail "pre-commit blocked a normal source-file commit (rc=${HOOK_RC})"
fi

# --- 7. A1 rename smoke ---
if [[ -d "${HOME}/.android/avd/abrg_benign.avd" && -d "${HOME}/.android/avd/abrg_mw.avd" && ! -d "${HOME}/.android/avd/malware_sandbox.avd" ]]; then
  pass "host AVDs: abrg_benign + abrg_mw present; malware_sandbox absent"
else
  fail "host AVD rename/create incomplete"
fi
if grep -q 'AVD_NAME="${AVD_NAME:-abrg_benign}"' extraction_pipeline/ensure_emulator.sh; then
  pass "ensure_emulator.sh default AVD_NAME=abrg_benign"
else
  fail "ensure_emulator.sh default not updated"
fi

note "=== gate_p0 summary: PASS=${PASS} FAIL=${FAIL} ==="
if [[ "${FAIL}" -ne 0 ]]; then
  exit 1
fi
exit 0
