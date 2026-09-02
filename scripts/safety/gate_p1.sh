#!/usr/bin/env bash
# Gate P1 — encrypted vault mount, quarantine seal/unseal, path hygiene.
# Cold start: vault must be unmounted at entry.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

PASS=0
FAIL=0
note() { printf '%s\n' "$*"; }
pass() { note "[PASS] $*"; PASS=$((PASS + 1)); }
fail() { note "[FAIL] $*"; FAIL=$((FAIL + 1)); }

VAULT_SH="${ROOT}/scripts/safety/vault.sh"
QUARANTINE_PY="${ROOT}/scripts/safety/quarantine.py"
KEYCHAIN_SERVICE="ABRG_MW_VAULT"
SPARSE="${HOME}/Vaults/abrg_mw.sparsebundle"

read_mount_root() {
  python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety.vault_paths import MOUNT_ROOT, STAGING_DIR, QUARANTINE_DIR
print(MOUNT_ROOT)
print(STAGING_DIR)
print(QUARANTINE_DIR)
PY
}

MOUNT_ROOT=""
STAGING_DIR=""
QUARANTINE_DIR=""
while IFS= read -r line; do
  if [[ -z "${MOUNT_ROOT}" ]]; then MOUNT_ROOT="${line}"
  elif [[ -z "${STAGING_DIR}" ]]; then STAGING_DIR="${line}"
  else QUARANTINE_DIR="${line}"; fi
done < <(read_mount_root)

note "=== gate_p1 cold start ==="
note "ROOT=${ROOT}"
note "date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# --- P0 still green ---
note "--- gate_p0 (prerequisite) ---"
if bash "${ROOT}/scripts/safety/gate_p0.sh"; then
  pass "gate_p0 prerequisite green"
else
  fail "gate_p0 prerequisite failed"
  note "=== gate_p1 summary: PASS=${PASS} FAIL=${FAIL} ==="
  exit 1
fi

# --- Entry: vault unmounted ---
note "--- vault must start unmounted ---"
if mount | grep -F " on ${MOUNT_ROOT} " >/dev/null 2>&1; then
  fail "vault already mounted at start — unmount before cold gate_p1"
  note "=== gate_p1 summary: PASS=${PASS} FAIL=${FAIL} ==="
  exit 1
fi
pass "vault unmounted at gate_p1 entry"

# --- Ensure sparse bundle + keychain (no password in repo) ---
if [[ ! -e "${SPARSE}" ]]; then
  note "--- creating vault sparse bundle (first run) ---"
  if ! security find-generic-password -a "${USER}" -s "${KEYCHAIN_SERVICE}" >/dev/null 2>&1; then
    VAULT_PASS="$(openssl rand -base64 32)"
    security add-generic-password -a "${USER}" -s "${KEYCHAIN_SERVICE}" -w "${VAULT_PASS}" -U
    note "stored vault password in Keychain service ${KEYCHAIN_SERVICE}"
    unset VAULT_PASS
  fi
  bash "${VAULT_SH}" init
  pass "vault sparse bundle created at ${SPARSE}"
else
  pass "vault sparse bundle exists"
fi

# Sync exclusion check (recorded in SAFETY.md; enforced here)
SYNC_OUT="$(python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety.vault_paths import SPARSE_BUNDLE, sparse_bundle_under_sync_root
print(SPARSE_BUNDLE)
print("under_sync_root=", sparse_bundle_under_sync_root())
PY
)"
note "${SYNC_OUT}"
if echo "${SYNC_OUT}" | grep -q 'under_sync_root= True'; then
  fail "sparse bundle resolves under a sync-managed root"
else
  pass "sparse bundle not under known sync roots"
fi

# --- Mount / status / layout ---
note "--- mount ---"
bash "${VAULT_SH}" mount
STATUS_MOUNTED="$(bash "${VAULT_SH}" status)"
note "${STATUS_MOUNTED}"
if echo "${STATUS_MOUNTED}" | grep -q '^mounted '; then
  pass "vault mounts cleanly; status reports mounted"
else
  fail "vault mount/status failed"
fi

# --- assert_mounted when mounted ---
if bash "${VAULT_SH}" assert_mounted; then
  pass "assert_mounted succeeds while mounted"
else
  fail "assert_mounted failed while mounted"
fi

# --- assert_mounted fails when unmounted ---
bash "${VAULT_SH}" unmount
STATUS_UNMOUNTED="$(bash "${VAULT_SH}" status)"
note "${STATUS_UNMOUNTED}"
if echo "${STATUS_UNMOUNTED}" | grep -q '^unmounted'; then
  pass "vault unmounts cleanly; status reports unmounted"
else
  fail "vault unmount/status failed"
fi
set +e
ASSERT_OUT="$(bash "${VAULT_SH}" assert_mounted 2>&1)"
ASSERT_RC=$?
set -e
note "assert_mounted_rc=${ASSERT_RC}"
note "${ASSERT_OUT}"
if [[ "${ASSERT_RC}" -ne 0 ]]; then
  pass "assert_mounted fails fast when unmounted"
else
  fail "assert_mounted should fail when unmounted"
fi

# --- Remount for seal/unseal proof (benign APK only) ---
bash "${VAULT_SH}" mount

BENIGN_APK="$(find "${ROOT}/data/apks/benign" -name '*.apk' -type f 2>/dev/null | head -n 1 || true)"
if [[ -z "${BENIGN_APK}" ]]; then
  fail "no benign APK found under data/apks/benign/"
  bash "${VAULT_SH}" unmount
  note "=== gate_p1 summary: PASS=${PASS} FAIL=${FAIL} ==="
  exit 1
fi
note "benign_seal_apk=${BENIGN_APK}"

ORIG_SHA="$(shasum -a 256 "${BENIGN_APK}" | awk '{print $1}')"
note "orig_sha256=${ORIG_SHA}"

# Copy into staging then seal (proves staging cleanup)
STAGING_APK="${MOUNT_ROOT}/staging/gate_p1_benign.apk"
cp "${BENIGN_APK}" "${STAGING_APK}"
SEAL_OUT="$(python3 "${QUARANTINE_PY}" seal "${STAGING_APK}")"
note "sealed_archive=${SEAL_OUT}"
if [[ -f "${SEAL_OUT}" && "${SEAL_OUT}" == "${MOUNT_ROOT}/quarantine/${ORIG_SHA}.7z" ]]; then
  pass "seal() produced quarantine/${ORIG_SHA}.7z"
else
  fail "seal() archive path wrong or missing"
fi
if [[ -f "${STAGING_APK}" ]]; then
  fail "raw APK still present in staging after seal"
else
  pass "raw APK removed from staging after seal"
fi

UNSEAL_DEST="${MOUNT_ROOT}/staging/gate_p1_restored.apk"
UNSEAL_OUT="$(python3 "${QUARANTINE_PY}" unseal "${ORIG_SHA}" "${UNSEAL_DEST}")"
note "unsealed_path=${UNSEAL_OUT}"
REST_SHA="$(shasum -a 256 "${UNSEAL_OUT}" | awk '{print $1}')"
note "rest_sha256=${REST_SHA}"
if [[ "${REST_SHA}" == "${ORIG_SHA}" ]]; then
  pass "unseal() reproduces identical SHA256"
else
  fail "unseal() SHA256 mismatch"
fi
rm -f "${UNSEAL_OUT}"

# unseal refuses destination outside staging
set +e
BAD_UNSEAL="$(python3 "${QUARANTINE_PY}" unseal "${ORIG_SHA}" /tmp/gate_p1_bad.apk 2>&1)"
BAD_RC=$?
set -e
note "bad_unseal_rc=${BAD_RC}"
note "${BAD_UNSEAL}"
if [[ "${BAD_RC}" -ne 0 ]] && echo "${BAD_UNSEAL}" | grep -qi 'outside staging\|refusing'; then
  pass "unseal() refuses destination outside staging/"
else
  fail "unseal() did not refuse outside staging"
fi

# --- Grep: no /Volumes/ outside vault_paths.py ---
note "--- grep /Volumes/ literals ---"
RG_OUT="$(rg -n '/Volumes/' "${ROOT}" \
  --glob '!logs/**' --glob '!experiment/**' --glob '!docs/**' --glob '!.cursor/**' \
  --glob '!scripts/safety/gate_p1.sh' \
  --glob '!SAFETY.md' \
  --glob '!extraction_pipeline/safety/vault_paths.py' 2>/dev/null || true)"
if [[ -z "${RG_OUT}" ]]; then
  pass "no /Volumes/ literal outside vault_paths.py"
else
  note "${RG_OUT}"
  fail "/Volumes/ literal found outside vault_paths.py"
fi

# --- staging empty at exit ---
find "${MOUNT_ROOT}/staging" -mindepth 1 -maxdepth 1 -print -delete 2>/dev/null || true
STAGING_LEFT="$(find "${MOUNT_ROOT}/staging" -mindepth 1 2>/dev/null | head -n 5 || true)"
if [[ -z "${STAGING_LEFT}" ]]; then
  pass "staging/ empty at gate exit"
else
  note "${STAGING_LEFT}"
  fail "staging/ not empty at gate exit"
fi

bash "${VAULT_SH}" unmount
FINAL_STATUS="$(bash "${VAULT_SH}" status)"
note "${FINAL_STATUS}"

note "=== gate_p1 summary: PASS=${PASS} FAIL=${FAIL} ==="
if [[ "${FAIL}" -ne 0 ]]; then
  exit 1
fi
exit 0
