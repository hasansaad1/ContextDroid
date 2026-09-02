#!/usr/bin/env bash
# Run gates P0–P5 in sequence (plan 5.6). Cold-capable entry; later gates may
# require vault/emulator state as documented per gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

note() { printf '%s\n' "$*"; }

note "=== gate_all start ==="
note "date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

for g in gate_p0 gate_p1 gate_p2 gate_p3 gate_p4 gate_p5; do
  note "--- ${g} ---"
  if ! bash "${ROOT}/scripts/safety/${g}.sh"; then
    note "=== gate_all FAIL at ${g} ==="
    exit 1
  fi
done

note "=== gate_all PASS ==="
exit 0
