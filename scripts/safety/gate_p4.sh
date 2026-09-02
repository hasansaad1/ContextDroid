#!/usr/bin/env bash
# Gate P4 — Option C custom sink + guest iptables + nf_conntrack original-dst.
# Benign probes only. Fail closed. No malware samples.
# Containment: specific DNATs + catch-all TCP/UDP + default DROP (gap fix).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT}"

PASS=0
FAIL=0
note() { printf '%s\n' "$*"; }
pass() { note "[PASS] $*"; PASS=$((PASS + 1)); }
fail() { note "[FAIL] $*"; FAIL=$((FAIL + 1)); }

ADB_BIN="${ADB_BIN:-${ROOT}/tools/platform-tools/adb}"
[[ -x "${ADB_BIN}" ]] || ADB_BIN="${HOME}/Library/Android/sdk/platform-tools/adb"
export ADB_BIN
MW_SERIAL="${MW_SERIAL:-emulator-5556}"
export ANDROID_SERIAL="${MW_SERIAL}"
RUN_ID="${ABRG_RUN_ID:-gatep4-$(date -u +%Y%m%dT%H%M%SZ)}"
DNS_HOST_PORT="${ABRG_SINK_DNS_PORT:-15353}"
HTTP_HOST_PORT="${ABRG_SINK_HTTP_PORT:-8080}"
UDP_CATCHALL_PORT="${ABRG_SINK_UDP_CATCHALL_PORT:-8053}"
WATCHDOG_INTERVAL="${ABRG_SINK_WATCHDOG_INTERVAL:-15}"
export ABRG_SINK_DNS_PORT="${DNS_HOST_PORT}"
export ABRG_SINK_HTTP_PORT="${HTTP_HOST_PORT}"
export ABRG_SINK_UDP_CATCHALL_PORT="${UDP_CATCHALL_PORT}"
export ABRG_SINK_WATCHDOG_INTERVAL="${WATCHDOG_INTERVAL}"

MARKER_HTTP="CONTEXTDROID_SINK_HTTP_MARKER"

note "=== gate_p4 start ==="
note "ROOT=${ROOT}"
note "date_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
note "run_id=${RUN_ID}"
note "mechanism=nf_conntrack (NFLOG rejected)"
note "catchall=tcp→${HTTP_HOST_PORT} udp→${UDP_CATCHALL_PORT} + default DROP"

cleanup() {
  bash "${ROOT}/scripts/safety/sink_rule_watchdog.sh" stop --run-id "${RUN_ID}" >/dev/null 2>&1 || true
  bash "${ROOT}/scripts/safety/guest_sink_rules.sh" teardown >/dev/null 2>&1 || true
  bash "${ROOT}/scripts/safety/network_sink.sh" stop --run-id "${RUN_ID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- Vault ---
if ! bash "${ROOT}/scripts/safety/vault.sh" status 2>/dev/null | grep -q '^mounted'; then
  if ! bash "${ROOT}/scripts/safety/vault.sh" mount; then
    fail "vault mount"
    note "=== gate_p4 summary: PASS=${PASS} FAIL=${FAIL} ==="
    exit 1
  fi
fi
pass "vault mounted"

SINK_DIR="$(python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, str(Path("extraction_pipeline").resolve()))
from safety.vault_paths import assert_mounted, ensure_layout, MOUNT_ROOT
assert_mounted(); ensure_layout()
print(MOUNT_ROOT / "logs" / "sink")
PY
)"
JSONL="${SINK_DIR}/${RUN_ID}.jsonl"
ENV_FILE="${SINK_DIR}/${RUN_ID}.env"
ABORT_FLAG="${SINK_DIR}/${RUN_ID}.abort"
WD_JSONL="${SINK_DIR}/${RUN_ID}.watchdog.jsonl"

# --- Refuse without sink ---
if bash "${ROOT}/scripts/safety/avd_session.sh" refuse-demo; then
  pass "avd_session refuses launch without run-id/Gate A"
else
  fail "avd_session refuse-demo"
fi

# --- Start sink + Gate A ---
if bash "${ROOT}/scripts/safety/network_sink.sh" start --run-id "${RUN_ID}"; then
  pass "network_sink start + Gate A"
else
  fail "network_sink start / Gate A"
  note "=== gate_p4 summary: PASS=${PASS} FAIL=${FAIL} ==="
  exit 1
fi

# shellcheck disable=SC1090
source "${ENV_FILE}"
note "nonce=${ABRG_SINK_NONCE}"

# Live Gate A again
if bash "${ROOT}/scripts/safety/network_sink.sh" gate-a --run-id "${RUN_ID}"; then
  pass "Gate A functional health (/__abrg_health + marker + nonce)"
else
  fail "Gate A"
fi

# --- Emulator: ensure abrg_mw online (cold gate_all leaves P3 with mw killed) ---
if ! "${ADB_BIN}" -s "${MW_SERIAL}" get-state 2>/dev/null | grep -q device; then
  note "abrg_mw offline — launching via avd_session after Gate A (cold-start path)"
  export AVD_NAME="${AVD_NAME:-abrg_mw}"
  if ! bash "${ROOT}/scripts/safety/avd_session.sh" launch --run-id "${RUN_ID}"; then
    fail "avd_session launch abrg_mw after Gate A"
    note "=== gate_p4 summary: PASS=${PASS} FAIL=${FAIL} ==="
    exit 1
  fi
  "${ADB_BIN}" -s "${MW_SERIAL}" wait-for-device
  boot_ok=0
  for _i in $(seq 1 240); do
    boot="$("${ADB_BIN}" -s "${MW_SERIAL}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
    if [[ "${boot}" == "1" ]]; then
      boot_ok=1
      break
    fi
    sleep 1
  done
  if [[ "${boot_ok}" -ne 1 ]]; then
    fail "abrg_mw boot timed out after avd_session launch"
    note "=== gate_p4 summary: PASS=${PASS} FAIL=${FAIL} ==="
    exit 1
  fi
  pass "abrg_mw launched cold via avd_session (Gate A required)"
fi
"${ADB_BIN}" -s "${MW_SERIAL}" root >/dev/null || true
sleep 2
"${ADB_BIN}" -s "${MW_SERIAL}" wait-for-device
pass "emulator ${MW_SERIAL} online + root"

# --- Guest rules ---
if bash "${ROOT}/scripts/safety/guest_sink_rules.sh" install; then
  pass "guest_sink_rules install + pin verify"
else
  fail "guest_sink_rules install"
  note "=== gate_p4 summary: PASS=${PASS} FAIL=${FAIL} ==="
  exit 1
fi

# Exact pin dump — FAIL if catch-all missing
note "===== pinned iptables -t nat -S ABRG_SINK ====="
NAT_PIN="$("${ADB_BIN}" -s "${MW_SERIAL}" shell 'iptables -t nat -S ABRG_SINK' | tr -d '\r')"
printf '%s\n' "${NAT_PIN}"
if ! printf '%s\n' "${NAT_PIN}" | grep -qE -- "-A ABRG_SINK -p tcp -j DNAT --to-destination 10\.0\.2\.2:${HTTP_HOST_PORT}"; then
  fail "catch-all TCP DNAT ABSENT from ABRG_SINK pin"
elif ! printf '%s\n' "${NAT_PIN}" | grep -qE -- "-A ABRG_SINK -p udp -j DNAT --to-destination 10\.0\.2\.2:${UDP_CATCHALL_PORT}"; then
  fail "catch-all UDP DNAT ABSENT from ABRG_SINK pin"
elif ! printf '%s\n' "${NAT_PIN}" | grep -qx -- '-A ABRG_SINK -j DROP'; then
  # Allow filter-fallback mode only if pin state says so
  # shellcheck disable=SC1090
  source "/tmp/abrg_sink_pin_${MW_SERIAL}.env" 2>/dev/null || true
  if [[ "${ABRG_NAT_DROP_OK:-1}" == "1" ]]; then
    fail "default nat DROP ABSENT from ABRG_SINK pin"
  else
    pass "nat DROP absent (documented filter fallback); catch-all DNATs present"
  fi
else
  pass "catch-all TCP/UDP + default DROP present in ABRG_SINK pin"
fi

# --- Gate B probes ---
RAND_DOM="gateb-$(openssl rand -hex 8).invalid"
note "RAND_DOM=${RAND_DOM}"

# Probe 1: DNS → 192.0.2.1 (ping prints resolved IP even when ICMP is dropped)
DNS_OUT="$("${ADB_BIN}" -s "${MW_SERIAL}" shell "ping -c 1 -W 3 ${RAND_DOM}" 2>&1 | tr -d '\r' || true)"
note "DNS_OUT=${DNS_OUT}"
if printf '%s\n' "${DNS_OUT}" | grep -qE "${RAND_DOM} \(192\.0\.2\.1\)"; then
  pass "Gate B DNS resolves ${RAND_DOM} → 192.0.2.1"
else
  fail "Gate B DNS did not resolve to 192.0.2.1"
fi

# Probe 2: HTTP marker + nonce via hostname (resolves to 192.0.2.1, DNAT to sink)
HTTP_RAW="$("${ADB_BIN}" -s "${MW_SERIAL}" shell \
  "printf 'GET /__abrg_gateb HTTP/1.0\\r\\nHost: ${RAND_DOM}\\r\\n\\r\\n' | toybox nc -w 5 ${RAND_DOM} 80" \
  2>&1 | tr -d '\r' || true)"
note "HTTP_RAW_HEAD=$(printf '%s\n' "${HTTP_RAW}" | head -15)"
if printf '%s\n' "${HTTP_RAW}" | grep -q "${MARKER_HTTP}" \
  && printf '%s\n' "${HTTP_RAW}" | grep -q "${ABRG_SINK_NONCE}" \
  && printf '%s\n' "${HTTP_RAW}" | grep -qiE 'X-CONTEXTDROID-SINK:[[:space:]]*1'; then
  pass "Gate B HTTP marker + nonce + X-CONTEXTDROID-SINK"
else
  fail "Gate B HTTP marker/nonce/header"
fi

# Probe 3: direct IP 1.2.3.4:80 + nf_conntrack original dst
DIRECT_RAW="$("${ADB_BIN}" -s "${MW_SERIAL}" shell \
  "printf 'GET /__abrg_direct_ip HTTP/1.0\\r\\nHost: 1.2.3.4\\r\\n\\r\\n' | toybox nc -w 5 1.2.3.4 80" \
  2>&1 | tr -d '\r' || true)"
note "DIRECT_RAW_HEAD=$(printf '%s\n' "${DIRECT_RAW}" | head -12)"
CT_LINE="$("${ADB_BIN}" -s "${MW_SERIAL}" shell \
  "grep -E 'dst=1\\.2\\.3\\.4 .*dport=80' /proc/net/nf_conntrack | head -1" \
  2>&1 | tr -d '\r' || true)"
note "CONNTRACK_LINE=${CT_LINE}"
if printf '%s\n' "${DIRECT_RAW}" | grep -q "${MARKER_HTTP}" \
  && printf '%s\n' "${CT_LINE}" | grep -q 'dst=1.2.3.4' \
  && printf '%s\n' "${CT_LINE}" | grep -q 'dport=80'; then
  pass "Gate B direct-IP sunk + nf_conntrack orig_dst=1.2.3.4:80"
  python3 - <<PY
import json, time
from pathlib import Path
p = Path("${JSONL}")
rec = {
  "ts": time.time(),
  "event": "prednat_original_dst",
  "run_id": "${RUN_ID}",
  "nonce": "${ABRG_SINK_NONCE}",
  "orig_dst": "1.2.3.4",
  "orig_dport": 80,
  "proto": "tcp",
  "mechanism": "nf_conntrack",
  "conntrack_line": """${CT_LINE}""".strip(),
}
with p.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")
PY
else
  fail "Gate B direct-IP / nf_conntrack original dst"
fi

# Probe 4: catch-all non-standard TCP port 1.2.3.4:1337 → host :8080
CATCH_RAW="$("${ADB_BIN}" -s "${MW_SERIAL}" shell \
  "printf 'GET /__abrg_catchall HTTP/1.0\\r\\nHost: 1.2.3.4\\r\\n\\r\\n' | toybox nc -w 5 1.2.3.4 1337" \
  2>&1 | tr -d '\r' || true)"
note "CATCHALL_RAW_HEAD=$(printf '%s\n' "${CATCH_RAW}" | head -12)"
CT_CATCH="$("${ADB_BIN}" -s "${MW_SERIAL}" shell \
  "grep -E 'dst=1\\.2\\.3\\.4 .*dport=1337' /proc/net/nf_conntrack | head -1" \
  2>&1 | tr -d '\r' || true)"
note "CONNTRACK_CATCHALL=${CT_CATCH}"
if printf '%s\n' "${CATCH_RAW}" | grep -q "${MARKER_HTTP}" \
  && printf '%s\n' "${CATCH_RAW}" | grep -q "${ABRG_SINK_NONCE}" \
  && printf '%s\n' "${CT_CATCH}" | grep -q 'dst=1.2.3.4' \
  && printf '%s\n' "${CT_CATCH}" | grep -q 'dport=1337' \
  && printf '%s\n' "${CT_CATCH}" | grep -qE 'sport=8080|src=10\.0\.2\.2'; then
  pass "Gate B catch-all TCP 1.2.3.4:1337 sunk (marker + nf_conntrack DNAT→10.0.2.2:8080)"
  python3 - <<PY
import json, time
from pathlib import Path
p = Path("${JSONL}")
rec = {
  "ts": time.time(),
  "event": "catch_all_hit",
  "run_id": "${RUN_ID}",
  "nonce": "${ABRG_SINK_NONCE}",
  "orig_dst": "1.2.3.4",
  "orig_dport": 1337,
  "proto": "tcp",
  "dnat_to": "10.0.2.2:8080",
  "mechanism": "nf_conntrack",
  "conntrack_line": """${CT_CATCH}""".strip(),
  "escaped_internet": False,
}
with p.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")
PY
else
  fail "Gate B catch-all TCP 1.2.3.4:1337 not sunk / no conntrack DNAT evidence"
fi

# ICMP DROP smoke (external ping should not succeed)
ICMP_OUT="$("${ADB_BIN}" -s "${MW_SERIAL}" shell 'ping -c 1 -W 2 8.8.8.8' 2>&1 | tr -d '\r' || true)"
if printf '%s\n' "${ICMP_OUT}" | grep -qE '1 received|bytes from'; then
  fail "ICMP DROP ineffective: ${ICMP_OUT}"
else
  pass "ICMP DROP (no successful external ping)"
fi

# --- jsonl event classes ---
JSONL_CHECK=0
python3 - <<PY || JSONL_CHECK=1
import json, sys
from pathlib import Path
p = Path("${JSONL}")
seen = set()
dns_ok = http_ok = prednat_ok = catch_ok = False
rand = "${RAND_DOM}"
nonce = "${ABRG_SINK_NONCE}"
run_id = "${RUN_ID}"
for line in p.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    rec = json.loads(line)
    ev = rec.get("event")
    seen.add(ev)
    if ev == "dns_query" and rec.get("qname") == rand and rec.get("answer") == "192.0.2.1" and rec.get("nonce") == nonce and rec.get("run_id") == run_id:
        dns_ok = True
    if ev == "http_fetch" and rec.get("nonce") == nonce and rec.get("run_id") == run_id and rec.get("marker") == "${MARKER_HTTP}":
        host = (rec.get("host") or "")
        path = (rec.get("path") or "")
        if rand in host or rand in (rec.get("url") or "") or "1.2.3.4" in host or path.startswith("/__abrg_"):
            http_ok = True
    if ev == "prednat_original_dst" and rec.get("orig_dst") == "1.2.3.4" and int(rec.get("orig_dport", 0)) == 80 and rec.get("proto") == "tcp":
        prednat_ok = True
    if ev == "catch_all_hit" and rec.get("orig_dst") == "1.2.3.4" and int(rec.get("orig_dport", 0)) == 1337:
        catch_ok = True
    if ev == "tcp_catchall" and rec.get("nonce") == nonce:
        catch_ok = True
print(f"jsonl_events_seen={sorted(seen)}")
print(f"dns_ok={dns_ok} http_ok={http_ok} prednat_ok={prednat_ok} catch_ok={catch_ok}")
sys.exit(0 if (dns_ok and http_ok and prednat_ok and catch_ok) else 1)
PY
if [[ "${JSONL_CHECK}" -eq 0 ]]; then
  pass "jsonl contains dns_query + http_fetch + prednat_original_dst + catch_all_hit"
else
  fail "jsonl missing required event class(es)"
  note "===== jsonl tail ====="
  tail -40 "${JSONL}" || true
fi

# --- Watchdog: first check right after Gate B PASS ---
rm -f "${ABORT_FLAG}"
if bash "${ROOT}/scripts/safety/sink_rule_watchdog.sh" once --run-id "${RUN_ID}" --interval "${WATCHDOG_INTERVAL}"; then
  pass "watchdog first tick (immediate post-Gate-B) ok"
else
  fail "watchdog first tick failed with rules intact"
fi

if bash "${ROOT}/scripts/safety/sink_rule_watchdog.sh" start --run-id "${RUN_ID}" --interval "${WATCHDOG_INTERVAL}"; then
  pass "watchdog started (interval=${WATCHDOG_INTERVAL}s)"
else
  fail "watchdog start"
fi

# Wait for at least one background tick after start (start already did an immediate tick;
# wait interval+2 for a subsequent loop tick).
note "waiting ${WATCHDOG_INTERVAL}+2s for background watchdog tick..."
sleep "$((WATCHDOG_INTERVAL + 2))"
WD_TICKS=0
if [[ -f "${WD_JSONL}" ]]; then
  WD_TICKS="$(grep -c '"event":"watchdog_tick"' "${WD_JSONL}" 2>/dev/null || echo 0)"
fi
note "watchdog_tick_count=${WD_TICKS}"
if [[ "${WD_TICKS}" -ge 2 ]]; then
  pass "watchdog background tick observed (>=2 ticks)"
else
  fail "watchdog background tick not observed (ticks=${WD_TICKS})"
fi

# Deliberate drift → fail-closed (no heal)
note "injecting deliberate nat pin drift (delete catch-all TCP DNAT)..."
"${ADB_BIN}" -s "${MW_SERIAL}" shell \
  "iptables -t nat -D ABRG_SINK -p tcp -j DNAT --to-destination 10.0.2.2:${HTTP_HOST_PORT}" \
  >/dev/null 2>&1 || true
# Immediate once-check must abort
set +e
bash "${ROOT}/scripts/safety/sink_rule_watchdog.sh" once --run-id "${RUN_ID}" --interval "${WATCHDOG_INTERVAL}"
DRIFT_RC=$?
set -e
if [[ "${DRIFT_RC}" -ne 0 ]] && [[ -f "${ABORT_FLAG}" ]]; then
  pass "watchdog fail-closed on deliberate drift (abort flag written)"
  note "===== abort flag ====="
  head -20 "${ABORT_FLAG}" || true
else
  fail "watchdog did not fail-closed on drift (rc=${DRIFT_RC} abort=$([[ -f ${ABORT_FLAG} ]] && echo yes || echo no))"
fi

# Stop watchdog; restore rules for clean teardown path
bash "${ROOT}/scripts/safety/sink_rule_watchdog.sh" stop --run-id "${RUN_ID}" >/dev/null 2>&1 || true
bash "${ROOT}/scripts/safety/guest_sink_rules.sh" install >/dev/null 2>&1 || true
rm -f "${ABORT_FLAG}"

# Sink-down refuse: stop sink, Gate A must fail
bash "${ROOT}/scripts/safety/network_sink.sh" stop --run-id "${RUN_ID}"
if bash "${ROOT}/scripts/safety/network_sink.sh" gate-a --run-id "${RUN_ID}" 2>/dev/null; then
  fail "Gate A unexpectedly passed after sink stop"
else
  pass "Gate A fails closed when sink is down"
fi
# Restart not required; trap cleans guest rules.

note "=== gate_p4 summary: PASS=${PASS} FAIL=${FAIL} ==="
if [[ "${FAIL}" -ne 0 ]]; then
  exit 1
fi
exit 0
