#!/usr/bin/env bash
# Guest iptables / ip6tables rules for Phase 4 Option C sink.
# Original-dst evidence: /proc/net/nf_conntrack (NOT NFLOG — rejected).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ADB_BIN="${ADB_BIN:-adb}"
SERIAL="${ANDROID_SERIAL:-emulator-5556}"

# Host-side listener ports (guest DNATs standard ports onto these via 10.0.2.2).
DNS_HOST_PORT="${ABRG_SINK_DNS_PORT:-15353}"
HTTP_HOST_PORT="${ABRG_SINK_HTTP_PORT:-8080}"
HTTPS_HOST_PORT="${ABRG_SINK_HTTPS_PORT:-8443}"
# Catch-all UDP (any non-53 dport) → host UDP sink. TCP catch-all → HTTP_HOST_PORT.
UDP_CATCHALL_PORT="${ABRG_SINK_UDP_CATCHALL_PORT:-8053}"

# Set by cmd_install after probing; expected_nat_pin includes -j DROP when workable.
# Persisted so verify/watchdog match the *intended* pin (not live-derived — that would
# mask DROP drift as "filter fallback mode").
NAT_DROP_OK="${ABRG_NAT_DROP_OK:-1}"
PIN_STATE_FILE="${ABRG_PIN_STATE_FILE:-/tmp/abrg_sink_pin_${SERIAL}.env}"

log() { printf '[guest_sink_rules] %s\n' "$*" >&2; }

load_pin_state() {
  if [[ -f "${PIN_STATE_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${PIN_STATE_FILE}"
    NAT_DROP_OK="${ABRG_NAT_DROP_OK:-${NAT_DROP_OK}}"
  fi
}

save_pin_state() {
  umask 077
  cat > "${PIN_STATE_FILE}" <<EOF
ABRG_NAT_DROP_OK=${NAT_DROP_OK}
ABRG_SINK_UDP_CATCHALL_PORT=${UDP_CATCHALL_PORT}
ABRG_SINK_DNS_PORT=${DNS_HOST_PORT}
ABRG_SINK_HTTP_PORT=${HTTP_HOST_PORT}
ABRG_SINK_HTTPS_PORT=${HTTPS_HOST_PORT}
EOF
}

adbsh() {
  "${ADB_BIN}" -s "${SERIAL}" shell "$@"
}

# Exact pin Gate B matches (must stay byte-stable with iptables v1.6.1 -S).
# Order: RETURN lo / 10.0.2.2 → specific DNATs → catch-all TCP/UDP → default DROP.
expected_nat_pin() {
  load_pin_state
  cat <<EOF
-N ABRG_SINK
-A ABRG_SINK -d 127.0.0.0/8 -j RETURN
-A ABRG_SINK -d 10.0.2.2/32 -j RETURN
-A ABRG_SINK -p udp -m udp --dport 53 -j DNAT --to-destination 10.0.2.2:${DNS_HOST_PORT}
-A ABRG_SINK -p tcp -m tcp --dport 53 -j DNAT --to-destination 10.0.2.2:${DNS_HOST_PORT}
-A ABRG_SINK -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.2.2:${HTTP_HOST_PORT}
-A ABRG_SINK -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.2.2:${HTTPS_HOST_PORT}
-A ABRG_SINK -p tcp -j DNAT --to-destination 10.0.2.2:${HTTP_HOST_PORT}
-A ABRG_SINK -p udp -j DNAT --to-destination 10.0.2.2:${UDP_CATCHALL_PORT}
EOF
  if [[ "${NAT_DROP_OK}" == "1" ]]; then
    printf '%s\n' '-A ABRG_SINK -j DROP'
  fi
}

# When nat DROP is rejected, filter pin adds fail-closed non-sink egress DROP.
expected_filter_pin() {
  load_pin_state
  if [[ "${NAT_DROP_OK}" == "1" ]]; then
    cat <<'EOF'
-N ABRG_SINK_FILTER
-A ABRG_SINK_FILTER -p icmp -j DROP
EOF
  else
    cat <<'EOF'
-N ABRG_SINK_FILTER
-A ABRG_SINK_FILTER -p icmp -j DROP
-A ABRG_SINK_FILTER -d 127.0.0.0/8 -j RETURN
-A ABRG_SINK_FILTER -d 10.0.2.2/32 -j RETURN
-A ABRG_SINK_FILTER -j DROP
EOF
  fi
}

# Probe whether -j DROP is accepted in the nat table on this guest image.
probe_nat_drop() {
  local out
  out="$(adbsh 'iptables -t nat -N ABRG_NAT_DROP_PROBE 2>/dev/null || iptables -t nat -F ABRG_NAT_DROP_PROBE
if iptables -t nat -A ABRG_NAT_DROP_PROBE -j DROP 2>/dev/null; then
  echo NAT_DROP_OK
else
  echo NAT_DROP_REJECT
fi
iptables -t nat -F ABRG_NAT_DROP_PROBE 2>/dev/null || true
iptables -t nat -X ABRG_NAT_DROP_PROBE 2>/dev/null || true
true' 2>/dev/null | tr -d '\r' || true)"
  if printf '%s\n' "${out}" | grep -q 'NAT_DROP_OK'; then
    NAT_DROP_OK=1
    log "nat DROP probe: accepted"
  else
    NAT_DROP_OK=0
    log "nat DROP probe: REJECTED — using filter fail-closed DROP for non-sink egress"
  fi
  save_pin_state
}

expected_v6_pin() {
  cat <<'EOF'
-N ABRG_V6_EGRESS
-A ABRG_V6_EGRESS -o lo -j RETURN
-A ABRG_V6_EGRESS -j DROP
EOF
}

cmd_teardown() {
  adbsh 'iptables -t nat -D OUTPUT -j ABRG_SINK 2>/dev/null || true
iptables -t filter -D OUTPUT -j ABRG_SINK_FILTER 2>/dev/null || true
ip6tables -t filter -D OUTPUT -j ABRG_V6_EGRESS 2>/dev/null || true
iptables -t nat -F ABRG_SINK 2>/dev/null || true
iptables -t nat -X ABRG_SINK 2>/dev/null || true
iptables -t filter -F ABRG_SINK_FILTER 2>/dev/null || true
iptables -t filter -X ABRG_SINK_FILTER 2>/dev/null || true
ip6tables -t filter -F ABRG_V6_EGRESS 2>/dev/null || true
ip6tables -t filter -X ABRG_V6_EGRESS 2>/dev/null || true
true' >/dev/null
  log "teardown done on ${SERIAL}"
}

cmd_install() {
  # Ensure rooted
  local idout
  idout="$(adbsh id | tr -d '\r')"
  if [[ "${idout}" != *uid=0* ]]; then
    "${ADB_BIN}" -s "${SERIAL}" root >/dev/null
    sleep 2
    "${ADB_BIN}" -s "${SERIAL}" wait-for-device
    idout="$(adbsh id | tr -d '\r')"
    if [[ "${idout}" != *uid=0* ]]; then
      log "fail-closed: not root on ${SERIAL}: ${idout}"
      exit 1
    fi
  fi

  cmd_teardown

  # Disable Private DNS (DoT) so UDP/53 DNAT is the resolution path.
  adbsh 'settings put global private_dns_mode off' >/dev/null || true

  probe_nat_drop

  # Build install script: specifics → catch-all TCP/UDP → optional nat DROP.
  local nat_drop_line="" filter_extra=""
  if [[ "${NAT_DROP_OK}" == "1" ]]; then
    nat_drop_line="iptables -t nat -A ABRG_SINK -j DROP"
  else
    filter_extra="iptables -t filter -A ABRG_SINK_FILTER -d 127.0.0.0/8 -j RETURN
iptables -t filter -A ABRG_SINK_FILTER -d 10.0.2.2/32 -j RETURN
iptables -t filter -A ABRG_SINK_FILTER -j DROP"
  fi

  adbsh "iptables -t nat -N ABRG_SINK
iptables -t nat -A ABRG_SINK -d 127.0.0.0/8 -j RETURN
iptables -t nat -A ABRG_SINK -d 10.0.2.2/32 -j RETURN
iptables -t nat -A ABRG_SINK -p udp -m udp --dport 53 -j DNAT --to-destination 10.0.2.2:${DNS_HOST_PORT}
iptables -t nat -A ABRG_SINK -p tcp -m tcp --dport 53 -j DNAT --to-destination 10.0.2.2:${DNS_HOST_PORT}
iptables -t nat -A ABRG_SINK -p tcp -m tcp --dport 80 -j DNAT --to-destination 10.0.2.2:${HTTP_HOST_PORT}
iptables -t nat -A ABRG_SINK -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.0.2.2:${HTTPS_HOST_PORT}
iptables -t nat -A ABRG_SINK -p tcp -j DNAT --to-destination 10.0.2.2:${HTTP_HOST_PORT}
iptables -t nat -A ABRG_SINK -p udp -j DNAT --to-destination 10.0.2.2:${UDP_CATCHALL_PORT}
${nat_drop_line}
iptables -t nat -I OUTPUT 1 -j ABRG_SINK

iptables -t filter -N ABRG_SINK_FILTER
iptables -t filter -A ABRG_SINK_FILTER -p icmp -j DROP
${filter_extra}
iptables -t filter -I OUTPUT 1 -j ABRG_SINK_FILTER

ip6tables -t filter -N ABRG_V6_EGRESS
ip6tables -t filter -A ABRG_V6_EGRESS -o lo -j RETURN
ip6tables -t filter -A ABRG_V6_EGRESS -j DROP
ip6tables -t filter -I OUTPUT 1 -j ABRG_V6_EGRESS
" >/dev/null

  cmd_verify
  log "install ok on ${SERIAL} (nat_drop=${NAT_DROP_OK} udp_catchall=${UDP_CATCHALL_PORT})"
}

cmd_show() {
  echo "===== nat ABRG_SINK ====="
  adbsh 'iptables -t nat -S ABRG_SINK' | tr -d '\r'
  echo "===== filter ABRG_SINK_FILTER ====="
  adbsh 'iptables -t filter -S ABRG_SINK_FILTER' | tr -d '\r'
  echo "===== filter ABRG_V6_EGRESS ====="
  adbsh 'ip6tables -t filter -S ABRG_V6_EGRESS' | tr -d '\r'
  echo "===== OUTPUT jumps ====="
  adbsh 'iptables -t nat -S OUTPUT; iptables -t filter -S OUTPUT; ip6tables -t filter -S OUTPUT' | tr -d '\r' | head -20
}

cmd_verify() {
  local got exp
  got="$(adbsh 'iptables -t nat -S ABRG_SINK' | tr -d '\r')"
  exp="$(expected_nat_pin)"
  if [[ "${got}" != "${exp}" ]]; then
    log "FAIL nat pin mismatch"
    printf 'GOT:\n%s\nWANTED:\n%s\n' "${got}" "${exp}" >&2
    exit 1
  fi
  got="$(adbsh 'iptables -t filter -S ABRG_SINK_FILTER' | tr -d '\r')"
  exp="$(expected_filter_pin)"
  if [[ "${got}" != "${exp}" ]]; then
    log "FAIL filter pin mismatch"
    printf 'GOT:\n%s\nWANTED:\n%s\n' "${got}" "${exp}" >&2
    exit 1
  fi
  got="$(adbsh 'ip6tables -t filter -S ABRG_V6_EGRESS' | tr -d '\r')"
  exp="$(expected_v6_pin)"
  if [[ "${got}" != "${exp}" ]]; then
    log "FAIL v6 pin mismatch"
    printf 'GOT:\n%s\nWANTED:\n%s\n' "${got}" "${exp}" >&2
    exit 1
  fi
  local nat_out filt_out v6_out
  nat_out="$(adbsh 'iptables -t nat -S OUTPUT' | tr -d '\r')"
  filt_out="$(adbsh 'iptables -t filter -S OUTPUT' | tr -d '\r')"
  v6_out="$(adbsh 'ip6tables -t filter -S OUTPUT' | tr -d '\r')"
  if ! printf '%s\n' "${nat_out}" | grep -q -- '-j ABRG_SINK'; then
    log "FAIL missing nat OUTPUT -> ABRG_SINK"
    exit 1
  fi
  if ! printf '%s\n' "${nat_out}" | head -1 | grep -q 'ABRG_SINK\|^-P'; then
    :
  fi
  # First jump in OUTPUT should be ABRG_SINK (after -P line).
  if ! printf '%s\n' "${nat_out}" | grep -E '^-A OUTPUT' | head -1 | grep -q -- '-j ABRG_SINK'; then
    log "FAIL ABRG_SINK is not first nat OUTPUT rule"
    printf '%s\n' "${nat_out}" >&2
    exit 1
  fi
  if ! printf '%s\n' "${filt_out}" | grep -E '^-A OUTPUT' | head -1 | grep -q -- '-j ABRG_SINK_FILTER'; then
    log "FAIL ABRG_SINK_FILTER is not first filter OUTPUT rule"
    exit 1
  fi
  if ! printf '%s\n' "${v6_out}" | grep -E '^-A OUTPUT' | head -1 | grep -q -- '-j ABRG_V6_EGRESS'; then
    log "FAIL ABRG_V6_EGRESS is not first ip6 filter OUTPUT rule"
    exit 1
  fi
  echo "VERIFY_OK"
}

cmd_pin() {
  expected_nat_pin
}

usage() {
  cat <<EOF
Usage: ANDROID_SERIAL=emulator-5556 $0 {install|teardown|show|verify|pin}
EOF
}

main() {
  local cmd="${1:-}"
  case "${cmd}" in
    install) cmd_install ;;
    teardown) cmd_teardown ;;
    show) cmd_show ;;
    verify) cmd_verify ;;
    pin) cmd_pin ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
