# Phase 4.1 — Network sink options (macOS host)

**Status:** evaluation only — **no sink chosen, nothing implemented.**  
**Audience:** human decision (manager / operator). Implementation of `gate_p4.sh` /
`network_sink.sh` / `avd_session.sh` sink flags is blocked until a choice is recorded.

**Posture (already decided):** simulated network sink. Frida still records connect /
HTTP attempts; nothing from the malware path may reach the public internet.
Full-network and no-network are both rejected (`SAFETY.md`, plan Phase 4).

---

## Host snapshot (diagnostics, 2026-08-05)

Verbatim probe output used for this memo (machine-local paths preserved as
collected evidence; not sanitised):

```
=== uname ===
Darwin Hasans-MacBook-Pro.local 25.3.0 Darwin Kernel Version 25.3.0: Wed Jan 28 20:51:28 PST 2026; root:xnu-12377.91.3~2/RELEASE_ARM64_T6041 arm64
=== docker ===
/usr/local/bin/docker
Docker version 28.5.1, build e180ab8
Cannot connect to the Docker daemon at unix://<HOME>/.docker/run/docker.sock. Is the docker daemon running?
=== dnsmasq ===
dnsmasq: not found
=== mitmproxy ===
mitmproxy: not found
=== python ===
Python 3.14.3
=== brew ===
/opt/homebrew/bin/brew
=== emulator ===
<HOME>/Library/Android/sdk/emulator/emulator
=== avd abrg_mw ===
(present; config: abi.type=arm64-v8a, image android-29/google_apis/arm64-v8a, pixel_2, hw.ramSize=2G)
=== pf ===
pfctl: /dev/pf: Permission denied   # without sudo
sudo: a password is required        # interactive sudo not available to agent
=== bind smoke ===
UDP 5353 bind FAIL [Errno 48] Address already in use
TCP 8080 bind OK
```

Home-directory paths in the block above were redacted to `<HOME>`; the output is otherwise verbatim.

Emulator help confirms `-dns-server` and `-http-proxy` are supported on this SDK.

---

## Repo / emulator constraints (apply to every option)

| Constraint | Implication |
|---|---|
| AVD `abrg_mw` (API 29, google_apis, arm64) | Guest sees host loopback as **`10.0.2.2`**. Launch must eventually use `-dns-server` (and optionally `-http-proxy`) targeting the sink. |
| `avd_session.sh` not built yet | Plan 4.2 will hard-require sink flags + live sink probe before malware AVD launch. Gate must prove refuse-to-launch. |
| Frida `hook_apis.js` | Hooks **`Socket.connect`**, **`HttpURLConnection.connect`**, **`URL.openConnection`**, OkHttp/Retrofit. **No dedicated `InetAddress` / DNS hook today.** Containment proof for DNS is sink resolution + sink logs (Gate P4), not a Frida DNS event. Connect/HTTP behavioral signal still fires whether the peer is real or sunk. |
| Vault | Sink logs → `/Volumes/ABRG_MW/logs/sink/` keyed by `run_id` (layout already reserved). |
| Fail-closed | No silent passthrough; no `\|\| true`; sink-down must block malware-path launch. |
| Phase 4.3 host firewall | `pfctl` needs sudo on this Mac. Treat as defense-in-depth; if unreliable, document residual risk in `SAFETY.md` rather than fake coverage. |
| macOS port 53 | Binding DNS on `:53` typically needs root and may fight system resolver / mDNSResponder. Prefer Docker-published 53, or document an explicit privileged-bind / redirect strategy. |
| Direct-IP egress | Gate must sink or block raw-IP connects (malware bypassing DNS). DNS-only catch-all is insufficient alone. |

---

## Option A — INetSim in Docker

**Idea:** Run INetSim (Linux) in a container; publish DNS/HTTP(S)/common ports to the host; point emulator `-dns-server` at `10.0.2.2` (mapped to container).

| Pros | Cons |
|---|---|
| Broad protocol stubs (DNS, HTTP/S, FTP, SMTP, …) — closer to “answers something” for diverse malware | **Docker Desktop dependency**; CLI present but **daemon was not running** at probe time |
| Easy wipe/reset of container state | Image/arch: host is **arm64**; need a working arm64 or emulated amd64 image |
| Community-known malware-analysis sink | Marker strings / headers must be **configured** (INetSim defaults are not `CONTEXTDROID_SINK_*`) |
| Isolates sink from host Python env | Port publish + `10.0.2.2` routing must be validated; Docker Desktop VM networking quirks on macOS |
| | Heavier ops (start Desktop before every malware session) |

**Fit to Gate P4:** Strong for DNS + HTTP markers if configured; direct-IP still needs published listeners on those ports or a firewall backstop.

---

## Option B — dnsmasq + mitmproxy

**Idea:** `dnsmasq` catch-all A → sink/host IP; `mitmproxy` (or `mitmdump`) addon returns canned bodies/headers with markers; emulator uses `-dns-server` and/or `-http-proxy`.

| Pros | Cons |
|---|---|
| Flexible HTTP/HTTPS canned responses and logging | **Neither tool installed** (`dnsmasq` / `mitmproxy` missing; brew can install) |
| TLS inspection possible when desired | **Cert pinning** and non-HTTP protocols fail or bypass proxy |
| Clear separation: DNS vs L7 | macOS **:53 privilege / conflict** for dnsmasq |
| | `-http-proxy` only covers proxy-aware paths; raw sockets / hardcoded IPs need separate listeners or pf |
| | More moving parts to keep fail-closed together |

**Fit to Gate P4:** DNS marker via dnsmasq logs + resolve-to-sink; HTTP marker via mitm addon. Direct-IP and non-HTTP remain the hard parts.

---

## Option C — Custom minimal DNS + HTTP/HTTPS responder

**Idea:** Small purpose-built sink (e.g. Python stdlib / asyncio) serving: catch-all DNS, HTTP(S) with fixed marker body/header, connection logging to vault `logs/sink/`.

| Pros | Cons |
|---|---|
| Exact markers and log schema under our control | **Maintenance burden** (TLS certs, edge cases, protocol gaps) |
| No Docker / third-party malware-lab stack required | Only protocols we implement get “successful” answers |
| Python 3.14 available; TCP 8080 bind smoke OK | Still faces macOS **:53** privilege issue unless non-root strategy is designed |
| Easiest to assert fail-closed health-check API for `avd_session.sh` | Easy to under-scope direct-IP / non-HTTP unless explicitly built |

**Fit to Gate P4:** Best control for distinctive markers and run_id logging; scope must explicitly include DNS + HTTP + raw-IP sink (or block) to pass the gate.

---

## Recommended marker strings (document later in `SAFETY.md` — **not wired**)

| Role | String |
|---|---|
| DNS / sink identity (TXT or log token) | `CONTEXTDROID_SINK_DNS_MARKER` |
| HTTP body | `CONTEXTDROID_SINK_HTTP_MARKER` |
| HTTP header (plan example family) | `X-CONTEXTDROID-SINK: 1` (or `X-ABRG-SINK: 1` per plan text — pick one at implement time and freeze in `SAFETY.md`) |

Gate proof: random NXDOMAIN-worthy name must resolve to sink IP **and** HTTP fetch must return the HTTP marker (200 without marker = leak).

---

## What `gate_p4.sh` must prove (plan Gate P4)

Benign network-capable app / `adb shell` only — **no malware**.

1. **DNS marker path:** random nonexistent domain resolves to the sink address (NXDOMAIN ⇒ real resolver leak).
2. **HTTP marker path:** fetch of an external hostname returns the distinctive marker string.
3. **DNS leak check:** that random name does not appear in the host’s real resolver path/logs.
4. **Direct-IP:** raw IP egress is blocked or sunk (not hostname-only).
5. **Fail-closed launch:** `avd_session.sh` refuses malware AVD when sink flags absent **or** sink not responding (both cases).
6. **Sink logs:** test queries present under vault `logs/sink/` with correct `run_id`.

Also expected by skill posture: no silent passthrough to the real internet on the malware path.

---

## Comparison (no selection)

| Criterion | A INetSim/Docker | B dnsmasq+mitmproxy | C Custom sink |
|---|---|---|---|
| Install state on this host | Docker CLI+App yes; **daemon off** | **Not installed** | Python ready |
| Marker control | Config needed | Addon needed | Native |
| Protocol breadth | High | Medium (HTTP-centric) | As coded |
| macOS :53 pain | Container publish | Host dnsmasq | Host bind / redirect |
| Direct-IP story | Multi-port stubs | Weak unless extended | Must implement |
| Ops / reset | Container recreate | Two daemons | One process |
| Fail-closed health check | Scriptable | Scriptable | Easiest to tailor |
| Residual risk if pf hard | Same class | Same class | Same class |

---

## Blockers for manager

1. **Human must pick sink option (A / B / C) before any implementation** — Phase 4.1 only; do not advance to 4.2–4.5 without a recorded choice.
2. If **A**: start Docker Desktop and confirm a usable INetSim image on **arm64** before coding `network_sink.sh`.
3. If **B**: install dnsmasq + mitmproxy and decide privileged DNS / proxy topology.
4. If **C**: accept ownership of protocol scope (especially direct-IP + HTTPS).
5. Phase **4.3 pf backstop** needs interactive sudo / human approval; agent cannot configure pf without credentials.
6. `avd_session.sh` does not exist yet — required for refuse-launch proofs once an option is chosen.

**Agent action after this memo:** stop. No `gate_p4.sh`, no `network_sink.sh`, no sink install.
