# SAFETY.md — Malware corpus handling policy

This document governs containment and handling of the malware tier of the ABRG
evaluation corpus. It is also source material for thesis ethics and
threats-to-validity sections.

**Governing rule:** no malware sample is executed until every phase gate of
`docs/malware_corpus_safety_plan.md` (as amended by `docs/PLAN_AMENDMENTS.md`)
has passed. Phase 0–5 of that plan execute **no malware**.

---

## Handling policy

1. Sample bytes exist only inside the encrypted vault (Phase 1+). They do not
   enter the git working tree, `/tmp`, Cursor context, or unencrypted sync roots.
2. Hashes, metadata, and traces (Frida JSONL without APK payloads) may leave the
   vault. APK content may not.
3. Samples are sealed at rest as 7-Zip AES-256 archives (password `infected` is
   an accident-prevention convention only — vault encryption is the real control).
4. Install and launch occur only on AVD `abrg_mw`, never on a physical device,
   never on `abrg_benign`.
5. The malware tier uses **`-wipe-data` + fresh boot per sample**. It does **not**
   use a golden snapshot. Persistence across `pm clear` / force-stop is assumed.
6. Network posture for the malware AVD is decided and proven in Phase 4
   (simulated sink). Until then, no malware-tier network run is permitted.
7. Every run appends one record to `logs/ledger/run_ledger.jsonl` via
   `extraction_pipeline/safety/ledger.py`.

---

## AVD naming (A1)

| Role | AVD name | Notes |
|---|---|---|
| Benign tier (historical) | `malware_sandbox` | **Renamed** — do not recreate |
| Benign tier (current) | `abrg_benign` | Same disk image as the former `malware_sandbox` |
| Malware tier | `abrg_mw` | Created with matching API 29 / pixel_2 / arm64-v8a / 2G / 6G data |

**Provenance:** v2 benign traces under `logs/bulk_llm_benign_v2/` do **not**
record the AVD name (zero matches for `malware_sandbox` in session metadata and
`dataset_index.csv`). Renaming does not orphan curated corpus links. Old→new
mapping is recorded here for operators reading host AVD directories or shell history.

Defaults in `ensure_emulator.sh`, `setup_emulator.sh`, `run_emulator_daemon.sh`,
`install_dependencies.sh`, and `run_bulk_llm_*.sh` now resolve to `abrg_benign`.

---

## Device reset asymmetry (A2)

| Tier | Reset mechanism | Why |
|---|---|---|
| Benign | Warm emulator; app-level `isolate_emulator_state` + `pm clear`; reboot every N apps | Matches the validated v2 collection path (`CONTEXTDROID_SKIP_SNAPSHOT_LOAD=1`, `-no-snapshot-load`) |
| Malware | `-wipe-data` + fresh boot **per sample** | Warm state is unsafe: malware persistence can survive `pm clear` / force-stop |

This isolation-strength asymmetry is **allowed**. Analysis configuration
(hooks, explore budget, timeouts, category universes, Ollama params, graph
params) must remain identical across tiers and is proven by comparing emitted
`config_snapshot.json` files (Phase 5 / amendment A5), not by matching device
reset verbs.

**Withdrawn:** golden snapshot `clean_mw` and plan step 3.5 `-read-only` launch
flags. Gate P3 proves wipe isolation (install benign package → wipe+reboot →
package absent), three consecutive times.

**Provisioning asymmetry (not analysis):** malware boots may use
`-writable-system` and re-push/start `frida-server` after each wipe. That is
host/device provisioning, recorded in the ledger / config snapshot, and does
not change hook scripts or agent config.

---

## Vault location

Recommended path (created in Phase 1):

```
~/Vaults/abrg_mw.sparsebundle
```

Mount volume name: `ABRG_MW` → `/Volumes/ABRG_MW/`.

Must not live under `~/Documents`, `~/Desktop`, `~/Library/Mobile Documents`,
Dropbox, or Drive roots. Sync-exclusion is verified at Phase 1 gate (`gate_p1`
runs `sparse_bundle_under_sync_root()` from `extraction_pipeline/safety/vault_paths.py`).
On this host the bundle path is **`~/Vaults/abrg_mw.sparsebundle`** — outside known
sync roots.

Vault password: macOS Keychain service **`ABRG_MW_VAULT`** (account = login user)
or interactive TTY prompt via `scripts/safety/vault.sh`. Never a repo file, env
var, or script literal.

7z quarantine password: `infected` (accident-prevention convention only — vault
APFS encryption is the real at-rest control; see seal/unseal in
`scripts/safety/quarantine.py`).


---

## Network posture

**Decision (Phase 4):** simulated network sink — **Option C** (custom DNS +
HTTP/HTTPS responder). Rationale: Frida still records connect/DNS attempts;
nothing reaches the public internet. Full-network rejected on ethical grounds;
no-network rejected because it records failure behavior rather than network
behavior. Options A/B were evaluated in `docs/phase4_sink_options.md` and not
selected.

### Containment (guest)

- `scripts/safety/guest_sink_rules.sh` installs iptables nat chain `ABRG_SINK`:
  RETURN loopback + `10.0.2.2`, DNAT DNS/HTTP/HTTPS to the host sink via
  `10.0.2.2`, **catch-all TCP→`:8080` / UDP→`:8053`**. Nat default `-j DROP`
  was probed and **rejected** on the API 29 image (`nat` table inhibits DROP);
  fail-closed equivalent is filter `ABRG_SINK_FILTER` (ICMP DROP + RETURN lo/
  `10.0.2.2` + default DROP). IPv6 egress DROP (`ABRG_V6_EGRESS`).
- Host DNS listens on **UDP/TCP 15353** (5353 is taken by adb mDNS on this host).
  Guest `:53` is DNATed to `10.0.2.2:15353`. HTTP `:80`→`:8080`, HTTPS `:443`→`:8443`.
  Nonstandard ports are catch-all DNATed (not left as internet passthrough).
  Host UDP catch-all listens on **8053**.
- DNS answers **`192.0.2.1`** (documentation prefix); that address is *not*
  RETURN’d so hostname fetches still hit the sink via DNAT.
- `scripts/safety/sink_rule_watchdog.sh` re-verifies the exact pin every **15s**;
  drift writes an abort flag and exits (no silent heal).

### Original-destination evidence

- Guest image has no `iptables` `LOG` target.
- **`NFLOG` works but is rejected** as the design mechanism (novelty / no manager ACK).
- **Chosen:** read `/proc/net/nf_conntrack` after DNAT — original tuple retains
  `dst=<ip> dport=<port>` (verified for `1.2.3.4:80` → reply `10.0.2.2:8080`).
- Frida v3 hooks Java `Socket.connect` / `HttpURLConnection` only — **no** native
  libc `connect` hook — so Frida is not used for pre-NAT evidence.

### Markers (must appear in Gate A/B proofs)

| Marker | Where |
|--------|--------|
| `CONTEXTDROID_SINK_HTTP_MARKER` | HTTP(S) response body |
| `CONTEXTDROID_SINK_DNS_MARKER` | Present in HTTP body companion line; DNS path logs `dns_query` with answer `192.0.2.1` |
| `X-CONTEXTDROID-SINK: 1` | HTTP(S) response header |
| Per-run `NONCE` (32 hex) | Gate A `/__abrg_health?nonce=` and Gate B HTTP body |

### Sink lifecycle

- `scripts/safety/network_sink.sh start --run-id <ID>` — vault must be mounted;
  logs only under vault `logs/sink/<run_id>.jsonl` (no `/tmp` sink logs).
- `scripts/safety/avd_session.sh` **refuses** malware AVD launch without Gate A.
- `scripts/safety/gate_p4.sh` — Gate A + Gate B (benign probes only).

### Residual risks

- Host `pfctl` egress backstop needs interactive sudo — not automated; defense-in-depth gap.
- HTTPS uses a self-signed cert; apps with pinning will fail closed (connection error), which is acceptable for containment but limits HTTPS behavioral signal.
- Emulator qemu DNS magic (`10.0.2.3`) is overridden by guest DNAT + Private DNS off; if a future image bypasses OUTPUT nat for DNS, Gate B DNS probe fails closed.

---

## adb device rule

- Exactly one adb device may be connected during a corpus run.
- It must be an emulator (`ro.kernel.qemu == 1`).
- AVD name must match the tier expectation from env (`abrg_benign` or `abrg_mw`).
- Fingerprint must match the recorded AVD fingerprint when one exists.
- Device-identity hard asserts run at emulator launch (`hard-prelaunch`) and
  immediately before `adb install` only. Mid-session protection is structural
  (`ANDROID_SERIAL` pinned via `scripts/safety/adb_pinned.sh` on every adb
  invocation) plus a background device-count watchdog off the hot path.
  Per-dump / mid-loop identity asserts were removed (A4 — Phase 3).

### Two-device fail-closed (A7 — USB phone step withdrawn)

No physical Android device is connected during malware analysis on this host.
The original Gate P3 USB phone bullet is **withdrawn** (`PLAN_AMENDMENTS.md`
A7). Accepted evidence:

| Check | Method | Expected |
|---|---|---|
| Two emulators | `abrg_benign` (`emulator-5554`) + `abrg_mw` (`emulator-5556`) both online | `device_guard.sh single` and `hard` exit non-zero with `expected exactly one online adb device` |
| One emulator | After shutting down `abrg_mw` | `single` passes |
| Zero devices | Empty `adb devices` (verified 2026-07-29) | `single` and `hard` exit 2 |
| Non-emulator | `ro.kernel.qemu` empty (unit test with mocked getprop) | hard assert rejects |

`gate_p3.sh` automates the two-emulator row. Do **not** block Phase 4+ on
plugging in a phone.

---

## A4 regression fixture (Phase 3)

A4 equivalence uses **`ac.robinson.mediaphone`** (v2 bundle APK,
`data/apks/benign/ac.robinson.mediaphone_65.apk`), LLM arm, 90s, fixed seed
`424242`.

**Observed signal (guard-disabled baselines):** ~361–368 Frida events
(~363 mean), ~286–293 meaningful (~80% meaningful ratio), 6 categories,
`hook_coverage=12` unique APIs fired of **58** hooked APIs in
`frida_scripts/hook_apis.js` v3 (**~21%**).

**Below the benign activation bar** (~500 events / ≥70% hook coverage in
`docs/malware_corpus_safety_plan.md` §5.4). That is acceptable: A4 tests
whether the device guard **perturbs** a real LLM+Frida+`screen.py` dump-path
trace, not activation quality. Structure (`category_set`, `hook_coverage`,
`exit_status`) is stable across repeated runs. Do not treat this fixture as
an activation exemplar.

### Why count-based A4 was abandoned

Frida event / meaningful / screen-dump counts are dominated by LLM planner
nondeterminism (evidence: guard-enabled run explore→execute fork at step 8,
−2 actions, −49 `content_access` events). Baseline itself spans ~356–368.
Guard budget is ~0.13% of a ~130s session (~50ms×2 hard asserts + ~10ms×N
watchdog polls). Detecting that through 14% count noise is infeasible
(~10⁴ runs/arm). Iterating min/max bands, mean−2σ, then prediction intervals /
two-sample t-tests only measured the wrong instrument — not the guard.

CONTROL 1 / CONTROL 2 remain in `gate_p3.sh` as **documentation** of that
failed approach (printed, not gated).

### Current A4 acceptance (direct instrumentation)

1. **EXACT:** `category_set`, `hook_coverage`, `exit_status` identical across
   all baseline and guard-enabled runs.
2. **DIRECT:** `guard_total_ms / session_wall_ms < 1%` on every guard-enabled
   run; no adb call >500ms temporally correlated with a watchdog poll
   (1s window). Timing fields emitted in session metadata by
   `device_guard.py` (**timing only — assert logic unchanged**).
3. **COUNTS:** reported in gate output, **not gated**.
4. **SMOKE FLOOR only:** `guard_mean > 0.7 × baseline_mean` on count metrics.
   Catches catastrophic breakage only. Explicitly **not** an equivalence test
   — would **not** have caught the historical 289/264/258 per-dump-assert
   count decline; that is what direct timing replaces.

### Phantom regression note

The old per-dump light assert measured ~10ms in isolation but coincided with
dump spacing growing 11s→18–20s. 10ms cannot cause a 7–9s gap. If live
`guard_total_ms` is tiny versus session wall, that historical count decline
was LLM path divergence (same class as the explore→execute fork), not guard
overhead — a phantom regression. Serial pinning + launch/install hard asserts
+ background watchdog remain the correct design either way.

---

## Human go/no-go (malware tier code interlock)

`--tier malware` in `scripts/corpus/run_sample.py` is **hard-refused** unless the
operator sets an explicit environment flag **after** human go/no-go sign-off:

```bash
export CONTEXTDROID_MALWARE_GO=1
```

| Rule | Detail |
|---|---|
| Exact flag | `CONTEXTDROID_MALWARE_GO=1` only (`true`/`yes` are **not** accepted) |
| Scope | `--tier malware` only; `--tier canary` does **not** require this flag |
| Fail closed | Missing/unset/wrong value → `REFUSE` before vault unseal, sink, install, or analyze |
| Not a bypass | The flag does not disable device guard, network sink, wipe-boot, or ledger |
| `--seal-from` | Allowed for `--tier canary` only; refused on malware tier |

Process-only go/no-go (chat sign-off without this env) is **insufficient**. Do not
export the flag until gates are green and a human has approved the first real
sample. Unset it after the supervised session.

**Operator readiness (required before GO):** fill and sign
`docs/operator_go_nogo_checklist.md` — supervised run window, incident
quick-check form, and hard stop criteria. Default remains **NO-GO**.

**Residual-risk defenses (A–D, non–host-separation):** see
`docs/malware_host_defense_plan.md`. Enforce with:

```bash
bash scripts/safety/malware_session_preflight.sh --mode idle      # NO-GO days
bash scripts/safety/malware_session_preflight.sh --mode go-armed # after GO + sink up
bash scripts/safety/malware_session_postflight.sh --run-id <id>
```

**Live window:** start `@corpus-sim-safety-manager` (launches A–D monitor
subagents). Continuous ticks / abort:

```bash
SIM_PHASE=live ABRG_RUN_ID=<id> bash scripts/safety/malware_sim_monitor_tick.sh --domain all
bash scripts/safety/malware_sim_abort.sh "<reason>"   # any suspicion — manager only
```

Optional host pf sketch (print-only, not auto-applied):
`scripts/safety/host_pf_backstop_sketch.sh`.

---

## UPC / institutional policy

AndroZoo malware-scope approval and institutional malware-handling policy are
**human** tasks running in parallel with this harness. Record the institutional
answer here when received. Until then: no malware download outside the vault
fetch path, and no execution of malware samples.

---

## Incident procedure

If a sample (or suspected sample) is found **outside** the vault:

1. **Do not open, install, unzip, or upload it.**
2. Disconnect any attached physical Android device; stop emulators if a sample
   may have been installed (`adb devices`, then power off / `emu kill`).
3. Move the file into the vault quarantine path **only after** the vault is
   mounted; if the vault is unavailable, power off the machine and seek help
   before copying further.
4. Record: path found, approximate time, who found it, whether any install or
   network activity may have occurred.
5. Append an incident note to this file and a ledger row with
   `outcome=incident_sample_outside_vault`.
6. Rotate any credentials that could have been exposed; treat host network logs
   as potentially relevant evidence.
7. Do not commit the sample. If it was staged, `git reset` / unstage and confirm
   `git status` is clean of APK/zip payloads. Notify the project lead.

If a physical device was the install target: isolate the device (airplane mode,
no USB file transfer of the APK), and do not factory-reset until evidence needs
are decided with the project lead.
