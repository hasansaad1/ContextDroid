# Operator go/no-go checklist — first real malware sample

**Default posture: NO-GO.** Keep `CONTEXTDROID_MALWARE_GO` unset until every
section below is filled and signed. First execution is **one sample only**,
supervised end-to-end. Do not batch.

Governing references: `SAFETY.md` (incident procedure + code interlock),
`docs/PLAN_AMENDMENTS.md` A7 (USB phone step withdrawn — use two-emulator
fail-closed evidence), `docs/malware_corpus_safety_plan.md` go/no-go list
(as amended), `docs/malware_host_defense_plan.md` (A–D residual-risk defenses).

**Harness checks (run these; do not set go flag for idle):**

```bash
bash scripts/safety/malware_session_preflight.sh --mode idle
# after a session:
bash scripts/safety/malware_session_postflight.sh --run-id <run_id>
```

**Live simulation:** open `@corpus-sim-safety-manager` (spawns A–D monitor
subagents). Manager aborts on any SUSPECT/ABORT via
`scripts/safety/malware_sim_abort.sh`.

Before first malware `run_sample` (only after §0 GO signed):

```bash
export CONTEXTDROID_MALWARE_GO=1
export ABRG_RUN_ID=<run_id>   # after network_sink start + gate-a
bash scripts/safety/malware_session_preflight.sh --mode go-armed
# then start @corpus-sim-safety-manager before run_sample
```

---

## 0) Pre-flight gate evidence (technical)

Paste or attach before considering GO:

| Evidence | Status | Date / pointer |
|----------|--------|----------------|
| Cold `gate_all.sh` green | [ ] | |
| Output pasted into `SAFETY.md` with date | [ ] | |
| Network containment proven by marker (Gate B) | [ ] | |
| Canary full path completed | [ ] | |
| Device-count fail-closed (A7 two-emulator) | [ ] | |
| `CONTEXTDROID_MALWARE_GO` currently **unset** | [ ] | |

Institutional / sourcing (human — out of scope for this form, but must be true
before GO): UPC policy recorded; AndroZoo scope approved; selection report reviewed.

**Decision:** [ ] NO-GO (default) [ ] GO — single sample only  
**Signed by:** ________________ **Date (UTC):** ________________

---

## 1) Supervised run window

### 1.1 People

| Role | Name | Contact |
|------|------|---------|
| Named operator (primary) | | |
| Backup operator | | |
| Project lead (incident escalation) | | |

### 1.2 Window

| Field | Value |
|-------|--------|
| Planned start (local + UTC) | |
| Planned end (local + UTC) | |
| Max wall-clock for this sample | _____ min (hard stop at end even if incomplete) |
| Location / host | |

Rules for this window:

1. **No unattended execution.** Operator remains at the keyboard for the full window.
2. **No multitask** during the first sample (no other IDE agents installing,
   no parallel adb/emulator work, no unrelated downloads).
3. Only one adb target: malware AVD `abrg_mw` (`ANDROID_SERIAL=emulator-5556`
   unless documented otherwise). No physical phone attached (A7).
4. Export `CONTEXTDROID_MALWARE_GO=1` only at window start after §0 is signed GO;
   never leave it set overnight.

### 1.3 Live monitoring surfaces (must be visible)

| Surface | How to watch | Owner |
|---------|--------------|-------|
| `run_sample.py` terminal | Foreground process; watch REFUSE / FAIL / ledger lines | Operator |
| Sink logs | Vault `/Volumes/ABRG_MW/logs/sink/<run_id>.jsonl` (and abort flag) | Operator |
| Ledger | `logs/ledger/run_ledger.jsonl` append for this `run_id` | Operator |
| adb device list | Periodic `adb devices -l` (exactly one emulator) | Operator |
| Sink rule watchdog | Abort flag / drift messages if started with session | Operator |

### 1.4 Post-run closeout (mandatory before leaving seat)

```bash
unset CONTEXTDROID_MALWARE_GO
bash scripts/safety/malware_session_postflight.sh --run-id <run_id>
# confirm unset:
echo "MALWARE_GO=${CONTEXTDROID_MALWARE_GO:-<unset>}"
```

| Check | Command / proof | Done |
|-------|-----------------|------|
| Postflight PASS | `malware_session_postflight.sh` exit 0 | [ ] |
| Flag unset | `echo` above shows `<unset>` | [ ] |
| Staging empty | vault mounted; `staging/` has no leftover APK | [ ] |
| Ledger row present | `run_id` with `executed` or `failed` + reason | [ ] |
| Package absent / wipe done | post-run uninstall + wipe path completed or aborted clean | [ ] |
| Sink stopped | `network_sink.sh stop` for this `run_id` (clear leftover `*.pid`) | [ ] |
| No sample bytes outside vault | spot-check; `git status` clean of APK/zip | [ ] |
| Session notes filed | short outcome in chat or ledger note | [ ] |

---

## 2) Incident quick-check form (execution-time)

Use for **any** anomaly during the supervised window (not only outside-vault
discovery). Full procedure remains in `SAFETY.md` § Incident procedure.

### Immediate actions (do these first)

1. Stop the run (Ctrl-C / kill `run_sample` / `analyze_apk` if needed).
2. Do **not** open, copy, or upload sample bytes outside the vault.
3. `adb devices -l` → if unexpected device, disconnect / kill extras.
4. Stop emulators if install may have occurred (`emu kill` / power off).
5. Unset `CONTEXTDROID_MALWARE_GO`.
6. Notify project lead.

### Fill in

| Field | Entry |
|-------|--------|
| Date / time (UTC) | |
| Operator | |
| `run_id` / sample sha256 (if known) | |
| What was happening | |
| What went wrong (observed) | |
| Guard / sink / vault / adb symptom | |
| Suspected sample outside vault? (Y/N) | |
| Physical device involved? (Y/N) | |
| Network activity suspected? (Y/N) | |
| Actions taken (bullets) | |
| Ledger / SAFETY.md incident note updated? | [ ] |
| Lead notified? | [ ] |

If sample found outside vault: follow `SAFETY.md` incident steps 1–7 before
moving any file.

---

## 3) Stop criteria — abort **now** if …

Any one of the following ends the session immediately (fail closed). Do not
“retry once to see.” Close out per §1.4, then file §2 if needed.

### Hard abort list

- [ ] Device guard failure (wrong serial, wrong AVD, not emulator, count ≠ 1)
- [ ] Sink rule watchdog drift / abort flag written
- [ ] Gate A / sink health failure (marker/nonce missing, sink down)
- [ ] Unexpected second adb device appears
- [ ] Vault unmount or vault write failure mid-run
- [ ] Evidence of off-path egress (HTTP 200 without sink marker; public IP where
      sink was expected; DNS not answering `192.0.2.1` for test domains)
- [ ] Install or run targeting unknown / non-`abrg_mw` device
- [ ] `CONTEXTDROID_DEVICE_GUARD_DISABLE` set or any other guard bypass appears
- [ ] Unexplained process behavior you cannot account for in-session
- [ ] Planned window end reached (hard stop even if sample incomplete)

### After abort

1. Unset `CONTEXTDROID_MALWARE_GO`.
2. Confirm staging empty (or remount + pre-run wipe path if vault was force-detached).
3. Confirm ledger `failed` (or incident) row.
4. Do **not** re-export the go flag without a fresh signed §0 decision.

---

## 4) First-sample run log (fill during GO session)

| Field | Value |
|-------|--------|
| Sample sha256 | |
| Family / selection note | |
| `run_id` | |
| Command used | `python3 scripts/corpus/run_sample.py --tier malware --sha256 …` |
| Outcome | executed / failed / aborted |
| Trace path (vault) | |
| Operator sign-off | |

**Reminder:** one sample. Review manually before any second run or batch.
