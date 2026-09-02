# Plan Amendments — post-recon

Read alongside `malware_corpus_safety_plan.md`. **On any conflict, this file wins.**
Written after the pre-Phase-0 recon revealed the plan made assumptions that do not hold
against the actual repo.

---

## A1 — AVD naming (DECISION REQUIRED before Phase 0)

**Finding:** the existing *benign* AVD is named `malware_sandbox`. The plan's device guard is
built on the premise that the two AVDs are distinguishable at a glance. Today the name says the
opposite of the truth.

**Resolution — pick one and record it in `SAFETY.md`:**

- **(a) Rename** `malware_sandbox` → `abrg_benign`; create `abrg_mw` for the malware tier.
  Cost: touch `ensure_emulator.sh`, `setup_emulator.sh`, `run_bulk_llm_*.sh`, any
  `ANDROID_SERIAL`/`EMULATOR_SERIAL` defaults, `~/.android/avd/*.ini` + `config.ini` `path=`
  entries. Reversible.
- **(b) Keep the name**, create `abrg_mw`, and rely on the guard's assertions alone.
  Cost: permanent ambiguity, paid every time someone reads a log under time pressure.

**Prerequisite before renaming — do not skip:** grep the existing v2 session metadata and
`dataset_index.csv` for `malware_sandbox`. If the AVD name is recorded in trace provenance,
renaming orphans the link between the curated corpus and the device that produced it. If it is
recorded, still rename, but write the old→new mapping into `SAFETY.md` and a provenance note
under `experiments/datasets/versions/v2/` so existing traces stay interpretable.

**Do not rename anything until this is confirmed with the user.**

---

## A2 — Device reset mechanism (DECISION REQUIRED before Phase 3)

**Finding 1 — internal inconsistency in the current pipeline.** `ensure_emulator.sh` launches
with `-no-snapshot-load -no-snapshot-save`, while `analyze_apk.py` calls
`adb emu avd snapshot load default_boot`. Determine which actually governs a v2 benign run and
report it. This must be understood before the malware tier copies it.

**Finding 2 — flag collision.** `-writable-system` is required for the frida-server push. It is
known to conflict with snapshot save/load on recent emulator versions. Verify against the
installed emulator version before committing to a mechanism. Plan step 3.5 additionally
specified `-read-only`, which compounds this — **treat 3.5's flag list as withdrawn** pending
this decision.

**Finding 3 — parity.** If the benign tier cold-boots and the malware tier restores a snapshot,
the two tiers begin from different device states. That is a confound in the device layer,
below anything `config_parity_check.py` would catch.

**Resolution — pick one:**

- **(a) Fresh boot + `-wipe-data` per sample.** Stronger isolation than snapshot restore
  (nothing carries over at all), no `-writable-system` conflict, matches the benign tier's
  existing behavior. Cost: ~60–90s boot per sample plus frida-server re-push — for 30–50
  samples this is minutes, not hours. `setup_emulator.sh` already does the post-boot push.
- **(b) Golden snapshot `clean_mw`** as originally planned, *if* the flag conflict resolves
  cleanly and the benign tier is also moved to snapshot-restore for parity.

**Gate P3's restore proof survives either choice** — install a benign package, reset by whichever
mechanism is chosen, assert the package is absent, three consecutive times. Only the reset verb
changes.

---

## A3 — Python package placement (supersedes plan 0.4, 1.4)

`abrg/` exists only in the sibling ABGA repo. The safety harness is a ContextDroid concern.

- `abrg/ledger.py` → **`extraction_pipeline/safety/ledger.py`**
- `abrg/vault_paths.py` → **`extraction_pipeline/safety/vault_paths.py`**
- Shell gates, hooks, `vault.sh`, `adb_guard.sh`, `avd_session.sh` → `scripts/safety/` as planned
- Corpus scripts → `scripts/corpus/` as planned

Do not create an `abrg/` package in ContextDroid. Do not import from the ABGA repo at runtime.

---

## A4 — adb guard is one chokepoint, not 324 edits (supersedes plan 3.3, 3.4)

**Finding:** 324 adb invocations across 35 files, nearly all of them in the *benign* pipeline
that currently works. The plan's wording implied editing all of them. It does not.

**Required approach:**

1. **Read `extraction_pipeline/tests/test_device_isolation.py` first** and report what it already
   asserts. Part of the guard may exist.
2. Identify the narrowest existing chokepoint through which adb invocations pass — candidates:
   `subprocess_util.py`, the `adb_bin` resolution, `llm_agent/device.py`. Report what fraction of
   the 324 call sites route through each. **Report before implementing.**
3. Implement the guard **inside that chokepoint**. If no single chokepoint covers everything,
   propose the minimal refactor that creates one — and propose it, do not perform it unasked.
4. The grep test then enforces that nothing bypasses the chokepoint, rather than banning the
   string `adb` across the repo.

**Regression requirement — non-negotiable.** This modifies a validated pipeline that produced the
existing corpus. Before and after guard insertion, run one benign app end to end and assert the
outputs are equivalent (trace event count, hook coverage, category set, exit status). A guard that
silently degrades benign collection is worse than no guard, because it corrupts the baseline the
whole comparison rests on.

**Tier-awareness:** the guard's assertions (exactly one device, is an emulator, matches the
expected AVD name from env) are correct for the benign tier too. Apply it to both. It is a strict
improvement for benign collection — it would catch a phone plugged in mid-run there as well.

---

## A5 — Config parity via emitted snapshot (supersedes plan 5.1)

**Finding:** run config is spread across `collection_v2.env`, `protocol_config.py`,
`llm_agent/config.py`, three shell scripts, `evaluate_corpus.py`, and the ABGA repo's
`abrg/config.py`. Comparing scattered sources directly is brittle and will drift.

**Required approach:** have the pipeline **emit** a `config_snapshot.json` at the start of every
run, recording the effective resolved values (not the defaults — what actually governed that run):
hook set version + file hash, session duration, timeout multiplier, explore floor/ratio,
`CATEGORY_UNIVERSE` (25), `GRAPH_CATEGORY_UNIVERSE` (22), `K_BURST`, `DELTA_SEC`,
`DELTA_MOTIF_SEC`, window params, Ollama model/endpoint/temperature/timeout/retries, judge
version, AVD name + fingerprint, reset mechanism.

Parity then becomes: malware snapshot equals the v2 benign snapshot, modulo an explicit allowed-
difference list (tier label, paths, AVD name). This also gives every trace a self-describing
config record, which the thesis reproducibility section needs regardless.

**Cross-repo constant risk:** `GRAPH_CATEGORY_UNIVERSE` has a canonical copy in the ABGA repo and
a derived copy in `experiments/datasets/curate_v2_reference.py`. The snapshot must record a hash
of the universe actually used, so drift between the two repos is detectable rather than silent.

---

## A6 — gitignore scope (extends plan 0.1)

Add explicitly, beyond the plan's list:

- `data/apks/` — currently holds ~4.6 GB of untracked benign APKs, one `git add -A` from disaster
- `logs/` run trees, if not already covered
- `experiment/*.zip`, `ABGA datasets/` export bundles

Confirm the pre-commit hook's 2 MB size rule does not false-positive on any file currently
tracked. Run it against the existing HEAD tree and report any hit before installing it.

---

## A7 — Physical-phone guard proof (supersedes plan Gate P3 phone bullet + go/no-go item)

**Host handling rule:** no physical Android device is connected to this Mac during malware
analysis. Physical-USB go/no-go is withdrawn.

**Accepted evidence (recorded in `SAFETY.md`, verified 2026-07-29):**

- Count assertion: second emulator (`abrg_mw` on `-port 5556`) live with `abrg_benign` →
  `device_guard` fails with `expected exactly one online adb device`; after shutdown → pass.
- Zero-device fail-closed: empty `adb devices` → both `single` and `hard` exit 2.
- `ro.kernel.qemu`: unit test with mocked empty `getprop` rejects; live accepts `qemu=1`.
- Residual risk mitigated by serial pinning on every device-targeted adb call.

Do not block Phase 4+ on plugging in a phone.

---

## Unchanged decision points (do not relitigate now)

- **2.2 family labelling** — still open, surfaces at Phase 2
- **4.1 sink implementation on macOS** — still open, surfaces at Phase 4
