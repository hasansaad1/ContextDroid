# Phase 5 failure-injection — status (plan 5.5)

## Live mid-run suite (preferred)

Run with vault mounted and `abrg_mw` online (benign canary only; never set
`CONTEXTDROID_MALWARE_GO`):

```bash
python3 scripts/corpus/tests/test_p5_midrun_failure_injection.py
# or: GATE_P5_MIDRUN=1 bash scripts/safety/gate_p5.sh
```

| Case | Coverage |
|------|----------|
| Emulator dies mid-run | Live: `emu kill` during canary `analyze_apk` |
| Install fails | Safe subset: junk sealed APK + staging empty (`test_p5_failure_injection.py`) |
| ContextDroid / analyze abort mid-run | Live: kill `analyze_apk` child mid-run |
| Vault unmounts mid-run | Live: `vault.sh unmount` during analyze; remount + staging empty |
| Second adb device mid-run | Live: boot `abrg_benign` mid-monkey; device-count watchdog on monkey arm |
| Sink goes down mid-run | Live: `network_sink.sh stop` mid-run; `run_sample` polls sink liveness |

Harness changes that made live proofs fail-closed (not guard weakening):

- Monkey arm now starts the same device-count watchdog as the LLM arm.
- Device-count watchdog polls immediately on start (then interval cadence).
- `run_sample` runs `analyze_apk` under Popen and aborts on sink-down, sink-rule
  abort flag, or vault unmount mid-run.
- Host-side ledger always appends (including vault-unmount aborts).
- Pre-run staging wipe recovers residue if a prior mid-run unmount skipped wipe.

Known residual (documented, not marked PASS as clean wipe-in-finally):

- Force vault detach mid-run leaves staging dirty until remount + pre-run wipe
  (finally cannot wipe while unmounted). Live suite asserts abort + recovery wipe.

## Safe offline subset

`scripts/corpus/tests/test_p5_failure_injection.py` still covers refuse paths
(guard-disable, malware GO interlock, missing archive, config parity mutation,
junk APK install fail) without a long live session.

Do not mark Gate P5 fully green on 5.5 until the live mid-run suite prints
`FAILINJ_SUMMARY PASS` (or manager explicitly accepts a documented residual).
