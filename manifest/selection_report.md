# Malware candidate selection report (Phase 2A)

Generated: 2026-07-28T08:35:30Z UTC

## Current status

- The previously frozen head slice `data/androzoo/latest_frozen_snapshot_250k.csv.gz` is **discarded for real selection input**.
- No real Phase 2 candidate selection is run in this environment until a **full valid** `latest.csv.gz` is provided by user and passes `gzip -t`.
- No malware APK bytes were fetched.

## What is now validated offline

- `scripts/corpus/select_malware.py` is deterministic and fixture-tested (byte-identical rerun).
- `scripts/corpus/label_samples.py` applies only hash cross-reference labels and sets unmatched rows to `family_source=none`, `family_confidence=none`.
- `scripts/safety/gate_p2.sh` passes fixture-only checks for selector determinism and labeller correctness.

## Selection policy constraints kept

- Selection filter remains `vt_detection >= 10`.
- Benign matching dimension is `apk_size` IQR only.
- No package-name family proxy is used.
- Over-selection target remains ~150 for pre-labelling pool.

## Holdout planning note

- Once real labels exist, use the labelled-subset family histogram and mark families with `>=3` samples.
- Choose zero-day held-out families from that `>=3` set at selection time.

## External inputs needed (user-provided)

See `manifest/SOURCING_TODO.md` for exact required files, expected formats, and verification commands.
