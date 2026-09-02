# Phase 2 External Inputs (User-provided)

This environment cannot fetch AndroZoo keyed endpoints or external label hosts. Provide these files locally, then Phase 2 can run without network fetches.

## 1) Full AndroZoo index file

- Expected path: `data/androzoo/latest.csv.gz`
- Expected format: gzip-compressed CSV with header row including:
  `sha256,sha1,md5,dex_date,apk_size,pkg_name,vercode,vt_detection,vt_scan_date,dex_size,markets`
- Verify integrity:
  - `gzip -t data/androzoo/latest.csv.gz` must exit `0`
  - `python3 scripts/corpus/inspect_androzoo_index.py --index data/androzoo/latest.csv.gz`

## 2) MalRadar labels

- Expected file: CSV from MalRadar metadata (`sample-info.csv` or equivalent table).
- Before running labelling, paste the **actual header row** back in chat so column mapping is confirmed against the real file (do not assume defaults).
- Required columns for `label_samples.py`:
  - SHA-256 column (default argument: `--malradar-sha-col sha256`)
  - Family column (default argument: `--malradar-family-col family`)
- If column names differ, pass explicit column names to `label_samples.py`.

## 3) AMD labels

- Expected file: CSV containing SHA-256 to family mapping (must be sha256 keyed for this pipeline).
- Before running labelling, paste the **actual header row** back in chat so column mapping is confirmed against the real file (do not assume defaults).
- Required columns:
  - SHA-256 column (set via `--amd-sha-col`)
  - Family column (set via `--amd-family-col`)
- If AMD source is not SHA-256 keyed, provide a trusted SHA-256 mapping sidecar before running labelling.

## 4) Drebin labels (optional, narrow-era)

- Expected file: CSV with `sha256,family` (or pass custom columns).
- Before running labelling, paste the **actual header row** back in chat so column mapping is confirmed against the real file (do not assume defaults).
- Used only as a fallback source after MalRadar and AMD in match precedence.

## 5) AndroZoo download scope for 2B

- `ANDROZOO_API_KEY` available in runtime environment.
- Key approved for malware sample download scope required by `fetch_samples.py` / 2B.
- 2B must remain blocked until this approval is confirmed.

## Notes

- Do not use `data/androzoo/latest_frozen_snapshot_250k.csv.gz` for real selection. It is derived from a truncated head slice and is only useful as a temporary deterministic debug artifact.
- Real candidate selection starts only after the full valid `latest.csv.gz` is provided and verified.
