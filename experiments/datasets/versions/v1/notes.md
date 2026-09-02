# v1 — initial faithfulness-curated working set

First tracked dataset version: the 129-session FAITHFUL+PARTIAL keep-set from `bulk_llm_benign_v6`, assembled with flailing filter **skipped** so volume is retained but tagged.

## Why this version exists

Baseline dataset for pipeline development while the faithfulness judge is tuned. Sessions are referenced by path only; no trace copies.

## What changed vs parent

None — root version (`parent_version` is null).

## Curation applied

- Pool: v6 corpus success sessions (238 total), judged by `evaluate_faithfulness.py`
- Keep: `FAITHFUL` (124) + `PARTIAL` (5)
- Flailing: **not removed**; suspect sessions tagged `FLAILING_SUSPECT`
- No gates on `meaningful_event_count`, Frida category counts, or graph viability
- Sparse / low-event sessions kept

## Human validation context

20 sessions hand-labeled during judge validation (`experiment/faithfulness_human_label_sheet.csv`):

- Exact agreement: 60% (12/20)
- Collapsed agreement: 75% (15/20) — below 90% automation threshold

Sessions from that sheet that appear in v1 have `human_label` filled. Disagreements with the judge are tagged `LOW_CONFIDENCE` (unless flailing).

## Open questions

- Re-snapshot as v2 after judge tuning or with flailing excluded
- Whether PARTIAL verdicts should remain in reference subset after judge v2
