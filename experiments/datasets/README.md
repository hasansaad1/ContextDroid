# Dataset experiment tracking

Immutable version history for ContextDroid working datasets. Each version records **which sessions are included, why, and how the manifest was produced** — without copying trace data.

## Layout

```
experiments/datasets/
  README.md              # this file
  schema.md              # column / field reference
  registry.csv             # one row per version (index of all versions)
  snapshot_dataset.py      # snapshot + diff tool
  versions/
    v1/
      manifest.csv         # one row per session in this version
      version_meta.json    # provenance
      notes.md             # free-text changelog
    v2/  ...
```

## Principles

1. **Versions are immutable.** Never edit `versions/vN/` after creation. New curation → new version id.
2. **Reference, don't copy.** `manifest.csv` stores repo-relative paths to session artifacts under `logs/`.
3. **`quality_tag` is mandatory** and separates clean reference (`FAITHFUL_VALIDATED`) from volume-retained flailing (`FLAILING_SUSPECT`) and uncertain judge labels (`LOW_CONFIDENCE`).
4. **Descriptive metrics are not gates.** `meaningful_event_count` and similar fields are metadata only.

## Snapshot a new version

From repo root:

```bash
python3 experiments/datasets/snapshot_dataset.py snapshot \
  --version-id v2 \
  --parent-version v1 \
  --description "Short one-line description" \
  --working-csv experiment/working_dataset.csv \
  --faithfulness-json experiment/faithfulness_full_pool.json \
  --human-labels experiment/faithfulness_human_label_sheet.csv
```

The script refuses to overwrite an existing `versions/<id>/` directory.

Optional flags:

- `--notes-file path/to/notes.md` — copy custom notes into the version (else auto-generated stub).
- `--retain-flailing` — tag flailing sessions `FLAILING_SUSPECT` and keep them included (default for v1-style exports).
- `--exclude-flailing` — mark flailing sessions `EXCLUDED` instead.

## Diff two versions

```bash
python3 experiments/datasets/snapshot_dataset.py diff v1 v2
```

Reports sessions added, removed, and sessions whose verdict, quality tag, or inclusion status changed.

## Filter clean reference subset

```python
import csv
rows = list(csv.DictReader(open("experiments/datasets/versions/v1/manifest.csv")))
clean = [r for r in rows if r["quality_tag"] == "FAITHFUL_VALIDATED" and r["inclusion_status"] == "INCLUDED"]
```

## Current versions

See `registry.csv` for the authoritative list.
