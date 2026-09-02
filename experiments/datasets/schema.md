# Dataset version schema

Dataset versions live under `experiments/datasets/versions/<version_id>/`. Each version is **immutable** once written. Sessions are referenced by stable ID and artifact path — trace data is never copied into version directories.

## `registry.csv` (one row per version)

| Column | Type | Description |
|--------|------|-------------|
| `version_id` | string | Version identifier, e.g. `v1`, `v2`. |
| `created_at` | ISO-8601 UTC | When this version was snapshotted. |
| `parent_version` | string | Version this was derived from; empty for root versions. |
| `n_sessions` | int | Rows in `manifest.csv` with `inclusion_status=INCLUDED`. |
| `n_apps` | int | Distinct `package` values among included sessions. |
| `n_faithful_validated` | int | Included sessions with `quality_tag=FAITHFUL_VALIDATED`. |
| `n_flailing_suspect` | int | Included sessions with `quality_tag=FLAILING_SUSPECT`. |
| `judge_version` | string | Faithfulness judge identifier used for labels in this version. |
| `description` | string | One-line summary of what this version is. |

## `manifest.csv` (one row per session in the version)

| Column | Type | Description |
|--------|------|-------------|
| `session_uid` | string | Stable unique id: `<package>__<source_run>__<session_id>`. |
| `package` | string | Android package name. |
| `source_run` | string | Collection run name, e.g. `bulk_llm_benign_v6`. |
| `session_id` | string | Session id from dynamic metadata / dataset index. |
| `artifact_dir` | path | Repo-relative path to `session_1/` artifacts (reference only). |
| `frida_trace_path` | path | Repo-relative path to `*_frida.jsonl`. |
| `agent_log_path` | path | Repo-relative path to `*_llm_actions.jsonl`. |
| `faithfulness_verdict` | enum | `FAITHFUL`, `PARTIAL`, or `FAILED` (judge output at snapshot time). |
| `judge_version` | string | Judge that produced `faithfulness_verdict`. |
| `inclusion_status` | enum | `INCLUDED` or `EXCLUDED` for this version. |
| `inclusion_reason` | string | Why included/excluded, e.g. `faithful`, `partial`, `flailing-retained-for-volume`, `excluded-stalled`, `excluded-degenerate`. |
| `quality_tag` | enum | **Mandatory.** `FAITHFUL_VALIDATED` (clean reference), `FLAILING_SUSPECT` (volume-retained flailing), or `LOW_CONFIDENCE` (judge/human disagreement or PARTIAL verdict). |
| `meaningful_event_count` | int | Descriptive Frida metric; **not** an inclusion gate. |
| `coverage_gap` | string | Judge note on missing / unvisited behavior. |
| `human_label` | enum | Optional hand label (`FAITHFUL` / `PARTIAL` / `FAILED`) if ever human-labeled; else empty. |
| `notes` | string | Free per-session notes (flailing evidence, validation flags, etc.). |

### `quality_tag` precedence (at snapshot time)

1. `FLAILING_SUSPECT` — mechanical-flailing detector fired (`assemble_working_dataset.detect_suspect_flailing`).
2. `LOW_CONFIDENCE` — verdict is `PARTIAL`, or human label disagrees with judge verdict.
3. `FAITHFUL_VALIDATED` — otherwise.

Filter to clean reference: `quality_tag == FAITHFUL_VALIDATED`.

## `version_meta.json` (provenance)

| Field | Type | Description |
|-------|------|-------------|
| `version_id` | string | Same as directory name. |
| `created_at` | ISO-8601 UTC | Snapshot timestamp. |
| `parent_version` | string \| null | Parent version id. |
| `description` | string | One-line purpose. |
| `source_runs` | list[string] | Collection runs represented. |
| `judge_version` | string | Judge identifier. |
| `curation_rules` | string | Explicit keep/exclude/tag rules used. |
| `counts` | object | Totals by `inclusion_status`, `quality_tag`, `faithfulness_verdict`, distinct apps. |
| `reproduction` | object | Commands and input files to regenerate this manifest. |
| `known_limitations` | list[string] | Honest caveats for this version. |

## `notes.md`

Free-text changelog: why this version exists, what changed vs parent, open questions.
