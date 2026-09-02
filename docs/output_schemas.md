# Output Schemas

This document describes the artifacts generated under `logs/` and the expected schema for downstream reproducible processing.

When comparison mode is enabled, per-session artifacts are stored under:
`logs/<sample_id>_<package>/dynamic/<arm>/session_<n>/...`

## `logs/dataset_index.csv`

Header:

`sample_id,apk_filename,apk_sha256,label,source,package_name,analysis_timestamp,duration_sec,status,status_detail,frida_log_path,strace_log_path,frida_csv_path,frida_quality_path,metadata_path,arm,metadata_source,context_confidence,session_id,planner_model`

Fields:

- `sample_id`: short identifier derived from APK SHA256 prefix.
- `apk_filename`: APK basename.
- `apk_sha256`: SHA256 of APK file.
- `label`: source folder name used as label in batch execution.
- `source`: APK input folder path.
- `package_name`: Android package name extracted from APK.
- `analysis_timestamp`: UTC timestamp for sample run.
- `duration_sec`: configured per-app analysis duration.
- `status`: backward-compatible coarse result (`success` or `failed`).
- `status_detail`: fine-grained result (`success`, `failed_extract_package`, `failed_install`, `failed_app_unstable`, `failed_frida_attach`, `failed_unexpected`, `failed_parse`, `failed_quality_gate`, `failed_analyze`).
  - May also contain protocol outcomes such as `partial:*`, `skip:*`, or `flag:*` from session metadata.
- `frida_log_path`: path to raw Frida JSONL output.
- `strace_log_path`: path to pulled strace log.
- `frida_csv_path`: path to parsed Frida CSV.
- `frida_quality_path`: path to Frida parse quality JSON.
- `metadata_path`: path to per-sample metadata JSON.
- `arm`: stimulation arm (`llm`, `monkey`, `unknown`).
- `metadata_source`: context source (`google_play`, `fdroid`, `apk_only`, `unknown`).
- `context_confidence`: context confidence (`high`, `medium`, `low`, `unknown`).
- `session_id`: per-session identifier.
- `planner_model`: LLM planner model name (`unknown` for non-LLM runs).

## `<package>_dynamic_metadata.json`

Primary fields:

- `package_name`
- `apk_path`
- `apk_sha256`
- `duration_sec`
- `started_at_epoch_ms`
- `elapsed_sec`
- `frida_mode`
- `hook_script_path`
- `hook_script_sha256`
- `app_pid`
- `strace_enabled`
- `strace_skip_reason`
- `frida_log_path`
- `frida_lines`
- `strace_log_path`
- `strace_size_bytes`
- `analysis_status`
- `analysis_exit_code`
- `monkey_seed`
- `arm`
- `session_id`
- `metadata_source`
- `context_confidence`
- `planner_model`
- `llm_status`
- `llm_actions_count`
- `llm_action_log_path`
- `app_context`
- `context_audit`
- `pre_setup` (see below)
- `snapshot_restored`
- `pm_clear_rc`

### `pre_setup` object

Present when the pipeline runs **LLM** arm pre-simulation setup, or **monkey** arm with **`--fairness-protocol`** (shared onboarding path before Frida attach).

| Field | Type | Meaning |
| ----- | ---- | ------- |
| `permissions_attempted` | int | Declared dangerous/runtime permissions `pm grant` was attempted for. |
| `permissions_granted` | int | Grants that returned success. |
| `warmup_monkey_rc` | int | Exit code from the short pre-onboarding Monkey warmup (seed/duration from `protocol_config`). |
| `dialogs_tapped_before_warmup` | int | Number of **tap** actions accepted during dialog resolution **before** warmup Monkey (each tap may also send ENTER). |
| `dialogs_tapped_after_warmup` | int | Same, **after** warmup Monkey. |
| `dialog_resolution_before_warmup` | array | Structured log for the **before-warmup** dialog phase (see step schema below). |
| `dialog_resolution_after_warmup` | array | Structured log for the **after-warmup** phase. |
| `verified_start_dump_rc` | int | `uiautomator dump` return code for the verified-start snapshot. |
| `verified_start_pull_rc` | int | `adb pull` return code for that XML. |
| `verified_start_path` | string | Local path to pulled `*_verified_start.xml`. |

**Dialog resolution step** (each element of `dialog_resolution_*` arrays):

| Key | Meaning |
| --- | ------- |
| `round` | 1-based iteration index within that phase (max rounds bounded in `analyze_apk`). |
| `action` | `tap`, `back`, or `none`. `back` is emitted when the transition guard detects a stuck repeat (same UI fingerprint and same tap target as the previous round). |
| `reason` | Heuristic label (e.g. `dismiss`, `permission_allow`, `allowish`, `no_confident_target`, `transition_guard_stuck_repeat`). |
| `target` | Present for `tap`: `[x, y]` in device coordinates. |
| `node_count` | Number of parsed nodes with valid bounds on that screen. |
| `screen_hash` | Short stable fingerprint (hex prefix of SHA-256 over a canonical encoding of visible node text/rid/class/center list) for comparing screens across runs. |
| `repeat_hash_streak` | Present on `back` steps: how many consecutive rounds shared the same UI hash when BACK was chosen. |

**Quick device pilot** (requires a connected device/emulator, `adb` on `PATH`, Frida/`frida-server` as in your usual setup):

```bash
cd /path/to/ContextDroid
python3 extraction_pipeline/analyze_apk.py \
  --apk /path/to/app.apk \
  --pkg com.example.app \
  --duration 30 \
  --output-dir logs/pilot_run \
  --arm monkey \
  --fairness-protocol
```

Then inspect `logs/pilot_run/<pkg>_dynamic_metadata.json` → `pre_setup` for `dialog_resolution_before_warmup` / `dialog_resolution_after_warmup`.

## `<package>_frida.csv`

Columns:

- `relative_time`: event timestamp relative to first valid event (ms).
- `category`: semantic category emitted by hook script.
- `api`: API/function identifier emitted by hook script.
- `args_str`: serialized event arguments JSON string.

## `<package>_frida.quality.json`

Fields:

- `total_lines`: number of non-empty lines processed from JSONL.
- `valid_events`: count of accepted event records.
- `malformed_lines`: count of malformed or incomplete event-like records.
- `non_event_lines`: count of structured non-event lines.
- `valid_ratio`: `valid_events / total_lines` (0 when total is 0).
- `unique_categories`: number of distinct event categories in valid events.
