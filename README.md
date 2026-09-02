# ContextDroid — Android Dynamic Behavior Dataset Pipeline

ContextDroid collects **benign** Android app behaviour traces in an emulator sandbox:
Frida API hooks, optional strace, and LLM- or monkey-driven UI stimulation. The repository
holds the collection code, safety harness for a planned malware tier, and packaged exports
used in thesis evaluation.

**Primary corpus:** the **v2 reference tier** (168 sessions, 59 apps) and the **v2_extended**
export (388 sessions). Session bundles and export traces are described under
[Data availability](#data-availability) below; they are not committed in this repository.

This repository contains a reproducible dynamic-analysis pipeline for Android APKs.
It installs apps on an emulator, runs deterministic + monkey-driven interaction, captures Frida and strace telemetry, and emits dataset-ready CSV/JSON artifacts.

## Safety — read before running anything

> **The corpus collected and exported from this repository is benign-only.** No malware
> samples were executed during v2 collection.

This repository also contains a **malware-tier collection harness** (vault, network sink,
device guard, go/no-go interlock, `-wipe-data` AVD workflow). Status:

| Control | Status |
|---------|--------|
| Benign collection (`run_dynamic_dataset.sh`, bulk LLM runners) | **Implemented and exercised** on benign F-Droid APKs |
| Repo hygiene gates (`scripts/safety/gate_p0.sh` … `gate_p5.sh`) | **Implemented**; cold-run green per project notes |
| Network sink + DNAT (`scripts/safety/network_sink*.sh`) | **Implemented**; validated on benign canary traffic |
| Device guard + two-emulator fail-closed | **Implemented**; tested with benign fixtures |
| Malware vault + `run_sample.py` | **Implemented**; **not exercised** on real malware |
| Human go/no-go (`CONTEXTDROID_MALWARE_GO`) | **Default NO-GO** — see `SAFETY.md` and `docs/operator_go_nogo_checklist.md` |

**Do not run malware collection** unless you have read `SAFETY.md`, passed all phase gates,
signed the operator checklist, and can provide the isolation this repository does **not**
verify for you (encrypted vault, dedicated AVD `abrg_mw`, network sink, host monitoring).
The README quick-start path is for **benign** APK folders only.

Governing safety docs: `SAFETY.md`, `docs/malware_corpus_safety_plan.md`,
`docs/malware_host_defense_plan.md`.

## Scope

- Included:
  - Dynamic behavior extraction code
  - Frida hooks
  - Manifest-based benign APK download workflow
  - Reproducibility metadata outputs
- Not included:
  - APK binaries
  - Private/internal datasets
  - Credentials/secrets

## Data availability

The v2 corpus session bundles are **not included** in this repository. Each bundle
packages Frida JSONL traces, LLM action logs, strace output, and per-session metadata
for the reference tier (168 sessions, 59 apps) and the extended collection (388 sessions
total). Corpus statistics, quality gates, and faithfulness labels reported in the thesis
were computed from these local bundles.

They are omitted because session metadata records absolute filesystem paths from the
collection machine (`apk_path`, `hook_script_path`, and all `*_log_path` fields), and
path sanitisation is not yet complete. The collection code in this repository is
complete; reproducing the exact corpus requires the bundles or a fresh collection run.

The bundles may be published in sanitised form later. Until then, contact the author
to request access for thesis reproduction.

## Project Structure

- `setup/`: environment and emulator setup
- `extraction_pipeline/`: per-APK analysis and parsing pipeline
- `frida_scripts/`: Frida JS hook definitions
- `manifests/`: package manifests and manifest generator
- `scripts/safety/`: malware-tier gates and session tooling (see Safety above)
- `docs/`: methodology, schemas, and safety plans

Local-only (not committed): `experiment/v2_dataset_bundle/`, `export/v2_extended/` — see
[Data availability](#data-availability).

## Prerequisites

- macOS or Linux
- Python 3.8+ (tested with 3.14 + pinned deps in `requirements.txt`)
- **`adb`** on `PATH`, or install locally without the full SDK:

  ```bash
  bash setup/install_adb_platform_tools.sh
  ```

  This unpacks Google’s standalone platform-tools under `tools/platform-tools/` (gitignored). `analyze_apk.py` resolves that `adb` automatically before searching `PATH` or `~/Library/Android/sdk`.

- For emulator workflows: Android SDK (`emulator`, `sdkmanager`, `avdmanager`, `aapt`) via `setup/install_dependencies.sh`
- Optional: Docker Desktop (recommended on macOS for Frida client stability)
- Optional: `fdroidcl` (for manifest-based benign APK acquisition)

Architecture note:

- `setup/install_dependencies.sh` auto-selects emulator ABI from host CPU:
  - Apple Silicon / ARM hosts -> `arm64-v8a`
  - Intel x86_64 hosts -> `x86_64`
- You can override with `TARGET_ABI=<abi>` when needed.

## Quick Start

```bash
cd ContextDroid
bash setup/install_dependencies.sh
bash setup/setup_emulator.sh
```

Run dataset generation:

```bash
bash extraction_pipeline/run_dynamic_dataset.sh /path/to/apk_folder 180
```

LLM-only mode (Phase 1 primary path):

```bash
ARM_MODE=llm OLLAMA_MODEL=llama3.2 OLLAMA_ENDPOINT=http://127.0.0.1:11434 \
bash extraction_pipeline/run_dynamic_dataset.sh /path/to/apk_folder 120
```

Comparison-enabled mode (runs `llm` + `monkey`, 3 sessions per arm by default):

```bash
ENABLE_COMPARISON=1 RUN_MODE=llm_plus_monkey OLLAMA_MODEL=llama3.2 \
bash extraction_pipeline/run_dynamic_dataset.sh /path/to/apk_folder 120
```

Validate arm/session artifact parity after comparison runs:

```bash
python3 extraction_pipeline/validate_comparison_artifacts.py --index logs/dataset_index.csv --expected-sessions 3
```

Compute comparison metrics (Phase 3, optional post-collection):

```bash
python3 extraction_pipeline/compute_comparison_metrics.py --index logs/dataset_index.csv --output-dir logs/comparison_metrics
```

Generate final markdown comparison report:

```bash
python3 extraction_pipeline/generate_comparison_report.py --metrics-dir logs/comparison_metrics --output logs/comparison_metrics/final_comparison_report.md
```

Generated files:

- `logs/comparison_metrics/session_metrics.csv`
- `logs/comparison_metrics/arm_summary.csv`
- `logs/comparison_metrics/app_union_summary.csv`
- `logs/comparison_metrics/final_comparison_report.md`

Session policy:

- default (`ENABLE_COMPARISON=0`): 1 session per app
- comparison enabled (`ENABLE_COMPARISON=1`): 3 sessions per app per arm
- override: `SESSIONS_PER_APP=<n>`

Optional deterministic monkey seed:

```bash
MONKEY_SEED=1337 bash extraction_pipeline/run_dynamic_dataset.sh /path/to/apk_folder 180
```

Arguments:
- argument 1: folder containing APK files
- argument 2: per-app analysis duration in seconds (default `180`)

## Outputs

All outputs are written under `logs/`.
For each APK:

- `logs/<sample_id>_<package>/dynamic/<package>_frida.jsonl`
- `logs/<sample_id>_<package>/dynamic/<package>_frida.csv`
- `logs/<sample_id>_<package>/dynamic/<package>_frida.quality.json`
- `logs/<sample_id>_<package>/dynamic/<package>_strace.log`
- `logs/<sample_id>_<package>/dynamic/<package>_monkey.log`
- `logs/<sample_id>_<package>/dynamic/<package>_dynamic_metadata.json`

Global index:

- `logs/dataset_index.csv`
- `logs/run_log.txt`
- `pipeline.log`

Field-level schema notes are documented in `docs/output_schemas.md`.

`dataset_index.csv` keeps backward-compatible `status` (`success`/`failed`) and includes a finer-grained `status_detail` column for traceability.
In LLM mode, additive columns include `arm`, `metadata_source`, `context_confidence`, `session_id`, and `planner_model`.

## Reproducibility Notes

- The pipeline records APK SHA256 and hook script SHA256 for traceability.
- Pin your experiment by tagging the git commit used for dataset production.
- When releasing a dataset, include:
  - repository URL
  - commit/tag
  - manifest file used
  - command lines + environment variables

Recommended run manifest for reproducibility:

- host OS + version
- Python version
- Android SDK build-tools/platform-tools versions
- emulator image/API level
- Frida mode (`FRIDA_USE_DOCKER`)
- quality thresholds (`MIN_VALID_EVENTS`, `MIN_CATEGORY_COUNT`)

## Methodology and Artifact Notes

- Methodology overview: `docs/methodology.md`
- Protocol constants and run modes: `docs/protocol_constants.md`
- Output schemas and examples: `docs/output_schemas.md`
- Citation metadata: `CITATION.cff`
- License: root `LICENSE`
- Third-party source and redistribution notes: `LICENSES.md`

## Safety and Legal

- **Benign collection:** use an isolated emulator; do not commit APKs or raw logs to git.
- **Malware tier:** default posture is NO-GO; see the Safety section above.
- Ensure you have legal rights to process and redistribute any data artifacts.
- Do not publish APK binaries unless licenses explicitly allow it.
- Runtime F-Droid metadata may include AGPL-licensed apps; this repo does not redistribute
  APKs or metadata dumps — see `LICENSES.md`.
