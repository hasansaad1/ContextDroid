# Methodology Notes (Dynamic Dataset Generation)

## Scope

This repository contains only the dynamic dataset-production pipeline for Android APK behavior capture. It intentionally excludes static feature extraction, graph-building stages, and private/internal assets.

Protocol constants frozen for the LLM-first methodology are documented in `docs/protocol_constants.md`.

## High-Level Procedure

1. Prepare environment and Android emulator tooling.
2. Install APK on emulator and launch the app.
3. Attach Frida hooks from `frida_scripts/hook_apis.js`.
4. Run deterministic stimulation followed by monkey-driven UI events.
5. Collect runtime traces (Frida JSONL and strace logs).
6. Parse Frida logs into CSV and quality metrics.
7. Record per-sample metadata and append dataset index entries.

## Reproducibility Controls

- Manifest-driven APK acquisition is supported via F-Droid tooling.
- Per-sample metadata records:
  - APK path and SHA256
  - hook script path and SHA256
  - duration and runtime timing fields
  - Frida mode and strace capture indicators
- Global index (`logs/dataset_index.csv`) records status and output artifact paths per sample.

## Determinism and Variance

- The pipeline applies deterministic stimulation before monkey events.
- Monkey traffic introduces controlled randomness by design; publication artifacts should report configuration and runtime parameters for interpretability.

## Data Handling and Safety

- Do not commit APK binaries, credentials, or private datasets.
- Run malware analysis only in isolated/sandboxed environments.
- Ensure legal rights for any redistribution of generated artifacts.

## Suggested Publication Metadata

Include the following in thesis/dataset release notes:

- repository URL and commit hash/tag
- manifest file/hash used for sample acquisition
- command line invocation and environment variables
- host environment (OS, Python, SDK/emulator details)
- run date window and quality-threshold settings
