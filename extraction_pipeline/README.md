# Extraction pipeline

Per-APK dynamic analysis: emulator install, Frida/strace capture, LLM or monkey UI stimulation, log parsing, and dataset indexing. Entry points include `analyze_apk.py`, `run_dynamic_dataset.sh`, and bulk resumable runners under this directory. Outputs land in `logs/` (gitignored). See root `README.md` and `docs/output_schemas.md`.
