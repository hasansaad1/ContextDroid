#!/usr/bin/env python3
"""Resumable fresh emulator runs for Step 6 PART A — scrollable cohort re-score."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "logs/step6_part_a/manifest.txt"
COLLECT_LOG = ROOT / "logs/step6_part_a/collect.log"
LOG_ROOT = ROOT / "logs/step6_part_a/after"
DURATION = int(os.environ.get("STEP6_PART_A_DURATION_SEC", "90"))


def log(msg: str) -> None:
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line, flush=True)
    COLLECT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with COLLECT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def scrollable_packages() -> list[str]:
    data = json.loads((ROOT / "experiment/phase_aware_metrics.json").read_text(encoding="utf-8"))
    sessions = (data.get("v6_success_pool_238") or {}).get("sessions") or []
    return sorted(
        {str(s["package"]) for s in sessions if s.get("cross_tab_bucket") == "high_back_wait_scrollable"}
    )


def manifest_lines() -> set[str]:
    if not MANIFEST.exists():
        return set()
    return {ln.strip() for ln in MANIFEST.read_text(encoding="utf-8").splitlines() if ln.strip()}


def append_manifest(jsonl: Path) -> None:
    path = str(jsonl.resolve())
    if path in manifest_lines():
        return
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    with MANIFEST.open("a", encoding="utf-8") as fh:
        fh.write(path + "\n")


def find_jsonl(log_root: Path, pkg: str) -> Path | None:
    hits = list(log_root.glob(f"**/{pkg}_llm_actions.jsonl"))
    for p in sorted(hits, key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file() and p.stat().st_size > 0:
            return p
    return None


def find_apk(pkg: str) -> Path | None:
    for base in (ROOT / "data/apks").rglob(f"{pkg}_*.apk"):
        return base
    direct = ROOT / "data/apks" / f"{pkg}.apk"
    return direct if direct.is_file() else None


def ensure_device() -> None:
    env = os.environ.copy()
    sdk = env.get("ANDROID_SDK_ROOT") or str(Path.home() / "Library/Android/sdk")
    env["ANDROID_SDK_ROOT"] = sdk
    env["PATH"] = f"{sdk}/platform-tools:{env.get('PATH', '')}"

    def _online() -> str:
        proc = subprocess.run(["adb", "devices"], capture_output=True, text=True, env=env, check=False)
        for line in proc.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                return parts[0]
        return ""

    if not _online():
        log("emulator offline; calling ensure_emulator.sh")
        subprocess.run(["bash", str(ROOT / "extraction_pipeline/ensure_emulator.sh")], env=env, check=False)
    device = _online()
    if not device:
        log("FATAL: no emulator device")
        sys.exit(2)
    os.environ["ANDROID_SERIAL"] = device
    log(f"device={device}")


def collect_one(pkg: str) -> bool:
    out_dir = LOG_ROOT / pkg
    existing = find_jsonl(out_dir, pkg)
    if existing is not None:
        append_manifest(existing)
        log(f"skip existing {pkg} -> {existing}")
        return True

    apk = find_apk(pkg)
    if apk is None:
        log(f"MISSING APK for {pkg}")
        return False

    staging = out_dir / "_apk_staging"
    if staging.exists():
        for child in staging.iterdir():
            if child.is_symlink() or child.is_file():
                child.unlink()
    else:
        staging.mkdir(parents=True, exist_ok=True)
    link = staging / apk.name
    link.symlink_to(apk.resolve())

    ensure_device()
    env = os.environ.copy()
    env["CONTEXTDROID_RUN_LOG_DIR"] = str(out_dir)
    env.setdefault("EMULATOR_SHOW_WINDOW", "0")
    env["FRIDA_USE_DOCKER"] = "0"
    env["CONTEXTDROID_SKIP_SNAPSHOT_LOAD"] = "1"
    env["SESSIONS_PER_APP"] = "1"
    env["MIN_VALID_EVENTS"] = "0"
    env["MIN_CATEGORY_COUNT"] = "0"
    env["RUN_MODE"] = "llm_only"
    env.pop("ENABLE_COMPARISON", None)
    env.pop("CONTEXTDROID_PRE_STEP2", None)

    log(f"RUN {pkg} duration={DURATION}s")
    rc = subprocess.run(
        ["bash", str(ROOT / "extraction_pipeline/run_dynamic_dataset.sh"), str(staging), str(DURATION)],
        env=env,
        check=False,
    ).returncode
    if rc != 0:
        log(f"run_dynamic_dataset rc={rc} for {pkg} (continuing)")

    jsonl = find_jsonl(out_dir, pkg)
    if jsonl is not None:
        append_manifest(jsonl)
        log(f"OK {pkg} -> {jsonl}")
        return True
    log(f"NO JSONL for {pkg}")
    return False


def main() -> int:
    log("=== collect_step6_scrollable_rescore start ===")
    ensure_device()
    pkgs = scrollable_packages()
    log(f"scrollable cohort n={len(pkgs)} duration={DURATION}s")
    ok = 0
    for pkg in pkgs:
        try:
            if collect_one(pkg):
                ok += 1
        except Exception as exc:
            log(f"exception {pkg}: {exc}")
    log(f"=== done collected={ok}/{len(pkgs)} ===")
    return 0 if ok == len(pkgs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
