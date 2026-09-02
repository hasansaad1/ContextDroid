#!/usr/bin/env python3
"""Step 5 behavioral-equivalence verification — fresh sessions before/after refactor."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGETS = [
    "ch.famoser.mensa",
    "ch.protonvpn.android",
    "app.govroam.getgovroam",
    "at.krixec.ied",
    "code.alimiracle.image_meta_cleaner",
]
DURATION = int(os.environ.get("STEP5_DURATION_SEC", "120"))


def log(msg: str, log_root: Path) -> None:
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line, flush=True)
    log_root.mkdir(parents=True, exist_ok=True)
    with (log_root / "collect.log").open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def find_apk(pkg: str) -> Path | None:
    for base in (ROOT / "data/apks").rglob(f"{pkg}_*.apk"):
        return base
    direct = ROOT / "data/apks" / f"{pkg}.apk"
    return direct if direct.is_file() else None


def ensure_device() -> str:
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

    device = _online()
    if not device:
        subprocess.run(
            ["bash", str(ROOT / "extraction_pipeline/ensure_emulator.sh")],
            env=env,
            check=False,
        )
        device = _online()
    if not device:
        print("FATAL: no emulator device", file=sys.stderr)
        sys.exit(2)
    os.environ["ANDROID_SERIAL"] = device
    return device


def collect_one(pkg: str, phase: str, *, force: bool = False) -> Path | None:
    log_root = ROOT / "logs/step5_verify" / phase
    out_dir = log_root / pkg.replace(".", "_")
    existing = list(out_dir.glob(f"**/{pkg}_llm_actions.jsonl"))
    existing = [p for p in existing if p.is_file() and p.stat().st_size > 0]
    if existing and not force:
        path = sorted(existing, key=lambda p: p.stat().st_mtime, reverse=True)[0]
        log(f"skip existing {pkg} -> {path}", log_root)
        return path

    apk = find_apk(pkg)
    if apk is None:
        log(f"MISSING APK for {pkg}", log_root)
        return None

    staging = log_root / f"apk_staging_{pkg.replace('.', '_')}"
    if staging.exists():
        import shutil

        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)
    link = staging / apk.name
    if link.exists() or link.is_symlink():
        link.unlink()
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

    log(f"collect {phase} {pkg} duration={DURATION}s -> {out_dir}", log_root)
    rc = subprocess.run(
        ["bash", str(ROOT / "extraction_pipeline/run_dynamic_dataset.sh"), str(staging), str(DURATION)],
        env=env,
        check=False,
    ).returncode
    hits = list(out_dir.glob(f"**/{pkg}_llm_actions.jsonl"))
    hits = [p for p in hits if p.stat().st_size > 0]
    if not hits:
        log(f"FAILED collect {pkg} rc={rc}", log_root)
        return None
    path = sorted(hits, key=lambda p: p.stat().st_mtime, reverse=True)[0]
    log(f"OK {pkg} -> {path}", log_root)
    return path


def main() -> int:
    phase = os.environ.get("STEP5_PHASE", "before").strip()
    force = os.environ.get("STEP5_FORCE", "").strip() == "1"
    only = os.environ.get("STEP5_ONLY", "").strip()
    targets = [only] if only else TARGETS
    log_root = ROOT / "logs/step5_verify" / phase
    results: list[tuple[str, Path | None]] = []
    for pkg in targets:
        results.append((pkg, collect_one(pkg, phase, force=force)))
    manifest = log_root / "manifest.txt"
    lines = [str(p.resolve()) for _, p in results if p is not None]
    manifest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return 0 if all(p is not None for _, p in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
