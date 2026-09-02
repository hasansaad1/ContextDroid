#!/usr/bin/env python3
"""Fresh Step 4 verification sessions (YidKey + EditText stall cohort)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGETS = [
    "click.dummer.yidkey",
    "app.eduroam.geteduroam",
    "app.govroam.getgovroam",
    "at.krixec.ied",
]
LOG_ROOT = ROOT / "logs/step4_verify"
DURATION = int(os.environ.get("STEP4_DURATION_SEC", "120"))
COLLECT_LOG = LOG_ROOT / "collect.log"


def log(msg: str) -> None:
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line, flush=True)
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    with COLLECT_LOG.open("a", encoding="utf-8") as fh:
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
        log("emulator offline; calling ensure_emulator.sh")
        subprocess.run(
            ["bash", str(ROOT / "extraction_pipeline/ensure_emulator.sh")],
            env=env,
            check=False,
        )
        device = _online()
    if not device:
        log("FATAL: no emulator device")
        sys.exit(2)
    os.environ["ANDROID_SERIAL"] = device
    log(f"device={device}")
    return device


def find_jsonl(log_root: Path, pkg: str) -> Path | None:
    hits = list(log_root.glob(f"**/{pkg}_llm_actions.jsonl"))
    for p in sorted(hits, key=lambda x: x.stat().st_mtime, reverse=True):
        if p.is_file() and p.stat().st_size > 0:
            return p
    return None


def collect_one(pkg: str) -> Path | None:
    out_dir = LOG_ROOT / pkg.replace(".", "_")
    existing = find_jsonl(out_dir, pkg)
    if existing is not None:
        log(f"skip existing {pkg} -> {existing}")
        return existing

    apk = find_apk(pkg)
    if apk is None:
        log(f"MISSING APK for {pkg}")
        return None

    staging = LOG_ROOT / f"apk_staging_{pkg.replace('.', '_')}"
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

    log(f"collect {pkg} duration={DURATION}s -> {out_dir}")
    rc = subprocess.run(
        ["bash", str(ROOT / "extraction_pipeline/run_dynamic_dataset.sh"), str(staging), str(DURATION)],
        env=env,
        check=False,
    ).returncode
    hits = list(out_dir.glob(f"**/{pkg}_llm_actions.jsonl"))
    hits = [p for p in hits if p.stat().st_size > 0]
    if not hits:
        log(f"FAILED collect {pkg} rc={rc}")
        return None
    path = sorted(hits, key=lambda p: p.stat().st_mtime, reverse=True)[0]
    log(f"OK {pkg} -> {path}")
    return path


def main() -> int:
    sys.path.insert(0, str(ROOT / "extraction_pipeline"))
    from quality_rules import _explore_metrics

    manifest = LOG_ROOT / "manifest.txt"
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    results: list[tuple[str, Path | None]] = []
    for pkg in TARGETS:
        results.append((pkg, collect_one(pkg)))

    lines = [str(p.resolve()) for _, p in results if p is not None]
    manifest.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    print("\n=== STEP 4 ACCEPTANCE SUMMARY ===")
    for pkg, path in results:
        if path is None:
            print(f"{pkg}: NO LOG")
            continue
        actions = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
        m = _explore_metrics(actions)
        inputs = [
            a
            for a in actions
            if str((a.get("parsed_action") or {}).get("action_type")) == "input"
            and str((a.get("parsed_action") or {}).get("text") or "").strip()
        ]
        advances = [
            a
            for a in actions
            if str((a.get("parsed_action") or {}).get("action_type")) == "advance_goal"
        ]
        print(
            f"{pkg}: ft={m['explore_functional_tap_count']} bw={m['explore_back_wait_ratio']:.2f} "
            f"inputs_with_text={len(inputs)} advance_goal={len(advances)} log={path}"
        )

    transitions_hits = 0
    for _, path in results:
        if path is None:
            continue
        plan = path.parent / path.name.replace("_llm_actions.jsonl", "_llm_ux_plan.json")
        if plan.is_file():
            blob = plan.read_text(encoding="utf-8", errors="replace")
            if "Tap TRANSITIONS:" in blob or "tap transitions:" in blob.lower():
                transitions_hits += 1
        for a in json.loads(path.read_text()):
            for key in ("ux_goal_active",):
                if "TRANSITIONS:" in str(a.get(key) or ""):
                    transitions_hits += 1
    print(f"TRANSITIONS degenerate goal hits in fresh logs: {transitions_hits}")
    return 0 if all(p is not None for _, p in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
