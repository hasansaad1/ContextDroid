#!/usr/bin/env python3
"""Resumable Step 2 verification log collection (ProtonVPN BEFORE + OTHER cohort AFTER)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = Path(
    os.environ.get(
        "STEP2_CORPUS_AFTER_MANIFEST",
        str(ROOT / "logs/step2_corpus_after_manifest.txt"),
    )
)
COLLECT_LOG = ROOT / "logs/step2_verification/collect.log"
OTHER_DURATION = int(os.environ.get("OTHER_DURATION_SEC", "90"))
VPN_DURATION = int(os.environ.get("VPN_DURATION_SEC", "120"))


def log(msg: str) -> None:
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line, flush=True)
    COLLECT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with COLLECT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def manifest_lines() -> set[str]:
    if not MANIFEST.exists():
        return set()
    return {ln.strip() for ln in MANIFEST.read_text(encoding="utf-8").splitlines() if ln.strip()}


def append_manifest(jsonl: Path) -> None:
    if not jsonl.is_file() or jsonl.stat().st_size == 0:
        return
    path = str(jsonl.resolve())
    if path in manifest_lines():
        return
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    with MANIFEST.open("a", encoding="utf-8") as fh:
        fh.write(path + "\n")
    log(f"manifest + {path}")


def find_jsonl(log_root: Path, pkg: str) -> Path | None:
    hits = list(log_root.glob(f"*/dynamic/llm/session_1/{pkg}_llm_actions.jsonl"))
    for p in hits:
        if p.is_file() and p.stat().st_size > 0:
            return p
    return None


def find_apk(pkg: str) -> Path | None:
    for base in (ROOT / "data/apks").rglob(f"{pkg}_*.apk"):
        return base
    direct = ROOT / "data/apks" / f"{pkg}.apk"
    return direct if direct.is_file() else None


def other_packages() -> list[str]:
    data = json.loads((ROOT / "experiment/phase_aware_metrics.json").read_text(encoding="utf-8"))
    sessions = (data.get("v6_success_pool_238") or {}).get("sessions") or []
    return sorted(
        {str(s["package"]) for s in sessions if s.get("cross_tab_bucket") == "high_back_wait_other"}
    )


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
        log("FATAL: no emulator device — stopping (no projected values)")
        sys.exit(2)
    os.environ["ANDROID_SERIAL"] = device
    log(f"device={device}")


def collect_one(pkg: str, duration: int, log_root: Path, *, pre_step2: bool = False) -> bool:
    existing = find_jsonl(log_root, pkg)
    if existing is not None:
        append_manifest(existing)
        log(f"skip existing {pkg} -> {existing}")
        return True

    apk = find_apk(pkg)
    if apk is None:
        log(f"MISSING APK for {pkg}")
        return False

    staging = log_root / "apk_staging"
    staging.mkdir(parents=True, exist_ok=True)
    link = staging / apk.name
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(apk.resolve())

    ensure_device()
    env = os.environ.copy()
    env["CONTEXTDROID_RUN_LOG_DIR"] = str(log_root)
    env.setdefault("EMULATOR_SHOW_WINDOW", "0")
    env["FRIDA_USE_DOCKER"] = "0"
    env["CONTEXTDROID_SKIP_SNAPSHOT_LOAD"] = "1"
    env["SESSIONS_PER_APP"] = "1"
    env["MIN_VALID_EVENTS"] = "0"
    env["MIN_CATEGORY_COUNT"] = "0"
    env["RUN_MODE"] = "llm_only"
    env.pop("ENABLE_COMPARISON", None)
    if pre_step2:
        env["CONTEXTDROID_PRE_STEP2"] = "1"
    else:
        env.pop("CONTEXTDROID_PRE_STEP2", None)

    log(f"RUN {pkg} duration={duration}s pre_step2={int(pre_step2)}")
    rc = subprocess.run(
        ["bash", str(ROOT / "extraction_pipeline/run_dynamic_dataset.sh"), str(staging), str(duration)],
        env=env,
        check=False,
    ).returncode
    if rc != 0:
        log(f"run_dynamic_dataset failed for {pkg} (rc={rc}, continuing)")

    jsonl = find_jsonl(log_root, pkg)
    if jsonl is not None:
        append_manifest(jsonl)
        log(f"OK {pkg} -> {jsonl}")
        return True
    log(f"NO JSONL for {pkg} under {log_root}")
    return False


def main() -> int:
    log("=== collect_step2_verification start (python) ===")
    ensure_device()

    vpn_after = (
        ROOT
        / "logs/step2_verification/protonvpn/after/0d50d7d9c132_ch.protonvpn.android/dynamic/llm/session_1/ch.protonvpn.android_llm_actions.jsonl"
    )
    if vpn_after.is_file():
        append_manifest(vpn_after)

    vpn_before_root = ROOT / "logs/step2_verification/protonvpn/before"
    collect_one("ch.protonvpn.android", VPN_DURATION, vpn_before_root, pre_step2=True)

    other_root = ROOT / "logs/step2_verification/other"
    pkgs = other_packages()
    log(f"OTHER cohort packages={len(pkgs)}")
    for pkg in pkgs:
        try:
            collect_one(pkg, OTHER_DURATION, other_root / pkg, pre_step2=False)
        except Exception as exc:
            log(f"collect_one exception for {pkg}: {exc}")

    log("=== collect_step2_verification done (python) ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
