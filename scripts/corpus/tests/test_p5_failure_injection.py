#!/usr/bin/env python3
"""Phase 5 failure-injection proofs (plan 5.5) — safe, fail-closed cases.

Deferred (need live multi-device / mid-run fault injection on abrg_mw; see
scripts/corpus/tests/FAILURE_INJECTION_DEFERRED.md):
  - emulator dies mid-run
  - vault unmounts mid-run
  - second adb device appears mid-run
  - sink goes down mid-run
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def _run(cmd: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(cmd, capture_output=True, text=True, cwd=str(REPO_ROOT), env=merged)


def test_refuse_guard_disable_on_malware_path() -> None:
    env = {"CONTEXTDROID_DEVICE_GUARD_DISABLE": "1"}
    proc = _run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "corpus" / "run_sample.py"),
            "--tier",
            "canary",
            "--sha256",
            "0" * 64,
            "--pkg",
            "ademar.textlauncher",
            "--no-boot-if-needed",
        ],
        env=env,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode != 0, blob
    assert "CONTEXTDROID_DEVICE_GUARD_DISABLE" in blob, blob
    assert "REFUSE" in blob, blob
    print("FAILINJ_OK refuse_guard_disable")


def test_refuse_malware_tier_without_go() -> None:
    env = {k: v for k, v in os.environ.items() if k != "CONTEXTDROID_MALWARE_GO"}
    env.pop("CONTEXTDROID_MALWARE_GO", None)
    env.pop("CONTEXTDROID_DEVICE_GUARD_DISABLE", None)
    proc = _run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "corpus" / "run_sample.py"),
            "--tier",
            "malware",
            "--sha256",
            "0" * 64,
            "--pkg",
            "ademar.textlauncher",
            "--no-boot-if-needed",
        ],
        env=env,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode != 0, blob
    assert "CONTEXTDROID_MALWARE_GO=1" in blob, blob
    assert "REFUSE" in blob, blob
    assert "unsealed" not in blob.lower() or "REFUSE" in blob
    print("FAILINJ_OK refuse_malware_without_go")


def test_refuse_seal_from_on_malware_tier() -> None:
    env = {k: v for k, v in os.environ.items()}
    env["CONTEXTDROID_MALWARE_GO"] = "1"
    env.pop("CONTEXTDROID_DEVICE_GUARD_DISABLE", None)
    # Any path is fine — refuse must happen before file existence matters.
    fake_apk = REPO_ROOT / "data" / "apks" / "benign" / "does_not_need_to_exist.apk"
    proc = _run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "corpus" / "run_sample.py"),
            "--tier",
            "malware",
            "--seal-from",
            str(fake_apk),
            "--pkg",
            "ademar.textlauncher",
            "--no-boot-if-needed",
        ],
        env=env,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode != 0, blob
    assert "seal-from is only allowed for --tier canary" in blob, blob
    assert "REFUSE" in blob, blob
    print("FAILINJ_OK refuse_seal_from_on_malware")


def test_malware_go_still_fail_closed_without_sample() -> None:
    """With GO set, missing archive must fail closed — no download/install of real malware."""
    env = {k: v for k, v in os.environ.items()}
    env["CONTEXTDROID_MALWARE_GO"] = "1"
    env.pop("CONTEXTDROID_DEVICE_GUARD_DISABLE", None)
    proc = _run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "corpus" / "run_sample.py"),
            "--tier",
            "malware",
            "--sha256",
            "0" * 64,
            "--pkg",
            "ademar.textlauncher",
            "--no-boot-if-needed",
        ],
        env=env,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode != 0, blob
    assert "REFUSE: --tier malware requires" not in blob, blob
    assert "run_sample: OK" not in blob, blob
    assert "analyze_apk starting" not in blob, blob
    assert (
        "REFUSE" in blob
        or "quarantine archive missing" in blob
        or "vault not mounted" in blob
        or "VaultNotMounted" in blob
    ), blob
    print("FAILINJ_OK malware_go_fail_closed_no_sample")


def test_refuse_missing_archive() -> None:
    env = {k: v for k, v in os.environ.items() if k != "CONTEXTDROID_DEVICE_GUARD_DISABLE"}
    env.pop("CONTEXTDROID_DEVICE_GUARD_DISABLE", None)
    # Ensure guard not disabled.
    proc = _run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "corpus" / "run_sample.py"),
            "--tier",
            "canary",
            "--sha256",
            "a" * 64,
            "--pkg",
            "ademar.textlauncher",
            "--no-boot-if-needed",
        ],
        env=env,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode != 0, blob
    # Either vault not mounted or archive missing — both fail closed.
    assert (
        "REFUSE" in blob
        or "quarantine archive missing" in blob
        or "vault not mounted" in blob
        or "VaultNotMounted" in blob
    ), blob
    print("FAILINJ_OK refuse_missing_or_vault")


def test_config_parity_mutation() -> None:
    proc = _run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "safety" / "config_parity_check.py"),
            "selftest",
            "--out-dir",
            str(REPO_ROOT / "logs" / "p5_config_parity"),
        ]
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode == 0, blob
    assert "CONFIG_PARITY_MUTATION_DETECTED_OK" in blob, blob
    print("FAILINJ_OK config_parity_mutation")


def test_install_fails_bad_apk_bytes() -> None:
    """Seal a non-APK blob; unseal+install must abort with ledger residue-free staging."""
    sys.path.insert(0, str(REPO_ROOT / "extraction_pipeline"))
    from safety.vault_paths import STAGING_DIR, is_mounted

    if not is_mounted():
        print("FAILINJ_SKIP install_fails_bad_apk (vault not mounted)")
        return

    # Import quarantine after path setup.
    sys.path.insert(0, str(REPO_ROOT / "scripts" / "safety"))
    import quarantine as q  # noqa: WPS433

    with tempfile.TemporaryDirectory() as td:
        junk = Path(td) / "not_an_apk.apk"
        junk.write_bytes(b"PK\x03\x04not-a-real-android-package")
        archive = q.seal(junk)
        sha = archive.stem
        print(f"FAILINJ sealed junk sha={sha}")

    env = {k: v for k, v in os.environ.items() if k != "CONTEXTDROID_DEVICE_GUARD_DISABLE"}
    env["ANDROID_SERIAL"] = "emulator-5556"
    env["AVD_NAME"] = "abrg_mw"
    # Without device / with device: must fail closed and leave staging empty.
    proc = _run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "corpus" / "run_sample.py"),
            "--tier",
            "canary",
            "--sha256",
            sha,
            "--pkg",
            "com.invalid.junk",
            "--duration",
            "10",
            "--arm",
            "monkey",
            "--no-boot-if-needed",
        ],
        env=env,
    )
    blob = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode != 0, blob
    # Staging must be empty after abort.
    if is_mounted() and STAGING_DIR.is_dir():
        left = list(STAGING_DIR.iterdir())
        assert not left, f"staging residue after failed run: {left}"
    print("FAILINJ_OK install_or_precond_fails_staging_empty")


def main() -> int:
    failures = 0
    for fn in (
        test_refuse_guard_disable_on_malware_path,
        test_refuse_malware_tier_without_go,
        test_refuse_seal_from_on_malware_tier,
        test_malware_go_still_fail_closed_without_sample,
        test_refuse_missing_archive,
        test_config_parity_mutation,
        test_install_fails_bad_apk_bytes,
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"FAILINJ_FAIL {fn.__name__}: {exc}")
    if failures:
        print(f"FAILINJ_SUMMARY FAIL={failures}")
        return 1
    print("FAILINJ_SUMMARY PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
