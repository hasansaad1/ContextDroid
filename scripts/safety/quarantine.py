#!/usr/bin/env python3
"""Seal/unseal APK samples into vault quarantine as AES-256 7z archives."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "extraction_pipeline"))

from safety.vault_paths import (  # noqa: E402
    QUARANTINE_7Z_PASSWORD,
    STAGING_DIR,
    assert_mounted,
    quarantine_archive_path,
    resolve_staging_path,
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _seven_zip_bin() -> str:
    for candidate in ("7z", "7za"):
        found = shutil.which(candidate)
        if found:
            return found
    raise RuntimeError("7z/7za not found on PATH")


def seal(apk_path: Path) -> Path:
    """Seal an APK into quarantine/<sha256>.7z; remove staging copy of raw APK afterward."""
    assert_mounted()
    apk = Path(apk_path).resolve()
    if not apk.is_file():
        raise FileNotFoundError(apk)
    digest = _sha256_file(apk)
    archive = quarantine_archive_path(digest)
    archive.parent.mkdir(parents=True, exist_ok=True)

    staging_apk = STAGING_DIR.resolve() / f"seal_{digest}.apk"
    shutil.copy2(apk, staging_apk)
    seven = _seven_zip_bin()
    cmd = [
        seven,
        "a",
        "-t7z",
        "-mhe=on",
        f"-p{QUARANTINE_7Z_PASSWORD}",
        str(archive),
        str(staging_apk),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        staging_apk.unlink(missing_ok=True)
        raise RuntimeError(
            f"7z seal failed (rc={proc.returncode}): {(proc.stderr or proc.stdout or '').strip()}"
        )
    staging_apk.unlink(missing_ok=True)
    # If caller placed the APK directly under staging/, remove the raw file after seal.
    try:
        if apk.parent.resolve() == STAGING_DIR.resolve():
            apk.unlink(missing_ok=True)
    except OSError:
        pass
    return archive


def unseal(sha256: str, dest: Path | str) -> Path:
    """Extract quarantine archive to dest (must resolve under staging/)."""
    assert_mounted()
    target = resolve_staging_path(dest)
    archive = quarantine_archive_path(sha256)
    if not archive.is_file():
        raise FileNotFoundError(archive)
    target.parent.mkdir(parents=True, exist_ok=True)
    seven = _seven_zip_bin()
    cmd = [
        seven,
        "x",
        f"-p{QUARANTINE_7Z_PASSWORD}",
        f"-o{target.parent}",
        str(archive),
        "-y",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"7z unseal failed (rc={proc.returncode}): {(proc.stderr or proc.stdout or '').strip()}"
        )
    # Archive contains a single APK named seal_<sha>.apk or original basename — pick extracted .apk
    extracted = sorted(target.parent.glob("*.apk"))
    if not extracted:
        raise RuntimeError(f"unseal produced no APK under {target.parent}")
    if len(extracted) == 1:
        out = extracted[0]
    else:
        out = max(extracted, key=lambda p: p.stat().st_mtime)
    if out != target:
        out.rename(target)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Vault quarantine seal/unseal")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_seal = sub.add_parser("seal", help="Seal APK into quarantine/")
    p_seal.add_argument("apk_path", type=Path)

    p_unseal = sub.add_parser("unseal", help="Unseal to staging/ only")
    p_unseal.add_argument("sha256")
    p_unseal.add_argument("dest", type=Path, help="Destination path under staging/")

    args = parser.parse_args(argv)
    if args.cmd == "seal":
        archive = seal(args.apk_path)
        print(archive)
        return 0
    if args.cmd == "unseal":
        out = unseal(args.sha256, args.dest)
        print(out)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
