#!/usr/bin/env python3
"""Step 2 helpers: verify Zenodo downloads, extract, inventory."""

from __future__ import annotations

import hashlib
import json
import sys
import tarfile
from pathlib import Path

import paths  # noqa: F401
from paths import DATA_DIR, EXTRACT_DIR, OUT_DIR


def md5_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.md5()
    with path.open("rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def load_zenodo_checksums(record_path: Path) -> dict[str, str]:
    """Return {filename: md5hex} from Zenodo API JSON."""
    rec = json.loads(record_path.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for f in rec.get("files", []):
        key = f.get("key") or f.get("filename")
        cs = f.get("checksum") or ""
        # format md5:hex
        if cs.startswith("md5:"):
            out[key] = cs.split(":", 1)[1]
        elif "md5" in (f.get("checksums") or {}):
            out[key] = f["checksums"]["md5"]
    return out


def version_info(record_path: Path) -> dict:
    rec = json.loads(record_path.read_text(encoding="utf-8"))
    meta = rec.get("metadata", {})
    links = rec.get("links", {})
    return {
        "id": rec.get("id"),
        "conceptrecid": rec.get("conceptrecid"),
        "doi": rec.get("doi") or meta.get("doi"),
        "version": meta.get("version"),
        "publication_date": meta.get("publication_date"),
        "versions_url": links.get("versions"),
        "title": meta.get("title"),
    }


def inventory_extracted(root: Path) -> dict:
    """Walk extracted tree; report per-class file counts and naming."""
    report: dict = {"roots": {}, "sample_names": {}}
    for cls in ("benign", "malware"):
        # find dirs matching class
        matches = [p for p in root.rglob("*") if p.is_dir() and cls in p.name.lower()]
        files: list[Path] = []
        for m in matches:
            files.extend([f for f in m.rglob("*") if f.is_file()])
        # also flat layout
        if not files:
            files = [f for f in root.rglob("*") if f.is_file() and cls in str(f).lower()]
        report["roots"][cls] = {
            "matching_dirs": [str(p.relative_to(root)) for p in matches[:20]],
            "n_files": len(files),
            "extensions": sorted({f.suffix for f in files}),
        }
        report["sample_names"][cls] = [f.name for f in sorted(files)[:10]]
    # top-level structure
    report["top_level"] = sorted(p.name for p in root.iterdir()) if root.is_dir() else []
    return report


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    record = DATA_DIR / "zenodo_record.json"
    benign = DATA_DIR / "trace-benign-2019.tar.gz"
    malware = DATA_DIR / "trace-malware-2019.tar.gz"
    status: dict = {"ok": True, "errors": []}

    if not record.is_file():
        status["ok"] = False
        status["errors"].append("MISSING zenodo_record.json — Zenodo API unreachable")
        (OUT_DIR / "step2_status.json").write_text(json.dumps(status, indent=2) + "\n")
        print("FAIL:", status["errors"][-1])
        return 2

    try:
        status["version"] = version_info(record)
        checksums = load_zenodo_checksums(record)
        status["zenodo_md5"] = checksums
    except Exception as e:
        status["ok"] = False
        status["errors"].append(f"zenodo_record.json not valid JSON: {e}")
        (OUT_DIR / "step2_status.json").write_text(json.dumps(status, indent=2) + "\n")
        print("FAIL:", status["errors"][-1])
        return 2

    for path, key in ((benign, "trace-benign-2019.tar.gz"), (malware, "trace-malware-2019.tar.gz")):
        if not path.is_file():
            status["ok"] = False
            status["errors"].append(f"MISSING {path.name}")
            continue
        got = md5_file(path)
        exp = checksums.get(key)
        status.setdefault("local_md5", {})[key] = got
        status.setdefault("md5_match", {})[key] = (got == exp) if exp else None
        if exp and got != exp:
            status["ok"] = False
            status["errors"].append(f"MD5 mismatch {key}: got={got} expected={exp}")

    if not status["ok"]:
        (OUT_DIR / "step2_status.json").write_text(json.dumps(status, indent=2) + "\n")
        print(json.dumps(status, indent=2))
        return 2

    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    for path in (benign, malware):
        with tarfile.open(path, "r:gz") as tf:
            tf.extractall(EXTRACT_DIR)

    status["inventory"] = inventory_extracted(EXTRACT_DIR)
    (OUT_DIR / "step2_status.json").write_text(json.dumps(status, indent=2) + "\n")
    print(json.dumps(status, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
