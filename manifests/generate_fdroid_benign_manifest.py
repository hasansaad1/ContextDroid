#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path

INDEX_URL = "https://f-droid.org/repo/index-v2.json"


def load_index() -> dict:
    with urllib.request.urlopen(INDEX_URL, timeout=120) as resp:
        return json.load(resp)


def package_is_candidate(pkg: str, entry: dict) -> bool:
    meta = entry.get("metadata", {})
    versions = entry.get("versions", {})
    if not versions:
        return False
    if meta.get("antiFeatures"):
        return False
    if pkg.startswith(("org.fdroid.", "test.", "debug.")):
        return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate F-Droid benign manifest.")
    parser.add_argument("--output", default="manifests/benign_packages_large.txt")
    parser.add_argument("--limit", type=int, default=300)
    args = parser.parse_args()

    output = Path(args.output).resolve()
    index = load_index()
    packages = index.get("packages", {})
    selected: list[str] = []
    for pkg in sorted(packages.keys()):
        if package_is_candidate(pkg, packages[pkg]):
            selected.append(pkg)
        if len(selected) >= args.limit:
            break
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(selected) + "\n", encoding="utf-8")
    print(f"Wrote {len(selected)} package IDs to {output}")


if __name__ == "__main__":
    main()
