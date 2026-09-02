#!/usr/bin/env python3
"""Compare bulk retry results against retry_baseline.json."""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def load_metadata(root: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for path in root.glob("**/**_dynamic_metadata.json"):
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        pkg = d.get("package_name")
        if pkg:
            out[pkg] = d
    return out


def summarize(meta: dict[str, dict]) -> dict:
    rc = Counter()
    owner = Counter()
    for d in meta.values():
        rc[d.get("analysis_exit_code", "?")] += 1
        owner[d.get("frida_server_owner") or "<missing>"] += 1
    return {
        "total_metadata": len(meta),
        "exit_code_counts": dict(sorted(rc.items(), key=lambda x: str(x[0]))),
        "frida_server_owner_counts": dict(owner),
        "success_packages": sorted(p for p, d in meta.items() if d.get("analysis_exit_code") == 0),
    }


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    log_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else repo / "logs" / "bulk_llm_dataset"
    baseline_path = log_dir / "state" / "retry_baseline.json"
    if not baseline_path.exists():
        print(f"Missing baseline: {baseline_path}", file=sys.stderr)
        return 1

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    current_meta = load_metadata(log_dir)
    current = summarize(current_meta)

    completed = {
        line.strip()
        for line in (log_dir / "state" / "completed_apks.sha256").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    failed = {
        line.strip()
        for line in (log_dir / "state" / "failed_apks.sha256").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }

    flipped: list[dict] = []
    for pkg, before in baseline.get("packages", {}).items():
        after = current_meta.get(pkg)
        if not after:
            continue
        b_rc = before.get("exit_code")
        a_rc = after.get("analysis_exit_code")
        if b_rc != a_rc:
            flipped.append(
                {
                    "package": pkg,
                    "before_rc": b_rc,
                    "after_rc": a_rc,
                    "after_owner": after.get("frida_server_owner"),
                    "after_status": after.get("analysis_status"),
                }
            )

    report = {
        "baseline_captured_at": baseline.get("captured_at"),
        "before": {
            "completed_count": baseline.get("completed_count"),
            "failed_count": baseline.get("failed_count"),
            "exit_code_counts": baseline.get("exit_code_counts"),
        },
        "after": {
            "completed_count": len(completed),
            "failed_count": len(failed),
            **current,
        },
        "delta_completed": len(completed) - int(baseline.get("completed_count", 0)),
        "delta_failed": len(failed) - int(baseline.get("failed_count", 0)),
        "rc_changes": sorted(flipped, key=lambda x: (x["before_rc"], x["package"])),
        "new_successes_from_failure": [
            x for x in flipped if x["before_rc"] != 0 and x["after_rc"] == 0
        ],
    }
    out_path = log_dir / "state" / "retry_comparison.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nWrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
