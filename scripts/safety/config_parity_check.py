#!/usr/bin/env python3
"""Compare emitted config_snapshot.json files for benign/malware tier parity (A5).

Allowed top-level differences: tier, paths, AVD name (+ fingerprint), reset_mechanism,
network_mode. Deliberate mutation of analysis fields must fail.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "extraction_pipeline"))

from safety.config_snapshot import (  # noqa: E402
    ALLOWED_DIFF_TOP_LEVEL,
    build_config_snapshot,
    compare_snapshots,
    write_config_snapshot,
)
from safety.vault_paths import MOUNT_ROOT  # noqa: E402 — canonical vault root only


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def cmd_compare(args: argparse.Namespace) -> int:
    left = _load(args.left)
    right = _load(args.right)
    mismatches = compare_snapshots(left, right)
    if mismatches:
        print("CONFIG_PARITY_FAIL")
        for line in mismatches:
            print(f"  {line}")
        return 1
    print("CONFIG_PARITY_OK")
    print(f"allowed_diffs={sorted(ALLOWED_DIFF_TOP_LEVEL)}")
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    """Emit two parity-equal snapshots, then prove a mutation fails."""
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    benign = build_config_snapshot(
        tier="benign",
        avd_name="abrg_benign",
        duration_sec=600,
        arm="llm",
        ollama_model="llama3.2",
        ollama_endpoint="http://127.0.0.1:11434",
        output_dir="logs/bulk_llm_benign_v2",
        network_mode="benign_default",
        reset_mechanism="warm_isolate",
        avd_fingerprint="benign-fp",
        repo_root=REPO_ROOT,
    )
    malware = build_config_snapshot(
        tier="malware",
        avd_name="abrg_mw",
        duration_sec=600,
        arm="llm",
        ollama_model="llama3.2",
        ollama_endpoint="http://127.0.0.1:11434",
        output_dir=str(MOUNT_ROOT / "traces" / "example"),
        network_mode="option_c_sink",
        reset_mechanism="wipe_data_per_sample",
        avd_fingerprint="mw-fp",
        repo_root=REPO_ROOT,
    )
    left_path = write_config_snapshot(benign, out_dir / "benign_config_snapshot.json")
    right_path = write_config_snapshot(malware, out_dir / "malware_config_snapshot.json")

    mismatches = compare_snapshots(benign, malware)
    if mismatches:
        print("CONFIG_PARITY_SELFTEST_FAIL: unexpected drift between benign/malware templates")
        for line in mismatches:
            print(f"  {line}")
        return 1
    print(f"CONFIG_PARITY_OK left={left_path} right={right_path}")

    # Deliberate mutation must fail.
    mutated = json.loads(json.dumps(malware))
    mutated["session"]["explore_ratio"] = 0.99
    mut_path = write_config_snapshot(mutated, out_dir / "malware_config_snapshot_mutated.json")
    mut_mismatches = compare_snapshots(benign, mutated)
    if not mut_mismatches:
        print("CONFIG_PARITY_SELFTEST_FAIL: mutated explore_ratio did not fail parity")
        return 1
    print("CONFIG_PARITY_MUTATION_DETECTED_OK")
    for line in mut_mismatches:
        print(f"  {line}")
    print(f"mutated_snapshot={mut_path}")

    # Universe size sanity.
    cats = benign["categories"]
    if cats["CATEGORY_UNIVERSE_size"] != 25:
        print(f"CONFIG_PARITY_SELFTEST_FAIL: CATEGORY_UNIVERSE_size={cats['CATEGORY_UNIVERSE_size']}")
        return 1
    if cats["GRAPH_CATEGORY_UNIVERSE_size"] != 22:
        print(
            "CONFIG_PARITY_SELFTEST_FAIL: "
            f"GRAPH_CATEGORY_UNIVERSE_size={cats['GRAPH_CATEGORY_UNIVERSE_size']}"
        )
        return 1
    print("CONFIG_PARITY_UNIVERSE_SIZES_OK category=25 graph=22")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Config snapshot parity check (A5)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_cmp = sub.add_parser("compare", help="Compare two emitted snapshots")
    p_cmp.add_argument("left", type=Path)
    p_cmp.add_argument("right", type=Path)
    p_cmp.set_defaults(func=cmd_compare)

    p_self = sub.add_parser("selftest", help="Emit equal snapshots + prove mutation fails")
    p_self.add_argument(
        "--out-dir",
        type=Path,
        default=REPO_ROOT / "logs" / "p5_config_parity",
    )
    p_self.set_defaults(func=cmd_selftest)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
