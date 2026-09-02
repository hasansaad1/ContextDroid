"""Emit resolved run config snapshots for tier parity (amendment A5)."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_jsonable(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return _sha256_bytes(payload.encode("utf-8"))


def _hook_script_version(path: Path) -> str:
    if not path.is_file():
        return "unknown"
    text = path.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r'version:\s*"(\d+)"', text)
    return match.group(1) if match else "unknown"


def _hooked_api_count(path: Path) -> int:
    if not path.is_file():
        return 0
    text = path.read_text(encoding="utf-8", errors="ignore")
    # Unique API names (SAFETY.md documents 58); logEvent may appear more than once.
    return len(set(re.findall(r'logEvent\(\s*"([^"]+)"', text)))


def _prompt_hashes(repo_root: Path) -> dict[str, str]:
    prompts = repo_root / "extraction_pipeline" / "llm_agent" / "prompts.py"
    out: dict[str, str] = {
        "prompts_py_sha256": _sha256_file(prompts) if prompts.is_file() else "",
        "algo": "sha256",
    }
    if prompts.is_file():
        text = prompts.read_text(encoding="utf-8", errors="ignore")
        for name in ("_build_explore_prompt", "_build_prompt", "_build_primary_ux_prompt"):
            # Hash the function body slice for drift detection without importing runtime deps.
            m = re.search(rf"def {name}\(.*?\n(?=def |\Z)", text, flags=re.S)
            out[f"{name}_sha256"] = _sha256_bytes(m.group(0).encode("utf-8")) if m else ""
    return out


def build_config_snapshot(
    *,
    tier: str,
    avd_name: str,
    duration_sec: int,
    arm: str,
    ollama_model: str,
    ollama_endpoint: str,
    output_dir: str | Path,
    network_mode: str,
    reset_mechanism: str,
    avd_fingerprint: str = "",
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Build the effective resolved config that will govern a run."""
    root = Path(repo_root) if repo_root is not None else REPO_ROOT
    hook_script = root / "frida_scripts" / "hook_apis.js"

    # Import analysis constants from the copies this repo actually uses.
    import sys

    ep = str(root / "extraction_pipeline")
    if ep not in sys.path:
        sys.path.insert(0, ep)
    from evaluate_corpus import (  # noqa: WPS433
        CATEGORY_UNIVERSE,
        DELTA_MOTIF_SEC,
        DELTA_SEC,
        K_BURST,
    )
    from evaluate_faithfulness import JUDGE_VERSION  # noqa: WPS433
    from protocol_config import (  # noqa: WPS433
        ACTION_HISTORY_WINDOW,
        LLM_TEMPERATURE,
        OLLAMA_GENERATE_RETRIES,
        REPETITION_THRESHOLD,
        REPETITION_WINDOW,
        SESSION_TIMEOUT_MULTIPLIER,
    )

    # GRAPH_CATEGORY_UNIVERSE is derived in curate_v2_reference; recompute identically.
    graph_excluded = frozenset({"lifecycle", "reflection", "navigation"})
    graph_universe = tuple(c for c in CATEGORY_UNIVERSE if c not in graph_excluded)

    explore_floor = os.environ.get("CONTEXTDROID_LLM_EXPLORE_UNTIL_SEC_FLOOR", "120")
    explore_ratio = os.environ.get("CONTEXTDROID_LLM_EXPLORE_RATIO", "0.35")
    temperature = float(os.environ.get("CONTEXTDROID_LLM_TEMPERATURE", str(LLM_TEMPERATURE)))
    ollama_timeout = float(os.environ.get("CONTEXTDROID_OLLAMA_GENERATE_TIMEOUT_SEC", "60"))
    timeout_mult = int(
        os.environ.get("CONTEXTDROID_SESSION_TIMEOUT_MULTIPLIER", str(SESSION_TIMEOUT_MULTIPLIER))
    )

    category_list = list(CATEGORY_UNIVERSE)
    graph_list = list(graph_universe)
    snapshot: dict[str, Any] = {
        "schema_version": 1,
        "tier": tier,
        "avd_name": avd_name,
        "avd_fingerprint": avd_fingerprint or "",
        "reset_mechanism": reset_mechanism,
        "network_mode": network_mode,
        "arm": arm,
        "paths": {
            "repo_root": str(root),
            "hook_script": str(hook_script),
            "output_dir": str(output_dir),
            "collection_config": os.environ.get("CONTEXTDROID_COLLECTION_CONFIG", "collection_v2"),
        },
        "hooks": {
            "version": _hook_script_version(hook_script),
            "sha256": _sha256_file(hook_script) if hook_script.is_file() else "",
            "hooked_api_count": _hooked_api_count(hook_script),
        },
        "session": {
            "duration_sec": int(duration_sec),
            "timeout_multiplier": timeout_mult,
            "explore_until_sec_floor": int(explore_floor) if str(explore_floor).isdigit() else explore_floor,
            "explore_ratio": float(explore_ratio),
        },
        "categories": {
            "CATEGORY_UNIVERSE": category_list,
            "CATEGORY_UNIVERSE_size": len(category_list),
            "CATEGORY_UNIVERSE_hash": _sha256_jsonable(category_list),
            "GRAPH_CATEGORY_UNIVERSE": graph_list,
            "GRAPH_CATEGORY_UNIVERSE_size": len(graph_list),
            "GRAPH_CATEGORY_UNIVERSE_hash": _sha256_jsonable(graph_list),
        },
        "graph": {
            "K_BURST": K_BURST,
            "DELTA_SEC": DELTA_SEC,
            "DELTA_MOTIF_SEC": DELTA_MOTIF_SEC,
        },
        "window": {
            "action_history_window": ACTION_HISTORY_WINDOW,
            "repetition_window": REPETITION_WINDOW,
            "repetition_threshold": REPETITION_THRESHOLD,
        },
        "ollama": {
            "model": ollama_model,
            "endpoint": ollama_endpoint,
            "temperature": temperature,
            "timeout_sec": ollama_timeout,
            "retries": OLLAMA_GENERATE_RETRIES,
        },
        "judge_version": JUDGE_VERSION,
        "prompt_hashes": _prompt_hashes(root),
    }
    snapshot["config_hash"] = _sha256_jsonable(
        {k: v for k, v in snapshot.items() if k != "config_hash"}
    )
    return snapshot


def write_config_snapshot(snapshot: Mapping[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(snapshot), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


# Fields that may differ across tiers without failing parity (plan 5.1 + SAFETY A2 / Phase 4).
ALLOWED_DIFF_TOP_LEVEL: frozenset[str] = frozenset(
    {
        "tier",
        "avd_name",
        "avd_fingerprint",
        "paths",
        "reset_mechanism",
        "network_mode",
        "config_hash",  # changes when allowed fields change
    }
)


def compare_snapshots(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    *,
    allowed_diffs: frozenset[str] | None = None,
) -> list[str]:
    """Return human-readable mismatch strings. Empty list means parity OK."""
    allow = allowed_diffs if allowed_diffs is not None else ALLOWED_DIFF_TOP_LEVEL
    mismatches: list[str] = []

    left_keys = set(left.keys())
    right_keys = set(right.keys())
    for key in sorted(left_keys | right_keys):
        if key in allow:
            continue
        if key not in left:
            mismatches.append(f"missing in left: {key}")
            continue
        if key not in right:
            mismatches.append(f"missing in right: {key}")
            continue
        if left[key] != right[key]:
            mismatches.append(f"drift at {key}: left={left[key]!r} right={right[key]!r}")
    return mismatches
