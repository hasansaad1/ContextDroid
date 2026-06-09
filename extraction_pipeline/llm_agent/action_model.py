"""Shared action identity helpers (leaf module — no navigation/dialog deps)."""

from __future__ import annotations

import json
from typing import Any


def _action_signature_for_candidate(action: dict[str, Any]) -> str:
    return json.dumps(
        {
            "action_type": action.get("action_type"),
            "target_resource_id": action.get("target_resource_id"),
            "target_content_desc": action.get("target_content_desc"),
            "x": action.get("x"),
            "y": action.get("y"),
        },
        sort_keys=True,
    )


def _nav_target_key(action: dict[str, Any]) -> str:
    rid = str(action.get("target_resource_id") or "").strip()
    cd = str(action.get("target_content_desc") or "").strip()
    if rid or cd:
        return f"{rid}|{cd}"
    return _action_signature_for_candidate(action)
