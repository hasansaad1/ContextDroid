from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import IO, Any, Optional

from protocol_config import (
    ACTION_HISTORY_WINDOW,
    LLM_TEMPERATURE,
    MAX_AGENT_XML_TOKENS,
    OLLAMA_DEAD_AFTER_CONSECUTIVE_STEPS,
    OLLAMA_GENERATE_RETRIES,
    OLLAMA_GENERATE_RETRY_BASE_SEC,
    PARTIAL_AGENT_STUCK,
    PARTIAL_OLLAMA_UNAVAILABLE,
    REPETITION_THRESHOLD,
    REPETITION_WINDOW,
    STAGNATION_CONSECUTIVE_FOR_BACK,
    STAGNATION_CONSECUTIVE_FOR_BAILOUT,
    SESSION_TIMEOUT_MULTIPLIER,
)

from .config import (
    _ACTION_TYPES_PLANNER,
    _LLM_TEMPERATURE_RUNTIME,
    _OLLAMA_GENERATE_TIMEOUT_SEC,
    _ollama_generate_options,
)

def _ollama_generate(
    prompt: str, model: str, endpoint: str, *, timeout_sec: float | None = None
) -> str:
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": _ollama_generate_options(),
        }
    ).encode("utf-8")
    req = urllib.request.Request(endpoint.rstrip("/") + "/api/generate", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    tout = _OLLAMA_GENERATE_TIMEOUT_SEC if timeout_sec is None else max(10.0, float(timeout_sec))
    with urllib.request.urlopen(req, timeout=tout) as resp:
        obj = json.loads(resp.read().decode("utf-8", errors="ignore"))
    return str(obj.get("response", "")).strip()

def _ollama_generate_with_retries(
    prompt: str,
    model: str,
    endpoint: str,
    *,
    max_attempts: int | None = None,
    timeout_sec: float | None = None,
) -> str:
    attempts = OLLAMA_GENERATE_RETRIES if max_attempts is None else max(1, int(max_attempts))
    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            return _ollama_generate(prompt, model, endpoint, timeout_sec=timeout_sec)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_exc = exc
            time.sleep(OLLAMA_GENERATE_RETRY_BASE_SEC * (2**attempt))
    logging.warning(
        "Ollama /api/generate failed after %d attempts (model=%s endpoint=%s): %s",
        attempts,
        model,
        endpoint,
        last_exc,
    )
    if last_exc is None:
        raise RuntimeError("Ollama retries exhausted without exception detail")
    raise last_exc

def _iter_json_roots(text: str):
    """Yield top-level JSON values embedded in noisy model output."""
    dec = json.JSONDecoder()
    i = 0
    n = len(text)
    while i < n:
        while i < n and text[i] not in "{[":
            i += 1
        if i >= n:
            break
        try:
            obj, end = dec.raw_decode(text, i)
            yield obj
            i = end
        except json.JSONDecodeError:
            i += 1

def _first_action_dict(obj: Any) -> dict[str, Any] | None:
    if isinstance(obj, dict) and "action_type" in obj:
        return obj
    if isinstance(obj, list):
        for item in obj:
            got = _first_action_dict(item)
            if got is not None:
                return got
    return None

def _tap_focus_compatible_with_input(tap: dict[str, Any], inp: dict[str, Any]) -> bool:
    """Merge tap→input only when tap targets an obvious query/search field and input lacks focus hints."""
    rid = str(tap.get("target_resource_id") or "")
    cd = str(tap.get("target_content_desc") or "")
    blob = f"{rid} {cd}".lower()
    entry_like = any(
        k in blob
        for k in (
            "search",
            "query",
            "find",
            "filter",
            "autocomplete",
            "src_text",
            ":edit_text",
            "edittext",
        )
    )
    inp_rid = str(inp.get("target_resource_id") or "").strip()
    inp_cd = str(inp.get("target_content_desc") or "").strip()
    inp_xy = inp.get("x") is not None and inp.get("y") is not None
    inp_needs_focus = not inp_rid and not inp_cd and not inp_xy
    return entry_like and inp_needs_focus

def _merge_adjacent_tap_input_pairs(acts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sequential merge of [tap search-like, input] into one input step (same as legacy single-action parse)."""
    out: list[dict[str, Any]] = []
    i = 0
    while i < len(acts):
        if i + 1 < len(acts):
            a0, a1 = acts[i], acts[i + 1]
            if str(a0.get("action_type")) == "tap" and str(a1.get("action_type")) == "input":
                if _tap_focus_compatible_with_input(a0, a1):
                    merged = dict(a1)
                    for key in ("target_resource_id", "target_content_desc", "x", "y"):
                        cur = merged.get(key)
                        empty_rid = key == "target_resource_id" and not str(cur or "").strip()
                        empty_cd = key == "target_content_desc" and not str(cur or "").strip()
                        missing_xy = key in ("x", "y") and cur is None
                        if empty_rid or empty_cd or missing_xy:
                            if a0.get(key) is not None:
                                merged[key] = a0[key]
                    out.append(merged)
                    i += 2
                    continue
        out.append(dict(acts[i]))
        i += 1
    return out

def _normalize_planner_action_fields(action: dict[str, Any]) -> dict[str, Any]:
    """Map common LLM schema aliases onto the executor contract (target_resource_id, text)."""
    out = dict(action)
    rid = str(out.get("target_resource_id") or "").strip()
    if not rid:
        for alias in ("element_id", "resource_id", "field_id", "target_id", "view_id"):
            val = str(out.get(alias) or "").strip()
            if val:
                out["target_resource_id"] = val
                break
    if not str(out.get("text") or "").strip():
        for alias in ("input_text", "value", "query"):
            val = str(out.get(alias) or "").strip()
            if val:
                out["text"] = val
                break
    return out


def _extract_action_dicts_from_root(root: Any) -> list[dict[str, Any]]:
    if isinstance(root, dict):
        inner = root.get("actions")
        if isinstance(inner, list):
            return [
                _normalize_planner_action_fields(x)
                for x in inner
                if isinstance(x, dict) and x.get("action_type")
            ]
        if root.get("action_type"):
            return [_normalize_planner_action_fields(root)]
        return []
    if isinstance(root, list):
        return [
            _normalize_planner_action_fields(x)
            for x in root
            if isinstance(x, dict) and x.get("action_type")
        ]
    return []

def _planner_contract_failure(error: str, detail: str = "") -> list[dict[str, Any]]:
    action: dict[str, Any] = {
        "action_type": "wait",
        "reason": f"planner_contract_{error}",
    }
    if detail:
        action["contract_detail"] = detail[:500]
    return [action]

def _planner_contract_diagnosis(root: Any) -> tuple[str, str]:
    if isinstance(root, dict):
        if "actions" in root:
            inner = root.get("actions")
            if not isinstance(inner, list):
                return "actions_not_list", f"actions_type={type(inner).__name__}"
            if not inner:
                return "empty_actions", "actions=[]"
            bad = [
                str(x.get("action_type") or "(missing)")
                for x in inner
                if isinstance(x, dict)
                and str(x.get("action_type") or "") not in _ACTION_TYPES_PLANNER
            ]
            if bad:
                return "invalid_action_type", ",".join(sorted(set(bad)))
            return "no_action_object", "actions contained no executable dict"
        if "action_type" in root:
            at = str(root.get("action_type") or "(missing)")
            if at not in _ACTION_TYPES_PLANNER:
                return "invalid_action_type", at
        return "no_action_object", "json object lacks action_type/actions"
    if isinstance(root, list):
        if not root:
            return "empty_actions", "[]"
        bad = [
            str(x.get("action_type") or "(missing)")
            for x in root
            if isinstance(x, dict)
            and str(x.get("action_type") or "") not in _ACTION_TYPES_PLANNER
        ]
        if bad:
            return "invalid_action_type", ",".join(sorted(set(bad)))
        return "no_action_object", "json array contained no executable action dict"
    return "no_action_object", f"json_root_type={type(root).__name__}"

def _json_root_action_score(root: Any) -> int:
    """Prefer planner action JSON over incidental hierarchy dumps (elements[], CLEAN_SCREEN, etc.)."""
    acts = _extract_action_dicts_from_root(root)
    if acts:
        return 100 + len(acts)
    if isinstance(root, dict) and root.get("action_type") in _ACTION_TYPES_PLANNER:
        return 90
    if isinstance(root, dict) and any(k in root for k in ("elements", "CLEAN_SCREEN_ELEMENTS")):
        return 0
    return 1

def _parse_actions_list(text: str, *, max_actions: int) -> list[dict[str, Any]]:
    """Parse one or many planner actions; prefers actionable JSON over hierarchy mirrors in prose."""
    text = _strip_llm_json_noise(text)
    best: list[dict[str, Any]] = []
    contract_errors: list[tuple[str, str]] = []
    roots = list(_iter_json_roots(text))
    roots.sort(key=_json_root_action_score, reverse=True)
    for root in roots:
        raw_acts = _extract_action_dicts_from_root(root)
        merged = _merge_adjacent_tap_input_pairs(raw_acts)
        merged = [a for a in merged if str(a.get("action_type")) in _ACTION_TYPES_PLANNER]
        if not merged:
            if _json_root_action_score(root) > 0:
                contract_errors.append(_planner_contract_diagnosis(root))
            continue
        if len(merged) > len(best):
            best = merged
    if not best:
        if not contract_errors:
            return _planner_contract_failure("no_json", "no JSON action object found")
        error, detail = contract_errors[0]
        return _planner_contract_failure(error, detail)
    return best[:max_actions]

def _parse_action(text: str) -> dict[str, Any]:
    xs = _parse_actions_list(text, max_actions=1)
    return xs[0] if xs else _planner_contract_failure("no_json", "empty parse result")[0]

def _normalize_unicode_quotes(s: str) -> str:
    return (
        s.replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2018", "'")
        .replace("\u2019", "'")
    )

def _strip_llm_json_noise(raw: str) -> str:
    """Drop BOM, fenced markdown, and generic preamble before the first JSON bracket."""
    s = _normalize_unicode_quotes(raw.strip())
    if s.startswith("\ufeff"):
        s = s.lstrip("\ufeff").strip()
    if "```" in s:
        parts = s.split("```")
        for k in range(1, len(parts), 2):
            cand = parts[k].strip()
            low = cand.lower()
            if low.startswith("json"):
                cand = cand[4:].lstrip()
            if cand.startswith("{") or cand.startswith("["):
                s = cand
                break
    lb = s.find("{")
    rb = s.find("[")
    starts = [p for p in (lb, rb) if p >= 0]
    if starts:
        s = s[min(starts) :]
    return s.strip()

def _extract_balanced_json_value(text: str, start_idx: int) -> str | None:
    """Slice one balanced {...} or [...] starting at start_idx (string-aware)."""
    if start_idx >= len(text):
        return None
    opener = text[start_idx]
    if opener not in "{[":
        return None
    stack: list[str] = []
    in_str = False
    esc = False
    quote_char = ""
    for j in range(start_idx, len(text)):
        c = text[j]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == quote_char:
                in_str = False
            continue
        if c in ('"', "'"):
            in_str = True
            quote_char = c
            esc = False
            continue
        if c == "{":
            stack.append("}")
        elif c == "[":
            stack.append("]")
        elif c in "}]":
            if not stack or c != stack[-1]:
                return None
            stack.pop()
            if not stack:
                return text[start_idx : j + 1]
    return None

def _normalize_goal_item(item: Any) -> str | None:
    if isinstance(item, str):
        s = item.strip()
        return s if s else None
    if isinstance(item, dict):
        for k in ("goal", "text", "description", "step", "title", "intent"):
            v = item.get(k)
            if v is not None:
                s = str(v).strip()
                if s:
                    return s
    return None

def _goals_from_parsed_root(root: Any, *, _depth: int = 0) -> list[str]:
    out: list[str] = []
    goal_keys = ("goals", "tasks", "steps", "ux_goals", "test_goals", "plan_goals")

    def pull_from_dict(d: dict[str, Any], depth: int) -> None:
        nonlocal out
        if depth > 8:
            return
        for key in goal_keys:
            g = d.get(key)
            if isinstance(g, list):
                for item in g:
                    n = _normalize_goal_item(item)
                    if n:
                        out.append(n)
        for v in d.values():
            if isinstance(v, dict):
                pull_from_dict(v, depth + 1)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        pull_from_dict(item, depth + 1)

    if isinstance(root, dict):
        pull_from_dict(root, _depth)
    elif isinstance(root, list):
        for item in root:
            n = _normalize_goal_item(item)
            if n:
                out.append(n)
            elif isinstance(item, dict):
                out.extend(_goals_from_parsed_root(item, _depth=_depth + 1))
    dedup: list[str] = []
    seen: set[str] = set()
    for g in out:
        key = g.casefold()
        if key not in seen:
            seen.add(key)
            dedup.append(g)
    return dedup[:14]

def _parse_ux_goals_lenient(raw: str) -> list[str]:
    """Extract goals[] from noisy planner output (markdown fences, preamble, trailing chatter)."""
    text = _strip_llm_json_noise(raw)
    best: list[str] = []
    for root in _iter_json_roots(text):
        got = _goals_from_parsed_root(root)
        if len(got) > len(best):
            best = got
    if len(best) >= 4:
        return best[:12]
    for i, ch in enumerate(text):
        if ch not in "{[":
            continue
        chunk = _extract_balanced_json_value(text, i)
        if not chunk:
            continue
        try:
            root = json.loads(chunk)
        except json.JSONDecodeError:
            continue
        got = _goals_from_parsed_root(root)
        if len(got) > len(best):
            best = got
        if len(best) >= 10:
            break
    return best[:12]

def _parse_ux_goals_from_plan(raw: str) -> list[str]:
    return _parse_ux_goals_lenient(raw)
