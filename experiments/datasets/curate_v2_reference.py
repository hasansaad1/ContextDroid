#!/usr/bin/env python3
"""Curate immutable v2 reference/volume dataset from logs/bulk_llm_benign_v2 (curation only)."""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASETS_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "extraction_pipeline"))

from evaluate_corpus import CATEGORY_UNIVERSE  # noqa: E402
from evaluate_faithfulness import (  # noqa: E402
    DEGRADED_RE,
    JUDGE_VERSION,
    evaluate_session,
)
from evaluate_scenario_level import FRAMEWORK_APIS, _load_frida_events  # noqa: E402
from quality_rules import _explore_metrics, detect_suspect_flailing  # noqa: E402

SOURCE_RUN = "bulk_llm_benign_v2"
LOG_ROOT = REPO_ROOT / "logs" / SOURCE_RUN
VERSION_ID = "v2"
VERSION_DIR = DATASETS_ROOT / "versions" / VERSION_ID

GRAPH_EXCLUDED = frozenset({"lifecycle", "reflection", "navigation"})
GRAPH_CATEGORY_UNIVERSE: tuple[str, ...] = tuple(
    c for c in CATEGORY_UNIVERSE if c not in GRAPH_EXCLUDED
)

REFERENCE_GATE_VERBATIM = (
    "A session enters the REFERENCE tier iff ALL of: "
    "(1) analyze_status=success; "
    "(2) llm_simulation_status=success; "
    "(3) faithfulness_verdict in {FAITHFUL, PARTIAL} (judge faithfulness_v2_phase_aware); "
    "(4) C0 explore engagement pass (>=3 named effective functional explore taps OR "
    ">=2 new functional explore screen hashes); "
    "(5) meaningful_frida_22cat > 0 over GRAPH_CATEGORY_UNIVERSE "
    "(22 hook categories excluding lifecycle, reflection, navigation; "
    "framework APIs hook_loaded/Method.invoke excluded); "
    "(6) NOT flailing (quality_rules.detect_suspect_flailing); "
    "(7) NOT login_required / auth_gated (llm_simulation_status != failed:skip:login_required); "
    "(8) NOT tagged NETWORK_DEGRADED (best-effort digest-keyword detection via DEGRADED_RE on "
    "agent action reasons). Everything else analyze-success -> VOLUME tier."
)

MANIFEST_FIELDS = [
    "session_id",
    "package",
    "app_class",
    "tier",
    "tags",
    "sim_status",
    "faithfulness_verdict",
    "effective_ft",
    "back_wait_ratio",
    "meaningful_frida_22cat",
    "coverage_gap",
    "artifact_dir",
    "frida_trace_path",
    "agent_log_path",
    "named_functional_explore_taps",
    "functional_explore_screens",
    "c0_pass",
    "analyze_status",
    "data_quality_status",
    "session_mode",
    "hook_version",
]

REGISTRY_FIELDS = [
    "version_id",
    "created_at",
    "parent_version",
    "n_sessions",
    "n_apps",
    "n_faithful_validated",
    "n_flailing_suspect",
    "judge_version",
    "description",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rel(path: Path | str) -> str:
    p = Path(path)
    if not str(path).strip():
        return ""
    try:
        return str(p.resolve().relative_to(REPO_ROOT.resolve()))
    except ValueError:
        return str(p)


def app_class(pkg: str) -> str:
    p = pkg.lower()
    if any(
        x in p
        for x in (
            "launcher",
            "homescreen",
            "novalauncher",
            "mlauncher",
            "textlauncher",
            "slauncher",
        )
    ):
        return "launcher"
    if any(
        x in p
        for x in ("game", "snake", "chess", "sudoku", "puzzle", "2048", "tetris", "click")
    ):
        return "game"
    if any(x in p for x in ("vpn", "proxy", "tor", "dns")):
        return "network_tool"
    if any(x in p for x in ("browser", "webview")):
        return "browser"
    if any(x in p for x in ("keyboard", "ime", "inputmethod", "yidkey")):
        return "ime"
    if any(x in p for x in ("mastodon", "chat", "messenger", "threema", "signal", "mail")):
        return "comm"
    if any(x in p for x in ("camera", "photo", "gallery", "player", "music", "podcast", "pipe")):
        return "media"
    return "other"


def _count_meaningful_22cat(frida_path: Path) -> tuple[int, Counter[str]]:
    events = _load_frida_events(frida_path)
    cats: Counter[str] = Counter()
    n = 0
    for ev in events:
        cat = ev.get("category") or ""
        api = ev.get("api") or ""
        if cat not in GRAPH_CATEGORY_UNIVERSE:
            continue
        if api in FRAMEWORK_APIS:
            continue
        n += 1
        cats[cat] += 1
    return n, cats


def _count_meaningful_25hook(frida_path: Path) -> int:
    """Prior report metric: exclude reflection/lifecycle/unknown only."""
    low = {"reflection", "lifecycle", "unknown"}
    events = _load_frida_events(frida_path)
    return sum(
        1
        for ev in events
        if (ev.get("category") or "") not in low and (ev.get("api") or "") not in FRAMEWORK_APIS
    )


def _network_degraded(actions: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    reasons = " ".join(
        str((a.get("parsed_action") or {}).get("reason") or a.get("reason") or "")
        for a in actions
    ).lower()
    hits = DEGRADED_RE.findall(reasons)
    return bool(hits), hits[:5]


def _load_index_rows() -> list[dict[str, str]]:
    path = LOG_ROOT / "dataset_index.csv"
    by_sid: dict[str, dict[str, str]] = {}
    for row in csv.DictReader(path.open(encoding="utf-8")):
        by_sid[row["session_id"]] = row
    return list(by_sid.values())


def _meta_by_session() -> dict[str, tuple[Path, dict[str, Any]]]:
    out: dict[str, tuple[Path, dict[str, Any]]] = {}
    for meta_path in LOG_ROOT.glob("*/dynamic/llm/session_*/*_dynamic_metadata.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        sid = str(meta.get("session_id") or "")
        if not sid:
            continue
        prev = out.get(sid)
        if prev is None or meta_path.stat().st_mtime >= prev[0].stat().st_mtime:
            out[sid] = (meta_path, meta)
    return out


def _build_tags(
    *,
    faith: str,
    flail: bool,
    meaningful_22: int,
    ft: int,
    sim: str,
    network_degraded: bool,
    cls: str,
    c0_pass: bool,
) -> list[str]:
    tags: list[str] = []
    if faith in {"FAITHFUL", "PARTIAL"}:
        tags.append("FAITHFUL_VALIDATED")
    if flail:
        tags.append("FLAILING_SUSPECT")
    if meaningful_22 <= 0:
        tags.append("ZERO_MEANINGFUL_FRIDA")
    if sim == "failed:skip:login_required":
        tags.append("AUTH_GATED")
    if network_degraded:
        tags.append("NETWORK_DEGRADED")
    if cls == "game":
        tags.append("CANVAS_OR_GAME")
    if cls == "launcher":
        tags.append("LAUNCHER")
    if ft >= 3 and meaningful_22 <= 0:
        tags.append("UI_MOTION_NO_SIGNAL")
    if sim == "failed:explore_non_navigable":
        tags.append("EXPLORE_NON_NAVIGABLE")
    return tags


def _reference_gate(
    *,
    analyze_ok: bool,
    sim: str,
    faith: str,
    c0_pass: bool,
    meaningful_22: int,
    flail: bool,
    auth_gated: bool,
    network_degraded: bool,
) -> bool:
    if not analyze_ok:
        return False
    return (
        sim == "success"
        and faith in {"FAITHFUL", "PARTIAL"}
        and c0_pass
        and meaningful_22 > 0
        and not flail
        and not auth_gated
        and not network_degraded
    )


def curate() -> dict[str, Any]:
    if VERSION_DIR.exists():
        raise SystemExit(f"refusing to overwrite existing version: {VERSION_DIR}")

    index_rows = _load_index_rows()
    meta_map = _meta_by_session()
    ok_rows = [r for r in index_rows if r.get("status") == "success"]

    manifest: list[dict[str, str]] = []
    stats: dict[str, Any] = {
        "graph_universe_size": len(GRAPH_CATEGORY_UNIVERSE),
        "graph_categories": list(GRAPH_CATEGORY_UNIVERSE),
        "analyze_success_n": len(ok_rows),
        "meaningful_25hook_gt0": 0,
        "meaningful_22cat_gt0": 0,
        "reference_n": 0,
        "volume_n": 0,
        "fallout": Counter(),
        "network_degraded_sessions": [],
        "reference_category_hits": Counter(),
        "reference_category_dead": [],
    }

    for row in ok_rows:
        sid = row["session_id"]
        pkg = row["package_name"]
        sim = row.get("llm_simulation_status") or "unknown"
        cls = app_class(pkg)

        base: Path | None = None
        meta: dict[str, Any] = {}
        if sid in meta_map:
            meta_path, meta = meta_map[sid]
            base = meta_path.parent
        else:
            mp = row.get("metadata_path") or ""
            if mp:
                meta_path = Path(mp)
                if meta_path.exists():
                    base = meta_path.parent
                    try:
                        meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    except (json.JSONDecodeError, OSError):
                        meta = {}

        actions: list[dict[str, Any]] = []
        report = None
        faith = "FAILED"
        coverage_gap = ""
        c0_pass = False
        named_taps = 0
        functional_screens = 0

        meaningful_22 = 0
        meaningful_25 = 0
        flail = False
        flail_reasons: list[str] = []
        em = _explore_metrics([])

        if base and base.exists():
            ap = base / f"{pkg}_llm_actions.jsonl"
            if ap.exists():
                for line in ap.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.strip():
                        try:
                            actions.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            rp = base / f"{pkg}_human_ux_report.json"
            if rp.exists():
                try:
                    report = json.loads(rp.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    report = None

            em = _explore_metrics(actions)
            flail, flail_reasons = detect_suspect_flailing(
                actions, sim_status=sim, report=report, explore_metrics=em
            )

            frida_path = base / f"{pkg}_frida.jsonl"
            if frida_path.exists():
                meaningful_22, cat_counts = _count_meaningful_22cat(frida_path)
                meaningful_25 = _count_meaningful_25hook(frida_path)
            else:
                cat_counts = Counter()

            eval_meta = meta or {
                "package_name": pkg,
                "llm_simulation_status": sim,
                "duration_sec": row.get("duration_sec"),
                "data_quality_status": row.get("data_quality_status"),
                "session_id": sid,
            }
            try:
                ev = evaluate_session(base, pkg, eval_meta)
                faith = str(ev.get("faithfulness") or "FAILED")
                coverage_gap = str(ev.get("coverage_gap") or "")
                c0 = ev.get("C0_EXPLORE_ENGAGEMENT") or {}
                c0_pass = c0.get("value") == "yes"
                evd = c0.get("evidence") or {}
                named_taps = int(evd.get("named_functional_explore_taps") or 0)
                functional_screens = int(evd.get("functional_explore_screen_hashes") or 0)
            except Exception:
                faith = "FAILED"
                c0_pass = False

        if meaningful_25 > 0:
            stats["meaningful_25hook_gt0"] += 1
        if meaningful_22 > 0:
            stats["meaningful_22cat_gt0"] += 1

        net_deg, net_hits = _network_degraded(actions)
        auth_gated = sim == "failed:skip:login_required"

        tags = _build_tags(
            faith=faith,
            flail=flail,
            meaningful_22=meaningful_22,
            ft=int(em.get("explore_functional_tap_count") or 0),
            sim=sim,
            network_degraded=net_deg,
            cls=cls,
            c0_pass=c0_pass,
        )

        is_ref = _reference_gate(
            analyze_ok=True,
            sim=sim,
            faith=faith,
            c0_pass=c0_pass,
            meaningful_22=meaningful_22,
            flail=flail,
            auth_gated=auth_gated,
            network_degraded=net_deg,
        )
        tier = "reference" if is_ref else "volume"

        if is_ref:
            stats["reference_n"] += 1
            for cat, cnt in cat_counts.items():
                if cnt > 0:
                    stats["reference_category_hits"][cat] += 1
        else:
            stats["volume_n"] += 1
            fail_reasons: list[str] = []
            if sim != "success":
                fail_reasons.append("sim_not_success")
            if faith not in {"FAITHFUL", "PARTIAL"}:
                fail_reasons.append(f"faith_{faith}")
            if not c0_pass:
                fail_reasons.append("explore_fail")
            if meaningful_22 <= 0:
                fail_reasons.append("zero_meaningful_frida_22cat")
            if flail:
                fail_reasons.append("flailing")
            if auth_gated:
                fail_reasons.append("auth_gated")
            if net_deg:
                fail_reasons.append("network_degraded")
            for reason in fail_reasons:
                stats["fallout"][reason] += 1
            stats["fallout"]["any_volume_or_fail"] += 1

        if net_deg:
            stats["network_degraded_sessions"].append(
                {"session_id": sid, "package": pkg, "keyword_hits": net_hits}
            )

        frida_path = (base / f"{pkg}_frida.jsonl") if base else Path()
        manifest.append(
            {
                "session_id": sid,
                "package": pkg,
                "app_class": cls,
                "tier": tier,
                "tags": "|".join(tags),
                "sim_status": sim,
                "faithfulness_verdict": faith,
                "effective_ft": str(int(em.get("explore_functional_tap_count") or 0)),
                "back_wait_ratio": str(em.get("explore_back_wait_ratio") or 0.0),
                "meaningful_frida_22cat": str(meaningful_22),
                "coverage_gap": coverage_gap,
                "artifact_dir": _rel(base) if base else "",
                "frida_trace_path": _rel(frida_path) if frida_path.exists() else "",
                "agent_log_path": _rel(base / f"{pkg}_llm_actions.jsonl") if base else "",
                "named_functional_explore_taps": str(named_taps),
                "functional_explore_screens": str(functional_screens),
                "c0_pass": "yes" if c0_pass else "no",
                "analyze_status": row.get("status") or "",
                "data_quality_status": row.get("data_quality_status") or "",
                "session_mode": str(meta.get("session_mode") or ""),
                "hook_version": str(meta.get("hook_version") or ""),
            }
        )

    manifest.sort(key=lambda r: (r["package"].lower(), r["session_id"]))

    ref_rows = [r for r in manifest if r["tier"] == "reference"]
    ref_apps = len({r["package"] for r in ref_rows})
    n_ref = len(ref_rows)
    n_ok = len(manifest)

    ref_cat_n = len(ref_rows) or 1
    dead = []
    for cat in GRAPH_CATEGORY_UNIVERSE:
        hit = stats["reference_category_hits"].get(cat, 0)
        pct = 100.0 * hit / ref_cat_n
        if hit == 0:
            dead.append(cat)
    stats["reference_category_dead"] = dead
    stats["reference_apps"] = ref_apps
    stats["reference_meaningful_ge6"] = sum(
        1 for r in ref_rows if int(r["meaningful_frida_22cat"]) >= 6
    )

    created_at = _utc_now()
    VERSION_DIR.mkdir(parents=True)
    with (VERSION_DIR / "manifest.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS)
        w.writeheader()
        w.writerows(manifest)

    tag_counts = Counter()
    for r in manifest:
        for t in r["tags"].split("|"):
            if t:
                tag_counts[t] += 1

    version_meta = {
        "version_id": VERSION_ID,
        "created_at": created_at,
        "parent_version": "v1",
        "description": (
            f"v2 bulk_llm_benign_v2 reference tier ({n_ref} sessions, {ref_apps} apps); "
            f"{n_ok - n_ref} volume-tier analyze-success sessions"
        ),
        "source_run": SOURCE_RUN,
        "hook_version": 3,
        "judge_version": JUDGE_VERSION,
        "judge_validation": {
            "sessions": 20,
            "exact_agreement_pct": 80.0,
            "collapsed_agreement_pct": 100.0,
            "source": "experiment/faithfulness_human_validation.json",
        },
        "graph_category_universe": {
            "size": len(GRAPH_CATEGORY_UNIVERSE),
            "excluded_from_hooks": sorted(GRAPH_EXCLUDED),
            "categories": list(GRAPH_CATEGORY_UNIVERSE),
        },
        "reference_gate_verbatim": REFERENCE_GATE_VERBATIM,
        "counts": {
            "analyze_success_sessions": n_ok,
            "reference_tier_sessions": n_ref,
            "reference_tier_apps": ref_apps,
            "volume_tier_sessions": n_ok - n_ref,
            "meaningful_frida_25hook_gt0": stats["meaningful_25hook_gt0"],
            "meaningful_frida_22cat_gt0": stats["meaningful_22cat_gt0"],
            "reference_meaningful_frida_22cat_ge6": stats["reference_meaningful_ge6"],
            "by_tier": dict(Counter(r["tier"] for r in manifest)),
            "by_tag": dict(tag_counts),
            "by_faithfulness_verdict_reference": dict(
                Counter(r["faithfulness_verdict"] for r in ref_rows)
            ),
            "by_app_class_reference": dict(Counter(r["app_class"] for r in ref_rows)),
            "reference_graph_category_coverage_pct": {
                cat: round(100.0 * stats["reference_category_hits"].get(cat, 0) / ref_cat_n, 1)
                for cat in GRAPH_CATEGORY_UNIVERSE
            },
            "reference_graph_category_dead": dead,
            "fallout_from_reference_among_analyze_success": dict(stats["fallout"].most_common()),
        },
        "known_limitations": [
            "Separate generation from v1 (129 legacy, hook v2 / judge_v1_75pct); never pool in evaluation.",
            "NETWORK_DEGRADED gate is best-effort via DEGRADED_RE keyword hits on agent action reasons; "
            "corpus-wide network-dependency tagging (remediation Step 9.11) is not implemented.",
            f"NETWORK_DEGRADED caught {len(stats['network_degraded_sessions'])} sessions "
            f"({len({s['package'] for s in stats['network_degraded_sessions']})} distinct apps).",
            "Varied-seed sessions often near-duplicate identical pairs (low explore variance).",
            "telephony and native_code categories remain near-dead even in reference tier.",
            "v1 lives at experiments/datasets/versions/v1/ and is untouched.",
        ],
        "reproduction": {
            "command": (
                "python3 experiments/datasets/curate_v2_reference.py "
                "(curation-only; reads logs/bulk_llm_benign_v2/dataset_index.csv + session artifacts)"
            ),
            "inputs": {
                "dataset_index": _rel(LOG_ROOT / "dataset_index.csv"),
                "session_artifacts": _rel(LOG_ROOT),
            },
        },
    }
    (VERSION_DIR / "version_meta.json").write_text(
        json.dumps(version_meta, indent=2), encoding="utf-8"
    )

    notes = _build_notes(stats, manifest, ref_rows, n_ref, ref_apps, n_ok)
    (VERSION_DIR / "notes.md").write_text(notes, encoding="utf-8")

    reg_row = {
        "version_id": VERSION_ID,
        "created_at": created_at,
        "parent_version": "v1",
        "n_sessions": str(n_ok),
        "n_apps": str(len({r["package"] for r in manifest})),
        "n_faithful_validated": str(n_ref),
        "n_flailing_suspect": str(tag_counts.get("FLAILING_SUSPECT", 0)),
        "judge_version": JUDGE_VERSION,
        "description": (
            f"v2 reference tier {n_ref}/{n_ok} analyze-success ({ref_apps} apps); "
            "22-cat GRAPH meaningful Frida gate; v1 legacy separate"
        ),
    }
    registry_path = DATASETS_ROOT / "registry.csv"
    with registry_path.open("a", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=REGISTRY_FIELDS)
        w.writerow(reg_row)

    stats["manifest_path"] = str(VERSION_DIR)
    stats["registry_row"] = reg_row
    return stats


def _build_notes(
    stats: dict[str, Any],
    manifest: list[dict[str, str]],
    ref_rows: list[dict[str, str]],
    n_ref: int,
    ref_apps: int,
    n_ok: int,
) -> str:
    ref_app_classes = Counter(r["app_class"] for r in ref_rows)
    lines = [
        "# v2 reference tier (bulk_llm_benign_v2)",
        "",
        "Immutable curation snapshot from the paused v2 collection run (197/284 apps completed at",
        "curation time; 594 analyze-success sessions indexed). **Curation only** — no re-collection.",
        "",
        "## Honest read",
        "",
        f"- **Reference tier:** {n_ref} sessions across **{ref_apps} distinct apps** (~{100*n_ref/n_ok:.1f}% of analyze-success).",
        f"- **Volume tier:** {n_ok - n_ref} analyze-success sessions that fail one or more reference gates.",
        "- Reference is intentionally small: sim success (~35%), flailing (~38%), and zero meaningful",
        "  Frida (~17% under old 25-hook metric) dominate fallout. The 22-category GRAPH correction",
        f"  shifts meaningful>0 from {stats['meaningful_25hook_gt0']} to {stats['meaningful_22cat_gt0']} sessions.",
        "- v1 (129 sessions, `experiments/datasets/versions/v1/`) is a **separate generation**",
        "  (v6 run, hook v2, judge_v1_75pct). Do not pool v1 and v2 in evaluation.",
        "",
        "## Why reference is ~59 apps, not 197",
        "",
        "Most completed apps never produce a reference session because:",
        "",
        "1. **Sim failure** (`ux_quality_gate`, `bad_handoff`, `explore_non_navigable`) — largest bucket.",
        "2. **Flailing** — mechanical explore or dominant-screen loops despite UI motion.",
        "3. **Faithfulness FAILED** — judge rejects incoherent or shallow sessions.",
        "4. **Zero GRAPH-category Frida** — UI motion without behavioral hook signal (lifecycle-only traces).",
        "5. **Auth / network** — login gates and best-effort offline/RETRY keyword detection.",
        "",
        "Launchers and canvas/game apps contribute almost no reference sessions (0% sim success in class).",
        "",
        "## Reference gate (verbatim)",
        "",
        REFERENCE_GATE_VERBATIM,
        "",
        "## Fallout drivers (multi-count among volume tier)",
        "",
    ]
    for reason, count in stats["fallout"].most_common():
        if reason != "any_volume_or_fail":
            lines.append(f"- `{reason}`: {count}")
    lines.extend(
        [
            "",
            "## 22-category coverage in reference tier",
            "",
            "Categories with 0 reference sessions firing:",
            "",
            f"- {', '.join(stats['reference_category_dead']) or '(none)'}",
            "",
            "## NETWORK_DEGRADED (best-effort)",
            "",
            f"Keyword gate caught **{len(stats['network_degraded_sessions'])}** sessions "
            f"({len({s['package'] for s in stats['network_degraded_sessions']})} apps). "
            "See `version_meta.json` for the session list.",
            "",
            "## Per-app evaluation viability",
            "",
            f"~{ref_apps} apps with ≥1 reference session is enough for **per-app spot checks** but not",
            "for robust stratified evaluation across all app classes. Reference skews toward `other`,",
            f"`network_tool`, and `media` ({dict(ref_app_classes)}). Launchers/games remain absent.",
            "",
            "## Regrowth targeting",
            "",
            "Use `coverage_gap` column in manifest.csv — descriptive judge notes on unvisited flows,",
            "not a quality penalty.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    stats = curate()
    print(f"Wrote {stats['manifest_path']}")
    print(
        f"analyze_success={stats['analyze_success_n']} "
        f"reference={stats['reference_n']} apps={stats['reference_apps']}"
    )
    print(
        f"meaningful>0: 25hook={stats['meaningful_25hook_gt0']} "
        f"22cat={stats['meaningful_22cat_gt0']} "
        f"delta={stats['meaningful_25hook_gt0'] - stats['meaningful_22cat_gt0']}"
    )
    print(f"fallout: {dict(stats['fallout'].most_common())}")
    print(f"registry: {stats['registry_row']}")


if __name__ == "__main__":
    main()
