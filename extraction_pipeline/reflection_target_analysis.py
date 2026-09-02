#!/usr/bin/env python3
"""Re-analyze reflection Method.invoke targets in existing Frida traces."""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate_scenario_level import (
    FRAMEWORK_APIS,
    LOW_SIGNAL_CATEGORIES,
    _is_meaningful_event,
)


def _load_frida_events(frida_jsonl: Path) -> list[dict[str, Any]]:
    """Load Frida events including args (needed for reflection target class)."""
    out: list[dict[str, Any]] = []
    if not frida_jsonl.exists():
        return out
    for line in frida_jsonl.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type", "event") != "event":
            continue
        ts = obj.get("timestamp")
        if ts is None:
            continue
        out.append(
            {
                "timestamp": int(ts),
                "category": str(obj.get("category") or ""),
                "api": str(obj.get("api") or ""),
                "args": obj.get("args") if isinstance(obj.get("args"), dict) else {},
            }
        )
    return out

OVERNIGHT_CUTOFF_ISO = "2026-06-28T21:41:00Z"

FRAMEWORK_PREFIXES = (
    "android.",
    "androidx.",
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "dalvik.",
    "com.google.android.",
    "sun.",
    "org.apache.harmony.",
    "libcore.",
)

SENSITIVE_CLASS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("network", re.compile(r"(^java\.net\.|^javax\.net\.|okhttp|retrofit|HttpURLConnection|URLConnection|Socket|URL$|OkHttp|okio\.)", re.I)),
    ("crypto", re.compile(r"(^javax\.crypto\.|^java\.security\.|SecretKey|Cipher|MessageDigest|Mac\b|KeyStore|KeyPair|Signature\b|IvParameterSpec)", re.I)),
    ("sms", re.compile(r"^android\.telephony\.", re.I)),
    ("dynamic_code_loading", re.compile(r"(DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader|System\.load|System\.loadLibrary)", re.I)),
    ("process", re.compile(r"(^java\.lang\.Runtime$|^java\.lang\.ProcessBuilder$|Runtime\.exec|ProcessBuilder\.start)", re.I)),
    ("reflection", re.compile(r"^java\.lang\.reflect\.(Method|Constructor|Field|Proxy|AccessibleObject)", re.I)),
]

DCL_LOADER_CLASSES = {
    "dalvik.system.DexClassLoader",
    "dalvik.system.PathClassLoader",
    "dalvik.system.InMemoryDexClassLoader",
    "dalvik.system.BaseDexClassLoader",
}


def _dist(vals: list[float]) -> dict[str, float]:
    if not vals:
        return {"min": 0.0, "p25": 0.0, "median": 0.0, "p75": 0.0, "max": 0.0, "n": 0}
    s = sorted(vals)
    n = len(s)
    q1 = statistics.quantiles(s, n=4)[0] if n >= 4 else s[0]
    q3 = statistics.quantiles(s, n=4)[2] if n >= 4 else s[-1]
    return {
        "min": float(s[0]),
        "p25": float(q1),
        "median": float(statistics.median(s)),
        "p75": float(q3),
        "max": float(s[-1]),
        "n": float(n),
    }


def _target_class(ev: dict[str, Any]) -> str:
    args = ev.get("args") or {}
    clazz = args.get("class") or args.get("clazz") or ""
    return str(clazz).strip()


def _target_method(ev: dict[str, Any]) -> str:
    args = ev.get("args") or {}
    return str(args.get("method") or "").strip()


def _is_reflection_event(ev: dict[str, Any]) -> bool:
    return ev.get("category") == "reflection" or ev.get("api") == "Method.invoke"


def _is_stripped_target(clazz: str) -> bool:
    if not clazz:
        return True
    parts = clazz.split(".")
    if len(parts) == 1:
        return len(clazz) <= 3 or clazz.islower() and len(clazz) <= 6
    if len(parts) >= 2 and all(len(p) == 1 for p in parts):
        return True
    if len(parts) >= 3 and all(len(p) <= 2 for p in parts):
        return True
    short = sum(1 for p in parts if len(p) <= 2)
    if len(parts) >= 4 and short / len(parts) >= 0.75:
        return True
    return False


def _is_readable_fqn(clazz: str) -> bool:
    if not clazz or _is_stripped_target(clazz):
        return False
    if "." not in clazz:
        return False
    return True


def _sensitive_categories(clazz: str, method: str) -> list[str]:
    hay = f"{clazz} {method}"
    out: list[str] = []
    for cat, pat in SENSITIVE_CLASS_PATTERNS:
        if pat.search(hay) or pat.search(clazz):
            out.append(cat)
    if clazz in DCL_LOADER_CLASSES:
        out.append("dynamic_code_loading")
    return sorted(set(out))


def _is_framework_prefix(clazz: str) -> bool:
    return any(clazz.startswith(p) for p in FRAMEWORK_PREFIXES)


def _bucket_target(clazz: str, method: str, app_package: str) -> str:
    if not clazz:
        return "B"
    sensitive = _sensitive_categories(clazz, method)
    if sensitive:
        return "C"
    if clazz in DCL_LOADER_CLASSES:
        return "C"
    if _is_framework_prefix(clazz):
        return "A"
    if app_package and clazz.startswith(f"{app_package}."):
        return "B"
    if not _is_framework_prefix(clazz) and clazz and "." in clazz:
        return "B"
    if clazz and not _is_framework_prefix(clazz):
        return "B"
    return "A"


def _category_from_reflection(clazz: str, method: str) -> str | None:
    cats = _sensitive_categories(clazz, method)
    if not cats:
        return None
    priority = ["dynamic_code_loading", "process", "crypto", "network", "sms", "reflection"]
    for cat in priority:
        if cat in cats:
            return cat
    return cats[0]


def _before_metrics(events: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(events)
    meaningful = [e for e in events if _is_meaningful_event(e)]
    cats = sorted({e["category"] for e in meaningful})
    reflection_noise = sum(
        1
        for e in events
        if e.get("api") in FRAMEWORK_APIS or e.get("category") in {"reflection", "lifecycle"}
    )
    return {
        "distinct_meaningful_categories": len(cats),
        "category_set": cats,
        "meaningful_events": len(meaningful),
        "reflection_share": (reflection_noise / total) if total else None,
        "total_frida_events": total,
    }


def _after_metrics(events: list[dict[str, Any]], app_package: str) -> dict[str, Any]:
    kept: list[dict[str, Any]] = []
    bc_reflection = 0
    framework_reflection_count = 0
    base_cats: set[str] = set()
    reflection_only_cats: set[str] = set()
    bc_buckets: Counter[str] = Counter()

    for ev in events:
        if _is_meaningful_event(ev):
            kept.append(ev)
            base_cats.add(ev["category"])
            continue
        if not _is_reflection_event(ev):
            continue
        clazz = _target_class(ev)
        method = _target_method(ev)
        bucket = _bucket_target(clazz, method, app_package)
        if bucket == "A":
            framework_reflection_count += 1
            continue
        kept.append(ev)
        bc_reflection += 1
        bc_buckets[bucket] += 1
        mapped = _category_from_reflection(clazz, method)
        if mapped:
            if mapped not in base_cats:
                reflection_only_cats.add(mapped)

    all_cats = set(base_cats)
    for ev in kept:
        if _is_reflection_event(ev):
            mapped = _category_from_reflection(_target_class(ev), _target_method(ev))
            if mapped:
                all_cats.add(mapped)

    kept_n = len(kept)
    return {
        "distinct_meaningful_categories": len(all_cats),
        "category_set": sorted(all_cats),
        "base_category_set": sorted(base_cats),
        "categories_only_via_reflection_target": sorted(reflection_only_cats),
        "meaningful_events": sum(1 for e in kept if not _is_reflection_event(e)),
        "bc_reflection_events": bc_reflection,
        "framework_reflection_count": framework_reflection_count,
        "reflection_share": (bc_reflection / kept_n) if kept_n else None,
        "kept_events": kept_n,
        "bc_bucket_counts": dict(bc_buckets),
    }


def _is_usable(distinct_cats: int, reflection_share: float | None) -> bool:
    return distinct_cats >= 3 and reflection_share is not None and reflection_share < 0.50


def _analyze_events(events: list[dict[str, Any]], app_package: str) -> dict[str, Any]:
    reflection_events = [e for e in events if _is_reflection_event(e)]
    readable = 0
    stripped = 0
    empty = 0
    buckets: Counter[str] = Counter()
    distinct_classes: Counter[str] = Counter()

    for ev in reflection_events:
        clazz = _target_class(ev)
        method = _target_method(ev)
        if not clazz:
            empty += 1
            continue
        distinct_classes[clazz] += 1
        if _is_stripped_target(clazz):
            stripped += 1
        elif _is_readable_fqn(clazz):
            readable += 1
        else:
            stripped += 1
        buckets[_bucket_target(clazz, method, app_package)] += 1

    n_refl = len(reflection_events)
    with_class = n_refl - empty
    readable_pct = (100.0 * readable / with_class) if with_class else 0.0
    stripped_pct = (100.0 * stripped / with_class) if with_class else 0.0

    before = _before_metrics(events)
    after = _after_metrics(events, app_package)
    before_usable = _is_usable(before["distinct_meaningful_categories"], before["reflection_share"])
    after_usable = _is_usable(after["distinct_meaningful_categories"], after["reflection_share"])

    return {
        "reflection_event_count": n_refl,
        "reflection_with_class": with_class,
        "reflection_empty_class": empty,
        "readable_fqn_count": readable,
        "stripped_target_count": stripped,
        "readable_fqn_pct_of_with_class": readable_pct,
        "stripped_target_pct_of_with_class": stripped_pct,
        "bucket_counts": dict(buckets),
        "bucket_pcts": {k: (100.0 * v / n_refl if n_refl else 0.0) for k, v in buckets.items()},
        "distinct_target_classes": len(distinct_classes),
        "top_target_classes": distinct_classes.most_common(15),
        "before": before,
        "after": after,
        "before_usable": before_usable,
        "after_usable": after_usable,
        "recovered_by_filtering": (not before_usable) and after_usable,
        "gated_on_reflection_only": (
            before["distinct_meaningful_categories"] >= 3
            and not before_usable
            and before.get("reflection_share") is not None
            and before["reflection_share"] >= 0.50
        ),
        "recovered_from_reflection_gate": (
            before["distinct_meaningful_categories"] >= 3
            and not before_usable
            and after_usable
        ),
    }


def _load_cohort_rows(index_path: Path, *, overnight_only: bool) -> list[dict[str, str]]:
    cutoff = datetime.fromisoformat(OVERNIGHT_CUTOFF_ISO.replace("Z", "+00:00"))
    rows: list[dict[str, str]] = []
    for row in csv.DictReader(index_path.open(encoding="utf-8")):
        if row.get("status") != "success":
            continue
        ts = row.get("analysis_timestamp") or ""
        if not ts:
            continue
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        is_overnight = dt >= cutoff
        if overnight_only and is_overnight:
            rows.append(row)
        elif not overnight_only and not is_overnight:
            rows.append(row)
    return rows


def _analyze_cohort(name: str, rows: list[dict[str, str]]) -> dict[str, Any]:
    per_session: list[dict[str, Any]] = []
    corpus_buckets: Counter[str] = Counter()
    total_reflection = 0
    total_readable = 0
    total_stripped = 0
    total_with_class = 0
    all_target_classes: Counter[str] = Counter()

    for row in rows:
        frida_path = Path(row["frida_log_path"])
        if not frida_path.exists():
            continue
        events = _load_frida_events(frida_path)
        pkg = row["package_name"]
        analysis = _analyze_events(events, pkg)
        total_reflection += analysis["reflection_event_count"]
        total_readable += analysis["readable_fqn_count"]
        total_stripped += analysis["stripped_target_count"]
        total_with_class += analysis["reflection_with_class"]
        for k, v in analysis["bucket_counts"].items():
            corpus_buckets[k] += v
        for clazz, cnt in analysis.get("top_target_classes", []):
            all_target_classes[clazz] += cnt

        per_session.append(
            {
                "package": pkg,
                "session_id": row.get("session_id", ""),
                "artifact_path": str(frida_path.parent),
                "analysis_timestamp": row.get("analysis_timestamp"),
                **analysis,
            }
        )

    readable_pct = (100.0 * total_readable / total_with_class) if total_with_class else 0.0
    stripped_pct = (100.0 * total_stripped / total_with_class) if total_with_class else 0.0
    proceed = readable_pct >= 50.0

    before_usable = [s for s in per_session if s["before_usable"]]
    after_usable = [s for s in per_session if s["after_usable"]]
    gated = [s for s in per_session if s["gated_on_reflection_only"]]
    recovered = [s for s in per_session if s["recovered_from_reflection_gate"]]
    cat_only_refl = [
        s
        for s in per_session
        if s["after"]["categories_only_via_reflection_target"]
    ]

    before_refl = [s["before"]["reflection_share"] for s in per_session if s["before"]["reflection_share"] is not None]
    after_refl = [s["after"]["reflection_share"] for s in per_session if s["after"]["reflection_share"] is not None]

    return {
        "cohort": name,
        "sessions": len(per_session),
        "step1_readability": {
            "reflection_events_total": total_reflection,
            "with_nonempty_class": total_with_class,
            "readable_fqn_count": total_readable,
            "stripped_target_count": total_stripped,
            "readable_fqn_pct": readable_pct,
            "stripped_target_pct": stripped_pct,
            "decision": "proceed" if proceed else "coarse-fallback",
            "decision_note": (
                "Majority of targets are readable FQNs; target-aware filtering is viable."
                if proceed
                else "Most targets are stripped/obfuscated; filtering will rely on sensitive-target + unknown-kept fallback."
            ),
            "distinct_target_classes_corpus": len(all_target_classes),
            "top_target_classes_corpus": all_target_classes.most_common(25),
        },
        "step2_bucket_breakdown": {
            "corpus_counts": dict(corpus_buckets),
            "corpus_pcts": {
                k: (100.0 * v / total_reflection if total_reflection else 0.0)
                for k, v in corpus_buckets.items()
            },
            "per_session_bucket_pcts": _dist(
                [
                    100.0 * s["bucket_counts"].get("A", 0) / s["reflection_event_count"]
                    for s in per_session
                    if s["reflection_event_count"] > 0
                ]
            ),
        },
        "step3_filtering": {
            "reflection_share_before": _dist(before_refl),
            "reflection_share_after": _dist(after_refl),
            "distinct_categories_before": _dist(
                [float(s["before"]["distinct_meaningful_categories"]) for s in per_session]
            ),
            "distinct_categories_after": _dist(
                [float(s["after"]["distinct_meaningful_categories"]) for s in per_session]
            ),
        },
        "step4_recovery": {
            "usable_before": len(before_usable),
            "usable_after": len(after_usable),
            "usable_before_pct": (100.0 * len(before_usable) / len(per_session)) if per_session else 0.0,
            "usable_after_pct": (100.0 * len(after_usable) / len(per_session)) if per_session else 0.0,
            "gated_sessions_ge3_cats_failed_reflection": len(gated),
            "recovered_from_reflection_gate": len(recovered),
            "recovered_packages": [s["package"] for s in recovered],
            "newly_usable_packages": [s["package"] for s in per_session if s["recovered_by_filtering"]],
            "category_only_via_sensitive_reflection": [
                {
                    "package": s["package"],
                    "session_id": s["session_id"],
                    "categories": s["after"]["categories_only_via_reflection_target"],
                }
                for s in cat_only_refl
            ],
        },
        "per_session": per_session,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", default="logs/bulk_llm_benign_v6/dataset_index.csv")
    parser.add_argument("--out-json", default="experiment/reflection_target_analysis.json")
    parser.add_argument("--out-csv", default="experiment/reference_reflection_recovered_usable.csv")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    index_path = root / args.index

    overnight_rows = _load_cohort_rows(index_path, overnight_only=True)
    prior_rows = _load_cohort_rows(index_path, overnight_only=False)
    all_rows = overnight_rows + prior_rows

    overnight = _analyze_cohort("overnight_engine_off", overnight_rows)
    prior = _analyze_cohort("prior_v6_engine_on", prior_rows)
    full = _analyze_cohort("full_v6_success", all_rows)

    rec = overnight["step4_recovery"]
    s1 = overnight["step1_readability"]
    verdict_a = rec["usable_after"] > rec["usable_before"]
    verdict_b = len(rec["category_only_via_sensitive_reflection"]) > 0
    if verdict_a and verdict_b:
        verdict = "worth implementing: recovers usable sessions and preserves unique reflection-carried signal"
    elif verdict_a:
        verdict = "worth implementing for recovery: usable sessions increase; limited unique category signal from reflection targets"
    elif verdict_b:
        verdict = "partial value: preserves unique signal but does not recover usable sessions under current gate"
    else:
        verdict = "limited value on this cohort: no usable-session recovery and no unique reflection-carried categories"

    result = {
        "experiment": "reflection_target_analysis",
        "log_dir": str(root / "logs/bulk_llm_benign_v6"),
        "overnight_cohort_cutoff": OVERNIGHT_CUTOFF_ISO,
        "step1_readability_verdict": {
            "overnight": s1,
            "full_v6": full["step1_readability"],
        },
        "overnight_analysis": {
            "step2_buckets": overnight["step2_bucket_breakdown"],
            "step3_filtering": overnight["step3_filtering"],
            "step4_recovery": overnight["step4_recovery"],
        },
        "comparison_prior_v6": prior["step4_recovery"],
        "comparison_full_v6": full["step4_recovery"],
        "verdict": verdict,
        "cohorts": {
            "overnight_engine_off": overnight,
            "prior_v6_engine_on": prior,
            "full_v6_success": full,
        },
    }

    out_json = root / args.out_json
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")

    out_csv = root / args.out_csv
    with out_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "package",
                "session_id",
                "artifact_path",
                "distinct_meaningful_categories_before",
                "distinct_meaningful_categories_after",
                "reflection_share_before",
                "reflection_share_after",
                "category_set_after",
                "categories_only_via_reflection",
                "recovered",
            ],
        )
        writer.writeheader()
        for s in overnight["per_session"]:
            if not s["after_usable"]:
                continue
            writer.writerow(
                {
                    "package": s["package"],
                    "session_id": s["session_id"],
                    "artifact_path": s["artifact_path"],
                    "distinct_meaningful_categories_before": s["before"]["distinct_meaningful_categories"],
                    "distinct_meaningful_categories_after": s["after"]["distinct_meaningful_categories"],
                    "reflection_share_before": s["before"]["reflection_share"],
                    "reflection_share_after": s["after"]["reflection_share"],
                    "category_set_after": "|".join(s["after"]["category_set"]),
                    "categories_only_via_reflection": "|".join(
                        s["after"]["categories_only_via_reflection_target"]
                    ),
                    "recovered": s["recovered_from_reflection_gate"],
                }
            )

    print(f"wrote {out_json}")
    print(f"wrote {out_csv}")
    print(f"step1: {s1['decision']} (readable {s1['readable_fqn_pct']:.1f}%, stripped {s1['stripped_target_pct']:.1f}%)")
    print(
        f"overnight usable before/after: {rec['usable_before']}/{rec['usable_after']} "
        f"(recovered from reflection gate: {rec['recovered_from_reflection_gate']}/{rec['gated_sessions_ge3_cats_failed_reflection']})"
    )
    print(f"verdict: {verdict}")


if __name__ == "__main__":
    main()
