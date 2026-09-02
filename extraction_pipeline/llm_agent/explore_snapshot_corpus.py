"""Build real (elements, ExploreState) snapshots from verification logs for equivalence tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from .explore_equivalence import ExploreEquivalenceSnapshot, replay_post_explore_action
from .explore_instrumentation import build_explore_candidate_instrumentation
from .explore_policy import ExploreState, ExploreTurnInput
from .navigation import _build_bfs_candidates, _build_tab_targets
from .dialogs import _bfs_filter_expand_candidates
from .screen import _normalized_elements

ROOT = Path(__file__).resolve().parents[2]

MENSA_HUB_HASH = "7132fbd33a1e42e4cebc50a4831998672a702f8d244def441d3b3b8be5ef16df"
MENSA_INTERIOR_HASH = "5952e172a5e8e6f53d7ee63e00259c17de07ea512eb2996b6937431d5751b082"
MENSA_LABELED_HASH = "c721dd894c139bae723c4fe2700235c9de7e120c689453b885c091e9edab1de9"
IED_HASH = "ebf883f4b45679aa6743a2c874e767153d900de833011e6ae0775018f5fd4e2f"


def _view_element(pkg: str, x: int, y: int, *, half_w: int = 60, half_h: int = 60) -> dict[str, str]:
    return {
        "package": pkg,
        "resource_id": "",
        "content_desc": "",
        "text": "",
        "class_name": "android.view.View",
        "bounds": f"[{x - half_w},{y - half_h}][{x + half_w},{y + half_h}]",
        "clickable": "true",
    }


def _labeled_button(pkg: str, rid: str, cd: str, bounds: str) -> dict[str, str]:
    return {
        "package": pkg,
        "resource_id": rid,
        "content_desc": cd,
        "text": "",
        "class_name": "android.widget.Button",
        "bounds": bounds,
        "clickable": "true",
    }


def mensa_hub_anonymous_elements() -> list[dict[str, str]]:
    """Four anonymous views on Mensa hub (other=4) — coords from step2_close nav artifact."""
    pkg = "ch.famoser.mensa"
    centers = [(1007, 148), (805, 294), (805, 420), (1007, 274)]
    return [_view_element(pkg, x, y) for x, y in centers]


def mensa_interior_anonymous_elements() -> list[dict[str, str]]:
    pkg = "ch.famoser.mensa"
    centers = [(805, 294), (805, 420), (1007, 148), (1007, 420)]
    return [_view_element(pkg, x, y) for x, y in centers]


def mensa_launch_ten_anonymous_elements() -> list[dict[str, str]]:
    """Launch screen from step2_mensa_fresh step 1 (other=10, all anonymous views)."""
    pkg = "ch.famoser.mensa"
    centers = [
        (1007, 148),
        (805, 294),
        (805, 420),
        (1007, 274),
        (540, 500),
        (540, 620),
        (540, 740),
        (540, 860),
        (540, 980),
        (540, 1100),
    ]
    return [_view_element(pkg, x, y) for x, y in centers]


def mensa_labeled_verified_start_elements() -> list[dict[str, str]]:
    xml = (
        ROOT
        / "logs/step2_scarcity_mensa/ef32499a74ab_ch.famoser.mensa/dynamic/llm/session_1/ch.famoser.mensa_verified_start.xml"
    )
    return _normalized_elements(xml.read_text(encoding="utf-8", errors="ignore"))


def protonvpn_hub_elements() -> list[dict[str, str]]:
    pkg = "ch.protonvpn.android"
    return [
        _labeled_button(pkg, f"{pkg}:id/connectButton", "Connect", "[100,50][900,150]"),
        _view_element(pkg, 540, 400),
    ]


def protonvpn_signin_sparse_elements() -> list[dict[str, str]]:
    return [_view_element("ch.protonvpn.android", 540, 400)]


def protonvpn_hub_four_anonymous_elements() -> list[dict[str, str]]:
    """Post-tab sparse hub from step5_verify vpn log (other=4, skipped=1)."""
    pkg = "ch.protonvpn.android"
    centers = [(540, 200), (540, 400), (540, 600), (540, 800)]
    return [_view_element(pkg, x, y) for x, y in centers]


def ied_text_entry_elements() -> list[dict[str, str]]:
    return [
        {
            "package": "at.krixec.ied",
            "resource_id": "",
            "content_desc": "",
            "text": "",
            "class_name": "android.widget.EditText",
            "bounds": "[500,50][580,76]",
            "clickable": "true",
        }
    ]


def govroam_edittext_elements() -> list[dict[str, str]]:
    return [
        {
            "package": "app.govroam.getgovroam",
            "resource_id": "",
            "content_desc": "",
            "text": "",
            "class_name": "android.widget.EditText",
            "bounds": "[480,150][600,206]",
            "clickable": "true",
        }
    ]


def govroam_one_expand_elements() -> list[dict[str, str]]:
    return [_view_element("app.govroam.getgovroam", 540, 400)]


def govroam_two_expand_elements() -> list[dict[str, str]]:
    return [
        _view_element("app.govroam.getgovroam", 400, 400),
        _view_element("app.govroam.getgovroam", 680, 400),
    ]


def image_meta_two_expand_elements() -> list[dict[str, str]]:
    return [
        _view_element("code.alimiracle.image_meta_cleaner", 400, 600),
        _view_element("code.alimiracle.image_meta_cleaner", 680, 600),
    ]


def image_meta_nav_tab_elements() -> list[dict[str, str]]:
    pkg = "code.alimiracle.image_meta_cleaner"
    return [
        _labeled_button(pkg, f"{pkg}:id/nav_home", "Home", "[0,1800][360,1920]"),
        _view_element(pkg, 540, 600),
    ]


def _bucket_counts(elements: list[dict[str, str]], pkg: str) -> dict[str, int]:
    nav, other = _build_bfs_candidates(elements)
    tabs = _build_tab_targets(elements)
    expand = _bfs_filter_expand_candidates(other, pkg, set())
    inst = build_explore_candidate_instrumentation(
        elements, nav, other, expand, tabs, screen_hash="", recovery_step=False
    )
    return dict(inst["explore_candidate_counts"])


def _elements_for_mensa_screen(screen_hash: str) -> list[dict[str, str]]:
    if screen_hash.startswith(MENSA_HUB_HASH[:8]) or screen_hash == MENSA_HUB_HASH:
        return mensa_hub_anonymous_elements()
    if screen_hash.startswith(MENSA_INTERIOR_HASH[:8]) or screen_hash == MENSA_INTERIOR_HASH:
        return mensa_interior_anonymous_elements()
    if screen_hash.startswith(MENSA_LABELED_HASH[:8]) or screen_hash == MENSA_LABELED_HASH:
        return mensa_launch_ten_anonymous_elements()
    return mensa_interior_anonymous_elements()


def _elements_for_govroam_row(row: dict[str, Any]) -> list[dict[str, str]]:
    counts = row.get("explore_candidate_counts") or {}
    other = int(counts.get("other_cands") or 0)
    skipped = int(counts.get("skipped_interactive") or 0)
    if other == 0 and skipped >= 1:
        return govroam_edittext_elements()
    if other == 1:
        return govroam_one_expand_elements()
    if other >= 2:
        return govroam_two_expand_elements()
    return govroam_one_expand_elements()


def _elements_for_image_meta_row(row: dict[str, Any]) -> list[dict[str, str]]:
    counts = row.get("explore_candidate_counts") or {}
    nav = int(counts.get("nav_cands") or 0)
    tab = int(counts.get("tab_cands") or 0)
    if nav >= 1 and tab >= 1:
        return image_meta_nav_tab_elements()
    return image_meta_two_expand_elements()


def _elements_for_protonvpn_row(row: dict[str, Any]) -> list[dict[str, str]]:
    counts = row.get("explore_candidate_counts") or {}
    nav = int(counts.get("nav_cands") or 0)
    other = int(counts.get("other_cands") or 0)
    if nav >= 2 and other == 0:
        return protonvpn_hub_elements() + [
            _labeled_button(
                "ch.protonvpn.android",
                "ch.protonvpn.android:id/tabCountries",
                "Countries",
                "[0,1800][360,1920]",
            ),
            _labeled_button(
                "ch.protonvpn.android",
                "ch.protonvpn.android:id/tabHome",
                "Home",
                "[360,1800][720,1920]",
            ),
        ]
    if other >= 4:
        return protonvpn_hub_four_anonymous_elements()
    if other == 1:
        return protonvpn_signin_sparse_elements()
    return protonvpn_hub_elements()


def _snapshots_from_session_log(
    jsonl: Path,
    *,
    pkg: str,
    category: str,
    element_fn,
    id_prefix: str = "",
    max_steps: int | None = None,
) -> list[ExploreEquivalenceSnapshot]:
    if not jsonl.is_file():
        return []
    rows = [
        json.loads(line)
        for line in jsonl.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    ]
    explore = [r for r in rows if str(r.get("pipeline_phase") or "") == "explore"]
    if max_steps is not None:
        explore = explore[:max_steps]
    state = ExploreState()
    stall_by_screen: dict[str, int] = {}
    out: list[ExploreEquivalenceSnapshot] = []
    for row in explore:
        step = int(row.get("step") or 0)
        sh = str(row.get("screen_hash") or "")
        elements = element_fn(sh, row)
        turn = ExploreTurnInput(elements=elements, pkg=pkg, screen_hash=sh, fg_now=pkg)
        snap_id = f"{id_prefix}step{step}_{sh[:8]}"
        out.append(
            ExploreEquivalenceSnapshot(
                snapshot_id=snap_id,
                category=category,
                turn=turn,
                state=copy.deepcopy(state),
            )
        )
        parsed = row.get("parsed_action") if isinstance(row.get("parsed_action"), dict) else None
        if parsed:
            replay_post_explore_action(
                state,
                parsed,
                screen_hash=sh,
                hash_after=str(row.get("screen_hash_after") or "") or None,
                ok=bool(row.get("action_success", True)),
                stall_by_screen=stall_by_screen,
            )
    return out


def build_equivalence_snapshot_corpus() -> list[ExploreEquivalenceSnapshot]:
    corpus: list[ExploreEquivalenceSnapshot] = []

    # --- Synthetic invariant fixtures (Step 2 / 4 categories) ---
    corpus.extend(
        [
            ExploreEquivalenceSnapshot(
                snapshot_id="mensa_anonymous_admission_empty_state",
                category="mensa_anonymous",
                turn=ExploreTurnInput(
                    elements=mensa_hub_anonymous_elements(),
                    pkg="ch.famoser.mensa",
                    screen_hash=MENSA_HUB_HASH,
                    fg_now="ch.famoser.mensa",
                ),
                state=ExploreState(),
                expected_buckets={
                    "nav_cands": 0,
                    "other_cands": 4,
                    "expand_cands": 4,
                    "tab_cands": 0,
                    "skipped_interactive": 0,
                },
            ),
            ExploreEquivalenceSnapshot(
                snapshot_id="mensa_labeled_scarcity_shut_verified_start",
                category="mensa_labeled",
                turn=ExploreTurnInput(
                    elements=mensa_labeled_verified_start_elements(),
                    pkg="ch.famoser.mensa",
                    screen_hash="mensa_labeled_verified",
                    fg_now="ch.famoser.mensa",
                ),
                state=ExploreState(),
            ),
            ExploreEquivalenceSnapshot(
                snapshot_id="mensa_launch_ten_anonymous",
                category="mensa_labeled",
                turn=ExploreTurnInput(
                    elements=mensa_launch_ten_anonymous_elements(),
                    pkg="ch.famoser.mensa",
                    screen_hash=MENSA_LABELED_HASH,
                    fg_now="ch.famoser.mensa",
                ),
                state=ExploreState(),
                expected_buckets={
                    "nav_cands": 0,
                    "other_cands": 10,
                    "expand_cands": 10,
                    "tab_cands": 0,
                    "skipped_interactive": 0,
                },
            ),
            ExploreEquivalenceSnapshot(
                snapshot_id="protonvpn_hub_scarcity_shut",
                category="protonvpn_hub",
                turn=ExploreTurnInput(
                    elements=protonvpn_hub_elements(),
                    pkg="ch.protonvpn.android",
                    screen_hash="protonvpn_hub",
                    fg_now="ch.protonvpn.android",
                ),
                state=ExploreState(),
                expected_buckets={
                    "nav_cands": 0,
                    "other_cands": 1,
                    "expand_cands": 1,
                    "tab_cands": 0,
                    "skipped_interactive": 1,
                },
            ),
            ExploreEquivalenceSnapshot(
                snapshot_id="protonvpn_signin_scarcity_open",
                category="protonvpn_signin",
                turn=ExploreTurnInput(
                    elements=protonvpn_signin_sparse_elements(),
                    pkg="ch.protonvpn.android",
                    screen_hash="protonvpn_signin",
                    fg_now="ch.protonvpn.android",
                ),
                state=ExploreState(),
                expected_buckets={
                    "nav_cands": 0,
                    "other_cands": 1,
                    "expand_cands": 1,
                    "tab_cands": 0,
                    "skipped_interactive": 0,
                },
            ),
            ExploreEquivalenceSnapshot(
                snapshot_id="ied_text_entry_probe",
                category="text_entry",
                turn=ExploreTurnInput(
                    elements=ied_text_entry_elements(),
                    pkg="at.krixec.ied",
                    screen_hash=IED_HASH,
                    fg_now="at.krixec.ied",
                ),
                state=ExploreState(),
            ),
        ]
    )
    st_probed = ExploreState()
    st_probed.bfs_text_entry_probed_keys.add(f"{IED_HASH}|xy:540:63")
    corpus.append(
        ExploreEquivalenceSnapshot(
            snapshot_id="ied_text_entry_probe_repeat_guard",
            category="text_entry",
            turn=ExploreTurnInput(
                elements=ied_text_entry_elements(),
                pkg="at.krixec.ied",
                screen_hash=IED_HASH,
                fg_now="at.krixec.ied",
            ),
            state=st_probed,
        )
    )

    # --- Replay from real verification logs (stateful sequential) ---
    log_specs: list[tuple[str, str, str, Any]] = [
        (
            "logs/step2_close/mensa_after_1/ef32499a74ab_ch.famoser.mensa/dynamic/llm/session_1/ch.famoser.mensa_llm_actions.jsonl",
            "ch.famoser.mensa",
            "mensa_replay_11tap",
            lambda sh, _row: _elements_for_mensa_screen(sh),
        ),
        (
            "logs/step2_mensa_fresh/ef32499a74ab_ch.famoser.mensa/dynamic/llm/session_1/ch.famoser.mensa_llm_actions.jsonl",
            "ch.famoser.mensa",
            "mensa_replay_9tap",
            lambda sh, _row: _elements_for_mensa_screen(sh),
        ),
        (
            "logs/step4_verify/app_govroam_getgovroam/88b111fbbfdc_app.govroam.getgovroam/dynamic/llm/session_1/app.govroam.getgovroam_llm_actions.jsonl",
            "app.govroam.getgovroam",
            "govroam_replay",
            lambda _sh, row: _elements_for_govroam_row(row),
        ),
        (
            "logs/step4_verify/at_krixec_ied/306d9927d530_at.krixec.ied/dynamic/llm/session_1/at.krixec.ied_llm_actions.jsonl",
            "at.krixec.ied",
            "ied_replay",
            lambda _sh, _row: ied_text_entry_elements(),
        ),
        (
            "logs/step5_verify/before/code_alimiracle_image_meta_cleaner/df7736a370d9_code.alimiracle.image_meta_cleaner/dynamic/llm/session_1/code.alimiracle.image_meta_cleaner_llm_actions.jsonl",
            "code.alimiracle.image_meta_cleaner",
            "image_meta_replay",
            lambda _sh, row: _elements_for_image_meta_row(row),
        ),
        (
            "logs/step5_verify/before/ch_protonvpn_android/0d50d7d9c132_ch.protonvpn.android/dynamic/llm/session_1/ch.protonvpn.android_llm_actions.jsonl",
            "ch.protonvpn.android",
            "protonvpn_replay",
            lambda _sh, row: _elements_for_protonvpn_row(row),
        ),
    ]
    for rel, pkg, category, element_fn in log_specs:
        jsonl = ROOT / rel
        prefix = category.split("_")[0] + "_"
        corpus.extend(
            _snapshots_from_session_log(
                jsonl,
                pkg=pkg,
                category=category,
                element_fn=element_fn,
                id_prefix=prefix,
            )
        )

    return corpus
