"""FROZEN pre-Step-5 inline explore logic (legacy reference).

Pure explore-phase policy: candidate buckets, tier walk, recovery (Step 5 seam).

No device I/O — safe to unit-test without an emulator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .action_model import _nav_target_key
from .config import _BFS_INTERIOR_EXPAND_BUDGET, _BFS_LAYER_EXPAND_BEFORE_CYCLE
from .dialogs import (
    _action_is_foreign_dialog_widget,
    _bfs_filter_expand_candidates,
    _derive_dialog_state,
    _dialog_policy_action,
    _first_non_foreign_bfs_candidate,
    _hierarchy_shows_permission_dialog,
    _nav_key_is_foreign_dialog,
)
from .navigation import (
    _action_is_back_like,
    _action_is_search_like,
    _bfs_has_untried_expand_on_screen,
    _bfs_pick_untried_expand_candidate,
    _bfs_screen_supports_layer_expansion,
    _build_bfs_candidates,
    _build_tab_targets,
    _element_passes_bfs_interactive_gate,
    _element_suggests_navigation_chrome,
    _is_likely_nav_candidate,
    _is_text_entry_element,
    _nav_graph_pick_uncovered_visible,
    _nav_graph_register_candidates,
    _pick_text_entry_explore_action,
)
from .screen import _bounds_center, _hierarchy_max_bottom_y


@dataclass(frozen=True)
class InteractiveElement:
    """Canonical explore element model (Step 5.3 / architect seam #2)."""

    package: str
    resource_id: str
    content_desc: str
    text: str
    class_name: str
    bounds: str
    clickable: bool
    screen_hash: str

    @classmethod
    def from_dict(cls, e: dict[str, str], *, screen_hash: str) -> InteractiveElement:
        return cls(
            package=str(e.get("package") or "").strip(),
            resource_id=str(e.get("resource_id") or "").strip(),
            content_desc=str(e.get("content_desc") or "").strip(),
            text=str(e.get("text") or "").strip(),
            class_name=str(e.get("class_name") or "").strip(),
            bounds=str(e.get("bounds") or "").strip(),
            clickable=str(e.get("clickable") or "").lower() in ("true", "1"),
            screen_hash=screen_hash,
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "package": self.package,
            "resource_id": self.resource_id,
            "content_desc": self.content_desc,
            "text": self.text,
            "class_name": self.class_name,
            "bounds": self.bounds,
            "clickable": "true" if self.clickable else "false",
        }

    @property
    def labeled(self) -> bool:
        return bool(self.text or self.content_desc or self.resource_id)

    @property
    def is_text_entry(self) -> bool:
        return _is_text_entry_element(self.as_dict())

    @property
    def viewport_visible(self) -> bool:
        """Elements reaching explore policy passed visibility/interactive filtering upstream."""
        return True

    @property
    def nav_likelihood(self) -> bool:
        bottom = _hierarchy_max_bottom_y([self.as_dict()])
        return _is_likely_nav_candidate(self.as_dict(), screen_bottom=bottom) or _element_suggests_navigation_chrome(
            self.as_dict()
        )

    @property
    def identity_key(self) -> str:
        if self.resource_id:
            return f"{self.screen_hash}|rid:{self.resource_id}"
        center = _bounds_center(self.bounds)
        if center is None:
            return f"{self.screen_hash}|unknown"
        return f"{self.screen_hash}|xy:{center[0]}:{center[1]}"


@dataclass
class ExploreState:
    """Mutable explore BFS / frontier state (session-global unless noted per-screen)."""

    nav_graph: dict[str, Any] = field(default_factory=lambda: {"targets": {}, "edges": []})
    nav_frontier_queue: list[str] = field(default_factory=list)
    nav_attempted: set[str] = field(default_factory=set)
    nav_key_to_action: dict[str, dict[str, Any]] = field(default_factory=dict)
    nav_defer_counts: dict[str, int] = field(default_factory=dict)
    tab_frontier_queue: list[str] = field(default_factory=list)
    tab_attempted: set[str] = field(default_factory=set)
    tab_key_to_action: dict[str, dict[str, Any]] = field(default_factory=dict)
    tab_cycle_keys: list[str] = field(default_factory=list)
    tab_cycle_index: int = 0
    pending_interior_expand: int = 0
    bfs_dialog_dismissed_tokens: set[str] = field(default_factory=set)
    bfs_permission_risk_keys_attempted: set[str] = field(default_factory=set)
    bfs_expand_streak_key: str = ""
    bfs_expand_streak_hash: str = ""
    bfs_expand_streak_count: int = 0
    bfs_expand_tried_on_screen: dict[str, set[str]] = field(default_factory=dict)
    bfs_text_entry_probed_keys: set[str] = field(default_factory=set)
    bfs_back_streak: int = 0


@dataclass
class CandidateBuckets:
    nav_cands: list[dict[str, Any]]
    other_cands: list[dict[str, Any]]
    expand_cands: list[dict[str, Any]]
    tab_cands: list[dict[str, Any]]
    interactive_elements: list[InteractiveElement]
    layer_expand_active: bool


@dataclass
class ExploreTurnInput:
    elements: list[dict[str, str]]
    pkg: str
    screen_hash: str
    fg_now: str


@dataclass
class ExplorePickResult:
    action: dict[str, Any]
    state: ExploreState
    nav_cands: list[dict[str, Any]]
    other_cands: list[dict[str, Any]]
    expand_cands: list[dict[str, Any]]
    tab_cands: list[dict[str, Any]]
    layer_expand_active: bool
    dialog_token: str
    dialog_state: dict[str, Any]


class CandidateBuilder:
    """elements → nav/tab/expand/other buckets."""

    def build(
        self,
        elements: list[dict[str, str]],
        *,
        pkg: str,
        screen_hash: str,
        permission_risk_keys: set[str],
    ) -> CandidateBuckets:
        interactive = [InteractiveElement.from_dict(e, screen_hash=screen_hash) for e in elements]
        element_dicts = [ie.as_dict() for ie in interactive]
        nav_cands, other_cands = _build_bfs_candidates(element_dicts)
        tab_cands = _build_tab_targets(element_dicts)
        expand_cands = _bfs_filter_expand_candidates(other_cands, pkg, permission_risk_keys)
        layer_expand_active = (
            _BFS_LAYER_EXPAND_BEFORE_CYCLE
            and _bfs_screen_supports_layer_expansion(tab_cands, nav_cands)
        )
        return CandidateBuckets(
            nav_cands=nav_cands,
            other_cands=other_cands,
            expand_cands=expand_cands,
            tab_cands=tab_cands,
            interactive_elements=interactive,
            layer_expand_active=layer_expand_active,
        )


class ActionChooser:
    """buckets + state → tiered tap/input choice (tiers 0–9 + text-entry + no-nav expand)."""

    def choose(
        self,
        *,
        state: ExploreState,
        buckets: CandidateBuckets,
        turn: ExploreTurnInput,
        dialog_action: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        chosen: dict[str, Any] | None = dialog_action
        nav_cands = buckets.nav_cands
        tab_cands = buckets.tab_cands
        expand_cands = buckets.expand_cands
        layer_expand_active = buckets.layer_expand_active
        screen_hash = turn.screen_hash
        pkg = turn.pkg

        visible_nav_keys: list[str] = []
        visible_tab_keys: list[str] = []

        for c in tab_cands:
            k = _nav_target_key(c)
            state.tab_key_to_action[k] = dict(c)
            visible_tab_keys.append(k)
            if _action_is_foreign_dialog_widget(c, pkg):
                continue
            if (
                k not in state.tab_cycle_keys
                and not _action_is_search_like(c)
                and not _action_is_back_like(c)
            ):
                state.tab_cycle_keys.append(k)
            if k not in state.tab_frontier_queue and k not in state.tab_attempted:
                state.tab_frontier_queue.append(k)

        if chosen is None and state.pending_interior_expand > 0:
            tried_on_screen = state.bfs_expand_tried_on_screen.setdefault(screen_hash, set())
            interior = _bfs_pick_untried_expand_candidate(
                expand_cands,
                target_pkg=pkg,
                tried_keys=tried_on_screen,
                reason="bfs_expand_after_tab_switch",
            )
            if interior is None:
                interior = _first_non_foreign_bfs_candidate(expand_cands, pkg)
                if interior is not None:
                    interior = dict(interior)
                    interior["reason"] = "bfs_expand_after_tab_switch"
            if interior:
                chosen = interior
                tried_on_screen.add(_nav_target_key(interior))
                state.pending_interior_expand -= 1
            else:
                state.pending_interior_expand = 0

        if chosen is None:
            chosen = _nav_graph_pick_uncovered_visible(
                state.nav_graph,
                tab_cands,
                candidate_kind="tab",
                target_pkg=pkg,
            )
        if chosen is None:
            chosen = _nav_graph_pick_uncovered_visible(
                state.nav_graph,
                nav_cands,
                candidate_kind="nav",
                target_pkg=pkg,
            )

        if chosen is None and state.tab_frontier_queue:
            for _ in range(len(state.tab_frontier_queue)):
                k = state.tab_frontier_queue.pop(0)
                if _nav_key_is_foreign_dialog(k, pkg):
                    continue
                if k in visible_tab_keys:
                    chosen = dict(state.tab_key_to_action[k])
                    chosen["reason"] = "bfs_tab_frontier"
                    state.tab_attempted.add(k)
                    break
                state.tab_frontier_queue.append(k)

        for c in nav_cands:
            k = _nav_target_key(c)
            state.nav_key_to_action[k] = dict(c)
            visible_nav_keys.append(k)
            if _action_is_foreign_dialog_widget(c, pkg):
                continue
            if k not in state.nav_frontier_queue and k not in state.nav_attempted:
                state.nav_frontier_queue.append(k)

        state.tab_cycle_keys[:] = [
            k for k in state.tab_cycle_keys if not _nav_key_is_foreign_dialog(k, pkg)
        ]
        state.tab_frontier_queue[:] = [
            k for k in state.tab_frontier_queue if not _nav_key_is_foreign_dialog(k, pkg)
        ]
        state.nav_frontier_queue[:] = [
            k for k in state.nav_frontier_queue if not _nav_key_is_foreign_dialog(k, pkg)
        ]

        if chosen is None and state.nav_frontier_queue:
            for _ in range(len(state.nav_frontier_queue)):
                k = state.nav_frontier_queue.pop(0)
                if _nav_key_is_foreign_dialog(k, pkg):
                    continue
                if k in visible_nav_keys:
                    chosen = dict(state.nav_key_to_action[k])
                    chosen["reason"] = "bfs_nav_frontier"
                    state.nav_attempted.add(k)
                    state.nav_defer_counts.pop(k, None)
                    break
                state.nav_defer_counts[k] = state.nav_defer_counts.get(k, 0) + 1
                if state.nav_defer_counts[k] <= 5:
                    state.nav_frontier_queue.append(k)

        if chosen is None and nav_cands:
            for c in nav_cands:
                k = _nav_target_key(c)
                if _action_is_foreign_dialog_widget(c, pkg):
                    continue
                if k not in state.nav_attempted and not _action_is_search_like(c):
                    chosen = dict(c)
                    chosen["reason"] = "bfs_nav_visible_fallback"
                    state.nav_attempted.add(k)
                    break

        if chosen is None:
            for c in expand_cands:
                ek = _nav_target_key(c)
                if (
                    ek == state.bfs_expand_streak_key
                    and screen_hash == state.bfs_expand_streak_hash
                    and state.bfs_expand_streak_count >= 2
                ):
                    continue
                chosen = dict(c)
                chosen["reason"] = "bfs_expand_frontier"
                state.bfs_expand_tried_on_screen.setdefault(screen_hash, set()).add(ek)
                if ek == state.bfs_expand_streak_key and screen_hash == state.bfs_expand_streak_hash:
                    state.bfs_expand_streak_count += 1
                else:
                    state.bfs_expand_streak_key = ek
                    state.bfs_expand_streak_hash = screen_hash
                    state.bfs_expand_streak_count = 1
                break

        if (
            chosen is None
            and _hierarchy_shows_permission_dialog(turn.elements, pkg)
            and state.bfs_back_streak < 1
        ):
            chosen = {"action_type": "back", "reason": "bfs_leave_permission_overlay"}

        if chosen is None and layer_expand_active and expand_cands:
            tried_on_screen = state.bfs_expand_tried_on_screen.setdefault(screen_hash, set())
            layer_pick = _bfs_pick_untried_expand_candidate(
                expand_cands,
                target_pkg=pkg,
                tried_keys=tried_on_screen,
            )
            if layer_pick is not None:
                chosen = layer_pick
                tried_on_screen.add(_nav_target_key(layer_pick))

        if (
            chosen is None
            and state.tab_cycle_keys
            and (
                not layer_expand_active
                or not _bfs_has_untried_expand_on_screen(
                    expand_cands,
                    target_pkg=pkg,
                    tried_keys=state.bfs_expand_tried_on_screen.get(screen_hash, set()),
                )
            )
        ):
            for off in range(len(state.tab_cycle_keys)):
                idx = (state.tab_cycle_index + off) % len(state.tab_cycle_keys)
                k = state.tab_cycle_keys[idx]
                if k not in visible_tab_keys and k not in visible_nav_keys:
                    continue
                base = state.tab_key_to_action.get(k) or state.nav_key_to_action.get(k)
                if not base:
                    continue
                chosen = dict(base)
                chosen["reason"] = "bfs_nav_cycle_after_exhaust"
                state.tab_cycle_index = (idx + 1) % len(state.tab_cycle_keys)
                break

        if (
            chosen is None
            and nav_cands
            and (
                not layer_expand_active
                or not _bfs_has_untried_expand_on_screen(
                    expand_cands,
                    target_pkg=pkg,
                    tried_keys=state.bfs_expand_tried_on_screen.get(screen_hash, set()),
                )
            )
        ):
            for c in nav_cands:
                if _action_is_foreign_dialog_widget(c, pkg):
                    continue
                if not _action_is_search_like(c) and not _action_is_back_like(c):
                    chosen = dict(c)
                    chosen["reason"] = "bfs_nav_cycle_after_exhaust"
                    break

        if chosen is None and nav_cands:
            for c in nav_cands:
                if _action_is_search_like(c):
                    chosen = dict(c)
                    chosen["reason"] = "bfs_search_after_frontier"
                    break

        if (
            chosen is None
            and nav_cands
            and (
                not layer_expand_active
                or not _bfs_has_untried_expand_on_screen(
                    expand_cands,
                    target_pkg=pkg,
                    tried_keys=state.bfs_expand_tried_on_screen.get(screen_hash, set()),
                )
            )
        ):
            for c in nav_cands:
                if not _action_is_foreign_dialog_widget(c, pkg):
                    chosen = dict(c)
                    chosen["reason"] = "bfs_nav_cycle_after_exhaust"
                    break

        if chosen is None and not nav_cands and not tab_cands and expand_cands:
            tried_on_screen = state.bfs_expand_tried_on_screen.setdefault(screen_hash, set())
            no_nav_pick = _bfs_pick_untried_expand_candidate(
                expand_cands,
                target_pkg=pkg,
                tried_keys=tried_on_screen,
                reason="bfs_expand_no_nav_tabs",
            )
            if no_nav_pick is not None:
                chosen = no_nav_pick
                tried_on_screen.add(_nav_target_key(no_nav_pick))

        if chosen is None:
            text_pick = _pick_text_entry_explore_action(
                turn.elements,
                pkg,
                screen_hash=screen_hash,
                probed_keys=state.bfs_text_entry_probed_keys,
            )
            if text_pick is not None and not nav_cands and not tab_cands and not expand_cands:
                chosen = text_pick

        return chosen


class RecoveryPolicy:
    """Final fallthrough when chooser returns None — back / wait recovery."""

    @staticmethod
    def apply(state: ExploreState) -> dict[str, Any]:
        if state.bfs_back_streak >= 1:
            return {"action_type": "wait", "reason": "bfs_avoid_back_loop"}
        return {"action_type": "back", "reason": "bfs_return_to_hub"}


def choose_explore_action_legacy(
    turn: ExploreTurnInput,
    state: ExploreState,
    *,
    candidate_builder: CandidateBuilder | None = None,
    action_chooser: ActionChooser | None = None,
    recovery_policy: RecoveryPolicy | None = None,
) -> ExplorePickResult:
    """Pure explore pick: buckets → tier walk → recovery. No device I/O."""
    builder = candidate_builder or CandidateBuilder()
    chooser = action_chooser or ActionChooser()
    recovery = recovery_policy or RecoveryPolicy()

    dialog_state = _derive_dialog_state(turn.fg_now, turn.elements, turn.pkg)
    if turn.fg_now == turn.pkg and not bool(dialog_state.get("visible")):
        state.bfs_dialog_dismissed_tokens.clear()

    dialog_token = str(dialog_state.get("token") or "")
    dialog_action = _dialog_policy_action(
        dialog_state,
        turn.elements,
        turn.pkg,
        state.bfs_dialog_dismissed_tokens,
    )

    buckets = builder.build(
        turn.elements,
        pkg=turn.pkg,
        screen_hash=turn.screen_hash,
        permission_risk_keys=state.bfs_permission_risk_keys_attempted,
    )
    _nav_graph_register_candidates(
        state.nav_graph,
        turn.screen_hash,
        buckets.tab_cands,
        candidate_kind="tab",
        target_pkg=turn.pkg,
    )
    _nav_graph_register_candidates(
        state.nav_graph,
        turn.screen_hash,
        buckets.nav_cands,
        candidate_kind="nav",
        target_pkg=turn.pkg,
    )

    chosen = chooser.choose(
        state=state,
        buckets=buckets,
        turn=turn,
        dialog_action=dialog_action,
    )
    if chosen is None:
        chosen = recovery.apply(state)

    return ExplorePickResult(
        action=chosen,
        state=state,
        nav_cands=buckets.nav_cands,
        other_cands=buckets.other_cands,
        expand_cands=buckets.expand_cands,
        tab_cands=buckets.tab_cands,
        layer_expand_active=buckets.layer_expand_active,
        dialog_token=dialog_token,
        dialog_state=dialog_state,
    )


class ExploreStrategy(Protocol):
    def pick_action(self, turn: ExploreTurnInput, state: ExploreState) -> ExplorePickResult: ...


class _LegacyNavGraphBfsExploreStrategy:
    """Default strategy — current nav-graph BFS tier walk."""

    def pick_action(self, turn: ExploreTurnInput, state: ExploreState) -> ExplorePickResult:
        return choose_explore_action_legacy(turn, state)


class _LegacyNoOpExploreStrategy:
    """Trivial strategy for seam tests — always wait without mutating tier logic."""

    def pick_action(self, turn: ExploreTurnInput, state: ExploreState) -> ExplorePickResult:
        buckets = CandidateBuilder().build(
            turn.elements,
            pkg=turn.pkg,
            screen_hash=turn.screen_hash,
            permission_risk_keys=state.bfs_permission_risk_keys_attempted,
        )
        return ExplorePickResult(
            action={"action_type": "wait", "reason": "noop_explore_strategy"},
            state=state,
            nav_cands=buckets.nav_cands,
            other_cands=buckets.other_cands,
            expand_cands=buckets.expand_cands,
            tab_cands=buckets.tab_cands,
            layer_expand_active=buckets.layer_expand_active,
            dialog_token="",
            dialog_state={},
        )


def interactive_elements_from_dicts(
    elements: list[dict[str, str]], *, screen_hash: str
) -> list[InteractiveElement]:
    return [InteractiveElement.from_dict(e, screen_hash=screen_hash) for e in elements]


def element_passes_explore_gate(element: InteractiveElement) -> bool:
    return _element_passes_bfs_interactive_gate(element.as_dict())
