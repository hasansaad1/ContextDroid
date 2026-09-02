# ContextDroid Remediation Plan — Task Breakdown

**Version:** 1.0
**Scope:** Fix the explore-phase collection pipeline, then re-collect and re-curate the corpus.
**Governing principle:** *Instrument before you fix. Fix before you multiply.*

Three separate misdirections in this project traced to the same root cause: **optimizing something no metric could see.**

| # | Incident | Root cause |
|---|---|---|
| 1 | `goals_completed` tracked engine skips | `advance_goal` returned success on `engine_prose_spiral_skip_unroutable` |
| 2 | Judge at 75% agreement, Mensa scored 0.96 | `direct_action_ratio` structurally blind to explore phase |
| 3 | 44 sessions idling with 11 elements on screen | Candidate emptiness invisible behind `interactive_element_count` |

Every ordering decision below follows from this. Logging precedes the fix it measures. Collection follows the collector it depends on.

---

## Status legend

| Tag | Meaning |
|---|---|
| **BLOCKER** | Something downstream is silently corrupted until this lands |
| **INSTRUMENT** | Produces no behavior change; makes the next task measurable |
| **FIX** | Confirmed, root-caused bug with cited lines |
| **SEAM** | Structural change that lowers the cost of everything after it |
| **COLLECT** | Touches data generation; do not run before its prerequisites |

---

# STEP 0 — Merge the flailing rules into `quality_rules.py`

**Tag:** BLOCKER · **Effort:** ~0.5 day · **Blocks:** Step 10 (re-curation), Step 7 (judge)

## Why this is first

`_flailing_new` (`phase_aware_metrics.py` 441–469) is **not a superset** of `detect_suspect_flailing` (`assemble_working_dataset.py` 63–122). It dropped two rules without replacement:

- `same_element_cycle` (old pattern 2b, lines 107–113)
- `dominant_screen when named ≥ 3`

**Twelve of the thirteen cleared sessions were flagged correctly by the old rules** — genuine execute-phase repetition that the explore-aware rules never examine. Examples: `cc.echonet.coolmicapp`, `ca.voiditswarranty.roadtripradar`.

So `46 → 35` (v129) and `106 → 85` (v6) was **a hole, not a stricter metric.** If dataset v2 is curated on `_flailing_new` as-is, the reference tier gains 12 genuinely-flailing sessions **and looks cleaner for it.**

This is the architect's **seam #3**: duplicate quality logic in two modules that have already diverged.

## Tasks

- [ ] **0.1** Create `extraction_pipeline/quality_rules.py` as the single source of flailing/quality rules.
- [ ] **0.2** Port `same_element_cycle` from `assemble_working_dataset.py` 107–113. Scope it to `execute` + `primary_ux` phases.
- [ ] **0.3** Port `dominant_screen` (with the `named ≥ 3` guard) from the old rule set. Same phase scoping.
- [ ] **0.4** Port `explore_back_wait_dominant` from `_flailing_new`. Scope to `explore` phase.
  - Correctly catches `app.traced_it`, `cat.mvmike.minimalcalendarwidget` (explore 100% back/wait, 0 functional taps, old ratio 1.0 from primary_ux).
- [ ] **0.5** Port `low_all_phase_direct_ratio` (replaces execute-only `low_direct_action_ratio`), gated on `sim=success`.
- [ ] **0.6** Import `quality_rules.py` from **both** `phase_aware_metrics.py` and `assemble_working_dataset.py`. Delete the duplicated logic from each.
- [ ] **0.7** Recompute flailing across v6 + v129 with the merged rules. Report:
  - counts vs. old rules vs. `_flailing_new`
  - the 12 restored sessions, named
  - the 2 new additions, named
  - confirm Mensa is flagged under both `explore_back_wait_dominant` AND the old `dominant_screen` path

## Acceptance criteria

- One module owns flailing rules. No duplicated logic.
- Merged count ≥ 46 on v129 (restores the 12, keeps the 2 additions).
- `ch.famoser.mensa` flagged. `app.traced_it` flagged. `cat.mvmike.minimalcalendarwidget` flagged.
- `cc.echonet.coolmicapp` and `ca.voiditswarranty.roadtripradar` flagged again.

## Do NOT

- Do not treat `46 → 35` as an improvement. It is under-detection.
- Do not re-curate the dataset in this step. Report label changes only.

---

# STEP 1 — Log the candidate buckets at every explore step

**Tag:** INSTRUMENT · **Effort:** ~0.5 day · **Blocks:** Step 2 (verification), all future explore work

## Why this precedes the fix

Cursor's own PART 1 opened with: *"the deciding query cannot be answered from existing logs."*

It fell back to `*_verified_start.xml` — **the launch screen** — replayed against recovery steps:

| Metric | Value |
|---|---|
| Recovery steps across the 44 OTHER sessions | 1,841 |
| Steps whose `screen_hash` matched `verified_start.xml` | **51 (2.8%)** |
| Sessions with zero replayable recovery steps | **41 / 44** |

The central finding (`median unvisited_non_nav = 0`) is, by Cursor's own words, *"a lower bound — wrong screen for 97% of steps."*

The mechanism argument for the `clickable` bug is strong — the lines are right there. But **you will have no way to verify the fix worked**, because the same instrumentation gap that prevented diagnosis will prevent measurement of the remedy. Ship blind and your evidence is *"back/wait went down,"* which a dozen things could cause.

**This is not the `explore_policy.py` extraction (Step 5).** The candidate lists already exist in memory at `navigation.py` 266–312. This is a log line.

## What exists today at recovery steps

In `*_llm_actions.jsonl`:
- `interactive_element_count` (= `len(elements)` after dump + filter; `session.py` ~1268)
- `screen_hash`, `app_state.screen_role`
- chosen `parsed_action` (back/wait + reason)

**Missing:** element list, candidate set, per-element clickability.

## Tasks

- [ ] **1.1** At every explore step, after `_build_bfs_candidates` returns, log:
  ```
  nav_cands          : int
  other_cands        : int
  expand_cands       : int
  tab_cands          : int
  skipped_interactive: int   # passed _is_visible_and_interactive, entered NO bucket
  ```
- [ ] **1.2** Log a trimmed element snapshot keyed by `screen_hash`:
  - per element: `class`, `bounds`, `clickable`, `has_rid`, `has_cd`, `has_text`, `bucket` (`nav|other|expand|tab|none`)
  - Keep it trimmed — this must not blow up log size across a 600s session.
- [ ] **1.3** Log the tier that produced the chosen action (`reason` string already does this; make the tier index explicit).
- [ ] **1.4** Ensure the snapshot is written at **recovery steps specifically** (`bfs_return_to_hub` / `bfs_avoid_back_loop`). These are the steps that could not be reconstructed.
- [ ] **1.5** Run 5 sessions spanning the classes. Confirm the new fields appear and `skipped_interactive > 0` on the OTHER archetypes.

## Acceptance criteria

- For `ch.famoser.mensa`: recovery step logs show `iec=11`, `nav=0`, `other=0`, `expand=0`, `skipped_interactive=11`.
- The 1A query is now answerable from logs alone, without `verified_start.xml` replay.

## Do NOT

- Do not change candidate selection behavior. Logging only.
- Do not extract `explore_policy.py` here.

---

# STEP 2 — Fix the element model: propagate `clickable`, admit anonymous clickables

**Tag:** FIX · **Effort:** ~1 day · **Depends on:** Step 1

## The actual bug — two lines, two files

| File | Lines | Problem |
|---|---|---|
| `screen.py` | 66–73 (`_normalized_elements`) | **`clickable` is never propagated** from XML into element dicts |
| `navigation.py` | 279–281 | `_build_bfs_candidates` **gates on `clickable`** |
| `navigation.py` | 294–295 | `other` bucket **additionally requires a label** (`text \| cd \| rid`) |

An anonymous clickable `View` — the modern Compose/Material norm — passes `_is_visible_and_interactive`, is counted in `interactive_element_count`, appears in logs as *"11 interactive elements on screen"*, and is **invisible to every candidate bucket.** Zero nav, zero other, zero expand → `chosen is None` → `bfs_return_to_hub` → back.

### Mensa, exactly

```
screen_hash : 4b284b2ea88ba68b…
screen_role : content
iec         : 11
digest      : View · View · … (no rid/text/cd)
candidates  : nav=0  other=0  expand=0
BFS chose   : back / bfs_return_to_hub
after       : screen_hash → empty hierarchy (4f53cda1…)
```

31 of the 44 OTHER sessions have unnamed-View recovery digests.

## Correcting the original hypothesis

The hypothesis *"BFS pursues only nav affordances and ignores named functional controls"* is **NOT confirmed.** Cursor refused it, correctly:

- Tier 3 `bfs_expand_frontier` (`session.py` 987–1006) **does** tap labeled non-nav `other_cands` — 35 such taps in the OTHER bucket.
- `verified_start` replay: `median unvisited_non_nav = 0` even *with* a simulated clickable fix.
- The failure is **candidate-set emptiness**, not nav-vs-functional ordering.

**The fix must target anonymous clickables and the missing `clickable` field — not "add named non-nav."**

### Skipped element taxonomy (from `verified_start` replay, n=100 skipped)

| Skip type | Count | Identity signals | Fix path |
|---|---|---|---|
| Unnamed clickable `View` | 67/100 (31/44 sessions) | `clickable=true`, no rid/cd/text | bounds-center key |
| Unlabeled `Button` | 11/18 Buttons | Button class, empty label | bounds-key, or inherit clickability from class |
| `EditText` | 9/11 | focusable input, often no rid | **separate input/focus tier**, not plain tap |
| Named non-nav | 11 sessions | rid/cd/text present | already in `other` — recovery means exhaustion, not exclusion |
| Nav-classified | rare in OTHER | tab rids, bottom-strip | **not the blocker** |

Skipped elements are **top-level anonymous clickables on flat/content screens** — not inside ignored scroll containers.

## Scope note that must not be understated

**This is not a 44-session bug. It is corpus-wide.** Every screen with anonymous clickables, in every session ever collected, had those elements structurally unreachable to explore. The 44 are where it *dominated*; it was suppressing engagement everywhere.

## ⚠ Decide before implementing: stable identity for unlabeled elements

Neither reviewer addressed this.

`_nav_target_key` (`action_model.py` 22–27) identifies unlabeled elements by a JSON signature **including `x,y`**. So:

> **An anonymous element's identity is its position.**

Consequences:
- Screen re-lays-out → same element gets a new key → **looks unvisited** (infinite re-tap)
- A *different* element occupies the old position → **looks visited** (never tapped)

This is tolerable on the flat, static content screens where the 31 live. **It breaks the moment scroll exists (Step 6).** Pick the scheme now.

Options to evaluate:
1. Bounds-center key (current path) — positionally fragile
2. Bounds-center + sibling index within parent — more stable under scroll
3. Bounds-center + `class` + parent chain hash — most stable, most expensive

- [ ] **2.0** **Decide and document the anonymous-element identity scheme before writing code.** Record the choice and its failure mode under scroll.

## Tasks

- [ ] **2.1** `screen.py` 66–73: propagate `clickable` (`"true"|"false"`) from XML into element dicts.
- [ ] **2.2** `navigation.py` 291–295: elements passing `_is_visible_and_interactive` but lacking labels → append to `other` with **bounds-center tap** and **bounds-key identity** (per 2.0).
- [ ] **2.3** Route `EditText` to a **separate input/focus tier** — do not plain-tap focusable inputs. (Ties into Step 4.)
- [ ] **2.4** Optional: raise expand priority when `nav_cands` AND `tab_cands` are both empty (small branch before `session.py` 1099).
- [ ] **2.5** Re-run the 5 verification sessions from Step 1.5.

## Acceptance criteria — measured with Step 1's logging

- At recovery steps: `skipped_interactive` was N → now ≈ 0; `other_cands` ≈ N.
- `ch.famoser.mensa`: `explore_functional_tap_count` > 0 (was 0), `explore_back_wait_ratio` < 1.0 (was 1.0).
- `ch.protonvpn.android` (control): **unchanged.** No new candidates, no behavior delta.
- Corpus-wide: report how many of the 44 OTHER sessions convert back/wait into functional taps.

## Do NOT

- Do not add scroll. Do not add gesture mode.
- Do not touch `hook_apis.js`, graph code, `CATEGORY_UNIVERSE`, or `GRAPH_CATEGORY_UNIVERSE`.
- Do not claim session-level coverage improvement without Step 1's per-step candidate logging.

---

# STEP 3 — Check `bfs_expand_stall_by_screen` (do WITH Step 2)

**Tag:** FIX · **Effort:** hours · **Runs alongside:** Step 2

## Why it may eat the fix

`session.py` 1199–1202: once `bfs_expand_stall_by_screen ≥ _BFS_EXPAND_STALL_LIMIT_PER_SCREEN`, **all expand keys on that `screen_hash` are marked tried.**

If content changes but the hash does not, **every candidate on that screen is permanently burned.** Rated MAJOR by the senior reviewer, independently suppressive.

**It interacts badly with Step 2:** you will admit new candidates, then have them marked-tried by a stall keyed on a hash that does not reflect content.

## Tasks

- [ ] **3.1** Instrument: log when `bfs_expand_stall_by_screen` fires, with `screen_hash`, streak count, and how many keys are being mark-all-tried.
- [ ] **3.2** Determine whether it fires on the **newly-admitted anonymous candidates** from Step 2.
- [ ] **3.3** If yes: change mark-all-tried to mark-only-the-tried-key, or key the stall on a content hash rather than `screen_hash`.
- [ ] **3.4** Check the NIT: `layer_expand_active` (1035–1040) blocks nav-cycle tiers when untried expand exists — on screens with zero expand candidates this condition is **vacuously true**. Confirm it is not blocking recovery paths on the OTHER archetypes.

## Acceptance criteria

- Newly-admitted candidates from Step 2 are not burned by the stall limit.
- A screen whose content changed under a stable `screen_hash` does not lose its candidate set.

---

# STEP 4 — Typing goal classifier fix

**Tag:** FIX · **Effort:** low · **Independent** — can run in parallel with 0–3

## The confirmed bug chain (YidKey)

```
explore: 36× tap same EditText
execute: 1× advance_goal (no typing ever happened)
primary: 20× swipe on a misclassified "search" surface
Frida  : 0 meaningful events
sim    : failed:ux_quality_gate | judge: FAITHFUL | human: FAILED
```

Root cause, pinned in `goals.py`:

1. Typing goals require `"search"` or `"query"` in goal text. **`"Input text in…"` does not qualify.**
2. `_goal_feasibility_status` marks **satisfied after 2 unchanged taps on the same screen.**
3. A lone `EditText` → `screen_role=search` → `primary_ux` swipes instead of typing.

This also removes a source of false `advance_goal` that pollutes every metric downstream.

## Tasks

- [ ] **4.1** Broaden `_goal_needs_text_entry_field` beyond `search` / `query`. Include `input`, `type`, `enter`, `write`, `fill`.
- [ ] **4.2** **Never** satisfy via unchanged taps when goal text contains an input/type/enter verb.
- [ ] **4.3** Lone `EditText` → classify `screen_role` as `form` / `text_entry`, **not** `search`.
- [ ] **4.4** Reject degenerate goals matching `Tap TRANSITIONS:` (non-affordance emitted when explore produces a sparse/empty digest).
- [ ] **4.5** Guard: with `len(ux_goals) == 1`, goal-progress gates currently **skip entirely.** Either enforce them or fail the session — do not let a single degenerate goal produce `advance_goal` on nonsense.

## Acceptance criteria

- `click.dummer.yidkey`: typing goal is routed as text entry, not search. `advance_goal` does not fire without an input event.
- No session completes with `Tap TRANSITIONS:` as its only goal.

## Related, from Step 2

`EditText` handling (2.3) must agree with this: focusable inputs get an input/focus tier, not a plain tap.

---

# STEP 5 — Extract `choose_explore_action()` into `explore_policy.py`

**Tag:** SEAM · **Effort:** 2–3 days · **Depends on:** Steps 1–3 landed and measured

## Why fifth, not second

The architect named this *"the ONE change that most reduces the cost of every subsequent change"* — and that is correct. But it **unblocks nothing directly** (0 sessions), and Steps 0–4 are cheap enough to do without it.

After this seam, scroll (Step 6) and app-class routing become **strategy hooks** rather than surgery on the session loop.

## The entanglement today

Candidate build + tier walk + recovery are inline across `session.py` 833–1137, coupled to device I/O.

### The tier walk, as it actually is

| Tier | Lines | Behavior |
|---|---|---|
| 0 | 841–846 | Dialog policy |
| 1 | 889–907 | Interior expand after tab switch |
| 2 | 910–923 | Nav-graph uncovered tab/nav |
| 3 | 926–937 | Tab frontier BFS |
| 4 | 960–974 | Nav frontier BFS |
| 5 | 977–986 | Nav visible fallback |
| **6** | **987–1006** | **Expand frontier — taps `other_cands`** |
| 7 | 1007–1012 | Permission overlay back |
| 8 | 1014–1028 | Layer expand |
| 9 | 1030–1097 | Tab/nav cycle after exhaust |
| — | **1099–1104** | **Fallthrough: `back` / `wait`** |

**Important correction to the earlier narrative:** expand is **Tier 6, not last-resort after recovery.** Recovery means the expand list was *empty* (or all keys marked tried by the stall limit — see Step 3). This is why "BFS only taps nav" was the wrong story.

## Tasks

- [ ] **5.1** Extract a pure function:
  ```
  choose_explore_action(elements, pkg, ExploreState) -> (action, ExploreState)
  ```
  No device I/O. `ExploreState` as a dataclass.
- [ ] **5.2** Decompose the conflated responsibilities into three components:
  - `CandidateBuilder` — elements → buckets
  - `ActionChooser` — buckets + state → tiered choice
  - `RecoveryPolicy` — currently embedded as `if chosen is None` inside the chooser
- [ ] **5.3** Introduce a canonical element model (**architect's seam #2**): `InteractiveElement` with `clickable`, `labeled`, `nav_likelihood`, `bounds`, `viewport_visible`. Replaces the incomplete dict from `screen.py` `_normalized_elements`.
- [ ] **5.4** Make `ExploreStrategy` pluggable. `NavGraphBfs` becomes the default strategy, one of several.
- [ ] **5.5** Unit-test the candidate selector in isolation — impossible today without copy-paste or subprocess.
- [ ] **5.6** Replace the `if exploring_phase` block (`session.py` 833) with `explore_strategy.pick_action(state)`.

## State-handling issues to resolve during extraction

| State | Scope | Location | Issue |
|---|---|---|---|
| `nav_attempted`, `tab_attempted` | session-global by `_nav_target_key` | 233–237, 934, 968, 985 | Key collision (MINOR) |
| `bfs_expand_tried_on_screen` | per `screen_hash` | 247, 999, 1020, 1200–1202 | Mark-all-tried (MAJOR — Step 3) |
| `nav_frontier_queue` / `tab_frontier_queue` | session-global, visibility-filtered per turn | 960–974 | — |

## Acceptance criteria

- `choose_explore_action` is unit-testable with no device.
- Adding a new `ExploreStrategy` requires no change to the session loop.
- Behavior is **bit-identical** to pre-refactor on the 5 verification sessions. This is a refactor, not a behavior change.

## Do NOT over-engineer

This is a research pipeline, not a product. The architect explicitly guards:

**Do not change:** nav-graph BFS core (works where nav exists — 55 expand taps in OTHER prove partial value) · three-phase timing (`explore_until_sec` — research-valid separation) · fail-fast for empty hierarchy · the LLM execute / goal router.

---

# STEP 6 — Scroll in explore

**Tag:** FIX · **Effort:** 2–3 days · **Depends on:** Step 5 (much cheaper after the seam)

## Why demoted twice — and why it stays

Original ordering put scroll first. It is now sixth. Both demotions were data-driven:

1. **Phase-aware metrics** revealed the high-back/wait cohort splits **21 scrollable / 23 empty-hierarchy / 44 other.** Scroll addresses 21, not "the modality gap."
2. **The candidate investigation** showed the 44 OTHER are an element-model bug (Step 2), cheaper and broader.

It stays on the list because **recycled `RecyclerView` content is genuinely unreachable** — no other fix reaches it. And some of the 21 may resolve at Step 2 (a scrollable screen with anonymous clickables at the top now gets *tapped* rather than scrolled past). Measure after Step 2 before committing the 2–3 days.

## The container asymmetry (this determines the whole design)

| Container | Off-screen children | Detection signal |
|---|---|---|
| `ScrollView`, `NestedScrollView`, `ViewPager` | **PRESENT** in tree, with off-screen bounds | content height > viewport |
| `RecyclerView`, `ListView`, `GridView` | **ABSENT** from tree entirely (recycled) | `scrollable=true` + class only |

Relying on *"content extends below the fold"* alone **misses recycled lists entirely** — which is most feeds.

## Two traps that will silently break it

### Trap 1 — `action_success` is meaningless for scroll

A swipe gesture **always** succeeds at the adb level. Scoring scroll by `action_success` reproduces the `primary_ux` flailing problem *inside* explore. This would be the **fourth** instance of "a no-op returns success and pollutes a metric."

**Success must be defined as CONTENT GAIN.**

### Trap 2 — "newly present" vs "newly visible"

For `RecyclerView`, gain = new nodes appear in the tree. Clean.
For `ScrollView`, the nodes **were already in the tree** — nothing new appears; bounds merely shift into the viewport.

A naive *"count newly revealed named elements"* returns **zero gain** on a ScrollView that scrolled perfectly, marks it `scroll_exhausted` after two no-ops, and stops. **False negative on exactly the apps being fixed.**

> **Content gain = newly VIEWPORT-VISIBLE elements** (bounds now inside the viewport rect), **not newly PRESENT elements.** This definition works for both container classes.

## Bounds are invalidated by every scroll

An off-screen element's bounds are **stale coordinates.** `adb shell input tap 540 1800` dispatches to whatever view is *rendered* at that pixel — not the target. It returns `action_success=True` regardless. Silent misfire.

> Correct sequence: **scroll → re-dump hierarchy → read updated bounds → tap.** Never cache bounds across a scroll.

(Phantom taps measured at 19/238 sessions, mean ratio 0.05, median 0 — **not** a dominant confound today. But the viewport gate exists at dump-time (`screen.py` 42–45) and is **absent at candidate selection**. Scroll makes this live.)

## Tasks

- [ ] **6.1** Add `scroll` as a first-class action type end-to-end: schema, executor (adb swipe, direction + bounded distance), logging (`pipeline_phase`, direction, target container, reason), action-type taxonomy in audit/eval.
  - Minimum: `scroll_down`, `scroll_up`. Horizontal only if the container reports horizontal scrollability; otherwise defer and say so.
- [ ] **6.2** Scroll must target a **specific scrollable container's bounds** — never a blind screen-center swipe.
- [ ] **6.3** Detect scrollability per screen: `scrollable=true` attr **OR** class in `{ListView, RecyclerView, ScrollView, NestedScrollView, ViewPager, GridView}` **OR** content height > viewport. Report which signal fired. Distinguish recycling vs present-child containers in the output.
- [ ] **6.4** Emit `has_scrollable_content` + container ref into the screen digest.
- [ ] **6.5** **Routing (the critical insertion point):** when the current screen has **no unvisited nav/tab candidates** AND `has_scrollable_content` → emit `scroll_down` **instead of** entering back/wait recovery.
- [ ] **6.6** Bound it: max N consecutive scrolls per screen (named constant, suggest 3–5). Stop when a scroll produces no content gain. **Then** fall through to existing back/wait recovery.
- [ ] **6.7** **Never** scroll when `has_scrollable_content` is false. **Never** use scroll as a generic idle action. Preserve back/wait for the genuinely-nowhere-to-go case.
- [ ] **6.8** After each scroll compute `scroll_content_gain` = count of newly **viewport-visible** named elements (+ content-region hash change). Log it.
- [ ] **6.9** Two consecutive `content_gain=false` scrolls → mark screen `scroll_exhausted`, stop scrolling it.
- [ ] **6.10** **Newly revealed elements MUST re-enter the BFS candidate set.** Scroll surfaces tappables; navigation then reaches them. Wire this explicitly.
- [ ] **6.11** Re-read bounds after **every** scroll. Add viewport-visibility gating to the candidate set (elements outside the viewport rect are not tappable).
- [ ] **6.12** Do **not** scroll on `empty_hierarchy` screens — that is Step 8's fail-fast territory / gesture mode, out of scope.
- [ ] **6.13** Instrument: `explore_scroll_count`, `scroll_content_gain_count`, `no_op_scroll_count`, `screens_with_scrollable_content`, `newly_revealed_elements_total`. Must be distinguishable from `primary_ux` swipes (`pipeline_phase` + `action_type`).

## Revisit the anonymous-identity decision (2.0)

Bounds-keyed anonymous elements + scroll = the failure mode named in Step 2. Confirm the identity scheme survives re-layout before shipping.

## Validation apps — BEFORE vs AFTER

| App | Class | Expect |
|---|---|---|
| `ch.rmy.android.statusbar_tacho` | scrollable + high back/wait | back/wait ↓, functional taps ↑ |
| `ch.bubendorf.locusaddon.gsakdatabase` | scrollable + high back/wait | back/wait ↓ |
| `be.chvp.nanoledger` | scrollable + high back/wait | back/wait ↓ |
| `ch.blinkenlights.android.vanilla` | list (music library) | categories ↑ |
| `ch.protonvpn.android` | **CONTROL** — hub-and-spoke | **UNCHANGED.** `scroll_count = 0` |

Report per app: `explore_back_wait_ratio`, `explore_functional_tap_count`, scroll counts + gain + no-op, `distinct_meaningful_categories`, `llm_simulation_status`.

## The two numbers that catch a bad implementation

- **`protonvpn` control.** Any change at all (`scroll_count > 0`, category shift, back/wait delta) means `has_scrollable_content` is too loose. A correct implementation leaves it untouched.
- **`no_op_scroll_count`.** If Mensa shows 20 scrolls with `content_gain=false` on 18, you replaced back/wait flailing with **scroll flailing** — same pathology, different action type. Want: a few scrolls, most with gain, followed by taps on newly-revealed elements.

---

# STEP 7 — Retune the faithfulness judge

**Tag:** FIX · **Effort:** medium · **Depends on:** Steps 0, 1, 2 (its inputs must be honest first)

## Why it could not be done earlier

The judge consumes `direct_action_ratio`. That metric was **structurally blind to explore** (`audit.py` 355–361, `_human_ux_scored_events` filters to `execute | primary_ux | legacy`).

Under phase-aware scoring, **Mensa moves `0.96 → 0.32`.**

```
ch.famoser.mensa
  explore : 23× back, 23× wait, 0 tap   ← invisible to the old metric
  execute : 1× advance_goal (degenerate goal)
  primary : 22× swipe                    ← rescued the ratio to 0.96
  sim=success | judge=FAITHFUL | human=FAILED
```

**That is the mechanism behind the 60% exact / 75% collapsed agreement** — not judge weights. C6 was reading `0.96` for a session with 100% explore back/wait and zero functional taps. Retuning before the metric fix would have been tuning against a broken feature.

## The 8 human/judge disagreements, mapped to cause

| Session | Human | Judge | Cause |
|---|---|---|---|
| Mensa, GSAK | FAILED | FAITHFUL | Late `primary_ux` swipes mask explore flailing (C2/C6 blind to explore) |
| YidKey | FAILED | FAITHFUL | Tap count + screen diversity pass C1/C2 despite zero typing |
| FakeTraveler, Sommerlichter | FAITHFUL | FAILED | **C4 hard-fails on `foreground_mismatch`** despite real explore engagement |
| Vanilla, VanillaPlug | PARTIAL | FAILED | C4 hard-fails on `bad_handoff` |
| Threema | FAILED | PARTIAL | License gate; judge gives partial credit for gate-cycling |

## Tasks

- [ ] **7.1** **New C0 — explore engagement.** Require ≥3 named functional explore taps **OR** ≥2 new functional screen hashes before FAITHFUL.
- [ ] **7.2** **C6** — penalize explore back/wait **regardless of** `primary_ux` ratio. Stop letting late swipes rescue a dead explore phase.
- [ ] **7.3** **C4** — split `foreground_mismatch` into **recoverable** vs **fatal**. A mismatch *after* substantial real engagement (FakeTraveler: 57 explore taps, then Chrome/OSM attribution links) is PARTIAL, not FAILED. A `bad_handoff` that prevented the app from ever being used **is** FAILED.
- [ ] **7.4** **C2/C3** — stop counting `action_success=True` on back/wait as "sustained engagement." (See the systemic no-op-success note below.)
- [ ] **7.5** **Step 1 (Infer the app)** must *gate* the verdict, not merely preface it. If the app's defining action never occurred (typing for a keyboard, playback for a media player), cap at PARTIAL regardless of screen diversity. This is the YidKey fix.
- [ ] **7.6** **Gate-stuck rule** — decide explicitly and encode it: never reached past an entry gate into real functionality → FAILED. (Resolves the Threema ambiguity either way; just pick.)
- [ ] **7.7** Align verdict with `llm_simulation_status`: FAITHFUL requires `sim=success` **OR** an explicit override tag with evidence.

## Validation — and guard against overfitting

- [ ] **7.8** Re-run against the **same 20 hand-labels.** Target ≥90% collapsed (keep/discard) agreement.
- [ ] **7.9** **Then re-validate on a FRESH 15–20 sessions never inspected.** If it only hits 90% on the original 20, you overfit to those 8 disagreements. This second set is what makes the number defensible rather than circular.
- [ ] **7.10** Report exact + collapsed agreement, confusion matrix, and every remaining disagreement with the judge's evidence.

## Thesis framing

Quote the **collapsed keep/discard agreement**, not the exact 3-way. That single number converts *"an AI filtered my data"* into *"an LLM judge validated at N% agreement against human labels."*

---

# STEP 8 — Fix `SESSIONS_PER_APP`

**Tag:** COLLECT · **Effort:** code fix · **Deliberately late**

## The dead config

`run_bulk_llm_manifest_resumable.sh` line 329 (and the resumable orchestrator at 303/343) **hardcodes** `session_1` / `sample_id_llm_s1`. The `SESSIONS_PER_APP` env var is exported by the shell scripts and **never read** by the bulk path.

The senior reviewer flags this as a **dead-config sibling** — check for others.

## Why late — the reasoning is stronger now

Multi-session per app is a **hard blocker for the ABRG per-app reference premise**: you cannot measure a deviation floor from one session each. Nothing to converge, nothing for `IsStable` to diagnose, no `E1` convergence curve.

**But** three sessions per app with a crawler that cannot see anonymous clickables just **triples a systematically narrow sample.** Fix the collector, then multiply.

## ⚠ Decide explicitly — this determines what the data can tell you

| Mode | Measures | Serves |
|---|---|---|
| **Identical-config** sessions | run-to-run behavioral variance | **the deviation floor** (ABRG E4, the FP baseline) |
| **Varied-seed** sessions | combined coverage per app | richer per-app reference graph |

Probably a mix: e.g. 1 identical pair for variance + 1 varied for coverage. **This is a decision, not a default.**

## Tasks

- [ ] **8.1** Make the bulk orchestrator loop actually read `SESSIONS_PER_APP`. Remove the hardcoded `session_1` at lines 303/343/329.
- [ ] **8.2** Give each session a distinct `sample_id` and a distinct agent seed (if varied-seed).
- [ ] **8.3** Audit for sibling dead-config bugs (env var exported, never read).
- [ ] **8.4** Record the identical-vs-varied decision in the run manifest, per session, so downstream analysis knows which is which.

---

# STEP 9 — Re-collect as corpus v2

**Tag:** COLLECT · **Depends on:** Steps 2, 3, 4, 6, 8

## The break is forced, not chosen

All 129 existing sessions were collected with **v2 hooks.** `hook_apis.js` is now **v3**, adding:

- `ipc_intents` — `Context.startActivity`, `sendBroadcast`, `startService`, `bindService`
- `native_code` — `System.loadLibrary`, `Runtime.loadLibrary`, `Runtime.load`
- `telephony` — `TelephonyManager.getCallState` (+ subId overload)

> **Three of the 22 graph nodes are structurally dead in every existing session** — not because apps don't use intents (they constantly do), but because **nothing was watching.**

Pooling v2-hook and v3-hook sessions is a confound: some graphs **cannot** have intent edges, others can.

## The tiering

| Tier | Contents | Use |
|---|---|---|
| **v1 legacy** | the existing 129 | pipeline-build volume, graph-code debugging |
| **v2 reference** | new v3-hook collection | benign-behavior claims, the ABRG reference corpus |

**Never mix them in an evaluation.**

## Collection config for v2

- [ ] **9.1** v3 hooks (`hook_apis.js` version marker `"3"`, sha recorded per session)
- [ ] **9.2** Fixed element model (Step 2) — anonymous clickables reachable
- [ ] **9.3** Stall-limit fix (Step 3)
- [ ] **9.4** Typing goal fix (Step 4)
- [ ] **9.5** Scroll in explore (Step 6), if shipped
- [ ] **9.6** Fail-fast on `explore_non_navigable` (already shipped, K=10) — **validate live first**, see below
- [ ] **9.7** `EXECUTE_ENGINE_ONLY=0` (the one validated config change: improved category coverage, no regressions, +2s/session)
- [ ] **9.8** `SESSIONS_PER_APP` per Step 8's decision
- [ ] **9.9** Separate log dir; record hook version + all config in `dynamic_metadata.json` per session

## Outstanding from the already-shipped fail-fast

The fail-fast (`failed:explore_non_navigable`, `K=10`) was **shipped in code but never validated on a device** — `B4` reported *"no emulator for live AFTER."* The before/after table is log-replay expectation, not observation.

- [ ] **9.10** Run **one** `S.N.A.K.E` session on the emulator. Confirm the trigger fires at ~step 10 (~85s), status is `failed:explore_non_navigable`, and that `ch.famoser.mensa` (non-empty hierarchy) and `ch.protonvpn.android` do **not** fire.

## Network-dependency caution

A network-dependent app traced offline produces **failure behavior** (retry loops, error handling), not real behavior. Folding that into a benign reference teaches the graph that failure-mode behavior is normal.

- [ ] **9.11** Categorize the benign corpus by network dependency. Ensure emulator has network for network-dependent apps, or tag those sessions as `degraded` and exclude from the reference tier.

---

# STEP 10 — Re-curate as dataset v2

**Tag:** COLLECT · **Depends on:** Steps 0 (merged rules), 7 (retuned judge), 9 (v2 corpus)

## Hard prerequisites

- **Without Step 0**, the reference tier silently absorbs the 12 under-detected flailing sessions.
- **Without Step 7**, it inherits the 75%-agreement judge and the Mensa-class false FAITHFUL.

## Tasks

- [ ] **10.1** New **immutable** version under `experiments/datasets/v2/` — `manifest.csv`, `version_meta.json`, `notes.md`. Append to `registry.csv`. Never edit v1.
- [ ] **10.2** `version_meta.json` must record: `parent_version`, `source_runs`, **`judge_version`** (the retuned judge, with its validated agreement %), `curation_rules` (verbatim), `hook_version` (`v3`), `counts`, `reproduction` command, `known_limitations`.
- [ ] **10.3** **Reference tier gate — all three required:**
  1. `faithfulness_verdict ∈ {FAITHFUL, PARTIAL}` (retuned judge)
  2. `sim_status == success`
  3. **explore engagement pass** — ≥3 named functional explore taps OR ≥2 new functional screen hashes
- [ ] **10.4** **Volume tier** = everything else. Retained for pipeline stress-testing.
- [ ] **10.5** `quality_tag` per session: `FAITHFUL_VALIDATED` / `FLAILING_SUSPECT` / `LOW_CONFIDENCE` / `EXPLORE_STALL`. This column is what lets one filter separate reference from volume.
- [ ] **10.6** `--diff v1 v2` mode: sessions added, removed, and those whose verdict/tag/inclusion changed.
- [ ] **10.7** Carry `coverage_gap` per session (the judge's note on what a real user would have done but the agent didn't) — this is the **regrowth targeting list**, not a quality penalty.

## Expectations to set now

**The reference tier will be small.** Cursor's estimate of `<50` is probably right. That is fine and it is the lesson of this entire arc:

> A small clean reference set beats a large contaminated one.

Build the graph pipeline on the volume tier. Make benign-behavior claims only from the reference tier.

---

# PARKED — tracked, not scheduled

## P1 · Negative control on the GAE ← *highest-value thesis question*

Benign vs. **structurally-corrupted** graph reconstruction.

Current state: fixed 22-node universe, whole-session `train 0.557 / test 0.580`, multiwindow `0.556 / 0.572`. Train/test now separate (was `0.556 / 0.556`, a trace-dependent-node artifact — superseded).

**But test-slightly-above-train only proves the model isn't degenerate.** It does **not** prove the model learned *discriminative* benign structure. Two situations produce identical numbers:

1. The model learned real benign structure → malware would reconstruct badly
2. Benign graphs are sparse and similar → **anything** reconstructs at the same floor, including malware

Reconstruction error is BCE. `0` = perfect, `ln(2) ≈ 0.693` = coin-flip guessing. Your `0.556` is below the guessing line (good — and `ln(2)` failures went 40% → 0%), but **its absolute value means nothing.** Only relative comparisons do — and the one you're missing is *against abnormal*.

**The test:** corrupt benign graphs (shuffle edges, inject edges between never-co-occurring categories, randomize weights). Score them.

- Corrupted ≈ 0.58 → **no discrimination.** The low error is a sparsity floor. Detection will not work, regardless of pipeline cleanliness.
- Corrupted ≫ 0.58 (say 0.8+) → the model learned real structure. `0.556` is a genuine benign floor that malware would deviate from.

**Independent of every collection fix above.** Runs today on the corrected 22-node graphs. This is the difference between *"the pipeline runs"* and *"the detection premise holds."*

## P2 · Engine skip-as-success removal

`engine_prose_spiral_skip_unroutable` / `engine_prose_spiral_skip_blocked` mark unroutable goals `action_success: true` and advance the pointer. Retired from metrics; **the code path still runs.**

A skipped goal is a **failure**, not a success. It should trigger exploration of that surface, not a fake advance.

## P3 · Target-aware reflection filtering

Reflection is ~90% of trace events (median, overnight cohort). Split by **target**:
- framework targets (`android.*`, `androidx.*`, `java.*`, `kotlin.*`) → **per-session count only**
- app / sensitive targets (network, crypto, SMS, `DexClassLoader`, `Runtime.exec`) → **keep as full events** — this is the evasion signal

Verify first that target class names are **readable** (not stripped/obfuscated). F-Droid apps rarely are, so this should be clean.

## P4 · The systemic `action_success` problem — decide the semantics

**Four instances of the same bug class:**

| # | Action | Returns success when | Pollutes |
|---|---|---|---|
| 1 | `advance_goal` | always (`session.py` 757–758) | `goals_completed`, S1, S2 |
| 2 | `wait` | always, after a 0.5s sleep (1137, 1261) | `explore_back_wait_ratio`, flailing, streak |
| 3 | `back` | `adb returncode == 0`, no screen-change check | same |
| 4 | `scroll` (Step 6) | swipe always succeeds | would poison `scroll_content_gain` if scored by `action_success` |

Recovery via `back`/`wait` is **intentional**, so this is not a logic bug in explore. It is a **metrics-fidelity** bug, rated MAJOR.

> **Decide:** should `action_success` mean *effected something* rather than *adb returned 0*?

This is the single recurring pathology of the entire project. Steps 1 (candidate logging) and 6.8 (content gain) are the same lesson applied locally. A global answer would prevent instance #5.

## P5 · Status taxonomy — three overlapping statuses

A session can be simultaneously: index-`success` + `sim=failed:ux_quality_gate` + `judge=FAITHFUL`. Operators reading one field draw wrong conclusions.

The architect's proposal — one `SessionOutcome` with facets, single write at session end, metrics **read** facets rather than recomputing cross-cutting rules:

```
SessionOutcome:
  run_status  : success | partial | failed | skip        # infra
  simulation  : { verdict, detail, phase_of_failure }    # UX sim
  faithfulness: { verdict, evidence[] }                  # research gate
  quality_tags: [FLAILING_SUSPECT, EXPLORE_STALL, …]     # derived, multi
```

## P6 · App-class routing

Pre-classify from manifest / first-screen signals: `nav_graph | list_feed | canvas | form | launcher`. Route explore strategy per class instead of one BFS for all.

**Lives in:** an `ExploreStrategy` registry, selected once post-launch. Requires Step 5's seam. `NavGraphBfs` becomes one strategy; `list_feed` gets scroll-first; `canvas` gets bounds-tap.

## P7 · Digest quality gate before execute

If the digest has <2 functional screens or >80% `View · View`, don't proceed to execute — trigger gesture explore or fail. This is what produces the degenerate `Tap TRANSITIONS:` goal (Step 4.4).

---

# Dependency graph

```
0 ──────────────────────────────────────────┐
   (merged rules)                           │
                                            ├──► 7 (judge) ──┐
1 ──► 2 ──► [3 alongside 2] ──────┬──► 5 ──► 6              │
   (log)   (element fix)          │  (seam) (scroll)        ├──► 10
                                  │                          │  (curate v2)
4 ────────────────────────────────┘                          │
   (typing goals, independent)                               │
                                                             │
8 ──► 9 ────────────────────────────────────────────────────┘
   (sessions/app)  (collect v2)

P1 (negative control) ── independent, runs any time, highest thesis value
```

---

# The branch worth watching

**After Step 2 lands and Step 1 measures it**, look at how many of the 44 OTHER sessions actually recover.

| Outcome | Reading | Action |
|---|---|---|
| Most recover | The element-model bug was the whole story | Scroll stays at 6 |
| Back/wait persists on screens that now have candidates | Something in the tier walk or stall limit still suppresses engagement | **Step 3 was insufficient; Step 5 (seam) moves up** |

This is the same check that demoted scroll twice. Let the data decide again.

---

# Effort summary

| Step | Effort | Sessions/apps unblocked |
|---|---|---|
| 0 · merge quality rules | 0.5 d | dataset integrity (12 restored labels) |
| 1 · candidate logging | 0.5 d | 0 direct — makes 2 verifiable |
| 2 · element model fix | 1 d | up to 44 OTHER; **corpus-wide** |
| 3 · stall limit | hours | protects Step 2 |
| 4 · typing goals | low | YidKey / Threema class |
| 5 · `explore_policy.py` seam | 2–3 d | 0 direct — makes 6 + P6 cheap |
| 6 · scroll | 2–3 d | 21 scrollable sessions |
| 7 · judge retune | medium | curation trustworthiness |
| 8 · `SESSIONS_PER_APP` | code fix | **unblocks the ABRG per-app premise** |
| 9 · collect v2 | run time | the reference corpus |
| 10 · curate v2 | 0.5 d | the reference tier (<50 expected) |

**Steps 0–4: ~3 days total.** Cheap, mostly independent, either instrument the system or fix confirmed bugs.
**Step 5** is the seam that makes 6 and everything after cheap.
**Steps 8–10** only pay off once the collector is any good.
