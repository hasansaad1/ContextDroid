# v2 reference tier (bulk_llm_benign_v2)

Immutable curation snapshot from the paused v2 collection run (197/284 apps completed at
curation time; 594 analyze-success sessions indexed). **Curation only** — no re-collection.

## Honest read

- **Reference tier:** 168 sessions across **59 distinct apps** (~28.3% of analyze-success).
- **Volume tier:** 426 analyze-success sessions that fail one or more reference gates.
- Reference is intentionally small: sim success (~35%), flailing (~38%), and zero meaningful
  Frida (~17% under old 25-hook metric) dominate fallout. The 22-category GRAPH correction
  shifts meaningful>0 from 492 to 492 sessions.
- v1 (129 sessions, `experiments/datasets/versions/v1/`) is a **separate generation**
  (v6 run, hook v2, judge_v1_75pct). Do not pool v1 and v2 in evaluation.

## Why reference is ~59 apps, not 197

Most completed apps never produce a reference session because:

1. **Sim failure** (`ux_quality_gate`, `bad_handoff`, `explore_non_navigable`) — largest bucket.
2. **Flailing** — mechanical explore or dominant-screen loops despite UI motion.
3. **Faithfulness FAILED** — judge rejects incoherent or shallow sessions.
4. **Zero GRAPH-category Frida** — UI motion without behavioral hook signal (lifecycle-only traces).
5. **Auth / network** — login gates and best-effort offline/RETRY keyword detection.

Launchers and canvas/game apps contribute almost no reference sessions (0% sim success in class).

## Reference gate (verbatim)

A session enters the REFERENCE tier iff ALL of: (1) analyze_status=success; (2) llm_simulation_status=success; (3) faithfulness_verdict in {FAITHFUL, PARTIAL} (judge faithfulness_v2_phase_aware); (4) C0 explore engagement pass (>=3 named effective functional explore taps OR >=2 new functional explore screen hashes); (5) meaningful_frida_22cat > 0 over GRAPH_CATEGORY_UNIVERSE (22 hook categories excluding lifecycle, reflection, navigation; framework APIs hook_loaded/Method.invoke excluded); (6) NOT flailing (quality_rules.detect_suspect_flailing); (7) NOT login_required / auth_gated (llm_simulation_status != failed:skip:login_required); (8) NOT tagged NETWORK_DEGRADED (best-effort digest-keyword detection via DEGRADED_RE on agent action reasons). Everything else analyze-success -> VOLUME tier.

## Fallout drivers (multi-count among volume tier)

- `sim_not_success`: 385
- `flailing`: 223
- `zero_meaningful_frida_22cat`: 102
- `faith_FAILED`: 94
- `explore_fail`: 83
- `auth_gated`: 12

## 22-category coverage in reference tier

Categories with 0 reference sessions firing:

- accounts, clipboard, device_info, dynamic_code_loading, media, sms, telephony

## NETWORK_DEGRADED (best-effort)

Keyword gate caught **0** sessions (0 apps). See `version_meta.json` for the session list.

## Per-app evaluation viability

~59 apps with ≥1 reference session is enough for **per-app spot checks** but not
for robust stratified evaluation across all app classes. Reference skews toward `other`,
`network_tool`, and `media` ({'other': 147, 'network_tool': 12, 'ime': 3, 'comm': 3, 'media': 3}). Launchers/games remain absent.

## Regrowth targeting

Use `coverage_gap` column in manifest.csv — descriptive judge notes on unvisited flows,
not a quality penalty.
