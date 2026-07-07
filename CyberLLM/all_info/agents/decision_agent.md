# `agents/decision_agent.py` — the central decision agent (response tier + asset tagging)

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

The `DecisionAgent` sits at the **core of the defense pipeline**. It aggregates
the findings from the three scanners, tags them with P2 asset categories, recalls
similar past incidents from signed memory, and reasons over the whole picture to
pick a **response tier** (`none/soft/moderate/hard`, P5) with a confidence and
justification. It then layers **deterministic policy** on top of the
probabilistic LLM call (re-planning escalation, cross-session memory). Its
`Decision` is what `pipeline.py` feeds into the action engine and guard.

---

## 2. Imports — lines 12–18

| line | import | why |
|------|--------|-----|
| 13 | `dataclass, field` | The `Decision` shape. |
| 14–15 | `json, re` | Render tiers; parse the LLM JSON. |
| 17 | `BaseAgent, AgentResult, Finding, Input` | Base class + shapes. |
| 18 | `MemoryStore` | Recall similar incidents + cross-session recommendation. |

---

## 3. Walkthrough

### `ASSET_CATEGORIES` — lines 22–30
The seven **human-centric P2 asset categories** (Life and Bodily Health, Privacy
and Personal Data, Material and Economic Resources, …). Findings get tagged with
one of these so the response is reasoned in terms of *what's at risk to people*,
not just technical severity.

### `Decision` — lines 33–40
`summary`, `asset_categories_touched`, `recommended_tier`, `confidence` (0–1),
`justification`, and the underlying `findings`.

### `DecisionAgent.PROMPT` — lines 44–65
The prompt assembles everything the model needs: the aggregated findings, recalled
memory (precedent, "not gospel"), the cross-session recommendation, this-run
feedback (empty on attempt 1), the asset taxonomy, and the tier thresholds. It
asks for strict JSON.

### `__init__` — lines 67–74
Stores the optional `memory`, the `recall_k`, and run-logger-visible state
(`consulted_memory`, `memory_recommendation`).

### `run(scanner_results, scenario_name, feedback)` — lines 76–131
1. 79–82 — aggregate findings across scanners; collect their rule-ids.
2. 85–89 — render findings into a compact deterministic block for the prompt.
3. 91–101 — **consult memory:** `recall_similar` for precedent and `recommend` for "what tier worked on this pattern before" (cross-session learning).
4. 103–108 — fill the prompt data (findings, memory few-shot, recommendation, feedback, assets, tiers).
5. 110–111 — call the LLM and parse the `Decision`.
6. 113–121 — **deterministic policy on top of the LLM:**
   - `_apply_feedback_escalation` — if the previous attempt this run failed/was refused, bump the tier at least one notch (P5 adaptive loop).
   - `_apply_memory_recommendation` — if a high-similarity precedent succeeded at a *stronger* tier, adopt it (escalate-only, never downgrade below the LLM's call).
7. 123–130 — **heuristic asset tagging:** assign the decision's top asset category to the three most severe findings.

### Policy helpers — lines 134–176
- `_render_recommendation` / `_render_feedback` (134–149) — human-readable strings for the prompt.
- `_apply_feedback_escalation` (151–164) — escalate the tier above the failed one, nudge confidence up, and annotate the justification.
- `_apply_memory_recommendation` (166–176) — adopt a stronger memory-recommended tier, annotating the justification. **Both are escalate-only.**

### `_parse_decision` — lines 179–199
Fence-tolerant JSON parse; on failure returns a safe `none`-tier decision whose
justification carries the raw text (so nothing is lost). Always attaches the
findings.

### Tier helpers — lines 202–218
`_severity_rank` (low→critical = 0→3); `_TIER_ORDER` and `_tier_index`/
`_escalate_tier` implement the `none < soft < moderate < hard` ladder used by the
escalation policy (unknown tier treated as `soft`).

---

## 4. Edge cases, gotchas & design decisions

- **Deterministic guardrails wrap the LLM.** The model proposes a tier, but escalation policy and memory can only **raise** it — never silently lower it. This makes the response *monotonic in caution*: feedback and precedent can make it stronger, not weaker.
- **Memory is precedent, not gospel.** The prompt explicitly frames recalled incidents as advisory; the hard escalate-only logic lives in code, not in the model's discretion.
- **Asset tagging is human-centric (P2).** Tagging the top findings with a "Life and Bodily Health"/"Privacy" category is what lets a brake-ECU issue outrank a cosmetic one even at equal technical severity.
- **Robust parse fallback.** A malformed LLM response yields a `none` decision with the raw text preserved, rather than crashing — and the re-planning loop can still escalate from there.
- **`recall_k` and `exclude_scenario`.** Recall is bounded (top-k) and excludes the current scenario, so a run doesn't "recall itself."
