# `agents/attack/attack_orchestrator.py` — sequence the attack from a goal

`[← back to all_info index](../../README.md)`

---

## 1. Purpose & place in the system

The attack-side mirror of the `DecisionAgent` (step [4/5]). It aggregates the two
exploiters' findings, considers the system instance and the operator scenario,
and selects an **`AttackPlan`**: which P2 asset to target, which 1–3 findings to
chain, the **poison path** and **trigger path** (P2 §5 bi-level search), and a
confidence. Each chosen exploit is tagged with the P1 property it violates — the
red-team mirror of the defense oracles.

## 2. Imports
`json`, `re`, `dataclass`; `AgentResult`/`BaseAgent`/`Finding`.

## 3. Walkthrough

### `ASSET_CATEGORIES` — lines 27–35
The same seven P2 human-centric categories as the defense side (so blue and red
reason over one taxonomy).

### `AttackPlan` — lines 38–48
`scenario`, `objective`, `target_asset`, `chosen_findings`, `poison_path`,
`trigger_path`, `confidence`, `justification`, `summary`.

### `plan(scanner_results, scenario, instance)` — lines 72–94
Aggregate findings, render them compactly, fill the prompt (scenario, instance,
findings, assets), call the LLM, and parse into an `AttackPlan`.

### `_render_instance` / `_parse_plan` — lines 97–145
- `_render_instance` (97–108) — compact view of the recon instance for the prompt.
- `_parse_plan` (110–145) — fence-tolerant JSON parse. **Robust fallback (115–129):** on a parse failure it picks the highest-severity findings heuristically and builds a low-confidence plan, so the pipeline still produces *something*. On success it resolves `chosen_rule_ids` back to the actual findings (falling back to the top-3 by severity if the ids don't match).

## 4. Edge cases, gotchas & design decisions
- **Mirror of the decision agent.** Same aggregation + LLM-decide shape, but the
  output is an offensive plan (target + poison/trigger chain) rather than a
  defensive tier.
- **Bi-level path (P2 §5).** Separating poison path (delivery) from trigger path
  (activation) is the core P2 attack model.
- **Always produces a plan.** The severity-heuristic fallback means even a broken
  LLM response yields a usable (if low-confidence) plan — important because the
  ethics guard and generator run on whatever this returns.
- **P1 properties tag exploits.** Each chosen exploit notes which contextual-
  security property it breaks, which is exactly the signal the defense pipeline
  can be evaluated against.
