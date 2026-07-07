# `skills/skills.py` — the declarative skill catalogue

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

A catalogue of **declarative capabilities** the agents can select by name. Two
halves: **defense skills** (P5 tiered response + P3 auto-correction) and **attack
skills** (P2 attack-path scenarios, mapped to the human-centric asset taxonomy).
Each skill is a `Skill` dataclass: metadata plus a callable that returns a small
action/attack descriptor dict. The decision/orchestrator side and the evaluation
harness reference these (e.g. `evaluate.py` imports `DEFENSE_SKILLS`).

## 2. Imports — lines 13–15
`dataclass`, `Callable`.

## 3. Walkthrough

### `Skill` — lines 18–25
`name`, `description`, `tier` (soft/moderate/hard/attack), `side`
(defense/attack), optional `target_asset` (P2), and an optional `fn`.

### Defense skills — lines 31–85
Small `fn`s returning `{"action": ..., "params": ...}` descriptors, grouped into
**P5 tiers**:
- `SOFT_RESPONSE_SKILLS` — rate-limit, traffic-shape.
- `MODERATE_RESPONSE_SKILLS` — session-terminate, block-ip.
- `HARD_RESPONSE_SKILLS` — isolate-node, segment-network, and `patch_code` (the P3 auto-correction).
`DEFENSE_SKILLS` (83–85) concatenates all three.

### Attack skills — lines 91–147
`fn`s returning `{"attack": ..., "path": ..., "params": ...}` descriptors that
encode P2 attack paths, each tagged with the **human-centric asset** it threatens:
`memory_poison` (Privacy), `a2a_fear_injection` (Mental/Emotional Well-Being),
`rag_poisoning` (Knowledge/Thought/Belief), `confused_deputy` and
`resource_depletion` (Material/Economic Resources).

### `find_skill(name)` — lines 150–154
Linear lookup across both lists by name (or `None`).

## 4. Edge cases, gotchas & design decisions
- **Declarative, not executable infrastructure.** A skill's `fn` returns a
  *descriptor* dict (what to do + params), not a side effect — the real execution
  lives in the action engine's MCP tools. Skills are a higher-level vocabulary.
- **Tiers map to P5.** The soft/moderate/hard grouping is the P5 response ladder,
  which is why `evaluate.py` can say "tier X would fire skills Y."
- **Attack skills carry an asset.** Tying each attack to a P2 human-centric asset
  is what lets the red team reason about *human* impact, not just technical effect.
