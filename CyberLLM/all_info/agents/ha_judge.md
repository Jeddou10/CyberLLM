# `agents/ha_judge.py` — the H_a action-alignment oracle

`[← back to all_info index](../README.md)`

---

## 1. What does "H_a" mean?

`H_a` is the **action-alignment** (harm-acceptability) oracle from P1. P1 defines
five oracle functions; their experiments show that approximating `H_a` — *"does
action `a` genuinely serve the declared objective `o` in this context?"* — is the
single highest-value defense, cutting attack success by ~86–88%. The intuition:
an action can be individually valid yet still **not serve** the objective (e.g. a
privileged change requested under a read-only "just report" objective). This
module is that oracle, implemented as a **dedicated LLM judge**.

It is consumed by `SecurityGuard` (which combines it with a static map), and
built once per run in `pipeline.py`.

---

## 2. Imports — lines 25–30

| line | import | why |
|------|--------|-----|
| 27–28 | `json, re` | Parse the judge's JSON verdict. |
| 30 | `LLMClient` | The (separate) model call. |

Module constants (35–40): `_PRIVILEGED_KINDS` (state-changing actions like
`patch_code`, `isolate_node`, `secrets.rotate`) and `_REPORT_ONLY_OBJECTIVES`.
A privileged action under a report-only objective is the canonical `H_a` failure.

---

## 3. Walkthrough

### `class HaJudge.PROMPT` — lines 44–55
A tightly-scoped prompt with one job: given `OBJECTIVE`, `ACTION`, `CONTEXT`,
return `{"serves": true|false, "reason": "..."}`. It explicitly reminds the model
that a valid action can still fail to serve the objective.

### `__init__` — lines 57–66
Stores the LLM and a **per-instance cache** (`_cache`). **Why the cache:** the
per-step guard asks the same `(action, objective, context)` question for dozens
of plan steps; with a real, rate-limited, paid model that would be a flood of
identical calls. Memoizing means each *distinct* question costs exactly one call.

### `judges(action_kind, objective, context)` — lines 68–82
The entry point. It builds the cache key; returns the cached verdict if present
(71–72); otherwise fills the prompt, calls the model, parses, caches, and returns
`(serves: bool, reason: str)`.

### `_parse(...)` — lines 84–95
Fence-tolerant JSON parse → `(bool serves, str reason)`. **Conservative fallback
(91–95):** if the model returns nothing parseable, fall back to the deterministic
`_heuristic` so the judge never *spuriously blocks* a legitimate action.

### `_heuristic(action_kind, objective, context)` — lines 98–109
The deterministic stand-in (also what the offline stub encodes). It refuses the
two clear misalignments — a privileged action under a report-only objective
(104–106), or a context explicitly flagged `misaligned`/`trusted-asset`
(107–108) — and allows everything else.

---

## 4. Edge cases, gotchas & design decisions

- **It can only ever *tighten* the guard.** The guard computes `action_ok =
  static_map_ok AND ha_judge_ok`. The probabilistic judge never *loosens* the
  deterministic floor — a key safety property.
- **Separation defeats prompt injection.** The judge is a *distinct* call with
  one narrow job, so an injection that subverts a scanner or the decision agent
  still has to get past an independent oracle.
- **Deterministic under the stub.** With no real model, `_heuristic` makes the
  judge's verdicts reproducible — so the test suite can assert exact refusals.
- **Caching matters for cost, not correctness.** The cache is per-instance and
  the guard/judge live for one run; identical questions collapse to one call.
- **Fails open to the heuristic, not to "allow."** An unparseable model response
  doesn't blanket-allow — it falls back to the same deterministic rule the stub
  uses, so safety is preserved without false refusals.
