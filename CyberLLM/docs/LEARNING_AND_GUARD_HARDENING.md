# Adaptive memory, guard hardening & static evaluation

This note documents the second implementation pass (2026-06-03) that
closed the *research / learning* gaps in
[`../improvements_and_exploration.md`](../improvements_and_exploration.md).
Everything here is **static-first** — no feature requires dynamically
running the target system.

---

## 1. Adaptive memory loop (Phase E)

```
   run N            signed SQLite store           run N+1
 ┌─────────┐   record(Incident, HMAC)   ┌──────────────────┐
 │ decision│ ────────────────────────►  │ incidents.db     │
 │  agent  │                            │  one row / outcome│
 └─────────┘                            └────────┬─────────┘
                                                 │ recall_similar(rule_ids, k)
                                                 │  (Jaccard overlap, verified)
                                                 ▼
                                        ┌──────────────────┐
                                        │ decision agent   │  injects the K most
                                        │  (run N+1)        │  similar past cases
                                        └──────────────────┘  as a [memory] few-shot
```

- **Store** — `agents/memory_store.MemoryStore`, stdlib `sqlite3` only
  (`memory/incidents.db`). One row per past defense/attack outcome.
- **Recall (E.2)** — `DecisionAgent.run` builds the current finding
  rule-id set, calls `recall_similar`, and injects the result into the
  prompt's `[memory]` slot. With the deterministic stub this changes
  nothing in the output (the stub ignores the extra context), so the
  loop is test-safe; with a real model it is genuine precedent.
- **Defence (E.3)** — every write is **HMAC-signed** (key from
  `memory.signing_key_env`) and tagged with its source. `recall_similar`
  drops any row whose signature fails to re-verify *or* whose source is
  not in `security.authenticated_sources`. `verify_all()` is the
  "has my memory been poisoned?" integrity sweep. This is paper 1's
  source-authorization property applied to the memory channel and
  paper 2 §4.2's poison-path defence.

Demo: run a batch (`python pipeline.py --example small`) and watch the
`recalled N past incident(s)` counter climb as the store fills.

---

## 2. Guard hardening (Phase F + C.4)

| Item | Where | What it adds |
|---|---|---|
| **F.1 H_a judge** | `agents/ha_judge.py` | A *separate* LLM call answering `{serves: 0/1}`. The guard uses `action_ok = static_map_ok AND ha_judge_ok` — it can only **tighten** the deterministic floor. |
| **F.2 provenance** | `agents/base_agent.Input` | `source` + `trust_level` are mandatory and lattice-checked; an un-attributed input cannot be constructed. |
| **F.3 compositional** | `SecurityGuard.check_trajectory` | Flags unsafe *combinations* (exfil chain, destructive-without-forensics, destructive-without-notify) even when each step is individually allowed. |
| **F.4 temporal** | `SecurityGuard.check_trajectory` | Flags TOCTOU (check-then-act with no re-verify) and memory-poisoning (destructive step in a memory-influenced plan). |
| **F.5 delegation** | `BaseAgent.delegate` | A child inherits the parent's *objective* but starts with an **empty** trusted-source set — authority can't be laundered through delegation. |
| **C.4 per-step guard** | `pipeline.build_step_guard` | The four properties + the H_a judge now run on **every** MCP tool call inside the action executor, not just the final aggregate action. |

The per-step adapter is the translation layer between the action
engine's concrete tool params and the guard's abstract four-property
vocabulary (legacy `kind` → objective + trusted destination).

---

## 3. Static evaluation harness (D.4 / D.5 / G.4)

`python evaluate.py` — scores the deterministic static analyzer against
`examples/labels.yaml` **without running the target**:

1. **Detection recall (D.4)** — per scenario, of the labelled must-have
   rule_ids, how many the static floor surfaces. (A green
   `tests/test_scenario_regression.py` ⇒ 100% here.)
2. **False-positive rate (D.4)** — measured *only* on the clean negative
   controls, where the exhaustive ground truth is "zero findings".
3. **Property-violation table (D.5)** — each detected finding → the
   paper-1 property it implicates → the paper-2 asset it threatens.
4. **Asset × scenario × skill scoreboard (G.4)** — touched assets →
   implied paper-5 tier → candidate defense skills.

**No mean-time-to-detect.** MTTD needs a live timeline; a static
analyzer has no runtime, so it is reported as N/A by design. The harness
measures static detection *coverage* instead — the metric that matches
the supervisor's "detect what can be extracted statically" constraint.

Output: console summary + `memory/eval_report.md`. Use `--strict` to
make CI fail on any missed rule or false positive.

---

## 4. Token budgeting (A.4) & credential fallback (A.2)

- `tools/tokens.py` — a dependency-free token estimator; `BaseAgent`
  accounts every prompt and warns past `guard.max_prompt_tokens`
  (default 4 096, paper 3's threshold).
- `LLMClient.create` — when a cloud provider is selected but its API-key
  env var is unset, it falls back to the deterministic stub **with a
  warning** instead of crashing, keeping CI / offline demos green.
