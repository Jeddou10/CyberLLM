# `agents/security_guard.py` — the P1 four-property guard

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

`SecurityGuard` is the **runtime enforcer of P1's four contextual-security
properties**. It is auditable by design: it *names* each check so future research
can replace any approximation independently. It has three entry points:
`check` (the whole final action), `check_step` (a single action-engine step), and
`check_trajectory` (a *sequence* of steps). The pipeline builds it once per run
and consults it before committing any action; the action executor calls
`check_step` before every tool. It optionally holds the `HaJudge` (which can only
*tighten* the action-alignment check).

The four properties: **task alignment** (objective is allowed), **action
alignment** (action fits the objective), **source authorization** (privileged
actions need an authenticated source), **data isolation** (only write to trusted
destinations).

---

## 2. Imports — lines 16–21

| line | import | why |
|------|--------|-----|
| 17 | `dataclass, field` | The three verdict shapes. |
| 19 | `legacy_kind` | Map an `ActionStep`'s tool to the legacy kind vocabulary. |
| 20 | `Action` | The legacy action shape `check` evaluates. |
| 21 | `Input` | To read trust levels for source authorization. |

---

## 3. Walkthrough

### Verdict dataclasses — lines 24–65
- `GuardVerdict` (24–31) — the result of `check` on a whole `Action`: the four booleans + `allowed` + `reason`.
- `StepVerdict` (34–49) — the per-step result; reasons about a *real `ActionStep`* (using its declared `side_effect`/`requires_authorization`) rather than a translated legacy action.
- `TrajectoryVerdict` (52–65) — the *sequence* result, splitting **compositional** (F.3 — is the combination safe?) and **temporal** (F.4 — does ordering avoid TOCTOU/poison?) so each oracle can improve independently.

### `_ACTION_OBJECTIVES` — lines 70–77
A coarse, **auditable** map: which objectives each action kind is compatible
with (`block_ip`→"produce defensive action", `patch_code`→"auto-correct insecure
code", `alert_only`/`noop`→"produce findings report"). This is the deterministic
floor for action alignment.

### `__init__` — lines 81–91
Stores the allowed objectives, authenticated sources, trusted destinations, and
the optional `ha_judge`. The comment is the key invariant: **H_a can only tighten,
never loosen** the deterministic floor.

### `check(action, objective, inputs, context)` — lines 93–159
Evaluates the four properties on a final `Action`:
1. **Task alignment (97–100):** objective ∈ allowed set.
2. **Action alignment (102–120):** static map is the floor (`static_action_ok`); if it passes *and* an H_a judge exists, the judge is consulted with a context (target/destination) and can flip `action_ok` to False — but never to True if the static map said no.
3. **Source authorization (122–137):** a *privileged* action (`patch_code`/`isolate_node`/`block_ip`) requires at least one authenticated input. External inputs are fine as *data*, but cannot *drive* a privileged action.
4. **Data isolation (139–149):** the action's destination must be in the trusted set (or a recognized internal sink).
- 151–159 — `allowed = all four`; the reason concatenates every failure (or "all four properties satisfied").

### `check_step(step, objective, inputs, decision_summary)` — lines 165–236
The "new step shape" check used by the executor per tool call. Differences from
`check`:
- **Privilege is read from the step** (`side_effect == destructive` or
  `requires_authorization`), not a hard-coded kind list (209).
- The H_a judge gets the **full step context** — tool, rule-id, side-effect,
  description, and the decision's threat summary (197–200) — so it reasons with
  the real threat picture, not a thin stub.
- Data isolation only flags an explicit untrusted `destination` param (genuine
  external egress is caught at the trajectory level).

### `check_trajectory(steps, inputs)` — lines 242–331
Evaluates the **sequence** for problems no single step can see. It duck-types the
steps (no hard import, so the guard stays a leaf module).
- **F.3 compositional (264–298):**
  - (a) **Exfil chain (267–281):** a sensitive read (`secrets.*`/`kb.lookup_cve`/`observe.log_tail`) *before* an external egress (`notify.webhook`/`email`) → flag, even though each step is individually allowed.
  - (b) **Destructive without forensics (283–290):** a destructive step with no `runtime.snapshot`/observe step in the plan.
  - (c) **Destructive without notify (291–296):** a state change with no human in the loop.
- **F.4 temporal (300–324):**
  - (a) **TOCTOU (305–312):** a contain/eradicate step that checks a precondition but never re-verifies (no `post`).
  - (b) **Memory poisoning (314–322):** a destructive action in a plan influenced by a `memory`-sourced input.
- 326–331 — `allowed = compositional_ok and temporal_ok`, with the full violation list.

---

## 4. Edge cases, gotchas & design decisions

- **H_a only tightens.** `action_ok = static_map_ok AND ha_judge_ok` — the probabilistic judge can refuse, never approve something the static floor rejected. This is the central safety guarantee for letting an LLM into the loop.
- **Three granularities, three oracles.** Single action (`check`), single step (`check_step`), and whole trajectory (`check_trajectory`) — P1 stresses that contextual security is *compositional and temporal*, so per-step checks alone are insufficient.
- **Privilege is data-driven in `check_step`.** Reading it from the step's declared `side_effect`/`requires_authorization` means a new destructive tool is automatically gated without editing the guard.
- **Exfil/forensics/notify composition rules** encode incident-response governance: you can't read-then-egress, can't destroy without a snapshot, can't change state with nobody notified.
- **Memory channel is guarded too.** A destructive action influenced by a `memory`-tagged input is flagged — closing the P1/P2 memory-poisoning path.
- **Every check is named and auditable.** The supervisor can read `_ACTION_OBJECTIVES` and each property's code directly; nothing is hidden in a model.
