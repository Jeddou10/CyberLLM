# `agents/action_engine/executor.py` — the `ActionExecutor`

`[← back to all_info index](../../README.md)`

---

## 1. Purpose & place in the system

`ActionExecutor` **runs** an `ActionPlan` step by step against the MCP registry.
For each step it: evaluates preconditions, runs the **per-step security check**
(so P1's properties apply to *every* tool call, not just the final action),
invokes the tool with retry/back-off, evaluates postconditions, and on failure
attempts **rollback** (LIFO). It produces a structured `ActionReport`. Crucially,
it **never overrides the registry's dry-run flag** — it only sequences and
verifies; the registry alone decides whether a real tool runs.

Created by `generator.py`; uses `mcp_registry.py` and the `types.py` shapes.

---

## 2. Imports — lines 20–36

| line | import | why |
|------|--------|-----|
| 22 | `dataclass` | The `GuardAdapter`. |
| 23 | `datetime` | Step/plan timestamps. |
| 24 | `Callable` | Type the guard function. |
| 26 | `MCPRegistry` | The tool layer it drives. |
| 27–36 | types | Plan/step/condition/status enums + `ToolResult`. |

---

## 3. Walkthrough

### `GuardAdapter` + `passthrough_guard` — lines 43–54
A tiny pluggable hook: `GuardAdapter.fn(step) -> (allowed, reason)`. The pipeline
wires this to the real `SecurityGuard.check_step` (via `build_step_guard`).
`passthrough_guard` (53–54) is the no-op default ("no guard configured") used in
tests or when per-step checking is disabled.

### `class ActionExecutor.__init__` — lines 62–68
Stores the registry, the guard (defaulting to passthrough), and `max_retries`.

### `execute(plan)` — lines 74–136  (the main loop)
Creates an `IN_PROGRESS` report and a `rollback_stack`, then for each step:
- **Pre (82–87):** evaluate preconditions; if any fail, the step is **SKIPPED** (not failed) and the loop continues — a step whose preconditions aren't met simply isn't applicable.
- **Guard (89–101):** run `self.guard.check(step)`. If refused, mark **REFUSED** with the reason. **Critical rule (98–100):** if a *CONTAIN* step is refused, stop the whole plan (`failed_hard`, `break`) — you cannot safely eradicate if you couldn't contain. Non-containment refusals just skip that step.
- **Execute (103–116):** `_invoke_with_retry`. On hard **FAILED**, if the step was CONTAIN/ERADICATE, **rollback** the completed steps and stop; NOTIFY/OBSERVE failures are recoverable and just continue.
- **Post (118–128):** evaluate postconditions; failure → **VERIFY_FAILED**, and for CONTAIN/ERADICATE it rolls back (including this step) and stops.
- **Success (130–131):** push the step onto the rollback stack (LIFO) and audit "completed."

At the end (133–135) it stamps the finish time, computes the final status, and
builds the summary.

### `_invoke_with_retry(step)` — lines 142–163
Runs the tool up to `1 + step.retries` times. It records attempts/timestamps,
captures the result's payload plus `_status`/`_real` flags, and on `ok`/
`would-execute` marks **COMPLETED** and returns. On a retryable failure it
sleeps `0.2 × (i+1)` (linear back-off) and tries again; exhausting attempts marks
**FAILED**. Note `would-execute` (dry-run) counts as success — so a dry-run plan
completes cleanly.

### `_eval_conditions(...)` — lines 165–188
Evaluate a list of `Condition`s by calling their `check_tool`. **Graceful
default (168–174):** if the condition's tool isn't registered, it's treated as a
**PASS** (with an audit note) rather than blocking the plan. Otherwise it calls
the tool and checks the match; the first failing condition returns `False`.

### `_condition_matches(c, result)` — lines 190–198
A condition passes when: `expected_status` matches (if set), every
`expected_payload` key/value is present in the result payload (if set), and the
result status is `ok`/`would-execute`.

### `_rollback(completed, report)` — lines 200–214
For each completed step (LIFO), run its `rollback_steps` via the registry,
record each rollback's status in the audit log, and mark the step
**ROLLED_BACK**. This is how a failed containment/eradication is safely undone.

### Helpers — lines 216–251
- `_audit(msg, step)` (216–225) — a compact audit record per step event.
- `_final_status(plan, failed_hard)` (227–238) — `FAILED` if a hard failure occurred; else `COMPLETED` if all steps completed, `PARTIAL` if some did, `REFUSED` if any were refused, else `FAILED`.
- `_summary(plan, report)` (240–251) — a one-line human tally (`N completed · M failed · …`) plus blast radius and assets.

---

## 4. Edge cases, gotchas & design decisions

- **The executor cannot make a tool "real."** It never touches the registry's `dry_run`; safety is decided in exactly one place (the registry). The executor's job is sequencing + verification.
- **CONTAIN is privileged.** A refused or failed containment step aborts the whole plan — the engine refuses to proceed to eradication/recovery if it couldn't stop the immediate damage. This is an explicit incident-response principle.
- **Skip vs fail vs refuse are distinct.** Pre-condition not met → SKIPPED; guard says no → REFUSED; tool errored → FAILED; post-condition failed → VERIFY_FAILED. Each is audited separately, so the report tells a precise story.
- **Rollback is LIFO and best-effort.** Completed steps are undone in reverse order; each rollback's status is itself audited.
- **Missing condition tools pass.** Treating an unregistered check tool as PASS keeps a partial toolset from blocking the whole plan — verification is opportunistic, not mandatory.
- **Back-off is bounded and linear.** Retries are few and short, so a flaky tool slows the plan slightly instead of hanging it.
