# `agents/action_engine/types.py` — the action-engine data model

`[← back to all_info index](../../README.md)`

---

## 1. Purpose & place in the system

This file defines **the shapes** the action engine works with. A defense
"action" is not a single canned command — it is a **structured, multi-step plan**
(`ActionPlan` of `ActionStep`s) run against a typed MCP tool registry, with
pre/post conditions, rollback, and per-step audit. Execution attaches a separate
`ActionReport` capturing the runtime outcome. Everything here is consumed by
`playbooks.py` (which builds plans), `generator.py` (which orchestrates), and
`executor.py` (which runs them).

Key design notes from the docstring: every step carries enough context for an
external reviewer to approve it; an `ActionPlan` is conceptually immutable once
built; `Condition` is the unit of pre/post verification, evaluated by calling an
MCP tool (so "did it work?" is itself auditable).

---

## 2. Imports — lines 20–26

| line | import | why |
|------|--------|-----|
| 22 | `dataclass, field, asdict` | Define the data shapes and serialize them. |
| 23 | `datetime` | Timestamps on steps/plans/reports. |
| 24 | `Enum` | Type-safe enumerations for side-effect/kind/status. |
| 25 | `Any` | Loose typing. |
| 26 | `uuid4` | Unique ids for steps. |

---

## 3. Walkthrough

### `SideEffect` — lines 33–37
`READ | WRITE | DESTRUCTIVE`. **Why:** drives the dry-run/authorization gate —
a destructive tool needs explicit authorization in live mode (see
`mcp_registry`).

### `StepKind` + `_KIND_ORDER` + `kind_priority` — lines 40–61
The incident-response phases: `CONTAIN, ERADICATE, RECOVER, NOTIFY, OBSERVE,
AUDIT`. `_KIND_ORDER` (50–57) gives the **execution order**, and notably
**OBSERVE is ranked right after CONTAIN** (so you measure immediately after
stopping the bleeding, before eradicating). `kind_priority` is the sort key the
generator uses to keep steps in the right order even after the LLM adds some.

### `StepStatus` — lines 64–72
The lifecycle of one step: `PENDING → RUNNING → {COMPLETED | FAILED | SKIPPED |
REFUSED | VERIFY_FAILED | ROLLED_BACK}`. `REFUSED` specifically means the guard
rejected it (distinct from a tool failure).

### `PlanStatus` — lines 75–81
The overall plan result: `NOT_STARTED, IN_PROGRESS, COMPLETED, PARTIAL,
FAILED, REFUSED`. `PARTIAL` ("partial_success") is what lets the re-planning loop
treat a half-done plan as acceptable.

### `_SEVERITY_RANK` + `severity_rank` — lines 84–88
Map `low/medium/high/critical` → `0..3` so a step can declare a `severity_min`
gate ("only run for findings at least this severe").

### `Condition` — lines 95–108
A pre/post check evaluated **by calling an MCP tool**. `expected_status` is
matched against the tool's status; `expected_payload` keys/values must appear in
the tool's output. If both are `None`, the condition just checks the tool call
succeeded. **Why this design:** verification reuses the same audited tool layer
as the actions themselves — "did the fix hold?" is a tool call, not an
unverifiable assertion.

### `ActionStep` — lines 115–149
The richest shape in the file. Static fields (117–131): `rule_id`, `kind`,
`tool`, `params`, `description`, plus **execution-quality metadata** —
`side_effect`, `severity_min` (gate), `timeout_s`, `retries`, `pre`/`post`
conditions, `rollback_steps` (other `ActionStep`s to undo this one), and
`requires_authorization`. Identity + mutable runtime state (133–141): a UUID
`step_id`, `status`, `attempts`, timestamps, `output`, `error`, `refusal_reason`.
`to_dict` (143–149) serializes it, hand-converting datetimes to ISO strings
(asdict already turns enums into their `.value`).

### `ActionPlan` — lines 152–174
`plan_id`, `decision_summary`, `blast_radius` (local→fleet), `asset_categories`,
the `steps`, and a `created_at`. `estimated_duration_s` (161–163) sums the step
timeouts. `to_dict` (165–174) produces the JSON the run logger writes.

### `ActionReport` — lines 177–225
Wraps a plan with runtime outcome: `started_at/finished_at`, a `PlanStatus`, a
`summary`, and an `audit_log`. The `@property` tallies (186–205) count steps by
status (completed/failed/refused/rolled_back/skipped) — computed on demand from
the steps, so they're always consistent. `to_dict` (207–225) bundles the status,
tallies, the full plan, and the audit log.

### `ToolResult` — lines 232–243
The **standard envelope every MCP tool returns**: `status` (`ok | failed |
would-execute | skipped`), `tool`, `payload`, `error`, `invoked_real_tool` (did
a real binary run, or was it dry-run/stub?), and `elapsed_ms`. This uniform
shape is why the executor and registry can treat all tools identically.

---

## 4. Edge cases, gotchas & design decisions

- **Enums subclass `str`.** `class SideEffect(str, Enum)` means `asdict` emits the plain string value, so JSON serialization "just works" without custom encoders.
- **OBSERVE before ERADICATE.** The `_KIND_ORDER` deliberately measures right after containment — you confirm the threat is contained before you start removing root causes.
- **`would-execute` is a success.** Dry-run returns `would-execute`, which the executor treats as OK — so a dry-run plan "completes" and the pipeline can reason about it without anything actually happening.
- **Plans are immutable in spirit, reports are mutable.** The plan describes intent; the report records what occurred. Keeping them separate means the original intent is preserved even after a messy execution.
- **Conditions are tool calls.** This is the subtle, powerful choice: verification is auditable and uses the same registry, so there's no "trust me, it worked" gap.
