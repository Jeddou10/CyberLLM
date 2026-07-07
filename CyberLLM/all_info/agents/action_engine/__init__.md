# `agents/action_engine/__init__.py` — the action-engine package surface

`[← back to all_info index](../../README.md)`

---

## 1. Purpose & place in the system

This is the package initializer for `agents/action_engine/`. It re-exports the
engine's public API so callers (mainly `pipeline.py`) can import everything from
one place: `from agents.action_engine import ActionGenerator, GuardAdapter,
legacy_kind`, etc. Its docstring states the central guarantee in one line:
**everything is dry-run by default**; opt into real side effects with
`dry_run=False`.

---

## 2. Imports / re-exports — lines 19–34

| line | re-exports | from |
|------|-----------|------|
| 19 | `ActionExecutor, GuardAdapter, passthrough_guard` | `.executor` |
| 20 | `Action, ActionGenerator, legacy_kind` | `.generator` |
| 21 | `MCPRegistry, MCPSchemaField, MCPTool` | `.mcp_registry` |
| 22 | `default_toolset` | `.mcp_tools` |
| 23 | `PLAYBOOKS, Playbook, StepTemplate, build_plan` | `.playbooks` |
| 24–34 | the `types` shapes (`ActionPlan, ActionReport, ActionStep, Condition, PlanStatus, SideEffect, StepKind, StepStatus, ToolResult`) | `.types` |

---

## 3. Walkthrough

There's no logic — only imports and an `__all__` list (36–60) that declares the
package's public names. `__all__` controls what `from agents.action_engine
import *` brings in and documents the intended public surface (so `_legacy_kind`,
internal helpers, etc., stay private).

The grouping in the docstring is a useful mental map of the subsystem:
- `ActionGenerator` — the agent the pipeline calls.
- `Action` — the legacy shape kept for the `SecurityGuard`.
- `ActionPlan`/`ActionStep`/`ActionReport` — typed structures written to the run log.
- `MCPRegistry`/`MCPTool`/`default_toolset` — the typed tool layer.
- `build_plan` — the pure plan builder (handy in unit tests).

---

## 4. Edge cases, gotchas & design decisions

- **One import path.** Re-exporting here means the rest of the codebase doesn't reach into submodules, so internal file reorganizations won't break callers.
- **`__all__` is curated.** Only the intended-public names are listed, keeping helpers like `_legacy_kind` and `_LEGACY_KIND_MAP` out of the package's advertised API.
- **The docstring is the contract.** "Everything is dry-run by default" is stated right at the package entrance — the single most important safety fact about the subsystem.
