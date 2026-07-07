# `agents/action_generator.py` — back-compat shim to the action engine

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

A **thin compatibility shim**. The real action engine lives in the
`action_engine/` package, but `pipeline.py` (and older code) imports
`ActionGenerator` and `Action` from `agents.action_generator`. This file
preserves that import path by re-exporting both names from the package, so the
pipeline's call site never had to change when the engine was refactored.

---

## 2. Imports — line 13

| line | import | why |
|------|--------|-----|
| 13 | `from .action_engine import Action, ActionGenerator` | Re-export the two public names the pipeline expects. `# noqa: F401` because they're imported only to be re-exported. |

---

## 3. Walkthrough

There is no logic. Line 13 imports `Action` and `ActionGenerator` from the
`action_engine` package; line 15 declares `__all__ = ["Action",
"ActionGenerator"]` so `from agents.action_generator import *` brings exactly
those two. The docstring explains the indirection: the engine is a planner +
playbook catalogue + MCP tool registry with pre/post verification and rollback —
see [`agents/action_engine/generator.md`](action_engine/generator.md).

---

## 4. Edge cases, gotchas & design decisions

- **Why keep this file at all?** Stable import path. The engine grew from a
  proof-of-concept tier-to-action map into a full subsystem; this shim meant the
  refactor was invisible to the pipeline.
- **No behavior here.** Anything you want to understand about action generation
  is in the `action_engine` package docs — this is pure re-export.
