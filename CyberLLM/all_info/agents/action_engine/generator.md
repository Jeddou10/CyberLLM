# `agents/action_engine/generator.py` — the `ActionGenerator` (planner + LLM tool selection)

`[← back to all_info index](../../README.md)`

---

## 1. Purpose & place in the system

`ActionGenerator` is the agent `pipeline.py` calls to turn a `Decision` into an
executed response. It keeps the old `generate(decision, vulnerable_code) ->
Action` signature for backward compatibility, but internally it now: builds a
typed `ActionPlan` from playbooks, optionally lets the LLM **add** validated/
guarded steps, runs the plan through the `ActionExecutor`, and returns a legacy
`Action` with the full `ActionReport` attached. Dry-run by default.

Flow: `Decision → build_plan → (LLM-selected extra steps) → ActionExecutor →
ActionReport → wrapped as Action`.

---

## 2. Imports — lines 19–34

| line | import | why |
|------|--------|-----|
| 21 | `dataclass, field` | The legacy `Action` shape. |
| 22 | `Any` | Loose typing. |
| 24 | `BaseAgent, Finding` | It *is* an agent (gets `call_llm`, `template`, `data`). |
| 25 | `LLMClient` | The LLM for tool selection. |
| 27–30 | executor / registry / default_toolset / build_plan | The pieces it orchestrates. |
| 31–34 | types | Plan/step/status/kind enums + `kind_priority`. |

---

## 3. Walkthrough

### `Action` (legacy shape) — lines 41–50
A dataclass: `kind`, `target`, `parameters`, `rationale`,
`originating_decision`, plus new optional `plan_id`/`report`. **Why keep it:**
the `SecurityGuard` and `pipeline.py` were written against this shape; preserving
it means the richer engine slots in without rewriting the guard.

### `class ActionGenerator(BaseAgent)` — lines 57–255
- **`__init__` (69–81):** read `dry_run`/`work_dir` from config, store the `on_tool` announce callback, build (or accept) the MCP registry, take an optional per-step `guard`, and create the `ActionExecutor`. Tracks `last_plan`/`last_report` so the run logger can read them.
- **`TOOL_SELECT_PROMPT` (91–104):** the prompt that exposes the tool catalogue to the LLM and lets it *propose extra steps*. Crucial framing: the deterministic playbook is the **floor**; the LLM may only **ADD** tools (preferably read-only/observe/verify), and is told *not* to invent destructive actions. Every proposed tool is still schema-validated and guarded.
- **`plan(decision, ctx)` (106–107):** delegate to `build_plan` (in `playbooks.py`).
- **`execute(plan)` (109–112):** run the plan, store `last_plan`/`last_report`.
- **`generate(decision, vulnerable_code)` (114–127):** the public entry point. Build the default context (optionally injecting the vulnerable code so the patch tool has it), build the plan, and — if `llm_tool_selection` is enabled — append LLM-selected steps and **re-sort by `kind_priority`** so the added steps land in the right phase. Then execute and wrap as a legacy `Action`.

### `_llm_select_tools(decision)` — lines 133–180
The "LLM as a first-class, but bounded, participant" feature.
- 138–141 — build the human-readable tool catalogue from the registry schemas.
- 142–149 — fill the prompt template with the decision summary/tier/assets/findings + catalogue.
- 150–154 — call the LLM and parse picks; **best-effort** — any exception returns `[]` (the playbook still stands).
- 156–179 — for each pick, **defense in depth:** skip it unless it names a real registered tool (159), has dict params (162), and **passes that tool's schema validation** (165). Only then is it turned into an `ActionStep` (with the tool's real side-effect and authorization flag). The executor *still* runs the per-step guard on it — so the LLM cannot bypass safety; it can only *suggest within the rails*.

### `_parse_tool_picks(text)` — lines 182–192
Strip ``` ```json ``` fences, parse JSON, and return the `tools` list (only dict
items). Returns `[]` on any parse failure — robust to a chatty model.

### Internals — lines 198–255
- `_build_default_registry` (198–202) — a registry wired with `default_toolset()` and the `on_call` announce hook.
- `_default_ctx` (204–213) — the substitution context for playbooks: repo path, workspace, the at-risk secret id, vehicle id, log path, default file.
- `_wrap_as_action` (215–246) — collapse the plan back to the legacy `Action`: pick a **primary** step (first CONTAIN, else first ERADICATE, else first), derive `kind` via the legacy map and `target` from the most salient param. A plan with no steps becomes a `noop` Action (222–231) — important so "nothing to do" is representable.
- `_primary_step` (248–255) — prefer a completed/running/pending step, else the first step.

### Legacy kind mapping — lines 262–295
`_LEGACY_KIND_MAP` translates each MCP tool name into the old `kind` vocabulary
the `SecurityGuard` understands (`block_ip`, `isolate_node`, `patch_code`,
`alert_only`, `rate_limit`). Note the deliberate choices: `secrets.rotate` →
`patch_code` (a privileged change), `secrets.revoke` → `block_ip`. `legacy_kind`
(290–294) is the public alias used by the pipeline's per-step guard adapter.

---

## 4. Edge cases, gotchas & design decisions

- **The LLM can only *add*, never *replace* or *escalate*.** The playbook is the deterministic floor; LLM picks are schema-validated, then guard-checked at execution. This is the central safety argument for letting a model touch the action plan at all.
- **Best-effort LLM selection.** A parse error or LLM failure silently yields no extra steps — the deterministic plan still runs, so the feature can never break a response.
- **Re-sort after adding steps.** Without the `kind_priority` re-sort, an LLM-added CONTAIN step could end up after ERADICATE — the sort keeps phases correct.
- **Back-compat by design.** Returning a legacy `Action` (with the report attached) means the guard, the pipeline, and the run logger didn't need rewriting when the engine grew up.
- **`noop` is a real outcome.** Some decisions need no action; representing that explicitly is what lets the re-planning loop treat "no steps" as success.
