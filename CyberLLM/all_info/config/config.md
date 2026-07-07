# `config.yaml` — every tunable, explained

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

`config.yaml` is the **single control panel**. `pipeline.load_config()` reads it
once; agents, the guard, memory, the action engine, and the example runner all
read their settings from it. Changing behavior almost never needs a code edit —
it needs a config edit. Below, every section is explained key by key.

---

## 2. Sections

### `llm_configs` — lines 14–24  (P4 LLM-Config block)
Named LLM profiles agents reference by name. `default` and `reasoning` both use
`provider: azure` with `model: gpt-4o` (the model doubles as the Azure deployment
name unless `AZURE_OPENAI_DEPLOYMENT` is set). `temperature`/`max_tokens` apply
because gpt-4o is a *standard* model. Until Azure creds are filled in, the client
transparently falls back to the stub. `reasoning` uses `temperature: 0.0` and a
larger budget (used by the decision agent + H_a judge).

### `scanners` — lines 34–39
- `external_static: true` — also run bandit/semgrep (regex still wins on dupes).
- `use_llm: true` — run the LLM refinement pass; the web UI overrides this
  per-request so the stub's canned findings never appear on real code.

### `agent_configs` — lines 42–75  (P4 schema)
One entry per agent, giving each its `llm` profile and a one-line `objective`
string. The objective is what the **security guard checks against** (it must be in
`security.allowed_objectives`). Defense agents (scanner/log/deployment/decision/
action) and attack agents (discovery/exploiters/orchestrator/generator) are all
declared here. The two "reasoning" consumers are `decision_agent` and
`attack_orchestrator`.

### `security` — lines 78–93  (P1 properties)
- `allowed_objectives` (set **O**) — the only objectives the guard's task-alignment check accepts.
- `authenticated_sources` (**S_auth**) — sources whose inputs are trusted (`user`, `rules_engine`, `mcp_tool`).
- `trusted_destinations` — destinations the data-isolation check accepts.

### `response_tiers` — lines 96–99  (P5)
Confidence thresholds for `soft` (0.40), `moderate` (0.65), `hard` (0.85) — the
ladder the decision agent and escalation policy use.

### `memory` — lines 106–113  (P5 learning + P1/P2 poison defense)
`enabled`, the `db_file`, `recall_k`, the `writer_identity` (must be an
authenticated source), `reject_unverified` (drop tampered/unauthenticated rows on
read), and the signing key: `signing_key_env` (export in production) with a
clearly-labelled insecure `dev_signing_key` fallback.

### `guard` — lines 116–119  (P1 oracles / roadmap F)
`ha_judge_enabled` (the separate H_a LLM call), `per_step_enabled` (check every
action step, not just the final action), and `max_prompt_tokens` (warn above
this).

### `action_engine` — lines 122–126
`dry_run: true` (never run a destructive command unless false — and
`CYBERLLM_FORCE_DRY_RUN` can force it on regardless), `work_dir`,
`max_replan_rounds: 2` (the adaptive loop), `llm_tool_selection: true` (let the
LLM propose extra, validated, guarded tools).

### `attack` — lines 132–148  (ethics/scope)
`allow_all_in_dev: true` (for offline demos — **turn off** anywhere that can reach
real systems), the `allowed_scenarios` list, and `authorized_targets` (including a
`*` wildcard that the comment says to remove outside the demo).

### `paths` — lines 151–155
`rules_dir`, `examples_dir` (the default example set), `memory_dir`, `prompts_dir`.

### `defaults` — lines 158–161
The `log`/`deployment` used in single-run mode when only `--code` is given.

### `example_sets` — lines 167–218
Named scenario batches (`test_blind`, `juliet`, `small`, `medium`, `large`) for
`--example <kind>`. Each scenario lists a name, a code path (file *or* directory —
a directory scans all code files inside), the paired log, the paired deployment,
and optionally an attack `scenario` file.

---

## 3. Edge cases, gotchas & design decisions
- **Config over code.** Provider choice, which agent uses which model, the guard's
  allowed objectives, the response thresholds, dry-run — all live here. This is
  what makes the system "a general algorithm" rather than a hard-coded demo.
- **The objective strings are security-critical.** Each agent's `objective` must
  appear in `security.allowed_objectives`, or the guard's task-alignment check
  fails. They are not just documentation.
- **Two dev escape hatches to remember to disable in production:** the `*`
  wildcard in `attack.authorized_targets` and `attack.allow_all_in_dev`, plus
  setting a real `CYBERLLM_MEMORY_KEY` instead of the dev signing key.
- **Windows-style paths work.** Some paths use backslashes (`examples\small`);
  `pipeline._norm` normalizes them, so config is portable.
