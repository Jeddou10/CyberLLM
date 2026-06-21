# Chapter 5 — Code reference (every file, class, function)

[◀ Attack pipeline](04_ATTACK_DEEP.md) · [Master index](../DEVELOPER_GUIDE.md) · [Next: Subsystems ▶](06_SUBSYSTEMS.md)

This is the "look up any symbol" chapter. It walks **every module** and
explains **what each class and function does**, in the order you'd meet
them. Use your editor's search (`Ctrl-F`) to jump to a name.

Legend: `cls` = class, `fn` = function/method.

---

## `pipeline.py` — the entry point & orchestrator

The spine: it wires agents together, runs the adaptive loop, handles batch
mode, and parses the CLI.

- `fn load_config()` → reads `config.yaml` into a dict.
- `fn load_rules(cfg)` → reads every `rules/*.yaml`, **merges by family**
  (`code_rules`, `log_rules`, `topology_rules`, `attack_rules`, …) into one
  dict.
- `fn rules_snippet(rules, family)` → a compact one-line-per-rule text block
  for putting rules into a prompt.
- `fn build_llms(cfg)` → `{name: LLMClient}` — one client per `llm_configs`
  entry (`default`, `reasoning`).
- `fn build_memory(cfg)` → a `MemoryStore` (or `None` if disabled); resolves
  the DB path, signing key (from `memory.signing_key_env`), authenticated
  sources, and the reject-unverified flag.
- `fn _writer_identity(cfg)` → which source name memory writes are tagged
  with (default `rules_engine`; must be authenticated).
- `dict _STEP_KIND_OBJECTIVE` → maps a legacy step kind to the objective the
  guard checks it against (`patch_code`→"auto-correct insecure code",
  `alert_only`/`noop`→"produce findings report").
- `fn build_step_guard(security_guard, inputs, decision_summary)` → returns a
  `GuardAdapter` whose `check(step)` calls `SecurityGuard.check_step` with
  the decision's threat summary as context. **This is the per-step guard
  the executor runs on every tool call (C.4).**
- `fn _norm(p)` / `fn _rel_or_abs(p)` → path helpers (resolve relative to the
  project root; render nicely for records/logs).
- `fn _collect_code_files(target)` → expands a file *or* a directory into the
  list of code files (`.py/.c/.cpp/.h`, skipping `__pycache__`).
- `fn _read_scenario(spec)` → resolves the attack scenario (file path,
  literal string, or default).
- `fn _rule_ids(findings)` → a sorted, de-duplicated rule-id string (for
  logging).
- `fn _llm_banner(llms)` → the one-line "which client/model did we get"
  banner; flags `(fallback→stub)` when a provider downgraded to the stub.
- **`fn run_defense_pipeline(...)`** → the defense flow narrated in
  [chapter 3](03_DEFENSE_DEEP.md): setup → inputs → 3 scanners →
  **adaptive loop** (decision → action → guard, escalate on failure) →
  persist. Returns the record dict.
- `fn _record_incident(memory, cfg, *, mode, scenario, rule_ids,
  asset_categories, tier, confidence, action_kind, guard_allowed,
  plan_status, remediation_ok)` → builds and signs an `Incident` and records
  it; never raises (returns a bool). Carries the **outcome** fields.
- **`fn run_attack_pipeline(...)`** → the attack flow narrated in
  [chapter 4](04_ATTACK_DEEP.md).
- `fn _scenarios_for(kind, cfg)` → the list of scenario dicts for an
  `--example` set (`small`/`medium`/`large`/`all`/`juliet`).
- `fn run_example_batch(kind, mode, cfg, rules, …, verbose, debug)` → runs
  every scenario in a set (defense and/or attack), collects rows, and prints
  the **DEFENSE/ATTACK summary** tables to **stdout** (the tests look for
  these). Threads `verbose`/`debug` into each run.
- `fn _infer_default_example(cfg)` → picks a default example set from
  `paths.examples_dir`.
- `fn main(argv)` → argparse: `--mode`, `--example`, `--code/--log/
  --deployment/--scenario`, `--authorize-target`, `-v/--verbose`,
  `-q/--quiet`. Dispatches to batch or single-run; prints the record JSON in
  single-run mode.

---

## `llm_client.py` — the LLM provider layer

- `cls LLMResponse` → `text` + optional `raw` (the provider's full response).
- `fn _warn_once(key, message)` → emit a `RuntimeWarning` once per key (so a
  batch run doesn't spam the same fallback warning).
- `fn _load_dotenv_once()` → a tiny zero-dependency `.env` parser; sets only
  env keys not already present (a real shell value always wins).
- `set _PLACEHOLDER_MARKERS` / `fn _looks_like_placeholder(value)` → detects
  a not-yet-filled credential (`replace`, `your_token`, `<`, …) so the client
  falls back to the stub instead of trying a doomed call.
- `cls LLMClient` — base + factory:
  - `staticmethod create(cfg)` → the dispatcher: loads `.env`, honours
    `CYBERLLM_FORCE_STUB`, then returns the right client for
    `cfg["provider"]`, falling back to the stub on missing/placeholder
    credentials.
  - `fn complete(prompt, system=None)` → abstract; subclasses implement.
- `cls StubLLM` → the deterministic offline model. `complete()` keyword-
  matches the prompt and returns canned JSON for: the **H_a judge**, the
  **decision agent**, the three **scanners**, and a **fix** sentence; else
  `"ACK: …"`. *This is why everything runs offline.*
- `cls GitHubModelsLLM` → GitHub Models (OpenAI-compatible). `_is_reasoning_model()`
  detects gpt-5/o-series and switches to `max_completion_tokens` + no
  `temperature`; `_build_body()` builds the request; `complete()` POSTs with
  a 429 retry/back-off.
- `cls AzureOpenAILLM` → **the default**. `_resolved()` reads endpoint /
  deployment / api-version / key from cfg-or-env; `_url()` builds the Azure
  URL (`/openai/deployments/<name>/chat/completions?api-version=…`);
  `complete()` POSTs with the `api-key` header + 429 retry.
- `cls OpenAILLM` / `cls AnthropicLLM` / `cls OllamaLLM` → the other
  providers (use their SDKs / localhost).

(Full LLM-layer deep-dive in [chapter 6](06_SUBSYSTEMS.md#61-the-llm-layer).)

---

## `agents/base_agent.py` — the agent contract

- `set ALLOWED_TRUST_LEVELS` = `{authenticated, external, tool, memory}`.
- `cls ProvenanceError(ValueError)` → raised for a missing/invalid provenance
  tag.
- `cls Finding` → the universal finding record (see [chapter 2](02_ARCHITECTURE.md)).
- `cls Input` → a provenance-tagged artefact; `__post_init__` enforces a
  non-empty `source` and a valid `trust_level`.
- `cls AgentResult` → what a scanner returns (`agent_id, objective,
  findings, raw_llm_text`).
- `cls BaseAgent`:
  - `__init__` → stores `agent_id, cfg, llm, objective`, a `data` dict, a
    `trusted_sources` set + `delegated_from` (for F.5 delegation), a
    `TokenBudget`, and the run-log hooks (`last_prompt`, `last_response`,
    `last_static_findings`).
  - `fn call_llm(prompt)` → the single LLM entry point: records the prompt,
    counts its tokens (warns if over budget), calls `self.llm.complete`,
    records the response.
  - `fn template(prompt)` → substitutes `[key]` → `str(self.data[key])`.
  - `fn _parse_findings(text)` → robustly reads `{"findings":[…]}` from an
    LLM reply (tolerates markdown fences).
  - `fn delegate(child_cls, child_cfg, llm, grant_sources)` → spawn a child
    agent that **inherits the objective but NOT the trusted-source set**
    (paper 1 F.5: authority can't be laundered through delegation).
  - `fn run(inputs)` → abstract; subclasses implement.

---

## The three defense scanners

Each follows the identical static→LLM→merge shape (see [chapter 3](03_DEFENSE_DEEP.md)).

- `agents/source_code_scanner.py` — `cls SourceCodeScannerAgent`: `run()`
  filters `.py/.c/.cpp` inputs, runs `scan_code_static`, then the LLM, then
  merges. `staticmethod load_example(path)` → `Input(external)`.
- `agents/log_analyzer.py` — `cls LogAnalyzerAgent`: same with
  `scan_log_static` over `.log/.txt`.
- `agents/deployment_scanner.py` — `cls DeploymentScannerAgent`: same with
  `scan_deployment_static` over `.yaml`; `load_example` → `Input(authenticated)`;
  also `staticmethod parse_actor_graph(yaml_text)` (the `{actors, datasources,
  edges}` dict paper-2 consumers use).

---

## `agents/decision_agent.py` — the verdict

- `list ASSET_CATEGORIES` → the paper-2 human-centric taxonomy.
- `cls Decision` → the verdict record.
- `cls DecisionAgent`:
  - `__init__(…, memory=None)` → keeps the `MemoryStore`, the `recall_k`, and
    exposes `consulted_memory` + `memory_recommendation` for the run-log.
  - `fn run(scanner_results, scenario_name=None, feedback=None)` → aggregate
    findings → consult memory (`recall_similar` + `recommend`) → LLM →
    `_parse_decision` → apply `_apply_feedback_escalation` then
    `_apply_memory_recommendation` → tag findings with the top asset.
  - `fn _render_recommendation()` / `_render_feedback(feedback)` → format the
    memory + feedback blocks for the prompt.
  - `fn _apply_feedback_escalation(decision, feedback)` → bump the tier above
    a tier that failed in the previous round (the re-planning policy).
  - `fn _apply_memory_recommendation(decision)` → adopt a stronger
    *worked-before* tier (escalate-only).
  - `fn _parse_decision(text, findings)` → read the `Decision` JSON
    (graceful fallback to `tier="none"` on parse failure).
- `fn _severity_rank(sev)` / `fn _tier_index(tier)` / `fn _escalate_tier(tier)`
  → the ordering helpers (`none<soft<moderate<hard`).

---

## `agents/security_guard.py` — paper-1 enforcement

- `cls GuardVerdict` / `cls StepVerdict` / `cls TrajectoryVerdict` → the three
  verdict shapes.
- `dict _ACTION_OBJECTIVES` → the coarse "action kind ↔ compatible objective"
  map (the deterministic floor for action-alignment).
- `cls SecurityGuard`:
  - `__init__(allowed_objectives, authenticated_sources, trusted_destinations,
    ha_judge=None)` → the policy sets + the optional H_a judge.
  - `fn check(action, objective, inputs, context="")` → the **four
    properties** on the final aggregate action: task / action (static map
    AND H_a) / source / data. Returns `GuardVerdict`.
  - `fn check_step(step, objective, inputs, decision_summary="")` → the
    **per-step** check on the real `ActionStep`: privilege from the step's
    `side_effect`/`requires_authorization`; H_a fed the step's full context.
    Returns `StepVerdict`.
  - `fn check_trajectory(steps, inputs)` → the **sequence** check:
    compositional (exfil chain, destructive-without-forensics/notify) +
    temporal (TOCTOU, memory-poisoning). Returns `TrajectoryVerdict`.

(Full guard deep-dive in [chapter 6](06_SUBSYSTEMS.md#63-the-guards-paper-1).)

---

## `agents/ha_judge.py` — the H_a oracle

- `set _PRIVILEGED_KINDS` / `set _REPORT_ONLY_OBJECTIVES` → the heuristic sets.
- `cls HaJudge`:
  - `PROMPT` → asks the model to answer `{"serves": bool, "reason": str}`.
  - `__init__(llm)` → keeps a per-instance **cache** so repeated identical
    (action, objective, context) questions cost one call.
  - `fn judges(action_kind, objective, context="")` → cache-or-call → parse.
  - `staticmethod _parse(text, …)` → read the JSON; fall back to the
    deterministic `_heuristic` if unparseable.
- `fn _heuristic(action_kind, objective, context)` → the deterministic
  stand-in (also what the stub encodes): refuse a privileged action under a
  report-only objective, or a context flagged misaligned/trusted-asset;
  allow otherwise.

---

## `agents/memory_store.py` — signed cross-session memory

- `tuple _SIGNED_FIELDS` → the fields covered by the HMAC signature
  (**includes the outcome fields**).
- `dict _MIGRATION_COLUMNS` → columns added after v1; `_init_schema`
  `ALTER TABLE`s an old DB to add them.
- `cls Incident` → one past outcome; `canonical()` normalises it for signing.
- `cls MemoryAuthError(PermissionError)` → unauthenticated write.
- `fn jaccard(a, b)` → set-overlap similarity in [0,1].
- `cls MemoryStore`:
  - `_init_schema()` → create the table (+ migrate).
  - `_sign(canonical)` / `verify_row(row)` → HMAC sign / verify (and check
    the source is authenticated).
  - `record(incident)` → sign + insert (refuses unauthenticated sources).
  - `_row_to_incident(row, sim)` → DB row → `Incident`.
  - `recall_similar(rule_ids, k, exclude_scenario, mode)` → top-K by Jaccard,
    verified rows only.
  - `recommend(rule_ids, mode, min_similarity, exclude_scenario)` → the most
    similar past incident whose **remediation worked** ("what worked before").
  - `verify_all()` → integrity sweep (poison check).
  - `count()` / `staticmethod render_fewshot(incidents)` → helpers (the
    few-shot now shows each incident's `outcome=worked/…`).

(Full memory deep-dive in [chapter 6](06_SUBSYSTEMS.md#64-the-memory-store).)

---

## `agents/action_engine/` — the response engine

- `types.py` — the data model: `SideEffect`, `StepKind` (+ `kind_priority`),
  `StepStatus`, `PlanStatus`, `severity_rank`, `Condition`, `ActionStep`,
  `ActionPlan`, `ActionReport`, `ToolResult`. (See [chapter 2](02_ARCHITECTURE.md).)
- `mcp_registry.py`:
  - `cls MCPSchemaField` → one parameter's name/type/required/enum/description.
  - `cls MCPTool` → base for every tool: class attrs (`name`, `description`,
    `domain`, `side_effect`, `idempotent`, `requires_authorization`, `schema`,
    `real_binary`); `validate(params)` (schema check), `real_available()`
    (is the CLI installed?), `call(params)` (validate → dry-run or real →
    `ToolResult`), `verify()` (post-condition hook), `_do_call()`/`_dry_run()`
    (subclasses override), `describe()` (catalogue entry).
  - `cls MCPRegistry` → `register`/`register_many`/`list_tools`/`schemas`/
    `has`/`get`/`set_authorization_hook`/`call` (+ destructive-tool auth gate)
    /`_append_audit`/`export_audit`; plus `_safe_for_audit` (redacts secrets).
- `mcp_tools.py` — ~22 concrete tools across 8 domains; `default_toolset()`
  returns them. (Listed in [chapter 6](06_SUBSYSTEMS.md#65-the-mcp-tools).)
- `playbooks.py`:
  - `cls StepTemplate` → a step recipe (`kind`, `tool`, `params_fn`,
    `pre/post`, `severity_min`, `side_effect`, `rollback_template`);
    `instantiate(finding, ctx, rule_id)` → an `ActionStep`.
  - `cls Playbook` → `rule_id_pattern` + `steps[]`.
  - the param closures (`_suspect_ip`, `_affected_file`, `_vehicle_id`,
    `_ecu_id`) + the patch-synthesis helpers (`_patch_for_code_finding`, …).
  - the `PLAYBOOKS` catalogue (specific per-rule), the `_GENERIC_*` family
    fallbacks, and `_TIER_PLAYBOOKS` (soft/moderate/hard).
  - `fn build_plan(decision, ctx)` → findings → ordered, deduped `ActionPlan`.
- `executor.py`:
  - `cls GuardAdapter` → wraps a `(step)->(bool, reason)` function; the hook
    the executor calls per step. `passthrough_guard()` = always-allow.
  - `cls ActionExecutor` → `execute(plan)` walks steps (pre → guard → invoke
    with retry → post → rollback), building an `ActionReport`.
- `generator.py`:
  - `cls Action` → the legacy flat view (`kind/target/parameters/…`).
  - `cls ActionGenerator` → `plan()` (build), `execute()`, `generate()`
    (build + **LLM tool selection** + execute + wrap), `_llm_select_tools()`
    (the validated, guarded LLM augmentation), `_wrap_as_action()`.
  - `fn legacy_kind(step)` → map a tool to the guard's legacy kind vocabulary.

---

## `agents/attack/` — the red-team mirror

- `system_info_discovery.py` — `cls SystemInstance`, `cls
  SystemInfoDiscoveryAgent` (`_build_instance` deterministic graph build).
- `source_code_exploiter.py` — `cls SourceCodeExploiterAgent` (reuses
  `scan_code_static`, frames as exploit plans).
- `deployment_exploiter.py` — `cls DeploymentExploiterAgent` (topology checks
  + `_enumerate_paths` → `ATK-PATH` poison/trigger findings).
- `attack_orchestrator.py` — `cls AttackPlan`, `cls AttackOrchestratorAgent`
  (`plan()` chooses 1–3 findings; heuristic fallback).
- `attack_generator.py` — `cls AttackScript`, `_TEMPLATES`, `cls
  AttackGeneratorAgent` (`generate()` per finding; templates + LLM fallback).
- `ethics_guard.py` — `cls EthicsVerdict`, `_DESTRUCTIVE_PATTERNS`, `cls
  EthicsGuard` (`check_plan` scope/target; `filter_scripts` redaction).

---

## `tools/` — the floor, the simple tools, helpers

- `static_analyzer.py` — **the deterministic floor**:
  - `cls StaticFinding` → same fields as `Finding`.
  - `fn scan_code_static(code, filename, rules)` → regex over `code_rules`.
  - `fn scan_log_static(log_text, rules)` → hand-coded per-`LOG-*` heuristics
    (brute-force counting, broadcast-rate, CAN anomaly, DNS entropy, large
    outbound, lateral scan, SYN flood, shadow read). Helpers: `_parse_ts`,
    `_shannon_entropy`, `_line_of`.
  - `fn scan_deployment_static(deployment_yaml, rules)` → graph checks
    (`TOP-001…008`) via an inner `fire()` helper.
  - `fn merge_findings(static, llm)` → de-dup, **static wins**.
  - `fn staticfinding_to_finding(static_findings, finding_cls)` → convert.
- `mcp_tools.py` — the simple `run()`-style registry (now real): `PortScanTool`,
  `StaticAnalysisTool`, `PacketCaptureTool`, `TOOL_REGISTRY`.
- `tokens.py` — `fn estimate_tokens(text)`, `cls TokenBudget` (`account`,
  warnings).
- `log.py` — `cls Console`: `section/info/step/kv/warn` (verbose channel),
  `detail/blob` (debug channel), `timed` (a context manager that times a
  block). Writes to **stderr**.

---

## `skills/skills.py`

- `cls Skill` → a named skill + tier + side + optional `target_asset` + `fn`.
- `DEFENSE_SKILLS` (paper-5 tiered: rate_limit, traffic_shape,
  session_terminate, block_ip, isolate_node, segment_network, patch_code) and
  `ATTACK_SKILLS` (paper-2: memory_poison, a2a_fear_injection, rag_poisoning,
  confused_deputy, resource_depletion).
- `fn find_skill(name)` → look up by name.

---

## `run_logger.py` — the per-run trace

- `cls RunLogger` — one instance per run; methods `log_meta`, `log_inputs`,
  `log_static`, `log_agent`, `log_decision`, `log_action`, `log_action_plan`,
  `log_guard`, `log_system_instance`, `log_plan`, `log_ethics`,
  `log_attack_scripts`, `finalize`, `trace`. Produces the
  `run_logs/<run>/` directory documented in [chapter 7](07_RUN_TEST_EXTEND_FAQ.md).

---

## `evaluate.py` — the static evaluation harness

- `fn property_for(rule_id)` → map a rule to a paper-1 property.
- `dict _ASSET_FALLBACK` / `fn asset_for(finding, rule_idx)` → resolve the
  paper-2 asset category.
- `fn tier_for_severity(sev)` / `fn skills_for_tier(tier)` → tier helpers.
- `fn scan_scenario(scn, rules)` → run the static analyzer on one labelled
  scenario.
- `fn evaluate(cfg, rules, labels)` → compute recall, false positives,
  property table, scoreboard.
- `fn render_markdown(report)` / `fn main(argv)` → write `memory/eval_report.md`.

That's the whole codebase. For *how a subsystem works internally* (not just
what a symbol is), continue to
**[Chapter 6 — Subsystems](06_SUBSYSTEMS.md)**.
