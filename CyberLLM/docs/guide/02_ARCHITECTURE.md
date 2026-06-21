# Chapter 2 — Architecture & data types

[◀ Foundations](01_FOUNDATIONS.md) · [Master index](../DEVELOPER_GUIDE.md) · [Next: Defense pipeline ▶](03_DEFENSE_DEEP.md)

Now that you know the vocabulary, this chapter shows **how the pieces fit
together** and **exactly what data flows between them**. If chapter 3 is
"the movie", this chapter is "the cast list and the props".

---

## 2.1 The two pipelines at a glance

There are two sibling pipelines that share one backbone (this is paper 4's
"same schema, different agents" idea).

**Defense (the blue team):**

```
 inputs                      detection                 decision        response            safety
 ──────                      ─────────                 ────────        ────────            ──────
 code      ─►  SourceCodeScannerAgent ─┐
 logs      ─►  LogAnalyzerAgent ───────┼─► Finding[] ─► DecisionAgent ─► Decision ─► ActionGenerator ─► ActionReport
 deployment─►  DeploymentScannerAgent ─┘                  (tier,            │  (playbook + executor)     │
 + operator prompt                                         confidence,      │                            │
                                                           assets)          ▼                            ▼
                                                                     SecurityGuard.check          SecurityGuard.check_step
                                                                     + check_trajectory           (runs on EVERY tool step)
```

**Attack (the red team — the mirror):**

```
 deployment ─► SystemInfoDiscoveryAgent ─► SystemInstance
 code       ─► SourceCodeExploiterAgent ─┐
 deployment ─► DeploymentExploiterAgent ─┼─► Finding[] ─► AttackOrchestratorAgent ─► AttackPlan
 scenario   ──────────────────────────── ┘                      │
                                                                 ▼
                                                          EthicsGuard.check_plan ─► (in scope?)
                                                                 │
                                                                 ▼
                                                          AttackGeneratorAgent ─► AttackScript[]
```

The correspondence between the two sides (defense block ↔ attack mirror) is
in the [README](../../README.md) §1.3. The important mental note: **finding
a vulnerability is the same problem in both modes; only what you *do* with
it differs.** That's why both sides share `tools/static_analyzer.py`.

---

## 2.2 What is an "agent" here, concretely?

Every agent inherits from `BaseAgent` ([`../../agents/base_agent.py`](../../agents/base_agent.py)).
An agent owns four things (paper 4's schema):

1. an **`objective`** string (its allowed goal — the guard checks against this),
2. an **LLM client** (`self.llm`) to call,
3. a **data dict** (`self.data`) that fills the `[placeholders]` in its prompt,
4. a **`run()`** method that does the work and returns a typed record.

The base class also gives every agent: `call_llm(prompt)` (records the
prompt/response for the run-log and counts tokens), `template(prompt)`
(substitutes `[key]` → `self.data["key"]`), and `_parse_findings(text)`
(robustly reads a JSON `{"findings":[…]}` out of an LLM reply).

**Why a base class?** So every agent is built and called the same way, can
be swapped for a smarter one, and is independently testable (paper 4).

---

## 2.3 The golden rule of communication: typed hand-offs

Agents **never** pass raw LLM text to each other. They pass **dataclasses**
(small typed records). Free-form text exists *inside* an agent (its prompt,
its raw reply) but the thing crossing the boundary is structured. This is
what makes the system reproducible and auditable: the next stage can reason
mechanically over the previous stage's output.

Here is the complete "props list". Each is a Python `@dataclass`.

### `Input` — a provenance-tagged artefact
File: [`../../agents/base_agent.py`](../../agents/base_agent.py)

```python
Input(content="…file text…", source="02_can_gateway.py", trust_level="external")
```

| field | meaning | example |
|-------|---------|---------|
| `content` | the raw text (file contents, or the operator's instruction) | the Python source |
| `source` | where it came from | `"02_can_gateway.py"`, `"user"`, `"03_can_injection.log"` |
| `trust_level` | how much we trust it | `authenticated` / `external` / `tool` / `memory` |

**Why provenance is mandatory.** Paper 1's *source-attribution oracle*
`L(x)→s` says you can only enforce "did an *authenticated* source cause
this privileged action?" if **every input is labelled at the moment it
enters the system**. So `Input.__post_init__` *raises* `ProvenanceError`
if `source` is empty or `trust_level` is not one of the four allowed
values. Code & logs enter as `external` (untrusted data); the deployment
YAML and the operator's prompt enter as `authenticated`.

### `Finding` — one detected issue (the universal currency)

```python
Finding(rule_id="CODE-001", severity="high",
        evidence="02_can_gateway.py: subprocess.call(x, shell=True)",
        explanation="Shell-injection sink fed by untrusted input.",
        source_agent="source_code_scanner",
        asset_category="Material and Economic Resources", line=14)
```

| field | meaning |
|-------|---------|
| `rule_id` | which rule it matched (`CODE-*`, `LOG-*`, `TOP-*`, `ATK-PATH`) |
| `severity` | `low` / `medium` / `high` / `critical` |
| `evidence` | the matched snippet / log line / graph edge |
| `explanation` | human-readable why |
| `source_agent` | which agent produced it |
| `asset_category` | paper-2 taxonomy (set later by the decision agent) |
| `line` | line number for code findings |

The static analyzer emits an identical-shaped `StaticFinding`, converted to
`Finding` by `staticfinding_to_finding`.

### `AgentResult` — what a scanner returns

```python
AgentResult(agent_id="source_code_scanner", objective="…",
            findings=[Finding(...), ...], raw_llm_text="…")
```
`raw_llm_text` is the *unparsed* LLM reply, kept so the run-logger can show
exactly what the model said.

### `Decision` — the verdict
File: [`../../agents/decision_agent.py`](../../agents/decision_agent.py)

```python
Decision(summary="…", asset_categories_touched=["Life and Bodily Health", …],
         recommended_tier="hard", confidence=0.90, justification="…",
         findings=[…the aggregated findings…])
```
`recommended_tier` is `soft`/`moderate`/`hard`/`none`. `confidence` is 0–1.

### The action-engine model
File: [`../../agents/action_engine/types.py`](../../agents/action_engine/types.py)

- **`SideEffect`** enum: `READ`, `WRITE`, `DESTRUCTIVE`. Drives the
  dry-run/authorisation gate. *Why:* a tool that only reads is safe to run;
  a destructive one must be gated.
- **`StepKind`** enum: `CONTAIN`, `ERADICATE`, `RECOVER`, `NOTIFY`,
  `OBSERVE`, `AUDIT`. Used to **order** steps (contain first). *Why:* you
  stop the bleeding before you remove the root cause.
- **`StepStatus`**: `PENDING`/`RUNNING`/`COMPLETED`/`FAILED`/`SKIPPED`/
  `REFUSED`/`VERIFY_FAILED`/`ROLLED_BACK`.
- **`PlanStatus`**: `NOT_STARTED`/`IN_PROGRESS`/`COMPLETED`/`PARTIAL`/
  `FAILED`/`REFUSED`.
- **`Condition`** — a pre/post check, evaluated by calling an MCP tool
  (`check_tool`, `check_params`, optional `expected_status`/`expected_payload`).
  *Why:* "did the fix actually work?" must itself be a tool call, so it's
  auditable.
- **`ActionStep`** — one tool call: `rule_id, kind, tool, params,
  description, side_effect, severity_min, retries, pre[], post[],
  rollback_steps[], requires_authorization` plus mutable run-state
  (`status`, `attempts`, `output`, `error`, …).
- **`ActionPlan`** — `plan_id, decision_summary, blast_radius,
  asset_categories, steps[]`. The ordered list of steps to run.
- **`ActionReport`** — `plan, status, summary, audit_log[]` with computed
  tallies (`completed/failed/refused/rolled_back/skipped`).
- **`ToolResult`** — every tool call returns this: `status
  ("ok"|"failed"|"would-execute"|"skipped"), tool, payload, error,
  invoked_real_tool, elapsed_ms`.

### Guard verdicts
File: [`../../agents/security_guard.py`](../../agents/security_guard.py)
- **`GuardVerdict`** (the final aggregate action): `allowed,
  task_alignment, action_alignment, source_authorization, data_isolation,
  reason`.
- **`StepVerdict`** (per individual step — the "new step shape" check):
  same four booleans + `reason`.
- **`TrajectoryVerdict`** (the *sequence* of steps): `allowed,
  compositional_ok, temporal_ok, violations[]`.

### Attack-side records
- **`SystemInstance`** ([`../../agents/attack/system_info_discovery.py`](../../agents/attack/system_info_discovery.py)):
  `actors[], datasources[], edges[], external_actors[], safety_actors[],
  notes[]`.
- **`AttackPlan`** ([`../../agents/attack/attack_orchestrator.py`](../../agents/attack/attack_orchestrator.py)):
  `scenario, objective, target_asset, chosen_findings[], poison_path[],
  trigger_path[], confidence, justification, summary`.
- **`AttackScript`** ([`../../agents/attack/attack_generator.py`](../../agents/attack/attack_generator.py)):
  `rule_id, title, language, body, target_hint, expected_effect`.

### Memory record
File: [`../../agents/memory_store.py`](../../agents/memory_store.py)
- **`Incident`**: `mode, scenario, rule_ids[], asset_categories[], tier,
  confidence, action_kind, guard_allowed, plan_status, remediation_ok,
  source, created_at` (+ an HMAC `signature` stored in the DB). The two
  *outcome* fields (`plan_status`, `remediation_ok`) are what enable
  cross-session learning.

### Skill
File: [`../../skills/skills.py`](../../skills/skills.py)
- **`Skill`**: `name, description, tier, side("defense"|"attack"),
  target_asset, fn`.

---

## 2.4 The directory map (where everything lives)

`▲` = added in the latest upgrade, `◆` = materially changed by it.

```
CyberLLM/
├── pipeline.py              ◆ entry point: both pipelines, the re-planning loop, batch, CLI
├── evaluate.py                static evaluation harness (recall / FP / scoreboard)
├── verify.py                  30-second offline smoke test
├── config.yaml              ◆ ALL configuration (+ new action_engine section)
├── llm_client.py              LLM providers (stub/azure/github/openai/anthropic/ollama) + .env loader
├── run_logger.py              writes the per-run debug trace under run_logs/
├── .env                       secrets (git-ignored): AZURE_OPENAI_*, GITHUB_TOKEN…
│
├── agents/
│   ├── base_agent.py          the agent contract: Input, Finding, AgentResult, BaseAgent
│   ├── source_code_scanner.py defense scanner — code
│   ├── log_analyzer.py        defense scanner — logs
│   ├── deployment_scanner.py  defense scanner — topology
│   ├── decision_agent.py    ◆ aggregates findings; memory recall + feedback escalation
│   ├── action_generator.py    thin shim → action_engine
│   ├── security_guard.py    ◆ paper-1 properties + check_step + trajectory checks
│   ├── ha_judge.py            the H_a oracle (separate LLM call, cached)
│   ├── memory_store.py      ◆ signed sqlite store + outcomes + recommend()
│   ├── action_engine/
│   │   ├── types.py           the data model above
│   │   ├── mcp_registry.py    MCPTool base + MCPRegistry (validate, dry-run, audit)
│   │   ├── mcp_tools.py      ◆ ~22 real tools (+ nmap + packet capture)
│   │   ├── playbooks.py       rule-id → typed step sequence; build_plan()
│   │   ├── executor.py        walks the plan: pre → guard → call → post → rollback
│   │   └── generator.py     ◆ ActionGenerator (+ LLM tool selection)
│   └── attack/                the red-team mirror (6 files)
│
├── tools/
│   ├── static_analyzer.py     THE deterministic floor
│   ├── mcp_tools.py         ◆ legacy run()-style tools, now real backends
│   ├── tokens.py              dependency-free token estimator
│   └── log.py                 Console (stderr diagnostics; verbose/debug)
│
├── skills/skills.py           defense + attack skill catalogues
├── rules/                     example_rules / extended_rules / attack_rules YAML
├── examples/                  demo code, logs, deployments, labels.yaml, scenarios.md
├── memory/                    OUTPUTS: per-run JSON + incidents.db
├── run_logs/                  OUTPUTS: per-run step traces
├── docs/                      this guide + companion docs
└── tests/                     ~155 pytest tests + conftest fixtures
```

> **Two MCP tool files?** `tools/mcp_tools.py` is the *simple* `run()`-style
> registry (3 tools). The *real engine* is
> `agents/action_engine/mcp_tools.py` (22 tools, schema-validated, audited,
> dry-run). New work uses the engine; the simple one is kept for the
> lightweight `run()` interface. Both are now real (chapter 6).

---

## 2.5 The "takes X, gives Y" summary table

This is the whole system as a chain of transformations. Chapters 3 and 4
expand every row.

| Stage | Takes | Gives | To |
|-------|-------|-------|----|
| Ingestion | file paths | `Input[]` (provenance-tagged) | the scanners |
| Each scanner | `Input[]` | `Finding[]` (static ⊕ LLM, merged) | the decision agent |
| Decision agent | `Finding[]` (+ memory) | `Decision` (tier, confidence, assets) | the action engine |
| Plan builder | `Decision` | `ActionPlan` (ordered `ActionStep[]`) | the executor |
| Executor | `ActionPlan` (+ per-step guard) | `ActionReport` | the pipeline + the loop |
| Security guard | the final `Action` + objective + `Input[]` | `GuardVerdict` (+ `TrajectoryVerdict`) | the loop / record |
| Re-planning loop | `ActionReport` + `GuardVerdict` | feedback → a new (escalated) `Decision` | back to the decision agent |
| Persistence | the whole run | `Incident` (signed, with outcome) + JSON record + run-log | memory + disk |

Now read **[Chapter 3 — The defense pipeline, deep](03_DEFENSE_DEEP.md)**,
which narrates every one of these rows in full.
