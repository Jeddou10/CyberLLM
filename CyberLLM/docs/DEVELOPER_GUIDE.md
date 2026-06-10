# CyberLLM — The Complete Developer Guide

> **Who this is for.** Someone who has *never seen this code* and is about
> to work on it. By the end you will understand **what** the system does,
> **why** every part exists (with the research paper it comes from),
> **how** data flows from a raw file to a final decision/action, and
> **where** to change things. Read it top-to-bottom the first time; use the
> table of contents as a reference afterwards.
>
> This guide is deliberately long and explicit. Nothing is assumed.

---

## Table of contents

1. [What is CyberLLM, in one page](#1-what-is-cyberllm-in-one-page)
2. [The five reference papers](#2-the-five-reference-papers)
3. [The mental model: two mirrored pipelines](#3-the-mental-model-two-mirrored-pipelines)
4. [Repository map (file by file)](#4-repository-map-file-by-file)
5. [The vocabulary: every core data type](#5-the-vocabulary-every-core-data-type)
6. [The rule catalogue (the system's "knowledge")](#6-the-rule-catalogue)
7. [The LLM layer (providers, .env, the stub)](#7-the-llm-layer)
8. [The static analyzer — the deterministic floor](#8-the-static-analyzer)
9. [The DEFENSE pipeline, step by step](#9-the-defense-pipeline-step-by-step)
10. [The action engine (planner + executor) in depth](#10-the-action-engine-in-depth)
11. [The guards & the paper-1 security model](#11-the-guards--the-paper-1-security-model)
12. [The adaptive memory subsystem](#12-the-adaptive-memory-subsystem)
13. [The ATTACK pipeline, step by step](#13-the-attack-pipeline-step-by-step)
14. [Run logging & console verbosity](#14-run-logging--console-verbosity)
15. [The static evaluation harness](#15-the-static-evaluation-harness)
16. [Configuration reference (config.yaml)](#16-configuration-reference)
17. [The complete input → output chain](#17-the-complete-input--output-chain)
18. [Testing](#18-testing)
19. [How to extend the system](#19-how-to-extend-the-system)
20. [A fully worked example](#20-a-fully-worked-example)
21. [Glossary](#21-glossary)

---

## 1. What is CyberLLM, in one page

CyberLLM is a **multi-agent cybersecurity system** built around Large
Language Models. It has **two halves that mirror each other**:

- **Defense** (the "blue team"): autonomously reads **source code**,
  **logs**, and **deployment configurations**, finds vulnerabilities and
  anomalies, decides how serious they are, and proposes/executes a
  defensive response — all under the supervision of a security guard.
- **Attack** (the "red team"): reads the same artefacts but produces an
  **attack plan** and **proof-of-concept exploit scripts** for authorised
  red-team exercises, under an ethics guard.

The primary domain is **automotive / Software-Defined Vehicles (SDV)** and
edge computing, but the design generalises to any system you can describe
as a graph of *actors* and *datasources*.

### The single most important design rule: **static-first**

> The supervisor's hard constraint: the system must *"mainly detect all
> static vulnerabilities and, if possible, active ones when running it"*.

Therefore **every scanner runs a deterministic, non-LLM static pass first**
(regular expressions over source code, hand-coded heuristics over logs,
graph checks over topology). Only *then* does it call an LLM to *refine,
explain, and extend* those findings. The two layers are merged with the
**static layer winning on duplicates**.

Why this matters, and why you should never break it:

| Layer | Deterministic? | Behaviour with no LLM / stub | Role |
|-------|----------------|------------------------------|------|
| Static analyzer | ✅ yes | produces **real, traceable** findings | the **trusted floor** |
| LLM scanner | ❌ no (probabilistic) | produces canned/low-signal findings | refinement on top |
| Merge layer | ✅ yes (static wins) | static findings survive verbatim | guarantees no regression |

**Consequence:** the whole pipeline runs end-to-end with **no API key, no
network** (a deterministic "stub" LLM ships in the box). Add a real model
and quality goes *up*, never down.

---

## 2. The five reference papers

Almost every design choice traces to one of five papers. You will see the
tags **(P1)…(P5)** throughout the code and this guide.

| Tag | Short name | What it gives CyberLLM | Where it lives in the code |
|-----|-----------|------------------------|----------------------------|
| **P1** | *Contextual security framework* (UCSC/Berkeley/Duke) | The thesis that "following instructions ≠ being secure". Defines **four security properties** + **five oracle functions** that a guard must approximate. | [`agents/security_guard.py`](../agents/security_guard.py), [`agents/ha_judge.py`](../agents/ha_judge.py) |
| **P2** | *AgentHeLLM* (BMW/TUM) | A human-centric **asset taxonomy**, the **actor/datasource graph**, and **poison-path vs trigger-path** attack modelling. | [`tools/static_analyzer.py`](../tools/static_analyzer.py), [`agents/attack/`](../agents/attack/) |
| **P3** | *Event chains + OCL + RAG* (TUM) | Model-Driven-Engineering: keep rules **outside** the LLM, give the LLM the deterministic hits as context (RAG), use auto-correction prompts. | [`rules/*.yaml`](../rules/), the "static-first" merge, the patch playbooks |
| **P4** | *Härer multi-agent schema* | The engineering backbone: a **schema-driven agent** (LLM-config + data + objective + template), agent-of-type invocation, typed hand-offs. | [`agents/base_agent.py`](../agents/base_agent.py), [`llm_client.py`](../llm_client.py), `config.yaml` |
| **P5** | *Edge MAS coordination* (Collins) | A **layered detection→decision→response** architecture, **tiered response** (soft/moderate/hard), and an **adaptive-learning loop**. | [`pipeline.py`](../pipeline.py), [`agents/action_engine/`](../agents/action_engine/), [`agents/memory_store.py`](../agents/memory_store.py) |

You do **not** need to read the papers to work on the code, but knowing
which paper a feature serves tells you what it is *trying* to be faithful
to. The per-paper notes live in [`../Papers_Notes/`](../../Papers_Notes/).

---

## 3. The mental model: two mirrored pipelines

The supervisor provided two diagrams. CyberLLM implements **both** as
sibling pipelines that share one backbone.

### 3.1 Defense pipeline (diagram 1)

```
 Source code ─┐
 Logs ────────┼─► [3 scanner agents] ─► findings ─► [Decision agent] ─► Decision
 Deployment ──┘     (static + LLM)                       │  (tier, confidence,
                                                          │   assets, memory recall)
                                                          ▼
                                                  [Action engine] ─► ActionPlan ─► ActionReport
                                                          │  (playbook → executor → MCP tools)
                                                          ▼
                                                  [Security guard] ─► allow / refuse
                                                          │  (paper-1 four properties + H_a)
                                                          ▼
                                                  memory record + run log
```

### 3.2 Attack pipeline (diagram 2) — the mirror

```
 Deployment ─► [System info discovery] ─► SystemInstance
 Source code ─► [Source-code exploiter] ─┐
 Deployment ──► [Deployment exploiter] ──┼─► findings ─► [Attack orchestrator] ─► AttackPlan
 Scenario/hint ──────────────────────────┘                      │
                                                                 ▼
                                                         [Ethics guard] ─► in scope?
                                                                 │
                                                                 ▼
                                                         [Attack generator] ─► AttackScript[]
                                                                 │  (templates + LLM fallback)
                                                                 ▼
                                                         memory record + run log + scripts/
```

### 3.3 The defense ↔ attack correspondence

| Defense block | Attack mirror | Shared backbone |
|---------------|---------------|-----------------|
| Decision agent | Attack orchestrator | `BaseAgent`, structured output |
| Source-code scanner | Source-code exploiter | `static_analyzer.scan_code_static` |
| Log analyzer | *(none — attacker generates logs)* | — |
| Deployment scanner | Deployment exploiter | actor/datasource graph |
| Action generator | Attack generator | template + LLM fallback |
| Security guard | Ethics guard | per-action permission check |
| Rules / policies | Attack rules | YAML-driven |

### 3.4 The six properties that make this *agentic* (not just automation)

From [`docs/AGENTIC_WORK.md`](AGENTIC_WORK.md): a pipeline is "agentic" here
only when **all six** hold — goal-directed (each agent has an `objective`),
specialised roles, **typed hand-offs** (agents exchange structured records,
never free text), tool use (MCP tools), observation+feedback (pre/post
conditions, retry, rollback), and guardrails (a separate component can
refuse a step). Keep these in mind: they are the project's quality bar.

---

## 4. Repository map (file by file)

Everything below is inside `CyberLLM/` (the project root — the directory
that contains `pipeline.py`).

```
CyberLLM/
├── pipeline.py              # ENTRY POINT. Orchestrates both pipelines + batch + CLI.
├── evaluate.py              # Static evaluation harness (recall / FP / scoreboard).
├── verify.py                # 30-second offline smoke test (no pytest needed).
├── config.yaml              # ALL configuration (LLMs, agents, security, memory, examples).
├── llm_client.py            # LLM provider abstraction + .env loader + offline stub.
├── run_logger.py            # Writes the per-run debug trace under run_logs/.
├── requirements.txt         # Only PyYAML is mandatory; the rest are optional.
├── .env                     # Secrets (git-ignored): AZURE_OPENAI_*, GITHUB_TOKEN, …
│
├── agents/                  # The agents (one specialised role each)
│   ├── base_agent.py        # P4 schema-driven base: Input, Finding, AgentResult, BaseAgent.
│   ├── source_code_scanner.py   # DEFENSE: regex static pass + LLM refinement on code.
│   ├── log_analyzer.py          # DEFENSE: heuristic static pass + LLM on logs.
│   ├── deployment_scanner.py    # DEFENSE: graph checks + LLM on topology YAML.
│   ├── decision_agent.py        # DEFENSE: aggregates findings, recalls memory, picks a tier.
│   ├── action_generator.py      # Thin shim → action_engine (back-compat name).
│   ├── security_guard.py        # P1 four properties + H_a + trajectory checks.
│   ├── ha_judge.py              # P1 H_a oracle as a separate LLM call.
│   ├── memory_store.py          # P5/E: signed SQLite incident store (recall + anti-poison).
│   ├── action_engine/           # The real defense "response" engine
│   │   ├── types.py             #   data model: ActionPlan/ActionStep/ActionReport/ToolResult/enums.
│   │   ├── mcp_registry.py      #   MCPTool base + MCPRegistry (validation, dry-run, audit).
│   │   ├── mcp_tools.py         #   ~20 real tools (firewall/network/secrets/code/runtime/notify/observe/kb).
│   │   ├── playbooks.py         #   rule-id → typed step sequence; build_plan().
│   │   ├── executor.py          #   walks the plan: pre → guard → call → post → rollback.
│   │   └── generator.py         #   public ActionGenerator (plan + execute, legacy Action view).
│   └── attack/                  # The red-team mirror (diagram 2)
│       ├── system_info_discovery.py  # passive recon → SystemInstance.
│       ├── source_code_exploiter.py  # static hits → exploit plans.
│       ├── deployment_exploiter.py   # topology → poison/trigger attack paths (ATK-PATH).
│       ├── attack_orchestrator.py    # choose 1–3 findings → AttackPlan.
│       ├── attack_generator.py       # AttackPlan → AttackScript[] (templates + LLM fallback).
│       └── ethics_guard.py           # scope/target/destructive-pattern gating.
│
├── tools/
│   ├── static_analyzer.py   # THE FLOOR: scan_code_static / scan_log_static / scan_deployment_static.
│   ├── mcp_tools.py         # Legacy MCP stub registry (older, simpler; superseded by action_engine).
│   ├── tokens.py           # Dependency-free token estimator + TokenBudget (A.4).
│   └── log.py              # Console: verbose/debug diagnostics to stderr.
│
├── skills/
│   └── skills.py           # Defense skills (P5 tiers) + attack skills (P2 scenarios).
│
├── prompts/                # Human-readable copies of a couple of prompts (reference only).
├── rules/
│   ├── example_rules.yaml  # baseline code_/log_/topology_ rules.
│   ├── extended_rules.yaml # ~40 more rules (CODE-004…, SAFE-*, etc.).
│   └── attack_rules.yaml   # offensive rule-id mappings.
│
├── examples/               # Test fixtures the pipeline scans
│   ├── small/              # 5 single-file scenarios (.py, .c).
│   ├── medium/             # 2 mini-projects (ev_charging_api, adas_decision).
│   ├── large/              # 1 realistic backend (fleet_management).
│   ├── logs/               # 6 named log scenarios.
│   ├── deployments/        # 3 deployment YAMLs (clean / misconfigured / complex SDV).
│   ├── attack_scenarios/   # 3 scenario/hint text files.
│   ├── juliet/             # a large C vulnerability corpus (Wireshark dissectors).
│   ├── labels.yaml         # ground truth for evaluate.py.
│   └── scenarios.md        # human-readable "expected findings" per scenario.
│
├── memory/                 # OUTPUTS: per-run JSON records + the signed incidents.db.
├── run_logs/               # OUTPUTS: per-run step-by-step debug directories.
└── tests/                  # pytest suite (≈138 tests) + conftest fixtures.
```

**Two MCP tool files?** Yes. [`tools/mcp_tools.py`](../tools/mcp_tools.py)
is the *original, simple* stub registry. The real engine is
[`agents/action_engine/mcp_tools.py`](../agents/action_engine/mcp_tools.py)
(20 tools, real subprocess calls, dry-run, audit). New work uses the
action_engine one; the old one is kept for reference / simple imports.

---

## 5. The vocabulary: every core data type

Agents **never pass free text to each other** — they pass these typed
records. Learn them and the whole system becomes legible.

### 5.1 `Input` — a provenance-tagged artefact ([`agents/base_agent.py`](../agents/base_agent.py))

```python
@dataclass
class Input:
    content: str          # the file contents / prompt text
    source: str           # e.g. "02_can_gateway.py", "user", "03_can_injection.log"
    trust_level: str      # "authenticated" | "external" | "tool" | "memory"
```

- **Why provenance is mandatory (P1).** Paper 1's *source-attribution
  oracle* `L(x)→s` says: you can only enforce "did an authenticated source
  cause this action?" if **every input is labelled at ingestion**. So
  `Input.__post_init__` **raises `ProvenanceError`** if `source` is empty
  or `trust_level` is not in the allowed lattice `ALLOWED_TRUST_LEVELS`.
- Which loader sets which level: code & logs are loaded as `external`
  (untrusted data), deployment YAML & the operator prompt as
  `authenticated`. Memory-recalled context would be `memory`.

### 5.2 `Finding` — one detected issue ([`agents/base_agent.py`](../agents/base_agent.py))

```python
@dataclass
class Finding:
    rule_id: str          # "CODE-001", "LOG-CAN-02", "TOP-002", "ATK-PATH" …
    severity: str         # "low" | "medium" | "high" | "critical"
    evidence: str         # the matched snippet / log line / edge
    explanation: str      # human-readable why
    source_agent: str     # which agent produced it
    asset_category: str | None = None   # P2 taxonomy, set by DecisionAgent
    line: int | None = None             # for code findings
```

This is the **universal currency** of the system. The static analyzer
emits `StaticFinding` (same fields) and converts to `Finding` via
`staticfinding_to_finding`.

### 5.3 `AgentResult` — what every scanner returns

```python
@dataclass
class AgentResult:
    agent_id: str
    objective: str
    findings: list[Finding]
    raw_llm_text: str | None = None   # the unparsed LLM response, for the run-log
```

### 5.4 `Decision` ([`agents/decision_agent.py`](../agents/decision_agent.py))

```python
@dataclass
class Decision:
    summary: str
    asset_categories_touched: list[str]   # P2 taxonomy
    recommended_tier: str                 # "soft" | "moderate" | "hard" | "none"
    confidence: float                     # 0.0 .. 1.0
    justification: str
    findings: list[Finding]               # the aggregated input findings
```

### 5.5 The action-engine model ([`agents/action_engine/types.py`](../agents/action_engine/types.py))

- `SideEffect` enum: `READ | WRITE | DESTRUCTIVE` (drives dry-run/auth gating).
- `StepKind` enum: `CONTAIN | ERADICATE | RECOVER | NOTIFY | OBSERVE | AUDIT`
  — used to **order** steps (containment first). The order is encoded in
  `_KIND_ORDER` → `kind_priority()`.
- `StepStatus`: `PENDING | RUNNING | COMPLETED | FAILED | SKIPPED |
  REFUSED | VERIFY_FAILED | ROLLED_BACK`.
- `PlanStatus`: `NOT_STARTED | IN_PROGRESS | COMPLETED | PARTIAL | FAILED | REFUSED`.
- `Condition` — a pre/post check evaluated by calling an MCP tool
  (`check_tool`, `check_params`, optional `expected_status`/`expected_payload`).
- `ActionStep` — one tool call: `rule_id, kind, tool, params, description,
  side_effect, severity_min, retries, pre[], post[], rollback_steps[]`,
  plus mutable execution state (`status`, `attempts`, `output`, `error`…).
- `ActionPlan` — `plan_id, decision_summary, blast_radius, asset_categories,
  steps[]`. Immutable once built.
- `ActionReport` — `plan, status, summary, audit_log[]` + computed tallies
  (`completed/failed/refused/rolled_back/skipped`).
- `ToolResult` — `status ("ok"|"failed"|"would-execute"|"skipped"), tool,
  payload, error, invoked_real_tool, elapsed_ms`.

### 5.6 The legacy `Action` ([`agents/action_engine/generator.py`](../agents/action_engine/generator.py))

A flattened view of the plan kept so the `SecurityGuard` (which predates
the engine) keeps working:
`Action{ kind, target, parameters, rationale, originating_decision, plan_id, report }`.
The mapping from a real MCP tool to a legacy `kind` is `_LEGACY_KIND_MAP`
(exposed publicly as `legacy_kind(step)`), e.g. `firewall.block_ipv4 →
block_ip`, `code.propose_patch → patch_code`, `notify.* → alert_only`.

### 5.7 Guard verdicts

- `GuardVerdict` (defense): `allowed, task_alignment, action_alignment,
  source_authorization, data_isolation, reason`.
- `TrajectoryVerdict` (defense, sequence-level): `allowed, compositional_ok,
  temporal_ok, violations[]`.
- `EthicsVerdict` (attack): `allowed, scope_ok, target_ok, non_destructive, reason`.

### 5.8 Attack-side types

- `SystemInstance` ([`system_info_discovery.py`](../agents/attack/system_info_discovery.py)):
  `actors[], datasources[], edges[], external_actors[], safety_actors[], notes[]`.
- `AttackPlan` ([`attack_orchestrator.py`](../agents/attack/attack_orchestrator.py)):
  `scenario, objective, target_asset, chosen_findings[], poison_path[],
  trigger_path[], confidence, justification, summary`.
- `AttackScript` ([`attack_generator.py`](../agents/attack/attack_generator.py)):
  `rule_id, title, language, body, target_hint, expected_effect`.

### 5.9 `Incident` — a memory row ([`agents/memory_store.py`](../agents/memory_store.py))

`mode, scenario, rule_ids[], asset_categories[], tier, confidence,
action_kind, guard_allowed, source, created_at` (+ HMAC `signature` in DB).

### 5.10 `Skill` ([`skills/skills.py`](../skills/skills.py))

`name, description, tier, side ("defense"|"attack"), target_asset, fn`.

---

## 6. The rule catalogue

Rules are **plain YAML** in [`rules/`](../rules/). At startup
`pipeline.load_rules()` reads every `*.yaml` and **merges by family**:
`code_rules`, `log_rules`, `topology_rules`, `attack_rules`,
`safety_rules`. This is the P3 idea: keep the security knowledge *outside*
the model so every finding is traceable to a versioned rule.

A **code rule** has a regex `pattern`; the static analyzer applies it
directly:

```yaml
code_rules:
  - id: CODE-001
    severity: high
    title: "Command injection sink"
    pattern: "subprocess\\.(call|run|Popen)\\(.+shell\\s*=\\s*True"
    asset_category: "Material and Economic Resources"
    rationale: "Shell execution of untrusted strings is a direct RCE."
```

A **log rule** carries a `signature` description but the *logic* is
hand-coded in `scan_log_static` (entropy, counts, thresholds — things a
regex can't express). A **topology rule** carries an OCL-style `rule`
text, but again the logic is hand-coded in `scan_deployment_static`.

**Rule-id families** (memorise these — they appear everywhere):

| Prefix | Family | Detected by | Example |
|--------|--------|-------------|---------|
| `CODE-*` | source-code patterns | regex | CODE-001 shell injection, CODE-003 hard-coded secret |
| `LOG-*` | log anomalies | heuristics | LOG-CAN-02 CAN injection, LOG-EXFIL-01 DNS exfil |
| `TOP-*` | topology/architecture | graph checks | TOP-002 external write to memory |
| `SAFE-*` | safety event-chains | (extended rules) | SAFE-001 |
| `ATK-PATH` | a candidate attack path | enumerated by the deployment exploiter | poison/trigger |

---

## 7. The LLM layer

File: [`llm_client.py`](../llm_client.py). This is the P4 "LLM-Config"
abstraction. One factory, several providers, and a deterministic stub.

### 7.1 `LLMClient.create(cfg)` — the factory

```python
client = LLMClient.create({"provider": "azure", "model": "gpt-4o", ...})
text  = client.complete(prompt).text
```

Resolution order inside `create()`:

1. **Load `.env`** once (`_load_dotenv_once()` — a tiny zero-dependency
   parser; sets only keys not already in the environment, so a shell value
   always wins).
2. **`CYBERLLM_FORCE_STUB`** set? → always return the offline stub (the
   tests and `verify.py` use this to stay hermetic/offline).
3. Dispatch on `provider`:
   - `stub` → `StubLLM`
   - `github` → `GitHubModelsLLM` (token from `GITHUB_TOKEN`)
   - `azure` → `AzureOpenAILLM` (the **current default**)
   - `openai` / `anthropic` / `ollama` → respective clients
4. **Graceful credential fallback (A.2):** if the selected provider's
   key/endpoint is **missing or still a placeholder**
   (`_looks_like_placeholder()`), it returns the **stub with a warning**
   instead of crashing. So the pipeline always runs.

### 7.2 The providers

| Provider | Class | Auth | Notes |
|----------|-------|------|-------|
| `stub` | `StubLLM` | none | Deterministic. Keyword-matches the prompt and returns canned JSON. **This is why the pipeline works offline.** |
| `azure` | `AzureOpenAILLM` | `api-key` header | **Default.** Model = the **deployment name** in the URL, not the model id. Versioned with `?api-version=`. Handles gpt-4o. |
| `github` | `GitHubModelsLLM` | `Bearer` token | GitHub Models GA endpoint; ids are namespaced (`openai/gpt-5-mini`). **Reasoning-model aware** (see below). |
| `openai` | `OpenAILLM` | `OPENAI_API_KEY` | uses the `openai` SDK. |
| `anthropic` | `AnthropicLLM` | `ANTHROPIC_API_KEY` | uses the `anthropic` SDK. |
| `ollama` | `OllamaLLM` | none (localhost) | local models. |

**Reasoning-model handling.** GPT-5 / o-series models reject `max_tokens`
and a custom `temperature`. `GitHubModelsLLM._is_reasoning_model()` detects
them and sends `max_completion_tokens` + omits `temperature`. Both
`GitHubModelsLLM` and `AzureOpenAILLM` also **retry once on HTTP 429**
(rate limit) with backoff.

### 7.3 The deterministic stub (`StubLLM`)

`StubLLM.complete()` inspects the prompt and returns plausible JSON:
- prompt contains `"action-alignment oracle h_a"` → returns
  `{"serves": true/false, "reason": …}` (the H_a judge).
- `"central decision agent"` + `"asset_categories_touched"` → a Decision JSON.
- `"source-code security scanner"` → findings JSON.
- `"log" + "anomal"` → log findings.
- `"deployment"/"topology"` → topology findings.
- `"fix"/"correct"` → a remediation sentence.
- else → `"ACK: …"`.

**Critical for testing:** because the stub keys on *substrings*, adding new
context to a prompt (e.g. the `[memory]` few-shot block) does **not** change
the stub's output — so the test suite stays deterministic.

### 7.4 `.env` and secrets

`.env` is **git-ignored**. Active provider keys live there. Example for
the default Azure setup:

```bash
AZURE_OPENAI_ENDPOINT=https://<your-resource>.openai.azure.com
AZURE_OPENAI_API_KEY=<key>
AZURE_OPENAI_DEPLOYMENT=<deployment name that serves gpt-4o>   # ← the deployment, not the model
AZURE_OPENAI_API_VERSION=2024-10-21
```

> ⚠️ **Azure gotcha learned the hard way:** a deployment can be *named*
> anything. On one resource the deployment literally named `gpt-4o` was
> actually serving gpt-5.1, and the real gpt-4o lived under `gpt-4o-2`.
> Always list deployments
> (`GET {endpoint}/openai/deployments?api-version=2023-03-15-preview`,
> header `api-key`) and pin the right name in `AZURE_OPENAI_DEPLOYMENT`.

### 7.5 Token budgeting (A.4) — [`tools/tokens.py`](../tools/tokens.py)

`estimate_tokens(text)` is a heuristic (≈ max(chars/3.5, words×1.3)) — no
tokeniser dependency. Each `BaseAgent` owns a `TokenBudget`; `call_llm()`
accounts every prompt and warns if it exceeds `max_prompt_tokens`
(default 4096, the threshold P3 used). It never blocks — it just flags that
content should move to RAG.

---

## 8. The static analyzer

File: [`tools/static_analyzer.py`](../tools/static_analyzer.py). This is the
deterministic floor. Three entry points, all pure functions:

### 8.1 `scan_code_static(code, filename, rules) -> list[StaticFinding]`

Compiles every `code_rules[*].pattern` (with `re.MULTILINE | re.IGNORECASE`)
and runs it over the source. For each match it records the rule id,
severity, a ±20-char evidence snippet, the line number (`_line_of`), and
the rule's `asset_category`.

### 8.2 `scan_log_static(log_text, rules) -> list[StaticFinding]`

Hand-coded detectors keyed by log rule id, e.g.:
- `LOG-AUTH-03`: ≥10 "Failed password" for root/admin within 60 s
  (timestamps parsed by `_parse_ts`).
- `LOG-NET-01`: a broadcast (`.255`) line with `rate ≥ 500 pkts/s`.
- `LOG-CAN-02`: an `anomaly` line referencing a gateway-only CAN id.
- `LOG-EXFIL-01`: ≥5 DNS queries whose subdomains have **Shannon entropy**
  (`_shannon_entropy`) > 3.0 (covert channel).
- `LOG-EXFIL-02`: `bytes_out ≥ 10 MB`.
- `LOG-LATERAL-01`, `LOG-DDOS-01`, `LOG-PRIV-01`: scan/flood/shadow-read.

### 8.3 `scan_deployment_static(deployment_yaml, rules) -> list[StaticFinding]`

Parses the YAML into `actors / datasources / edges` and runs **graph
checks** that a regex couldn't express, e.g.:
- `TOP-001`: every `HPC → ZoneECU` edge must be `ethernet` + `IEEE-1722`.
- `TOP-002`: no `external` actor may `write` to a `*memory*` datasource
  (the **poison path**).
- `TOP-005`: a `Database` with `bind_address: 0.0.0.0`.
- `TOP-006`: a `SecretStore` with `access_policy: world-readable`.
- `TOP-007`: a safety actuator commanded by a non-safety actor.
- `TOP-008`: an external A2A agent with a `respond` edge to an in-vehicle agent.

### 8.4 The merge — `merge_findings(static, llm)`

De-dupes on `(rule_id, evidence-prefix[:40])`. **Static findings are kept
first and always win.** This is the guarantee that the LLM can only *add*,
never *remove*.

---

## 9. The DEFENSE pipeline, step by step

Function: `run_defense_pipeline(...)` in [`pipeline.py`](../pipeline.py).
Read it alongside this section. Signature:

```python
run_defense_pipeline(code_paths, log_path, deploy_path, cfg, rules,
                     scenario_name="default", verbose=True, debug=False) -> dict
```

**Step 0 — setup.** Build a `Console` (verbosity), build the LLM clients
(`build_llms` → one client per `llm_configs` entry), build the signed
memory store (`build_memory`, may be `None`), open a `RunLogger`.

**Step 1 — build provenance-tagged inputs.** Each code file →
`Input(external)`, the log → `Input(external)`, the deployment →
`Input(authenticated)`, plus an operator `Input("…requested by authorised
operator", source="user", trust_level="authenticated")`. Logged via
`rlog.log_inputs`.

**Steps 2–4 — the three scanners** (each is *static-first*; same 3 sub-steps):

For `SourceCodeScannerAgent.run(inputs)`
([source_code_scanner.py](../agents/source_code_scanner.py)):
1. **Static pass:** `scan_code_static` over each `.py/.c/.cpp` input →
   `StaticFinding[]` → converted to `Finding[]` (stored on
   `agent.last_static_findings`).
2. **LLM pass:** fill the agent's `data` dict (`code`, `filename`, `rules`
   snippet, and the static findings rendered as text), substitute into the
   `PROMPT` via `BaseAgent.template()` (replaces `[placeholders]`), call the
   LLM, parse the JSON (`_parse_findings`).
3. **Merge:** `merge_findings(static, llm)` → returned in `AgentResult`.

`LogAnalyzerAgent` and `DeploymentScannerAgent` are identical in shape,
using `scan_log_static` / `scan_deployment_static`. Each agent **filters
inputs by file extension** so each only sees its kind of artefact.

> **Pedagogical point:** the prompt literally hands the LLM the
> deterministic hits and says *"refine, explain, or extend — do not
> duplicate"*. That is P4 "augmentation + constraint" and P3 "RAG context"
> in one move. The LLM's job is **refinement, not invention.**

**Step 5 — Decision agent** ([decision_agent.py](../agents/decision_agent.py)).
`DecisionAgent.run([code_result, log_result, dep_result], scenario_name)`:
1. Concatenate all findings.
2. **Memory recall (E.2):** if a store is wired, `memory.recall_similar(
   rule_ids, k, exclude_scenario, mode="defense")` returns the K most
   similar past incidents (by **Jaccard overlap** of rule-id sets). They
   are rendered into the prompt's `[memory]` slot as few-shot precedent.
3. Call the LLM (the `reasoning` config — a heavier model by design),
   parse a `Decision` JSON: asset categories, recommended tier, confidence,
   justification. The top-severity findings get tagged with the primary
   asset category.

**Step 6 — Build the guard up-front** (so it can also gate every action
step). Construct the `HaJudge` (if `guard.ha_judge_enabled`) and the
`SecurityGuard`, then build a per-step `GuardAdapter` via
`build_step_guard(guard, inputs)`.

**Step 7 — Action engine** ([action_generator.py](../agents/action_generator.py)
→ [action_engine/](../agents/action_engine/)).
`ActionGenerator(..., guard=step_guard).generate(decision, vulnerable_code)`:
1. `build_plan(decision, ctx)` turns the decision's findings into an
   `ActionPlan` (see §10).
2. The `ActionExecutor` walks the plan (dry-run by default), producing an
   `ActionReport`.
3. A legacy `Action` view is returned for the guard + run-log.

**Step 8 — Security guard** ([security_guard.py](../agents/security_guard.py)).
`guard.check(action, objective, inputs)` evaluates the **four paper-1
properties** (see §11) and returns a `GuardVerdict`. Then
`guard.check_trajectory(plan.steps, inputs)` evaluates the
**compositional + temporal** properties over the whole step sequence.

**Step 9 — Persist.** Build the `record` dict (decision, action,
guard_verdict, trajectory_verdict, findings, consulted_memory, committed),
**record a signed `Incident`** to the store (`_record_incident`), write
`memory/defense_<scenario>.json` (or `last_run_defense.json`), finalise the
run-log. The function returns `record`.

### 9.1 The defense data-flow chain (one line)

```
files → Input[] → (static + LLM + merge) → Finding[] → Decision
      → ActionPlan → ActionReport → GuardVerdict → record(JSON) + incident(DB) + run_log/
```

---

## 10. The action engine in depth

This is the most sophisticated subsystem. Folder:
[`agents/action_engine/`](../agents/action_engine/).

### 10.1 Playbooks ([playbooks.py](../agents/action_engine/playbooks.py))

A **playbook** is a typed sequence of `StepTemplate`s keyed to a rule-id
(exact string or regex). A `StepTemplate` carries a `StepKind`, a `tool`
name, a `params_fn` closure `(finding, ctx) -> params` (pulls the suspect
IP, affected file, vehicle id, ECU id out of the finding), a
`severity_min` gate, a `side_effect`, and an optional `rollback_template`.

Specific playbooks exist for high-value ids, e.g.:
- `LOG-CAN-02` → `runtime.safe_mode` (CONTAIN) + `network.isolate_node`
  (CONTAIN) + `notify.driver` (NOTIFY) + `runtime.snapshot` (AUDIT).
- `CODE-003` (hard-coded secret) → `secrets.rotate` + `code.propose_patch`
  + `code.scrub_git_history` runbook + incident.
- `CODE-(001|005|012|020|038)` → real `code.static_scan` + propose patch + incident.
- `TOP-006` → critical incident + secret rotation.

Fallbacks cascade: a **family-generic** playbook (`CODE-.+`, `LOG-.+`,
`TOP-.+`) and finally a **tier-generic** playbook (`soft`/`moderate`/`hard`)
if nothing else fired.

`build_plan(decision, ctx)`:
1. Sort findings by severity (critical first).
2. **Skip findings below `medium`** (don't automate on noise).
3. Look up a playbook per rule-id (specific → family → none).
4. Instantiate each `StepTemplate` whose `severity_min` is met.
5. If nothing fired but a tier was recommended and ≥1 finding is actionable
   → use the tier-generic playbook.
6. **Order steps by `StepKind`** (contain → observe → eradicate → recover
   → notify → audit) and **deduplicate** equivalent steps.
7. Compute the `blast_radius` (max over steps) and return the `ActionPlan`.

### 10.2 The MCP registry & tools ([mcp_registry.py](../agents/action_engine/mcp_registry.py), [mcp_tools.py](../agents/action_engine/mcp_tools.py))

Every tool subclasses `MCPTool` and declares: `name`, `description`,
`domain`, `side_effect`, `idempotent`, `requires_authorization`, a typed
`schema` (`MCPSchemaField` list, validated before the call), and a
`real_binary` (the CLI it wraps). `MCPTool.call()`:
- validates params (returns `failed` on a bad/missing/enum-mismatch param),
- if `dry_run` **or** the real binary is unavailable → `_dry_run()` returns
  a `would-execute` envelope,
- else `_do_call()` runs the real command.

The **~20 tools** span eight domains: `firewall.*` (iptables/netsh/pf),
`network.*` (isolate node), `secrets.*` (rotate/revoke), `code.*`
(**real `bandit`/`semgrep`** scan, propose patch, scrub-history runbook),
`runtime.*` (restart/snapshot/safe-mode), `notify.*` (webhook/incident/
email/driver), `observe.*` (endpoint/log-tail/port-closed — used by
pre/post conditions), `kb.*` (CVE lookup via NVD).

`MCPRegistry` registers tools, routes `call()`, holds a **dry-run flag**, an
optional **authorization hook** (for destructive tools in live mode), and an
**audit log** (`_safe_for_audit` redacts password/secret/token/apikey).

### 10.3 The executor — the loop that makes it agentic ([executor.py](../agents/action_engine/executor.py))

For each step in the plan:
1. **Evaluate pre-conditions** (via `observe.*` tools). Fail → SKIP the step.
2. **Per-step guard** (`GuardAdapter.check(step)`). Refuse → mark REFUSED;
   if the step was a `CONTAIN`, abort the plan.
3. **Invoke the tool with retry** (back-off on transient failure).
4. **Evaluate post-conditions.** Fail → `VERIFY_FAILED` → rollback.
5. **Rollback on hard failure** (LIFO over completed steps, running each
   step's `rollback_steps`).
6. Record every event in the report's `audit_log`.

Final `PlanStatus` is `COMPLETED / PARTIAL / FAILED / REFUSED` depending on
the step statuses.

**Default is safe:** `dry_run=True`, so no destructive command ever runs
unless a developer flips the switch *and* a real binary is present *and*
the guard allows it.

---

## 11. The guards & the paper-1 security model

P1's thesis: *instruction-following is not security*. An agent can follow
instructions perfectly and still be exploited, depending on **context**.
So a separate, mechanical, auditable guard evaluates context.

### 11.1 The four properties — `SecurityGuard.check()` ([security_guard.py](../agents/security_guard.py))

1. **Task alignment** — is `objective` in the allowed set `O`
   (`config.security.allowed_objectives`)?
2. **Action alignment** — is the action's `kind` compatible with the
   objective? Floor = static map `_ACTION_OBJECTIVES`. If an **H_a judge**
   is wired, `action_ok = static_ok AND judge_ok` — the judge can only
   **tighten**, never loosen.
3. **Source authorization** — did an *authenticated* source cause a
   *privileged* action? A privileged action (`patch_code/isolate_node/
   block_ip`) driven only by external inputs is rejected.
4. **Data isolation** — does the action write only to *trusted
   destinations*?

### 11.2 The H_a oracle — [`ha_judge.py`](../agents/ha_judge.py)

P1 §6–7 found that approximating the **action-alignment oracle `H_a`**
("does action *a* serve objective *o* in this context?") cut attack-success
by 86–88%. `HaJudge` is a **separate LLM call** with one job: return
`{"serves": bool, "reason": str}`. Keeping it separate means a prompt
injection that subverts a scanner still has to fool an independent judge.
It **caches** verdicts by `(action, objective, context)` so the per-step
guard doesn't make dozens of identical (paid) calls. With the stub it is a
deterministic heuristic; with a real model it genuinely reasons (and can be
*stricter* than the stub — see §20).

### 11.3 Trajectory checks — `SecurityGuard.check_trajectory()`

P1 §7: security is **compositional** and **temporal**. Each step can be
fine yet the *combination* or *order* be unsafe.
- **Compositional (F.3):** flags read-sensitive→external-egress (exfil
  chain), destructive-without-forensics, destructive-without-notify.
- **Temporal (F.4):** flags TOCTOU (a contain/eradicate step with a
  pre-check but no post re-check) and the memory-poisoning pattern
  (a destructive step in a plan influenced by a `memory`-sourced input).

### 11.4 Per-step enforcement (C.4) — `build_step_guard()` in [pipeline.py](../pipeline.py)

The executor calls the guard on **every** tool call. `build_step_guard`
translates an `ActionStep` into the guard's vocabulary (legacy kind →
objective + trusted destination) so the four properties + H_a run per step,
not just on the final action.

### 11.5 The attack-side mirror — `EthicsGuard` ([ethics_guard.py](../agents/attack/ethics_guard.py))

`check_plan(scenario, target_asset)` enforces **scope** (scenario in
`attack.allowed_scenarios`) and **target** (asset in
`attack.authorized_targets`, or a `--authorize-target` CLI override, or
`allow_all_in_dev`). `filter_scripts()` scans generated scripts for
**destructive patterns** (`rm -rf /`, fork bomb, `dd if=/dev/zero`,
`mkfs`, …) and **redacts** any match.

### 11.6 Delegation (F.5) — `BaseAgent.delegate()`

When agent A spawns agent B, B **inherits A's objective but NOT A's trusted
source set** (it starts empty unless sources are explicitly granted). This
prevents authority being laundered through delegation.

---

## 12. The adaptive memory subsystem

File: [`agents/memory_store.py`](../agents/memory_store.py). This closes
P5's adaptive-learning loop.

- **Store (E.1):** a single SQLite DB `memory/incidents.db` (stdlib only,
  no new dependency). One row per past defense/attack outcome.
- **Recall (E.2):** `recall_similar(rule_ids, k)` ranks past incidents by
  **Jaccard overlap** of their rule-id sets and returns the top-K. The
  Decision Agent injects them as few-shot precedent.
- **Anti-poisoning (E.3):** every write is **HMAC-signed**
  (`memory.signing_key_env`) and tagged with its source. `recall_similar`
  **drops any row** whose signature fails to re-verify *or* whose source is
  not authenticated. `verify_all()` is the "has my memory been poisoned?"
  integrity sweep. This is P1's source-authorization applied to the memory
  channel and P2's poison-path defence.

Wired in `pipeline.build_memory()`; recording is done by
`_record_incident()` (never crashes a run — a memory failure is a flag, not
an exception). Disable with `memory.enabled: false`.

---

## 13. The ATTACK pipeline, step by step

Function: `run_attack_pipeline(...)` in [`pipeline.py`](../pipeline.py). It
is the structural mirror of defense.

1. **A0 — Read the scenario/hint.** `_read_scenario()` resolves a file
   path, a literal string, or a per-example default. This is the **damage
   scenario** (P2 victim-modelling).
2. **A1 — System info discovery** ([system_info_discovery.py](../agents/attack/system_info_discovery.py)).
   Builds the `SystemInstance` graph **deterministically** from the YAML
   (external actors, safety actors, notes about exposure/binds/world-read).
   The LLM call only adds "notes". **Passive recon only — no packets sent.**
3. **A2 — Source-code exploiter** ([source_code_exploiter.py](../agents/attack/source_code_exploiter.py)).
   Reuses `scan_code_static` for the same hits, then asks the LLM to turn
   each into an **exploit plan** (payload, CWE/rule, which P1 property it
   violates, expected effect). Same static-first shape as the defense
   scanner — only the framing differs.
4. **A3 — Deployment exploiter** ([deployment_exploiter.py](../agents/attack/deployment_exploiter.py)).
   Runs `scan_deployment_static` **plus** `_enumerate_paths()`, which emits
   an **`ATK-PATH`** finding for every `external→write` edge ("poison") and
   every `external→respond` edge ("trigger").
5. **A4 — Attack orchestrator** ([attack_orchestrator.py](../agents/attack/attack_orchestrator.py)).
   Aggregates exploiter findings + the instance + the scenario, and chooses
   1–3 findings to chain into an `AttackPlan` (target asset, poison path,
   trigger path, confidence). Falls back to a severity heuristic if the LLM
   JSON won't parse.
6. **A5 — Ethics guard.** `check_plan(scenario, target_asset)` — scope +
   target gating (§11.5). If refused, **no scripts are generated.**
7. **A6 — Attack generator** ([attack_generator.py](../agents/attack/attack_generator.py)).
   For each chosen finding, emit one `AttackScript`. Common rule-ids have
   **hard-coded benign templates** (`_TEMPLATES`: CODE-001 shell probe,
   CODE-005 pickle RCE, CODE-012 SQLi probe, CODE-020 JWT-none, TOP-002
   memory-poison message, TOP-008 A2A fear-injection, LOG-CAN-02 `cansend`
   frame, …) that touch a benign canary (`/tmp/atk_canary`). Anything else
   → an LLM fallback constrained to a benign canary. Then `filter_scripts`
   redacts any destructive pattern.
8. **A7 — Persist.** Same shape as defense; writes
   `memory/attack_<scenario>.json` and one file per script under
   `run_logs/<run>/scripts/`.

---

## 14. Run logging & console verbosity

### 14.1 `RunLogger` ([run_logger.py](../run_logger.py))

Every run creates `run_logs/<timestamp>_<mode>_<scenario>/` containing:
`00_meta.json`, `01_inputs.json`, `02_static_<scanner>.json`,
`0N_<agent>_prompt.txt` / `_response.txt` / `_findings.json`,
`ZZ_decision.json` / `_action.json` / `_guard.json` (defense) or
`_instance.json` / `_plan.json` / `_ethics.json` (attack),
`scripts/` (attack), a single-line `_trace.log`, and a human-readable
`_summary.md`. `_latest_defense.txt` / `_latest_attack.txt` point at the
newest run.

### 14.2 `Console` ([tools/log.py](../tools/log.py))

Diagnostics go to **stderr**; results (summary tables, record JSON) go to
**stdout** — so `python pipeline.py … > out.json` is clean. Two dials:
- `verbose` (default on): section headers, per-step finding ids, the
  **LLM-client banner** (tells you if you're really on gpt-4o or fell back
  to stub), decision, guard verdict, trajectory.
- `debug` (`-v`): timings, token estimates, static-vs-LLM split, recalled
  memory, per-action-step status, and **truncated previews of every prompt
  and LLM response**. `-q` silences everything but the stdout result.

---

## 15. The static evaluation harness

File: [`evaluate.py`](../evaluate.py); ground truth in
[`examples/labels.yaml`](../examples/labels.yaml). It scores the
**deterministic static analyzer** against labelled scenarios **without
running anything dynamically** (true to the static-first constraint).

Run: `python evaluate.py` (writes `memory/eval_report.md`), `--strict`
(non-zero exit on any miss/FP). It produces four artefacts:
1. **Detection recall (D.4):** per scenario, of the must-have rule-ids, how
   many the static floor surfaces (mirrors the regression test).
2. **False-positive rate (D.4):** measured **only on the clean negative
   controls**, where the exhaustive ground truth is "zero findings".
3. **Property-violation table (D.5):** each finding → the P1 property it
   implicates → the P2 asset it threatens.
4. **Asset × scenario × skill scoreboard (G.4):** touched assets → implied
   P5 tier → candidate defense skills.

> **Why no Mean-Time-To-Detect?** MTTD needs a live timeline; a static
> analyzer has no runtime. It is reported as N/A **by design** — the
> harness measures static *coverage* instead.

---

## 16. Configuration reference

File: [`config.yaml`](../config.yaml). Every section:

| Section | Purpose |
|---------|---------|
| `llm_configs` | The `default` and `reasoning` LLM slots (provider, model, temperature, max_tokens, token_env). The decision agent + attack orchestrator use `reasoning`; everything else uses `default`. |
| `agent_configs` | Per-agent `llm` (which slot) + `objective` string (the P1 `H_p` goal the guard enforces). |
| `security` | `allowed_objectives` (set O), `authenticated_sources` (S_auth), `trusted_destinations`. Consumed by `SecurityGuard`. |
| `response_tiers` | Confidence thresholds for soft/moderate/hard (P5). |
| `memory` | `enabled`, `db_file`, `recall_k`, `writer_identity`, `reject_unverified`, `signing_key_env`, `dev_signing_key`. |
| `guard` | `ha_judge_enabled` (F.1), `per_step_enabled` (C.4), `max_prompt_tokens` (A.4). |
| `attack` | `allow_all_in_dev`, `allowed_scenarios`, `authorized_targets` — consumed by `EthicsGuard`. |
| `paths` | `rules_dir`, `examples_dir`, `memory_dir`, `prompts_dir`. |
| `defaults` | Single-run defaults for `--log` / `--deployment`. |
| `example_sets` | The named scenario sets (`small/medium/large/juliet`) used by `--example`. |

### 16.1 The CLI

```
python pipeline.py [--mode defense|attack|both]
                   [--example small|medium|large|all]   # batch
                   [--code PATH] [--log PATH] [--deployment PATH] [--scenario PATH|STR]
                   [--authorize-target T]   # extra EthicsGuard target
                   [-v | --verbose]         # debug diagnostics
                   [-q | --quiet]           # only the result
```
If `--example` is given (or no `--code`), it runs the **batch**; otherwise a
**single run**. Defense needs `--log`; attack needs `--scenario`.

---

## 17. The complete input → output chain

### 17.1 Inputs the system accepts
- **Source code:** `.py`, `.c`, `.cpp`, `.h` (single file or a directory,
  recursively collected by `_collect_code_files`, `__pycache__` skipped).
- **Logs:** `.log` / `.txt` (defense only).
- **Deployment:** a YAML graph of `actors`, `datasources`, `edges`.
- **Scenario/hint:** a `.txt` file or literal string (attack only).
- **The operator prompt:** an authenticated `Input` the pipeline injects.

### 17.2 What flows between stages (the typed hand-offs)

| From → To | Record on the wire |
|-----------|--------------------|
| files → scanners | `Input[]` (provenance-tagged) |
| scanner → decision | `Finding[]` (static ⊕ LLM, merged) |
| decision → action engine | `Decision` (+ memory few-shot) |
| action engine → pipeline | `ActionReport` (+ legacy `Action`) |
| any step → guard | `(Action, objective, inputs)` → `GuardVerdict` |
| plan → trajectory check | `ActionStep[]` → `TrajectoryVerdict` |
| everything → run logger | prompt + response + structured record |

### 17.3 Outputs the system produces
- `memory/last_run_<mode>.json` — the most recent single run's full record.
- `memory/<mode>_<scenario>.json` — per-scenario record in a batch.
- `memory/batch_<mode>_<kind>.json` — the batch summary table.
- `memory/incidents.db` — the signed cross-run learning store.
- `memory/eval_report.md` — the static-evaluation report.
- `run_logs/<run>/…` — the full per-step debug trace (+ `scripts/` for attack).
- **stdout:** the summary tables / record JSON. **stderr:** diagnostics.

---

## 18. Testing

Three layers (run in order):

```bash
python verify.py                 # 30-second offline smoke test → 6/6 checks
python -m pytest tests/          # full suite (~138 tests)
python evaluate.py               # static detection/FP scoreboard
```

Both `verify.py` and the suite **force the offline stub**
(`CYBERLLM_FORCE_STUB=1`, set autouse in `tests/conftest.py`) so they never
hit the network or cost tokens, regardless of `config.yaml`'s provider.

What the test files assert:
- `test_static_analyzer.py` — every rule fires on a positive snippet and is
  silent on a clean one.
- `test_rules_and_parsing.py` — YAML loads, ids unique, regexes compile.
- `test_guards.py` — the four properties + EthicsGuard scope/redaction.
- `test_pipeline_integration.py` — full defense + attack end-to-end.
- `test_scenario_regression.py` — must-have rule-ids per scenario triple.
- `test_action_engine.py` — registry, playbooks, executor, generator.
- `test_memory_store.py` / `test_memory_pipeline.py` — recall, HMAC tamper
  detection, unauthenticated-write refusal, the loop closing end-to-end.
- `test_ha_judge_and_trajectory.py` — H_a tightening + compositional/temporal.
- `test_provenance_and_delegation.py` — mandatory provenance + delegation.
- `test_token_budget.py` — token estimate + every provider's fallback.
- `test_evaluation.py` — the static eval harness.

> **Environment note:** on this machine the global Python has
> `PYTHONNOUSERSITE=1`, so deps live in the user site. If you hit
> `No module named 'yaml'`, run with
> `PYTHONPATH=C:/Users/Oussama_Jeddou/AppData/Roaming/Python/Python311/site-packages`
> or `pip install --user pyyaml pytest`.

---

## 19. How to extend the system

- **Add a detection rule:** append to a `rules/*.yaml`. A *code* rule with
  a `pattern` works automatically. A *log/topology* rule with non-trivial
  logic also needs an `if rule_id in by_id:` block in
  `tools/static_analyzer.py`.
- **Add a scenario:** add an entry to `config.yaml → example_sets`.
- **Add a response playbook:** add a `_book(...)` in
  `action_engine/playbooks.py` keyed by rule-id, listing `StepTemplate`s.
- **Add an MCP tool:** subclass `MCPTool` in
  `action_engine/mcp_tools.py`, declare its schema/side-effect, add it to
  `default_toolset()`.
- **Add an attack template:** add an entry to `_TEMPLATES` in
  `attack_generator.py`.
- **Add an LLM provider:** add a branch in `LLMClient.create` and a
  subclass implementing `complete()`.
- **Add an agent:** subclass `BaseAgent`, give it a `PROMPT` with
  `[placeholders]`, implement `run()`, and wire it into `pipeline.py`.

Golden rule: **never let the LLM remove a static finding.** Keep the
static-first invariant intact.

---

## 20. A fully worked example

Run, against the real Azure gpt-4o:

```bash
python pipeline.py -v \
  --code examples/small/02_can_gateway.py \
  --log examples/logs/03_can_injection.log \
  --deployment examples/deployments/03_complex_sdv.yaml
```

What happens, in order (this is a real trace):

1. **Banner:** `LLM clients: default=AzureOpenAILLM<gpt-4o> · reasoning=AzureOpenAILLM<gpt-4o>`.
2. **Source-code scanner:** static regex finds CODE-001/003/005/006…; the
   LLM adds a couple more → 11 findings.
3. **Log analyzer:** `scan_log_static` flags `LOG-CAN-02` (critical) → 4 findings.
4. **Deployment scanner:** graph checks flag `TOP-001/002/007…` → 11 findings.
5. **Decision agent** (reasoning model): recalls 0 past incidents (empty
   DB), returns `tier=hard, confidence=0.90`, assets = `Life and Bodily
   Health, Privacy and Personal Data, Material and Economic Resources`.
6. **Action engine:** the `LOG-CAN-02` playbook fires → safe-mode + isolate
   + driver-notify + snapshot; the plan executes in dry-run.
7. **Security guard:** evaluates the four properties; with the **real**
   H_a judge it may *refuse* the final `isolate_node` if it judges the
   action doesn't serve the objective in the (thin) context it's given —
   that's the judge being stricter than the stub (it can only tighten).
8. **Persist:** a signed incident is written; `memory/last_run_defense.json`
   and `run_logs/<run>/` are produced.

> **Lesson for newcomers:** the same run with the **stub** LLM allows the
> action; with **gpt-4o** the H_a judge reasons and can refuse. Behaviour
> that depends on the model lives behind the guard's H_a check — if you
> want the strict judge to be better-informed, enrich the `context` string
> passed in `build_step_guard()` / the final `guard.check(..., context=…)`.

---

## 21. Glossary

- **Static-first** — run deterministic detection before any LLM; the LLM
  only refines. The project's prime directive.
- **Provenance / trust level** — the `source` + `trust_level` tag on every
  `Input`; the basis of P1 source-authorization.
- **Finding** — one detected issue, the universal currency.
- **Tier** (`soft/moderate/hard/none`) — P5 response intensity, chosen by
  the decision agent from confidence + severity.
- **Asset category** — P2 human-centric taxonomy (Life and Bodily Health,
  Privacy and Personal Data, Material and Economic Resources, Mental and
  Emotional Well-Being, Knowledge/Thought/Belief, Reputation and Dignity,
  Social Relationships and Trust).
- **Poison path / trigger path** — P2: how a payload *reaches* the victim
  vs. what makes the victim *consume* it.
- **The four properties** (P1) — task alignment, action alignment, source
  authorization, data isolation.
- **H_a** — P1's action-alignment oracle: "does action *a* serve objective
  *o* in this context?" Implemented as a separate LLM judge.
- **Playbook** — a typed sequence of MCP-tool steps keyed to a rule-id.
- **Blast radius** — how far an action reaches: local < service < node <
  network < fleet.
- **Dry-run** — the action engine's safe default; no destructive command
  runs.
- **Stub** — the deterministic offline LLM that keeps the pipeline runnable
  without credentials.

---

### Suggested reading order for the code itself

1. `pipeline.py` (`run_defense_pipeline` first) — the spine.
2. `agents/base_agent.py` — the agent contract + `Input`/`Finding`.
3. `tools/static_analyzer.py` — the deterministic floor.
4. One scanner: `agents/source_code_scanner.py`.
5. `agents/decision_agent.py` → `agents/action_engine/playbooks.py` →
   `executor.py`.
6. `agents/security_guard.py` + `agents/ha_judge.py`.
7. `agents/memory_store.py`.
8. The attack mirror: `agents/attack/attack_orchestrator.py` then the rest
   of `agents/attack/`.
9. `evaluate.py`, `run_logger.py`, `llm_client.py`.

Companion docs: [`README.md`](../README.md) (the narrative walkthrough),
[`docs/AGENTIC_WORK.md`](AGENTIC_WORK.md) (why it's agentic),
[`docs/LEARNING_AND_GUARD_HARDENING.md`](LEARNING_AND_GUARD_HARDENING.md)
(memory + guards deep-dive), and
[`improvements_and_exploration.md`](../improvements_and_exploration.md)
(the forward roadmap with status).
```
