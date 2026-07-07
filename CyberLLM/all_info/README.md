# CyberLLM — Complete Code Documentation (`all_info`)

> A friendly, exhaustive, block-by-block and line-by-line explanation of the
> **entire** CyberLLM codebase. Read this index first to understand the shape
> of the program, then jump into the per-file explainers linked below. Every
> file gets its own document; every document explains *what* each block does,
> *why* it is designed that way, and *what would change* if it were different.

If you can read this folder end to end, you can answer essentially any
question about how CyberLLM works and why.

---

## 1. What is CyberLLM, in one paragraph?

CyberLLM is a **multi-agent LLM cybersecurity system**. It has two mirror
pipelines:

- **DEFENSE (blue team):** read source code, runtime logs, and a deployment
  topology → detect vulnerabilities/anomalies → decide a *response tier* →
  build a **guarded, dry-run-capable remediation plan** using real MCP tools →
  remember the outcome.
- **ATTACK (red team):** the same skeleton run "in reverse" — discover system
  information, find exploitable weaknesses in code and topology, plan an
  attack, and (subject to an ethics/scope guard) generate proof-of-concept
  artifacts.

Its guiding philosophy is **static-first**: it analyzes code as *text and
structure* (regex + AST tools like bandit/semgrep + an LLM reasoning pass) and
**never executes** the code under test. Actions taken in response (firewall
rules, key rotation, packet capture, etc.) default to **dry-run** so nothing
destructive happens unless explicitly enabled.

---

## 2. The research foundation (the "5 papers")

The code comments refer to five papers by shorthand. You will see these
references throughout, so keep this table handy:

| Ref | Short name | What CyberLLM borrows from it |
|-----|------------|-------------------------------|
| **P1** | Contextual security | The **four security properties** (confidentiality, integrity, availability, authorization) and the **H_a oracle** — a guard that asks *"is the harm of this action acceptable in context?"* before allowing it. |
| **P2** | AgentHeLLM | An **asset taxonomy** (categorize what's at risk) and an **actor/datasource interaction graph** (who reads/writes/communicates with what), plus poison/trigger attack-path ideas. |
| **P3** | Rules-as-context / OCL | Feed detection **rules into the prompt as context**, and check the deployment topology against **constraint rules** (OCL-style graph checks). |
| **P4** | Härer | A **schema-driven agent template**: every agent has an id, an objective, a constrained prompt, and structured (JSON) output. |
| **P5** | Layered / tiered / adaptive | **Layered detection**, a **tiered response** (do nothing → soft → moderate → hard), and an **adaptive re-planning loop** that escalates when an action is refused or fails. |

> **What does "H_a" mean?** `H_a` is the **harm-acceptability** judgment from
> P1: a small oracle (`agents/ha_judge.py`) that decides whether the *harm* a
> proposed action could cause is acceptable given the context. The security
> guard uses it to allow or refuse steps and trajectories.

---

## 3. How a request flows through the system

### Defense (the common case)

```
                       ┌─────────────────────────────────────────────┐
 code / logs /         │              pipeline.run_defense_pipeline    │
 deployment  ─────────▶│                                               │
                       │  1. load config + rules                       │
                       │  2. build inputs (each tagged with provenance)│
                       │  3. source-code scanner ─┐                    │
                       │  4. log analyzer          ├─ findings          │
                       │  5. deployment scanner ───┘                    │
                       │  6. decision agent  → response tier (P5)      │
                       │  7. action generator → ActionPlan (playbooks) │
                       │  8. security guard  → allow/refuse (P1 + H_a) │
                       │     ↑ adaptive re-planning loop (P5)          │
                       │  9. enrich findings → detailed records        │
                       │ 10. persist to signed memory                  │
                       └─────────────────────────────────────────────┘
                                          │
                                          ▼
              detailed result record (findings, decision, action, guard)
```

Each detection stage uses the same three-layer pattern:

```
   regex floor   ⊕   bandit/semgrep (AST)   ⊕   LLM refinement
   (always on)       (extra layer, optional)    (optional / gated by use_llm)
                         └──────── merged: deterministic layers win ────────┘
```

### Two ways to run it

- **Command line:** `python pipeline.py …` (defense, attack, or both).
- **Web UI:** `python server.py` serves a single-page app that runs the *real*
  defense pipeline on pasted code, with actions forced to dry-run.

---

## 4. Directory map & per-file documentation

Each link below is a full explainer for that file. Files are grouped by role.

### 4.1 Top-level orchestration & entry points

| File | Lines | What it is | Explainer |
|------|------:|------------|-----------|
| `pipeline.py` | 1206 | The orchestrator: defense & attack pipelines, re-planning loop, finding enrichment, CLI. | [pipeline.md](pipeline.md) |
| `server.py` | 253 | Local web-UI server (stdlib `http.server`); runs the real pipeline on pasted code, dry-run forced. | [server.md](server.md) |
| `llm_client.py` | 510 | LLM provider abstraction (stub/azure/github/openai/anthropic/ollama) + graceful fallback. | [llm_client.md](llm_client.md) |
| `run_logger.py` | 385 | Writes the detailed per-step `run_logs/` trace (`_summary.md`, `_trace.log`, scripts). | [run_logger.md](run_logger.md) |
| `evaluate.py` | 373 | Static evaluation harness — recall, false-positive rate, scoreboard. | [evaluate.md](evaluate.md) |
| `verify.py` | 181 | Hermetic end-to-end smoke check (sets the env kill-switches). | [verify.md](verify.md) |
| `run_blind_tests.py` | 46 | Runs the pipeline on "blind" examples for spot-checking. | [run_blind_tests.md](run_blind_tests.md) |

### 4.2 The detection tools (`tools/`) — static-first core

| File | Lines | What it is | Explainer |
|------|------:|------------|-----------|
| `tools/static_analyzer.py` | 564 | Regex floor + external AST layer (bandit/semgrep) + finding merge/dedup. | [tools/static_analyzer.md](tools/static_analyzer.md) |
| `tools/log.py` | 85 | Console/diagnostic logging helper. | [tools/log.md](tools/log.md) |
| `tools/tokens.py` | 71 | Token-count / budget estimation. | [tools/tokens.md](tools/tokens.md) |
| `tools/mcp_tools.py` | 162 | Legacy `run()`-style real tools (port scan, static analysis, packet capture). | [tools/mcp_tools.md](tools/mcp_tools.md) |
| `tools/__init__.py` | 12 | Package exports. | [tools/__init__.md](tools/__init__.md) |

### 4.3 Defense agents (`agents/`)

| File | Lines | What it is | Explainer |
|------|------:|------------|-----------|
| `agents/base_agent.py` | 168 | The P4 agent template (id, objective, prompt, structured output, provenance). | [agents/base_agent.md](agents/base_agent.md) |
| `agents/source_code_scanner.py` | 110 | Three-layer source-code detection. | [agents/source_code_scanner.md](agents/source_code_scanner.md) |
| `agents/log_analyzer.py` | 81 | Log anomaly detection (static + LLM). | [agents/log_analyzer.md](agents/log_analyzer.md) |
| `agents/deployment_scanner.py` | 97 | Topology graph checks (P2 + P3). | [agents/deployment_scanner.md](agents/deployment_scanner.md) |
| `agents/decision_agent.py` | 218 | Picks the response tier (P5), tags assets (P2), consults memory. | [agents/decision_agent.md](agents/decision_agent.md) |
| `agents/action_generator.py` | 15 | Thin shim to the action engine. | [agents/action_generator.md](agents/action_generator.md) |
| `agents/security_guard.py` | 331 | The P1 four-property guard: `check`, `check_step`, `check_trajectory`. | [agents/security_guard.md](agents/security_guard.md) |
| `agents/ha_judge.py` | 109 | The H_a (harm-acceptable?) oracle, cached, with heuristic fallback. | [agents/ha_judge.md](agents/ha_judge.md) |
| `agents/memory_store.py` | 334 | Signed (HMAC) SQLite memory; cross-session recommendations. | [agents/memory_store.md](agents/memory_store.md) |
| `agents/__init__.py` | 1 | Package marker. | [agents/__init__.md](agents/__init__.md) |

### 4.4 The action engine (`agents/action_engine/`)

| File | Lines | What it is | Explainer |
|------|------:|------------|-----------|
| `action_engine/types.py` | 243 | Dataclasses/enums: `ActionPlan`, `ActionStep`, statuses, reports. | [agents/action_engine/types.md](agents/action_engine/types.md) |
| `action_engine/playbooks.py` | 761 | Remediation playbooks: tier/finding → ordered guarded steps. | [agents/action_engine/playbooks.md](agents/action_engine/playbooks.md) |
| `action_engine/generator.py` | 294 | `ActionGenerator`: findings + tier + playbooks → `ActionPlan`; LLM tool selection. | [agents/action_engine/generator.md](agents/action_engine/generator.md) |
| `action_engine/mcp_registry.py` | 264 | `MCPRegistry` + `MCPTool` base: schema validation, audit, `on_call` hook. | [agents/action_engine/mcp_registry.md](agents/action_engine/mcp_registry.md) |
| `action_engine/mcp_tools.py` | 913 | ~22 real MCP tools (scan/observe/remediate), dry-run by default. | [agents/action_engine/mcp_tools.md](agents/action_engine/mcp_tools.md) |
| `action_engine/executor.py` | 251 | `ActionExecutor`: runs a plan step-by-step (pre/guard/call/post/rollback). | [agents/action_engine/executor.md](agents/action_engine/executor.md) |
| `action_engine/__init__.py` | 60 | Package wiring/exports. | [agents/action_engine/__init__.md](agents/action_engine/__init__.md) |

### 4.5 Attack agents (`agents/attack/`)

| File | Lines | What it is | Explainer |
|------|------:|------------|-----------|
| `attack/system_info_discovery.py` | 114 | Discover system facts (diagram-2 entry node). | [agents/attack/system_info_discovery.md](agents/attack/system_info_discovery.md) |
| `attack/source_code_exploiter.py` | 106 | Find exploitable code weaknesses. | [agents/attack/source_code_exploiter.md](agents/attack/source_code_exploiter.md) |
| `attack/deployment_exploiter.py` | 131 | Find exploitable topology weaknesses. | [agents/attack/deployment_exploiter.md](agents/attack/deployment_exploiter.md) |
| `attack/attack_orchestrator.py` | 145 | Sequence the attack from a goal/scenario. | [agents/attack/attack_orchestrator.md](agents/attack/attack_orchestrator.md) |
| `attack/ethics_guard.py` | 121 | Scope/ethics gate before generating artifacts. | [agents/attack/ethics_guard.md](agents/attack/ethics_guard.md) |
| `attack/attack_generator.py` | 185 | Produce PoC artifacts (template + LLM fallback). | [agents/attack/attack_generator.md](agents/attack/attack_generator.md) |
| `attack/__init__.py` | 22 | Package exports. | [agents/attack/__init__.md](agents/attack/__init__.md) |

### 4.6 Skills, configuration, rules & the web UI

| File | Lines | What it is | Explainer |
|------|------:|------------|-----------|
| `skills/skills.py` | 154 | Reusable agent "skills" helpers. | [skills/skills.md](skills/skills.md) |
| `skills/__init__.py` | 10 | Package exports. | [skills/__init__.md](skills/__init__.md) |
| `config.yaml` | — | All tunables: LLM configs, agent configs, scanners, guard, memory, examples. | [config/config.md](config/config.md) |
| `rules/*.yaml` | — | The detection-rule knowledge base (code/log/topology/attack rules). | [config/rules.md](config/rules.md) |
| `webapp/index.html` | — | The single-page UI (findings, annotated code, decision/guard panels). | [webapp/index.md](webapp/index.md) |

---

## 5. Cross-cutting concepts to keep in mind

- **Provenance / trust levels.** Every `Input` carries a `trust_level`
  (e.g. `authenticated`, `external`). This drives P1 reasoning about whether
  untrusted data can reach a sensitive sink.
- **Findings have a precise shape.** The final, user-facing finding record is
  `{rule_id, severity, title, location, line, detail, …}`. The enrichment that
  builds it lives in `pipeline.py` (`_enrich_finding`).
- **`use_llm` gating.** Each scanner can run its LLM pass or not. The web UI
  turns it off ("Fast" mode) so the offline stub's canned findings never appear
  on real code, and turns it on ("Deep") only when a real LLM is configured.
- **Dry-run everywhere.** The action engine and MCP tools honor a dry-run flag
  (`CYBERLLM_FORCE_DRY_RUN`) so the system can plan and "execute" safely.
- **Determinism for tests.** `CYBERLLM_FORCE_STUB`, `CYBERLLM_FORCE_DRY_RUN`,
  and `CYBERLLM_NO_EXTERNAL_STATIC` make runs reproducible regardless of which
  LLM provider or external binaries are installed.

---

## 6. Walkthrough, benchmark & quiz

- **[full_steps.md](full_steps.md)** — one worked example traced step by step
  through the **defense** pipeline (10 steps) and the **attack** pipeline
  (7 steps), with a "Result now" block after every step.
- **[../benchmark/automotive/README.md](../benchmark/automotive/README.md)** —
  the independent **automotive security benchmark**: 47 ground-truthed
  vulnerabilities across original C/C++/Rust ECU code, runnable from the web
  UI's **Benchmark** tab with coverage/precision/recall/F1 and per-file results.
- **[EXAM_QUESTIONS.md](EXAM_QUESTIONS.md)** — a supervisor-style question bank
  (with answers) covering architecture, each subsystem, design trade-offs, and
  "why did you do it this way?" defenses.

---

*Generated as a complete companion to the source. If a line number in a
per-file doc ever drifts from the code (after edits), trust the code and the
surrounding explanation — the structure and rationale remain accurate.*
