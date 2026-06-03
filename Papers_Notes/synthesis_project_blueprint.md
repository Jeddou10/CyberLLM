# Synthesis — Mapping the 5 Papers to the CyberLLM Project Blueprint

This document is the bridge between the five paper notes and the
`../CyberLLM/` implementation. It answers a single question:

> **Where does each design decision in `CyberLLM/` come from, and what
> paper backs it?**

---

## 1. Project topic (recap from `image.png`)

> *LLM Agents for Cybersecurity — defense (and attack) agents that
> autonomously analyze logs, source code, and configurations to detect
> vulnerabilities, run risk assessment, and trigger automated responses.
> Primary domain: automotive (but not limited to).*

Required technical pieces:
- LLMs over text (hints, logs, source code, configs).
- MCPs for external scan / analysis / defense tools or traffic capture.
- Agent skills for different defense **and** attack strategies.
- *(Optional)* persistent agent memory.

---

## 2. Diagram-block ↔ Paper-source mapping

| Diagram block                | Paper(s) that drive the design                                                  | What we take                                                                                                  |
|------------------------------|---------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| **Metamodel**                | Paper 3 (TUM)                                                                   | EMF / OCL-style metamodel — we use a lightweight YAML schema for "topology + signals + roles".                |
| **Instance creation**        | Paper 3 (TUM) — Prompt Construct 3                                              | LLM takes user description → structured system instance.                                                      |
| **Constraint modeling**      | Paper 3 (TUM) — Prompt Construct 4; Paper 1 — security properties               | Rules are encoded in YAML + Python checkers; security properties are the *meta-constraints* every action must respect. |
| **Rules / Policies**         | Paper 3 (TUM) OCL rules; Paper 1 attack catalogue                               | `rules/example_rules.yaml` — temporal event-chain rules + property rules.                                     |
| **Events**                   | Paper 5 (edge defense); Paper 3 (event chains)                                  | Incoming observations (log lines, alerts, traffic) parsed by detection agents.                                |
| **Decision agent**           | Paper 4 (Härer) execution engine; Paper 5 orchestration layer                   | Stack-based orchestrator that selects skills based on confidence + properties.                                |
| **Action generator**         | Paper 3 Prompt Construct 2b (auto-correction); Paper 5 response tiers           | Emits soft/moderate/hard response actions, or proposes a code-level fix.                                      |
| **Target system**            | Paper 3 (SDV testbench, CARLA, digital.auto)                                    | Abstract `TargetAdapter` interface — we stub it for the demo; you swap in CARLA/SDV later.                    |
| **Source-code scanner**      | Paper 3 (VSS/CAN extraction); Paper 1 (attack examples for code)                | LLM + RAG over rules + code → findings tagged by asset (paper 2).                                             |
| **Log analyzer**             | Paper 5 (detection agent role); Paper 4 (Network-Security-Agent test case)      | LLM reads log lines, classifies anomalies, references rule violations.                                        |
| **Deployment scanner**       | Paper 3 (topology workflow + OCL); Paper 2 (A2A surface)                        | LLM reads YAML/JSON config, builds actor/datasource graph (paper 2), checks against OCL-style rules.          |

---

## 3. Cross-cutting modules (not in the diagram, but mandatory)

| Module                      | Why it's needed                              | Source paper                                                  |
|-----------------------------|----------------------------------------------|---------------------------------------------------------------|
| **MCP / tools layer**       | Project assignment requires it.              | Paper 4 (execution functions); Paper 5 (response agents).     |
| **Security guard**          | Wrap every action with the four checks.       | Paper 1 (oracles + properties).                               |
| **Threat model registry**   | Tag every finding by asset + path.            | Paper 2 (AgentHeLLM taxonomy).                                |
| **RAG over rules / CVEs**   | Avoid hallucinated signals.                  | Paper 3 (Retrieve-and-Re-Rank with MiniLM).                   |
| **Agent memory (optional)** | Persist confirmed incidents and lessons.     | Paper 5 (adaptive learning loop); Paper 1 (memory-poisoning awareness). |
| **Attack orchestrator**     | "Both attack simulation and defense" piece.  | Paper 2 (poison + trigger paths); Paper 1 (attack catalogue). |

---

## 4. What the first pipeline (`CyberLLM/pipeline.py`) actually does

The first pipeline is **deliberately narrow** — it instantiates the
diagram end-to-end on **one** scenario, so every block is exercised and
testable, then we add scenarios incrementally.

Scenario chosen: *"A vehicle ECU receives a configuration update and a
batch of CAN logs; the defense agents must decide whether the update is
safe to deploy, whether any of the log events indicate an attack, and
generate a response."*

Steps in the first pipeline:

```
1.  Load: rules/, sample log, sample source code, sample deployment config.
2.  Build the system instance from the deployment config (paper 3 Prompt 3).
3.  Run three scanner agents in parallel (papers 4 + 5):
      - SourceCodeScannerAgent      -- finds insecure patterns in code.
      - LogAnalyzerAgent            -- classifies anomalies in CAN log.
      - DeploymentScannerAgent      -- checks topology vs rules.
4.  Aggregate findings into a structured "events" list (paper 3 event chain).
5.  DecisionAgent reasons over (events, rules, system instance):
      - tags findings with asset category (paper 2).
      - checks security properties (paper 1) for any proposed action.
6.  ActionGenerator picks soft / moderate / hard response (paper 5),
    or proposes a code fix (paper 3 Prompt 2b).
7.  SecurityGuard validates the proposed action against the four
    properties; only safe actions are committed to the (stub) target.
8.  All steps + verdicts are logged to memory/ for the optional
    adaptive-learning loop (paper 5 step 6).
```

This makes it easy to talk to a supervisor: *"Block X of the diagram
corresponds to file Y, driven by paper Z."*

---

## 5. Concrete near-term roadmap

(Detailed version lives in `../CyberLLM/improvements_and_exploration.md`.)

- **Phase 1** (the first pipeline — already shipped):
  Skeleton orchestrator, stub LLM client, hand-written rule examples,
  one attack scenario, one defense response, security-guard skeleton.
- **Phase 2:** Plug in a real LLM (Ollama LLaMA-3.x or OpenAI/Anthropic
  API). Add real RAG over a small CVE / rules corpus.
- **Phase 3:** Add MCP servers wrapping `nmap`, `tcpdump`, `bandit`,
  `semgrep`, and a CAN replay tool.
- **Phase 4:** Add attack agents (replay AgentHeLLM-style attack paths
  on the target). Both sides instrumented so we can measure detection
  rate vs false-positive rate.
- **Phase 5:** Persistent memory + adaptive learning loop; evaluation
  on CyberMetric, AgentDojo, CAR-bench.

---

## 6. Reading dependencies

If you want to revisit the papers selectively:

- **To implement the executor** → re-read paper 4 (Härer).
- **To extend rules / event chains** → re-read paper 3 (TUM).
- **To add an attack agent / threat model** → re-read paper 2 (BMW/TUM).
- **To harden the defense agent itself** → re-read paper 1 (UCSC/UCB).
- **To explain the high-level shape to a non-technical reader** →
  re-read paper 5 (Collins).
