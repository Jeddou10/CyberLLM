# CyberLLM — LLM Agents for Cybersecurity

> Defense **and** attack LLM agents that autonomously analyse logs,
> source code, and system configurations to identify vulnerabilities,
> generate actionable insights, and — in attack mode — produce
> proof-of-concept exploit scripts for authorised red-team exercises.
> Primary domain: automotive. Generalises to any edge / cloud system
> that can be described as an actor / datasource graph.

This README is the **definitive walkthrough** of what the agent does
at every step, *why* that step exists, and *which of the five
reference papers* the design choice comes from. Read it linearly —
the order mirrors the order in which the code runs.

---

## 0. Project brief (verbatim from the supervisor)

> *"Defense agents support cybersecurity by autonomously analysing
> diverse data sources — logs, source code, system configurations —
> to identify vulnerabilities, detect anomalies, and generate
> actionable insights. Both attack simulation and defense by
> reasoning over complex system behaviours, enabling threat
> detection, risk assessment, and automated response can be taken
> into account. By transforming unstructured security data into
> structured knowledge, LLM agents enhance situational awareness and
> strengthen proactive security measures."*
>
> **Domain.** Automotive (but not limited to).
>
> **Technical components.**
> - LLMs for handling textual information (user hints, logs, source
>   code, configurations).
> - MCPs to potentially use external scan / analysis / defense tools
>   or traffic capturing / interception.
> - Agent skills definition for different defense and attack
>   strategies.
> - *(Optional)* Agent memory adoption for defense / attack.
>
> **Critical design rule** *(supervisor note, May 2026)*: the system
> must **mainly detect all static vulnerabilities and, if possible,
> active ones when running it**. → Hence the project is built
> **static-first**: every scanner runs a deterministic static pass
> **before** asking the LLM anything (see §2.1 below).

---

## 1. The two architectures (one for each mode)

The supervisor provided two diagrams. We implement **both** as
sibling pipelines that share the same backbone (paper 4).

### 1.1 Defense agent — diagram 1

```
                       ┌────────────┐
                       │ Metamodel  │
                       └────┬───────┘
                            │
   New requirements   ┌─────▼─────┐                ┌─────────────┐
   / Updates ────────►│ Instance  │   ┌───────────►│  Rules /    │
                      │ creation  │   │            │  Policies   │
                      └─────┬─────┘   │            └──────┬──────┘
                            │         │                   │
                            ▼         │                   ▼
                       ┌────────────┐ │           ┌─────────────┐
   Events ────────────►│  Decision  │◄┴───────────│ Constraint  │
                       │   agent    │             │  modeling   │
                       └─┬───┬───┬──┘             └─────────────┘
        Source code      │   │   │                ┌──────────┐  ┌─────────┐
        scanner ◄────────┘   │   └───────────────►│  Action  │─►│  Target │
                             │                    │ generator│  │ system  │
        Log analyzer ◄───────┤                    └──────────┘  └─────────┘
                             │
        Deployment scanner ◄─┘
                ▲                ▲                ▲
                │                │                │
           Source code          Log         Deployment config
```

### 1.2 Attack agent — diagram 2

```
                       ┌────────────┐
                       │ Metamodel  │
                       └────┬───────┘
                            │
   System information ┌─────▼─────┐               ┌─────────────┐
   discovery ────────►│ Instance  │   ┌──────────►│  Attack     │
                      │ creation  │   │           │  rules      │
                      └─────┬─────┘   │           └──────┬──────┘
                            │         │                  │
                            ▼         │                  ▼
                       ┌────────────┐ │          ┌─────────────┐
   Scenario / hint ───►│  Attack    │◄┴──────────│ Constraint  │
                       │   agent    │            │  modeling   │
                       └─┬─────┬──┬─┘            └─────────────┘
   Source code        ┌──▼┐    │  └────►┌──────────┐    Attack scripts
   exploit ◄──────────┤   │    │        │  Attack  │──────────────────►┌──────┐
                      └─┬─┘    │        │ generator│                   │Target│
                        │      │        └──────────┘                   │system│
   Deployment exploit ◄─┘      │                                       └──────┘
                ▲              │
                │              │
        Deployment        Source code
        config
```

### 1.3 What's the same / different

| Block in diagram 1 (defense) | Mirror in diagram 2 (attack)        | Shared backbone (paper 4) |
|------------------------------|-------------------------------------|---------------------------|
| Decision agent               | Attack agent (orchestrator)         | `BaseAgent`, stack-based execution |
| Source code scanner          | Source code exploit                 | static_analyzer → LLM refinement   |
| Log analyzer                 | *(omitted — attacker generates logs, doesn't analyse them)* | — |
| Deployment scanner           | Deployment exploit                  | actor/datasource graph (paper 2)   |
| Action generator             | Attack generator                    | template + LLM fallback            |
| Security guard               | Ethics guard                        | per-action permission check        |
| Rules / Policies             | Attack rules                        | YAML-driven                        |
| New requirements / Updates   | System information discovery        | "Instance creation" prompt         |
| Events                       | Scenario / hint                     | free-text user input               |

Code mapping:

| Diagram block      | Defense file                                                                 | Attack file                                                                       |
|--------------------|------------------------------------------------------------------------------|-----------------------------------------------------------------------------------|
| central agent      | [`agents/decision_agent.py`](agents/decision_agent.py)                       | [`agents/attack/attack_orchestrator.py`](agents/attack/attack_orchestrator.py)    |
| code scanner       | [`agents/source_code_scanner.py`](agents/source_code_scanner.py)             | [`agents/attack/source_code_exploiter.py`](agents/attack/source_code_exploiter.py)|
| log / discovery    | [`agents/log_analyzer.py`](agents/log_analyzer.py)                           | [`agents/attack/system_info_discovery.py`](agents/attack/system_info_discovery.py)|
| topology scanner   | [`agents/deployment_scanner.py`](agents/deployment_scanner.py)               | [`agents/attack/deployment_exploiter.py`](agents/attack/deployment_exploiter.py)  |
| action generator   | [`agents/action_generator.py`](agents/action_generator.py)                   | [`agents/attack/attack_generator.py`](agents/attack/attack_generator.py)          |
| guard              | [`agents/security_guard.py`](agents/security_guard.py)                       | [`agents/attack/ethics_guard.py`](agents/attack/ethics_guard.py)                  |
| rules YAML         | [`rules/example_rules.yaml`](rules/example_rules.yaml), [`rules/extended_rules.yaml`](rules/extended_rules.yaml) | [`rules/attack_rules.yaml`](rules/attack_rules.yaml) |

---

## 2. Quick start

```bash
pip install -r requirements.txt           # only PyYAML is mandatory

# DEFENSE (default)
python pipeline.py --example small
python pipeline.py --example medium
python pipeline.py --example large
python pipeline.py --example all

# ATTACK (red team)
python pipeline.py --mode attack --example small
python pipeline.py --mode attack --example medium

# RED + BLUE side-by-side (one summary table per side)
python pipeline.py --mode both --example small

# Single file, defense
python pipeline.py --code examples/small/02_can_gateway.py

# Single project, attack with an explicit scenario file
python pipeline.py --mode attack \
    --code       examples/medium/ev_charging_api \
    --deployment examples/deployments/02_misconfigured_cloud.yaml \
    --scenario   examples/attack_scenarios/01_data_exfiltration.txt
```

Everything runs offline with a deterministic stub LLM. Swap in a real
provider in `config.yaml -> llm_configs.default.provider`
(`openai` / `anthropic` / `ollama`).

Output:

- `memory/last_run_<mode>.json` — final-outcome record for the most recent single run.
- `memory/<mode>_<scenario>.json` — final-outcome record per scenario in a batch.
- `memory/batch_<mode>_<kind>.json` — batch summary table.
- `run_logs/<timestamp>_<mode>_<scenario>/` — **detailed per-step debug
  trace** of every run (prompts sent, raw LLM responses, static-analyzer
  findings, merged findings, decision, action, guard verdict, generated
  attack scripts). Each subdirectory has a `_summary.md` and a
  `_trace.log`. See [`run_logs/README.md`](run_logs/README.md) for the
  full layout. `_latest_defense.txt` / `_latest_attack.txt` always
  point at the newest run.

---

## 3. The defense pipeline — step by step

Every block below corresponds to a function call in
[`pipeline.run_defense_pipeline`](pipeline.py). Read straight down.

### Step 0  Load configuration and rules

- **What.** Read `config.yaml`; load every `*.yaml` in `rules/` and
  merge by rule family (`code_rules`, `log_rules`, `topology_rules`,
  `safety_rules`, `attack_rules`).
- **Why.** Separating the rules from the agents is the
  Model-Driven-Engineering pattern that **paper 3 (TUM)** uses to
  keep LLM behaviour grounded — every finding can be traced back to
  an explicit OCL-style rule. Without this we'd be at the mercy of
  the LLM's training data.
- **Where.** `pipeline.load_config`, `pipeline.load_rules`.

### Step 1  Build inputs, each tagged with **provenance**

- **What.** Wrap every file (`code`, `log`, `deployment`, plus the
  user prompt) into a `BaseAgent.Input` object that carries a
  `source` name and a `trust_level`
  (`authenticated | external | tool | memory`).
- **Why.** **Paper 1 (UCSC / UC Berkeley / Duke)** §4.2 defines the
  *source-attribution oracle* `L(x) → s`. The only way our defense
  agent can implement the *source authorisation* property at runtime
  is to label every input at ingestion. If we lose the tag now, no
  downstream guard can recover it.
- **Where.** `BaseAgent.Input` dataclass and the `inputs:` list built
  at the top of `run_defense_pipeline`.

### Step 2  Source-code scanner — static-first

This is the canonical pattern; the log and deployment scanners use
the **same** three sub-steps.

#### 2.1  Deterministic static pass

- **What.** Iterate every `code_rules[*].pattern` regex against the
  source file; record line numbers and asset categories.
- **Why.** The supervisor's brief is explicit: *"mainly detect all
  static vulnerabilities"*. An LLM can hallucinate, refuse, or rate-
  limit; a regex always runs and always returns the same result.
  Static is therefore the **trusted floor** of the system.
- **Where.** `tools/static_analyzer.scan_code_static`.
- **Output.** A list of `StaticFinding` objects with `rule_id`,
  `severity`, `evidence`, `line`, `explanation`.

#### 2.2  LLM refinement pass (constraint + augmentation)

- **What.** Build a prompt that contains:
  - the rule snippet (compact list of all applicable rules),
  - the static findings already produced (so the LLM knows the floor),
  - the source code itself, and
  - a strict JSON output contract.
  Then call the LLM.
- **Why.** **Paper 4 (Härer) §IV-B-1** "Augmentation and Constraints":
  giving the LLM the deterministic hits as context makes its job
  *refinement* rather than *invention*, which (a) reduces
  hallucination, (b) keeps the output format strict, and (c)
  guarantees no regression vs the static baseline. **Paper 3 (TUM)**
  §III uses the same Retrieve-and-Re-rank idea with VSS / CAN
  catalogs.
- **Where.** `agents/source_code_scanner.SourceCodeScannerAgent.run`,
  the `PROMPT` constant, and `BaseAgent.template` for `[placeholder]`
  substitution (paper 4 §III-C).

#### 2.3  Merge

- **What.** Combine static and LLM findings, deduplicating on
  `(rule_id, evidence-prefix)`. Static wins on duplicates.
- **Why.** Static is deterministic and traceable to a YAML rule;
  the LLM is probabilistic. When in doubt, trust the deterministic
  source — that's the conservative choice for a system whose primary
  job is to *find every static vulnerability*.
- **Where.** `tools/static_analyzer.merge_findings`.

### Step 3  Log analyzer — same three-stage pattern

- **Static pass.** Hand-coded heuristics per `LOG-*` rule id:
  brute-force counting (`LOG-AUTH-03`), broadcast-rate threshold
  (`LOG-NET-01`), gateway-only CAN-ID anomaly (`LOG-CAN-02`),
  DNS-entropy covert-channel (`LOG-EXFIL-01`), large-outbound
  (`LOG-EXFIL-02`), internal-scan (`LOG-LATERAL-01`), SYN flood
  (`LOG-DDOS-01`), shadow / IMDS read (`LOG-PRIV-01`).
- **Why these specific heuristics.** Paper 5 (Collins) lists the
  detection-agent role first in the layered architecture, and paper
  2 (BMW/TUM) names the asset categories the log anomalies threaten
  (e.g., `LOG-CAN-02` → Life and Bodily Health).
- **Where.** `tools/static_analyzer.scan_log_static`.

### Step 4  Deployment scanner — graph checks (paper 2 + paper 3)

- **Static pass.** Hand-coded graph checks on the actor / datasource
  / edges YAML:
  - `TOP-001` — HPC ↔ ZoneECU must be Ethernet + IEEE-1722 (paper 3
    OCL rule).
  - `TOP-002` — external actors must not have `write` edges into
    `long_term_memory` or similar (paper 2 poison-path).
  - `TOP-004` — admin portal exposed to public internet without WAF.
  - `TOP-005` — database `bind_address: 0.0.0.0`.
  - `TOP-006` — secrets store with `access_policy: world-readable`.
  - `TOP-007` — safety actuator commanded by non-safety actor.
  - `TOP-008` — external A2A `respond` edge to in-vehicle agent
    (paper 2 §4.2 — the BMW A2A surface).
- **Why graph checks.** Paper 2's whole point is that a topology can
  be analysed independently from the code. Catching `TOP-002`
  statically would have prevented EchoLeak and CurXecute (cited in
  paper 2 §4.2.3).
- **Where.** `tools/static_analyzer.scan_deployment_static`.

### Step 5  Decision agent — paper 5 tiered response, paper 2 asset tagging

- **What.** Aggregate the three scanners' findings, ask an LLM
  (`llm_configs.reasoning`) to:
  1. tag which paper-2 asset categories are touched,
  2. recommend a response tier (`soft | moderate | hard | none`),
  3. quantify confidence in [0, 1],
  4. justify in one paragraph.
  Return strict JSON.
- **Why a reasoning model.** Paper 4 §IV-B-2 shows that on
  cybersecurity reasoning chains, OpenAI o1 and DeepSeek-R1
  outperform smaller models. We provision a dedicated
  `llm_configs.reasoning` slot so the decision step can use a heavier
  model (`gpt-4o` / `o1-preview` / `deepseek-r1`) while the scanners
  use a cheaper one.
- **Where.** `agents/decision_agent.py`.

### Step 6  Action generator — paper 5 response tiers + paper 3 auto-correct

- **What.** Translate the decision into a concrete action:
  - `soft` → `rate_limit`
  - `moderate` → `block_ip`
  - `hard` → `isolate_node` / `segment_network`
  - special: `patch_code` — paper 3 Prompt Construct 2b auto-
    correction prompt sent to the LLM, returning a fixed code snippet.
- **Why tiers.** Paper 5 §2.5 maps confidence ⇒ response intensity.
  This avoids the false-positive cost of always isolating a node
  (`hard` is expensive) and the false-negative cost of always rate-
  limiting (`soft` may miss an in-progress breach).
- **Where.** `agents/action_generator.py`.

### Step 7  Security guard — paper 1's four properties

- **What.** Before the action is executed, evaluate the four paper-1
  properties:
  1. **Task alignment** — is `objective ∈ O` (allowed set)?
  2. **Action alignment** — is the action *kind* compatible with the
     declared objective?
  3. **Source authorisation** — every input that caused the action
     must originate from an authenticated source (else escalate).
  4. **Data isolation** — destination must be in the trusted-
     destinations set.
- **Why an explicit guard.** Paper 1's central thesis is that
  "instruction-following is not inherently secure" (§5) — an agent
  that successfully follows instructions can still violate security
  depending on context. The guard makes context-evaluation
  *mechanical and auditable* instead of leaving it to the LLM.
- **Where.** `agents/security_guard.SecurityGuard.check`.
- **Result.** If `allowed=True`, the (stub) target receives the
  action; otherwise it is **refused** and only the audit log is
  written.

### Step 8  Persist to memory

- **What.** Write a JSON record to `memory/defense_<scenario>.json`
  capturing inputs, decision, action, guard verdict, findings list.
- **Why.** Paper 5 §2.4 calls for a continuous adaptive-learning
  loop. The memory directory is the seed of that loop; in a future
  phase the decision agent retrieves the K most similar past
  incidents and injects them as few-shot examples.

That's the full defense pipeline. **Eight steps; every step has a WHY
and a paper citation.** Now the same for attack.

---

## 4. The attack pipeline — step by step

[`pipeline.run_attack_pipeline`](pipeline.py). The shape is identical
to defense — that's the whole point of paper 4's schema-driven design.

### Step A0  Read the scenario / hint

- **What.** `--scenario examples/attack_scenarios/01_data_exfiltration.txt`,
  or a literal hint string, or a per-example default from
  `config.yaml`. The scenario gives the orchestrator a *goal*.
- **Why.** Paper 2 §3.2 introduces the **victim-modeling** approach
  — you don't enumerate attacks in the abstract, you start from a
  damage scenario ("driver distraction", "credentials exfil",
  "battery drain") and *backchain* technical primitives that achieve
  it. The scenario is that damage scenario.
- **Where.** `pipeline._read_scenario`.

### Step A1  System information discovery — diagram 2 top-left node

- **What.** Parse the deployment YAML into the structured
  `SystemInstance` dataclass: external actors, safety actors, all
  edges, free-form notes ("X is internet-exposed",
  "Y binds 0.0.0.0", "Z is world-readable").
- **Why.** This is the *passive reconnaissance* step. Paper 2 §4.2
  models the system as a graph; we must build that graph before any
  attack reasoning. Active recon (live nmap / fingerprinting) is
  deliberately deferred to `tools/active_analyzer.py` (future work)
  and gated by the EthicsGuard.
- **Where.** `agents/attack/system_info_discovery.py`.

### Step A2  Source-code exploiter

- **What.** Re-uses `tools/static_analyzer.scan_code_static` for the
  deterministic pass — the same static findings, **different
  framing**. The LLM is then asked to turn each finding into an
  *exploit plan*: what payload to send, which paper-1 property it
  violates, the expected effect.
- **Why share the static layer.** Finding a vulnerability is the
  same problem regardless of intent; only what you *do* with it
  differs. Sharing the layer halves the maintenance cost and
  guarantees red and blue agree on the rule catalogue.
- **Where.** `agents/attack/source_code_exploiter.py`.

### Step A3  Deployment exploiter

- **What.** Same `scan_deployment_static` pass, plus an extra
  enumeration that flags every `external → write` edge as a
  candidate **poison path** and every `external → respond` edge as a
  candidate **trigger path**, emitting `ATK-PATH` findings.
- **Why.** Paper 2 §4.2.2 distinguishes poison paths ("How does the
  payload reach the victim?") from trigger paths ("What causes the
  victim to consume it?"). The exploiter emits both kinds so the
  orchestrator can pick a poison + trigger combination.
- **Where.** `agents/attack/deployment_exploiter.py`.

### Step A4  Attack orchestrator

- **What.** Aggregate exploiter findings + system instance + scenario
  hint. Choose 1-3 findings to chain. Output an `AttackPlan` with:
  target asset, chosen rule_ids, poison path, trigger path,
  confidence, justification.
- **Why structured output.** Paper 4 Listing 2 shows the Server-
  Security-Agent invoking an Audit-Report-Agent with a typed
  data hand-off (`ipv4-network`, `scan-result`). The same pattern
  here: the orchestrator's JSON is the typed hand-off to the
  attack-generator.
- **Where.** `agents/attack/attack_orchestrator.py`.

### Step A5  Ethics / scope guard

- **What.** Before any script is generated:
  1. **scope_ok** — is the scenario in `config.yaml ->
     attack.allowed_scenarios`?
  2. **target_ok** — is the target asset in
     `attack.authorized_targets` (or in `--authorize-target` CLI
     overrides)?
  3. **non_destructive** — when scripts are produced, they are
     filtered for destructive patterns (`rm -rf /`, fork bomb,
     `dd if=/dev/zero of=/dev/sda`, …) and redacted.
- **Why explicit gating.** Without this an offensive LLM could be
  weaponised against unauthorised targets. Paper 1's four-property
  framework — adapted for offense — gives us a clean way to phrase
  the gates: *task alignment* (scenario in scope), *data isolation*
  (target in scope), *action alignment* (script does what the plan
  says), *source authorisation* (operator who launched is authed).
- **Where.** `agents/attack/ethics_guard.py`.

### Step A6  Attack generator — template + LLM fallback

- **What.** For each chosen finding, emit one script. The most
  common rule_ids have **hard-coded templates** with explicit
  placeholder hostnames and a benign canary effect
  (`touch /tmp/atk_canary`). Anything not in the template table
  falls back to an LLM call constrained by the orchestrator's plan.
- **Why both layers.** Hard-coded templates are deterministic and
  reviewable — a human security engineer can audit them once. The
  LLM fallback covers the long tail.
- **Where.** `agents/attack/attack_generator.py`,
  particularly `_TEMPLATES` for CODE-001 / 005 / 007 / 012 / 020 /
  038 / TOP-002 / TOP-008 / LOG-CAN-02 / ATK-PATH.

### Step A7  Persist to memory

- Same shape as the defense side; file name
  `memory/attack_<scenario>.json`.

---

## 5. Why the static-first design is the right call

A summary of the supervisor's hard constraint and how the project
honours it.

| Layer            | Determinism | Source of truth                                   | Behaviour with stub LLM            |
|------------------|-------------|---------------------------------------------------|--------------------------------------|
| Static analyzer  | yes         | YAML rules — auditable, version-controlled        | produces real findings              |
| LLM scanner      | no          | language-model judgement                          | produces canned findings (low signal)|
| Merge layer      | yes         | static-wins-on-dupes                              | static findings survive verbatim    |

→ Even with the LLM stubbed (CI / offline demos / first time you
clone the repo), the pipeline produces **real, traceable**
vulnerability reports. Once a real LLM is wired in, accuracy goes up
monotonically.

This is a direct application of **paper 3 §III**: ground LLM outputs
in catalog-derived context (here: the YAML rule snippets and the
static findings) to "prevent unsafe or unverified behaviours from
entering the generated artifacts".

---

## 6. Directory layout

```
CyberLLM/
├── pipeline.py                  # entry point — defense / attack / both
├── config.yaml                  # LLM, agent, security, example_sets, attack scope
├── llm_client.py                # provider abstraction (stub / openai / anthropic / ollama)
├── requirements.txt
├── README.md                    # this file
├── improvements_and_exploration.md
│
├── agents/
│   ├── base_agent.py            # paper 4 schema-driven template
│   ├── source_code_scanner.py   # defense
│   ├── log_analyzer.py          # defense
│   ├── deployment_scanner.py    # defense
│   ├── decision_agent.py        # defense orchestrator (paper 5)
│   ├── action_generator.py      # defense action (paper 5 tiers + paper 3 fix)
│   ├── security_guard.py        # paper 1 four properties
│   └── attack/                  # diagram 2 mirror
│       ├── system_info_discovery.py
│       ├── source_code_exploiter.py
│       ├── deployment_exploiter.py
│       ├── attack_orchestrator.py
│       ├── attack_generator.py  # templates + LLM fallback
│       └── ethics_guard.py      # offensive-side scope guard
│
├── tools/
│   ├── mcp_tools.py             # MCP adapters: nmap / bandit / pcap stubs
│   └── static_analyzer.py       # deterministic regex + graph checks (the floor)
│
├── skills/
│   └── skills.py                # defense skills (paper 5) + attack skills (paper 2)
│
├── prompts/                     # human-readable system prompts
├── rules/
│   ├── example_rules.yaml       # baseline 1st-pipeline rules
│   ├── extended_rules.yaml      # ~40 additional rules
│   └── attack_rules.yaml        # offensive rule-id mappings
│
├── examples/
│   ├── README.md
│   ├── scenarios.md             # expected findings per (code, log, dep) triple
│   ├── run_examples.py          # legacy batch runner
│   ├── small/                   # 5 single-file scenarios
│   ├── medium/                  # 2 mini-projects
│   ├── large/                   # 1 realistic fleet_management backend
│   ├── logs/                    # 6 log scenarios
│   ├── deployments/             # 3 deployment YAMLs
│   └── attack_scenarios/        # 3 scenario/hint text files
│
├── memory/
│   ├── defense_*.json           # per-scenario defense records (final outcomes)
│   ├── attack_*.json            # per-scenario attack records (final outcomes)
│   └── batch_*.json             # batch summary tables
│
└── run_logs/                    # per-step debug trace of every run
    ├── README.md                # layout + workflow tips
    ├── _latest_defense.txt      # name of the most recent defense run
    ├── _latest_attack.txt       # name of the most recent attack run
    └── <timestamp>_<mode>_<scenario>/
        ├── 00_meta.json
        ├── 01_inputs.json
        ├── 02_static_*.json     # deterministic static-analyzer findings
        ├── 0N_<agent>_prompt.txt
        ├── 0N_<agent>_response.txt
        ├── 0N_<agent>_findings.json
        ├── 0N_{decision|action|guard|plan|ethics|instance}.json
        ├── scripts/             # attack only — one file per script
        ├── _trace.log
        └── _summary.md
```

---

## 7. Paper-to-code crosswalk (one-line summary)

| Paper                                   | What it gives us                                                                                                | Where in the code                                                                                          |
|-----------------------------------------|-----------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| **Paper 1** — Contextual security        | The four properties + oracles that the SecurityGuard / EthicsGuard implement.                                  | `agents/security_guard.py`, `agents/attack/ethics_guard.py`.                                              |
| **Paper 2** — AgentHeLLM                | Asset taxonomy, actor/datasource graph, poison + trigger paths.                                                 | `tools/static_analyzer.scan_deployment_static`, `agents/attack/deployment_exploiter.py`, `decision_agent.ASSET_CATEGORIES`. |
| **Paper 3** — Event chains + OCL + RAG   | Rule-driven design, prompt constructs for code/instance/constraints + auto-correct.                            | `rules/*.yaml`, `agents/action_generator.py` FIX_PROMPT, `agents/source_code_scanner.py`.                  |
| **Paper 4** — Härer schema              | The whole engineering backbone: agent schema, templating, provider abstraction, agent-of-type invocation.       | `agents/base_agent.py`, `llm_client.py`, `config.yaml -> agent_configs / llm_configs`.                     |
| **Paper 5** — Edge MAS coordination      | Layered architecture, tiered response, adaptive-learning loop.                                                  | `pipeline.run_defense_pipeline`, `agents/action_generator.py`, `memory/`.                                  |

The deep version of this mapping is in
[`../Papers_Notes/paper4_in_code.md`](../Papers_Notes/paper4_in_code.md)
and the per-paper summaries in [`../Papers_Notes/`](../Papers_Notes/).

---

## 8. Extending the system

### 8.1  Add a new static-analysis rule

1. Append an entry to one of `rules/*.yaml` (use `pattern` for code,
   no pattern needed for hand-coded log/topology checks).
2. If it's a code rule, you're done — `scan_code_static` picks up
   the regex automatically.
3. If it's a log or topology rule with non-trivial semantics, add
   the matching `if rule_id in by_id:` block to
   `tools/static_analyzer.py`.

### 8.2  Add a new defense or attack scenario

Edit the `example_sets:` map in `config.yaml`:

```yaml
example_sets:
  small:
    - name: my_new_scenario
      code: examples/path/to/code        # file OR directory
      log:  examples/logs/02_brute_force_ssh.log    # defense only
      deployment: examples/deployments/02_misconfigured_cloud.yaml
      scenario: examples/attack_scenarios/01_data_exfiltration.txt   # attack only
```

Then `python pipeline.py --example small`.

### 8.3  Wire in a real LLM

```yaml
llm_configs:
  default:
    provider: ollama          # or openai / anthropic
    model:    llama3.1:8b-instruct-q4_K_M
    temperature: 0.2
    max_tokens: 1024
  reasoning:
    provider: openai
    model:    gpt-4o
```

Set `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` or start `ollama serve`,
and re-run.

### 8.4  Add a new attack skill / template

Add an entry to `_TEMPLATES` in
[`agents/attack/attack_generator.py`](agents/attack/attack_generator.py)
keyed by the rule id you want to exploit, and (optionally) add a
matching offensive rule to `rules/attack_rules.yaml`.

### 8.5  Add a new external tool (MCP)

Drop a class into `tools/mcp_tools.py` that exposes `run(**kwargs)
-> dict`. The agent that needs it imports `TOOL_REGISTRY[name]` and
calls it.

---

## 8.5  Testing

Three layers, run them in order:

```bash
# 1. 30-second smoke check, no pytest needed.
python verify.py

# 2. Full automated suite (~2 s, 62 tests).
pip install pytest
python -m pytest tests/

# 3. Manual / qualitative spot-checks — inspect the run-log summary
#    of the most recent run.
python pipeline.py --mode both --example small
cat "$(cat run_logs/_latest_defense.txt)/_summary.md"
cat "$(cat run_logs/_latest_attack.txt)/_summary.md"
```

What each layer asserts is documented in [`tests/README.md`](tests/README.md):

- `tests/test_static_analyzer.py` — every code / log / topology rule
  fires on a positive snippet **and** doesn't fire on a clean one.
- `tests/test_rules_and_parsing.py` — rule YAML loads, ids unique,
  every regex compiles, JSON findings parser is robust.
- `tests/test_guards.py` — SecurityGuard's four paper-1 properties +
  EthicsGuard's scope / destructive-pattern checks.
- `tests/test_pipeline_integration.py` — full defense + attack
  pipelines run end-to-end on real example files.
- `tests/test_scenario_regression.py` — for five (code, log,
  deployment) triples, the **must-have** rule_ids are detected. This
  is your regression alarm when a rule regex breaks.
- `tests/test_cli_smoke.py` — `python pipeline.py --help` + each
  `--mode` runs.

If something LLM-quality-related needs judgement (does the
`justification` text make sense? is the auto-generated patch
correct?), do it manually via the run-log `_summary.md`.

## 9. What's deliberately NOT done yet

These are tracked in [`improvements_and_exploration.md`](improvements_and_exploration.md):

- **Active analysis** — real `nmap` / `tcpdump` / live `bandit`.
  Today's `tools/mcp_tools.py` stubs hand back canned data.
- **Full RAG over CVEs / VSS catalogs** — rules are inlined in
  prompts; paper 3's `MiniLM + cross-encoder` flow is Phase B.
- **Real H_a LLM judge** — the SecurityGuard's action-alignment
  check is a coarse mapping today. Phase F.1 swaps in a separate
  LLM call dedicated to the H_a oracle (paper 1 §7).
- **Adaptive memory loop** — `memory/` is written but not yet read
  by the next run. Phase E.
- **Benchmarks** — CyberMetric Q&A (paper 4), AgentDojo (paper 1),
  CAR-bench (paper 2).

---

## 10. Reading order if you're new

1. This README (you are here).
2. [`Papers_Notes/00_README.md`](../Papers_Notes/00_README.md) — the
   reading order for the five papers.
3. [`Papers_Notes/synthesis_project_blueprint.md`](../Papers_Notes/synthesis_project_blueprint.md)
   — concept ↔ paper mapping.
4. [`Papers_Notes/paper4_in_code.md`](../Papers_Notes/paper4_in_code.md)
   — concrete file:line references for the engineering backbone.
5. [`examples/scenarios.md`](examples/scenarios.md) — what each
   example is supposed to detect.
6. The code, in this order:
   `pipeline.py` → `agents/base_agent.py` →
   `tools/static_analyzer.py` → one defense agent →
   `agents/decision_agent.py` → one attack agent
   (`source_code_exploiter.py`) → `agents/attack/attack_orchestrator.py`.

---

## 11. License & ethics note

This codebase is intended for academic use, authorised red-team
exercises, and defensive research. The `EthicsGuard` is a **policy
enforcement point**, not a legal indemnity. Do not run the attack
pipeline against systems you do not own or have explicit written
authorisation to test.
