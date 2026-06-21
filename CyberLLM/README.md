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

**Verbosity (great for testing).** Diagnostics go to **stderr**, results
(summary tables / record JSON) to **stdout**, so they never mix.

```bash
python pipeline.py --example small        # default: per-step progress
python pipeline.py -v --example small     # debug: timings, token counts,
                                          #   static-vs-LLM split, recalled
                                          #   memory, per-step status, and a
                                          #   preview of every prompt+response
python pipeline.py -q --example small     # quiet: only the summary tables
python pipeline.py -v --code … 2>run.log  # capture the debug trace to a file
```

The default LLM is **Azure OpenAI gpt-4o** (`config.yaml` → `llm_configs`);
set the Azure variables in `.env` (`AZURE_OPENAI_API_KEY`,
`AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT`, `AZURE_OPENAI_API_VERSION`)
to activate it, otherwise it falls back to the offline stub.
`CYBERLLM_FORCE_STUB=1` forces the stub regardless.

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

### 2.1 Web UI (local server)

A polished single-page UI runs the **same defense pipeline** on code you
paste in the browser — no extra dependencies (stdlib `http.server` only):

```bash
python server.py                 # → http://127.0.0.1:8000
python server.py --port 9000 --host 0.0.0.0
```

Then open the URL, paste code (or pick a bundled example), and press
**Scan**. You get:

- **Findings** in the `rule_id / severity / title / location / line / detail`
  format, severity-colour-coded and sorted worst-first.
- An **annotated source view** — flagged lines are highlighted by severity;
  click any finding to jump to its line.
- The **decision · action · guard** panel (recommended tier, justification,
  the dry-run action plan, the four-property guard verdict, MCP tool calls).
- The full raw JSON record.

Two modes:

- **Fast** (default) — the deterministic `regex + bandit/semgrep` layers,
  offline and instant.
- **Deep (AI)** — adds the LLM refinement pass (Azure gpt-4o) on top, used
  **only** when real LLM credentials are present; otherwise it transparently
  falls back to Fast (the offline stub's canned findings are never shown on
  real code). Install bandit for a much stronger Python static layer:
  `pip install bandit` (the server auto-detects it, even via `python -m`).

**Safety:** browser-initiated runs force **dry-run** actions — no real OS
command is ever executed from the UI. Detection is real; remediation is
simulated. Each scan runs in an isolated temp workspace and is stateless.

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
├── server.py                    # local web UI server (stdlib http.server, zero deps)
├── webapp/
│   └── index.html               # single-page UI (findings, annotated code, decision/guard)
├── evaluate.py                  # static eval harness (D.4/D.5/G.4) — recall, FP, scoreboard
├── config.yaml                  # LLM, agent, security, memory, guard, example_sets
├── llm_client.py                # provider abstraction (+ A.2 credential fallback to stub)
├── requirements.txt
├── README.md                    # this file
├── improvements_and_exploration.md
│
├── agents/
│   ├── base_agent.py            # paper 4 template (+ F.2 provenance, F.5 delegation, A.4 budget)
│   ├── source_code_scanner.py   # defense
│   ├── log_analyzer.py          # defense
│   ├── deployment_scanner.py    # defense
│   ├── decision_agent.py        # defense orchestrator (paper 5) — + E.2 memory recall
│   ├── action_generator.py      # defense action (shim → action_engine/)
│   ├── security_guard.py        # paper 1 four properties + F.1/F.3/F.4 hardening
│   ├── ha_judge.py              # F.1 — separate H_a action-alignment oracle
│   ├── memory_store.py          # Phase E — signed sqlite incident store
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
│   ├── tokens.py                # A.4 — dependency-free token estimator + budget
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
│   ├── labels.yaml              # machine-readable ground truth for evaluate.py
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

**Default: Azure OpenAI (`gpt-4o`).** `config.yaml` ships with the
`azure` provider for both `default` and `reasoning`. Fill the four
`AZURE_OPENAI_*` values in `.env`:

```bash
# .env  (git-ignored)
AZURE_OPENAI_ENDPOINT=https://<your-resource>.openai.azure.com
AZURE_OPENAI_API_KEY=<your key>
AZURE_OPENAI_DEPLOYMENT=<your gpt-4o deployment name>   # NOT the model name!
AZURE_OPENAI_API_VERSION=2024-10-21
```

On Azure, the model is selected by the **deployment name** (not the model
id), auth uses the `api-key` header, and requests are versioned. The
`model` field in `config.yaml` is only used as the deployment name when
`AZURE_OPENAI_DEPLOYMENT` is unset. ⚠️ A deployment can be named anything —
verify which deployment actually serves gpt-4o (list them with
`GET {endpoint}/openai/deployments?api-version=2023-03-15-preview`, header
`api-key`). Until the Azure credentials are filled in, the client
**transparently falls back to the offline stub**.

Prefer a different backend? Swap the provider:

```yaml
llm_configs:
  default:
    provider: github          # azure | github | openai | anthropic | ollama | stub
    model:    openai/gpt-5-mini   # GitHub Models id (needs GITHUB_TOKEN)
  reasoning:
    provider: azure
    model:    gpt-4o
```

Set `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`, start `ollama serve`, or put
`GITHUB_TOKEN` in `.env`, then re-run. (Tip: `CYBERLLM_FORCE_STUB=1`
forces the offline stub regardless of config — the test suite uses it.)

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

# 2. Full automated suite (~3 s, 131 tests).
pip install pytest
python -m pytest tests/

# 3. Static evaluation scoreboard (detection recall, false-positive rate,
#    paper-1 property table, asset×scenario×skill scoreboard). No LLM,
#    no dynamic execution. Writes memory/eval_report.md.
python evaluate.py

# 4. Manual / qualitative spot-checks — inspect the run-log summary
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
- `tests/test_memory_store.py` / `tests/test_memory_pipeline.py` —
  the signed store (Phase E): recall by Jaccard, HMAC tamper detection,
  unauthenticated-write refusal, and the recall loop closing end-to-end.
- `tests/test_ha_judge_and_trajectory.py` — the H_a judge (F.1, tightens
  only) + compositional/temporal trajectory checks (F.3/F.4).
- `tests/test_provenance_and_delegation.py` — mandatory provenance (F.2)
  + delegation source-set isolation (F.5).
- `tests/test_token_budget.py` — token estimation (A.4) + credential
  fallback to stub (A.2).
- `tests/test_evaluation.py` — the static eval harness (D.4/D.5/G.4).

If something LLM-quality-related needs judgement (does the
`justification` text make sense? is the auto-generated patch
correct?), do it manually via the run-log `_summary.md`.

## 9. What's done, and what's deliberately deferred

Full status is in [`improvements_and_exploration.md`](improvements_and_exploration.md)
(updated 2026-06-03). The **research / learning** gaps that used to live
here have now been closed:

- **Adaptive memory loop (Phase E)** — *done*. A signed SQLite store
  (`agents/memory_store.py`) records every outcome; the Decision Agent
  recalls the K most-similar past incidents as few-shot context; writes
  are HMAC-signed and reads are source-authenticated (anti-poisoning).
- **H_a LLM judge (F.1)** — *done*. `agents/ha_judge.py` is a separate
  0/1 oracle call that can only *tighten* the guard's action-alignment.
- **Guard hardening (F.2–F.5, C.4)** — *done*. Mandatory provenance,
  delegation rules, compositional + temporal trajectory checks, and a
  per-step guard wired into the action executor.
- **Static evaluation (D.4/D.5/G.4)** — *done*. `python evaluate.py`
  scores detection recall + false-positives on clean controls, a
  property-violation table, and an asset×scenario×skill scoreboard —
  all **statically** (no MTTD; that is a dynamic metric).

Still deferred (need heavy deps or external corpora):

- **Active analysis** — real `nmap` / `tcpdump` (dynamic). Note `bandit`
  /`semgrep` *are* wired (`action_engine/mcp_tools.CodeStaticScan`).
- **Full RAG over CVE / VSS catalogs** — Phase B (`MiniLM + cross-encoder`).
- **External benchmarks** — CyberMetric (paper 4), AgentDojo (paper 1),
  CAR-bench (paper 2). The *internal* static scoreboard (G.4) is done.

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
