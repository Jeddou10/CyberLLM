# CyberLLM — First Pipeline

A first end-to-end multi-agent LLM cybersecurity pipeline. It instantiates
every block of the project's reference diagram (in `../image.png`) on a
small but realistic automotive / edge scenario, and runs offline with a
deterministic stub LLM so you can demo it without any credentials.

The design is *paper-driven* — every file is justified by one of the five
reference papers in `../Papers_Notes/`. Read those summaries (start with
`Papers_Notes/00_README.md`) for the why behind every decision.

---

## What the pipeline does

```
            ┌──────────────────────────┐
            │      User prompt          │  (authenticated source)
            └────────────┬─────────────┘
                         │
   ┌─────────────────────┼─────────────────────┐
   │                     │                     │
   ▼                     ▼                     ▼
┌──────────┐   ┌──────────────────┐   ┌──────────────────┐
│  Source  │   │  Log Analyzer    │   │  Deployment      │
│   Code   │   │  (anomaly        │   │  Scanner         │
│ Scanner  │   │   detection)     │   │  (topology+OCL)  │
└────┬─────┘   └────────┬─────────┘   └────────┬─────────┘
     │                  │                       │
     └──────────────────┴───────────────────────┘
                        ▼
              ┌─────────────────────┐
              │   Decision Agent    │  uses paper-2 asset taxonomy
              │  (LLM, reasoning)   │  + paper-5 response tiers
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │  Action Generator   │  paper-3 auto-correction prompt
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │  Security Guard     │  paper-1 four properties
              │  (task/action/      │
              │   source/data)      │
              └──────────┬──────────┘
                         ▼
              ┌─────────────────────┐
              │   Target system     │  (stubbed; swap in CARLA/SDV)
              └─────────────────────┘
                         ▲
                         │
            ┌────────────┴────────────┐
            │ rules/  +  metamodel    │
            └─────────────────────────┘
                         │
                         ▼
                   memory/  (audit log + adaptive-learning seed)
```

---

## Quick start

```bash
# 1. install dependencies
pip install -r requirements.txt

# 2. run the demo (uses deterministic stub LLM, no API key needed)
python pipeline.py

# 3. inspect the audit log
cat memory/last_run.json
```

To run on different inputs:

```bash
python pipeline.py \
  --code        examples/sample_code.py \
  --log         examples/sample_log.log \
  --deployment  examples/sample_deployment.yaml
```

---

## Directory layout

```
CyberLLM/
├── pipeline.py                # main entry point
├── config.yaml                # LLM configs + agent configs + security policy
├── llm_client.py              # provider abstraction (stub | openai | anthropic | ollama)
├── requirements.txt
├── README.md                  # this file
├── improvements_and_exploration.md
│
├── agents/
│   ├── base_agent.py          # schema-driven base class (paper 4)
│   ├── source_code_scanner.py # paper 3 Prompt Construct 1
│   ├── log_analyzer.py        # paper 5 detection agent
│   ├── deployment_scanner.py  # paper 3 topology + paper 2 actor graph
│   ├── decision_agent.py      # orchestrator (papers 4 & 5)
│   ├── action_generator.py    # paper 5 tiered response + paper 3 Prompt 2b
│   └── security_guard.py      # paper 1 four properties at runtime
│
├── skills/
│   └── skills.py              # defense skills (paper 5) + attack skills (paper 2)
│
├── tools/
│   └── mcp_tools.py           # MCP adapters (nmap / static analysis / pcap stubs)
│
├── prompts/                   # human-readable system prompts
│   ├── decision_agent.txt
│   └── source_code_scanner.txt
│
├── rules/
│   └── example_rules.yaml     # code_rules + log_rules + topology_rules
│
├── examples/
│   ├── sample_code.py
│   ├── sample_log.log
│   └── sample_deployment.yaml
│
└── memory/
    └── last_run.json          # audit log of the last pipeline run
```

---

## What each block contributes (and which paper backs it)

| Code module                              | Diagram block(s)                                                | Paper(s) used                                            |
|------------------------------------------|-----------------------------------------------------------------|----------------------------------------------------------|
| `agents/base_agent.py`                   | Common pattern for every agent                                  | Härer (paper 4) — agent schema, templating, action chain |
| `agents/source_code_scanner.py`          | "Source code scanner"                                           | TUM (paper 3) — Prompt Construct 1                       |
| `agents/log_analyzer.py`                 | "Log analyzer"                                                  | Collins (paper 5) — detection agent role                 |
| `agents/deployment_scanner.py`           | "Deployment scanner", "Instance creation", "Constraint modeling"| TUM (paper 3) topology + BMW/TUM (paper 2) actor graph   |
| `agents/decision_agent.py`               | "Decision agent" + "Events"                                     | Härer (paper 4) execution; Collins (paper 5) coordination |
| `agents/action_generator.py`             | "Action generator"                                              | Collins (paper 5) tiers; TUM (paper 3) Prompt 2b         |
| `agents/security_guard.py`               | Cross-cutting guard before "Target system"                      | UCSC/UCB/Duke (paper 1) — four contextual properties     |
| `skills/skills.py`                       | "Agent skills definition for different defense/attack strategies"| Collins (paper 5) tiers + BMW/TUM (paper 2) attacks      |
| `tools/mcp_tools.py`                     | "MCPs to use external scan/analysis/defense tools"              | Härer (paper 4) execution functions                      |
| `rules/example_rules.yaml`               | "Rules / Policies" + "Constraint modeling"                      | TUM (paper 3) OCL examples + paper 1 contextual rules    |
| `memory/`                                | Optional "Agent memory adoption"                                | Collins (paper 5) adaptive learning loop                 |

---

## Reading order if you want to extend the system

1. **`config.yaml`** — to add a new agent or change LLM provider.
2. **`agents/base_agent.py`** — to understand the templating / parsing.
3. **`pipeline.py`** — to see how agents are wired together.
4. **`rules/example_rules.yaml`** — to add new vulnerabilities to look for.
5. **`skills/skills.py`** — to add a new defense or attack skill.

---

## Swapping in a real LLM

1. Install a provider package, e.g. `pip install openai` or `pip install ollama`.
2. Edit `config.yaml`:

   ```yaml
   llm_configs:
     default:
       provider: openai           # or "ollama" or "anthropic"
       model: gpt-4o-mini         # or "llama3.1:8b-instruct-q4_K_M"
       temperature: 0.2
       max_tokens: 1024
   ```
3. For OpenAI/Anthropic, set the appropriate environment variable
   (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`).
4. For Ollama, make sure `ollama serve` is running on port 11434.

The rest of the pipeline is provider-agnostic.

---

## What this first pipeline deliberately does **not** do yet

- It does not use a real RAG index (paper 3) — rules are inlined.
- It does not run real `nmap`/`bandit` (paper 4 §IV) — `tools/mcp_tools.py` is stub.
- It does not run the attack agents end-to-end (paper 2) — `skills/`
  catalogues them, but the orchestrator only runs defense skills.
- The security guard's instruction attribution (`I`) is coarse — see
  paper 1 §7 for what a future implementation would need.

All four are tracked in [`improvements_and_exploration.md`](improvements_and_exploration.md).
