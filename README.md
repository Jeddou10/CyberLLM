<p align="center">
  <img src="docs/assets/cyberllm-shield.png" alt="Pixel shield protecting a vehicle, connected to three AI agent nodes" width="160">
</p>

<h1 align="center">
  <img src="docs/assets/cyberllm-wordmark.svg" alt="CyberLLM:" width="560">
</h1>
<h3 align="center">A Multi-Agent LLM Framework for Autonomous Detection and Guarded Response in Automotive Cybersecurity</h3>

**Static-first security analysis with LLM agents for code, logs, and deployment topologies.**

CyberLLM is a research prototype focused on automotive and software-defined
vehicle systems. It combines deterministic detection rules, optional external
static analyzers, and LLM reasoning with guarded response planning. A local web
interface supports scanning, benchmark evaluation, and authorized attack modeling.

[Getting started](docs/getting-started.md) · [Architecture](docs/architecture.md) ·
[Research foundations](#research-foundations) · [Configuration](docs/configuration.md) · [Contributing](CONTRIBUTING.md) ·
[MIT license](LICENSE)

## Capabilities

| Area | What it does |
| --- | --- |
| Defense | Analyze source, logs, and actor/datasource graphs; classify findings; build guarded response plans. |
| Attack modeling | Perform passive analysis, assemble poison/trigger paths, and generate proof-of-concept text for authorized research. Generated scripts are not executed by the attack pipeline. |
| Local interface | Explore findings and source locations, request model-generated fixes, and inspect simulated attack outcomes. |
| Evaluation | Compare detection against labeled scenarios and an automotive corpus containing 47 labeled vulnerabilities and two clean controls. |
| Incident memory | Store signed incident records in SQLite and recall similar outcomes across runs. |
| Offline operation | Use deterministic rules and a stub LLM without provider credentials. |

The code under analysis is read as data. Response tools are **dry-run by default**;
live LLMs and optional external analyzers are separate capabilities. See the
[security model and limitations](SECURITY.md) before changing execution settings.

## Research foundations

CyberLLM builds on the following five papers. Their **P1–P5** identifiers are
retained throughout the code to connect implementation choices to the research
that inspired them.

| Reference | Paper | Role in CyberLLM |
| --- | --- | --- |
| **P1** · Siu et al. (2026) | [A Framework for Formalizing LLM Agent Security](https://arxiv.org/abs/2603.19469) | Contextual security properties and action-alignment checks. |
| **P2** · Stappen et al. (2026) | [Agent2Agent Threats in Safety-Critical LLM Assistants: A Human-Centric Taxonomy](https://arxiv.org/abs/2602.05877) | Human-centric assets, actor/datasource graphs, and poison/trigger paths. |
| **P3** · Petrovic et al. (2026) | [LLM-Empowered Functional Safety and Security by Design in Automotive Systems](https://arxiv.org/abs/2601.02215) | Automotive safety/security rules and code-correction workflows. |
| **P4** · Härer (2025) | [Specification and Evaluation of Multi-Agent LLM Systems — Prototype and Cybersecurity Applications](https://arxiv.org/abs/2506.10467) | Schema-driven agents, prompt templates, and structured handoffs. |
| **P5** · Collins, James, Thomas (2026) | *LLM-Orchestrated Multi-Agent Coordination for Adaptive Cyber Defense at the Edge* | Tiered adaptive responses, coordination, and incident-memory feedback. |

See [research background](docs/research.md) for the detailed implementation
mapping. P5 is preserved from the original project bibliography; its direct
publication link has not yet been confirmed.

[CyberLLM: A Multi-Agent LLM Framework for Autonomous Detection and Guarded Response in Automotive Cybersecurity](https://arxiv.org/abs/2608.06651)

## Quick start

Use Python 3.11 for the locally verified setup. From the repository root:

```bash
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
source .venv/bin/activate
```

Install and start the local interface:

```bash
python -m pip install -r requirements.txt
python CyberLLM/server.py
```

Open **http://127.0.0.1:8000**. Missing credentials for the default Azure provider
select the offline stub. Start with **Fast** scanning; live AI remediation needs
a configured provider. For a deterministic smoke check, run:

```bash
python CyberLLM/verify.py
```

For command-line examples, use the existing application directory:

```bash
cd CyberLLM
python pipeline.py --example small
python pipeline.py --mode attack --example small
python pipeline.py --mode both --example medium
```

See [getting started](docs/getting-started.md) for fully offline settings, provider
setup, custom inputs, and the difference between CLI stub results and Fast scans.

## Repository layout

```text
.
├── .github/             # CI workflow and issue / pull-request templates
├── docs/                # setup, architecture, configuration, API, evaluation
├── CyberLLM/            # application root; existing commands and paths preserved
│   ├── agents/          # scanners, decisions, guards, action engine, attack agents
│   ├── reporting/       # finding titles, source locations, and output formatting
│   ├── tools/           # static analyzers, tool adapters, logging, token budgets
│   ├── rules/           # detection and topology rule catalogs
│   ├── skills/          # declarative defense and attack skills
│   ├── webapp/          # HTML interface and separate CSS / JavaScript assets
│   ├── benchmark/      # automotive corpus and line-based ground truth
│   ├── examples/       # synthetic code, logs, topologies, and labeled scenarios
│   ├── tests/          # offline unit, integration, benchmark, and CLI tests
│   ├── config.yaml     # runtime configuration
│   ├── pipeline.py     # CLI and defense / attack orchestration
│   └── server.py       # local HTTP server and JSON API
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE
```

Runtime records, traces, credentials, virtual environments, and action workspaces
are ignored by Git. Example logs and benchmark inputs are intentional fixtures.

## Documentation

- [Getting started](docs/getting-started.md): installation, CLI, UI, offline mode.
- [Architecture](docs/architecture.md): data flow and module responsibilities.
- [Configuration](docs/configuration.md): providers, paths, policies, environment variables.
- [Local HTTP API](docs/api.md): endpoints and request fields.
- [Testing](docs/testing.md): checks, coverage, and reproducibility.
- [Evaluation](docs/evaluation.md): labeled scenarios and benchmark scoring.
- [Research background](docs/research.md): the original P1–P5 design references.
- [Known limitations](docs/known-limitations.md): existing behavior and constraints.

## Development

From the repository root, with the virtual environment active:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

The suite forces the stub provider, dry-run responses, and disabled external
static tools. CI is configured for Windows and Linux on Python 3.11 and 3.12.
See [CONTRIBUTING.md](CONTRIBUTING.md) for change and validation guidelines.

## License

Copyright (c) 2026 Oussama Jeddou. Released under the [MIT License](LICENSE).
