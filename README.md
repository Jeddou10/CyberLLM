# CyberLLM — LLM Agents for Cybersecurity

CyberLLM is a research prototype of **defense and attack LLM agents** that
autonomously analyse source code, logs, and system-deployment topologies to
identify vulnerabilities, reason about them, and — under strict guards — either
**remediate** them (blue team) or produce **benign proof-of-concept exploits**
for authorised red-team exercises. The primary domain is **automotive /
software-defined vehicles**; the design generalises to any edge or cloud system
that can be described as an actor / datasource graph.

The guiding principle is **static-first, defense-in-depth**: a deterministic
static-analysis floor carries the detection, the LLM only *refines* it, every
action passes a contextual security guard, and nothing runs against the code
under test — remediation and response actions default to **dry-run**.

---

## The five reference papers

The architecture is derived from five papers, cited by shorthand (**P1**–**P5**)
throughout the code. This is the research foundation of the project.

| # | Paper | Authors (year) | Role in CyberLLM |
|---|-------|----------------|-------------------|
| **P1** | *A Framework for Formalizing LLM Agent Security* | **Siu, He, Montgomery, Wang, Gong, Wang, Song** — UC Santa Cruz / UC Berkeley / Duke (2026) · arXiv:2603.19469 | Four contextual-security properties (task / action / source-authorization / data-isolation) + the **H_a** action-alignment oracle → the runtime security & ethics guards. |
| **P2** | *Agent2Agent Threats in Safety-Critical LLM Assistants: A Human-Centric Taxonomy* | **Stappen, Turan, Hagerer, Groh** — BMW Group + TUM (2026) · arXiv:2602.05877 | Human-centric asset taxonomy + actor/datasource graph with **poison-path vs trigger-path** attack modelling → deployment analysis and the attack pipeline. |
| **P3** | *LLM-Empowered Functional Safety and Security by Design in Automotive Systems* | **Petrovic, Zolfaghari, Pan, Knoll** — TUM (2026) · arXiv:2601.02215 | Rules-as-context (OCL-style topology rules), retrieve-and-refine prompting, and the automated code-correction loop. |
| **P4** | *Specification and Evaluation of Multi-Agent LLM Systems* | **Felix Härer** — FHNW (2025) · arXiv:2506.10467 | The engineering backbone: schema-driven agents, prompt templating, provider abstraction, typed agent-to-agent hand-off. |
| **P5** | *LLM-Orchestrated Multi-Agent Coordination for Adaptive Cyber Defense at the Edge* | **Collins, James, Thomas** (2026) | The layered architecture, **tiered / adaptive response**, and the learning-from-memory loop. |

---

## What's in this repository

The full project — code, web UI, benchmark, and tests — lives in the
[`CyberLLM/`](CyberLLM/) directory.

```
.
├── README.md          # this front page
└── CyberLLM/          # the project (code, web UI, automotive benchmark, tests)
    └── README.md      # full documentation: setup, architecture, benchmark, safety model
```

**Two mirror pipelines** share one schema-driven backbone (P4):

- **Defense (blue team):** scan code / logs / deployment → detect
  vulnerabilities → decide a response *tier* (P5) → build a guarded, dry-run
  remediation plan → auto-remediate & re-verify → record the outcome to signed
  memory.
- **Attack (red team):** passive recon → reframe findings as exploits → choose a
  poison/trigger chain (P2) → **ethics-gate** it (P1) → emit benign PoC scripts →
  **LLM-simulate** their effect against the target. Scripts are never executed.

---

## Quick start

```bash
cd CyberLLM
pip install -r requirements.txt          # PyYAML is the only hard dependency

python server.py                          # web UI → http://127.0.0.1:8000
#   or
python pipeline.py --example small        # command-line defense run
```

With no LLM credentials, CyberLLM falls back to a deterministic **offline stub**,
so the pipeline, the web UI, and the full test suite all run out of the box. To
use a live model, add Azure OpenAI (or OpenAI / Anthropic / Ollama) credentials —
see [`CyberLLM/README.md`](CyberLLM/README.md#quick-start) for the full setup,
architecture walkthrough, benchmark results, and safety model.

---

## Safety & ethics

The code under test is never executed; detection is static (regex + AST + LLM
reasoning). Response and remediation actions are **dry-run by default**, every
action passes the P1 `SecurityGuard`, and the attack side is gated by an
`EthicsGuard` that enforces scope and redacts destructive payloads. This project
is intended for academic use, authorised red-team exercises, and defensive
research only — do not run the attack pipeline against systems you do not own or
have explicit written authorisation to test.
