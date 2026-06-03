# Papers Notes — Reading Guide

These notes distill the five reference papers into a goal-directed form,
keeping **only** the information that helps build the CyberLLM project
described in `../image.png` (LLM Agents for Cybersecurity, with automotive
as the primary domain).

## Project recap (from `image.png`)

**Goal.** Build defense (and optionally attack) LLM agents that autonomously
analyze logs, source code, and system configurations to:

- identify vulnerabilities,
- detect anomalies,
- generate actionable insights,
- and, when appropriate, take automated response actions.

**Architecture pieces shown in the diagram.**

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

**Technical components (mandated).**
- LLM core that ingests text inputs (user hints, logs, source code, configs).
- MCP-based external tools for scanning / analysis / defense / traffic capture.
- Agent **skills** definition for different defense and attack strategies.
- *(Optional)* Persistent agent **memory** for defense/attack.

## How to read this folder

Read in this order — it goes from foundations to applied design:

1. **`paper4_Multi_Agent_LLM_System_Spec.md`** — Härer.
   *Why first.* It is the cleanest blueprint for a working multi-agent LLM
   system: agent schema, prompt/action/evaluation functions, stack-based
   execution, and cybersecurity test cases (CyberMetric Q&A, server +
   network security tasks). This is the closest paper to a runnable
   reference implementation.

2. **`paper5_LLM_Orchestrated_MAS_Edge_Defense.md`** — Collins et al.
   *Why second.* High-level layered architecture (Edge Agent Layer / LLM
   Orchestration Layer / Security Intelligence Layer) and the
   detection-analysis-response-verification agent roles. Gives the
   coordination "shape" of the system.

3. **`paper3_LLM_Empowered_Functional_Safety_Security_by_Design.md`** —
   Petrovic et al. (TUM). *Why third.* This is the most directly aligned
   with the project diagram: event-chain models, RAG over VSS / CAN
   catalogs, OCL rules over a metamodel, automated correction loop.
   This is essentially the *implementation pattern* of the diagram.

4. **`paper1_LLM_Agent_Security_Framework.md`** — Siu et al. (UC Berkeley
   / UC Santa Cruz / Duke). *Why fourth.* Formal contextual security
   framework (task / action / source / data-isolation properties + oracle
   functions). Use this to **validate** that your defense agent's actions
   are themselves safe.

5. **`paper2_Agent2Agent_Threats_AgentHeLLM.md`** — Stappen et al.
   (BMW / TUM). *Why last.* Threat modeling specifically for in-vehicle
   LLM agents: human-centric asset taxonomy, poison-path vs trigger-path
   attack graphs. Use this to define what your **attack** agents simulate
   and what your **defense** agents must catch.

## After the per-paper notes

Read **`synthesis_project_blueprint.md`** — it maps every component of
your project (from `image.png`) to concrete ideas pulled from the five
papers, and explains how the first pipeline in `../CyberLLM/` instantiates
that mapping.
