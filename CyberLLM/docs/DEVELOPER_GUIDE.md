# CyberLLM — Developer Guide (master index)

> **Read me first.** This is the front door to the CyberLLM documentation.
> It is written for someone who has **never seen this code** and may not
> have a strong background in cybersecurity or LLMs. By the time you finish
> the chapters linked below, you should be able to answer essentially *any*
> question about what the program does, why it is built the way it is, and
> what every file, class, and function does.

CyberLLM is a research/engineering project that uses **Large Language
Models (LLMs)** as the "brains" of a **multi-agent cybersecurity system**.
It has two halves: a **defense** side that finds and responds to security
problems, and an **attack** side that produces proof-of-concept exploits
for *authorised* red-team testing. Its home domain is **cars / Software
Defined Vehicles (SDV)** and edge computing, but it generalises.

---

## How this documentation is organised

The material is split into focused chapters under [`guide/`](guide/).
**Read them in order the first time**; afterwards use them as reference.

| # | Chapter | What you'll learn | For whom |
|---|---------|-------------------|----------|
| 1 | [Foundations](guide/01_FOUNDATIONS.md) | The problem, the domain, every key term (LLM, agent, MCP, CAN bus, vulnerability…), the 5 research papers in plain English, and the one big design rule ("static-first"). | **Start here if you're new.** |
| 2 | [Architecture & data types](guide/02_ARCHITECTURE.md) | The two pipelines, how agents talk to each other, the directory map, and **every data structure** field-by-field. | Everyone |
| 3 | [The defense pipeline, deep](guide/03_DEFENSE_DEEP.md) | The full "this takes X and gives Y, which goes to Z" walkthrough of the defense flow, including the new adaptive re-planning loop. | Everyone — the centerpiece |
| 4 | [The attack pipeline, deep](guide/04_ATTACK_DEEP.md) | The same deep walkthrough for the red-team mirror. | Everyone |
| 5 | [Code reference](guide/05_CODE_REFERENCE.md) | **Every file, class, and function** explained. The "answer any code detail" chapter. | When you need specifics |
| 6 | [Subsystems: LLM, config, guards, memory, tools](guide/06_SUBSYSTEMS.md) | Deep dives on the LLM layer (incl. Azure), `config.yaml` every key, the security guards, the memory store, and the action engine / MCP tools. | When you work on one subsystem |
| 7 | [Running, testing, extending & FAQ](guide/07_RUN_TEST_EXTEND_FAQ.md) | How to run it, how the tests work, how to add things, troubleshooting, and a Q&A. | Day-to-day work |

There are also three companion docs that pre-date this guide and remain
accurate:
- [`AGENTIC_WORK.md`](AGENTIC_WORK.md) — *why* the system counts as "agentic".
- [`LEARNING_AND_GUARD_HARDENING.md`](LEARNING_AND_GUARD_HARDENING.md) — memory + guards design note.
- [`PRODUCTION_UPGRADES.md`](PRODUCTION_UPGRADES.md) — the most recent upgrade (the adaptive loop, LLM tool selection, per-step guard, cross-session memory, real tools).

And the project's narrative overview is the top-level [`../README.md`](../README.md).

---

## The 60-second mental model

If you remember only one diagram, remember this — the **defense** flow:

```
  source code ┐
  logs        ├─►  3 scanner agents  ─►  findings  ─►  decision agent  ─►  "how bad is it?"
  deployment  ┘    (rules first,                        (a tier + why)        │
                    then the LLM)                                              ▼
                                                          action engine  ─►  a plan of tool steps
                                                          (executes them, safely)   │
                                                                                    ▼
                                                          security guard  ─►  allow or refuse
                                                                                    │
                                                       if it didn't resolve, LOOP back ↑ and escalate
                                                                                    │
                                                                                    ▼
                                                          memory + run log  ─►  "remember what worked"
```

Two ideas make the whole thing trustworthy and worth understanding:

1. **Static-first.** Before any LLM is asked anything, a *deterministic*
   pass runs (plain pattern-matching and graph checks). The LLM only
   *refines* those results. So the system produces real, traceable answers
   even with **no API key and no internet** — it ships with a fake
   "stub" model for exactly that. (Full explanation in chapter 1.)
2. **Typed hand-offs + guards.** Agents pass each other small, well-defined
   data records (not free text), and a separate "guard" can refuse any
   dangerous action. That is what makes it *auditable*.

---

## Current status (what's true *right now*)

- **LLM provider:** the default is **Azure OpenAI** running **gpt-4o**
  (configured in [`../config.yaml`](../config.yaml), credentials in
  `.env`). Other providers — GitHub Models, OpenAI, Anthropic, Ollama, and
  the offline **stub** — are all supported. If credentials are missing the
  client **automatically falls back to the offline stub**, so the program
  always runs.
- **Adaptive loop:** the defense pipeline now *re-plans*. The action engine
  executes a response; if it didn't resolve the incident (a step was
  refused or failed), the outcome is fed back to the decision agent which
  **escalates** and tries again, up to a bounded number of rounds.
- **LLM picks tools:** the deterministic playbook is still the floor, but
  the LLM may *propose extra* MCP tools — each one schema-validated and
  passed through the guard.
- **Per-step guard:** the security guard now inspects the *real* shape of
  each tool step (its side-effect, whether it needs authorisation).
- **Cross-session memory:** every run records *whether the response
  worked*, and future runs get a "we saw this before and tier X worked"
  recommendation.
- **Real tools, live by default:** the MCP tools call real `nmap`,
  `bandit`, `semgrep`, `tshark`/`tcpdump`/`candump`, `iptables`/`netsh`,
  etc. `config.yaml → action_engine.dry_run` is now **`false`** (live), so a
  defense run *actually executes* its response tools — but each tool still
  (a) falls back to a simulated "would-execute" envelope when its real
  binary isn't installed, (b) passes the per-step `SecurityGuard`, and
  (c) is announced on screen (`MCP tool ▶ … → status [real|sim]`). The test
  suite and `verify.py` force dry-run (`CYBERLLM_FORCE_DRY_RUN=1`) so they
  never touch the OS. Set `dry_run: true` (or that env var) to simulate.
- **Tests:** `python verify.py` (offline smoke, 6/6) and
  `python -m pytest tests/` (**155 tests**) both pass.

---

## The fastest way to see it work

```bash
cd CyberLLM
pip install --user pyyaml          # the only mandatory dependency
python verify.py                   # 30-second offline check → 6/6 OK
python pipeline.py --example small # run the defense pipeline on 5 demo scenarios
```

Add `-v` for a deep trace (every prompt, response, step, and decision).
Everything runs offline on the stub; add Azure credentials to `.env` to use
real gpt-4o. See chapter 7 for all the run options.

Now go to **[chapter 1 — Foundations](guide/01_FOUNDATIONS.md)**.
