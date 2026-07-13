# CyberLLM — Static-First, Multi-Agent LLM Cybersecurity

CyberLLM is a research prototype that pairs a **deterministic static-analysis
floor** with **LLM reasoning** and a **guarded action engine** to both *defend*
and *red-team* software — with a focus on automotive / edge (SDV) code. It
**analyses code statically** (as text + AST + LLM reasoning) and **never executes
the code under test**; any remediation or response action defaults to **dry-run**.

It ships two mirror pipelines and a polished local web UI:

- **Defense (blue team):** scan source code / logs / deployment topology →
  detect vulnerabilities → decide a response *tier* → build a **guarded,
  dry-run** remediation plan → auto-remediate & re-verify → remember the outcome.
- **Attack (red team):** recon → reframe findings as exploits → choose a
  poison/trigger chain → **ethics-gate** it → emit benign proof-of-concept
  scripts → **LLM-simulate** their effect against the target (no execution).

> **Design principle — defense in depth.** A deterministic detection floor +
> dry-run-by-default + a guard the LLM can only ever *tighten*. No single
> probabilistic component can cause harm on its own.

---

## Highlights

- **Three-layer detection** — regex floor ⊕ AST analysers (bandit / semgrep) ⊕
  LLM refinement, merged so the deterministic layers win on duplicates.
- **Contextual security guard (paper 1)** — four properties (task / action /
  source-authorization / data-isolation) + the **H_a** "does this action serve
  the objective?" oracle, applied per-step and per-trajectory.
- **Action engine** — rule-specific **playbooks** → typed `ActionPlan` →
  executor over a schema-validated, audited **MCP tool registry**, dry-run by
  default.
- **Signed cross-session memory** — HMAC-signed SQLite incident store; reads
  verify signature + source, defeating memory-poisoning.
- **Automotive security benchmark** — 47 ground-truthed vulnerabilities across
  original C / C++ / Rust ECU code, with detection *and* remediation metrics.
- **Local web UI** (zero dependencies) — **Scan**, **Benchmark**, and **Attack**
  tabs with a Finding Explorer, auto-remediation, and PoC simulation.
- **Runs on clone** — with no LLM credentials it falls back to a deterministic
  offline stub, so the pipeline and tests always run.

### Research basis
The design cites five papers by shorthand throughout the code:
**P1** contextual security (4 properties + H_a oracle) · **P2** AgentHeLLM (asset
taxonomy + actor/datasource graph, poison/trigger paths) · **P3** rules-as-context
/ OCL topology checks · **P4** Härer schema-driven agents · **P5** layered,
tiered, adaptive response.

---

## Quick start

```bash
pip install -r requirements.txt          # PyYAML is the only hard dependency
pip install bandit                        # optional: real AST layer for Python (recommended)
```

**LLM provider (optional but recommended).** The default is **Azure OpenAI
gpt-4o**. Put credentials in a git-ignored `.env` at the project root:

```dotenv
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_ENDPOINT=https://<your-resource>.openai.azure.com
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_API_VERSION=2024-10-21
```

Without valid credentials, CyberLLM automatically uses the **offline stub** (a
deterministic, network-free model) so everything still runs.

### 1. Web UI (recommended)

```bash
python server.py                          # → http://127.0.0.1:8000
```

Open the URL. Toggle **Deep (AI)** to use the live LLM; leave it off for the
instant, offline deterministic layers. Three tabs:

| Tab | What it does |
|-----|--------------|
| **🛡️ Scan** | Paste/load code → verdict overview, a clickable **pipeline** (detect → decide → act → guard), and a **Finding Explorer** (findings · source slice · fixed-output slice). On a Deep scan it **auto-remediates** (guard-gated, per finding) and shows a **Correction Result** with before/after. |
| **📊 Benchmark** | Runs the scanner over the automotive corpus vs. ground truth → coverage, precision/recall/F1, per-file/severity/language breakdowns. Optional **Measure resolved** also auto-remediates and reports the resolution rate. |
| **🎯 Attack** | Ethics-guarded red-team analysis: recon → exploit explorer (click an exploit for its **PoC** and a **simulated outcome** against the code) → poison/trigger chain → ethics verdict. Scripts are generated as text, **never executed**. |

Browser-initiated actions are always **dry-run** — no OS command runs from the UI.

### 2. Command line

```bash
# Defense (default)
python pipeline.py --example small                     # a bundled scenario set
python pipeline.py --code path/to/file_or_dir --log app.log --deployment topo.yaml

# Attack (red team)
python pipeline.py --mode attack --example small
python pipeline.py --mode attack --code app.py --scenario "Exfiltrate fleet records"

# Both, side by side
python pipeline.py --mode both --example medium

# -v debug (timings, prompts, static-vs-LLM split) · -q quiet (summary only)
```

Results are written to `memory/` (per-run JSON) and a detailed step-by-step
trace to `run_logs/<timestamp>_<mode>_<scenario>/` (`_summary.md`, `_trace.log`).

---

## The automotive benchmark

`benchmark/automotive/` is an independent, ground-truthed corpus: **9 original
C / C++ / Rust ECU modules** (CAN gateway, UDS diagnostics, secure boot, OTA,
MQTT telemetry, ADAS sensor fusion, CAN parser, key store, vehicle API) seeded
with **47 layered vulnerabilities** — plus **2 clean controls** for
false-positive measurement. There are no hint comments; every flaw is located in
`ground_truth.yaml`. See [`benchmark/automotive/README.md`](benchmark/automotive/README.md).

Reference results (location-based matching, ±3 lines; precision measured on the
clean controls):

| Mode | Coverage | Precision | Recall | F1 |
|------|:--------:|:---------:|:------:|:--:|
| **Fast** (offline: regex + bandit/semgrep) | ~34% | 1.000 | 0.34 | 0.51 |
| **Deep** (live gpt-4o + completeness pass) | ~70% | 1.000 | 0.70 | ~0.83 |

Deep numbers vary a few points run-to-run (the model is non-deterministic).

---

## Repository structure

```
CyberLLM/
├── server.py               # local web-UI server (stdlib http.server, zero deps)
├── pipeline.py             # orchestrator: defense + attack pipelines, re-planning, CLI
├── llm_client.py           # LLM provider abstraction (azure/openai/anthropic/ollama/github/stub)
├── run_logger.py           # per-run forensic trace writer (run_logs/)
├── evaluate.py             # static evaluation harness (recall / false-positive rate)
├── verify.py               # 30-second offline smoke test (no pytest needed)
├── config.yaml             # all tunables: LLM, agents, scanners, guard, memory, examples
├── requirements.txt · pytest.ini
│
├── agents/                 # the multi-agent system
│   ├── base_agent.py       #   P4 schema-driven template + mandatory provenance
│   ├── source_code_scanner.py · log_analyzer.py · deployment_scanner.py
│   ├── decision_agent.py   #   response-tier decision (P5) + asset tagging (P2)
│   ├── security_guard.py   #   P1 four-property guard (check / check_step / check_trajectory)
│   ├── ha_judge.py         #   H_a action-alignment oracle
│   ├── memory_store.py     #   signed (HMAC) cross-session incident memory
│   ├── action_engine/      #   playbooks → ActionPlan → executor → MCP tool registry
│   └── attack/             #   red-team mirror (recon, exploiters, orchestrator, ethics, generator)
│
├── tools/
│   ├── static_analyzer.py  # regex floor + bandit/semgrep AST layer + finding merge/dedup
│   └── mcp_tools.py · log.py · tokens.py
│
├── rules/                  # detection knowledge base (code / log / topology / attack / native)
├── skills/                 # declarative response + attack skills
├── webapp/index.html       # single-page UI (Scan · Benchmark · Attack) — inline CSS/JS
├── benchmark/automotive/   # ground-truthed C/C++/Rust security benchmark + labels
├── examples/               # sample code, logs, deployments, labelled scenario sets
├── tests/                  # pytest suite (185 tests)
└── memory/                 # runtime incident store (git-ignored; .gitkeep only)
```

---

## Safety model

- **Static-first:** the code under test is never executed — detection is
  regex + AST + LLM reasoning. Even the red-team side does passive recon and
  emits PoC *text*; the attack "simulation" is LLM reasoning, not execution.
- **Dry-run by default:** the action engine and MCP tools return a
  "would-execute" envelope unless explicitly run live. `CYBERLLM_FORCE_DRY_RUN`
  can force dry-run on but nothing can force real execution against your intent;
  the web server hard-forces dry-run.
- **Guarded:** every action/step passes the P1 `SecurityGuard`; the H_a oracle
  can only *tighten* the deterministic floor. The attack side is gated by an
  `EthicsGuard` that checks scope/target and redacts destructive payloads.
- **Signed memory:** incidents are HMAC-signed; reads verify signature + source.

---

## Testing

```bash
python verify.py                                  # 30-second offline smoke check
python -m pytest tests/ -q                        # full suite (185 tests)
```

The suite is hermetic via three env kill-switches (set automatically in
`tests/conftest.py`): `CYBERLLM_FORCE_STUB` (offline LLM),
`CYBERLLM_FORCE_DRY_RUN` (no real commands), `CYBERLLM_NO_EXTERNAL_STATIC` (skip
bandit/semgrep) — so results are deterministic regardless of provider or
installed binaries.

---

## Configuration (`config.yaml`)

| Section | Purpose |
|---------|---------|
| `llm_configs` | Named LLM profiles (`default`, `reasoning`) — provider, model, temperature, tokens. |
| `scanners` | `external_static` (bandit/semgrep), `use_llm`, `second_pass` (completeness critic). |
| `agent_configs` | Per-agent LLM profile + objective string (the guard checks against these). |
| `security` | P1 allowed objectives, authenticated sources, trusted destinations. |
| `response_tiers` | P5 confidence thresholds (soft / moderate / hard). |
| `guard` | H_a judge + per-step checking toggles; prompt-token budget. |
| `action_engine` | `dry_run`, workspace, re-planning rounds, LLM tool-selection. |
| `attack` | Ethics/scope: allowed scenarios, authorized targets (`allow_all_in_dev`). |
| `example_sets` | Named batches for `--example`. |

Two dev-only escape hatches to disable before any real deployment:
`attack.allow_all_in_dev` and the `*` wildcard in `attack.authorized_targets`;
also set a real `CYBERLLM_MEMORY_KEY` instead of the dev signing key.

---

## Notes

- `memory/`, `run_logs/`, `mcp_workspace/`, and `.env` are git-ignored (runtime
  output / secrets).
- The optional `juliet` example set uses a large third-party CWE corpus that is
  **not** shipped in this repository; the automotive benchmark is the intended
  showcase. Missing example inputs are skipped gracefully.
- This is a research prototype: P1's oracles are approximations (each guard check
  is *named* so it can be replaced), and the LLM layer is probabilistic — hence
  the deterministic floor and the guard.
