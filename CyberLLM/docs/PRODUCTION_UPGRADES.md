# Production Upgrades — closing the agentic gaps

This document describes the upgrade that turned the four "not yet agentic"
items (previously listed in [`AGENTIC_WORK.md`](AGENTIC_WORK.md) §8) into
real, tested features, plus the move from stub MCP tools to **real
production tools**. Read it as a companion to the
[`DEVELOPER_GUIDE.md`](DEVELOPER_GUIDE.md).

Everything here keeps the project's invariants: **static-first**, **safe
by default** (dry-run), **offline-runnable** (deterministic stub), and the
**138 → 155 test suite stays green**.

---

## 0. TL;DR — what changed

| # | Gap (was) | Now | Key files |
|---|-----------|-----|-----------|
| 1 | Agents don't re-plan on each other's results | **Adaptive re-planning loop**: the action engine *executes*, the outcome feeds back to the decision agent, which escalates the tier and re-plans (bounded rounds) | `pipeline.py`, `agents/decision_agent.py` |
| 2 | LLM is not a first-class tool selector (playbooks are deterministic) | **LLM-as-tool-selector**: the MCP catalogue is exposed to the LLM, which proposes extra tools; every pick is schema-validated and per-step-guarded | `agents/action_engine/generator.py` |
| 3 | Per-step guard wired but only the legacy guard runs | **Per-step contextual check on the real step shape**: `SecurityGuard.check_step` reads the step's `side_effect`/`requires_authorization` and feeds the H_a judge the full threat context | `agents/security_guard.py`, `pipeline.py` |
| 4 | Memory is one-shot per run | **Cross-session learning**: each run records *whether the remediation worked*; `recommend()` surfaces "we saw this before and tier X worked" into the next decision | `agents/memory_store.py`, `agents/decision_agent.py`, `pipeline.py` |
| 5 | MCP tools partly stubbed | **Real tools**: `nmap` + `tshark/tcpdump/candump` added to the engine; legacy `tools/mcp_tools.py` rewritten with real `nmap`/`bandit`/`semgrep`/capture backends | `agents/action_engine/mcp_tools.py`, `tools/mcp_tools.py` |
| + | (bug) final guard objective mismatched `alert_only` actions | **Fixed**: objective is now derived from the action kind, so an `alert_only` primary serves a *reporting* objective | `pipeline.py` |

---

## 1. The adaptive re-planning loop (closes gap #1)

**Before:** scanners → decision (one tier) → action (execute once) → guard.
The decision never saw the execution outcome.

**Now** the defense pipeline runs a **bounded loop** (`action_engine.max_replan_rounds`, default 2):

```
            ┌───────────────────────────────────────────────┐
            │                                               │
 findings ─►│  DecisionAgent.run(findings, feedback) ─► tier │
            │            │                                  │
            │            ▼                                  │
            │  ActionGenerator.generate ─► ActionReport     │
            │            │   (per-step guard runs here)     │
            │            ▼                                  │
            │  SecurityGuard.check + check_trajectory       │
            │            │                                  │
            │     resolved?  ──yes──► break                 │
            │            │no                                │
            │            ▼                                  │
            │  feedback = {prior_tier, plan_status,         │
            │              guard_allowed, reason}  ─────────┘  (escalate)
            └───────────────────────────────────────────────┘
```

- **The decision agent consumes the feedback** (`run(..., feedback=…)`) and
  applies a **deterministic escalation policy** on top of the LLM's call:
  if the previous attempt failed or was refused, the tier is bumped at
  least one notch above the tier that failed (`none < soft < moderate <
  hard`). This works with the stub *and* a real model.
- **"Resolved"** = the final guard allowed **and** the plan completed (or
  there was nothing to remediate). Otherwise the loop escalates and tries
  again, up to `max_replan_rounds`.
- The full per-round history is written to the record under
  `replanning: {rounds, resolved, history[]}`.

**Live behaviour (Azure gpt-4o):** on the CAN scenario the loop ran 2
rounds; the per-step H_a judge refused one containment step (model
judgment), so the plan aborted, the outcome was fed back, the tier
re-escalated, and the result was recorded as `UNRESOLVED` with a full
audit trail. With the offline stub the same scenario resolves in round 1.

---

## 2. LLM-as-tool-selector (closes gap #2)

**Before:** the action plan came purely from deterministic playbooks.

**Now** (`ActionGenerator._llm_select_tools`, gated by
`action_engine.llm_tool_selection`):

1. The deterministic playbook builds the plan — **this is still the floor.**
2. The full MCP catalogue (`registry.schemas()` — names, domains,
   side-effects, descriptions) is shown to the LLM, which proposes extra
   tool calls as JSON.
3. **Every pick is validated**: the tool must exist in the registry *and*
   pass that tool's parameter-schema validation, or it is dropped.
4. Valid picks become `ActionStep`s (`rule_id="LLM-SELECTED"`), appended
   and re-ordered by `StepKind`. They run through the **same per-step
   SecurityGuard** as playbook steps — so the LLM cannot smuggle an
   unsafe action past the guard.

With the offline stub the prompt matches no canned branch, so no JSON is
returned and **no extra steps are added** — deterministic and test-safe.
With a real model it genuinely augments the plan (e.g. adds an
`observe.*` verification step).

---

## 3. Per-step contextual guard on the real step shape (closes gap #3)

**Before:** the per-step adapter translated each step into a *legacy*
`Action` and ran the one-shot `check()`, with a thin
`destination=internal` context.

**Now** `SecurityGuard.check_step(step, objective, inputs, decision_summary)`
evaluates the **actual `ActionStep`**:

- **privilege** is read from the step's declared `side_effect`
  (`destructive`) and `requires_authorization` — not a hard-coded kind
  list. A privileged step requires an authenticated source among the inputs.
- the **H_a judge** is given the step's `tool`, `rule_id`, `side_effect`,
  `description` **and the decision's threat summary**, so it reasons with
  the real threat picture instead of a stub. This both implements the
  "new step shape" check and makes the judge far better-informed.
- returns a dedicated `StepVerdict` (four properties + reason).

`pipeline.build_step_guard(guard, inputs, decision_summary)` wires it into
the executor, which calls it on **every** tool call.

---

## 4. Cross-session learning (closes gap #4)

**Before:** memory recorded an incident but not whether the response
*worked*; recall was within-session precedent only.

**Now** the signed store (`agents/memory_store.py`) records the **outcome**:

- two new signed fields — `plan_status` (the action-engine `PlanStatus`)
  and `remediation_ok` (did the response succeed end-to-end?) — added to
  `Incident`, the SQLite schema (with an `ALTER TABLE` migration for old
  DBs), and the HMAC signature.
- **`recommend(rule_ids)`** returns the most-similar *past* incident whose
  remediation **worked** (above a similarity threshold) — i.e. "we saw
  this pattern before, and tier X resolved it."
- the **Decision Agent** consults `recommend()` and, escalate-only, adopts
  a stronger precedent tier; the recalled few-shot now shows each past
  incident's `outcome=worked/…`.

Because the store persists across runs, this is genuine cross-session
learning. (Verified: running the same pattern twice, the second run picks
up a `sim=1.0` recommendation from the first.)

---

## 5. Real production MCP tools (closes gap #5)

### Action engine (`agents/action_engine/mcp_tools.py`)
Two real tools added to `default_toolset()`:

- **`network.port_scan`** — real `nmap -sT -Pn --open` (parsed), with a
  bounded **pure-Python TCP connect-scan fallback** when nmap is absent.
  `requires_authorization=True`; dry-run is the default gate.
- **`observe.packet_capture`** — real `tshark` → `tcpdump` → `candump`
  (whichever is present), bounded by a hard time cap; dry-run by default.

These complete the previously-deferred C.1 (nmap) and C.3 (packet capture)
roadmap items with real backends.

### Legacy registry (`tools/mcp_tools.py`)
The three `run()`-style tools are now **real**, not canned:
`PortScanTool` (nmap/socket), `StaticAnalysisTool` (real `bandit`/`semgrep`
JSON), `PacketCaptureTool` (tshark/tcpdump/candump). Intrusive tools
default to a **dry-run envelope** and execute only with `live=True`;
read-only static analysis runs whenever a backend is installed.

> All subprocess calls use an explicit `args=[...]` list (never
> `shell=True`), bounded timeouts, and structured output parsing.

---

## 6. The full new code structure

`▲` = new file, `◆` = materially changed in this upgrade.

```
CyberLLM/
├── pipeline.py                  ◆ adaptive re-planning loop; per-step guard wiring;
│                                  objective-derivation fix; outcome recording
├── evaluate.py                    static evaluation harness (unchanged)
├── verify.py                      offline smoke test (forces stub)
├── config.yaml                  ◆ + action_engine{} section (dry_run, work_dir,
│                                  max_replan_rounds, llm_tool_selection)
├── llm_client.py                  providers: stub | azure | github | openai | anthropic | ollama
├── run_logger.py                  per-run debug trace
├── .env                           AZURE_OPENAI_* (active) + GITHUB_TOKEN (alt) — git-ignored
│
├── agents/
│   ├── base_agent.py              Input(provenance)/Finding/AgentResult; token budget; delegation
│   ├── source_code_scanner.py     defense scanner (static + LLM + merge)
│   ├── log_analyzer.py            defense scanner
│   ├── deployment_scanner.py      defense scanner
│   ├── decision_agent.py        ◆ feedback escalation + cross-session recommend() nudge
│   ├── action_generator.py        shim → action_engine
│   ├── security_guard.py        ◆ + check_step() (new step shape) + StepVerdict
│   ├── ha_judge.py                H_a oracle (separate LLM call, cached)
│   ├── memory_store.py          ◆ + plan_status/remediation_ok + recommend() (cross-session)
│   ├── action_engine/
│   │   ├── types.py               ActionPlan/ActionStep/ActionReport/ToolResult/enums
│   │   ├── mcp_registry.py        MCPTool base + registry (validate, dry-run, audit)
│   │   ├── mcp_tools.py         ◆ + NetworkPortScan (nmap) + ObservePacketCapture (tshark…)
│   │   ├── playbooks.py           rule-id → typed step sequence; build_plan()
│   │   ├── executor.py            walks plan: pre → guard → call → post → rollback
│   │   └── generator.py         ◆ + LLM-as-tool-selector (_llm_select_tools)
│   └── attack/                    red-team mirror (discovery / exploiters / orchestrator /
│                                  generator / ethics_guard) — unchanged
│
├── tools/
│   ├── static_analyzer.py         the deterministic floor (regex / heuristics / graph)
│   ├── mcp_tools.py             ◆ real nmap / bandit / semgrep / tshark backends (run() API)
│   ├── tokens.py                  token estimator + budget
│   └── log.py                     Console (stderr diagnostics; verbose/debug)
│
├── skills/skills.py               defense + attack skill catalogues
├── rules/                         example_rules / extended_rules / attack_rules YAML
├── examples/                      small/medium/large code, logs, deployments, labels.yaml
├── memory/                        per-run JSON + incidents.db (signed, now with outcomes)
├── run_logs/                      per-run step traces
├── docs/
│   ├── DEVELOPER_GUIDE.md          full code walkthrough
│   ├── AGENTIC_WORK.md             why it's agentic
│   ├── LEARNING_AND_GUARD_HARDENING.md   memory + guards deep-dive
│   └── PRODUCTION_UPGRADES.md    ▲ this file
└── tests/
    ├── … (existing suites) …
    └── test_production_upgrades.py ▲ 17 tests for the upgrades above
```

---

## 7. Config knobs (all in `config.yaml`)

```yaml
action_engine:
  dry_run: true              # never run a destructive command unless false
  work_dir: mcp_workspace
  max_replan_rounds: 2       # how many decision↔action rounds before giving up
  llm_tool_selection: true   # let the LLM propose extra MCP tools (validated + guarded)

guard:
  ha_judge_enabled: true     # the separate H_a oracle call
  per_step_enabled: true     # per-step contextual check (check_step) on every tool call
  max_prompt_tokens: 4096

memory:
  enabled: true
  recall_k: 5
  reject_unverified: true    # drop tampered / unauthenticated rows
```

**Tuning notes**
- A real H_a judge is *strict*: it can refuse an individual containment
  step (which aborts the plan and triggers a re-plan). If you want fewer
  refusals on a known-good scenario, either enrich the decision summary,
  set `guard.ha_judge_enabled: false` (keep only the deterministic
  action-alignment map), or raise `max_replan_rounds`.
- `llm_tool_selection` and the re-planning loop add LLM calls per round.
  On a rate-limited tier, lower `max_replan_rounds` to 1 or disable
  `llm_tool_selection`.

---

## 8. How to run & verify

```bash
python verify.py                         # offline smoke (forces stub) → 6/6
python -m pytest tests/                   # full suite → 155 passed
python pipeline.py -v --code examples/small/02_can_gateway.py \
   --log examples/logs/03_can_injection.log \
   --deployment examples/deployments/03_complex_sdv.yaml
```

In the `-v` output you'll now see the adaptive loop:
`round 1 decision → round 1 action → round 1 result → (re-planning…) →
round 2 …`, the per-step statuses, the trajectory check, the memory
recommendation (when a precedent exists), and the final
`replanning: N round(s), final=RESOLVED|UNRESOLVED`.

---

## 9. Safety recap

- **Dry-run is the default** — no destructive command (firewall, isolate,
  rotate, port scan, packet capture) runs unless `action_engine.dry_run:
  false` *and* the real binary is present *and* the per-step guard allows.
- **The LLM cannot bypass the guard** — every LLM-selected tool is
  schema-validated and runs through `check_step`.
- **Memory is tamper-evident** — outcomes are part of the HMAC signature;
  a poisoned or unauthenticated row is dropped on read.
- **Offline still works** — with no credentials the deterministic stub
  drives the whole loop; with Azure gpt-4o (the configured default) the
  same loop uses the real model.
```
