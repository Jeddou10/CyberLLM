# The Agentic Work in CyberLLM

This document explains *how* the system is agentic, *who* the agents
are, *what* they pass to one another, and *what is now possible*
since the defense action engine moved from a proof-of-concept to a
proper MCP-style planner + executor.

---

## 1. What "agentic" means here

A pipeline is *agentic*, in this project, when **all six** of these
properties hold simultaneously:

| Property | What it means in CyberLLM |
|---|---|
| **Goal-directed** | Every agent carries an explicit `objective` string (the user-supplied goal it is allowed to pursue, in the sense of paper 1's `H_p` oracle). |
| **Specialised role** | One agent per problem — source-code, log, topology, decision, action — instead of one monolithic LLM call. |
| **Typed hand-off** | Agents exchange *structured records* (Findings, Decisions, Plans, Reports), not free-form text. The next agent can reason mechanically over the previous agent's output. |
| **Tool use** | Agents may call deterministic tools (regex scanners, graph checks, MCP firewall / patch / notify) — not just produce text. |
| **Observation + feedback** | Agents observe the world (pre/post conditions, real or simulated metrics) and react: retry, roll back, escalate, refuse. |
| **Guardrails** | A separate component (Security Guard, Ethics Guard) can refuse a step, and the framework supports refusal as a first-class outcome. |

Anything missing one of these six is "automation", not an agent.

---

## 2. The roster of defense-side agents

The defense pipeline (the focus of this update) is composed of five
agents plus two cross-cutting components:

```
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ Source-code      │    │ Log analyser     │    │ Deployment       │
│ scanner          │    │                  │    │ scanner          │
│   role: static + │    │ role: anomaly    │    │ role: topology   │
│         LLM hits │    │  detection       │    │  rule checks     │
│   inputs : code  │    │ inputs : log     │    │ inputs : YAML    │
│   output : list  │    │ output : list    │    │ output : list    │
│           Finding│    │         Finding  │    │         Finding  │
└────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
         │                       │                       │
         └───────────────┬───────┴───────────────────────┘
                         ▼
                 ┌───────────────┐
                 │ Decision      │  role: aggregate, asset-tag,
                 │ agent         │        pick tier + confidence
                 │ inputs:list[Finding]
                 │ output: Decision
                 └───────┬───────┘
                         ▼
                ┌────────────────┐
                │ Action engine  │  role: realise the decision
                │ (planner +     │  inputs: Decision (+ context)
                │  executor)     │  output: ActionReport
                └────────────────┘
                         │
            ┌────────────┴────────────┐
            ▼                          ▼
   ┌────────────────┐         ┌────────────────┐
   │ Security guard │         │ Run logger     │
   │  paper-1 4-prop│         │  per-step audit│
   └────────────────┘         └────────────────┘
```

Each agent is independently instantiable, independently testable, and
backed by **its own LLM configuration** (the decision agent uses a
reasoning-class model; everything else uses the cheaper default).
That separation is the schema-driven principle from paper 4.

---

## 3. The hand-off contracts

Every arrow above carries a *typed* record. Free-form LLM text exists
*inside* each agent (the prompt and the raw response) but never
crosses the boundary between agents.

| From → To | Contract |
|---|---|
| Scanner → Decision | `Finding{ rule_id, severity, evidence, explanation, source_agent, asset_category, line }` — produced by static analysis, refined by LLM, merged. |
| Decision → Action engine | `Decision{ summary, asset_categories_touched, recommended_tier, confidence, justification, findings[] }`. |
| Action engine → Pipeline | `ActionReport{ plan, status, summary, audit_log, tallies{...} }` plus a back-compat `Action` view. |
| Any step → Security guard | the proposed action + the current objective + the input set. |
| Any step → Run logger | one prompt + one response + a structured findings array (per agent). |

The contract is what makes the system *agentic and reproducible at the
same time*: any agent can be replaced with a smarter one (or a real
LLM, or a different vendor) without touching the rest, as long as the
typed record on the wire is the same.

---

## 4. The agentic loop, per agent

Inside each agent the loop is:

```
            ┌─────────────────────────────────────────────────┐
            │                                                 │
   inputs ──►  1. ground-pass             ──►  static hits    │
            │                                                 │
            ▼                                                 │
   2. constrained LLM call (prompt = rules + static + artefact)
            │                                                 │
            ▼                                                 │
   3. parse JSON response                ──►  LLM hits        │
            │                                                 │
            ▼                                                 │
   4. merge (static wins on duplicates)  ──►  typed record    │
            │                                                 │
            ▼                                                 │
            stash prompt + response + record  for the run-logger
            │
            ▼ hand-off
```

The decision agent and action engine work on the same skeleton but
their step 1 is different (no static-pass for the decision; a
playbook lookup for the action engine).

---

## 5. The action engine — what changed in this update

The previous action generator was a single switch: tier `soft` →
`rate_limit`, `moderate` → `block_ip`, `hard` → `isolate_node`, plus a
patch-code special case. That was honest about being a proof of
concept; it was not an agent.

The new action engine is **a planner + executor on top of an MCP-style
tool registry**. The conceptual diagram is:

```
                      Decision (asset categories, tier, findings)
                                         │
                                         ▼
                            ┌──────────────────────────┐
                            │   Plan builder           │
                            │  (paper-2/3/5 knowledge) │
                            └────────────┬─────────────┘
                                         ▼
                              ┌───────────────────┐
                              │   ActionPlan      │
                              │  ordered ActionStep
                              │  with pre/post,   │
                              │  rollback, side-  │
                              │  effect, severity │
                              └─────────┬─────────┘
                                        ▼
                          ┌──────────────────────────┐
                          │  ActionExecutor          │
                          │  - eval pre-conditions   │
                          │  - per-step guard check  │
                          │  - call MCP tool         │
                          │  - eval post-conditions  │
                          │  - retry on failure      │
                          │  - rollback on failure   │
                          └──────────────┬───────────┘
                                         ▼
                           ┌─────────────────────────┐
                           │   ActionReport          │
                           │   + MCP audit log       │
                           └─────────────────────────┘
```

### 5.1  The MCP-shaped tool registry

Each tool exposes:

- **name** (`firewall.block_ipv4`, `secrets.rotate`, `code.propose_patch`, …)
- **typed schema** (every parameter declared, enums validated)
- **side effect** (`read` / `write` / `destructive`)
- **idempotency** hint (so retries are safe)
- **`real_binary`** — the underlying CLI / API the tool wraps
- **`call(params)`** which routes to either:
  - `_do_call(params)` — real `iptables`, `bandit`, `semgrep`, `git`,
    `systemctl`, `urllib`, SMTP, …
  - `_dry_run(params)` — a professional dry-run envelope when the
    engine is in dry-run mode *or* the real binary is unavailable.
- **`verify(params, result)`** — optional verification hook used by
  the executor's post-condition check.

The current toolset has **twenty tools** across eight domains:
firewall, network, secrets, code, runtime, notify, observe, kb. Each
tool calls a real local command where one exists; on environments
that lack it (or the engine is in dry-run mode, which is the default)
the tool emits a typed `would-execute` result that the audit log
records and the post-condition can still reason about.

### 5.2  The playbook catalogue

A playbook is a typed sequence of `StepTemplate`s keyed to a rule id
(or a rule-id regex). Each template carries:

- a **kind** (`contain`, `observe`, `eradicate`, `recover`, `notify`,
  `audit`) — used by the planner to order the plan,
- a **target tool** + a **`params_fn`** closure that pulls the
  concrete parameters out of the finding (e.g. the suspect IP, the
  affected file, the vehicle id),
- **severity gate** (`severity_min`) — only fires for findings of at
  least this severity,
- **side effect** (so the executor / guard can gate destructive calls),
- **rollback template** — an inverse step the executor runs LIFO if a
  later step fails.

Specific playbooks exist for the high-impact rule ids
(`LOG-CAN-02` → safe-mode + ECU isolation + driver notify + forensic
snapshot, `CODE-003` → rotate + patch + history-scrub runbook,
`TOP-006` → critical incident + secret rotation, etc.). Anything not
covered specifically falls back to a family-generic playbook (code /
log / topology), and ultimately to a tier-generic playbook
(`soft` / `moderate` / `hard`) when no findings match.

### 5.3  The executor — the loop that makes it agentic

For every step the executor:

1. **Evaluates pre-conditions** via the same MCP registry the action
   tools use. Skip the step if any precondition fails.
2. **Runs the per-step Security Guard** — paper-1's four properties
   are checked *per tool call*, not just on the final action. A
   refusal on a containment step aborts the plan.
3. **Calls the MCP tool** with retries (back-off) on transient failures.
4. **Evaluates post-conditions** — did the step actually achieve
   what it claimed?
5. **Rolls back** on verify-failure or hard error, walking the
   completed-step stack LIFO and running each step's rollback step.
6. **Records every event** in the run-log + the registry audit.

The result is an `ActionReport` whose status is one of `completed`,
`partial_success`, `failed`, or `refused`, with a per-step status
matrix.

### 5.4  Why this is more agentic than the previous design

| Aspect | Old (PoC) | New (engine) |
|---|---|---|
| Inputs considered | tier only | every finding individually |
| Steps per response | 1 hard-coded action | N steps from a typed playbook |
| Tool surface | hard-coded `kind`/`target` | MCP registry, ~20 tools across 8 domains |
| Verifies its own work | no | pre + post conditions per step |
| Recovers from failure | no | retries + rollback (LIFO) |
| Auditable per step | no (just the final action) | every prompt, every tool call, every condition |
| Real side effects | none possible | available; gated by dry-run + guard |
| Safe by default | n/a | yes — dry-run is the default |

---

## 6. Safety: how the guards keep the agency in check

The fact that the agents now *can* take real actions makes the guards
the most important component of the system.

- **Security guard (paper 1).** Runs both at the top of the plan (the
  legacy entry point still goes through it) and **per step inside
  the executor** through the `GuardAdapter`. The four contextual
  properties (task / action / source / data) are evaluated against
  each step in turn.
- **Dry-run default.** The action-engine config exposes a `dry_run`
  switch defaulting to `True`. In dry-run mode no destructive
  MCP tool can change state — even if the OS-level binary is
  present. The audit log marks every record `dry_run=True`.
- **Authorisation hook.** Destructive tools (`secrets.rotate`,
  `runtime.safe_mode`, `network.isolate_node`, `code.scrub_git_history`)
  declare `requires_authorization=True`. The registry exposes a
  `set_authorization_hook(fn)` slot — connect it to your SOAR
  approval flow before going live.
- **Audit redaction.** The registry's audit log redacts obvious
  secrets (`password`, `secret`, `token`, `apikey`) before persisting,
  so the run-log is safe to share with reviewers.

---

## 7. What an agent run feels like from the operator's seat

Running the defense pipeline today, in dry-run mode, on a CAN-injection
scenario produces output along these lines (paraphrased):

```
[defense:can-injection] source-code scanner (1 file) → 7 findings
[defense:can-injection] log analyser                  → 3 findings
[defense:can-injection] deployment scanner            → 5 findings
[defense:can-injection] decision: tier=moderate conf=0.72
[defense:can-injection] action: kind=isolate_node target=TESTBENCH-01
[defense:can-injection] plan: [completed] 26 completed · 0 failed
                              · 0 refused · 0 rolled-back · 0 skipped.
                              blast_radius=node; assets=[Material…,
                              Privacy…, Life and Bodily Health].
[defense:can-injection] guard: allowed=True (all four properties satisfied)
```

The accompanying `_summary.md` for the run breaks down every step:
which playbook fired, which tool was called, what the dry-run
envelope returned, whether the post-condition passed.

That is what "agentic" looks like operationally: not a single LLM
answer, but a structured, auditable chain of typed decisions where
the LLM is one tool among many.

---

## 8. What is still *not* agentic (yet)

To be honest about the boundaries of the current implementation:

- Agents do not yet **re-plan in response to each other's results.**
  The decision agent does not currently see partial action-execution
  outcomes and adjust the tier; the action engine does not feed
  back to the scanners. Adding that loop is the next step toward
  paper-5's adaptive learning loop.
- The LLM is not yet a **first-class participant in tool selection.**
  Playbooks are deterministic. A future iteration could expose the
  MCP schema catalogue to the decision agent and let it pick tools.
- The per-step Security Guard adapter is wired but only the legacy
  guard runs by default. Per-step contextual checks for the new
  step shape are queued.
- Memory is one-shot (per run). Cross-session learning — "we saw
  this pattern last week and the patch worked" — is paper-5 Phase E
  on the roadmap.

These are not omissions but staged work. The current update closes
the gap on *robustness, MCP, and observability of actions* — the
parts the supervisor flagged as still proof-of-concept.

---

## 9. One-paragraph summary

CyberLLM defense is now an **agentic pipeline** in the strict sense:
specialised, goal-directed agents exchange typed records through a
contracted hand-off; the response step is a real planner / executor
on top of a typed MCP tool registry with pre/post-conditions,
rollback, retries, per-step authorisation, and a redacted audit log;
dry-run is the safe default, real side effects are one config switch
away; every prompt, tool call, and decision is captured for review.
The LLM does what LLMs are good at — refining, explaining, deciding
under uncertainty — while the engine, the rules, and the tools do
what determinism is good at: holding the line.
