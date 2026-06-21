# Chapter 3 — The defense pipeline, deep

[◀ Architecture](02_ARCHITECTURE.md) · [Master index](../DEVELOPER_GUIDE.md) · [Next: Attack pipeline ▶](04_ATTACK_DEEP.md)

This is the heart of the system. We narrate `run_defense_pipeline()` in
[`../../pipeline.py`](../../pipeline.py) **stage by stage**, always saying
what each stage *takes*, what it *gives*, and *where that goes next*. Open
`pipeline.py` beside this and read along.

The function signature:

```python
run_defense_pipeline(code_paths, log_path, deploy_path, cfg, rules,
                     scenario_name="default", verbose=True, debug=False) -> dict
```

It returns a **record** (a dict), and writes that record to
`memory/defense_<scenario>.json` plus a full trace under `run_logs/`.

---

## Stage 0 — Setup

**Takes:** the parsed `config.yaml` (`cfg`) and the merged rule set (`rules`).
**Gives:** the building blocks for the run.

```python
con   = Console(verbose, debug)          # where diagnostics print (stderr)
llms  = build_llms(cfg)                  # one LLM client per llm_configs entry
memory = build_memory(cfg)               # the signed incident store (or None)
rlog  = RunLogger(RUN_LOGS_DIR, "defense", scenario_name)
```

- `build_llms` turns each entry under `llm_configs` (`default`, `reasoning`)
  into a concrete client via `LLMClient.create`. With the default config
  that's two Azure gpt-4o clients; with no credentials they fall back to
  the stub. The console prints a **banner** so you can see which you got:
  `LLM clients: default=AzureOpenAILLM<gpt-4o> · reasoning=AzureOpenAILLM<gpt-4o>`.
- `build_memory` opens `memory/incidents.db` (signed). Returns `None` if
  `memory.enabled` is false.
- `RunLogger` makes a fresh `run_logs/<timestamp>_defense_<scenario>/`
  folder that will accumulate every prompt, response, and decision.

---

## Stage 1 — Build provenance-tagged inputs

**Takes:** the file paths. **Gives:** a list of `Input` objects. **To:** all
three scanners.

```python
inputs = [SourceCodeScannerAgent.load_example(p) for p in code_paths] + [
    LogAnalyzerAgent.load_example(log_path),          # → Input(external)
    DeploymentScannerAgent.load_example(deploy_path), # → Input(authenticated)
    Input("Defense scan requested by authorised operator.",
          source="user", trust_level="authenticated"),
]
```

`load_example(path)` just reads the file and wraps it in an `Input` with the
right trust level. **Why an operator `Input`?** It is the *authenticated*
source the guard later looks for when deciding whether a privileged action
was properly requested (paper 1 source-authorization).

---

## Stages 2–4 — The three scanners (static-first, three sub-steps each)

All three scanners have the **same shape**; only the artefact and the rule
family differ. Here is `SourceCodeScannerAgent.run(inputs)` in detail
([`../../agents/source_code_scanner.py`](../../agents/source_code_scanner.py)):

**Sub-step 1 — deterministic static pass.**
```python
static_hits = scan_code_static(inp.content, inp.source, rules)   # regex over code_rules
static_as_findings = staticfinding_to_finding(static_hits, Finding)
```
*Takes* the code text + the rules. *Gives* a list of `StaticFinding` (every
regex that matched). This **always runs** and is the floor.

**Sub-step 2 — LLM refinement pass.**
```python
self.data["code"] = inp.content
self.data["rules"] = rules_snippet           # compact list of applicable rules
self.data["static_findings"] = "…rendered static hits…"
prompt = self.template(self.PROMPT)          # fills the [placeholders]
resp = self.call_llm(prompt)
llm_findings = self._parse_findings(resp.text)
```
*Takes* the code + the rules + **the static hits as context**. *Gives* the
LLM's findings (parsed from its JSON). The prompt literally says *"refine,
explain, or extend — do not duplicate"*. This is paper 3 (rules as context)
and paper 4 (constraint + augmentation).

**Sub-step 3 — merge.**
```python
merged = merge_findings(static_as_findings, llm_findings)  # static wins on dupes
```
*Gives* the final `Finding[]` for this scanner, returned in an
`AgentResult`.

The pipeline runs all three and collects three `AgentResult`s:
```python
code_result = _run_scanner("source-code scanner", 1, code_agent, "source_code")
log_result  = _run_scanner("log analyzer",        2, log_agent,  "log")
dep_result  = _run_scanner("deployment scanner",  3, dep_agent,  "deployment")
```
Each scanner filters inputs by file extension, so the code scanner only
sees `.py/.c/.cpp`, the log analyzer only `.log/.txt`, the deployment
scanner only `.yaml`.

**What the run-log captures here:** the static findings (`02_static_*.json`),
the exact prompt sent, the raw LLM reply, and the merged findings — per
scanner. So you can always see *why* a finding appeared.

---

## Stage 5 onward — The adaptive loop (decision → action → guard → maybe re-plan)

This is the part that changed most recently. Instead of "decide once, act
once", the pipeline runs a **bounded loop** (`action_engine.max_replan_rounds`,
default 2). Built once before the loop:

```python
guard = SecurityGuard(allowed_objectives, authenticated_sources,
                      trusted_destinations, ha_judge=HaJudge(reasoning_llm))
decision_agent = DecisionAgent("decision_agent", decision_cfg, reasoning_llm, memory=memory)
```

Then, for each round:

### 5a. Decision (now sees prior-round feedback + memory)

**Takes:** the three `AgentResult`s, plus (after round 1) **feedback** from
the previous attempt. **Gives:** a `Decision`.
([`../../agents/decision_agent.py`](../../agents/decision_agent.py))

```python
decision = decision_agent.run([code_result, log_result, dep_result],
                              scenario_name=scenario_name, feedback=feedback)
```

Inside `DecisionAgent.run`:
1. **Aggregate** all findings into one list and a compact text block.
2. **Consult memory (cross-session):**
   - `recall_similar(rule_ids, k)` — the K most *similar* past incidents
     (by Jaccard overlap of rule-id sets), rendered as few-shot precedent
     in the prompt's `[memory]` slot.
   - `recommend(rule_ids)` — the single most-similar past incident **whose
     remediation worked**, surfaced in `[recommendation]` ("last time tier
     X resolved this").
3. **Call the LLM** (`reasoning` config) → parse a `Decision` JSON: which
   asset categories, the tier, the confidence, the justification.
4. **Apply two deterministic policies on top of the LLM:**
   - `_apply_feedback_escalation(decision, feedback)` — if the previous
     round failed/was-refused, bump the tier **at least one notch above**
     the tier that failed (`none < soft < moderate < hard`). *This is what
     makes the loop adaptive even with the stub.*
   - `_apply_memory_recommendation(decision)` — if a similar past incident
     *worked* at a stronger tier, adopt that tier (escalate-only — never
     downgrade below the LLM's call).

**Why a deterministic policy on top of the LLM?** The LLM proposes; the
policy guarantees the loop actually escalates on failure and reuses proven
responses, regardless of model variance.

### 5b. The per-step guard for *this* round's threat

```python
step_guard = build_step_guard(guard, inputs, decision.summary)
```
This wraps `SecurityGuard.check_step` with the current decision's threat
summary as context. The executor will call it on **every** tool step. (Full
mechanics in chapter 7's guard section and chapter 6.)

### 5c. Action engine — plan then execute

**Takes:** the `Decision`. **Gives:** an `ActionReport` (and a legacy
`Action` view). ([`../../agents/action_engine/generator.py`](../../agents/action_engine/generator.py))

```python
action_agent = ActionGenerator("action_generator", action_cfg, default_llm, guard=step_guard)
action = action_agent.generate(decision, vulnerable_code=vulnerable_code)
report = action_agent.last_report
```

Inside `generate()`:
1. **`build_plan(decision, ctx)`** — turn the decision's findings into an
   ordered `ActionPlan`. A *playbook* per rule-id chooses concrete tool
   steps (e.g. `LOG-CAN-02` → safe-mode + isolate ECU + notify driver +
   forensic snapshot). Findings below `medium` are skipped; steps are
   ordered contain → observe → eradicate → recover → notify → audit. This
   is the **deterministic floor** of the response. (Details in chapter 6.)
2. **LLM tool selection (optional, `llm_tool_selection`)** — the MCP
   catalogue is shown to the LLM, which may propose *extra* tools. Each
   pick is schema-validated against the registry and appended as a guarded
   step. The playbook remains the floor; the LLM can only *add*.
3. **`execute(plan)`** — the `ActionExecutor` walks the plan step by step
   (next section). Dry-run by default, so nothing destructive actually
   happens.

### 5d. Inside the executor (per step)
([`../../agents/action_engine/executor.py`](../../agents/action_engine/executor.py))

For each `ActionStep`, in order:
1. **Pre-conditions** — evaluate any `pre` `Condition`s by calling an
   `observe.*` tool. If a pre-condition fails, the step is **SKIPPED**.
2. **Per-step guard** — `step_guard.check(step)`. If refused, the step is
   **REFUSED**; and if it was a `CONTAIN` step, the whole plan **aborts**
   (you don't proceed to eradicate if you couldn't contain).
3. **Invoke the tool** (with retry/back-off). In dry-run it returns a
   `would-execute` envelope; live, it runs the real command.
4. **Post-conditions** — verify the step achieved its goal; on failure,
   **VERIFY_FAILED** → roll back.
5. **Rollback** — on a hard failure of a contain/eradicate step, walk the
   completed steps LIFO and run each one's `rollback_steps`.
Every event is appended to the report's `audit_log`. The final
`PlanStatus` is `COMPLETED` / `PARTIAL` / `FAILED` / `REFUSED`.

### 5e. The final guard + trajectory check

**Takes:** the final `Action`, an objective derived from the action kind,
and the `Input[]`. **Gives:** a `GuardVerdict` and a `TrajectoryVerdict`.

```python
objective = {"patch_code":"auto-correct insecure code",
             "alert_only":"produce findings report",
             "noop":"produce findings report"}.get(action.kind, "produce defensive action")
verdict = guard.check(action, objective, inputs, context=decision.summary)
traj    = guard.check_trajectory(plan.steps, inputs)
```
- `check()` evaluates the **four paper-1 properties** (task / action /
  source / data) on the final aggregate action.
- `check_trajectory()` evaluates the **sequence** for compositional and
  temporal problems (exfil chains, TOCTOU, memory-poisoning patterns).

### 5f. Did the response resolve? Loop or stop.

```python
n_steps = len(plan.steps)
plan_ok = report.status.value in ("completed", "partial_success")
final_success = (n_steps == 0) or (verdict.allowed and plan_ok)
```
- If `final_success` (or we've hit `max_replan_rounds`) → **break**.
- Otherwise build `feedback = {prior_tier, plan_status, guard_allowed,
  reason}` and loop back to 5a. The decision agent will escalate.

**Why treat "0 steps" as success?** If there was nothing severe enough to
act on, that's not a *failure* to escalate — it's "nothing to do".

The full per-round history is kept in `replan_history` and stored in the
record under `replanning`.

---

## Stage 6 — Persist (and learn)

**Takes:** everything from the final round. **Gives:** the record (returned
+ written to `memory/`), a signed `Incident`, and the finalised run-log.

```python
record = {... decision, action, action_report, guard_verdict,
          trajectory_verdict, replanning, memory_recommendation,
          findings, consulted_memory, committed ...}

record["memory_recorded"] = _record_incident(
    memory, cfg, mode="defense", scenario=scenario_name, rule_ids=…,
    asset_categories=…, tier=decision.recommended_tier,
    confidence=decision.confidence, action_kind=action.kind,
    guard_allowed=verdict.allowed,
    plan_status=final_plan_status, remediation_ok=final_success)  # ← the outcome!
```

The crucial new bit is `plan_status` + `remediation_ok`: the store now
records **whether the response worked**, which is exactly what
`recommend()` reads on a future run. That closes paper 5's adaptive-learning
loop *across* runs (chapter 6 has the memory deep-dive).

`committed` is the action that was actually allowed (or `None` if refused).

---

## A real end-to-end trace (CAN scenario, Azure gpt-4o)

Running:
```bash
python pipeline.py -v --code examples/small/02_can_gateway.py \
  --log examples/logs/03_can_injection.log \
  --deployment examples/deployments/03_complex_sdv.yaml
```
produced (abridged):
```
LLM clients: default=AzureOpenAILLM<gpt-4o> · reasoning=AzureOpenAILLM<gpt-4o>
[4-6/6] adaptive loop (decision → action → guard, max 2 round(s))
  round 1 decision: tier=hard conf=0.90
  round 1 action: kind=isolate_node plan=[failed] 2 completed · 1 refused · …
  round 1 result: plan=failed steps=29 guard=PASS
  [!] round 1 did not resolve (plan failed); re-planning…
  round 2 decision: tier=hard conf=0.90
  round 2 result: plan=failed steps=30 guard=PASS
  replanning  : 2 round(s), final=UNRESOLVED
  memory      : recorded=True (outcome=failed)
```
**How to read this:** scanners found the CAN-injection issue; the decision
agent rated it `hard`; the action engine built a 29-step plan; the *per-step
H_a judge* (real gpt-4o) refused one **containment** step (it judged the
isolate action not clearly justified by the thin context it saw), which
aborts the plan; the loop fed that back, re-planned (still `hard` — already
the top tier), the LLM tool-selector added one step (29→30), the step was
again refused, and after 2 rounds the run ended **UNRESOLVED** — recorded
faithfully as `outcome=failed` so it won't be recommended as "worked".

With the **stub** LLM the same scenario *resolves in round 1* (the stub H_a
is permissive). This difference is the whole point of having a guard: a
capable model is more cautious. It is tunable (chapter 7): enrich the
decision summary, set `guard.ha_judge_enabled: false`, or raise
`max_replan_rounds`.

---

## One-paragraph recap

The defense pipeline **takes** code + logs + a deployment config, **runs a
deterministic scan and then an LLM refinement** to produce findings,
**aggregates them into a tiered decision** (consulting signed memory for
precedent), **turns the decision into an executable, guarded plan of MCP
tool steps**, **executes it safely (dry-run)**, **checks it against paper-1
security properties per step and as a whole**, **re-plans with escalation if
it didn't resolve**, and finally **records the outcome (including whether it
worked) into signed cross-session memory** and a full run-log.

Next: **[Chapter 4 — The attack pipeline](04_ATTACK_DEEP.md)**.
