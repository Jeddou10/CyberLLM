# Chapter 6 — Subsystems: LLM, config, guards, memory, tools

[◀ Code reference](05_CODE_REFERENCE.md) · [Master index](../DEVELOPER_GUIDE.md) · [Next: Run/test/extend/FAQ ▶](07_RUN_TEST_EXTEND_FAQ.md)

Chapter 5 told you *what* each symbol is. This chapter explains *how the
important subsystems work internally* and *why they're built that way*.

---

## 6.1 The LLM layer

File: [`../../llm_client.py`](../../llm_client.py).

**The problem it solves.** Agents need to call "an LLM", but we want to swap
models (a fake stub for tests, Azure gpt-4o in production, GitHub Models or
Ollama elsewhere) **without changing any agent code**. So there's one
factory and several interchangeable clients (paper 4's "LLM-Config").

**`LLMClient.create(cfg)` — the resolution order:**
1. `_load_dotenv_once()` — read `.env` into the environment (only keys not
   already set, so an exported shell value wins).
2. If `CYBERLLM_FORCE_STUB` is set → return the stub. (Tests and
   `verify.py` set this so they're hermetic/offline regardless of config.)
3. `provider == "stub"` → `StubLLM`.
4. `provider == "github"` → check `GITHUB_TOKEN`; if missing/placeholder →
   stub + warning, else `GitHubModelsLLM`.
5. `provider == "azure"` → check `AZURE_OPENAI_API_KEY` +
   `AZURE_OPENAI_ENDPOINT`; if missing/placeholder → stub + warning, else
   `AzureOpenAILLM`. **This is the configured default.**
6. `openai`/`anthropic` → check the key env var (placeholder-aware) → stub
   or the real client.
7. `ollama` → `OllamaLLM` (localhost).

**Graceful fallback (the "A.2" feature).** Missing or placeholder
credentials never crash a run — `_looks_like_placeholder()` catches a
not-yet-filled key and the client downgrades to the stub with a one-time
warning. So you can clone the repo and run immediately.

**The stub, in detail.** `StubLLM.complete()` looks for keywords:
- `"action-alignment oracle h_a"` → returns `{"serves": …, "reason": …}`
  (so the guard's H_a check is deterministic offline).
- `"central decision agent"` + `"asset_categories_touched"` → a Decision JSON.
- `"source-code security scanner"` → code findings; `"log"+"anomal"` → log
  findings; `"deployment"/"topology"` → topology findings.
- `"fix"/"correct"` → a remediation sentence.
- else → `"ACK: …"`.
Because it matches *substrings*, adding extra context to a prompt (the
`[memory]`/`[feedback]` blocks, the tool catalogue) **does not change** the
stub's output — which is exactly why the test suite stays deterministic.

**Reasoning models (gpt-5 / o-series).** These reject `max_tokens` and a
custom `temperature`. `GitHubModelsLLM._is_reasoning_model()` detects them
and sends `max_completion_tokens` with no `temperature`. Both the GitHub and
Azure clients also **retry once on HTTP 429** (rate-limit) with back-off.

**Azure specifics (important and easy to trip on).** Azure OpenAI is *not*
vanilla OpenAI:
- the model is chosen by the **deployment name** in the URL path, *not* the
  model id;
- auth uses the **`api-key`** header (not `Authorization: Bearer`);
- the request is **versioned** with `?api-version=`.
`AzureOpenAILLM._url()` builds
`https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=<ver>`.
`.env` supplies `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`,
`AZURE_OPENAI_DEPLOYMENT`, `AZURE_OPENAI_API_VERSION`.
> ⚠️ **A deployment can be named anything.** On the project's resource the
> deployment literally named `gpt-4o` actually served gpt-5.1, and the real
> gpt-4o lived under `gpt-4o-2`. Always list deployments
> (`GET {endpoint}/openai/deployments?api-version=2023-03-15-preview`,
> header `api-key`) and pin the right name.

**Token budgeting.** `BaseAgent.call_llm` runs every prompt through
`tools/tokens.py:TokenBudget`, which `estimate_tokens()` (a heuristic, no
tokeniser dependency) and warns if a prompt exceeds `guard.max_prompt_tokens`
(default 4096, paper-3's threshold). It never blocks — it flags that content
should move to RAG.

---

## 6.2 `config.yaml` — every key

File: [`../../config.yaml`](../../config.yaml). Everything tunable lives here.

```yaml
llm_configs:                 # one entry per "slot"; agents reference a slot
  default: {provider, model, temperature, max_tokens, token_env?}
  reasoning: {…}             # used by the decision agent + attack orchestrator
agent_configs:               # per agent: which llm slot + its objective string
  source_code_scanner: {llm: default, objective: "…"}
  decision_agent:      {llm: reasoning, objective: "…"}
  …
security:                    # consumed by SecurityGuard
  allowed_objectives: […]    # the set O (task alignment)
  authenticated_sources: […] # S_auth (source authorization)
  trusted_destinations: […]  # data isolation
response_tiers:              # paper-5 confidence thresholds
  soft_threshold / moderate_threshold / hard_threshold
memory:                      # the signed store
  enabled, db_file, recall_k, writer_identity, reject_unverified,
  signing_key_env, dev_signing_key
guard:                       # paper-1 hardening
  ha_judge_enabled           # F.1 — run the separate H_a oracle
  per_step_enabled           # C.4 — run check_step on every tool step
  max_prompt_tokens          # A.4 — the prompt-budget warning threshold
action_engine:               # the planner+executor + the adaptive loop
  dry_run                    # never run a destructive command unless false
  work_dir                   # scratch dir (patches/snapshots/secret store)
  max_replan_rounds          # decision↔action rounds (escalate on failure)
  llm_tool_selection         # let the LLM propose extra (validated) tools
attack:                      # consumed by EthicsGuard
  allow_all_in_dev, allowed_scenarios, authorized_targets
paths:                       # rules_dir, examples_dir, memory_dir, prompts_dir
defaults:                    # single-run defaults for --log / --deployment
example_sets:                # the named --example sets (small/medium/large/juliet)
```

The key insight: **agents are configured, not hard-wired.** Want the
decision agent on a heavier model? Change `llm_configs.reasoning`. Want the
loop to try harder? Raise `action_engine.max_replan_rounds`.

---

## 6.3 The guards (paper 1)

File: [`../../agents/security_guard.py`](../../agents/security_guard.py) +
[`../../agents/ha_judge.py`](../../agents/ha_judge.py).

**The thesis (paper 1).** *Following instructions correctly ≠ being secure.*
An action can be individually valid and still be wrong **in context**. So a
separate, mechanical, auditable component evaluates context. It checks at
three granularities:

**(a) The four properties — `check()` on the final aggregate action:**
1. **Task alignment** — is the `objective` in the allowed set `O`?
2. **Action alignment** — is the action's kind compatible with the
   objective? Floor = the static `_ACTION_OBJECTIVES` map. If an **H_a
   judge** is wired, `action_ok = static_ok AND judge_ok` — *the judge can
   only tighten, never loosen.*
3. **Source authorization** — was a *privileged* action caused by an
   *authenticated* source? A privileged action driven only by external
   inputs is rejected.
4. **Data isolation** — does the action only write to a *trusted
   destination*?

**(b) The per-step check — `check_step()` on each real `ActionStep`:**
the "new step shape" check. Privilege is read from the step's *declared*
`side_effect` (`destructive`) and `requires_authorization` — not a hard-coded
list. The H_a judge is given the step's `tool`, `rule_id`, `side_effect`,
`description` **and the decision's threat summary**, so it reasons with the
real picture. The executor runs this on **every** tool call (so a single bad
step can't slip through, and an LLM-selected tool is gated too).

**(c) The trajectory check — `check_trajectory()` on the whole sequence:**
paper 1 §7 — security is *compositional* and *temporal*.
- **Compositional**: read-sensitive → external-egress (exfil chain),
  destructive-without-forensics, destructive-without-notify.
- **Temporal**: TOCTOU (a contain/eradicate step that checks a pre-condition
  but never re-verifies), and the memory-poisoning pattern (a destructive
  step in a plan influenced by a `memory`-sourced input).

**The H_a oracle (`HaJudge`).** Paper 1 §6-7 found that approximating the
*action-alignment oracle* `H_a` — "does action *a* serve objective *o* in
this context?" — cut attack-success by 86-88%. It's a **separate** LLM call
with one job: `{"serves": bool, "reason": str}`. Separation matters: a prompt
injection that subverts a scanner still has to fool an independent judge. It
**caches** verdicts by `(action, objective, context)` so the per-step guard
doesn't make dozens of identical (paid) calls. With the stub it's a
deterministic heuristic; with a real model it genuinely reasons — and is
often *stricter* than the stub (which is why the live CAN run ended
UNRESOLVED in [chapter 3](03_DEFENSE_DEEP.md)).

**The attack-side mirror (`EthicsGuard`).** Same idea for offense:
`check_plan` enforces scenario-scope + target-scope; `filter_scripts`
redacts destructive patterns. (See [chapter 4](04_ATTACK_DEEP.md).)

---

## 6.4 The memory store

File: [`../../agents/memory_store.py`](../../agents/memory_store.py).

**The goal (paper 5).** The system should *learn across runs* — "we saw this
pattern last week and tier X fixed it". Older code wrote per-run JSON files
that were never read back; this store reads them back, safely.

**How it works:**
- **Storage** — one SQLite DB (`memory/incidents.db`), stdlib only, one row
  per past outcome. The row includes the **outcome** (`plan_status`,
  `remediation_ok`) — i.e. *did the response work?*
- **Recall (within-pattern precedent)** — `recall_similar(rule_ids, k)`
  ranks past incidents by **Jaccard overlap** of their rule-id sets and
  returns the top-K. The decision agent injects them as few-shot context.
- **Recommendation (cross-session learning)** — `recommend(rule_ids)`
  returns the single most-similar past incident **whose remediation worked**
  (above a similarity threshold). The decision agent adopts its (stronger)
  tier — "this worked before, do it again".
- **Anti-poisoning (paper 1/2)** — every write is **HMAC-signed** with a
  per-deployment key (and the outcome is *part of* the signature). On read,
  `recall_similar`/`recommend` **drop any row** whose signature doesn't
  re-verify or whose source isn't authenticated. `verify_all()` is the "has
  my memory been tampered with?" sweep. Writes from an unauthenticated
  source raise `MemoryAuthError`.

**Why sign the outcome too?** Otherwise an attacker who could edit the DB
could mark a *bad* response as "worked" and trick a future run into reusing
it. Signing the outcome closes that.

This is the concrete realisation of "remember what worked" in the
[60-second model](../DEVELOPER_GUIDE.md#the-60-second-mental-model).

---

## 6.5 The MCP tools

Files: [`../../agents/action_engine/mcp_registry.py`](../../agents/action_engine/mcp_registry.py),
[`../../agents/action_engine/mcp_tools.py`](../../agents/action_engine/mcp_tools.py),
and the simpler [`../../tools/mcp_tools.py`](../../tools/mcp_tools.py).

**Why MCP-shaped?** A tool decouples *what* an agent wants to do from *how*
it's done. Each tool declares a **schema** (so params can be validated), a
**side-effect** (so the engine can gate destructive calls), an
**idempotency** hint (so retries are safe), and a `call()` that returns a
standard `ToolResult`.

**`MCPTool.call()` — the safety routing:**
```python
errors = self.validate(params)            # bad params → "failed"
if self.dry_run or not self.real_available():
    result = self._dry_run(params)        # "would-execute" envelope; no side effect
else:
    result = self._do_call(params)        # the real command
```
So **dry-run (the default) means nothing destructive ever runs**, even if
the real binary is present. `real_available()` checks whether the underlying
CLI is installed.

**The toolset (`default_toolset()`), 22 tools across 8 domains:**
- `firewall.*` — `block_ipv4`, `rate_limit`, `list_rules` (iptables/netsh/pf)
- `network.*` — `isolate_node`, **`port_scan`** (real nmap, or a bounded
  pure-Python connect-scan fallback)
- `secrets.*` — `rotate`, `revoke`
- `code.*` — `static_scan` (real **bandit/semgrep**), `propose_patch`,
  `scrub_git_history` (writes a runbook, never auto-rewrites history)
- `runtime.*` — `restart_service`, `snapshot` (tar forensics), `safe_mode`
- `notify.*` — `webhook`, `create_incident`, `email`, `driver`
- `observe.*` — `endpoint`, `log_tail`, `port_closed`, **`packet_capture`**
  (real tshark/tcpdump/candump) — these power the executor's pre/post checks
- `kb.*` — `lookup_cve` (NVD, with a local cache)

The **registry** (`MCPRegistry`) holds the tools, a **dry-run flag**, an
optional **authorization hook** (for destructive tools in live mode), and an
**audit log** that `_safe_for_audit` redacts (password/secret/token/apikey)
before persisting.

**The simple registry** (`tools/mcp_tools.py`) keeps the original
`run(**kwargs)->dict` interface but now has **real backends** too:
`PortScanTool` (nmap/socket), `StaticAnalysisTool` (bandit/semgrep),
`PacketCaptureTool` (tshark/tcpdump/candump). Intrusive ones default to a
**dry-run envelope** and only execute with `live=True`.

---

## 6.6 The action engine internals (playbooks + executor)

Files: [`../../agents/action_engine/playbooks.py`](../../agents/action_engine/playbooks.py),
[`../../agents/action_engine/executor.py`](../../agents/action_engine/executor.py),
[`../../agents/action_engine/generator.py`](../../agents/action_engine/generator.py).

**Playbooks — "match the *kind* of finding, not just its severity".** A
hard-coded "soft→rate_limit, hard→isolate" map is fine for a demo but isn't
auditable. Instead, a **playbook** is a typed sequence of `StepTemplate`s
keyed to a rule-id (exact or regex). Examples:
- `LOG-CAN-02` → safe-mode (CONTAIN) + isolate ECU (CONTAIN) + notify driver
  (NOTIFY) + forensic snapshot (AUDIT).
- `CODE-003` (hard-coded secret) → rotate secret + propose patch + scrub-history
  runbook + incident.

`build_plan(decision, ctx)`:
1. sort findings by severity (critical first),
2. skip findings below `medium` (don't automate on noise),
3. look up a playbook per rule-id (specific → family `CODE-.+`/`LOG-.+`/`TOP-.+`
   → none),
4. instantiate each `StepTemplate` whose `severity_min` is met (its
   `params_fn` pulls the suspect IP / file / ECU from the finding),
5. if nothing fired but a tier was set and ≥1 finding is actionable → the
   tier-generic playbook,
6. **order by `StepKind`** (contain → observe → eradicate → recover → notify
   → audit) and **deduplicate** equivalent steps,
7. return the `ActionPlan`.

**Executor — the loop that makes it agentic.** For each step:
pre-conditions (skip on fail) → **per-step guard** (refuse → if it was a
CONTAIN step, abort the plan) → invoke with retry → post-conditions
(verify-fail → rollback) → record every event. Final `PlanStatus` reflects
the mix of step statuses.

**Generator — LLM tool selection.** After `build_plan` (the floor),
`_llm_select_tools()` shows the LLM the catalogue (`registry.schemas()`) and
parses its proposed extra tools. Each pick must **name a real tool** and
**pass that tool's schema validation**, or it's dropped; survivors become
`ActionStep`s that run through the **same per-step guard**. So the LLM is a
first-class participant but **cannot bypass safety**.

Next: **[Chapter 7 — Running, testing, extending & FAQ](07_RUN_TEST_EXTEND_FAQ.md)**.
