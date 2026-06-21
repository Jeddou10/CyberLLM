# Chapter 7 — Running, testing, extending & FAQ

[◀ Subsystems](06_SUBSYSTEMS.md) · [Master index](../DEVELOPER_GUIDE.md)

The practical chapter: how to run it, what the outputs look like, how the
tests work, how to add things, how to debug, and a Q&A that should let you
answer almost anything.

---

## 7.1 Running it

```bash
cd CyberLLM
pip install --user pyyaml            # the only mandatory dependency

# DEFENSE (default mode)
python pipeline.py --example small           # all 5 small scenarios
python pipeline.py --example medium|large|all
python pipeline.py --code examples/small/02_can_gateway.py \
                   --log examples/logs/03_can_injection.log \
                   --deployment examples/deployments/03_complex_sdv.yaml

# ATTACK (red team)
python pipeline.py --mode attack --example small
python pipeline.py --mode attack --code … --deployment … --scenario examples/attack_scenarios/01_data_exfiltration.txt

# BOTH side by side
python pipeline.py --mode both --example small

# verbosity
python pipeline.py --example small        # default: per-step progress (stderr)
python pipeline.py -v --example small     # debug: timings, tokens, prompts+responses, per-step status
python pipeline.py -q --example small     # quiet: only the summary tables (stdout)
python pipeline.py -v --code … 2> run.log # diagnostics → stderr, results → stdout
```

**stdout vs stderr:** results (summary tables, the single-run record JSON)
go to **stdout**; all diagnostics go to **stderr**. So `… > out.json` is a
clean machine-readable artefact.

**The LLM banner** (first lines, with `-v` or default) tells you what you
got: `AzureOpenAILLM<gpt-4o>` means the real model;
`StubLLM<…> (fallback→stub)` means credentials were missing/placeholder and
it's running offline.

---

## 7.2 Outputs (where results land)

- `memory/last_run_<mode>.json` — the most recent single run's full record.
- `memory/<mode>_<scenario>.json` — per-scenario record in a batch.
- `memory/batch_<mode>_<kind>.json` — the batch summary table.
- `memory/incidents.db` — the **signed cross-session store** (now with
  outcomes). Git-ignored.
- `memory/eval_report.md` — the static evaluation report.
- `run_logs/<timestamp>_<mode>_<scenario>/` — the **per-step debug trace**:
  - `00_meta.json`, `01_inputs.json`,
  - `02_static_*.json` (deterministic findings per scanner),
  - `0N_<agent>_prompt.txt` / `_response.txt` / `_findings.json`,
  - `ZZ_decision.json` / `_action.json` / `_action_plan.json` /
    `_action_report.json` / `_guard.json` (defense),
  - `ZZ_instance.json` / `_plan.json` / `_ethics.json` + `scripts/` (attack),
  - `_trace.log` (one-line-per-event), `_summary.md` (human-readable).
  - `_latest_defense.txt` / `_latest_attack.txt` point at the newest run.

Read the `_summary.md` first; drill into the numbered files for detail.

---

## 7.3 Testing

Three layers, run in order:

```bash
python verify.py                 # 30-second offline smoke test → 6/6 OK
python -m pytest tests/          # full suite → 155 passed
python evaluate.py               # static detection/FP scoreboard
python evaluate.py --strict      # non-zero exit on any miss / false positive
```

Both `verify.py` and the suite **force the offline stub**
(`CYBERLLM_FORCE_STUB=1`, set autouse in `tests/conftest.py`) so they never
touch the network or cost tokens — *even with Azure credentials present*.

What each test file checks:
- `test_static_analyzer.py` — every rule fires on a positive snippet, is
  silent on a clean one.
- `test_rules_and_parsing.py` — YAML loads, ids unique, regexes compile.
- `test_guards.py` — the four properties + EthicsGuard scope/redaction.
- `test_pipeline_integration.py` — full defense + attack end-to-end.
- `test_scenario_regression.py` — must-have rule-ids per scenario triple.
- `test_action_engine.py` — registry, playbooks, executor, generator.
- `test_memory_store.py` / `test_memory_pipeline.py` — recall, HMAC tamper
  detection, unauthenticated-write refusal, the recall loop end-to-end.
- `test_ha_judge_and_trajectory.py` — H_a tightening + compositional/temporal.
- `test_provenance_and_delegation.py` — mandatory provenance + delegation.
- `test_token_budget.py` — token estimate + every provider's fallback.
- `test_evaluation.py` — the static eval harness.
- `test_production_upgrades.py` — the latest upgrade: memory outcomes +
  `recommend()`, re-planning escalation + memory nudge, `check_step`, LLM
  tool selection, and the real tools' dry-run.
- `test_cli_smoke.py` — `--help` + each `--mode` runs (subprocess).

**The static evaluation harness** (`evaluate.py`) scores the deterministic
analyzer against `examples/labels.yaml` *without running targets*: detection
recall, false-positive rate on the clean controls, a paper-1
property-violation table, and an asset×scenario×skill scoreboard. There is
**no "mean time to detect"** — that's a *dynamic* metric and this is a
static harness (it says so in the report).

> **Environment note (this machine).** The global Python has
> `PYTHONNOUSERSITE=1`, so user-installed packages are hidden. If you hit
> `No module named 'yaml'`, run with
> `PYTHONPATH=C:/Users/Oussama_Jeddou/AppData/Roaming/Python/Python311/site-packages`
> (or `pip install --user pyyaml pytest` and reopen the terminal).

---

## 7.4 Using a real model

Default config = **Azure OpenAI gpt-4o**. Fill `.env`:
```bash
AZURE_OPENAI_ENDPOINT=https://<your-resource>.openai.azure.com
AZURE_OPENAI_API_KEY=<key>
AZURE_OPENAI_DEPLOYMENT=<the deployment that serves gpt-4o>   # NOT necessarily "gpt-4o"
AZURE_OPENAI_API_VERSION=2024-10-21
```
Then run normally; the banner should read `AzureOpenAILLM<gpt-4o>`.
To switch providers, change `llm_configs.*.provider` in `config.yaml`
(`github` needs `GITHUB_TOKEN`; `ollama` needs `ollama serve`). Force the
stub anytime with `CYBERLLM_FORCE_STUB=1`.

---

## 7.5 Extending the system

- **Add a detection rule** → append to a `rules/*.yaml`. A *code* rule with a
  `pattern` (regex) works automatically. A *log/topology* rule with
  non-trivial logic also needs an `if rule_id in by_id:` block in
  `tools/static_analyzer.py`.
- **Add a scenario** → add an entry under `config.yaml → example_sets`, and
  (optionally) its ground truth to `examples/labels.yaml` for `evaluate.py`.
- **Add a response playbook** → add a `_book(...)` in
  `agents/action_engine/playbooks.py` keyed by rule-id, listing
  `StepTemplate`s.
- **Add an MCP tool** → subclass `MCPTool` in
  `agents/action_engine/mcp_tools.py`, declare its `schema`/`side_effect`/
  `domain`, implement `_do_call` (and rely on `_dry_run` for safety), and add
  it to `default_toolset()`.
- **Add an attack template** → add an entry to `_TEMPLATES` in
  `agents/attack/attack_generator.py`.
- **Add an LLM provider** → add a branch in `LLMClient.create` and a subclass
  implementing `complete()`.
- **Add an agent** → subclass `BaseAgent`, give it a `PROMPT` with
  `[placeholders]`, implement `run()`, and wire it into `pipeline.py`.

**The golden rule:** never let the LLM *remove* a static finding. Keep the
static-first floor intact.

---

## 7.6 Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `No module named 'yaml'` | deps in user site hidden by `PYTHONNOUSERSITE`; set `PYTHONPATH` (see §7.3) or `pip install --user pyyaml`. |
| Banner says `(fallback→stub)` but you set a key | the key is a placeholder, or for Azure the endpoint/key/deployment env vars aren't all set; check `.env`. |
| `GitHub Models request failed (404)` | the model id isn't in your catalogue; list it and fix `config.yaml`. |
| Azure `404 unknown deployment` | `AZURE_OPENAI_DEPLOYMENT` is wrong; list deployments and pin the right name. |
| Run ends `UNRESOLVED` with a real model | the per-step H_a judge refused a (often destructive) step. This is the guard working. Tune: enrich the decision summary, set `guard.ha_judge_enabled: false`, or raise `action_engine.max_replan_rounds`. |
| Lots of 429s | free GitHub Models tier; lower `max_replan_rounds`, disable `llm_tool_selection`, or use a higher-quota model/Azure. |
| A destructive tool "ran" | it didn't — `action_engine.dry_run` is true by default; the audit marks `dry_run=True`. |

---

## 7.7 FAQ (answer-anything)

**Q: Does it need the internet or an API key?** No. It ships with a
deterministic stub LLM and runs fully offline; the static analyzer produces
real findings regardless.

**Q: What's the difference between the static analyzer and the LLM?** The
static analyzer is deterministic rules (regex/heuristics/graph checks) — the
trusted floor. The LLM refines/explains/extends those findings. Static wins
on duplicates.

**Q: How does it "decide how bad" something is?** The decision agent
aggregates findings, consults memory for precedent, and (LLM + deterministic
policy) picks a tier (`soft/moderate/hard/none`) + confidence + the paper-2
asset categories at risk.

**Q: What stops a bad/destructive action?** Three things: (1) the action
engine is **dry-run by default**; (2) the **per-step `SecurityGuard`** can
refuse any tool step (and aborts the plan if a containment step is refused);
(3) destructive tools require authorization in live mode.

**Q: What is the "re-planning loop"?** After executing, if the response
didn't resolve the incident, the outcome is fed back to the decision agent,
which **escalates the tier** and tries again — up to `max_replan_rounds`.
This closes paper-5's adaptive loop *within* a run.

**Q: What is "cross-session learning"?** The memory store records *whether
each response worked*. A future run with a similar finding-set gets a
"tier X worked before" recommendation — adaptive learning *across* runs.

**Q: Can the LLM call any tool it wants?** It can *propose* tools from the
catalogue, but each proposal is schema-validated and runs through the same
per-step guard. It cannot invent a tool or bypass safety.

**Q: How is memory protected from tampering?** Every row is HMAC-signed
(outcome included). On read, unverified or unauthenticated rows are dropped;
`verify_all()` audits the whole store.

**Q: Why did the live gpt-4o run end UNRESOLVED but the stub resolved?** A
capable model is stricter: its per-step H_a judge refused a containment step.
That's the guard doing its job; it's tunable (§7.6).

**Q: Is the attack side dangerous?** No — it produces benign canary scripts
for *authorised* targets only, gated by the EthicsGuard, and redacts
destructive patterns. Don't run it against systems you don't own.

**Q: Which paper does feature X come from?** P1 = guards/H_a; P2 =
assets/graph/poison-trigger; P3 = rules-as-context/static-first; P4 =
agent schema/providers; P5 = layers/tiers/memory/re-planning. See
[chapter 1 §1.3](01_FOUNDATIONS.md#13-the-five-research-papers-in-plain-english).

**Q: Where do I look to understand a specific function?**
[Chapter 5 — Code reference](05_CODE_REFERENCE.md).

**Q: How do I see exactly what the model was asked and answered?** Run with
`-v` (prints truncated prompt+response previews), or read the
`run_logs/<run>/0N_<agent>_prompt.txt` / `_response.txt` files.

---

You've reached the end of the guide. Between the
[master index](../DEVELOPER_GUIDE.md), the
[foundations](01_FOUNDATIONS.md), the two pipeline deep-dives
([defense](03_DEFENSE_DEEP.md) / [attack](04_ATTACK_DEEP.md)), the
[code reference](05_CODE_REFERENCE.md), the
[subsystems](06_SUBSYSTEMS.md), and this chapter, you should be able to
answer essentially any question about CyberLLM — what it does, why, and how
every piece works.
