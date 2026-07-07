# `pipeline.py` — the orchestrator (defense + attack pipelines, re-planning, CLI)

`[← back to all_info index](README.md)`

---

## 1. Purpose & place in the system

`pipeline.py` is the **conductor** of CyberLLM. Everything else (agents, tools,
guards, memory, the web server) is a player; this file decides the order they
play in. It:

- loads `config.yaml` and the `rules/*.yaml` knowledge base,
- builds the LLM clients and the signed memory store,
- runs the **defense pipeline** (`run_defense_pipeline`) and the **attack
  pipeline** (`run_attack_pipeline`),
- implements the **adaptive re-planning loop** (P5),
- turns raw `Finding` objects into **detailed, human-readable records**
  (`_enrich_finding`), and
- exposes a **command-line interface** (`main`) plus a **batch runner**
  (`run_example_batch`).

It is imported by `server.py` (the web UI calls `run_defense_pipeline`,
`load_config`, `load_rules`) and by `verify.py`. It is also the program's
`__main__` entry point.

---

## 2. Imports — lines 35–79

| line | import | why it's needed |
|------|--------|-----------------|
| 36 | `argparse` | Build the CLI (`--mode`, `--example`, `--code`, …). |
| 37 | `ast` | Parse Python source to find the *enclosing function/class* of a finding (precise location without running code). |
| 38 | `json` | Serialize the result records written to `memory/`. |
| 39 | `os` | Read environment kill-switches (`CYBERLLM_FORCE_DRY_RUN`) and the memory signing key. |
| 40 | `re` | Regex fallback for finding the enclosing function in non-Python (C-like) files. |
| 41 | `sys` | Exit codes, stderr for progress, UTF-8 reconfigure. |
| 42 | `from dataclasses import asdict` | Convert guard/ethics verdict dataclasses into plain dicts for the JSON record. |
| 43 | `from pathlib import Path` | All filesystem paths. |
| 45 | `import yaml` | Parse `config.yaml` and the rule files. |
| 47–52 | UTF-8 reconfigure loop | Windows consoles default to cp1252; reconfiguring stdout/stderr to UTF-8 prevents `UnicodeEncodeError` when printing the `▶`, `·`, `→` glyphs used in progress output. Wrapped in `try/except` because not every stream supports `reconfigure`. |
| 55–63 | defense agents | The five defense-side agents + `Input`, `GuardAdapter`, `legacy_kind`. |
| 66–73 | attack agents | The six attack-side agents, imported as a group from `agents.attack`. |
| 75 | memory types | `Incident` (a row), `MemoryAuthError` (signing failure), `MemoryStore`. |
| 77–79 | `LLMClient`, `RunLogger`, `Console` | The provider factory, the per-run trace writer, and the verbosity-aware console. |

**Module constants (lines 82–84):**
- `HERE` — the directory of this file; every relative path is resolved against it so the program works regardless of the current working directory.
- `RUN_LOGS_DIR` — where per-run traces go. **Important:** it is a *module-level* variable so tests (and `server.py`) can redirect it to a temp directory by reassigning `pipeline.RUN_LOGS_DIR`.
- `CODE_EXTENSIONS` — which file suffixes count as "code" when scanning a directory (`.py .c .cpp .h`).

---

## 3. Walkthrough (block by block)

### `load_config()` — lines 91–93
- **What:** open `config.yaml` (UTF-8) and return the parsed dict.
- **Why:** a single choke-point means every caller (CLI, server, tests) reads config the same way.

### `load_rules(cfg)` — lines 96–104
- **What:** read every `*.yaml` file in the configured `rules_dir`, then **merge by family** into one dict like `{"code_rules": [...], "log_rules": [...], ...}`.
- **Line by line:**
  - 97 — resolve the rules directory under `HERE`.
  - 99 — `sorted(...glob("*.yaml"))`: sorting makes load order deterministic (so the merged list order is stable across machines).
  - 102–103 — `rules.setdefault(family, []).extend(items)`: families that appear in multiple files are concatenated rather than overwritten. This is *why* you can split rules across `example_rules.yaml`, `extended_rules.yaml`, etc.

### `rules_snippet(rules, family)` — lines 107–116
- **What:** render one rule family as a compact bulleted string for injection into an LLM prompt (this is the **P3 "rules-as-context"** mechanism).
- **Why this design:** the LLM should see the *active* rules so its findings reference real `rule_id`s instead of inventing them. Each line is `- ID [severity]: title — rationale/rule/signature`.
- 114 — the `r.get('rationale') or r.get('rule') or r.get('signature') or ''` chain is a graceful fallback: different rule families use different keys for "the explanation", and this picks whichever exists.
- 116 — returns `"(no rules loaded)"` if the family is empty, so the prompt never contains a bare blank.

### `build_llms(cfg)` — lines 119–120
- **What:** instantiate one `LLMClient` per entry in `cfg["llm_configs"]` (e.g. `default`, `reasoning`), returning `{name: client}`.
- **Why:** agents reference an LLM by *name* (`llms[cfg["llm"]]`), so you can point different agents at different models without touching code.

### `build_memory(cfg)` — lines 123–147
- **What:** construct the signed `MemoryStore` (Phase E) — or return `None` when memory is disabled.
- **Line by line:**
  - 133–134 — early return `None` if `memory.enabled` is false. The pipeline then behaves statelessly (the web UI uses this).
  - 137–140 — the signing key (HMAC, see `memory_store.py`) is read from the **env var named in config** (`signing_key_env`), falling back to a config dev key, then a clearly-labelled insecure default. This keeps real keys out of the repo while still working out of the box.
  - 144–146 — `authenticated_sources` and `reject_unverified` decide which writers the store trusts and whether to drop rows whose signature can't be verified.

### `_writer_identity(cfg)` — lines 150–151
Tiny helper: which identity string we record as the *writer* of an incident (defaults to `"rules_engine"`). Used so memory rows can be attributed and signed.

### `_STEP_KIND_OBJECTIVE` + `build_step_guard(...)` — lines 157–180
- **What:** adapt the rich `SecurityGuard` into the simple `(bool, reason)` callback shape the action **executor** expects to call before every MCP tool step (this is wiring point **C.4**).
- **Why this design:** the executor shouldn't know about the guard's internals. `build_step_guard` closes over the guard, the inputs, and the decision summary, returning a `GuardAdapter` whose `check(step)` runs `guard.check_step(...)`.
- 175 — `legacy_kind(step)` maps the new typed step back to an old "kind" string (`patch_code`/`alert_only`/`noop`) so we can look up an objective.
- 176 — the objective tells the guard *what this step is trying to achieve*, which feeds the H_a judge's context. An `alert_only` step is a *reporting* objective, not a *defensive action* one — getting this right is why the map exists.

### `_norm`, `_rel_or_abs`, `_collect_code_files`, `_read_scenario` — lines 183–215
Path/scenario plumbing:
- `_norm` (183–184) — turn any user path into an absolute, OS-normalized `Path` under `HERE`; the `replace("\\","/")` lets Windows-style paths in config work on any OS.
- `_rel_or_abs` (187–194) — prefer a *repo-relative* string for readability, but fall back to absolute when the path is outside the repo (the case when tests redirect `run_logs/` to a temp dir). The `try/except ValueError` is exactly that fall-back.
- `_collect_code_files` (197–206) — accept either a single file or a whole directory; for a directory it recursively globs code files, skipping `__pycache__`. Raises `FileNotFoundError` for a bad path (caught upstream and turned into a SKIP).
- `_read_scenario` (209–215) — the attack `--scenario` operand may be **either a file path or a literal hint**. Lines 212–214 decide: if it doesn't start with `"Find "`/`"Goal "` and the path exists, read the file; otherwise treat the string itself as the scenario. Line 211 supplies a sensible default goal.

### `_rule_ids` and `_llm_banner` — lines 222–239
- `_rule_ids` (222–225) — compact, sorted, de-duplicated rule-id list for progress lines.
- `_llm_banner` (228–239) — **a testing lifesaver.** It prints which concrete client each config resolved to, and appends `(fallback→stub)` when a non-stub provider silently fell back to the offline stub (line 236–237). This is how you notice "I *think* I'm hitting gpt-4o but I'm actually on the stub."

### Finding-enrichment helpers — lines 247–371

This block converts an internal `Finding` into the **detailed record**
`{rule_id, severity, title, location, line, detail, asset_category, …}` that the
CLI prints and the web UI renders.

- **`_rule_index(rules)` (247–255)** — flatten all rule families into `{rule_id: rule_dict}` so a finding can look up its rule's human title. Guards with `isinstance(r, dict) and "id" in r` so malformed rules don't crash it.
- **`_strip_ev_filename(evidence)` (258–265)** — evidence is stored as `"<filename>: <snippet>"`; this returns just the snippet. Line 263 only strips the head if it *looks like a code filename* (ends in `.py/.c/.cpp/.h`), so log/topology evidence with colons in it isn't mangled.
- **`_enclosing_location(source, line, filename)` (268–294)** — the headline trick: name the **function/class containing a finding** *without executing the code*.
  - For Python (274–293) it parses the AST and walks every `FunctionDef`/`AsyncFunctionDef`/`ClassDef`, keeping the **innermost** node whose `start ≤ line ≤ end` (line 286, `start > best[0]` = deepest match wins). Returns `"name()"` for functions, `"class Name"` for classes, else `"module level"`.
  - On `SyntaxError` (277–278) it falls back to the regex scanner — so even un-parseable Python still gets a best-effort location.
- **`_enclosing_location_regex(source, line)` (297–304)** — for C/C++/headers (no Python AST). It scans **upward** from the finding line for the nearest line that looks like a function signature, skipping keywords (`if/for/while/switch/return`) so a control-flow line isn't mistaken for a function.
- **`_finding_file` (307–315)** — figure out which scanned file a finding belongs to: prefer the filename embedded in the evidence; if there's only one file, it's unambiguous.
- **`_finding_location` (318–329)** — combine the above: if we have source + line, return the enclosing function (prefixed with the filename when scanning multiple files). For findings without a code line, it returns a sensible bucket: `"log stream"` for `LOG-*` rules, `"deployment topology"` for `TOP-*`/`ATK-PATH`.
- **`_enrich_finding` (332–360)** — assemble the final dict:
  - 338–344 — derive a **title**: prefer the rule's official title; else the part of the explanation before `" — "`; else the first sentence; else the rule id. (Recent change: it also strips trailing `[bandit Bxxx]`/`[semgrep]` tags via `expl_clean` so tool-sourced findings get a clean title.)
  - 345–348 — derive a **detail**: the rationale, plus the matched snippet appended if it isn't already present.
  - 349–360 — return the record, retaining bonus context (`asset_category`, `source_agent`, raw `evidence`) so nothing is lost downstream.
- **`_enrich_findings` (363–371)** — map `_enrich_finding` over all findings, after pre-loading each scanned file's text into `code_by_name` (so the AST/regex location lookup has the source available).

---

### `run_defense_pipeline(...)` — lines 378–735  (the heart of the program)

**Signature (378–387):** takes `code_paths`, `log_path`, `deploy_path`, `cfg`,
`rules`, a `scenario_name`, and `verbose`/`debug` flags; returns the result
`record` dict.

**Setup (388–449):**
- 388–392 — create the verbosity-aware `Console`, print the scenario banner and the inputs.
- 394–398 — build the LLM clients (and print the all-important `_llm_banner`), build memory.
- 399–408 — create the `RunLogger` and log the run metadata (mode, scenario, input paths).
- 410–431 — **scanner configuration** including the `use_llm` gates:
  - `external_static` (411) toggles the bandit/semgrep AST layer.
  - `use_llm` (412) is the global LLM-pass switch; `use_llm_log`/`use_llm_dep` (lines just below) are **per-scanner overrides** defaulting to the global. *Why:* the web UI runs the log/topology LLM pass **only** when the user actually supplied a log/deployment, so a code-only scan never invents log findings.
  - 422–431 — each scanner's config dict is built by *merging* its `agent_configs` entry with the rules snippet (P3), the full rules, and the gates.
- 433–437 — instantiate the three scanner agents, each handed `llms[cfg["llm"]]` (the LLM named in its config).
- 439–446 — build the `Input` list: one per code file, plus the log, the deployment, and a synthetic **authenticated "operator requested this scan"** input. The trust levels matter for the P1 guard.

**The `_run_scanner` closure (452–474):** runs one scanner agent and emits
rich progress: it logs the *static floor* count, then how many findings the LLM
*added on top* (465–466), then names every finding. This is the verbose
testing view the user asked for. It returns the `AgentResult`.

- 476–480 — run the three scanners in order: source code [1/6], log [2/6], deployment [3/6].

**Guard + decision + action setup (482–520):**
- 484–492 — build the `SecurityGuard` **once** (its H_a judge cache must persist across re-planning rounds). The H_a judge uses the `reasoning` LLM if configured, else `default`.
- 495–500 — build the `DecisionAgent`, handing it the response-tier table and the memory store (so it can recall past incidents).
- 502–520 — build the **action config**: `dry_run` honors `config.action_engine.dry_run` **but is forced true** whenever `CYBERLLM_FORCE_DRY_RUN` is set (507–508). This is the safety interlock the web UI and tests rely on.

**The `_on_tool` callback (524–530):** printed every time the MCP registry runs
a tool — it picks a *salient* parameter (ip, file, target, …) and shows
`MCP tool ▶ name(arg) → status [real|sim]`. The `[real|sim]` flag comes from
`result.invoked_real_tool`, so you can *see* whether a real OS command ran.

- 531–537 — read the first Python file's text into `vulnerable_code` (used by the action engine when it patches code).

**The adaptive re-planning loop (539–646)** — this is **P5's** "detect → decide
→ act → observe → re-decide" closed loop:
- 546 — `max_rounds` (default 2).
- 555 — `for round_idx in range(1, max_rounds+1):`
  - **Decide (557–575):** the decision agent runs with the previous round's `feedback` (None on round 1) and memory. On round 1 it prints what it recalled and what memory recommends.
  - **Act (577–596):** build a per-step `GuardAdapter` (so the guard sees *this round's* threat summary), create a fresh `ActionGenerator`, and `generate(decision, vulnerable_code)`. Each plan step's status is logged.
  - **Final guard + trajectory (598–614):** derive the objective from the action kind (602–606), run `guard.check(...)` for the whole action, then `guard.check_trajectory(...)` over the plan's steps to catch cross-step problems.
  - **Resolved? (616–633):** compute `final_success`. *Subtlety (621):* **zero steps is a terminal success, not a failure** — "nothing to remediate" is fine. Otherwise success requires `guard.allowed` AND the plan completed/partially-succeeded. Each round is appended to `replan_history`.
  - **Escalate (635–646):** if resolved or out of rounds, `break`; otherwise build `feedback` describing *why* it failed and loop again so the decision agent can escalate the tier.

**Build & persist the record (647–735):**
- 649–656 — enrich the findings and print the final FINDINGS section (`rule_id [severity] title / location / line / detail`).
- 658–698 — assemble the `record` dict: inputs, decision (summary, asset categories, tier, confidence, justification), action (kind/target/params/plan_id), `action_report`, `mcp_audit`, `guard_verdict`, `trajectory_verdict`, `replanning` history, `memory_recommendation`, the enriched `findings`, `consulted_memory`, and `committed` (the action only if the guard allowed it).
- 700–711 — record the outcome to signed memory **including whether the remediation worked** (`remediation_ok=final_success`) — that's the cross-session learning signal.
- 713–717 — also dump the record to `memory/last_run_defense.json` (or `defense_<scenario>.json`).
- 718–735 — finalize the run log and print the DONE banner; return the record.

### `_record_incident(...)` — lines 738–759
- **What:** persist one outcome row to the signed store, **never crashing the run** on a memory failure — it returns `False` instead (caught `MemoryAuthError` at 758).
- **Why:** memory is an *enhancement*; a signing/db error must not take down a security scan.

---

### `run_attack_pipeline(...)` — lines 766–974  (the red-team mirror)

Same skeleton as defense, but with the attack agents and an **ethics guard**
instead of the security guard:
- 777–795 — banner, LLMs, memory, run-logger meta (note: attack records the scenario length, and there is **no log file** on the attack side per "diagram 2").
- 798–821 — build the attack agent configs and instantiate: `SystemInfoDiscovery`, `SourceCodeExploiter`, `DeploymentExploiter`, `AttackOrchestrator`, `AttackGenerator`.
- 824–832 — inputs: code files + deployment + the scenario string (authenticated).
- 834–848 — **[1/5] discovery:** passive recon builds a `system_instance` (actors, datasources, edges, external/safety actors). The comment stresses "no packets sent" — static-first applies to attack too.
- 850–874 — **[2/5] source-code exploiter** and **[3/5] deployment exploiter**: same static-floor-then-LLM pattern, but framing findings as *exploits/attack paths*.
- 876–887 — **[4/5] orchestrator:** `plan(...)` chooses a target asset and an exploit chain (poison_path / trigger_path from P2), with a justification.
- 889–914 — **[5/5] ethics guard:** `EthicsGuard.check_plan(scenario, target)` gates whether scripts may be generated at all. Only if `verdict.allowed` does it call `generator.generate(plan)`, then `filter_scripts` redacts anything still out of scope.
- 916–950 — assemble the attack `record` (system instance, plan, ethics verdict, generated scripts with bodies, redactions).
- 952–974 — record the outcome to memory, dump JSON, finalize, return.

---

### Batch orchestration — lines 981–1099

- **`_scenarios_for(kind, cfg)` (981–991)** — resolve a named example set (`small/medium/large`, or `all` = the three concatenated) from `config.yaml`. Unknown set → a helpful `SystemExit` listing the available ones.
- **`run_example_batch(...)` (994–1099)** — loop over scenarios, running defense and/or attack for each, collecting one summary `row` per run. *Robustness:* each run is wrapped in `try/except` (1040, 1062) so one failing scenario doesn't abort the batch — it logs an `error` row and continues. At the end it prints aligned **summary tables** (1066–1090) and writes `batch_<mode>_<kind>.json`.

---

### Entry point — lines 1106–1206

- **`_infer_default_example(cfg)` (1106–1109)** — if no `--example` is given, infer one from the configured examples dir name, defaulting to `small`.
- **`main(argv)` (1112–1202):**
  - 1113–1148 — define all CLI flags with helpful epilog examples. Note `--authorize-target` uses `action="append"` so it can be repeated.
  - 1150–1153 — **verbosity model:** `-q` → quiet (only summary), default → per-step view, `-v` → debug (timings, tokens, prompt previews). So `verbose = not quiet` and `debug = verbose-flag`.
  - 1155–1156 — load config + rules once.
  - 1158–1169 — **batch mode** when `--example` is given *or* no `--code` (the common `python pipeline.py --example small`).
  - 1171–1200 — **single-run mode** when `--code` is given: collect files, resolve log/deployment (CLI override → config default), run defense and/or attack, and print the record JSON.
- 1205–1206 — `sys.exit(main())` so the process exit code reflects success/failure.

---

## 4. Edge cases, gotchas & design decisions

- **`RUN_LOGS_DIR` is reassignable.** `server.py` and tests set
  `pipeline.RUN_LOGS_DIR = <temp>` so runs don't pollute the repo. Because it's
  read at `RunLogger(RUN_LOGS_DIR, …)` *inside* the function, the reassignment
  takes effect per call.
- **Dry-run is force-able but never force-*off*.** Config can request live
  execution, but `CYBERLLM_FORCE_DRY_RUN` can only *force it on* — there is no
  switch that forces real execution against the operator's intent.
- **Zero-step plans are success.** A finding that needs no action (e.g. an
  `alert_only` with nothing to do) must not be counted as a failed remediation,
  or the re-planning loop would escalate forever. Line 621 encodes this.
- **The H_a judge / decision agent live *outside* the loop.** They're built once
  (484–500) so the H_a cache and any per-agent state persist across rounds.
- **Static-first is enforced even for attack.** Discovery is "passive recon, no
  packets sent"; exploiters analyze, they don't run the target.
- **Per-scanner `use_llm`.** A code-only web scan sets `use_llm_log` /
  `use_llm_deployment` to false, so the LLM never hallucinates log/topology
  findings from empty inputs. This is a deliberate correctness fix.
- **Title cleaning.** `_enrich_finding` strips `[bandit Bxxx]`/`[semgrep]` tags
  so externally-sourced findings read like first-class findings.
- **Everything degrades gracefully.** Missing memory → `None`; signing failure →
  `False`; un-parseable Python → regex location; a crashing scenario → an error
  row. The pipeline is built to *finish and report*, not to crash.
