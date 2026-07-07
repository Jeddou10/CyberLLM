# CyberLLM — Supervisor Question Bank (with answers)

> Read this **after** the per-file explainers in [README.md](README.md). These
> are the questions a supervisor/professor is likely to ask in a defense or code
> review, grouped from "big picture" down to "show me that line." Each answer is
> short enough to say out loud, with a pointer to the file that proves it.
>
> Tip for the viva: when asked "why," always answer in two layers — *what the
> code does* and *which paper/threat it defends against*.

---

## A. Big-picture / architecture

**A1. In one sentence, what is CyberLLM?**
A multi-agent LLM cybersecurity system with mirror **defense** and **attack**
pipelines that analyze code/logs/topology **statically** (never executing the
target) and respond through a guarded, dry-run-capable action engine.

**A2. What does "static-first" mean and why did you choose it?**
It analyzes artifacts as *text/structure* (regex + AST tools + LLM reasoning),
never running them. It's the supervisor's hard constraint, and it's safe (you
can scan untrusted code without detonating it) and reproducible. Dynamic metrics
like MTTD are therefore N/A by design (see [evaluate.md](evaluate.md)).

**A3. Walk me through a defense run end to end.**
Load config + rules → build provenance-tagged inputs → three scanners (code/log/
topology), each `regex floor ⊕ bandit/semgrep ⊕ LLM`, merged deterministic-wins →
decision agent picks a P5 tier + tags P2 assets → action engine builds a playbook
plan of MCP-tool steps → security guard checks P1 properties per step and overall
→ adaptive re-planning loop escalates on failure → enrich findings → persist a
signed outcome to memory. All in [pipeline.md](pipeline.md).

**A4. Defense vs attack pipeline — what's the same, what differs?**
Same skeleton (discover → detect → decide → act → guard → persist) and the same
static detection layers. Differences: attack reframes findings as exploits,
swaps the `SecurityGuard` for the `EthicsGuard`, and ends in PoC scripts instead
of remediation. Symmetry is intentional (scanner↔exploiter, decision↔orchestrator,
action↔generator, security-guard↔ethics-guard).

**A5. What are the five papers and where does each show up?**
P1 contextual security → `security_guard.py` + `ha_judge.py` (four properties +
H_a). P2 asset taxonomy + actor/datasource graph → `decision_agent.py`,
`deployment_scanner.py`, the attack path enumeration. P3 rules-as-context/OCL →
`rules_snippet`, the topology checks, token budgeting. P4 schema-driven agents →
`base_agent.py`. P5 layered/tiered/adaptive → the three detection layers,
`response_tiers`, and the re-planning loop.

---

## B. The detection layers

**B1. Is the static analyzer "just regex"?**
No. It's three layers: a regex **floor** (`scan_code_static`), an **AST layer**
(real bandit/semgrep via `scan_code_external`), and an **LLM refinement** pass —
merged with `merge_findings`/`merge_static_layers` so deterministic layers win on
duplicates. ([tools/static_analyzer.md](tools/static_analyzer.md))

**B2. Where do bandit/semgrep run, and why not from the start?**
They run as the AST layer inside the code scanner. The regex floor runs first
because it's instant, dependency-free, and high-recall; bandit/semgrep add
data-flow-aware structure. Regex wins on the same `(rule_id, line)` so the same
issue isn't double-reported. bandit hits inherit our `CODE-*` ids via
`_BANDIT_TO_RULE` for traceability.

**B3. How does a bandit finding keep our rule ids?**
`_BANDIT_TO_RULE` maps bandit test-ids (e.g. `B602`→`CODE-001`, `B608`→`CODE-012`)
so a bandit hit inherits our title/severity/asset. Unmapped ids become
`BANDIT-<id>`.

**B4. The earlier bug — same vulnerability shown three times. Cause and fix?**
`merge_findings` originally deduped on evidence *text*, so an LLM restatement of a
bandit/regex hit (different wording) survived. Fixed to dedup on `(rule_id, line)`
with a rule-id fallback for line-less LLM findings — keeping genuinely new loci.

**B5. Why would the system invent a "critical CAN injection" on a clean log, and
how is it prevented?** With a real LLM and `use_llm` on, the log analyzer
hallucinated a finding from a sample log the user never supplied. Fix: per-scanner
`use_llm` gating — a code-only web scan feeds *empty* log/deployment and disables
their LLM passes, so only code findings appear ([pipeline.md](pipeline.md),
[server.md](server.md)).

---

## C. The guard (P1) — the part most likely to be probed

**C1. What are the four properties and where are they checked?**
Task alignment (objective ∈ allowed set), action alignment (action fits the
objective), source authorization (privileged actions need an authenticated
source), data isolation (write only to trusted destinations) — all in
`SecurityGuard.check` / `check_step` ([agents/security_guard.md](agents/security_guard.md)).

**C2. What does "H_a" mean?**
The **action-alignment oracle** from P1: "does this action *genuinely serve* the
declared objective in this context?" An action can be individually valid yet not
serve the objective (e.g. a privileged change under a read-only objective). It's a
dedicated LLM judge ([agents/ha_judge.md](agents/ha_judge.md)).

**C3. Can the H_a judge make the system *less* safe?**
No. The guard computes `action_ok = static_map_ok AND ha_judge_ok` — the judge can
only *tighten*, never loosen, the deterministic floor. And it's a separate call,
so a prompt injection that subverts a scanner still faces an independent oracle.

**C4. Why check a *trajectory*, not just each action?**
P1 stresses contextual security is compositional and temporal. `check_trajectory`
catches what per-step checks can't: a read-then-egress exfil chain, a destructive
step with no forensic snapshot or no human notified (compositional), and TOCTOU /
memory-poisoning ordering issues (temporal).

**C5. What stops an external instruction from triggering a privileged action?**
Two things: provenance is mandatory (`Input.__post_init__`), and the source-
authorization check refuses a privileged action unless an authenticated source is
among the inputs. Delegated child agents also start with **no** inherited trust
(`BaseAgent.delegate`).

---

## D. The action engine

**D1. Why playbooks instead of "tier → command"?**
A response should match the *kind* of finding, not just severity. Playbooks are
auditable, kind-specific, ordered step sequences (contain→observe→eradicate→
recover→notify→audit) with pre/post conditions and rollback
([agents/action_engine/playbooks.md](agents/action_engine/playbooks.md)).

**D2. What is "dry-run" and who enforces it?**
The **registry** decides whether a real binary runs — gated by the `dry_run` flag
(forced on by `CYBERLLM_FORCE_DRY_RUN`). The executor only sequences/verifies; it
never overrides the flag. So a browser button or test can never run `iptables`.

**D3. How can the LLM add tools without becoming a security hole?**
`ActionGenerator._llm_select_tools` lets the LLM *propose* extra steps, but each
must name a real registered tool, pass that tool's schema validation, and is still
run through the per-step `SecurityGuard`. The deterministic playbook is the floor;
the LLM can only add within the rails.

**D4. What makes an MCP tool "real" vs a stub?**
`MCPTool.call` runs `_do_call` (the real command) only if not dry-run *and*
`real_available()` (the binary is on PATH); otherwise `_dry_run` returns a
"would-execute" envelope. `ToolResult.invoked_real_tool` records which happened.

**D5. How does the adaptive re-planning loop terminate?**
It runs at most `max_replan_rounds`. It stops when the response resolves
(`final_success`) or rounds are exhausted. Note a **zero-step plan is success**
("nothing to remediate"), which prevents infinite escalation.

---

## E. Memory & learning

**E1. Why a signed SQLite store instead of the JSON files?**
The JSON files are never read back. `MemoryStore` is queryable and cross-session:
the decision agent recalls similar past incidents and "what tier worked." Writes
are HMAC-signed and reads verify signature + source, so a poisoned row can't steer
a decision ([agents/memory_store.md](agents/memory_store.md)).

**E2. How is "similar" computed?**
Jaccard overlap of the finding **rule-id sets** — deterministic and explainable;
zero-overlap incidents are never recalled.

**E3. How does memory make responses safer, not just different?**
`recommend()` only returns *successful* precedents, and the decision agent uses
them to *escalate* the tier (escalate-only). So learning makes responses more
cautious, never less.

**E4. Concretely, how is memory-poisoning defended?**
`verify_row` rejects any row whose source isn't authenticated or whose HMAC
doesn't match — checked at *read* time, so even a row inserted directly into the
DB file never reaches the decision agent. The trajectory guard also flags a
destructive action influenced by a memory-sourced input.

---

## F. The LLM seam

**F1. What happens with no API key?**
`LLMClient.create` falls back to the deterministic `StubLLM` (with a one-time
warning), so the pipeline always runs. Placeholder tokens count as "unset"
([llm_client.md](llm_client.md)).

**F2. How do you know whether a run really hit gpt-4o?**
`_llm_banner` in the pipeline prints each client's concrete class and appends
`(fallback→stub)` when a configured provider silently fell back. The web health
endpoint reports `llm_real`.

**F3. Why is Azure handled specially?**
Azure selects the model by **deployment name in the URL**, authenticates with an
`api-key` header (not Bearer), and versions with `?api-version=`. All three are
handled in `AzureOpenAILLM`.

**F4. What keeps tests deterministic regardless of provider/binaries?**
Three env kill-switches: `CYBERLLM_FORCE_STUB` (offline LLM),
`CYBERLLM_FORCE_DRY_RUN` (no real commands), `CYBERLLM_NO_EXTERNAL_STATIC` (skip
bandit/semgrep). conftest/verify set all three.

---

## G. The web UI

**G1. Is the web UI a mock or does it run the real pipeline?**
Real. `server.run_web_scan` runs `run_defense_pipeline` in an isolated temp
workspace, with actions forced to dry-run for browser safety
([server.md](server.md)).

**G2. What's the difference between Fast and Deep mode?**
Fast = deterministic regex + bandit/semgrep, offline/instant (forces the stub).
Deep = adds the live LLM pass, but **only** when real credentials exist; otherwise
it transparently falls back to Fast (so the stub's canned findings never show on
real code).

**G3. Why zero dependencies for the server?**
It uses stdlib `http.server` and a fully self-contained `index.html` (inline
CSS/JS) — runs offline, no build step, no supply-chain surface.

---

## H. "Show me the line" — pointed code questions

**H1. Where is a finding's enclosing function determined without running code?**
`pipeline._enclosing_location` — Python uses the AST (innermost
function/class containing the line); C-like files use an upward regex scan.

**H2. Where is provenance made mandatory?**
`Input.__post_init__` in `base_agent.py` — raises `ProvenanceError` if `source`
is empty or `trust_level` isn't in the lattice.

**H3. Where does the regex floor compute a finding's line number?**
`_line_of(text, offset)` in `static_analyzer.py` (`text.count("\n", 0, offset)+1`).

**H4. Where does the executor decide to roll back?**
`ActionExecutor.execute` — a failed/verify-failed CONTAIN or ERADICATE step
triggers `_rollback` (LIFO) and aborts the plan; a refused CONTAIN aborts too.

**H5. Where are audit secrets scrubbed?**
`mcp_registry._safe_for_audit` redacts keys containing
password/secret/token/apikey and truncates long strings before the audit row is
stored.

**H6. Where is bandit found if it isn't on PATH?**
`static_analyzer._analyzer_cmd` falls back to `[sys.executable, "-m", name]` when
the binary shim isn't on PATH (common with `pip install --user`).

---

## I. Limitations & honesty (good to volunteer)

**I1. What are the approximations?**
P1's oracles are open problems; the guard *names* each check so any one can be
replaced. The property/asset mappings in `evaluate.py` are documented
approximations. Token budgeting is a heuristic, not a real tokenizer.

**I2. What would you not claim?**
No dynamic detection (static-first by design), the LLM layer is probabilistic
(hence the deterministic floor + guard), and `allow_all_in_dev` / the `*` target
wildcard / the dev signing key must be disabled before touching real systems.

**I3. What's the single most important safety property?**
Defense in depth: deterministic detection floor + dry-run by default + a guard
that the LLM can only *tighten*. No single probabilistic component can cause harm
on its own.
