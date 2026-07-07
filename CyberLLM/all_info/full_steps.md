# CyberLLM — Full Pipeline, Step by Step (with a worked example)

`[← back to all_info index](README.md)`

> This document follows **one concrete example** all the way through the
> **defense** pipeline and then the **attack** pipeline. After every step you'll
> see a **"Result now"** block showing exactly what the program produced at that
> point, so you can watch the data transform from raw files into a final guarded
> decision (defense) and a guarded attack plan (attack).
>
> Numbers/shapes here match how the code actually behaves (see
> [pipeline.md](pipeline.md), [tools/static_analyzer.md](tools/static_analyzer.md),
> [agents/security_guard.md](agents/security_guard.md), etc.). Treat the exact
> finding text as illustrative; the *structure* is exact.

---

## 0. The example inputs

We feed the pipeline three artifacts — a code file, a log file, and a deployment
topology. (In the web UI you usually paste just the code; here we use all three to
show every stage.)

**`telemetry_service.py`** (the code under test)
```python
import os, sqlite3, hashlib

API_KEY = "AKIA1234567890ABCDEF"          # (1) hard-coded secret

def get_vehicle(db, vin):
    q = "SELECT * FROM vehicles WHERE vin = '" + vin + "'"   # (2) SQL injection
    return db.execute(q).fetchall()

def store_pin(pin):
    return hashlib.md5(pin.encode()).hexdigest()             # (3) weak hash

def run_diag(cmd):
    os.system("candump " + cmd)                              # (4) command injection
```

**`canbus.log`** (runtime log)
```
2026-06-29T08:00:21Z can0 frame arb=0x100 src=GatewayECU bus_load=14%
2026-06-29T08:02:05Z can0 anomaly gateway-only 0x7E0 src=DriveECU   # CAN injection
```

**`deployment.yaml`** (the actor/datasource topology)
```yaml
actors:
  - {id: ext_app, type: ExternalA2AAgent, trust_level: external}
  - {id: gw, type: HighPerformanceComputer}
  - {id: zone, type: ZoneECU}
  - {id: ltm, type: Datastore}
edges:
  - {source: gw, target: zone, transport: can, standard: proprietary}   # TOP-001
  - {source: ext_app, target: ltm_memory, primitive: write}             # TOP-002
```

**The objective** (an authenticated operator request): *"Defense scan requested by
authorised operator."*

---

# PART 1 — THE DEFENSE PIPELINE

Entry point: `run_defense_pipeline(code_paths, log_path, deploy_path, cfg, rules)`.

---

## Step 0 — Load configuration and rules

**What happens:** `load_config()` reads `config.yaml`; `load_rules()` reads every
`rules/*.yaml` and merges them by family into `{code_rules, log_rules,
topology_rules, attack_rules}`. `build_llms()` constructs the LLM clients;
`build_memory()` opens the signed SQLite store.

**Result now:**
- LLM banner printed, e.g. `LLM clients: default=AzureOpenAILLM<gpt-4o> · reasoning=AzureOpenAILLM<gpt-4o>` (or `StubLLM` if no creds).
- Rules loaded: ~30+ `code_rules`, several `log_rules`/`topology_rules`.
- Memory: `enabled`.

---

## Step 1 — Build inputs, each tagged with provenance

**What happens:** every artifact becomes an `Input` with a `source` and a
`trust_level` (P1). The code/log/deployment are loaded; a synthetic authenticated
operator input is appended. Provenance is **mandatory** — an un-tagged input would
raise `ProvenanceError`.

**Result now:**
```
inputs: 4 item(s) —
  telemetry_service.py [external]      ← code is treated as untrusted data
  canbus.log           [external]
  deployment.yaml      [authenticated]
  user                 [authenticated] ← "Defense scan requested by operator"
```

---

## Step 2 — Source-code scanner  `[1/6]`  (three detection layers)

**What happens** (`SourceCodeScannerAgent.run`): for the code file,
1. **Regex floor** (`scan_code_static`) applies every `code_rules[*].pattern`.
2. **AST layer** (`scan_code_external`) runs **bandit** (Python) and merges —
   regex wins on the same `(rule_id, line)`.
3. **LLM pass** (only if `use_llm`) refines/extends using the static hits as
   context (P3), then `merge_findings` drops LLM duplicates.

**Result now** — the static floor + bandit detect:
```
static analyzer DETECTED 4 issue(s): CODE-001, CODE-002, CODE-003, CODE-012
  • CODE-003 [critical] Hard-coded secret              @ line 3   via source_code_scanner (regex)
  • CODE-012 [critical] Raw SQL with interpolation     @ line 6   via bandit (B608)
  • CODE-002 [medium]   Weak hash for credentials       @ line 9   via source_code_scanner (regex)
  • CODE-001 [high]     Command injection sink          @ line 12  via bandit (B605)
LLM refinement → 4 finding(s) total (LLM added 0 new loci; it confirmed + explained)
```
> In **Deep mode** the LLM may add explanations or a finding the regex/bandit
> missed; duplicates on the same `(rule_id, line)` are merged away.

---

## Step 3 — Log analyzer  `[2/6]`

**What happens** (`LogAnalyzerAgent.run`): `scan_log_static` runs the hand-coded
`LOG-*` detectors (burst windows, entropy, CAN signatures), then the optional LLM
pass.

**Result now:**
```
static analyzer DETECTED 1 issue(s): LOG-CAN-02
  • LOG-CAN-02 [critical] CAN-bus injection from non-gateway ECU @ "anomaly gateway-only 0x7E0 src=DriveECU"
      asset: Life and Bodily Health
```

---

## Step 4 — Deployment scanner  `[3/6]`

**What happens** (`DeploymentScannerAgent.run`): `scan_deployment_static` builds
the actor/edge graph (P2) and runs OCL-style topology checks (P3).

**Result now:**
```
graph analyzer DETECTED 2 finding(s): TOP-001, TOP-002
  • TOP-001 [high]   HPC↔ZoneECU on transport=can standard=proprietary (must be ethernet+IEEE-1722)
  • TOP-002 [high]   external actor ext_app writes to ltm_memory (poison path)
```

**Aggregate after Steps 2–4:** 7 findings —
`CODE-001, CODE-002, CODE-003, CODE-012, LOG-CAN-02, TOP-001, TOP-002`.

---

## Step 5 — Decision agent  (response tier + asset tagging)

**What happens** (`DecisionAgent.run`): aggregates the 7 findings, recalls similar
past incidents from signed memory, asks the LLM for a tier (P5), then applies
**deterministic policy** (re-planning escalation + memory recommendation, both
escalate-only) and tags the top findings with a P2 asset.

**Result now:**
```
recalled: (none on first run)
decision: tier=hard  conf=0.88
  assets touched: [Life and Bodily Health, Privacy and Personal Data,
                   Material and Economic Resources]
  summary: "Multiple critical code vulns (hard-coded secret, SQL injection) plus a
            safety-critical CAN injection and two topology violations."
```
> Why **hard**? Critical findings + a "Life and Bodily Health" asset (the CAN
> injection) push confidence above the `hard_threshold` (0.85 in `config.yaml`).

---

## Step 6 — Action engine  (build → execute a guarded plan)

**What happens** (`ActionGenerator.generate`): `build_plan` maps each actionable
finding (severity ≥ medium) to a **playbook** of MCP-tool steps, ordered
`contain → observe → eradicate → recover → notify → audit`. If `llm_tool_selection`
is on, the LLM may *add* validated, guarded steps. The `ActionExecutor` runs each
step against the MCP registry (**dry-run by default**), evaluating pre/post
conditions and rolling back on failure.

**Result now** (dry-run — nothing real executes):
```
action mode: DRY-RUN (simulated)
plan (blast_radius=node):
  step contain    code.propose_patch        -> completed   (patch for CODE-012 SQL)
  step eradicate  secrets.rotate            -> completed   (rotate the hard-coded API_KEY)
  step observe    observe.log_tail          -> completed
  step notify     notify.create_incident    -> completed   (critical incident opened)
MCP tool ▶ code.propose_patch(telemetry_service.py) → would-execute [sim]
MCP tool ▶ secrets.rotate(primary-api-token)        → would-execute [sim]
report: [completed] 4 completed · 0 failed · 0 refused
primary action: kind=patch_code → target=telemetry_service.py
```

---

## Step 7 — Security guard  (P1 four properties) + trajectory

**What happens** (`SecurityGuard`): the executor already ran `check_step` before
*every* tool (per-step P1 check + H_a oracle). Now the whole action gets
`check(...)`, and the plan's step sequence gets `check_trajectory(...)`.

**Result now:**
```
guard: allowed=True (all four properties satisfied)
  task_alignment=True  action_alignment=True
  source_authorization=True  data_isolation=True
trajectory: compositional_ok=True  temporal_ok=True  (no exfil chain, snapshot+notify present)
```
> If the H_a judge had decided a privileged step didn't serve the objective, or a
> destructive step had no notify/snapshot, the guard would **refuse** and the
> action would not be committed.

---

## Step 8 — Adaptive re-planning loop (did it resolve?)

**What happens** (P5): the loop checks `final_success = (no steps) or (guard
allowed AND plan completed/partial)`. If not resolved, it feeds the failure back
and the decision agent **escalates the tier** for another round (up to
`max_replan_rounds`).

**Result now:**
```
replanning: 1 round(s), final=RESOLVED
```
> Had the guard refused, round 2 would re-run with tier escalated `hard → (stays hard, max)`
> and a feedback note; after `max_replan_rounds` it stops and reports UNRESOLVED.

---

## Step 9 — Enrich findings → the detailed result records

**What happens** (`_enrich_findings`): each finding becomes the detailed record
`{rule_id, severity, title, location, line, detail, asset_category, …}`. The
**location** is the enclosing function, found via the Python **AST** (no execution).

**Result now (the headline output):**
```
FINDINGS (7)
  • CODE-003  [critical]  Hard-coded secret
      location: module level                line: 3
      detail:   Hard-coded secrets leak via repo/binary — matched: API_KEY = "AKIA…"
  • CODE-012  [critical]  Raw SQL with interpolated variables
      location: get_vehicle()               line: 6
      detail:   convert to a parameterised query
  • CODE-002  [medium]    Weak hash for credentials
      location: store_pin()                 line: 9
  • CODE-001  [high]      Command injection sink
      location: run_diag()                  line: 12
  • LOG-CAN-02 [critical] CAN-bus injection from non-gateway ECU   location: log stream
  • TOP-001   [high]      Architecture violation (transport)       location: deployment topology
  • TOP-002   [high]      External write to long-term memory       location: deployment topology
```

---

## Step 10 — Persist to signed memory

**What happens** (`_record_incident`): the outcome — rule_ids, tier, confidence,
guard verdict, **and whether the remediation worked** — is HMAC-signed and written
to `incidents.db`, plus a JSON dump to `memory/`.

**Result now:**
```
memory: recorded=True (outcome=worked)
record: memory/last_run_defense.json
run log: run_logs/2026…_defense_default/   (_summary.md, _trace.log, per-step JSON)
DEFENSE · default · DONE (7 findings, tier=hard, guard=PASS)
```

**End state of defense:** 7 detailed findings, tier `hard`, a guarded dry-run
remediation plan that completed, and a signed memory row the *next* run can learn
from.

---

# PART 2 — THE ATTACK PIPELINE

Entry point: `run_attack_pipeline(code_paths, deploy_path, scenario, cfg, rules)`.
Same code + deployment, plus an operator **scenario**:
> *"Find the highest-impact exploit chain that could affect vehicle safety."*

---

## Step A0 — Read the scenario / inputs

**What happens:** the scenario is read (file or literal string); inputs are built
(code `external`, deployment `authenticated`, scenario `authenticated`). No log
file on the attack side.

**Result now:** `scenario: "Find the highest-impact exploit chain…"`, 3 inputs.

---

## Step A1 — System info discovery  `[1/5]`  (passive recon)

**What happens** (`SystemInfoDiscoveryAgent`): builds the P2 actor/datasource graph
from the deployment YAML — **no packets sent**. An optional LLM call adds notes.

**Result now:**
```
external=['ext_app']  safety=['gw', 'zone']
actors=4 datasources=… edges=2
notes: ['ext_app is external and can write to memory']
```

---

## Step A2 — Source-code exploiter  `[2/5]`

**What happens** (`SourceCodeExploiterAgent`): reuses the **same** static hits as
the defense scanner, but the LLM reframes each as an **exploit plan** (what input
to send, which CWE/rule, which P1 property it breaks, expected effect).

**Result now:**
```
static analyzer DETECTED 4 exploitable issue(s); 4 exploit(s) after LLM framing:
  CODE-001, CODE-002, CODE-003, CODE-012
  • CODE-012 → "send vin = ' OR '1'='1 → dump all vehicles" (violates data-isolation)
  • CODE-001 → "diag cmd = '; id > /tmp/x' → RCE on the gateway" (violates action-alignment)
```

---

## Step A3 — Deployment exploiter  `[3/5]`

**What happens** (`DeploymentExploiterAgent`): runs the topology checks AND
**enumerates attack paths** deterministically (`ATK-PATH`: external→write = poison,
external→respond = trigger), then the LLM frames poison/trigger chains.

**Result now:**
```
graph analyzer DETECTED 3 attack-path/finding(s): TOP-001, TOP-002, ATK-PATH
  • ATK-PATH: poison: ext_app (external) -write-> ltm_memory
```

---

## Step A4 — Attack orchestrator  `[4/5]`

**What happens** (`AttackOrchestratorAgent.plan`): aggregates the exploiter
findings + the instance + scenario, then selects a **target asset**, chains 1–3
findings, and lays out a **poison path** and **trigger path** (P2 §5) with a
confidence.

**Result now:**
```
plan target: Life and Bodily Health (conf=0.81)
chosen: TOP-002, ATK-PATH, CODE-012
poison_path: ['ext_app -write-> ltm_memory']
trigger_path: ['zone ECU consumes poisoned rule on next drive cycle']
justification: "External write to memory poisons a rule the safety ECU later trusts."
```

---

## Step A5 — Ethics / scope guard  `[5/5]`

**What happens** (`EthicsGuard.check_plan`): is the scenario in scope? Is the target
authorized (config + any `--authorize-target`)? Then `filter_scripts` redacts any
destructive payload.

**Result now:**
```
ethics: allowed=True (scenario + target in scope)
  scope_ok=True  target_ok=True  non_destructive=True
```
> If the target weren't authorized, **no scripts** would be generated and the
> record would show `ethics REFUSED`.

---

## Step A6 — Attack generator  (benign PoC scripts)

**What happens** (`AttackGeneratorAgent.generate`): one **attack script** per chosen
finding — from a built-in template if available (benign canary, placeholder hosts),
else an LLM-authored benign PoC. Scripts are **never executed** here.

**Result now:**
```
generated 3 script(s); redacted 0
  • CODE-012 [http]    Boolean-based SQL injection probe   GET /login?username=admin'--
  • TOP-002  [payload] External-actor memory-poison message
  • ATK-PATH [payload] Generic poison/trigger replay
```

---

## Step A7 — Persist to signed memory

**What happens:** the attack outcome (target, chosen rule_ids, ethics verdict,
scripts) is signed and recorded; JSON dumped to `memory/`.

**Result now:**
```
memory: recorded=True
ATTACK · default · DONE (ethics=PASS, 3 script(s))
```

**End state of attack:** a chosen target asset, a poison→trigger chain, and 3
benign, in-scope PoC scripts written to the run log's `scripts/` folder.

---

# PART 3 — How the Web UI maps to these steps

When you paste code and press **Scan** in the web UI (`server.py` runs the **defense**
pipeline only, dry-run forced):

| UI element | Comes from |
|------------|-----------|
| Severity stat tiles + worst-first **findings list** | Step 9 (`record.findings`) |
| **Annotated source** (highlighted lines, click to jump) | Step 9 `line` + Step 2 detection |
| **Decision · Action · Guard** panel | Steps 5–8 (`decision`, `action`, `guard_verdict`, `replanning`, `mcp_audit`) |
| **DEEP/FAST** + provider badge | the LLM seam (Step 0); Fast forces the stub, Deep uses gpt-4o |
| Raw JSON | the whole `record` |

A code-only web scan feeds **empty** log/deployment (and disables their LLM
passes), so you'll see the **code findings** (Steps 2/9) but not Steps 3–4's
log/topology findings — by design, so the model can't invent them.

---

## One-paragraph summary

**Defense:** tag inputs → detect in three layers (regex ⊕ bandit/semgrep ⊕ LLM,
merged deterministic-wins) → decide a tier and tag human assets → build and run a
guarded, dry-run remediation plan → escalate if it didn't resolve → emit detailed
findings → remember the outcome. **Attack:** the mirror — recon the graph → reframe
findings as exploits → enumerate poison/trigger paths → choose a target chain →
ethics-gate → emit benign PoC scripts → remember. Across both, the deterministic
layers form a floor the probabilistic LLM can only *improve*, and the guards can
only *tighten* — so no single component can cause harm alone.
