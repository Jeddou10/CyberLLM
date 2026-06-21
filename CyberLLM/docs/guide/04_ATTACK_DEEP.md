# Chapter 4 — The attack pipeline, deep

[◀ Defense pipeline](03_DEFENSE_DEEP.md) · [Master index](../DEVELOPER_GUIDE.md) · [Next: Code reference ▶](05_CODE_REFERENCE.md)

The attack ("red team") pipeline is the **mirror** of defense. Its job is
**not** to harm anything — it produces an **attack plan** and **benign
proof-of-concept scripts** so that defenders can test their detection on
authorised lab systems. A separate **EthicsGuard** makes sure it only
operates in scope.

We narrate `run_attack_pipeline()` in [`../../pipeline.py`](../../pipeline.py)
stage by stage, same "takes X → gives Y → to Z" style as chapter 3.

```python
run_attack_pipeline(code_paths, deploy_path, scenario, cfg, rules,
                    scenario_name="default", verbose=True,
                    cli_authorized_targets=None, debug=False) -> dict
```

> **Ethics first.** This pipeline is for *authorised* red-team exercises.
> The built-in scripts only touch a harmless "canary" (`/tmp/atk_canary`);
> destructive patterns are scanned for and redacted; and nothing runs
> against a target unless the EthicsGuard says the scenario *and* the target
> are in scope. The licence note is in [README §11](../../README.md).

---

## Stage A0 — Read the scenario / hint

**Takes:** a `--scenario` path, a literal string, or a per-example default.
**Gives:** the *goal* text the attacker is trying to achieve. **To:** the
orchestrator.

```python
scenario = _read_scenario(spec)   # a damage scenario, e.g. "spoof a brake command"
```

**Why start from a goal?** Paper 2's **victim-modelling**: you don't
enumerate attacks abstractly; you start from a *damage scenario* ("driver
distraction", "battery drain") and back-chain the technical steps that
achieve it.

---

## Stage A1 — System information discovery (passive recon)

**Takes:** the deployment YAML. **Gives:** a `SystemInstance` graph. **To:**
the orchestrator.
([`../../agents/attack/system_info_discovery.py`](../../agents/attack/system_info_discovery.py))

```python
instance = SystemInfoDiscoveryAgent._build_instance(deployment_yaml)
```

This is **deterministic** — it parses the YAML and computes:
- `external_actors` — actors whose `trust_level == "external"` or whose type
  is an external one (`ExternalUser`, `ExternalA2AAgent`, `ExternalService`),
- `safety_actors` — `SafetyECU` / `ZoneECU` / `HighPerformanceComputer`,
- `notes` — flags like "X is internet-exposed", "Y binds 0.0.0.0", "Z is
  world-readable".

The LLM is called only to add free-form `notes`. **No packets are sent** —
this is *passive* reconnaissance (active recon is deferred and would be
gated by the EthicsGuard). This mirrors the defense "instance creation"
(paper 3) and builds paper 2's actor/datasource graph.

---

## Stage A2 — Source-code exploiter

**Takes:** the same code files. **Gives:** `Finding[]` framed as *exploit
plans*. **To:** the orchestrator.
([`../../agents/attack/source_code_exploiter.py`](../../agents/attack/source_code_exploiter.py))

It **reuses `scan_code_static`** — the exact same static findings as the
defense scanner — then asks the LLM to turn each into an *exploit plan*:
what input the attacker sends, which CWE/rule it abuses, **which paper-1
property it violates**, and the expected effect. Same static-first,
three-sub-step shape as defense; only the *framing* differs.

**Why share the static layer?** Finding a vulnerability is the same problem
regardless of intent. Sharing it halves maintenance and guarantees red and
blue agree on the rule catalogue.

---

## Stage A3 — Deployment exploiter (enumerate attack paths)

**Takes:** the deployment YAML. **Gives:** `Finding[]` including explicit
**`ATK-PATH`** findings. **To:** the orchestrator.
([`../../agents/attack/deployment_exploiter.py`](../../agents/attack/deployment_exploiter.py))

It runs `scan_deployment_static` (the same topology checks) **plus**
`_enumerate_paths()`, which walks the graph and emits:
- a **poison path** for every `external → write` edge ("attacker writes into
  this datasource"),
- a **trigger path** for every `external → respond` edge ("attacker makes
  the victim consume it").

**Why poison vs trigger (paper 2 §4.2)?** An attack needs both: *how the
payload reaches the victim* (poison) and *what causes the victim to use it*
(trigger). The exploiter surfaces both so the orchestrator can pick a
combination.

---

## Stage A4 — Attack orchestrator (choose a plan)

**Takes:** the exploiter findings + the `SystemInstance` + the scenario.
**Gives:** an `AttackPlan`. **To:** the ethics guard.
([`../../agents/attack/attack_orchestrator.py`](../../agents/attack/attack_orchestrator.py))

```python
plan = orchestrator.plan([code_result, dep_result], scenario, instance)
```

It aggregates the findings, shows the LLM the scenario + the instance + the
allowed asset categories, and asks it to choose **1–3 findings to chain**
into an end-to-end plan: which paper-2 **target asset**, the **poison path**,
the **trigger path**, and a **confidence**. If the LLM's JSON won't parse,
it **falls back** to a severity heuristic (pick the top high/critical
findings). This mirrors the defense `DecisionAgent` (paper 4's typed
hand-off).

---

## Stage A5 — Ethics / scope guard

**Takes:** the scenario + the plan's target asset. **Gives:** an
`EthicsVerdict`. **To:** the generator (only if allowed).
([`../../agents/attack/ethics_guard.py`](../../agents/attack/ethics_guard.py))

```python
verdict = guard.check_plan(scenario, plan.target_asset)
```

Two gates:
- **scope_ok** — is the scenario in `attack.allowed_scenarios` (or
  `allow_all_in_dev`)?
- **target_ok** — is the target asset in `attack.authorized_targets`, or a
  `--authorize-target` CLI override, or the `*` wildcard?

If either fails, the verdict is `allowed=False` and **no scripts are
generated**. This is the offensive analogue of paper 1's properties:
*source authorisation* ("is the requester authorised?"), *task alignment*
("is the scenario in scope?"), *data isolation* ("is the target in scope?").

---

## Stage A6 — Attack generator (produce scripts)

**Takes:** the `AttackPlan`. **Gives:** a list of `AttackScript`. **To:** the
ethics filter + the run-log.
([`../../agents/attack/attack_generator.py`](../../agents/attack/attack_generator.py))

For each chosen finding it emits one script:
- **Hard-coded templates** for the common rule-ids (`_TEMPLATES`): e.g.
  `CODE-001` shell-injection probe, `CODE-005` pickle RCE, `CODE-012` SQLi
  probe, `CODE-020` JWT-`none` token, `TOP-002` memory-poison message,
  `TOP-008` A2A fear-injection, `LOG-CAN-02` `cansend` frame. Each is benign
  (touches `/tmp/atk_canary`) and reviewable.
- **LLM fallback** for anything else, constrained to use placeholder
  hostnames and a benign canary.

Then `guard.filter_scripts(scripts)` scans every body for **destructive
patterns** (`rm -rf /`, fork bomb, `dd if=/dev/zero`, `mkfs`, …) and
**redacts** any match — the script is replaced with a stub and its title is
listed under `redacted`.

**Why templates + LLM?** Templates are deterministic and human-auditable
(review once, trust forever); the LLM covers the long tail.

---

## Stage A7 — Persist

**Takes:** the whole attack run. **Gives:** `memory/attack_<scenario>.json`,
one file per script under `run_logs/<run>/scripts/`, and a signed
`Incident` (mode `attack`).

---

## The attack chain as one table

| Stage | Takes | Gives | To |
|-------|-------|-------|----|
| A0 read scenario | a path/string/default | the goal text | orchestrator |
| A1 discovery | deployment YAML | `SystemInstance` (graph) | orchestrator |
| A2 code exploiter | code files | `Finding[]` (exploit plans) | orchestrator |
| A3 deployment exploiter | deployment YAML | `Finding[]` + `ATK-PATH` (poison/trigger) | orchestrator |
| A4 orchestrator | findings + instance + scenario | `AttackPlan` (asset, paths, confidence) | ethics guard |
| A5 ethics guard | scenario + target | `EthicsVerdict` (scope/target) | generator |
| A6 generator | `AttackPlan` | `AttackScript[]` (templates/LLM, filtered) | persist |
| A7 persist | the run | JSON record + `scripts/` + signed `Incident` | disk/memory |

---

## How `--mode both` works

`python pipeline.py --mode both …` runs the **defense** pipeline and then
the **attack** pipeline on the same inputs, and prints a summary table for
each side. It's the easiest way to see the red/blue symmetry on one
scenario.

---

## One-paragraph recap

The attack pipeline **takes** a deployment + code + a damage scenario,
**maps the system into a graph** (passive recon), **reuses the same static
findings but frames them as exploit plans**, **enumerates poison/trigger
attack paths**, **chooses a 1–3-step attack plan** aimed at a paper-2 asset,
**checks scope/target with the EthicsGuard**, and (only if in scope) **emits
benign, reviewable proof-of-concept scripts** — recording everything for
review. It is the controlled adversary that lets the defense side be tested
honestly.

Next: **[Chapter 5 — Code reference](05_CODE_REFERENCE.md)** — every file,
class, and function.
