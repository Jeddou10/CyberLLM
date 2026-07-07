# `agents/attack/system_info_discovery.py` — passive recon (diagram-2 entry node)

`[← back to all_info index](../../README.md)`

---

## 1. Purpose & place in the system

The first attack-pipeline step (step [1/5]). It reads the deployment YAML and
builds a structured `SystemInstance` — the **P2 actor/datasource graph** — that
the orchestrator reasons over. This is **passive reconnaissance**: no packets are
sent to the target (static-first applies to attack too). It draws on P2 §4.2.1
(model the system as actors + datasources) and P3 §III (turn text/catalogs into a
structured instance).

## 2. Imports
`yaml`; `AgentResult`/`BaseAgent`/`Input` from the base.

## 3. Walkthrough

### `SystemInstance` — lines 30–39
The recon output: `actors`, `datasources`, `edges`, plus the derived
`external_actors`, `safety_actors`, and free-text `notes`.

### `run(inputs)` — lines 56–79
Select the deployment YAML (none → empty result), **build the instance
deterministically** (`_build_instance`), stash it on `self.data`, then make an
**optional** LLM call only for extra "notes" (71–73) — the instance itself is
fully built from YAML, so the pipeline works even with the stub. The structured
instance is attached to the result (`result.system_instance`) for the
orchestrator to pick up.

### `_build_instance(deployment_yaml)` — lines 82–114
Parse the YAML and derive:
- **external actors (89–93):** anything `trust_level=external` or an
  External* type.
- **safety actors (94–96):** `SafetyECU`/`ZoneECU`/`HighPerformanceComputer`.
- **notes (98–105):** flags for exposed/internet-reachable actors, `0.0.0.0`
  binds, and world-readable access policies.

Returns a fully-populated `SystemInstance`.

## 4. Edge cases, gotchas & design decisions
- **Passive only.** The docstring is explicit: no packets sent. Active recon
  would live behind the `EthicsGuard` — it's deliberately not here.
- **Deterministic instance, optional LLM.** The graph is built from YAML; the LLM
  only adds commentary, so discovery is reproducible under the stub.
- **The instance is the shared currency** between recon, the exploiters, and the
  orchestrator — the same P2 graph the defense side uses.
