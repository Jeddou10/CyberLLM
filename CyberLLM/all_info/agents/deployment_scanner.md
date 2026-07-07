# `agents/deployment_scanner.py` — topology / deployment graph checks (P2 + P3)

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

The third defense scanner (step [3/6]). It reads a deployment YAML describing the
**actor/datasource interaction graph** (P2) and checks it against topology rules
(P3 OCL-style constraints), then optionally refines with the LLM. It also exposes
`parse_actor_graph`, which the attack-side threat modeller consumes. Run by
`run_defense_pipeline`; uses `scan_deployment_static` + `merge_findings`.

---

## 2. Imports
`yaml`; `BaseAgent`/`AgentResult`/`Finding`/`Input`; from `tools.static_analyzer`:
`merge_findings`, `scan_deployment_static`, `staticfinding_to_finding`.

---

## 3. Walkthrough

### `PROMPT` — lines 25–38
Frames the model as a topology security analyzer: build the actor/datasource
graph from the YAML, identify rule violations, don't duplicate the deterministic
hits, and return JSON findings.

### `run(inputs)` — lines 40–77
1. **Select deployment inputs (41–46):** keep `.yaml`/`.yml`; none → empty result.
2. **Graph-check pass (49–54):** `scan_deployment_static` runs the OCL-style
   `TOP-*` checks over the actor/edge graph (HPC↔ZoneECU transport, external
   write-to-memory poison paths, world-readable secrets, safety-ECU command
   sources, etc.), converted to `Finding`s tagged with this agent.
3. **LLM pass (57–66):** **gated by `use_llm`.** When on, it injects the static
   findings as context and asks for refinement; `raw_text = resp.text`. When off,
   `llm_findings = []` and a disabled note (the same `raw_text` fix as the other
   scanners).
4. **Merge + return (70–77).**

### `load_example` — lines 80–84
Build an `Input` from a YAML path, tagged `trust_level="authenticated"`.

### `parse_actor_graph(yaml_text)` — lines 86–95
A lightweight helper returning `{actors, datasources, edges}` — the P2 graph the
attack-side threat modeller consumes. Kept deliberately simple.

---

## 4. Edge cases, gotchas & design decisions

- **Graph checks express what regex can't.** "An external actor has a write edge
  into long-term memory" (a poison path) is a *graph* property — hence the
  hand-coded OCL-style checks in `scan_deployment_static`.
- **`use_llm` gate + `raw_text` fix.** As with the other scanners, the web UI
  disables the topology LLM pass unless the user supplied a deployment, so it
  can't hallucinate topology findings from an empty graph.
- **Shared graph model (P2).** `parse_actor_graph` gives both the defense scanner
  and the attack orchestrator the same `{actors, datasources, edges}` view, so
  blue and red reason over one representation.
- **Parse-safe.** A malformed YAML yields no static findings rather than crashing
  (the parse guard lives in `scan_deployment_static`).
