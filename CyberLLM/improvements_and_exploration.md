# Improvements & Exploration Roadmap

This is the *forward map* for the CyberLLM project. Each item is
prioritised, tagged with the paper(s) that motivate it, and includes
concrete acceptance criteria so you can mark it done.

Legend: **(P1)** = paper 1 (formal security framework), **(P2)** =
paper 2 (AgentHeLLM threat model), **(P3)** = paper 3 (TUM event
chains), **(P4)** = paper 4 (Härer multi-agent spec), **(P5)** =
paper 5 (edge MAS coordination).

---

## Status as of 2026-06-03

A second implementation pass closed the **research / learning** gaps that
remained after the engineering backbone was built. Checkboxes below are
now accurate (`[x]` done, `[~]` partial, `[ ]` deferred). What changed in
this pass:

- **Phase A** — A.2 graceful credential fallback + A.4 token budgeting:
  **done** (`llm_client.py`, `tools/tokens.py`, `agents/base_agent.py`).
- **Phase C.4** — per-step contextual guard is now wired into the action
  executor (`pipeline.build_step_guard`).
- **Phase E** — the adaptive memory loop is **closed**: a signed SQLite
  incident store (`agents/memory_store.py`), recall-as-few-shot in the
  Decision Agent, and HMAC-verified, source-authenticated reads.
- **Phase F** — H_a LLM-judge (`agents/ha_judge.py`), mandatory
  provenance, delegation rules, and compositional + temporal trajectory
  checks (`agents/security_guard.py`).
- **D.4 / D.5 / G.4** — a **static** evaluation harness (`evaluate.py` +
  `examples/labels.yaml`): detection recall, false-positive rate on
  clean controls, a property-violation table, and an asset×scenario×skill
  scoreboard. (No MTTD — that is a dynamic metric; see the note in
  `evaluate.py`.)

Deferred by decision (need heavy deps or external corpora): **Phase B**
(RAG), **G.1–G.3** (CyberMetric / AgentDojo / CAR-bench), **Phase H**
(federated / quantised-edge / auto-spawn research).

---

## Phase A — Replace the stub LLM with a real one (≈ 1 week)

**Why first.** Everything downstream becomes meaningful only when a real
model is generating findings and decisions.

- [x] **A.1 — Wire up Ollama for local development.** *(P4)*
  `OllamaLLM` provider exists in `llm_client.py`; switching
  `config.yaml` `llm_configs.default.provider` to `ollama` is all that's
  needed (pulling the model is the operator's machine-local step).
- [x] **A.2 — Add OpenAI / Anthropic configs.** *(P4)*
  Both providers exist; `LLMClient.create` now reads the API-key env var
  and **falls back to the stub with a warning** when it is missing, so
  CI / offline demos never crash (`_PROVIDER_KEY_ENV`).
- [x] **A.3 — Add a reasoning agent.** *(P4)*
  The `reasoning` LLM config + slot exist and are used by the decision
  agent and attack orchestrator; point it at `gpt-4o` / `o1` / DeepSeek-R1
  via config.
- [x] **A.4 — Token-budgeting.** *(P3)*
  `tools/tokens.py` (`estimate_tokens`, `TokenBudget`) — a dependency-free
  estimator; `BaseAgent.call_llm` accounts every prompt and warns past
  `max_prompt_tokens` (default 4 096, paper 3's threshold). (Streaming is
  provider-specific and left to the real client.)

**Done when:** the same `python pipeline.py` produces *model-generated*
findings, the decision JSON is consistent, and a regression test runs
in CI.

---

## Phase B — RAG over rules, CVEs, and signal catalogs (≈ 1–2 weeks)

**Why.** Inlining all rules in the prompt blows up tokens and bleeds
content (paper 3 §III warns explicitly about this).

- [ ] **B.1 — Index the local rule catalogue.** *(P3)*
  Add `tools/rag_index.py`. Use
  `sentence-transformers/all-MiniLM-L6-v2` to embed each rule. Store
  vectors in a local SQLite + FAISS DB.
- [ ] **B.2 — Re-rank with a cross-encoder.** *(P3)*
  Use `cross-encoder/ms-marco-MiniLM-L-6-v2` to re-rank top-k
  candidates (paper 3's exact recipe).
- [ ] **B.3 — Index a CVE / MITRE ATT&CK corpus.** *(P5)*
  Pull a subset of CVE JSONs that match our domain (CAN-bus, infotainment,
  Linux kernel). The Decision Agent can then ground each finding to a
  CVE if applicable.
- [ ] **B.4 — Index the VSS signal catalogue.** *(P3)*
  Optional, automotive-specific. Paper 3 shows VSS retrieval reaches
  100% accuracy on a 70B local model.
- [ ] **B.5 — Add a citation field to findings.** *(P1)*
  Each finding must carry the IDs of the rules / CVEs that *caused* the
  detection. This is the practical implementation of paper 1's
  instruction-attribution oracle `I`.

**Done when:** at least one finding cites a rule that was *retrieved*
rather than included verbatim in the prompt.

---

## Phase C — Real MCP tools (≈ 1 week)

- [ ] **C.1 — nmap MCP.** *(P4, P5)*  Deferred — dynamic/active probe,
  out of scope for the static-first pass. `observe.port_closed` does a
  socket check today.
- [x] **C.2 — Static analysis MCP.** *(P3)*
  `agents/action_engine/mcp_tools.CodeStaticScan` runs real
  `bandit -r … -f json` (and `semgrep --config=auto` when present),
  falling back to a dry-run envelope otherwise.
- [ ] **C.3 — Packet capture MCP.** *(P5)*  Deferred — dynamic capture.
- [x] **C.4 — Tool-use security check.** *(P1)*
  The per-step `GuardAdapter` is now wired into the action executor
  (`pipeline.build_step_guard`): paper 1's four properties **and** the
  H_a judge run on *every* MCP tool call, not just the final action.

**Done when:** the pipeline can scan a real localhost target and
detect a real port-listing diff.

---

## Phase D — Add the attack agents (≈ 2 weeks)

This is the "attack simulation" half of the project assignment.

- [x] **D.1 — Build an actor/datasource graph from the deployment YAML.**
  *(P2)*  `agents/attack/system_info_discovery.py` builds the
  `SystemInstance`; `deployment_exploiter.py` enumerates poison/trigger
  edges; trusted vs. external nodes are extracted.
- [ ] **D.2 — Implement bi-level path search.** *(P2)*  Deferred — the
  orchestrator chooses chains via LLM + severity heuristic today; a true
  A\*/BFS bi-level search is future work.
- [ ] **D.3 — Realise each attack skill as a replayable trace.** *(P2)*
  Deferred — skills emit descriptors; staging synthetic traces back
  through the defense pipeline (`--poison`) is future work.
- [x] **D.4 — Red / Blue evaluation harness (static).** *(P1, P2)*
  `evaluate.py`: per-scenario **detection recall** and **false-positive
  rate** on clean controls. *Mean-time-to-detect is intentionally N/A* —
  it is a dynamic metric and this system is static-first (documented in
  `evaluate.py`).
- [x] **D.5 — Map findings to the contextual security properties they
  violate.** *(P1)*  `evaluate.py` emits a property-violation table:
  each detected finding → the paper-1 property it implicates → the
  paper-2 asset it threatens.

**Done when:** the harness runs a benchmark of ≥ 5 attack scenarios and
prints a Red/Blue scoreboard.

---

## Phase E — Persistent memory and adaptive learning (≈ 1 week)

- [x] **E.1 — Promote `memory/` to a sqlite DB.** *(P5)*
  `agents/memory_store.MemoryStore` — a stdlib-only SQLite store
  (`memory/incidents.db`) holding one signed row per past outcome.
- [x] **E.2 — `consult_memory` at the start of the Decision Agent.**
  `DecisionAgent.run` recalls the K most-similar past incidents by
  **Jaccard overlap of the finding rule-id set** and injects them into
  the prompt as a `[memory]` few-shot block. Verified: in a batch the
  recall count grows as the store fills.
- [x] **E.3 — Defend memory.** *(P1, P2)*  Every write is **HMAC-signed**
  (`signing_key_env`) and tagged with its source; `recall_similar`
  verifies the signature **and** that the source is authenticated, so a
  tampered or unauthenticated row can never steer a decision.
  `verify_all()` is the integrity-sweep / "was my memory poisoned?" check.

---

## Phase F — Hardening the security guard (≈ ongoing)

Paper 1 is clear that all five oracle functions are open problems. We
should improve our approximations incrementally:

- [x] **F.1 — `H_a` LLM-judge.** *(P1)*  `agents/ha_judge.HaJudge` — a
  *separate* call answering `{serves: 0/1}`. The guard takes
  `action_ok = static_map_ok AND ha_judge_ok`, so the judge can only
  **tighten** the deterministic floor, never loosen it.
- [x] **F.2 — Provenance tags mandatory.** *(P1)*  `Input.__post_init__`
  rejects a missing `source` or an out-of-lattice `trust_level`
  (`ProvenanceError`); the pipeline therefore cannot feed an
  un-attributed artefact to an agent.
- [x] **F.3 — Compositional check.** *(P1)*
  `SecurityGuard.check_trajectory` flags combinations that are unsafe
  even when each step passes: read-sensitive→external-egress (exfil),
  destructive-without-forensics, destructive-without-notify.
- [x] **F.4 — Temporal check.** *(P1)*  Same method flags TOCTOU
  (check-then-act with no re-verification) and the memory-poisoning
  pattern (a destructive step in a plan influenced by a memory-sourced
  input).
- [x] **F.5 — Delegation rules.** *(P1)*  `BaseAgent.delegate` — a child
  inherits the parent's objective but starts with an **empty** trusted-
  source set (granted explicitly via `grant_sources`), so authority is
  never laundered through delegation.

---

## Phase G — Benchmarks and evaluation (≈ 2 weeks)

- [ ] **G.1 — CyberMetric Q&A.** *(P4)*  Replicate the 10-question
  baseline from paper 4 to validate that our agents have basic
  cybersecurity knowledge.
- [ ] **G.2 — AgentDojo.** *(P1)*  Run our Security Guard against
  the prompt-injection benchmark used in paper 1; report ASR
  reduction and benign-utility drop, matching paper 1's headline
  numbers (PI detector reduced ASR by 86% with benign utility
  dropping 69 → 41.5).
- [ ] **G.3 — CAR-bench (or analogous automotive benchmark).** *(P2)*
  Paper 2 highlights CAR-bench as evaluating consistency and
  limit-awareness of in-vehicle LLM agents. Use it for the in-vehicle
  agent slice.
- [x] **G.4 — Internal Red/Blue scoreboard.** *(P2)*  `evaluate.py`
  emits an **asset category × scenario × defense-skill** scoreboard
  (each scenario's touched assets → implied paper-5 tier → candidate
  skills), alongside detection recall and the property-violation table.

---

## Phase H — Reach beyond the diagram

- [ ] **H.1 — Federated learning across edge nodes.** *(P5)*
  Privacy-preserving threat-model updates across deployments.
- [ ] **H.2 — Distilled / quantised on-edge LLM.** *(P5)*
  Move the *detection* agents onto the edge with a 4-bit quantised
  3B–8B model; keep the *decision* agent in the cloud.
- [ ] **H.3 — Adversarially robust prompt engineering.** *(P1, P2)*
  Templates that resist trigger-path injection from external A2A
  agents.
- [ ] **H.4 — Auto-spawn agents under load.** *(P5)*
  Self-evolving agent swarm: clone a detection agent when log volume
  exceeds a threshold; reap idle clones.
- [ ] **H.5 — Counterfactual mitigation analysis.** *(P2)*
  "If we add rule X, which attack paths are removed?" — paper 2 lists
  this in its future-work section.

---

## Practical things to try this week (low-hanging fruit)

1. **Run with Ollama.** *(Phase A.1)* — provider is ready; flip the
   config and pull a model.
2. **Add a 7th rule to `rules/*.yaml`.** Done and exceeded —
   `extended_rules.yaml` carries ~40 rules beyond the baseline.
3. **Add one attack scenario end-to-end (`--poison`).** Still open
   (D.3) — staging a synthetic poison trace back through defense.
4. **Wire `bandit`.** *(Phase C.2)* — done (`CodeStaticScan`).

New since this pass: `python evaluate.py` produces a static Red/Blue
scoreboard, and the adaptive memory loop (Phase E) is live — run a batch
and watch the decision agent recall similar past incidents.

---

## Open research questions to keep an eye on

- How to robustly approximate paper 1's instruction-attribution `I` in
  a black-box LLM setting?
- Can we use *structured constrained generation* (e.g. JSON Schema
  enforcement) to make oracle outputs reliable enough for production?
- How to evaluate emergent multi-step attacks where each step is
  individually-aligned (paper 1 §7 compositional security)?
- What's the right format for a TARA-friendly audit report? Use the
  AgentHeLLM table format (paper 2 §4) as the starting point.
- For automotive: do the OCL-style topology rules of paper 3 generalise
  to non-automotive edge networks (paper 5)?
