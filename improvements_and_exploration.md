# Improvements & Exploration Roadmap

This is the *forward map* for the CyberLLM project. Each item is
prioritised, tagged with the paper(s) that motivate it, and includes
concrete acceptance criteria so you can mark it done.

Legend: **(P1)** = paper 1 (formal security framework), **(P2)** =
paper 2 (AgentHeLLM threat model), **(P3)** = paper 3 (TUM event
chains), **(P4)** = paper 4 (Härer multi-agent spec), **(P5)** =
paper 5 (edge MAS coordination).

---

## Phase A — Replace the stub LLM with a real one (≈ 1 week)

**Why first.** Everything downstream becomes meaningful only when a real
model is generating findings and decisions.

- [ ] **A.1 — Wire up Ollama for local development.** *(P4)*
  Pull `llama3.1:8b-instruct` or `qwen2.5-coder:7b`. Switch
  `config.yaml` `llm_configs.default.provider` to `ollama`. Re-run
  `python pipeline.py` and confirm scanners produce non-stub findings.
- [ ] **A.2 — Add OpenAI / Anthropic configs.** *(P4)*
  Keep stub as a CI fallback. Add an env-var read in `llm_client.py`
  so missing keys fall back to stub with a warning.
- [ ] **A.3 — Add a reasoning agent.** *(P4)*
  In `config.yaml`, the `reasoning` LLM config currently points at
  the stub. Point it at `gpt-4o`, `o1-preview`, or DeepSeek-R1 (see
  paper 4 §IV results: these three completed all 12 cybersecurity
  test cases). The decision agent uses `reasoning` by design.
- [ ] **A.4 — Stream + token-budgeting.** *(P3)*
  Add a per-prompt token counter and warn when prompts exceed 4 096
  tokens (the threshold paper 3 used for LLaMA-3.3 70B).

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

- [ ] **C.1 — nmap MCP.** *(P4, P5)*
  Replace `tools/mcp_tools.PortScanTool.run` with a `subprocess` call
  to `nmap -sS -p 1-1024 …`. Parse XML output to the existing dict
  schema.
- [ ] **C.2 — Static analysis MCP.** *(P3)*
  Wrap `bandit` (Python) and `semgrep` (multi-language). The
  source-code scanner agent should call this *first* and pass the
  output to the LLM as evidence, not as raw code.
- [ ] **C.3 — Packet capture MCP.** *(P5)*
  Wrap `tshark` / `tcpdump` with a 10-second cap. For automotive
  experimentation, add a `can-utils` adapter (`candump`).
- [ ] **C.4 — Tool-use security check.** *(P1)*
  Before invoking any tool, the Security Guard runs an `H_a` check:
  *"does invoking this tool serve the declared objective?"*. Reject
  if not.

**Done when:** the pipeline can scan a real localhost target and
detect a real port-listing diff.

---

## Phase D — Add the attack agents (≈ 2 weeks)

This is the "attack simulation" half of the project assignment.

- [ ] **D.1 — Build an actor/datasource graph from the deployment YAML.**
  *(P2)*  Implemented partially in `deployment_scanner.parse_actor_graph`.
  Extract trusted vs. untrusted nodes.
- [ ] **D.2 — Implement bi-level path search.** *(P2)*
  Main planner: A\* over poison paths. Sub-search: BFS over trigger
  paths. Use unit cost for trigger steps, variable cost for poison
  steps. Output ranked attack paths.
- [ ] **D.3 — Realise each `skills/skills.py:ATTACK_SKILLS` skill.**
  *(P2)*  Make `memory_poison`, `a2a_fear_injection`,
  `rag_poisoning`, `confused_deputy`, `resource_depletion` produce
  *actual* synthetic traces that flow back through the defense
  pipeline.
- [ ] **D.4 — Add a Red / Blue evaluation harness.** *(P1, P2)*
  For each attack scenario, measure:
  - true-positive detection rate,
  - mean time to detect,
  - false-positive rate on benign traffic.
- [ ] **D.5 — Map every attack to the contextual security properties
  it violates.** *(P1)*  Output a table for each scenario: which
  property failed, which oracle approximation missed it, what would
  need to improve.

**Done when:** the harness runs a benchmark of ≥ 5 attack scenarios and
prints a Red/Blue scoreboard.

---

## Phase E — Persistent memory and adaptive learning (≈ 1 week)

- [ ] **E.1 — Promote `memory/` from a single JSON to a sqlite DB.** *(P5)*
- [ ] **E.2 — Add a `consult_memory` step at the start of the
  Decision Agent.** Retrieve the 5 most-similar past incidents (by
  finding-rule-id set) and inject them as few-shot examples.
- [ ] **E.3 — Defend memory.** *(P1, P2)*  Implement memory-poisoning
  defences: every memory write is signed with the source's
  authentication token; the security guard rejects reads from
  unauthenticated writes.

---

## Phase F — Hardening the security guard (≈ ongoing)

Paper 1 is clear that all five oracle functions are open problems. We
should improve our approximations incrementally:

- [ ] **F.1 — `H_a` LLM-judge.** *(P1)*  A small *separate* LLM call
  whose only job is to answer 0/1: "does action *a* serve objective
  *o*?". This is the single highest-value addition (paper 1 §6:
  defenses that approximate `H_a` reduced ASR by 86–88%).
- [ ] **F.2 — Provenance tags on every input.** *(P1)*  Make
  `Input.source` and `Input.trust_level` mandatory and let the
  pipeline refuse to run if any input lacks them.
- [ ] **F.3 — Compositional check.** *(P1)*  After every action,
  re-evaluate the trajectory: did the *combination* of recent actions
  violate any property even though each step individually was OK?
- [ ] **F.4 — Temporal check.** *(P1)*  Detect TOCTOU and
  memory-poisoning patterns at the trajectory level.
- [ ] **F.5 — Delegation rules.** *(P1)*  When agent A invokes agent
  B, B inherits A's objective but **not** its source set. Make
  this explicit in `BaseAgent`.

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
- [ ] **G.4 — Internal Red/Blue scoreboard.** *(P2)*  Output a table
  per asset category × attack scenario × defense skill.

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

1. **Run with Ollama.** *(Phase A.1)* — the single biggest payoff:
   the pipeline becomes a *real* demo.
2. **Add a 7th rule to `rules/example_rules.yaml`.** Pick one from the
   CWE Top 25; verify the source-code scanner picks it up.
3. **Add one attack scenario end-to-end.** Pick `memory_poison`.
   Stage the poison via a `--poison` CLI flag, then run the
   defense pipeline and confirm whether it's caught.
4. **Wire `bandit` into `StaticAnalysisTool`.** *(Phase C.2)*  A real
   tool plus a real LLM is much more convincing than either alone.

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
