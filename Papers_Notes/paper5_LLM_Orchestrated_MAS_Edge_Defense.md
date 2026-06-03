# Paper 5 — LLM-Orchestrated Multi-Agent Coordination for Adaptive Cyber Defense at the Edge (Collins, James, Thomas, 2026)

> *"LLM-Orchestrated Multi-Agent Coordination for Adaptive Cyber Defense
> at the Edge"*, 2026.

This paper is **conceptual** (no code, no benchmark) — but it gives the
clearest *layered shape* of what we are building. Use it as the
architectural blueprint above Härer's executable backbone.

---

## 1. Three-layer architecture

| Layer                       | Components                       | Role                                                              |
|-----------------------------|----------------------------------|-------------------------------------------------------------------|
| **Edge Agent Layer**        | Monitoring agents, Response agents | Collect traffic/logs/behaviour; execute local mitigation.        |
| **LLM Orchestration Layer** | Central LLM engine, Prompt Manager | Global reasoning, threat interpretation, task allocation.        |
| **Security Intelligence Layer** | Threat KB, Learning module     | Stores signatures/embeddings; updates threat models from feedback.|

The **Prompt Manager** is worth highlighting: raw agent inputs are
converted into *structured* prompts before they hit the LLM. This maps
directly onto Härer's prompt-template + data-dict pattern (paper 4) and
onto the RAG layer in the TUM paper (paper 3).

The LLM is **not** on every edge node. Lightweight proxy models do
preprocessing; the heavy LLM lives in the orchestration layer. → For our
project: cheap local LLM near the data source, big model in the
decision agent.

---

## 2. Specialized agent roles (copy these into CyberLLM)

The paper proposes **heterogeneous agents** at the edge:

| Agent type            | Job                                                                |
|-----------------------|--------------------------------------------------------------------|
| **Detection agent**   | Identify anomalies in network traffic.                             |
| **Analysis agent**    | Local classification of suspicious behaviour.                      |
| **Response agent**    | Execute immediate defensive actions.                               |
| **Verification agent**| Validate threat legitimacy, reduce false positives.                |

These map cleanly onto the diagram in `image.png`:

- Source code scanner ⇆ analysis agent
- Log analyzer        ⇆ detection agent
- Deployment scanner  ⇆ analysis agent (config-side)
- Action generator    ⇆ response agent
- Decision agent      ⇆ verification + orchestrator

We instantiate exactly this set in `CyberLLM/agents/`.

---

## 3. Coordination cycle (the loop our pipeline runs)

```
1. Agents collect local observations
2. Observations → structured semantic inputs
3. LLM processes inputs → global situational awareness
4. Task allocation decisions issued to agents
5. Agents execute responses → report outcomes
6. Feedback refines future decisions
```

We implement steps 1–5 in `pipeline.py`; step 6 is the
*adaptive learning loop* and corresponds to the `memory/` directory
(optional feature in the assignment).

---

## 4. Tiered response strategy

The LLM picks one of three response intensities, conditional on threat
confidence:

| Intensity | Examples                              |
|-----------|---------------------------------------|
| **Soft**     | Rate limiting, traffic shaping.       |
| **Moderate** | Session termination, IP blocking.     |
| **Hard**     | Node isolation, network segmentation. |

We expose this directly in `CyberLLM/skills/skills.py` as
`soft_response`, `moderate_response`, `hard_response` skills, each with
its own confidence threshold.

---

## 5. Challenges the paper flags (and how we should mitigate)

| Challenge                       | Our mitigation                                                                                                                     |
|---------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| Latency                         | Local proxy models for pre-filtering; heavy LLM only on escalated events.                                                          |
| Resource limits on edge devices | Use Ollama-deployable small LLMs (LLaMA-3.x, DeepSeek-R1-Distill).                                                                  |
| Adversarial prompt manipulation | Use the contextual-security oracles from paper 1; check `source authorization` and `action alignment` before executing any action. |
| Privacy of transmitted data     | Redact / hash sensitive fields in the Prompt Manager before LLM call.                                                              |
| Coordination complexity         | Use Härer's schema-driven approach (paper 4) so agents are declarative, not hand-coded.                                            |

---

## 6. Forward-looking extensions the paper recommends

These go straight into `improvements_and_exploration.md`:

- **Federated learning** for privacy-preserving updates of the threat KB.
- **Lightweight LLMs on edge devices** (quantized, distilled).
- **Adversarially robust prompt engineering** (interplay with paper 1).
- **Self-evolving agent swarms** — auto-spawn analysis agents when load
  spikes.

---

## 7. Why this paper is the architectural shape

- Confirms the multi-agent decomposition we need (detection / analysis
  / response / verification).
- Gives us the layered separation (edge / orchestration / intelligence)
  that maps to the diagram.
- Provides the response-tiering taxonomy we expose as skills.
- Names the realistic deployment constraints (latency, resources,
  adversarial pressure) that our design must keep in mind.

This paper does **not** give us code — combine with paper 4 (Härer) for
the executable backbone and paper 3 (TUM) for the rules / metamodel layer.
