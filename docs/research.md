# Research foundations

CyberLLM: A Multi-Agent LLM Framework for Autonomous Detection and Guarded Response in Automotive Cybersecurity.

## Associated CyberLLM paper

This project is associated with the paper **[CyberLLM: A Multi-Agent LLM Framework for Autonomous Detection and Guarded Response in Automotive Cybersecurity](https://arxiv.org/abs/2608.06651)**.

**Authors:** Nenad Petrovic, Oussama Jeddou, Feres Ben Fraj, Vahid Zolfaghari,
Fengjunjie Pan, Andre Schamschurko, and Alois Knoll.

**Published on arXiv:** 6 August 2026 · **Identifier:** arXiv:2608.06651.

[Read the PDF](https://arxiv.org/pdf/2608.06651) ·
[DOI: 10.48550/arXiv.2608.06651](https://doi.org/10.48550/arXiv.2608.06651)

### Citing the CyberLLM paper

```bibtex
@misc{petrovic2026cyberllm,
  title = {{CyberLLM}: A Multi-Agent {LLM} Framework for Autonomous Detection and Guarded Response in Automotive Cybersecurity},
  author = {Nenad Petrovic and Oussama Jeddou and Feres Ben Fraj and Vahid Zolfaghari and Fengjunjie Pan and Andre Schamschurko and Alois Knoll},
  year = {2026},
  eprint = {2608.06651},
  archivePrefix = {arXiv},
  primaryClass = {cs.CR},
  doi = {10.48550/arXiv.2608.06651},
  url = {https://arxiv.org/abs/2608.06651}
}
```

## Foundational works (P1–P5)

The five papers below underpin the project's design. Their **P1–P5** identifiers
connect the code to its research foundations. The implementation mapping records
how CyberLLM uses these ideas; it does not imply endorsement by the authors or
certification of the implementation's security properties.

| # | Paper | Authors (year) | What CyberLLM takes from it |
|---|-------|----------------|------------------------------|
| **P1** | [A Framework for Formalizing LLM Agent Security](https://arxiv.org/abs/2603.19469) | **Vincent Siu, Jingxuan He, Kyle Montgomery, Zhun Wang, Neil Gong, Chenguang Wang, Dawn Song** (2026) | Four contextual-security properties (task / action / source-authorization / data-isolation) + the **H_a** "does this action serve the objective?" oracle → the `SecurityGuard` / `EthicsGuard`. |
| **P2** | [Agent2Agent Threats in Safety-Critical LLM Assistants: A Human-Centric Taxonomy](https://arxiv.org/abs/2602.05877) | **Lukas Stappen, Ahmet Erkan Turan, Johann Hagerer, Georg Groh** (2026) | Human-centric asset taxonomy and the actor / datasource graph with **poison-path vs trigger-path** attack modelling → deployment scanner + attack side. |
| **P3** | [LLM-Empowered Functional Safety and Security by Design in Automotive Systems](https://arxiv.org/abs/2601.02215) | **Nenad Petrovic, Vahid Zolfaghari, Fengjunjie Pan, Alois Knoll** (2026) | Rules-as-context (OCL-style topology rules), retrieve-and-refine prompting, and the automated code-correction loop → `rules/*.yaml`, remediation. |
| **P4** | [Specification and Evaluation of Multi-Agent LLM Systems — Prototype and Cybersecurity Applications](https://arxiv.org/abs/2506.10467) | **Felix Härer** (2025) | The engineering backbone: schema-driven agents, prompt templating, provider abstraction, typed agent-to-agent hand-off → `agents/base_agent.py`, `llm_client.py`, `config.yaml`. |
| **P5** | *LLM-Orchestrated Multi-Agent Coordination for Adaptive Cyber Defense at the Edge* | **Collins, James, Thomas** (2026) | The layered architecture, **tiered/adaptive response**, and the learning-from-memory loop → pipeline orchestration, response tiers, signed memory. |

## Reference status

P1–P4 link directly to their arXiv records; titles and author names were checked
against those records. P4 uses the complete title, including its subtitle.

P5 remains credited with the title and authors supplied in the original project.
Its direct publication link and identifier have not yet been confirmed. No DOI,
venue, or publication identifier has been invented.
