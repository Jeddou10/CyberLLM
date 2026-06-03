# Paper 3 — LLM-Empowered Functional Safety and Security by Design in Automotive Systems (Petrovic, Zolfaghari, Pan, Knoll — TUM, 2026)

> arXiv:2601.02215v1 — TUM, Chair of Robotics, Artificial Intelligence
> and Real-Time Systems.

This paper is **the closest one to the diagram in `image.png`** —
because the diagram itself is in the style of this group's work
(metamodel + instance creation + OCL rules + LLM + decision pipeline).
Treat this as the *implementation pattern of the diagram*.

---

## 1. Two workflows, both directly transposable to CyberLLM

### 1.1 Code analysis workflow (functional safety angle)

```
(1a/1b)  VSS catalog          CAN catalog
            │                      │
            ▼                      ▼
        Catalog parsers ──► RAG indexer ──► RAG context  (2a/2b, 3)
                                       │
   ┌───────────────────────────────────┘
   │
   ▼
Source code (target SDV component)
   │
   ▼
LLM with Prompt Construct 1  ─►  VSS/CAN signal extractor  (4-8)
   │                                   │
   ▼                                   ▼
LLM with Prompt Construct 2  ─►  Event-chain (PlantUML)    (9-11)
   │
   ▼
Model-to-model transform (PlantUML → JSON)
   │
   ▼
Rule checking against safety/security rules               (11-12)
   │                          │
   ▼ pass                     ▼ fail → Prompt Construct 2b (auto-correct code)
Deploy to target / SDV testbench                          (13-14)
```

### 1.2 Topology security workflow (security by design)

```
User description of system topology
   │
   ▼
Prompt Construct 3 (system model creation/update)
   │
   ▼
LLM-assisted instance model (PlantUML)
   │
   ▼
Security guidelines (textual)
   │
   ▼
Prompt Construct 4 → OCL constraints over the metamodel
   │
   ▼
EMF model + OCL rule checker
   │
   ├── pass → done
   └── fail → Prompt Construct 4b (auto-correct system model)
```

Both workflows = **`LLM + RAG + metamodel + rules + iterative correction`**.
That is exactly the loop in our project diagram (events → decision agent
→ action generator → target, with rules/policies + metamodel feeding the
agent).

---

## 2. The prompts to copy (they are concrete and reusable)

The paper publishes the prompt skeletons — these go straight into
`CyberLLM/prompts/`.

**Prompt Construct 1 — VSS/CAN message extraction.**
```
You are extracting a list of VSS signals and CAN messages based on the
given source code {code}. For each step's signal/message, extract:
name, type, value, protocol.
```

**Prompt Construct 2 — Event-chain generation from code.**
```
You are updating a PlantUML activity diagram about the automotive event
chain (no comments, no explanations) given as {current-event-chain},
based on source code {code}, taking into account
{relevant messages/signals}. For each event-chain step, the following
parameters are considered as notes: input, input_format, output,
output_format.
```

**Prompt Construct 2b — Automated code correction.**
```
Based on the code analysis outcome {result}, correct the following code
{code} to eliminate the detected functional-safety-related issues.
```

**Prompt Construct 3 — System model creation/update.**
```
Update model instance {current-system}, with respect to {metamodel},
based on requirements {user-input}.
```

**Prompt Construct 4 — System model constraint generation.**
```
Generate automotive system security constraints with respect to
{metamodel}, based on reference specification {security-guidelines}.
```

**Prompt Construct 4b — System model correction.**
```
Update automotive system model with respect to {metamodel}, based on
current representation {current-system} and analysis outcome
{OCL pass/fail list}.
```

All five use Härer's `[placeholder]` template idea (paper 4) and the RAG
context idea below.

---

## 3. Why RAG is essential (and what to index)

- VSS catalogs are *thousands* of entries; CAN catalogs *hundreds* of
  message types. Putting them in the prompt blows up tokens and
  hallucinates signals.
- The paper uses a **Retrieve-and-Re-rank** pipeline:
  - Encoder: `sentence-transformers/all-MiniLM-L6-v2`
  - Cross-encoder re-ranker: `ms-marco-MiniLM-L-6-v2`
  - Top-k retrieved chunks → fit into LLM context window.

For CyberLLM, **what to index**:
1. VSS signal catalogue (if automotive domain).
2. CAN/CAN-FD message dictionary.
3. Known-attack DB (MITRE ATT&CK, ATLAS, CVE excerpts).
4. The project's own rules/policies (so the agent can cite which rule
   it violated).
5. Past incidents (memory feature).

---

## 4. Example OCL rules (translate to your own rule language)

The paper gives reusable patterns:

```ocl
-- Communication-level safety
context Message
  inv SteeringCommandWithinLimits:
    self.target.oclIsTypeOf(SteeringActuator) implies
      let angle : Real = self.payloadValue.toReal()
      in angle >= -15.0 and angle <= 15.0

-- Architectural / topology security
context Message
  inv HPCtoZoneEthernetIEEE1722:
    self.source.oclIsTypeOf(HighPerformanceComputer)
    and self.target.oclIsTypeOf(ZoneECU)
    implies
      self.network.oclIsTypeOf(Ethernet)
      and self.standard = MessageStandardKind::IEEE-1722

-- Global safety bound
context VSSMessage
  inv TargetSpeedWithinSafetyLimit:
    self.vssPath = 'Vehicle.Speed.Target'
    implies self.payloadValue.toReal() <= 30.0
```

Plus event-chain temporal rules:

```
accelerate         before  pedestrian-camera-detected   (BAD — must not hold)
brake              after   camera-pedestrian-detected   (REQUIRED)
camera-sense       before  camera-pedestrian-detected   (REQUIRED — sensing first)
```

In CyberLLM we use a YAML/Python equivalent (`rules/example_rules.yaml`)
to keep the project lightweight, but the structure is identical.

---

## 5. Evaluation results to keep in mind

The paper measured GPT-5 vs LLaMA-3.3-70B-Instruct on three tasks:

| Task                         | GPT-5 (20 candidates) | LLaMA 3.3 70B |
|------------------------------|-----------------------|---------------|
| CAN-FD signal mapping        | 90%                   | 80%           |
| VSS signal mapping           | 100%                  | 100%          |
| Event-chain functional safety| S1=90%, S2=90%, S3=100% | S1=70%, S2=80%, S3=80% |

Take-aways for our model choice:

- **VSS-style structured inputs** are easy enough for a local 70B model
  to handle.
- **Free-form CAN message interpretation** benefits from a frontier
  model.
- For LLaMA, the run used 1× NVIDIA A100 80GB, token limit 4096, default
  temperature.

---

## 6. Tooling stack they use (good defaults)

| Need                            | Tool                              |
|---------------------------------|-----------------------------------|
| Workflow orchestration          | **n8n**                           |
| Local LLM runtime               | (implied) Ollama / vLLM           |
| Event chain visual notation     | PlantUML activity diagrams        |
| Modelling framework             | Eclipse Modeling Framework (EMF), Ecore |
| Constraint language             | OCL                               |
| Embeddings                      | sentence-transformers MiniLM      |
| Target / simulator              | CARLA + digital.auto testbench    |

For CyberLLM we keep this lighter: Python + LangChain-style prompt
templates + simple rules engine + Ollama for local LLM. The architectural
ideas (RAG, metamodel + OCL, auto-correction loop) carry over unchanged.

---

## 7. Why this paper is the implementation pattern

- It instantiates **every block** of the project diagram:
  - Metamodel ⇔ EMF / Ecore metamodel.
  - Instance creation ⇔ Prompt Construct 3.
  - Constraint modeling ⇔ Prompt Construct 4 + OCL.
  - Rules/Policies ⇔ OCL rules + textual security guidelines.
  - Decision agent ⇔ orchestrator running prompt constructs in order.
  - Action generator ⇔ Prompt Construct 2b (auto-correction code).
  - Target system ⇔ Testbench / CARLA / digital.auto.
  - Source-code / Log / Deployment scanners ⇔ VSS extractor / event
    chain extractor / topology analyzer.
- It introduces the **auto-correction feedback loop** — the LLM not
  only flags the issue, it proposes a fix. Our project should adopt
  this from day 1.
- The RAG-retrieve-and-re-rank pattern is mature and easy to reuse.

**Carry into CyberLLM:** rules-driven design, RAG over signal/CVE/rules
catalogs, PlantUML or YAML event chains for analysis traces,
auto-correction prompts (`{result}, {code} → fixed code`).
