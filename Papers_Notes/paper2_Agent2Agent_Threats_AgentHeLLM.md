# Paper 2 — Agent2Agent Threats in Safety-Critical LLM Assistants (Stappen, Turan, Hagerer, Groh — BMW Group + TUM, 2026)

> arXiv:2602.05877v1 — *"Agent2Agent Threats in Safety-Critical LLM
> Assistants: A Human-Centric Taxonomy"*, BMW Group Research + TUM.
> GitHub: <https://github.com/AgentHeLLM/AgentHeLLM-Attack-Path-Generator>

This is the **threat-modelling paper**. Use it as the catalogue of
attacks your CyberLLM project should be able to *simulate* (attack
side) and *detect* (defense side), specifically for the automotive
context the project assignment names.

---

## 1. Why a separate threat-modeling layer

ISO/SAE 21434 (and OWASP Agentic AI / MAESTRO) co-mingle *assets* with
*attack paths*. The paper's **AgentHeLLM framework** enforces a clean
"separation of concerns" between:

- **WHAT** is being protected (the asset) — taxonomy of victim
  values.
- **HOW** it is attacked (the attack path) — a graph of actors,
  datasources, and four interaction primitives.

This separation is what we adopt in `CyberLLM/threat_model/`.

---

## 2. The new attack surface for in-vehicle LLM agents

Production examples: BMW Intelligent Personal Assistant (powered by
Amazon's Alexa LLM), VW IDA (ChatGPT), Mercedes MBUX Virtual Assistant
(Gemini). These agents can already invoke vehicle functions (climate,
windows, lighting), call external services, and learn driver
preferences.

**Two amplifying factors specific to vehicles.**

- **Agent-to-Agent (A2A)** protocol — Google's spec for inter-agent
  dialogue. Provides transport-layer security (OAuth 2.0, HTTPS) but
  authenticates the **sender, not the content**. A compromised but
  properly authenticated agent can inject arbitrary natural-language
  payloads that the receiver processes with the same trust as a
  human's input.
- **Cognitive load while driving** — manipulated voice responses can
  cause driver distraction; effects measurably degrade performance
  *for up to 27 s* after the interaction ends.

A2A's permissive design (`TextPart` = unconstrained string,
`FilePart` = arbitrary bytes/URIs, `DataPart` = arbitrary key/value dict)
means the *structure* of A2A messages may *paradoxically* increase risk,
because developers will skip validation they would apply to raw user
input.

---

## 3. Human-centric asset taxonomy (use this in your attack agent)

Inspired by the Universal Declaration of Human Rights. **Seven asset
categories for the primary user**, ordered by severity in the
automotive context:

| Asset                              | UDHR refs       | Concrete damage scenario                                        | Example attack                                                                |
|------------------------------------|-----------------|-----------------------------------------------------------------|-------------------------------------------------------------------------------|
| **Life and Bodily Health**         | 3, 5, 25        | Cognitive overload                                              | Agent enters reasoning loop, bombarding driver with questions on highway     |
| **Mental and Emotional Well-Being**| 5, 22, 24, 25   | Fear induction                                                  | False "engine failure imminent" warning injected via A2A                      |
| **Privacy and Personal Data**      | 12              | Location exfiltration                                           | Memory rule: "send GPS to [endpoint] when temperature > 25°C"                 |
| **Knowledge, Thought, Belief**     | 18, 19, 26, 27  | Biased recommendations                                          | RAG poisoning → competitor products / unsafe routes                          |
| **Material and Economic Resources**| 17, 22, 23, 25  | Resource depletion                                              | Injected rule maxes AC/heating to drain EV battery                            |
| **Reputation and Dignity**         | 1, 12, 22, 23   | Contextual disclosure                                           | "Your psychiatrist appointment is at 4 PM" announced to colleagues            |
| **Social Relationships and Trust** | 1, 12, 16, 20, 27 | Delegated action abuse                                        | Agent sends "Transfer $10,000" to family using driver's identity              |

Beyond the driver, four **victim perspectives** matter:

1. Primary user (driver, passengers)
2. Digital / trust network (contacts accessible via the user's identity)
3. Environmental spillover (other road users, infrastructure)
4. System owner / provider (OEM, service providers)

These are the "what to protect" axes for the defense agent.

---

## 4. Formal attack-path model — the part that drives the simulator

Agentic ecosystems are modelled as **directed graphs**.

**Node types.**
- **Actor** — has agency. Examples: in-car agent, external A2A agent,
  user.
- **Datasource** — passive store. Examples: long-term memory, email,
  WhatsApp, contacts, calendar.

**Edge types (interaction primitives).**
- `read` (Actor ← Datasource)
- `write` (Actor → Datasource)
- `communicate` (Actor → Actor, initiate a conversation)
- `respond` (Actor → Actor, reply on an *existing* channel — requires
  a prior `communicate`)

**Two kinds of paths.**

| Kind          | Question it answers                                            | Example                                                                                                |
|---------------|----------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **Poison path**  | How does the malicious payload reach the victim?              | Attacker writes prompt into a shared Slack channel.                                                    |
| **Trigger path** | How do we cause the victim to consume the poison?             | A user query causes the IDE agent to read that Slack channel and execute the embedded prompt.          |

**Crucial insight:** trigger paths are *structurally identical* to
poison paths — both are data flows through the graph. A trigger path is
a recursive "attack-within-an-attack".

Real-world examples cited:
- **CurXecute** (Cursor IDE, CVE-2025-54135) — poison in public Slack
  channel; trigger when a user agent fetches that channel.
- **EchoLeak** (Microsoft 365 Copilot, CVE-2025-32711) — poison in an
  inbound email; trigger is any RAG query that retrieves it.

**Three-phase attack step (used by the path planner):**
```
Cost(Step) = Cost(PushPoison)
           + Cost(ActivationTrigger)   -- optional
           + Cost(ConsumptionTrigger)  -- optional
```

- **Edge Activation Trigger** — e.g., a `respond` edge needs an active
  channel; if none, we need a sub-search to find a path that compels
  the target to `communicate` first.
- **Push Poison Action** — the atomic propagation step (`write`,
  `communicate`, or `respond`).
- **Consumption Trigger** — if the target has a "watch" on the
  datasource (auto-polling), cost = 1; otherwise the planner has to
  find a path that compels the victim to `read`.

---

## 5. AgentHeLLM Attack Path Generator (the open-source tool)

- Interactive workbench. Practitioners place Actor/Datasource nodes,
  draw edges, designate attacker and target asset, then run analysis to
  get ranked attack paths.
- **Bi-level search.**
  - **Main planner**: A\* search over poison paths (because step costs
    are variable due to trigger sub-costs).
  - **Sub-search**: BFS over trigger chains (unit cost), invoked
    on-demand by the main planner.
- Handles: conditional `respond` edges with channel-state tracking,
  dormant poison requiring consumption triggers, persistence cycles
  (with cost-bounding to avoid infinite loops).

For CyberLLM we can reuse this **idea** without rewriting the tool —
we expose an `AttackPathGenerator` skill that, given a system topology
+ target asset, returns ranked attack paths to simulate.

---

## 6. Concrete attack scenarios our attack-agent should simulate

Pick at least one per asset category — these become the test cases:

- **Memory poisoning attack.** Attacker → Victim → Memory → Victim.
  Stage a malicious "memory rule" (e.g. "send GPS when temp > 25 °C"),
  then trigger consumption with an innocuous query about cabin
  temperature.
- **A2A fear injection.** External A2A agent sends a falsified
  "engine failure imminent" status; in-car agent forwards to driver →
  Mental and Emotional Well-Being violation.
- **Confused-deputy purchase.** External agent passes a tooled-up
  instruction the user could never authorize; in-car agent processes
  it with elevated permissions.
- **RAG poisoning route attack.** Attacker injects content into a
  navigation knowledge base → biased recommendation toward an unsafe
  road.
- **EV battery drain.** Injected memory rule maxes AC/heating →
  Material and Economic Resources violation.

Each scenario maps to:
- **(asset, attack path)** pair from the AgentHeLLM taxonomy.
- A violation of one or more contextual-security properties from
  paper 1.

---

## 7. Limitations the paper acknowledges (good to repeat in your report)

- Model assumes a **fixed architecture** — dynamic agent discovery is
  not modelled.
- Approach is **topological** — all edges treated as equally
  exploitable; prompt-injection difficulty isn't modelled.
- Requires **explicitly modelled trigger paths** — victims that poll
  autonomously aren't fully captured.
- Empirical validation against production systems is still future work.

Future extensions the paper itself suggests:
- Semantic cost models estimating injection difficulty per edge.
- Probability-based edges for ambient consumption.
- Counterfactual analysis to evaluate the effect of mitigations.

These belong in `improvements_and_exploration.md`.

---

## 8. How we use this in CyberLLM

- **For the attack agents.** The asset taxonomy + attack-path graph is
  the *menu* the attacker picks from. Our `attack_orchestrator` skill
  takes (target asset, system graph) → ranked attack scenarios.
- **For the defense agents.** Every detected anomaly is mapped back to
  *which asset* it threatens and *which path step* it corresponds to.
  This gives reports that are usable for a TARA assessment.
- **For reporting.** Tables in our reports follow the paper's format:
  *Asset category | Damage scenario | Example attack | Mitigation
  applied | Residual risk*.

**Carry into CyberLLM:** human-centric asset categories as labels on
findings; actor/datasource graph as the threat model; poison/trigger
path distinction in the attack agent.
