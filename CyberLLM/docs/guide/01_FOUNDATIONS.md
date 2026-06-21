# Chapter 1 — Foundations (start here, no background assumed)

[◀ Master index](../DEVELOPER_GUIDE.md) · [Next: Architecture & data ▶](02_ARCHITECTURE.md)

This chapter assumes you know how to read Python but **not** that you know
cybersecurity, cars, or LLMs. We build up every idea from zero, and for
each one we say *why it matters for this project*.

---

## 1.1 What problem does CyberLLM solve?

Modern systems — especially cars — are full of software. That software has
three kinds of artefacts that can hide security problems:

- **Source code** — the programs themselves (bugs like "this runs whatever
  text a stranger sends it").
- **Logs** — the running diary a system writes ("user X failed to log in
  12 times in 10 seconds" = someone is guessing passwords).
- **Deployment configuration** — *how the pieces are wired together* ("the
  database is reachable from the public internet" = bad).

A human security analyst reads all three, decides how serious a problem is,
and responds (patch the code, block an attacker, isolate a component).
**CyberLLM automates that analyst** using LLMs as the reasoning engine —
and adds a mirror "attacker" that generates proof-of-concept exploits so
defenders can test themselves. The supervisor's brief (quoted in the
[README](../../README.md) §0) is exactly this.

> **Why automate it?** Cars and fleets produce far more code/logs/configs
> than humans can review. An agent that turns "unstructured security data
> into structured knowledge" scales that review.

---

## 1.2 The vocabulary (every term you'll meet)

Read this once; refer back as needed.

**LLM (Large Language Model)** — a model like GPT-4o that takes text in and
produces text out. Here it's used to *read* code/logs and *write* a
structured finding or decision (as JSON). It is powerful but
**probabilistic**: it can be wrong, refuse, or vary. That's why we never
trust it alone (see "static-first" below).

**Agent** — in this project, a small Python class with: an *objective* (a
one-line goal), an *LLM* to call, a *prompt template*, and a `run()` method.
"Multi-agent" = several specialised agents, each doing one job, passing
results to the next. (Contrast: one giant LLM call doing everything.)

**Prompt** — the text we send the LLM. We build it from a *template* with
`[placeholders]` we fill in (e.g. `[code]`, `[rules]`).

**Stub** — a *fake* LLM that ships in the box. It looks at keywords in the
prompt and returns canned, deterministic JSON. It lets the whole program
run with **no API key and no internet**, and it makes tests reproducible.

**Finding** — one detected issue: a rule id (`CODE-001`), a severity, the
evidence (the matched snippet), and an explanation. The "atom" of the
system.

**Rule** — a small entry in a YAML file describing a thing to look for
(e.g. a regular expression for "command injection"). Rules live *outside*
the code so every finding is traceable to a versioned rule.

**Regular expression (regex)** — a pattern that matches text. E.g.
`subprocess\.(call|run)\(.+shell\s*=\s*True` matches code that runs a shell
command from untrusted input. Used by the *static* (deterministic) scanner.

**Static vs dynamic analysis** — *static* = examine the artefact **without
running it** (read the code, parse the config). *dynamic* = run it and
watch. This project is **static-first** (see §1.4).

**Vulnerability / CWE** — a weakness an attacker can abuse (e.g. CWE-78
"OS command injection"). Rule ids like `CODE-001` map to these classes.

**CAN bus** — the internal network inside a car where electronic control
units (ECUs) talk. "CAN injection" = sending forged messages on it (can be
safety-critical, e.g. faking a brake command).

**ECU (Electronic Control Unit)** — a small computer in a car (engine,
brakes, body control…). A **safety ECU** controls something dangerous.

**SDV (Software-Defined Vehicle)** — a car whose features are largely
software, with a powerful central computer ("HPC", High-Performance
Computer) and zone controllers.

**Actor / datasource / edge** — how we model a deployment as a **graph**:
*actors* are components or users; *datasources* are stores (a database, a
memory); *edges* are who-talks-to-whom with a *primitive*
(`read`/`write`/`communicate`/`respond`). Drawn from paper 2.

**Topology** — the shape of that graph. A *topology rule* checks structural
facts ("the secrets store must not be world-readable").

**Tier (soft / moderate / hard)** — how strong a defensive response should
be, chosen from how confident/severe the situation is (paper 5). Soft =
rate-limit; moderate = block an IP; hard = isolate a node.

**MCP (Model Context Protocol) tool** — a standardised "tool" an agent can
call to *do* something in the world (block an IP, run `bandit`, send an
alert). Each tool declares its inputs, its side-effect, and how to run it.

**Guard** — a separate component that can **refuse** an action it judges
unsafe or out-of-scope. Defense side = `SecurityGuard`; attack side =
`EthicsGuard`.

**Dry-run** — "pretend to do it and report what *would* happen", without
actually changing anything. The action engine is dry-run by default for
safety.

**Provenance / trust level** — a label on every input saying where it came
from and how much we trust it (`authenticated`, `external`, `tool`,
`memory`). Critical for the guard's reasoning.

**Memory (the store)** — a small database of past runs and their outcomes,
so the system can "remember what worked last time".

---

## 1.3 The five research papers (in plain English)

The whole design is justified by five papers. You don't need to read them,
but knowing what each contributes explains *why* code looks the way it does.
You'll see tags `(P1)…(P5)` everywhere.

- **P1 — Contextual security.** Big idea: *"following instructions
  correctly is not the same as being secure."* An agent can do exactly what
  it's told and still be exploited, depending on **context**. P1 defines
  **four properties** a guard should check and **five "oracle" functions**
  (hard sub-problems) it should approximate. → becomes our `SecurityGuard`
  and the `HaJudge`.
- **P2 — AgentHeLLM (BMW/TUM).** Gives us a **human-centric asset taxonomy**
  (what's ultimately at risk: "Life and Bodily Health", "Privacy", …), the
  **actor/datasource graph**, and **poison-path vs trigger-path** attack
  modelling. → becomes our topology checks and the attack agents.
- **P3 — Event chains + OCL + RAG (TUM).** Big idea: keep the security
  rules **outside** the LLM and *hand them to it as context* (a form of
  "retrieval-augmented generation", RAG), so the model refines rather than
  invents. → becomes our `rules/*.yaml` + the "static-first" merge.
- **P4 — Härer multi-agent schema.** The engineering backbone: a
  **schema-driven agent** (an LLM-config + a data dict + an objective + a
  prompt template), agents calling agents with **typed hand-offs**. →
  becomes `BaseAgent` and the provider abstraction.
- **P5 — Edge MAS coordination (Collins).** A **layered**
  detect → decide → respond architecture, **tiered response**, and an
  **adaptive-learning loop** (learn from outcomes over time). → becomes the
  pipeline shape, the tiers, the memory store, and the new re-planning loop.

Per-paper notes live in [`../../../Papers_Notes/`](../../../Papers_Notes/).

---

## 1.4 The one rule that explains everything: **static-first**

The supervisor's hard constraint:

> *"mainly detect all static vulnerabilities and, if possible, active ones
> when running it."*

So **every scanner runs a deterministic pass before asking the LLM**:

1. **Static pass** — run the rules (regex on code, hand-coded heuristics on
   logs, graph checks on topology). This *always* runs, *always* returns
   the same answer, and is *traceable* to a rule. It's the **floor**.
2. **LLM pass** — the static findings are put *into* the prompt, and the
   LLM is asked to "refine, explain, or extend — do not duplicate". Its job
   is *refinement, not invention*.
3. **Merge** — combine the two, **static wins on duplicates**.

**Analogy.** Think of a spell-checker (deterministic, always finds the
obvious typos) plus a human editor (smart, catches subtle issues, but
occasionally distracted). You run the spell-checker first so nothing
obvious is ever missed, then the editor improves the rest.

**Why this matters so much:**
- The program produces **real, useful findings with no LLM at all** (the
  stub). Tests and demos work offline.
- A real LLM only ever makes results *better*, never worse — it can't
  delete a static finding.
- Every static finding points at a rule you can read in a YAML file.

The single most common way to "break" this project is to let the LLM
*replace* the static layer. **Don't.** Keep the floor.

> A note on the word "static" here: it also shapes the **evaluation**
> (chapter 7) — we score detection on the labelled corpus *without running
> targets*, and we explicitly do **not** report "mean time to detect"
> because that's a *dynamic* metric.

---

## 1.5 Why "agentic" and not just "a script"?

A pipeline is "agentic" in this project only when six properties hold
(detailed in [`../AGENTIC_WORK.md`](../AGENTIC_WORK.md)): goal-directed
(each agent has an `objective`), specialised roles, **typed hand-offs**
(structured records, not free text), **tool use** (MCP tools), **observation
+ feedback** (it checks whether its action worked and reacts), and
**guardrails** (a separate component can refuse). The recent upgrade added
the missing "observation + feedback" piece — the **re-planning loop** — so
the system now genuinely closes that loop (chapter 3).

---

## 1.6 What you should now be able to say

- *What does CyberLLM do?* Reads code/logs/configs, finds security issues,
  decides severity, and responds — with a mirror that generates exploits
  for authorised testing.
- *Why is it trustworthy/offline-capable?* Static-first: deterministic
  rules run before any LLM, and a stub LLM ships in the box.
- *Why these design choices?* Each maps to one of five papers (P1 guards,
  P2 graph/assets, P3 rules-as-context, P4 agent schema, P5 layers + tiers
  + learning).

Next: **[Chapter 2 — Architecture & data types](02_ARCHITECTURE.md)**, where
we lay out the two pipelines and every data structure they pass around.
