# Paper 1 — A Framework for Formalizing LLM Agent Security (Siu, He, Montgomery, Wang, Gong, Wang, Song — UCSC/UCB/Duke, 2026)

> arXiv:2603.19469v1 — "A Framework for Formalizing LLM Agent Security",
> UC Santa Cruz, UC Berkeley, Duke.

This is the **safety/security validator** for our defense agents. It
gives us four formal security properties and "oracle functions". Use
them as the *runtime guards* around any action the agent wants to take.

---

## 1. The core insight — security is contextual

> The same action may be a legitimate task **or** a security violation
> depending on the **execution context** Cₜ.

Naive content-based detection ("any prompt containing `delete file` is
malicious") forces a utility-vs-security tradeoff. The framework
resolves this by checking authorization at runtime.

Execution context formally:

```
C_t = ( p, Tr_{t-1}, M_t, E_t, S_auth,t, G )
```

where
- `p` — user prompt
- `Tr_{t-1}` — trajectory of (action, observation) pairs so far
- `M_t` — agent's persistent memory
- `E_t` — environment state
- `S_auth,t` — set of currently authenticated sources
- `G = (S, R)` — source permission graph (who may access what)

This is the *exact* state our `DecisionAgent` should keep around and
log for every step.

---

## 2. The four security properties to enforce

| # | Property               | Question it answers                                                |
|---|------------------------|--------------------------------------------------------------------|
| 1 | **Task alignment**     | Is the pursued objective `o₀ ∈ O` (the allowed space)? Has the trajectory drifted? |
| 2 | **Action alignment**   | Does this individual action `aₜ` serve `o₀`?                       |
| 3 | **Source authorization** | Did the inputs that caused `aₜ` come from authenticated sources `S_auth,t`? |
| 4 | **Data isolation**     | Does the information flow respect the permission graph `R`?        |

**Security predicate (combined).**

```
secure(a_t, C_t) ⇔
    o₀ ∈ O                                            -- task in allowed space
  ∧ H_Tr(Tr_{t-1}, o₀) = 1                            -- trajectory still aligned
  ∧ H_a(a_t, Tr_{t-1}, o₀) = 1                        -- this action serves o₀
  ∧ ∀ x ∈ x⃗, ∀ s ∈ L(x):
        s ∈ S_auth,t  ∨  H_a(a_t, Tr_{t-1}, o₀) = 1   -- source authorized
  ∧ ∀ destination s* of x: (L(x), s*) ∈ R             -- data isolation
```

Any single violation = the action is a security breach.

---

## 3. Oracle functions (what our defense agent must approximate)

The paper introduces five idealized oracles. Real systems approximate
them — but we should **name** them explicitly in our codebase so the
agent's checks are auditable.

| Oracle | Signature                                             | What it does                                                           |
|--------|--------------------------------------------------------|------------------------------------------------------------------------|
| `H_p`  | `prompt → objective`                                  | Extracts the task objective `o₀` from the user prompt.                 |
| `H_Tr` | `(trajectory, o₀) → {0,1}`                            | "Is the trajectory still aligned with `o₀`?"                           |
| `H_a`  | `(action, trajectory, o₀) → {0,1}`                    | "Does this action serve `o₀`?"                                         |
| `I`    | `(action, model, mem, prompt, trajectory) → inputs`   | **Instruction attribution** — which inputs caused this action?         |
| `L`    | `input → sources`                                     | **Source attribution** — provenance tracking.                          |

Practical approximations the paper acknowledges:
- `H_Tr`, `H_a` → an LLM-judge (a separate LLM call that scores 0/1).
- `I` → attention / influence functions (coarse).
- `L` → tag inputs at ingestion (we control the pipeline, so we can
  *label* every input with its origin).

For our pipeline this turns into a `SecurityGuard` module that wraps
every action call.

---

## 4. Attack catalogue, re-expressed in the framework

These are the attacks our **defense agent** must detect, and our **attack
agent** can be told to simulate:

| Attack                      | Which properties it violates                                                    |
|-----------------------------|---------------------------------------------------------------------------------|
| Indirect prompt injection   | Source authorization **AND** action alignment.                                  |
| Direct prompt injection     | Task alignment (user vs. system instruction hierarchy).                         |
| Jailbreaking                | Task alignment (`o₀ ∉ O`).                                                      |
| Confused deputy             | Source authorization — agent uses *its* permissions to act on user request the user couldn't make. |
| Task drift                  | Task alignment (trajectory drifted without authorization).                      |
| Agentic misalignment        | Source authorization + task alignment (agent invents its own objective).        |
| Capability misuse           | Action alignment (legit capability used for a task it shouldn't serve).         |
| Cross-context info leakage  | Data isolation (info flows across user/session boundaries).                     |
| Malicious tool exploitation | Task alignment (compromised tool falsifies observations).                       |
| Memory poisoning            | Source authorization at `t₂` because malicious data was written into memory at `t₁`. |

Notice how the *same* taxonomy fits both *what to detect* and *what to
simulate* — this is what makes the framework attractive to our
attack-and-defense project.

---

## 5. Defenses, re-expressed in the framework

Two families of defense — both we can implement:

**5.1 Prevention — strengthen the oracle approximations.**
- Better prompt engineering / instruction hierarchies.
- RLHF / DPO that improves `I` and the model's understanding of `O`.
- Policy specification (AgentSpec, GuardAgent, R²-Guard) — encode `R`
  and `O` declaratively. We do this with our `rules/` directory.
- Privilege separation / sandboxing — implicitly restrict `R`.

**5.2 Detection — implement property checks at runtime.**
- Input filtering (DataSentinel, PromptArmor) — limited because they
  detect *patterns*, not causal `I`.
- Tool-use alignment validation (TaskShield) — implements `H_a` check.
- Circuit breaking — flags `H_Tr = 0` (task drift).
- Output filtering (Llama Guard, LlavaGuard) — approximate `H_a`/`H_Tr`.
- Sandboxing — coarse `R` enforcement.
- Runtime monitoring (Pro²Guard) — multi-property checking.

**Empirical observation worth keeping:** in AgentDojo, the defenses
that most directly approximate `H_a` (PI detector, tool filter) reduce
targeted attack success rate by 86–88%, but at significant utility cost
(benign utility drops from 69% to 41.5%). → Accurate `H_a` is the
single most valuable thing we can add.

---

## 6. Open problems we should *not* claim to have solved

The paper is clear on what's still hard — these become future work in
`improvements_and_exploration.md`:

- Practical implementation of `I` (instruction attribution).
- Practical `H_Tr` / `H_a` that are robust to adversarial inputs.
- **Compositional security** — individually-OK actions becoming unsafe
  in combination.
- Dynamic / multi-actor environments — `Cₜ` evolves outside the
  agent's control.
- **Temporal** attacks (TOCTOU, memory poisoning across sessions).
- Realistic benchmarks that include explicit authorization context.
- Multi-agent **delegated authority** — when Agent A asks Agent B to
  do something, which properties must hold for the delegation itself?

---

## 7. How we use this in CyberLLM

The `CyberLLM/agents/security_guard.py` module implements a
lightweight version of the framework:

- Every input is tagged at ingestion with `source` and
  `trust_level` (`authenticated`, `external`, `tool`, `memory`).
- Every action carries a declared `objective` and a `parent input
  reference` ⇒ we can compute a coarse `I`.
- `SecurityGuard.check(action, context)` runs four checks
  corresponding to the four properties; an action only executes if all
  four pass.
- The audit log keeps every (action, context, verdict, reasoning)
  tuple — this is what a TARA assessor would ask for.

**Carry into CyberLLM:** four named property checks, source/trust
tagging, an LLM-judge for `H_a` / `H_Tr`, an explicit objective `o₀` on
every task.
