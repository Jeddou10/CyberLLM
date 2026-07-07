# `agents/base_agent.py` — the schema-driven agent template (P4)

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

This file is the **base class every agent extends** and the home of the core
shared data shapes. It implements the Härer (P4) schema: an agent owns an LLM
client, a `data` dict the prompt template draws from, and an `objective` string
the security guard checks against. It also defines `Input` (with **mandatory
provenance**, P1), `Finding`, and `AgentResult`. Imported by every scanner,
exploiter, the decision agent, and the action generator.

---

## 2. Imports — lines 11–18

| line | import | why |
|------|--------|-----|
| 12 | `dataclass, field` | The `Finding`/`Input`/`AgentResult` shapes. |
| 13 | `Any` | The `data` dict's value type. |
| 14–15 | `json, re` | Parse LLM JSON; template substitution. |
| 17 | `LLMClient, LLMResponse` | The provider seam. |
| 18 | `TokenBudget` | Per-agent prompt-size accounting (P3 / A.4). |

---

## 3. Walkthrough

### `ALLOWED_TRUST_LEVELS` + `ProvenanceError` — lines 24–28
The fixed provenance lattice `{authenticated, external, tool, memory}` (P1 §4.2)
and the error raised when an input lacks a valid tag. **Why mandatory:** the
guard's source-authorization property is only enforceable if *every* input is
attributed at ingestion — so the type system refuses an un-tagged input.

### `Finding` — lines 31–39
The internal finding shape: `rule_id, severity, evidence, explanation,
source_agent`, plus `asset_category` (set later by the decision agent, P2) and an
optional `line`. The same fields as `StaticFinding`, so the static and LLM layers
merge cleanly.

### `Input` — lines 42–64
Content + `source` + `trust_level`. The `__post_init__` (57–64) **enforces
provenance**: a non-empty source and a `trust_level` in the lattice, raising
`ProvenanceError` otherwise. This is the gate that makes P1 reasoning possible.

### `AgentResult` — lines 67–72
What a scanner returns: `agent_id`, `objective`, the `findings`, and the raw LLM
text (for the run logger).

### `class BaseAgent` — lines 75–168
- **`__init__` (76–100):** stores id/cfg/llm/objective and an empty `data` dict. It also sets up:
  - **delegation state (83–88):** `trusted_sources` (sources this agent treats as authenticated) and `delegated_from`. A delegated child does **not** inherit the parent's trusted sources (see `delegate`).
  - **token budget (90–93):** a `TokenBudget` for prompt-size warnings.
  - **debug hooks (95–100):** `last_prompt`, `last_response`, `last_static_findings` — read by the run logger after each `run()`.
- **`call_llm(prompt)` (103–112):** the **single LLM entry point**. It records the prompt, accounts it against the token budget, calls `self.llm.complete`, records the response, and returns it. Centralizing this is why the run logger can always capture exactly what each agent sent and received.
- **`delegate(...)` (115–134):** spawn a child agent that **inherits the objective but not the authority** (P1 §7). The child starts with an *empty* trusted-source set and only the sources explicitly granted (133). **Why:** otherwise an external instruction the parent may *read* could be laundered into a privileged action by a child — this prevents that scope-widening attack.
- **`template(prompt)` (136–143):** substitute `[key]` placeholders with `self.data[key]` (P4 templating). The regex allows alphanumerics plus `_/-` in keys.
- **`_parse_findings(text)` (145–164):** robustly read a `{"findings": [...]}` JSON object, **tolerating markdown code fences** (148) and returning `[]` on a parse error. Each item becomes a `Finding` tagged with this agent's id.
- **`run(inputs)` (167–168):** abstract — subclasses implement it.

---

## 4. Edge cases, gotchas & design decisions

- **Provenance is enforced at construction, not checked later.** You literally cannot build an un-attributed `Input`, so the guard can always rely on the tag existing.
- **Delegation drops authority by default.** This is a deliberate P1 security property: a child agent must be *granted* trust, never inherit it — defeating instruction-laundering.
- **One LLM choke-point (`call_llm`).** Token accounting and run-logging both hang off this single method, so every model interaction is uniformly budgeted and logged.
- **Fence-tolerant JSON parsing.** Real models wrap JSON in ```` ```json ````; `_parse_findings` strips that, and a malformed response degrades to "no findings" rather than crashing the scan.
- **`Finding` mirrors `StaticFinding`.** The two detection layers were intentionally given the same fields so `merge_findings` can treat them uniformly.
