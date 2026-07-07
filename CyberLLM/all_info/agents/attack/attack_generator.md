# `agents/attack/attack_generator.py` — produce PoC scripts (template + LLM fallback)

`[← back to all_info index](../../README.md)`

---

## 1. Purpose & place in the system

The attack-side mirror of the `ActionGenerator`. Given an `AttackPlan`, it emits
one **attack script** per chosen finding. Scripts are returned as text and are
**never executed** by this module — execution belongs to a separate runner the
`EthicsGuard` authorizes. It ships built-in **templates** for the common exploit
classes so the pipeline produces something useful even with the stub LLM, and
falls back to an LLM-authored script for anything without a template.

## 2. Imports
`textwrap`, `dataclass`; `BaseAgent`/`Finding`; `AttackPlan` from the
orchestrator.

## 3. Walkthrough

### `AttackScript` — lines 30–37
`rule_id`, `title`, `language` (python/shell/http/payload), `body`, `target_hint`,
`expected_effect`.

### `_TEMPLATES` — lines 40–140
A dict mapping rule-id → a **benign canary** proof-of-concept. The key design
choice: every template demonstrates the vulnerability *without real damage* (e.g.
writing to `/tmp/atk_canary`, using placeholder `<TARGET>`/`<ENDPOINT>` hosts).
Coverage spans shell-injection, pickle/eval RCE, path traversal, SQL-injection,
JWT `alg=none`, the P2 memory-poison and A2A payloads, and a CAN-injection frame
for the automotive case. These exist so a stub-LLM run still yields concrete,
safe PoCs.

### `AttackGeneratorAgent.FREEFORM_PROMPT` — lines 144–153
The fallback prompt: author a short runnable PoC using placeholder hosts, **no
destructive payloads — a benign canary is enough**, return only the body.

### `generate(plan)` / `_for_finding(f, plan)` — lines 155–185
`generate` emits one script per chosen finding. `_for_finding` (161–185) uses the
template if one exists for the rule-id; otherwise it fills the freeform prompt and
asks the LLM for a benign PoC, wrapping the result as an `AttackScript`.

## 4. Edge cases, gotchas & design decisions
- **Benign canaries only.** Both the templates and the LLM prompt are constrained
  to non-destructive demonstrations (touch a canary file, placeholder hosts).
  Anything that slips through is caught by the `EthicsGuard`'s
  `filter_scripts`/`_DESTRUCTIVE_RE`.
- **Templates first, LLM second.** Templates make common cases deterministic and
  safe under the stub; the LLM fallback only handles rule-ids without a template.
- **Never executes.** This module *writes* scripts; running them is a separate,
  authorization-gated concern — keeping generation and execution apart is a core
  safety boundary.
- **Automotive-aware.** The `LOG-CAN-02` template emits a `cansend` frame and the
  `TOP-008` payload targets an in-car agent — reflecting the SDV threat model.
