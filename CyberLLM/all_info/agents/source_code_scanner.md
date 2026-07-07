# `agents/source_code_scanner.py` — three-layer source-code detection

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

The first defense scanner. It detects vulnerabilities in **source code without
executing it** by combining three layers: a deterministic regex **floor**, an
**external AST layer** (bandit/semgrep), and an optional **LLM refinement** pass —
then merges them (deterministic layers win on duplicates). It's run as step [1/6]
of `run_defense_pipeline` and returns an `AgentResult` of `Finding`s. Uses
`tools/static_analyzer.py` for all three layers.

---

## 2. Imports (key ones)
`BaseAgent`/`Finding`/`Input` (the agent template + shapes); from
`tools.static_analyzer`: `scan_code_static` (regex floor), `scan_code_external`
(bandit/semgrep), `merge_static_layers`, `merge_findings`,
`staticfinding_to_finding`; plus `os` (read the `CYBERLLM_NO_EXTERNAL_STATIC`
kill-switch).

---

## 3. Walkthrough — `run(inputs)` (the core)

The method (lines ~38–103) walks every code input and builds findings in three
layers:

- **Gates (44–55):**
  - `external_on` (49–50) = config `external_static` **and** the
    `CYBERLLM_NO_EXTERNAL_STATIC` env var is **not** set. The kill-switch is how
    the test suite keeps results deterministic regardless of whether bandit is
    installed.
  - `use_llm` (55) = config `use_llm` (default True). The web UI's Fast mode sets
    this False so the offline stub's canned findings never appear on real code.
- **Per file (60–96):**
  1. **Regex floor (61–66):** `scan_code_static` → `Finding`s tagged with this agent.
  2. **External AST layer (67–75):** if `external_on`, run `scan_code_external`
     (bandit for `.py`, else semgrep) and `merge_static_layers` — regex wins on
     the same `(rule_id, line)`, so structural hits bandit catches that regex
     missed are added without double-reporting. The bandit/semgrep findings keep
     their tool name as `source_agent`.
  3. **LLM pass (78–92):** only if `use_llm`. It feeds the static layer to the
     model as context (P3 RAG) and asks it to refine/extend (not duplicate). When
     disabled, `llm_findings = []` and `raw_text` is a "disabled" note (this is
     the fix that avoided an `UnboundLocalError` on the `resp` variable).
  4. **Merge (94–96):** `merge_findings(static_layer, llm_findings)` — the static
     layer wins on dedup; LLM findings on genuinely new loci are kept.
- **Return (98–103):** an `AgentResult` with all findings and the joined raw LLM
  text. `self.last_static_findings` is populated for the run logger.

---

## 4. Edge cases, gotchas & design decisions

- **High recall → high precision.** Regex catches everything plausible; bandit
  adds structure; the LLM refines. Merging "deterministic wins" keeps precision.
- **Two independent off-switches.** `external_on` (AST layer) and `use_llm` (LLM
  pass) are separate, so you can run regex-only, regex+bandit, or all three.
- **The `use_llm=False` correctness fix.** On *arbitrary real* code the stub's
  canned findings are wrong, so the web UI disables the LLM pass unless a real
  model is configured — and the scanner returns a clean "disabled" raw-text note
  instead of referencing an unbound `resp`.
- **bandit hits inherit our rule-ids.** Via `_BANDIT_TO_RULE`, so every finding's
  `rule_id` traces back to a documented rule regardless of which layer found it.
- **Never executes code.** All three layers are static (text/AST/LLM-reasoning).
