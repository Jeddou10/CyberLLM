# `agents/log_analyzer.py` — log anomaly detection (static + LLM)

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

The second defense scanner (step [2/6]). It reads log lines and classifies
anomalies (reconnaissance, brute force, lateral movement, exfiltration, CAN
injection) using the same two-stage pattern: a deterministic heuristic pass over
the `LOG-*` rules, then an optional LLM refinement, merged. Run by
`run_defense_pipeline`; uses `scan_log_static` + `merge_findings` from
`tools/static_analyzer.py`.

---

## 2. Imports
`BaseAgent`/`AgentResult`/`Finding`/`Input`; from `tools.static_analyzer`:
`merge_findings`, `scan_log_static`, `staticfinding_to_finding`.

---

## 3. Walkthrough — `run(inputs)` (lines ~34–73)

1. **Select log inputs (35–38):** keep inputs whose source ends in `.log`/`.txt`;
   if none, return an empty result early.
2. **Join + static pass (40–48):** concatenate the log content, run
   `scan_log_static` (the hand-coded `LOG-*` detectors — burst windows, entropy,
   etc.), convert to `Finding`s tagged with this agent, and store them in
   `last_static_findings` for the run logger.
3. **LLM pass (50–64):** **gated by `self.cfg.get("use_llm", True)`.** When on, it
   feeds the static findings to the model as context and asks it to
   refine/extend; `raw_text = resp.text`. When off, `llm_findings = []` and
   `raw_text` is a "disabled" note. The comment is explicit: disabling avoids the
   stub's canned anomalies polluting real logs.
4. **Merge (66–73):** `merge_findings(static, llm)` and return an `AgentResult`
   with the joined raw text.

---

## 4. Edge cases, gotchas & design decisions

- **`use_llm` gate + the `raw_text` fix.** Same correctness fix as the code
  scanner: when the LLM pass is disabled, the method must not reference the unset
  `resp` — it sets `raw_text` to a disabled note. The web UI disables this pass on
  a code-only scan (no log supplied) so the model can't invent a critical
  CAN-injection from an empty/clean log.
- **Static detectors are semantic, not regex-only.** Brute-force ("≥10 fails in
  <60 s"), DNS-exfil (entropy), and SYN-flood detectors live in
  `scan_log_static` — things a bare regex can't express.
- **Empty input → empty result.** No log lines means no findings, cleanly.
- **CAN awareness.** `LOG-CAN-02` flags gateway-only CAN ids from non-gateway
  ECUs as `critical` / "Life and Bodily Health" — the automotive safety angle.
