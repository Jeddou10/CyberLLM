# `tools/static_analyzer.py` — the deterministic detection core

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

This is the **static-first heart** of CyberLLM: a deterministic detector that
runs with no LLM. It supplies three things:

1. A **regex/heuristic floor** that always fires (so even the stub LLM yields
   real findings), derived from the `rules/*.yaml` knowledge base.
2. **Context for the LLM** — the static hits are injected into the scanner
   prompts so the model refines/explains real findings rather than inventing
   them (P3 RAG).
3. An optional **external AST layer** (bandit/semgrep) that catches structural
   issues regex misses, mapped onto our own rule-ids.

It is consumed by the three defense scanners (`source_code_scanner.py`,
`log_analyzer.py`, `deployment_scanner.py`) and the attack exploiters, and its
`merge_findings` is the dedup logic used everywhere two layers combine.

Three public entry points: `scan_code_static`, `scan_log_static`,
`scan_deployment_static`; plus the external layer (`scan_code_external`) and the
merge helpers.

---

## 2. Imports — lines 30–46

| line | import | why |
|------|--------|-----|
| 32 | `importlib.util` | Detect an importable bandit/semgrep *module* (for `python -m` fallback). |
| 33 | `json` | Parse bandit/semgrep JSON output. |
| 34 | `math` | Shannon entropy (DNS-exfil heuristic). |
| 35 | `re` | The regex floor + log heuristics. |
| 36 | `shutil` | `which()` to find analyzer binaries on PATH. |
| 37 | `subprocess` | Run bandit/semgrep (no `shell=True`, bounded timeout). |
| 38 | `sys` | `sys.executable` for the `python -m` fallback. |
| 39 | `tempfile` | Write code to a temp file so the analyzer sees realistic line numbers. |
| 40 | `Counter, defaultdict` | Entropy counts / grouping. |
| 41 | `dataclass` | The `StaticFinding` shape. |
| 42 | `datetime, timedelta` | Log timestamp parsing + burst windows. |
| 43 | `Path` | Paths. |
| 44 | `Iterable` | Typing for the converter. |
| 46 | `yaml` | Parse the deployment topology. |

---

## 3. Walkthrough

### `StaticFinding` — lines 54–62
A dataclass with **the same fields as the LLM scanner's `Finding`**
(`rule_id, severity, evidence, explanation, source_agent, asset_category,
line`) so the two layers merge seamlessly. `source_agent` defaults to
`"static_analyzer"` and is overwritten to `"bandit"`/`"semgrep"` for those
layers (provenance you can see in the UI).

### `_line_of(text, offset)` — lines 65–66
Convert a character offset into a 1-based line number by counting newlines
before it. Used so every code finding carries the exact line.

### `scan_code_static(code, filename, rules)` — lines 73–100  (the regex floor)
- **What:** apply every `code_rules[*].pattern` regex to the source.
- **Line by line:**
  - 77–80 — iterate rules; skip rules without a `pattern` (some rules are bandit-only or topology-only).
  - 86 — compile with `MULTILINE | IGNORECASE`. **Why IGNORECASE:** so the hard-coded-secret rule catches both `api_key` and `API_KEY`; a rule that genuinely needs case sensitivity can use an inline `(?-i:…)`.
  - 87–88 — a bad regex is skipped (`re.error`), never crashes the scan.
  - 89–99 — for each match, capture a ±20-char snippet (with newlines flattened), and build a `StaticFinding` whose evidence is `"<filename>: <snippet>"`, explanation is `title — rationale`, and `line` is computed from the match offset.

### Log heuristics — lines 107–253
Regex alone can't express "≥10 failures in <60 s"; these are **hand-coded
semantic detectors**, one per `LOG-*` rule, each guarded by
`if "<RULE-ID>" in by_id` so a detector only fires when that rule is loaded.
- `_TS_RE` / `_parse_ts` (107–117) — extract an ISO timestamp from a line (or `None`).
- `_shannon_entropy` (120–125) — character-distribution entropy, used to spot high-randomness DNS subdomains.
- **`scan_log_static` (128–253)** detectors:
  - **LOG-AUTH-03 (134–153):** collect timestamps of failed-password lines for root/admin; fire only if **≥10 within a 60 s window** (sort, compare the 10th to the 1st). This is the brute-force signature.
  - **LOG-NET-01 (155–169):** a broadcast (`.255`) line with `rate=… pkts/s ≥ 500`.
  - **LOG-CAN-02 (171–182):** an anomaly line mentioning a gateway-only CAN id (`0x7E…`) — a safety-critical CAN injection, defaulted to `critical` severity and the "Life and Bodily Health" asset.
  - **LOG-EXFIL-01 (184–203):** ≥5 DNS queries whose subdomains have **average entropy > 3.0** — a covert DNS channel.
  - **LOG-EXFIL-02 (204–216):** an outbound transfer with `bytes_out ≥ 10 MB`.
  - **LOG-LATERAL-01 (218–228):** internal port-scan signature.
  - **LOG-DDOS-01 (230–239):** ≥3 SYN-flood lines.
  - **LOG-PRIV-01 (241–251):** a `sudo` read of `/etc/shadow` or cloud IAM creds (critical).
  - Each appends a `StaticFinding` with evidence drawn from the offending line and `break`s after the first hit (one finding per rule per log is enough).

### Topology checks — lines 260–351
- `_actor_by_id` (260–261) — index actors by id for O(1) edge lookups.
- **`scan_deployment_static` (264–351):** parse the YAML (returns `[]` on a parse error, 269–270), then run **OCL-style graph checks (P3) over the actor/datasource graph (P2)**. The nested `fire(rule_id, evidence, **over)` helper (278–288) only emits a finding if that topology rule is loaded.
  - **TOP-001 (290–298):** an HPC→ZoneECU edge must use `ethernet` + `IEEE-1722`; otherwise it's an architecture violation.
  - **TOP-002 (300–307):** an **external** actor with a `write` edge into `…memory…` — the P2 "poison path."
  - **TOP-004 (309–316):** an external user/agent reaching an `admin` surface with no WAF.
  - **TOP-005 (318–321):** a `Database` bound to `0.0.0.0` (exposed).
  - **TOP-006 (323–327):** a world-readable secret store (forced `critical`).
  - **TOP-007 (329–336):** a safety/brake ECU commanded by a non-safety source (a safety-integrity violation).
  - **TOP-008 (338–349):** an external A2A agent (or any external actor) with a `respond` edge into an in-vehicle agent — the P2 "trigger path."

### `merge_findings(static, llm_findings)` — lines 358–390
- **What:** combine the deterministic layer with the LLM's, **dropping LLM duplicates**. Static wins because it's precise.
- **Why this exact logic (a deliberate fix):** an LLM restating a known issue should not double-report. An LLM finding is dropped when it matches a static one by `(rule_id, line)`, by `(rule_id, evidence-prefix)`, **or** when it has the same `rule_id` but **no line** (the deterministic layer already covers that rule and the LLM added no new locus). An LLM finding on a *different* line is kept — that's genuinely new signal. The three `seen_*` sets (line/evidence/rule-id) implement exactly this.

### `merge_static_layers(primary, extra)` — lines 393–407
Combine **two static layers** (regex floor = `primary`, bandit/semgrep =
`extra`). The regex floor wins: an `extra` finding is added only if its
`(rule_id, line)` isn't already present. **Why:** keep the structural issues
bandit catches that regex missed, without double-reporting the same line.

### External AST layer — lines 410–503
- `_BANDIT_TO_RULE` (423–434) — map bandit test-ids onto our `CODE-*` rule-ids so a bandit hit inherits our title/severity/asset. E.g. `B602/B603/…` (shell) → `CODE-001`; `B608` (SQL) → `CODE-012`; `B105/B106/B107` (hard-coded password) → `CODE-003`. Unmapped ids become `BANDIT-<id>`.
- `_BANDIT_SEV` / `_SEMGREP_SEV` (436–437) — normalize each tool's severity vocabulary onto ours.
- `_rule_index` (440–446) — `{rule_id: rule}` for title lookups.
- `bandit_results_to_findings` (449–...) — **pure mapping** from bandit JSON to `StaticFinding[]` (no subprocess, so it's unit-testable on synthetic data). It prefers our rule's severity when the id is mapped, else bandit's; carries the snippet as evidence; tags `source_agent="bandit"`.
- `semgrep_results_to_findings` — the analogous mapping for semgrep.
- `_analyzer_cmd(name)` — **the PATH-vs-module resolver:** prefer the binary on PATH; else fall back to `[sys.executable, "-m", name]` if the module is importable; else `None`. This is why bandit installed with `pip install --user` (no PATH shim) still works.
- `external_static_available(suffix)` — whether a real analyzer can run for that file type (used by the server's health endpoint).
- `scan_code_external(code, filename, rules, timeout)` — write the code to a temp file named like the original (so line numbers match), run bandit for `.py` else semgrep, parse JSON, map to findings. **Always graceful:** any error or missing backend returns `[]` and the regex floor stands. No `shell=True`; bounded timeout; temp dir cleaned in `finally`.

### `staticfinding_to_finding(static_findings, finding_cls)` — lines 506–520
Convert `StaticFinding` → the agents' `Finding` dataclass (same fields), so the
rest of the pipeline consumes one uniform type.

---

## 4. Edge cases, gotchas & design decisions

- **High recall, then high precision.** The regex floor is intentionally broad (catch everything plausible); bandit/semgrep add structure; the LLM refines. Merging with "deterministic wins" keeps precision without losing recall.
- **Every detector is guarded by rule presence.** A `LOG-*`/`TOP-*` detector only fires if that rule is loaded, so you can disable a rule by removing it from YAML — no code change.
- **The dedup fix is subtle but important.** `merge_findings` had been keyed on evidence text, which let the LLM duplicate a bandit/regex hit. Keying on `(rule_id, line)` with a line-less rule-id fallback fixed the "same vuln shown three times" bug.
- **External layer is best-effort.** It never throws into the pipeline — missing binary, bad JSON, or timeout all degrade to `[]`.
- **bandit id mapping keeps traceability.** Because bandit hits inherit our `CODE-*` ids, a finding's rule_id always points back to a documented rule, whether it came from regex, bandit, or the LLM.
- **No code is ever executed.** Even the external analyzers are *static* (AST/data-flow); the code under test never runs.
