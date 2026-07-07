# `rules/*.yaml` — the detection-rule knowledge base

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

The `rules/` directory holds the **detection knowledge base** — the data that
drives both the deterministic scanners *and* the LLM prompts (P3 rules-as-context).
`pipeline.load_rules()` reads every `*.yaml` in this directory and **merges them by
family** into one dict, so rules can be split across files. The shipped files:

- `example_rules.yaml` — the core code/log/topology rules.
- `extended_rules.yaml` — additional rules (more `CODE-*`, etc.).
- `attack_rules.yaml` — the `attack_rules` family used by the exploiters.

A rule is just data — adding or disabling detection is a YAML edit, no code change.

---

## 2. The rule families

| family | consumed by | drives |
|--------|-------------|--------|
| `code_rules` | `scan_code_static` + the code scanner/exploiter prompts | regex patterns over source |
| `log_rules` | `scan_log_static` + the log analyzer prompt | log anomaly signatures |
| `topology_rules` | `scan_deployment_static` + the deployment scanner prompt | actor/edge graph constraints |
| `attack_rules` | the attack exploiter prompts | offensive framing of the above |

---

## 3. The rule schema (by example)

A `code_rules` entry (from `example_rules.yaml`):

```yaml
- id: CODE-001
  severity: high
  title: "Command injection sink"
  pattern: "subprocess\\.(call|run|Popen)\\(.+shell\\s*=\\s*True"
  asset_category: "Material and Economic Resources"
  rationale: "Shell execution of untrusted strings is a direct RCE."
```

| field | meaning | used where |
|-------|---------|-----------|
| `id` | the stable rule id (`CODE-*`/`LOG-*`/`TOP-*`) every finding carries | everywhere; the join key for dedup, memory, evaluation |
| `severity` | low/medium/high/critical | drives playbook gating + decision tier |
| `title` | the human title shown in a finding | `_enrich_finding` |
| `pattern` | (code rules) the regex `scan_code_static` compiles | the regex floor |
| `signature` | (log/topology rules) a human description of the heuristic | the prompt; the actual detector is hand-coded in `static_analyzer.py` |
| `asset_category` | the P2 human-centric asset at risk | finding enrichment + decision tagging |
| `rationale` | the "why" injected into prompts (P3) | `rules_snippet` |

Notes on specific entries:
- `CODE-003` (hard-coded secret) — its regex (line 37 of `example_rules.yaml`) is
  carefully built: `\w*` after the keyword tolerates suffixes like `_ID`/
  `_ACCESS_KEY`, the value class includes `/` and `+` so base64-ish AWS secrets
  match, and a 16-char minimum avoids matching short literals. It's compiled
  `IGNORECASE` so `API_KEY` and `api_key` both hit.
- `LOG-*` / `TOP-*` entries carry a `signature` (a description) rather than a
  `pattern`, because their detectors are *semantic* (burst windows, entropy, graph
  reachability) and live in `scan_log_static` / `scan_deployment_static`. The YAML
  entry supplies the id/severity/title/asset and the prompt text; the code
  supplies the logic.

---

## 4. Edge cases, gotchas & design decisions

- **Rules are merged across files by family.** Putting a new `CODE-*` rule in any
  `*.yaml` under `rules/` automatically extends `code_rules` — load order is
  sorted for determinism.
- **A rule with no `pattern` simply isn't matched by the regex floor.** Such rules
  (log/topology) rely on the hand-coded detectors, which are themselves guarded by
  `if "<RULE-ID>" in by_id` — so removing the YAML entry disables the detector.
- **`id` is the universal join key.** Findings, the bandit→rule map
  (`_BANDIT_TO_RULE`), memory recall (Jaccard over rule-id sets), and the
  evaluation labels all key on it — keep ids stable.
- **Rationale feeds the LLM (P3).** `rules_snippet` renders `id [severity]: title —
  rationale` into the scanner prompts, so the model references real rules instead
  of inventing them.
- **`attack_rules` reuses the same shape** but frames detections offensively; the
  exploiters inject it via `attack_rules_snippet`.
