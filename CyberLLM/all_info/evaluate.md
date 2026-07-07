# `evaluate.py` — the static evaluation harness (recall / FP / scoreboard)

`[← back to all_info index](README.md)`

---

## 1. Purpose & place in the system

`evaluate.py` scores the **deterministic static analyzer** against the labelled
corpus in `examples/labels.yaml`, *without running any target*. It produces four
artifacts aligned with the roadmap: per-scenario **detection rate (recall)**,
**false-positive rate** (measured only on clean negative controls), a **P1
property-violation table**, and a **P2 asset × scenario × P5 tier scoreboard**.
It writes `memory/eval_report.md` and prints a summary; `--strict` exits non-zero
if recall < 1 or any false positive appears.

It's a standalone CLI; it imports the pipeline's loaders, the static scanners, and
the skills catalogue.

## 2. Imports — lines 32–47
`argparse`, `sys`, `yaml`; from `pipeline`: `HERE`, `_collect_code_files`,
`_norm`, `load_config`, `load_rules`; `DEFENSE_SKILLS`; the three static scanners.
Lines 43–47 reconfigure stdout to UTF-8 (same Windows-glyph reason as the
pipeline).

## 3. Walkthrough

### Mapping tables — lines 57–106
- `_PROPERTY_BY_RULE` (57–73) + `property_for` (76–83) — map each rule to the P1
  property it most directly implicates (documented as an approximation, since P1
  says the oracles are open problems). Code/injection rules default to
  `action_alignment`.
- `_ASSET_FALLBACK` (89–106) — a P2 asset category for rules whose YAML lacks one,
  so the tables are never "(unmapped)".

### Helpers — lines 108–140
`asset_for` (resolve a finding's asset), `tier_for_severity` (P5 tier from
severity), `skills_for_tier` (which defense skills would fire), and a local
`_rule_index`.

### `scan_scenario(scn, rules)` — lines 142–171
Run the appropriate static scanner(s) over one labelled scenario's code/log/
deployment and return its findings — the static-only detection for that scenario.

### `evaluate(cfg, rules, labels)` — lines 172–266
The core: for each labelled scenario, compute recall against the **must-have**
rule ids (recall, not precision — the labels are must-have, not exhaustive), and
on the clean negative controls compute false positives (ground truth = zero
findings, so any hit is a true FP). It assembles the property-violation table and
the asset/tier/skill scoreboard.

### `render_markdown` / `_print_summary` / `main` — lines 268–...
`render_markdown` builds `eval_report.md`; `_print_summary` prints the headline
numbers; `main` (338–...) parses `--strict`, runs the evaluation, writes the
report, and sets the exit code.

## 4. Edge cases, gotchas & design decisions
- **Recall, measured against must-have labels.** The label set is deliberately
  not exhaustive, so the metric is recall (did we catch the must-haves?), and FP
  is measured only where ground truth is genuinely "zero."
- **MTTD is N/A by design.** Mean-time-to-detect is a *dynamic* metric; a static
  analyzer has no runtime, so the harness reports static coverage instead.
- **Property/asset mappings are explicit approximations.** They're in plain tables
  the supervisor can audit, with the caveat that P1's oracles are open problems.
- **`--strict` is CI-friendly.** It turns "recall < 1 or any FP" into a non-zero
  exit, so the corpus can gate a build.
