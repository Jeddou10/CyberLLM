# `run_blind_tests.py` — spot-check the pipeline on "blind" examples

`[← back to all_info index](README.md)`

---

## 1. Purpose & place in the system

A small script-style harness that runs the **defense pipeline** over every file in
`examples/test_blind/` and collects the **code findings**, then prints a table.
"Blind" means these examples aren't part of the labelled corpus — it's a quick way
to eyeball how the scanner behaves on fresh code.

## 2. Imports — lines 2–6
`json`, `os`, `pathlib`, `subprocess`, `sys` — it shells out to the pipeline
rather than importing it.

## 3. Walkthrough
- 8–11 — find every `.py`/`.c` file under `examples/test_blind/`.
- 13–31 — for each file, run `python pipeline.py --mode defense --code <file>` as a subprocess, then read back `memory/last_run_defense.json` and keep only findings whose `source_agent == "source_code_scanner"`. Errors are caught and recorded as an empty result.
- 33–46 — print a table: per file, the count and rule-ids, then each finding's rule_id, severity, line, and a 60-char explanation excerpt.

## 4. Edge cases, gotchas & design decisions
- **Subprocess, not import.** Running the pipeline as a child process exercises
  the real CLI path and reads the same `memory/last_run_defense.json` artifact a
  user would — a true end-to-end spot-check.
- **Code findings only.** It filters to `source_code_scanner` findings because
  blind tests are about code detection; log/topology defaults aren't the focus.
- **Best-effort.** A failed run becomes an empty result with an error line, so one
  bad file doesn't stop the sweep.
- **Inherits the ambient environment** (`env={**os.environ}`), so whichever
  provider/kill-switches you've set apply to the child runs.
