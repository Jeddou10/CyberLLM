# `run_logger.py` — the per-run, step-by-step trace writer

`[← back to all_info index](README.md)`

---

## 1. Purpose & place in the system

`RunLogger` produces a **forensic record of a single pipeline run**. For each
defense or attack run, it creates a fresh directory
`run_logs/<timestamp>_<mode>_<scenario>/` and fills it with numbered JSON/text
files (inputs, every prompt + raw response, static findings, the decision, the
action plan, guard verdicts, attack scripts), plus two human-friendly roll-ups:
`_trace.log` (one line per event, easy to `tail`) and `_summary.md` (a readable
walkthrough). It is created and driven by `pipeline.py` (`rlog = RunLogger(...)`,
then `rlog.log_*` calls throughout the pipeline, then `rlog.finalize()`).

It writes only; it never affects pipeline logic — so it's safe to be verbose.

---

## 2. Imports — lines 42–47

| line | import | why |
|------|--------|-----|
| 42 | `json` | Serialize every artifact. |
| 43 | `re` | Sanitize names for the filesystem. |
| 44 | `asdict, is_dataclass` | Convert agent dataclasses (findings, verdicts) to plain dicts generically. |
| 45 | `datetime` | Timestamps for the dir name, trace lines, duration. |
| 46 | `Path` | Filesystem paths. |
| 47 | `Any` | Loose typing for the generic JSON-coercer. |

---

## 3. Walkthrough

### `_safe(name)` — lines 50–54
Replace any non-`[A-Za-z0-9._-]` run with `-`, cap at 60 chars, default to
`"run"`. **Why:** scenario names and rule ids become parts of filenames; this
prevents path-traversal/illegal-char bugs and over-long names.

### `_to_jsonable(obj)` — lines 57–66
Recursively coerce anything into JSON-serializable form: dataclasses → `asdict`
(58–59), lists/tuples → recursed lists, dicts → recursed dicts with string keys,
`Path` → string, everything else unchanged. **Why:** the logger receives a zoo
of dataclasses; this one function means every `log_*` method can just hand its
object over without bespoke serialization. (The `not isinstance(obj, type)`
guard at 58 avoids treating a dataclass *class* as an *instance*.)

### `class RunLogger.__init__` — lines 72–84
- 75–77 — record the start time and build the dir name `YYYYmmddTHHMMSS_mode_scenario` (both name parts `_safe`-d).
- 78 — `mkdir(parents=True, exist_ok=True)` — create it immediately.
- 79–84 — initialize the step counter (`_step`), the in-memory `_trace_lines` and `_summary_blocks` buffers (flushed at `finalize`), the scripts sub-dir, and the `_meta` dict.

### The public `log_*` API
Each method writes a numbered JSON file, appends a one-line `trace`, and appends
a Markdown block to the summary. They all follow the same shape, so I'll
describe what each captures rather than repeat the mechanics:

- **`log_meta` (90–99)** — run metadata + the summary's title block. Also emits the `=== START ... ===` trace marker.
- **`log_inputs` (101–119)** — every `Input` with its `source`, `trust_level`, length, and a 300-char preview. Provenance is first-class evidence, so it's logged prominently.
- **`log_static` (121–132)** — the deterministic static-analyzer findings *per scanner* (the trusted floor), with a de-duplicated rule-id preview.
- **`log_agent` (134–162)** — the exact prompt (`..._prompt.txt`), the raw LLM response (`..._response.txt`), and the merged findings JSON. This is your window into *what the model actually saw and said*.
- **`log_decision` (164–188)** — the defense `DecisionAgent` output: tier, confidence, asset categories, justification, and the finding rule-ids it reasoned over.
- **`log_action` (190–205)** — the action proposal: kind, target, parameters, rationale.
- **`log_action_plan` (207–241)** — the typed `ActionPlan` and its `ActionReport` (to_dict), plus the MCP audit log if reachable on the registry (213–217). The summary lists each step's tool, kind, and final status, and the plan's *blast radius* and outcome counts (completed/failed/refused/rolled-back/skipped).
- **`log_guard` (243–256)** — the `SecurityGuard` verdict broken out into P1's four properties (task/action alignment, source authorization, data isolation) plus the human reason.
- **`log_system_instance` (260–279)** — attack: the discovered actor/datasource/edge graph, with external and safety actors called out.
- **`log_plan` (281–307)** — attack: the orchestrator's chosen target asset, exploit chain, poison/trigger paths (P2), confidence, justification.
- **`log_ethics` (309–321)** — attack: the `EthicsGuard` verdict (scope/target/non-destructive).
- **`log_attack_scripts` (323–348)** — attack: writes each generated script to `scripts/NN_rule_title.ext` with a provenance header, and notes any redacted (destructive) scripts. The `ext_map` (325–326) picks a sensible extension per language.

### `finalize()` — lines 354–367
- 355–358 — stamp `ended_at` and `duration_seconds` into meta and rewrite `00_meta.json`.
- 360–363 — flush the buffered `_trace.log` and `_summary.md` to disk in one write each (cheap, atomic-ish).
- 366–367 — write `_latest_<mode>.txt` pointing at this run's dir name — so "show me the latest defense run" is a one-liner.

### Internals — lines 373–385
- `trace(msg)` (373–375) — append a millisecond-timestamped line to the in-memory buffer.
- `_next()` (377–379) — bump and zero-pad the step counter (`01`, `02`, …) so files sort in execution order.
- `_write_json(name, obj)` (381–385) — coerce with `_to_jsonable`, dump with `indent=2` and `default=str` (so anything still unserializable becomes its string form rather than crashing the write).

---

## 4. Edge cases, gotchas & design decisions

- **Why `run_logs/` and not `logging/`?** (docstring 32–37) Python has a stdlib `logging` module; a top-level `logging/` package can shadow it in some import edge cases. `run_logs/` sidesteps that entirely.
- **One directory per run** makes successive runs trivial to diff and grep without losing structure.
- **The logger is write-only and defensive.** `default=str` in `_write_json` and `getattr(..., default)` everywhere mean a malformed object degrades the *log*, never the *run*.
- **Numbered prefixes encode order.** Because `_next()` is monotonic, the on-disk file order matches the pipeline's execution order — you can read a run top-to-bottom.
- **`_summary.md` first, JSON for drill-down.** The intended workflow: skim the Markdown summary, then open the specific numbered artifact when you need the raw prompt/response/findings.
- **It is reused by tests.** Because `pipeline.RUN_LOGS_DIR` is redirected to a temp dir in tests and the web server, these artifacts don't pollute the repo during automated runs.
