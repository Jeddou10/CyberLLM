# `tools/log.py` — the verbosity-aware console (`Console`)

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

`Console` is the human-facing progress/diagnostics channel. Its central design
rule is **two strictly separated streams**:

- **stdout** is reserved for *results* (the batch summary tables and the
  single-run record JSON), so `python pipeline.py … > out.json` yields a clean,
  machine-readable file.
- **stderr** (everything `Console` prints) carries human chatter, so it never
  corrupts the result on stdout.

`pipeline.py` creates one `Console` per run and calls its methods to narrate the
pipeline. Two dials control how much it says: `verbose` (default on — section
headers, per-step counts, verdicts) and `debug` (`-v` — timings, token
estimates, static-vs-LLM splits, and truncated previews of every prompt and LLM
response).

---

## 2. Imports — lines 21–25

| line | import | why |
|------|--------|-----|
| 23 | `sys` | Default to `sys.stderr`. |
| 24 | `time` | `perf_counter` for the `timed` context manager. |
| 25 | `contextmanager` | Make `timed` a `with`-block. |

---

## 3. Walkthrough

### `class Console.__init__` — lines 29–32
Stores `verbose`, `debug_on`, and the output `stream` (defaulting to
`sys.stderr`). Letting `stream` be injected makes `Console` testable (point it
at a `StringIO`).

### `_w(s)` — lines 35–36
The single low-level writer: `print(..., file=self.stream, flush=True)`. The
`flush=True` matters so progress appears live during a long LLM call instead of
being buffered until the end.

### Info channel (gated by `verbose`) — lines 39–59
- `section(title)` (39–41) — a `====== TITLE ======` banner.
- `info(msg)` (43–45) — a plain line.
- `step(msg)` (47–49) — an indented `  - …` sub-step.
- `kv(label, value)` (51–53) — an aligned `label : value` pair.
- `warn(msg)` (55–59) — a `[!] …` line for refusals/violations. **Design note:** warnings show at *normal* verbosity (so a default run surfaces a guard refusal) but are silenced by `-q`.

### Debug channel (gated by `debug`) — lines 62–75
- `detail(msg)` (62–64) — a deeply-indented `. …` line (timings, token counts).
- `blob(label, text, limit=1000)` (66–75) — preview a long string (a prompt or LLM response), clipped to `limit` chars with a `…[+N more chars]` marker, each line prefixed with `| `. This is the "what did gpt-4o actually say?" view — invaluable when debugging prompts.

### `timed(label)` — lines 77–85
A context manager that times the wrapped block and reports the elapsed
milliseconds via `detail` (so it only shows in debug). Used around each agent
call (`with con.timed("round 1 decision"): …`). The `finally` guarantees the
timing is reported even if the block raises.

---

## 4. Edge cases, gotchas & design decisions

- **stdout vs stderr is the key invariant.** Results go to stdout; chatter to stderr. Break it and piping the JSON output breaks.
- **`flush=True` everywhere** keeps the progress live for long-running LLM calls.
- **Verbosity is two independent booleans,** mapped from the CLI as `verbose = not -q` and `debug = -v` (see `pipeline.main`). So `-q` is quietest, default is mid, `-v` is loudest.
- **`timed` reports via `detail`,** so timings are debug-only — they don't clutter a normal run.
