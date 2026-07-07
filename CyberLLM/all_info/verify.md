# `verify.py` — the 30-second offline smoke check

`[← back to all_info index](README.md)`

---

## 1. Purpose & place in the system

`verify.py` is a fast, **pytest-free** sanity check you run right after install to
confirm the project is wired up. It exits 0 on success, non-zero with a clear
message otherwise. It's an **offline plumbing test** — it forces the deterministic
stub and dry-run, so it checks *wiring*, not LLM quality or real tool execution.

## 2. Imports & env — lines 18–36
`os`, `sys`, `traceback`, `Path`. It inserts the project dir on `sys.path` (27),
then **sets the three kill-switches** via `setdefault` (34–36):
`CYBERLLM_FORCE_STUB`, `CYBERLLM_FORCE_DRY_RUN`, `CYBERLLM_NO_EXTERNAL_STATIC`.
Using `setdefault` means you can override any of them to exercise the real
model/tools instead.

## 3. Walkthrough

### The `@step` registry — lines 39–47
A tiny decorator that appends each check `(title, fn)` to `CHECKS`, so `main` can
run them in order and report per-check status.

### The checks — lines 53–151
1. **`_imports` (53–67):** every core module + all defense/attack agents import cleanly.
2. **`_rules` (70–76):** the rule catalogue loads and contains all four families.
3. **`_static_fires` (79–88):** the static analyzer catches `CODE-001` on a known shell-injection snippet (the deterministic floor works).
4. **`_defense_runs` (91–105):** the defense pipeline runs end-to-end on the CAN-gateway example and surfaces the expected rule ids (`CODE-005/006`, `TOP-001/002`, `LOG-CAN-02`), with the guard allowing.
5. **`_attack_runs` (108–121):** the attack pipeline runs on a brake-tampering scenario, ethics passes, and scripts are emitted.
6. **`_guards` (124–151):** `SecurityGuard.check` and `EthicsGuard.check_plan` return well-formed, expected verdicts on synthetic inputs.

### `main()` — lines 160–177
Run every check, print `OK`/`FAIL` (with color and a traceback on failure), and
return 1 if any failed else 0, suggesting `pytest tests/` for the full suite.

## 4. Edge cases, gotchas & design decisions
- **Offline by default, overridable.** `setdefault` on the three env switches
  keeps the smoke test deterministic and side-effect-free, but lets you unset any
  to test the real model/tools.
- **Asserts exact rule ids.** Because it runs under the stub + no-external layer,
  the expected findings are deterministic, so the assertions are exact — a drift
  in detection is caught immediately.
- **Complements, doesn't replace, pytest.** It's a 30-second wiring check; the
  real coverage is in `tests/`.
