# `agents/action_engine/mcp_registry.py` — the typed tool registry + `MCPTool` base

`[← back to all_info index](../../README.md)`

---

## 1. Purpose & place in the system

This file defines the **MCP-style tool layer**: an abstract `MCPTool` base class
(every concrete tool in `mcp_tools.py` subclasses it) and an `MCPRegistry` that
holds tools, validates their inputs, gates destructive calls, runs them, and
**audits every call**. The MCP shape decouples *what* an agent wants (by tool
name + schema) from *how* it's done, and centralizes the dry-run / authorization
/ audit machinery in one place.

Used by `generator.py` (builds the registry, exposes the catalogue to the LLM),
`executor.py` (calls tools), and `mcp_tools.py` (the concrete tools).

---

## 2. Imports — lines 27–36

| line | import | why |
|------|--------|-----|
| 29 | `json` | `export_audit` serialization. |
| 30 | `shutil` | `which()` — is the real binary available? |
| 31 | `time` | `perf_counter` for `elapsed_ms`. |
| 32 | `dataclass, field` | `MCPSchemaField`. |
| 33 | `datetime` | Audit timestamps. |
| 34 | `Callable` | Type the `on_call`/authorization hooks. |
| 36 | `SideEffect, ToolResult` from `.types` | Side-effect gating + the result envelope. |

---

## 3. Walkthrough

### `MCPSchemaField` — lines 43–49
One declared parameter: `name`, `type` (string/int/ipv4/bool/dict/list/enum),
`required`, optional `enum` choices, and a `description`. The schema is how the
planner/LLM discovers what a tool needs and how validation is done.

### `class MCPTool` — lines 52–152  (the base every tool extends)
- **Class attributes (55–66):** `name`, `description`, `side_effect`, `idempotent` (retry-safe?), `requires_authorization`, `schema`, `real_binary` (the CLI it wraps), `domain` (firewall/secrets/code/…), and the registry-injected `dry_run`/`work_dir`.
- **`validate(params)` (70–84):** return a list of errors (empty = OK). It checks required params are present (75–77) and that `enum`-typed params are in range (82–83). Unknown params are ignored (permissive).
- **`real_available()` (86–90):** true only if `real_binary` is set *and* on PATH — the gate between "really run it" and "dry-run/stub it."
- **`call(params)` (92–111):** the public entry point. It validates first (failing fast with a `failed` result), times the call, and **chooses dry-run vs real** at 99: if `self.dry_run` *or* the binary isn't available → `_dry_run` (and `invoked_real_tool=False`); else `_do_call` (`invoked_real_tool=True`). Any exception becomes a `failed` `ToolResult` (105–108) — a tool never throws into the executor. It stamps `tool` and `elapsed_ms` before returning.
- **`verify(params, result)` (113–115):** default post-check = status is `ok`/`would-execute`; tools can override.
- **`_do_call` / `_dry_run` (119–133):** subclasses implement `_do_call` (the real thing); the default `_dry_run` returns a realistic `would-execute` envelope describing what *would* have run — so a dry-run plan is informative without side effects.
- **`describe()` (137–152):** a JSON-able description (incl. `real_available()`), used to build the LLM tool catalogue and the run-log schema dump.

### `class MCPRegistry` — lines 159–246
- **`__init__` (162–172):** holds the tools, the global `dry_run`/`work_dir`, the `audit` list, an optional `_authorization_hook`, and an optional `_on_call` observer (the pipeline wires this to the Console so each tool run is announced). The observer is a pure side-channel — "never affects results."
- **Registration (176–197):** `register` injects the registry's `dry_run`/`work_dir` into each tool, then stores it by name. `list_tools`/`schemas`/`has`/`get` are discovery/lookup helpers (`get` raises `KeyError` on an unknown tool).
- **`set_authorization_hook` (201–203):** install a callback that approves/denies a destructive call (defaults to allow).
- **`call(name, params)` (205–226):** the heart. It fetches the tool; if the tool is **destructive and a hook is set**, it consults the hook (211–214); a denied call becomes a `failed` "not authorised" result, otherwise it runs the tool. **Every** call is appended to the audit log (220), and the `_on_call` observer is invoked in a `try/except` so a broken observer can never break a run (221–225).
- **Audit (230–246):** `_append_audit` records a rich row per call — timestamp, tool, side-effect, whether a real tool ran, dry-run flag, elapsed ms, status, scrubbed params/payload, error. `export_audit` dumps it as JSON.

### `_safe_for_audit(obj)` — lines 249–264
Recursively sanitize audit data: **redact** any key containing
`password/secret/token/apikey` (254–256) and **truncate** strings over 800 chars.
**Why:** the audit log is persisted to disk and shown in the UI — it must not
leak secrets or balloon with huge payloads.

---

## 4. Edge cases, gotchas & design decisions

- **The registry — not the executor — owns dry-run.** The executor only sequences and verifies; whether a real binary runs is decided here (line 99). This single point of control is the core safety property.
- **Destructive ⇒ authorization hook.** Only `DESTRUCTIVE` tools consult the hook, and only if one is set; everything else is allowed. In dry-run mode it's moot (nothing real runs anyway).
- **Tools never throw.** `call` wraps `_do_call` in `try/except` and returns a `failed` result, so one misbehaving tool can't crash the plan.
- **Audit is the source of truth.** The run logger persists `registry.audit`; secret-scrubbing and truncation happen at write time so the artifact is safe to share.
- **`real_available()` makes "real vs sim" automatic.** If `nmap` isn't installed, the port-scan tool transparently dry-runs even in live mode — so missing binaries degrade gracefully instead of erroring.
