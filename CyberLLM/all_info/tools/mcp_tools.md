# `tools/mcp_tools.py` — legacy `run()`-style real tools

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

A lightweight set of **three real external tools** with the simple
`run(**kwargs) -> dict` interface, exposed via a `TOOL_REGISTRY` dict. They are
genuinely backed by real binaries (`nmap`, `bandit`/`semgrep`,
`tshark`/`tcpdump`/`candump`) but default to a **safe dry-run** for intrusive
operations.

> This is the *legacy / lightweight* tool entry point. For the richer,
> schema-validated, audited tooling the action engine uses, see
> [`agents/action_engine/mcp_tools.md`](../agents/action_engine/mcp_tools.md).
> This module exists so anything importing `TOOL_REGISTRY` keeps working.

---

## 2. Imports — lines 26–31

| line | import | why |
|------|--------|-----|
| 28 | `json` | Parse bandit/semgrep JSON. |
| 29 | `shutil` | `which()` to detect installed binaries. |
| 30 | `socket` | Pure-Python TCP connect-scan fallback when `nmap` is absent. |
| 31 | `subprocess` | Run the real tools (no `shell=True`, bounded timeout). |

---

## 3. Walkthrough

### `_run(args, timeout)` — lines 34–43
A safe `subprocess.run` wrapper returning `(returncode, stdout, stderr)`. It
**never raises**: a missing binary becomes `(127, "", "binary not found")` and a
timeout becomes `(124, …, "timeout")`. No `shell=True` — args are always a list,
so there's no shell-injection surface.

### `_COMMON_PORTS` — lines 46–47
The port list the pure-Python fallback scanner probes (ssh, http, db ports,
Ollama's 11434, …) when `nmap` isn't installed.

### `class PortScanTool` — lines 50–81
- **Intrusive → dry-run by default.** With `live=False` (56–59) it returns a "would-run" envelope showing the exact `nmap` command, and runs nothing.
- With `live=True` and `nmap` present (60–67), it runs `nmap -sT -Pn --open` in greppable mode and parses `\d+/open` to a sorted set of open ports.
- Without nmap (68–81), it falls back to a bounded pure-Python `connect_ex` scan over `_COMMON_PORTS` with a 0.5 s timeout per port, always closing the socket in `finally`.

### `class StaticAnalysisTool` — lines 84–123
- **Read-only → runs whenever a backend exists** (nothing to gate).
- bandit branch (91–105): `bandit -r <file> -f json -q`, parse `results` into `{line, rule, severity, msg}`.
- semgrep branch (106–121): `semgrep --config=auto --json`, parse the analogous fields.
- No backend (122–123): returns an empty issue list with a "install bandit or semgrep" note.

### `class PacketCaptureTool` — lines 126–155
- **Intrusive → dry-run by default.** With `live=False` (134–137) it lists which capture backends are available and runs nothing.
- With `live=True` it caps the duration at 30 s (138) and uses whichever of `tshark`/`tcpdump`/`candump` is installed (note CAN support via `candump`), returning a record count and a 20-line sample. No backend → an error dict.

### `TOOL_REGISTRY` — lines 158–162
A name→instance dict (`port_scan`, `static_analysis`, `packet_capture`) — the
public lookup table importers use.

---

## 4. Edge cases, gotchas & design decisions

- **Dry-run by default for anything intrusive.** Port scan and packet capture return a "would-run" envelope unless `live=True` — mirroring the action engine's dry-run gate. Read-only static analysis runs freely.
- **Never `shell=True`.** Every call passes an explicit args list with a bounded timeout, so there's no shell-injection or hang risk.
- **Graceful degradation.** Missing binary or bad JSON yields a clean dict with a note, never an exception — callers always get a usable result.
- **Why keep a "legacy" module?** Backward compatibility for `TOOL_REGISTRY` importers and a minimal-ceremony way to call a real tool. New code should prefer the action-engine registry for schema validation + auditing.
