# `tools/__init__.py` — the `tools` package surface

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

This is the package initializer for `tools/`. Its docstring frames the package
as "MCP-style external tool adapters" — where you wire real backends (`nmap`,
`tcpdump`, `bandit`, `semgrep`, CAN replay). It **re-exports** the legacy tool
classes and the registry so callers can write `from tools import TOOL_REGISTRY`
without reaching into the submodule.

---

## 2. Imports — lines 7–12

| line | import | why |
|------|--------|-----|
| 7–12 | `PortScanTool, StaticAnalysisTool, PacketCaptureTool, TOOL_REGISTRY` from `.mcp_tools` | Surface the three legacy tools + the registry at the package level. |

---

## 3. Walkthrough

There is no logic here — it's a pure re-export module. The single statement
(7–12) imports the four names from `tools/mcp_tools.py` so they're accessible as
`tools.PortScanTool`, etc. The docstring documents intent (this is the seam for
external tooling) and notes the first release ships deterministic-ish stubs so
the demo runs offline.

---

## 4. Edge cases, gotchas & design decisions

- **Re-export, not re-implement.** Keeping the package `__init__` thin means the
  actual tool code lives in one place (`mcp_tools.py`) and there's a single
  import path for consumers.
- **`static_analyzer.py` is intentionally *not* re-exported here.** It is
  imported directly (`from tools.static_analyzer import …`) because it's the
  detection core, conceptually distinct from the "external tool adapters" this
  package advertises.
