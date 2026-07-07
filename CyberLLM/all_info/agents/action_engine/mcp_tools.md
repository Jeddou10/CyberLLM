# `agents/action_engine/mcp_tools.py` — the 22 concrete MCP tools

`[← back to all_info index](../../README.md)`

---

## 1. Purpose & place in the system

This file implements the **real action/observation tools** the engine runs.
Each is an `MCPTool` subclass (from `mcp_registry.py`) with: an explicit
validated schema, a declared side effect, a real OS-level command/service where
one exists on the host (in live mode), and a **professional dry-run envelope**
otherwise. `default_toolset()` returns the full set, which `generator.py`
registers. Tools are grouped by domain: `firewall.*`, `network.*`, `secrets.*`,
`code.*`, `runtime.*`, `notify.*`, `observe.*`, `kb.*`. All real invocations use
`subprocess.run(args=[...])` (never `shell=True`) with bounded timeouts.

---

## 2. Imports — lines 25–43

| line | import | why |
|------|--------|-----|
| 27–28 | `json, os` | Payloads, root/uid checks, env. |
| 29 | `platform` | OS-specific command choice. |
| 30–31 | `re, shutil` | Validate IPs; find binaries. |
| 32 | `smtplib` | `notify.email`. |
| 33 | `socket` | Pure-Python port scan / port-closed checks. |
| 34–36 | `subprocess, sys, time` | Run real commands; platform flags; timing. |
| 37 | `urllib.request` | `notify.webhook`, endpoint probes, CVE lookup. |
| 38–40 | `datetime, EmailMessage, Path` | Timestamps, email, workspace paths. |
| 42–43 | `MCPSchemaField, MCPTool`, `SideEffect, ToolResult` | The base + shapes. |

**Helpers (50–78):** `IS_LINUX/IS_WINDOWS/IS_MACOS` platform flags; `_run` (a
`subprocess.run` wrapper returning `(rc, out, err)`, turning a timeout into rc
124); `_is_root` (admin check, cross-platform via `ctypes` on Windows,
`os.geteuid` elsewhere); `_resolve_workdir` (create/return the workspace dir).

---

## 3. Walkthrough — the tool catalogue

Every tool follows the same contract: class attributes (`name`, `domain`,
`side_effect`, `requires_authorization`, `schema`, `real_binary`), an optional
`validate` override, and `_do_call` (the real implementation). If `dry_run` is on
or the binary is missing, the base class's `_dry_run` returns a "would-execute"
envelope instead — so nothing here can do harm unless explicitly in live mode
with the binary present and (for destructive tools) authorized.

| tool (`name`) | domain | side effect | real backend | what it does |
|---|---|---|---|---|
| `firewall.block_ipv4` | firewall | WRITE† | iptables/netsh/pfctl | DROP a source IP at the host firewall |
| `firewall.rate_limit` | firewall | WRITE† | iptables/… | rate-limit a source IP |
| `firewall.list_rules` | firewall | READ | iptables/… | list current firewall rules (verification) |
| `network.isolate_node` | network | DESTRUCTIVE† | ip link / nmcli | quarantine a node onto an isolation VLAN |
| `network.port_scan` | network | READ† | nmap (else sockets) | active TCP port scan of a host |
| `secrets.rotate` | secrets | DESTRUCTIVE† | vault/local store | rotate a secret/credential |
| `secrets.revoke` | secrets | DESTRUCTIVE† | vault/local store | revoke a credential |
| `code.static_scan` | code | READ | bandit/semgrep | run a static scan over a path |
| `code.propose_patch` | code | WRITE | git/file | write a remediation patch proposal |
| `code.scrub_git_history` | code | DESTRUCTIVE† | git filter-repo/BFG | purge a leaked secret from git history |
| `runtime.restart_service` | runtime | WRITE† | systemctl/… | restart a service |
| `runtime.snapshot` | runtime | WRITE | tar/lvm | snapshot state for forensics |
| `runtime.safe_mode` | runtime | WRITE† | app hook | put a vehicle/app into safe mode |
| `notify.webhook` | notify | WRITE | HTTP POST | post an alert to a webhook |
| `notify.create_incident` | notify | WRITE | file/SOAR | open a tracked incident |
| `notify.email` | notify | WRITE | SMTP | email the security team |
| `notify.driver` | notify | WRITE | app hook | notify the vehicle driver |
| `observe.endpoint` | observe | READ | HTTP probe | check an endpoint's health |
| `observe.log_tail` | observe | READ | file read | tail a log for a pattern (verification) |
| `observe.port_closed` | observe | READ | socket | confirm a port is now closed (post-check) |
| `observe.packet_capture` | observe | READ† | tshark/tcpdump/candump | capture a bounded burst of packets/CAN frames |
| `kb.lookup_cve` | kb | READ | NVD/local YAML | look up CVE / playbook info |

† = `requires_authorization` (the registry's authorization hook gates these in live mode).

### Representative implementations (line-by-line highlights)

**`FirewallBlockIPv4` (85–135)** — the canonical write tool.
- 92–97 — schema: required `ipv4`, optional `duration_minutes`/`reason`.
- 98 — `real_binary` is chosen per OS (`iptables` on Linux, `netsh` on Windows, `pfctl` on macOS).
- 100–105 — a `validate` override adds a **dotted-quad regex check** on top of the base validation, so a malformed IP fails fast.
- 107–120 — `_do_call`: refuses gracefully if not root on Linux (109–114), else runs `iptables -I INPUT -s <ip> -j DROP` and reports success/failure with the rule in the payload.

**`NetworkPortScan` (780–829)** — note `real_available()` is overridden to always
return `True` (796–797): a pure-Python socket scan is always possible, so the
**dry-run flag (not binary presence) is the safety gate**. With `nmap` present it
parses `\d+/open`; otherwise it connect-scans a bounded `_COMMON_PORTS` list with
a 0.5 s per-port timeout, always closing the socket in `finally`.

**`ObservePacketCapture` (836–880)** — `real_available()` is true if *any* of
tshark/tcpdump/candump exists (851–852). `_do_call` caps the capture at 30 s
(857), and supports CAN via `candump` (872–878) — this is the safety-critical
automotive observation tool. Missing all backends → a clean `failed` result.

These three illustrate the patterns the others follow: schema-validate, choose a
real backend if present + permitted, otherwise return a structured result, never
raise.

### `default_toolset()` — lines 887–911
Returns one instance of each of the 22 tools, in a sensible order. This is the
list `generator._build_default_registry()` registers, so the whole catalogue is
available to both the deterministic playbooks and the LLM tool-selector.

---

## 4. Edge cases, gotchas & design decisions

- **Dry-run is the universal safety net.** Even a "real" tool returns a would-execute envelope when `dry_run` is on (the project default, and forced by `CYBERLLM_FORCE_DRY_RUN`). The web UI relies on this — no browser click can run `iptables`.
- **`real_available()` decides real-vs-sim per tool.** Missing `nmap`/`tshark`/`iptables` transparently degrades to a stub/socket fallback or a dry-run, so the engine works on any host.
- **Privilege is checked, not assumed.** Firewall/network tools verify root/admin and fail with a clear message rather than producing a misleading "success."
- **Never `shell=True`.** Every real command is an explicit args list with a timeout — no shell-injection surface, no hangs.
- **Authorization vs side-effect are separate axes.** A tool can be READ but still `requires_authorization` (e.g. an active port scan is read-only but intrusive) — the registry gates destructive *and* authorization-flagged calls appropriately.
- **CAN/automotive awareness.** `observe.packet_capture` (candump), `runtime.safe_mode`, and `notify.driver` exist because the target domain is software-defined vehicles, where the "node" can be an ECU and safety is physical.
