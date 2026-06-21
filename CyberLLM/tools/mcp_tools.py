"""MCP tools — real backends with a safe dry-run default.

These three tools keep the original simple `run(**kwargs) -> dict`
interface (so anything importing `TOOL_REGISTRY` keeps working), but the
bodies are now **real**:

  - `PortScanTool`      → `nmap` if installed, else a bounded pure-Python
                          TCP connect scan.
  - `StaticAnalysisTool`→ real `bandit` (JSON) or `semgrep`.
  - `PacketCaptureTool` → `tshark` / `tcpdump` / `candump`.

Safety model (production-minded):
  - **Active / intrusive** tools (port scan, packet capture) default to a
    *dry-run* that returns a "would-run" envelope; pass `live=True` to
    actually execute. This mirrors the action-engine's dry-run gate.
  - **Read-only** tools (static analysis) run whenever the backend is
    present — there is nothing to gate.
  - All subprocess calls use an explicit `args=[...]` list (never
    `shell=True`) and a bounded timeout.

For richer, schema-validated, audited tooling prefer the action-engine
registry (`agents/action_engine/mcp_tools.py`); this module is the
lightweight `run()`-style entry point.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess


def _run(args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    """subprocess.run wrapper → (returncode, stdout, stderr). No shell."""
    try:
        cp = subprocess.run(args, capture_output=True, text=True,
                            timeout=timeout, check=False)
        return cp.returncode, cp.stdout or "", cp.stderr or ""
    except FileNotFoundError:
        return 127, "", "binary not found"
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or ""), (exc.stderr or "timeout")


_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389,
                 5432, 6379, 8080, 8443, 11434]


class PortScanTool:
    name = "port_scan"
    description = "Active TCP port scan (nmap, else pure-Python connect scan)."

    def run(self, target: str = "127.0.0.1", ports: str = "1-1024",
            live: bool = False, **_) -> dict:
        if not live:
            return {"tool": self.name, "target": target, "dry_run": True,
                    "would_run": f"nmap -sT -Pn --open -p {ports} {target}",
                    "note": "pass live=True to actually scan (authorised targets only)."}
        if shutil.which("nmap"):
            import re
            _, out, _ = _run(["nmap", "-sT", "-Pn", "--open", "-p", ports,
                              "-oG", "-", target], timeout=120)
            open_ports = sorted({int(m) for m in re.findall(r"(\d+)/open", out)})
            return {"tool": self.name, "target": target, "backend": "nmap",
                    "hosts": [{"ip": target.split("/")[0],
                               "open_ports": open_ports}]}
        host = target.split("/")[0]
        open_ports = []
        for p in _COMMON_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            try:
                if s.connect_ex((host, p)) == 0:
                    open_ports.append(p)
            except Exception:           # noqa: BLE001
                pass
            finally:
                s.close()
        return {"tool": self.name, "target": host, "backend": "socket",
                "hosts": [{"ip": host, "open_ports": open_ports}]}


class StaticAnalysisTool:
    name = "static_analysis"
    description = "Real static analysis via bandit (JSON) or semgrep."

    def run(self, filename: str, **_) -> dict:
        print(f"Running static analysis on {filename}...")
        # Read-only — safe to run whenever a backend is present.
        if shutil.which("bandit"):
            rc, out, _ = _run(["bandit", "-r", filename, "-f", "json", "-q"],
                              timeout=120)
            try:
                data = json.loads(out)
                issues = [{"line": r.get("line_number"),
                           "rule": r.get("test_id"),
                           "severity": (r.get("issue_severity") or "").lower(),
                           "msg": r.get("issue_text")}
                          for r in data.get("results", [])]
            except Exception:           # noqa: BLE001
                issues = []
            print(f"Bandit found {len(issues)} issue(s) in {filename}")
            return {"tool": self.name, "filename": filename,
                    "backend": "bandit", "issues": issues}
        if shutil.which("semgrep"):
            rc, out, _ = _run(["semgrep", "--config=auto", "--json", filename],
                              timeout=120)
            try:
                data = json.loads(out)
                issues = [{"line": r.get("start", {}).get("line"),
                           "rule": r.get("check_id"),
                           "severity": (r.get("extra", {}).get("severity")
                                        or "").lower(),
                           "msg": r.get("extra", {}).get("message")}
                          for r in data.get("results", [])]
            except Exception:           # noqa: BLE001
                issues = []
            print(f"Semgrep found {len(issues)} issue(s) in {filename}")
            return {"tool": self.name, "filename": filename,
                    "backend": "semgrep", "issues": issues}
        return {"tool": self.name, "filename": filename, "backend": None,
                "issues": [], "note": "install bandit or semgrep for a real scan."}


class PacketCaptureTool:
    name = "packet_capture"
    description = "Capture packets / CAN frames (tshark / tcpdump / candump)."

    def run(self, interface: str = "any", count: int = 50,
            timeout_s: int = 10, live: bool = False, **_) -> dict:
        backends = {b: shutil.which(b)
                    for b in ("tshark", "tcpdump", "candump")}
        if not live:
            return {"tool": self.name, "interface": interface, "dry_run": True,
                    "available_backends": [b for b, p in backends.items() if p],
                    "note": "pass live=True to capture (needs privileges)."}
        timeout_s = min(int(timeout_s), 30)
        if backends["tshark"]:
            _, out, _ = _run(["tshark", "-i", interface, "-a",
                              f"duration:{timeout_s}", "-c", str(count), "-n"],
                             timeout=timeout_s + 15)
        elif backends["tcpdump"]:
            _, out, _ = _run(["tcpdump", "-i", interface, "-c", str(count),
                              "-nn", "-tt"], timeout=timeout_s + 15)
        elif backends["candump"]:
            _, out, _ = _run(["candump", "-n", str(count), interface],
                             timeout=timeout_s + 5)
        else:
            return {"tool": self.name, "interface": interface,
                    "error": "no tshark/tcpdump/candump installed"}
        lines = [ln for ln in out.splitlines() if ln.strip()]
        return {"tool": self.name, "interface": interface,
                "summary": f"captured {len(lines)} record(s)",
                "sample": lines[:20]}


TOOL_REGISTRY = {
    PortScanTool.name: PortScanTool(),
    StaticAnalysisTool.name: StaticAnalysisTool(),
    PacketCaptureTool.name: PacketCaptureTool(),
}
