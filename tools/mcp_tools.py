"""Stub MCP tools.

Each class exposes a `run(**kwargs)` method that returns a dict. In
production, replace the body with a real MCP client invocation. The
shape of the response is what the rest of the pipeline expects, so
swapping in real tools requires no other changes.
"""

from __future__ import annotations


class PortScanTool:
    name = "port_scan"
    description = "Run nmap-style scan against an IPv4 network."

    def run(self, ipv4_network: str = "10.1.1.0/24", **_) -> dict:
        return {
            "tool": self.name,
            "target": ipv4_network,
            "hosts": [
                {"ip": "10.1.1.24", "open_ports": [22, 80, 443, 8080]},
                {"ip": "10.1.1.99", "open_ports": [23]},  # telnet — bad
            ],
        }


class StaticAnalysisTool:
    name = "static_analysis"
    description = "Run a static-analysis pass on the given file (bandit / semgrep stub)."

    def run(self, filename: str, **_) -> dict:
        return {
            "tool": self.name,
            "filename": filename,
            "issues": [
                {"line": 14, "rule": "B602", "severity": "high",
                 "msg": "subprocess call with shell=True identified"},
            ],
        }


class PacketCaptureTool:
    name = "packet_capture"
    description = "Capture the first N packets on a given interface."

    def run(self, interface: str = "can0", count: int = 50, **_) -> dict:
        return {
            "tool": self.name,
            "interface": interface,
            "summary": f"captured {count} packets",
            "anomalies": [
                {"ts": "2026-05-19T09:21:14Z",
                 "msg": "burst of CAN-ID 0x7E0 from non-gateway ECU"}
            ],
        }


TOOL_REGISTRY = {
    PortScanTool.name: PortScanTool(),
    StaticAnalysisTool.name: StaticAnalysisTool(),
    PacketCaptureTool.name: PacketCaptureTool(),
}
