"""MCP-style external tool adapters.

This is where you wire `nmap`, `tcpdump`, `bandit`, `semgrep`,
CAN replay tools, etc. For the first pipeline we ship deterministic
stubs so the demo runs offline.
"""
from .mcp_tools import (
    PortScanTool,
    StaticAnalysisTool,
    PacketCaptureTool,
    TOOL_REGISTRY,
)
