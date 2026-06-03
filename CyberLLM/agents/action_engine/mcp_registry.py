"""MCP-style tool registry.

Why MCP-shaped
--------------
The Model-Context-Protocol pattern decouples **what** an agent wants
to do from **how** it gets done. Each tool exposes:

  - a name + schema (so the planner / LLM can discover and address it),
  - a side-effect declaration (so the executor can gate destructive
    calls behind a dry-run flag and / or a security guard),
  - an idempotency hint (so retries are safe),
  - a `call(params)` entry point that returns a `ToolResult`,
  - an optional `verify(params, result)` hook used by the executor's
    post-condition check.

Tools call real system commands or remote services where they can —
`iptables`, `ufw`, `systemctl`, `bandit`, `git`, HTTP webhooks — and
fall back to professional-grade stubs (logged + journaled) where the
underlying command is unavailable or the engine is in dry-run mode.

Audit log
---------
Every call (real or dry-run) is appended to a tool-level audit log.
That log is what the run-logger persists at the end of a defense run.
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from .types import SideEffect, ToolResult


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

@dataclass
class MCPSchemaField:
    name: str
    type: str             # "string" | "int" | "ipv4" | "bool" | "dict" | "list" | "enum"
    required: bool = True
    enum: list[str] = field(default_factory=list)
    description: str = ""


class MCPTool:
    """Abstract base class for every MCP-style tool."""

    name: str = "abstract.tool"
    description: str = ""
    side_effect: SideEffect = SideEffect.READ
    idempotent: bool = True
    requires_authorization: bool = False
    schema: list[MCPSchemaField] = []
    real_binary: str | None = None         # the underlying CLI command, if any
    domain: str = "generic"                # firewall | network | secrets | code | runtime | notify | observe | kb

    # Provided by the registry before call() is invoked.
    dry_run: bool = True
    work_dir: str | None = None

    # ---- public API used by the executor --------------------------------

    def validate(self, params: dict) -> list[str]:
        """Return a list of validation errors. Empty list = OK."""
        errors = []
        provided = set(params.keys())
        declared = {f.name: f for f in self.schema}
        missing = {n for n, f in declared.items() if f.required} - provided
        for n in missing:
            errors.append(f"missing required param: {n}")
        for n, v in params.items():
            f = declared.get(n)
            if not f:
                continue
            if f.type == "enum" and v not in f.enum:
                errors.append(f"{n}: '{v}' not in {f.enum}")
        return errors

    def real_available(self) -> bool:
        """Is the underlying real CLI / API reachable here?"""
        if not self.real_binary:
            return False
        return shutil.which(self.real_binary) is not None

    def call(self, params: dict) -> ToolResult:
        errors = self.validate(params)
        if errors:
            return ToolResult(status="failed", tool=self.name,
                              error="; ".join(errors))
        start = time.perf_counter()
        try:
            if self.dry_run or not self.real_available():
                result = self._dry_run(params)
                result.invoked_real_tool = False
            else:
                result = self._do_call(params)
                result.invoked_real_tool = True
        except Exception as exc:        # noqa: BLE001
            return ToolResult(status="failed", tool=self.name,
                              error=f"{type(exc).__name__}: {exc}",
                              elapsed_ms=(time.perf_counter() - start) * 1000.0)
        result.tool = self.name
        result.elapsed_ms = (time.perf_counter() - start) * 1000.0
        return result

    def verify(self, params: dict, result: ToolResult) -> bool:
        """Override to add a tool-specific verification step."""
        return result.status in ("ok", "would-execute")

    # ---- subclasses override these --------------------------------------

    def _do_call(self, params: dict) -> ToolResult:
        """Invoke the underlying real implementation."""
        raise NotImplementedError

    def _dry_run(self, params: dict) -> ToolResult:
        """Return a realistic ToolResult without performing side effects."""
        return ToolResult(
            status="would-execute",
            tool=self.name,
            payload={
                "dry_run": True,
                "would_invoke": self.real_binary or "(no real binary)",
                "params": params,
            },
        )

    # ---- discovery ------------------------------------------------------

    def describe(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "domain": self.domain,
            "side_effect": self.side_effect.value,
            "idempotent": self.idempotent,
            "requires_authorization": self.requires_authorization,
            "real_binary": self.real_binary,
            "real_available": self.real_available(),
            "schema": [
                {"name": f.name, "type": f.type, "required": f.required,
                 "enum": f.enum, "description": f.description}
                for f in self.schema
            ],
        }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class MCPRegistry:
    """Collection of tools + a runtime audit log."""

    def __init__(self, dry_run: bool = True, work_dir: str | None = None):
        self._tools: dict[str, MCPTool] = {}
        self.dry_run = dry_run
        self.work_dir = work_dir
        self.audit: list[dict] = []
        self._authorization_hook: Callable[[str, dict], bool] | None = None

    # ---- registration ---------------------------------------------------

    def register(self, tool: MCPTool) -> None:
        tool.dry_run = self.dry_run
        tool.work_dir = self.work_dir
        self._tools[tool.name] = tool

    def register_many(self, tools: list[MCPTool]) -> None:
        for t in tools:
            self.register(t)

    def list_tools(self) -> list[str]:
        return sorted(self._tools)

    def schemas(self) -> dict[str, dict]:
        return {n: t.describe() for n, t in self._tools.items()}

    def has(self, name: str) -> bool:
        return name in self._tools

    def get(self, name: str) -> MCPTool:
        if name not in self._tools:
            raise KeyError(f"unknown MCP tool: {name}")
        return self._tools[name]

    # ---- invocation -----------------------------------------------------

    def set_authorization_hook(self,
                                fn: Callable[[str, dict], bool]) -> None:
        self._authorization_hook = fn

    def call(self, name: str, params: dict | None = None) -> ToolResult:
        params = params or {}
        tool = self.get(name)
        # Authorisation hook: defaults to "allow". Callers (e.g. the
        # executor) can override to require operator approval for
        # destructive tools in live mode.
        authorized = True
        if (tool.side_effect == SideEffect.DESTRUCTIVE
                and self._authorization_hook is not None):
            authorized = self._authorization_hook(name, params)
        if not authorized:
            result = ToolResult(status="failed", tool=name,
                                error="not authorised for destructive call")
        else:
            result = tool.call(params)
        self._append_audit(tool, params, result)
        return result

    # ---- audit ----------------------------------------------------------

    def _append_audit(self, tool: MCPTool, params: dict,
                       result: ToolResult) -> None:
        self.audit.append({
            "ts": datetime.now().isoformat(timespec="milliseconds"),
            "tool": tool.name,
            "side_effect": tool.side_effect.value,
            "real_invoked": result.invoked_real_tool,
            "dry_run": self.dry_run,
            "elapsed_ms": round(result.elapsed_ms, 2),
            "status": result.status,
            "params": _safe_for_audit(params),
            "result_payload": _safe_for_audit(result.payload),
            "error": result.error,
        })

    def export_audit(self) -> str:
        return json.dumps(self.audit, indent=2)


def _safe_for_audit(obj):
    """Truncate large strings + scrub obvious secrets from audit records."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if any(s in str(k).lower()
                   for s in ("password", "secret", "token", "apikey")):
                out[k] = "***redacted***"
            else:
                out[k] = _safe_for_audit(v)
        return out
    if isinstance(obj, list):
        return [_safe_for_audit(x) for x in obj]
    if isinstance(obj, str) and len(obj) > 800:
        return obj[:800] + "…[truncated]"
    return obj
