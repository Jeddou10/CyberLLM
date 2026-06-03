"""Action engine — defense-side planner + executor.

Public API:

  - `ActionGenerator`  — the agent the pipeline calls; replaces the
    proof-of-concept tier-to-action map.
  - `Action`           — legacy shape (kind/target/parameters) for
    backward-compatibility with the existing SecurityGuard.
  - `ActionPlan` / `ActionStep` / `ActionReport` — typed structures
    written out into the run-log for review.
  - `MCPRegistry` / `MCPTool` / `default_toolset` — the typed tool
    layer (firewall, secrets, code, runtime, notify, observe, kb).
  - `build_plan`       — pure plan builder, useful for unit tests.

Everything is dry-run by default. Pass `dry_run=False` to the
generator (or set `cfg.dry_run: false`) to opt into real side effects.
"""

from .executor import ActionExecutor, GuardAdapter, passthrough_guard
from .generator import Action, ActionGenerator
from .mcp_registry import MCPRegistry, MCPSchemaField, MCPTool
from .mcp_tools import default_toolset
from .playbooks import PLAYBOOKS, Playbook, StepTemplate, build_plan
from .types import (
    ActionPlan,
    ActionReport,
    ActionStep,
    Condition,
    PlanStatus,
    SideEffect,
    StepKind,
    StepStatus,
    ToolResult,
)

__all__ = [
    "Action",
    "ActionExecutor",
    "ActionGenerator",
    "ActionPlan",
    "ActionReport",
    "ActionStep",
    "Condition",
    "GuardAdapter",
    "MCPRegistry",
    "MCPSchemaField",
    "MCPTool",
    "PLAYBOOKS",
    "PlanStatus",
    "Playbook",
    "SideEffect",
    "StepKind",
    "StepStatus",
    "StepTemplate",
    "ToolResult",
    "build_plan",
    "default_toolset",
    "passthrough_guard",
]
