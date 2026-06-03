"""Public `ActionGenerator` — defense-side action engine.

Replaces the proof-of-concept tier-to-action map. The pipeline still
sees a `generate(decision, vulnerable_code)` method that returns an
`Action`, so the existing call-site keeps working; the richer
`ActionReport` is exposed via `last_report` for the run-logger.

Flow inside `generate()`:

    Decision  ──►  build_plan  ──►  ActionExecutor  ──►  ActionReport
                       │                                        │
                       └── plays the rule-id → playbook map ────┘

Dry-run by default (no destructive side-effects) — set
`cfg.dry_run: false` or pass `dry_run=False` to the constructor to
enable real tool invocations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agents.base_agent import BaseAgent, Finding
from llm_client import LLMClient

from .executor import ActionExecutor, GuardAdapter
from .mcp_registry import MCPRegistry
from .mcp_tools import default_toolset
from .playbooks import build_plan
from .types import (
    ActionPlan, ActionReport, ActionStep, PlanStatus, SideEffect, StepStatus,
)


# ---------------------------------------------------------------------------
# Legacy Action shape — preserved for pipeline back-compatibility
# ---------------------------------------------------------------------------

@dataclass
class Action:
    kind: str
    target: str
    parameters: dict
    rationale: str
    originating_decision: Any
    # New fields (populated by the engine; ignored by older callers).
    plan_id: str | None = None
    report: dict | None = None      # ActionReport.to_dict()


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

class ActionGenerator(BaseAgent):
    """Defense action engine.

    The agent owns an MCP registry, a playbook catalogue, and an
    executor. Each `generate()` call:

        1. Builds an ActionPlan from the Decision via playbook lookup.
        2. Runs the plan through the ActionExecutor (dry-run by default).
        3. Returns a legacy Action shape for back-compat, with the
           full report attached.
    """

    def __init__(self, agent_id: str, cfg: dict, llm: LLMClient,
                 registry: MCPRegistry | None = None,
                 guard: GuardAdapter | None = None):
        super().__init__(agent_id, cfg, llm)
        self.dry_run = bool(cfg.get("dry_run", True))
        self.work_dir = cfg.get("work_dir", "./mcp_workspace")
        self.registry = registry or self._build_default_registry()
        self.guard = guard
        self.executor = ActionExecutor(self.registry, guard=self.guard)
        self.last_plan: ActionPlan | None = None
        self.last_report: ActionReport | None = None

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------

    def plan(self, decision, ctx: dict | None = None) -> ActionPlan:
        return build_plan(decision, ctx or self._default_ctx())

    def execute(self, plan: ActionPlan) -> ActionReport:
        report = self.executor.execute(plan)
        self.last_plan, self.last_report = plan, report
        return report

    def generate(self, decision, vulnerable_code: str = "") -> Action:
        """Backwards-compatible entry point used by `pipeline.py`."""
        ctx = self._default_ctx()
        if vulnerable_code:
            ctx["vulnerable_code"] = vulnerable_code
        plan = self.plan(decision, ctx)
        report = self.execute(plan)
        return self._wrap_as_action(decision, plan, report)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _build_default_registry(self) -> MCPRegistry:
        reg = MCPRegistry(dry_run=self.dry_run, work_dir=self.work_dir)
        reg.register_many(default_toolset())
        return reg

    def _default_ctx(self) -> dict:
        return {
            "repo_path": self.cfg.get("repo_path", "."),
            "workspace_path": self.work_dir,
            "at_risk_secret": self.cfg.get("at_risk_secret",
                                              "primary-api-token"),
            "vehicle_id": self.cfg.get("vehicle_id", "TESTBENCH-01"),
            "log_path": self.cfg.get("log_path", ""),
            "default_file": self.cfg.get("default_file", "unknown.py"),
        }

    def _wrap_as_action(self, decision, plan: ActionPlan,
                          report: ActionReport) -> Action:
        # Pick the "primary" step for legacy `kind`/`target`/`parameters`
        # fields — the first CONTAIN step if any, otherwise the first
        # ERADICATE, otherwise the first step at all.
        primary = self._primary_step(plan)
        if primary is None:
            return Action(
                kind="noop",
                target="",
                parameters={},
                rationale=("No remediation steps generated for this decision; "
                            "see the report for details."),
                originating_decision=decision,
                plan_id=plan.plan_id,
                report=report.to_dict(),
            )
        return Action(
            kind=_legacy_kind(primary),
            target=primary.params.get("ipv4")
                    or primary.params.get("node_id")
                    or primary.params.get("file")
                    or primary.params.get("service")
                    or primary.params.get("target")
                    or "engine",
            parameters=primary.params,
            rationale=(f"{primary.description}. "
                        f"Plan: {report.summary}"),
            originating_decision=decision,
            plan_id=plan.plan_id,
            report=report.to_dict(),
        )

    @staticmethod
    def _primary_step(plan: ActionPlan) -> ActionStep | None:
        for s in plan.steps:
            if s.status in (StepStatus.COMPLETED,
                             StepStatus.RUNNING,
                             StepStatus.PENDING):
                return s
        return plan.steps[0] if plan.steps else None


# ---------------------------------------------------------------------------
# Mapping back to the legacy `kind` strings the SecurityGuard knows.
# ---------------------------------------------------------------------------

_LEGACY_KIND_MAP = {
    "firewall.rate_limit":    "rate_limit",
    "firewall.block_ipv4":    "block_ip",
    "network.isolate_node":   "isolate_node",
    "code.propose_patch":     "patch_code",
    "notify.create_incident": "alert_only",
    "notify.webhook":         "alert_only",
    "notify.email":           "alert_only",
    "notify.driver":          "alert_only",
    "secrets.rotate":         "patch_code",       # treat as a privileged change
    "secrets.revoke":         "block_ip",
    "runtime.safe_mode":      "isolate_node",
    "runtime.restart_service":"block_ip",
    "runtime.snapshot":       "alert_only",
    "observe.endpoint":       "alert_only",
    "observe.log_tail":       "alert_only",
    "observe.port_closed":    "alert_only",
    "code.static_scan":       "alert_only",
    "code.scrub_git_history": "patch_code",
    "kb.lookup_cve":          "alert_only",
    "firewall.list_rules":    "alert_only",
}


def _legacy_kind(step: ActionStep) -> str:
    return _LEGACY_KIND_MAP.get(step.tool, "alert_only")
