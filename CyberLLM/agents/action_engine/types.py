"""Action-engine data model.

The defense pipeline's "action" is no longer a single canned command
per response tier — it is a structured, multi-step plan executed
against a typed MCP tool registry, with pre/post conditions,
rollback, and per-step audit. This module defines the shapes.

Design notes
------------
- Every `ActionStep` carries enough context (tool, params,
  side-effect, severity gate) for an external reviewer to decide
  whether to approve it.
- An `ActionPlan` is *immutable once built*. Execution attaches a
  separate `ActionReport` that captures the runtime outcome.
- `Condition` is the unit of pre/post-verification. The executor
  evaluates it by invoking an MCP tool — same registry as the
  action tools — which keeps "did it work?" auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SideEffect(str, Enum):
    """How invasive a tool is. Drives the dry-run / authorization gate."""
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


class StepKind(str, Enum):
    """Coarse classification used to order steps (containment first)."""
    CONTAIN = "contain"        # stop the immediate damage
    ERADICATE = "eradicate"    # remove the root cause
    RECOVER = "recover"        # restore service
    NOTIFY = "notify"          # tell humans
    OBSERVE = "observe"        # measure / verify
    AUDIT = "audit"            # persist evidence


_KIND_ORDER = {
    StepKind.CONTAIN: 0,
    StepKind.OBSERVE: 1,
    StepKind.ERADICATE: 2,
    StepKind.RECOVER: 3,
    StepKind.NOTIFY: 4,
    StepKind.AUDIT: 5,
}


def kind_priority(kind: StepKind) -> int:
    return _KIND_ORDER[kind]


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    REFUSED = "refused"             # guard rejected it
    VERIFY_FAILED = "verification_failed"
    ROLLED_BACK = "rolled_back"


class PlanStatus(str, Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    PARTIAL = "partial_success"
    FAILED = "failed"
    REFUSED = "refused"


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def severity_rank(sev: str) -> int:
    return _SEVERITY_RANK.get((sev or "").lower(), 0)


# ---------------------------------------------------------------------------
# Conditions — pre / post verification
# ---------------------------------------------------------------------------

@dataclass
class Condition:
    """A single pre- or post-condition evaluated via an MCP tool.

    `expected_status` is matched against the tool's reported status;
    `expected_payload` (optional) is a dict whose keys/values must
    appear in the tool's output payload. If both are None, the
    condition only checks that the tool call succeeded.
    """
    description: str
    check_tool: str
    check_params: dict = field(default_factory=dict)
    expected_status: str | None = None
    expected_payload: dict | None = None


# ---------------------------------------------------------------------------
# Steps and plans
# ---------------------------------------------------------------------------

@dataclass
class ActionStep:
    rule_id: str | None
    kind: StepKind
    tool: str
    params: dict
    description: str

    # Quality-of-execution metadata.
    side_effect: SideEffect = SideEffect.READ
    severity_min: str = "low"           # only run for finding-severity >= this
    timeout_s: int = 30
    retries: int = 1                    # number of *additional* attempts
    pre: list[Condition] = field(default_factory=list)
    post: list[Condition] = field(default_factory=list)
    rollback_steps: list["ActionStep"] = field(default_factory=list)
    requires_authorization: bool = False

    # Identity + mutable execution state.
    step_id: str = field(default_factory=lambda: str(uuid4()))
    status: StepStatus = StepStatus.PENDING
    attempts: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    output: dict | None = None
    error: str | None = None
    refusal_reason: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        # asdict serialises enums as their .value already; datetimes need a hand.
        for k in ("started_at", "finished_at"):
            if isinstance(d.get(k), datetime):
                d[k] = d[k].isoformat()
        return d


@dataclass
class ActionPlan:
    plan_id: str
    decision_summary: str
    blast_radius: str        # "local" | "service" | "node" | "network" | "fleet"
    asset_categories: list[str]
    steps: list[ActionStep]
    created_at: datetime = field(default_factory=datetime.now)

    @property
    def estimated_duration_s(self) -> int:
        return sum(s.timeout_s for s in self.steps)

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id,
            "decision_summary": self.decision_summary,
            "blast_radius": self.blast_radius,
            "asset_categories": self.asset_categories,
            "created_at": self.created_at.isoformat(),
            "estimated_duration_s": self.estimated_duration_s,
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclass
class ActionReport:
    plan: ActionPlan
    started_at: datetime
    finished_at: datetime | None = None
    status: PlanStatus = PlanStatus.NOT_STARTED
    summary: str = ""
    audit_log: list[dict] = field(default_factory=list)

    @property
    def completed(self) -> int:
        return sum(1 for s in self.plan.steps if s.status == StepStatus.COMPLETED)

    @property
    def failed(self) -> int:
        return sum(1 for s in self.plan.steps
                   if s.status in (StepStatus.FAILED, StepStatus.VERIFY_FAILED))

    @property
    def refused(self) -> int:
        return sum(1 for s in self.plan.steps if s.status == StepStatus.REFUSED)

    @property
    def rolled_back(self) -> int:
        return sum(1 for s in self.plan.steps if s.status == StepStatus.ROLLED_BACK)

    @property
    def skipped(self) -> int:
        return sum(1 for s in self.plan.steps if s.status == StepStatus.SKIPPED)

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan.plan_id,
            "status": self.status.value,
            "summary": self.summary,
            "started_at": self.started_at.isoformat(),
            "finished_at": (self.finished_at.isoformat()
                             if self.finished_at else None),
            "tallies": {
                "total": len(self.plan.steps),
                "completed": self.completed,
                "failed": self.failed,
                "refused": self.refused,
                "rolled_back": self.rolled_back,
                "skipped": self.skipped,
            },
            "plan": self.plan.to_dict(),
            "audit_log": self.audit_log,
        }


# ---------------------------------------------------------------------------
# MCP tool result
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    """Standard envelope returned by every MCP tool call."""
    status: str                  # "ok" | "failed" | "would-execute" (dry-run) | "skipped"
    tool: str
    payload: dict = field(default_factory=dict)
    error: str | None = None
    invoked_real_tool: bool = False
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)
