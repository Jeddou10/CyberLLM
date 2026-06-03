"""Action-plan executor.

Responsibilities
----------------
- Walk an `ActionPlan` step by step.
- Evaluate each step's preconditions via MCP `observe.*` tools.
- Per-step *contextual security check* through an optional adapter
  hook (so paper-1 properties apply not just to the final action but
  to every individual tool call).
- Invoke the MCP tool, with retry / back-off.
- Evaluate postconditions; on failure, attempt rollback.
- Maintain an audit log linkable to the registry's own audit log.
- Produce a structured `ActionReport`.

The executor never short-circuits the registry's dry-run flag; the
registry alone decides whether a real tool runs. The executor only
sequences and verifies.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from .mcp_registry import MCPRegistry
from .types import (
    ActionPlan,
    ActionReport,
    ActionStep,
    Condition,
    PlanStatus,
    StepKind,
    StepStatus,
    ToolResult,
)


# ---------------------------------------------------------------------------
# Guard adapter
# ---------------------------------------------------------------------------

@dataclass
class GuardAdapter:
    """Pluggable hook that lets the per-step contextual-security check
    use either the project's `SecurityGuard` or a custom function."""
    fn: Callable[[ActionStep], tuple[bool, str]]

    def check(self, step: ActionStep) -> tuple[bool, str]:
        return self.fn(step)


def passthrough_guard() -> GuardAdapter:
    return GuardAdapter(fn=lambda step: (True, "no guard configured"))


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------

class ActionExecutor:
    def __init__(self,
                 registry: MCPRegistry,
                 guard: GuardAdapter | None = None,
                 max_step_retries: int = 1):
        self.registry = registry
        self.guard = guard or passthrough_guard()
        self.max_retries = max_step_retries

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------

    def execute(self, plan: ActionPlan) -> ActionReport:
        report = ActionReport(plan=plan, started_at=datetime.now(),
                               status=PlanStatus.IN_PROGRESS)
        rollback_stack: list[ActionStep] = []
        failed_hard = False

        for step in plan.steps:
            # ---- pre ----------------------------------------------------
            if not self._eval_conditions(step.pre, phase="pre",
                                          step=step, report=report):
                step.status = StepStatus.SKIPPED
                report.audit_log.append(self._audit("skipped (pre failed)",
                                                      step))
                continue

            # ---- guard --------------------------------------------------
            allowed, reason = self.guard.check(step)
            if not allowed:
                step.status = StepStatus.REFUSED
                step.refusal_reason = reason
                report.audit_log.append(
                    self._audit(f"refused by guard: {reason}", step))
                # If a containment step is refused, we cannot continue
                # safely with downstream eradication.
                if step.kind == StepKind.CONTAIN:
                    failed_hard = True
                    break
                continue

            # ---- execute (with retry) -----------------------------------
            self._invoke_with_retry(step)

            if step.status == StepStatus.FAILED:
                report.audit_log.append(
                    self._audit(f"failed: {step.error}", step))
                # Rollback completed steps (LIFO) if this step was
                # supposed to be contain / eradicate. Notify and
                # observe failures are recoverable.
                if step.kind in (StepKind.CONTAIN, StepKind.ERADICATE):
                    self._rollback(rollback_stack, report)
                    failed_hard = True
                    break
                continue

            # ---- post ---------------------------------------------------
            if not self._eval_conditions(step.post, phase="post",
                                          step=step, report=report):
                step.status = StepStatus.VERIFY_FAILED
                report.audit_log.append(
                    self._audit("post-condition failed", step))
                if step.kind in (StepKind.CONTAIN, StepKind.ERADICATE):
                    self._rollback([step] + rollback_stack, report)
                    failed_hard = True
                    break
                continue

            rollback_stack.insert(0, step)
            report.audit_log.append(self._audit("completed", step))

        report.finished_at = datetime.now()
        report.status = self._final_status(plan, failed_hard)
        report.summary = self._summary(plan, report)
        return report

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _invoke_with_retry(self, step: ActionStep) -> None:
        attempts = max(1, 1 + step.retries)
        for i in range(attempts):
            step.attempts = i + 1
            step.status = StepStatus.RUNNING
            step.started_at = datetime.now()
            result = self.registry.call(step.tool, step.params)
            step.finished_at = datetime.now()
            step.output = (result.payload or {}) | {
                "_status": result.status,
                "_real": result.invoked_real_tool,
            }
            if result.status in ("ok", "would-execute"):
                step.status = StepStatus.COMPLETED
                step.error = None
                return
            step.error = result.error or result.status
            # On retryable failure: small back-off then try again.
            if i < attempts - 1:
                import time
                time.sleep(0.2 * (i + 1))
        step.status = StepStatus.FAILED

    def _eval_conditions(self, conditions: list[Condition], phase: str,
                          step: ActionStep, report: ActionReport) -> bool:
        for c in conditions:
            if not self.registry.has(c.check_tool):
                report.audit_log.append({
                    "phase": phase,
                    "step_id": step.step_id,
                    "msg": f"condition tool '{c.check_tool}' not registered "
                            "— treated as PASS",
                })
                continue
            result = self.registry.call(c.check_tool, c.check_params)
            ok = self._condition_matches(c, result)
            report.audit_log.append({
                "phase": phase,
                "step_id": step.step_id,
                "condition": c.description,
                "tool": c.check_tool,
                "result_status": result.status,
                "passed": ok,
            })
            if not ok:
                return False
        return True

    @staticmethod
    def _condition_matches(c: Condition, result: ToolResult) -> bool:
        if c.expected_status is not None and result.status != c.expected_status:
            return False
        if c.expected_payload:
            for k, v in c.expected_payload.items():
                if result.payload.get(k) != v:
                    return False
        return result.status in ("ok", "would-execute")

    def _rollback(self, completed: list[ActionStep],
                   report: ActionReport) -> None:
        for done in completed:
            for rb in done.rollback_steps:
                rb_result = self.registry.call(rb.tool, rb.params)
                rb.status = (StepStatus.COMPLETED
                              if rb_result.status in ("ok", "would-execute")
                              else StepStatus.FAILED)
                report.audit_log.append({
                    "phase": "rollback",
                    "of_step_id": done.step_id,
                    "rollback_tool": rb.tool,
                    "status": rb_result.status,
                })
            done.status = StepStatus.ROLLED_BACK

    @staticmethod
    def _audit(msg: str, step: ActionStep) -> dict:
        return {
            "step_id": step.step_id,
            "tool": step.tool,
            "kind": step.kind.value,
            "status": step.status.value,
            "msg": msg,
            "attempts": step.attempts,
        }

    @staticmethod
    def _final_status(plan: ActionPlan, failed_hard: bool) -> PlanStatus:
        if failed_hard:
            return PlanStatus.FAILED
        statuses = [s.status for s in plan.steps]
        if all(s == StepStatus.COMPLETED for s in statuses):
            return PlanStatus.COMPLETED
        if any(s == StepStatus.COMPLETED for s in statuses):
            return PlanStatus.PARTIAL
        if any(s == StepStatus.REFUSED for s in statuses):
            return PlanStatus.REFUSED
        return PlanStatus.FAILED

    @staticmethod
    def _summary(plan: ActionPlan, report: ActionReport) -> str:
        tally = (
            f"{report.completed} completed · "
            f"{report.failed} failed · "
            f"{report.refused} refused · "
            f"{report.rolled_back} rolled-back · "
            f"{report.skipped} skipped"
        )
        return (f"[{report.status.value}] {tally}. "
                f"blast_radius={plan.blast_radius}; "
                f"assets={plan.asset_categories}.")
