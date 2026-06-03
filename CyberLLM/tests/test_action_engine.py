"""Tests for the action engine — MCP registry, playbooks, executor, generator.

These tests run entirely in dry-run mode (the default), so no real
side effects ever occur on the test machine.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from agents.action_engine import (
    ActionExecutor,
    ActionGenerator,
    ActionPlan,
    ActionStep,
    Condition,
    GuardAdapter,
    MCPRegistry,
    MCPSchemaField,
    MCPTool,
    PlanStatus,
    SideEffect,
    StepKind,
    StepStatus,
    ToolResult,
    build_plan,
    default_toolset,
    passthrough_guard,
)
from agents.base_agent import Finding


# ---------------------------------------------------------------------------
# Mock decision (minimal shape needed by build_plan)
# ---------------------------------------------------------------------------

@dataclass
class _Decision:
    summary: str
    asset_categories_touched: list[str]
    recommended_tier: str
    confidence: float
    justification: str
    findings: list[Finding]


def _finding(rule_id, severity="high", evidence="x.py: foo", line=10):
    return Finding(
        rule_id=rule_id, severity=severity, evidence=evidence,
        explanation=f"explanation for {rule_id}",
        source_agent="test", line=line,
    )


def _decision(*rule_ids, tier="moderate"):
    return _Decision(
        summary="test", asset_categories_touched=["Privacy and Personal Data"],
        recommended_tier=tier, confidence=0.72, justification="ok",
        findings=[_finding(r) for r in rule_ids],
    )


# ===========================================================================
# MCP registry / tools
# ===========================================================================

class TestMCPRegistry:

    def test_default_toolset_is_registered(self):
        r = MCPRegistry(dry_run=True)
        r.register_many(default_toolset())
        # Each domain must have at least one tool.
        domains = {r.get(n).domain for n in r.list_tools()}
        for d in ("firewall", "network", "secrets", "code",
                  "runtime", "notify", "observe", "kb"):
            assert d in domains, f"missing MCP domain: {d}"

    def test_unknown_tool_raises(self):
        r = MCPRegistry()
        with pytest.raises(KeyError):
            r.get("does.not.exist")

    def test_dry_run_does_not_invoke_real_binary(self):
        r = MCPRegistry(dry_run=True)
        r.register_many(default_toolset())
        res = r.call("firewall.block_ipv4", {"ipv4": "1.2.3.4"})
        assert res.status == "would-execute"
        assert res.invoked_real_tool is False
        # Audit trail records the call.
        assert any(a["tool"] == "firewall.block_ipv4" for a in r.audit)

    def test_validation_rejects_missing_required(self):
        r = MCPRegistry(dry_run=True)
        r.register_many(default_toolset())
        res = r.call("firewall.block_ipv4", {})        # no ipv4
        assert res.status == "failed"
        assert "ipv4" in (res.error or "")

    def test_validation_rejects_bad_enum(self):
        r = MCPRegistry(dry_run=True)
        r.register_many(default_toolset())
        res = r.call("notify.create_incident",
                     {"severity": "nope", "summary": "x"})
        assert res.status == "failed"
        assert "nope" in (res.error or "")

    def test_validation_rejects_bad_ipv4(self):
        r = MCPRegistry(dry_run=True)
        r.register_many(default_toolset())
        res = r.call("firewall.block_ipv4", {"ipv4": "not-an-ip"})
        assert res.status == "failed"

    def test_audit_redacts_obvious_secrets(self):
        r = MCPRegistry(dry_run=True)
        r.register_many(default_toolset())
        # Use an arbitrary tool; just need to push something through.
        r.call("notify.create_incident",
               {"severity": "high", "summary": "x",
                "evidence": "api_key=abc"})
        # Pass a synthetic params dict for audit visibility.
        # The audit call is internal — instead just check that
        # `_safe_for_audit` redacts when a 'password' key is passed.
        from agents.action_engine.mcp_registry import _safe_for_audit
        out = _safe_for_audit({"password": "topsecret", "ok": "fine"})
        assert out["password"] == "***redacted***"
        assert out["ok"] == "fine"


# ===========================================================================
# Playbooks / plan builder
# ===========================================================================

class TestPlanBuilder:

    def test_builds_empty_plan_from_no_findings(self):
        plan = build_plan(_decision())
        assert plan.steps == []

    def test_specific_playbook_fires_for_can_injection(self):
        plan = build_plan(_decision("LOG-CAN-02"))
        tools = [s.tool for s in plan.steps]
        # Containment first.
        assert "runtime.safe_mode" in tools
        assert "network.isolate_node" in tools
        # And a driver notification.
        assert "notify.driver" in tools

    def test_specific_playbook_fires_for_hardcoded_secret(self):
        plan = build_plan(_decision("CODE-003"))
        tools = [s.tool for s in plan.steps]
        assert "secrets.rotate" in tools
        assert "code.propose_patch" in tools
        assert "code.scrub_git_history" in tools

    def test_steps_are_ordered_contain_before_eradicate(self):
        plan = build_plan(_decision("LOG-AUTH-03"))
        kinds = [s.kind for s in plan.steps]
        contain = [i for i, k in enumerate(kinds) if k == StepKind.CONTAIN]
        eradicate = [i for i, k in enumerate(kinds) if k == StepKind.ERADICATE]
        notify = [i for i, k in enumerate(kinds) if k == StepKind.NOTIFY]
        if contain and eradicate:
            assert max(contain) < min(eradicate)
        if contain and notify:
            assert max(contain) < min(notify)

    def test_low_severity_findings_are_filtered_out(self):
        plan = build_plan(
            _Decision(summary="", asset_categories_touched=[],
                      recommended_tier="soft", confidence=0.1,
                      justification="",
                      findings=[_finding("CODE-001", severity="low")]))
        assert plan.steps == []

    def test_generic_fallback_for_unknown_rule_id(self):
        # An unknown CODE-XXX still gets the generic code playbook.
        plan = build_plan(_decision("CODE-9999"))
        tools = [s.tool for s in plan.steps]
        assert any(t == "code.propose_patch" for t in tools)

    def test_tier_fallback_when_no_specific_playbook(self):
        # Decision with only a finding whose severity is below medium
        # *and* recommended_tier=hard — should still produce a hard
        # generic step.
        plan = build_plan(
            _Decision(summary="", asset_categories_touched=[],
                      recommended_tier="hard", confidence=0.95,
                      justification="",
                      findings=[_finding("UNKNOWN-1", severity="medium")]))
        # 'UNKNOWN-1' does not match CODE/LOG/TOP prefix → tier fallback fires.
        assert any(s.kind == StepKind.CONTAIN for s in plan.steps)


# ===========================================================================
# Executor
# ===========================================================================

class _AlwaysOK(MCPTool):
    name = "test.ok"
    description = "always succeeds"
    side_effect = SideEffect.READ
    schema: list[MCPSchemaField] = []
    def _do_call(self, params): return ToolResult(status="ok", tool=self.name,
                                                   payload={})
    def _dry_run(self, params): return ToolResult(status="ok", tool=self.name,
                                                   payload={})


class _AlwaysFail(MCPTool):
    name = "test.fail"
    description = "always fails"
    side_effect = SideEffect.WRITE
    schema: list[MCPSchemaField] = []
    def _do_call(self, params): return ToolResult(status="failed",
                                                   tool=self.name,
                                                   error="boom")
    def _dry_run(self, params): return ToolResult(status="failed",
                                                   tool=self.name,
                                                   error="boom")


class _RollbackTool(MCPTool):
    name = "test.rollback"
    description = "rollback target"
    side_effect = SideEffect.READ
    schema: list[MCPSchemaField] = []
    def _do_call(self, params): return ToolResult(status="ok", tool=self.name,
                                                   payload={"rolled": True})
    def _dry_run(self, params): return ToolResult(status="ok", tool=self.name,
                                                   payload={"rolled": True})


class TestExecutor:

    def _registry(self):
        r = MCPRegistry(dry_run=False)
        r.register(_AlwaysOK())
        r.register(_AlwaysFail())
        r.register(_RollbackTool())
        return r

    def test_executes_simple_plan(self):
        r = self._registry()
        ex = ActionExecutor(r)
        plan = ActionPlan(plan_id="p1", decision_summary="", blast_radius="local",
                          asset_categories=[],
                          steps=[ActionStep(rule_id="R", kind=StepKind.NOTIFY,
                                             tool="test.ok", params={},
                                             description="step 1")])
        report = ex.execute(plan)
        assert report.status == PlanStatus.COMPLETED
        assert report.completed == 1

    def test_hard_failure_in_contain_stops_plan(self):
        r = self._registry()
        ex = ActionExecutor(r)
        plan = ActionPlan(plan_id="p2", decision_summary="", blast_radius="local",
                          asset_categories=[],
                          steps=[
                              ActionStep(rule_id="R", kind=StepKind.CONTAIN,
                                          tool="test.fail", params={},
                                          description="must-stop", retries=0),
                              ActionStep(rule_id="R", kind=StepKind.NOTIFY,
                                          tool="test.ok", params={},
                                          description="never runs"),
                          ])
        report = ex.execute(plan)
        assert report.status == PlanStatus.FAILED
        # Second step never runs.
        assert plan.steps[1].status == StepStatus.PENDING

    def test_guard_refusal_on_contain_stops_plan(self):
        r = self._registry()
        def deny(step):
            return False, f"refused {step.tool}"
        ex = ActionExecutor(r, guard=GuardAdapter(fn=deny))
        plan = ActionPlan(plan_id="p3", decision_summary="", blast_radius="local",
                          asset_categories=[],
                          steps=[ActionStep(rule_id="R", kind=StepKind.CONTAIN,
                                             tool="test.ok", params={},
                                             description="will be refused")])
        report = ex.execute(plan)
        assert report.refused == 1
        assert report.status == PlanStatus.FAILED

    def test_rollback_runs_on_post_failure(self):
        # A pre-condition that always passes, a step that succeeds,
        # then a post-condition that fails — should roll back.
        r = self._registry()
        ex = ActionExecutor(r)
        rollback = ActionStep(rule_id="R", kind=StepKind.NOTIFY,
                               tool="test.rollback", params={},
                               description="undo")
        bad_post = Condition(description="impossible",
                              check_tool="test.fail",
                              check_params={})
        plan = ActionPlan(plan_id="p4", decision_summary="",
                          blast_radius="service", asset_categories=[],
                          steps=[ActionStep(
                              rule_id="R", kind=StepKind.ERADICATE,
                              tool="test.ok", params={},
                              description="erase", retries=0,
                              post=[bad_post],
                              rollback_steps=[rollback],
                          )])
        report = ex.execute(plan)
        assert report.status == PlanStatus.FAILED
        assert plan.steps[0].status == StepStatus.ROLLED_BACK


# ===========================================================================
# Public ActionGenerator
# ===========================================================================

class TestActionGenerator:

    def test_generate_returns_legacy_action(self, stub_llm):
        d = _decision("LOG-CAN-02")
        gen = ActionGenerator("action_generator",
                               {"objective": "produce defensive action"},
                               stub_llm)
        action = gen.generate(d, vulnerable_code="print('hi')")
        # Legacy fields present.
        assert action.kind
        assert action.target is not None
        assert isinstance(action.parameters, dict)
        # New fields present.
        assert action.plan_id
        assert isinstance(action.report, dict)
        assert "tallies" in action.report

    def test_generate_works_with_no_findings(self, stub_llm):
        d = _decision()
        gen = ActionGenerator("action_generator",
                               {"objective": "produce defensive action"},
                               stub_llm)
        action = gen.generate(d)
        assert action.kind == "noop"

    def test_dry_run_default_does_no_real_side_effects(self, stub_llm):
        d = _decision("CODE-003")
        gen = ActionGenerator("action_generator",
                               {"objective": "produce defensive action"},
                               stub_llm)
        gen.generate(d)
        # Every MCP audit entry should mark dry_run=True.
        for a in gen.registry.audit:
            assert a["dry_run"] is True
