"""Tests for the H_a judge (F.1) and trajectory checks (F.3 + F.4)."""

from __future__ import annotations

from agents.action_engine import ActionPlan, ActionStep, Condition, SideEffect, StepKind
from agents.action_generator import Action
from agents.base_agent import Input
from agents.decision_agent import Decision
from agents.ha_judge import HaJudge
from agents.security_guard import SecurityGuard


def _guard(ha_judge=None):
    return SecurityGuard(
        allowed_objectives=["produce defensive action",
                            "auto-correct insecure code",
                            "produce findings report"],
        authenticated_sources=["user", "rules_engine", "mcp_tool"],
        trusted_destinations=["findings_report", "audit_log"],
        ha_judge=ha_judge,
    )


def _action(kind="block_ip", target="suspect_source_ip"):
    return Action(kind=kind, target=target, parameters={}, rationale="",
                  originating_decision=Decision("", [], "moderate", 0.7, "", []))


class TestHaJudge:

    def test_privileged_under_report_only_is_refused(self, stub_llm):
        j = HaJudge(stub_llm)
        serves, reason = j.judges("isolate_node", "produce findings report")
        assert serves is False and "report-only" in reason

    def test_passive_action_under_report_only_is_fine(self, stub_llm):
        j = HaJudge(stub_llm)
        serves, _ = j.judges("alert_only", "produce findings report")
        assert serves is True

    def test_aligned_action_passes(self, stub_llm):
        j = HaJudge(stub_llm)
        serves, _ = j.judges("isolate_node", "produce defensive action")
        assert serves is True

    def test_context_can_force_refusal(self, stub_llm):
        j = HaJudge(stub_llm)
        serves, _ = j.judges("block_ip", "produce defensive action",
                             context="the target is a trusted-asset")
        assert serves is False


class TestGuardWithJudge:
    """The judge can only TIGHTEN — it never loosens the static floor."""

    def test_judge_does_not_loosen(self, stub_llm):
        # patch_code + 'produce defensive action' is incompatible per the
        # static map; the judge cannot rescue it.
        g = _guard(HaJudge(stub_llm))
        v = g.check(_action(kind="patch_code"), "produce defensive action",
                    [Input("hi", "user", "authenticated")])
        assert not v.allowed and not v.action_alignment

    def test_judge_tightens_on_context(self, stub_llm):
        g = _guard(HaJudge(stub_llm))
        v = g.check(_action(kind="block_ip"), "produce defensive action",
                    [Input("hi", "user", "authenticated")],
                    context="target is a trusted-asset internal node")
        assert not v.allowed and not v.action_alignment
        assert "H_a judge refused" in v.reason

    def test_without_judge_same_action_passes(self):
        g = _guard(ha_judge=None)
        v = g.check(_action(kind="block_ip"), "produce defensive action",
                    [Input("hi", "user", "authenticated")])
        assert v.allowed


def _step(tool, kind, side_effect=SideEffect.READ, pre=None, post=None):
    return ActionStep(rule_id="R", kind=kind, tool=tool, params={},
                      description=tool, side_effect=side_effect,
                      pre=pre or [], post=post or [])


class TestTrajectory:

    def test_clean_plan_is_allowed(self):
        g = _guard()
        steps = [
            _step("network.isolate_node", StepKind.CONTAIN,
                  SideEffect.DESTRUCTIVE,
                  post=[Condition("verify", "observe.port_closed", {})]),
            _step("runtime.snapshot", StepKind.OBSERVE, SideEffect.WRITE),
            _step("notify.driver", StepKind.NOTIFY, SideEffect.WRITE),
        ]
        v = g.check_trajectory(steps)
        assert v.allowed and v.compositional_ok and v.temporal_ok

    def test_exfil_composition_flagged(self):
        g = _guard()
        steps = [
            _step("observe.log_tail", StepKind.OBSERVE, SideEffect.READ),
            _step("notify.webhook", StepKind.NOTIFY, SideEffect.WRITE),
        ]
        v = g.check_trajectory(steps)
        assert not v.compositional_ok
        assert any("exfil" in x for x in v.violations)

    def test_destructive_without_forensics_or_notify_flagged(self):
        g = _guard()
        steps = [_step("secrets.revoke", StepKind.ERADICATE,
                       SideEffect.DESTRUCTIVE)]
        v = g.check_trajectory(steps)
        assert not v.compositional_ok
        assert any("forensic" in x for x in v.violations)
        assert any("notify" in x for x in v.violations)

    def test_toctou_flagged_when_pre_without_post(self):
        g = _guard()
        steps = [
            _step("network.isolate_node", StepKind.CONTAIN,
                  SideEffect.DESTRUCTIVE,
                  pre=[Condition("reachable", "observe.endpoint", {})]),
            _step("notify.driver", StepKind.NOTIFY, SideEffect.WRITE),
            _step("runtime.snapshot", StepKind.OBSERVE, SideEffect.WRITE),
        ]
        v = g.check_trajectory(steps)
        assert not v.temporal_ok
        assert any("TOCTOU" in x for x in v.violations)

    def test_memory_poisoning_temporal_flagged(self):
        g = _guard()
        steps = [
            _step("network.isolate_node", StepKind.CONTAIN,
                  SideEffect.DESTRUCTIVE,
                  post=[Condition("v", "observe.port_closed", {})]),
            _step("notify.driver", StepKind.NOTIFY, SideEffect.WRITE),
            _step("runtime.snapshot", StepKind.OBSERVE, SideEffect.WRITE),
        ]
        memory_input = [Input("recalled rule", "long_term_memory", "memory")]
        v = g.check_trajectory(steps, memory_input)
        assert not v.temporal_ok
        assert any("memory-poisoning" in x for x in v.violations)
