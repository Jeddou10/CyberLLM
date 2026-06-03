"""Tests for SecurityGuard (paper 1) and EthicsGuard (attack side)."""

from __future__ import annotations

from agents.action_generator import Action
from agents.attack.attack_generator import AttackScript
from agents.attack.ethics_guard import EthicsGuard
from agents.base_agent import Input
from agents.decision_agent import Decision
from agents.security_guard import SecurityGuard


# ---------------------------------------------------------------------------
# SecurityGuard
# ---------------------------------------------------------------------------

class TestSecurityGuard:

    def _make_guard(self):
        return SecurityGuard(
            allowed_objectives=["produce defensive action",
                                "auto-correct insecure code",
                                "produce findings report"],
            authenticated_sources=["user", "rules_engine", "mcp_tool"],
            trusted_destinations=["findings_report", "audit_log"],
        )

    def _dummy_decision(self) -> Decision:
        return Decision(summary="", asset_categories_touched=[],
                        recommended_tier="moderate", confidence=0.7,
                        justification="ok", findings=[])

    def test_passes_when_all_four_properties_hold(self):
        g = self._make_guard()
        action = Action(kind="block_ip", target="suspect_source_ip",
                        parameters={}, rationale="",
                        originating_decision=self._dummy_decision())
        verdict = g.check(action, "produce defensive action",
                          [Input("hi", "user", "authenticated")])
        assert verdict.allowed
        assert (verdict.task_alignment and verdict.action_alignment
                and verdict.source_authorization and verdict.data_isolation)

    def test_task_alignment_violation(self):
        g = self._make_guard()
        action = Action(kind="block_ip", target="x", parameters={},
                        rationale="", originating_decision=self._dummy_decision())
        verdict = g.check(action, "this objective is not allowed",
                          [Input("hi", "user", "authenticated")])
        assert not verdict.allowed
        assert not verdict.task_alignment

    def test_action_alignment_violation(self):
        g = self._make_guard()
        # patch_code declared with a non-matching objective.
        action = Action(kind="patch_code", target="vulnerable_file",
                        parameters={}, rationale="",
                        originating_decision=self._dummy_decision())
        verdict = g.check(action, "produce defensive action",
                          [Input("hi", "user", "authenticated")])
        assert not verdict.allowed
        assert not verdict.action_alignment

    def test_source_authorization_violation_for_privileged_action(self):
        g = self._make_guard()
        action = Action(kind="isolate_node", target="affected_ECU",
                        parameters={}, rationale="",
                        originating_decision=self._dummy_decision())
        # No authenticated input among the inputs.
        verdict = g.check(action, "produce defensive action",
                          [Input("evil", "external_api", "external")])
        assert not verdict.allowed
        assert not verdict.source_authorization


# ---------------------------------------------------------------------------
# EthicsGuard
# ---------------------------------------------------------------------------

class TestEthicsGuard:

    def test_in_scope_scenario_and_target_pass(self):
        g = EthicsGuard(
            allowed_scenarios=["data exfiltration"],
            authorized_targets=["Privacy and Personal Data"],
            allow_all_in_dev=False,
        )
        v = g.check_plan("data exfiltration in scope",
                         "Privacy and Personal Data")
        assert v.allowed

    def test_out_of_scope_scenario_rejected(self):
        g = EthicsGuard(
            allowed_scenarios=["data exfiltration"],
            authorized_targets=["Privacy and Personal Data"],
            allow_all_in_dev=False,
        )
        v = g.check_plan("unrelated objective",
                         "Privacy and Personal Data")
        assert not v.allowed
        assert not v.scope_ok

    def test_out_of_scope_target_rejected(self):
        g = EthicsGuard(
            allowed_scenarios=["data exfiltration"],
            authorized_targets=["Privacy and Personal Data"],
            allow_all_in_dev=False,
        )
        v = g.check_plan("data exfiltration",
                         "Life and Bodily Health")  # not in authorized set
        assert not v.allowed
        assert not v.target_ok

    def test_allow_all_in_dev_short_circuits(self):
        g = EthicsGuard([], [], allow_all_in_dev=True)
        v = g.check_plan("anything goes", "Life and Bodily Health")
        assert v.allowed

    def test_cli_authorized_targets_are_honoured(self):
        g = EthicsGuard(
            allowed_scenarios=["x"],
            authorized_targets=[],
            allow_all_in_dev=False,
            cli_authorized_targets=["Life and Bodily Health"],
        )
        v = g.check_plan("x", "Life and Bodily Health")
        assert v.allowed

    def test_destructive_pattern_is_redacted(self):
        g = EthicsGuard([], ["*"], allow_all_in_dev=True)
        scripts = [
            AttackScript(rule_id="CODE-001", title="benign canary",
                         language="shell", body="touch /tmp/atk_canary",
                         target_hint="x", expected_effect="canary"),
            AttackScript(rule_id="ANY", title="DELETE EVERYTHING",
                         language="shell", body="rm -rf /",
                         target_hint="x", expected_effect="bad"),
        ]
        safe, redacted = g.filter_scripts(scripts)
        assert len(safe) == 2
        # The destructive one is rewritten to a stub.
        bad_in_safe = next(s for s in safe if s.rule_id == "ANY")
        assert "REDACTED" in bad_in_safe.title
        assert "REDACTED" in bad_in_safe.body
        assert "DELETE EVERYTHING" in redacted
