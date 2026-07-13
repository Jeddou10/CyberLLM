"""Tests for the production-readiness upgrades:

- cross-session memory outcomes + recommend()
- decision-agent re-planning escalation + memory-recommendation nudge
- SecurityGuard.check_step (per-step contextual check, new step shape)
- LLM-as-tool-selector (validated, guarded)
- real MCP tools (dry-run envelopes + new engine tools)
"""

from __future__ import annotations

from types import SimpleNamespace

from agents.action_engine import (
    ActionGenerator, ActionStep, SideEffect, StepKind, default_toolset,
)
from agents.base_agent import Input
from agents.decision_agent import DecisionAgent
from agents.memory_store import Incident, MemoryStore
from agents.security_guard import SecurityGuard
from llm_client import LLMResponse


# ===========================================================================
# Cross-session memory: outcomes + recommend()
# ===========================================================================

class TestMemoryOutcomes:

    def _store(self, tmp_path):
        return MemoryStore(tmp_path / "incidents.db", "k",
                           ["user", "rules_engine", "mcp_tool"])

    def test_outcome_roundtrips_and_verifies(self, tmp_path):
        s = self._store(tmp_path)
        s.record(Incident(mode="defense", scenario="a", rule_ids=["CODE-001"],
                          tier="hard", action_kind="isolate_node",
                          guard_allowed=True, plan_status="completed",
                          remediation_ok=True, source="rules_engine"))
        assert s.verify_all()["n_rejected"] == 0
        hit = s.recall_similar(["CODE-001"])[0]
        assert hit.plan_status == "completed" and hit.remediation_ok is True

    def test_recommend_returns_worked_precedent(self, tmp_path):
        s = self._store(tmp_path)
        s.record(Incident(mode="defense", scenario="worked",
                          rule_ids=["CODE-001", "TOP-002"], tier="hard",
                          action_kind="isolate_node", guard_allowed=True,
                          plan_status="completed", remediation_ok=True,
                          source="rules_engine"))
        rec = s.recommend(["CODE-001", "TOP-002"], mode="defense")
        assert rec and rec["tier"] == "hard" and rec["scenario"] == "worked"

    def test_recommend_ignores_failed_precedent(self, tmp_path):
        s = self._store(tmp_path)
        s.record(Incident(mode="defense", scenario="failed",
                          rule_ids=["CODE-001"], tier="soft",
                          action_kind="rate_limit", guard_allowed=False,
                          plan_status="failed", remediation_ok=False,
                          source="rules_engine"))
        assert s.recommend(["CODE-001"], mode="defense") is None


# ===========================================================================
# Decision-agent re-planning + memory nudge
# ===========================================================================

def _stub_decision_agent(stub_llm, memory=None):
    return DecisionAgent("decision_agent",
                         {"objective": "decide", "response_tiers": {}},
                         stub_llm, memory=memory)


def _results(*rule_ids):
    from agents.base_agent import AgentResult, Finding
    findings = [Finding(rule_id=r, severity="high", evidence="x",
                        explanation="y", source_agent="t") for r in rule_ids]
    return [AgentResult("scanner", "obj", findings)]


class TestReplanningEscalation:

    def test_feedback_escalates_tier(self, stub_llm):
        agent = _stub_decision_agent(stub_llm)
        base = agent.run(_results("CODE-001"))           # stub → moderate
        feedback = {"prior_tier": base.recommended_tier,
                    "plan_status": "failed", "guard_allowed": False,
                    "reason": "guard refused"}
        escalated = agent.run(_results("CODE-001"), feedback=feedback)
        order = ["none", "soft", "moderate", "hard"]
        assert order.index(escalated.recommended_tier) > order.index(base.recommended_tier)

    def test_no_feedback_no_escalation(self, stub_llm):
        agent = _stub_decision_agent(stub_llm)
        d1 = agent.run(_results("CODE-001"))
        d2 = agent.run(_results("CODE-001"), feedback=None)
        assert d1.recommended_tier == d2.recommended_tier


class TestMemoryNudge:

    def test_recommendation_raises_tier(self, stub_llm, tmp_path):
        store = MemoryStore(tmp_path / "incidents.db", "k",
                            ["user", "rules_engine", "mcp_tool"])
        # A worked precedent at 'hard' for the same rule set.
        store.record(Incident(mode="defense", scenario="prev",
                              rule_ids=["CODE-001"], tier="hard",
                              action_kind="isolate_node", guard_allowed=True,
                              plan_status="completed", remediation_ok=True,
                              source="rules_engine"))
        agent = _stub_decision_agent(stub_llm, memory=store)
        d = agent.run(_results("CODE-001"), scenario_name="new")
        # stub LLM says 'moderate'; the worked 'hard' precedent escalates it.
        assert d.recommended_tier == "hard"
        assert agent.memory_recommendation is not None


# ===========================================================================
# Per-step contextual guard (new step shape)
# ===========================================================================

def _guard(ha_judge=None):
    return SecurityGuard(
        allowed_objectives=["produce defensive action",
                            "auto-correct insecure code",
                            "produce findings report"],
        authenticated_sources=["user", "rules_engine", "mcp_tool"],
        trusted_destinations=["findings_report", "audit_log"],
        ha_judge=ha_judge,
    )


def _step(tool, kind=StepKind.CONTAIN, side_effect=SideEffect.READ,
          requires_auth=False):
    return ActionStep(rule_id="R", kind=kind, tool=tool, params={},
                      description=tool, side_effect=side_effect,
                      requires_authorization=requires_auth)


class TestCheckStep:

    def test_destructive_step_needs_authenticated_source(self):
        g = _guard()
        step = _step("network.isolate_node", side_effect=SideEffect.DESTRUCTIVE)
        # only external inputs → privileged step refused
        v = g.check_step(step, "produce defensive action",
                         [Input("data", "log_file", "external")])
        assert not v.allowed and not v.source_authorization

    def test_destructive_step_ok_with_authenticated_source(self):
        g = _guard()
        step = _step("network.isolate_node", side_effect=SideEffect.DESTRUCTIVE)
        v = g.check_step(step, "produce defensive action",
                         [Input("op", "user", "authenticated")])
        assert v.allowed

    def test_read_step_not_privileged(self):
        g = _guard()
        step = _step("observe.endpoint", kind=StepKind.OBSERVE,
                     side_effect=SideEffect.READ)
        # observe.* maps to the 'alert_only' kind → a reporting objective.
        v = g.check_step(step, "produce findings report",
                         [Input("data", "log_file", "external")])
        # read-only step doesn't need an authenticated source
        assert v.source_authorization and v.allowed

    def test_ha_judge_can_refuse_step_via_context(self, stub_llm):
        from agents.ha_judge import HaJudge
        g = _guard(HaJudge(stub_llm))
        # A *privileged* block_ip step (requires authorisation) whose context
        # flags a trusted asset → the H_a oracle refuses it. (H_a is reserved
        # for privileged steps; benign steps pass on the deterministic floor.)
        step = _step("firewall.block_ipv4", side_effect=SideEffect.WRITE,
                     requires_auth=True)
        v = g.check_step(step, "produce defensive action",
                         [Input("op", "user", "authenticated")],
                         decision_summary="target is a trusted-asset internal node")
        assert not v.allowed and not v.action_alignment

    def test_ha_judge_not_consulted_for_benign_step(self):
        # A non-privileged defensive step passes without invoking H_a, even
        # when the context looks suspicious — the deterministic floor decides.
        from agents.ha_judge import HaJudge

        class _Boom(HaJudge):
            def __init__(self): pass
            def judges(self, *a, **k): raise AssertionError("H_a must not run here")
        g = _guard(_Boom())
        step = _step("code.propose_patch", kind=StepKind.ERADICATE,
                     side_effect=SideEffect.WRITE)
        v = g.check_step(step, "auto-correct insecure code",
                         [Input("op", "user", "authenticated")],
                         decision_summary="trusted-asset misaligned")
        assert v.allowed


# ===========================================================================
# LLM-as-tool-selector
# ===========================================================================

class _PickLLM:
    """Fake LLM that returns a tool-selection JSON."""
    def __init__(self, body):
        self.cfg = {}
        self._body = body
    def complete(self, prompt, system=None):
        return LLMResponse(text=self._body)


def _gen(llm):
    return ActionGenerator("action_generator",
                           {"objective": "act", "llm_tool_selection": True},
                           llm)


class TestLLMToolSelection:

    def test_valid_pick_is_appended(self):
        body = ('{"tools":[{"tool":"observe.endpoint","kind":"observe",'
                '"params":{"url":"http://x"},"why":"verify"}]}')
        gen = _gen(_PickLLM(body))
        steps = gen._llm_select_tools(SimpleNamespace(
            summary="s", recommended_tier="hard",
            asset_categories_touched=[], findings=[]))
        assert len(steps) == 1
        assert steps[0].tool == "observe.endpoint"
        assert steps[0].rule_id == "LLM-SELECTED"

    def test_unknown_tool_is_dropped(self):
        body = '{"tools":[{"tool":"does.not.exist","params":{}}]}'
        gen = _gen(_PickLLM(body))
        steps = gen._llm_select_tools(SimpleNamespace(
            summary="", recommended_tier="", asset_categories_touched=[],
            findings=[]))
        assert steps == []

    def test_schema_invalid_pick_is_dropped(self):
        # firewall.block_ipv4 requires an ipv4 → empty params fails validation
        body = '{"tools":[{"tool":"firewall.block_ipv4","params":{}}]}'
        gen = _gen(_PickLLM(body))
        steps = gen._llm_select_tools(SimpleNamespace(
            summary="", recommended_tier="", asset_categories_touched=[],
            findings=[]))
        assert steps == []

    def test_garbage_response_yields_no_picks(self, stub_llm):
        # the stub returns ACK… → no JSON → no picks (deterministic, offline)
        gen = _gen(stub_llm)
        steps = gen._llm_select_tools(SimpleNamespace(
            summary="", recommended_tier="", asset_categories_touched=[],
            findings=[]))
        assert steps == []


# ===========================================================================
# Real MCP tools (dry-run envelopes + new engine tools)
# ===========================================================================

class TestRealTools:

    def test_legacy_active_tools_default_dry_run(self):
        from tools.mcp_tools import TOOL_REGISTRY
        assert TOOL_REGISTRY["port_scan"].run(target="127.0.0.1")["dry_run"] is True
        assert TOOL_REGISTRY["packet_capture"].run()["dry_run"] is True

    def test_engine_has_new_real_tools(self):
        names = {t.name for t in default_toolset()}
        assert "network.port_scan" in names
        assert "observe.packet_capture" in names

    def test_port_scan_dry_run_via_registry(self):
        from agents.action_engine import MCPRegistry
        r = MCPRegistry(dry_run=True)
        r.register_many(default_toolset())
        res = r.call("network.port_scan", {"target": "127.0.0.1"})
        assert res.status == "would-execute"
        assert res.invoked_real_tool is False
