"""Tests for mandatory provenance (F.2) and delegation rules (F.5)."""

from __future__ import annotations

import pytest

from agents.base_agent import BaseAgent, Input, ProvenanceError


class TestProvenance:

    def test_valid_input_constructs(self):
        i = Input("data", "user", "authenticated")
        assert i.source == "user" and i.trust_level == "authenticated"

    def test_missing_source_rejected(self):
        with pytest.raises(ProvenanceError):
            Input("data", "", "authenticated")

    def test_blank_source_rejected(self):
        with pytest.raises(ProvenanceError):
            Input("data", "   ", "external")

    def test_invalid_trust_level_rejected(self):
        with pytest.raises(ProvenanceError):
            Input("data", "user", "totally-trusted")

    def test_all_lattice_levels_accepted(self):
        for tl in ("authenticated", "external", "tool", "memory"):
            assert Input("d", "src", tl).trust_level == tl


class _Dummy(BaseAgent):
    def run(self, inputs):           # pragma: no cover - not exercised
        return None


class TestDelegation:

    def _parent(self, stub_llm):
        p = _Dummy("parent", {"objective": "scan source code",
                              "trusted_sources": ["user", "rules_engine"]},
                   stub_llm)
        return p

    def test_child_inherits_objective(self, stub_llm):
        parent = self._parent(stub_llm)
        child = parent.delegate(_Dummy)
        assert child.objective == "scan source code"
        assert child.delegated_from == "parent"

    def test_child_does_not_inherit_source_set(self, stub_llm):
        parent = self._parent(stub_llm)
        assert parent.trusted_sources == {"user", "rules_engine"}
        child = parent.delegate(_Dummy)
        # The key paper-1 property: B does NOT inherit A's authority.
        assert child.trusted_sources == set()

    def test_explicit_grant_is_honoured(self, stub_llm):
        parent = self._parent(stub_llm)
        child = parent.delegate(_Dummy, grant_sources=["mcp_tool"])
        assert child.trusted_sources == {"mcp_tool"}
        assert "user" not in child.trusted_sources

    def test_child_objective_can_be_overridden(self, stub_llm):
        parent = self._parent(stub_llm)
        child = parent.delegate(_Dummy, child_cfg={"objective": "analyze logs"})
        assert child.objective == "analyze logs"
