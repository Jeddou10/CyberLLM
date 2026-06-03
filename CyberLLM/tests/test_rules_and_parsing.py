"""Tests for rule loading, prompt templating, and JSON-findings parsing."""

from __future__ import annotations

import pytest


class TestRulesLoading:

    def test_all_expected_families_present(self, all_rules):
        for family in ("code_rules", "log_rules", "topology_rules",
                       "safety_rules", "attack_rules"):
            assert family in all_rules, f"missing family: {family}"
            assert isinstance(all_rules[family], list), \
                f"{family} should be a list"
            assert all_rules[family], f"{family} is empty"

    def test_every_rule_has_required_fields(self, all_rules):
        for family, items in all_rules.items():
            for r in items:
                assert "id" in r, f"{family}: rule missing id: {r}"
                assert "severity" in r, f"{family}/{r['id']}: missing severity"
                assert "title" in r, f"{family}/{r['id']}: missing title"

    def test_rule_ids_are_unique_within_a_family(self, all_rules):
        for family, items in all_rules.items():
            ids = [r["id"] for r in items]
            dupes = {x for x in ids if ids.count(x) > 1}
            assert not dupes, f"{family} has duplicate ids: {dupes}"

    def test_code_rule_patterns_are_valid_regex(self, all_rules):
        import re
        for r in all_rules["code_rules"]:
            if "pattern" in r:
                # If this raises, the rule has a broken regex.
                re.compile(r["pattern"])


class TestBaseAgentTemplate:

    def test_placeholder_substitution(self, stub_llm):
        from agents.base_agent import BaseAgent

        class Dummy(BaseAgent):
            def run(self, inputs):
                ...

        a = Dummy("dummy", {"objective": "o"}, stub_llm)
        a.data = {"x": "hello", "y": 42}
        rendered = a.template("a=[x] b=[y] c=[missing]")
        assert rendered == "a=hello b=42 c="

    def test_template_supports_nested_keys(self, stub_llm):
        from agents.base_agent import BaseAgent

        class Dummy(BaseAgent):
            def run(self, inputs):
                ...

        a = Dummy("dummy", {"objective": "o"}, stub_llm)
        a.data = {"answers/A": "HTTP"}
        assert a.template("[answers/A]") == "HTTP"


class TestFindingsParsing:

    def test_parses_well_formed_json(self, stub_llm):
        from agents.base_agent import BaseAgent
        class Dummy(BaseAgent):
            def run(self, inputs): ...
        a = Dummy("dummy", {"objective": "o"}, stub_llm)
        text = (
            '{"findings": [{"rule_id": "CODE-001", "severity": "high", '
            '"evidence": "x", "explanation": "y", "line": 7}]}'
        )
        out = a._parse_findings(text)
        assert len(out) == 1
        assert out[0].rule_id == "CODE-001"
        assert out[0].line == 7
        assert out[0].source_agent == "dummy"

    def test_strips_markdown_fence(self, stub_llm):
        from agents.base_agent import BaseAgent
        class Dummy(BaseAgent):
            def run(self, inputs): ...
        a = Dummy("dummy", {"objective": "o"}, stub_llm)
        text = "```json\n{\"findings\": [{\"rule_id\":\"X\",\"severity\":\"low\",\"evidence\":\"e\",\"explanation\":\"x\"}]}\n```"
        out = a._parse_findings(text)
        assert len(out) == 1 and out[0].rule_id == "X"

    def test_malformed_json_returns_empty_list(self, stub_llm):
        from agents.base_agent import BaseAgent
        class Dummy(BaseAgent):
            def run(self, inputs): ...
        a = Dummy("dummy", {"objective": "o"}, stub_llm)
        assert a._parse_findings("not json at all") == []

    def test_missing_findings_key_returns_empty(self, stub_llm):
        from agents.base_agent import BaseAgent
        class Dummy(BaseAgent):
            def run(self, inputs): ...
        a = Dummy("dummy", {"objective": "o"}, stub_llm)
        assert a._parse_findings('{"other_key": []}') == []
