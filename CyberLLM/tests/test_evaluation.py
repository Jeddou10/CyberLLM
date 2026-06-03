"""Tests for the static evaluation harness (D.4 / D.5 / G.4)."""

from __future__ import annotations

import yaml

import evaluate as ev
from pipeline import _norm, load_config, load_rules


def _labels():
    with open(_norm("examples/labels.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


class TestMappings:

    def test_property_for_known_and_default(self):
        assert ev.property_for("TOP-002") == "source_authorization"
        assert ev.property_for("CODE-999") == "action_alignment"
        assert ev.property_for("LOG-NET-01") == "task_alignment"

    def test_tier_for_severity(self):
        assert ev.tier_for_severity("critical") == "hard"
        assert ev.tier_for_severity("high") == "hard"
        assert ev.tier_for_severity("medium") == "moderate"
        assert ev.tier_for_severity("low") == "soft"

    def test_skills_for_tier_nonempty(self):
        assert ev.skills_for_tier("hard")
        assert ev.skills_for_tier("soft")


class TestEvaluate:

    def test_static_recall_is_perfect_on_labelled_corpus(self):
        cfg = load_config()
        rules = load_rules(cfg)
        report = ev.evaluate(cfg, rules, _labels())
        agg = report["aggregate"]
        # The static floor must detect every labelled must-have rule —
        # this mirrors tests/test_scenario_regression.py.
        assert agg["overall_recall"] == 1.0
        assert agg["expected_total"] > 0

    def test_no_false_positives_on_clean_controls(self):
        cfg = load_config()
        rules = load_rules(cfg)
        report = ev.evaluate(cfg, rules, _labels())
        assert report["aggregate"]["false_positive_findings"] == 0
        assert report["aggregate"]["clean_scenarios"] >= 1

    def test_property_and_scoreboard_populated(self):
        cfg = load_config()
        rules = load_rules(cfg)
        report = ev.evaluate(cfg, rules, _labels())
        assert report["properties"], "property-violation table is empty"
        assert report["scoreboard"], "scoreboard is empty"
        # Every property row names one of the paper-1 four properties.
        props = {r["property_violated"] for r in report["properties"]}
        assert props <= {"task_alignment", "action_alignment",
                         "source_authorization", "data_isolation"}

    def test_mttd_marked_not_applicable(self):
        cfg = load_config()
        rules = load_rules(cfg)
        report = ev.evaluate(cfg, rules, _labels())
        assert "N/A" in report["aggregate"]["mttd_note"]

    def test_markdown_renders(self):
        cfg = load_config()
        rules = load_rules(cfg)
        report = ev.evaluate(cfg, rules, _labels())
        md = ev.render_markdown(report)
        assert "# CyberLLM — static evaluation report" in md
        assert "Detection rate per scenario" in md
