"""Tests for the external (bandit/semgrep) static-analysis layer.

The pure mapping functions are tested on synthetic tool JSON (no bandit /
semgrep binary required), and `scan_code_external` is checked to degrade
gracefully when no backend is installed.
"""

from __future__ import annotations

import tools.static_analyzer as SA
from tools.static_analyzer import (
    StaticFinding, bandit_results_to_findings, merge_static_layers,
    scan_code_external, semgrep_results_to_findings,
)


_RULES = {"code_rules": [
    {"id": "CODE-001", "severity": "high", "title": "Command injection sink",
     "asset_category": "Material and Economic Resources"},
    {"id": "CODE-003", "severity": "critical", "title": "Hard-coded secret",
     "asset_category": "Privacy and Personal Data"},
]}


class TestBanditMapping:

    def test_mapped_id_inherits_our_rule(self):
        results = [{"test_id": "B602", "issue_severity": "MEDIUM",
                    "issue_text": "subprocess shell=True",
                    "code": "subprocess.call(x, shell=True)", "line_number": 14}]
        out = bandit_results_to_findings(results, "x.py", _RULES)
        assert len(out) == 1
        f = out[0]
        assert f.rule_id == "CODE-001"           # B602 → CODE-001
        assert f.severity == "high"              # inherits our rule's severity
        assert f.source_agent == "bandit"
        assert f.asset_category == "Material and Economic Resources"
        assert f.line == 14 and f.evidence.startswith("x.py:")
        assert "[bandit B602]" in f.explanation

    def test_unmapped_id_kept_as_bandit_prefix(self):
        results = [{"test_id": "B999", "issue_severity": "LOW",
                    "issue_text": "something", "line_number": 3}]
        out = bandit_results_to_findings(results, "x.py", _RULES)
        assert out[0].rule_id == "BANDIT-B999"
        assert out[0].severity == "low"          # falls back to bandit's severity

    def test_hardcoded_secret_maps_to_code_003(self):
        results = [{"test_id": "B105", "issue_severity": "LOW",
                    "issue_text": "hardcoded password", "line_number": 8}]
        out = bandit_results_to_findings(results, "x.py", _RULES)
        assert out[0].rule_id == "CODE-003" and out[0].severity == "critical"


class TestSemgrepMapping:

    def test_maps_result(self):
        results = [{"check_id": "python.lang.security.audit.dangerous-eval",
                    "extra": {"severity": "ERROR", "message": "eval is dangerous",
                              "lines": "eval(payload)"},
                    "start": {"line": 5}}]
        out = semgrep_results_to_findings(results, "x.py")
        assert out[0].rule_id == "SEMGREP-dangerous-eval"
        assert out[0].severity == "high" and out[0].line == 5
        assert out[0].source_agent == "semgrep"


class TestMergeStaticLayers:

    def test_regex_wins_on_same_rule_and_line(self):
        regex = [StaticFinding("CODE-001", "high", "f.py: a", "e", "static_analyzer",
                               None, 14)]
        extra = [StaticFinding("CODE-001", "high", "f.py: b", "e", "bandit", None, 14),
                 StaticFinding("CODE-005", "critical", "f.py: c", "e", "bandit", None, 20)]
        merged = merge_static_layers(regex, extra)
        # the duplicate (CODE-001, line 14) from bandit is dropped; CODE-005 kept
        assert len(merged) == 2
        ids = {(f.rule_id, f.line) for f in merged}
        assert ("CODE-001", 14) in ids and ("CODE-005", 20) in ids
        # the kept CODE-001 is the regex one (source_analyzer), not bandit
        c1 = next(f for f in merged if f.rule_id == "CODE-001")
        assert c1.source_agent == "static_analyzer"


class TestGracefulFallback:

    def test_returns_empty_without_a_backend(self, monkeypatch):
        # simulate no backend at all: neither a binary on PATH nor an
        # importable module (bandit/semgrep may be pip-installed locally).
        monkeypatch.setattr(SA.shutil, "which", lambda *_: None)
        monkeypatch.setattr(SA.importlib.util, "find_spec", lambda *_: None)
        assert scan_code_external("import os\nos.system('x')\n", "x.py", _RULES) == []
