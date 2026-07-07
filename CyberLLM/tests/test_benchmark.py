"""Tests for the automotive security benchmark (server.run_benchmark + matching).

Run under the hermetic env from conftest (FORCE_STUB / NO_EXTERNAL_STATIC), so
"Fast" mode is deterministic: the offline stub is used and the external AST
layer is off, leaving the regex floor. Numbers are therefore stable.
"""

from __future__ import annotations

import server


# --------------------------------------------------------------------------
# manifest
# --------------------------------------------------------------------------

def test_manifest_shape():
    m = server.benchmark_manifest()
    assert m["total_vulns"] == 47
    assert len(m["files"]) == 11
    # C / C++ / Rust are all ingested now (scanner accepts .c/.cpp/.rs/…)
    not_ingested = [f for f in m["files"] if not f["ingested"] and not f["clean"]]
    assert not_ingested == []
    # two clean negative controls
    assert sum(1 for f in m["files"] if f["clean"]) == 2


def test_ground_truth_lines_in_range():
    """Every labelled line must exist inside its file (catches drift)."""
    gt = server._load_ground_truth()
    for f in gt["files"]:
        if f.get("clean"):
            continue
        n_lines = len((server.BENCH_DIR / f["path"]).read_text(
            encoding="utf-8").splitlines())
        for v in f["vulnerabilities"]:
            assert 1 <= v["line"] <= n_lines, f"{f['path']}:{v['line']} out of range"
            if "line_end" in v:
                assert v["line"] <= v["line_end"] <= n_lines


# --------------------------------------------------------------------------
# matching logic
# --------------------------------------------------------------------------

class TestMatch:
    def test_within_window_matches(self):
        gt = [{"line": 40, "severity": "high", "category": "memory-safety", "cwe": "CWE-787"}]
        findings = [{"line": 42, "rule_id": "CODE-X", "severity": "high"}]
        matched, extra = server._match_file(gt, findings, 3)
        assert matched[0]["detected"] is True
        assert matched[0]["matched"]["rule_id"] == "CODE-X"
        assert extra == []

    def test_outside_window_misses(self):
        gt = [{"line": 40, "severity": "high", "category": "x", "cwe": "Y"}]
        findings = [{"line": 50, "rule_id": "CODE-X", "severity": "high"}]
        matched, extra = server._match_file(gt, findings, 3)
        assert matched[0]["detected"] is False
        assert len(extra) == 1                 # the unmatched finding is "extra"

    def test_one_finding_matches_one_vuln(self):
        gt = [{"line": 40, "severity": "high", "category": "x", "cwe": "Y"},
              {"line": 41, "severity": "high", "category": "x", "cwe": "Z"}]
        findings = [{"line": 40, "rule_id": "R", "severity": "high"}]
        matched, _ = server._match_file(gt, findings, 3)
        # greedy one-to-one: exactly one of the two labels is covered
        assert sum(1 for m in matched if m["detected"]) == 1


# --------------------------------------------------------------------------
# full Fast run (deterministic)
# --------------------------------------------------------------------------

class TestRun:
    def test_fast_run_metrics(self):
        r = server.run_benchmark(deep=False)
        m = r["metrics"]
        assert r["ok"] is True and r["deep"] is False
        assert m["total_vulns"] == 47
        assert 0 <= m["covered"] <= 47
        assert m["covered"] + m["missed"] == 47
        # clean controls must stay clean → zero false positives, precision 1.0
        assert m["false_positives"] == 0
        assert m["precision"] == 1.0
        # Rust is now ingested; the native regex rules detect some of it
        # even in Fast (offline) mode.
        assert m["by_language"]["rust"]["total"] == 16
        assert m["by_language"]["rust"]["covered"] > 0

    def test_every_file_present_in_result(self):
        r = server.run_benchmark(deep=False)
        assert len(r["files"]) == 11
        clean = [f for f in r["files"] if f["clean"]]
        assert all(f["false_positives"] == 0 for f in clean)
