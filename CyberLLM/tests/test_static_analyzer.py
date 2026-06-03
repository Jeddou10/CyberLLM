"""Unit tests for tools/static_analyzer.

The static analyzer is the deterministic floor of the system, so
these tests are the primary quality gate. Each test isolates one
detector and asserts both **detection** (the rule fires when it
should) and **specificity** (it does not fire on clean code).
"""

from __future__ import annotations

import pytest

from tools.static_analyzer import (
    merge_findings,
    scan_code_static,
    scan_deployment_static,
    scan_log_static,
    staticfinding_to_finding,
)
from agents.base_agent import Finding


# ---------------------------------------------------------------------------
# CODE-LEVEL RULES
# ---------------------------------------------------------------------------

class TestCodeStaticAnalyzer:
    """One assertion per CWE we expect to detect."""

    def test_shell_injection_is_caught(self, all_rules, vuln_snippets):
        hits = scan_code_static(vuln_snippets["CODE-001 shell injection"],
                                "x.py", all_rules)
        ids = {h.rule_id for h in hits}
        assert "CODE-001" in ids

    def test_md5_password_is_caught(self, all_rules, vuln_snippets):
        hits = scan_code_static(vuln_snippets["CODE-002 md5 password"],
                                "x.py", all_rules)
        assert "CODE-002" in {h.rule_id for h in hits}

    def test_hardcoded_api_key_is_caught(self, all_rules, vuln_snippets):
        hits = scan_code_static(vuln_snippets["CODE-003 hardcoded api key"],
                                "x.py", all_rules)
        assert "CODE-003" in {h.rule_id for h in hits}

    def test_pickle_loads_is_caught(self, all_rules, vuln_snippets):
        hits = scan_code_static(vuln_snippets["CODE-005 pickle.loads"],
                                "x.py", all_rules)
        assert "CODE-005" in {h.rule_id for h in hits}

    def test_verify_false_is_caught(self, all_rules, vuln_snippets):
        hits = scan_code_static(vuln_snippets["CODE-006 verify=False"],
                                "x.py", all_rules)
        assert "CODE-006" in {h.rule_id for h in hits}

    def test_sql_fstring_is_caught(self, all_rules, vuln_snippets):
        hits = scan_code_static(vuln_snippets["CODE-012 sql fstring"],
                                "x.py", all_rules)
        assert "CODE-012" in {h.rule_id for h in hits}

    def test_strcpy_in_c_is_caught(self, all_rules, vuln_snippets):
        hits = scan_code_static(vuln_snippets["CODE-013 strcpy C"],
                                "x.c", all_rules)
        assert "CODE-013" in {h.rule_id for h in hits}

    def test_jwt_none_is_caught(self, all_rules, vuln_snippets):
        hits = scan_code_static(vuln_snippets["CODE-020 jwt none"],
                                "x.py", all_rules)
        assert "CODE-020" in {h.rule_id for h in hits}

    def test_base64_eval_is_caught(self, all_rules, vuln_snippets):
        hits = scan_code_static(vuln_snippets["CODE-038 base64 eval"],
                                "x.py", all_rules)
        assert "CODE-038" in {h.rule_id for h in hits}

    @pytest.mark.parametrize("name", list({
        "argon2 clean", "subprocess argv list (safe)",
    }))
    def test_clean_snippets_dont_trigger_high_severity(
        self, all_rules, clean_snippets, name
    ):
        hits = scan_code_static(clean_snippets[name], "ok.py", all_rules)
        high_or_worse = [h for h in hits if h.severity in {"high", "critical"}]
        assert high_or_worse == [], \
            f"clean snippet {name!r} produced unexpected hits: {high_or_worse}"

    def test_findings_carry_line_numbers(self, all_rules, vuln_snippets):
        hits = scan_code_static(
            "# l1\n# l2\n" + vuln_snippets["CODE-001 shell injection"],
            "x.py", all_rules,
        )
        c1 = [h for h in hits if h.rule_id == "CODE-001"]
        assert c1, "CODE-001 must fire"
        assert c1[0].line and c1[0].line >= 3, \
            f"CODE-001 line should be >=3 (after the 2 prefix comments), got {c1[0].line}"


# ---------------------------------------------------------------------------
# LOG-LEVEL HEURISTICS
# ---------------------------------------------------------------------------

class TestLogStaticAnalyzer:

    def test_brute_force_detected(self, all_rules):
        # 12 failed-password lines within 12 seconds for root.
        lines = []
        for i in range(12):
            ts = f"2026-05-19T10:11:{i:02d}Z"
            lines.append(
                f"{ts} auth sshd[2020]: Failed password for root from "
                f"185.220.101.42 port 51234 ssh2"
            )
        hits = scan_log_static("\n".join(lines), all_rules)
        assert "LOG-AUTH-03" in {h.rule_id for h in hits}

    def test_brute_force_NOT_detected_below_threshold(self, all_rules):
        lines = [
            f"2026-05-19T10:11:{i:02d}Z auth sshd[2020]: "
            "Failed password for root from 1.2.3.4 port 51234 ssh2"
            for i in range(5)
        ]
        hits = scan_log_static("\n".join(lines), all_rules)
        assert "LOG-AUTH-03" not in {h.rule_id for h in hits}

    def test_broadcast_burst_detected(self, all_rules):
        line = ("2026-05-19T09:21:16Z net 10.0.0.42 -> 10.0.0.255 "
                "port 7000 rate=1218 pkts/s")
        hits = scan_log_static(line, all_rules)
        assert "LOG-NET-01" in {h.rule_id for h in hits}

    def test_can_injection_detected(self, all_rules):
        line = ("2026-05-19T13:42:14Z can0 frame arb=0x7E0 dlc=8 "
                "src=BodyCtrl anomaly=\"gateway-only id from non-gateway ECU\"")
        hits = scan_log_static(line, all_rules)
        assert "LOG-CAN-02" in {h.rule_id for h in hits}

    def test_dns_exfil_high_entropy_detected(self, all_rules):
        lines = "\n".join(
            f"2026-05-19T22:00:0{i}Z dns query name="
            f"{token}.exfil.example.com type=A qclass=IN src=10.0.4.18"
            for i, token in enumerate([
                "a3f5c1e9d4b7a6f2", "b9d4b7a6f2c8d0e4",
                "c7a9b1c3d8a3f5c1", "d4b7a6f2c8d0e4f7",
                "e7a9b1c3d8a3f5c1", "fa3f5c1e9d4b7a6f",
            ])
        )
        hits = scan_log_static(lines, all_rules)
        assert "LOG-EXFIL-01" in {h.rule_id for h in hits}

    def test_large_outbound_detected(self, all_rules):
        line = ("2026-05-19T22:00:13Z net 10.0.4.18 -> 185.220.101.42 "
                "port 443 bytes_out=12_582_912 duration=8s")
        hits = scan_log_static(line, all_rules)
        assert "LOG-EXFIL-02" in {h.rule_id for h in hits}

    def test_syn_flood_detected(self, all_rules):
        lines = "\n".join(
            "2026-05-19T03:14:0%dZ net inbound 1.2.3.4 syn-flood ack=0" % i
            for i in range(4)
        )
        hits = scan_log_static(lines, all_rules)
        assert "LOG-DDOS-01" in {h.rule_id for h in hits}

    def test_clean_log_has_no_findings(self, all_rules):
        clean = (
            "2026-05-19T08:00:01Z auth sshd[1019]: Accepted publickey for ops\n"
            "2026-05-19T08:01:00Z app  health-check ok\n"
        )
        hits = scan_log_static(clean, all_rules)
        assert hits == []


# ---------------------------------------------------------------------------
# DEPLOYMENT (TOPOLOGY) GRAPH CHECKS
# ---------------------------------------------------------------------------

class TestDeploymentStaticAnalyzer:

    def test_clean_topology_has_no_findings(self, all_rules,
                                             clean_deployment_yaml):
        hits = scan_deployment_static(clean_deployment_yaml, all_rules)
        assert hits == []

    def test_top001_hpc_to_zone_must_be_ethernet(self, all_rules,
                                                   bad_deployment_yaml):
        hits = scan_deployment_static(bad_deployment_yaml, all_rules)
        assert "TOP-001" in {h.rule_id for h in hits}

    def test_top002_external_write_to_memory(self, all_rules,
                                               bad_deployment_yaml):
        hits = scan_deployment_static(bad_deployment_yaml, all_rules)
        assert "TOP-002" in {h.rule_id for h in hits}

    def test_top005_db_bound_to_0_0_0_0(self, all_rules, bad_deployment_yaml):
        hits = scan_deployment_static(bad_deployment_yaml, all_rules)
        assert "TOP-005" in {h.rule_id for h in hits}

    def test_top006_world_readable_secrets(self, all_rules,
                                             bad_deployment_yaml):
        hits = scan_deployment_static(bad_deployment_yaml, all_rules)
        assert "TOP-006" in {h.rule_id for h in hits}

    def test_top008_external_a2a_respond(self, all_rules,
                                           bad_deployment_yaml):
        hits = scan_deployment_static(bad_deployment_yaml, all_rules)
        assert "TOP-008" in {h.rule_id for h in hits}

    def test_malformed_yaml_returns_empty_not_crash(self, all_rules):
        assert scan_deployment_static("this: [is not: valid", all_rules) == []


# ---------------------------------------------------------------------------
# MERGE / CONVERSION HELPERS
# ---------------------------------------------------------------------------

class TestMergeAndConvert:

    def test_merge_deduplicates_on_rule_id_and_evidence_prefix(self):
        from tools.static_analyzer import StaticFinding
        # merge_findings dedups on (rule_id, evidence[:40]) — give both
        # CODE-001 entries the same 40-char prefix so the dedup fires.
        shared_prefix = "x.py: subprocess.call(user_input, shell=Tr"  # 40+ chars
        a = StaticFinding(rule_id="CODE-001", severity="high",
                          evidence=shared_prefix + "ue) ## static",
                          explanation="static")
        b_dup = Finding(rule_id="CODE-001", severity="high",
                        evidence=shared_prefix + "ue) ## llm-duplicate",
                        explanation="llm", source_agent="llm")
        b_new = Finding(rule_id="CODE-002", severity="medium",
                        evidence="x.py: hashlib.md5(password)  ## new",
                        explanation="llm", source_agent="llm")
        out = merge_findings([a], [b_dup, b_new])
        ids = [getattr(f, "rule_id") for f in out]
        # static `a` survives; b_dup is dropped; b_new is appended.
        assert ids.count("CODE-001") == 1
        assert "CODE-002" in ids

    def test_staticfinding_to_finding_round_trip(self):
        from tools.static_analyzer import StaticFinding
        sf = StaticFinding(rule_id="CODE-001", severity="high",
                           evidence="e", explanation="ex",
                           asset_category="LBH", line=42)
        out = staticfinding_to_finding([sf], Finding)
        assert len(out) == 1
        assert out[0].rule_id == "CODE-001"
        assert out[0].line == 42
        assert out[0].asset_category == "LBH"
