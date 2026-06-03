"""End-to-end pipeline tests.

These spin up the *full* defense and attack pipelines on real example
files and assert structural invariants of the produced records.

They run in seconds against the stub LLM but exercise every agent,
every static analyzer pass, both guards, and the RunLogger.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import pipeline as pipeline_mod


# ---------------------------------------------------------------------------
# DEFENSE
# ---------------------------------------------------------------------------

class TestDefensePipeline:

    def test_defense_end_to_end_on_can_gateway(self, cfg, all_rules,
                                                tmp_path, monkeypatch):
        # Redirect run_logs + memory into tmp so we don't pollute the repo.
        monkeypatch.setattr(pipeline_mod, "RUN_LOGS_DIR", tmp_path / "run_logs")
        cfg = dict(cfg)
        cfg["paths"] = dict(cfg["paths"], memory_dir=str(tmp_path / "memory"))

        root = pipeline_mod.HERE
        code_paths = [root / "examples" / "small" / "02_can_gateway.py"]
        log_path = root / "examples" / "logs" / "03_can_injection.log"
        dep_path = root / "examples" / "deployments" / "03_complex_sdv.yaml"

        rec = pipeline_mod.run_defense_pipeline(
            code_paths, log_path, dep_path, cfg, all_rules,
            scenario_name="can_gateway_test", verbose=False,
        )

        # Required keys in the record.
        for k in ("mode", "scenario", "inputs", "decision", "action",
                  "guard_verdict", "findings", "committed", "run_log_dir"):
            assert k in rec, f"defense record missing key: {k}"

        # Static analyzer must surface at least these on this scenario.
        rule_ids = {f["rule_id"] for f in rec["findings"]}
        for must_have in {"CODE-005", "CODE-006", "TOP-001", "TOP-002", "LOG-CAN-02"}:
            assert must_have in rule_ids, \
                f"defense run is missing static hit {must_have} " \
                f"(got: {sorted(rule_ids)})"

        # SecurityGuard must produce a verdict shape.
        v = rec["guard_verdict"]
        for k in ("allowed", "task_alignment", "action_alignment",
                  "source_authorization", "data_isolation", "reason"):
            assert k in v

        # Per-step debug files are present in the run-log dir.
        log_dir = tmp_path / "run_logs"
        runs = list(log_dir.glob("*defense_can_gateway_test"))
        assert runs, "RunLogger directory was not created"
        files = {p.name for p in runs[0].iterdir() if p.is_file()}
        for expected in ("00_meta.json", "01_inputs.json",
                         "_trace.log", "_summary.md"):
            assert expected in files, \
                f"RunLogger missing {expected} (have: {sorted(files)})"

    def test_clean_inputs_should_not_trigger_high_severity_static(
        self, cfg, all_rules, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(pipeline_mod, "RUN_LOGS_DIR", tmp_path / "run_logs")
        cfg = dict(cfg)
        cfg["paths"] = dict(cfg["paths"], memory_dir=str(tmp_path / "memory"))

        root = pipeline_mod.HERE
        code_paths = [root / "examples" / "small" / "01_clean_auth.py"]
        log_path = root / "examples" / "logs" / "01_clean_baseline.log"
        dep_path = root / "examples" / "deployments" / "01_clean_minimal.yaml"

        rec = pipeline_mod.run_defense_pipeline(
            code_paths, log_path, dep_path, cfg, all_rules,
            scenario_name="clean_baseline_test", verbose=False,
        )

        # Static analyzer should be silent on clean inputs. The LLM stub
        # may produce some canned findings — we only assert that *static*
        # findings are absent.
        static_only = [f for f in rec["findings"]
                       if f.get("source_agent") == "static_analyzer"
                       or "static" in (f.get("source_agent") or "")]
        # Either no static hits, or none at high/critical severity.
        high = [f for f in static_only
                if f.get("severity") in {"high", "critical"}]
        assert high == [], f"clean inputs produced high-severity static hits: {high}"


# ---------------------------------------------------------------------------
# ATTACK
# ---------------------------------------------------------------------------

class TestAttackPipeline:

    def test_attack_end_to_end_on_brake_tampering(self, cfg, all_rules,
                                                    tmp_path, monkeypatch):
        monkeypatch.setattr(pipeline_mod, "RUN_LOGS_DIR", tmp_path / "run_logs")
        cfg = dict(cfg)
        cfg["paths"] = dict(cfg["paths"], memory_dir=str(tmp_path / "memory"))

        root = pipeline_mod.HERE
        code_paths = [root / "examples" / "small" / "02_can_gateway.py"]
        dep_path = root / "examples" / "deployments" / "03_complex_sdv.yaml"
        scenario_text = (root / "examples" / "attack_scenarios"
                         / "02_brake_tampering.txt").read_text(encoding="utf-8")

        rec = pipeline_mod.run_attack_pipeline(
            code_paths, dep_path, scenario_text, cfg, all_rules,
            scenario_name="brake_test", verbose=False,
        )

        for k in ("mode", "scenario", "system_instance", "plan",
                  "ethics_verdict", "scripts", "redacted", "run_log_dir"):
            assert k in rec

        # EthicsGuard should pass with allow_all_in_dev=true.
        assert rec["ethics_verdict"]["allowed"] is True

        # At least one script must be produced (ethics passed).
        assert rec["scripts"], "ethics passed but no scripts produced"

        # System instance must list the external actors from the YAML.
        assert "pirate_radio" in rec["system_instance"]["external_actors"] \
            or rec["system_instance"]["external_actors"], \
            "system_info_discovery did not enumerate external actors"

        # Run-log directory has the attack-specific files.
        log_dir = tmp_path / "run_logs"
        runs = list(log_dir.glob("*attack_brake_test"))
        assert runs
        files = {p.name for p in runs[0].iterdir() if p.is_file()}
        assert "_summary.md" in files
        # scripts/ subdir should exist with at least one script.
        scripts_dir = runs[0] / "scripts"
        assert scripts_dir.exists() and any(scripts_dir.iterdir())

    def test_ethics_guard_blocks_unauthorized_target(self, cfg, all_rules,
                                                      tmp_path, monkeypatch):
        monkeypatch.setattr(pipeline_mod, "RUN_LOGS_DIR", tmp_path / "run_logs")
        # Override the attack policy to a strict set with no wildcard.
        cfg = json_clone(cfg)
        cfg["attack"] = {
            "allow_all_in_dev": False,
            "allowed_scenarios": ["nothing matches"],
            "authorized_targets": ["completely-unrelated-target"],
        }
        cfg["paths"] = dict(cfg["paths"], memory_dir=str(tmp_path / "memory"))

        root = pipeline_mod.HERE
        code_paths = [root / "examples" / "small" / "02_can_gateway.py"]
        dep_path = root / "examples" / "deployments" / "03_complex_sdv.yaml"

        rec = pipeline_mod.run_attack_pipeline(
            code_paths, dep_path,
            "an out-of-scope objective",
            cfg, all_rules,
            scenario_name="blocked_test", verbose=False,
        )
        assert rec["ethics_verdict"]["allowed"] is False
        assert rec["scripts"] == []   # no scripts when ethics fails


def json_clone(obj):
    return json.loads(json.dumps(obj))
