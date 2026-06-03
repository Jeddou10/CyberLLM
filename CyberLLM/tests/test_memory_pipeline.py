"""Integration test: the adaptive memory loop closes (E.2) in the pipeline.

Run the defense pipeline twice (same inputs, different scenario names) and
confirm the second run recalls the first from the signed store, and that
each run records its own outcome.
"""

from __future__ import annotations

import pipeline as pipeline_mod


def _run(cfg, all_rules, tmp_path, monkeypatch, name):
    monkeypatch.setattr(pipeline_mod, "RUN_LOGS_DIR", tmp_path / "run_logs")
    cfg = dict(cfg)
    cfg["paths"] = dict(cfg["paths"], memory_dir=str(tmp_path / "memory"))
    root = pipeline_mod.HERE
    return pipeline_mod.run_defense_pipeline(
        [root / "examples" / "small" / "02_can_gateway.py"],
        root / "examples" / "logs" / "03_can_injection.log",
        root / "examples" / "deployments" / "03_complex_sdv.yaml",
        cfg, all_rules, scenario_name=name, verbose=False,
    )


def test_memory_loop_recalls_prior_run(cfg, all_rules, tmp_path, monkeypatch):
    rec1 = _run(cfg, all_rules, tmp_path, monkeypatch, "mem_run_1")
    rec2 = _run(cfg, all_rules, tmp_path, monkeypatch, "mem_run_2")

    # Both runs persisted a signed incident.
    assert rec1["memory_recorded"] is True
    assert rec2["memory_recorded"] is True

    # The first run had an empty store → nothing to recall.
    assert rec1["consulted_memory"] == []

    # The second run recalled the first (same rules, different scenario name).
    assert rec2["consulted_memory"], "second run did not recall the first"
    recalled = {c["scenario"] for c in rec2["consulted_memory"]}
    assert "mem_run_1" in recalled
    assert all(c["similarity"] > 0 for c in rec2["consulted_memory"])


def test_memory_can_be_disabled(cfg, all_rules, tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline_mod, "RUN_LOGS_DIR", tmp_path / "run_logs")
    cfg = dict(cfg)
    cfg["paths"] = dict(cfg["paths"], memory_dir=str(tmp_path / "memory"))
    cfg["memory"] = dict(cfg.get("memory", {}), enabled=False)
    root = pipeline_mod.HERE
    rec = pipeline_mod.run_defense_pipeline(
        [root / "examples" / "small" / "02_can_gateway.py"],
        root / "examples" / "logs" / "03_can_injection.log",
        root / "examples" / "deployments" / "03_complex_sdv.yaml",
        cfg, all_rules, scenario_name="no_mem", verbose=False,
    )
    # With memory off the pipeline still runs and records nothing.
    assert rec["memory_recorded"] is False
    assert rec["consulted_memory"] == []
    assert not (tmp_path / "memory" / "incidents.db").exists()
