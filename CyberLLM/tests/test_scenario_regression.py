"""Scenario-level regression test.

For each (code, log, deployment) triple defined here, we run the
defense pipeline and assert the **must-have** rule_ids are present.
These are the ground-truth labels you'd want a real LLM to also
satisfy. The static analyzer floor alone is enough to make them pass.

If this file ever goes red, it usually means a rule regex broke, a
YAML rule was removed, or a scanner stopped propagating findings.
"""

from __future__ import annotations

import pytest

import pipeline as pipeline_mod


# ---------------------------------------------------------------------------
# Ground truth — only the deterministic must-haves, not the full label set.
# Severity ordering: criticals first; we don't list LLM-only findings here.
# ---------------------------------------------------------------------------

SCENARIOS = [
    # (name, code, log, deployment, must_have_rule_ids)
    (
        "can_gateway",
        "examples/small/02_can_gateway.py",
        "examples/logs/03_can_injection.log",
        "examples/deployments/03_complex_sdv.yaml",
        {"CODE-005", "CODE-006", "TOP-001", "TOP-002", "LOG-CAN-02"},
    ),
    (
        "ota_updater",
        "examples/small/03_ota_updater.py",
        "examples/logs/05_lateral_movement.log",
        "examples/deployments/02_misconfigured_cloud.yaml",
        {"CODE-010", "TOP-005", "TOP-006"},
    ),
    (
        "telemetry_uploader",
        "examples/small/04_telemetry_uploader.py",
        "examples/logs/04_data_exfiltration.log",
        "examples/deployments/02_misconfigured_cloud.yaml",
        {"CODE-003", "CODE-006", "CODE-012",
         "LOG-EXFIL-01", "LOG-EXFIL-02"},
    ),
    (
        "mqtt_handler",
        "examples/small/05_mqtt_handler.c",
        "examples/logs/02_brute_force_ssh.log",
        "examples/deployments/03_complex_sdv.yaml",
        {"CODE-013", "TOP-001", "TOP-002", "LOG-AUTH-03"},
    ),
    (
        "ev_charging_api",
        "examples/medium/ev_charging_api",
        "examples/logs/04_data_exfiltration.log",
        "examples/deployments/02_misconfigured_cloud.yaml",
        {"CODE-003", "CODE-012", "TOP-005", "TOP-006",
         "LOG-EXFIL-01", "LOG-EXFIL-02"},
    ),
]


@pytest.mark.parametrize("name,code,log,dep,must_have", SCENARIOS,
                          ids=[s[0] for s in SCENARIOS])
def test_defense_detects_must_have_rules(
    name, code, log, dep, must_have, cfg, all_rules,
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(pipeline_mod, "RUN_LOGS_DIR", tmp_path / "run_logs")
    cfg = dict(cfg)
    cfg["paths"] = dict(cfg["paths"], memory_dir=str(tmp_path / "memory"))

    root = pipeline_mod.HERE
    code_path = root / code
    code_paths = (
        sorted(code_path.rglob("*.py")) + sorted(code_path.rglob("*.c"))
        if code_path.is_dir() else [code_path]
    )

    rec = pipeline_mod.run_defense_pipeline(
        code_paths,
        root / log,
        root / dep,
        cfg, all_rules,
        scenario_name=f"regression_{name}",
        verbose=False,
    )

    seen = {f["rule_id"] for f in rec["findings"]}
    missing = must_have - seen
    assert not missing, (
        f"[{name}] defense missed {missing}\n"
        f"  must-have: {sorted(must_have)}\n"
        f"  seen:      {sorted(seen)}"
    )
