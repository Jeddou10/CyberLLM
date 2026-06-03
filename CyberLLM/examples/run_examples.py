"""Batch runner — runs the pipeline on every story in scenarios.md
and prints a detection-rate / tier-accuracy table.

Usage:
    python examples/run_examples.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = Path(__file__).resolve().parent


# (story_name, code, log, deployment, expected_tier, expected_rule_ids)
STORIES = [
    ("bench:CAN-attack",
     "examples/small/02_can_gateway.py",
     "examples/logs/03_can_injection.log",
     "examples/deployments/03_complex_sdv.yaml",
     "hard",
     {"CODE-001", "CODE-003", "CODE-005", "CODE-006",
      "LOG-CAN-02", "TOP-001", "TOP-007"}),

    ("bench:OTA-supply-chain",
     "examples/small/03_ota_updater.py",
     "examples/logs/05_lateral_movement.log",
     "examples/deployments/02_misconfigured_cloud.yaml",
     "hard",
     {"CODE-007", "CODE-008", "CODE-010", "CODE-011",
      "LOG-LATERAL-01", "TOP-006"}),

    ("bench:exfil-via-api",
     "examples/medium/ev_charging_api/routes.py",
     "examples/logs/04_data_exfiltration.log",
     "examples/deployments/02_misconfigured_cloud.yaml",
     "hard",
     {"CODE-001", "CODE-005", "CODE-007", "CODE-025", "CODE-026",
      "LOG-EXFIL-01", "TOP-004", "TOP-005"}),

    ("bench:adas-tampering",
     "examples/medium/adas_decision/perception.py",
     "examples/logs/03_can_injection.log",
     "examples/deployments/03_complex_sdv.yaml",
     "hard",
     {"SAFE-002", "CODE-028", "LOG-CAN-02", "TOP-001", "TOP-007"}),

    ("bench:fleet-full",
     "examples/large/fleet_management/api/admin.py",
     "examples/logs/04_data_exfiltration.log",
     "examples/deployments/02_misconfigured_cloud.yaml",
     "hard",
     {"CODE-001", "CODE-026", "CODE-037",
      "LOG-EXFIL-01", "LOG-EXFIL-02", "TOP-006"}),

    ("bench:false-positive",
     "examples/small/01_clean_auth.py",
     "examples/logs/01_clean_baseline.log",
     "examples/deployments/01_clean_minimal.yaml",
     "none",
     set()),
]


def run_one(code: str, log: str, deployment: str) -> dict:
    cmd = [
        sys.executable, str(ROOT / "pipeline.py"),
        "--code", str(ROOT / code),
        "--log", str(ROOT / log),
        "--deployment", str(ROOT / deployment),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          cwd=str(ROOT), check=False)
    if proc.returncode != 0:
        return {"error": proc.stderr.strip() or proc.stdout.strip(),
                "raw_stdout": proc.stdout}
    record_path = ROOT / "memory" / "last_run.json"
    return json.loads(record_path.read_text(encoding="utf-8"))


def score(expected_ids: set[str], expected_tier: str, record: dict) -> dict:
    if "error" in record:
        return {"error": record["error"]}
    actual_ids = {f["rule_id"] for f in record.get("findings", [])}
    tier = record.get("decision", {}).get("recommended_tier", "none")

    matched = expected_ids & actual_ids
    missed = expected_ids - actual_ids
    extra = actual_ids - expected_ids

    detection = (len(matched) / len(expected_ids)) if expected_ids else 1.0
    fp_rate = (len(extra) / max(len(actual_ids), 1)) if expected_ids \
        else len(actual_ids)   # for false-positive story, raw count
    return {
        "actual_tier": tier,
        "tier_ok": tier == expected_tier,
        "detection_rate": detection,
        "fp_rate_or_count": fp_rate,
        "matched": sorted(matched),
        "missed": sorted(missed),
        "extra": sorted(extra),
        "decision_confidence": record.get("decision", {}).get("confidence", 0.0),
    }


def main() -> int:
    print(f"{'story':<28} {'tier':<8} {'tier_ok':<8} {'detection':<10} "
          f"{'fp':<8} {'conf':<6}")
    print("-" * 80)
    all_results = {}
    for name, code, log, dep, exp_tier, exp_ids in STORIES:
        record = run_one(code, log, dep)
        s = score(exp_ids, exp_tier, record)
        if "error" in s:
            print(f"{name:<28} ERROR: {s['error'][:100]}")
            continue
        det = f"{s['detection_rate']*100:.0f}%"
        fp = (f"{s['fp_rate_or_count']*100:.0f}%"
              if exp_ids else str(int(s['fp_rate_or_count'])))
        print(f"{name:<28} {s['actual_tier']:<8} {str(s['tier_ok']):<8} "
              f"{det:<10} {fp:<8} {s['decision_confidence']:.2f}")
        all_results[name] = s

    out = EXAMPLES / "last_batch_results.json"
    out.write_text(json.dumps(all_results, indent=2), encoding="utf-8")
    print(f"\nWrote detailed results to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
