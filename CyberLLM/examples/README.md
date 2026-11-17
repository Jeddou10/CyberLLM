# Example inputs

These are synthetic analysis fixtures, including intentionally vulnerable source
code. Read them as test inputs; they are not deployable application templates.
The pipeline does not need their third-party application dependencies installed.

## Layout

| Path | Contents |
| --- | --- |
| `small/` | Five single-file examples, including a clean authentication control. |
| `medium/` | EV charging API and ADAS decision mini-projects. |
| `large/fleet_management/` | Multi-module fleet backend fixture. |
| `logs/` | Clean, brute-force, CAN injection, exfiltration, lateral movement, and DDoS logs. |
| `deployments/` | Clean, misconfigured cloud, and SDV actor/datasource topologies. |
| `attack_scenarios/` | Scenario text for attack-modeling runs. |
| `test_vulns/`, `test_blind/` | Additional source fixtures and blind-test expected findings. |
| `labels.yaml` | Ground truth for the static evaluation harness. |
| `scenarios.md` | Narrative scenario descriptions and expected findings. |
| `sample_*` | Original sample inputs retained for compatibility and CLI defaults. |

## Run

From `CyberLLM/`:

```bash
python pipeline.py --example small
python pipeline.py --mode both --example medium
python pipeline.py --code examples/test_blind/01_fleet_db_service.py
python evaluate.py
```

Use the [offline switches](../../docs/getting-started.md#deterministic-offline-runs)
to force deterministic local execution. CLI stub responses can contain canned
findings; use the static harness or Fast web scanning for detection measurements.

`run_examples.py` and `../run_blind_tests.py` are legacy helpers with known record
format mismatches. See [known limitations](../../docs/known-limitations.md).
The optional Juliet corpus is not included in this repository.
