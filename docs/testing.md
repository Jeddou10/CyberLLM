# Testing

From the repository root, with the virtual environment active:

```bash
python -m pip install -r requirements-dev.txt
python CyberLLM/verify.py
python -m pytest -q
```

The original application-directory workflow also works:

```bash
cd CyberLLM
python verify.py
python -m pytest tests/ -q
```

## Test layers

| Area | Coverage |
| --- | --- |
| Rules and parsing | Rule schemas, regex compilation, deterministic detections, model-response parsing. |
| Scanners | Code/log/topology analysis, merging, mocked external analyzer outputs. |
| Guards | Scope, provenance, action/step/trajectory checks, delegation, alignment judge. |
| Action engine | Playbooks, tool schemas, dry-run execution, verification, rollback, re-planning. |
| Memory | HMAC integrity, authenticated writers, recall, cross-session feedback. |
| Pipelines and CLI | Defense/attack orchestration, scenario regressions, command-line subprocesses. |
| Web API | Static assets, file-access boundaries, scans, provider information, remediation/attack behavior. |
| Evaluation | Ground-truth integrity, location matching, clean controls, detection metrics. |

`CyberLLM/tests/conftest.py` forces the stub provider, dry-run tools, and disabled
external static analyzers for each test. CI also sets these before collection.
Changing the configured provider does **not** turn pytest into a live-model test.
Some tests deliberately replace clients or tool functions with controlled fakes.

Run a focused area while developing, then run the full suite for shared changes:

```bash
python -m pytest CyberLLM/tests/test_web_server.py -q
python -m pytest CyberLLM/tests/test_scenario_regression.py -q
```

## Continuous integration

[The workflow](../.github/workflows/ci.yml) installs development dependencies,
runs the smoke check, and runs pytest on Windows/Linux with Python 3.11/3.12.
It needs no provider keys and does not publish packages or deploy the application.

## Limits

Offline tests establish application contracts, not live-model quality or generated
patch correctness. Evaluate those separately with authorized inputs and record
the provider/model, configuration, optional analyzer versions, and commit.

The smoke check and CLI tests create ignored local records and run logs. The
benchmark source and labels are immutable test inputs for organizational changes:
moving lines changes the scoring target. See [evaluation](evaluation.md).
