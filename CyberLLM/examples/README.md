# Examples — test inputs for the CyberLLM pipeline

This directory holds a graded set of realistic test inputs, ranging
from one-file toy programs to a multi-module backend. Use them to
stress-test the pipeline, measure detection vs false-positive rates,
and develop new rules.

## Layout

```
examples/
├── README.md                ← this file
├── scenarios.md             ← per-example expected findings table
├── run_examples.py          ← batch test runner
│
├── sample_code.py           ← legacy 1st-pipeline file (kept for back-compat)
├── sample_log.log
├── sample_deployment.yaml
│
├── small/                   ← single-file scenarios
│   ├── 01_clean_auth.py             (negative control — should be clean)
│   ├── 02_can_gateway.py            (automotive CAN gateway)
│   ├── 03_ota_updater.py            (firmware OTA installer)
│   ├── 04_telemetry_uploader.py     (IoT uploader)
│   └── 05_mqtt_handler.c            (embedded C, MQTT callback)
│
├── medium/                  ← multi-file mini-projects
│   ├── ev_charging_api/             (Flask EV-charging REST API)
│   └── adas_decision/               (ADAS perception → decision → actuator)
│
├── large/                   ← realistic backend layout
│   └── fleet_management/            (FastAPI + Kafka + Postgres fleet backend)
│
├── logs/                    ← log scenarios paired with the source files
│   ├── 01_clean_baseline.log
│   ├── 02_brute_force_ssh.log
│   ├── 03_can_injection.log
│   ├── 04_data_exfiltration.log
│   ├── 05_lateral_movement.log
│   └── 06_ddos_pattern.log
│
└── deployments/             ← topology / deployment configs
    ├── 01_clean_minimal.yaml
    ├── 02_misconfigured_cloud.yaml
    └── 03_complex_sdv.yaml
```

## How to run

The pipeline accepts one of each input type per run (code / log /
deployment). To run a single combination:

```bash
python pipeline.py \
    --code        examples/small/02_can_gateway.py \
    --log         examples/logs/03_can_injection.log \
    --deployment  examples/deployments/03_complex_sdv.yaml
```

To run **every** suggested combination (defined in `scenarios.md`)
and write a results table to disk:

```bash
python examples/run_examples.py
```

## What the stub LLM will and won't catch

`run_examples.py` will work, but with the default `provider: stub`
the baseline detection rate is intentionally low — the stub returns
canned findings for the three original demo files and doesn't know
about the new ones. **That is by design**: the harness is what you
need first; the LLM is what makes the numbers go up.

Recommended next step: switch `config.yaml` to a real provider (Ollama
locally, or OpenAI / Anthropic) and re-run `run_examples.py`. The
scorecard format stays the same; the detection rates should improve
substantially.

## Notes on the "clean" examples

`small/01_clean_auth.py`, parts of `large/fleet_management/auth/`,
`large/fleet_management/utils/logging_setup.py`, and
`deployments/01_clean_minimal.yaml` are deliberately CLEAN. They serve
two purposes:

1. **False-positive baseline.** If your real LLM raises findings on
   these, you have a precision problem to fix in your prompts or
   rules.
2. **Confidence calibration.** The decision agent should pick the
   `none` tier with high confidence here. If it doesn't, the scoring
   needs more weight on "did *any* scanner produce a finding".

## Notes on the "deliberately bad" examples

Every vulnerability is tagged in a comment with a `CODE-NNN`,
`SAFE-NNN`, `TOP-NNN`, or `LOG-…` rule id. The id corresponds to an
entry in either `../rules/example_rules.yaml` or
`../rules/extended_rules.yaml`.

This lets you run the pipeline and then **diff** the rule ids it
reported against the rule ids hidden in the comments — that's your
detection rate.
