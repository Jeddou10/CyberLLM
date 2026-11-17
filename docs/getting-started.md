# Getting started

## Install

Create and activate a Python 3.11 virtual environment using the
[root quick start](../README.md#quick-start), then install from the repository root:

```bash
python -m pip install -r requirements.txt
python CyberLLM/verify.py
```

The runtime requirements remain PyYAML, requests, and pydantic. Optional provider
SDKs and external analyzers are installed separately; the sample applications
are analysis fixtures and do not need their own Flask, database, or Kafka services.

## Local interface

```bash
python CyberLLM/server.py
```

Open http://127.0.0.1:8000. Stop the server with Ctrl+C. To select another port:

```bash
python CyberLLM/server.py --port 9000
```

| Tab | Workflow |
| --- | --- |
| Scan | Paste code or load an example, run analysis, inspect findings and source slices. Deep mode can request model-generated corrections and re-scan them. |
| Benchmark | Run the automotive corpus against its labels. Optional remediation measures how many labeled issues disappear on a subsequent scan. |
| Attack | Analyze code and an optional deployment/scenario, inspect generated proof-of-concept text, and request a simulated outcome. |

Fast mode disables LLM refinement of submitted code. Deep mode uses the configured
provider when available, otherwise detection falls back to static analysis.
Auto-remediation requires a live model. A clean re-scan is not a correctness proof.

## Deterministic offline runs

Set all three switches in the shell before starting the CLI or server:

```powershell
# Windows PowerShell
$env:CYBERLLM_FORCE_STUB = "1"
$env:CYBERLLM_FORCE_DRY_RUN = "1"
$env:CYBERLLM_NO_EXTERNAL_STATIC = "1"
```

```bash
# macOS / Linux
export CYBERLLM_FORCE_STUB=1
export CYBERLLM_FORCE_DRY_RUN=1
export CYBERLLM_NO_EXTERNAL_STATIC=1
```

The stub is a demonstration of agent wiring: it can return canned findings.
CLI stub output is therefore different from the web interface's Fast mode,
which disables LLM finding refinement. Use Fast mode or the static evaluation
harness for deterministic detection measurements.

All three switches currently treat **any nonempty string as enabled**, including
`0` and `false`. Remove a switch to stop forcing it; configuration and server
defaults still apply. In PowerShell use `Remove-Item Env:CYBERLLM_FORCE_STUB`; in
Bash use `unset CYBERLLM_FORCE_STUB` (and likewise for the other switches).

## Command-line analysis

Run the following from `CyberLLM/`. Relative input paths resolve against this
application directory. Absolute paths also work.

```bash
python pipeline.py --example small
python pipeline.py --mode both --example medium
python pipeline.py --mode defense --code examples/small/02_can_gateway.py --log examples/logs/03_can_injection.log --deployment examples/deployments/03_complex_sdv.yaml
python pipeline.py --mode attack --code examples/small/02_can_gateway.py --scenario examples/attack_scenarios/02_brake_tampering.txt
python pipeline.py --help
```

Use `--code` for a file or directory, `--log` for a log, and `--deployment` for a
topology YAML. In single-run mode, omitted log/deployment inputs use the samples
in `config.yaml`. `--scenario` accepts a text file or a literal scenario.
`-v` adds debug detail; `-q` suppresses per-step progress.

The maintained example sets are `small`, `medium`, `large`, and `all`. Read
[known limitations](known-limitations.md) before using the legacy blind runner
or the optional `juliet` set.

## Optional LLM providers

Copy `CyberLLM/.env.example` to `CyberLLM/.env`, fill in credentials locally, and
select the provider/model in `CyberLLM/config.yaml`. Shell values override `.env`.
For Azure, set the endpoint, API key, and your deployment name. Both the default
and reasoning profiles use the same environment configuration unless overridden.

The [configuration guide](configuration.md#providers) describes the adapters
already implemented in this repository. No credentials are needed for offline
tests. Restart the server after changing configuration or `.env`.

## Outputs

CLI runs write JSON under `CyberLLM/memory/`, a signed SQLite incident store, and
per-run traces under `CyberLLM/run_logs/`. A trace includes `_summary.md`,
`_trace.log`, and intermediate agent/tool records. The action engine uses
`CyberLLM/mcp_workspace/` for its workspace.

Run logs can contain submitted code, prompts, and model output. Review and redact
them before sharing. Web scans use temporary run-log and memory directories and
disable cross-session incident memory for the scan.
