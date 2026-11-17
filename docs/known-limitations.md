# Known limitations

These describe existing behavior retained during repository organization.

- **Local server:** the HTTP API has no built-in authentication and is intended
  for loopback use. It caches configuration and uses process-global state for
  some scan operations; it is not a multi-tenant deployment architecture.
- **Detection:** regex rules and model reasoning can both miss defects or report
  false positives. A clean scan is not evidence that a program is safe.
- **Offline stub:** it returns canned responses for exercising agent flow. CLI
  defaults can include those findings; Fast web scans disable model refinement.
- **External analyzers:** optional tools are best-effort. Semgrep is invoked
  with `--config=auto`, which may retrieve rules. Disable external analysis for
  deterministic network-free operation.
- **Provider fallback:** missing cloud credentials select the stub; errors from
  configured live providers can propagate instead of falling back.
- **Environment switches:** any nonempty value enables the three override flags,
  including `0`. See [configuration](configuration.md#execution-switches).
- **Development policy:** attack scope includes a wildcard and development bypass;
  incident signing falls back to a public development key. These are demo defaults.
- **Legacy blind batch:** the `test_blind` entry in `config.yaml` refers to
  `examples/01_fleet_db_service.py`, while the bundled file is under
  `examples/test_blind/`. The missing input is skipped. Use an explicit `--code`
  path for that corpus.
- **Legacy helper scripts:** `examples/run_examples.py` reads `memory/last_run.json`
  although the pipeline now writes `last_run_defense.json`; `run_blind_tests.py`
  expects an `explanation` field where enriched records expose `detail`.
  Use `pipeline.py --example ...`, an explicit `--code` path, or `evaluate.py`.
- **Juliet:** the optional third-party corpus is not distributed here; missing
  configured inputs are skipped.
- **Research references:** P1–P5 labels are preserved from the original project;
  the P5 bibliography is incomplete. See [research background](research.md).

Behavioral fixes to these areas should be separate changes with explicit tests.
