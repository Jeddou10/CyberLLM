# Contributing

Start with the [project overview](README.md), [architecture](docs/architecture.md),
and [known limitations](docs/known-limitations.md). Bug reports should include
the commit, Python/OS versions, reproduction steps, and sanitized output.

## Development setup

Create and activate a virtual environment as described in the README, then run
these commands from the repository root:

```bash
python -m pip install -r requirements-dev.txt
python CyberLLM/verify.py
python -m pytest -q
```

No provider credentials or external static analyzers are needed for the tests.
Keep private settings in `CyberLLM/.env`; do not commit runtime logs or databases.

## Making changes

- Keep changes focused and preserve existing CLI commands, configuration keys,
  and output records unless the change explicitly requires a new contract.
- Keep module responsibilities clear. Shared finding presentation belongs in
  `reporting/`; orchestration stays in `pipeline.py`; UI assets live in `webapp/`.
- For a detection rule, include a positive case and a clean control. For guard
  changes, test both allowed and refused behavior. For an API change, test the
  real HTTP boundary as well as the underlying function where appropriate.
- Do not execute or auto-format intentionally vulnerable examples/benchmarks.
  Benchmark labels depend on exact line locations.
- Use UTF-8, the repository's EditorConfig conventions, and readable names.
  Avoid mixing broad formatting changes into behavior changes.
- Update the relevant guide when changing setup, configuration, or public behavior.

Run focused checks during development, then the full suite for shared changes.
In a pull request, describe the concrete behavior and the checks performed.
Distinguish offline verification from experiments with real providers or tools.

## Security and licensing

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability in CyberLLM.
Use synthetic inputs in issues and tests. Be respectful and constructive in
discussion. Contributions are distributed under the repository's [MIT License](LICENSE).
