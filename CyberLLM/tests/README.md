# Tests

From the repository root:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

From `CyberLLM/`, the original `python -m pytest tests/ -q` also works.
`conftest.py` provides shared fixtures and forces offline LLMs, dry-run response
tools, and disabled external static analyzers. Configuring a live provider does
not make the automated suite call it.

See the [testing guide](../../docs/testing.md) for coverage and CI, and
[CONTRIBUTING.md](../../CONTRIBUTING.md) for adding or changing tests.
