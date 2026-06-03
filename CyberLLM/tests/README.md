# Testing CyberLLM

**TL;DR — three layers, run them in order:**

```bash
# 1.  Quick smoke check (30 s, no pytest needed)
python verify.py

# 2.  Full automated test suite (~2 s, needs pytest)
pip install --user pytest
python -m pytest tests/

# 3.  Manual / qualitative spot-checks (see §3 below)
python pipeline.py --mode both --example small
```

---

## 1. Why automated tests, not just manual runs

Manual runs (`python pipeline.py --example small`) show you *that* the
pipeline still runs end-to-end. They do **not** catch:

- a rule regex regression that silently stops firing on a real
  vulnerability (your eye won't notice CODE-001 missing from a
  20-finding list);
- a JSON parser that starts dropping fields when an LLM responds
  with markdown fences;
- a guard that allows an action it shouldn't, because the failure
  mode is "no message" rather than a crash;
- a refactor that swaps the order of two agents and breaks data
  flow between them.

The automated suite catches all four classes of bug because it asserts
*structural invariants*, not just "no exception was raised".

## 2. Layout

```
tests/
├── conftest.py                       # shared fixtures (rules, stub LLM, snippets)
├── test_static_analyzer.py           # one test per CWE / topology / log rule
├── test_rules_and_parsing.py         # rules YAML loads + findings JSON parsing
├── test_guards.py                    # SecurityGuard + EthicsGuard verdicts
├── test_pipeline_integration.py      # end-to-end defense + attack pipelines
├── test_scenario_regression.py       # per-scenario "must-have" rule_ids
└── test_cli_smoke.py                 # `python pipeline.py --help` etc.

pytest.ini                            # pytest config
verify.py                             # no-pytest 30-second smoke check
```

## 3. What each test layer covers

| File                              | Layer                | Speed | What it asserts                                                                                              |
|-----------------------------------|----------------------|-------|--------------------------------------------------------------------------------------------------------------|
| `test_static_analyzer.py`         | unit (deterministic) | <0.1s | Every code/log/topology rule fires on a positive case AND doesn't fire on a clean case.                      |
| `test_rules_and_parsing.py`       | unit                 | <0.1s | All rule YAML files load; required fields exist; ids unique; every regex compiles. JSON-findings parser is robust to markdown fences / malformed input. |
| `test_guards.py`                  | unit                 | <0.1s | SecurityGuard correctly accepts/rejects on each of the four paper-1 properties. EthicsGuard rejects out-of-scope scenarios + redacts destructive scripts. |
| `test_pipeline_integration.py`    | integration          | <0.5s | Full defense + full attack pipelines run end-to-end. Records have all required keys. Run-log directory + per-step files exist. |
| `test_scenario_regression.py`     | regression           | <1s   | For five real (code, log, deployment) triples, the **must-have** rule_ids are all detected. Catches accidental rule deletions or scanner breakage. |
| `test_cli_smoke.py`               | smoke                | ~30s  | `python pipeline.py --help`, `--example small` (defense + attack) all exit 0 with the expected summary tables. |

## 4. Common workflows

### Add a new rule
1. Edit `rules/*.yaml`.
2. Add a unit test in `test_static_analyzer.py` showing the rule
   fires on a positive snippet.
3. Run `pytest tests/test_static_analyzer.py -k <rule_id>` to confirm.

### Refactor an agent
1. Make the change.
2. Run `pytest tests/` — if integration tests are still green and
   scenario regression is still green, the agent's *contract* is
   preserved.

### Add a new example scenario
1. Edit `config.yaml` under `example_sets:`.
2. Add a row to `SCENARIOS` in `test_scenario_regression.py` listing
   the rule_ids you expect the static analyzer to surface for it.
3. Run `pytest tests/test_scenario_regression.py` to lock the
   expectation in.

### Wire in a real LLM
1. Edit `config.yaml -> llm_configs`.
2. Run `pytest tests/` — the suite uses the configured provider, so
   the integration tests will exercise the real LLM. If you don't want
   real LLM calls in CI, set the provider back to `stub` for tests:
   either via an env var your code reads, or by running CI with
   `--example all -m both` instead of pytest.

## 5. What is *not* tested automatically (and why)

These belong in the manual / qualitative loop because they are
non-deterministic or depend on a real LLM:

- **LLM output quality** — does the model's `justification` text
  make sense? Read it in `run_logs/<latest>/_summary.md`.
- **Auto-correction code quality** — does `patch_code` produce
  correct Python? Eyeball the patch in `memory/<scenario>.json`.
- **Attack-script realism** — would the generated payload actually
  work against a real target? Test in a lab.

For these, the workflow is:

```bash
python pipeline.py --mode both --example small
cat $(cat run_logs/_latest_defense.txt)/_summary.md
cat $(cat run_logs/_latest_attack.txt)/_summary.md
```

Inspect, judge, iterate.

## 6. Continuous integration recipe

If you wire this up to GitHub Actions / GitLab CI, a sensible default
job is:

```yaml
- name: Install
  run: pip install -r requirements.txt && pip install pytest
- name: Smoke
  run: python verify.py
- name: Unit + integration tests
  run: python -m pytest tests/
- name: CLI smoke (defense + attack)
  run: |
    python pipeline.py --mode defense --example small
    python pipeline.py --mode attack  --example small
```

The first two steps run in under five seconds; the last step is the
realistic end-to-end smoke. None require an LLM API key because the
default provider is `stub`.
