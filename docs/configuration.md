# Configuration

The application reads [`CyberLLM/config.yaml`](../CyberLLM/config.yaml). Its
defaults are preserved. Relative configured paths resolve under `CyberLLM/`;
the server caches configuration at startup, so restart it after edits.

## Sections

| Section | Purpose |
| --- | --- |
| `llm_configs` | Named provider/model profiles and generation parameters. |
| `scanners` | Optional external tools, model refinement, completeness second pass. |
| `agent_configs` | Agent objectives and selected LLM profiles. |
| `security` | Allowed objectives, authenticated sources, trusted destinations. |
| `response_tiers` | Soft/moderate/hard response thresholds provided to the decision agent. |
| `memory` | Incident database, recall count, writer identity, signature settings. |
| `guard` | Alignment judge, per-step checks, prompt token budget. |
| `action_engine` | Dry-run mode, workspace, maximum re-plan rounds, model tool selection. |
| `attack` | Scenario scope, authorized targets, development bypass. |
| `paths` | Rule, example, and memory directories. |
| `defaults` | Sample log/deployment used when single-run inputs are omitted. |
| `example_sets` | Named batches of code, log, deployment, and scenario paths. |

## Providers

These are the adapters implemented by `llm_client.py`, not a guarantee that every
model is compatible with every adapter's request parameters.

| Provider | Configuration / credentials | Additional dependency |
| --- | --- | --- |
| `stub` | No credentials; canned offline responses. | None |
| `azure` | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT`; optional `AZURE_OPENAI_API_VERSION`. | None; uses standard-library HTTP |
| `github` | `GITHUB_TOKEN` by default; `token_env` can override its name. | None; uses standard-library HTTP |
| `openai` | `OPENAI_API_KEY`, configured model. | `openai` |
| `anthropic` | `ANTHROPIC_API_KEY`, configured model. | `anthropic` |
| `ollama` | Local server at `http://localhost:11434`, configured installed model. | `requests` (already in runtime requirements) |

The shipped profiles select Azure and use `gpt-5.5` as their model/deployment
fallback. `AZURE_OPENAI_DEPLOYMENT` can supply your actual Azure deployment name.
The adapter's API-version fallback is `2024-10-21`. These describe the checked-in
configuration; they are not a recommendation of a particular provider model.

Missing or placeholder cloud credentials select the stub. Errors from an already
configured live provider can propagate; invalid live credentials do not universally
fall back to the stub. Ollama requires a reachable local service.

## Environment file

Copy [`.env.example`](../CyberLLM/.env.example) to `CyberLLM/.env`.
The built-in loader accepts simple `KEY=VALUE` lines, ignores comments, and loads
once per process. Existing shell values take precedence. A repository-root `.env`
is not read by this loader. Keep real credentials out of version control.

## Execution switches

| Variable | Effect when nonempty |
| --- | --- |
| `CYBERLLM_FORCE_STUB` | Force offline stub selection. |
| `CYBERLLM_FORCE_DRY_RUN` | Force pipeline response tools into dry-run mode. |
| `CYBERLLM_NO_EXTERNAL_STATIC` | Disable optional external scanner invocation. |
| `CYBERLLM_MEMORY_KEY` | Supply the default incident-memory signing key. |

The first three switches use string truthiness: `0` and `false` still enable
them. Unset them to return to configuration/default behavior. Tests force all
three to `1`. The smoke runner supplies defaults with `setdefault`.

`server.py` initializes an absent `CYBERLLM_FORCE_DRY_RUN` to the nonempty string
`0`; the pipeline treats this as enabled. Thus normal server startup forces
dry-run, but a preexisting empty value is not overwritten. Keep
`action_engine.dry_run: true` or explicitly set the switch to `1` for dry-run use.

## Research defaults

`attack.allow_all_in_dev: true`, the target wildcard `*`, and the documented
development memory key support local demonstrations. They are not authentication
or production isolation. HMAC signing verifies integrity, not confidentiality.
Read [the security policy](../SECURITY.md) before using sensitive inputs.
