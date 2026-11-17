# Security policy

CyberLLM is a local research prototype for authorized security analysis. Its
development policies and model-assisted checks are not a production security
boundary. Use only systems and inputs you are authorized to analyze.

## Reporting a vulnerability

For a vulnerability in CyberLLM itself, use the repository's private vulnerability
reporting option if it is enabled. If no private channel is available, open a
minimal issue asking the maintainer for a private contact channel; omit exploit
details, credentials, and sensitive inputs until a channel is established.
Include the affected commit, impact, and a minimal reproduction in the private
report. There is no promised response SLA or published supported-release matrix.

The intentionally vulnerable code under `CyberLLM/examples/` and
`CyberLLM/benchmark/` is test data. A seeded defect there is not, by itself, a
vulnerability in the analysis application.

## Execution boundaries

- Source analysis reads submitted code rather than running it. Optional static
  analyzers are external processes; Semgrep's automatic configuration may fetch
  rules. Disable external tools for a fully offline run.
- Response tools default to dry-run. The normal server initialization also
  forces dry-run through the existing nonempty environment-switch behavior.
  See [configuration](docs/configuration.md#execution-switches) for the exact
  semantics; set `CYBERLLM_FORCE_DRY_RUN=1` explicitly when required.
- If live response execution is enabled through configuration and environment,
  tools may change files, services, network settings, or other host resources.
- The attack pipeline emits script text; it does not execute that text. Pattern
  filtering and scenario checks are limited approximations, not a sandbox.
- Generated fixes are re-scanned, not proven correct or safe to deploy.

## Data and access

Bind the unauthenticated server to its default loopback address. Live providers
receive prompt content, which can include source code, logs, and deployments.
Run traces can contain the same data and model output. Keep credentials and
private artifacts out of commits and shared reports.

Incident memory is signed, not encrypted. The default development signing key
is public; use a private `CYBERLLM_MEMORY_KEY` for sensitive deployments. The
default attack configuration includes `allow_all_in_dev: true` and a wildcard
target. Review both before any use beyond local demonstrations.

The [MIT License](LICENSE) governs distribution; it does not authorize access to
third-party systems.
