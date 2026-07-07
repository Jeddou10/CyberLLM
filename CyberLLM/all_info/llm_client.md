# `llm_client.py` — the LLM provider abstraction

`[← back to all_info index](README.md)`

---

## 1. Purpose & place in the system

This file is the single seam between CyberLLM and any large language model. It
mirrors the **LLM-Config block of the Härer agent schema (P4)**: every agent
holds an `LLMClient` and calls `.complete(prompt, system)`; it does not know or
care which provider answers. A factory (`LLMClient.create`) picks the concrete
subclass from config, and — crucially — **gracefully falls back to a
deterministic offline stub** whenever credentials are missing or still
placeholders, so the pipeline always runs.

Providers implemented: `stub` (offline), `github` (GitHub Models), `azure`
(Azure OpenAI, the project default for gpt-4o), `openai`, `anthropic`, `ollama`.

Imported by `pipeline.py` (`build_llms`), `server.py` (provider detection), and
every agent.

---

## 2. Imports — lines 9–18

| line | import | why |
|------|--------|-----|
| 10 | `dataclass` | Define the tiny `LLMResponse`. |
| 11 | `json` | Build request bodies, parse responses, encode stub JSON. |
| 12 | `os` | Read credentials/markers from the environment. |
| 13 | `re` | Parse fields out of prompts (the stub), detect reasoning models. |
| 14–15 | `urllib.error`, `urllib.request` | Make HTTP calls with **no third-party dependency** (so github/azure work out of the box). |
| 16 | `warnings` | Emit one-time fallback warnings. |
| 17 | `Path` | Locate the `.env` file. |
| 18 | `Any` | Loose typing for `LLMResponse.raw`. |

---

## 3. Walkthrough

### `LLMResponse` — lines 21–24
A 2-field dataclass: `text` (the model's content string) and `raw` (the full
provider payload, kept for debugging). Every provider returns this shape, so
callers are provider-agnostic.

### One-time warning machinery — lines 29–35
`_WARNED` is a module-level `set`; `_warn_once(key, msg)` emits a warning the
first time a given `key` is seen. **Why:** a batch run of 20 scenarios would
otherwise print "falling back to stub" 20 times — annoying and misleading.

### `_PROVIDER_KEY_ENV` — lines 42–45
Map `openai`/`anthropic` → the env var that holds their key. Used by the generic
fallback check (140–148). (github/azure have their own dedicated checks.)

### `.env` loader — lines 51–75
- **What:** a tiny, zero-dependency `.env` parser (`_load_dotenv_once`).
- **Why this design:** avoids a `python-dotenv` dependency while still letting you keep secrets in a git-ignored file.
- **Line by line:**
  - 60–63 — load at most once (module global guard).
  - 64–66 — the `.env` sits next to this file; absent → just return.
  - 67–75 — parse `KEY=VALUE`: skip blanks/comments/malformed lines (69), strip surrounding quotes (73), and **only set keys not already in the environment** (74) — so a value exported in the real shell always wins over the file.

### Placeholder detection — lines 81–87
`_PLACEHOLDER_MARKERS` lists fragments that mean "this is still the shipped
placeholder" (`your_token`, `replace`, `<`, `>`, …). `_looks_like_placeholder`
returns true for an empty string **or** any value containing a marker. **Why:**
a freshly-cloned repo has placeholder creds; treating those as "not configured"
makes the stub fallback automatic, so tests and demos never explode on a 401.

### `class LLMClient` + `create(cfg)` factory — lines 90–162
The base class and the provider router.
- 93 — load `.env` first so credentials are visible.
- 94 — read the provider name (default `stub`).
- 98–99 — **hermetic escape hatch:** if `CYBERLLM_FORCE_STUB` is set and the provider isn't already stub, return the stub no matter what. This is how the test suite and Fast-mode web scans guarantee offline determinism.
- 101–102 — explicit `stub`.
- 105–117 — **github:** read the token env; if it's a placeholder, warn once and return the stub; otherwise build `GitHubModelsLLM`.
- 120–134 — **azure (the default):** resolve key + endpoint from cfg/env; if either is a placeholder, warn once and stub; otherwise build `AzureOpenAILLM`.
- 140–148 — **generic credential fallback (roadmap A.2)** for openai/anthropic: if the key is missing/placeholder, warn once and stub.
- 150–156 — construct the real openai/anthropic/ollama client, or raise `ValueError` for an unknown provider.
- 158–162 — `__init__` stores `cfg`; `complete` is abstract (each subclass implements it).

### `StubLLM` — lines 165–286
The **deterministic offline brain**. It pattern-matches keywords in the prompt
and returns plausible JSON, so the entire pipeline runs with no network.
- **Why this design:** P4 wants a working agent out of the box; the stub means "the pipeline produces real *static* findings even with no LLM, and accuracy only goes up when a real model is added."
- **Order matters (175–177).** The decision-agent prompt also contains scanner keywords, so more-specific branches are checked first.
- 182–207 — **H_a oracle branch (must be first).** When the prompt is the harm-acceptability oracle, it extracts `OBJECTIVE`/`ACTION`/`CONTEXT` with regex, then decides `serves`: a *privileged* action (patch_code, isolate_node, block_ip, secrets.rotate, …) does **not** serve a *report-only* objective (195–198); a context flagged "misaligned"/"trusted-asset" also fails (199–201); otherwise it serves. Returns `{serves, reason}` JSON. This encodes P1's action-alignment check deterministically.
- 209–226 — the **rich decision** branch (when the prompt is the central decision agent and mentions asset categories): returns a canned moderate-tier decision with P2 asset categories.
- 228–260 — the three **scanner** branches (code / log / topology): each returns canned findings with real `rule_id`s, severities, evidence, explanations. *(These canned findings are exactly why the web UI gates `use_llm` off on real code — see `pipeline.md`.)*
- 262–276 — a simpler decision branch.
- 278–284 — a "fix"/"correct" branch returning a remediation suggestion string.
- 286 — the default: echo the (whitespace-collapsed, truncated) prompt as `ACK: …`, so even an unmatched prompt yields a deterministic, harmless response.

### `GitHubModelsLLM` — lines 289–375
OpenAI-compatible inference behind a GitHub token, called directly with
`urllib` (no SDK).
- 303–305 — default GA endpoint + retry budget.
- 307–312 — `_is_reasoning_model`: gpt-5 and the o-series need a different request shape; detect by name prefix.
- 314–324 — `_build_body`: reasoning models use `max_completion_tokens` and reject a custom temperature; others use `max_tokens` + `temperature`. This is the trap that bit the project earlier and is now handled centrally.
- 326–375 — `complete`: build messages, POST with a `Bearer` token, and **retry on HTTP 429** honoring `Retry-After` (358–367). On non-retryable errors it raises a `RuntimeError` whose message tells you exactly what to check (model id, token scope) and includes the truncated response body (368–372).

### `AzureOpenAILLM` — lines 378–460  (the project default)
Azure differs from vanilla OpenAI in three ways, all handled here (381–384):
the model is chosen by **deployment name in the URL path**, auth uses the
`api-key` header (not `Authorization: Bearer`), and the request is versioned
with `?api-version=`.
- 393–394 — default API version + retry budget.
- 396–410 — `_resolved`: pull endpoint, deployment, api-version, and key from cfg-then-env (deployment falls back to cfg `model`). Centralizing this means the URL builder and the request use identical values.
- 412–415 — `_url`: assemble `{endpoint}/openai/deployments/{deployment}/chat/completions?api-version=...`.
- 417–460 — `complete`: gpt-4o is a *standard* model, so it sends `temperature` + `max_tokens`; POST with the `api-key` header; same 429-retry logic; same actionable error message naming the deployment/endpoint/version to check.

### `OpenAILLM`, `AnthropicLLM`, `OllamaLLM` — lines 463–510
Thin adapters using each vendor's SDK (or a local Ollama HTTP call). They're
marked `# pragma: no cover` because they require credentials/installs the test
suite doesn't have. Each imports its SDK lazily inside `complete` and raises a
clear "install the X package" error if missing (467–468, 487–488).

---

## 4. Edge cases, gotchas & design decisions

- **Why a stub at all?** It makes the project *runnable on clone* and keeps CI hermetic. It is also why `_llm_banner` in `pipeline.py` exists — to warn you when you're silently on the stub.
- **Placeholder ≈ unset.** Treating placeholder tokens as "not configured" prevents confusing 401s and lets the suite stay green regardless of `.env` contents.
- **`CYBERLLM_FORCE_STUB` wins over everything.** It short-circuits before any network client is built — the backbone of deterministic tests and Fast-mode web scans.
- **No third-party HTTP dependency for github/azure.** Using `urllib` keeps the default install light; the SDK providers are opt-in.
- **Reasoning vs standard models.** The `max_completion_tokens` / no-temperature handling is isolated in `GitHubModelsLLM._build_body`; Azure gpt-4o deliberately uses the standard params.
- **Retries are bounded and polite.** Max 2 retries, honoring `Retry-After`, capped at 30 s, so a rate-limited batch slows down instead of hammering or hanging.
