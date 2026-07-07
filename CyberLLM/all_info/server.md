# `server.py` — the local web-UI server

`[← back to all_info index](README.md)`

---

## 1. Purpose & place in the system

`server.py` is a **zero-dependency local web server** (Python's stdlib
`http.server`) that puts a friendly browser UI on top of the *real* defense
pipeline. It serves the single-page app in `webapp/index.html` and a small JSON
API. When you paste code and press **Scan**, it runs `run_defense_pipeline`
(from `pipeline.py`) in an isolated temp workspace, with **actions forced to
dry-run** so nothing destructive can happen from a browser button.

It imports `pipeline`, `LLMClient`/`StubLLM` (from `llm_client.py`), and
`_analyzer_cmd` (from `tools/static_analyzer.py`). It is run directly:
`python server.py [--port N] [--host H]`.

---

## 2. Imports — lines 25–43

| line | import | why it's needed |
|------|--------|-----------------|
| 27 | `argparse` | `--host` / `--port` CLI flags. |
| 28 | `copy` | `deepcopy` the loaded config per scan so request-specific tweaks don't leak between scans. |
| 29 | `json` | Encode API responses / decode request bodies. |
| 30 | `os` | Set/read the dry-run + force-stub env switches. |
| 31 | `shutil` | `which()` for tool detection; `rmtree` to clean the temp workspace. |
| 32 | `tempfile` | Create an isolated per-scan workspace. |
| 33 | `threading` | A lock to serialize scans (run-log dir is global state). |
| 34 | `traceback` | Print a full stack trace on a scan error (server console). |
| 35 | `from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer` | The HTTP stack — `ThreadingHTTPServer` so the browser's parallel requests (health + examples on load) don't block each other. |
| 36 | `from pathlib import Path` | Paths. |
| 39 | `os.environ.setdefault("CYBERLLM_FORCE_DRY_RUN", "1")` | **Safety interlock:** before importing the pipeline, force dry-run so no browser action can ever run a real OS command. `setdefault` means an operator who *explicitly* exported it differently is still honored, but the default is safe. |
| 41–43 | `pipeline`, `LLMClient`/`StubLLM`, `_analyzer_cmd` | The pipeline entry point, the provider factory + stub type (to detect "is the LLM real?"), and the bandit/semgrep command resolver. |

**Module state (44–50):**
- `HERE`, `WEBAPP` — this file's dir and the `webapp/` folder.
- `_CFG`, `_RULES` — config + rules loaded **once** at import (cheap; scans deep-copy `_CFG`).
- `_SCAN_LOCK` — a `threading.Lock` to **serialize scans**, because `pipeline.RUN_LOGS_DIR` (and the temporary `CYBERLLM_FORCE_STUB` toggle) are process-global; two scans at once would race.

---

## 3. Walkthrough

### `_provider_info()` — lines 56–75
- **What:** report which LLM the "deep" mode would use, and which analyzer binaries are available — **without making any network call** (it only constructs the client object).
- **Line by line:**
  - 63 — `LLMClient.create(...)` builds the client; for Azure with creds present this returns an `AzureOpenAILLM`, otherwise a `StubLLM`.
  - 66 — `real = not isinstance(client, StubLLM)` — the crucial "is the LLM live?" flag.
  - 67–68 — any construction error degrades gracefully to "stub / not real."
  - 71–73 — tool availability: bandit/semgrep use `_analyzer_cmd(...) is not None` (which also counts a `python -m bandit` module install, not just a PATH binary); the network tools use plain `shutil.which`.

### `run_web_scan(code, filename, log_text, deployment_text, deep)` — lines 78–149
The backend entry point. **Thread-safe** (serialized by `_SCAN_LOCK`).
- 84–86 — compute `effective_deep`: deep mode is honored **only if a real LLM exists** (`info["llm_real"]`); otherwise we silently fall back to the deterministic layers (the stub's canned findings must never appear on real code). `has_log`/`has_dep` record whether the user actually supplied those inputs.
- 91–101 — make a fresh temp workspace; remember the previous `RUN_LOGS_DIR` and `CYBERLLM_FORCE_STUB` so we can restore them in `finally`.
- 104–111 — write the pasted code to a file named like the user's filename (so line numbers/extension detection match). **Empty** log/deployment files are written when the user supplied none (110–111) — so neither the static nor the LLM pass invents log/topology findings the user never asked about.
- 112–120 — deep-copy the config and tweak it for this scan: temp memory dir, **memory disabled** (each scan is stateless), `external_static=True` (run real bandit/semgrep), `use_llm=effective_deep` for the code scanner, and **per-input** `use_llm_log`/`use_llm_deployment` gated on whether that input was supplied. `max_replan_rounds=1` and `llm_tool_selection=False` keep web responses snappy.
- 122–128 — **the offline/online switch:** non-deep scans temporarily set `CYBERLLM_FORCE_STUB=1` (instant, offline, no network); deep scans clear it so the real provider is used. Done under the lock so the global env toggle is safe.
- 130–133 — redirect `pipeline.RUN_LOGS_DIR` into the temp dir, then run the real `run_defense_pipeline`.
- 134–142 — return a UI-ready dict: `ok`, `deep` (effective) vs `deep_requested`, the provider info, filename, the original code (so the UI can render an annotated view), and the full `record`.
- 143–149 — `finally`: always restore `RUN_LOGS_DIR` and `CYBERLLM_FORCE_STUB`, and delete the temp workspace. This block runs even on exceptions, so global state never leaks.

### `_examples()` — lines 152–163
Read a few bundled example snippets (CAN gateway, telemetry uploader, EV-charging DB, clean auth) so first-time users can see a scan work immediately. Robust to missing files.

### `class Handler(BaseHTTPRequestHandler)` — lines 170–221
The HTTP request handler.
- 174–175 — `log_message` override prefixes server logs with `[web]` and keeps them readable.
- 177–186 — `_send` / `_json` helpers: set status, content-type, length, and `Cache-Control: no-store` (so the browser always re-fetches the SPA during development).
- **`do_GET` (188–199):** routes `/` and `/index.html` → the SPA file; `/api/health` → provider info; `/api/examples` → the bundled snippets; everything else → 404 JSON.
- **`do_POST` (201–221):** only `/api/scan`. It reads the JSON body, rejects empty code with HTTP 400 (208–209), calls `run_web_scan(...)`, and returns the result. Any exception is logged with a traceback and returned as a 500 JSON `{ok:false, error}` (218–221) — the server never crashes on a bad request.

### `main(argv)` — lines 224–247
- 225–228 — parse `--host`/`--port` (defaults `127.0.0.1:8000`).
- 230–240 — print a startup banner showing the URL, which LLM deep mode would use (`real` vs `offline stub`), analyzer availability, and the **DRY-RUN** notice. Line 240 flushes so the banner shows even with buffered stdout.
- 241–247 — `serve_forever()`, with a clean `KeyboardInterrupt` shutdown and `server_close()` in `finally`.

---

## 4. Edge cases, gotchas & design decisions

- **Dry-run is set at import time (line 39)** *before* `import pipeline`, so even the act of importing can't change the default away from safe.
- **Scans are serialized** because `RUN_LOGS_DIR` and the `CYBERLLM_FORCE_STUB` toggle are process-global. The lock is the simplest correct design for a local tool; a multi-user deployment would refactor those to per-call state.
- **Deep is only honored with a real LLM.** A user can tick "Deep (AI)" with no credentials configured; the server quietly does a Fast scan and the UI shows `deep:false` / `deep_requested:true` so the front end can explain why.
- **Empty default inputs, not sample inputs.** Earlier the server fed a sample "clean baseline" log; the real LLM then *hallucinated* a critical CAN-bus finding from it. Feeding empty inputs (and gating the log/topology LLM pass) fixed that — a code-only scan returns only code findings.
- **bandit via `python -m`.** On Windows `pip install --user bandit` puts `bandit.exe` outside PATH; `_analyzer_cmd` detects the importable module and runs `python -m bandit`, so the health endpoint correctly reports `bandit: yes`.
- **No external assets.** The SPA is fully self-contained (inline CSS/JS), so the server needs no static-file routing beyond `index.html`.
