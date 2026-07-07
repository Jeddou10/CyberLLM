# `webapp/index.html` — the single-page UI

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

The browser front end for the local server (`server.py`). It is a **single,
self-contained HTML file** — all CSS and JS inline, no external assets — so it
works offline and needs no build step. The user pastes code, picks Fast/Deep,
presses Scan; the page calls the server's JSON API and renders a detailed,
colour-coded result. The server serves this file at `/`.

The file has three parts: a `<style>` block (the dark theme), the `<body>` markup
(top bar + a two-column grid of Source / Results), and a `<script>` block (all the
client logic).

---

## 2. Structure

### CSS (`<style>`)
A CSS-variable theme (`--bg`, severity colors `--crit/--high/--med/--low`, etc.)
and component styles: the sticky top bar, the input card, severity-tinted finding
cards, the annotated code viewer (a `<table>` with line-number gutter and
`hl-<severity>` row classes), stat tiles, badges, and the toggle switch. Severity
drives color throughout, so the UI reads at a glance.

### Markup (`<body>`)
- **Top bar:** brand, a provider pill (filled by `/api/health`), the **Deep (AI)**
  toggle, and the **Scan** button.
- **Left card — Source:** language select, filename, an examples dropdown, the
  code textarea, and collapsible optional **log** and **deployment** fields, plus a
  live mode note.
- **Right column — Results** (hidden until a scan): a summary banner (mode/tier/
  guard/confidence badges), severity stat tiles, the findings list, the **annotated
  source** viewer, the decision·action·guard panel, and a collapsible raw-JSON
  block.

### Client JS (`<script>`)
- **`loadHealth()`** — `GET /api/health`; fills the provider pill (live vs offline
  stub) and the mode note based on `llm_real` + the Deep toggle. This is how the UI
  honestly tells you whether Deep mode will actually use a model.
- **`loadExamples()`** — `GET /api/examples`; populates the dropdown; selecting one
  fills the code + filename + language.
- **`runScan()`** — `POST /api/scan` with `{code, filename, log, deployment,
  deep}`; shows a spinner; on success calls `render(data)`, on error shows a
  message. Empty code is rejected client-side too.
- **`render(data)`** — the heart. It sorts findings worst-first, builds the banner
  (mode/tier/guard/confidence/replan badges), the severity stat tiles, the finding
  cards (each clickable), the annotated code, the reasoning panel, and the raw
  JSON.
- **`renderCode(code, findings)`** — builds a line-numbered `<table>`; lines with a
  finding get an `hl-<worst-severity>` class and an inline rule-id tag. Clicking a
  finding scrolls its line into view and flashes it (`data-line` ↔ `tr[data-ln]`).
- **`renderReasoning(rec)`** — renders the decision (tier, confidence, assets,
  justification), the dry-run action plan (kind→target, params), the guard verdict
  (allowed/refused + reason), the re-planning rounds, and the MCP tool-call audit.
- Small helpers: `esc()` (HTML-escape to prevent the pasted code from injecting
  markup), `sevClass()` (normalize severity to a known class).

---

## 3. How it maps to the backend

The page renders exactly the `record` shape `run_defense_pipeline` returns
(documented in [pipeline.md](../pipeline.md)): `record.findings` (the
`rule_id/severity/title/location/line/detail` records) drive the list + code
highlights; `record.decision`, `record.action`, `record.guard_verdict`,
`record.replanning`, and `record.mcp_audit` drive the reasoning panel; `data.deep`
vs `data.deep_requested` drive the mode badge and the "deep unavailable" note.

---

## 4. Edge cases, gotchas & design decisions

- **Self-contained, offline.** All CSS/JS inline, no CDNs — it loads from the local
  server with no network and no build.
- **Honest about the LLM.** The provider pill and mode note reflect `llm_real`, and
  the banner shows `DEEP` vs `FAST`, so the user always knows whether a real model
  ran. (`deep_requested && !deep` means "you asked for Deep but there are no
  creds.")
- **`esc()` everywhere.** Pasted code and finding text are HTML-escaped before
  insertion, so a snippet containing `<script>` can't execute in the UI.
- **Click-to-locate.** The finding↔line linkage (`data-line`/`data-ln` + flash) is
  what makes the result feel like an IDE: click an issue, jump to the highlighted
  line.
- **Worst-first ordering + severity color** make triage immediate — critical/high
  rise to the top and are the most saturated.
- **Graceful failure.** A non-OK API response shows an inline error rather than a
  blank page; the spinner always clears in `finally`.
