# `agents/memory_store.py` — signed, queryable cross-session memory

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

`MemoryStore` implements P5's **adaptive-learning loop** and the P1/P2
**memory-poisoning defense**. The pipeline already writes per-run JSON, but those
files are never read back. This module promotes that archive to a **queryable,
cross-session SQLite store** that the `DecisionAgent` consults: it recalls similar
past incidents (few-shot context) and recommends "what tier *worked* on this
pattern before." Crucially, every write is **HMAC-signed** and tagged with its
source, and every read **verifies the signature + source** — so a poisoned or
unauthenticated entry can never influence a future decision. All static and
offline: SQLite + a keyed hash + set arithmetic. No network, no model.

Built by `pipeline.build_memory`; used by `DecisionAgent`.

---

## 2. Imports — lines 29–37

| line | import | why |
|------|--------|-----|
| 31–32 | `hashlib, hmac` | HMAC-SHA256 signing of each row. |
| 33 | `json` | Serialize set fields and the canonical signing payload. |
| 34 | `sqlite3` | The store (stdlib — no new dependency). |
| 35 | `dataclass, field` | The `Incident` shape. |
| 36 | `datetime` | `created_at` timestamps. |
| 37 | `Path` | DB path handling. |

Module constants: `_SIGNED_FIELDS` (43–47) — the fields the signature covers, in
a fixed order, binding content+outcome to the claimed source. `_MIGRATION_COLUMNS`
(51–54) — columns added after v1, applied via `ALTER TABLE` so an old DB keeps
working.

---

## 3. Walkthrough

### `Incident` — lines 57–82
One past outcome: mode, scenario, `rule_ids`, asset categories, tier, confidence,
`action_kind`, `guard_allowed`, and — the learning signal — `plan_status` +
`remediation_ok` (did it actually work end-to-end?). Plus `source` (who wrote
it). `canonical()` (76–82) builds the order-independent dict that gets signed
(sorting the set-valued fields so signing doesn't depend on insertion order).

### `MemoryAuthError` + `jaccard` — lines 85–96
The error for unauthenticated writes, and the **Jaccard similarity** (`|A∩B| /
|A∪B|`) used to score how similar two incidents' rule-id sets are.

### `MemoryStore.__init__` — lines 102–111
Stores the DB path (creating parent dirs), the signing key (bytes), the
authenticated-source set, the `reject_unverified` flag, and initializes the
schema.

### Schema + migration — lines 117–149
`_connect` (117–120) opens SQLite with a `Row` factory (dict-like rows).
`_init_schema` (122–149) creates the `incidents` table if absent, then **migrates**
an older DB by adding any missing `_MIGRATION_COLUMNS` via `ALTER TABLE` — so an
existing `incidents.db` upgrades transparently.

### Signing (E.3) — lines 155–182
- `_sign(canonical)` (155–158) — HMAC-SHA256 over the canonical JSON (sorted keys, compact separators) → hex digest.
- `verify_row(row)` (160–182) — **the read-time gate.** It first rejects any row whose `source` isn't authenticated (163), then recomputes the HMAC over the row's signed fields and compares with `hmac.compare_digest` (constant-time, 182). Both content tampering and an unauthenticated source fail verification.

### `record(incident)` — lines 188–222
The write path. It **refuses** a write from an unauthenticated source
(`MemoryAuthError`, 191–195), stamps `created_at` if absent, signs the canonical
form, and inserts the row (booleans stored as 0/1). Returns the new row id.

### Read (E.2) — lines 228–291
- `_row_to_incident` (228–242) — reconstruct an `Incident` from a row (handling the migrated columns defensively via `"col" in keys`).
- `recall_similar(rule_ids, k, exclude_scenario, mode)` (244–267) — load all rows, **skip any that fail verification** (255), filter by mode/scenario, score by Jaccard, drop zero-overlap, and return the top-k sorted by similarity then recency. This is the few-shot recall the decision agent injects.
- `recommend(rule_ids, mode, min_similarity, exclude_scenario)` (269–291) — cross-session learning: among similar incidents above `min_similarity` **whose remediation succeeded** (`remediation_ok`), return the best as a tier hint, or `None`. This is what lets "this worked last time" bias the decision.

### Audit helpers — lines 297–334
- `verify_all` (297–311) — an **integrity sweep** ("has my memory been poisoned?"): counts valid vs rejected rows.
- `count` (313–316) — row count.
- `render_fewshot(incidents)` (318–334) — render recalled incidents into a compact, **deterministic** prompt block (safe for the stub LLM), labeling each with its outcome (`worked`/status).

---

## 4. Edge cases, gotchas & design decisions

- **Signing binds content *and* source.** Because `source` is in `_SIGNED_FIELDS`, you can't relabel a row's writer without breaking the signature — P1 source-authorization applied to the memory channel.
- **Reads verify, not just writes.** Even if an attacker inserts a row directly into the SQLite file, `verify_row` (constant-time HMAC check + source check) rejects it at recall time, so it can never reach the decision agent. This is the concrete P2 poison-path defense.
- **Escalate-only learning.** `recommend` only returns *successful* precedents, and the decision agent uses it to *raise* the tier — memory makes responses more cautious, never less.
- **Forward-compatible schema.** `_MIGRATION_COLUMNS` + `ALTER TABLE` means an old `incidents.db` keeps working after the outcome columns were added; reads tolerate either shape.
- **Jaccard on rule-id sets.** Similarity is over *what rules fired*, not free text — deterministic and explainable, and zero-overlap incidents are never recalled.
- **Entirely offline.** SQLite + HMAC + set math — no network or model, so memory is reproducible and can't itself be a network attack surface.
- **`reject_unverified` is configurable** but defaults to True; turning it off (e.g. for debugging) is the only way an unverified row could surface, and that's an explicit operator choice.
