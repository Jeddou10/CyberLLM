"""Persistent, signed incident memory — paper 5's adaptive-learning loop
and the implementation of paper 1 / 2's memory-poisoning defence.

What this adds over the old `memory/*.json` files
--------------------------------------------------
The pipeline already writes a per-run JSON record. Those files are a
flat archive: nothing ever *reads them back*. This module promotes the
archive to a queryable, **cross-session** store:

- **E.1** — a single SQLite database (`incidents.db`, stdlib only, no
  new dependency) holding one row per past defense/attack outcome,
  **including how the remediation turned out** (`plan_status`,
  `remediation_ok`).
- **E.2** — `recall_similar()` retrieves the K most similar past
  incidents by Jaccard overlap of their *finding rule-id set*, so the
  Decision Agent can inject them as few-shot context, and `recommend()`
  answers "we saw this pattern before — what tier/action *worked*?".
- **E.3** — every write is **HMAC-signed** with a per-deployment key and
  tagged with the writing source. Reads **verify the signature and the
  source authorisation** before returning a row, so a poisoned or
  unauthenticated memory entry can never influence a future decision
  (paper 1 source-authorization applied to the memory channel; paper 2
  §4.2 poison-path defence).

Everything here is static and offline: SQLite on the local disk, a
keyed hash, and set arithmetic. No network, no model.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# The fields covered by the signature, in a fixed order. The signature
# binds the *content* of an incident (including its outcome) to its
# claimed source, so neither can be altered after the fact undetected.
_SIGNED_FIELDS = (
    "created_at", "mode", "scenario", "rule_ids", "asset_categories",
    "tier", "confidence", "action_kind", "guard_allowed",
    "plan_status", "remediation_ok", "source",
)

# Columns added after the first schema version. `_init_schema` migrates
# an existing DB by ALTER TABLE (so an old incidents.db keeps working).
_MIGRATION_COLUMNS = {
    "plan_status": "TEXT DEFAULT ''",
    "remediation_ok": "INTEGER DEFAULT 0",
}


@dataclass
class Incident:
    """One past pipeline outcome, suitable for recall as a few-shot."""
    mode: str                       # "defense" | "attack"
    scenario: str
    rule_ids: list[str] = field(default_factory=list)
    asset_categories: list[str] = field(default_factory=list)
    tier: str = ""                  # defense decision tier (or attack target)
    confidence: float = 0.0
    action_kind: str = ""           # defense action.kind (or attack plan summary)
    guard_allowed: bool = False
    plan_status: str = ""           # action-engine PlanStatus value, e.g. "completed"
    remediation_ok: bool = False    # did the response actually succeed end-to-end?
    source: str = "rules_engine"    # who wrote it — must be authenticated
    created_at: str = ""
    # populated on read
    rowid: int | None = None
    similarity: float | None = None

    def canonical(self) -> dict:
        d = {k: getattr(self, k) for k in _SIGNED_FIELDS}
        # normalise the set-valued fields so signing is order-independent
        d["rule_ids"] = sorted(set(self.rule_ids))
        d["asset_categories"] = sorted(set(self.asset_categories))
        d["remediation_ok"] = bool(self.remediation_ok)
        return d


class MemoryAuthError(PermissionError):
    """Raised when a write is attempted from an unauthenticated source."""


def jaccard(a: set[str], b: set[str]) -> float:
    """Set-overlap similarity in [0, 1]. Empty/empty → 0.0."""
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


class MemoryStore:
    """Signed, queryable, cross-session incident store backed by SQLite."""

    def __init__(self, db_path: str | Path, signing_key: str,
                 authenticated_sources: list[str] | None = None,
                 reject_unverified: bool = True):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._key = signing_key.encode("utf-8")
        self.authenticated_sources = set(
            authenticated_sources or ["user", "rules_engine", "mcp_tool"])
        self.reject_unverified = reject_unverified
        self._init_schema()

    # ------------------------------------------------------------------
    # schema (+ forward migration)
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at      TEXT NOT NULL,
                    mode            TEXT NOT NULL,
                    scenario        TEXT NOT NULL,
                    rule_ids        TEXT NOT NULL,
                    asset_categories TEXT NOT NULL,
                    tier            TEXT,
                    confidence      REAL,
                    action_kind     TEXT,
                    guard_allowed   INTEGER,
                    plan_status     TEXT DEFAULT '',
                    remediation_ok  INTEGER DEFAULT 0,
                    source          TEXT NOT NULL,
                    signature       TEXT NOT NULL
                )
                """
            )
            # Migrate an older DB that predates the outcome columns.
            existing = {r["name"] for r in
                        conn.execute("PRAGMA table_info(incidents)").fetchall()}
            for col, decl in _MIGRATION_COLUMNS.items():
                if col not in existing:
                    conn.execute(f"ALTER TABLE incidents ADD COLUMN {col} {decl}")

    # ------------------------------------------------------------------
    # signing (E.3)
    # ------------------------------------------------------------------

    def _sign(self, canonical: dict) -> str:
        payload = json.dumps(canonical, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify_row(self, row: sqlite3.Row) -> bool:
        """Recompute the HMAC over a row's signed fields and check it
        matches the stored signature *and* the source is authenticated."""
        if row["source"] not in self.authenticated_sources:
            return False
        canonical = {
            "created_at": row["created_at"],
            "mode": row["mode"],
            "scenario": row["scenario"],
            "rule_ids": json.loads(row["rule_ids"]),
            "asset_categories": json.loads(row["asset_categories"]),
            "tier": row["tier"],
            "confidence": row["confidence"],
            "action_kind": row["action_kind"],
            "guard_allowed": bool(row["guard_allowed"]),
            "plan_status": (row["plan_status"] if "plan_status" in row.keys()
                            else "") or "",
            "remediation_ok": bool(row["remediation_ok"]
                                   if "remediation_ok" in row.keys() else 0),
            "source": row["source"],
        }
        expected = self._sign(canonical)
        return hmac.compare_digest(expected, row["signature"] or "")

    # ------------------------------------------------------------------
    # write
    # ------------------------------------------------------------------

    def record(self, incident: Incident) -> int:
        """Sign and persist an incident. Refuses writes from a source
        that is not in the authenticated set (E.3)."""
        if incident.source not in self.authenticated_sources:
            raise MemoryAuthError(
                f"refusing memory write from unauthenticated source "
                f"'{incident.source}'; authenticated = "
                f"{sorted(self.authenticated_sources)}")
        if not incident.created_at:
            incident.created_at = datetime.now().isoformat(timespec="seconds")
        canonical = incident.canonical()
        signature = self._sign(canonical)
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO incidents
                  (created_at, mode, scenario, rule_ids, asset_categories,
                   tier, confidence, action_kind, guard_allowed,
                   plan_status, remediation_ok, source, signature)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    canonical["created_at"], canonical["mode"],
                    canonical["scenario"],
                    json.dumps(canonical["rule_ids"]),
                    json.dumps(canonical["asset_categories"]),
                    canonical["tier"], canonical["confidence"],
                    canonical["action_kind"],
                    1 if canonical["guard_allowed"] else 0,
                    canonical["plan_status"],
                    1 if canonical["remediation_ok"] else 0,
                    canonical["source"], signature,
                ),
            )
            return int(cur.lastrowid)

    # ------------------------------------------------------------------
    # read (E.2)
    # ------------------------------------------------------------------

    def _row_to_incident(self, row: sqlite3.Row, sim: float | None) -> Incident:
        keys = row.keys()
        return Incident(
            mode=row["mode"], scenario=row["scenario"],
            rule_ids=sorted(set(json.loads(row["rule_ids"]))),
            asset_categories=json.loads(row["asset_categories"]),
            tier=row["tier"], confidence=row["confidence"],
            action_kind=row["action_kind"],
            guard_allowed=bool(row["guard_allowed"]),
            plan_status=(row["plan_status"] if "plan_status" in keys else "") or "",
            remediation_ok=bool(row["remediation_ok"]
                                if "remediation_ok" in keys else 0),
            source=row["source"], created_at=row["created_at"],
            rowid=row["id"], similarity=(round(sim, 3) if sim is not None else None),
        )

    def recall_similar(self, rule_ids, k: int = 5,
                       exclude_scenario: str | None = None,
                       mode: str | None = None) -> list[Incident]:
        """Return up to `k` past incidents most similar to the current
        finding set, ranked by Jaccard overlap of rule-id sets. Only
        signature-verified, authenticated rows are eligible (E.3)."""
        query = set(rule_ids or [])
        out: list[Incident] = []
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM incidents").fetchall()
        for row in rows:
            if self.reject_unverified and not self.verify_row(row):
                continue
            if mode and row["mode"] != mode:
                continue
            if exclude_scenario and row["scenario"] == exclude_scenario:
                continue
            sim = jaccard(query, set(json.loads(row["rule_ids"])))
            if sim <= 0.0:
                continue
            out.append(self._row_to_incident(row, sim))
        # Most similar first; tie-break on recency (created_at desc).
        out.sort(key=lambda i: (i.similarity, i.created_at), reverse=True)
        return out[:k]

    def recommend(self, rule_ids, mode: str = "defense",
                  min_similarity: float = 0.5,
                  exclude_scenario: str | None = None) -> dict | None:
        """Cross-session learning: "we saw this pattern before — what
        *worked*?". Returns the most-similar past incident whose
        remediation succeeded (above `min_similarity`), as a hint the
        decision agent can use to bias its tier. None if no precedent."""
        candidates = [i for i in self.recall_similar(
                        rule_ids, k=20, mode=mode,
                        exclude_scenario=exclude_scenario)
                      if (i.similarity or 0) >= min_similarity
                      and i.remediation_ok]
        if not candidates:
            return None
        best = candidates[0]   # already sorted by similarity desc
        return {
            "scenario": best.scenario,
            "similarity": best.similarity,
            "tier": best.tier,
            "action_kind": best.action_kind,
            "plan_status": best.plan_status,
            "seen_at": best.created_at,
        }

    # ------------------------------------------------------------------
    # audit helpers
    # ------------------------------------------------------------------

    def verify_all(self) -> dict:
        """Integrity sweep: how many rows are valid vs rejected. Useful
        for a 'has my memory been poisoned?' check."""
        total = valid = 0
        rejected: list[int] = []
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM incidents").fetchall()
        for row in rows:
            total += 1
            if self.verify_row(row):
                valid += 1
            else:
                rejected.append(int(row["id"]))
        return {"total": total, "valid": valid,
                "rejected": rejected, "n_rejected": len(rejected)}

    def count(self) -> int:
        with self._connect() as conn:
            return int(conn.execute(
                "SELECT COUNT(*) FROM incidents").fetchone()[0])

    @staticmethod
    def render_fewshot(incidents: list[Incident]) -> str:
        """Render recalled incidents as a compact few-shot block for a
        prompt (E.2). Deterministic — safe for the stub LLM."""
        if not incidents:
            return "(no similar past incidents on record)"
        lines = []
        for i in incidents:
            outcome = ("worked" if i.remediation_ok
                       else (i.plan_status or "unknown"))
            lines.append(
                f"- past[{i.scenario}] sim={i.similarity}: "
                f"rules={i.rule_ids} → tier={i.tier} "
                f"(action={i.action_kind}, guard_allowed={i.guard_allowed}, "
                f"outcome={outcome})"
            )
        return "\n".join(lines)
