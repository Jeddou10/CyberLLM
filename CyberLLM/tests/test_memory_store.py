"""Tests for the signed incident store (Phase E: E.1 store, E.3 defence)."""

from __future__ import annotations

import sqlite3

import pytest

from agents.memory_store import (
    Incident, MemoryAuthError, MemoryStore, jaccard,
)


KEY = "test-signing-key"
AUTH = ["user", "rules_engine", "mcp_tool"]


def _store(tmp_path):
    return MemoryStore(tmp_path / "incidents.db", KEY, AUTH)


def _incident(scenario, rule_ids, source="rules_engine", tier="hard"):
    return Incident(mode="defense", scenario=scenario, rule_ids=rule_ids,
                    asset_categories=["Privacy and Personal Data"],
                    tier=tier, confidence=0.7, action_kind="isolate_node",
                    guard_allowed=True, source=source)


class TestJaccard:
    def test_identical(self):
        assert jaccard({"a", "b"}, {"a", "b"}) == 1.0

    def test_disjoint(self):
        assert jaccard({"a"}, {"b"}) == 0.0

    def test_partial(self):
        assert jaccard({"a", "b"}, {"b", "c"}) == pytest.approx(1 / 3)


class TestRecordAndRecall:

    def test_record_then_recall_by_similarity(self, tmp_path):
        s = _store(tmp_path)
        s.record(_incident("alpha", ["CODE-001", "TOP-002"]))
        s.record(_incident("beta", ["CODE-001", "TOP-002", "LOG-CAN-02"]))
        s.record(_incident("gamma", ["LOG-DDOS-01"]))

        hits = s.recall_similar(["CODE-001", "TOP-002"], k=5, mode="defense")
        names = [h.scenario for h in hits]
        # alpha is an exact match → highest similarity; gamma has no overlap
        # → excluded entirely.
        assert names[0] == "alpha"
        assert "gamma" not in names
        assert all(h.similarity > 0 for h in hits)

    def test_exclude_scenario(self, tmp_path):
        s = _store(tmp_path)
        s.record(_incident("alpha", ["CODE-001"]))
        hits = s.recall_similar(["CODE-001"], exclude_scenario="alpha")
        assert hits == []

    def test_empty_store_returns_empty(self, tmp_path):
        s = _store(tmp_path)
        assert s.recall_similar(["CODE-001"]) == []

    def test_render_fewshot_deterministic(self, tmp_path):
        s = _store(tmp_path)
        s.record(_incident("alpha", ["CODE-001"]))
        hits = s.recall_similar(["CODE-001"])
        text = MemoryStore.render_fewshot(hits)
        assert "alpha" in text and "CODE-001" in text


class TestMemoryDefence:
    """E.3 — signed writes, verified reads, poison rejection."""

    def test_unauthenticated_write_refused(self, tmp_path):
        s = _store(tmp_path)
        with pytest.raises(MemoryAuthError):
            s.record(_incident("evil", ["X"], source="attacker_a2a"))

    def test_tamper_is_detected(self, tmp_path):
        s = _store(tmp_path)
        rid = s.record(_incident("alpha", ["CODE-001"]))
        assert s.verify_all()["n_rejected"] == 0
        # Tamper directly in the DB, bypassing record().
        con = sqlite3.connect(str(tmp_path / "incidents.db"))
        con.execute("UPDATE incidents SET tier='soft' WHERE id=?", (rid,))
        con.commit(); con.close()
        sweep = s.verify_all()
        assert sweep["n_rejected"] == 1 and rid in sweep["rejected"]

    def test_recall_skips_tampered_rows(self, tmp_path):
        s = _store(tmp_path)
        good = s.record(_incident("good", ["CODE-001"]))
        bad = s.record(_incident("bad", ["CODE-001"]))
        con = sqlite3.connect(str(tmp_path / "incidents.db"))
        con.execute("UPDATE incidents SET confidence=0.999 WHERE id=?", (bad,))
        con.commit(); con.close()
        names = [h.scenario for h in s.recall_similar(["CODE-001"], k=5)]
        assert "good" in names and "bad" not in names

    def test_forged_source_row_is_rejected_on_read(self, tmp_path):
        s = _store(tmp_path)
        # Insert a row with a valid-looking signature but an unauthenticated
        # source by writing straight to the DB (simulating a poisoned entry).
        con = sqlite3.connect(str(tmp_path / "incidents.db"))
        con.execute(
            "INSERT INTO incidents (created_at, mode, scenario, rule_ids, "
            "asset_categories, tier, confidence, action_kind, guard_allowed, "
            "source, signature) VALUES "
            "('2026-01-01T00:00:00','defense','poison','[\"CODE-001\"]','[]',"
            "'hard',0.9,'isolate_node',1,'attacker','deadbeef')")
        con.commit(); con.close()
        assert s.recall_similar(["CODE-001"], k=5) == []
        assert s.verify_all()["n_rejected"] == 1
