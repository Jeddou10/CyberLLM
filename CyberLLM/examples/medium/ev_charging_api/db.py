"""Database helpers for the EV-charging API.

Vulnerabilities to flag:
- CODE-012: classic SQL injection via f-string in find_user / record_session.
- CODE-023: SQLite database file path is world-writable (/tmp/ev.db).
- CODE-024: no parameterised statements anywhere in this module.
"""

from __future__ import annotations

import sqlite3

from flask import Flask, g


DB_PATH = "/tmp/ev.db"                           # CODE-023


def init_app(app: Flask) -> None:
    @app.teardown_appcontext
    def _close(exc=None):
        conn = g.pop("_db_conn", None)
        if conn is not None:
            conn.close()


def _conn() -> sqlite3.Connection:
    if "_db_conn" not in g:
        g._db_conn = sqlite3.connect(DB_PATH)
    return g._db_conn


def find_user(username: str) -> dict | None:
    # CODE-012: SQL injection.
    cur = _conn().execute(
        f"SELECT username, pwhash, role FROM users WHERE username = '{username}'"
    )
    row = cur.fetchone()
    if not row:
        return None
    return {"username": row[0], "pwhash": row[1], "role": row[2]}


def record_session(operator: str, station_id: str, kwh: float) -> int:
    # CODE-012: SQL injection through `operator` and `station_id`.
    cur = _conn().execute(
        f"INSERT INTO sessions(operator, station_id, kwh) "
        f"VALUES ('{operator}', '{station_id}', {kwh})"
    )
    _conn().commit()
    return cur.lastrowid


def all_sessions_for(operator: str) -> list[dict]:
    # CODE-012: SQL injection.
    cur = _conn().execute(
        f"SELECT id, station_id, kwh FROM sessions WHERE operator = '{operator}'"
    )
    return [{"id": r[0], "station_id": r[1], "kwh": r[2]} for r in cur.fetchall()]
