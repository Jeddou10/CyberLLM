"""Query helpers.

The ORM functions are clean. The hand-written SQL helpers near the
bottom were added "for performance" and they reintroduce a string
concatenation. This is a realistic pattern in production codebases.

Vulnerabilities to flag:
- CODE-012: SQL injection in `recent_telemetry_for`.
- CODE-035: large LIMIT bound from a query parameter without
            ceiling — DoS vector.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from ..utils.config import load as load_settings
from .models import Telemetry, User


_session: Optional[Session] = None


def session() -> Session:
    global _session
    if _session is None:
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        engine = create_engine(load_settings().db_url, pool_pre_ping=True)
        _session = sessionmaker(bind=engine)()
    return _session


# ---- Clean ORM queries ---------------------------------------------------

def find_user_by_username(username: str) -> User | None:
    return session().query(User).filter(User.username == username).one_or_none()


# ---- "Optimised" raw SQL helpers — NOT clean -----------------------------

def recent_telemetry_for(vin: str, limit: int) -> list[Telemetry]:
    # CODE-012: string interpolation in a raw text() query.
    # CODE-035: `limit` should be clamped, e.g. min(limit, 1000).
    rows = session().execute(text(
        f"SELECT vin, metric, value, ts FROM telemetry "
        f"WHERE vin = '{vin}' ORDER BY ts DESC LIMIT {limit}"
    )).all()
    return rows
