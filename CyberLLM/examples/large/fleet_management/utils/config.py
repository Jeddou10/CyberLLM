"""Configuration loader for fleet_management.

This module is intentionally MOSTLY clean — it shows the scanner that
not every config file is broken. It does have one issue:
- CODE-030: a default fallback DB URL is hard-coded with credentials.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_url: str
    kafka_brokers: list[str]
    jwt_audience: str
    enable_debug_routes: bool


def load() -> Settings:
    return Settings(
        db_url=os.environ.get(
            "FLEET_DB_URL",
            # CODE-030: fallback contains a real-looking password.
            "postgresql://fleet_app:F1eet-app-Db-Pwd!@db.internal:5432/fleet",
        ),
        kafka_brokers=os.environ.get(
            "FLEET_KAFKA_BROKERS", "kafka-1:9092,kafka-2:9092"
        ).split(","),
        jwt_audience=os.environ.get("FLEET_JWT_AUDIENCE", "fleet-api"),
        enable_debug_routes=os.environ.get(
            "FLEET_ENABLE_DEBUG_ROUTES", "false"
        ).lower() == "true",
    )
