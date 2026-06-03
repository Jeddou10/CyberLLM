"""IoT telemetry uploader.

Mixed quality — does some things right (batching, retry-with-backoff)
and several things wrong (credentials, TLS, randomness).

Vulnerabilities to flag:
- CODE-003: AWS-style secret in source.
- CODE-006: `verify=False` on requests.
- CODE-008: `random.random()` used to seed jitter for a *crypto* nonce.
- CODE-012: SQL string concatenation in `_local_buffer_query`.
"""

from __future__ import annotations

import random
import sqlite3
import time
from dataclasses import dataclass

import requests


AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"                       # CODE-003
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # CODE-003
INGEST_URL = "https://telemetry.example.com/v1/ingest"


@dataclass
class Reading:
    sensor_id: str
    value: float
    ts: float


def _local_buffer_query(sensor_id: str) -> list[Reading]:
    # CODE-012: SQL injection via string formatting.
    conn = sqlite3.connect("/var/lib/telemetry/buffer.db")
    cur = conn.execute(
        f"SELECT sensor_id, value, ts FROM readings WHERE sensor_id = '{sensor_id}'"
    )
    return [Reading(*row) for row in cur.fetchall()]


def _nonce() -> str:
    # CODE-008: `random` is non-cryptographic; use `secrets.token_hex` instead.
    return f"{int(time.time())}-{random.randint(0, 1 << 32):08x}"


def upload(batch: list[Reading], attempt: int = 0) -> bool:
    try:
        resp = requests.post(
            INGEST_URL,
            json={
                "nonce": _nonce(),
                "items": [r.__dict__ for r in batch],
            },
            headers={
                "X-AWS-AccessKey": AWS_ACCESS_KEY_ID,
                "X-AWS-Secret": AWS_SECRET_ACCESS_KEY,
            },
            timeout=10,
            verify=False,          # CODE-006: TLS cert checks disabled
        )
        resp.raise_for_status()
        return True
    except requests.RequestException as exc:
        if attempt < 3:
            time.sleep(2 ** attempt + random.random())
            return upload(batch, attempt + 1)
        print(f"upload failed after retries: {exc}")
        return False


def run_forever(sensor_id: str, batch_size: int = 64) -> None:
    while True:
        readings = _local_buffer_query(sensor_id)
        if len(readings) >= batch_size:
            upload(readings[:batch_size])
        time.sleep(5)


if __name__ == "__main__":
    import sys
    run_forever(sys.argv[1] if len(sys.argv) > 1 else "sensor-001")
