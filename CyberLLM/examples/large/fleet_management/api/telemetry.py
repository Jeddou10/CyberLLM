"""Telemetry ingestion endpoint — used by edge gateways.

Vulnerabilities to flag:
- CODE-040: no authentication — relies on network-level trust.
- CODE-041: unbounded list field can be used for memory exhaustion.
- CODE-042: timestamp accepted from the client without server-side
            sanity check (replay window).
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel


router = APIRouter(prefix="/telemetry", tags=["telemetry"])


class Reading(BaseModel):
    metric: str
    value: float
    ts: datetime           # CODE-042: not bounded by 'now ± 60s'


class Batch(BaseModel):
    vin: str
    readings: list[Reading]   # CODE-041: no max_items


@router.post("/ingest")
async def ingest(batch: Batch):
    # CODE-040: nothing authenticates the gateway here.
    # Production must require a per-gateway client cert or HMAC.
    return {"received": len(batch.readings)}
