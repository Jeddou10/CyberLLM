"""Vehicle endpoints.

Vulnerabilities to flag:
- CODE-036: IDOR — any authenticated user can fetch any VIN's history
  because the endpoint trusts the path parameter directly without
  checking ownership.
- CODE-027: VIN logged at INFO level alongside last-seen position.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request

from ..auth.rbac import requires_role
from ..db.queries import recent_telemetry_for


router = APIRouter(prefix="/vehicles", tags=["vehicles"])
log = logging.getLogger("fleet.api.vehicles")


@router.get("/{vin}/history")
@requires_role("fleet-operator", "admin")
async def vehicle_history(request: Request, vin: str, limit: int = 100):
    # CODE-036: no ownership check. A fleet-operator from company A
    # can pull company B's telemetry by guessing/scraping VINs.
    rows = recent_telemetry_for(vin, limit)
    # CODE-027: PII (VIN) in logs.
    log.info("history pulled vin=%s rows=%d", vin, len(rows))
    return {"vin": vin, "rows": [dict(r._mapping) for r in rows]}
