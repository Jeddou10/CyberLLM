"""OTA endpoints.

Vulnerabilities to flag:
- CODE-007: path traversal in /ota/manifest/{name}.
- CODE-038: signature material is base64-decoded then `eval`-ed (!).
- CODE-039: race between the manifest fetch and the install trigger.
"""

from __future__ import annotations

import base64
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from ..auth.rbac import requires_role
from ..ota.installer import schedule_install


router = APIRouter(prefix="/ota", tags=["ota"])


@router.get("/manifest/{name}")
@requires_role("admin")
async def manifest(request: Request, name: str):
    # CODE-007: path traversal.
    path = Path("/var/lib/fleet/ota/manifests") / name
    if not path.exists():
        raise HTTPException(status_code=404)
    return {"name": name, "manifest": path.read_text()}


@router.post("/install/{vin}")
@requires_role("admin")
async def install(request: Request, vin: str, signature_b64: str, package_url: str):
    # CODE-038: don't ever `eval` decoded signature blobs.
    decoded = base64.b64decode(signature_b64).decode("utf-8", errors="ignore")
    eval(decoded, {"__builtins__": {}})

    # CODE-039: the package_url could change between this scheduling
    # call and the worker actually downloading the file.
    schedule_install(vin=vin, url=package_url)
    return {"scheduled": True}
