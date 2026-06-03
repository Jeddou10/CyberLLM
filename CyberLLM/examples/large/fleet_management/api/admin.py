"""Admin endpoints.

Vulnerabilities to flag:
- CODE-026: SSRF in /admin/proxy.
- CODE-037: arbitrary file read in /admin/logs.
- CODE-001: shell injection in /admin/exec.
- CODE-018: missing CSRF token on a state-changing endpoint.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import requests
from fastapi import APIRouter, HTTPException, Request

from ..auth.rbac import requires_role


router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/proxy")
@requires_role("admin")
async def proxy(request: Request, url: str):
    # CODE-026: SSRF — server fetches an attacker-supplied URL.
    r = requests.get(url, timeout=5, verify=False)
    return {"status": r.status_code, "body": r.text[:1024]}


@router.get("/logs")
@requires_role("admin")
async def fetch_log(request: Request, path: str):
    # CODE-037: path traversal — `path` is concatenated directly.
    full = Path("/var/log/fleet") / path
    if not full.exists():
        raise HTTPException(status_code=404)
    return full.read_text()


@router.post("/exec")
async def exec_command(request: Request, cmd: str):
    # CODE-018: state-changing endpoint with no auth decorator,
    # no CSRF check, and an obvious RCE primitive on top.
    out = subprocess.check_output(cmd, shell=True, text=True)
    return {"out": out}
