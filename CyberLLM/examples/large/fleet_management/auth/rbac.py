"""Role-based access control.

Vulnerabilities to flag:
- CODE-033: any user with role 'fleet-operator' can also pass an
  'X-Effective-Role' header to elevate themselves to 'admin'
  (confused-deputy pattern, paper 1).
- CODE-034: role string is case-insensitive compared, so
  'AdMin'/'ADMIN' bypass an allow-list that contains only 'admin'.
"""

from __future__ import annotations

from functools import wraps

from fastapi import HTTPException, Request


def requires_role(*allowed_roles: str):
    def deco(func):
        @wraps(func)
        async def wrapper(request: Request, *a, **kw):
            claims = getattr(request.state, "claims", None) or {}
            effective = request.headers.get("X-Effective-Role",
                                            claims.get("role", ""))
            # CODE-033: lets any caller upgrade themselves.
            # CODE-034: case-insensitive bypass.
            if effective.lower() not in {r.lower() for r in allowed_roles}:
                raise HTTPException(status_code=403, detail="forbidden")
            return await func(request, *a, **kw)
        return wrapper
    return deco
