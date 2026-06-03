"""Authentication for the EV-charging API.

Vulnerabilities to flag:
- CODE-002: SHA-1 / MD5 for password hashing (here SHA-1 + no salt).
- CODE-008: secrets.compare not used for token comparison.
- CODE-020: JWT with `algorithms=['none']` accepted (alg confusion).
- CODE-021: timing-attack-friendly login (no constant time).
- CODE-022: missing rate-limiting on /login.
"""

from __future__ import annotations

import hashlib
from functools import wraps

import jwt
from flask import Flask, abort, request


JWT_SECRET = "ev-charging-shared-secret-123"      # CODE-003


def init_app(app: Flask) -> None:
    @app.route("/login", methods=["POST"])
    def login():  # CODE-022: no rate limit decorator
        body = request.get_json(force=True) or {}
        username = body.get("username", "")
        password = body.get("password", "")
        user = _lookup_user(username)
        if not user:
            abort(401)
        # CODE-021: short-circuit, length-leaking comparison.
        if hashlib.sha1(password.encode("utf-8")).hexdigest() == user["pwhash"]:
            return {"token": _issue(username)}
        abort(401)


def _lookup_user(username: str) -> dict | None:
    # SECURITY ISSUE: lookup is implemented in db.py with a SQL
    # injection. We just call into it here.
    from .db import find_user
    return find_user(username)


def _issue(username: str) -> str:
    return jwt.encode({"sub": username, "scope": "fleet"}, JWT_SECRET, algorithm="HS256")


def requires_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        try:
            # CODE-020: 'none' is allowed → attackers can forge tokens.
            claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256", "none"])
        except jwt.PyJWTError:
            abort(401)
        request.claims = claims  # type: ignore[attr-defined]
        return f(*a, **kw)
    return wrapper
