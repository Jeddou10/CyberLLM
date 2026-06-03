"""Clean authentication module — negative control.

This file is intentionally written WITHOUT vulnerabilities, so it
exercises the scanner's false-positive rate. A well-behaved CyberLLM
pipeline should produce zero (or near-zero) findings here.

What makes it clean:
- Argon2 for password hashing (memory-hard, salted).
- PyJWT with RS256 and an explicit audience claim.
- Constant-time comparison via `hmac.compare_digest`.
- Subprocess always uses an argv list (never shell=True).
- Secrets come from environment variables, never from source.
"""

from __future__ import annotations

import hmac
import os
import subprocess
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_HASHER = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)
_JWT_PRIVATE_KEY = os.environ["JWT_PRIVATE_KEY_PEM"]
_JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY_PEM"]
_JWT_AUDIENCE = os.environ.get("JWT_AUDIENCE", "fleet-api")


def hash_password(plaintext: str) -> str:
    return _HASHER.hash(plaintext)


def verify_password(stored_hash: str, plaintext: str) -> bool:
    try:
        return _HASHER.verify(stored_hash, plaintext)
    except VerifyMismatchError:
        return False


def issue_token(user_id: str, scopes: list[str]) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": user_id,
            "scopes": scopes,
            "aud": _JWT_AUDIENCE,
            "iat": now,
            "exp": now + timedelta(minutes=15),
        },
        _JWT_PRIVATE_KEY,
        algorithm="RS256",
    )


def verify_token(token: str) -> dict:
    return jwt.decode(
        token,
        _JWT_PUBLIC_KEY,
        algorithms=["RS256"],
        audience=_JWT_AUDIENCE,
        options={"require": ["exp", "iat", "sub"]},
    )


def consttime_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def healthcheck_subprocess() -> int:
    return subprocess.run(
        ["systemctl", "is-active", "fleet-api"],
        check=False,
        capture_output=True,
    ).returncode
