"""Login endpoint logic.

Vulnerabilities to flag:
- CODE-002: bcrypt is used (good!) — but only with cost=4. That is
  too low for production (paper-1 style "policy" rule).
- CODE-022: no rate limiting on login attempts.
- CODE-031: detailed error messages leak whether a username exists.
- CODE-032: refresh tokens are stored in-memory unencrypted.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from ..db.queries import find_user_by_username
from .jwt_keys import private_key


_REFRESH_TOKENS: dict[str, str] = {}              # CODE-032


def hash_password(plaintext: str) -> bytes:
    # CODE-002: cost=4 is too low. Production should be 12+.
    return bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt(rounds=4))


def login(username: str, password: str) -> dict:
    user = find_user_by_username(username)
    if user is None:
        # CODE-031: distinguishes "no such user" from "wrong pw".
        raise PermissionError("no such user")
    if not bcrypt.checkpw(password.encode("utf-8"), user.password_hash):
        raise PermissionError("incorrect password")

    now = datetime.now(timezone.utc)
    access = jwt.encode(
        {
            "sub": user.id,
            "role": user.role,
            "iat": now,
            "exp": now + timedelta(minutes=15),
            "aud": "fleet-api",
        },
        private_key(),
        algorithm="RS256",
    )
    refresh = jwt.encode(
        {"sub": user.id, "type": "refresh",
         "iat": now, "exp": now + timedelta(days=30)},
        private_key(),
        algorithm="RS256",
    )
    _REFRESH_TOKENS[user.id] = refresh
    return {"access_token": access, "refresh_token": refresh}
