"""JWT key management — fully clean (negative control).

Loads RS256 keypairs from disk paths supplied via environment.
Demonstrates the scanner should NOT raise findings here.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def private_key() -> bytes:
    return Path(os.environ["FLEET_JWT_PRIVATE_KEY_PATH"]).read_bytes()


@lru_cache(maxsize=1)
def public_key() -> bytes:
    return Path(os.environ["FLEET_JWT_PUBLIC_KEY_PATH"]).read_bytes()
