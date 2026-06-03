"""Perception fusion stub for the ADAS decision module.

Bugs to flag:
- SAFE-002: no integrity check on incoming sensor frames — a forged
  CAN frame can directly drive `_LAST_TRACK`.
- CODE-016: missing `None` checks on dict accesses (KeyError → silent
  fallback to zero, which can mask real hazards).
- CODE-028: thread-unsafe read/write of `_LAST_TRACK`.
"""

from __future__ import annotations

import socket
import struct
import threading

_LAST_TRACK: dict | None = None       # CODE-028: not protected by a lock


def latest_fused_track() -> dict | None:
    return _LAST_TRACK


def _ingest_loop() -> None:
    global _LAST_TRACK
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 38123))
    while True:
        data, _ = s.recvfrom(64)
        if len(data) != 24:
            continue
        # SAFE-002: data is read straight off the wire, no HMAC.
        v, c, ttc, vin_lo, vin_hi = struct.unpack("<fff8s8s", data)
        _LAST_TRACK = {
            "vehicle_speed_mps": v,
            "closing_speed_mps": c,
            "ttc_seconds": ttc,
            "vin": (vin_lo + vin_hi).decode("ascii", errors="replace"),
        }


def start() -> None:
    threading.Thread(target=_ingest_loop, daemon=True).start()
