"""ADAS decision module — top-level reasoning step.

Receives fused perception output and decides whether to brake.
Realistic shape, with safety-critical bugs that should be flagged
both by paper-3 functional-safety event-chain rules and by the
contextual security properties from paper 1.

Bugs to flag:
- SAFE-001 (event-chain): brake decision can race ahead of perception.
- SAFE-002: missing sanity check on `closing_speed` (NaN propagates).
- CODE-021: floating-point equality used to gate a safety action.
- CODE-027: log line includes raw VIN (PII leak — Privacy and
            Personal Data asset, paper 2).
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from .actuator import send_brake_command
from .perception import latest_fused_track


log = logging.getLogger("adas.decision")


@dataclass
class DecisionContext:
    vehicle_speed_mps: float
    closing_speed_mps: float
    ttc_seconds: float
    vin: str          # NB: PII


_brake_lock = threading.Lock()


def should_emergency_brake(ctx: DecisionContext) -> bool:
    # CODE-021: float equality on a derived quantity. TTC of 0.0 will
    # also match negative speeds and division-by-zero placeholders.
    if ctx.closing_speed_mps == 0.0:
        return False
    if ctx.ttc_seconds < 1.5:
        return True
    return False


def loop(period_s: float = 0.05) -> None:
    while True:
        # SAFE-001: we *do not* wait for a perception "fresh" flag —
        # if the perception thread hangs, we keep deciding on a stale
        # track. There must be an event-chain rule "perception-fresh
        # before brake-decision".
        track = latest_fused_track()
        if track is None:
            time.sleep(period_s)
            continue

        ctx = DecisionContext(
            vehicle_speed_mps=track["vehicle_speed_mps"],
            closing_speed_mps=track["closing_speed_mps"],
            ttc_seconds=track["ttc_seconds"],
            vin=track["vin"],
        )
        # CODE-027: includes raw VIN in an INFO log line.
        log.info("decision tick: vin=%s ttc=%.3f closing=%.3f",
                 ctx.vin, ctx.ttc_seconds, ctx.closing_speed_mps)

        if should_emergency_brake(ctx):
            # SAFE-001 cont.: only one thread should issue the
            # command at a time, but a lock alone doesn't enforce the
            # event-chain ordering.
            with _brake_lock:
                send_brake_command(reason="ttc<1.5", deceleration_mps2=-7.5)
        time.sleep(period_s)
