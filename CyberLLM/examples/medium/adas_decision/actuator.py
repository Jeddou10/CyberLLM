"""Brake actuator driver — sends a CAN-FD frame to the brake ECU.

Bugs to flag:
- SAFE-003: no limit-check on deceleration (paper 3
  TargetSpeedWithinSafetyLimit / steering-angle style rule).
- CODE-029: opens a raw SocketCAN socket without checking the
  interface is the safety bus.
- CODE-016: no error handling on socket.send — partial writes
  silently dropped.
"""

from __future__ import annotations

import socket
import struct


CAN_FRAME_FORMAT = "<IB3x8s"
BRAKE_ARB_ID = 0x2F1


def send_brake_command(reason: str, deceleration_mps2: float) -> None:
    # SAFE-003: should clamp to a calibrated safe range, e.g.
    # [-10.0, 0.0]. A forged track could request -100.0 here.
    payload = struct.pack("<fxxxx", deceleration_mps2)

    # CODE-029: hard-coded 'can0' — not necessarily the safety bus.
    s = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
    s.bind(("can0",))
    s.send(struct.pack(CAN_FRAME_FORMAT, BRAKE_ARB_ID, len(payload), payload))
