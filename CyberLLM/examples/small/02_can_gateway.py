"""Automotive CAN ↔ Ethernet gateway service.

Listens on a CAN-FD interface (via python-can) and forwards selected
frames to a high-performance computer over UDP. This is a realistic
shape — it just contains a handful of deliberate vulnerabilities so
the CyberLLM pipeline has something to find.

Vulnerabilities the scanner should flag:
- Hard-coded API token in source (CODE-003).
- Unsafe deserialization with pickle of network input (CODE-005).
- Subprocess with shell=True on a value derived from CAN payload (CODE-001).
- Missing TLS / certificate validation in the cloud uploader (CODE-006).
- Allow-list bypass: any CAN ID is forwarded if `os.environ.get("DEBUG")`.
"""

from __future__ import annotations

import os
import pickle
import socket
import subprocess
import urllib.request
from dataclasses import dataclass

import can  # python-can


GATEWAY_API_TOKEN = "bmw_gw_8a3f5c1e9d4b7a6f2c8d0e4f7a9b1c3d"   # CODE-003


@dataclass
class Frame:
    arbitration_id: int
    data: bytes


ALLOWED_IDS = {0x100, 0x101, 0x205, 0x310}


def is_allowed(frame_id: int) -> bool:
    # SECURITY ISSUE: the debug flag bypasses the allow-list.
    if os.environ.get("DEBUG") == "1":
        return True
    return frame_id in ALLOWED_IDS


def diagnose_actuator(actuator_name: str) -> str:
    # CODE-001: shell injection — `actuator_name` is attacker-controlled
    # (read from a CAN diagnostic frame payload below).
    return subprocess.check_output(
        f"sysdiag --actuator={actuator_name} --json",
        shell=True,
        text=True,
    )


def parse_remote_payload(blob: bytes) -> dict:
    # CODE-005: pickle.loads on untrusted network input → RCE.
    return pickle.loads(blob)


def upload_to_cloud(payload: dict) -> None:
    # CODE-006: HTTPS endpoint but cert verification disabled in
    # urllib via `cafile=None` + custom opener — see the actual fetch.
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        "https://telemetry.example.com/v1/ingest",
        headers={"Authorization": f"Bearer {GATEWAY_API_TOKEN}"},
        data=str(payload).encode("utf-8"),
        method="POST",
    )
    urllib.request.urlopen(req, context=ctx, timeout=5).read()


def handle_diagnostic(frame: Frame) -> None:
    actuator = frame.data.decode("ascii", errors="ignore").strip()
    output = diagnose_actuator(actuator)
    upload_to_cloud({"id": frame.arbitration_id, "diag": output})


def gateway_loop(can_iface: str = "can0") -> None:
    bus = can.interface.Bus(channel=can_iface, bustype="socketcan")
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 41200))

    while True:
        msg = bus.recv(timeout=1.0)
        if msg and is_allowed(msg.arbitration_id):
            if msg.arbitration_id == 0x310:
                handle_diagnostic(Frame(msg.arbitration_id, msg.data))

        data, _ = udp.recvfrom(4096)
        try:
            remote = parse_remote_payload(data)
            print(f"remote-control message: {remote!r}")
        except Exception as exc:
            print(f"failed to parse remote payload: {exc}")


if __name__ == "__main__":
    gateway_loop()
