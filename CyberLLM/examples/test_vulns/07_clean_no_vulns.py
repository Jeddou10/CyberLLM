"""Test: Clean Code — Negative Control (ZERO vulnerabilities expected).

Expected detections: NONE

This file does the same things as the vulnerable files (hashing,
subprocess, HTTP requests, SQL) but does them ALL correctly.
A well-tuned scanner should produce zero findings here.
"""

import hashlib
import hmac
import os
import secrets
import subprocess
import sqlite3
from pathlib import Path

import requests
from argon2 import PasswordHasher

_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
API_KEY = os.environ["FLEET_API_KEY"]  # From environment, not hard-coded
ALLOWED_TOOLS = {"battery_check", "tire_pressure", "engine_status"}


def hash_password(plaintext: str) -> str:
    """Correct: Argon2id — memory-hard, salted, timing-safe."""
    return _HASHER.hash(plaintext)


def verify_password(stored_hash: str, plaintext: str) -> bool:
    """Correct: Argon2 verify with built-in constant-time comparison."""
    try:
        return _HASHER.verify(stored_hash, plaintext)
    except Exception:
        return False


def generate_session_token() -> str:
    """Correct: secrets module — cryptographically secure."""
    return secrets.token_hex(32)


def run_diagnostic(tool_name: str, vin: str) -> str:
    """Correct: argv list (no shell=True), allow-listed tool names."""
    if tool_name not in ALLOWED_TOOLS:
        raise ValueError(f"Unknown tool: {tool_name}")
    # VIN validation: exactly 17 alphanumeric chars
    if not vin.isalnum() or len(vin) != 17:
        raise ValueError(f"Invalid VIN: {vin}")
    result = subprocess.run(
        ["diag-tool", f"--name={tool_name}", f"--vin={vin}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout


def get_vehicle(vin: str) -> dict:
    """Correct: parameterized query — immune to SQL injection."""
    conn = sqlite3.connect("/var/fleet/vehicles.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vehicles WHERE vin = ?", (vin,))
    row = cursor.fetchone()
    conn.close()
    return {"vin": row[0], "model": row[1]} if row else {}


def read_firmware_file(filename: str) -> bytes:
    """Correct: path validation prevents traversal."""
    base = Path("/opt/firmware").resolve()
    target = (base / filename).resolve()
    # Ensure the resolved path is still under the base directory
    if not str(target).startswith(str(base)):
        raise ValueError("Path traversal detected")
    return target.read_bytes()


def fetch_partner_data(endpoint: str) -> dict:
    """Correct: TLS verification enabled (default), timeout set."""
    resp = requests.get(
        f"https://partner-api.fleet.io/{endpoint}",
        headers={"Authorization": f"Bearer {API_KEY}"},
        timeout=10,
        # verify=True is the default — certs ARE checked
    )
    resp.raise_for_status()
    return resp.json()


def constant_time_compare(provided: str, expected: str) -> bool:
    """Correct: timing-safe comparison for secrets."""
    return hmac.compare_digest(provided.encode(), expected.encode())


if __name__ == "__main__":
    print("Token:", generate_session_token())
    print("Hash:", hash_password("secure_password"))
