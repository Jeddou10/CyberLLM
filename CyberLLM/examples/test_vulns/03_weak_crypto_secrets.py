"""Test: Weak Cryptography + Hard-coded Secrets.

Expected detections:
  - CODE-002: Weak hash (MD5) for credentials
  - CODE-003: Hard-coded secrets (API keys, tokens)
  - CODE-008: Non-cryptographic randomness for security
  - CODE-030: Hard-coded credential in connection string

This file simulates a telemetry service that has terrible
cryptographic and secrets management practices.
"""

import hashlib
import random
import string
import requests

# CODE-003: Hard-coded API key in source
CLOUD_API_KEY = "sk_prod_4f8a9c2b1d6e3f7a0b5c8d2e1a9f4c6b"

# CODE-030: Hard-coded credential in database connection string
DATABASE_URL = "postgresql://admin:SuperSecret123!@db.internal.fleet.io:5432/telemetry"

# CODE-003: Another hard-coded token
MQTT_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiJ9.fleet_telemetry_rw_token_prod"


def hash_device_password(password: str) -> str:
    """CODE-002: Using MD5 for password storage — trivially crackable."""
    return hashlib.md5(password.encode()).hexdigest()


def generate_session_token(length: int = 32) -> str:
    """CODE-008: Using random (Mersenne Twister) for session tokens.
    
    This is predictable — attacker can reproduce the PRNG state.
    Should use secrets.token_hex() instead.
    """
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def generate_otp() -> str:
    """CODE-008: Predictable OTP — random.randint is not crypto-secure."""
    return str(random.randint(100000, 999999))


def verify_device(device_id: str, password: str) -> bool:
    """Uses the weak MD5 hash for verification."""
    stored_hash = get_stored_hash(device_id)  # from DB
    return hash_device_password(password) == stored_hash


def upload_telemetry(data: dict) -> dict:
    """Sends data to cloud using hard-coded credentials."""
    resp = requests.post(
        "https://api.fleet.io/v1/telemetry",
        json=data,
        headers={"Authorization": f"Bearer {CLOUD_API_KEY}"},
    )
    return resp.json()


def get_stored_hash(device_id: str) -> str:
    """Placeholder — would query the DB using the hard-coded URL."""
    import psycopg2
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM devices WHERE id = %s", (device_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else ""


if __name__ == "__main__":
    print("Hash:", hash_device_password("device_pass_123"))
    print("Token:", generate_session_token())
    print("OTP:", generate_otp())
