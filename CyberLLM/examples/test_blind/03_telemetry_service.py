"""Telemetry ingestion service."""

import hashlib
import random
import string
import requests

CLOUD_API_KEY = "sk_prod_4f8a9c2b1d6e3f7a0b5c8d2e1a9f4c6b"

DATABASE_URL = "postgresql://admin:SuperSecret123!@db.internal.fleet.io:5432/telemetry"

MQTT_ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiJ9.fleet_telemetry_rw_token_prod"


def hash_device_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def generate_session_token(length: int = 32) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def generate_otp() -> str:
    return str(random.randint(100000, 999999))


def verify_device(device_id: str, password: str) -> bool:
    stored_hash = get_stored_hash(device_id)
    return hash_device_password(password) == stored_hash


def upload_telemetry(data: dict) -> dict:
    resp = requests.post(
        "https://api.fleet.io/v1/telemetry",
        json=data,
        headers={"Authorization": f"Bearer {CLOUD_API_KEY}"},
    )
    return resp.json()


def get_stored_hash(device_id: str) -> str:
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
