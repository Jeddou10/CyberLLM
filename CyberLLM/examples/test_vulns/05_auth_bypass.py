"""Test: Authentication & Authorization Bypass.

Expected detections:
  - CODE-020: JWT algorithm 'none' accepted
  - CODE-033: Authorization trusts client-supplied role header
  - CODE-036: IDOR — no ownership check on resource access
  - CODE-006: TLS certificate verification disabled
  - CODE-040: Sensitive endpoint without authentication

This file simulates a fleet management API with broken
authentication and authorization logic.
"""

import jwt
import requests
from flask import Flask, request, jsonify, abort

app = Flask(__name__)
SECRET_KEY = "fleet-jwt-secret"


def decode_token(token: str) -> dict:
    """CODE-020: Accepts 'none' algorithm — attacker forges tokens freely.
    
    Attacker removes signature, sets alg='none' in header,
    and the server happily trusts the payload.
    """
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])


def get_user_role(headers: dict) -> str:
    """CODE-033: Trusts client-supplied X-User-Role header.
    
    Attacker just sends: X-User-Role: admin
    Server treats them as admin without verification.
    """
    return headers.get("X-User-Role", "viewer")


@app.route("/vehicles/<vehicle_id>/location")
def get_vehicle_location(vehicle_id: str):
    """CODE-036: IDOR — any authenticated user can query any vehicle.
    
    No check that the requesting user actually owns or has
    access to the specified vehicle_id.
    """
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = decode_token(token)
    # BUG: Should verify user["sub"] has access to vehicle_id
    location = query_vehicle_location(vehicle_id)
    return jsonify(location)


@app.route("/admin/reset-all", methods=["POST"])
def admin_reset():
    """CODE-033: Role from header — no server-side check."""
    role = get_user_role(request.headers)
    if role == "admin":
        # Dangerous action protected only by a client header!
        reset_all_vehicles()
        return jsonify({"status": "all vehicles reset"})
    return abort(403)


@app.route("/debug/dump-db")
def dump_database():
    """CODE-040: Sensitive endpoint with NO authentication at all.
    
    Anyone who knows the URL can dump the entire database.
    """
    import sqlite3
    conn = sqlite3.connect("/var/fleet/vehicles.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vehicles")
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)


def fetch_partner_api(endpoint: str) -> dict:
    """CODE-006: TLS verification disabled — MITM possible.
    
    Attacker on the network can intercept and modify responses.
    """
    resp = requests.get(
        f"https://partner-api.fleet.io/{endpoint}",
        verify=False,  # Disables certificate checking!
    )
    return resp.json()


# Helper stubs
def query_vehicle_location(vid: str) -> dict:
    return {"vehicle_id": vid, "lat": 48.1351, "lon": 11.5820}

def reset_all_vehicles():
    pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9090)
