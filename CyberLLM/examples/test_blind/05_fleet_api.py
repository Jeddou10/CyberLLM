"""Fleet management API."""

import jwt
import requests
from flask import Flask, request, jsonify, abort
import sqlite3

app = Flask(__name__)
SECRET_KEY = "fleet-jwt-secret"


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256", "none"])


def get_user_role(headers: dict) -> str:
    return headers.get("X-User-Role", "viewer")


@app.route("/vehicles/<vehicle_id>/location")
def get_vehicle_location(vehicle_id: str):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = decode_token(token)
    location = query_vehicle_location(vehicle_id)
    return jsonify(location)


@app.route("/admin/reset-all", methods=["POST"])
def admin_reset():
    role = get_user_role(request.headers)
    if role == "admin":
        reset_all_vehicles()
        return jsonify({"status": "all vehicles reset"})
    return abort(403)


@app.route("/debug/dump-db")
def dump_database():
    conn = sqlite3.connect("/var/fleet/vehicles.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vehicles")
    rows = cursor.fetchall()
    conn.close()
    return jsonify(rows)


def fetch_partner_api(endpoint: str) -> dict:
    resp = requests.get(
        f"https://partner-api.fleet.io/{endpoint}",
        verify=False,
    )
    return resp.json()


def query_vehicle_location(vid: str) -> dict:
    return {"vehicle_id": vid, "lat": 48.1351, "lon": 11.5820}

def reset_all_vehicles():
    pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9090)
