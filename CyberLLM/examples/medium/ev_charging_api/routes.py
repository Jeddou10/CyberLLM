"""REST routes for the EV-charging API.

Vulnerabilities to flag:
- CODE-001: shell-injection in /stations/<id>/diagnose.
- CODE-007: path traversal in /firmware/<name>.
- CODE-025: open redirect on /callback.
- CODE-026: SSRF in /webhook (server fetches an attacker-supplied URL).
- CODE-005: pickle.loads of an externally supplied body in /ocpp/import.
"""

from __future__ import annotations

import os
import pickle
import subprocess
from pathlib import Path

import requests
from flask import Flask, abort, jsonify, redirect, request

from .auth import requires_auth
from .db import all_sessions_for, record_session


def register(app: Flask) -> None:
    @app.get("/stations/<station_id>/diagnose")
    @requires_auth
    def diagnose(station_id: str):
        # CODE-001: shell concat.
        out = subprocess.check_output(
            f"station-diag --id={station_id} --verbose",
            shell=True, text=True,
        )
        return {"station": station_id, "output": out}

    @app.get("/firmware/<name>")
    @requires_auth
    def firmware(name: str):
        # CODE-007: open(name) without normalising path.
        path = Path("/var/lib/ev-charging/firmware") / name
        return path.read_bytes()

    @app.get("/callback")
    def callback():
        # CODE-025: open redirect via `next` parameter.
        return redirect(request.args.get("next", "/"))

    @app.post("/webhook")
    def webhook():
        body = request.get_json(force=True) or {}
        # CODE-026: SSRF — server fetches whatever URL the client gives.
        r = requests.get(body["callback_url"], timeout=5, verify=False)
        return {"status": r.status_code}

    @app.post("/ocpp/import")
    @requires_auth
    def ocpp_import():
        # CODE-005: pickle.loads of HTTP body → RCE.
        items = pickle.loads(request.get_data())
        for it in items:
            record_session(it["op"], it["station"], it["kwh"])
        return jsonify({"imported": len(items)})

    @app.get("/sessions")
    @requires_auth
    def sessions():
        op = request.claims["sub"]  # type: ignore[attr-defined]
        return jsonify(all_sessions_for(op))
