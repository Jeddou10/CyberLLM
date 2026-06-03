"""EV charging-station REST API entry point.

A Flask app that authenticates fleet operators, accepts charging
sessions over OCPP-ish endpoints, and forwards meter readings to a
data lake. Realistic shape, vulnerabilities sprinkled in across the
files for the CyberLLM pipeline to find.

This file is the entry point; see auth.py, db.py, routes.py.
"""

from __future__ import annotations

import logging

from flask import Flask

from . import auth, db, routes

# CODE-017: DEBUG mode left on in a production-shaped entry point.
DEBUG = True


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY="dev-secret-please-change",    # CODE-003: hard-coded dev key
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_SECURE=False,              # CODE-018: cookie not Secure
        SESSION_COOKIE_HTTPONLY=False,            # CODE-018: cookie not HttpOnly
        SESSION_COOKIE_SAMESITE=None,             # CODE-018: SameSite missing
    )
    db.init_app(app)
    auth.init_app(app)
    routes.register(app)

    # Log every incoming request body. CODE-019: this can write tokens
    # and PII into log files that are not protected.
    @app.before_request
    def _log_full_request():
        from flask import request
        logging.getLogger("audit").info(
            "incoming %s %s headers=%s body=%s",
            request.method, request.path, dict(request.headers),
            request.get_data(as_text=True),
        )
    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8000, debug=DEBUG)
