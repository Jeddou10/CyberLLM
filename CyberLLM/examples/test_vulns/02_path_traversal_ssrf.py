"""Test: Path Traversal + Server-Side Request Forgery (SSRF).

Expected detections:
  - CODE-007: Path traversal (open with user input containing ../)
  - CODE-026: SSRF (fetching URL from user-controlled input)
  - CODE-037: Arbitrary file read via path parameter

This file simulates a firmware management API that fetches and reads
files based on user-supplied parameters — without validation.
"""

import urllib.request
from flask import Flask, request, jsonify

app = Flask(__name__)
FIRMWARE_DIR = "/opt/firmware/"


@app.route("/firmware/read")
def read_firmware_file():
    """CODE-007 + CODE-037: path traversal — user controls the filename."""
    filename = request.args.get("name", "")
    # No sanitization! Attacker sends: ?name=../../../etc/passwd
    filepath = FIRMWARE_DIR + filename
    with open(filepath, "r") as f:
        content = f.read()
    return jsonify({"filename": filename, "content": content})


@app.route("/firmware/fetch")
def fetch_remote_firmware():
    """CODE-026: SSRF — user supplies the URL to fetch."""
    url = request.args.get("url", "")
    # Attacker sends: ?url=http://169.254.169.254/latest/meta-data/
    # No allow-list, no schema check, no internal IP blocking
    response = urllib.request.urlopen(url)
    data = response.read()
    return jsonify({"status": "fetched", "size": len(data)})


@app.route("/logs/view")
def view_log():
    """CODE-007: another path traversal via log_file parameter."""
    log_file = request.args.get("file", "app.log")
    # Attacker: ?file=../../../../etc/shadow
    with open(f"/var/log/{log_file}", "r") as f:
        return f.read()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
