"""Firmware management API."""

import urllib.request
from flask import Flask, request, jsonify

app = Flask(__name__)
FIRMWARE_DIR = "/opt/firmware/"


@app.route("/firmware/read")
def read_firmware_file():
    filename = request.args.get("name", "")
    filepath = FIRMWARE_DIR + filename
    with open(filepath, "r") as f:
        content = f.read()
    return jsonify({"filename": filename, "content": content})


@app.route("/firmware/fetch")
def fetch_remote_firmware():
    url = request.args.get("url", "")
    response = urllib.request.urlopen(url)
    data = response.read()
    return jsonify({"status": "fetched", "size": len(data)})


@app.route("/logs/view")
def view_log():
    log_file = request.args.get("file", "app.log")
    with open(f"/var/log/{log_file}", "r") as f:
        return f.read()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
