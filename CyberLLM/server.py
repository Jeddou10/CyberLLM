"""CyberLLM — local web server (a polished UI over the defense pipeline).

Zero new dependencies: this uses only Python's stdlib `http.server`. It
serves the single-page app in `webapp/index.html` and a small JSON API:

    GET  /                 → the SPA
    GET  /api/health       → which LLM provider is active + tool availability
    GET  /api/examples     → bundled example snippets the UI can load
    POST /api/scan         → run the static-first defense pipeline on the
                             posted code (+ optional log / deployment) and
                             return a detailed, UI-ready result

Run:
    python server.py                      # http://127.0.0.1:8000
    python server.py --port 9000 --host 0.0.0.0

Safety: the action engine is forced to **dry-run** here (no real OS command
runs from a browser button). Detection (regex + bandit/semgrep + optional
LLM) is real. "Deep (AI)" mode uses the configured LLM (Azure gpt-4o) only
when real credentials are present; otherwise the scan is the deterministic
regex + bandit layers (the stub's canned findings are never shown on real
code).
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import tempfile
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Browser buttons must never trigger destructive OS commands.
os.environ.setdefault("CYBERLLM_FORCE_DRY_RUN", "1")

import pipeline
from llm_client import LLMClient, StubLLM
from tools.static_analyzer import _analyzer_cmd

HERE = Path(__file__).resolve().parent
WEBAPP = HERE / "webapp"

# Cached config + rules (loaded once); scans copy + tweak the config.
_CFG = pipeline.load_config()
_RULES = pipeline.load_rules(_CFG)
_SCAN_LOCK = threading.Lock()        # serialise scans (RUN_LOGS_DIR is global)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _provider_info() -> dict:
    """What LLM the 'deep' mode would use, plus tool availability. Never
    makes a network call — it only constructs the client object."""
    try:
        client = LLMClient.create(dict(_CFG["llm_configs"]["default"]))
        impl = type(client).__name__
        model = client.cfg.get("model", "?")
        real = not isinstance(client, StubLLM)
    except Exception:               # noqa: BLE001
        impl, model, real = "StubLLM", "stub", False
    # bandit/semgrep may be importable as a module without an .exe on PATH
    # (typical for `pip install --user` on Windows) — count those as available.
    tools = {b: _analyzer_cmd(b) is not None for b in ("bandit", "semgrep")}
    tools.update({b: bool(shutil.which(b)) for b in ("nmap", "tshark", "tcpdump")})
    return {
        "llm_impl": impl,
        "llm_model": model,
        "llm_real": real,
        "tools": tools,
    }


def run_web_scan(code: str, filename: str = "input.py",
                 log_text: str | None = None,
                 deployment_text: str | None = None,
                 deep: bool = False) -> dict:
    """Run the defense pipeline on pasted content in an isolated temp
    workspace and return a UI-ready result. Thread-safe (serialised)."""
    info = _provider_info()
    # Deep (AI) mode is only honoured when a real LLM is actually available;
    # otherwise we fall back to the deterministic regex + bandit layers.
    effective_deep = bool(deep) and info["llm_real"]
    has_log = bool((log_text or "").strip())
    has_dep = bool((deployment_text or "").strip())

    with _SCAN_LOCK:
        tmp = Path(tempfile.mkdtemp(prefix="cyberllm_web_"))
        prev_runlogs = pipeline.RUN_LOGS_DIR
        prev_force_stub = os.environ.get("CYBERLLM_FORCE_STUB")
        try:
            code_file = tmp / (Path(filename).name or "input.py")
            code_file.write_text(code, encoding="utf-8")
            # When the user supplies no log / deployment we write EMPTY inputs
            # (not a sample) so neither the static nor the LLM pass invents
            # log/topology findings the user never asked about.
            log_file = tmp / "input.log"
            log_file.write_text(log_text if has_log else "", encoding="utf-8")
            dep_file = tmp / "deployment.yaml"
            dep_file.write_text(
                deployment_text if has_dep
                else "actors: []\ndatasources: []\nedges: []\n",
                encoding="utf-8")

            cfg = copy.deepcopy(_CFG)
            cfg["paths"]["memory_dir"] = str(tmp / "memory")
            cfg.setdefault("memory", {})["enabled"] = False     # stateless per scan
            cfg.setdefault("scanners", {})
            cfg["scanners"]["external_static"] = True            # real bandit/semgrep
            cfg["scanners"]["use_llm"] = effective_deep          # code scanner
            # log / topology LLM only when the user actually supplied that input
            cfg["scanners"]["use_llm_log"] = effective_deep and has_log
            cfg["scanners"]["use_llm_deployment"] = effective_deep and has_dep
            cfg.setdefault("action_engine", {})
            cfg["action_engine"]["max_replan_rounds"] = 1        # snappy
            cfg["action_engine"]["llm_tool_selection"] = False

            # Static / non-deep scans force the offline stub so they are
            # instant and never call the network; deep scans use the real
            # provider (Azure gpt-4o).
            if not effective_deep:
                os.environ["CYBERLLM_FORCE_STUB"] = "1"
            elif prev_force_stub is None:
                os.environ.pop("CYBERLLM_FORCE_STUB", None)

            pipeline.RUN_LOGS_DIR = tmp / "run_logs"
            record = pipeline.run_defense_pipeline(
                [code_file], log_file, dep_file, cfg, _RULES,
                scenario_name="web", verbose=False)
            return {
                "ok": True,
                "deep": effective_deep,
                "deep_requested": bool(deep),
                "provider": info,
                "filename": Path(filename).name,
                "code": code,
                "record": record,
            }
        finally:
            pipeline.RUN_LOGS_DIR = prev_runlogs
            if prev_force_stub is None:
                os.environ.pop("CYBERLLM_FORCE_STUB", None)
            else:
                os.environ["CYBERLLM_FORCE_STUB"] = prev_force_stub
            shutil.rmtree(tmp, ignore_errors=True)


def _examples() -> list[dict]:
    """A few bundled snippets the UI can load (so users see it work fast)."""
    out = []
    for rel in ("examples/small/02_can_gateway.py",
                "examples/small/04_telemetry_uploader.py",
                "examples/medium/ev_charging_api/db.py",
                "examples/small/01_clean_auth.py"):
        p = HERE / rel
        if p.exists():
            out.append({"name": p.name, "filename": p.name,
                        "code": p.read_text(encoding="utf-8", errors="replace")})
    return out


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "CyberLLM/1.0"

    # quieter logging
    def log_message(self, fmt, *args):       # noqa: A003
        print(f"  [web] {self.address_string()} {fmt % args}")

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            f = WEBAPP / "index.html"
            if not f.exists():
                return self._json(500, {"ok": False,
                                        "error": "webapp/index.html missing"})
            return self._send(200, f.read_bytes(), "text/html; charset=utf-8")
        if self.path == "/api/health":
            return self._json(200, {"ok": True, **_provider_info()})
        if self.path == "/api/examples":
            return self._json(200, {"ok": True, "examples": _examples()})
        return self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if self.path != "/api/scan":
            return self._json(404, {"ok": False, "error": "not found"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}")
            code = (payload.get("code") or "").strip()
            if not code:
                return self._json(400, {"ok": False, "error": "no code provided"})
            result = run_web_scan(
                code=code,
                filename=payload.get("filename") or "input.py",
                log_text=payload.get("log") or None,
                deployment_text=payload.get("deployment") or None,
                deep=bool(payload.get("deep")),
            )
            return self._json(200, result)
        except Exception as exc:        # noqa: BLE001
            traceback.print_exc()
            return self._json(500, {"ok": False,
                                    "error": f"{type(exc).__name__}: {exc}"})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CyberLLM local web UI server.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)

    info = _provider_info()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print("=" * 64)
    print(" CyberLLM web UI")
    print(f"   URL       : http://{args.host}:{args.port}")
    print(f"   LLM (deep): {info['llm_impl']}<{info['llm_model']}> "
          f"({'real' if info['llm_real'] else 'offline stub'})")
    print(f"   analysers : " + ", ".join(
        f"{b}={'yes' if ok else 'no'}" for b, ok in info["tools"].items()))
    print("   actions   : DRY-RUN (no real OS command runs from the browser)")
    print("=" * 64, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
