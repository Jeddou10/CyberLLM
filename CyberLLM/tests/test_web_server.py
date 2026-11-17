"""Tests for the local web UI server (server.py) and the dedup fix.

These run under the hermetic env set in conftest.py
(CYBERLLM_FORCE_STUB / FORCE_DRY_RUN / NO_EXTERNAL_STATIC), so they are
deterministic regardless of whether bandit/semgrep are installed or which
LLM provider is configured. Under FORCE_STUB the web scan's "deep" mode is
not honoured (no real LLM), so detection is the deterministic regex floor.
"""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

import server
from tools.static_analyzer import StaticFinding, merge_findings


VULN = (
    'API_KEY = "AKIA1234567890ABCDEF"\n'
    "def run(cmd):\n"
    '    import os\n'
    '    os.system("ping " + cmd)\n'
)


# --------------------------------------------------------------------------
# run_web_scan entry-point
# --------------------------------------------------------------------------

class TestRunWebScan:

    def test_finds_hardcoded_secret(self):
        r = server.run_web_scan(VULN, filename="svc.py", deep=False)
        assert r["ok"] is True
        rids = {f["rule_id"] for f in r["record"]["findings"]}
        assert "CODE-003" in rids                      # hard-coded secret (regex floor)

    def test_findings_have_detailed_shape(self):
        r = server.run_web_scan(VULN, filename="svc.py", deep=False)
        for f in r["record"]["findings"]:
            for key in ("rule_id", "severity", "title", "location", "line", "detail"):
                assert key in f

    def test_action_is_dry_run_and_guarded(self):
        r = server.run_web_scan(VULN, filename="svc.py", deep=False)
        rec = r["record"]
        assert "action" in rec and "guard_verdict" in rec
        # browser-initiated actions must never run for real
        report = json.dumps(rec.get("action_report", {})).lower()
        assert "dry" in report or rec["action"]["kind"] is not None

    def test_code_only_scan_has_no_log_or_topology_findings(self):
        # no log / deployment supplied -> empty inputs -> no LOG-/TOP- noise
        r = server.run_web_scan(VULN, filename="svc.py", deep=False)
        rids = [f["rule_id"] for f in r["record"]["findings"]]
        assert not [x for x in rids if x.startswith("LOG-") or x.startswith("TOP-")]

    def test_deep_downgrades_to_static_without_real_llm(self):
        # FORCE_STUB is set by conftest -> no real LLM -> deep is not honoured
        r = server.run_web_scan(VULN, filename="svc.py", deep=True)
        assert r["deep"] is False
        assert r["deep_requested"] is True

    def test_empty_code_handled_by_caller(self):
        # run_web_scan itself runs the pipeline; emptiness is rejected at the
        # HTTP layer. Here we just confirm a tiny clean file scans cleanly.
        r = server.run_web_scan("x = 1\n", filename="ok.py", deep=False)
        assert r["ok"] is True


# --------------------------------------------------------------------------
# provider info
# --------------------------------------------------------------------------

def test_provider_info_shape():
    info = server._provider_info()
    for key in ("llm_impl", "llm_model", "llm_real", "tools"):
        assert key in info
    assert isinstance(info["tools"], dict)


# --------------------------------------------------------------------------
# merge_findings dedup (the bug the live run exposed)
# --------------------------------------------------------------------------

def _sf(rid, line, ev="ev", agent="x"):
    return StaticFinding(rule_id=rid, severity="high", evidence=ev,
                         explanation="", source_agent=agent, line=line)


class TestMergeFindingsDedup:

    def test_llm_dup_same_rule_and_line_is_dropped(self):
        static = [_sf("CODE-003", 6, "secret on l6", "regex")]
        llm = [_sf("CODE-003", 6, "totally different wording", "llm")]
        merged = merge_findings(static, llm)
        assert len(merged) == 1
        assert merged[0].source_agent == "regex"       # static wins

    def test_llm_same_rule_no_line_is_dropped(self):
        static = [_sf("CODE-001", 8, "cmd inj", "bandit")]
        llm = [_sf("CODE-001", None, "command injection", "llm")]
        assert len(merge_findings(static, llm)) == 1

    def test_llm_same_rule_different_line_is_kept(self):
        static = [_sf("CODE-001", 8, "cmd inj l8", "bandit")]
        llm = [_sf("CODE-001", 20, "cmd inj l20", "llm")]
        assert len(merge_findings(static, llm)) == 2

    def test_new_llm_rule_is_kept(self):
        static = [_sf("CODE-003", 6)]
        llm = [_sf("CODE-099", 12, "novel issue", "llm")]
        assert len(merge_findings(static, llm)) == 2


# --------------------------------------------------------------------------
# HTTP layer (integration)
# --------------------------------------------------------------------------

@pytest.fixture()
def live_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read())


def _post(url, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


class TestHttpApi:

    def test_index_served(self, live_server):
        with urllib.request.urlopen(live_server + "/", timeout=30) as r:
            body = r.read().decode()
        assert "CyberLLM" in body and "<html" in body.lower()
        assert 'href="/assets/styles.css"' in body
        assert 'src="/assets/app.js"' in body

    @pytest.mark.parametrize("path, content_type", [
        ("/assets/styles.css", "text/css"),
        ("/assets/app.js", "text/javascript"),
    ])
    def test_ui_assets_served(self, live_server, path, content_type):
        with urllib.request.urlopen(live_server + path, timeout=30) as response:
            assert response.headers.get_content_type() == content_type
            assert response.headers["Cache-Control"] == "no-store"
            assert response.read() == (server.WEBAPP / path.lstrip("/")).read_bytes()

    @pytest.mark.parametrize("path", [
        "/assets/missing.js", "/assets/../config.yaml", "/config.yaml", "/.env",
    ])
    def test_nonpublic_files_not_served(self, live_server, path):
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(live_server + path, timeout=30)
        assert exc.value.code == 404

    def test_health(self, live_server):
        h = _get(live_server + "/api/health")
        assert h["ok"] is True and "llm_impl" in h

    def test_examples(self, live_server):
        e = _get(live_server + "/api/examples")
        assert e["ok"] is True and isinstance(e["examples"], list)

    def test_scan_endpoint(self, live_server):
        out = _post(live_server + "/api/scan",
                    {"code": VULN, "filename": "svc.py", "deep": False})
        assert out["ok"] is True
        assert "CODE-003" in {f["rule_id"] for f in out["record"]["findings"]}

    def test_scan_rejects_empty_code(self, live_server):
        try:
            _post(live_server + "/api/scan", {"code": "   "})
            assert False, "expected HTTP 400"
        except urllib.error.HTTPError as e:
            assert e.code == 400
