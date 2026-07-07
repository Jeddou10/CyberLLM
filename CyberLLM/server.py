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
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

# Browser buttons must never trigger destructive OS commands.
os.environ.setdefault("CYBERLLM_FORCE_DRY_RUN", "1")

import pipeline
from llm_client import LLMClient, StubLLM
from tools.static_analyzer import _analyzer_cmd
from agents.base_agent import Input
from agents.source_code_scanner import CODE_SUFFIXES, SourceCodeScannerAgent

HERE = Path(__file__).resolve().parent
WEBAPP = HERE / "webapp"
BENCH_DIR = HERE / "benchmark" / "automotive"

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
            cfg["scanners"]["second_pass"] = effective_deep      # completeness critic
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


def _benchmark_files() -> list[dict]:
    """The automotive benchmark corpus, loadable file-by-file in the Scan tab
    so each case can be inspected in the rich findings/annotated-source view."""
    try:
        gt = _load_ground_truth()
    except Exception:        # noqa: BLE001
        return []
    out = []
    for f in gt["files"]:
        p = BENCH_DIR / f["path"]
        if not p.exists():
            continue
        n = len(f.get("vulnerabilities", []))
        tag = "clean control" if f.get("clean") else f"{n} labelled vuln(s)"
        out.append({
            "name": f"{f['path']} — {f['subsystem']} ({tag})",
            "filename": f["path"],
            "language": f["language"],
            "n_vulns": n,
            "clean": bool(f.get("clean")),
            "code": p.read_text(encoding="utf-8", errors="replace"),
        })
    return out


# ---------------------------------------------------------------------------
# Attack (red-team) — generates ethics-gated PoC scripts; NEVER executes them.
# ---------------------------------------------------------------------------

def run_web_attack(code: str, filename: str = "input.py",
                   scenario: str = "",
                   deployment_text: str | None = None,
                   deep: bool = False) -> dict:
    """Run the attack pipeline on pasted code in an isolated temp workspace.
    The generator only emits script *text*; nothing is executed, and the
    EthicsGuard redacts destructive payloads. Thread-safe (serialised)."""
    info = _provider_info()
    effective_deep = bool(deep) and info["llm_real"]
    has_dep = bool((deployment_text or "").strip())
    scenario = (scenario or "").strip() or \
        "Find the highest-impact exploit chain in this code."

    with _SCAN_LOCK:
        tmp = Path(tempfile.mkdtemp(prefix="cyberllm_atk_"))
        prev_runlogs = pipeline.RUN_LOGS_DIR
        prev_force_stub = os.environ.get("CYBERLLM_FORCE_STUB")
        try:
            code_file = tmp / (Path(filename).name or "input.py")
            code_file.write_text(code, encoding="utf-8")
            dep_file = tmp / "deployment.yaml"
            dep_file.write_text(
                deployment_text if has_dep
                else "actors: []\ndatasources: []\nedges: []\n", encoding="utf-8")

            cfg = copy.deepcopy(_CFG)
            cfg["paths"]["memory_dir"] = str(tmp / "memory")
            cfg.setdefault("memory", {})["enabled"] = False
            cfg.setdefault("scanners", {})
            cfg["scanners"]["external_static"] = True
            cfg["scanners"]["use_llm"] = effective_deep   # exploiter LLM gate

            if not effective_deep:
                os.environ["CYBERLLM_FORCE_STUB"] = "1"
            elif prev_force_stub is None:
                os.environ.pop("CYBERLLM_FORCE_STUB", None)

            pipeline.RUN_LOGS_DIR = tmp / "run_logs"
            record = pipeline.run_attack_pipeline(
                [code_file], dep_file, scenario, cfg, _RULES,
                scenario_name="web", verbose=False)
            return {
                "ok": True, "deep": effective_deep, "deep_requested": bool(deep),
                "provider": info, "filename": Path(filename).name,
                "scenario": scenario, "code": code, "record": record,
            }
        finally:
            pipeline.RUN_LOGS_DIR = prev_runlogs
            if prev_force_stub is None:
                os.environ.pop("CYBERLLM_FORCE_STUB", None)
            else:
                os.environ["CYBERLLM_FORCE_STUB"] = prev_force_stub
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Benchmark — run the scanner over the labelled automotive corpus and score it
# against ground truth (location-based matching). See benchmark/automotive/.
# ---------------------------------------------------------------------------

# Source files the scanner actually ingests (kept in sync with the scanner).
_SCANNED_EXTS = CODE_SUFFIXES


def _load_ground_truth() -> dict:
    return yaml.safe_load((BENCH_DIR / "ground_truth.yaml").read_text(encoding="utf-8"))


def benchmark_manifest() -> dict:
    """The corpus summary the UI shows before a run (no scanning)."""
    gt = _load_ground_truth()
    files, total = [], 0
    for f in gt["files"]:
        n = len(f.get("vulnerabilities", []))
        total += n
        files.append({
            "path": f["path"], "language": f["language"],
            "subsystem": f["subsystem"], "clean": bool(f.get("clean")),
            "n_vulns": n,
            "ingested": f["path"].endswith(_SCANNED_EXTS),
        })
    return {"meta": gt["meta"], "files": files, "total_vulns": total}


def _scan_findings(code: str, filename: str, file_path: Path, deep: bool):
    """Run ONLY the source-code scanner on one file and return enriched
    findings. Lighter than the full pipeline (no decision/action) to keep a
    Deep benchmark to one LLM call per ingested file. Thread-safe."""
    info = _provider_info()
    effective_deep = bool(deep) and info["llm_real"]
    with _SCAN_LOCK:
        prev_force_stub = os.environ.get("CYBERLLM_FORCE_STUB")
        try:
            if not effective_deep:
                os.environ["CYBERLLM_FORCE_STUB"] = "1"
            elif prev_force_stub is None:
                os.environ.pop("CYBERLLM_FORCE_STUB", None)
            llms = pipeline.build_llms(_CFG)
            code_cfg = dict(_CFG["agent_configs"]["source_code_scanner"],
                            rules_snippet=pipeline.rules_snippet(_RULES, "code_rules"),
                            rules_full=_RULES, external_static=True,
                            use_llm=effective_deep, second_pass=effective_deep)
            agent = SourceCodeScannerAgent(
                "source_code_scanner", code_cfg, llms[code_cfg["llm"]])
            result = agent.run([Input(content=code, source=filename,
                                      trust_level="external")])
            findings = pipeline._enrich_findings(result.findings, _RULES,
                                                 [file_path])
            return findings, effective_deep
        finally:
            if prev_force_stub is None:
                os.environ.pop("CYBERLLM_FORCE_STUB", None)
            else:
                os.environ["CYBERLLM_FORCE_STUB"] = prev_force_stub


def _match_file(gt_vulns: list, findings: list, window: int):
    """Greedy one-to-one, location-based match. Each labelled vuln is matched
    by the nearest unused finding within [line-window, line_end+window]."""
    finding_lines = [(i, f.get("line")) for i, f in enumerate(findings)
                     if isinstance(f.get("line"), int)]
    used: set[int] = set()
    matched = []
    for v in gt_vulns:
        lo = v["line"] - window
        hi = v.get("line_end", v["line"]) + window
        best_i, best_d = None, None
        for i, ln in finding_lines:
            if i in used or not (lo <= ln <= hi):
                continue
            d = abs(ln - v["line"])
            if best_d is None or d < best_d:
                best_d, best_i = d, i
        if best_i is not None:
            used.add(best_i)
            fnd = findings[best_i]
            matched.append({**v, "detected": True,
                            "matched": {"rule_id": fnd.get("rule_id"),
                                        "line": fnd.get("line"),
                                        "severity": fnd.get("severity")}})
        else:
            matched.append({**v, "detected": False, "matched": None})
    extra = [findings[i] for i in range(len(findings)) if i not in used]
    return matched, extra


def run_benchmark(deep: bool = False, window: int | None = None) -> dict:
    """Scan every corpus file, score against ground truth, return metrics."""
    gt = _load_ground_truth()
    window = int(window) if window is not None else int(gt["meta"].get("match_window", 3))

    files_out = []
    tp = fn = fp_clean = extra_total = 0
    by_sev = defaultdict(lambda: {"total": 0, "covered": 0})
    by_cat = defaultdict(lambda: {"total": 0, "covered": 0})
    by_lang = defaultdict(lambda: {"total": 0, "covered": 0})
    effective_deep_any = False

    for f in gt["files"]:
        path = BENCH_DIR / f["path"]
        code = path.read_text(encoding="utf-8", errors="replace")
        findings, eff = _scan_findings(code, f["path"], path, deep)
        effective_deep_any = effective_deep_any or eff
        ingested = f["path"].endswith(_SCANNED_EXTS)

        if f.get("clean"):
            fp_clean += len(findings)
            files_out.append({
                "path": f["path"], "language": f["language"],
                "subsystem": f["subsystem"], "clean": True, "ingested": ingested,
                "n_vulns": 0, "covered": 0, "false_positives": len(findings),
                "findings": findings, "vulns": [], "extra": findings,
            })
            continue

        matched, extra = _match_file(f.get("vulnerabilities", []), findings, window)
        covered = sum(1 for m in matched if m["detected"])
        tp += covered
        fn += len(matched) - covered
        extra_total += len(extra)
        for m in matched:
            for tbl, key in ((by_sev, m["severity"]), (by_cat, m["category"]),
                             (by_lang, f["language"])):
                tbl[key]["total"] += 1
                if m["detected"]:
                    tbl[key]["covered"] += 1
        files_out.append({
            "path": f["path"], "language": f["language"],
            "subsystem": f["subsystem"], "clean": False, "ingested": ingested,
            "n_vulns": len(matched), "covered": covered,
            "false_positives": 0, "vulns": matched, "extra": extra,
            "n_findings": len(findings),
        })

    total = tp + fn
    recall = tp / total if total else 0.0
    precision = tp / (tp + fp_clean) if (tp + fp_clean) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "ok": True,
        "deep": effective_deep_any,
        "deep_requested": bool(deep),
        "provider": _provider_info(),
        "window": window,
        "metrics": {
            "total_vulns": total, "covered": tp, "missed": fn,
            "false_positives": fp_clean, "extra_findings": extra_total,
            "coverage_pct": round(recall * 100, 1),
            "precision": round(precision, 3), "recall": round(recall, 3),
            "f1": round(f1, 3),
            "by_severity": dict(by_sev), "by_category": dict(by_cat),
            "by_language": dict(by_lang),
        },
        "files": files_out,
    }


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
            return self._json(200, {"ok": True, "examples": _examples(),
                                    "benchmark": _benchmark_files()})
        if self.path == "/api/benchmark":
            try:
                return self._json(200, {"ok": True, **benchmark_manifest()})
            except Exception as exc:        # noqa: BLE001
                return self._json(500, {"ok": False, "error": str(exc)})
        return self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if self.path == "/api/benchmark":
            try:
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"{}")
                result = run_benchmark(deep=bool(payload.get("deep")),
                                       window=payload.get("window"))
                return self._json(200, result)
            except Exception as exc:        # noqa: BLE001
                traceback.print_exc()
                return self._json(500, {"ok": False,
                                        "error": f"{type(exc).__name__}: {exc}"})
        if self.path == "/api/attack":
            try:
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"{}")
                code = (payload.get("code") or "").strip()
                if not code:
                    return self._json(400, {"ok": False, "error": "no code provided"})
                result = run_web_attack(
                    code=code, filename=payload.get("filename") or "input.py",
                    scenario=payload.get("scenario") or "",
                    deployment_text=payload.get("deployment") or None,
                    deep=bool(payload.get("deep")))
                return self._json(200, result)
            except Exception as exc:        # noqa: BLE001
                traceback.print_exc()
                return self._json(500, {"ok": False,
                                        "error": f"{type(exc).__name__}: {exc}"})
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
