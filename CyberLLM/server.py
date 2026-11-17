"""CyberLLM — local web server (a polished UI over the defense pipeline).

Zero new dependencies: this uses only Python's stdlib `http.server`. It
serves the single-page app in `webapp/index.html` and a small JSON API:

    GET  /                 → the SPA
    GET  /api/health       → which LLM provider is active + tool availability
    GET  /api/examples     → bundled example snippets the UI can load
    POST /api/scan         → run the static-first defense pipeline on the
                             posted code (+ optional log / deployment) and
                             return a detailed, UI-ready result
    POST /api/remediate    → LLM-rewrite the posted code to fix its findings,
                             then RE-SCAN it to prove the vulns are gone

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
import re
import shutil
import tempfile
import threading
import traceback
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml

# Browser buttons must never trigger destructive OS commands.
os.environ.setdefault("CYBERLLM_FORCE_DRY_RUN", "0")

import pipeline
from llm_client import LLMClient, StubLLM
from tools.static_analyzer import _analyzer_cmd
from agents.base_agent import Input
from agents.source_code_scanner import CODE_SUFFIXES, SourceCodeScannerAgent
from agents.security_guard import SecurityGuard
from agents.action_engine.types import ActionStep, SideEffect, StepKind

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


# ---------------------------------------------------------------------------
# Auto-remediation — LLM rewrites the code, then we RE-SCAN it to prove the
# vulnerabilities are actually gone (a real before/after, not a claim).
# ---------------------------------------------------------------------------

def _strip_code_fences(text: str) -> str:
    """Drop a leading/trailing ```lang fenced-code wrapper if the model added
    one, so we persist pure source, not markdown."""
    t = (text or "").strip()
    if t.startswith("```"):
        lines = t.split("\n")
        lines = lines[1:]                                   # opening ``` (+lang)
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]                              # closing ```
        t = "\n".join(lines)
    return t.strip("\n") + "\n"


def _llm_fix_code(code: str, filename: str, fix_findings: list,
                  keep_findings: list | None = None) -> str:
    """Ask the configured LLM to rewrite the file so the AUTHORISED
    vulnerabilities (`fix_findings`) are fixed, while leaving the code for
    `keep_findings` (whose remediation the guard refused) exactly as-is.
    Returns the corrected source (fences stripped)."""
    # Reasoning models (e.g. gpt-5.5) spend part of max_completion_tokens on
    # hidden reasoning; give the rewrite a generous ceiling so the visible
    # answer is never truncated to empty.
    cfg = dict(_CFG["llm_configs"]["default"])
    cfg["max_tokens"] = max(int(cfg.get("max_tokens", 2048) or 2048), 8000)
    # Large secure rewrites through a reasoning model can run well past the
    # default 120s HTTP timeout, so give this call a generous ceiling.
    cfg["timeout"] = 600
    client = LLMClient.create(cfg)
    keep_findings = keep_findings or []
    def _fmt(items):
        return "\n".join(
            f"- [{f.get('severity', '?')}] {f.get('rule_id', '?')} "
            f"(line {f.get('line', '?')}): {f.get('title', '')} — "
            f"{f.get('detail', '')}"
            for f in items)
    vulns = _fmt(fix_findings) or "(none)"
    keep = _fmt(keep_findings)
    system = (
        "You are a senior secure-coding engineer. You are given a source file "
        "and the security vulnerabilities found in it. Rewrite the ENTIRE file "
        "so that every listed vulnerability is fixed using safe-by-"
        "construction patterns: parameterised SQL queries; no shell=True (use "
        "shlex.split + an allow-list, or argument lists); secrets read from "
        "environment variables / a secret manager; strict input validation and "
        "path-traversal guards; safe deserialisation; constant-time secret "
        "comparisons; least privilege. Preserve the original behaviour, public "
        "function signatures and overall structure as closely as possible.\n"
        "Also write code that is clean under static analysers (bandit / "
        "semgrep):\n"
        "- When you must run an external process, resolve the executable to a "
        "full path (e.g. via shutil.which) and pass arguments as a list; never "
        "a partial name and never shell=True.\n"
        "- Avoid time-of-check/time-of-use (TOCTOU) races: open the file first, "
        "then validate via the open descriptor (os.fstat), instead of checking "
        "the path and opening it afterwards.\n"
        "- Do not leave unused imports.\n"
        "Output ONLY the complete corrected file contents — no markdown code "
        "fences, no explanations, no commentary.")
    prompt = (
        f"Filename: {filename}\n\n"
        f"Vulnerabilities you MUST fix:\n{vulns}\n\n"
        + (f"Vulnerabilities you MUST NOT touch — their remediation was NOT "
           f"authorised by the security guard, so leave that code exactly "
           f"as-is:\n{keep}\n\n" if keep else "")
        + f"Original file:\n{code}\n\n"
        "Return the full corrected file now — fix ONLY the authorised "
        "vulnerabilities and preserve everything else verbatim.")
    resp = client.complete(prompt, system=system)
    return _strip_code_fences(resp.text)


def _remedy_guard() -> SecurityGuard:
    """The deterministic P1 guard used to gate per-finding fixes. No H_a
    oracle here — code patches are non-destructive, so the four-property
    floor decides, which keeps legitimate fixes from being over-refused."""
    sec = _CFG.get("security", {}) or {}
    return SecurityGuard(
        allowed_objectives=sec.get("allowed_objectives", []),
        authenticated_sources=sec.get("authenticated_sources", []),
        trusted_destinations=sec.get("trusted_destinations", []),
        ha_judge=None)


def _plan_fixes(before: list, name: str, code: str) -> list:
    """One guard-gated `code.propose_patch` step per finding. Returns a list of
    {f, params, allowed, reason}."""
    guard = _remedy_guard()
    inputs = [
        Input(content=code, source=name, trust_level="external"),
        Input(content="Remediation requested by an authorised operator.",
              source="user", trust_level="authenticated"),
    ]
    plan = []
    for f in before:
        sev = str(f.get("severity", "")).lower()
        step = ActionStep(
            rule_id=f.get("rule_id"), kind=StepKind.ERADICATE,
            tool="code.propose_patch",
            params={"rule_id": f.get("rule_id"), "file": name,
                    "line": f.get("line"),
                    "fix": "rewrite to a safe-by-construction pattern"},
            description=f"auto-correct {f.get('rule_id')} — {f.get('title', '')}",
            side_effect=SideEffect.WRITE,
            requires_authorization=sev in ("critical", "high"))
        v = guard.check_step(step, "auto-correct insecure code", inputs)
        plan.append({"f": f, "params": step.params,
                     "allowed": v.allowed, "reason": v.reason})
    return plan


def _apply_fixes(code: str, name: str, before: list):
    """Guard-gate the fixes, apply the allowed ones with the LLM, and re-scan.
    Returns (fixed_code, after_findings, plan). Shared by the web UI and the
    benchmark's resolution metric."""
    plan = _plan_fixes(before, name, code)
    allowed = [p["f"] for p in plan if p["allowed"]]
    blocked = [p["f"] for p in plan if not p["allowed"]]
    fixed_code = code
    if allowed:
        cand = _llm_fix_code(code, name, allowed, blocked)
        if len(cand.strip()) >= max(20, len(code.strip()) // 4):
            fixed_code = cand
    tmp = Path(tempfile.mkdtemp(prefix="cyberllm_fix_"))
    try:
        fpath = tmp / ("fixed__" + name)
        fpath.write_text(fixed_code, encoding="utf-8")
        after, _ = _scan_findings(fixed_code, name, fpath, deep=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return fixed_code, after, plan


def run_web_remediate(code: str, filename: str = "input.py",
                      deep: bool = True, before: list | None = None) -> dict:
    """Plan-driven fix-and-verify. For each finding we build a
    `code.propose_patch` step and run it through the SecurityGuard; the LLM
    then corrects ONLY the findings whose step the guard allowed. A refused
    finding is left in place (its code is not touched), and the re-scan proves
    it. This simulates executing the guarded plan rather than a blind rewrite.
    Thread-safe (each `_scan_findings` takes the scan lock internally)."""
    info = _provider_info()
    if not info["llm_real"]:
        return {"ok": False,
                "error": ("Auto-remediation needs a live LLM (Deep mode). "
                          "Set the AZURE_OPENAI_* values in .env.")}
    name = Path(filename).name or "input.py"
    tmp = Path(tempfile.mkdtemp(prefix="cyberllm_fix_"))
    try:
        # Reuse the caller's scan findings when supplied, so the per-finding
        # plan lines up EXACTLY with what the Explorer shows (two independent
        # Deep scans are non-deterministic and would otherwise mismatch).
        if before is None:
            orig_path = tmp / name
            orig_path.write_text(code, encoding="utf-8")
            before, _ = _scan_findings(code, name, orig_path, deep=True)

        # ---- per-finding remediation plan, gated by the guard --------------
        guard = _remedy_guard()
        inputs = [
            Input(content=code, source=name, trust_level="external"),
            Input(content="Remediation requested by an authorised operator.",
                  source="user", trust_level="authenticated"),
        ]
        plan = []
        for f in before:
            sev = str(f.get("severity", "")).lower()
            step = ActionStep(
                rule_id=f.get("rule_id"), kind=StepKind.ERADICATE,
                tool="code.propose_patch",
                params={"rule_id": f.get("rule_id"), "file": name,
                        "line": f.get("line"),
                        "fix": "rewrite to a safe-by-construction pattern"},
                description=f"auto-correct {f.get('rule_id')} — {f.get('title', '')}",
                side_effect=SideEffect.WRITE,
                requires_authorization=sev in ("critical", "high"))
            v = guard.check_step(step, "auto-correct insecure code", inputs)
            plan.append({"f": f, "params": step.params,
                         "allowed": v.allowed, "reason": v.reason})

        allowed = [p["f"] for p in plan if p["allowed"]]
        blocked = [p["f"] for p in plan if not p["allowed"]]
        if allowed:
            fixed_code = _llm_fix_code(code, name, allowed, blocked)
            if len(fixed_code.strip()) < max(20, len(code.strip()) // 4):
                return {"ok": False,
                        "error": ("The model returned an incomplete rewrite. "
                                  "Please try again.")}
        else:
            fixed_code = code            # nothing authorised → code unchanged

        fixed_path = tmp / ("fixed__" + name)
        fixed_path.write_text(fixed_code, encoding="utf-8")
        after, _ = _scan_findings(fixed_code, name, fixed_path, deep=True)

        def _sev_counts(items):
            c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in items:
                s = str(f.get("severity", "")).lower()
                c[s if s in c else "info"] += 1
            return c

        def _still(f, items):
            return any(x.get("rule_id") == f.get("rule_id")
                       and x.get("line") == f.get("line") for x in items)

        plan_out = []
        for p in plan:
            f = p["f"]
            still = _still(f, after)
            plan_out.append({
                "rule_id": f.get("rule_id"), "title": f.get("title"),
                "severity": f.get("severity"), "line": f.get("line"),
                "tool": "code.propose_patch", "params": p["params"],
                "allowed": p["allowed"], "guard_reason": p["reason"],
                "still_present": still,
                "outcome": ("blocked" if not p["allowed"]
                            else ("fixed" if not still else "attempted")),
            })

        before_sev = _sev_counts(before)
        after_sev = _sev_counts(after)
        blocking_after = after_sev["critical"] + after_sev["high"]
        allowed_fixed = sum(1 for p in plan_out
                            if p["allowed"] and not p["still_present"])
        return {
            "ok": True, "provider": info, "filename": name,
            "original_code": code, "fixed_code": fixed_code,
            "before": before, "after": after, "plan": plan_out,
            "before_count": len(before), "after_count": len(after),
            "before_sev": before_sev, "after_sev": after_sev,
            "advisory_after": after_sev["medium"] + after_sev["low"] + after_sev["info"],
            "allowed_count": len(allowed), "blocked_count": len(blocked),
            "allowed_fixed": allowed_fixed,
            "verified_safe": blocking_after == 0,
        }
    finally:
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


def run_attack_sim(code: str, filename: str = "input.py",
                   script: dict | None = None, scenario: str = "") -> dict:
    """Simulate — never execute — running a PoC exploit against the target
    code, reasoning statically with the LLM. Returns a verdict of whether the
    exploit would actually work against THIS code and the concrete outcome.
    Offline (no live LLM) → a labelled heuristic placeholder."""
    info = _provider_info()
    s = script or {}
    rid, title = s.get("rule_id", ""), s.get("title", "")
    lang, body = s.get("language", ""), s.get("body", "")
    effect = s.get("expected_effect", "")
    if not info["llm_real"]:
        return {"ok": True, "live": False, "simulation": {
            "reachable": None, "success": None,
            "outcome": (f"(offline heuristic) If the '{title or rid}' PoC reaches "
                        f"the flagged sink, its expected effect is: "
                        f"{effect or 'as described by the exploit'}."),
            "impact": "Enable Deep (a live LLM) for a reasoned, code-specific simulation.",
            "observable": "—", "preconditions": [], "confidence": 0.0}}
    cfg = dict(_CFG["llm_configs"]["default"])
    cfg["max_tokens"] = max(int(cfg.get("max_tokens", 2048) or 2048), 1500)
    cfg["timeout"] = 300
    client = LLMClient.create(cfg)
    system = (
        "You SIMULATE — never execute — the effect of running a proof-of-concept "
        "exploit against a target source file, reasoning statically about the "
        "code. Decide whether the exploit would ACTUALLY work against THIS "
        "specific code and describe the concrete outcome step by step. Be "
        "honest: if the vulnerable path is unreachable or the bug is not really "
        "exploitable here, set success=false and explain why. Do not invent "
        "behaviour the code does not support.\n"
        "Return ONLY strict JSON: {\"reachable\": true|false, \"success\": "
        "true|false, \"outcome\": \"...\", \"impact\": \"...\", \"observable\": "
        "\"...\", \"preconditions\": [\"...\"], \"confidence\": <0..1>}.")
    prompt = (
        f"Target file: {filename}\n\nTarget source:\n{code}\n\n"
        f"Proof-of-concept exploit (rule {rid} — {title}; {lang}); "
        f"expected effect: {effect}\n---\n{body}\n---\n"
        + (f"Attacker goal: {scenario}\n\n" if scenario else "")
        + "Simulate running this PoC against the target and return the JSON verdict now.")
    try:
        resp = client.complete(prompt, system=system)
    except Exception as exc:        # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    txt = re.sub(r"```(?:json)?", "", resp.text or "").strip("`\n ")
    try:
        sim = json.loads(txt)
    except Exception:        # noqa: BLE001 — model didn't return clean JSON
        sim = {"reachable": None, "success": None,
               "outcome": (resp.text or "")[:800], "impact": "",
               "observable": "", "preconditions": [], "confidence": 0.0}
    return {"ok": True, "live": True, "simulation": sim}


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


def run_benchmark(deep: bool = False, window: int | None = None,
                  remediate: bool = False) -> dict:
    """Scan every corpus file, score against ground truth, return metrics.
    When `remediate` is set (and a live LLM is available in Deep mode), also
    run the guard-gated auto-remediation per file and count how many DETECTED
    ground-truth vulnerabilities are successfully resolved (gone on re-scan)."""
    gt = _load_ground_truth()
    window = int(window) if window is not None else int(gt["meta"].get("match_window", 3))
    do_remediate = bool(remediate) and bool(deep) and _provider_info()["llm_real"]

    files_out = []
    tp = fn = fp_clean = extra_total = total_resolved = 0
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

        # ---- optional: remediate and count successfully-resolved vulns -----
        resolved = 0
        remediated = False
        if do_remediate and findings:
            try:
                _fixed, after, _plan = _apply_fixes(code, f["path"], findings)
                remediated = True
                for m in matched:
                    if m["detected"] and m.get("matched"):
                        mm = m["matched"]
                        gone = not any(x.get("rule_id") == mm.get("rule_id")
                                       and x.get("line") == mm.get("line")
                                       for x in after)
                        m["resolved"] = bool(gone)
                        if gone:
                            resolved += 1
                            for tbl, key in ((by_sev, m["severity"]),
                                             (by_cat, m["category"]),
                                             (by_lang, f["language"])):
                                tbl[key]["resolved"] = tbl[key].get("resolved", 0) + 1
            except Exception:        # noqa: BLE001 — remediation is best-effort
                remediated = False
        total_resolved += resolved

        files_out.append({
            "path": f["path"], "language": f["language"],
            "subsystem": f["subsystem"], "clean": False, "ingested": ingested,
            "n_vulns": len(matched), "covered": covered,
            "resolved": resolved, "remediated": remediated,
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
            "remediated": do_remediate,
            "resolved": total_resolved,
            "resolution_rate": round(total_resolved / tp, 3) if tp else 0.0,
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
        # Serve only the two application assets, never arbitrary local paths.
        assets = {
            "/assets/styles.css": ("assets/styles.css", "text/css; charset=utf-8"),
            "/assets/app.js": ("assets/app.js", "text/javascript; charset=utf-8"),
        }
        if self.path in assets:
            relative_path, content_type = assets[self.path]
            asset = WEBAPP / relative_path
            if not asset.is_file():
                return self._json(404, {"ok": False, "error": "asset not found"})
            return self._send(200, asset.read_bytes(), content_type)
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
                                       window=payload.get("window"),
                                       remediate=bool(payload.get("remediate")))
                return self._json(200, result)
            except Exception as exc:        # noqa: BLE001
                traceback.print_exc()
                return self._json(500, {"ok": False,
                                        "error": f"{type(exc).__name__}: {exc}"})
        if self.path == "/api/attack_sim":
            try:
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"{}")
                code = (payload.get("code") or "").strip()
                if not code:
                    return self._json(400, {"ok": False, "error": "no code provided"})
                return self._json(200, run_attack_sim(
                    code=code, filename=payload.get("filename") or "input.py",
                    script=payload.get("script") or {},
                    scenario=payload.get("scenario") or ""))
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
        if self.path == "/api/remediate":
            try:
                length = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(length) or b"{}")
                code = (payload.get("code") or "").strip()
                if not code:
                    return self._json(400, {"ok": False, "error": "no code provided"})
                _before = payload.get("findings")
                result = run_web_remediate(
                    code=code, filename=payload.get("filename") or "input.py",
                    deep=bool(payload.get("deep", True)),
                    before=_before if isinstance(_before, list) and _before else None)
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
