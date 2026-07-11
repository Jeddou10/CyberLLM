"""Deterministic static analyzer — the baseline detector.

Why this exists
---------------
The supervisor's brief says: "this system is built to mainly detect all
static vulnerabilities and if possible active ones when running it".

The LLM scanner is powerful but probabilistic and, when the
provider is stubbed, returns canned findings. This module supplies a
*deterministic* layer that:

1. Always runs (no LLM call needed).
2. Provides ground-truth findings derived from the rules YAML files
   (paper 3 OCL-style rules; paper 1 contextual security rules; paper
   2 actor/datasource graph rules).
3. Acts as input *context* to the LLM scanner — so the LLM is asked
   to explain / refine / add to a real list of hits rather than
   inventing one from scratch (paper 3 §III: RAG context).
4. Catches what the LLM would otherwise miss — the regex layer is
   high-recall, the LLM layer is high-precision; combined they are
   strictly better.

Three entry points, one per scanner type
----------------------------------------
- `scan_code_static(code, filename, rules)`        — regex on source files.
- `scan_log_static(log_text, rules)`               — semantic heuristics on log lines.
- `scan_deployment_static(deployment_yaml, rules)` — graph checks on the actor / datasource topology.
"""

from __future__ import annotations

import importlib.util
import json
import math
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

import yaml


# ---------------------------------------------------------------------------
# Output shape — same fields as the LLM scanner's Finding so the two
# layers can be merged seamlessly downstream.
# ---------------------------------------------------------------------------

@dataclass
class StaticFinding:
    rule_id: str
    severity: str
    evidence: str
    explanation: str
    source_agent: str = "static_analyzer"
    asset_category: str | None = None
    line: int | None = None


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


# ---------------------------------------------------------------------------
# 1.  CODE — regex pattern scanner
# ---------------------------------------------------------------------------

def scan_code_static(code: str, filename: str, rules: dict) -> list[StaticFinding]:
    """Apply every `code_rules[*].pattern` regex against the code."""
    out: list[StaticFinding] = []
    code_rules = rules.get("code_rules", [])
    for rule in code_rules:
        pat = rule.get("pattern")
        if not pat:
            continue
        try:
            # IGNORECASE so e.g. the CODE-003 pattern catches both
            # `api_key = "…"` and `API_KEY = "…"`. Patterns that
            # legitimately want case-sensitivity can override with
            # an inline `(?-i:…)` group.
            compiled = re.compile(pat, re.MULTILINE | re.IGNORECASE)
        except re.error:
            continue
        for m in compiled.finditer(code):
            snippet = code[max(0, m.start() - 20): m.end() + 20].replace("\n", " ")
            out.append(StaticFinding(
                rule_id=rule["id"],
                severity=rule.get("severity", "medium"),
                evidence=f"{filename}: {snippet.strip()[:120]}",
                explanation=rule.get("title", "")
                            + (f" — {rule['rationale']}" if rule.get("rationale") else ""),
                asset_category=rule.get("asset_category"),
                line=_line_of(code, m.start()),
            ))
    return out


# ---------------------------------------------------------------------------
# 2.  LOG — semantic heuristics
# ---------------------------------------------------------------------------

_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z?")


def _parse_ts(line: str) -> datetime | None:
    m = _TS_RE.match(line)
    if not m:
        return None
    try:
        return datetime.fromisoformat(m.group(1))
    except ValueError:
        return None


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def scan_log_static(log_text: str, rules: dict) -> list[StaticFinding]:
    """Apply hand-coded detectors per LOG-* rule id, plus generic regex."""
    out: list[StaticFinding] = []
    by_id = {r["id"]: r for r in rules.get("log_rules", [])}
    lines = log_text.splitlines()

    # ---- LOG-AUTH-03  ≥10 failed auth attempts in <60 s for root/admin
    if "LOG-AUTH-03" in by_id:
        fails: list[datetime] = []
        for ln in lines:
            if "Failed password" in ln and (" root" in ln or " admin" in ln
                                            or "for invalid user" in ln):
                ts = _parse_ts(ln)
                if ts:
                    fails.append(ts)
        if len(fails) >= 10:
            fails.sort()
            if fails[9] - fails[0] <= timedelta(seconds=60):
                r = by_id["LOG-AUTH-03"]
                out.append(StaticFinding(
                    rule_id=r["id"], severity=r.get("severity", "medium"),
                    evidence=f"{len(fails)} failed auth attempts in "
                             f"{(fails[-1]-fails[0]).total_seconds():.0f}s",
                    explanation=r.get("title", ""),
                    asset_category=r.get("asset_category"),
                ))

    # ---- LOG-NET-01  burst >500 pkts/s on a broadcast address
    if "LOG-NET-01" in by_id:
        rx = re.compile(r"rate[=\s]+(\d[\d_]*)\s*pkts/s")
        for ln in lines:
            if ".255" in ln or "broadcast" in ln.lower():
                m = rx.search(ln)
                if m and int(m.group(1).replace("_", "")) >= 500:
                    r = by_id["LOG-NET-01"]
                    out.append(StaticFinding(
                        rule_id=r["id"], severity=r.get("severity", "high"),
                        evidence=ln.strip()[:200],
                        explanation=r.get("title", ""),
                        asset_category=r.get("asset_category"),
                    ))
                    break

    # ---- LOG-CAN-02  gateway-only CAN ID from non-gateway ECU
    if "LOG-CAN-02" in by_id:
        for ln in lines:
            if "anomaly" in ln and ("0x7E" in ln or "gateway-only" in ln):
                r = by_id["LOG-CAN-02"]
                out.append(StaticFinding(
                    rule_id=r["id"], severity=r.get("severity", "critical"),
                    evidence=ln.strip()[:200],
                    explanation=r.get("title", ""),
                    asset_category=r.get("asset_category", "Life and Bodily Health"),
                ))
                break

    # ---- LOG-EXFIL-01  DNS covert channel (high entropy / volume)
    if "LOG-EXFIL-01" in by_id:
        dns_qs: list[str] = []
        for ln in lines:
            if " dns " in ln.lower() or "dns query" in ln.lower() or "exfil" in ln.lower():
                m = re.search(r"name=([\w\.\-]+)", ln)
                if m:
                    dns_qs.append(m.group(1).split(".")[0])
        if len(dns_qs) >= 5:
            avg_entropy = sum(_shannon_entropy(q) for q in dns_qs) / len(dns_qs)
            if avg_entropy > 3.0:
                r = by_id["LOG-EXFIL-01"]
                out.append(StaticFinding(
                    rule_id=r["id"], severity=r.get("severity", "high"),
                    evidence=f"{len(dns_qs)} DNS queries, "
                             f"avg subdomain entropy={avg_entropy:.2f}",
                    explanation=r.get("title", ""),
                    asset_category="Privacy and Personal Data",
                ))

    # ---- LOG-EXFIL-02  large outbound transfer
    if "LOG-EXFIL-02" in by_id:
        rx = re.compile(r"bytes_out=(\d[\d_]*)")
        for ln in lines:
            m = rx.search(ln)
            if m and int(m.group(1).replace("_", "")) >= 10_000_000:
                r = by_id["LOG-EXFIL-02"]
                out.append(StaticFinding(
                    rule_id=r["id"], severity=r.get("severity", "high"),
                    evidence=ln.strip()[:200],
                    explanation=r.get("title", ""),
                ))
                break

    # ---- LOG-LATERAL-01  internal port-scan rate from one host
    if "LOG-LATERAL-01" in by_id:
        for ln in lines:
            if "internal-scan" in ln.lower() or "rate=" in ln and "/24 port" in ln:
                r = by_id["LOG-LATERAL-01"]
                out.append(StaticFinding(
                    rule_id=r["id"], severity=r.get("severity", "high"),
                    evidence=ln.strip()[:200],
                    explanation=r.get("title", ""),
                ))
                break

    # ---- LOG-DDOS-01  distributed SYN flood
    if "LOG-DDOS-01" in by_id:
        flood_lines = [ln for ln in lines if "syn-flood" in ln.lower()]
        if len(flood_lines) >= 3:
            r = by_id["LOG-DDOS-01"]
            out.append(StaticFinding(
                rule_id=r["id"], severity=r.get("severity", "high"),
                evidence=f"{len(flood_lines)} SYN-flood log lines",
                explanation=r.get("title", ""),
            ))

    # ---- LOG-PRIV-01  shadow / sensitive file read via sudo
    if "LOG-PRIV-01" in by_id:
        for ln in lines:
            if "sudo" in ln and ("/etc/shadow" in ln or "iam/security-credentials" in ln):
                r = by_id["LOG-PRIV-01"]
                out.append(StaticFinding(
                    rule_id=r["id"], severity=r.get("severity", "critical"),
                    evidence=ln.strip()[:200],
                    explanation=r.get("title", ""),
                ))
                break

    return out


# ---------------------------------------------------------------------------
# 3.  DEPLOYMENT — graph checks on the actor/datasource topology
# ---------------------------------------------------------------------------

def _actor_by_id(actors: list[dict]) -> dict[str, dict]:
    return {a["id"]: a for a in actors}


def scan_deployment_static(deployment_yaml: str, rules: dict) -> list[StaticFinding]:
    """Hand-coded checks for the topology rules — these are the rules
    a regex couldn't express on its own."""
    try:
        doc = yaml.safe_load(deployment_yaml) or {}
    except yaml.YAMLError:
        return []

    actors = doc.get("actors", [])
    edges = doc.get("edges", [])
    actor = _actor_by_id(actors)
    by_id = {r["id"]: r for r in rules.get("topology_rules", [])}
    out: list[StaticFinding] = []

    def fire(rule_id: str, evidence: str, **over) -> None:
        if rule_id not in by_id:
            return
        r = by_id[rule_id]
        out.append(StaticFinding(
            rule_id=r["id"],
            severity=over.get("severity", r.get("severity", "medium")),
            evidence=evidence,
            explanation=r.get("title", ""),
            asset_category=r.get("asset_category"),
        ))

    # ---- TOP-001  HPC ↔ ZoneECU must be Ethernet + IEEE-1722
    for e in edges:
        s = actor.get(e.get("source"), {})
        t = actor.get(e.get("target"), {})
        if s.get("type") == "HighPerformanceComputer" and t.get("type") == "ZoneECU":
            if e.get("transport") != "ethernet" or e.get("standard") != "IEEE-1722":
                fire("TOP-001",
                     f"{e['source']} → {e['target']} on transport={e.get('transport')} "
                     f"standard={e.get('standard')}")

    # ---- TOP-002  external actors must not write to long-term memory
    for e in edges:
        s = actor.get(e.get("source"), {})
        if (s.get("trust_level") == "external"
                and e.get("primitive") == "write"
                and "memory" in (e.get("target") or "")):
            fire("TOP-002",
                 f"external actor {e['source']} writes to {e['target']} (poison path)")

    # ---- TOP-004  admin portal exposed to public internet without WAF
    for e in edges:
        s = actor.get(e.get("source"), {})
        t = actor.get(e.get("target"), {})
        if (s.get("type") in {"ExternalUser", "ExternalA2AAgent"}
                and "admin" in (e.get("target") or "")
                and not e.get("waf")):
            fire("TOP-004", f"{e['source']} → {e['target']}: no WAF on admin surface")

    # ---- TOP-005  database bound to 0.0.0.0
    for a in actors:
        if a.get("type") == "Database" and a.get("bind_address") == "0.0.0.0":
            fire("TOP-005", f"database {a['id']} binds 0.0.0.0")

    # ---- TOP-006  secrets store world-readable
    for a in actors:
        if a.get("type") == "SecretStore" and a.get("access_policy") == "world-readable":
            fire("TOP-006", f"secrets store {a['id']} access_policy=world-readable",
                 severity="critical")

    # ---- TOP-007  brake / safety ECU receives commands from non-safety source
    for e in edges:
        s = actor.get(e.get("source"), {})
        t = actor.get(e.get("target"), {})
        if (t.get("type") == "SafetyECU" and "brake" in (e.get("target") or "")
                and s.get("type") not in {"SafetyECU", "Sensor"}):
            fire("TOP-007",
                 f"safety actuator {e['target']} commanded by non-safety actor {e['source']}")

    # ---- TOP-008  external A2A respond-edge to in-vehicle agent
    for e in edges:
        s = actor.get(e.get("source"), {})
        if s.get("type") == "ExternalA2AAgent" and e.get("primitive") == "respond":
            fire("TOP-008",
                 f"external A2A agent {e['source']} can respond to {e['target']}")
        # Also catch attacker actors with respond
        if (s.get("trust_level") == "external"
                and e.get("primitive") == "respond"
                and "agent" in (e.get("target") or "")):
            fire("TOP-008",
                 f"external actor {e['source']} responds to in-vehicle agent {e['target']}")

    return out


# ---------------------------------------------------------------------------
# Merge helper — used when combining static and LLM findings.
# ---------------------------------------------------------------------------

def merge_findings(static: list[StaticFinding],
                   llm_findings: list) -> list:
    """Merge the deterministic (static) findings with the LLM's, dropping
    LLM duplicates. Static findings take priority because they are precise.

    An LLM finding is dropped when it restates a static one:
      * same (rule_id, line)            — same issue, same locus, or
      * same (rule_id, evidence prefix) — same issue, same snippet, or
      * same rule_id with no line       — the deterministic layer already
        covers that rule and the LLM added no new, specific locus.
    LLM findings on a *different* line (a locus the static layer missed) are
    kept, so we never lose real signal."""
    out = list(static)
    seen_line = {(f.rule_id, f.line) for f in static
                 if getattr(f, "line", None) is not None}
    seen_ev = {(f.rule_id, (f.evidence or "")[:40]) for f in static}
    seen_rid = {f.rule_id for f in static}
    for f in llm_findings:
        rid = getattr(f, "rule_id", None)
        line = getattr(f, "line", None)
        ev_key = (rid, (getattr(f, "evidence", "") or "")[:40])
        if line is not None and (rid, line) in seen_line:
            continue
        if ev_key in seen_ev:
            continue
        if line is None and rid in seen_rid:
            continue
        out.append(f)
        seen_ev.add(ev_key)
        seen_rid.add(rid)
        if line is not None:
            seen_line.add((rid, line))
    return out


def merge_static_layers(primary: list[StaticFinding],
                        extra: list[StaticFinding]) -> list[StaticFinding]:
    """Combine two *static* layers (e.g. the regex floor and the bandit /
    semgrep layer). The `primary` layer wins: an `extra` finding is added
    only if its (rule_id, line) is not already covered by `primary`, so we
    keep the issues the external analyser catches that regex missed without
    double-reporting the same issue on the same line."""
    out = list(primary)
    seen = {(f.rule_id, f.line) for f in primary}
    for f in extra:
        key = (f.rule_id, f.line)
        if key not in seen:
            out.append(f)
            seen.add(key)
    return out


# ---------------------------------------------------------------------------
# Optional external static-analysis layer — bandit (Python) / semgrep.
#
# Why: regex is a high-recall but shallow floor. bandit/semgrep are AST- and
# data-flow-aware, so they catch structural issues a regex misses. We run
# them as an *additional detection layer* (merged with the regex floor and
# then the LLM), mapping their findings onto our own rule-ids where we can
# so everything stays traceable. They are optional: if the binary is not
# installed (or errors), this returns [] and the regex floor still stands.
# ---------------------------------------------------------------------------

# bandit test-id → our CODE-* rule-id (so a bandit hit inherits our title,
# severity and asset category). Unmapped ids are kept as `BANDIT-<id>`.
_BANDIT_TO_RULE = {
    "B602": "CODE-001", "B604": "CODE-001",
    "B605": "CODE-001", "B609": "CODE-001",
    "B303": "CODE-002", "B324": "CODE-002",
    "B105": "CODE-003", "B106": "CODE-003", "B107": "CODE-003",
    "B608": "CODE-012",
    "B301": "CODE-005", "B302": "CODE-005", "B403": "CODE-005",
    "B506": "CODE-005",
    "B307": "CODE-038",
    "B501": "CODE-006", "B502": "CODE-006", "B503": "CODE-006",
    "B311": "CODE-008",
}
# Note: B603 (subprocess_without_shell_equals_true) and B606
# (start_process_with_no_shell) are bandit LOW-severity *advisories* that
# fire on the SAFE argv-list subprocess pattern. Mapping them to the high
# CODE-001 "command injection sink" produced false positives on correctly
# remediated code, so they are intentionally left unmapped (surfaced as a
# low-severity BANDIT-B603 / BANDIT-B606 advisory instead). The genuinely
# dangerous shell paths (B602/B604 shell=True, B605 os.system) stay mapped.

_BANDIT_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
_SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _rule_index(rules: dict) -> dict:
    idx: dict = {}
    for items in (rules or {}).values():
        for r in (items or []):
            if isinstance(r, dict) and "id" in r:
                idx[r["id"]] = r
    return idx


def bandit_results_to_findings(results: list, filename: str,
                               rules: dict | None = None) -> list[StaticFinding]:
    """Pure mapping: bandit JSON `results` → StaticFinding[] (no subprocess,
    so this is unit-testable on synthetic data)."""
    rule_idx = _rule_index(rules or {})
    out: list[StaticFinding] = []
    for r in results:
        test_id = r.get("test_id", "")
        rid = _BANDIT_TO_RULE.get(test_id, f"BANDIT-{test_id or 'UNKNOWN'}")
        rule = rule_idx.get(rid, {})
        bandit_sev = _BANDIT_SEV.get((r.get("issue_severity") or "").upper(), "medium")
        snippet = (r.get("code") or r.get("issue_text") or "").strip().replace("\n", " ")
        out.append(StaticFinding(
            rule_id=rid,
            # prefer our rule's severity when the id is mapped, else bandit's
            severity=rule.get("severity", bandit_sev),
            evidence=f"{filename}: {snippet[:120]}",
            explanation=((rule.get("title") or r.get("issue_text") or "")
                         + f" [bandit {test_id}]").strip(),
            source_agent="bandit",
            asset_category=rule.get("asset_category"),
            line=r.get("line_number"),
        ))
    return out


def semgrep_results_to_findings(results: list, filename: str) -> list[StaticFinding]:
    """Pure mapping: semgrep JSON `results` → StaticFinding[]."""
    out: list[StaticFinding] = []
    for r in results:
        check = (r.get("check_id") or "semgrep").split(".")[-1][:24]
        extra = r.get("extra", {}) or {}
        sev = _SEMGREP_SEV.get((extra.get("severity") or "").upper(), "medium")
        lines = (extra.get("lines") or "").strip().replace("\n", " ")
        out.append(StaticFinding(
            rule_id=f"SEMGREP-{check}",
            severity=sev,
            evidence=f"{filename}: {lines[:120]}",
            explanation=((extra.get("message") or "semgrep finding")[:200]
                         + " [semgrep]"),
            source_agent="semgrep",
            line=(r.get("start", {}) or {}).get("line"),
        ))
    return out


def _analyzer_cmd(name: str) -> list[str] | None:
    """Resolve how to invoke `name` (bandit/semgrep): prefer the binary on
    PATH, else fall back to `python -m <name>` if the module is importable
    (common for `pip install --user` on Windows, where the .exe shim is not
    on PATH). Returns the command prefix, or None if unavailable."""
    if shutil.which(name):
        return [name]
    if importlib.util.find_spec(name) is not None:
        return [sys.executable, "-m", name]
    return None


def external_static_available(suffix: str = ".py") -> bool:
    """True when a real AST analyser can run for files of this suffix."""
    if suffix.lower() == ".py" and _analyzer_cmd("bandit"):
        return True
    return _analyzer_cmd("semgrep") is not None


def scan_code_external(code: str, filename: str, rules: dict | None = None,
                       timeout: int = 60) -> list[StaticFinding]:
    """Run a *real* static analyser (bandit for Python, else semgrep) over
    `code` and return StaticFinding[]. Always graceful: returns [] when no
    backend is installed or on any error — the regex floor is unaffected.

    `code` is written to a temp file named like `filename` so line numbers
    line up with the original. No `shell=True`; bounded timeout."""
    suffix = (Path(filename).suffix or ".py").lower()
    bandit_cmd = _analyzer_cmd("bandit")
    semgrep_cmd = _analyzer_cmd("semgrep")
    tmpdir = tempfile.mkdtemp(prefix="cyberllm_ext_")
    try:
        tmpfile = Path(tmpdir) / (Path(filename).name or "code.py")
        tmpfile.write_text(code, encoding="utf-8")
        if suffix == ".py" and bandit_cmd:
            cp = subprocess.run([*bandit_cmd, "-f", "json", "-q", str(tmpfile)],
                                capture_output=True, text=True,
                                timeout=timeout, check=False)
            data = json.loads(cp.stdout or "{}")
            return bandit_results_to_findings(
                data.get("results", []), filename, rules)
        if semgrep_cmd:
            cp = subprocess.run([*semgrep_cmd, "--config=auto", "--json",
                                 "--quiet", str(tmpfile)],
                                capture_output=True, text=True,
                                timeout=timeout, check=False)
            data = json.loads(cp.stdout or "{}")
            return semgrep_results_to_findings(data.get("results", []), filename)
    except Exception:        # noqa: BLE001 — external layer is best-effort
        return []
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return []


def staticfinding_to_finding(static_findings: Iterable[StaticFinding], finding_cls):
    """Convert StaticFinding → the BaseAgent.Finding dataclass shape so
    the rest of the pipeline can consume it uniformly."""
    out = []
    for sf in static_findings:
        out.append(finding_cls(
            rule_id=sf.rule_id,
            severity=sf.severity,
            evidence=sf.evidence,
            explanation=sf.explanation,
            source_agent=sf.source_agent,
            asset_category=sf.asset_category,
            line=sf.line,
        ))
    return out
