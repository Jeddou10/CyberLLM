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

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
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
    """De-dup by (rule_id, evidence prefix). Static findings take priority
    because they are deterministic."""
    out = list(static)
    seen = {(f.rule_id, (f.evidence or "")[:40]) for f in static}
    for f in llm_findings:
        key = (getattr(f, "rule_id", None), (getattr(f, "evidence", "") or "")[:40])
        if key not in seen:
            out.append(f)
            seen.add(key)
    return out


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
