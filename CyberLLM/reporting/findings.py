"""Enrich scanner findings with rule titles and source locations.

Kept separate from orchestration so CLI and web records share one format.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path


# ---------------------------------------------------------------------------
# Finding enrichment — turn a Finding into a detailed, human-readable record
# (rule_id, severity, title, location, line, detail, …)
# ---------------------------------------------------------------------------

def _rule_index(rules: dict) -> dict:
    """{rule_id: rule_dict} across every rule family — used to look up the
    human title of a rule for a finding."""
    idx: dict[str, dict] = {}
    for items in rules.values():
        for r in (items or []):
            if isinstance(r, dict) and "id" in r:
                idx[r["id"]] = r
    return idx


def _strip_ev_filename(evidence: str) -> str:
    """Evidence is stored as '<filename>: <snippet>'. Return just the
    snippet (the part that actually shows the issue)."""
    ev = (evidence or "").strip()
    head, sep, tail = ev.partition(":")
    if sep and head.strip().endswith((".py", ".c", ".cpp", ".h")):
        return tail.strip()
    return ev


def _enclosing_location(source: str, line: int, filename: str) -> str:
    """The function / class that contains `line` — e.g. 'search_vehicles()'
    or 'class FleetDB'. Falls back to 'module level'. Python uses the AST
    (precise); C-like files use a regex scanning upward for a signature."""
    if not source or not line:
        return "module level"
    if filename.endswith(".py"):
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return _enclosing_location_regex(source, line)
        best = None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                start = getattr(node, "lineno", None)
                end = getattr(node, "end_lineno", start)
                if start and end and start <= line <= end:
                    if best is None or start > best[0]:   # innermost wins
                        best = (start, node)
        if best:
            node = best[1]
            if isinstance(node, ast.ClassDef):
                return f"class {node.name}"
            return f"{node.name}()"
        return "module level"
    return _enclosing_location_regex(source, line)


def _enclosing_location_regex(source: str, line: int) -> str:
    lines = source.splitlines()
    sig = re.compile(r"^\s*(?:[A-Za-z_][\w\s\*]+?\s+)?([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{?\s*$")
    for i in range(min(line, len(lines)) - 1, -1, -1):
        m = sig.match(lines[i])
        if m and m.group(1) not in {"if", "for", "while", "switch", "return"}:
            return f"{m.group(1)}()"
    return "module level"


def _finding_file(f, code_by_name: dict) -> tuple:
    ev = getattr(f, "evidence", "") or ""
    cand = ev.split(":", 1)[0].strip() if ":" in ev else ""
    if cand in code_by_name:
        return cand, code_by_name[cand]
    if len(code_by_name) == 1:                 # single-file scan → unambiguous
        name = next(iter(code_by_name))
        return name, code_by_name[name]
    return None, None


def _finding_location(f, code_by_name: dict) -> str:
    rid = getattr(f, "rule_id", "") or ""
    fname, src = _finding_file(f, code_by_name)
    line = getattr(f, "line", None)
    if src and line:
        loc = _enclosing_location(src, line, fname or "")
        return f"{fname} → {loc}" if (fname and len(code_by_name) > 1) else loc
    if rid.startswith("LOG-"):
        return "log stream"
    if rid.startswith("TOP-") or rid == "ATK-PATH":
        return "deployment topology"
    return fname or "module level"


def _enrich_finding(f, rule_index: dict, code_by_name: dict) -> dict:
    """Build the detailed finding record: rule_id / severity / title /
    location / line / detail (+ a little bonus context)."""
    rid = getattr(f, "rule_id", "?")
    expl = getattr(f, "explanation", "") or ""
    rule = rule_index.get(rid, {})
    # strip trailing tool tags like "[bandit B602]" / "[semgrep]" for display
    expl_clean = re.sub(r"\s*\[(?:bandit|semgrep)[^\]]*\]\s*$", "", expl).strip()
    title = (rule.get("title")
             or (expl_clean.split(" — ")[0] if " — " in expl_clean else "")
             or (expl_clean.split(". ")[0][:70] if expl_clean else "")
             or rid)
    # the rationale = explanation with any leading duplicated title stripped
    rationale = expl_clean
    if title and expl_clean.startswith(title):
        rationale = expl_clean[len(title):].lstrip(" —-:").strip()
    snippet = _strip_ev_filename(getattr(f, "evidence", ""))
    detail = rationale or expl or snippet
    if snippet and snippet not in detail:
        detail = f"{detail} — matched: {snippet}".strip(" —")
    return {
        "rule_id": rid,
        "severity": getattr(f, "severity", "?"),
        "title": title,
        "location": _finding_location(f, code_by_name),
        "line": getattr(f, "line", None),
        "detail": detail or "(no further detail)",
        # bonus context retained so nothing is lost downstream
        "asset_category": getattr(f, "asset_category", None),
        "source_agent": getattr(f, "source_agent", ""),
        "evidence": getattr(f, "evidence", ""),
    }


def _enrich_findings(findings, rules: dict, code_paths: list[Path]) -> list[dict]:
    rule_index = _rule_index(rules)
    code_by_name: dict[str, str] = {}
    for p in code_paths:
        try:
            code_by_name[p.name] = p.read_text(encoding="utf-8", errors="replace")
        except Exception:        # noqa: BLE001
            pass
    return [_enrich_finding(f, rule_index, code_by_name) for f in findings]
