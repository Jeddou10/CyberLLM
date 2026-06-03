"""Static evaluation harness — Red/Blue scoreboard without running the target.

The supervisor's hard constraint is *static-first*: detect what can be
extracted **without dynamically running** the system. So this harness
scores the deterministic static analyzer against the labelled corpus in
`examples/labels.yaml` and produces four artefacts:

  1. **Detection rate (recall)** per scenario — roadmap D.4. For each
     vulnerable scenario, of the expected must-have rule_ids, how many
     does the static floor surface? (Recall, not precision: the label
     set is must-have, not exhaustive — see labels.yaml.)
  2. **False-positive rate** — roadmap D.4. Measured *only* on the clean
     negative controls, where ground truth is "zero findings", so any hit
     is a genuine false positive.
  3. **Property-violation table** — roadmap D.5. Each detected finding is
     mapped to the paper-1 contextual-security property it violates and
     the paper-2 asset category it threatens.
  4. **Asset × scenario × skill scoreboard** — roadmap G.4. Which paper-2
     asset categories each scenario touches, the implied paper-5 response
     tier, and the candidate defense skills that would fire.

Note on "mean time to detect": MTTD is a *dynamic* metric (it needs a
live timeline). A static analyzer has no runtime, so MTTD is reported as
N/A by design — this harness measures static detection coverage instead.

Run:  python evaluate.py            # writes memory/eval_report.md + prints
      python evaluate.py --strict   # exit non-zero if recall<1 or any FP
"""

from __future__ import annotations

import argparse
import sys

import yaml

from pipeline import HERE, _collect_code_files, _norm, load_config, load_rules
from skills.skills import DEFENSE_SKILLS
from tools.static_analyzer import (
    scan_code_static, scan_deployment_static, scan_log_static,
)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Mappings (paper 1 properties; paper 5 tiers)
# ---------------------------------------------------------------------------

# Which paper-1 contextual-security property a detected rule most directly
# implicates. An approximation — documented as such (paper 1 says the
# oracles are open problems).
_PROPERTY_BY_RULE = {
    "TOP-002": "source_authorization",   # external write into memory
    "TOP-008": "source_authorization",   # external A2A respond edge
    "LOG-AUTH-03": "source_authorization",
    "LOG-PRIV-01": "source_authorization",
    "LOG-LATERAL-01": "source_authorization",
    "TOP-004": "data_isolation",         # exposed admin surface
    "TOP-005": "data_isolation",         # db bound to 0.0.0.0
    "TOP-006": "data_isolation",         # world-readable secrets
    "LOG-EXFIL-01": "data_isolation",
    "LOG-EXFIL-02": "data_isolation",
    "TOP-001": "action_alignment",       # wrong transport for the link
    "TOP-007": "action_alignment",       # non-safety actor commands safety ECU
    "LOG-CAN-02": "action_alignment",    # gateway-only CAN id from wrong ECU
    "LOG-NET-01": "task_alignment",
    "LOG-DDOS-01": "task_alignment",
}


def property_for(rule_id: str) -> str:
    if rule_id in _PROPERTY_BY_RULE:
        return _PROPERTY_BY_RULE[rule_id]
    # Code-execution / injection sinks let an attacker drive the agent to
    # take actions outside its objective → action alignment.
    if rule_id.startswith("CODE-"):
        return "action_alignment"
    return "task_alignment"


# Paper-2 asset fallback for rules whose YAML entry carries no
# `asset_category` (most TOP-* / LOG-* rules). Keeps the D.5 table and
# the G.4 scoreboard complete instead of showing "(unmapped)".
_ASSET_FALLBACK = {
    "TOP-001": "Life and Bodily Health",
    "TOP-002": "Privacy and Personal Data",
    "TOP-004": "Material and Economic Resources",
    "TOP-005": "Privacy and Personal Data",
    "TOP-006": "Privacy and Personal Data",
    "TOP-007": "Life and Bodily Health",
    "TOP-008": "Mental and Emotional Well-Being",
    "LOG-AUTH-03": "Material and Economic Resources",
    "LOG-PRIV-01": "Privacy and Personal Data",
    "LOG-LATERAL-01": "Material and Economic Resources",
    "LOG-EXFIL-01": "Privacy and Personal Data",
    "LOG-EXFIL-02": "Privacy and Personal Data",
    "LOG-NET-01": "Material and Economic Resources",
    "LOG-DDOS-01": "Material and Economic Resources",
    "LOG-CAN-02": "Life and Bodily Health",
}


def asset_for(finding, rule_idx: dict) -> str:
    """Resolve a finding's paper-2 asset category: explicit tag → rule
    YAML → documented fallback → '(unmapped)'."""
    return (finding.asset_category
            or rule_idx.get(finding.rule_id, {}).get("asset_category")
            or _ASSET_FALLBACK.get(finding.rule_id)
            or "(unmapped)")


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def tier_for_severity(sev: str) -> str:
    r = _SEVERITY_RANK.get((sev or "").lower(), 1)
    return "hard" if r >= 2 else ("moderate" if r == 1 else "soft")


def skills_for_tier(tier: str) -> list[str]:
    return [s.name for s in DEFENSE_SKILLS if s.tier == tier]


# ---------------------------------------------------------------------------
# Static scan of one labelled scenario
# ---------------------------------------------------------------------------

def _rule_index(rules: dict) -> dict:
    idx = {}
    for family, items in rules.items():
        for r in items:
            if isinstance(r, dict) and "id" in r:
                idx[r["id"]] = r
    return idx


def scan_scenario(scn: dict, rules: dict) -> list:
    """Return the list of StaticFinding objects for one scenario, purely
    from the deterministic static analyzer (no LLM, no execution)."""
    findings = []

    code_target = _norm(scn["code"])
    try:
        code_paths = _collect_code_files(code_target)
    except FileNotFoundError:
        code_paths = []
    for p in code_paths:
        text = p.read_text(encoding="utf-8", errors="replace")
        findings.extend(scan_code_static(text, p.name, rules))

    if scn.get("log"):
        log_text = _norm(scn["log"]).read_text(encoding="utf-8", errors="replace")
        findings.extend(scan_log_static(log_text, rules))

    if scn.get("deployment"):
        dep_text = _norm(scn["deployment"]).read_text(
            encoding="utf-8", errors="replace")
        findings.extend(scan_deployment_static(dep_text, rules))

    return findings


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate(cfg: dict, rules: dict, labels: dict) -> dict:
    rule_idx = _rule_index(rules)
    detection_rows = []
    fp_rows = []
    property_rows = []
    scoreboard_rows = []

    tot_expected = tot_hit = 0
    n_clean = 0
    tot_fp = 0

    for scn in labels.get("scenarios", []):
        name = scn["name"]
        findings = scan_scenario(scn, rules)
        detected_ids = sorted({f.rule_id for f in findings})

        if scn.get("clean"):
            n_clean += 1
            tot_fp += len(detected_ids)
            fp_rows.append({
                "scenario": name,
                "false_positives": detected_ids,
                "n": len(detected_ids),
            })
            continue

        expected = set(scn.get("expected", []))
        hit = expected & set(detected_ids)
        missing = expected - set(detected_ids)
        recall = (len(hit) / len(expected)) if expected else 1.0
        tot_expected += len(expected)
        tot_hit += len(hit)
        detection_rows.append({
            "scenario": name,
            "expected": sorted(expected),
            "detected_of_expected": sorted(hit),
            "missing": sorted(missing),
            "extra": sorted(set(detected_ids) - expected),
            "recall": round(recall, 3),
        })

        # D.5 — property-violation table
        for f in findings:
            asset = asset_for(f, rule_idx)
            property_rows.append({
                "scenario": name,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "property_violated": property_for(f.rule_id),
                "asset_category": asset,
            })

        # G.4 — asset x scenario x skill scoreboard
        by_asset: dict[str, dict] = {}
        for f in findings:
            asset = asset_for(f, rule_idx)
            slot = by_asset.setdefault(
                asset, {"rule_ids": set(), "max_rank": 0})
            slot["rule_ids"].add(f.rule_id)
            slot["max_rank"] = max(slot["max_rank"],
                                   _SEVERITY_RANK.get(f.severity.lower(), 1))
        for asset, slot in sorted(by_asset.items()):
            max_sev = [k for k, v in _SEVERITY_RANK.items()
                       if v == slot["max_rank"]][0]
            tier = tier_for_severity(max_sev)
            scoreboard_rows.append({
                "scenario": name,
                "asset_category": asset,
                "rule_ids": sorted(slot["rule_ids"]),
                "max_severity": max_sev,
                "implied_tier": tier,
                "candidate_skills": skills_for_tier(tier),
            })

    return {
        "detection": detection_rows,
        "false_positives": fp_rows,
        "properties": property_rows,
        "scoreboard": scoreboard_rows,
        "aggregate": {
            "overall_recall": round(tot_hit / tot_expected, 3) if tot_expected else 1.0,
            "expected_total": tot_expected,
            "detected_total": tot_hit,
            "clean_scenarios": n_clean,
            "false_positive_findings": tot_fp,
            "false_positive_rate_per_clean_scenario":
                round(tot_fp / n_clean, 3) if n_clean else 0.0,
            "mttd_note": "N/A — MTTD is a dynamic metric; this is a static harness.",
        },
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_markdown(report: dict) -> str:
    agg = report["aggregate"]
    out = ["# CyberLLM — static evaluation report", "",
           "Generated by `evaluate.py` (deterministic static analyzer only; "
           "no LLM, no dynamic execution).", "",
           "## Aggregate", "",
           f"- **overall detection rate (recall)**: "
           f"{agg['overall_recall']:.2%} "
           f"({agg['detected_total']}/{agg['expected_total']} must-have rules)",
           f"- **false positives on {agg['clean_scenarios']} clean control(s)**: "
           f"{agg['false_positive_findings']} "
           f"(rate {agg['false_positive_rate_per_clean_scenario']} per clean scenario)",
           f"- **mean-time-to-detect**: {agg['mttd_note']}", ""]

    out += ["## 1. Detection rate per scenario (D.4)", "",
            "| scenario | recall | detected | missing | extra (bonus) |",
            "|---|---|---|---|---|"]
    for r in report["detection"]:
        out.append(
            f"| {r['scenario']} | {r['recall']:.0%} | "
            f"{', '.join(r['detected_of_expected']) or '—'} | "
            f"{', '.join(r['missing']) or '—'} | "
            f"{', '.join(r['extra']) or '—'} |")
    out.append("")

    out += ["## 2. False positives on negative controls (D.4)", "",
            "| clean scenario | false-positive rule_ids | count |",
            "|---|---|---|"]
    for r in report["false_positives"]:
        out.append(f"| {r['scenario']} | "
                   f"{', '.join(r['false_positives']) or '(none)'} | {r['n']} |")
    out.append("")

    out += ["## 3. Property-violation table (D.5)", "",
            "Each detected finding mapped to the paper-1 property it "
            "implicates and the paper-2 asset it threatens.", "",
            "| scenario | rule_id | severity | paper-1 property | paper-2 asset |",
            "|---|---|---|---|---|"]
    for r in report["properties"]:
        out.append(f"| {r['scenario']} | {r['rule_id']} | {r['severity']} | "
                   f"{r['property_violated']} | {r['asset_category']} |")
    out.append("")

    out += ["## 4. Asset × scenario × skill scoreboard (G.4)", "",
            "| scenario | asset category | rules | max sev | tier | candidate defense skills |",
            "|---|---|---|---|---|---|"]
    for r in report["scoreboard"]:
        out.append(f"| {r['scenario']} | {r['asset_category']} | "
                   f"{', '.join(r['rule_ids'])} | {r['max_severity']} | "
                   f"{r['implied_tier']} | {', '.join(r['candidate_skills'])} |")
    out.append("")
    return "\n".join(out)


def _print_summary(report: dict) -> None:
    agg = report["aggregate"]
    print("\n========== STATIC EVAL summary ==========")
    print(f"detection recall : {agg['overall_recall']:.2%} "
          f"({agg['detected_total']}/{agg['expected_total']} must-have rules)")
    print(f"false positives  : {agg['false_positive_findings']} on "
          f"{agg['clean_scenarios']} clean control(s)")
    print(f"MTTD             : {agg['mttd_note']}")
    print("\nper-scenario detection:")
    hdr = f"{'scenario':<22} {'recall':>7}  missing"
    print(hdr); print("-" * len(hdr))
    for r in report["detection"]:
        print(f"{r['scenario']:<22} {r['recall']:>6.0%}  "
              f"{', '.join(r['missing']) or '—'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CyberLLM static evaluation harness (D.4/D.5/G.4).")
    parser.add_argument("--labels", default="examples/labels.yaml",
                        help="path to the ground-truth labels YAML.")
    parser.add_argument("--out", default="memory/eval_report.md",
                        help="where to write the Markdown report.")
    parser.add_argument("--strict", action="store_true",
                        help="exit non-zero if recall<1.0 or any false positive.")
    args = parser.parse_args(argv)

    cfg = load_config()
    rules = load_rules(cfg)
    with open(_norm(args.labels), encoding="utf-8") as f:
        labels = yaml.safe_load(f)

    report = evaluate(cfg, rules, labels)
    md = render_markdown(report)
    out_path = _norm(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md, encoding="utf-8")
    _print_summary(report)
    try:
        print(f"\nWrote {out_path.relative_to(HERE)}")
    except ValueError:
        print(f"\nWrote {out_path}")

    if args.strict:
        agg = report["aggregate"]
        if agg["overall_recall"] < 1.0 or agg["false_positive_findings"] > 0:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
