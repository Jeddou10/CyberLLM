"""CyberLLM — first end-to-end defense pipeline.

This file wires together every block of the project diagram:

  Source-code scanner  ──┐
  Log analyzer        ───┼──► Decision agent ──► Action generator ──► Target
  Deployment scanner  ──┘                  ▲
                                            │
                            Rules / Policies + Metamodel
                                            │
                                  Security guard (paper 1)

Run it with:

    python pipeline.py
    python pipeline.py --code examples/sample_code.py \
                       --log  examples/sample_log.log  \
                       --deployment examples/sample_deployment.yaml

The default LLM provider is `stub`, so it runs without network access.
Swap providers in config.yaml when you have credentials.
"""

from __future__ import annotations
import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

import yaml

# Make stdout UTF-8 on Windows so the small arrows in our log messages
# don't trip the default cp1252 codec.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from agents.action_generator import ActionGenerator
from agents.base_agent import Input
from agents.decision_agent import DecisionAgent
from agents.deployment_scanner import DeploymentScannerAgent
from agents.log_analyzer import LogAnalyzerAgent
from agents.security_guard import SecurityGuard
from agents.source_code_scanner import SourceCodeScannerAgent
from llm_client import LLMClient


HERE = Path(__file__).parent


def load_config() -> dict:
    with open(HERE / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_rules(cfg: dict) -> dict:
    rules_dir = HERE / cfg["paths"]["rules_dir"]
    rules = {}
    for path in rules_dir.glob("*.yaml"):
        with open(path, encoding="utf-8") as f:
            rules.update(yaml.safe_load(f) or {})
    return rules


def rules_snippet(rules: dict, family: str) -> str:
    """Render a compact textual block of rules for prompt injection."""
    items = rules.get(family, [])
    lines = []
    for r in items:
        lines.append(f"- {r['id']} [{r.get('severity', '?')}]: "
                     f"{r.get('title', '')} — "
                     f"{r.get('rationale') or r.get('rule') or r.get('signature') or ''}")
    return "\n".join(lines) or "(no rules loaded)"


def build_llms(cfg: dict) -> dict:
    return {name: LLMClient.create(c) for name, c in cfg["llm_configs"].items()}


def run_pipeline(code_path: Path, log_path: Path, deploy_path: Path,
                 cfg: dict, rules: dict) -> dict:
    llms = build_llms(cfg)

    # ---- 1. Build scanner agents -----------------------------------------
    code_cfg = dict(cfg["agent_configs"]["source_code_scanner"],
                    rules_snippet=rules_snippet(rules, "code_rules"))
    log_cfg = dict(cfg["agent_configs"]["log_analyzer"],
                   rules_snippet=rules_snippet(rules, "log_rules"))
    dep_cfg = dict(cfg["agent_configs"]["deployment_scanner"],
                   rules_snippet=rules_snippet(rules, "topology_rules"))

    code_agent = SourceCodeScannerAgent(
        "source_code_scanner", code_cfg, llms[code_cfg["llm"]])
    log_agent = LogAnalyzerAgent(
        "log_analyzer", log_cfg, llms[log_cfg["llm"]])
    dep_agent = DeploymentScannerAgent(
        "deployment_scanner", dep_cfg, llms[dep_cfg["llm"]])

    # ---- 2. Load example inputs (each tagged with provenance) ------------
    inputs: list[Input] = [
        SourceCodeScannerAgent.load_example(code_path),
        LogAnalyzerAgent.load_example(log_path),
        DeploymentScannerAgent.load_example(deploy_path),
    ]
    # The user issuing the task is an authenticated source.
    user_input = Input(content="Scan the new ECU update and the latest logs.",
                       source="user", trust_level="authenticated")
    inputs.append(user_input)

    # ---- 3. Run scanners in sequence -------------------------------------
    print("[pipeline] running source-code scanner ...")
    code_result = code_agent.run(inputs)
    print(f"  → {len(code_result.findings)} finding(s)")

    print("[pipeline] running log analyzer ...")
    log_result = log_agent.run(inputs)
    print(f"  → {len(log_result.findings)} finding(s)")

    print("[pipeline] running deployment scanner ...")
    dep_result = dep_agent.run(inputs)
    print(f"  → {len(dep_result.findings)} finding(s)")

    # ---- 4. Decision agent aggregates ------------------------------------
    decision_cfg = dict(cfg["agent_configs"]["decision_agent"],
                        response_tiers=cfg["response_tiers"])
    decision_agent = DecisionAgent(
        "decision_agent", decision_cfg, llms[decision_cfg["llm"]])
    decision = decision_agent.run([code_result, log_result, dep_result])

    print(f"[pipeline] decision: tier={decision.recommended_tier} "
          f"confidence={decision.confidence:.2f}")

    # ---- 5. Action generator proposes a concrete action ------------------
    action_cfg = cfg["agent_configs"]["action_generator"]
    action_agent = ActionGenerator(
        "action_generator", action_cfg, llms[action_cfg["llm"]])
    action = action_agent.generate(
        decision,
        vulnerable_code=Path(code_path).read_text(encoding="utf-8"),
    )
    print(f"[pipeline] proposed action: kind={action.kind} target={action.target}")

    # ---- 6. Security guard validates the action --------------------------
    guard = SecurityGuard(
        allowed_objectives=cfg["security"]["allowed_objectives"],
        authenticated_sources=cfg["security"]["authenticated_sources"],
        trusted_destinations=cfg["security"]["trusted_destinations"],
    )
    objective = ("auto-correct insecure code" if action.kind == "patch_code"
                 else "produce defensive action")
    verdict = guard.check(action, objective, inputs)
    print(f"[pipeline] security verdict: allowed={verdict.allowed} "
          f"({verdict.reason})")

    # ---- 7. (Stub) commit to target or refuse ----------------------------
    if verdict.allowed:
        committed = {"action": action.kind, "target": action.target,
                     "parameters": action.parameters}
        print("[pipeline] target system: action committed (stub).")
    else:
        committed = None
        print("[pipeline] target system: action REFUSED by guard.")

    # ---- 8. Persist to memory for the optional adaptive loop -------------
    record = {
        "user_prompt": user_input.content,
        "decision": {
            "summary": decision.summary,
            "asset_categories_touched": decision.asset_categories_touched,
            "recommended_tier": decision.recommended_tier,
            "confidence": decision.confidence,
        },
        "action": {"kind": action.kind, "target": action.target,
                   "parameters": action.parameters},
        "guard_verdict": asdict(verdict),
        "findings": [asdict(f) for f in decision.findings],
        "committed": committed,
    }
    mem_path = HERE / cfg["paths"]["memory_dir"] / "last_run.json"
    mem_path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"[pipeline] memory: wrote {mem_path}")

    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CyberLLM first pipeline")
    parser.add_argument("--code", default=str(HERE / "examples" / "sample_code.py"))
    parser.add_argument("--log",  default=str(HERE / "examples" / "sample_log.log"))
    parser.add_argument("--deployment",
                        default=str(HERE / "examples" / "sample_deployment.yaml"))
    args = parser.parse_args(argv)

    cfg = load_config()
    rules = load_rules(cfg)
    record = run_pipeline(Path(args.code), Path(args.log),
                          Path(args.deployment), cfg, rules)

    print("\n========== run summary ==========")
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
