"""CyberLLM — end-to-end pipeline (defense + attack modes).

Modes
-----
- `--mode defense` (default) — diagram 1: scanners → DecisionAgent →
  ActionGenerator → SecurityGuard → target.
- `--mode attack`            — diagram 2: SystemInfoDiscovery +
  SourceCodeExploiter + DeploymentExploiter → AttackOrchestrator →
  AttackGenerator → EthicsGuard → target.
- `--mode both`              — runs defense, then attack, side-by-side.

Operands
--------
- `--example small | medium | large | all` — run every scenario in the
  named set (definitions in `config.yaml`).
- `--code` / `--log` / `--deployment` / `--scenario` — single-run mode
  overrides. In defense mode `--log` is required; in attack mode
  `--scenario` is required (a text file or a literal string).

Why the static-first design
---------------------------
The supervisor's brief says the project must "mainly detect all static
vulnerabilities". So every scanner / exploiter:
1. Runs a deterministic static pass (regex / graph checks) over the
   YAML rules — see `tools/static_analyzer.py`.
2. Hands the static findings to the LLM as *context*, asking it to
   refine, explain, and extend (paper 4 §IV-B-1 "constraint +
   augmentation").
3. Merges the two layers, static wins on duplicates.

So with the stubbed LLM you already get real findings; once a real LLM
is wired in, accuracy goes up monotonically.
"""

from __future__ import annotations
import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

import yaml

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ---- defense agents -------------------------------------------------------
from agents.action_generator import ActionGenerator
from agents.base_agent import Input
from agents.decision_agent import DecisionAgent
from agents.deployment_scanner import DeploymentScannerAgent
from agents.log_analyzer import LogAnalyzerAgent
from agents.security_guard import SecurityGuard
from agents.source_code_scanner import SourceCodeScannerAgent

# ---- attack agents --------------------------------------------------------
from agents.attack import (
    AttackGeneratorAgent,
    AttackOrchestratorAgent,
    DeploymentExploiterAgent,
    EthicsGuard,
    SourceCodeExploiterAgent,
    SystemInfoDiscoveryAgent,
)

from llm_client import LLMClient
from run_logger import RunLogger


HERE = Path(__file__).parent
RUN_LOGS_DIR = HERE / "run_logs"
CODE_EXTENSIONS = {".py", ".c", ".cpp", ".h"}


# ---------------------------------------------------------------------------
# Config + rule loading
# ---------------------------------------------------------------------------

def load_config() -> dict:
    with open(HERE / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_rules(cfg: dict) -> dict:
    rules_dir = HERE / cfg["paths"]["rules_dir"]
    rules: dict = {}
    for path in sorted(rules_dir.glob("*.yaml")):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for family, items in data.items():
            rules.setdefault(family, []).extend(items)
    return rules


def rules_snippet(rules: dict, family: str) -> str:
    items = rules.get(family, [])
    lines = []
    for r in items:
        lines.append(
            f"- {r['id']} [{r.get('severity', '?')}]: "
            f"{r.get('title', '')} — "
            f"{r.get('rationale') or r.get('rule') or r.get('signature') or ''}"
        )
    return "\n".join(lines) or "(no rules loaded)"


def build_llms(cfg: dict) -> dict:
    return {name: LLMClient.create(c) for name, c in cfg["llm_configs"].items()}


def _norm(p: str | Path) -> Path:
    return (HERE / str(p).replace("\\", "/")).resolve()


def _rel_or_abs(p: Path) -> str:
    """Return a path relative to HERE when possible (nicer for the
    in-repo case), otherwise the absolute path (needed when tests
    redirect run_logs/ to a temp directory outside the project)."""
    try:
        return str(p.resolve().relative_to(HERE))
    except ValueError:
        return str(p.resolve())


def _collect_code_files(code_target: Path) -> list[Path]:
    if code_target.is_file():
        return [code_target]
    if code_target.is_dir():
        return sorted(
            f for f in code_target.rglob("*")
            if f.is_file() and f.suffix.lower() in CODE_EXTENSIONS
            and "__pycache__" not in f.parts
        )
    raise FileNotFoundError(f"code target not found: {code_target}")


def _read_scenario(spec: str | None) -> str:
    if not spec:
        return "Find the highest-impact exploit chain in this system."
    p = _norm(spec) if not spec.startswith(("Find ", "Goal ")) else None
    if p is not None and p.exists():
        return p.read_text(encoding="utf-8")
    return spec


# ===========================================================================
# DEFENSE PIPELINE
# ===========================================================================

def run_defense_pipeline(
    code_paths: list[Path],
    log_path: Path,
    deploy_path: Path,
    cfg: dict,
    rules: dict,
    scenario_name: str = "default",
    verbose: bool = True,
) -> dict:
    llms = build_llms(cfg)
    rlog = RunLogger(RUN_LOGS_DIR, mode="defense", scenario=scenario_name)
    rlog.log_meta({
        "mode": "defense",
        "scenario": scenario_name,
        "inputs": {
            "code": [str(p) for p in code_paths],
            "log": str(log_path),
            "deployment": str(deploy_path),
        },
    })

    code_cfg = dict(cfg["agent_configs"]["source_code_scanner"],
                    rules_snippet=rules_snippet(rules, "code_rules"),
                    rules_full=rules)
    log_cfg = dict(cfg["agent_configs"]["log_analyzer"],
                   rules_snippet=rules_snippet(rules, "log_rules"),
                   rules_full=rules)
    dep_cfg = dict(cfg["agent_configs"]["deployment_scanner"],
                   rules_snippet=rules_snippet(rules, "topology_rules"),
                   rules_full=rules)

    code_agent = SourceCodeScannerAgent(
        "source_code_scanner", code_cfg, llms[code_cfg["llm"]])
    log_agent = LogAnalyzerAgent("log_analyzer", log_cfg, llms[log_cfg["llm"]])
    dep_agent = DeploymentScannerAgent(
        "deployment_scanner", dep_cfg, llms[dep_cfg["llm"]])

    inputs: list[Input] = [
        SourceCodeScannerAgent.load_example(p) for p in code_paths
    ] + [
        LogAnalyzerAgent.load_example(log_path),
        DeploymentScannerAgent.load_example(deploy_path),
        Input(content="Defense scan requested by authorised operator.",
              source="user", trust_level="authenticated"),
    ]
    rlog.log_inputs(inputs)

    if verbose:
        print(f"\n[defense:{scenario_name}] source-code scanner ({len(code_paths)} file(s))")
    code_result = code_agent.run(inputs)
    rlog.log_static("source_code", code_agent.last_static_findings)
    rlog.log_agent("source_code_scanner",
                   code_agent.last_prompt, code_agent.last_response,
                   code_result.findings)
    if verbose:
        print(f"  -> {len(code_result.findings)} finding(s)")
        print(f"[defense:{scenario_name}] log analyzer")
    log_result = log_agent.run(inputs)
    rlog.log_static("log", log_agent.last_static_findings)
    rlog.log_agent("log_analyzer",
                   log_agent.last_prompt, log_agent.last_response,
                   log_result.findings)
    if verbose:
        print(f"  -> {len(log_result.findings)} finding(s)")
        print(f"[defense:{scenario_name}] deployment scanner")
    dep_result = dep_agent.run(inputs)
    rlog.log_static("deployment", dep_agent.last_static_findings)
    rlog.log_agent("deployment_scanner",
                   dep_agent.last_prompt, dep_agent.last_response,
                   dep_result.findings)
    if verbose:
        print(f"  -> {len(dep_result.findings)} finding(s)")

    decision_cfg = dict(cfg["agent_configs"]["decision_agent"],
                        response_tiers=cfg["response_tiers"])
    decision_agent = DecisionAgent(
        "decision_agent", decision_cfg, llms[decision_cfg["llm"]])
    decision = decision_agent.run([code_result, log_result, dep_result])
    rlog.log_agent("decision_agent",
                   decision_agent.last_prompt, decision_agent.last_response,
                   findings=None)
    rlog.log_decision(decision)
    if verbose:
        print(f"[defense:{scenario_name}] decision: tier={decision.recommended_tier} "
              f"conf={decision.confidence:.2f}")

    action_cfg = dict(
        cfg["agent_configs"]["action_generator"],
        dry_run=cfg.get("action_engine", {}).get("dry_run", True),
        work_dir=str(HERE / cfg.get("action_engine", {}).get(
            "work_dir", "mcp_workspace")),
        repo_path=str(HERE),
        log_path=str(log_path),
        default_file=(str(code_paths[0]) if code_paths else "unknown.py"),
    )
    action_agent = ActionGenerator(
        "action_generator", action_cfg, llms[action_cfg["llm"]])
    vulnerable_code = ""
    for p in code_paths:
        if p.suffix.lower() == ".py":
            vulnerable_code = p.read_text(encoding="utf-8", errors="replace")
            break
    if not vulnerable_code and code_paths:
        vulnerable_code = code_paths[0].read_text(encoding="utf-8", errors="replace")
    action = action_agent.generate(decision, vulnerable_code=vulnerable_code)
    if action_agent.last_prompt:
        rlog.log_agent("action_generator",
                       action_agent.last_prompt, action_agent.last_response,
                       findings=None)
    rlog.log_action(action)
    if action_agent.last_plan is not None:
        rlog.log_action_plan(action_agent.last_plan, action_agent.last_report)
    if verbose:
        print(f"[defense:{scenario_name}] action: kind={action.kind} target={action.target}")
        if action_agent.last_report is not None:
            print(f"[defense:{scenario_name}] plan: "
                  f"{action_agent.last_report.summary}")

    guard = SecurityGuard(
        allowed_objectives=cfg["security"]["allowed_objectives"],
        authenticated_sources=cfg["security"]["authenticated_sources"],
        trusted_destinations=cfg["security"]["trusted_destinations"],
    )
    objective = ("auto-correct insecure code" if action.kind == "patch_code"
                 else "produce defensive action")
    verdict = guard.check(action, objective, inputs)
    rlog.log_guard(verdict)
    if verbose:
        print(f"[defense:{scenario_name}] guard: allowed={verdict.allowed} "
              f"({verdict.reason})")

    record = {
        "mode": "defense",
        "scenario": scenario_name,
        "inputs": {
            "code": [_rel_or_abs(p) for p in code_paths],
            "log": _rel_or_abs(Path(log_path)),
            "deployment": _rel_or_abs(Path(deploy_path)),
        },
        "decision": {
            "summary": decision.summary,
            "asset_categories_touched": decision.asset_categories_touched,
            "recommended_tier": decision.recommended_tier,
            "confidence": decision.confidence,
            "justification": decision.justification,
        },
        "action": {"kind": action.kind, "target": action.target,
                   "parameters": action.parameters,
                   "plan_id": action.plan_id},
        "action_report": action.report,
        "mcp_audit": (action_agent.registry.audit
                       if hasattr(action_agent, "registry") else []),
        "guard_verdict": asdict(verdict),
        "findings": [asdict(f) for f in decision.findings],
        "committed": ({"action": action.kind, "target": action.target,
                       "parameters": action.parameters}
                      if verdict.allowed else None),
    }

    mem_dir = HERE / cfg["paths"]["memory_dir"]
    mem_dir.mkdir(parents=True, exist_ok=True)
    fname = "last_run_defense.json" if scenario_name == "default" \
        else f"defense_{scenario_name}.json"
    (mem_dir / fname).write_text(json.dumps(record, indent=2), encoding="utf-8")
    record["run_log_dir"] = _rel_or_abs(rlog.dir)
    rlog.finalize()
    return record


# ===========================================================================
# ATTACK PIPELINE
# ===========================================================================

def run_attack_pipeline(
    code_paths: list[Path],
    deploy_path: Path,
    scenario: str,
    cfg: dict,
    rules: dict,
    scenario_name: str = "default",
    verbose: bool = True,
    cli_authorized_targets: list[str] | None = None,
) -> dict:
    llms = build_llms(cfg)
    rlog = RunLogger(RUN_LOGS_DIR, mode="attack", scenario=scenario_name)
    rlog.log_meta({
        "mode": "attack",
        "scenario": scenario_name,
        "inputs": {
            "code": [str(p) for p in code_paths],
            "deployment": str(deploy_path),
            "scenario_chars": len(scenario or ""),
        },
    })

    # ---- Shared agent configs --------------------------------------------
    discovery_cfg = dict(cfg["agent_configs"]["system_info_discovery"],
                         rules_full=rules)
    code_cfg = dict(cfg["agent_configs"]["source_code_exploiter"],
                    rules_full=rules,
                    attack_rules_snippet=rules_snippet(rules, "attack_rules"))
    dep_cfg = dict(cfg["agent_configs"]["deployment_exploiter"],
                   rules_full=rules,
                   attack_rules_snippet=rules_snippet(rules, "attack_rules"))
    orch_cfg = dict(cfg["agent_configs"]["attack_orchestrator"])
    gen_cfg = dict(cfg["agent_configs"]["attack_generator"])

    # ---- Instantiate the attack-side agents -------------------------------
    discovery = SystemInfoDiscoveryAgent(
        "system_info_discovery", discovery_cfg, llms[discovery_cfg["llm"]])
    code_exploit = SourceCodeExploiterAgent(
        "source_code_exploiter", code_cfg, llms[code_cfg["llm"]])
    dep_exploit = DeploymentExploiterAgent(
        "deployment_exploiter", dep_cfg, llms[dep_cfg["llm"]])
    orchestrator = AttackOrchestratorAgent(
        "attack_orchestrator", orch_cfg, llms[orch_cfg["llm"]])
    generator = AttackGeneratorAgent(
        "attack_generator", gen_cfg, llms[gen_cfg["llm"]])

    # ---- Inputs (no log file on the attack side per diagram 2) -----------
    inputs: list[Input] = [
        SourceCodeExploiterAgent.load_example(p) for p in code_paths
    ] + [
        DeploymentExploiterAgent.load_example(deploy_path),
        Input(content=scenario, source="user", trust_level="authenticated"),
    ]
    rlog.log_inputs(inputs)

    if verbose:
        print(f"\n[attack:{scenario_name}] system_info_discovery")
    discovery_result = discovery.run(inputs)
    instance = getattr(discovery_result, "system_instance", None)
    rlog.log_agent("system_info_discovery",
                   discovery.last_prompt, discovery.last_response,
                   findings=None)
    if instance is not None:
        rlog.log_system_instance(instance)
    if verbose and instance is not None:
        print(f"  -> external={instance.external_actors} "
              f"safety={instance.safety_actors}")

    if verbose:
        print(f"[attack:{scenario_name}] source_code_exploiter ({len(code_paths)} file(s))")
    code_result = code_exploit.run(inputs)
    rlog.log_static("source_code_exploit", code_exploit.last_static_findings)
    rlog.log_agent("source_code_exploiter",
                   code_exploit.last_prompt, code_exploit.last_response,
                   code_result.findings)
    if verbose:
        print(f"  -> {len(code_result.findings)} exploit(s)")
        print(f"[attack:{scenario_name}] deployment_exploiter")
    dep_result = dep_exploit.run(inputs)
    rlog.log_static("deployment_exploit", dep_exploit.last_static_findings)
    rlog.log_agent("deployment_exploiter",
                   dep_exploit.last_prompt, dep_exploit.last_response,
                   dep_result.findings)
    if verbose:
        print(f"  -> {len(dep_result.findings)} exploit(s)")

    plan = orchestrator.plan([code_result, dep_result], scenario, instance)
    rlog.log_agent("attack_orchestrator",
                   orchestrator.last_prompt, orchestrator.last_response,
                   findings=None)
    rlog.log_plan(plan)
    if verbose:
        print(f"[attack:{scenario_name}] orchestrator: target={plan.target_asset} "
              f"conf={plan.confidence:.2f} chose={[f.rule_id for f in plan.chosen_findings]}")

    # ---- Ethics / scope guard --------------------------------------------
    guard = EthicsGuard(
        allowed_scenarios=cfg.get("attack", {}).get("allowed_scenarios", []),
        authorized_targets=cfg.get("attack", {}).get("authorized_targets", []),
        allow_all_in_dev=cfg.get("attack", {}).get("allow_all_in_dev", False),
        cli_authorized_targets=cli_authorized_targets,
    )
    verdict = guard.check_plan(scenario, plan.target_asset)
    rlog.log_ethics(verdict)
    if verbose:
        print(f"[attack:{scenario_name}] ethics: allowed={verdict.allowed} ({verdict.reason})")

    scripts = []
    redacted: list[str] = []
    if verdict.allowed:
        scripts = generator.generate(plan)
        scripts, redacted = guard.filter_scripts(scripts)
        rlog.log_attack_scripts(scripts, redacted)
        if verbose:
            print(f"[attack:{scenario_name}] generated {len(scripts)} script(s); "
                  f"redacted {len(redacted)}")

    record = {
        "mode": "attack",
        "scenario": scenario_name,
        "scenario_text": scenario[:500],
        "inputs": {
            "code": [_rel_or_abs(p) for p in code_paths],
            "deployment": _rel_or_abs(Path(deploy_path)),
        },
        "system_instance": {
            "external_actors": instance.external_actors if instance else [],
            "safety_actors": instance.safety_actors if instance else [],
            "notes": instance.notes if instance else [],
        },
        "plan": {
            "target_asset": plan.target_asset,
            "summary": plan.summary,
            "chosen_rule_ids": [f.rule_id for f in plan.chosen_findings],
            "poison_path": plan.poison_path,
            "trigger_path": plan.trigger_path,
            "confidence": plan.confidence,
            "justification": plan.justification,
        },
        "ethics_verdict": asdict(verdict),
        "scripts": [
            {
                "rule_id": s.rule_id,
                "title": s.title,
                "language": s.language,
                "target_hint": s.target_hint,
                "expected_effect": s.expected_effect,
                "body": s.body,
            } for s in scripts
        ],
        "redacted": redacted,
    }

    mem_dir = HERE / cfg["paths"]["memory_dir"]
    mem_dir.mkdir(parents=True, exist_ok=True)
    fname = "last_run_attack.json" if scenario_name == "default" \
        else f"attack_{scenario_name}.json"
    (mem_dir / fname).write_text(json.dumps(record, indent=2), encoding="utf-8")
    record["run_log_dir"] = _rel_or_abs(rlog.dir)
    rlog.finalize()
    return record


# ===========================================================================
# BATCH ORCHESTRATION
# ===========================================================================

def _scenarios_for(kind: str, cfg: dict) -> list[dict]:
    sets = cfg.get("example_sets", {})
    if kind == "all":
        out: list[dict] = []
        for k in ("small", "medium", "large"):
            out.extend(sets.get(k, []))
        return out
    if kind not in sets:
        available = ", ".join(sorted(sets.keys())) or "(none)"
        raise SystemExit(f"Unknown example set '{kind}'. Available: {available}, all")
    return sets[kind]


def run_example_batch(
    kind: str,
    mode: str,
    cfg: dict,
    rules: dict,
    log_override: str | None = None,
    deployment_override: str | None = None,
    scenario_override: str | None = None,
    cli_authorized_targets: list[str] | None = None,
) -> int:
    scenarios = _scenarios_for(kind, cfg)
    print(f"==> mode={mode}  example={kind}  ({len(scenarios)} scenario(s))\n")

    defense_rows: list[dict] = []
    attack_rows: list[dict] = []

    for s in scenarios:
        name = s["name"]
        code_target = _norm(s["code"])
        try:
            code_paths = _collect_code_files(code_target)
        except FileNotFoundError as exc:
            print(f"[{name}] SKIP — {exc}")
            continue

        if mode in {"defense", "both"}:
            log_path = _norm(log_override) if log_override else _norm(s["log"])
            dep_path = _norm(deployment_override) if deployment_override else _norm(s["deployment"])
            try:
                rec = run_defense_pipeline(code_paths, log_path, dep_path,
                                           cfg, rules, scenario_name=name)
                defense_rows.append({
                    "name": name,
                    "files_scanned": len(code_paths),
                    "findings": len(rec["findings"]),
                    "tier": rec["decision"]["recommended_tier"],
                    "confidence": rec["decision"]["confidence"],
                    "guard": "PASS" if rec["guard_verdict"]["allowed"] else "REFUSED",
                    "action": rec["action"]["kind"],
                })
            except Exception as exc:        # noqa: BLE001
                print(f"[defense:{name}] ERROR — {type(exc).__name__}: {exc}")
                defense_rows.append({"name": name, "error": str(exc)})

        if mode in {"attack", "both"}:
            dep_path = _norm(deployment_override) if deployment_override else _norm(s["deployment"])
            scenario_spec = scenario_override or s.get("scenario")
            scenario_text = _read_scenario(scenario_spec)
            try:
                rec = run_attack_pipeline(code_paths, dep_path, scenario_text,
                                          cfg, rules, scenario_name=name,
                                          cli_authorized_targets=cli_authorized_targets)
                attack_rows.append({
                    "name": name,
                    "files_scanned": len(code_paths),
                    "chosen": rec["plan"]["chosen_rule_ids"],
                    "target_asset": rec["plan"]["target_asset"],
                    "confidence": rec["plan"]["confidence"],
                    "ethics": "PASS" if rec["ethics_verdict"]["allowed"] else "REFUSED",
                    "scripts": len(rec["scripts"]),
                })
            except Exception as exc:        # noqa: BLE001
                print(f"[attack:{name}] ERROR — {type(exc).__name__}: {exc}")
                attack_rows.append({"name": name, "error": str(exc)})

    # ---- print summary tables -----------------------------------------
    if defense_rows:
        print("\n========== DEFENSE summary ==========")
        hdr = f"{'scenario':<22} {'files':>5} {'findings':>9} {'tier':<9} {'conf':>5}  {'guard':<7} {'action'}"
        print(hdr); print("-" * len(hdr))
        for row in defense_rows:
            if "error" in row:
                print(f"{row['name']:<22} ERROR — {row['error'][:60]}")
                continue
            print(f"{row['name']:<22} {row['files_scanned']:>5d} {row['findings']:>9d} "
                  f"{row['tier']:<9} {row['confidence']:>5.2f}  "
                  f"{row['guard']:<7} {row['action']}")

    if attack_rows:
        print("\n========== ATTACK summary ==========")
        hdr = f"{'scenario':<22} {'files':>5} {'chose':<22} {'asset':<22} {'conf':>5} {'ethics':<7} {'#scripts':>8}"
        print(hdr); print("-" * len(hdr))
        for row in attack_rows:
            if "error" in row:
                print(f"{row['name']:<22} ERROR — {row['error'][:60]}")
                continue
            chose = ",".join(row["chosen"])[:20]
            asset = row["target_asset"][:20]
            print(f"{row['name']:<22} {row['files_scanned']:>5d} {chose:<22} {asset:<22} "
                  f"{row['confidence']:>5.2f} {row['ethics']:<7} {row['scripts']:>8d}")

    mem_dir = HERE / cfg["paths"]["memory_dir"]
    mem_dir.mkdir(parents=True, exist_ok=True)
    out = mem_dir / f"batch_{mode}_{kind}.json"
    out.write_text(json.dumps({"defense": defense_rows,
                               "attack": attack_rows}, indent=2),
                   encoding="utf-8")
    print(f"\nWrote batch summary to {out}")
    return 0


# ===========================================================================
# ENTRY POINT
# ===========================================================================

def _infer_default_example(cfg: dict) -> str:
    ex = cfg.get("paths", {}).get("examples_dir", "")
    name = Path(ex.replace("\\", "/")).name
    return name if name in {"small", "medium", "large", "all"} else "small"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="CyberLLM — defense & attack pipelines (paper 4 schema-driven).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python pipeline.py --example small\n"
            "  python pipeline.py --mode attack --example small\n"
            "  python pipeline.py --mode both  --example medium\n"
            "  python pipeline.py --mode defense --code examples/small/02_can_gateway.py\n"
            "  python pipeline.py --mode attack  --code examples/medium/ev_charging_api \\\n"
            "                      --deployment examples/deployments/02_misconfigured_cloud.yaml \\\n"
            "                      --scenario  examples/attack_scenarios/01_data_exfiltration.txt\n"
        ),
    )
    parser.add_argument("--mode", choices=["defense", "attack", "both"], default="defense",
                        help="Which pipeline(s) to run.")
    parser.add_argument("--example", default=None,
                        help="Named example set: small | medium | large | all.")
    parser.add_argument("--code", default=None,
                        help="Single-run mode: path to a code file OR directory.")
    parser.add_argument("--log", default=None,
                        help="Defense single-run: path to a log file.")
    parser.add_argument("--deployment", default=None,
                        help="Path to a deployment YAML.")
    parser.add_argument("--scenario", default=None,
                        help="Attack mode: path to a scenario .txt OR a literal hint string.")
    parser.add_argument("--authorize-target", action="append", default=[],
                        help="Add an extra authorised target (attack EthicsGuard).")
    args = parser.parse_args(argv)

    cfg = load_config()
    rules = load_rules(cfg)

    # ---- batch mode -----------------------------------------------------
    if args.example or args.code is None:
        kind = args.example or _infer_default_example(cfg)
        return run_example_batch(
            kind, args.mode, cfg, rules,
            log_override=args.log,
            deployment_override=args.deployment,
            scenario_override=args.scenario,
            cli_authorized_targets=args.authorize_target,
        )

    # ---- single-run mode -----------------------------------------------
    code_target = _norm(args.code)
    try:
        code_paths = _collect_code_files(code_target)
    except FileNotFoundError as exc:
        print(f"ERROR — {exc}", file=sys.stderr)
        return 2

    defaults = cfg.get("defaults", {})
    log_path = _norm(args.log) if args.log else _norm(defaults.get("log", "examples/sample_log.log"))
    dep_path = _norm(args.deployment) if args.deployment \
        else _norm(defaults.get("deployment", "examples/sample_deployment.yaml"))

    if args.mode in {"defense", "both"}:
        rec_def = run_defense_pipeline(code_paths, log_path, dep_path, cfg, rules,
                                       scenario_name="default", verbose=True)
        if args.mode == "defense":
            print("\n========== defense run summary ==========")
            print(json.dumps(rec_def, indent=2))

    if args.mode in {"attack", "both"}:
        scenario_text = _read_scenario(args.scenario)
        rec_atk = run_attack_pipeline(code_paths, dep_path, scenario_text,
                                      cfg, rules, scenario_name="default",
                                      verbose=True,
                                      cli_authorized_targets=args.authorize_target)
        print("\n========== attack run summary ==========")
        print(json.dumps(rec_atk, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
