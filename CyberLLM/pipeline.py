

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
import ast
import json
import os
import re
import sys
from dataclasses import asdict
from pathlib import Path

import yaml

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

# ---- defense agents -------------------------------------------------------
from agents.action_engine import GuardAdapter, legacy_kind
from agents.action_generator import ActionGenerator
from agents.base_agent import Input
from agents.decision_agent import DecisionAgent
from agents.deployment_scanner import DeploymentScannerAgent
from agents.ha_judge import HaJudge
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

from agents.memory_store import Incident, MemoryAuthError, MemoryStore

from llm_client import LLMClient
from run_logger import RunLogger
from tools.log import Console


HERE = Path(__file__).parent
RUN_LOGS_DIR = HERE / "run_logs"
CODE_EXTENSIONS = {".py", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx",
                   ".rs", ".go", ".java", ".js", ".ts"}


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


def build_memory(cfg: dict) -> MemoryStore | None:
    """Construct the signed incident store (Phase E) if enabled.

    The signing key (E.3) is read from the env var named in
    `memory.signing_key_env` (falling back to a clearly-labelled dev
    key) so a real deployment keeps the key out of the repo. Returns
    None when memory is disabled, in which case the pipeline behaves
    exactly as before.
    """
    mem_cfg = cfg.get("memory", {}) or {}
    if not mem_cfg.get("enabled", True):
        return None
    mem_dir = HERE / cfg["paths"]["memory_dir"]
    db_path = mem_dir / mem_cfg.get("db_file", "incidents.db")
    key_env = mem_cfg.get("signing_key_env", "CYBERLLM_MEMORY_KEY")
    signing_key = (os.environ.get(key_env)
                   or mem_cfg.get("dev_signing_key")
                   or "cyberllm-dev-insecure-key")
    return MemoryStore(
        db_path=db_path,
        signing_key=signing_key,
        authenticated_sources=cfg.get("security", {}).get(
            "authenticated_sources", ["user", "rules_engine", "mcp_tool"]),
        reject_unverified=bool(mem_cfg.get("reject_unverified", True)),
    )


def _writer_identity(cfg: dict) -> str:
    return (cfg.get("memory", {}) or {}).get("writer_identity", "rules_engine")


# Map a step's legacy kind to the objective the SecurityGuard checks it
# against. (The destination / privilege is now read from the step itself by
# `SecurityGuard.check_step`, so no destination-translation table is needed.)
_STEP_KIND_OBJECTIVE = {
    "patch_code": "auto-correct insecure code",
    "alert_only": "produce findings report",
    "noop": "produce findings report",
}


def build_step_guard(security_guard: SecurityGuard,
                     inputs: list[Input],
                     decision_summary: str = "") -> GuardAdapter:
    """Adapt the SecurityGuard into a per-step `GuardAdapter` (C.4).

    The executor calls this on *every* MCP tool call. We use the new
    `check_step` so the guard sees the **real step shape** (its tool,
    side-effect, requires_authorization) and feeds the H_a judge the full
    context — the step description plus the decision's threat summary — so
    the judge reasons with the actual threat picture, not a thin stub."""
    def check(step) -> tuple[bool, str]:
        kind = legacy_kind(step)
        objective = _STEP_KIND_OBJECTIVE.get(kind, "produce defensive action")
        verdict = security_guard.check_step(step, objective, inputs,
                                            decision_summary=decision_summary)
        return verdict.allowed, verdict.reason
    return GuardAdapter(fn=check)


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


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def _rule_ids(findings) -> str:
    """Compact, sorted, de-duplicated rule-id list for a findings list."""
    ids = sorted({getattr(f, "rule_id", "?") for f in findings})
    return ", ".join(ids) if ids else "(none)"


def _llm_banner(llms: dict) -> str:
    """One-line summary of which concrete client each llm-config resolved
    to. Crucial during testing: shows whether you are really hitting
    gpt-4o or silently falling back to the offline stub."""
    parts = []
    for name, client in llms.items():
        impl = type(client).__name__
        model = client.cfg.get("model", "?")
        note = " (fallback→stub)" if impl == "StubLLM" \
            and client.cfg.get("provider", "stub") != "stub" else ""
        parts.append(f"{name}={impl}<{model}>{note}")
    return "LLM clients: " + " · ".join(parts)


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
    debug: bool = False,
) -> dict:
    con = Console(verbose=verbose, debug=debug)
    con.section(f"DEFENSE · {scenario_name}")
    con.kv("code", ", ".join(p.name for p in code_paths) or "(none)")
    con.kv("log", Path(log_path).name)
    con.kv("deployment", Path(deploy_path).name)

    llms = build_llms(cfg)
    con.info(_llm_banner(llms))
    memory = build_memory(cfg)
    con.kv("memory", "enabled" if memory is not None
           else "disabled")
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

    _scan_cfg = cfg.get("scanners", {}) or {}
    external_static = bool(_scan_cfg.get("external_static", True))
    use_llm = bool(_scan_cfg.get("use_llm", True))
    # Per-scanner overrides (default to the global use_llm). The web UI uses
    # these to run the log/topology LLM pass only when the user actually
    # supplied a log / deployment — so a code-only scan never invents log or
    # topology findings out of an empty or default input.
    use_llm_log = bool(_scan_cfg.get("use_llm_log", use_llm))
    use_llm_dep = bool(_scan_cfg.get("use_llm_deployment", use_llm))
    second_pass = bool(_scan_cfg.get("second_pass", False))
    code_cfg = dict(cfg["agent_configs"]["source_code_scanner"],
                    rules_snippet=rules_snippet(rules, "code_rules"),
                    rules_full=rules,
                    external_static=external_static, use_llm=use_llm,
                    second_pass=second_pass)
    log_cfg = dict(cfg["agent_configs"]["log_analyzer"],
                   rules_snippet=rules_snippet(rules, "log_rules"),
                   rules_full=rules, use_llm=use_llm_log)
    dep_cfg = dict(cfg["agent_configs"]["deployment_scanner"],
                   rules_snippet=rules_snippet(rules, "topology_rules"),
                   rules_full=rules, use_llm=use_llm_dep)

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
    con.detail(f"inputs: {len(inputs)} item(s) — "
               + ", ".join(f"{i.source}[{i.trust_level}]" for i in inputs))

    # ---- scanners (static floor + LLM refinement) ----------------------
    def _run_scanner(label, n, agent, result_kind):
        con.info(f"[{n}/6] {label} — agent '{agent.agent_id}' starting")
        con.step("running deterministic static analyzer (no code is executed)…")
        with con.timed(label):
            result = agent.run(inputs)
        rlog.log_static(result_kind, agent.last_static_findings)
        rlog.log_agent(agent.agent_id, agent.last_prompt,
                       agent.last_response, result.findings)
        # what the *static analyzer* found (the trusted floor)
        n_static = len(agent.last_static_findings)
        con.step(f"static analyzer DETECTED {n_static} issue(s)"
                 + (f": {_rule_ids(agent.last_static_findings)}" if n_static else ""))
        # what the LLM refinement added on top
        con.step(f"LLM refinement → {len(result.findings)} finding(s) total"
                 f" (LLM added {max(0, len(result.findings) - n_static)})")
        # name every detected finding (so detections are visible)
        for f in result.findings:
            con.detail(f"  detected {f.rule_id} [{f.severity}] {(f.evidence or '')[:70]}")
        con.detail(f"prompt ~{agent.last_prompt_tokens} tok, "
                   f"response {len(agent.last_response)} chars")
        con.blob(f"{agent.agent_id} prompt", agent.last_prompt)
        con.blob(f"{agent.agent_id} response", agent.last_response)
        return result

    code_result = _run_scanner(
        f"source-code scanner ({len(code_paths)} file(s))", 1,
        code_agent, "source_code")
    log_result = _run_scanner("log analyzer", 2, log_agent, "log")
    dep_result = _run_scanner("deployment scanner", 3, dep_agent, "deployment")

    # ---- SecurityGuard (paper 1) — built once; its H_a judge cache and
    #      the decision agent persist across re-planning rounds.
    guard_cfg = cfg.get("guard", {}) or {}
    ha_judge = (HaJudge(llms.get("reasoning") or llms["default"])
                if guard_cfg.get("ha_judge_enabled", True) else None)
    guard = SecurityGuard(
        allowed_objectives=cfg["security"]["allowed_objectives"],
        authenticated_sources=cfg["security"]["authenticated_sources"],
        trusted_destinations=cfg["security"]["trusted_destinations"],
        ha_judge=ha_judge,
    )
    per_step = guard_cfg.get("per_step_enabled", True)

    decision_cfg = dict(cfg["agent_configs"]["decision_agent"],
                        response_tiers=cfg["response_tiers"],
                        recall_k=int((cfg.get("memory", {}) or {}).get("recall_k", 5)))
    decision_agent = DecisionAgent(
        "decision_agent", decision_cfg, llms[decision_cfg["llm"]],
        memory=memory)

    ae_cfg = cfg.get("action_engine", {}) or {}
    # Honour config.action_engine.dry_run, but always force dry-run when the
    # CYBERLLM_FORCE_DRY_RUN env is set (the test suite + verify.py set it so
    # they never execute real OS commands, regardless of config).
    dry_run = bool(ae_cfg.get("dry_run", True))
    if os.environ.get("CYBERLLM_FORCE_DRY_RUN"):
        dry_run = True
    con.kv("action mode", "DRY-RUN (simulated)" if dry_run
           else "LIVE (real tool execution)")
    action_cfg = dict(
        cfg["agent_configs"]["action_generator"],
        dry_run=dry_run,
        work_dir=str(HERE / ae_cfg.get("work_dir", "mcp_workspace")),
        repo_path=str(HERE),
        log_path=str(log_path),
        default_file=(str(code_paths[0]) if code_paths else "unknown.py"),
        max_prompt_tokens=int(guard_cfg.get("max_prompt_tokens", 4096)),
        llm_tool_selection=bool(ae_cfg.get("llm_tool_selection", True)),
    )

    # Callback so the MCP registry can announce every tool it runs (visible
    # at the default verbosity — especially useful now that tools run live).
    def _on_tool(name, params, result):
        salient = next((str(params[k]) for k in
                        ("ipv4", "node_id", "file", "path", "target",
                         "service", "secret_id", "url")
                        if k in params), "")
        mode = "real" if getattr(result, "invoked_real_tool", False) else "sim"
        con.step(f"MCP tool ▶ {name}({salient}) → {result.status} [{mode}]")
    vulnerable_code = ""
    for p in code_paths:
        if p.suffix.lower() == ".py":
            vulnerable_code = p.read_text(encoding="utf-8", errors="replace")
            break
    if not vulnerable_code and code_paths:
        vulnerable_code = code_paths[0].read_text(encoding="utf-8", errors="replace")

    # ===================================================================
    # ADAPTIVE RE-PLANNING LOOP (paper 5).
    # The decision agent proposes a tier; the action engine realises it and
    # *executes*; if the response did not resolve (plan failed / guard
    # refused), the outcome is fed back and the decision agent escalates —
    # closing the detect → decide → act → observe → re-decide loop.
    # ===================================================================
    max_rounds = int(ae_cfg.get("max_replan_rounds", 2))
    feedback: dict | None = None
    replan_history: list[dict] = []
    decision = action = verdict = trajectory = None
    action_agent = None
    final_plan_status, final_success = "completed", True
    con.info(f"[4-6/6] adaptive loop (decision → action → guard, "
             f"max {max_rounds} round(s))")

    for round_idx in range(1, max_rounds + 1):
        # ---- decision (sees prior-round feedback + memory) -------------
        with con.timed(f"round {round_idx} decision"):
            decision = decision_agent.run(
                [code_result, log_result, dep_result],
                scenario_name=scenario_name, feedback=feedback)
        rlog.log_agent("decision_agent", decision_agent.last_prompt,
                       decision_agent.last_response, findings=None)
        rlog.log_decision(decision)
        if round_idx == 1:
            if decision_agent.consulted_memory:
                con.detail("recalled: " + ", ".join(
                    f"{i.scenario}(sim={i.similarity},outcome="
                    f"{'worked' if i.remediation_ok else i.plan_status})"
                    for i in decision_agent.consulted_memory))
            if decision_agent.memory_recommendation:
                con.detail("memory recommends tier="
                           f"{decision_agent.memory_recommendation['tier']} "
                           f"(worked on {decision_agent.memory_recommendation['scenario']})")
        con.kv(f"round {round_idx} decision",
               f"tier={decision.recommended_tier} conf={decision.confidence:.2f}")

        # ---- action engine (per-step guard sees this round's threat) ---
        step_guard = (build_step_guard(guard, inputs, decision.summary)
                      if per_step else None)
        action_agent = ActionGenerator(
            "action_generator", action_cfg, llms[action_cfg["llm"]],
            guard=step_guard, on_tool=_on_tool)
        con.info(f"[round {round_idx}] action engine — executing the response plan…")
        with con.timed(f"round {round_idx} action engine"):
            action = action_agent.generate(decision, vulnerable_code=vulnerable_code)
        if action_agent.last_prompt:
            rlog.log_agent("action_generator", action_agent.last_prompt,
                           action_agent.last_response, findings=None)
        rlog.log_action(action)
        report = action_agent.last_report
        if action_agent.last_plan is not None:
            rlog.log_action_plan(action_agent.last_plan, report)
            for s in action_agent.last_plan.steps:
                con.detail(f"step {s.kind.value:9} {s.tool:26} -> {s.status.value}")
        con.kv(f"round {round_idx} action",
               f"kind={action.kind} plan={report.summary if report else 'n/a'}")

        # ---- final guard + trajectory (rich context for H_a) -----------
        # Derive the objective from the action kind so it matches the
        # guard's action-alignment map (an `alert_only` primary serves a
        # reporting objective, not a "defensive action" one).
        objective = {
            "patch_code": "auto-correct insecure code",
            "alert_only": "produce findings report",
            "noop": "produce findings report",
        }.get(action.kind, "produce defensive action")
        verdict = guard.check(action, objective, inputs, context=decision.summary)
        rlog.log_guard(verdict)
        trajectory = None
        if action_agent.last_plan is not None:
            traj = guard.check_trajectory(action_agent.last_plan.steps, inputs)
            trajectory = asdict(traj)
            for v in traj.violations:
                con.warn(f"trajectory: {v}")

        # ---- did the response resolve? ---------------------------------
        n_steps = len(action_agent.last_plan.steps) if action_agent.last_plan else 0
        final_plan_status = report.status.value if report is not None else "completed"
        plan_ok = final_plan_status in ("completed", "partial_success")
        # Nothing to remediate (no steps) is terminal, not a failure.
        final_success = (n_steps == 0) or (verdict.allowed and plan_ok)
        replan_history.append({
            "round": round_idx,
            "tier": decision.recommended_tier,
            "plan_status": final_plan_status,
            "steps": n_steps,
            "guard_allowed": verdict.allowed,
            "guard_reason": verdict.reason,
            "success": final_success,
        })
        con.kv(f"round {round_idx} result",
               f"plan={final_plan_status} steps={n_steps} "
               f"guard={'PASS' if verdict.allowed else 'REFUSED'}")

        if final_success or round_idx == max_rounds:
            break
        # Escalate: feed the failure back so the decision agent re-plans.
        feedback = {
            "prior_tier": decision.recommended_tier,
            "plan_status": final_plan_status,
            "guard_allowed": verdict.allowed,
            "reason": (verdict.reason if not verdict.allowed
                       else f"plan {final_plan_status}"),
        }
        con.warn(f"round {round_idx} did not resolve "
                 f"({feedback['reason'][:70]}); re-planning…")

    con.kv("decision", f"tier={decision.recommended_tier} "
           f"conf={decision.confidence:.2f}")
    con.kv("guard", f"allowed={verdict.allowed} ({verdict.reason})")
    con.kv("replanning", f"{len(replan_history)} round(s), "
           f"final={'RESOLVED' if final_success else 'UNRESOLVED'}")
    if not verdict.allowed:
        con.warn(f"final action REFUSED: {verdict.reason}")

    # ---- build the DETAILED findings (rule_id/severity/title/location/
    #      line/detail) and print them as the final result ---------------
    detailed_findings = _enrich_findings(decision.findings, rules, code_paths)
    con.section(f"FINDINGS ({len(detailed_findings)})")
    for d in detailed_findings:
        con.info(f"  • {d['rule_id']}  [{d['severity']}]  {d['title']}")
        con.info(f"      location: {d['location']}   line: {d['line']}")
        con.info(f"      detail:   {d['detail']}")
        if d.get("asset_category"):
            con.info(f"      asset:    {d['asset_category']}")

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
        "trajectory_verdict": trajectory,
        "replanning": {
            "rounds": len(replan_history),
            "resolved": final_success,
            "history": replan_history,
        },
        "memory_recommendation": decision_agent.memory_recommendation,
        "findings": detailed_findings,
        "consulted_memory": [
            {"scenario": i.scenario, "similarity": i.similarity,
             "rule_ids": i.rule_ids, "tier": i.tier,
             "guard_allowed": i.guard_allowed,
             "remediation_ok": i.remediation_ok}
            for i in decision_agent.consulted_memory
        ],
        "committed": ({"action": action.kind, "target": action.target,
                       "parameters": action.parameters}
                      if verdict.allowed else None),
    }

    # ---- E.2/E.3: record this outcome (incl. whether it WORKED) --------
    rule_ids = sorted({getattr(f, "rule_id", "?") for f in decision.findings})
    record["memory_recorded"] = _record_incident(
        memory, cfg, mode="defense", scenario=scenario_name,
        rule_ids=rule_ids,
        asset_categories=decision.asset_categories_touched,
        tier=decision.recommended_tier, confidence=decision.confidence,
        action_kind=action.kind, guard_allowed=verdict.allowed,
        plan_status=final_plan_status, remediation_ok=final_success)

    con.kv("memory", f"recorded={record['memory_recorded']} "
           f"(outcome={'worked' if final_success else final_plan_status})")

    mem_dir = HERE / cfg["paths"]["memory_dir"]
    mem_dir.mkdir(parents=True, exist_ok=True)
    fname = "last_run_defense.json" if scenario_name == "default" \
        else f"defense_{scenario_name}.json"
    (mem_dir / fname).write_text(json.dumps(record, indent=2), encoding="utf-8")
    record["run_log_dir"] = _rel_or_abs(rlog.dir)
    rlog.finalize()
    con.kv("record", _rel_or_abs(mem_dir / fname))
    con.kv("run log", record["run_log_dir"])
    con.section(f"DEFENSE · {scenario_name} · DONE "
                f"({len(record['findings'])} findings, "
                f"tier={decision.recommended_tier}, "
                f"guard={'PASS' if verdict.allowed else 'REFUSED'})")
    return record


def _record_incident(memory: MemoryStore | None, cfg: dict, *, mode: str,
                     scenario: str, rule_ids: list[str],
                     asset_categories: list[str], tier: str,
                     confidence: float, action_kind: str,
                     guard_allowed: bool, plan_status: str = "",
                     remediation_ok: bool = False) -> bool:
    """Persist one outcome to the signed store, **including whether the
    remediation worked** (cross-session learning). Never crashes the run —
    a memory failure is logged via the return flag, not an exception."""
    if memory is None:
        return False
    try:
        memory.record(Incident(
            mode=mode, scenario=scenario, rule_ids=rule_ids,
            asset_categories=list(asset_categories or []),
            tier=tier or "", confidence=float(confidence or 0.0),
            action_kind=action_kind or "", guard_allowed=bool(guard_allowed),
            plan_status=plan_status or "", remediation_ok=bool(remediation_ok),
            source=_writer_identity(cfg)))
        return True
    except MemoryAuthError:
        return False


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
    debug: bool = False,
) -> dict:
    con = Console(verbose=verbose, debug=debug)
    con.section(f"ATTACK · {scenario_name}")
    con.kv("code", ", ".join(p.name for p in code_paths) or "(none)")
    con.kv("deployment", Path(deploy_path).name)
    con.kv("scenario", (scenario or "")[:120].replace("\n", " "))

    llms = build_llms(cfg)
    con.info(_llm_banner(llms))
    memory = build_memory(cfg)
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
                    attack_rules_snippet=rules_snippet(rules, "attack_rules"),
                    external_static=bool(cfg.get("scanners", {}).get(
                        "external_static", True)),
                    use_llm=bool(cfg.get("scanners", {}).get("use_llm", True)))
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
    con.detail(f"inputs: {len(inputs)} item(s) — "
               + ", ".join(f"{i.source}[{i.trust_level}]" for i in inputs))

    con.info("[1/5] system info discovery — agent starting (passive recon, no packets sent)")
    with con.timed("system_info_discovery"):
        discovery_result = discovery.run(inputs)
    instance = getattr(discovery_result, "system_instance", None)
    rlog.log_agent("system_info_discovery",
                   discovery.last_prompt, discovery.last_response,
                   findings=None)
    if instance is not None:
        rlog.log_system_instance(instance)
        con.step(f"external={instance.external_actors} "
                 f"safety={instance.safety_actors}")
        con.detail(f"actors={len(instance.actors)} "
                   f"datasources={len(instance.datasources)} "
                   f"edges={len(instance.edges)}")
    con.blob("discovery response", discovery.last_response)

    con.info(f"[2/5] source-code exploiter ({len(code_paths)} file(s)) — agent starting")
    con.step("running deterministic static analyzer (no code is executed)…")
    with con.timed("source_code_exploiter"):
        code_result = code_exploit.run(inputs)
    rlog.log_static("source_code_exploit", code_exploit.last_static_findings)
    rlog.log_agent("source_code_exploiter",
                   code_exploit.last_prompt, code_exploit.last_response,
                   code_result.findings)
    con.step(f"static analyzer DETECTED {len(code_exploit.last_static_findings)} "
             f"exploitable issue(s); {len(code_result.findings)} exploit(s) after "
             f"LLM framing: {_rule_ids(code_result.findings)}")
    con.blob("source_code_exploiter prompt", code_exploit.last_prompt)
    con.blob("source_code_exploiter response", code_exploit.last_response)

    con.info("[3/5] deployment exploiter — agent starting")
    con.step("running deterministic topology/graph analyzer (no system is run)…")
    with con.timed("deployment_exploiter"):
        dep_result = dep_exploit.run(inputs)
    rlog.log_static("deployment_exploit", dep_exploit.last_static_findings)
    rlog.log_agent("deployment_exploiter",
                   dep_exploit.last_prompt, dep_exploit.last_response,
                   dep_result.findings)
    con.step(f"graph analyzer DETECTED {len(dep_result.findings)} attack-path/finding(s): "
             f"{_rule_ids(dep_result.findings)}")
    con.blob("deployment_exploiter response", dep_exploit.last_response)

    con.info("[4/5] attack orchestrator")
    with con.timed("attack_orchestrator"):
        plan = orchestrator.plan([code_result, dep_result], scenario, instance)
    rlog.log_agent("attack_orchestrator",
                   orchestrator.last_prompt, orchestrator.last_response,
                   findings=None)
    rlog.log_plan(plan)
    con.kv("plan target", f"{plan.target_asset} (conf={plan.confidence:.2f})")
    con.kv("chosen", ", ".join(f.rule_id for f in plan.chosen_findings) or "(none)")
    con.detail(f"poison_path={plan.poison_path} trigger_path={plan.trigger_path}")
    con.detail(f"justification: {plan.justification}")
    con.blob("orchestrator response", orchestrator.last_response)

    # ---- Ethics / scope guard --------------------------------------------
    guard = EthicsGuard(
        allowed_scenarios=cfg.get("attack", {}).get("allowed_scenarios", []),
        authorized_targets=cfg.get("attack", {}).get("authorized_targets", []),
        allow_all_in_dev=cfg.get("attack", {}).get("allow_all_in_dev", False),
        cli_authorized_targets=cli_authorized_targets,
    )
    verdict = guard.check_plan(scenario, plan.target_asset)
    rlog.log_ethics(verdict)
    con.info("[5/5] ethics guard + script generation")
    con.kv("ethics", f"allowed={verdict.allowed} ({verdict.reason})")
    con.detail(f"scope_ok={verdict.scope_ok} target_ok={verdict.target_ok} "
               f"non_destructive={verdict.non_destructive}")

    scripts = []
    redacted: list[str] = []
    if verdict.allowed:
        with con.timed("attack_generator"):
            scripts = generator.generate(plan)
        scripts, redacted = guard.filter_scripts(scripts)
        rlog.log_attack_scripts(scripts, redacted)
        con.step(f"generated {len(scripts)} script(s); redacted {len(redacted)}")
        for s in scripts:
            con.detail(f"script {s.rule_id:10} [{s.language}] {s.title}")
    else:
        con.warn(f"ethics REFUSED — no scripts generated ({verdict.reason})")

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

    # ---- E.2/E.3: record the attack outcome into the signed store ------
    record["memory_recorded"] = _record_incident(
        memory, cfg, mode="attack", scenario=scenario_name,
        rule_ids=sorted({f.rule_id for f in plan.chosen_findings}),
        asset_categories=[plan.target_asset] if plan.target_asset else [],
        tier=plan.target_asset, confidence=plan.confidence,
        action_kind=f"{len(scripts)} script(s)", guard_allowed=verdict.allowed)

    con.kv("memory", f"recorded={record['memory_recorded']}")

    mem_dir = HERE / cfg["paths"]["memory_dir"]
    mem_dir.mkdir(parents=True, exist_ok=True)
    fname = "last_run_attack.json" if scenario_name == "default" \
        else f"attack_{scenario_name}.json"
    (mem_dir / fname).write_text(json.dumps(record, indent=2), encoding="utf-8")
    record["run_log_dir"] = _rel_or_abs(rlog.dir)
    rlog.finalize()
    con.kv("record", _rel_or_abs(mem_dir / fname))
    con.kv("run log", record["run_log_dir"])
    con.section(f"ATTACK · {scenario_name} · DONE "
                f"(ethics={'PASS' if verdict.allowed else 'REFUSED'}, "
                f"{len(scripts)} script(s))")
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
    verbose: bool = True,
    debug: bool = False,
) -> int:
    scenarios = _scenarios_for(kind, cfg)
    print(f"==> mode={mode}  example={kind}  ({len(scenarios)} scenario(s))\n")

    defense_rows: list[dict] = []
    attack_rows: list[dict] = []

    for idx, s in enumerate(scenarios, start=1):
        name = s["name"]
        if verbose:
            print(f"\n>>> [{idx}/{len(scenarios)}] scenario '{name}'",
                  file=sys.stderr)
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
                                           cfg, rules, scenario_name=name,
                                           verbose=verbose, debug=debug)
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
                                          cli_authorized_targets=cli_authorized_targets,
                                          verbose=verbose, debug=debug)
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
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Debug logging: timings, token counts, recalled "
                             "memory, per-step status, and truncated previews "
                             "of every prompt and LLM response.")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress per-step progress (only the final "
                             "summary tables / record on stdout).")
    args = parser.parse_args(argv)

    # Verbosity: -q silences progress; -v adds debug detail; default is the
    # mid-level per-step view.
    verbose = not args.quiet
    debug = args.verbose

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
            verbose=verbose,
            debug=debug,
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
                                       scenario_name="default", verbose=verbose,
                                       debug=debug)
        if args.mode == "defense":
            print("\n========== defense run summary ==========")
            print(json.dumps(rec_def, indent=2))

    if args.mode in {"attack", "both"}:
        scenario_text = _read_scenario(args.scenario)
        rec_atk = run_attack_pipeline(code_paths, dep_path, scenario_text,
                                      cfg, rules, scenario_name="default",
                                      verbose=verbose,
                                      cli_authorized_targets=args.authorize_target,
                                      debug=debug)
        print("\n========== attack run summary ==========")
        print(json.dumps(rec_atk, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
