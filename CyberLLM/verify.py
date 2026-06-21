"""verify.py — 30-second smoke check, no pytest required.

Run this right after `pip install -r requirements.txt` to confirm the
project is wired up correctly. Exits 0 on success, non-zero with a
clear message on failure.

What it checks (in order):
  1. Critical imports succeed.
  2. Rules YAML loads and has all expected families.
  3. Static analyzer fires on a known-vulnerable snippet.
  4. Defense pipeline runs end-to-end on `examples/small/02_can_gateway.py`.
  5. Attack pipeline runs end-to-end on the same code + brake scenario.
  6. SecurityGuard and EthicsGuard return verdicts of the expected shape.

If everything green-lights, run `pytest tests/` for the full test suite.
"""

from __future__ import annotations

import os
import sys
import traceback
from pathlib import Path


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# This is an *offline* plumbing smoke test: it checks the pipeline wiring,
# not LLM quality and not real tool execution. Force the deterministic stub
# AND dry-run so it stays fast and side-effect-free, even though config.yaml
# selects gpt-4o and live tools. Unset these yourself to exercise the real
# model / real tools instead.
os.environ.setdefault("CYBERLLM_FORCE_STUB", "1")
os.environ.setdefault("CYBERLLM_FORCE_DRY_RUN", "1")
os.environ.setdefault("CYBERLLM_NO_EXTERNAL_STATIC", "1")


CHECKS = []


def step(title):
    def deco(fn):
        CHECKS.append((title, fn))
        return fn
    return deco


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

@step("import core modules")
def _imports():
    import pipeline                          # noqa: F401
    import run_logger                        # noqa: F401
    import llm_client                        # noqa: F401
    from tools import static_analyzer        # noqa: F401
    from agents import (                      # noqa: F401
        source_code_scanner, log_analyzer, deployment_scanner,
        decision_agent, action_generator, security_guard,
    )
    from agents.attack import (              # noqa: F401
        SourceCodeExploiterAgent, DeploymentExploiterAgent,
        SystemInfoDiscoveryAgent, AttackOrchestratorAgent,
        AttackGeneratorAgent, EthicsGuard,
    )


@step("load rule catalogue")
def _rules():
    from pipeline import load_config, load_rules
    cfg = load_config()
    rules = load_rules(cfg)
    for f in ("code_rules", "log_rules", "topology_rules", "attack_rules"):
        assert f in rules and rules[f], f"missing rule family: {f}"


@step("static analyzer catches CODE-001")
def _static_fires():
    from pipeline import load_config, load_rules
    from tools.static_analyzer import scan_code_static
    rules = load_rules(load_config())
    code = ("import subprocess\n"
            "subprocess.call(user_input, shell=True)\n")
    hits = scan_code_static(code, "x.py", rules)
    assert "CODE-001" in {h.rule_id for h in hits}, \
        f"static analyzer missed CODE-001 (got: {[h.rule_id for h in hits]})"


@step("defense pipeline end-to-end on can_gateway")
def _defense_runs():
    import pipeline as P
    cfg = P.load_config()
    rules = P.load_rules(cfg)
    code = [HERE / "examples" / "small" / "02_can_gateway.py"]
    log = HERE / "examples" / "logs" / "03_can_injection.log"
    dep = HERE / "examples" / "deployments" / "03_complex_sdv.yaml"
    rec = P.run_defense_pipeline(code, log, dep, cfg, rules,
                                  scenario_name="verify_defense",
                                  verbose=False)
    rule_ids = {f["rule_id"] for f in rec["findings"]}
    for must in {"CODE-005", "CODE-006", "TOP-001", "TOP-002", "LOG-CAN-02"}:
        assert must in rule_ids, f"defense missed {must}"
    assert rec["guard_verdict"]["allowed"] is True


@step("attack pipeline end-to-end on brake-tampering scenario")
def _attack_runs():
    import pipeline as P
    cfg = P.load_config()
    rules = P.load_rules(cfg)
    code = [HERE / "examples" / "small" / "02_can_gateway.py"]
    dep = HERE / "examples" / "deployments" / "03_complex_sdv.yaml"
    scenario = (HERE / "examples" / "attack_scenarios"
                / "02_brake_tampering.txt").read_text(encoding="utf-8")
    rec = P.run_attack_pipeline(code, dep, scenario, cfg, rules,
                                 scenario_name="verify_attack",
                                 verbose=False)
    assert rec["ethics_verdict"]["allowed"] is True
    assert rec["scripts"], "ethics passed but no scripts emitted"


@step("guards return well-formed verdicts")
def _guards():
    from agents.action_generator import Action
    from agents.attack.ethics_guard import EthicsGuard
    from agents.base_agent import Input
    from agents.decision_agent import Decision
    from agents.security_guard import SecurityGuard

    g = SecurityGuard(
        allowed_objectives=["produce defensive action"],
        authenticated_sources=["user"],
        trusted_destinations=["audit_log"],
    )
    decision = Decision(summary="", asset_categories_touched=[],
                        recommended_tier="moderate", confidence=0.7,
                        justification="", findings=[])
    v = g.check(
        Action(kind="block_ip", target="x", parameters={}, rationale="",
               originating_decision=decision),
        "produce defensive action",
        [Input("hi", "user", "authenticated")],
    )
    assert v.allowed

    eg = EthicsGuard([], [], allow_all_in_dev=True)
    ev = eg.check_plan("anything", "Anything")
    assert ev.allowed


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

GREEN, RED, RESET = "\033[32m", "\033[31m", "\033[0m"


def main() -> int:
    width = max(len(t) for t, _ in CHECKS) + 4
    failed = 0
    for title, fn in CHECKS:
        try:
            fn()
            print(f"  {title.ljust(width)} {GREEN}OK{RESET}")
        except Exception as exc:        # noqa: BLE001
            print(f"  {title.ljust(width)} {RED}FAIL — {exc}{RESET}")
            traceback.print_exc()
            failed += 1
    print()
    if failed:
        print(f"{RED}{failed} of {len(CHECKS)} checks failed.{RESET}")
        return 1
    print(f"{GREEN}all {len(CHECKS)} checks passed — "
          f"run `pytest tests/` for the full suite.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
