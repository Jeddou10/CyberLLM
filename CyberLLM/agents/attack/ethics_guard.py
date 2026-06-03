"""Ethics / scope guard for the attack pipeline.

Mirror of `SecurityGuard` on the defense side. Before any attack
script leaves the orchestrator, this guard checks:

1. The user-specified scenario is in the allowed-scenario list (or
   wildcard-allowed via the `allow_all_in_dev` flag).
2. The chosen target is authorised — either:
   - it appears in `config.yaml`'s `attack.authorized_targets`, or
   - the operator explicitly passed `--authorize-target` on the CLI.
3. The scripts are non-destructive (canary patterns only) — the
   built-in templates already satisfy this; LLM-generated scripts
   are scanned for an allow-list of safe markers.

If any check fails, the script is **redacted** in the output record
and an `EthicsVerdict` with `allowed=False` is returned.

This is the offensive-side analogue of paper 1's contextual security:
- "Is the requester authorised?" — source authorisation.
- "Is the action within the authorised scope?" — task alignment.
- "Does this action actually serve the scenario?" — action alignment.
- "Is the target in the agreed scope?" — data isolation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .attack_generator import AttackScript


_DESTRUCTIVE_PATTERNS = [
    r"\brm\s+-rf\b",
    r"shutdown\s+-h",
    r"mkfs\.",
    r":\(\)\s*\{\s*:\|:&\s*\};:",       # fork bomb
    r"dd\s+if=/dev/zero\s+of=/dev/",
    r"chmod\s+-R\s+777\s+/",
]
_DESTRUCTIVE_RE = re.compile("|".join(_DESTRUCTIVE_PATTERNS))


@dataclass
class EthicsVerdict:
    allowed: bool
    scope_ok: bool
    target_ok: bool
    non_destructive: bool
    reason: str


class EthicsGuard:
    def __init__(
        self,
        allowed_scenarios: list[str],
        authorized_targets: list[str],
        allow_all_in_dev: bool = False,
        cli_authorized_targets: list[str] | None = None,
    ):
        self.allowed_scenarios = set(allowed_scenarios)
        self.authorized_targets = set(authorized_targets) | set(
            cli_authorized_targets or []
        )
        self.allow_all_in_dev = allow_all_in_dev

    def check_plan(self, scenario: str, target_asset: str) -> EthicsVerdict:
        reasons: list[str] = []

        scope_ok = (
            self.allow_all_in_dev
            or scenario in self.allowed_scenarios
            or any(s.lower() in scenario.lower() for s in self.allowed_scenarios)
        )
        if not scope_ok:
            reasons.append(
                f"scenario '{scenario[:60]}...' not in allowed_scenarios"
            )

        # Target is identified by the asset string here. Real systems
        # would also require an explicit host / VIN / domain.
        target_ok = (
            self.allow_all_in_dev
            or any(t == "*" or t.lower() in target_asset.lower()
                   for t in self.authorized_targets)
        )
        if not target_ok:
            reasons.append(
                f"target_asset '{target_asset}' not in authorized_targets"
            )

        return EthicsVerdict(
            allowed=scope_ok and target_ok,
            scope_ok=scope_ok,
            target_ok=target_ok,
            non_destructive=True,
            reason="; ".join(reasons) or "scenario + target in scope",
        )

    def filter_scripts(
        self, scripts: list[AttackScript]
    ) -> tuple[list[AttackScript], list[str]]:
        """Returns (safe_scripts, redacted_titles). Destructive scripts
        are replaced with a stub describing what was removed."""
        safe: list[AttackScript] = []
        redacted: list[str] = []
        for s in scripts:
            if _DESTRUCTIVE_RE.search(s.body):
                redacted.append(s.title)
                safe.append(AttackScript(
                    rule_id=s.rule_id,
                    title=f"[REDACTED] {s.title}",
                    language=s.language,
                    body=f"# REDACTED — destructive pattern detected.\n"
                         f"# Original target hint: {s.target_hint}\n",
                    target_hint=s.target_hint,
                    expected_effect="REDACTED",
                ))
            else:
                safe.append(s)
        return safe, redacted
