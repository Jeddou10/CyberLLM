"""Security guard — runtime enforcement of paper 1's four properties.

This is a lightweight, auditable implementation: it doesn't claim to
solve instruction attribution (`I`) or trajectory judgment (`H_Tr`) in
general, but it *names* every check so future research can replace
each approximation independently.

The four checks (paper 1):
1. Task alignment       — objective lies in the allowed set.
2. Action alignment     — the action's kind is consistent with the objective.
3. Source authorization — every input that fed the action came from an
                          authenticated source.
4. Data isolation       — the action only writes to trusted destinations.
"""

from __future__ import annotations
from dataclasses import dataclass

from .action_generator import Action
from .base_agent import Input


@dataclass
class GuardVerdict:
    allowed: bool
    task_alignment: bool
    action_alignment: bool
    source_authorization: bool
    data_isolation: bool
    reason: str


# Coarse map from action kind to compatible objectives. Keep this
# explicit so the supervisor can audit it.
_ACTION_OBJECTIVES = {
    "rate_limit":   {"produce defensive action"},
    "block_ip":     {"produce defensive action"},
    "isolate_node": {"produce defensive action"},
    "patch_code":   {"auto-correct insecure code"},
    "alert_only":   {"produce findings report"},
    "noop":         {"produce findings report"},
}


class SecurityGuard:
    def __init__(self, allowed_objectives: list[str],
                 authenticated_sources: list[str],
                 trusted_destinations: list[str]):
        self.allowed_objectives = set(allowed_objectives)
        self.authenticated_sources = set(authenticated_sources)
        self.trusted_destinations = set(trusted_destinations)

    def check(self, action: Action, objective: str,
              inputs: list[Input]) -> GuardVerdict:
        reasons: list[str] = []

        # 1. Task alignment
        task_ok = objective in self.allowed_objectives
        if not task_ok:
            reasons.append(f"objective '{objective}' is not in allowed set O")

        # 2. Action alignment
        compatible = _ACTION_OBJECTIVES.get(action.kind, set())
        action_ok = bool(compatible & {objective})
        if not action_ok:
            reasons.append(
                f"action '{action.kind}' incompatible with objective "
                f"'{objective}' (expected one of {sorted(compatible) or '∅'})"
            )

        # 3. Source authorization — every input that "instructed" the
        #    pipeline must come from an authenticated source.
        unauth = [i for i in inputs
                  if i.trust_level not in {"authenticated", "tool", "memory"}]
        # External inputs are allowed as *data*, but they must not have
        # caused a privileged action. A patch_code or isolate_node
        # action is privileged; if its rationale was driven only by
        # external inputs, that's a source-auth violation.
        privileged = action.kind in {"patch_code", "isolate_node", "block_ip"}
        source_ok = not (privileged and unauth and not any(
            i.trust_level == "authenticated" for i in inputs))
        if not source_ok:
            reasons.append(
                "privileged action requested but no authenticated source "
                "is among the inputs (source authorization violation)"
            )

        # 4. Data isolation — declare the destination explicitly.
        destination = action.target if action.target in self.trusted_destinations \
            else action.parameters.get("destination", "internal")
        isolation_ok = destination in self.trusted_destinations \
            or destination in {"internal", "suspect_source_ip",
                               "affected_ECU", "vulnerable_file",
                               "security_team"}
        if not isolation_ok:
            reasons.append(
                f"destination '{destination}' is not in the trusted set"
            )

        allowed = task_ok and action_ok and source_ok and isolation_ok
        return GuardVerdict(
            allowed=allowed,
            task_alignment=task_ok,
            action_alignment=action_ok,
            source_authorization=source_ok,
            data_isolation=isolation_ok,
            reason="; ".join(reasons) or "all four properties satisfied",
        )
