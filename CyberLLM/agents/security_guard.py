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
from dataclasses import dataclass, field

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


@dataclass
class TrajectoryVerdict:
    """Result of evaluating a *sequence* of actions (paper 1 §7).

    Paper 1 is explicit that contextual security is *compositional and
    temporal*: each individual step can satisfy the four properties yet
    the combination — or the order — can still violate security. This
    verdict captures those two trajectory-level oracles separately so
    each can be improved independently.
    """
    allowed: bool
    compositional_ok: bool        # F.3 — does the *combination* stay safe?
    temporal_ok: bool             # F.4 — does the *ordering* avoid TOCTOU / poison?
    violations: list[str] = field(default_factory=list)


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
                 trusted_destinations: list[str],
                 ha_judge=None):
        self.allowed_objectives = set(allowed_objectives)
        self.authenticated_sources = set(authenticated_sources)
        self.trusted_destinations = set(trusted_destinations)
        # Optional paper-1 H_a oracle (roadmap F.1). When present it can
        # only *tighten* the action-alignment check — never loosen the
        # deterministic floor below.
        self.ha_judge = ha_judge

    def check(self, action: Action, objective: str,
              inputs: list[Input], context: str = "") -> GuardVerdict:
        reasons: list[str] = []

        # 1. Task alignment
        task_ok = objective in self.allowed_objectives
        if not task_ok:
            reasons.append(f"objective '{objective}' is not in allowed set O")

        # 2. Action alignment — coarse static map is the floor; the H_a
        #    judge (if configured) can only make it stricter.
        compatible = _ACTION_OBJECTIVES.get(action.kind, set())
        static_action_ok = bool(compatible & {objective})
        action_ok = static_action_ok
        if not static_action_ok:
            reasons.append(
                f"action '{action.kind}' incompatible with objective "
                f"'{objective}' (expected one of {sorted(compatible) or '∅'})"
            )
        elif self.ha_judge is not None:
            ctx = context or (
                f"target={action.target}; "
                f"destination={action.parameters.get('destination', 'internal')}")
            serves, ha_reason = self.ha_judge.judges(
                action.kind, objective, context=ctx)
            if not serves:
                action_ok = False
                reasons.append(f"H_a judge refused: {ha_reason}")

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

    # ------------------------------------------------------------------
    # Trajectory-level checks (paper 1 §7; roadmap F.3 + F.4)
    # ------------------------------------------------------------------

    def check_trajectory(self, steps: list, inputs: list[Input] | None = None
                         ) -> TrajectoryVerdict:
        """Evaluate a *sequence* of action steps for compositional (F.3)
        and temporal (F.4) violations that the per-step check cannot see.

        `steps` is duck-typed: each item needs `.tool` (str),
        `.kind` (enum with `.value`), `.side_effect` (enum with `.value`),
        `.pre` and `.post` (lists). This matches `action_engine.ActionStep`
        but avoids a hard import so the guard stays a leaf module.
        """
        inputs = inputs or []
        violations: list[str] = []

        def _val(x) -> str:
            return getattr(x, "value", str(x))

        tools = [getattr(s, "tool", "") for s in steps]
        side_effects = [_val(getattr(s, "side_effect", "read")) for s in steps]
        kinds = [_val(getattr(s, "kind", "")) for s in steps]
        destructive_idx = [i for i, se in enumerate(side_effects)
                           if se == "destructive"]

        # ---- F.3 compositional --------------------------------------------
        # (a) Exfil composition: reading sensitive material and then sending
        #     it outbound, even though each step is individually allowed.
        reads_sensitive = any(
            t in {"kb.lookup_cve", "secrets.rotate", "secrets.revoke",
                  "observe.log_tail"} for t in tools)
        external_egress = any(
            t in {"notify.webhook", "notify.email"} for t in tools)
        if reads_sensitive and external_egress:
            read_pos = min(i for i, t in enumerate(tools)
                           if t in {"kb.lookup_cve", "secrets.rotate",
                                    "secrets.revoke", "observe.log_tail"})
            egress_pos = max(i for i, t in enumerate(tools)
                             if t in {"notify.webhook", "notify.email"})
            if read_pos < egress_pos:
                violations.append(
                    "compositional: sensitive read precedes an external "
                    "egress step (possible exfil chain)")

        # (b) Destructive without a forensic snapshot/observe step.
        has_forensics = any(t in {"runtime.snapshot"} for t in tools) or \
            any(k == "observe" for k in kinds)
        if destructive_idx and not has_forensics:
            violations.append(
                "compositional: destructive step(s) with no forensic "
                "snapshot/observe step in the plan")

        # (c) Destructive action with nobody notified (governance gap).
        has_notify = any(k == "notify" for k in kinds)
        if destructive_idx and not has_notify:
            violations.append(
                "compositional: destructive step(s) without any notify step "
                "(state change with no human in the loop)")

        compositional_ok = not violations

        # ---- F.4 temporal -------------------------------------------------
        temporal: list[str] = []
        # (a) TOCTOU: a contain/eradicate step that checks a precondition
        #     but never re-verifies afterwards — the world can change
        #     between check and act.
        for s in steps:
            k = _val(getattr(s, "kind", ""))
            pre = getattr(s, "pre", []) or []
            post = getattr(s, "post", []) or []
            if k in {"contain", "eradicate"} and pre and not post:
                temporal.append(
                    f"temporal: step '{getattr(s, 'tool', '?')}' checks a "
                    f"precondition but never re-verifies (TOCTOU risk)")

        # (b) Memory-poisoning: a privileged/destructive action whose plan
        #     was influenced by a *memory*-sourced input (paper 1/2).
        memory_inputs = [i for i in inputs
                         if getattr(i, "trust_level", "") == "memory"]
        if memory_inputs and destructive_idx:
            temporal.append(
                "temporal: destructive action in a plan influenced by a "
                "memory-sourced input (memory-poisoning TOCTOU risk)")

        temporal_ok = not temporal
        violations.extend(temporal)

        return TrajectoryVerdict(
            allowed=compositional_ok and temporal_ok,
            compositional_ok=compositional_ok,
            temporal_ok=temporal_ok,
            violations=violations,
        )
