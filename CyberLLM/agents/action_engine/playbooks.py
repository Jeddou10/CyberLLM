"""Playbook catalogue + deterministic plan builder.

Why a catalogue
---------------
A response should match the *kind* of finding, not just its severity
tier. A SQL-injection finding wants a code patch and a credential
rotation; a CAN-injection log wants safe-mode + ECU isolation +
driver notification; a topology violation wants a block-deployment +
notify-architect. Hard-coding "soft → rate_limit, hard → isolate" is
fine for a demo but isn't auditable.

Playbooks are typed (per rule-id) sequences of MCP-tool steps with
pre/post conditions. The plan builder:

  1. Sorts findings by severity (critical first).
  2. Looks up a specific playbook per rule-id, falling back to a
     family-generic playbook (code / log / topology) and finally to a
     tier-generic playbook (soft / moderate / hard).
  3. Instantiates each step template with concrete params filled from
     the finding (file, line, source IP, …).
  4. Topologically orders steps by `StepKind` so containment runs
     before eradication, eradication before recovery, etc.
  5. Deduplicates equivalent steps across findings.

The result is an `ActionPlan` ready for the executor.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable
from uuid import uuid4

from .types import (
    ActionPlan,
    ActionStep,
    Condition,
    SideEffect,
    StepKind,
    kind_priority,
    severity_rank,
)


# ---------------------------------------------------------------------------
# Step template
# ---------------------------------------------------------------------------

@dataclass
class StepTemplate:
    kind: StepKind
    tool: str
    description: str
    params_fn: Callable[[Any, dict], dict]    # (finding, decision_ctx) -> params
    pre: list[Condition] = field(default_factory=list)
    post: list[Condition] = field(default_factory=list)
    severity_min: str = "low"
    side_effect: SideEffect = SideEffect.READ
    retries: int = 1
    timeout_s: int = 30
    requires_authorization: bool = False
    rollback_template: "StepTemplate | None" = None

    def instantiate(self, finding, decision_ctx, rule_id) -> ActionStep:
        rollback = ([self.rollback_template.instantiate(finding, decision_ctx,
                                                          rule_id)]
                     if self.rollback_template else [])
        return ActionStep(
            rule_id=rule_id,
            kind=self.kind,
            tool=self.tool,
            params=self.params_fn(finding, decision_ctx),
            description=self.description.format(rule_id=rule_id),
            side_effect=self.side_effect,
            severity_min=self.severity_min,
            timeout_s=self.timeout_s,
            retries=self.retries,
            requires_authorization=self.requires_authorization,
            pre=list(self.pre),
            post=list(self.post),
            rollback_steps=rollback,
        )


@dataclass
class Playbook:
    rule_id_pattern: str             # exact id or regex
    title: str
    blast_radius: str
    steps: list[StepTemplate]


# ---------------------------------------------------------------------------
# Helpers used by params_fn closures
# ---------------------------------------------------------------------------

def _suspect_ip(finding, ctx) -> str:
    # Try to pull an IPv4 out of the finding evidence first.
    m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b",
                  (finding.evidence or "") + " " + (finding.explanation or ""))
    if m:
        return m.group(1)
    # Then from ctx (e.g. recent log line).
    m2 = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", ctx.get("hint", ""))
    return m2.group(1) if m2 else "0.0.0.0"


def _affected_file(finding, ctx) -> str:
    ev = finding.evidence or ""
    # Static-analyzer evidence prefix is "<filename>: …"
    m = re.match(r"^([^:\s]+):", ev)
    if m:
        return m.group(1)
    return ctx.get("default_file", "unknown.py")


def _vehicle_id(finding, ctx) -> str:
    return ctx.get("vehicle_id", "TESTBENCH-01")


def _ecu_id(finding, ctx) -> str:
    ev = (finding.evidence or "").lower()
    if "bodyctrl" in ev:
        return "BodyCtrl"
    if "gatewayecu" in ev:
        return "GatewayECU"
    return "rogue-ECU"


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------

PLAYBOOKS: list[Playbook] = []


def _book(*args, **kwargs):
    pb = Playbook(*args, **kwargs)
    PLAYBOOKS.append(pb)
    return pb


# ----- LOG-* playbooks ------------------------------------------------------

_book(
    rule_id_pattern="LOG-AUTH-03",
    title="Brute-force on privileged account",
    blast_radius="service",
    steps=[
        StepTemplate(
            kind=StepKind.CONTAIN,
            tool="firewall.rate_limit",
            description="rate-limit the suspect source IP",
            params_fn=lambda f, ctx: {"ipv4": _suspect_ip(f, ctx),
                                        "rate_per_minute": 6,
                                        "duration_minutes": 30},
            side_effect=SideEffect.WRITE,
            requires_authorization=True,
            severity_min="medium",
        ),
        StepTemplate(
            kind=StepKind.OBSERVE,
            tool="observe.log_tail",
            description="watch the auth log for 5 s after the rate-limit",
            params_fn=lambda f, ctx: {"path": ctx.get("log_path", ""),
                                        "pattern": "Failed password",
                                        "timeout_s": 5},
        ),
        StepTemplate(
            kind=StepKind.CONTAIN,
            tool="firewall.block_ipv4",
            description="block the source IP if attempts continue",
            params_fn=lambda f, ctx: {"ipv4": _suspect_ip(f, ctx),
                                        "duration_minutes": 60,
                                        "reason": "LOG-AUTH-03"},
            side_effect=SideEffect.WRITE,
            requires_authorization=True,
        ),
        StepTemplate(
            kind=StepKind.NOTIFY,
            tool="notify.create_incident",
            description="open a security-team incident",
            params_fn=lambda f, ctx: {
                "severity": "high",
                "summary": "Brute-force pattern detected",
                "rule_id": f.rule_id,
                "evidence": (f.evidence or "")[:200],
            },
            side_effect=SideEffect.WRITE,
        ),
    ],
)

_book(
    rule_id_pattern="LOG-CAN-02",
    title="CAN injection from non-gateway ECU",
    blast_radius="node",
    steps=[
        StepTemplate(
            kind=StepKind.CONTAIN,
            tool="runtime.safe_mode",
            description="switch the affected vehicle into safe mode",
            params_fn=lambda f, ctx: {"target": _vehicle_id(f, ctx)},
            side_effect=SideEffect.DESTRUCTIVE,
            requires_authorization=True,
            severity_min="high",
        ),
        StepTemplate(
            kind=StepKind.CONTAIN,
            tool="network.isolate_node",
            description="isolate the offending ECU on the CAN bus",
            params_fn=lambda f, ctx: {"node_id": _ecu_id(f, ctx),
                                        "quarantine_vlan": 99},
            side_effect=SideEffect.DESTRUCTIVE,
            requires_authorization=True,
        ),
        StepTemplate(
            kind=StepKind.NOTIFY,
            tool="notify.driver",
            description="notify the driver",
            params_fn=lambda f, ctx: {
                "vehicle": _vehicle_id(f, ctx),
                "message": ("Safety-critical bus anomaly detected. "
                             "Vehicle is in limited mode — please pull "
                             "over safely."),
                "urgency": "critical",
            },
            side_effect=SideEffect.WRITE,
        ),
        StepTemplate(
            kind=StepKind.AUDIT,
            tool="runtime.snapshot",
            description="snapshot the workspace for forensic analysis",
            params_fn=lambda f, ctx: {"source_path": ctx.get("workspace_path",
                                                                "./"),
                                        "label": "can_injection"},
            side_effect=SideEffect.WRITE,
        ),
    ],
)

_book(
    rule_id_pattern=r"LOG-EXFIL-0[12]",
    title="Data exfiltration",
    blast_radius="network",
    steps=[
        StepTemplate(
            kind=StepKind.CONTAIN,
            tool="firewall.block_ipv4",
            description="block the exfiltration peer",
            params_fn=lambda f, ctx: {"ipv4": _suspect_ip(f, ctx),
                                        "duration_minutes": 240,
                                        "reason": "data exfiltration"},
            side_effect=SideEffect.WRITE,
            requires_authorization=True,
            severity_min="high",
        ),
        StepTemplate(
            kind=StepKind.ERADICATE,
            tool="secrets.rotate",
            description="rotate the credentials likely to have been exposed",
            params_fn=lambda f, ctx: {"secret_id": ctx.get("at_risk_secret",
                                                              "primary-api-token"),
                                        "length": 32},
            side_effect=SideEffect.DESTRUCTIVE,
            requires_authorization=True,
        ),
        StepTemplate(
            kind=StepKind.NOTIFY,
            tool="notify.create_incident",
            description="open a high-severity incident",
            params_fn=lambda f, ctx: {
                "severity": "critical",
                "summary": "Likely data exfiltration",
                "rule_id": f.rule_id,
                "evidence": (f.evidence or "")[:200],
            },
            side_effect=SideEffect.WRITE,
        ),
    ],
)

_book(
    rule_id_pattern="LOG-DDOS-01",
    title="Distributed SYN flood",
    blast_radius="service",
    steps=[
        StepTemplate(
            kind=StepKind.CONTAIN,
            tool="firewall.rate_limit",
            description="aggressive rate-limit on the front door",
            params_fn=lambda f, ctx: {"ipv4": "0.0.0.0",
                                        "rate_per_minute": 600,
                                        "duration_minutes": 30},
            side_effect=SideEffect.WRITE,
            requires_authorization=True,
        ),
        StepTemplate(
            kind=StepKind.NOTIFY,
            tool="notify.create_incident",
            description="open an incident for the ops on-call",
            params_fn=lambda f, ctx: {
                "severity": "high",
                "summary": "DDoS pattern: distributed SYN flood",
                "rule_id": f.rule_id,
            },
        ),
    ],
)

_book(
    rule_id_pattern="LOG-PRIV-01",
    title="Privileged read of sensitive files",
    blast_radius="node",
    steps=[
        StepTemplate(
            kind=StepKind.CONTAIN,
            tool="secrets.rotate",
            description="rotate the sudoer's credentials immediately",
            params_fn=lambda f, ctx: {"secret_id": "ops-sudo-token"},
            side_effect=SideEffect.DESTRUCTIVE,
            requires_authorization=True,
        ),
        StepTemplate(
            kind=StepKind.NOTIFY,
            tool="notify.create_incident",
            description="open a critical incident",
            params_fn=lambda f, ctx: {
                "severity": "critical",
                "summary": "Privileged read of /etc/shadow or equivalent",
                "rule_id": f.rule_id,
            },
        ),
    ],
)

# ----- CODE-* playbooks -----------------------------------------------------

_book(
    rule_id_pattern="CODE-003",
    title="Hard-coded secret in source",
    blast_radius="service",
    steps=[
        StepTemplate(
            kind=StepKind.ERADICATE,
            tool="secrets.rotate",
            description="rotate the secret in the secret store",
            params_fn=lambda f, ctx: {"secret_id":
                                        ctx.get("at_risk_secret",
                                                  "hardcoded-secret")},
            side_effect=SideEffect.DESTRUCTIVE,
            requires_authorization=True,
        ),
        StepTemplate(
            kind=StepKind.ERADICATE,
            tool="code.propose_patch",
            description="propose a patch that reads the secret from env",
            params_fn=lambda f, ctx: {
                "rule_id": f.rule_id,
                "file": _affected_file(f, ctx),
                "diff": _patch_for_hardcoded_secret(_affected_file(f, ctx)),
                "rationale": "Move secret to env var or secret manager.",
            },
            side_effect=SideEffect.WRITE,
        ),
        StepTemplate(
            kind=StepKind.AUDIT,
            tool="code.scrub_git_history",
            description="generate a runbook to scrub the secret from git history",
            params_fn=lambda f, ctx: {
                "repo_path": ctx.get("repo_path", "."),
                "pattern": _secret_token_excerpt(f),
            },
            side_effect=SideEffect.DESTRUCTIVE,
            requires_authorization=True,
        ),
        StepTemplate(
            kind=StepKind.NOTIFY,
            tool="notify.create_incident",
            description="record the hard-coded-secret incident",
            params_fn=lambda f, ctx: {
                "severity": "critical",
                "summary": "Hard-coded secret in source",
                "rule_id": f.rule_id,
                "evidence": (f.evidence or "")[:200],
            },
        ),
    ],
)

_book(
    rule_id_pattern=r"CODE-(001|005|012|020|038)",
    title="High-impact code vulnerability (RCE / injection / unsafe deserialise / JWT-none)",
    blast_radius="service",
    steps=[
        StepTemplate(
            kind=StepKind.OBSERVE,
            tool="code.static_scan",
            description="run a real second-opinion static scanner",
            params_fn=lambda f, ctx: {"path": _affected_file(f, ctx),
                                        "analyser": "auto"},
        ),
        StepTemplate(
            kind=StepKind.ERADICATE,
            tool="code.propose_patch",
            description="propose a safe-by-construction patch",
            params_fn=lambda f, ctx: {
                "rule_id": f.rule_id,
                "file": _affected_file(f, ctx),
                "diff": _patch_for_code_finding(f),
                "rationale": ("Replace the dangerous construct with the "
                                "safe equivalent recommended in the rule."),
            },
            side_effect=SideEffect.WRITE,
        ),
        StepTemplate(
            kind=StepKind.NOTIFY,
            tool="notify.create_incident",
            description="open a code-vulnerability incident",
            params_fn=lambda f, ctx: {
                "severity": f.severity or "high",
                "summary": f"{f.rule_id}: {f.explanation[:80]}",
                "rule_id": f.rule_id,
                "evidence": (f.evidence or "")[:200],
            },
        ),
    ],
)

# ----- TOP-* playbooks ------------------------------------------------------

_book(
    rule_id_pattern="TOP-006",
    title="Secrets store world-readable",
    blast_radius="network",
    steps=[
        StepTemplate(
            kind=StepKind.CONTAIN,
            tool="notify.create_incident",
            description="open a critical incident on the secrets store",
            params_fn=lambda f, ctx: {
                "severity": "critical",
                "summary": "Secrets store is world-readable",
                "rule_id": f.rule_id,
            },
        ),
        StepTemplate(
            kind=StepKind.ERADICATE,
            tool="secrets.rotate",
            description="rotate every secret that lived in that store",
            params_fn=lambda f, ctx: {"secret_id":
                                        ctx.get("at_risk_secret",
                                                  "store-master")},
            side_effect=SideEffect.DESTRUCTIVE,
            requires_authorization=True,
        ),
    ],
)

_book(
    rule_id_pattern=r"TOP-00[12578]",
    title="Architectural / topology violation",
    blast_radius="service",
    steps=[
        StepTemplate(
            kind=StepKind.NOTIFY,
            tool="notify.create_incident",
            description="raise an architecture-review ticket",
            params_fn=lambda f, ctx: {
                "severity": f.severity or "high",
                "summary": f"{f.rule_id}: {f.explanation[:80]}",
                "rule_id": f.rule_id,
            },
        ),
    ],
)

# ----- Generic family fallbacks --------------------------------------------

_GENERIC_CODE = Playbook(
    rule_id_pattern=r"CODE-.+",
    title="Generic code-side finding",
    blast_radius="service",
    steps=[
        StepTemplate(
            kind=StepKind.ERADICATE,
            tool="code.propose_patch",
            description="propose a remediation patch",
            params_fn=lambda f, ctx: {
                "rule_id": f.rule_id,
                "file": _affected_file(f, ctx),
                "diff": _patch_for_code_finding(f),
                "rationale": "Auto-generated remediation proposal.",
            },
            side_effect=SideEffect.WRITE,
        ),
        StepTemplate(
            kind=StepKind.NOTIFY,
            tool="notify.create_incident",
            description="open a generic code-vuln incident",
            params_fn=lambda f, ctx: {
                "severity": f.severity or "medium",
                "summary": f"{f.rule_id}: {f.explanation[:80]}",
                "rule_id": f.rule_id,
            },
        ),
    ],
)

_GENERIC_LOG = Playbook(
    rule_id_pattern=r"LOG-.+",
    title="Generic log-side finding",
    blast_radius="service",
    steps=[
        StepTemplate(
            kind=StepKind.NOTIFY,
            tool="notify.create_incident",
            description="open a log-anomaly incident",
            params_fn=lambda f, ctx: {
                "severity": f.severity or "medium",
                "summary": f"{f.rule_id}: log anomaly",
                "rule_id": f.rule_id,
                "evidence": (f.evidence or "")[:200],
            },
        ),
    ],
)

_GENERIC_TOP = Playbook(
    rule_id_pattern=r"TOP-.+",
    title="Generic topology finding",
    blast_radius="service",
    steps=[
        StepTemplate(
            kind=StepKind.NOTIFY,
            tool="notify.create_incident",
            description="open a topology-violation ticket",
            params_fn=lambda f, ctx: {
                "severity": f.severity or "high",
                "summary": f"{f.rule_id}: topology rule violated",
                "rule_id": f.rule_id,
            },
        ),
    ],
)


_TIER_PLAYBOOKS = {
    "soft": Playbook(
        rule_id_pattern="*",
        title="Soft response",
        blast_radius="local",
        steps=[
            StepTemplate(
                kind=StepKind.CONTAIN,
                tool="firewall.rate_limit",
                description="rate-limit suspect traffic",
                params_fn=lambda f, ctx: {"ipv4": _suspect_ip(f, ctx),
                                            "rate_per_minute": 60,
                                            "duration_minutes": 15},
                side_effect=SideEffect.WRITE,
                requires_authorization=True,
            ),
        ],
    ),
    "moderate": Playbook(
        rule_id_pattern="*",
        title="Moderate response",
        blast_radius="service",
        steps=[
            StepTemplate(
                kind=StepKind.CONTAIN,
                tool="firewall.block_ipv4",
                description="block suspect source IP",
                params_fn=lambda f, ctx: {"ipv4": _suspect_ip(f, ctx),
                                            "duration_minutes": 60},
                side_effect=SideEffect.WRITE,
                requires_authorization=True,
            ),
        ],
    ),
    "hard": Playbook(
        rule_id_pattern="*",
        title="Hard response",
        blast_radius="node",
        steps=[
            StepTemplate(
                kind=StepKind.CONTAIN,
                tool="network.isolate_node",
                description="isolate the affected node",
                params_fn=lambda f, ctx: {"node_id": ctx.get("target_node",
                                                                "affected-node"),
                                            "quarantine_vlan": 99},
                side_effect=SideEffect.DESTRUCTIVE,
                requires_authorization=True,
            ),
        ],
    ),
}


# ---------------------------------------------------------------------------
# Patch synthesis helpers
# ---------------------------------------------------------------------------

_PATCH_HINTS = {
    "CODE-001": ("replace `subprocess.call(x, shell=True)` with\n"
                 "    `subprocess.run(shlex.split(x), check=True)`\n"
                 "    and validate `x` against an allow-list."),
    "CODE-002": "replace `hashlib.md5(p)` with `argon2.PasswordHasher().hash(p)`.",
    "CODE-005": "replace `pickle.loads(b)` with `json.loads(b)` after schema validation.",
    "CODE-006": "remove `verify=False`; provide a CA bundle via `verify='/path/to/ca.pem'`.",
    "CODE-012": ("convert f-string SQL to parameterised query:\n"
                 "    cur.execute('SELECT … WHERE u = ?', (u,))"),
    "CODE-020": ("restrict JWT decode algorithms: "
                 "`jwt.decode(t, k, algorithms=['HS256'])`."),
    "CODE-038": "never `eval()` decoded payloads; parse JSON instead.",
}


def _patch_for_code_finding(f) -> str:
    hint = _PATCH_HINTS.get(f.rule_id, "follow the rule's remediation guidance.")
    return (
        f"--- a/{_affected_file(f, {})}\n"
        f"+++ b/{_affected_file(f, {})}\n"
        f"@@ context-of-finding @@\n"
        f"# rule_id: {f.rule_id}  ({f.severity})\n"
        f"# evidence: {(f.evidence or '')[:120]}\n"
        f"# remediation: {hint}\n"
    )


def _patch_for_hardcoded_secret(file: str) -> str:
    return (
        f"--- a/{file}\n"
        f"+++ b/{file}\n"
        f"@@ secret-load-site @@\n"
        f"- API_KEY = '<hard-coded-secret>'\n"
        f"+ import os\n"
        f"+ API_KEY = os.environ['API_KEY']        # CODE-003 remediation\n"
    )


def _secret_token_excerpt(f) -> str:
    # Pull what looks like the literal secret out of the evidence.
    m = re.search(r"['\"]([A-Za-z0-9_\-/+]{16,})['\"]", f.evidence or "")
    return m.group(1) if m else "<secret>"


# ---------------------------------------------------------------------------
# Plan builder
# ---------------------------------------------------------------------------

def _lookup_playbook(rule_id: str) -> Playbook | None:
    for pb in PLAYBOOKS:
        if re.fullmatch(pb.rule_id_pattern, rule_id):
            return pb
    if rule_id.startswith("CODE-"):
        return _GENERIC_CODE
    if rule_id.startswith("LOG-"):
        return _GENERIC_LOG
    if rule_id.startswith("TOP-"):
        return _GENERIC_TOP
    return None


def _dedupe_steps(steps: list[ActionStep]) -> list[ActionStep]:
    seen: set[tuple] = set()
    out: list[ActionStep] = []
    for s in steps:
        key = (s.tool, tuple(sorted(_hashable_params(s.params).items())))
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def _hashable_params(d: dict) -> dict:
    return {k: (json.dumps(v, sort_keys=True) if not isinstance(v, str) else v)
            for k, v in d.items()}


def build_plan(decision, ctx: dict | None = None) -> ActionPlan:
    """Build an ActionPlan from a Decision.

    `decision` is the dataclass produced by `DecisionAgent` (it has
    `summary`, `recommended_tier`, `confidence`, `asset_categories_touched`,
    and `findings`). `ctx` carries optional environment (log path, repo
    path, vehicle id) used by `params_fn` closures.
    """
    ctx = ctx or {}
    findings = sorted(getattr(decision, "findings", []),
                       key=lambda f: severity_rank(f.severity),
                       reverse=True)
    steps: list[ActionStep] = []
    seen_rule_ids: set[str] = set()
    for f in findings:
        # Skip findings whose severity is below the soft threshold —
        # the decision agent already chose a tier; informational hits
        # don't drive automated response.
        if severity_rank(f.severity) < severity_rank("medium"):
            continue
        pb = _lookup_playbook(f.rule_id)
        if pb is None:
            continue
        # Only apply a specific playbook once per rule_id (the
        # finding-by-finding loop already deduplicates evidence).
        key = (pb.title, f.rule_id)
        if key in seen_rule_ids:
            continue
        seen_rule_ids.add(key)
        for tmpl in pb.steps:
            if severity_rank(f.severity) < severity_rank(tmpl.severity_min):
                continue
            steps.append(tmpl.instantiate(f, ctx, f.rule_id))

    # If a tier was recommended and no specific steps fired, fall back
    # to the tier-generic playbook — but only if at least one finding
    # is above the action threshold. Otherwise we'd respond to noise.
    if not steps:
        actionable = [f for f in findings
                       if severity_rank(f.severity) >= severity_rank("medium")]
        tier = getattr(decision, "recommended_tier", None)
        pb = _TIER_PLAYBOOKS.get((tier or "").lower())
        if pb is not None and actionable:
            steps.extend(t.instantiate(actionable[0], ctx, "GENERIC")
                          for t in pb.steps)

    # Order by StepKind (contain → observe → eradicate → recover →
    # notify → audit) and dedup.
    steps.sort(key=lambda s: kind_priority(s.kind))
    steps = _dedupe_steps(steps)

    blast = max((pb.blast_radius
                 for pb in (_lookup_playbook(s.rule_id) for s in steps)
                 if pb), default="local",
                key=_radius_rank)

    plan = ActionPlan(
        plan_id=str(uuid4()),
        decision_summary=getattr(decision, "summary", "") or "",
        blast_radius=blast,
        asset_categories=list(getattr(decision, "asset_categories_touched", [])
                                or []),
        steps=steps,
        created_at=datetime.now(),
    )
    return plan


_RADIUS_RANK = {"local": 0, "service": 1, "node": 2, "network": 3, "fleet": 4}


def _radius_rank(r: str) -> int:
    return _RADIUS_RANK.get(r, 0)


