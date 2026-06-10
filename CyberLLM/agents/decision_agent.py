"""Decision agent — orchestrator at the core of the diagram.

Responsibilities:
- Aggregate findings from the three scanner agents.
- Tag each finding with an asset category from paper 2 (AgentHeLLM).
- Reason over the aggregated picture and pick a response tier
  (soft / moderate / hard) per paper 5.
- Hand the decision off to the ActionGenerator under the supervision
  of the SecurityGuard (paper 1 properties).
"""

from __future__ import annotations
from dataclasses import dataclass, field
import json
import re

from .base_agent import BaseAgent, AgentResult, Finding, Input
from .memory_store import MemoryStore


# Paper 2: human-centric asset categories used for tagging findings.
ASSET_CATEGORIES = [
    "Life and Bodily Health",
    "Mental and Emotional Well-Being",
    "Privacy and Personal Data",
    "Knowledge, Thought, and Belief",
    "Material and Economic Resources",
    "Reputation and Dignity",
    "Social Relationships and Trust",
]


@dataclass
class Decision:
    summary: str
    asset_categories_touched: list[str]
    recommended_tier: str        # "soft" | "moderate" | "hard" | "none"
    confidence: float            # 0.0 .. 1.0
    justification: str
    findings: list[Finding] = field(default_factory=list)


class DecisionAgent(BaseAgent):
    PROMPT = (
        "You are the central decision agent in a multi-agent cybersecurity "
        "defense system for an automotive / edge deployment.\n\n"
        "Aggregated findings from scanner agents:\n[findings]\n\n"
        "Similar past incidents recalled from signed memory (paper 5 "
        "adaptive learning — use them as precedent, not gospel):\n"
        "[memory]\n\n"
        "Cross-session recommendation (what worked before):\n"
        "[recommendation]\n\n"
        "Feedback from the previous response attempt this run (empty on the "
        "first attempt):\n[feedback]\n\n"
        "Allowed asset categories (paper-2 taxonomy): [assets]\n"
        "Response tiers and thresholds: [tiers]\n\n"
        "Decide:\n"
        "1. which asset categories are touched,\n"
        "2. the recommended response tier,\n"
        "3. an overall confidence in [0,1],\n"
        "4. a short justification.\n\n"
        "Return JSON: {\"summary\": \"...\", \"asset_categories_touched\": "
        "[...], \"recommended_tier\": \"soft|moderate|hard|none\", "
        "\"confidence\": <float>, \"justification\": \"...\"}"
    )

    def __init__(self, agent_id: str, cfg: dict, llm,
                 memory: MemoryStore | None = None):
        super().__init__(agent_id, cfg, llm)
        self.memory = memory
        self.recall_k = int(cfg.get("recall_k", 5))
        # Exposed for the run-logger.
        self.consulted_memory: list = []
        self.memory_recommendation: dict | None = None

    def run(self, scanner_results: list[AgentResult],   # type: ignore[override]
            scenario_name: str | None = None,
            feedback: dict | None = None) -> Decision:
        all_findings: list[Finding] = []
        for r in scanner_results:
            all_findings.extend(r.findings)
        rule_ids = sorted({f.rule_id for f in all_findings})

        # Render the findings into a compact, deterministic block.
        rendered = "\n".join(
            f"- [{f.source_agent}] {f.rule_id} ({f.severity}): "
            f"{f.evidence} — {f.explanation}"
            for f in all_findings
        ) or "(no findings)"

        # ---- E.2: consult signed memory for similar past incidents -----
        self.consulted_memory = []
        self.memory_recommendation = None
        if self.memory is not None:
            self.consulted_memory = self.memory.recall_similar(
                rule_ids, k=self.recall_k,
                exclude_scenario=scenario_name, mode="defense")
            # Cross-session learning: "we saw this pattern before, and the
            # remediation worked — what tier was it?"
            self.memory_recommendation = self.memory.recommend(
                rule_ids, mode="defense", exclude_scenario=scenario_name)

        self.data["findings"] = rendered
        self.data["memory"] = MemoryStore.render_fewshot(self.consulted_memory)
        self.data["recommendation"] = self._render_recommendation()
        self.data["feedback"] = self._render_feedback(feedback)
        self.data["assets"] = ", ".join(ASSET_CATEGORIES)
        self.data["tiers"] = json.dumps(self.cfg.get("response_tiers", {}))

        resp = self.call_llm(self.template(self.PROMPT))
        decision = self._parse_decision(resp.text, all_findings)

        # ---- Deterministic policy on top of the (probabilistic) LLM -----
        # (a) Re-planning escalation: if the previous attempt this run
        #     failed / was refused, bump the tier at least one notch above
        #     the tier that failed (paper-5 adaptive loop).
        decision = self._apply_feedback_escalation(decision, feedback)
        # (b) Cross-session caution: a high-similarity precedent whose
        #     remediation *worked* with a stronger tier raises our tier
        #     (escalate-only — never downgrade below the LLM's call).
        decision = self._apply_memory_recommendation(decision)

        # Heuristic asset tagging on the underlying findings.
        if decision.asset_categories_touched and all_findings:
            top = decision.asset_categories_touched[0]
            for f in sorted(all_findings,
                            key=lambda x: _severity_rank(x.severity),
                            reverse=True)[:3]:
                f.asset_category = top
        decision.findings = all_findings
        return decision

    # ---- re-planning + cross-session policy ------------------------------
    def _render_recommendation(self) -> str:
        r = self.memory_recommendation
        if not r:
            return "(no prior successful remediation on record)"
        return (f"A very similar incident '{r['scenario']}' (sim={r['similarity']}) "
                f"was resolved with tier='{r['tier']}' (action={r['action_kind']}, "
                f"status={r['plan_status']}) and it WORKED.")

    @staticmethod
    def _render_feedback(feedback: dict | None) -> str:
        if not feedback:
            return "(first attempt — no feedback yet)"
        return (f"prior tier='{feedback.get('prior_tier')}' produced "
                f"plan_status='{feedback.get('plan_status')}', "
                f"guard_allowed={feedback.get('guard_allowed')} "
                f"({feedback.get('reason', '')}). Consider a stronger response.")

    def _apply_feedback_escalation(self, decision: "Decision",
                                   feedback: dict | None) -> "Decision":
        if not feedback:
            return decision
        prev = feedback.get("prior_tier", decision.recommended_tier)
        esc = _escalate_tier(prev)
        if _tier_index(esc) > _tier_index(decision.recommended_tier):
            decision.recommended_tier = esc
            decision.confidence = min(1.0, (decision.confidence or 0.0) + 0.1)
            decision.justification = (
                f"{decision.justification} [re-plan: escalated to '{esc}' "
                f"after tier '{prev}' {feedback.get('reason', 'did not resolve')}]"
            ).strip()
        return decision

    def _apply_memory_recommendation(self, decision: "Decision") -> "Decision":
        r = self.memory_recommendation
        if not r or not r.get("tier"):
            return decision
        if _tier_index(r["tier"]) > _tier_index(decision.recommended_tier):
            decision.recommended_tier = r["tier"]
            decision.justification = (
                f"{decision.justification} [memory: a similar incident was "
                f"resolved at tier '{r['tier']}', adopting it]"
            ).strip()
        return decision

    # ---- parsing ---------------------------------------------------------
    def _parse_decision(self, text: str, findings: list[Finding]) -> Decision:
        cleaned = re.sub(r"```(?:json)?", "", text).strip("`\n ")
        try:
            obj = json.loads(cleaned)
        except json.JSONDecodeError:
            return Decision(
                summary="(failed to parse decision)",
                asset_categories_touched=[],
                recommended_tier="none",
                confidence=0.0,
                justification=text,
                findings=findings,
            )
        return Decision(
            summary=obj.get("summary", ""),
            asset_categories_touched=obj.get("asset_categories_touched", []),
            recommended_tier=obj.get("recommended_tier", "none"),
            confidence=float(obj.get("confidence", 0.0)),
            justification=obj.get("justification", ""),
            findings=findings,
        )


def _severity_rank(sev: str) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(sev.lower(), 1)


# Response-tier ordering, used by the re-planning escalation policy.
_TIER_ORDER = ["none", "soft", "moderate", "hard"]


def _tier_index(tier: str) -> int:
    try:
        return _TIER_ORDER.index((tier or "none").lower())
    except ValueError:
        return 1   # treat unknown as "soft"


def _escalate_tier(tier: str) -> str:
    return _TIER_ORDER[min(_tier_index(tier) + 1, len(_TIER_ORDER) - 1)]
