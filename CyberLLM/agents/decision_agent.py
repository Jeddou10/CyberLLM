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
        # Most recent recall, exposed for the run-logger.
        self.consulted_memory: list = []

    def run(self, scanner_results: list[AgentResult],   # type: ignore[override]
            scenario_name: str | None = None) -> Decision:
        all_findings: list[Finding] = []
        for r in scanner_results:
            all_findings.extend(r.findings)

        # Render the findings into a compact, deterministic block.
        rendered = "\n".join(
            f"- [{f.source_agent}] {f.rule_id} ({f.severity}): "
            f"{f.evidence} — {f.explanation}"
            for f in all_findings
        ) or "(no findings)"

        # ---- E.2: consult signed memory for similar past incidents -----
        self.consulted_memory = []
        if self.memory is not None:
            rule_ids = sorted({f.rule_id for f in all_findings})
            self.consulted_memory = self.memory.recall_similar(
                rule_ids, k=self.recall_k,
                exclude_scenario=scenario_name, mode="defense")

        self.data["findings"] = rendered
        self.data["memory"] = MemoryStore.render_fewshot(self.consulted_memory)
        self.data["assets"] = ", ".join(ASSET_CATEGORIES)
        self.data["tiers"] = json.dumps(self.cfg.get("response_tiers", {}))

        resp = self.call_llm(self.template(self.PROMPT))
        decision = self._parse_decision(resp.text, all_findings)

        # Heuristic asset tagging on the underlying findings — if the LLM
        # named a category, propagate it to severity-ranked findings.
        if decision.asset_categories_touched and all_findings:
            top = decision.asset_categories_touched[0]
            for f in sorted(all_findings,
                            key=lambda x: _severity_rank(x.severity),
                            reverse=True)[:3]:
                f.asset_category = top
        decision.findings = all_findings
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
