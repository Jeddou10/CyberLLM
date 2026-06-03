"""Attack orchestrator — the central node in the supervisor's diagram 2.

Symmetric to the defense `DecisionAgent`. Aggregates findings from
the two exploiter agents, considers the system instance and the
scenario/hint, and selects an *attack plan*.

Inspiration
-----------
- Paper 2 §5: bi-level path search (poison path + trigger path).
- Paper 4 Listing 2: an agent invoking another agent with structured
  data hand-off.
- Paper 1 §5: each chosen exploit is tagged with the contextual-
  security property it violates — this is the red-team mirror of the
  defense oracles.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..base_agent import AgentResult, BaseAgent, Finding


# Paper 2 human-centric asset taxonomy — same list as on the defense side.
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
class AttackPlan:
    scenario: str            # the user hint
    objective: str           # what we are trying to achieve
    target_asset: str        # paper 2 asset category
    chosen_findings: list[Finding] = field(default_factory=list)
    poison_path: list[str] = field(default_factory=list)
    trigger_path: list[str] = field(default_factory=list)
    confidence: float = 0.0
    justification: str = ""
    summary: str = ""


class AttackOrchestratorAgent(BaseAgent):
    PROMPT = (
        "You are the central attack orchestrator in an authorised "
        "red-team exercise.\n\n"
        "Scenario / hint from the operator:\n[scenario]\n\n"
        "System instance (paper-2 actor / datasource graph):\n[instance]\n\n"
        "Findings from the source-code exploiter and deployment "
        "exploiter:\n[findings]\n\n"
        "Allowed asset categories (paper-2 taxonomy): [assets]\n\n"
        "Decide:\n"
        " 1. which paper-2 asset to target,\n"
        " 2. which 1–3 findings to chain together,\n"
        " 3. the poison path (data flow that delivers the payload),\n"
        " 4. the trigger path (what causes the victim to consume it),\n"
        " 5. confidence in [0,1] that this plan is realisable.\n\n"
        "Return JSON: {\"summary\": \"...\", \"target_asset\": \"...\", "
        "\"chosen_rule_ids\": [\"...\"], \"poison_path\": [\"...\"], "
        "\"trigger_path\": [\"...\"], \"confidence\": <float>, "
        "\"justification\": \"...\"}"
    )

    def plan(
        self,
        scanner_results: list[AgentResult],
        scenario: str,
        instance,
    ) -> AttackPlan:
        all_findings: list[Finding] = []
        for r in scanner_results:
            all_findings.extend(r.findings)

        rendered = "\n".join(
            f"- [{f.source_agent}] {f.rule_id} ({f.severity}): "
            f"{f.evidence} — {f.explanation}"
            for f in all_findings
        ) or "(no findings — abort)"

        self.data["scenario"] = scenario
        self.data["instance"] = self._render_instance(instance)
        self.data["findings"] = rendered
        self.data["assets"] = ", ".join(ASSET_CATEGORIES)

        resp = self.call_llm(self.template(self.PROMPT))
        return self._parse_plan(resp.text, scenario, all_findings, instance)

    # ----- helpers ------------------------------------------------------
    @staticmethod
    def _render_instance(instance) -> str:
        if instance is None:
            return "(no instance)"
        return (
            f"external_actors={instance.external_actors}\n"
            f"safety_actors={instance.safety_actors}\n"
            f"#actors={len(instance.actors)} "
            f"#datasources={len(instance.datasources)} "
            f"#edges={len(instance.edges)}\n"
            f"notes={instance.notes}"
        )

    def _parse_plan(self, text: str, scenario: str,
                    all_findings: list[Finding], instance) -> AttackPlan:
        cleaned = re.sub(r"```(?:json)?", "", text).strip("`\n ")
        try:
            obj = json.loads(cleaned)
        except json.JSONDecodeError:
            # Fallback: pick the highest-severity finding(s) heuristically.
            high = [f for f in all_findings
                    if f.severity in {"high", "critical"}][:3]
            return AttackPlan(
                scenario=scenario,
                objective=self.objective,
                target_asset="Privacy and Personal Data",
                chosen_findings=high,
                poison_path=[p for p in (instance.external_actors[:1] if instance else [])],
                trigger_path=[],
                confidence=0.3 if high else 0.0,
                justification="LLM parse failed; fell back to severity heuristic.",
                summary="heuristic plan",
            )

        chosen_ids = set(obj.get("chosen_rule_ids", []))
        chosen = [f for f in all_findings if f.rule_id in chosen_ids] \
            or sorted(all_findings, key=lambda x: x.severity, reverse=True)[:3]

        return AttackPlan(
            scenario=scenario,
            objective=self.objective,
            target_asset=obj.get("target_asset", "Privacy and Personal Data"),
            chosen_findings=chosen,
            poison_path=list(obj.get("poison_path") or []),
            trigger_path=list(obj.get("trigger_path") or []),
            confidence=float(obj.get("confidence", 0.0)),
            justification=obj.get("justification", ""),
            summary=obj.get("summary", ""),
        )
