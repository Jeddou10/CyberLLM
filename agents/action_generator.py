"""Action generator — translates a decision into concrete commands.

Inspiration:
- Paper 5 (Collins) — three response tiers: soft / moderate / hard.
- Paper 3 (TUM) — Prompt Construct 2b: given the analysis outcome and
  the code, propose a corrected version.
"""

from __future__ import annotations
from dataclasses import dataclass

from .base_agent import BaseAgent
from .decision_agent import Decision


@dataclass
class Action:
    kind: str             # "rate_limit" | "block_ip" | "isolate_node" |
                          # "patch_code" | "alert_only" | "noop"
    target: str
    parameters: dict
    rationale: str
    originating_decision: Decision


class ActionGenerator(BaseAgent):
    FIX_PROMPT = (
        "Based on the analysis outcome:\n[result]\n\n"
        "Correct the following code to eliminate the detected security "
        "issues. Return only the corrected snippet, no commentary.\n\n"
        "Code:\n```\n[code]\n```"
    )

    def generate(self, decision: Decision,
                 vulnerable_code: str | None = None) -> Action:
        tier = decision.recommended_tier
        if tier == "soft":
            return Action(
                kind="rate_limit",
                target="suspect_source_ip",
                parameters={"rate_per_minute": 30, "duration_minutes": 15},
                rationale=decision.justification,
                originating_decision=decision,
            )
        if tier == "moderate":
            return Action(
                kind="block_ip",
                target="suspect_source_ip",
                parameters={"duration_minutes": 60},
                rationale=decision.justification,
                originating_decision=decision,
            )
        if tier == "hard":
            return Action(
                kind="isolate_node",
                target="affected_ECU",
                parameters={"vlan": "quarantine-99"},
                rationale=decision.justification,
                originating_decision=decision,
            )
        if vulnerable_code:
            self.data["result"] = decision.summary + "\n" + decision.justification
            self.data["code"] = vulnerable_code
            resp = self.llm.complete(self.template(self.FIX_PROMPT))
            return Action(
                kind="patch_code",
                target="vulnerable_file",
                parameters={"patch_proposal": resp.text},
                rationale=decision.justification,
                originating_decision=decision,
            )
        return Action(
            kind="alert_only",
            target="security_team",
            parameters={"report": decision.summary},
            rationale=decision.justification,
            originating_decision=decision,
        )
