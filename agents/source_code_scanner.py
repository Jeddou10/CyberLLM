"""Source-code scanner agent.

Inspiration:
- Paper 3 (TUM) Prompt Construct 1 — extract VSS/CAN signals from code.
- Paper 4 (Härer) — schema-driven agent with an extract → evaluate
  action chain.
- Paper 1 — code findings are tagged with the rule_id of the rule they
  violate, so the security guard can later cross-reference.
"""

from __future__ import annotations
from pathlib import Path

from .base_agent import BaseAgent, AgentResult, Input


class SourceCodeScannerAgent(BaseAgent):
    PROMPT = (
        "You are a source-code security scanner.\n"
        "Analyze the following code and identify insecure patterns "
        "(command injection, hard-coded secrets, weak crypto, unsafe "
        "deserialization, missing input validation, race conditions).\n\n"
        "Rules in scope (only consider these):\n[rules]\n\n"
        "Source code (file: [filename]):\n```\n[code]\n```\n\n"
        "Return JSON of the form: {\"findings\": [{\"rule_id\": \"...\", "
        "\"severity\": \"low|medium|high|critical\", \"line\": <int>, "
        "\"evidence\": \"...\", \"explanation\": \"...\"}, ...]}"
    )

    def run(self, inputs: list[Input]) -> AgentResult:
        code_inputs = [i for i in inputs if i.source.endswith(".py")
                       or i.source.endswith(".c") or i.source.endswith(".cpp")]
        if not code_inputs:
            return AgentResult(self.agent_id, self.objective, [])

        all_findings = []
        raw_texts = []
        for inp in code_inputs:
            self.data["code"] = inp.content
            self.data["filename"] = inp.source
            self.data["rules"] = self.cfg.get("rules_snippet", "")
            prompt = self.template(self.PROMPT)
            resp = self.llm.complete(prompt)
            raw_texts.append(resp.text)
            all_findings.extend(self._parse_findings(resp.text))

        return AgentResult(
            agent_id=self.agent_id,
            objective=self.objective,
            findings=all_findings,
            raw_llm_text="\n---\n".join(raw_texts),
        )

    # ------ convenience for the demo --------------------------------------
    @staticmethod
    def load_example(path: str | Path) -> Input:
        p = Path(path)
        return Input(content=p.read_text(encoding="utf-8"),
                     source=p.name, trust_level="external")
