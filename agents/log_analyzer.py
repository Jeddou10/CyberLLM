"""Log analyzer agent — detection role from paper 5.

Reads structured / unstructured log lines and classifies anomalies.
"""

from __future__ import annotations
from pathlib import Path

from .base_agent import BaseAgent, AgentResult, Input


class LogAnalyzerAgent(BaseAgent):
    PROMPT = (
        "You are a log anomaly detector for an automotive ECU / fleet "
        "telemetry pipeline.\n"
        "Analyze the log lines below and identify anomalies that suggest "
        "reconnaissance, brute force, lateral movement, data exfiltration, "
        "or CAN-bus injection.\n\n"
        "Active detection rules:\n[rules]\n\n"
        "Log lines:\n```\n[log]\n```\n\n"
        "Return JSON: {\"findings\": [{\"rule_id\": \"...\", \"severity\": "
        "\"low|medium|high|critical\", \"evidence\": \"...\", "
        "\"explanation\": \"...\"}, ...]}"
    )

    def run(self, inputs: list[Input]) -> AgentResult:
        log_inputs = [i for i in inputs if i.source.endswith(".log")
                      or i.source.endswith(".txt")]
        if not log_inputs:
            return AgentResult(self.agent_id, self.objective, [])

        # Concatenate all log inputs for a single LLM call.
        self.data["log"] = "\n".join(i.content for i in log_inputs)
        self.data["rules"] = self.cfg.get("rules_snippet", "")
        prompt = self.template(self.PROMPT)
        resp = self.llm.complete(prompt)
        return AgentResult(
            agent_id=self.agent_id,
            objective=self.objective,
            findings=self._parse_findings(resp.text),
            raw_llm_text=resp.text,
        )

    @staticmethod
    def load_example(path: str | Path) -> Input:
        p = Path(path)
        return Input(content=p.read_text(encoding="utf-8"),
                     source=p.name, trust_level="external")
