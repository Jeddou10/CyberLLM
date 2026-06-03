"""Log analyzer agent — detection role from paper 5.

Reads structured / unstructured log lines and classifies anomalies.
Combines a deterministic static pass (heuristics over log_rules) with
an LLM refinement pass — paper 4 §IV-B "constraint + augmentation".
"""

from __future__ import annotations
from pathlib import Path

from .base_agent import AgentResult, BaseAgent, Finding, Input
from tools.static_analyzer import (
    merge_findings, scan_log_static, staticfinding_to_finding,
)


class LogAnalyzerAgent(BaseAgent):
    PROMPT = (
        "You are a log anomaly detector for an automotive ECU / fleet "
        "telemetry pipeline.\n"
        "Analyze the log lines below and identify anomalies that suggest "
        "reconnaissance, brute force, lateral movement, data exfiltration, "
        "or CAN-bus injection.\n\n"
        "Active detection rules:\n[rules]\n\n"
        "Deterministic heuristic hits already produced for this log "
        "(refine, explain, or extend — do not duplicate):\n"
        "[static_findings]\n\n"
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

        log_text = "\n".join(i.content for i in log_inputs)
        rules = self.cfg.get("rules_full", {})

        # ---- 1. Deterministic static pass -----------------------------
        static_hits = scan_log_static(log_text, rules)
        static_as_findings = staticfinding_to_finding(static_hits, Finding)
        for f in static_as_findings:
            f.source_agent = self.agent_id
        self.last_static_findings = list(static_as_findings)

        # ---- 2. LLM pass with the static findings as context ----------
        self.data["log"] = log_text
        self.data["rules"] = self.cfg.get("rules_snippet", "")
        self.data["static_findings"] = (
            "\n".join(f"- {f.rule_id}: {f.evidence}" for f in static_as_findings)
            or "(no static findings)"
        )
        prompt = self.template(self.PROMPT)
        resp = self.call_llm(prompt)
        llm_findings = self._parse_findings(resp.text)

        # ---- 3. Merge --------------------------------------------------
        merged = merge_findings(static_as_findings, llm_findings)
        return AgentResult(
            agent_id=self.agent_id,
            objective=self.objective,
            findings=merged,
            raw_llm_text=resp.text,
        )

    @staticmethod
    def load_example(path: str | Path) -> Input:
        p = Path(path)
        return Input(content=p.read_text(encoding="utf-8"),
                     source=p.name, trust_level="external")
