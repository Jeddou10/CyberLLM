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

from .base_agent import BaseAgent, AgentResult, Finding, Input
from tools.static_analyzer import (
    merge_findings, scan_code_static, staticfinding_to_finding,
)


class SourceCodeScannerAgent(BaseAgent):
    PROMPT = (
        "You are a source-code security scanner.\n"
        "Analyze the following code and identify insecure patterns "
        "(command injection, hard-coded secrets, weak crypto, unsafe "
        "deserialization, missing input validation, race conditions).\n\n"
        "Rules in scope (only consider these):\n[rules]\n\n"
        "Deterministic static-analysis hits already produced for this "
        "file (you may refine, explain, or extend them — do not "
        "duplicate them):\n[static_findings]\n\n"
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

        rules = self.cfg.get("rules_full", {})
        all_findings: list[Finding] = []
        raw_texts: list[str] = []
        self.last_static_findings = []

        for inp in code_inputs:
            # ---- 1. Deterministic static pass (regex over the rules) -----
            static_hits = scan_code_static(inp.content, inp.source, rules)
            static_as_findings = staticfinding_to_finding(static_hits, Finding)
            for f in static_as_findings:
                f.source_agent = self.agent_id
            self.last_static_findings.extend(static_as_findings)

            # ---- 2. LLM pass — given the static hits as context ---------
            self.data["code"] = inp.content
            self.data["filename"] = inp.source
            self.data["rules"] = self.cfg.get("rules_snippet", "")
            self.data["static_findings"] = (
                "\n".join(f"- {f.rule_id} (line {f.line}): {f.evidence}"
                          for f in static_as_findings)
                or "(no static findings)"
            )
            prompt = self.template(self.PROMPT)
            resp = self.call_llm(prompt)
            raw_texts.append(resp.text)
            llm_findings = self._parse_findings(resp.text)

            # ---- 3. Merge (static wins on dedup) ------------------------
            merged = merge_findings(static_as_findings, llm_findings)
            all_findings.extend(merged)

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
