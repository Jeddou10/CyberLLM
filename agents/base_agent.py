"""Base agent — the schema-driven template from paper 4 (Härer).

An agent owns:
- an LLM client (paper 4 LLM-Config),
- a data dict the prompt template draws from (paper 4 Data),
- an objective string used by the security guard (paper 1 H_p).

Subclasses override `run()` and may declare their own action chain.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import json
import re

from llm_client import LLMClient


@dataclass
class Finding:
    rule_id: str
    severity: str          # low | medium | high | critical
    evidence: str
    explanation: str
    source_agent: str
    asset_category: str | None = None    # set by DecisionAgent, paper 2 taxonomy
    line: int | None = None              # optional, for code findings


@dataclass
class Input:
    """Every input is tagged with provenance (paper 1: source attribution L)."""
    content: str
    source: str                  # e.g. "user", "log_file", "external_api"
    trust_level: str             # "authenticated" | "external" | "tool" | "memory"


@dataclass
class AgentResult:
    agent_id: str
    objective: str
    findings: list[Finding] = field(default_factory=list)
    raw_llm_text: str | None = None


class BaseAgent:
    def __init__(self, agent_id: str, cfg: dict, llm: LLMClient):
        self.agent_id = agent_id
        self.cfg = cfg
        self.llm = llm
        self.objective = cfg["objective"]
        self.data: dict[str, Any] = {}

    # ---- helpers ----------------------------------------------------------
    def template(self, prompt: str) -> str:
        """Substitute `[key]` placeholders with values from self.data
        (paper 4 templating)."""
        def repl(match: re.Match) -> str:
            key = match.group(1)
            val = self.data.get(key, "")
            return str(val)
        return re.sub(r"\[([a-zA-Z0-9_/-]+)\]", repl, prompt)

    def _parse_findings(self, text: str) -> list[Finding]:
        """Try to read a JSON object with a `findings` list. Robust to
        the LLM wrapping JSON in markdown code fences."""
        cleaned = re.sub(r"```(?:json)?", "", text).strip("`\n ")
        try:
            obj = json.loads(cleaned)
        except json.JSONDecodeError:
            return []
        raw = obj.get("findings", []) if isinstance(obj, dict) else []
        out: list[Finding] = []
        for item in raw:
            out.append(Finding(
                rule_id=item.get("rule_id", "UNKNOWN"),
                severity=item.get("severity", "medium"),
                evidence=item.get("evidence", ""),
                explanation=item.get("explanation", ""),
                line=item.get("line"),
                source_agent=self.agent_id,
            ))
        return out

    # ---- to override ------------------------------------------------------
    def run(self, inputs: list[Input]) -> AgentResult:  # pragma: no cover
        raise NotImplementedError
