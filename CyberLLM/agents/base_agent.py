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

from llm_client import LLMClient, LLMResponse
from tools.tokens import TokenBudget


# Paper 1 §4.2: every input must carry a provenance label drawn from a
# fixed lattice so a downstream guard can reason about it. We make the
# lattice explicit and *mandatory* (roadmap F.2).
ALLOWED_TRUST_LEVELS = {"authenticated", "external", "tool", "memory"}


class ProvenanceError(ValueError):
    """Raised when an Input is missing or has an invalid provenance tag."""


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
    """Every input is tagged with provenance (paper 1: source attribution L).

    Provenance is **mandatory** (roadmap F.2): an Input cannot be built
    without a non-empty `source` and a `trust_level` drawn from
    `ALLOWED_TRUST_LEVELS`. The pipeline therefore *cannot* feed an
    un-attributed artefact to an agent — the source-authorization
    property (paper 1) is only enforceable if the tag exists at
    ingestion.
    """
    content: str
    source: str                  # e.g. "user", "log_file", "external_api"
    trust_level: str             # "authenticated" | "external" | "tool" | "memory"

    def __post_init__(self) -> None:
        if not self.source or not str(self.source).strip():
            raise ProvenanceError(
                "Input.source is mandatory (paper 1 source attribution L)")
        if self.trust_level not in ALLOWED_TRUST_LEVELS:
            raise ProvenanceError(
                f"Input.trust_level '{self.trust_level}' invalid; "
                f"must be one of {sorted(ALLOWED_TRUST_LEVELS)}")


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

        # ---- delegation state (paper 1 §7, roadmap F.5) -----------------
        # The set of sources this agent treats as authenticated. A
        # delegated child does NOT inherit its parent's set — it starts
        # empty and must be granted sources explicitly.
        self.trusted_sources: set[str] = set(cfg.get("trusted_sources", []))
        self.delegated_from: str | None = None

        # ---- token budgeting (paper 3, roadmap A.4) ---------------------
        self.token_budget = TokenBudget(
            max_prompt_tokens=int(cfg.get("max_prompt_tokens", 4096)))
        self.last_prompt_tokens: int = 0

        # ---- debugging hooks (populated by `call_llm`) ------------------
        # The pipeline's RunLogger reads these after each agent.run() to
        # build the per-step debug files.
        self.last_prompt: str = ""
        self.last_response: str = ""
        self.last_static_findings: list[Finding] = []

    # ---- helpers ----------------------------------------------------------
    def call_llm(self, prompt: str) -> LLMResponse:
        """Single LLM entry point — records prompt + response so the
        RunLogger can capture them after the agent returns. Also accounts
        the prompt against this agent's token budget (A.4)."""
        self.last_prompt = prompt
        self.last_prompt_tokens = self.token_budget.account(
            prompt, label=self.agent_id)
        resp = self.llm.complete(prompt)
        self.last_response = resp.text
        return resp

    # ---- delegation (paper 1 §7 compositional / delegation rules) ---------
    def delegate(self, child_cls, child_cfg: dict | None = None,
                 llm: LLMClient | None = None,
                 grant_sources: list[str] | None = None) -> "BaseAgent":
        """Spawn a child agent that **inherits this agent's objective but
        NOT its source set** (paper 1, roadmap F.5).

        When agent A invokes agent B, B is bound to A's objective `o`
        (it may not silently widen scope), yet B must *not* inherit A's
        authority over inputs — otherwise an external instruction that A
        is allowed to read could be laundered into a privileged action by
        B. B therefore starts with an empty trusted-source set and only
        the sources A *explicitly* grants via `grant_sources`.
        """
        cfg = dict(child_cfg or {})
        cfg.setdefault("objective", self.objective)   # inherit objective
        child = child_cls(f"{self.agent_id}->{child_cls.__name__}",
                          cfg, llm or self.llm)
        child.delegated_from = self.agent_id
        child.trusted_sources = set(grant_sources or [])   # NOT inherited
        return child

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
