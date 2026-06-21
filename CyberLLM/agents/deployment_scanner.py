"""Deployment / topology scanner.

Inspiration:
- Paper 3 (TUM) topology workflow — builds an EMF/Ecore model from the
  user description and checks it against OCL rules.
- Paper 2 (AgentHeLLM) — represents the system as a graph of Actors
  and Datasources connected by read/write/communicate/respond edges.
- Paper 4 (Härer) — schema-driven agent with constraint prompting.

Combines a deterministic graph-check pass (paper-3-style OCL) with an
LLM refinement pass.
"""

from __future__ import annotations
from pathlib import Path
import yaml

from .base_agent import AgentResult, BaseAgent, Finding, Input
from tools.static_analyzer import (
    merge_findings, scan_deployment_static, staticfinding_to_finding,
)


class DeploymentScannerAgent(BaseAgent):
    PROMPT = (
        "You are a system-topology security analyzer for an SDV / "
        "edge-computing deployment.\n"
        "Build the actor/datasource interaction graph from the deployment "
        "config and identify rule violations.\n\n"
        "Topology rules in scope:\n[rules]\n\n"
        "Deterministic graph-check hits already produced for this "
        "deployment (refine, explain, or extend — do not duplicate):\n"
        "[static_findings]\n\n"
        "Deployment config (YAML):\n```\n[deployment]\n```\n\n"
        "Return JSON: {\"findings\": [{\"rule_id\": \"...\", \"severity\": "
        "\"low|medium|high|critical\", \"evidence\": \"...\", "
        "\"explanation\": \"...\"}, ...]}"
    )

    def run(self, inputs: list[Input]) -> AgentResult:
        dep_inputs = [i for i in inputs
                      if i.source.endswith(".yaml") or i.source.endswith(".yml")]
        if not dep_inputs:
            return AgentResult(self.agent_id, self.objective, [])

        deployment_yaml = dep_inputs[0].content
        rules = self.cfg.get("rules_full", {})

        # ---- 1. Deterministic graph-check pass -----------------------
        static_hits = scan_deployment_static(deployment_yaml, rules)
        static_as_findings = staticfinding_to_finding(static_hits, Finding)
        for f in static_as_findings:
            f.source_agent = self.agent_id
        self.last_static_findings = list(static_as_findings)

        # ---- 2. LLM pass with static findings as context -------------
        if self.cfg.get("use_llm", True):
            self.data["deployment"] = deployment_yaml
            self.data["rules"] = self.cfg.get("rules_snippet", "")
            self.data["static_findings"] = (
                "\n".join(f"- {f.rule_id}: {f.evidence}" for f in static_as_findings)
                or "(no static findings)"
            )
            prompt = self.template(self.PROMPT)
            resp = self.call_llm(prompt)
            llm_findings = self._parse_findings(resp.text)
            raw_text = resp.text
        else:
            llm_findings = []
            raw_text = "(LLM pass disabled — static layers only)"

        # ---- 3. Merge ------------------------------------------------
        merged = merge_findings(static_as_findings, llm_findings)
        return AgentResult(
            agent_id=self.agent_id,
            objective=self.objective,
            findings=merged,
            raw_llm_text=raw_text,
        )

    # ---- convenience -----------------------------------------------------
    @staticmethod
    def load_example(path: str | Path) -> Input:
        p = Path(path)
        return Input(content=p.read_text(encoding="utf-8"),
                     source=p.name, trust_level="authenticated")

    @staticmethod
    def parse_actor_graph(yaml_text: str) -> dict:
        """Build the {actors, datasources, edges} dict that the threat
        modeller (paper 2) consumes. Kept lightweight on purpose."""
        data = yaml.safe_load(yaml_text) or {}
        return {
            "actors": data.get("actors", []),
            "datasources": data.get("datasources", []),
            "edges": data.get("edges", []),
        }
