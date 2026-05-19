"""Deployment / topology scanner.

Inspiration:
- Paper 3 (TUM) topology workflow — builds an EMF/Ecore model from the
  user description and checks it against OCL rules.
- Paper 2 (AgentHeLLM) — represents the system as a graph of Actors
  and Datasources connected by read/write/communicate/respond edges.

In this skeleton we read a YAML deployment file, build that actor /
datasource graph, and pass it to the LLM together with the topology
rules. The LLM (or a future symbolic checker) returns rule violations.
"""

from __future__ import annotations
from pathlib import Path
import yaml

from .base_agent import BaseAgent, AgentResult, Input


class DeploymentScannerAgent(BaseAgent):
    PROMPT = (
        "You are a system-topology security analyzer for an SDV / "
        "edge-computing deployment.\n"
        "Build the actor/datasource interaction graph from the deployment "
        "config and identify rule violations.\n\n"
        "Topology rules in scope:\n[rules]\n\n"
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

        self.data["deployment"] = dep_inputs[0].content
        self.data["rules"] = self.cfg.get("rules_snippet", "")
        prompt = self.template(self.PROMPT)
        resp = self.llm.complete(prompt)
        return AgentResult(
            agent_id=self.agent_id,
            objective=self.objective,
            findings=self._parse_findings(resp.text),
            raw_llm_text=resp.text,
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
