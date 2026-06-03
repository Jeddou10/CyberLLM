"""System information discovery — diagram 2, top-left node.

What it does
------------
Reads everything we have about the target system (deployment YAML +
optional fingerprint files) and produces a structured "instance"
description the attack agent can reason over.

This is the **passive reconnaissance** stage. No packets are sent to
the target. Active recon would belong in `tools/active_analyzer.py`
(future work; gated by the EthicsGuard).

Inspiration
-----------
- Paper 2 (AgentHeLLM) §4.2.1 — model the system as a graph of Actors
  and Datasources. The output here is exactly that graph.
- Paper 3 (TUM) §III "Instance creation" — turn user text + catalogs
  into a structured instance model.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from ..base_agent import AgentResult, BaseAgent, Input


@dataclass
class SystemInstance:
    """Result of the discovery step — fed into the attack orchestrator."""

    actors: list[dict] = field(default_factory=list)
    datasources: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    external_actors: list[str] = field(default_factory=list)
    safety_actors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class SystemInfoDiscoveryAgent(BaseAgent):
    PROMPT = (
        "You are a passive reconnaissance assistant for an authorised "
        "red-team exercise.\n"
        "Given the deployment YAML below, summarise the attack surface:\n"
        " - list the externally reachable actors,\n"
        " - list the safety-critical actors,\n"
        " - list datasources writable from any external actor,\n"
        " - flag any open ports / weak transports.\n\n"
        "Deployment config:\n```\n[deployment]\n```\n\n"
        "Return JSON: {\"external_actors\": [...], \"safety_actors\": [...], "
        "\"writable_from_external\": [...], \"notes\": [\"...\"]}"
    )

    def run(self, inputs: list[Input]) -> AgentResult:  # type: ignore[override]
        dep_inputs = [i for i in inputs
                      if i.source.endswith(".yaml") or i.source.endswith(".yml")]
        if not dep_inputs:
            return AgentResult(self.agent_id, self.objective, [])

        deployment_yaml = dep_inputs[0].content
        instance = self._build_instance(deployment_yaml)

        # Make the instance available on `data` so downstream agents
        # can read it via the orchestrator.
        self.data["instance"] = instance
        self.data["deployment"] = deployment_yaml

        # The LLM call is optional here — the instance is fully built
        # from YAML. We call it for any extra "notes" the LLM spots.
        prompt = self.template(self.PROMPT)
        resp = self.call_llm(prompt)
        result = AgentResult(self.agent_id, self.objective, [],
                             raw_llm_text=resp.text)
        # Stash the structured instance on the result so the orchestrator
        # can pick it up.
        result.system_instance = instance  # type: ignore[attr-defined]
        return result

    # ---- deterministic graph build -------------------------------------
    @staticmethod
    def _build_instance(deployment_yaml: str) -> SystemInstance:
        doc = yaml.safe_load(deployment_yaml) or {}
        actors = doc.get("actors", [])
        datasources = doc.get("datasources", [])
        edges = doc.get("edges", [])

        external = [a["id"] for a in actors
                    if a.get("trust_level") == "external"
                    or a.get("type") in {"ExternalUser",
                                         "ExternalA2AAgent",
                                         "ExternalService"}]
        safety = [a["id"] for a in actors
                  if a.get("type") in {"SafetyECU", "ZoneECU",
                                       "HighPerformanceComputer"}]

        notes: list[str] = []
        for a in actors:
            if a.get("exposed"):
                notes.append(f"{a['id']} is exposed (internet-reachable)")
            if a.get("bind_address") == "0.0.0.0":
                notes.append(f"{a['id']} binds 0.0.0.0")
            if a.get("access_policy") == "world-readable":
                notes.append(f"{a['id']} is world-readable")

        return SystemInstance(
            actors=actors,
            datasources=datasources,
            edges=edges,
            external_actors=external,
            safety_actors=safety,
            notes=notes,
        )
