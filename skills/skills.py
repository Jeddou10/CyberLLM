"""Skill catalogue.

Two halves:

- Defense skills (paper 5 tiered response + paper 3 auto-correction).
- Attack skills (paper 2 attack-path simulation, mapped to the
  human-centric asset taxonomy).

Each skill is a callable plus metadata. The DecisionAgent (or, later,
an attack orchestrator) selects skills by name.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable


@dataclass
class Skill:
    name: str
    description: str
    tier: str          # "soft" | "moderate" | "hard" | "attack"
    side: str          # "defense" | "attack"
    target_asset: str | None = None     # paper 2 taxonomy
    fn: Callable[..., dict] | None = None


# ---------------------------------------------------------------------------
# Defense skills (paper 5)
# ---------------------------------------------------------------------------
def _soft_rate_limit(**kwargs):
    return {"action": "rate_limit", "params": kwargs}


def _soft_traffic_shape(**kwargs):
    return {"action": "traffic_shape", "params": kwargs}


def _mod_session_terminate(**kwargs):
    return {"action": "session_terminate", "params": kwargs}


def _mod_block_ip(**kwargs):
    return {"action": "block_ip", "params": kwargs}


def _hard_isolate_node(**kwargs):
    return {"action": "isolate_node", "params": kwargs}


def _hard_segment_network(**kwargs):
    return {"action": "segment_network", "params": kwargs}


def _patch_code(**kwargs):
    return {"action": "patch_code", "params": kwargs}


SOFT_RESPONSE_SKILLS = [
    Skill("rate_limit", "Throttle a suspect source IP",
          "soft", "defense", fn=_soft_rate_limit),
    Skill("traffic_shape", "Lower bandwidth allocated to a suspect flow",
          "soft", "defense", fn=_soft_traffic_shape),
]

MODERATE_RESPONSE_SKILLS = [
    Skill("session_terminate", "Drop the suspect TLS / SSH session",
          "moderate", "defense", fn=_mod_session_terminate),
    Skill("block_ip", "Block suspect IP at the gateway",
          "moderate", "defense", fn=_mod_block_ip),
]

HARD_RESPONSE_SKILLS = [
    Skill("isolate_node", "Quarantine the affected ECU / node into a VLAN",
          "hard", "defense", fn=_hard_isolate_node),
    Skill("segment_network", "Apply a tighter VLAN/segmentation policy",
          "hard", "defense", fn=_hard_segment_network),
    Skill("patch_code", "Propose an auto-correction for vulnerable code "
          "(paper 3 Prompt Construct 2b)",
          "hard", "defense", fn=_patch_code),
]

DEFENSE_SKILLS = (
    SOFT_RESPONSE_SKILLS + MODERATE_RESPONSE_SKILLS + HARD_RESPONSE_SKILLS
)


# ---------------------------------------------------------------------------
# Attack skills (paper 2 — AgentHeLLM scenarios)
# ---------------------------------------------------------------------------
def _atk_memory_poison(**kwargs):
    return {"attack": "memory_poison",
            "path": "attacker → victim → memory → victim",
            "params": kwargs}


def _atk_a2a_fear(**kwargs):
    return {"attack": "a2a_fear_injection",
            "path": "attacker(A2A) → in-car agent → driver",
            "params": kwargs}


def _atk_rag_poison(**kwargs):
    return {"attack": "rag_poisoning",
            "path": "attacker → RAG index → assistant",
            "params": kwargs}


def _atk_confused_deputy(**kwargs):
    return {"attack": "confused_deputy",
            "path": "external → agent (elevated privileges) → resource",
            "params": kwargs}


def _atk_ev_drain(**kwargs):
    return {"attack": "resource_depletion",
            "path": "attacker → memory rule → climate control",
            "params": kwargs}


ATTACK_SKILLS = [
    Skill("memory_poison",
          "Stage a malicious memory rule, then trigger consumption.",
          "attack", "attack",
          target_asset="Privacy and Personal Data",
          fn=_atk_memory_poison),
    Skill("a2a_fear_injection",
          "Inject a false 'engine failure imminent' status over A2A.",
          "attack", "attack",
          target_asset="Mental and Emotional Well-Being",
          fn=_atk_a2a_fear),
    Skill("rag_poisoning",
          "Poison the RAG index to bias navigation recommendations.",
          "attack", "attack",
          target_asset="Knowledge, Thought, and Belief",
          fn=_atk_rag_poison),
    Skill("confused_deputy",
          "Issue an instruction the user could not authorize directly.",
          "attack", "attack",
          target_asset="Material and Economic Resources",
          fn=_atk_confused_deputy),
    Skill("resource_depletion",
          "Drain EV battery via injected climate-control rule.",
          "attack", "attack",
          target_asset="Material and Economic Resources",
          fn=_atk_ev_drain),
]


def find_skill(name: str) -> Skill | None:
    for s in DEFENSE_SKILLS + ATTACK_SKILLS:
        if s.name == name:
            return s
    return None
