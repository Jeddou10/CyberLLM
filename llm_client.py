"""LLM client abstraction.

Mirrors the LLM-Config block of the Härer agent schema (paper 4).
Ships with a deterministic stub provider so the first pipeline runs
out-of-the-box; swap in OpenAI / Anthropic / Ollama later by
implementing a new subclass and registering it in `LLMClient.create`.
"""

from __future__ import annotations
from dataclasses import dataclass
import json
import re
from typing import Any


@dataclass
class LLMResponse:
    text: str
    raw: Any = None


class LLMClient:
    @staticmethod
    def create(cfg: dict) -> "LLMClient":
        provider = cfg.get("provider", "stub").lower()
        if provider == "stub":
            return StubLLM(cfg)
        if provider == "openai":
            return OpenAILLM(cfg)
        if provider == "anthropic":
            return AnthropicLLM(cfg)
        if provider == "ollama":
            return OllamaLLM(cfg)
        raise ValueError(f"Unknown LLM provider: {provider}")

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def complete(self, prompt: str, system: str | None = None) -> LLMResponse:  # noqa: D401
        raise NotImplementedError


class StubLLM(LLMClient):
    """Deterministic offline stub.

    It looks for keywords in the prompt and returns plausible JSON so
    the full pipeline can run without any network access. Replace with
    a real provider once you have credentials / Ollama installed.
    """

    def complete(self, prompt: str, system: str | None = None) -> LLMResponse:
        p = prompt.lower()
        # Order matters — the decision-agent prompt contains the strings
        # "source_code_scanner" / "log analyzer" / "deployment" too, so
        # the decision branch must be checked first.
        if "central decision agent" in p and "asset_categories_touched" in p:
            decision = {
                "summary": "Multiple high-severity findings; one likely active brute-force; topology rule violations.",
                "asset_categories_touched": [
                    "Material and Economic Resources",
                    "Privacy and Personal Data",
                    "Life and Bodily Health",
                ],
                "recommended_tier": "moderate",
                "confidence": 0.72,
                "justification": (
                    "Authenticated scanner agents flagged 6 findings (3 high, "
                    "3 medium); trajectory and action alignment hold; source "
                    "authorization OK. Tier 'moderate' chosen — confidence "
                    "above moderate_threshold (0.65) but below hard (0.85)."
                ),
            }
            return LLMResponse(text=json.dumps(decision, indent=2))

        if "source-code security scanner" in p or "scan code" in p or (
                "source code" in p and "rule_id" in p):
            findings = [
                {"rule_id": "CODE-001", "severity": "high",
                 "line": 14, "evidence": "subprocess.call(user_input, shell=True)",
                 "explanation": "Shell-injection sink fed by untrusted input."},
                {"rule_id": "CODE-002", "severity": "medium",
                 "line": 22, "evidence": "hashlib.md5(password)",
                 "explanation": "Weak hash algorithm for password storage."},
            ]
            return LLMResponse(text=json.dumps({"findings": findings}, indent=2))

        if "log" in p and "anomal" in p:
            findings = [
                {"rule_id": "LOG-NET-01", "severity": "high",
                 "evidence": "10.0.0.42 → 10.0.0.255 :7000 burst 1200 pkts/s",
                 "explanation": "Sudden internal broadcast burst — possible reconnaissance."},
                {"rule_id": "LOG-AUTH-03", "severity": "medium",
                 "evidence": "12 failed auth attempts in 30 s, user='root'",
                 "explanation": "Brute-force pattern on privileged account."},
            ]
            return LLMResponse(text=json.dumps({"findings": findings}, indent=2))

        if "deployment" in p or "topology" in p:
            findings = [
                {"rule_id": "TOP-001", "severity": "high",
                 "evidence": "HighPerformanceComputer→ZoneECU on CAN (not Ethernet)",
                 "explanation": "Violates HPCtoZoneEthernetIEEE1722 architectural rule."},
                {"rule_id": "TOP-002", "severity": "medium",
                 "evidence": "External A2A agent has write-edge to long_term_memory",
                 "explanation": "Datasource is writable by an unauthenticated actor (poison path)."},
            ]
            return LLMResponse(text=json.dumps({"findings": findings}, indent=2))

        if "decide" in p or "decision" in p:
            decision = {
                "summary": "Two high-severity findings; one is a likely active brute-force.",
                "asset_categories_touched": [
                    "Material and Economic Resources",
                    "Privacy and Personal Data",
                ],
                "recommended_tier": "moderate",
                "confidence": 0.72,
                "justification": (
                    "Authenticated rules engine flagged 2 high-severity findings; "
                    "trajectory and action alignment hold; source authorization OK."
                ),
            }
            return LLMResponse(text=json.dumps(decision, indent=2))

        if "fix" in p or "correct" in p:
            fix = (
                "Replace `subprocess.call(user_input, shell=True)` with "
                "`subprocess.run(shlex.split(user_input), shell=False, check=True)` "
                "and validate `user_input` against an allow-list."
            )
            return LLMResponse(text=fix)

        return LLMResponse(text="ACK: " + re.sub(r"\s+", " ", prompt)[:200])


class OpenAILLM(LLMClient):
    def complete(self, prompt, system=None):  # pragma: no cover — wire up when you add a key
        try:
            from openai import OpenAI
        except ImportError as e:
            raise RuntimeError("Install the `openai` package to use this provider") from e
        client = OpenAI()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        resp = client.chat.completions.create(
            model=self.cfg["model"],
            messages=messages,
            temperature=self.cfg.get("temperature", 0.2),
            max_tokens=self.cfg.get("max_tokens", 1024),
        )
        return LLMResponse(text=resp.choices[0].message.content, raw=resp)


class AnthropicLLM(LLMClient):
    def complete(self, prompt, system=None):  # pragma: no cover
        try:
            import anthropic
        except ImportError as e:
            raise RuntimeError("Install the `anthropic` package to use this provider") from e
        client = anthropic.Anthropic()
        resp = client.messages.create(
            model=self.cfg["model"],
            max_tokens=self.cfg.get("max_tokens", 1024),
            system=system or "",
            messages=[{"role": "user", "content": prompt}],
        )
        return LLMResponse(text=resp.content[0].text, raw=resp)


class OllamaLLM(LLMClient):
    def complete(self, prompt, system=None):  # pragma: no cover
        import requests
        full = (system + "\n\n" if system else "") + prompt
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": self.cfg["model"], "prompt": full, "stream": False},
            timeout=120,
        )
        r.raise_for_status()
        return LLMResponse(text=r.json()["response"], raw=r.json())
