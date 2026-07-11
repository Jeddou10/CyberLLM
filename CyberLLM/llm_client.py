"""LLM client abstraction.

Mirrors the LLM-Config block of the Härer agent schema (paper 4).
Ships with a deterministic stub provider so the first pipeline runs
out-of-the-box; swap in OpenAI / Anthropic / Ollama later by
implementing a new subclass and registering it in `LLMClient.create`.
"""

from __future__ import annotations
from dataclasses import dataclass
import json
import os
import re
import urllib.error
import urllib.request
import warnings
from pathlib import Path
from typing import Any


@dataclass
class LLMResponse:
    text: str
    raw: Any = None


# Remember which fallback warnings we have already emitted so a batch
# run of many scenarios doesn't print the same message dozens of times.
_WARNED: set[str] = set()


def _warn_once(key: str, message: str) -> None:
    if key not in _WARNED:
        _WARNED.add(key)
        warnings.warn(message, RuntimeWarning, stacklevel=3)


# Which environment variable holds the credential for each cloud
# provider. If it is absent we fall back to the deterministic stub so
# CI / offline demos keep working (roadmap A.2: "keep stub as a CI
# fallback").
_PROVIDER_KEY_ENV = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}


# ---------------------------------------------------------------------------
# Minimal .env loader (zero-dependency).
# ---------------------------------------------------------------------------
_DOTENV_LOADED = False


def _load_dotenv_once() -> None:
    """Load `KEY=VALUE` pairs from a project-root `.env` into os.environ.

    Only sets keys that are not already present, so a real value exported
    in the shell always wins over the file. No python-dotenv dependency.
    """
    global _DOTENV_LOADED
    if _DOTENV_LOADED:
        return
    _DOTENV_LOADED = True
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


# Markers that identify a token left as the shipped placeholder. A token
# matching any of these is treated as "not configured" → stub fallback,
# so the suite / offline demos keep working until a real token is supplied.
_PLACEHOLDER_MARKERS = ("your_token", "your_github", "replace", "placeholder",
                        "changeme", "example", "<", ">")


def _looks_like_placeholder(value: str) -> bool:
    s = (value or "").strip().lower()
    return (not s) or any(m in s for m in _PLACEHOLDER_MARKERS)


class LLMClient:
    @staticmethod
    def create(cfg: dict) -> "LLMClient":
        _load_dotenv_once()
        provider = cfg.get("provider", "stub").lower()

        # Hermetic-test / offline escape hatch: when this is set we never
        # construct a network-backed client, regardless of config.
        if os.environ.get("CYBERLLM_FORCE_STUB") and provider != "stub":
            return StubLLM(cfg)

        if provider == "stub":
            return StubLLM(cfg)

        # ---- GitHub Models (gpt-4o via a GitHub token) ------------------
        if provider == "github":
            token_env = cfg.get("token_env", "GITHUB_TOKEN")
            token = os.environ.get(token_env, "")
            if _looks_like_placeholder(token):
                _warn_once(
                    "github:notoken",
                    f"LLM provider 'github' selected but {token_env} is "
                    f"unset or still the placeholder; falling back to the "
                    f"deterministic stub. Put a real GitHub token in .env "
                    f"to use {cfg.get('model', 'gpt-4o')} via GitHub Models.",
                )
                return StubLLM(cfg)
            return GitHubModelsLLM(cfg)

        # ---- Azure OpenAI Service (gpt-4o via a deployment) -------------
        if provider == "azure":
            key = os.environ.get(cfg.get("api_key_env", "AZURE_OPENAI_API_KEY"), "")
            endpoint = (cfg.get("endpoint")
                        or os.environ.get(cfg.get("endpoint_env",
                                                   "AZURE_OPENAI_ENDPOINT"), ""))
            if _looks_like_placeholder(key) or _looks_like_placeholder(endpoint):
                _warn_once(
                    "azure:noconfig",
                    "LLM provider 'azure' selected but AZURE_OPENAI_API_KEY / "
                    "AZURE_OPENAI_ENDPOINT is unset or still a placeholder; "
                    "falling back to the deterministic stub. Fill the "
                    "AZURE_OPENAI_* values in .env to use Azure OpenAI.",
                )
                return StubLLM(cfg)
            return AzureOpenAILLM(cfg)

        # ---- graceful credential fallback (A.2) -------------------------
        # For the cloud providers, refuse to construct a real client when
        # the API key is missing OR still a shipped placeholder — fall back
        # to the stub with a warning rather than crashing a whole batch run.
        key_env = _PROVIDER_KEY_ENV.get(provider)
        if key_env and _looks_like_placeholder(os.environ.get(key_env, "")):
            _warn_once(
                f"{provider}:nokey",
                f"LLM provider '{provider}' selected but {key_env} is unset "
                f"or still a placeholder; falling back to the deterministic "
                f"stub. Put a real {key_env} in .env to use the model.",
            )
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

        # ---- H_a action-alignment oracle (paper 1, roadmap F.1) ---------
        # Must precede the "fix"/"correct" branch because an objective of
        # "auto-correct insecure code" would otherwise be mis-routed.
        if "action-alignment oracle h_a" in p:
            m_obj = re.search(r"OBJECTIVE:\s*(.*)", prompt)
            m_act = re.search(r"ACTION:\s*(.*)", prompt)
            m_ctx = re.search(r"CONTEXT:\s*(.*)", prompt)
            objective = (m_obj.group(1).strip().lower() if m_obj else "")
            action = (m_act.group(1).strip() if m_act else "")
            context = (m_ctx.group(1).strip().lower() if m_ctx else "")
            privileged = {
                "patch_code", "isolate_node", "block_ip", "rate_limit",
                "segment_network", "secrets.rotate", "secrets.revoke",
                "runtime.safe_mode", "code.scrub_git_history",
            }
            report_only = {"produce findings report", "produce findings"}
            if action in privileged and objective in report_only:
                serves, reason = False, (
                    f"privileged action '{action}' does not serve "
                    f"report-only objective '{objective}'")
            elif "misaligned" in context or "trusted-asset" in context:
                serves, reason = False, ("context indicates the action does "
                                         "not serve the objective")
            else:
                serves, reason = True, (
                    f"action '{action}' is consistent with objective "
                    f"'{objective}'")
            return LLMResponse(text=json.dumps(
                {"serves": serves, "reason": reason}))

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


class GitHubModelsLLM(LLMClient):
    """GitHub Models (https://github.com/marketplace/models).

    OpenAI-compatible inference authenticated with a GitHub token. We hit
    the `/chat/completions` endpoint directly with `urllib` so the
    provider needs no extra dependency (the `openai` SDK works too — just
    point its `base_url` at the same endpoint).

    Default endpoint is the GA endpoint `https://models.github.ai/inference`,
    where model ids are publisher-namespaced (e.g. `openai/gpt-5`). The
    legacy preview endpoint `https://models.inference.ai.azure.com` (bare
    ids like `gpt-4o`) can be selected via GITHUB_MODELS_ENDPOINT.
    """

    DEFAULT_ENDPOINT = "https://models.github.ai/inference"
    # How many times to retry on a 429 (free-tier rate limit) before giving up.
    MAX_RETRIES = 2

    @staticmethod
    def _is_reasoning_model(model: str) -> bool:
        """GPT-5 and the o-series use `max_completion_tokens` and reject a
        custom `temperature` — they need a different request shape."""
        name = model.split("/")[-1].lower()
        return name.startswith(("o1", "o3", "o4")) or name.startswith("gpt-5")

    def _build_body(self, messages: list) -> dict:
        model = self.cfg["model"]
        body = {"model": model, "messages": messages}
        max_out = int(self.cfg.get("max_tokens", 1024))
        if self._is_reasoning_model(model):
            # gpt-5 / o-series: renamed token param, fixed temperature.
            body["max_completion_tokens"] = max_out
        else:
            body["max_tokens"] = max_out
            body["temperature"] = self.cfg.get("temperature", 0.2)
        return body

    def complete(self, prompt, system=None):
        import time
        token_env = self.cfg.get("token_env", "GITHUB_TOKEN")
        token = os.environ.get(token_env, "")
        endpoint = (self.cfg.get("endpoint")
                    or os.environ.get("GITHUB_MODELS_ENDPOINT")
                    or self.DEFAULT_ENDPOINT).rstrip("/")
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        body = json.dumps(self._build_body(messages)).encode("utf-8")

        last_detail = ""
        for attempt in range(self.MAX_RETRIES + 1):
            req = urllib.request.Request(
                endpoint + "/chat/completions",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    data = json.loads(r.read().decode("utf-8"))
                return LLMResponse(
                    text=data["choices"][0]["message"]["content"], raw=data)
            except urllib.error.HTTPError as e:
                last_detail = e.read().decode("utf-8", "replace")[:500]
                # 429 = rate limited; honour Retry-After and try again.
                if e.code == 429 and attempt < self.MAX_RETRIES:
                    wait = e.headers.get("Retry-After")
                    delay = min(float(wait), 30.0) if (wait and wait.isdigit()) \
                        else 2.0 * (attempt + 1)
                    warnings.warn(
                        f"GitHub Models rate-limited (429); retrying in "
                        f"{delay:.0f}s ({attempt + 1}/{self.MAX_RETRIES})",
                        RuntimeWarning, stacklevel=2)
                    time.sleep(delay)
                    continue
                raise RuntimeError(
                    f"GitHub Models request failed ({e.code}) for model "
                    f"'{self.cfg['model']}'. Check the id exists in your "
                    f"catalog and {token_env} has Models access. "
                    f"Response: {last_detail}") from e
        raise RuntimeError(
            f"GitHub Models still rate-limited after {self.MAX_RETRIES} "
            f"retries. Response: {last_detail}")


class AzureOpenAILLM(LLMClient):
    """Azure OpenAI Service — chat completions (e.g. a gpt-4o deployment).

    Azure differs from vanilla OpenAI in three ways, all handled here:
      * the model is chosen by the **deployment name** in the URL path,
      * auth uses the `api-key` header (not `Authorization: Bearer`),
      * the request is versioned with `?api-version=`.
    gpt-4o is a standard (non-reasoning) model, so the usual `max_tokens`
    and `temperature` apply. Resolved from cfg first, then env:
      AZURE_OPENAI_ENDPOINT     e.g. https://my-resource.openai.azure.com
      AZURE_OPENAI_API_KEY
      AZURE_OPENAI_DEPLOYMENT   deployment name (falls back to cfg `model`)
      AZURE_OPENAI_API_VERSION  defaults to a recent GA version
    """

    DEFAULT_API_VERSION = "2024-10-21"
    MAX_RETRIES = 2

    def _resolved(self) -> tuple[str, str, str, str]:
        c = self.cfg
        endpoint = (c.get("endpoint")
                    or os.environ.get(c.get("endpoint_env",
                                            "AZURE_OPENAI_ENDPOINT"), "")
                    ).rstrip("/")
        deployment = (c.get("deployment")
                      or os.environ.get(c.get("deployment_env",
                                              "AZURE_OPENAI_DEPLOYMENT"), "")
                      or c.get("model", ""))
        api_version = (c.get("api_version")
                       or os.environ.get("AZURE_OPENAI_API_VERSION")
                       or self.DEFAULT_API_VERSION)
        key = os.environ.get(c.get("api_key_env", "AZURE_OPENAI_API_KEY"), "")
        return endpoint, deployment, api_version, key

    def _url(self) -> str:
        endpoint, deployment, api_version, _ = self._resolved()
        return (f"{endpoint}/openai/deployments/{deployment}"
                f"/chat/completions?api-version={api_version}")

    @staticmethod
    def _is_reasoning_model(deployment: str) -> bool:
        """gpt-5 and the o-series use `max_completion_tokens` and reject a
        custom `temperature`, so they need a different request shape."""
        name = deployment.split("/")[-1].lower()
        return name.startswith(("o1", "o3", "o4")) or name.startswith("gpt-5")

    def complete(self, prompt, system=None):
        import time
        endpoint, deployment, api_version, key = self._resolved()
        url = self._url()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload: dict[str, Any] = {"messages": messages}
        max_out = int(self.cfg.get("max_tokens", 1024))
        if self._is_reasoning_model(deployment):
            # gpt-5 / o-series: renamed token param, fixed temperature.
            payload["max_completion_tokens"] = max_out
        else:
            payload["max_tokens"] = max_out
            payload["temperature"] = self.cfg.get("temperature", 0.2)
        body = json.dumps(payload).encode("utf-8")

        timeout = float(self.cfg.get("timeout", 120))
        last_detail = ""
        for attempt in range(self.MAX_RETRIES + 1):
            req = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json", "api-key": key})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = json.loads(r.read().decode("utf-8"))
                return LLMResponse(
                    text=data["choices"][0]["message"]["content"], raw=data)
            except urllib.error.HTTPError as e:
                last_detail = e.read().decode("utf-8", "replace")[:500]
                if e.code == 429 and attempt < self.MAX_RETRIES:
                    wait = e.headers.get("Retry-After")
                    delay = min(float(wait), 30.0) if (wait and wait.isdigit()) \
                        else 2.0 * (attempt + 1)
                    warnings.warn(
                        f"Azure OpenAI rate-limited (429); retrying in "
                        f"{delay:.0f}s ({attempt + 1}/{self.MAX_RETRIES})",
                        RuntimeWarning, stacklevel=2)
                    time.sleep(delay)
                    continue
                raise RuntimeError(
                    f"Azure OpenAI request failed ({e.code}) for deployment "
                    f"'{deployment}' at {endpoint} (api-version "
                    f"{api_version}). Check the AZURE_OPENAI_* settings in "
                    f".env. Response: {last_detail}") from e
        raise RuntimeError(
            f"Azure OpenAI still rate-limited after {self.MAX_RETRIES} "
            f"retries. Response: {last_detail}")


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
            temperature=self.cfg.get("temperature", 1.0),
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
