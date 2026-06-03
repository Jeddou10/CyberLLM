"""Tests for token estimation (A.4) and the graceful LLM fallback (A.2)."""

from __future__ import annotations

import pytest

from llm_client import LLMClient, StubLLM
from tools.tokens import TokenBudget, estimate_tokens


class TestTokenEstimate:

    def test_empty_is_zero(self):
        assert estimate_tokens("") == 0

    def test_monotonic_in_length(self):
        short = estimate_tokens("hello world")
        long = estimate_tokens("hello world " * 100)
        assert long > short

    def test_budget_flags_over_threshold(self):
        b = TokenBudget(max_prompt_tokens=10)
        b.account("a small prompt", label="x")          # under
        assert b.over_budget_prompts == 0
        b.account("word " * 500, label="big")           # over
        assert b.over_budget_prompts == 1
        assert b.warnings and "exceeds budget" in b.warnings[0]
        assert b.prompts_seen == 2
        assert b.total_tokens > 0


class TestLLMFallback:

    def test_openai_without_key_falls_back_to_stub(self, monkeypatch):
        # Opt out of the hermetic force-stub so the real fallback path runs.
        monkeypatch.delenv("CYBERLLM_FORCE_STUB", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.warns(RuntimeWarning):
            client = LLMClient.create({"provider": "openai", "model": "gpt-4o"})
        assert isinstance(client, StubLLM)

    def test_anthropic_without_key_falls_back_to_stub(self, monkeypatch):
        monkeypatch.delenv("CYBERLLM_FORCE_STUB", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            client = LLMClient.create({"provider": "anthropic", "model": "x"})
        assert isinstance(client, StubLLM)

    def test_stub_is_returned_directly(self):
        assert isinstance(
            LLMClient.create({"provider": "stub", "model": "x"}), StubLLM)


class TestGitHubModelsProvider:

    def test_placeholder_token_falls_back_to_stub(self, monkeypatch):
        monkeypatch.delenv("CYBERLLM_FORCE_STUB", raising=False)
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_REPLACE_WITH_YOUR_GITHUB_TOKEN")
        with pytest.warns(RuntimeWarning):
            client = LLMClient.create({"provider": "github", "model": "gpt-4o"})
        assert isinstance(client, StubLLM)

    def test_force_stub_overrides_github(self, monkeypatch):
        monkeypatch.setenv("CYBERLLM_FORCE_STUB", "1")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_aRealLookingToken0123456789")
        client = LLMClient.create({"provider": "github", "model": "gpt-4o"})
        assert isinstance(client, StubLLM)

    def test_real_token_builds_github_client(self, monkeypatch):
        from llm_client import GitHubModelsLLM
        monkeypatch.delenv("CYBERLLM_FORCE_STUB", raising=False)
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_aRealLookingToken0123456789")
        client = LLMClient.create({"provider": "github", "model": "gpt-4o"})
        assert isinstance(client, GitHubModelsLLM)
        assert client.cfg["model"] == "gpt-4o"


class TestAzureProvider:

    def test_placeholder_falls_back_to_stub(self, monkeypatch):
        monkeypatch.delenv("CYBERLLM_FORCE_STUB", raising=False)
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT",
                           "https://REPLACE-YOUR-RESOURCE.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY",
                           "REPLACE_WITH_YOUR_AZURE_OPENAI_KEY")
        with pytest.warns(RuntimeWarning):
            client = LLMClient.create({"provider": "azure", "model": "gpt-4o"})
        assert isinstance(client, StubLLM)

    def test_force_stub_overrides_azure(self, monkeypatch):
        monkeypatch.setenv("CYBERLLM_FORCE_STUB", "1")
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://r.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "realkey0123456789")
        client = LLMClient.create({"provider": "azure", "model": "gpt-4o"})
        assert isinstance(client, StubLLM)

    def test_real_creds_build_azure_client_and_url(self, monkeypatch):
        from llm_client import AzureOpenAILLM
        monkeypatch.delenv("CYBERLLM_FORCE_STUB", raising=False)
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT",
                           "https://myres.openai.azure.com/")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "realkey0123456789")
        monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "my-gpt4o")
        monkeypatch.setenv("AZURE_OPENAI_API_VERSION", "2024-10-21")
        client = LLMClient.create({"provider": "azure", "model": "gpt-4o"})
        assert isinstance(client, AzureOpenAILLM)
        assert client._url() == (
            "https://myres.openai.azure.com/openai/deployments/my-gpt4o"
            "/chat/completions?api-version=2024-10-21")

    def test_deployment_falls_back_to_model(self, monkeypatch):
        from llm_client import AzureOpenAILLM
        monkeypatch.delenv("CYBERLLM_FORCE_STUB", raising=False)
        monkeypatch.delenv("AZURE_OPENAI_DEPLOYMENT", raising=False)
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://r.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "realkey0123456789")
        client = LLMClient.create({"provider": "azure", "model": "gpt-4o"})
        assert isinstance(client, AzureOpenAILLM)
        assert "/deployments/gpt-4o/" in client._url()
