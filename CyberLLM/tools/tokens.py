"""Dependency-free token estimation + per-prompt budgeting.

Why
---
Paper 3 (TUM) reports that prompt quality degrades and content "bleeds"
once a prompt grows past the model's comfortable window — they used a
4 096-token threshold for LLaMA-3.3 70B. We don't ship a tokeniser
dependency (the project's hard rule is "PyYAML is the only mandatory
dep"), so this module provides a *heuristic* estimator that is good
enough to raise an early warning before a prompt is sent.

The estimate is deliberately conservative (rounds up): it is better to
warn slightly early than to silently overflow the window.

This is a **static** check — it inspects the prompt string before any
LLM call and never executes anything.
"""

from __future__ import annotations

import math
import re

# A widely-used rule of thumb for English text is ~4 characters per
# token; for code / JSON (which our prompts are full of) the ratio is
# closer to ~3 because of punctuation density. We blend a char-based
# and a word-based estimate and take the larger so we never under-count.
_CHARS_PER_TOKEN = 3.5
_TOKENS_PER_WORD = 1.3

_WORD_RE = re.compile(r"\S+")


def estimate_tokens(text: str) -> int:
    """Heuristic token count for `text`. No model / network required."""
    if not text:
        return 0
    char_est = len(text) / _CHARS_PER_TOKEN
    word_est = len(_WORD_RE.findall(text)) * _TOKENS_PER_WORD
    return int(math.ceil(max(char_est, word_est)))


class TokenBudget:
    """Tracks cumulative token spend and flags prompts over a threshold.

    Used by `BaseAgent.call_llm` to attach a one-line warning to the
    run-log when a single prompt exceeds `max_prompt_tokens`. It does
    not block the call — it surfaces the risk so the operator can move
    that content into RAG (paper 3 §III) instead of inlining it.
    """

    def __init__(self, max_prompt_tokens: int = 4096):
        self.max_prompt_tokens = int(max_prompt_tokens)
        self.total_tokens = 0
        self.prompts_seen = 0
        self.over_budget_prompts = 0
        self.warnings: list[str] = []

    def account(self, prompt: str, *, label: str = "prompt") -> int:
        """Record a prompt, return its estimated token count, and append
        a warning to `self.warnings` if it is over budget."""
        n = estimate_tokens(prompt)
        self.total_tokens += n
        self.prompts_seen += 1
        if n > self.max_prompt_tokens:
            self.over_budget_prompts += 1
            msg = (f"{label}: ~{n} tokens exceeds budget "
                   f"{self.max_prompt_tokens} — consider RAG (paper 3) "
                   f"instead of inlining rules/code")
            self.warnings.append(msg)
        return n
