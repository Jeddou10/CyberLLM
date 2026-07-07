# `tools/tokens.py` — dependency-free token estimation & budgeting

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

A small, **dependency-free** estimator of how many tokens a prompt will cost,
plus a `TokenBudget` that flags prompts over a threshold. The motivation is from
P3 (TUM): prompt quality degrades and content "bleeds" once a prompt exceeds the
model's comfortable window (they used ~4096 tokens). CyberLLM's hard rule is
"PyYAML is the only mandatory dependency," so rather than ship a real tokenizer
it uses a deliberately **conservative heuristic** (rounds up) to warn *before* a
prompt is sent. This is a **static** check — it inspects the string, never calls
the model.

Used by `BaseAgent.call_llm` to attach a one-line over-budget warning to the run
log.

---

## 2. Imports — lines 19–22

| line | import | why |
|------|--------|-----|
| 21 | `math` | `ceil` to round the estimate up. |
| 22 | `re` | Count whitespace-separated words. |

Module constants (28–31): `_CHARS_PER_TOKEN = 3.5` and `_TOKENS_PER_WORD = 1.3`
— blended ratios chosen because our prompts are code/JSON-heavy (punctuation
dense ⇒ fewer chars per token than prose). `_WORD_RE = \S+` matches word runs.

---

## 3. Walkthrough

### `estimate_tokens(text)` — lines 34–40
- **What:** estimate token count with no model/network.
- **How:** compute a char-based estimate (`len/3.5`) and a word-based estimate
  (`words × 1.3`), then take the **larger** and round up (`ceil`). Taking the
  max means we never *under*-count — better to warn early than overflow silently.
- 36–37 — empty text → 0 (avoids a divide/`ceil` on nothing).

### `class TokenBudget` — lines 43–71
- **`__init__` (52–57):** stores `max_prompt_tokens` (default 4096, the P3 figure) and running counters: `total_tokens`, `prompts_seen`, `over_budget_prompts`, and a `warnings` list.
- **`account(prompt, label)` (59–71):** estimate the prompt's tokens, add to the running total, increment `prompts_seen`, and if it exceeds the budget, increment `over_budget_prompts` and append a human warning suggesting RAG (P3 §III) instead of inlining rules/code. **Crucially it does not block** — it returns the count and surfaces the risk, leaving the decision to the operator.

---

## 4. Edge cases, gotchas & design decisions

- **Conservative by design.** Using `max(char_est, word_est)` + `ceil` biases toward *over*-estimating, so a borderline-large prompt is flagged rather than missed.
- **Advisory, not enforcing.** It never refuses a call; it annotates the run log. The pipeline still runs, so a big prompt doesn't break a demo — it just warns.
- **No tokenizer dependency.** This is a deliberate trade-off: a heuristic that's "good enough to warn" keeps the install to PyYAML only. If exact accounting were ever needed you'd swap in the model's real tokenizer here without touching callers.
