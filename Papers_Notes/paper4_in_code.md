# Paper 4 → Code: where every concept lands

> Felix Härer, *"Specification and Evaluation of Multi-Agent LLM
> Systems — Prototype and Cybersecurity Applications"*,
> arXiv:2506.10467v1 (2025).

Paper 4 is the **engineering backbone** of CyberLLM. Almost every
structural decision in the codebase comes from Härer's schema-driven
design. Below is a one-to-one mapping between the paper's concepts
and the files / functions / lines that implement them.

---

## 1. Architecture overview — Figure 1 of the paper

The paper describes a *Client Application* with four sub-systems:

| Paper concept (§III-B Fig. 1)   | Where it lives in CyberLLM                                                                                                          |
|---------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| **Agent Manager**               | The orchestration in [pipeline.py:run_pipeline](../CyberLLM/pipeline.py#L125) — instantiates and runs agents.                       |
| **Conversation Manager**        | Inside each agent's `run()` method: builds the prompt via `template()` then calls `self.llm.complete(prompt)`.                      |
| **Execution Engine**            | Same `run_pipeline` — calls scanner agents in sequence, then `DecisionAgent`, then `ActionGenerator`.                                |
| **Host Execution Environment**  | [tools/mcp_tools.py](../CyberLLM/tools/mcp_tools.py) — `PortScanTool.run`, `StaticAnalysisTool.run`, `PacketCaptureTool.run`.        |
| **LLM Services**                | [llm_client.py](../CyberLLM/llm_client.py) — `LLMClient` with `StubLLM` / `OpenAILLM` / `AnthropicLLM` / `OllamaLLM` subclasses.     |
| **Conversational UI**           | Not implemented (we use CLI + memory/ JSON dumps). Replaceable later.                                                                |

We deliberately **flattened** the literal stack-based execution into a
deterministic sequence of agent calls — it's easier to reason about
for the first pipeline and equivalent for the use cases we care about.

---

## 2. Agent Schema — Listing 1 of the paper

The paper's JSON schema has four building blocks:

```text
Agent Schema ⊃ { Agent Types, Functions, Agent Configurations, LLM Configurations }
```

We mirror that block-for-block, in YAML for readability:

### 2.1 Agent Types — paper §III-C

Paper:
```json
{ "id": "Security-Q&A-Agent", "prompts": [...], "actions": [...], "data": [...] }
```

Code: one Python class per agent type, each carrying its own
prompt template, action chain, and data dict.

| Paper field         | Where in our code                                                                                          |
|---------------------|------------------------------------------------------------------------------------------------------------|
| `id` / type name    | The class name + `agent_id` arg, e.g. [SourceCodeScannerAgent](../CyberLLM/agents/source_code_scanner.py). |
| `prompts`           | The class-level `PROMPT` string, e.g. [log_analyzer.py:14-25](../CyberLLM/agents/log_analyzer.py#L14-L25). |
| `actions`           | The body of each agent's `run()` method — call LLM, parse JSON, return findings.                           |
| `data` (key/value)  | [BaseAgent.data](../CyberLLM/agents/base_agent.py#L52) — populated before each prompt is templated.        |

### 2.2 Functions (execution + evaluation) — paper §III-C

Paper:
- **Execution Functions** — runnable commands (`copy-file`, `evaluate-syntax-shell`, `execute-shell`).
- **Evaluation Functions** — match outputs to expected classes (`verify-file` with sha256).

Code:

| Paper concept              | Where in our code                                                                                                                       |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| Execution Functions        | [tools/mcp_tools.py](../CyberLLM/tools/mcp_tools.py) — each tool exposes `run(**kwargs) → dict`. Today these are stubs; swap for `nmap`, `bandit`, `tcpdump` when ready. |
| Skill catalogue (extension)| [skills/skills.py](../CyberLLM/skills/skills.py) — each `Skill` has a callable `fn`; defense + attack skills both follow this shape.    |
| Evaluation Functions       | [BaseAgent._parse_findings](../CyberLLM/agents/base_agent.py#L65) extracts structured findings; [DecisionAgent._parse_decision](../CyberLLM/agents/decision_agent.py#L75) extracts the decision JSON; [SecurityGuard.check](../CyberLLM/agents/security_guard.py) decides allow/refuse. |
| Result-class pattern match | Instead of regex `result-classes`, every prompt mandates **strict JSON** (`Return JSON: {"findings": ...}`). A schema is a stricter form of pattern matching. |

### 2.3 Agent Configurations — paper §III-C

Paper:
```json
{ "file-broker-ag": { "LLM-Config.": "gpt4o", ... } }
```

Code: [config.yaml:21-38](../CyberLLM/config.yaml#L21-L38) `agent_configs:`. Each
entry binds an agent type to an `llm:` config name and an explicit
`objective:` (the latter is our addition — feeds paper 1's H_p oracle).

### 2.4 LLM Configurations — paper §III-C

Paper:
```json
{ "gpt4o": { ... } }, { "codeLlama": { ... } }
```

Code: [config.yaml:9-19](../CyberLLM/config.yaml#L9-L19) `llm_configs:` —
provider, model, temperature, max_tokens. Two named configs
(`default`, `reasoning`) match the paper's separation between fast
models and reasoning models (paper §II "DeepSeek R / OpenAI o variants").

---

## 3. Templating with `[placeholder]` — paper §III-C "Prompt-Template"

The paper's `prompt-template` substitutes `[question]`, `[answers/A]`, etc.
We copy this verbatim:

- Implementation: [BaseAgent.template](../CyberLLM/agents/base_agent.py#L56-L62)
- Examples of placeholders in real prompts:
  - `[code]`, `[filename]`, `[rules]` in [source_code_scanner.py](../CyberLLM/agents/source_code_scanner.py)
  - `[log]`, `[rules]` in [log_analyzer.py](../CyberLLM/agents/log_analyzer.py)
  - `[deployment]`, `[rules]` in [deployment_scanner.py](../CyberLLM/agents/deployment_scanner.py)
  - `[findings]`, `[assets]`, `[tiers]` in [decision_agent.py](../CyberLLM/agents/decision_agent.py)
  - `[result]`, `[code]` in [action_generator.py](../CyberLLM/agents/action_generator.py)

The substitution rule (regex `\[([a-zA-Z0-9_/-]+)\]` matched against
`self.data`) is the same idea as the paper's nested key reference
`[answers/A]`.

---

## 4. Stack-based execution loop — paper §III-B

The paper describes:

```
1. Pop top prompt → LLM (Conversation Manager)
2. Topmost agent receives response
3. Agent executes all specified functions (HEE)
4. Agent runs evaluation functions
5. Result decides which prompt (or which agent) runs next
```

Our [pipeline.run_pipeline](../CyberLLM/pipeline.py#L125) is the
flattened equivalent — each agent's `run()` performs steps 1–4
internally; the orchestrator does step 5 (which agent runs next)
deterministically:

```
SourceCodeScanner  ─┐
LogAnalyzer        ─┼──►  DecisionAgent  ──►  ActionGenerator  ──►  SecurityGuard
DeploymentScanner  ─┘
```

The `Decision` value drives the next-agent choice (paper 4's "result
class applies" condition) — see
[ActionGenerator.generate](../CyberLLM/agents/action_generator.py),
which branches on `decision.recommended_tier` to pick a soft / moderate
/ hard / patch-code action.

---

## 5. Agent-of-type invocation with data hand-off — paper §IV-B Listing 2

Paper:
```json
"invoke": {
  "agent-of-type": "Audit-Report-Agent",
  "prompt-id": 1,
  "data-keys": ["ipv4-address", "ipv4-network", "scan-result"]
}
```

We use the same pattern in two places:

- [DecisionAgent.run](../CyberLLM/agents/decision_agent.py#L59) accepts
  the three scanner `AgentResult`s and re-renders them as
  `data["findings"]` (the equivalent of "data-keys").
- [ActionGenerator.generate](../CyberLLM/agents/action_generator.py)
  is invoked by the orchestrator with `decision` + the vulnerable
  code's text — same handoff shape.

When you wire in a real LLM, you can extend this so the **Decision
Agent itself** issues an `invoke` instruction in its JSON output, just
like the paper's Server-Security-Agent invoking Audit-Report-Agent.

---

## 6. Provider abstraction — paper §III-A requirement 1

Paper requirement 1: *"Specification of the access to open source and
commercial LLMs through interfaces and parameters with an API or a
local LLM runtime such as Ollama."*

Code: [LLMClient.create](../CyberLLM/llm_client.py#L24) dispatches on
`provider:` and returns the right subclass:

- [StubLLM](../CyberLLM/llm_client.py#L43) — deterministic offline default.
- [OpenAILLM](../CyberLLM/llm_client.py#L136) — OpenAI API.
- [AnthropicLLM](../CyberLLM/llm_client.py#L156) — Anthropic API.
- [OllamaLLM](../CyberLLM/llm_client.py#L172) — local Ollama runtime.

This is exactly the paper's "external LLM services with common APIs
… in addition to local LLM applications such as Ollama" (§III-B).

---

## 7. Reasoning models for hard sub-tasks — paper §IV §II

Paper §II: DeepSeek-R / OpenAI-o models have "the ability to produce
one or multiple subsequent answers" and "evaluate the answers in a
subsequent reasoning step". The paper's eval shows GPT-4o and
DeepSeek-R1 handle Server-Security tasks better than a small distilled
model.

Code: we expose this as a **second** LLM config:

```yaml
llm_configs:
  default:    { provider: stub, model: stub-echo, ... }
  reasoning:  { provider: stub, model: stub-reasoning, ... }

agent_configs:
  decision_agent:
    llm: reasoning            # the hardest reasoning step uses the reasoning model
```

When you switch providers, the natural pairing is `default → gpt-4o-mini`
or `llama3.1:8b`, `reasoning → gpt-4o`, `o1-preview`, or `deepseek-r1`.

---

## 8. Constraint prompting — paper §IV-B-1

The paper says (§IV-B):

> "Constraints reduce the solution space and narrow possible answers
> by specifying aspects of the response structure or content. … e.g.,
> requesting and requiring a response in a specific data type such as
> an IPv4 address, a language such as python, or a data format such
> as JSON."

Every prompt template in our codebase ends with a JSON contract.
Examples:

- Scanners: `Return JSON: {"findings": [{"rule_id": "...", "severity": "...", "evidence": "...", "explanation": "..."}, ...]}`
- Decision agent: `Return JSON: {"summary": "...", "asset_categories_touched": [...], "recommended_tier": "soft|moderate|hard|none", "confidence": <float>, "justification": "..."}`

Combined with [_parse_findings](../CyberLLM/agents/base_agent.py#L65)
(robust to markdown code fences), this matches the paper's
"replication of the structure or syntax tends to be replicated and
instantiated correctly by the LLM" observation.

---

## 9. Reasoning chains across agents — paper §IV-B-2

Paper §IV-B-2: chained agents accumulate context (`ipv4-address`,
`ipv4-network`, `scan-result`) across multiple prompts before invoking
a specialised report agent.

Our chain (live today):

```
inputs ── code/log/deployment ──►  scanners
                                     │
                                     ▼ {findings}
                                  DecisionAgent
                                     │
                                     ▼ {tier, confidence, assets}
                                  ActionGenerator
                                     │
                                     ▼ {action, parameters}
                                  SecurityGuard ──►  commit or refuse
```

Each step accumulates structured data the next step depends on — the
direct analogue of the paper's Server-Security-Agent → Audit-Report-Agent
chain (Listing 2).

---

## 10. Cybersecurity test cases — paper §IV-A and §IV-B

The paper validates the framework on three task families. We reuse
this taxonomy when designing the example library:

| Paper task family             | Where in our examples                                                                                                 |
|-------------------------------|------------------------------------------------------------------------------------------------------------------------|
| Q&A on CyberMetric            | Future Phase G.1 in [improvements_and_exploration.md](../CyberLLM/improvements_and_exploration.md).                    |
| Server-Security (Ubuntu)      | `examples/medium/ev_charging_api/` — a Flask backend with config / auth / SQL issues.                                  |
| Network-Security (nmap)       | `examples/small/02_can_gateway.py` + `examples/logs/03_can_injection.log`; stub tool in `tools/mcp_tools.py:PortScanTool`. |
| Audit-Report-Agent (Listing 2)| Implicitly: `DecisionAgent` summary + `ActionGenerator` "patch_code" output play the audit-report role.                |

The paper's empirical findings ("R1D fails the firewall command but
the larger models all complete it") inform our LLM-config split into
`default` (cheap) and `reasoning` (heavy) and our recommendation in
Phase A.3 of the improvements doc.

---

## 11. The `--example` batch runner — paper §IV results table

The paper presents Table I — per-agent, per-LLM, per-task pass/fail
counts. Our `python pipeline.py --example all` produces an analogous
table:

```
scenario               files  findings tier       conf  guard   action
----------------------------------------------------------------------
clean_auth                 1         …  …          …    PASS    …
can_gateway                1         …  …          …    PASS    …
ev_charging_api            5         …  …          …    PASS    …
adas_decision              4         …  …          …    PASS    …
fleet_management          20         …  …          …    PASS    …
```

This is implemented in
[pipeline.run_example_batch](../CyberLLM/pipeline.py#L284) and is
deliberately shaped like the paper's evaluation harness so the same
benchmark methodology drops in (Phase G).

---

## 12. What we deliberately did NOT copy from Paper 4

For completeness, here is what we left out of v1 and why:

| Paper feature                                   | Why we skipped it (for now)                                                                                  |
|-------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| Literal stack-based execution with push/pop     | Sequential `run_pipeline` is easier to debug and equivalent for our DAG-shaped workflow.                     |
| `result-classes` with regex `pattern`           | Replaced by strict JSON parsing — stronger and easier to verify.                                              |
| Conversational UI                               | CLI + `memory/*.json` audit logs are enough for the first pipeline; a UI is purely cosmetic at this stage.   |
| `prompt-id` numeric references                  | Replaced by direct Python method names; small project, no need for indirection.                              |
| Replicate as a provider                         | Only ship OpenAI / Anthropic / Ollama; Replicate is one extra subclass when you actually need it.            |
| Per-agent persistent conversation context       | Each invocation is stateless; persistent context will arrive in Phase E together with paper 5's memory loop. |

---

## 13. Cheat-sheet — "I want to do X, which paper-4 idea applies?"

| You want to…                                            | Read paper section                | Edit / extend file                                                                            |
|---------------------------------------------------------|-----------------------------------|------------------------------------------------------------------------------------------------|
| Add a new agent type                                    | §III-C "Agent Schema"             | New file under [agents/](../CyberLLM/agents/), inherit from `BaseAgent`. Add to `config.yaml`. |
| Add a new external tool (nmap, bandit, …)               | §III-B "Host Execution Env."      | [tools/mcp_tools.py](../CyberLLM/tools/mcp_tools.py).                                          |
| Add a new LLM provider                                  | §III-A Req. 1                     | New subclass in [llm_client.py](../CyberLLM/llm_client.py); register in `LLMClient.create`.    |
| Wire an agent to invoke another agent                   | §IV-B Listing 2                   | Pattern is already in [decision_agent.py](../CyberLLM/agents/decision_agent.py).               |
| Tighten output format with a JSON contract              | §IV-B-1 "Constraints"             | Add the contract to your agent's `PROMPT` string.                                              |
| Run a benchmark like Table I                            | §IV                               | Extend [example_sets:](../CyberLLM/config.yaml) and run `--example all`.                       |

---

## TL;DR

Paper 4 gives us:

1. The **agent schema** (Agent Types × Functions × Agent Configs × LLM Configs) — copied directly into `config.yaml` + `BaseAgent`.
2. **`[placeholder]` templating** — same syntax, same semantics, in `BaseAgent.template`.
3. **Provider-agnostic LLM access** with first-class local Ollama support — in `LLMClient`.
4. **Reasoning vs default model split** — `llm_configs.reasoning` for the hardest step (decision agent).
5. **Agent-of-type invocation with structured data hand-off** — between scanners → decision → action generator.
6. **Strict-JSON constraint prompting** — every agent prompt.
7. **A cybersecurity-task evaluation shape** — `--example` + the batch summary table mirrors the paper's Table I.

Everything else in the codebase is either the *defensive shape* from
paper 5, the *threat model* from paper 2, the *event-chain / OCL
rules* from paper 3, or the *contextual security checks* from paper 1.
But the executable backbone — what makes `python pipeline.py` actually
run — is paper 4.
