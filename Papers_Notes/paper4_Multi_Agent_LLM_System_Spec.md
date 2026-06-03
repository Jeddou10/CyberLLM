# Paper 4 — Specification and Evaluation of Multi-Agent LLM Systems (Härer, 2025)

> arXiv:2506.10467v1 — "Specification and Evaluation of Multi-Agent LLM
> Systems — Prototype and Cybersecurity Applications", Felix Härer, FHNW.
> GitHub: <https://github.com/fhaer/multi-agent-llm-system>

This is the **most directly reusable** paper for the project. It gives a
concrete architecture, a schema-based agent specification language, and
working cybersecurity test cases. Treat this as the *engineering
backbone* of CyberLLM.

---

## 1. What to take away

A multi-agent LLM system can be specified declaratively with four building
blocks:

| Concept              | What it is                                                                                                       |
|----------------------|------------------------------------------------------------------------------------------------------------------|
| **Agent Type**       | A named role with `prompts`, `actions`, and `data` (key/value).                                                  |
| **Functions**        | `execution-functions` (run a shell / Python / tool command) and `evaluation-functions` (decide if result is OK). |
| **Agent Config**     | Binds an agent type to an LLM config + runtime data.                                                             |
| **LLM Config**       | The LLM endpoint (OpenAI API, Ollama, Replicate, …) and parameters.                                              |

This is exactly the design pattern we adopt in `../CyberLLM/`.

---

## 2. Execution architecture (Figure 1 of paper)

```
┌────────────────────────────────────────────────────────────────────┐
│  Client Application                                                │
│                                                                    │
│  ┌────────────┐  ┌──────────────┐  ┌────────────┐  ┌────────────┐  │
│  │   Agent    │  │ Conversation │  │ Execution  │  │   LLM      │  │
│  │  Manager   │─►│   Manager    │─►│   Engine   │─►│  Services  │  │
│  └────────────┘  └──────────────┘  └────────────┘  └────────────┘  │
│        ▲                                  │                        │
│        │                                  ▼                        │
│  ┌────────────┐                  ┌──────────────────┐              │
│  │  Conversa- │                  │  Host Execution  │              │
│  │ tional UI  │                  │  Environment     │              │
│  └────────────┘                  │  (shell/python)  │              │
│                                  └──────────────────┘              │
└────────────────────────────────────────────────────────────────────┘
```

**Stack-based execution loop.** For each agent on the stack:
1. Pop the top prompt → send to LLM via Conversation Manager.
2. LLM responds → response stored in the agent's data dict.
3. All `execution-functions` referenced by the prompt run (e.g.
   `extract-code`, `evaluate-syntax-shell`, `execute-shell`).
4. All `evaluation-functions` run (e.g. `verify-file` with sha256).
5. The evaluation outcome decides which prompt is activated next, or
   which agent is invoked next.

This is the loop we implement in `CyberLLM/pipeline.py`.

---

## 3. Agent schema (the part to copy)

JSON-style schema, taken directly from the paper's Listing 1:

```json
[
  {
    "id": "Security-Q&A-Agent",
    "prompts": [{
      "prompt": "In TCP/IP networking, which protocol …",
      "answers": { "A": "HTTP", "B": "IP", "C": "TCP", "D": "UDP" },
      "answer": "B"
    }],
    "prompt-template": "Question: [question]\nOptions:\nA) [answers/A] …",
    "evaluate": {
      "result-classes": [
        { "class": "A", "pattern": "ANSWER: A",
          "eval-expected": "correct", "eval-unexpected": "incorrect" }
      ]
    }
  },
  {
    "id": "Network-Security-Agent",
    "prompts": [{
      "prompt": "Scan the local network [ipv4-network] for reachable hosts …",
      "actions": ["write-to-file", "extract-ip-scan-results"],
      "expected-value": "10.11.1.24"
    }],
    "actions": ["write-to-file", "extract-code",
                "evaluate-syntax-shell", "execute-shell"],
    "data": {
      "report-file": "network-report.txt",
      "ipv4-network": "10.1.1.0/24"
    }
  }
]
```

Key design points to copy:

- **Templating with placeholders** like `[ipv4-network]` filled from the
  agent's `data` dict at runtime ⇒ this is poor-man's RAG and works very
  well for cybersecurity inputs (IP ranges, file paths, signal names).
- **Action chaining** via the `actions` list — `extract-code` →
  `evaluate-syntax-shell` → `execute-shell` is exactly what we want for
  generated nmap / iptables / Python scripts.
- **Evaluation classes** map regex patterns (`"ANSWER: A"`,
  `"expected-value": "10.11.1.24"`) to a label (`correct` / `incorrect`).

---

## 4. Agent-to-agent invocation (multi-agent)

Listing 2 of the paper shows a Server-Security-Agent calling an
Audit-Report-Agent and passing data:

```json
{
  "id": "Server-Security-Agent",
  "prompts": [{
    "prompt": "…",
    "invoke": {
      "agent-of-type": "Audit-Report-Agent",
      "prompt-id": 1,
      "data-keys": ["ipv4-address", "ipv4-network", "scan-result"]
    }
  }]
},
{
  "id": "Audit-Report-Agent",
  "prompts": [{
    "prompt": "Create a report of the findings for the server with IP
               address [ipv4-address] in the network [ipv4-network].
               Consider each of the hosts found in the scan result …
               Scan result:\n\n[scan-result]"
  }]
}
```

We reuse this pattern: a `DecisionAgent` invokes a `LogAnalyzerAgent`,
passes the log excerpt + parsed events, and the analyzer returns a
finding object.

---

## 5. Cybersecurity test cases (paper §IV)

The paper validates the framework on three task families — these are
useful directly as initial **defense skills** for CyberLLM:

| Family                  | Concrete task                                                                                  |
|-------------------------|------------------------------------------------------------------------------------------------|
| Cyber Q&A               | 10 questions from the **CyberMetric** dataset; pure knowledge test.                            |
| Server-Security tasks   | 4 tasks: assess firewall config, generate system report, etc., on Ubuntu 24.04.                |
| Network-Security tasks  | 4 tasks: generate a Python nmap script, execute it, extract reachable hosts.                    |

Reasoning chain + RAG-style templating + script execution + result
evaluation is exactly the pipeline we copy.

**Results to remember when picking your LLM:** GPT-4o, o1-preview and
DeepSeek-R1 completed **all 12 tasks correctly**. The small distilled
8B model (R1D) failed 2/4 server-security tasks (wrong shell command,
incomplete report). Implication: a small local model is *usable* for
Q&A and network scan generation, but the larger models matter for tasks
that need precise shell syntax.

---

## 6. Reasoning chains and constraints

The paper insists on two prompting techniques that we should bake in:

1. **Constraint prompting** — request a specific output type (IPv4
   address, Python code, JSON), enforce it with a regex / syntax check
   before execution. Lower hallucinations, easy to verify automatically.
2. **Reasoning chains** — predefined prompt sequence with conditional
   branching (`invoke` on result class). This is more controllable than
   "free CoT" and easier to evaluate.

---

## 7. Why this paper is the backbone

- It gives us a **schema** that fits our diagram one-to-one:
  - Agent Manager / Conversation Manager / Execution Engine map to our
    `DecisionAgent` orchestrator.
  - Execution / Evaluation functions map to MCP-tool calls + result
    classifiers.
- It demonstrates **on cybersecurity tasks** that this design works on
  state-of-the-art and on small local LLMs (Ollama-deployable).
- The agent-of-type invocation pattern is exactly what we need for
  "scanner agents → decision agent → action agent".

**Carry into CyberLLM:** JSON agent schema, prompt templating with
`[placeholder]`, action chains, evaluation classes, agent-to-agent
invocation, optional reasoning-model agents (DeepSeek-R1, o1) for the
hardest decisions.
