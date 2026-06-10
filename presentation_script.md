# CyberLLM — Presentation Script

> Read naturally, not word-for-word. Use these as your guide. Each slide has ~60-90 seconds of talking time.

---

## Slide 1 — Title

"Good morning/afternoon. My name is [NAME] and today I'll present CyberLLM — a multi-agent LLM system designed for automotive cybersecurity.

The system uses 12 specialized agents, over 20 tool integrations, and introduces several novel features: adaptive re-planning, an LLM-based tool selector, a dedicated alignment judge, and a cryptographically signed memory store.

Let me walk you through how we got here and what we built."

---

## Slide 2 — Agenda

"Here's the roadmap for today's talk.

We'll start with the motivation — why LLM agents are relevant for automotive cybersecurity. Then we'll cover the five research papers that ground our work. The main part is section three, where I'll walk through our architecture, the agents, the re-planning loop, and the security mechanisms. We'll see a real demo output, and I'll close with our limitations and future work.

Let's begin."

---

## Slide 3 — Motivation: The Problem & Our Approach

"Modern vehicles have over 100 million lines of code, multiple connected ECUs, and increasingly, in-vehicle LLM assistants — like BMW's IPA, VW's IDA, or Mercedes MBUX.

The critical issue: protocols like Google's Agent-to-Agent authenticate the *sender*, but not the *content*. So a compromised but properly authenticated agent can inject arbitrary payloads into the vehicle's decision pipeline.

ISO/SAE 21434 requires continuous automated monitoring — manual audits don't scale.

Our approach is: *static-first* — deterministic regex and heuristic rules always run, and the LLM only refines their output. We have specialized agents for code, logs, and deployment topology. We support both defense and red-team attack simulation. And every action is guarded by four contextual security properties.

The system works fully offline with a stub LLM and scales up to GPT-4o or Claude when available."

---

## Slide 4 — The Automotive Attack Surface

"Paper 2 from BMW and TUM identifies a new attack class: agent-to-agent threats.

Three concrete examples: First, *cognitive overload* — an agent enters a reasoning loop, bombarding the driver with questions while driving at highway speed. Research shows the cognitive effect lasts 27 seconds after the interaction ends.

Second, *data exfiltration* — a malicious memory rule says 'send GPS coordinates to an endpoint when outside temperature exceeds 25 degrees' — a steganographic trigger that's hard to detect.

Third, *RAG poisoning* — injecting biased knowledge that steers recommendations toward unsafe routes or competitor products.

The table shows the asset taxonomy from Paper 2, derived from the Universal Declaration of Human Rights. At the top: life and bodily health — brake tampering via CAN injection. This taxonomy is how our Decision Agent categorizes findings."

---

## Slide 5 — Related Work: 5 Foundational Papers

"Our work is grounded in five recent papers.

Paper 1 defines four formal security properties that every agent action must satisfy. We implement these as the SecurityGuard, and now also as the H-a judge oracle.

Paper 2 gives us the human-centric asset taxonomy and the formal attack-path model with poison paths and trigger paths — which our attack pipeline implements.

Paper 3 from TUM provides the design pattern: YAML rules feed a static analyzer, then an LLM refines the output, and the two are merged — static always wins on duplicates.

Paper 4 gives us the agent schema: each agent has an ID, prompt templates with placeholders, data bindings, and an LLM config reference. This is exactly our BaseAgent class.

Paper 5 provides the three-layer architecture — edge, orchestration, intelligence — plus tiered response and the adaptive learning loop, which we now implement as our re-planning mechanism and signed memory store."

---

## Slide 6 — Key Concepts We Adopt

"Let me zoom in on what we took from each paper.

From Paper 1: every action — at every granularity — must pass four checks: is the task in the allowed set? Does the action serve the objective? Are all inputs from authenticated sources? Does the output go only to trusted destinations? We added the H-a oracle — a separate LLM call that can only *tighten* the decision, never loosen it.

From Paper 3: the static-then-LLM-then-merge pattern. The static pass always runs, the LLM enriches it, and on conflicts, the deterministic result wins.

From Paper 5: the closed loop — detect, decide, act, observe, and if it didn't resolve, re-decide with escalated parameters.

From Paper 2: the memory-poisoning defense. We protect the incident store with HMAC signatures and source authentication, so a tampered or unauthenticated memory entry can never influence a future decision."

---

## Slide 7 — Architecture Overview

"Here's the high-level architecture.

The system is layered. At the top: inputs — source code, logs, deployment YAML. These enter the *edge layer* — three scanner agents running deterministic checks: 45 regex rules for code, 8 temporal heuristics for logs, 8 graph checks for deployment topology.

The *orchestration layer* is the Decision Agent, backed by a signed memory store. It recalls similar past incidents via Jaccard similarity, picks a response tier, and provides a confidence score.

The *action engine* takes that decision: a deterministic playbook provides the baseline steps, the LLM tool selector can propose additional tools, and the executor runs each step through the MCP registry.

The *guard layer* runs three levels of checks: per-step, final action, and trajectory-level. It includes the H-a judge.

If the guard refuses or the plan fails, the *re-planning loop* feeds the failure back and the decision agent escalates — up to 2 rounds.

Finally, everything is persisted: JSON records, run logs, and the signed incident database."

---

## Slide 8 — Defense Pipeline: Re-Planning + LLM Tool Selector

"Let me drill into the defense pipeline's two main innovations.

First: adaptive re-planning. It's a closed loop. The decision agent proposes a tier; the action engine realizes it; the guard checks it. If the plan status is 'failed' or the guard refused, we feed back the prior tier, the plan status, and the reason. The decision agent then escalates — for example, from 'soft' to 'moderate'. This runs for at most 2 rounds, configurable in the YAML.

The decision agent is also memory-aware: it recalls the 5 most similar past incidents by Jaccard overlap of rule-ID sets. If a similar incident was resolved successfully with a particular tier, it adopts that tier — but it only escalates, never downgrades.

Second: LLM as tool selector. The deterministic playbook provides the *floor* — the minimum guaranteed response. Then we ask the LLM: given this decision and this tool catalogue, propose additional tools that would strengthen the response. Each proposal is schema-validated against the tool's declared fields, must name a registered tool, and passes through the same per-step security guard. If the LLM can't parse or proposes invalid tools, we get an empty list — safe fallback. Selected tools are tagged with rule_id='LLM-SELECTED' for auditability."

---

## Slide 9 — Scanner Agents

"We have three scanner agents. Each follows the same pattern: static pass, then LLM refinement, then merge.

The *source code scanner* applies 45+ compiled regex patterns. Examples: shell injection via subprocess with shell=True, weak hashing, hardcoded secrets over 16 characters, pickle/eval deserialization, path traversal, SQL injection via string concatenation, JWT with algorithm 'none'.

The *log analyzer* uses temporal heuristics. For brute-force: 10 or more failed password attempts within a 60-second window. For CAN injection: the pattern 'anomaly' combined with a gateway-only CAN ID. For data exfiltration: DNS queries with Shannon entropy above 3.0, which suggests a covert channel.

The *deployment scanner* parses structured YAML — actors, datasources, edges — and walks the graph. It checks things like: is the HPC-to-ZoneECU link Ethernet with IEEE-1722? Can an external actor write directly to memory? Is the brake ECU taking commands from a non-safety source?

All three produce Finding objects: rule_id, severity, line number, evidence, explanation."

---

## Slide 10 — Decision Agent + Signed Memory Store

"The Decision Agent sits at the center. It uses the 'reasoning' LLM config — GPT-4o at temperature zero for determinism.

Its prompt now includes four sections: the aggregated findings, similar past incidents from memory, a cross-session recommendation, and feedback from the previous attempt this run.

On top of the LLM's output, we apply deterministic policy: if the prior round failed, we bump the tier one notch. If memory says a similar incident was resolved at a higher tier, we adopt it. We never downgrade.

The *signed memory store* is backed by SQLite — no new dependencies. Each incident row stores the mode, scenario, rule IDs, the tier, and critically: whether the remediation actually *worked*. Every write is HMAC-signed with a per-deployment key. Every read verifies the signature and checks the source is in the authenticated set. If someone tampers with the database or writes from an unauthorized source, the row is rejected. This implements Paper 1's source-authorization property applied to the memory channel, and Paper 2's memory-poisoning defense."

---

## Slide 11 — Action Engine & MCP Tools

"The action engine has three components.

*Playbooks* map rule IDs to multi-step response templates. For example, a brute-force detection triggers: rate-limit, then observe, then block IP, then create an incident ticket. A CAN injection triggers: safe mode, isolate the node, notify the driver, and take a forensic snapshot.

The *executor* walks the plan step by step: evaluate preconditions using observe tools, run the per-step security guard, invoke the MCP tool with retry and backoff, evaluate postconditions. If a critical step fails, it performs LIFO rollback of completed steps.

The *MCP tools* operate in two layers. Layer 1 is the action-engine registry: 20+ schema-validated tool subclasses — firewall, network, secrets, code, runtime, notify, observe, knowledge-base. Layer 2 is the real tools module: a port scanner backed by nmap or fallback TCP connect, a static analysis tool backed by bandit or semgrep, and a packet capture tool backed by tshark, tcpdump, or candump.

Everything defaults to dry-run: no destructive side effects unless explicitly enabled. All subprocess calls use argument lists — never shell=True — with bounded timeouts."

---

## Slide 12 — Security Guard + Hₐ Judge + Trajectory

"The security guard operates at three levels.

Level 1: the *final action check*. Four properties checked once on the overall action. This is the coarse static map — a kind-to-objective compatibility table.

Level 2: the *per-step check*. This runs on every single MCP tool call via the GuardAdapter. It uses the step's actual declared side-effect and requires-authorization flags — not a hard-coded list. If the H-a judge is enabled, it's called here with the full context: tool name, rule ID, side effect, step description, and the decision's threat summary.

Level 3: the *trajectory check*. This evaluates the entire sequence of steps for patterns the per-step check can't see. Compositional violations: reading sensitive data followed by external egress is a possible exfiltration chain. Destructive steps without a forensic snapshot or without a notification are governance gaps. Temporal violations: a contain step that checks a precondition but never re-verifies is a TOCTOU risk. A destructive plan influenced by memory-sourced inputs is a memory-poisoning risk.

The H-a judge itself is a separate, independent LLM call. Paper 1's experiments show this single addition cuts attack success rate by 86 to 88 percent. It can only tighten — if the static map says 'allowed', the judge can refuse, but never the reverse. Results are memoized per instance."

---

## Slide 13 — Attack Pipeline

"The attack pipeline is the red-team mirror.

It starts with a scenario text and the same code and deployment inputs. The SystemInfoDiscovery agent parses the deployment YAML to extract external actors, safety-critical ECUs, and exposed surfaces.

The SourceCodeExploiter and DeploymentExploiter reuse the same static analyzers but in attack mode — they look for *exploitable* findings rather than *defend-against* findings.

The Attack Orchestrator, using the LLM, selects a target asset, chains 1-3 findings into an attack plan, and identifies the poison path and trigger path from Paper 2's formal model.

The Attack Generator has built-in exploit templates for common rule IDs — shell injection probes, pickle RCE, path traversal, SQL injection, JWT forgery, CAN frame injection. For unknown rules, it falls back to the LLM.

Everything passes through the *Ethics Guard*: scope check — is the scenario in the allowed set? Target check — is the target authorized? And a destructive-pattern filter that regex-scans generated scripts for things like rm -rf, shutdown, fork bombs. Matched scripts are redacted."

---

## Slide 14 — Observability & Diagnostics

"Auditability is a first-class concern.

Every run creates a timestamped directory with: the meta information, all inputs with provenance tags, static findings, every prompt sent to the LLM, every raw response, the decision, the full action plan, and the guard verdict. Any run can be fully reconstructed.

The console logger separates machine output on stdout from human-readable progress on stderr. In verbose mode you see decisions and counts. In debug mode you see timings, token estimates, and truncated prompt previews.

The token budget is a dependency-free heuristic: 3.5 characters per token, blended with 1.3 tokens per word, take the maximum. When a prompt exceeds 4096 tokens, it emits a warning suggesting RAG instead of inlining — this is Paper 3's finding that quality degrades past 4K.

The signed incident database persists every outcome with its plan status and whether the remediation worked, enabling cross-session learning."

---

## Slide 15 — Demo Output

"Here's what a real run looks like.

We run the defense pipeline on the 'small' example set. The system loads the stub LLM and enables memory. The three scanners produce 10 total findings.

Then the adaptive loop begins. Round 1: the decision agent picks tier 'moderate' with confidence 0.72. It consulted memory and found a similar incident — ota_updater with similarity 0.6 — that was resolved successfully. The action engine generates a plan: rate-limit, observe log tail, block IP, create incident — all four steps complete in dry-run mode. The guard passes — all four properties satisfied.

Since it resolved in round 1, no re-planning needed. The outcome is recorded to the signed memory store for future sessions.

On the attack side: the system discovers external agents and safety ECUs, finds 7 exploitable vulnerabilities, the orchestrator targets 'Life and Bodily Health' with confidence 0.78, the ethics guard approves, and two attack scripts are generated."

---

## Slide 16 — Limitations

"Let me be transparent about limitations.

On the LLM side: the stub returns canned JSON — it can't detect novel attack patterns. The real LLM needs an API key. The token budget warns but doesn't enforce, and we don't have RAG chunking yet.

On tools: most require root or admin privileges we don't have in development. The network isolation and safe-mode tools are connector stubs — there's no real SDN switch or ECU controller behind them.

On detection: our code scanner is regex-based — it can't find logic vulnerabilities or obfuscated code. The log analyzer has only 8 hand-coded heuristics with no ML-based anomaly detection. Languages are limited to Python, C, and C++.

On architecture: re-planning is capped at 2 rounds. Memory recall uses Jaccard similarity, not embeddings. We're batch-only — no real-time streaming. And our trajectory checks are heuristic approximations, not formal proofs."

---

## Slide 17 — Future Work

"The good news: several items from our original roadmap are now implemented — you can see them in the green banner.

For future phases: Phase A is RAG — embedding rules and CVE databases to replace inlining, which the token budget is already flagging. Phase B is real-time streaming and event-driven ingestion. Phase C is vehicle integration — CANoe, CARLA simulator, real CAN-utils. Phase D is a full red/blue evaluation harness with automated scoring. Phase E replaces Jaccard with vector similarity for memory recall. Phase F is edge deployment with quantized models."

---

## Slide 18 — Summary

"To summarize what we built:

12 agents across dual pipelines. 20+ MCP tools with real backends. An adaptive re-planning loop that closes the detect-decide-act-observe cycle. An LLM tool selector that can only strengthen — never bypass — the deterministic floor. The H-a judge that cuts attack success by 86-88%. A signed memory store with HMAC integrity and cross-session learning. Trajectory-level checks for compositional and temporal safety. And token budgeting for prompt quality control.

All of this grounded in five recent papers and implemented with a key principle: *static-first, guard-enforced, dry-run by default*.

The system works offline, scales up with real LLMs, and every decision is auditable."

---

## Slide 19 — Thank You

"Thank you for your attention. I'm happy to take questions.

If you'd like to see a live demo, I can run the pipeline right now — it works offline with the stub LLM in about 2 seconds per scenario."

---

## Q&A Preparation — Likely Questions

**Q: Why not just use a single LLM for everything?**
> Multi-agent design allows specialization (code vs. logs vs. topology have very different patterns), independent failure (one agent's hallucination doesn't corrupt others), and the security guard can't be bypassed by prompt injection because it's a separate call.

**Q: How do you handle LLM hallucinations?**
> Static-first design: the regex/heuristic layer always runs and produces ground-truth findings. The LLM can only ADD findings, and on duplicates the static version wins. The H-a judge is an independent check that can refuse actions.

**Q: What happens if the real LLM is unavailable?**
> The system falls back to StubLLM automatically. You still get all deterministic findings. The LLM layer adds zero findings but the pipeline completes successfully.

**Q: Why HMAC for memory instead of a database with access control?**
> HMAC provides integrity verification without infrastructure. The signing key is per-deployment, stored in an environment variable. Even if someone gets write access to the SQLite file, tampered rows are detected and rejected on read.

**Q: How does the H-a judge differ from the SecurityGuard?**
> The SecurityGuard uses a deterministic static map (kind → compatible objectives). The H-a judge is a separate LLM call with full context that can reason about subtler misalignments. It can only tighten — never loosen — what the static map allows.

**Q: Can the attack pipeline be dangerous?**
> The Ethics Guard filters destructive patterns (rm -rf, fork bombs, etc.) and redacts them. The scope check ensures only authorized scenarios and targets are attacked. In dev mode, all scenarios are allowed but with benign canaries only.
