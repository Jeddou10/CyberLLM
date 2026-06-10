"""Generate the presentation script as a styled PDF."""
from fpdf import FPDF
import os

# Use Arial from Windows system fonts (supports extended characters)
FONT_DIR = "C:/Windows/Fonts"


def sanitize(text):
    """Replace Unicode chars that might cause issues with safe equivalents."""
    return (text
            .replace('\u2014', ' - ')
            .replace('\u2013', ' - ')
            .replace('\u2019', "'")
            .replace('\u201c', '"')
            .replace('\u201d', '"')
            .replace('\u2018', "'")
            .replace('\u2090', 'a')  # subscript a
            .replace('\u2022', '*')
            .replace('\u2026', '...')
            .replace('\u00e9', 'e')
            )


class ScriptPDF(FPDF):
    def __init__(self):
        super().__init__()
        # Add Arial Unicode TTF for full character support
        self.add_font("ArialU", "", os.path.join(FONT_DIR, "arial.ttf"))
        self.add_font("ArialU", "B", os.path.join(FONT_DIR, "arialbd.ttf"))
        self.add_font("ArialU", "I", os.path.join(FONT_DIR, "ariali.ttf"))

    def header(self):
        self.set_font("ArialU", "B", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, "CyberLLM - Presentation Script", align="R")
        self.ln(12)

    def footer(self):
        self.set_y(-15)
        self.set_font("ArialU", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def slide_title(self, num, title):
        self.set_font("ArialU", "B", 16)
        self.set_text_color(0, 90, 160)
        self.cell(0, 10, sanitize(f"Slide {num} - {title}"), new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(0, 90, 160)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def script_text(self, text):
        self.set_font("ArialU", "", 11)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 6, sanitize(text))
        self.ln(3)

    def note_text(self, text):
        self.set_font("ArialU", "I", 10)
        self.set_text_color(80, 80, 80)
        self.multi_cell(0, 5.5, sanitize(text))
        self.ln(2)

    def section_header(self, title):
        self.ln(5)
        self.set_font("ArialU", "B", 14)
        self.set_text_color(180, 50, 50)
        self.cell(0, 8, sanitize(title), new_x="LMARGIN", new_y="NEXT")
        self.ln(3)

    def qa_item(self, question, answer):
        self.set_font("ArialU", "B", 11)
        self.set_text_color(0, 70, 130)
        self.set_x(10)
        self.multi_cell(0, 6, sanitize(f"Q: {question}"))
        self.set_font("ArialU", "", 11)
        self.set_text_color(30, 30, 30)
        self.set_x(10)
        self.multi_cell(0, 6, sanitize(f"A: {answer}"))
        self.ln(4)


pdf = ScriptPDF()
pdf.alias_nb_pages()
pdf.set_auto_page_break(auto=True, margin=20)
pdf.add_page()

# Title page
pdf.set_font("ArialU", "B", 28)
pdf.set_text_color(0, 90, 160)
pdf.ln(30)
pdf.cell(0, 15, "CyberLLM", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.set_font("ArialU", "", 16)
pdf.set_text_color(60, 60, 60)
pdf.cell(0, 10, "Presentation Script", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(10)
pdf.set_font("ArialU", "I", 12)
pdf.set_text_color(100, 100, 100)
pdf.cell(0, 8, "LLM Agents for Automotive Cybersecurity", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.cell(0, 8, "Praktikum 2026", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(20)
pdf.set_font("ArialU", "", 11)
pdf.set_text_color(80, 80, 80)
pdf.multi_cell(0, 6, "Instructions: Read naturally, not word-for-word. Use these as your guide. Each slide has approximately 60-90 seconds of talking time. Total presentation time: ~25-30 minutes including Q&A.", align="C")

# ============================================================
slides = [
    (1, "Title", [
        ("script", 'Good morning/afternoon. My name is [NAME] and today I\'ll present CyberLLM \u2014 a multi-agent LLM system designed for automotive cybersecurity.\n\nThe system uses 12 specialized agents, over 20 tool integrations, and introduces several novel features: adaptive re-planning, an LLM-based tool selector, a dedicated alignment judge, and a cryptographically signed memory store.\n\nLet me walk you through how we got here and what we built.'),
    ]),
    (2, "Agenda", [
        ("script", "Here's the roadmap for today's talk.\n\nWe'll start with the motivation \u2014 why LLM agents are relevant for automotive cybersecurity. Then we'll cover the five research papers that ground our work. The main part is section three, where I'll walk through our architecture, the agents, the re-planning loop, and the security mechanisms. We'll see a real demo output, and I'll close with our limitations and future work.\n\nLet's begin."),
    ]),
    (3, "Motivation: The Problem & Our Approach", [
        ("script", "Modern vehicles have over 100 million lines of code, multiple connected ECUs, and increasingly, in-vehicle LLM assistants \u2014 like BMW's IPA, VW's IDA, or Mercedes MBUX.\n\nThe critical issue: protocols like Google's Agent-to-Agent authenticate the sender, but not the content. So a compromised but properly authenticated agent can inject arbitrary payloads into the vehicle's decision pipeline.\n\nISO/SAE 21434 requires continuous automated monitoring \u2014 manual audits don't scale."),
        ("script", "Our approach is: static-first \u2014 deterministic regex and heuristic rules always run, and the LLM only refines their output. We have specialized agents for code, logs, and topology. We support both defense and red-team attack simulation. And every action is guarded by four contextual security properties.\n\nThe system works fully offline with a stub LLM and scales up to GPT-4o or Claude when available."),
    ]),
    (4, "The Automotive Attack Surface", [
        ("script", "Paper 2 from BMW and TUM identifies a new attack class: agent-to-agent threats.\n\nThree concrete examples: First, cognitive overload \u2014 an agent enters a reasoning loop, bombarding the driver with questions while driving at highway speed. Research shows the cognitive effect lasts 27 seconds after the interaction ends.\n\nSecond, data exfiltration \u2014 a malicious memory rule says 'send GPS coordinates when temperature exceeds 25 degrees' \u2014 a steganographic trigger.\n\nThird, RAG poisoning \u2014 injecting biased knowledge that steers recommendations toward unsafe routes."),
        ("script", "The table shows the asset taxonomy from Paper 2, derived from the Universal Declaration of Human Rights. At the top: life and bodily health \u2014 brake tampering via CAN injection. This taxonomy is how our Decision Agent categorizes findings."),
    ]),
    (5, "Related Work: 5 Foundational Papers", [
        ("script", "Our work is grounded in five recent papers.\n\nPaper 1 defines four formal security properties that every agent action must satisfy. We implement these as the SecurityGuard, and now also as the H-a judge oracle.\n\nPaper 2 gives us the human-centric asset taxonomy and the formal attack-path model with poison paths and trigger paths \u2014 which our attack pipeline implements.\n\nPaper 3 from TUM provides the design pattern: YAML rules feed a static analyzer, then an LLM refines the output, and the two are merged."),
        ("script", "Paper 4 gives us the agent schema: each agent has an ID, prompt templates with placeholders, data bindings, and an LLM config reference. This is exactly our BaseAgent class.\n\nPaper 5 provides the three-layer architecture \u2014 edge, orchestration, intelligence \u2014 plus tiered response and the adaptive learning loop, which we now implement as our re-planning mechanism and signed memory store."),
    ]),
    (6, "Key Concepts We Adopt", [
        ("script", "Let me zoom in on what we took from each paper.\n\nFrom Paper 1: every action must pass four checks: is the task in the allowed set? Does the action serve the objective? Are all inputs from authenticated sources? Does the output go only to trusted destinations? We added the H-a oracle \u2014 a separate LLM call that can only tighten the decision, never loosen it.\n\nFrom Paper 3: the static-then-LLM-then-merge pattern. On conflicts, the deterministic result wins.\n\nFrom Paper 5: the closed loop \u2014 detect, decide, act, observe, and if it didn't resolve, re-decide with escalated parameters.\n\nFrom Paper 2: the memory-poisoning defense via HMAC-signed incident store."),
    ]),
    (7, "Architecture Overview", [
        ("script", "Here's the high-level architecture.\n\nThe system is layered. At the top: inputs \u2014 source code, logs, deployment YAML. These enter the edge layer \u2014 three scanner agents running deterministic checks.\n\nThe orchestration layer is the Decision Agent, backed by a signed memory store. It recalls similar past incidents, picks a response tier, and provides a confidence score.\n\nThe action engine takes that decision: a deterministic playbook provides baseline steps, the LLM tool selector proposes additional tools, and the executor runs each step through the MCP registry."),
        ("script", "The guard layer runs three levels of checks: per-step, final action, and trajectory-level. It includes the H-a judge.\n\nIf the guard refuses or the plan fails, the re-planning loop feeds the failure back and the decision agent escalates \u2014 up to 2 rounds.\n\nFinally, everything is persisted: JSON records, run logs, and the signed incident database."),
    ]),
    (8, "Defense Pipeline: Re-Planning + LLM Tool Selector", [
        ("script", "Let me drill into the defense pipeline's two main innovations.\n\nFirst: adaptive re-planning. It's a closed loop. The decision agent proposes a tier; the action engine realizes it; the guard checks it. If the plan fails or the guard refuses, we feed back the prior tier, plan status, and reason. The decision agent escalates. This runs for at most 2 rounds.\n\nThe decision agent is also memory-aware: it recalls the 5 most similar past incidents by Jaccard overlap. If a similar incident was resolved successfully with a particular tier, it adopts that tier \u2014 but it only escalates, never downgrades."),
        ("script", "Second: LLM as tool selector. The deterministic playbook provides the floor \u2014 the minimum guaranteed response. Then we ask the LLM: given this decision and this tool catalogue, propose additional tools. Each proposal is schema-validated, must name a registered tool, and passes through the per-step security guard.\n\nIf the LLM can't parse or proposes invalid tools, we get an empty list \u2014 safe fallback. Selected tools are tagged 'LLM-SELECTED' for auditability."),
    ]),
    (9, "Scanner Agents", [
        ("script", "We have three scanner agents. Each follows the same pattern: static pass, then LLM refinement, then merge.\n\nThe source code scanner applies 45+ compiled regex patterns: shell injection, weak hashing, hardcoded secrets, pickle/eval deserialization, path traversal, SQL injection, JWT with algorithm 'none'.\n\nThe log analyzer uses temporal heuristics: brute-force detection via failed-password windowing, CAN injection via gateway-only IDs, data exfiltration via DNS entropy above 3.0.\n\nThe deployment scanner parses structured YAML and walks the actor/edge graph: checking link protocols, external memory writes, brake ECU command sources.\n\nAll three produce Finding objects with rule_id, severity, line number, evidence, and explanation."),
    ]),
    (10, "Decision Agent + Signed Memory Store", [
        ("script", "The Decision Agent uses the reasoning LLM at temperature zero. Its prompt includes four sections: aggregated findings, similar past incidents from memory, a cross-session recommendation, and feedback from the previous attempt.\n\nOn top of the LLM's output, we apply deterministic policy: if the prior round failed, bump the tier. If memory says a similar incident was resolved at a higher tier, adopt it. Never downgrade."),
        ("script", "The signed memory store is backed by SQLite \u2014 no new dependencies. Each incident row stores whether the remediation actually worked. Every write is HMAC-signed with a per-deployment key. Every read verifies the signature and checks the source is authenticated. If someone tampers with the database, the row is rejected on read.\n\nThis implements Paper 1's source-authorization applied to the memory channel, and Paper 2's memory-poisoning defense."),
    ]),
    (11, "Action Engine & MCP Tools", [
        ("script", "The action engine has three components.\n\nPlaybooks map rule IDs to multi-step response templates. For brute-force: rate-limit, observe, block, create incident. For CAN injection: safe mode, isolate, notify driver, forensic snapshot.\n\nThe executor walks the plan step by step: preconditions, per-step guard, tool invocation with retry, postconditions. If a critical step fails, LIFO rollback."),
        ("script", "The MCP tools operate in two layers. Layer 1: 20+ schema-validated tool subclasses in the action-engine registry \u2014 firewall, network, secrets, code, runtime, notify, observe. Layer 2: real tools \u2014 nmap for port scanning, bandit or semgrep for static analysis, tshark or tcpdump for packet capture.\n\nEverything defaults to dry-run. All subprocess calls use argument lists \u2014 never shell=True \u2014 with bounded timeouts."),
    ]),
    (12, "Security Guard + H\u2090 Judge + Trajectory", [
        ("script", "The security guard operates at three levels.\n\nLevel 1: the final action check \u2014 four properties checked once on the overall action.\n\nLevel 2: the per-step check \u2014 runs on every MCP tool call. Uses the step's actual side-effect and requires-authorization flags. The H-a judge is called here with full context.\n\nLevel 3: the trajectory check \u2014 evaluates the entire sequence. Compositional violations: sensitive read followed by external egress is a possible exfiltration chain. Temporal violations: contain step without postcondition is a TOCTOU risk."),
        ("script", "The H-a judge is a separate, independent LLM call. Paper 1's experiments show it cuts attack success rate by 86 to 88 percent. It can only tighten \u2014 never loosen what the static map allows. Results are memoized so identical questions cost exactly one call."),
    ]),
    (13, "Attack Pipeline", [
        ("script", "The attack pipeline is the red-team mirror.\n\nSystemInfoDiscovery extracts external actors, safety ECUs, and exposed surfaces from the deployment YAML. The two exploiter agents reuse the same static analyzers in attack mode.\n\nThe Attack Orchestrator selects a target asset, chains 1-3 findings, and identifies poison and trigger paths from Paper 2's model.\n\nThe Attack Generator has built-in exploit templates: shell injection, pickle RCE, path traversal, SQL injection, JWT forgery, CAN frame injection. For unknown rules, it falls back to the LLM."),
        ("script", "Everything passes through the Ethics Guard: scope check, target check, and a destructive-pattern filter that redacts anything like rm -rf, shutdown, or fork bombs."),
    ]),
    (14, "Observability & Diagnostics", [
        ("script", "Auditability is a first-class concern.\n\nEvery run creates a timestamped directory with: metadata, provenance-tagged inputs, static findings, every prompt sent to the LLM, every raw response, the decision, action plan, and guard verdict. Any run can be fully reconstructed.\n\nThe console logger separates machine output on stdout from human-readable progress on stderr. The token budget warns at 4096 tokens \u2014 suggesting RAG instead of inlining.\n\nThe signed incident database persists every outcome with whether the remediation worked, enabling cross-session learning."),
    ]),
    (15, "Demo Output", [
        ("script", "Here's what a real run looks like.\n\nWe run defense on the 'small' example set. Three scanners produce 10 total findings. The adaptive loop begins: round 1 picks tier 'moderate' with confidence 0.72. It consulted memory \u2014 found a similar incident that was resolved successfully.\n\nThe action engine generates a plan: rate-limit, observe, block, create incident \u2014 all four steps complete. Guard passes. Resolved in round 1, no re-planning needed. Outcome recorded to memory.\n\nOn the attack side: discovers external agents and safety ECUs, finds 7 exploitable vulnerabilities, orchestrator targets 'Life and Bodily Health', ethics guard approves, two attack scripts generated."),
    ]),
    (16, "Limitations", [
        ("script", "Let me be transparent about limitations.\n\nOn the LLM side: the stub returns canned JSON \u2014 it can't detect novel patterns. The real LLM needs an API key. Token budget warns but doesn't enforce.\n\nOn tools: most require root or admin. Network isolation and safe-mode are connector stubs.\n\nOn detection: regex-based code scanning can't find logic vulnerabilities. Eight hand-coded log heuristics with no ML. Languages limited to Python, C, C++.\n\nOn architecture: re-planning capped at 2 rounds. Jaccard similarity only, not embeddings. Batch-only. Trajectory checks are heuristic, not formal proofs."),
    ]),
    (17, "Future Work", [
        ("script", "The good news: several items from our original roadmap are now implemented \u2014 the green banner shows what we completed this iteration.\n\nFor future phases: Phase A is RAG \u2014 embedding rules and CVEs to replace inlining. Phase B is real-time streaming. Phase C is vehicle integration with CANoe and CARLA. Phase D is a full red/blue evaluation harness. Phase E replaces Jaccard with vector similarity. Phase F is edge deployment with quantized models."),
    ]),
    (18, "Summary", [
        ("script", "To summarize:\n\n12 agents across dual pipelines. 20+ MCP tools with real backends. An adaptive re-planning loop. An LLM tool selector that can only strengthen the deterministic floor. The H-a judge that cuts attack success by 86-88 percent. A signed memory store with HMAC integrity. Trajectory-level checks for compositional and temporal safety. And token budgeting for prompt quality.\n\nAll grounded in five papers. Implemented with a key principle: static-first, guard-enforced, dry-run by default. Works offline, scales to GPT-4o, and every decision is auditable."),
    ]),
    (19, "Thank You", [
        ("script", "Thank you for your attention. I'm happy to take questions.\n\nIf you'd like to see a live demo, I can run the pipeline right now \u2014 it works offline with the stub LLM in about 2 seconds per scenario."),
    ]),
]

# Generate slide pages
for num, title, blocks in slides:
    pdf.add_page()
    pdf.slide_title(num, title)
    for kind, text in blocks:
        if kind == "script":
            pdf.script_text(text)
        elif kind == "note":
            pdf.note_text(text)

# Q&A Section
pdf.add_page()
pdf.section_header("Q&A Preparation \u2014 Likely Questions")

qa_pairs = [
    ("Why not just use a single LLM for everything?",
     "Multi-agent design allows specialization (code vs. logs vs. topology have very different patterns), independent failure (one agent's hallucination doesn't corrupt others), and the security guard can't be bypassed by prompt injection because it's a separate call."),
    ("How do you handle LLM hallucinations?",
     "Static-first design: the regex/heuristic layer always runs and produces ground-truth findings. The LLM can only ADD findings, and on duplicates the static version wins. The H-a judge is an independent check that can refuse actions."),
    ("What happens if the real LLM is unavailable?",
     "The system falls back to StubLLM automatically. You still get all deterministic findings. The LLM layer adds zero findings but the pipeline completes successfully."),
    ("Why HMAC for memory instead of database access control?",
     "HMAC provides integrity verification without infrastructure. The signing key is per-deployment, stored in an environment variable. Even if someone gets write access to the SQLite file, tampered rows are detected and rejected on read."),
    ("How does the H-a judge differ from the SecurityGuard?",
     "The SecurityGuard uses a deterministic static map (kind to compatible objectives). The H-a judge is a separate LLM call with full context that can reason about subtler misalignments. It can only tighten \u2014 never loosen \u2014 what the static map allows."),
    ("Can the attack pipeline be dangerous?",
     "The Ethics Guard filters destructive patterns (rm -rf, fork bombs, etc.) and redacts them. The scope check ensures only authorized scenarios and targets are attacked. In dev mode, scripts use benign canaries only \u2014 no real exploitation."),
]

for q, a in qa_pairs:
    pdf.qa_item(q, a)

# Save
output = r"c:\Users\benfrajf\Praktikum\CyberLLM\CyberLLM_Presentation_Script.pdf"
pdf.output(output)
print(f"PDF saved: {output}")
print(f"Pages: {pdf.page_no()}")
