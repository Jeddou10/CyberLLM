"""Generate a professional PowerPoint presentation for CyberLLM."""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu, Cm
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from copy import deepcopy

# -- Color palette --
BG_DARK = RGBColor(0x0F, 0x17, 0x2A)
BG_CARD = RGBColor(0x1E, 0x29, 0x3B)
ACCENT_CYAN = RGBColor(0x00, 0xD4, 0xFF)
ACCENT_PURPLE = RGBColor(0xA7, 0x8B, 0xFA)
ACCENT_GREEN = RGBColor(0x34, 0xD3, 0x99)
ACCENT_RED = RGBColor(0xF8, 0x71, 0x71)
ACCENT_ORANGE = RGBColor(0xFB, 0xBF, 0x24)
TEXT_WHITE = RGBColor(0xE8, 0xEA, 0xED)
TEXT_GRAY = RGBColor(0x94, 0xA3, 0xB8)
TEXT_DIM = RGBColor(0x64, 0x74, 0x8B)

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

# Use blank layout
blank_layout = prs.slide_layouts[6]


def set_slide_bg(slide, color=BG_DARK):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = color


def add_text_box(slide, left, top, width, height, text, font_size=18,
                 bold=False, color=TEXT_WHITE, align=PP_ALIGN.LEFT,
                 font_name="Segoe UI"):
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(font_size)
    p.font.bold = bold
    p.font.color.rgb = color
    p.font.name = font_name
    p.alignment = align
    return txBox


def add_bullet_frame(slide, left, top, width, height, items, font_size=16,
                     color=TEXT_WHITE, bullet_color=ACCENT_CYAN):
    txBox = slide.shapes.add_textbox(left, top, width, height)
    tf = txBox.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = item
        p.font.size = Pt(font_size)
        p.font.color.rgb = color
        p.font.name = "Segoe UI"
        p.space_before = Pt(6)
        p.level = 0
    return txBox


def add_card(slide, left, top, width, height, title, body_items,
             accent_color=ACCENT_CYAN, title_size=16, body_size=13):
    # Card background
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                   left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = BG_CARD
    shape.line.color.rgb = accent_color
    shape.line.width = Pt(1.5)
    shape.shadow.inherit = False

    # Title
    add_text_box(slide, left + Inches(0.2), top + Inches(0.15),
                 width - Inches(0.4), Inches(0.4),
                 title, font_size=title_size, bold=True, color=accent_color)
    # Body
    if body_items:
        add_bullet_frame(slide, left + Inches(0.2), top + Inches(0.55),
                         width - Inches(0.4), height - Inches(0.7),
                         body_items, font_size=body_size, color=TEXT_GRAY)


def add_section_title(slide, text):
    add_text_box(slide, Inches(0.6), Inches(0.3), Inches(12), Inches(0.7),
                 text, font_size=32, bold=True, color=ACCENT_CYAN)
    # Underline
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE,
                                   Inches(0.6), Inches(1.0),
                                   Inches(12), Pt(3))
    shape.fill.solid()
    shape.fill.fore_color.rgb = RGBColor(0x1E, 0x3A, 0x5F)
    shape.line.fill.background()


# ============================================================
# SLIDE 1: TITLE
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide, RGBColor(0x0A, 0x0A, 0x2E))

add_text_box(slide, Inches(1), Inches(1.8), Inches(11), Inches(1.2),
             "CyberLLM", font_size=60, bold=True, color=ACCENT_CYAN,
             align=PP_ALIGN.CENTER)
add_text_box(slide, Inches(1), Inches(3.0), Inches(11), Inches(0.8),
             "LLM Agents for Automotive Cybersecurity",
             font_size=28, color=TEXT_GRAY, align=PP_ALIGN.CENTER)
add_text_box(slide, Inches(1), Inches(4.0), Inches(11), Inches(0.6),
             "Multi-Agent Defense & Red-Team System",
             font_size=20, color=TEXT_DIM, align=PP_ALIGN.CENTER)
add_text_box(slide, Inches(1), Inches(5.5), Inches(11), Inches(0.5),
             "12 Agents  •  20+ MCP Tools  •  Adaptive Re-Planning  •  LLM Tool Selector  •  Hₐ Judge  •  Signed Memory",
             font_size=14, color=TEXT_DIM, align=PP_ALIGN.CENTER)
add_text_box(slide, Inches(1), Inches(6.3), Inches(11), Inches(0.4),
             "Praktikum — 2026", font_size=14, color=TEXT_DIM,
             align=PP_ALIGN.CENTER)

# ============================================================
# SLIDE 2: AGENDA
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "Agenda")

agenda_items = [
    ("1. Introduction & Background", ACCENT_CYAN,
     ["Motivation — Why LLMs for Cybersecurity?", "The Automotive Attack Surface"]),
    ("2. Related Work", ACCENT_PURPLE,
     ["5 foundational papers", "Key concepts we adopt"]),
    ("3. Our Work — CyberLLM", ACCENT_GREEN,
     ["Architecture & Adaptive Re-Planning", "Agents, LLM Tool Selection, Hₐ Judge", "MCP Tools & Signed Memory"]),
    ("4. Demo & Results", ACCENT_ORANGE,
     ["Defense pipeline walkthrough", "Attack pipeline walkthrough"]),
    ("5. Limitations & Future Work", ACCENT_RED,
     ["Current gaps", "Roadmap"]),
]
for i, (title, color, items) in enumerate(agenda_items):
    col = i % 3
    row = i // 3
    left = Inches(0.5 + col * 4.2)
    top = Inches(1.4 + row * 3.1)
    add_card(slide, left, top, Inches(3.9), Inches(2.8),
             title, items, accent_color=color)

# ============================================================
# SLIDE 3: MOTIVATION — THE PROBLEM
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "1. Why LLM Agents for Automotive Cybersecurity?")

add_card(slide, Inches(0.5), Inches(1.3), Inches(6.0), Inches(3.0),
         "🚨  The Problem", [
             "Modern vehicles = 100M+ lines of code, connected ECUs, V2X",
             "In-vehicle LLM assistants deployed (BMW IPA, VW IDA, MBUX)",
             "A2A protocol authenticates senders, not content",
             "New threat: compromised-but-authenticated agents",
             "ISO/SAE 21434 demands continuous monitoring",
         ], accent_color=ACCENT_RED)

add_card(slide, Inches(0.5), Inches(4.5), Inches(6.0), Inches(2.7),
         "💡  Our Approach", [
             "Static-first: deterministic rules always run, LLM refines",
             "Multi-agent: specialized for code, logs, topology",
             "Dual-mode: defense AND red-team attack simulation",
             "Guard-enforced: 4 security properties on every action",
         ], accent_color=ACCENT_GREEN)

# Right side: simple diagram
add_card(slide, Inches(6.8), Inches(1.3), Inches(6.0), Inches(5.9),
         "CyberLLM monitors:", [
             "📝  Source code — 45+ regex rules (CODE-001..045)",
             "📊  Runtime logs — 8 heuristic detectors",
             "🌐  Deployment topology — 8 graph checks",
             "",
             "Key properties:",
             "✓  Works offline with StubLLM (no API needed)",
             "✓  Scales to GPT-4o / Claude / Ollama",
             "✓  Dry-run default — no destructive side effects",
             "✓  Full audit trail on every run",
         ], accent_color=ACCENT_CYAN)

# ============================================================
# SLIDE 4: ATTACK SURFACE
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "1. The Automotive LLM Attack Surface")

add_text_box(slide, Inches(0.6), Inches(1.2), Inches(12), Inches(0.5),
             "Paper 2 (BMW/TUM): Agent-to-Agent threats — compromised but authenticated agents inject arbitrary payloads",
             font_size=15, color=TEXT_GRAY)

threats = [
    ("🧠 Cognitive Overload", "Reasoning loops bombard driver\non highway — 27+ second effect", ACCENT_RED),
    ("🔓 Data Exfiltration", "Memory rule: send GPS when\ntemperature > 25°C (trigger)", ACCENT_ORANGE),
    ("🎭 RAG Poisoning", "Injected knowledge biases\nrecommendations — unsafe routes", ACCENT_PURPLE),
]
for i, (title, desc, color) in enumerate(threats):
    left = Inches(0.5 + i * 4.2)
    add_card(slide, left, Inches(1.9), Inches(3.9), Inches(1.8),
             title, desc.split("\n"), accent_color=color)

# Asset taxonomy table
add_text_box(slide, Inches(0.6), Inches(3.9), Inches(12), Inches(0.4),
             "Human-Centric Asset Taxonomy (Paper 2 — from UDHR)",
             font_size=18, bold=True, color=ACCENT_PURPLE)

assets = [
    ("🫀 Life & Bodily Health", "Brake tampering via CAN injection", "Critical"),
    ("🧠 Mental & Emotional Well-Being", "False 'engine failure' warnings", "High"),
    ("🔒 Privacy & Personal Data", "Location exfiltration", "High"),
    ("📚 Knowledge & Belief", "RAG poisoning → biased info", "Medium"),
    ("💰 Material & Economic", "EV battery drain via max AC", "Medium"),
    ("👤 Reputation & Dignity", "Medical appointment disclosure", "Medium"),
    ("🤝 Social Relationships", "Unauthorized transactions", "Medium"),
]

tbl = slide.shapes.add_table(len(assets) + 1, 3,
                              Inches(0.6), Inches(4.4),
                              Inches(12), Inches(2.9)).table
tbl.columns[0].width = Inches(4.5)
tbl.columns[1].width = Inches(5.5)
tbl.columns[2].width = Inches(2.0)

headers = ["Asset Category", "Example Threat", "Severity"]
for i, h in enumerate(headers):
    cell = tbl.cell(0, i)
    cell.text = h
    cell.fill.solid()
    cell.fill.fore_color.rgb = RGBColor(0x0D, 0x2B, 0x45)
    p = cell.text_frame.paragraphs[0]
    p.font.bold = True
    p.font.size = Pt(12)
    p.font.color.rgb = ACCENT_CYAN

for r, (asset, threat, sev) in enumerate(assets, 1):
    for c, val in enumerate([asset, threat, sev]):
        cell = tbl.cell(r, c)
        cell.text = val
        cell.fill.solid()
        cell.fill.fore_color.rgb = BG_CARD
        p = cell.text_frame.paragraphs[0]
        p.font.size = Pt(11)
        p.font.color.rgb = TEXT_GRAY

# ============================================================
# SLIDE 5: RELATED WORK
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "2. Related Work — 5 Foundational Papers")

papers = [
    ("P1", "Framework for Formalizing LLM Agent Security",
     "Siu et al. — UCSC/UCB/Duke", "4 contextual security properties + oracle functions",
     "→ SecurityGuard + Hₐ Judge", ACCENT_CYAN),
    ("P2", "Agent2Agent Threats — AgentHeLLM",
     "Stappen et al. — BMW + TUM", "7 human-centric asset categories + attack path model",
     "→ Asset tagging + Attack pipeline", ACCENT_PURPLE),
    ("P3", "LLM-Empowered Safety & Security by Design",
     "Petrovic et al. — TUM", "Model-driven rules + static→LLM→merge pattern",
     "→ Rules YAML + Static analyzer", ACCENT_GREEN),
    ("P4", "Multi-Agent LLM System Specification",
     "Härer — FHNW", "Schema-driven agents + prompt templates",
     "→ BaseAgent + [placeholder] templating", ACCENT_ORANGE),
    ("P5", "LLM-Orchestrated MAS for Edge Defense",
     "Collins et al.", "Three layers + tiered response + adaptive loop",
     "→ Pipeline layers + re-planning + memory", ACCENT_RED),
]

for i, (tag, title, authors, key, impl, color) in enumerate(papers):
    col = i % 3
    row = i // 3
    left = Inches(0.3 + col * 4.3)
    top = Inches(1.3 + row * 3.2)
    h = Inches(2.9) if row == 0 else Inches(2.9)
    add_card(slide, left, top, Inches(4.1), h,
             f"[{tag}] {title}", [authors, key, "", impl],
             accent_color=color, title_size=14, body_size=12)

# ============================================================
# SLIDE 6: KEY CONCEPTS
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "2. Key Concepts We Adopt")

# Paper 1: four properties
add_card(slide, Inches(0.4), Inches(1.3), Inches(6.2), Inches(2.8),
         "Paper 1 — Four Security Properties (checked on EVERY action)", [
             "1️⃣  Task Alignment — objective ∈ allowed set O?",
             "2️⃣  Action Alignment — action serves the objective?",
             "3️⃣  Source Authorization — inputs from authenticated sources?",
             "4️⃣  Data Isolation — output to trusted destinations only?",
             "",
             "⚡ NEW: Hₐ oracle (separate LLM judge) for property #2",
         ], accent_color=ACCENT_CYAN, body_size=14)

# Paper 3 + 5
add_card(slide, Inches(0.4), Inches(4.3), Inches(6.2), Inches(2.9),
         "Paper 3 — Static→LLM→Merge Pattern", [
             "Rules (YAML)  →  Static Analysis  →  LLM Refinement",
             "                                  →  Merge (static wins)",
             "                                  →  Findings + fixes",
             "",
             "Paper 5 — Three Layers + Adaptive Loop:",
             "  Edge (scanners) → Orchestration (decision) → Intelligence (memory)",
             "  detect → decide → act → observe → re-decide (closed loop)",
         ], accent_color=ACCENT_GREEN, body_size=13)

# Paper 4
add_card(slide, Inches(6.9), Inches(1.3), Inches(6.0), Inches(2.8),
         "Paper 4 — Agent Schema", [
             "Agent = {",
             '  id:       "source_code_scanner"',
             "  prompts:  [template with [placeholders]]",
             "  data:     {code, rules, findings}",
             "  llm:      LLM-Config reference",
             "  actions:  [extract, evaluate, respond]",
             "}",
         ], accent_color=ACCENT_ORANGE, body_size=13)

# Paper 2
add_card(slide, Inches(6.9), Inches(4.3), Inches(6.0), Inches(2.9),
         "Paper 2 — Attack Model", [
             "Formal graph: actors + datasources + edges",
             "Poison path: external → memory → decision",
             "Trigger path: event → tool → actuator",
             "",
             "⚡ NEW: Memory-poisoning defense via HMAC-signed",
             "   incident store (paper 1 source-auth on memory)",
         ], accent_color=ACCENT_PURPLE, body_size=13)

# ============================================================
# SLIDE 7: ARCHITECTURE OVERVIEW (VISUAL FLOW)
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "3. Architecture — High-Level Flow")

# Visual flow using shapes
layers = [
    ("INPUT", "Source code (.py/.c)\nLogs (.log)\nDeployment (.yaml)", Inches(0.3), ACCENT_CYAN),
    ("EDGE LAYER", "Static Analyzer\n3 Scanner Agents\n(regex + heuristics + graph)", Inches(2.4), ACCENT_CYAN),
    ("ORCHESTRATION", "Decision Agent + Memory\n(tier selection, recall\nsimilar incidents)", Inches(4.0), ACCENT_PURPLE),
    ("ACTION ENGINE", "Playbooks + LLM Tool Selector\n→ ActionExecutor\n→ 20+ MCP Tools", Inches(5.6), ACCENT_GREEN),
    ("GUARD", "SecurityGuard (4 props)\n+ Hₐ Judge + Trajectory\n+ Per-Step check", Inches(7.2), ACCENT_RED),
]

# Draw boxes with arrows
for i, (label, desc, top_pos, color) in enumerate(layers):
    left = Inches(0.5)
    width = Inches(12.3)
    height = Inches(1.3)
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                   left, top_pos, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = BG_CARD
    shape.line.color.rgb = color
    shape.line.width = Pt(2)
    # Label
    add_text_box(slide, left + Inches(0.3), top_pos + Inches(0.1),
                 Inches(2.5), Inches(0.4),
                 label, font_size=14, bold=True, color=color)
    # Description
    add_text_box(slide, left + Inches(3.0), top_pos + Inches(0.1),
                 Inches(9.0), Inches(1.1),
                 desc, font_size=13, color=TEXT_GRAY)

# Re-planning arrow annotation
add_text_box(slide, Inches(9.5), Inches(6.5), Inches(3.5), Inches(0.8),
             "🔄 RE-PLAN LOOP\nIf guard refuses / plan fails → escalate tier → round 2",
             font_size=12, bold=True, color=ACCENT_ORANGE)

# ============================================================
# SLIDE 8: DEFENSE PIPELINE — RE-PLANNING
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "3. Defense Pipeline — Adaptive Re-Planning Loop")

# Flow nodes
nodes = ["Inputs", "Static\nScan", "LLM\nRefine", "Merge", "Decision\n+ Memory",
         "Action\n+ LLM Select", "Guard\n+ Hₐ", "Re-Plan?"]
colors = [TEXT_DIM, ACCENT_CYAN, ACCENT_CYAN, ACCENT_CYAN, ACCENT_PURPLE,
          ACCENT_GREEN, ACCENT_RED, ACCENT_ORANGE]

for i, (node, color) in enumerate(zip(nodes, colors)):
    left = Inches(0.3 + i * 1.62)
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                   left, Inches(1.3), Inches(1.45), Inches(1.0))
    shape.fill.solid()
    shape.fill.fore_color.rgb = BG_CARD
    shape.line.color.rgb = color
    shape.line.width = Pt(1.5)
    tf = shape.text_frame
    tf.word_wrap = True
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.text = node
    p.font.size = Pt(11)
    p.font.color.rgb = color
    p.font.bold = True

# Main content: two cards
add_card(slide, Inches(0.3), Inches(2.6), Inches(6.3), Inches(4.6),
         "Adaptive Re-Planning (Paper 5)", [
             "Closed loop: detect → decide → act → observe → re-decide",
             "",
             "• Max rounds: configurable (default: 2)",
             "• Escalation: if plan fails/refused → tier bumps up",
             "• Feedback: prior_tier + plan_status + reason → Decision Agent",
             "• Memory-aware: recalls K=5 similar past incidents (Jaccard)",
             "• Cross-session: 'tier X worked before' → adopt",
             "• Terminal: stops when resolved OR max rounds reached",
             "",
             "Code (pipeline.py):",
             "  for round in range(1, max_rounds+1):",
             "    decision = agent.run(results, feedback=feedback)",
             "    action = generator.generate(decision, code)",
             "    verdict = guard.check(action, objective, inputs)",
             "    if success: break",
             "    feedback = {prior_tier, plan_status, reason}",
         ], accent_color=ACCENT_CYAN, body_size=12)

add_card(slide, Inches(6.8), Inches(2.6), Inches(6.2), Inches(4.6),
         "LLM as Tool Selector (generator.py)", [
             "Deterministic playbook = FLOOR",
             "LLM can only ADD tools — never bypass safety",
             "",
             "How it works:",
             "• Registry exposes tool catalogue (name, domain, side_effect)",
             "• LLM proposes: {tools: [{tool, kind, params, why}]}",
             "• Each pick schema-validated against tool's MCPSchemaField",
             "• Only registered tools accepted",
             "• Per-step SecurityGuard runs on every LLM-selected step",
             "• Tagged: rule_id='LLM-SELECTED' for audit trail",
             "• Parse failure → empty list (safe fallback)",
             "",
             "Key guarantee:",
             "  Playbook provides minimum response",
             "  LLM strengthens it (observe/verify preferred)",
         ], accent_color=ACCENT_GREEN, body_size=12)

# ============================================================
# SLIDE 9: SCANNER AGENTS
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "3. Scanner Agents")

add_card(slide, Inches(0.3), Inches(1.3), Inches(4.1), Inches(5.9),
         "📝 Source Code Scanner", [
             "File: agents/source_code_scanner.py",
             "Static: scan_code_static()",
             "  re.compile(pattern, MULTILINE)",
             "",
             "Rules (45+):",
             "• CODE-001: subprocess shell=True",
             "• CODE-002: hashlib.md5/sha1",
             "• CODE-003: hardcoded secrets (16+ char)",
             "• CODE-005: pickle.loads / eval()",
             "• CODE-007: path traversal (../)",
             "• CODE-012: SQL string concat",
             "• CODE-020: JWT alg=['none']",
             "• ...up to CODE-045",
         ], accent_color=ACCENT_CYAN, body_size=12)

add_card(slide, Inches(4.6), Inches(1.3), Inches(4.1), Inches(5.9),
         "📊 Log Analyzer", [
             "File: agents/log_analyzer.py",
             "Static: scan_log_static()",
             "  temporal heuristics per rule",
             "",
             "Rules (8):",
             "• LOG-AUTH-03: ≥10 'Failed' in 60s",
             "• LOG-NET-01: broadcast burst ≥500 pkts/s",
             "• LOG-CAN-02: gateway-only CAN ID (0x7E)",
             "• LOG-EXFIL-01: DNS entropy > 3.0",
             "• LOG-EXFIL-02: bytes_out ≥ 10MB",
             "• LOG-LATERAL-01: internal port-scan",
             "• LOG-DDOS-01: ≥3 SYN-flood lines",
             "• LOG-PRIV-01: sudo + /etc/shadow",
         ], accent_color=ACCENT_PURPLE, body_size=12)

add_card(slide, Inches(8.9), Inches(1.3), Inches(4.1), Inches(5.9),
         "🌐 Deployment Scanner", [
             "File: agents/deployment_scanner.py",
             "Static: scan_deployment_static()",
             "  YAML parse → graph walk",
             "",
             "Rules (8):",
             "• TOP-001: HPC→ZoneECU not Ethernet",
             "• TOP-002: external writes to memory",
             "• TOP-004: admin portal without WAF",
             "• TOP-005: bind_address=0.0.0.0",
             "• TOP-006: secrets world-readable",
             "• TOP-007: brake cmds from non-safety",
             "• TOP-008: external A2A → in-vehicle",
             "",
             "Input: YAML with actors[], edges[]",
         ], accent_color=ACCENT_GREEN, body_size=12)

# ============================================================
# SLIDE 10: DECISION AGENT + MEMORY
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "3. Decision Agent + Signed Memory Store")

add_card(slide, Inches(0.3), Inches(1.3), Inches(6.3), Inches(3.0),
         "Decision Agent (decision_agent.py)", [
             "• Uses 'reasoning' LLM (GPT-4o, temp=0)",
             "• Aggregates findings from 3 scanners",
             "• Prompt includes: [findings], [memory], [recommendation], [feedback]",
             "• Returns: tier (soft|moderate|hard), confidence [0..1], justification",
             "",
             "Policy on top of LLM (deterministic):",
             "• Escalation: if prior tier failed → bump one notch",
             "• Memory: similar incident worked at tier X → adopt (never downgrade)",
         ], accent_color=ACCENT_PURPLE, body_size=13)

add_card(slide, Inches(0.3), Inches(4.5), Inches(6.3), Inches(2.7),
         "Tier Thresholds (config.yaml)", [
             "🟢 Soft (conf ≥ 0.40): rate limiting, traffic shaping",
             "🟠 Moderate (conf ≥ 0.65): IP block, session kill",
             "🔴 Hard (conf ≥ 0.85): node isolation, safe mode",
         ], accent_color=ACCENT_ORANGE, body_size=14)

add_card(slide, Inches(6.8), Inches(1.3), Inches(6.2), Inches(5.9),
         "Signed Memory Store (memory_store.py)", [
             "SQLite + HMAC-SHA256 — no new dependencies",
             "",
             "Features:",
             "• E.1: One row per incident (incl. plan_status, remediation_ok)",
             "• E.2: recall_similar(rule_ids, k=5) — Jaccard overlap",
             "• E.3: Every write HMAC-signed; reads verify signature + source",
             "• Poison defense: unauthenticated → MemoryAuthError",
             "• Cross-session: recommend() → 'tier X worked on similar'",
             "",
             "Write flow:",
             "  Incident(mode, scenario, rule_ids, tier, plan_status, ...)",
             "  → HMAC-sign canonical fields → INSERT INTO incidents",
             "",
             "Read flow:",
             "  recall_similar(query_rule_ids) → Jaccard similarity",
             "  → verify_row(signature, source) → ranked results",
         ], accent_color=ACCENT_GREEN, body_size=12)

# ============================================================
# SLIDE 11: ACTION ENGINE + MCP
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "3. Action Engine & MCP Tools")

add_card(slide, Inches(0.3), Inches(1.3), Inches(6.3), Inches(3.0),
         "Playbook Catalogue (playbooks.py)", [
             "Rule → multi-step response:",
             "• LOG-AUTH-03: rate_limit → observe → block → incident",
             "• LOG-CAN-02: safe_mode → isolate → notify_driver → snapshot",
             "• LOG-EXFIL-*: block_ip → rotate_secrets → incident",
             "• CODE-003: rotate → patch → scrub_git → incident",
             "• CODE-001/005: scan → patch → incident",
         ], accent_color=ACCENT_CYAN, body_size=13)

add_card(slide, Inches(0.3), Inches(4.5), Inches(6.3), Inches(2.7),
         "Executor (executor.py)", [
             "For each step in plan:",
             "  1. Evaluate preconditions (observe tools)",
             "  2. Per-step SecurityGuard check (paper 1)",
             "     → if REFUSED + CONTAIN: abort",
             "  3. Invoke MCP tool (with retry + 0.2s backoff)",
             "  4. Evaluate postconditions",
             "     → if FAILED + critical: LIFO rollback",
         ], accent_color=ACCENT_ORANGE, body_size=13)

add_card(slide, Inches(6.8), Inches(1.3), Inches(6.2), Inches(5.9),
         "20+ MCP Tools (two layers)", [
             "Layer 1 — Action-Engine Registry (schema-validated):",
             "  firewall.block_ipv4     (iptables/netsh)  WRITE",
             "  firewall.rate_limit     (iptables)        WRITE",
             "  network.isolate_node    (nmcli/SDN)       DESTRUCTIVE",
             "  secrets.rotate          (Vault/token)     DESTRUCTIVE",
             "  code.propose_patch      (git diff)        WRITE",
             "  runtime.safe_mode       (connector)       DESTRUCTIVE",
             "  notify.create_incident  (webhook/file)    WRITE",
             "  observe.log_tail        (file+regex)      READ",
             "  kb.lookup_cve           (NVD API/YAML)    READ",
             "",
             "Layer 2 — Real Tools (tools/mcp_tools.py):",
             "  PortScanTool      → nmap or TCP connect",
             "  StaticAnalysisTool → bandit -f json / semgrep",
             "  PacketCaptureTool → tshark / tcpdump / candump",
             "",
             "All: dry-run default, no shell=True, bounded timeout",
         ], accent_color=ACCENT_GREEN, body_size=12)

# ============================================================
# SLIDE 12: SECURITY GUARD + Ha JUDGE
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "3. Security Guard + Hₐ Judge + Trajectory Checks")

add_card(slide, Inches(0.3), Inches(1.3), Inches(4.1), Inches(2.5),
         "1. Final Action Check", [
             "guard.check(action, objective, inputs)",
             "4 properties on translated Action",
             "Coarse static map is the floor",
             "Runs once per pipeline round",
         ], accent_color=ACCENT_CYAN, body_size=13)

add_card(slide, Inches(4.6), Inches(1.3), Inches(4.1), Inches(2.5),
         "2. Per-Step Check", [
             "guard.check_step(step, objective, inputs)",
             "Runs on EVERY MCP tool call",
             "Uses real side_effect + requires_auth",
             "Not a hard-coded kind list",
         ], accent_color=ACCENT_PURPLE, body_size=13)

add_card(slide, Inches(8.9), Inches(1.3), Inches(4.1), Inches(2.5),
         "3. Trajectory Check", [
             "guard.check_trajectory(steps)",
             "F.3: exfil chain, no snapshot, no notify",
             "F.4: TOCTOU risk, memory-poisoning",
             "Evaluates the whole SEQUENCE",
         ], accent_color=ACCENT_ORANGE, body_size=13)

add_card(slide, Inches(0.3), Inches(4.0), Inches(6.3), Inches(3.2),
         "Hₐ Judge — Separate LLM Oracle (ha_judge.py)", [
             "Paper 1: cuts attack-success-rate by 86-88%",
             "",
             "Design:",
             "• Independent model call (separate from scanners/decision)",
             "• Prompt: 'Does action A serve objective O in context C?'",
             "• Returns: {serves: true|false, reason: '...'}",
             "• Can only TIGHTEN — never loosens the deterministic floor",
             "• Per-instance memoisation (same question = one call)",
             "• Deterministic fallback on parse failure",
         ], accent_color=ACCENT_RED, body_size=13)

add_card(slide, Inches(6.8), Inches(4.0), Inches(6.2), Inches(3.2),
         "Guard Policy (from config.yaml)", [
             "security:",
             "  allowed_objectives:",
             '    - "produce findings report"',
             '    - "produce defensive action"',
             '    - "auto-correct insecure code"',
             "  authenticated_sources: [user, rules_engine, mcp_tool]",
             "  trusted_destinations: [findings_report, audit_log]",
             "",
             "guard:",
             "  ha_judge_enabled: true",
             "  per_step_enabled: true",
             "  max_prompt_tokens: 4096",
         ], accent_color=TEXT_DIM, body_size=12)

# ============================================================
# SLIDE 13: ATTACK PIPELINE
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "3. Attack Pipeline")

# Flow
atk_nodes = ["Scenario\n+ Code", "SystemInfo\nDiscovery", "Source\nExploiter",
             "Deploy\nExploiter", "Attack\nOrchestrator", "Attack\nGenerator", "Ethics\nGuard"]
for i, node in enumerate(atk_nodes):
    left = Inches(0.2 + i * 1.85)
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                   left, Inches(1.3), Inches(1.7), Inches(1.0))
    shape.fill.solid()
    shape.fill.fore_color.rgb = BG_CARD
    shape.line.color.rgb = ACCENT_RED
    shape.line.width = Pt(1.5)
    tf = shape.text_frame
    tf.word_wrap = True
    tf.paragraphs[0].alignment = PP_ALIGN.CENTER
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.text = node
    p.font.size = Pt(11)
    p.font.color.rgb = ACCENT_RED
    p.font.bold = True

add_card(slide, Inches(0.3), Inches(2.6), Inches(6.3), Inches(4.6),
         "Attack Generator (attack_generator.py)", [
             "Built-in exploit templates + LLM fallback:",
             "• CODE-001: Shell-injection probe (curl)",
             "• CODE-005: Pickle RCE payload",
             "• CODE-007: Path-traversal (..%2f)",
             "• CODE-012: SQL injection (admin'--)",
             "• CODE-020: JWT alg=none forgery",
             "• TOP-002: Memory-poison payload",
             "• TOP-008: A2A fear-injection",
             "• LOG-CAN-02: CAN frame cansend 7E0#...",
             "",
             "Orchestrator (LLM):",
             "• Selects target asset + chains 1-3 findings",
             "• Identifies poison path + trigger path (Paper 2)",
         ], accent_color=ACCENT_RED, body_size=12)

add_card(slide, Inches(6.8), Inches(2.6), Inches(6.2), Inches(4.6),
         "Ethics Guard (ethics_guard.py)", [
             "Two checks + one filter:",
             "",
             "1. check_plan(scenario, target_asset):",
             "   • scope_ok: scenario ∈ allowed_scenarios",
             "   • target_ok: target ∈ authorized_targets",
             "",
             "2. filter_scripts(scripts):",
             "   • Regex scan for destructive patterns:",
             "     rm -rf, shutdown -h, mkfs., fork bomb",
             "   • Matched scripts → REDACTED in output",
             "",
             "Config (allow_all_in_dev: true for offline demos)",
             "",
             "Output: EthicsVerdict(",
             "  allowed, scope_ok, target_ok, non_destructive, reason)",
         ], accent_color=ACCENT_GREEN, body_size=12)

# ============================================================
# SLIDE 14: OBSERVABILITY
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "3. Observability & Diagnostics")

add_card(slide, Inches(0.3), Inches(1.3), Inches(4.1), Inches(3.0),
         "Run Logger (run_logs/)", [
             "Timestamped directory per run:",
             "• 00_meta.json — mode, inputs",
             "• 02_static_*.json — deterministic",
             "• 03_*_prompt.txt — exact LLM input",
             "• 03_*_response.txt — raw output",
             "• ZZ_decision.json — tier + confidence",
             "• ZZ_action_plan.json — full MCP plan",
             "• ZZ_guard.json — 4-property verdict",
         ], accent_color=ACCENT_CYAN, body_size=12)

add_card(slide, Inches(4.6), Inches(1.3), Inches(4.1), Inches(3.0),
         "Console Logger (tools/log.py)", [
             "stdout → results (machine JSON)",
             "stderr → human-facing progress",
             "",
             "Channels:",
             "• verbose (default): decisions, counts",
             "• debug (-v): timings, token estimates",
             "  prompt previews, LLM responses",
             "• con.timed(): elapsed ms per phase",
         ], accent_color=ACCENT_PURPLE, body_size=12)

add_card(slide, Inches(8.9), Inches(1.3), Inches(4.1), Inches(3.0),
         "Token Budget (tools/tokens.py)", [
             "Dependency-free heuristic:",
             "• char_est = len(text) / 3.5",
             "• word_est = words × 1.3",
             "• take max (conservative)",
             "",
             "Warns at 4096 tokens:",
             "'consider RAG instead of inlining'",
             "(Paper 3: quality degrades past 4K)",
         ], accent_color=ACCENT_ORANGE, body_size=12)

# Bottom: what's captured
caps = [
    ("📝 Every Prompt", "Exact text + token count"),
    ("🔧 Every MCP Call", "Params, result, dry_run"),
    ("🛡️ Every Verdict", "Guard + Hₐ + trajectory"),
    ("🔄 Re-Plan History", "Per-round tier/status"),
]
for i, (title, desc) in enumerate(caps):
    left = Inches(0.3 + i * 3.25)
    add_card(slide, left, Inches(4.6), Inches(3.0), Inches(2.5),
             title, [desc, "", "Fully reconstructible",
                     "audit trail per run"],
             accent_color=ACCENT_GREEN, body_size=12)

# ============================================================
# SLIDE 15: DEMO OUTPUT
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "4. Demo — Pipeline Output")

add_card(slide, Inches(0.3), Inches(1.3), Inches(6.3), Inches(5.9),
         "Defense Run (--example small)", [
             "$ python pipeline.py --mode defense --example small",
             "",
             "====== DEFENSE · can_gateway ======",
             "  LLM: default=StubLLM · reasoning=StubLLM",
             "  memory: enabled",
             "",
             "[1/6] source-code scanner → 5 findings",
             "[2/6] log analyzer → 3 findings",
             "[3/6] deployment scanner → 2 findings",
             "",
             "[4-6/6] adaptive loop (max 2 rounds)",
             "  round 1 decision: tier=moderate conf=0.72",
             "    recalled: ota_updater(sim=0.6, worked)",
             "  round 1 action: kind=rate_limit",
             "    steps: rate_limit → log_tail → block → incident",
             "  round 1 result: plan=completed guard=PASS",
             "",
             "  replanning: 1 round(s), RESOLVED",
             "  memory: recorded=True (outcome=worked)",
         ], accent_color=ACCENT_CYAN, body_size=12)

add_card(slide, Inches(6.8), Inches(1.3), Inches(6.2), Inches(3.4),
         "Attack Run (brake_tampering)", [
             "[attack] system_info_discovery",
             "  → external=[A2AAgent] safety=[BrakeECU]",
             "[attack] source_code_exploiter → 5 exploits",
             "[attack] deployment_exploiter → 2 exploits",
             "[attack] orchestrator:",
             "  target=Life and Bodily Health conf=0.78",
             "[attack] ethics: allowed=True",
             "[attack] generated 2 script(s)",
             '  - "CAN injection frame" (shell)',
             '  - "Shell-injection probe" (shell)',
         ], accent_color=ACCENT_RED, body_size=12)

add_card(slide, Inches(6.8), Inches(4.9), Inches(6.2), Inches(2.3),
         "CLI Usage", [
             "python pipeline.py --mode defense --example small",
             "python pipeline.py --mode both --example medium",
             "python pipeline.py --code file.py --log app.log \\",
             "  --deployment deploy.yaml",
             "python pipeline.py --mode attack --scenario brake.txt",
         ], accent_color=ACCENT_ORANGE, body_size=12)

# ============================================================
# SLIDE 16: LIMITATIONS
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "5. Limitations")

add_card(slide, Inches(0.3), Inches(1.3), Inches(6.3), Inches(3.0),
         "🤖  LLM Limitations", [
             "• StubLLM: keyword-matched — cannot detect novel patterns",
             "• Real LLM requires API key + network",
             "• Token budget warns but doesn't block (no RAG yet)",
             "• Hₐ judge is probabilistic (fallback on parse failure)",
             "• LLM tool selector is best-effort (empty on failure)",
         ], accent_color=ACCENT_RED, body_size=13)

add_card(slide, Inches(6.8), Inches(1.3), Inches(6.2), Inches(3.0),
         "🔧  MCP Tools — Dry-Run Default", [
             "• Firewall tools need root/admin — rarely available",
             "• network.isolate_node → connector stub (no real SDN)",
             "• runtime.safe_mode → connector stub (no real ECU)",
             "• Port scan/capture require live=True + installed binary",
             "• No SOAR/SIEM integration yet",
         ], accent_color=ACCENT_ORANGE, body_size=13)

add_card(slide, Inches(0.3), Inches(4.5), Inches(6.3), Inches(2.7),
         "📏  Detection Coverage", [
             "• Code scanner: regex — no logic vulns or obfuscation",
             "• Log analyzer: 8 heuristics — no ML anomaly detection",
             "• Deployment: YAML-specific — not arbitrary configs",
             "• Languages: Python, C, C++ only",
             "• Rules manually authored (no auto CVE-to-rule)",
         ], accent_color=ACCENT_PURPLE, body_size=13)

add_card(slide, Inches(6.8), Inches(4.5), Inches(6.2), Inches(2.7),
         "🔄  Architecture Gaps", [
             "• Re-planning limited to 2 rounds",
             "• Memory recall: Jaccard only (no embeddings)",
             "• Batch processing — no real-time streaming",
             "• Single-process — no distributed edge",
             "• Trajectory checks are heuristic (not formal)",
         ], accent_color=ACCENT_CYAN, body_size=13)

# ============================================================
# SLIDE 17: FUTURE WORK
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "6. Future Work")

# Already implemented banner
add_card(slide, Inches(0.3), Inches(1.2), Inches(12.7), Inches(1.4),
         "✓ Already Implemented This Iteration", [
             "Re-planning loop  •  LLM tool selector  •  Hₐ judge oracle  •  Signed memory (HMAC)  •  Trajectory checks  •  Real tools (nmap, bandit, tshark)  •  Token budget  •  Console diagnostics",
         ], accent_color=ACCENT_GREEN, body_size=14)

phases = [
    ("Phase A: RAG", "Embed rules (MiniLM)\nCVE/ATT&CK index\nReplace inlining", ACCENT_CYAN),
    ("Phase B: Real-Time", "Event-driven ingestion\nIncremental analysis\nWebhook-triggered", ACCENT_PURPLE),
    ("Phase C: Vehicle", "CANoe/CAPL scripts\nCARLA simulator\nECU connector", ACCENT_GREEN),
    ("Phase D: Red/Blue", "Automated scoring\nA2A protocol testing\nAdversarial prompts", ACCENT_ORANGE),
    ("Phase E: Memory++", "Vector similarity\nFederated learning\nMemory aging/TTL", ACCENT_RED),
    ("Phase F: Edge", "Quantized LLM (3B)\nDistributed agents\nFormal verification", TEXT_DIM),
]
for i, (title, desc, color) in enumerate(phases):
    col = i % 3
    row = i // 3
    left = Inches(0.3 + col * 4.3)
    top = Inches(2.9 + row * 2.3)
    add_card(slide, left, top, Inches(4.1), Inches(2.1),
             title, desc.split("\n"), accent_color=color, body_size=13)

# ============================================================
# SLIDE 18: SUMMARY
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide)
add_section_title(slide, "Summary")

add_card(slide, Inches(0.3), Inches(1.3), Inches(6.3), Inches(4.5),
         "What We Built", [
             "• 12 agents — defense (6) + attack (6) pipelines",
             "• 20+ MCP tools with real backends (nmap, bandit, tshark)",
             "• Adaptive re-planning — closed loop (max 2 rounds)",
             "• LLM as tool selector — schema-validated + guarded",
             "• Hₐ judge oracle — cuts ASR by 86-88%",
             "• Signed memory — SQLite + HMAC, cross-session learning",
             "• Trajectory guard — compositional + temporal checks",
             "• Token budget — heuristic estimator, RAG warnings",
         ], accent_color=ACCENT_CYAN, body_size=14)

add_card(slide, Inches(0.3), Inches(5.9), Inches(6.3), Inches(1.3),
         "Key Design Decisions", [
             "Static-First  •  Dry-Run Default  •  Per-Step Guard  •  Closed Loop  •  Provider-Agnostic",
         ], accent_color=ACCENT_GREEN, body_size=14)

add_card(slide, Inches(6.8), Inches(1.3), Inches(6.2), Inches(3.0),
         "Grounded in 5 Papers", [
             "[P1] SecurityGuard + Hₐ Judge (4 properties + oracle)",
             "[P2] Asset taxonomy + attack path + poison defense",
             "[P3] YAML rules + static→LLM→merge + token budgeting",
             "[P4] BaseAgent + [placeholder] templating",
             "[P5] Three layers + tiered response + re-planning + memory",
         ], accent_color=ACCENT_PURPLE, body_size=13)

add_card(slide, Inches(6.8), Inches(4.5), Inches(6.2), Inches(2.7),
         "New Modules (this iteration)", [
             "ha_judge.py — LLM action-alignment oracle",
             "memory_store.py — Signed SQLite incident store",
             "tools/mcp_tools.py — Real backends (nmap, bandit, tshark)",
             "tools/tokens.py — Token estimator + budget",
             "tools/log.py — Two-channel console diagnostics",
             "security_guard.py — + check_step + check_trajectory",
         ], accent_color=ACCENT_ORANGE, body_size=13)

# ============================================================
# SLIDE 19: THANK YOU
# ============================================================
slide = prs.slides.add_slide(blank_layout)
set_slide_bg(slide, RGBColor(0x0A, 0x0A, 0x2E))

add_text_box(slide, Inches(1), Inches(2.5), Inches(11), Inches(1.5),
             "Thank You", font_size=56, bold=True, color=ACCENT_CYAN,
             align=PP_ALIGN.CENTER)
add_text_box(slide, Inches(1), Inches(4.2), Inches(11), Inches(0.8),
             "Questions?", font_size=28, color=TEXT_GRAY, align=PP_ALIGN.CENTER)
add_text_box(slide, Inches(1), Inches(5.5), Inches(11), Inches(1.0),
             "CyberLLM — Multi-Agent LLM System for Automotive Cybersecurity\n"
             "12 Agents  •  20+ MCP Tools  •  Adaptive Re-Planning  •  Signed Memory  •  Hₐ Judge",
             font_size=14, color=TEXT_DIM, align=PP_ALIGN.CENTER)

# ============================================================
# SAVE
# ============================================================
output_path = r"c:\Users\benfrajf\Praktikum\CyberLLM\CyberLLM_Presentation.pptx"
prs.save(output_path)
print(f"✓ Presentation saved to: {output_path}")
print(f"  {len(prs.slides)} slides generated")
