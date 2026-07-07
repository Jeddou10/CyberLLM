"""Source-code scanner agent.

Inspiration:
- Paper 3 (TUM) Prompt Construct 1 — extract VSS/CAN signals from code.
- Paper 4 (Härer) — schema-driven agent with an extract → evaluate
  action chain.
- Paper 1 — code findings are tagged with the rule_id of the rule they
  violate, so the security guard can later cross-reference.
"""

from __future__ import annotations
import os
from pathlib import Path

from .base_agent import BaseAgent, AgentResult, Finding, Input
from tools.static_analyzer import (
    merge_findings, merge_static_layers, scan_code_external,
    scan_code_static, staticfinding_to_finding,
)

# Source-file suffixes the code scanner ingests. The regex floor is
# language-agnostic; the external AST layer routes by suffix (bandit for
# Python, semgrep for the rest); the LLM pass is fully language-agnostic.
CODE_SUFFIXES = (".py", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx",
                 ".rs", ".go", ".java", ".js", ".ts")


class SourceCodeScannerAgent(BaseAgent):
    PROMPT = (
        "You are a source-code security scanner.\n"
        "Analyze the following code and identify insecure patterns "
        "(command injection, hard-coded secrets, weak crypto, unsafe "
        "deserialization, missing input validation, race conditions).\n\n"
        "Rules in scope (only consider these):\n[rules]\n\n"
        "Deterministic static-analysis hits already produced for this "
        "file (you may refine, explain, or extend them — do not "
        "duplicate them):\n[static_findings]\n\n"
        "Source code (file: [filename]):\n```\n[code]\n```\n\n"
        "Return JSON of the form: {\"findings\": [{\"rule_id\": \"...\", "
        "\"severity\": \"low|medium|high|critical\", \"line\": <int>, "
        "\"evidence\": \"...\", \"explanation\": \"...\"}, ...]}"
    )

    # Completeness "what did you miss?" critic (roadmap: second pass). Phrased
    # to AVOID the offline stub's trigger keywords, so under the stub it returns
    # nothing (no-op) and only a real model does extra work. Targets the subtle,
    # semantic classes that pattern-matching and a single pass tend to miss.
    SECOND_PASS_PROMPT = (
        "You are reviewing one program file for security defects an earlier "
        "automated pass may have OVERLOOKED. That pass already reported these "
        "rule ids: [found].\n\n"
        "Hunt specifically for SUBTLE, semantic issues that pattern matching "
        "misses:\n"
        " - race conditions / unsynchronised shared state,\n"
        " - off-by-one and other boundary errors,\n"
        " - NULL or dangling pointer dereference, use-after-free, double free,\n"
        " - integer overflow / underflow feeding an allocation or copy,\n"
        " - reachable panics / aborts on attacker-influenced input,\n"
        " - missing authorization or capability checks,\n"
        " - time-of-check to time-of-use (TOCTOU) gaps.\n\n"
        "Report ONLY genuine, newly-identified defects you are HIGHLY CONFIDENT "
        "are exploitable — do NOT repeat any rule id listed above. Treat these "
        "defensive patterns as SAFE and never report them: parameterized / bound "
        "queries, length-checked or bounds-checked copies, constant-time "
        "comparisons, and Result/Option error handling that does not unwrap. If "
        "the file appears secure, return an empty list. Map each real defect to "
        "the closest rule id you know, or a CWE id.\n\n"
        "File [filename]:\n```\n[code]\n```\n\n"
        "Return JSON: {\"findings\": [{\"rule_id\": \"...\", \"severity\": "
        "\"low|medium|high|critical\", \"line\": <int>, \"evidence\": \"...\", "
        "\"explanation\": \"...\"}, ...]}"
    )

    def run(self, inputs: list[Input]) -> AgentResult:
        code_inputs = [i for i in inputs if i.source.endswith(CODE_SUFFIXES)]
        if not code_inputs:
            return AgentResult(self.agent_id, self.objective, [])

        rules = self.cfg.get("rules_full", {})
        # The AST-based external analyser (bandit/semgrep) is an *extra*
        # detection layer. On by default; disabled by config flag or by the
        # CYBERLLM_NO_EXTERNAL_STATIC kill-switch (the test suite sets it so
        # results stay deterministic whether or not bandit is installed).
        external_on = (self.cfg.get("external_static", True)
                       and not os.environ.get("CYBERLLM_NO_EXTERNAL_STATIC"))
        # When the configured LLM is the offline stub, its canned findings
        # are wrong for *arbitrary real* code — so callers (e.g. the web UI)
        # set use_llm=False to return the deterministic regex+bandit layers
        # only. Defaults True (examples / real provider).
        use_llm = self.cfg.get("use_llm", True)
        all_findings: list[Finding] = []
        raw_texts: list[str] = []
        self.last_static_findings = []

        for inp in code_inputs:
            # ---- 1a. Deterministic static FLOOR (regex over the rules) ---
            static_hits = scan_code_static(inp.content, inp.source, rules)
            static_as_findings = staticfinding_to_finding(static_hits, Finding)
            for f in static_as_findings:
                f.source_agent = self.agent_id

            # ---- 1b. External AST layer (bandit/semgrep) — regex wins ----
            if external_on:
                ext_hits = scan_code_external(inp.content, inp.source, rules)
                ext_findings = staticfinding_to_finding(ext_hits, Finding)
                # keep their tool name ('bandit'/'semgrep') as source_agent
                static_layer = merge_static_layers(static_as_findings, ext_findings)
            else:
                static_layer = static_as_findings
            self.last_static_findings.extend(static_layer)

            # ---- 2. LLM pass — given the static layer as context --------
            if use_llm:
                self.data["code"] = inp.content
                self.data["filename"] = inp.source
                self.data["rules"] = self.cfg.get("rules_snippet", "")
                self.data["static_findings"] = (
                    "\n".join(f"- {f.rule_id} (line {f.line}): {f.evidence}"
                              for f in static_layer)
                    or "(no static findings)"
                )
                prompt = self.template(self.PROMPT)
                resp = self.call_llm(prompt)
                raw_texts.append(resp.text)
                llm_findings = self._parse_findings(resp.text)
            else:
                llm_findings = []

            # ---- 3. Merge (static layer wins on dedup) ------------------
            merged = merge_findings(static_layer, llm_findings)

            # ---- 4. Completeness second pass (optional) ----------------
            # A focused critic that looks for the subtle classes (races,
            # off-by-one, UAF, integer over/underflow, reachable panics,
            # missing authz, TOCTOU) the first pass misses. Gated by use_llm
            # AND the `second_pass` flag; a no-op under the offline stub.
            if use_llm and self.cfg.get("second_pass"):
                self.data["code"] = inp.content
                self.data["filename"] = inp.source
                self.data["found"] = (
                    ", ".join(sorted({f.rule_id for f in merged})) or "(none)")
                resp2 = self.call_llm(self.template(self.SECOND_PASS_PROMPT))
                raw_texts.append(resp2.text)
                missed = self._parse_findings(resp2.text)
                merged = merge_findings(merged, missed)

            all_findings.extend(merged)

        return AgentResult(
            agent_id=self.agent_id,
            objective=self.objective,
            findings=all_findings,
            raw_llm_text="\n---\n".join(raw_texts),
        )

    # ------ convenience for the demo --------------------------------------
    @staticmethod
    def load_example(path: str | Path) -> Input:
        p = Path(path)
        return Input(content=p.read_text(encoding="utf-8"),
                     source=p.name, trust_level="external")
