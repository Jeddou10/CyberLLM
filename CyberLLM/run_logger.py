"""Per-run step-by-step logger for debugging.

What it produces
----------------
For every pipeline run (defense or attack), a fresh directory under
`run_logs/<timestamp>_<mode>_<scenario>/` is created containing:

  00_meta.json                — mode, scenario, paths, timestamps.
  01_inputs.json              — every Input with provenance + content preview.
  02_static_<scanner>.json    — deterministic static-analyzer findings, per scanner.
  03_<agent>_prompt.txt       — exact prompt sent to the LLM by that agent.
  03_<agent>_response.txt     — raw LLM response text.
  03_<agent>_findings.json    — parsed findings (merged static + LLM).
  04_…                        — each subsequent agent gets the next numeric prefix.
  ZZ_decision.json            — defense: the DecisionAgent's structured decision.
  ZZ_action.json              — defense: the ActionGenerator's proposal.
  ZZ_guard.json               — defense: SecurityGuard verdict.
  ZZ_instance.json            — attack: SystemInfoDiscovery system instance.
  ZZ_plan.json                — attack: AttackOrchestrator plan.
  ZZ_ethics.json              — attack: EthicsGuard verdict.
  scripts/<NN>_<rule>.<ext>   — attack: one file per generated attack script.
  _trace.log                  — single-line plaintext trace, easy to `tail -f`.
  _summary.md                 — human-friendly Markdown walkthrough of the run.

Why a separate directory per run
--------------------------------
- Easy to diff successive runs.
- Easy to grep across runs without losing structure.
- The `_summary.md` is what you skim first; everything else is for
  drill-down debugging.

Why the name `run_logs/` and not `logging/`
-------------------------------------------
Python has a stdlib module called `logging`. A directory named
`logging/` in the project root can become a namespace-package
candidate and shadow stdlib imports in some edge cases. `run_logs/`
avoids that risk entirely while still being self-documenting.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe(name: str) -> str:
    return _SAFE_NAME_RE.sub("-", name)[:60] or "run"


def _to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, Path):
        return str(obj)
    return obj


class RunLogger:
    """One logger instance per scenario run."""

    def __init__(self, root_dir: Path, mode: str, scenario: str):
        self.mode = mode
        self.scenario = scenario
        self.started_at = datetime.now()
        ts = self.started_at.strftime("%Y%m%dT%H%M%S")
        self.dir = root_dir / f"{ts}_{_safe(mode)}_{_safe(scenario)}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self._step = 0
        self._trace_lines: list[str] = []
        self._summary_blocks: list[str] = []
        self.root_dir = root_dir
        self._scripts_dir = self.dir / "scripts"
        self._meta: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def log_meta(self, meta: dict) -> None:
        self._meta.update(meta)
        self._meta["started_at"] = self.started_at.isoformat()
        self._write_json("00_meta.json", self._meta)
        self.trace(f"=== START mode={self.mode} scenario={self.scenario} ===")
        self._summary_blocks.append(
            f"# Run summary — `{self.mode}` / `{self.scenario}`\n\n"
            f"- **started**: {self._meta['started_at']}\n"
            f"- **inputs**: {json.dumps(meta.get('inputs', {}))}\n"
        )

    def log_inputs(self, inputs: list) -> None:
        rendered = []
        for i in inputs:
            rendered.append({
                "source": getattr(i, "source", "?"),
                "trust_level": getattr(i, "trust_level", "?"),
                "content_length": len(getattr(i, "content", "") or ""),
                "content_preview": (getattr(i, "content", "") or "")[:300],
            })
        n = self._next()
        self._write_json(f"{n}_inputs.json", rendered)
        self.trace(f"inputs: {len(inputs)} item(s)")
        self._summary_blocks.append(
            f"## Inputs ({len(inputs)})\n\n" +
            "\n".join(f"- `{r['source']}` "
                      f"[trust={r['trust_level']}, "
                      f"{r['content_length']} chars]"
                      for r in rendered) + "\n"
        )

    def log_static(self, scanner_name: str, findings: list) -> None:
        n = self._next()
        rendered = [_to_jsonable(f) for f in findings]
        self._write_json(f"{n}_static_{_safe(scanner_name)}.json", rendered)
        self.trace(f"static[{scanner_name}]: {len(findings)} finding(s)")
        if findings:
            preview = ", ".join(sorted({getattr(f, 'rule_id', '?')
                                         for f in findings}))
            self._summary_blocks.append(
                f"## Static analyzer — {scanner_name}\n\n"
                f"- {len(findings)} hit(s): `{preview}`\n"
            )

    def log_agent(
        self,
        agent_id: str,
        prompt: str | None,
        response: str | None,
        findings: list | None = None,
    ) -> None:
        n = self._next()
        if prompt is not None:
            (self.dir / f"{n}_{_safe(agent_id)}_prompt.txt").write_text(
                prompt, encoding="utf-8")
        if response is not None:
            (self.dir / f"{n}_{_safe(agent_id)}_response.txt").write_text(
                response, encoding="utf-8")
        if findings is not None:
            rendered = [_to_jsonable(f) for f in findings]
            self._write_json(f"{n}_{_safe(agent_id)}_findings.json", rendered)

        n_findings = len(findings) if findings is not None else "?"
        plen = len(prompt) if prompt else 0
        rlen = len(response) if response else 0
        self.trace(f"agent[{agent_id}]: prompt={plen}c response={rlen}c "
                   f"findings={n_findings}")
        self._summary_blocks.append(
            f"## Agent — {agent_id}\n\n"
            f"- prompt size: {plen} chars\n"
            f"- response size: {rlen} chars\n"
            f"- merged findings: {n_findings}\n"
        )

    def log_decision(self, decision) -> None:
        n = self._next()
        d = {
            "summary": getattr(decision, "summary", ""),
            "asset_categories_touched": getattr(
                decision, "asset_categories_touched", []),
            "recommended_tier": getattr(decision, "recommended_tier", ""),
            "confidence": getattr(decision, "confidence", 0.0),
            "justification": getattr(decision, "justification", ""),
            "finding_rule_ids": [
                getattr(f, "rule_id", "?")
                for f in getattr(decision, "findings", [])
            ],
        }
        self._write_json(f"{n}_decision.json", d)
        self.trace(f"decision: tier={d['recommended_tier']} "
                   f"conf={d['confidence']:.2f} "
                   f"assets={d['asset_categories_touched']}")
        self._summary_blocks.append(
            f"## Decision (defense)\n\n"
            f"- **tier**: `{d['recommended_tier']}`\n"
            f"- **confidence**: {d['confidence']:.2f}\n"
            f"- **assets**: {d['asset_categories_touched']}\n"
            f"- **justification**: {d['justification']}\n"
        )

    def log_action(self, action) -> None:
        n = self._next()
        a = {
            "kind": getattr(action, "kind", ""),
            "target": getattr(action, "target", ""),
            "parameters": getattr(action, "parameters", {}),
            "rationale": getattr(action, "rationale", ""),
        }
        self._write_json(f"{n}_action.json", a)
        self.trace(f"action: kind={a['kind']} target={a['target']}")
        self._summary_blocks.append(
            f"## Action proposal (defense)\n\n"
            f"- **kind**: `{a['kind']}`\n"
            f"- **target**: `{a['target']}`\n"
            f"- **parameters**: `{a['parameters']}`\n"
        )

    def log_action_plan(self, plan, report) -> None:
        n = self._next()
        self._write_json(f"{n}_action_plan.json", plan.to_dict())
        n2 = self._next()
        self._write_json(f"{n2}_action_report.json",
                          report.to_dict() if report else None)
        # MCP audit log lives on the registry; if accessible, persist it.
        registry = getattr(getattr(report, "plan", None), "_registry", None)
        if registry is not None:
            n3 = self._next()
            self._write_json(f"{n3}_mcp_audit.json", registry.audit)
        self.trace(
            f"action_plan: steps={len(plan.steps)} "
            f"status={getattr(report, 'status', 'n/a')}"
        )
        if report is not None:
            self._summary_blocks.append(
                f"## Action plan & report\n\n"
                f"- **status**: `{report.status.value}`\n"
                f"- **summary**: {report.summary}\n"
                f"- **blast radius**: `{plan.blast_radius}`\n"
                f"- **steps**: {len(plan.steps)} — completed "
                f"{report.completed} · failed {report.failed} · "
                f"refused {report.refused} · rolled-back {report.rolled_back} · "
                f"skipped {report.skipped}\n"
            )
            # List each step's outcome.
            lines = []
            for s in plan.steps:
                lines.append(
                    f"  - `{s.tool}` ({s.kind.value}) → "
                    f"**{s.status.value}** — {s.description}"
                )
            if lines:
                self._summary_blocks.append("\n".join(lines) + "\n")

    def log_guard(self, verdict) -> None:
        n = self._next()
        v = _to_jsonable(verdict)
        self._write_json(f"{n}_guard.json", v)
        self.trace(f"guard: allowed={v.get('allowed')} ({v.get('reason', '')[:80]})")
        self._summary_blocks.append(
            f"## SecurityGuard verdict (paper 1)\n\n"
            f"- **allowed**: `{v.get('allowed')}`\n"
            f"- task_alignment: `{v.get('task_alignment')}` | "
            f"action_alignment: `{v.get('action_alignment')}` | "
            f"source_authorization: `{v.get('source_authorization')}` | "
            f"data_isolation: `{v.get('data_isolation')}`\n"
            f"- **reason**: {v.get('reason')}\n"
        )

    # ---- attack-side ----------------------------------------------------

    def log_system_instance(self, instance) -> None:
        n = self._next()
        d = {
            "external_actors": getattr(instance, "external_actors", []),
            "safety_actors": getattr(instance, "safety_actors", []),
            "n_actors": len(getattr(instance, "actors", []) or []),
            "n_datasources": len(getattr(instance, "datasources", []) or []),
            "n_edges": len(getattr(instance, "edges", []) or []),
            "notes": getattr(instance, "notes", []),
        }
        self._write_json(f"{n}_instance.json", d)
        self.trace(f"instance: external={d['external_actors']} "
                   f"safety={d['safety_actors']}")
        self._summary_blocks.append(
            f"## System instance (attack)\n\n"
            f"- external actors: `{d['external_actors']}`\n"
            f"- safety actors: `{d['safety_actors']}`\n"
            f"- {d['n_actors']} actors, {d['n_datasources']} datasources, "
            f"{d['n_edges']} edges\n"
        )

    def log_plan(self, plan) -> None:
        n = self._next()
        d = {
            "scenario": getattr(plan, "scenario", ""),
            "target_asset": getattr(plan, "target_asset", ""),
            "summary": getattr(plan, "summary", ""),
            "chosen_rule_ids": [
                getattr(f, "rule_id", "?")
                for f in getattr(plan, "chosen_findings", [])
            ],
            "poison_path": getattr(plan, "poison_path", []),
            "trigger_path": getattr(plan, "trigger_path", []),
            "confidence": getattr(plan, "confidence", 0.0),
            "justification": getattr(plan, "justification", ""),
        }
        self._write_json(f"{n}_plan.json", d)
        self.trace(f"plan: target={d['target_asset']} "
                   f"conf={d['confidence']:.2f} chose={d['chosen_rule_ids']}")
        self._summary_blocks.append(
            f"## Attack plan (orchestrator)\n\n"
            f"- **target**: `{d['target_asset']}`\n"
            f"- **chosen**: `{d['chosen_rule_ids']}`\n"
            f"- **poison path**: {d['poison_path']}\n"
            f"- **trigger path**: {d['trigger_path']}\n"
            f"- **confidence**: {d['confidence']:.2f}\n"
            f"- **justification**: {d['justification']}\n"
        )

    def log_ethics(self, verdict) -> None:
        n = self._next()
        v = _to_jsonable(verdict)
        self._write_json(f"{n}_ethics.json", v)
        self.trace(f"ethics: allowed={v.get('allowed')} ({v.get('reason', '')[:80]})")
        self._summary_blocks.append(
            f"## EthicsGuard verdict (attack)\n\n"
            f"- **allowed**: `{v.get('allowed')}`\n"
            f"- scope_ok: `{v.get('scope_ok')}` | "
            f"target_ok: `{v.get('target_ok')}` | "
            f"non_destructive: `{v.get('non_destructive')}`\n"
            f"- **reason**: {v.get('reason')}\n"
        )

    def log_attack_scripts(self, scripts: list, redacted: list[str]) -> None:
        self._scripts_dir.mkdir(parents=True, exist_ok=True)
        ext_map = {"shell": "sh", "python": "py", "http": "http",
                   "payload": "json"}
        for i, s in enumerate(scripts, start=1):
            ext = ext_map.get(getattr(s, "language", "payload"), "txt")
            fname = f"{i:02d}_{_safe(getattr(s, 'rule_id', 'ATK'))}_" \
                    f"{_safe(getattr(s, 'title', 'script'))[:30]}.{ext}"
            header = (
                f"# rule_id: {getattr(s, 'rule_id', '?')}\n"
                f"# title:   {getattr(s, 'title', '?')}\n"
                f"# target:  {getattr(s, 'target_hint', '?')}\n"
                f"# effect:  {getattr(s, 'expected_effect', '?')}\n"
                f"# ----------------------------------------\n\n"
            )
            (self._scripts_dir / fname).write_text(
                header + getattr(s, "body", ""), encoding="utf-8")
        self.trace(f"scripts: generated={len(scripts)} redacted={len(redacted)}")
        if scripts or redacted:
            lines = [f"- `{s.rule_id}` — {s.title} (`{s.language}`)"
                     for s in scripts]
            self._summary_blocks.append(
                f"## Generated attack scripts ({len(scripts)})\n\n"
                + ("\n".join(lines) if lines else "(none)") + "\n"
                + (f"\nRedacted (destructive): `{redacted}`\n" if redacted else "")
            )

    # ------------------------------------------------------------------
    # finalisation
    # ------------------------------------------------------------------

    def finalize(self) -> None:
        ended = datetime.now()
        self._meta["ended_at"] = ended.isoformat()
        self._meta["duration_seconds"] = (ended - self.started_at).total_seconds()
        self._write_json("00_meta.json", self._meta)
        self.trace(f"=== END duration={self._meta['duration_seconds']:.2f}s ===")
        (self.dir / "_trace.log").write_text(
            "".join(self._trace_lines), encoding="utf-8")
        (self.dir / "_summary.md").write_text(
            "\n".join(self._summary_blocks) + "\n", encoding="utf-8")

        # latest-pointer (helpful when iterating quickly)
        latest = self.root_dir / f"_latest_{self.mode}.txt"
        latest.write_text(str(self.dir.name), encoding="utf-8")

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def trace(self, msg: str) -> None:
        line = f"{datetime.now().isoformat(timespec='milliseconds')}  {msg}\n"
        self._trace_lines.append(line)

    def _next(self) -> str:
        self._step += 1
        return f"{self._step:02d}"

    def _write_json(self, name: str, obj: Any) -> None:
        (self.dir / name).write_text(
            json.dumps(_to_jsonable(obj), indent=2, default=str),
            encoding="utf-8",
        )
