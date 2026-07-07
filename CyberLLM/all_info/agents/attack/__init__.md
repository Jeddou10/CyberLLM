# `agents/attack/__init__.py` — the attack package surface

`[← back to all_info index](../../README.md)`

---

## 1. Purpose & place in the system

Package initializer for the **attack (red-team) agents** — the mirror of the
defense agents, matching the supervisor's "diagram 2." Its docstring is also a
safety statement: these agents produce attack *plans* and *scripts* (for
authorized red-team exercises, P2 threat modelling, and as training data that
makes the defense pipeline more accurate), and they do **not** execute attacks
against real targets without authorization — the `EthicsGuard` is the offensive
analogue of the defense `SecurityGuard`.

## 2. Imports / re-exports — lines 17–22
Re-exports the six attack classes + their result shapes:
`SourceCodeExploiterAgent`, `DeploymentExploiterAgent`,
`SystemInfoDiscoveryAgent`, `AttackOrchestratorAgent`+`AttackPlan`,
`AttackGeneratorAgent`+`AttackScript`, `EthicsGuard`+`EthicsVerdict`. This is why
`pipeline.py` can do `from agents.attack import (...)` in one statement.

## 3. Walkthrough
No logic — pure re-export so the attack pipeline has one import path.

## 4. Edge cases, gotchas & design decisions
- **The docstring is an ethics contract.** It states up front that nothing here
  attacks real systems unauthorized; the `EthicsGuard` enforces it in code.
- **Symmetry with defense.** The exports line up one-to-one with the defense
  agents (scanner↔exploiter, decision↔orchestrator, action↔generator,
  security-guard↔ethics-guard), which is the whole design conceit of the mirror
  pipeline.
