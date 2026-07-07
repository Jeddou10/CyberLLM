# `agents/__init__.py` — the `agents` package marker

`[← back to all_info index](../README.md)`

---

## 1. Purpose & place in the system

A one-line package initializer. It marks `agents/` as a Python package and its
docstring points readers to `base_agent.py` for the template that all agents
extend. There is no code to walk — it exists so `from agents.X import Y` works.

## 2. Imports
None.

## 3. Walkthrough
The entire file is a module docstring (line 1):
`"""Agent implementations. See base_agent.py for the template."""`. No symbols
are exported here; each agent module is imported directly (e.g.
`from agents.decision_agent import DecisionAgent`).

## 4. Edge cases, gotchas & design decisions
- **Intentionally empty.** Unlike `action_engine/__init__.py`, this package does
  not aggregate re-exports — agents are imported by their own module paths, which
  keeps import cycles impossible and makes each agent's origin obvious at the
  call site.
