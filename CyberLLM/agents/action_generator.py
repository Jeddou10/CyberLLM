"""Defense action generator.

Thin back-compat shim. The real implementation lives in the
`action_engine` package: a planner that consumes the decision agent's
findings, builds a multi-step plan from a rule-id-keyed playbook
catalogue, then runs the plan through an MCP-style tool registry
with pre/post-condition verification and step-level rollback.

The pipeline keeps importing `ActionGenerator` and `Action` from this
module exactly as before.
"""

from .action_engine import Action, ActionGenerator   # noqa: F401

__all__ = ["Action", "ActionGenerator"]
