"""Attack-side agents — mirror of the defense agents, matching the
supervisor's second diagram.

These agents do **not** execute attacks against real targets without
explicit authorisation. They produce attack *plans* + *scripts*
intended for use in:

- red-team exercises against authorised systems,
- AgentHeLLM-style threat modelling (paper 2),
- training data for the defense pipeline (paper 1's contextual
  security framework gains accuracy when it sees concrete attacks).

The `EthicsGuard` (see `ethics_guard.py`) blocks execution against
unauthorised targets — analogous to the defense-side `SecurityGuard`.
"""

from .source_code_exploiter import SourceCodeExploiterAgent
from .deployment_exploiter import DeploymentExploiterAgent
from .system_info_discovery import SystemInfoDiscoveryAgent
from .attack_orchestrator import AttackOrchestratorAgent, AttackPlan
from .attack_generator import AttackGeneratorAgent, AttackScript
from .ethics_guard import EthicsGuard, EthicsVerdict
