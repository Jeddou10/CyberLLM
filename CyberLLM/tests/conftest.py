"""Shared pytest fixtures.

Why
---
Most of our tests need the merged rule set and a stub-backed LLM
client. Centralising those here keeps individual test files short.

Path note
---------
This file adjusts `sys.path` so test modules can `import pipeline`,
`import agents.…`, etc. directly without having to install the
project as a package.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml


# Make the CyberLLM/ project root importable.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _force_stub_llm(monkeypatch):
    """Keep the test suite hermetic and deterministic.

    `config.yaml` now selects the `github` (gpt-4o) provider. Without this
    guard, a developer who has a real GITHUB_TOKEN exported would make the
    integration tests hit the network (and cost tokens). Forcing the stub
    for the whole suite keeps tests offline and reproducible regardless of
    the configured provider or any token present in the env / .env.
    """
    monkeypatch.setenv("CYBERLLM_FORCE_STUB", "1")


@pytest.fixture(scope="session")
def project_root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def all_rules() -> dict:
    """Merged rule set, same way pipeline.load_rules merges them."""
    from pipeline import load_rules, load_config
    return load_rules(load_config())


@pytest.fixture(scope="session")
def cfg() -> dict:
    from pipeline import load_config
    return load_config()


@pytest.fixture()
def stub_llm():
    from llm_client import LLMClient
    return LLMClient.create({"provider": "stub", "model": "stub-echo",
                             "temperature": 0.0, "max_tokens": 256})


# Re-usable code snippets that the static analyzer should recognise.
VULN_SNIPPETS = {
    "CODE-001 shell injection": (
        "import subprocess\n"
        "def diag(x):\n"
        "    return subprocess.call(x, shell=True)\n"
    ),
    "CODE-002 md5 password": (
        "import hashlib\n"
        "def hash_pw(p):\n"
        "    return hashlib.md5(p.encode()).hexdigest()\n"
    ),
    "CODE-003 hardcoded api key": (
        "API_KEY = 'sk_live_8f4d2c5a9b1e3a7d4f6c'\n"
    ),
    "CODE-005 pickle.loads": (
        "import pickle\n"
        "def load(b): return pickle.loads(b)\n"
    ),
    "CODE-006 verify=False": (
        "import requests\n"
        "requests.post('https://x', verify=False)\n"
    ),
    "CODE-012 sql fstring": (
        "def find(u, conn):\n"
        "    return conn.execute(f\"SELECT * FROM users WHERE u='{u}'\")\n"
    ),
    "CODE-013 strcpy C": "void f(char *s){ char b[8]; strcpy(b, s); }\n",
    "CODE-020 jwt none": (
        "import jwt\n"
        "jwt.decode(t, k, algorithms=['HS256', 'none'])\n"
    ),
    "CODE-038 base64 eval": (
        "import base64\n"
        "eval(base64.b64decode(payload))\n"
    ),
}


CLEAN_SNIPPETS = {
    "argon2 clean": (
        "from argon2 import PasswordHasher\n"
        "_ph = PasswordHasher()\n"
        "def hash_pw(p): return _ph.hash(p)\n"
    ),
    "subprocess argv list (safe)": (
        "import subprocess\n"
        "subprocess.run(['ls', '-l'], check=True)\n"
    ),
}


@pytest.fixture()
def vuln_snippets() -> dict[str, str]:
    return VULN_SNIPPETS


@pytest.fixture()
def clean_snippets() -> dict[str, str]:
    return CLEAN_SNIPPETS


@pytest.fixture()
def clean_deployment_yaml() -> str:
    return yaml.safe_dump({
        "actors": [
            {"id": "in_car_agent", "type": "LLMAgent", "trust_level": "authenticated"},
            {"id": "hpc", "type": "HighPerformanceComputer", "trust_level": "authenticated"},
            {"id": "zone", "type": "ZoneECU", "trust_level": "authenticated"},
        ],
        "datasources": [
            {"id": "ltm", "holds": ["prefs"]},
        ],
        "edges": [
            {"source": "hpc", "target": "zone", "primitive": "communicate",
             "transport": "ethernet", "standard": "IEEE-1722"},
        ],
    })


@pytest.fixture()
def bad_deployment_yaml() -> str:
    return yaml.safe_dump({
        "actors": [
            {"id": "hpc", "type": "HighPerformanceComputer", "trust_level": "authenticated"},
            {"id": "zone", "type": "ZoneECU", "trust_level": "authenticated"},
            {"id": "atk", "type": "ExternalA2AAgent", "trust_level": "external"},
            {"id": "pg", "type": "Database", "bind_address": "0.0.0.0",
             "trust_level": "authenticated"},
            {"id": "sec", "type": "SecretStore", "access_policy": "world-readable",
             "trust_level": "authenticated"},
        ],
        "datasources": [{"id": "long_term_memory", "holds": ["prefs"]}],
        "edges": [
            # TOP-001: HPC ↔ Zone NOT on Ethernet/IEEE-1722
            {"source": "hpc", "target": "zone", "primitive": "communicate",
             "transport": "can_fd", "standard": "vendor_specific"},
            # TOP-002: external write to memory
            {"source": "atk", "target": "long_term_memory", "primitive": "write"},
            # TOP-008: external respond to in-vehicle agent
            {"source": "atk", "target": "in_car_agent", "primitive": "respond"},
        ],
    })
