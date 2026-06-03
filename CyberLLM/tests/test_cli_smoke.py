"""CLI smoke tests.

Run pipeline.py in a subprocess to make sure the entry points still
work. Cheap insurance against argparse / import-time bugs.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent.parent


def _env_for_subprocess() -> dict:
    """Propagate the user-site-packages path on Windows + force UTF-8."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    site = (
        r"C:\Users\Oussama_Jeddou\AppData\Roaming\Python\Python311\site-packages"
    )
    if os.path.isdir(site):
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (site + os.pathsep + existing) if existing else site
    return env


def _run(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(HERE / "pipeline.py"), *args],
        cwd=str(HERE),
        env=_env_for_subprocess(),
        capture_output=True, text=True,
        timeout=timeout,
    )


class TestCLI:

    def test_help_exits_zero(self):
        cp = _run("--help")
        assert cp.returncode == 0
        assert "--mode" in cp.stdout

    def test_unknown_example_set_fails_cleanly(self):
        cp = _run("--example", "nonsense")
        # The pipeline raises SystemExit with a helpful message.
        assert cp.returncode != 0
        assert "Unknown example set" in (cp.stderr + cp.stdout)

    def test_defense_small_batch_runs(self):
        cp = _run("--mode", "defense", "--example", "small", timeout=120)
        assert cp.returncode == 0, cp.stderr[-500:]
        assert "DEFENSE summary" in cp.stdout

    def test_attack_small_batch_runs(self):
        cp = _run("--mode", "attack", "--example", "small", timeout=120)
        assert cp.returncode == 0, cp.stderr[-500:]
        assert "ATTACK summary" in cp.stdout
