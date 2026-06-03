"""Console diagnostics for the pipeline.

Two channels, kept strictly separate:

  * **stdout** is reserved for *results* — the batch summary tables and the
    single-run record JSON. Piping `python pipeline.py ... > out.json`
    therefore yields a clean, machine-readable artefact.
  * **stderr** (this module) carries all human-facing progress / debug
    chatter, so it never corrupts the result on stdout.

Verbosity has two dials:

  * `verbose` (default on)  — section headers, per-step counts, decisions,
    guard verdicts. This is what you watch during a normal run.
  * `debug`  (`-v` on the CLI) — adds timings, token estimates, static-vs-LLM
    splits, recalled-memory detail, per-action-step status, and truncated
    previews of every prompt and LLM response. This is the "what did gpt-4o
    actually say?" view.
"""

from __future__ import annotations

import sys
import time
from contextlib import contextmanager


class Console:
    def __init__(self, verbose: bool = True, debug: bool = False, stream=None):
        self.verbose = verbose
        self.debug_on = debug
        self.stream = stream or sys.stderr

    # ---- low-level ------------------------------------------------------
    def _w(self, s: str = "") -> None:
        print(s, file=self.stream, flush=True)

    # ---- info channel (gated by `verbose`) ------------------------------
    def section(self, title: str) -> None:
        if self.verbose:
            self._w(f"\n{'='*6} {title} {'='*6}")

    def info(self, msg: str) -> None:
        if self.verbose:
            self._w(msg)

    def step(self, msg: str) -> None:
        if self.verbose:
            self._w(f"  - {msg}")

    def kv(self, label: str, value) -> None:
        if self.verbose:
            self._w(f"  {label:<12}: {value}")

    def warn(self, msg: str) -> None:
        # Refusals / violations — shown at the normal verbosity level (so a
        # default run surfaces them) but silenced by -q / verbose=False.
        if self.verbose:
            self._w(f"  [!] {msg}")

    # ---- debug channel (gated by `debug`) -------------------------------
    def detail(self, msg: str) -> None:
        if self.debug_on:
            self._w(f"      . {msg}")

    def blob(self, label: str, text: str, limit: int = 1000) -> None:
        """Preview a long string (prompt / response) — debug only."""
        if not self.debug_on:
            return
        text = text or ""
        clipped = (text if len(text) <= limit
                   else text[:limit] + f" …[+{len(text) - limit} more chars]")
        self._w(f"      . {label} ({len(text)} chars):")
        for line in (clipped.splitlines() or [""]):
            self._w(f"        | {line}")

    @contextmanager
    def timed(self, label: str):
        """Time a block and report the elapsed ms (helpful with a real LLM)."""
        start = time.perf_counter()
        try:
            yield
        finally:
            ms = (time.perf_counter() - start) * 1000.0
            self.detail(f"{label} took {ms:.0f} ms")
