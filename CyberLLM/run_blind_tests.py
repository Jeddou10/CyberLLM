"""Run all blind test files through the pipeline and collect code findings."""
import json
import os
import pathlib
import subprocess
import sys

pyexe = sys.executable
files = sorted(pathlib.Path("examples/test_blind").glob("*"))
files = [f for f in files if f.suffix in (".py", ".c")]
results = {}

for f in files:
    print(f"Running: {f.name}...", flush=True)
    r = subprocess.run(
        [pyexe, "pipeline.py", "--mode", "defense", "--code", str(f)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**os.environ},
    )
    try:
        data = json.loads(
            pathlib.Path("memory/last_run_defense.json").read_text(encoding="utf-8")
        )
        code_findings = [
            x for x in data["findings"] if x["source_agent"] == "source_code_scanner"
        ]
        results[f.name] = code_findings
        print(f"  Done: {len(code_findings)} code findings", flush=True)
    except Exception as e:
        print(f"  ERROR: {e}", flush=True)
        results[f.name] = []

print()
print("=" * 80)
print(f"{'FILE':<35} {'#FINDS':<8} RULE_IDS")
print("=" * 80)
for fname, findings in results.items():
    rule_ids = [x["rule_id"] for x in findings]
    print(f"{fname:<35} {len(findings):<8} {rule_ids}")
    for x in findings:
        line = x.get("line", "?")
        rid = x["rule_id"]
        sev = x["severity"]
        exp = x["explanation"][:60]
        print(f"    {rid:<12} {sev:<10} L{str(line):<5} {exp}")
    print()
