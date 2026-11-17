# Automotive Security Benchmark

An independent, **ground-truthed** test corpus for evaluating CyberLLM's
source-code detection on realistic automotive software. The code is original
C / C++ / Rust modelled on real ECU subsystems and seeded with **layered,
non-obvious vulnerabilities** — there are **no hint comments**; every flaw is
located only in `ground_truth.yaml`.

> Design intent: this corpus was written to **test** the program, not to flatter
> it. Vulnerabilities are real-world classes (memory-safety, injection, crypto,
> auth, DoS) placed in plausible code, independent of how CyberLLM detects
> things. A low score on a class is a legitimate, reportable result.

## What's here

| File | Lang | Subsystem | Labelled vulns |
|------|:----:|-----------|:--------------:|
| `can_gateway.c` | C | CAN→Ethernet gateway | 6 |
| `uds_security.c` | C | UDS (ISO 14229) security access | 5 |
| `secure_boot.c` | C | Verified-boot loader | 4 |
| `ota_update.cpp` | C++ | OTA firmware update agent | 6 |
| `telemetry_mqtt.cpp` | C++ | MQTT telemetry publisher | 6 |
| `sensor_fusion.cpp` | C++ | ADAS sensor-fusion buffers | 4 |
| `can_parser.rs` | Rust | CAN-FD parser + C FFI | 5 |
| `crypto_keystore.rs` | Rust | Key store + session tokens | 6 |
| `vehicle_api.rs` | Rust | Local fleet vehicle API | 5 |
| `clean_ringbuffer.c` | C | **clean control** (no vulns) | 0 |
| `clean_config.rs` | Rust | **clean control** (no vulns) | 0 |

**Total: 47 labelled vulnerabilities** across 9 files, plus 2 clean controls.
CWEs covered include CWE-787/125/120/190/191/416/476/362 (memory & concurrency),
CWE-78/89/22/134 (injection), CWE-798/330/327/208/916/347/295 (crypto & secrets),
CWE-287/862/1390 (auth), and CWE-248 (reachable panics / DoS).

## How to run it

Launch the web UI and open the **Benchmark** tab:

```bash
python server.py            # → http://127.0.0.1:8000  → "Benchmark" tab → "Run benchmark"
```

- **Fast** (default): the deterministic layers only (regex floor; bandit/semgrep
  if present). Disable external analyzers for a fully offline run.
- **Deep (AI)**: toggle it on to use the configured live LLM. The optional
  completeness pass makes an additional call per file. Latency and cost depend
  on the provider, input size, and model.

The UI shows coverage %, precision/recall/F1, false positives, coverage bars by
**severity / category / language**, and a per-file accordion marking each
labelled vuln ✓ found / ✗ missed (with the matching finding), plus any extra
unlabeled findings.

Programmatically: `POST /api/benchmark {"deep": false, "window": 3}` (or
`server.run_benchmark(deep=False)`).

## Scoring methodology (location-based)

- A labelled vuln counts as **detected** when the scanner emits a finding whose
  line is within `meta.match_window` (default ±3) of the labelled line/range.
  Matching is **greedy one-to-one** and **does not require the rule_id to equal
  the CWE** — CWE/category are for reporting, so the program isn't penalised for
  naming a rule differently.
- **Recall / coverage** = detected ÷ total labelled.
- **False positives** are measured **only on the clean control files** (where
  any finding is a true FP). **Precision** = TP ÷ (TP + clean-file FP).
- Findings on a vulnerable file that don't match a label are reported as
  **extra (unlabeled)** and are *not* scored as wrong — the label set is
  must-have, not exhaustive (same convention as `evaluate.py`).

## Reproducibility and limits

The original documentation reported roughly 34% Fast coverage and 70% Deep
coverage. Those historical figures are not accompanied by reproducible run
artifacts in the current tree and are not a performance guarantee. Run the
benchmark again before citing results, and record the commit, provider/model,
optional analyzer versions, configuration, and match window.

A precision of 1.0 here means that the two clean controls produced no findings
in that run. It does not establish general precision on arbitrary source code.
Model prompts that request high-confidence findings do not guarantee the absence
of false positives. A disappearing finding after remediation is not proof of
functional correctness.

Keep source lines and `ground_truth.yaml` synchronized when intentionally
changing the corpus. Do not reformat these fixtures during repository cleanup.
The [evaluation guide](../../../docs/evaluation.md) explains both evaluation
paths; [testing](../../../docs/testing.md) describes the offline checks.
