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
  if present). Offline, instant, free.
- **Deep (AI)**: toggle it on to run the live LLM (Azure gpt-4o) once per
  ingested file — the realistic detector for C/C++/Rust. Costs tokens, ~30 s.

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

## Results (reference)

Measured on this corpus with greedy location matching (±3 lines). Precision is
1.000 in every run — the clean controls produce zero findings.

| Run | Coverage | Precision | Recall | F1 | C | C++ | Rust |
|-----|:--------:|:---------:|:------:|:--:|:---:|:---:|:----:|
| Fast (offline) | **34.0%** (16/47) | 1.000 | 0.340 | 0.508 | 3/15 | 6/16 | 7/16 |
| Deep (gpt-4o + completeness pass) | **~70%** (33/47) | 1.000 | 0.70 | **0.83** | 9/15 | 12/16 | 12/16 |

Deep is the LLM run *with the completeness second pass on*; medium-severity
coverage (races, off-by-one, UAF, reachable panics) rises from 3/11 to ~8/11.
Deep numbers vary a few points run-to-run (the model is non-deterministic);
precision stays 1.000 because the second-pass critic is told to treat
defensive patterns as safe and only report high-confidence defects.

**Progression** (each improvement, Deep coverage / F1):
first cut 25.5% / 0.41  →  +multi-language & native rules 55.3% / 0.71  →
+completeness second pass ~70% / ~0.83.

## Improvements applied to make detection production-grade

- **Multi-language ingestion.** The scanner now accepts `.c/.h/.cc/.cpp/.cxx/
  .hpp/.rs/.go/.java/.js/.ts` (was `.py/.c/.cpp`), so Rust and headers are
  actually analysed (`agents/source_code_scanner.py: CODE_SUFFIXES`).
- **Native-language rules.** `rules/native_rules.yaml` adds C/C++/Rust patterns
  (banned string functions, `system`/`popen`, `unsafe`, `unwrap/expect`,
  `transmute`, weak RNG, `format!` SQL, shell spawning) that lift the offline
  regex floor *and* anchor the LLM (rules-as-context). Each pattern is verified
  not to fire on the clean controls, so precision stays 1.000.
- **Larger LLM budget.** `config.yaml` default `max_tokens` 1024 → 2048 so
  multi-finding scans of larger files aren't truncated.
- **Completeness second pass.** After the first LLM pass, a focused
  "what did you miss?" critic (`scanners.second_pass`) hunts the subtle classes
  pattern-matching misses — races, off-by-one, use-after-free, integer
  over/underflow, reachable panics, missing authorization, TOCTOU. It is told to
  report only high-confidence defects and to treat defensive patterns
  (parameterized queries, bounds-checked copies, constant-time compares,
  Result/Option handling) as safe, so precision is preserved. Gated by `use_llm`
  and a no-op under the offline stub.
- **semgrep**: the AST layer is wired (`scan_code_external`) and activates
  automatically wherever the `semgrep` binary/module is installed — a strong
  offline boost for C/C++/Rust on Linux/CI. It is simply skipped (gracefully)
  where semgrep is absent.

## Honest limitations (read before quoting numbers)

- **Fast vs Deep.** Fast is the deterministic floor (regex + bandit/semgrep
  where present); Deep adds the LLM. Quote Deep for a realistic capability
  number, Fast for the offline/zero-cost baseline.
- **Medium-severity logic/DoS** (subtle races, off-by-one, NULL deref) remain
  the hardest class and are where most remaining misses sit — the most useful
  signal for where to invest next.
- The label set is *must-have*, not exhaustive: "extra (unlabeled)" findings on
  vulnerable files are reported but not scored as wrong.
