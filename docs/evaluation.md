# Evaluation

CyberLLM has two separate evaluation paths. Report which one was used, along with
the commit, provider/model, analyzer versions, and configuration.

## Labeled scenarios

The static harness combines code, log, and deployment analysis against
[`examples/labels.yaml`](../CyberLLM/examples/labels.yaml):

```bash
cd CyberLLM
python evaluate.py
python evaluate.py --strict
```

The default report is `CyberLLM/memory/eval_report.md`. Use `--labels` and `--out`
to select alternative files. `--strict` exits nonzero if overall recall is below
1.0 or there are false-positive findings. This evaluates deterministic detection,
not live-model remediation quality.

## Automotive benchmark

The [automotive corpus](../CyberLLM/benchmark/automotive/README.md) contains nine
vulnerable C/C++/Rust files with 47 labels, plus two clean controls. Labels live
in [`ground_truth.yaml`](../CyberLLM/benchmark/automotive/ground_truth.yaml).

Start the server, open **Benchmark**, and run Fast or Deep analysis. The same
operation is available through `POST /api/benchmark`.

- Matching is greedy and one-to-one by source location within the configured
  window (default ±3 lines). Rule IDs need not equal the label's CWE.
- Recall/coverage is matched labels divided by total labels.
- False positives are measured on the two clean controls only.
- Precision uses matched labels and those clean-control false positives.
- Unmatched findings in vulnerable files are reported as extra/unlabeled and
  are not counted as false positives.
- Optional remediation re-scans model-generated changes and reports remaining
  labels; disappearance of a finding is not proof that the code is correct.

This precision measure is specific to this corpus and its clean controls. It
must not be presented as general real-world precision or a certification.
Historical Deep figures in the original documentation were not accompanied by
reproducible run artifacts; run a fresh evaluation before quoting performance.

Preserve the benchmark source text and label locations together. Do not format
the intentionally vulnerable fixtures as part of routine cleanup.
