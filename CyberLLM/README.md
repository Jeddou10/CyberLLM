# CyberLLM application

**CyberLLM: A Multi-Agent LLM Framework for Autonomous Detection and Guarded Response in Automotive Cybersecurity**

This project is associated with the [CyberLLM research paper (arXiv:2608.06651)](https://arxiv.org/pdf/2608.06651).
See [paper details and citation](../docs/research.md#citing-the-cyberllm-paper).

This directory is the runtime root. Configuration, rules, examples, and generated
outputs retain their existing locations. Start with the
[repository README](../README.md) for installation and an overview.

With dependencies installed, these commands work from this directory:

```bash
python server.py
python pipeline.py --example small
python pipeline.py --mode attack --example small
python verify.py
python -m pytest tests/ -q
```

The default server listens at http://127.0.0.1:8000. To configure a provider, copy
[.env.example](.env.example) to `.env` here and edit [config.yaml](config.yaml).
The loader reads `CyberLLM/.env`, not a `.env` at the repository root.

## Guides

- [Setup and usage](../docs/getting-started.md)
- [Architecture and module map](../docs/architecture.md)
- [Research foundations and the five reference papers](../docs/research.md)
- [Configuration reference](../docs/configuration.md)
- [HTTP API](../docs/api.md)
- [Testing](../docs/testing.md) and [evaluation](../docs/evaluation.md)
- [Examples](examples/README.md) and [automotive benchmark](benchmark/automotive/README.md)
- [Security model](../SECURITY.md) and [known limitations](../docs/known-limitations.md)

Runtime output goes to `memory/`, `run_logs/`, and `mcp_workspace/`. These
directories are ignored by Git, apart from `memory/.gitkeep`.
