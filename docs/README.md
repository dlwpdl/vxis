# `docs/` — Project Documentation

> Design docs, configuration references, and the superpowers-skill artifact tree.

## Top-level docs

| File | Purpose |
|---|---|
| [`BLUEPRINT.md`](BLUEPRINT.md) | High-level product blueprint and business vision |
| [`CONFIGURATION.md`](CONFIGURATION.md) | Runtime configuration reference (`config.toml` schema) |
| [`LOCAL_LLM_RUNBOOK.md`](LOCAL_LLM_RUNBOOK.md) | Local llama.cpp / compact-proxy runbook and improvement memo |
| [`../ARCHITECTURE.md`](../ARCHITECTURE.md) | Current Brain-first runtime architecture, including worker / verifier / judge layering |
| [`SCAN_SCHEDULING.md`](SCAN_SCHEDULING.md) | Continuous monitoring scheduler setup |
| [`SCORING.md`](SCORING.md) | VXIS capability score calculation reference |
| [`scfw-blocked.md`](scfw-blocked.md) | Known SCFW sandbox blocking notes |

## Subdirectories

- [`superpowers/`](superpowers/README.md) — Skill output (plans, benchmarks)

## See also

- [`../README.md`](../README.md) — Project overview
- [`../ARCHITECTURE.md`](../ARCHITECTURE.md) — Brain-first architecture deep dive and AI review hierarchy
- [`../PHASE_STATUS.md`](../PHASE_STATUS.md) — Migration roadmap progress
- [`../CLAUDE.md`](../CLAUDE.md) — Project rules (must read before editing code)
