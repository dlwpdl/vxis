# `docs/superpowers/benchmarks/` - Benchmark Captures

> Measurable data captures for engine-quality decisions. Generated artifacts are
> not kept in the working tree; benchmark notes summarize the evidence and exact
> commands.

## Canonical Benchmark Targets

| Target | URL | Docker image |
|---|---|---|
| Juice Shop | `http://localhost:3000` | `bkimminich/juice-shop` |
| WebGoat | `http://localhost:8080/WebGoat` | `webgoat/webgoat` |
| Local repo/source target | TBD | Use only after source-aware VXIS tools are promoted |

## Current Comparison Contract

Same-environment Strix vs VXIS comparisons must record:

- confirmed findings
- critical/high count
- false positives
- chain depth
- wall time
- LLM requests/tokens
- repro completeness
- exact commands
- git SHA and model

Use one dated file per comparison:

- `YYYY-MM-DD-strix-vxis-comparison.md`

The active template is
[`2026-06-23-strix-vxis-comparison.md`](2026-06-23-strix-vxis-comparison.md).

## Artifact Policy

Do not commit HTML reports, raw scan logs, stdout captures, timing files, or
screenshots. Put the important metrics and short excerpts in the benchmark note.

## Benchmark-Authoring Rules

1. Use the same target state, model, network, and budget for both tools.
2. Record the exact command and working directory.
3. Capture VXIS `VXIS_BENCHMARK` fields: `peak_context_bytes`,
   `llm_call_count`, `brain_decision_count`, and `findings_count`.
4. Record Strix token/request/cost artifacts from its run directory when
   available.
5. Count only reproducible confirmed findings as confirmed.
6. Mark weak, unverified, or non-replayable findings as false positive or
   incomplete, not as confirmed.
7. Explain significant deltas in a short analysis section.

## Historical Baselines

- [2026-04-08 - Phase A Baseline](2026-04-08-phase-a-baseline.md)
- [2026-04-09 - Phase A Task 11 Result](2026-04-09-phase-a-task11-result.md)
