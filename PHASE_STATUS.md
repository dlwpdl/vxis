# Phase Status - Current Runtime Direction

> Updated 2026-06-23. VXIS is no longer described as "Strix parity first." The
> current direction is narrower and deeper: authorized system -> assisted
> validation -> reproducible evidence -> bilingual report or bug bounty PoC export.

## Current State In One Line

Single Brain loop, one tool per turn, sandbox-backed web black-box validation,
scope/policy gates, high/critical evidence contract, verifier-aware finding
status, related-evidence pressure, NCC-style report, and `bugbounty`
profile/export.

## Production Public Surface

| Surface | Status | Notes |
|---|---|---|
| Web black-box validation scan | Production | `vxis scan <authorized-system>` through `ScanPipelineV2` and `ScanAgentLoop` |
| Deep validation profile | Production | `--profile crown` |
| Bug bounty helper profile | Production | `--profile bugbounty`, aliases `bug-bounty`, `bug_bounty`, `bb` |
| Bug bounty export | Production | `vxis export <scan_id> --format bugbounty` emits accepted replayable findings |
| NCC-style HTML report | Production | Bilingual-ready report path remains the professional deliverable |
| MCP scan integration | Production | Keep to working scan/primitive tools only |
| Benchmark notes | Production contract | Same-environment comparison notes live under `docs/superpowers/benchmarks/` |

## Recently Completed

- Added `bugbounty` as an active core profile with stricter authorized-scope
  runtime policy and researcher-oriented modules.
- Added high/critical evidence contract requirements for request/payload,
  response/effect, control comparison, replay command/raw HTTP, repeat,
  negative/refutation, and impact.
- Added `Finding.replay_command` and metadata carry-through so report/export
  artifacts can preserve replayable evidence.
- Added lightweight bug bounty JSON export filtered to accepted replayable
  findings.
- Updated CLI/dashboard/profile help to expose bug bounty mode without exposing
  source/mobile/game/runtime placeholders.

## Direction Compared With Strix

VXIS should borrow useful Strix product patterns:

- sandbox-first execution
- compact run artifacts
- resumable state
- clear CLI/CI UX
- source-aware scan once tools are real

VXIS should not clone Strix's broad multi-agent graph as the first move. The
asset to protect is the narrower choke point: policy, verifier, evidence
contract, scoring, and report discipline.

## In Progress

- Target-derived vector candidate generation from discovered routes, forms,
  parameters, and technologies.
- Finish-gate pressure for unattempted high-value vectors and missing chains.
- Benchmark baseline: same-environment Strix vs VXIS comparison across Juice
  Shop, WebGoat, and one local repo/source validation target when source tools
  are promoted.
- CI-friendly scan output after engine-quality benchmarks stabilize.

## Planned Or Incubator

These are not production/public promises until promoted with tool registration,
scope gate, report evidence, benchmark target, and regression tests:

1. Source-aware white/grey-box scanning.
2. Mobile runtime analysis.
3. Game runtime analysis.
4. Hardware/firmware runtime analysis.
5. Cloud-console session automation.
6. Multi-agent swarm orchestration beyond narrow validator subtasks.

## Current Success Gates

- Public docs mention only production-wired surfaces or explicitly mark planned
  work as incubator.
- High/critical findings without replayable evidence are rejected.
- Bug bounty export contains accepted findings only.
- Public registries do not expose source/mobile/game/hardware placeholders.
- Benchmarks record confirmed findings, high/critical count, false positives,
  related-evidence depth, wall time, LLM requests/tokens, and repro completeness.

## Historical Note

Earlier phase documents used "Strix parity" as the headline for the Brain-first
migration away from hardcoded phases. That migration remains useful context, but
the current product promise is assisted verification depth rather than broad
parity.
