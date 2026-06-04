# `docs/superpowers/plans/` — Implementation Plans

> Step-by-step plans for multi-task feature migrations. Written via `superpowers:writing-plans`, executed via `superpowers:subagent-driven-development` or `superpowers:executing-plans`.

## Active plans

### [2026-06-02 — Cognitive Engine v3](2026-06-02-cognitive-engine-v3.md)

**Goal:** Make `crown` behave like a senior pentester who remembers — persistent target intelligence (PTI), hypothesis DAG, cost-aware brain routing, coverage-gated `finish_scan`, block-aware adaptation, self-evaluation loop. Focus axes: **cognitive depth** + **operational autonomy**.

**Status:** Source of truth for the engine path. In-scope v3 = A-F + I, with J absorbed into A as trajectory/distillation format. G/H/K are recorded as trigger-gated Beyond v3 components, not immediate implementation scope.

### [2026-06-01 — VXIS v2 Strategy & Engine Plan](2026-06-01-vxis-v2-strategy-and-engine.md)

**Goal:** Lock in CAPT (Continuous Autonomous Pentest) category, 3 ICP packages (Continuous DevSec / VC Portfolio Monitoring / Pre-Investment DD) + compliance-mapping add-on, SaaS-only deployment with Korean-market wedge, and a 6-week engine build sequence (benchmark league v2 → delta scan → asset discovery → credential vault → compliance mapping).

**Status:** Product/BM parent context only. Benchmark League v2 remains the measurement scaffold; v3 owns the engine roadmap. Delta scan, asset discovery, credential vault, compliance mapping, and SaaS/VC packaging stay outside v3 implementation.

### [2026-04-08 — Phase A Strix-Parity Single-Loop Migration](2026-04-08-phase-a-strix-parity-single-loop.md)

**Goal:** Kill the 14-Phase `ScanPipeline` orchestrator. Make a single persistent Brain ReAct loop the owner of an entire scan end-to-end. Make VXIS architecturally equivalent to Strix.

**Status:** Foundation architecture for v2/v3. See [`../../../PHASE_STATUS.md`](../../../PHASE_STATUS.md) for the live progress matrix.

**Key moments recorded in this plan:**
- Task 1 discovery: baseline `brain_decision_count = 0` — proof that legacy `pipeline.py:1927-1929` explicitly bypasses `AgentBrain.think()`
- Task 3.5 audit: `AGENT_SYSTEM_PROMPT` compatibility — chose β3 adapter strategy
- Task 4 milestone: first `brain_decision_count = 1` via `think_in_loop` end-to-end
- 2026-04-09 pivot: Tasks 7–11 (phase wrappers) replaced with Strix-power tools (`shell_exec` + `python_exec` + Docker sandbox)
- Task 10 milestone: `ScanPipelineV2` 360-line shim replaces 5234-line legacy
- Task 11 first run: `brain_decision_count = 0 → 20` (success), `findings = 3 → 0` (Phase B tuning deferred)

## Historical plans (superseded or completed)

| Plan | Status | Note |
|---|---|---|
| [2026-06-01 — VC/B2B Profile Plan](2026-06-01-vc-b2b-profile-plan.md) | Superseded by 2026-06-01 VXIS v2 | Original VC monitoring sketch, replaced by the broader v2 strategy plan after competitor review |
| [2026-03-24 — Advanced Cognitive Layer Roadmap](2026-03-24-advanced-cognitive-layer-roadmap.md) | Superseded by Phase A | Earlier roadmap, replaced when Task 1 revealed Brain-First violation |
| [2026-03-24 — Phase 1 Core Foundation](2026-03-24-phase1-core-foundation.md) | Completed | Original bootstrap |
| [2026-03-30 — Dual Brain + Growth Loop](2026-03-30-dual-brain-growth-loop.md) | Partial — deferred to Phase B | Dual-brain concept lives on in Phase B planning |
| [2026-04-02 — Pipeline Improvements](2026-04-02-pipeline-improvements.md) | Superseded by Phase A | Attempted to fix `pipeline.py` incrementally before the full migration decision |
| [2026-04-04 — Ghost Layer](2026-04-04-ghost-layer.md) | Completed | Stealth layer shipped |
| [2026-04-06 — Pipeline-Sync MCP Progress](2026-04-06-pipeline-sync-mcp-progress.md) | Partially done | MCP server work |
| [2026-04-07 — MCP Brain-First Architecture](2026-04-07-mcp-brain-first-architecture.md) | Superseded by Phase A | Predecessor of the Phase A strategy |

## Plan-authoring rules

When writing a new plan in this folder:

1. Use `superpowers:writing-plans` skill — gives the template header, file-structure section, task decomposition, self-review checklist
2. Filename format: `YYYY-MM-DD-<kebab-case-feature-name>.md`
3. Every task must have bite-sized sub-steps (2–5 min each), exact file paths, complete code blocks, and a commit message
4. Every plan must have a "Success criteria" section with measurable gates
5. Every plan must have a "Risks & mitigations" table
6. When a plan is revised mid-execution (as Phase A was), preserve the revision history in the plan doc itself under a "PIVOT" section — don't rewrite silently

## Execution handoff convention

After writing a plan, hand off to one of two skills:

- **Subagent-Driven Development** (`superpowers:subagent-driven-development`): same session, fresh subagent per task, two-stage review (spec then quality). Used for Phase A.
- **Executing Plans** (`superpowers:executing-plans`): parallel session, batch execution with checkpoints.

Phase A's execution trail is in the worktree's git history (`.worktrees/phase-a`, branch `phase-a/strix-parity`).
