# Chapters — Step-by-Step Context Index

> Fast-recovery narrative log. Each chapter is one milestone, one
> decision, or one pivot. Read these in order to quickly understand
> how VXIS evolved and WHY things are the way they are.

## Reading order

| # | Chapter | Date | Key outcome |
|---|---|---|---|
| 01 | [Phase A — Architecture Migration](01-phase-a-architecture-migration.md) | 2026-04-08 | 14-phase pipeline → single ReAct loop. `brain_decision_count: 0 → 20` |
| 02 | [Phase B Day 1 — Findings Breakthrough](02-phase-b-day1-findings-breakthrough.md) | 2026-04-09 | Strix-style adapter + auto-hint + dedup. 0 → 8 findings on Juice Shop |
| 03 | [Phase B Day 2 — Playbook Architecture Pivot](03-phase-b-day2-playbook-pivot.md) | 2026-04-09 | User insight: memorize techniques, not targets. `load_playbook` tool + 7 stack playbooks |
| 04 | [Phase B Day 2 — Fingerprint + Memory + Stabilization](04-phase-b-day2-fingerprint-memory.md) | 2026-04-09 | `fingerprint_target` + `query_scan_memory` + 4 more playbooks. 15 tools total |
| 05 | [Phase B Day 2 — sqlmap/critic stabilization](05-phase-b-day2-sqlmap-critic-stabilization.md) | 2026-04-09 | sqlmap integration + dual-brain critic + JSON recovery hardening |
| 06 | [Phase C — Verifier, Belief State, Egress Filter](06-phase-c-verifier-belief-egress.md) | 2026-04-10 | Adversarial verifier + rubric rebalance + belief tracking + enterprise egress guardrail |

## What these chapters are for

- **When you come back after a break**: read chapters in order, get context in ~10 min
- **When you hit a weird behavior**: find the chapter that introduced the feature, understand why it was designed that way
- **When you're about to break something**: check if a chapter warns against it
- **When deciding what's next**: look at the last chapter's "next actions"

## What they are NOT

- Not a changelog (see `git log` for that)
- Not a full technical spec (see `ARCHITECTURE.md`)
- Not a task list (see `PHASE_STATUS.md`)

Chapters are **narrative**: they explain the reasoning behind each major
decision and the lessons learned from failed attempts.

## Format convention

Each chapter has:
1. **Context** — what was the state of the project before this chapter
2. **Problem** — what specifically was broken or missing
3. **Decision** — what we chose to do and why (and what we rejected)
4. **Execution** — high-level summary of the work
5. **Result** — measurable outcome
6. **Lessons learned** — things to remember for future work
7. **Next** — what the chapter sets up for the following chapter

Keep each chapter under ~150 lines. If it grows beyond that, split it.
