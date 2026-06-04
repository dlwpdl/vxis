# VXIS v3 — Cognitive Engine

> Where VXIS is heading after Phase A–E. Focus: **cognitive depth** (gets smarter per target) + **operational autonomy** (no human babysitter). Surface completeness and fleet optimization come later as separate tracks.

## Why v3

Phases A–E got `crown` to Strix-parity Brain-First with adversarial verifier and vector exhaustion (see [`../../PHASE_STATUS.md`](../../PHASE_STATUS.md)). The remaining gap to senior-pentester equivalence: every scan still starts from zero, costs the same per iteration regardless of decision class, and stops when the loop says so rather than when the work is actually done.

v3 closes that gap with seven in-scope components: A-F plus I. J is absorbed into
A as the distillation-ready trajectory format. G/H/K are preserved in this plan
as trigger-gated Beyond v3 components so Phase 1 schemas are forward-compatible.

## Seven components

| ID | Component | What it does |
|---|---|---|
| **A** | Persistent Target Intelligence (PTI) Store **+ distillation-ready trajectory format (J)** | Per-target dossier (stack, surface, defenses, finding history, authored tools, payload library, hypothesis history) that accumulates across scans. Every Brain decision also persisted as `TrajectoryRecord` for future domain-specific model distillation |
| **B** | Hypothesis DAG | Replaces flat `vector_candidates` with a hierarchical belief graph — Brain forms hypotheses at scan start, tests them, propagates priors, prunes refuted branches |
| **C** | Cost-aware Brain Routing | Decision-class taxonomy (recon / triage / strategy / exploit / verify / critique) → Haiku / Sonnet / Opus routing. Target: `llm_cost_per_finding` −40% without recall regression |
| **D** | Coverage Matrix + Coverage-gated `finish_scan` | `(surface × vector_class)` matrix tracks what's actually been probed. `finish_scan` blocks when high-value surfaces or high-prior hypotheses are still untested |
| **E** | Block-aware Adaptation | Classifies WAF / rate / IP-ban / honeypot / behavioral blocks → switches strategy (encoding / Tor rotate / Ghost / browser fallback). Bypasses persist into PTI |
| **F** | Self-Evaluation Loop | Periodic critique on DAG + coverage matrix + finding chains. If gaps exist, adds new hypotheses and continues. Otherwise allows `finish_scan` |
| **I** | Human-in-the-loop Ask Primitive | Small but high-value: `ambiguous_ask` queue for genuinely-ambiguous findings. Unattended scans skip with default + report rationale; attended scans pause for operator input. Does not break autonomy |

## Phasing

**Phase 1 (weeks 1–4) — Foundation**
- A: PTI Store
- B: Hypothesis DAG

Ships independently. Gate: repeated scan against same target reaches first finding in <60% of fresh-scan iterations.

**Phase 2 (weeks 5–10) — Autonomy layer**
- C: Cost-aware Brain Routing
- D: Coverage Matrix + coverage-gated `finish_scan`
- E: Block-aware Adaptation
- F: Self-Evaluation Loop
- I: Human-in-the-loop Ask Primitive (~3 days inside weeks 9–10)

Layered on Phase 1. Each component lands behind a feature flag with its own benchmark delta.

## What's locked vs deferred vs out-of-scope

**Locked into v3:**
- Cognitive depth (A, B)
- Operational autonomy (C, D, E, F)
- Human ambiguity handling (I)
- Distillation-ready data format (J, absorbed into A)

**Beyond v3 — trigger-gated, forward-compat reserved in v3 schemas:**
- **G** Cross-target Knowledge Graph — trigger: ≥50 dossiers or first VC portfolio sign-on
- **H** Post-finding Exploitation Module — trigger: `chain_depth_mean` stuck below 3 after Phase 2 stabilizes
- **K** Multi-agent Swarm decision — trigger: single-Brain fails specific benchmark target after 3 critique cycles

**Out-of-scope — separate plans:**
- Axis 2 (Surface Completeness) — API DAST, role-matrix, business-logic synthesizer, visual reasoning
- Axis 4 (Fleet Optimization) — surface change detection, CVE → portfolio correlation, business-context severity. Triggered after VC sign-on.
- v2 infra items beyond benchmark league v2 (delta scan, asset discovery, credential vault, compliance mapping)
- Adversarial self-play, public exploit DB live ingestion, MITRE attack-tree visualization (parked, no v3 forward-compat dependency)

## Source plans

- [`../superpowers/plans/2026-06-02-cognitive-engine-v3.md`](../superpowers/plans/2026-06-02-cognitive-engine-v3.md) — full v3 plan: data models, task decomposition, success criteria, risks
- [`../superpowers/plans/2026-06-01-vxis-v2-strategy-and-engine.md`](../superpowers/plans/2026-06-01-vxis-v2-strategy-and-engine.md) — parent v2 strategy plan (ICPs, KR wedge, SaaS deployment, benchmark league v2)

## Success criteria (headline)

**Phase 1**
- Iterations-to-first-finding drops ≥40% by repeat-scan #3 on the same target
- DAG: ≥10 nodes per Juice Shop scan, ≥50% reach confirmed/refuted
- PTI dossier round-trips cleanly across scans

**Phase 2**
- `llm_cost_per_finding` drops ≥40% vs pre-routing baseline
- Coverage gate blocks `finish_scan` when high-value surface untested (proven via integration test)
- Block classifier ≥90% accuracy on Cloudflare / Akamai fixtures
- Self-critique fills ≥1 real gap per scan on benchmark targets
- Full league run with no human intervention, finish gated correctly, no infinite loop

## Execution

Each in-scope component (A-F + I) will get its own sub-plan with task-level decomposition (2-5 min sub-steps, exact file paths, code blocks, commit messages) via `superpowers:writing-plans`. Execution via `superpowers:subagent-driven-development` on worktree `.worktrees/cognitive-v3`, merge to main only after Phase 1 clears benchmark league v2, then Phase 2 components individually behind flags.

## Relationship to existing architecture

- No changes to Brain-First single-loop architecture from Phase A
- New module locations: `src/vxis/pti/`, `src/vxis/pti/trajectory.py`, `src/vxis/agent/hypothesis/`, `src/vxis/agent/routing/`, `src/vxis/agent/coverage/`, `src/vxis/agent/block/`, `src/vxis/agent/critique/`, `src/vxis/agent/ask/`
- `ScanLoopState` gains: `pti`, `hypothesis_dag`, `coverage_matrix`, `block_history`, `cost_report`, `ask_queue`
- `finish_scan` gating conditions extended (existing gates kept)
- `ScanAgentLoop._build_scan_dashboard()` extended with PTI excerpt + DAG summary + coverage summary
- NCC HTML report gains: Hypotheses Tested section, Coverage Summary section
