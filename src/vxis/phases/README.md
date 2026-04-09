# `src/vxis/phases/` — Legacy 14-Phase Guides (DEPRECATED)

> ⚠️ **This module is deprecated** as of Phase A. It will be deleted in Task 12 (Phase A cleanup).

## What this module WAS

`phases/` houses `PhaseGuide` metadata objects — NOT execution code. Each `guides/pN_*.py` file declares a `PhaseGuide` pydantic dataclass with:

- `id`, `name_en`, `name_ko`, `stage`
- `objective_en` / `objective_ko`
- `entry_conditions`, `depends_on`, `parallel_group`
- `recommended_primitives`, `mandatory_primitives`
- `dead_end_criteria` (tuples of `DeadEndCriterion`)
- `key_tasks`, `success_metrics`

These were **playbooks the Brain was supposed to follow** within each phase of the legacy `pipeline.py:ScanPipeline._phaseN_*` dispatch.

## Why it's deprecated

Task 1 of the Phase A migration measured `brain_decision_count = 0` on a baseline scan. Inspection revealed that `pipeline.py:1927-1929` explicitly skips the Brain's ReAct entry point for the AgentBrain backend:

```python
def _consult_brain_for_vector(self, ctx, vector_id, vector_name, phase_name):
    from vxis.agent.brain_filebased import FileBasedBrain
    if not isinstance(self.brain, FileBasedBrain):
        return None   # ← AgentBrain never uses PhaseGuide
```

In other words: the `PhaseGuide` metadata was only consumed by the `FileBasedBrain` backend (rare / experimental). For the live `AgentBrain` path, the guides were never loaded. So the 14 files in `guides/` were effectively documentation, not execution logic.

Phase A replaces the phase-based dispatch entirely with a single ReAct loop that has direct access to a tool catalog. There is no longer any "phase" concept at the scan level — the Brain decides what to do per iteration.

## Files

| File | Legacy role |
|---|---|
| `base.py` | `PhaseGuide`, `DeadEndCriterion` dataclasses |
| `registry.py` | Collects all PhaseGuides into a registry (used by old pipeline phase scheduler) |
| `guides/p0_foundation.py` | P0 foundation playbook |
| `guides/p1_director.py` | P1 director / mission decomposition |
| `guides/p2_agents.py` | P2 agent fleet dispatch |
| `guides/p3_hypothesis.py` | P3 hypothesis generation |
| `guides/p4_cpr.py` | P4 Crawl/Probe/Recon |
| `guides/p5_special.py` | P5 special exploitation |
| `guides/p6_report.py` | P6 report generation |
| `guides/p7_hardware.py` | P7 hardware attack surface |
| `guides/p8_synthesis.py` | P8 attack chain synthesis |
| `guides/p11_mutation.py` | P11 chain mutation |
| `guides/p12_evolution.py` | P12 self-evolution |
| `guides/p13_biometrics.py` | P13 behavioral biometrics (OSINT) |
| `guides/p15_digital_twin.py` | P15 digital twin pre-simulation |
| `guides/p18_collective.py` | P18 collective knowledge base |

## Scheduled removal

**Task 12** (final task of Phase A) will delete:

1. Entire `src/vxis/phases/` directory
2. Entire `src/vxis/pipeline/pipeline.py` (5234-line legacy)
3. Any remaining references in `src/vxis/agent/` (legacy files like `director.py`, `agents/`, `runner.py` that only existed to serve the phase dispatch)

The PhaseGuide content (objectives, mandatory primitives, dead-end criteria) is semantically valuable and may be resurrected in Phase B as **prompt snippets** or **RAG-retrievable playbooks** that the Brain can consult mid-scan via a new `load_playbook(phase_id)` tool. This is tracked as a Phase B possibility but not yet planned.

## Do NOT add new PhaseGuide files

Any new "playbook" work should go into Phase B's prompt tuning layer or Phase C's structured belief state — not here.
