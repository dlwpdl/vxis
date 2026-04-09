# `src/vxis/graph/` — Attack Graph + Hypothesis Queue

Living attack graph data structure + hypothesis queue for tracking "things to try next". Used by the legacy `AgentRunner` for multi-round hypothesis-driven scans.

Key types:
- `LivingAttackGraph` — DAG of hypotheses and confirmed attack paths
- `HypothesisQueue` — priority queue of untested vulnerability hypotheses

Phase A's Brain does not currently consume this — it tracks its own context via `ScanLoopState.messages[]`. Phase C's structured belief state may resurrect this as the persistent backing store.
