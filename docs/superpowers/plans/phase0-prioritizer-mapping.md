# Phase 0 Prioritizer Mapping

Source of truth after Phase 0: `HypothesisDAG.nodes[node_id]`.

Legacy `vector_candidates`, `scan_todos`, and `branches` remain as compatibility/UI side-tables during the rollback window. They no longer own finish priority.

## VectorCandidate -> HypothesisNode

| Old field | New home |
|---|---|
| `id` | `HypothesisNode.node_id` |
| `vector_id` | `HypothesisNode.proposed_vector_class` after canonical vector-family mapping; raw value kept in evidence |
| `title` | `HypothesisNode.claim` |
| `priority` | `HypothesisNode.prior = priority / 100` |
| `evidence` | `HypothesisNode.evidence[]` |
| `status` | `HypothesisNode.status` (`open/retryable/attempted/failed -> untested/testing`, `found -> confirmed`, `clean/dead -> refuted`, `blocked -> inconclusive`) |
| `attempts` | side-table: `VectorCandidate.attempts`; reflected in evidence updates |
| `created_iter` | `HypothesisNode.created_iter` |
| `last_iter` | `HypothesisNode.last_updated_iter` |
| `last_tool` | side-table, and appended to `HypothesisNode.evidence` on update |
| `last_summary` | `HypothesisNode.evidence[]` on update |

## ScanTodo -> HypothesisNode

| Old field | New home |
|---|---|
| `id` | `HypothesisNode.node_id` |
| `title` | `HypothesisNode.claim` |
| `priority` | `HypothesisNode.prior` |
| `source_candidate_id` | `HypothesisNode.node_id` / side-table link |
| `status` | derived from `HypothesisNode.status` for UI |
| `detail` | side-table UI preview; source evidence is `HypothesisNode.evidence[]` |
| `last_iter` | `HypothesisNode.last_updated_iter` |

## BranchState -> HypothesisNode

| Old field | New home |
|---|---|
| `id` | `HypothesisNode.node_id` when branch is candidate-backed; otherwise side-table keyed by branch id |
| `vector_id` | `HypothesisNode.proposed_vector_class` after canonical mapping |
| `title` | `HypothesisNode.claim` |
| `priority` | `HypothesisNode.prior` |
| `role`, `phase`, `owner` | side-table keyed by `node_id` |
| `parent_branch_id`, `child_ids` | DAG edge (`parent_ids` / `child_ids`) when candidate-backed; otherwise side-table |
| `source_candidate_id` | `HypothesisNode.node_id` link |
| `source_finding_id` | side-table; future typed edge `pivots_to` |
| `objective`, `next_step`, `crown_jewel` | side-table execution metadata |
| `blocker`, `escalation_*` | side-table operational state |
| `evidence` | `HypothesisNode.evidence[]` |
| `status` | `HypothesisNode.status` via terminal mapping |
| `attempts`, `last_tool`, `last_summary`, `last_report`, `watch_terms`, `last_iter` | side-table/UI metadata; summaries also appended to `HypothesisNode.evidence[]` |

## Deletion Plan

`VectorCandidate`, `ScanTodo`, and `BranchState` are not deleted in Phase 0 because they are still used for dashboard and compatibility paths. Phase 0 replaces finish priority with DAG queries and keeps the side-tables as projections. Deletion moves to the later cleanup phase after parity is measured.
