"""Deterministic self-critique primitives for v3."""

from vxis.agent.critique.loop import (
    CritiqueReport,
    ProposedHypothesis,
    SelfCritique,
    compute_chain_depths,
    evaluate_coverage_gaps,
    find_untested_high_prior_hypotheses,
)

__all__ = [
    "CritiqueReport",
    "ProposedHypothesis",
    "SelfCritique",
    "compute_chain_depths",
    "evaluate_coverage_gaps",
    "find_untested_high_prior_hypotheses",
]
