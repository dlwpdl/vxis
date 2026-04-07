"""VXIS Phase Guides — Brain-First strategic guidance for each pipeline Phase.

This package defines the rich PhaseGuide objects consumed by Brain via MCP.
Each guide describes objectives, recommended primitives, dead-end criteria,
and bilingual strategic advice. Unlike `vxis.registry.PhaseInfo` (which is a
lightweight execution-order spec), PhaseGuide is the *strategic playbook*
the Brain reads at the start of every Phase.
"""

from vxis.phases.base import DeadEndCriterion, PhaseGuide
from vxis.phases.registry import (
    EXECUTION_ORDER,
    PHASE_REGISTRY,
    get_parallel_groups,
    get_phase,
    list_phases,
    validate_dependencies,
)

__all__ = [
    "DeadEndCriterion",
    "PhaseGuide",
    "PHASE_REGISTRY",
    "EXECUTION_ORDER",
    "get_phase",
    "list_phases",
    "get_parallel_groups",
    "validate_dependencies",
]
