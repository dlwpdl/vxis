"""Phase Registry — central lookup for all 14 PhaseGuides.

EXECUTION_ORDER preserves the Brain-First sequence; PHASE_REGISTRY is a
dict for O(1) lookup by id. Helper functions cover the typical orchestrator
needs (parallel grouping, dependency validation).
"""

from __future__ import annotations

from collections import defaultdict

from vxis.phases.base import PhaseGuide
from vxis.phases.guides.p0_foundation import PHASE_GUIDE as P0
from vxis.phases.guides.p1_director import PHASE_GUIDE as P1
from vxis.phases.guides.p2_agents import PHASE_GUIDE as P2
from vxis.phases.guides.p3_hypothesis import PHASE_GUIDE as P3
from vxis.phases.guides.p4_cpr import PHASE_GUIDE as P4
from vxis.phases.guides.p5_special import PHASE_GUIDE as P5
from vxis.phases.guides.p6_report import PHASE_GUIDE as P6
from vxis.phases.guides.p7_hardware import PHASE_GUIDE as P7
from vxis.phases.guides.p8_synthesis import PHASE_GUIDE as P8
from vxis.phases.guides.p11_mutation import PHASE_GUIDE as P11
from vxis.phases.guides.p12_evolution import PHASE_GUIDE as P12
from vxis.phases.guides.p13_biometrics import PHASE_GUIDE as P13
from vxis.phases.guides.p15_digital_twin import PHASE_GUIDE as P15
from vxis.phases.guides.p18_collective import PHASE_GUIDE as P18

# Brain-First execution order. Same parallel_group => can run concurrently.
# P6 report is intentionally LAST so it sees P12/P18 learning output.
EXECUTION_ORDER: list[str] = [
    "P0_foundation",
    "P1_director",
    "P4_cpr",
    "P13_biometrics",
    "P15_digital_twin",
    "P2_agents",
    "P3_hypothesis",
    "P5_special",
    "P7_hardware",
    "P8_synthesis",
    "P11_mutation",
    "P12_evolution",
    "P18_collective",
    "P6_report",
]

PHASE_REGISTRY: dict[str, PhaseGuide] = {
    g.id: g
    for g in (P0, P1, P4, P13, P15, P2, P3, P5, P7, P8, P11, P12, P18, P6)
}


def get_phase(phase_id: str) -> PhaseGuide:
    """Return the PhaseGuide for `phase_id` or raise KeyError."""
    if phase_id not in PHASE_REGISTRY:
        raise KeyError(f"Unknown phase id: {phase_id}")
    return PHASE_REGISTRY[phase_id]


def list_phases() -> list[PhaseGuide]:
    """Return all guides in canonical execution order."""
    return [PHASE_REGISTRY[pid] for pid in EXECUTION_ORDER]


def get_parallel_groups() -> list[list[PhaseGuide]]:
    """Group guides by parallel_group, returning groups in ascending order."""
    buckets: dict[int, list[PhaseGuide]] = defaultdict(list)
    for guide in PHASE_REGISTRY.values():
        buckets[guide.parallel_group].append(guide)
    return [buckets[g] for g in sorted(buckets.keys())]


def validate_dependencies() -> None:
    """Assert every depends_on id exists and respects parallel_group ordering."""
    for guide in PHASE_REGISTRY.values():
        for dep in guide.depends_on:
            if dep not in PHASE_REGISTRY:
                raise ValueError(
                    f"Phase {guide.id} depends on unknown phase {dep}"
                )
            dep_guide = PHASE_REGISTRY[dep]
            if dep_guide.parallel_group >= guide.parallel_group:
                raise ValueError(
                    f"Phase {guide.id} (group {guide.parallel_group}) depends on "
                    f"{dep} (group {dep_guide.parallel_group}) — dependency must "
                    f"belong to an earlier parallel group"
                )
    # Sanity: EXECUTION_ORDER and PHASE_REGISTRY agree
    if set(EXECUTION_ORDER) != set(PHASE_REGISTRY.keys()):
        raise ValueError("EXECUTION_ORDER and PHASE_REGISTRY are out of sync")
