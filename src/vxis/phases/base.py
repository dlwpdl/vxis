"""Base dataclasses for VXIS Phase Guides.

PhaseGuide is the strategic spec the Brain reads at every Phase entry.
DeadEndCriterion bundles a bilingual description with a runtime check
(lambda) the orchestrator can use to detect when recon/exploit is exhausted.
"""

from __future__ import annotations

import dataclasses as dc
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class DeadEndCriterion:
    """A single dead-end signal — when this returns True, the Phase is exhausted."""

    id: str
    description_en: str
    description_ko: str
    # `check` is excluded from MCP serialization (lambdas aren't JSON-safe).
    check: Callable[[Any], bool]


@dataclass(frozen=True)
class PhaseGuide:
    """Brain-First strategic guide for a single Phase.

    Consumed by Brain via MCP at Phase entry. Bilingual fields are required
    so the Korean Brain prompts get full context.
    """

    id: str
    name_en: str
    name_ko: str
    stage: str  # init / recon / intelligence / exploitation / chain / report / learning
    parallel_group: int
    depends_on: tuple[str, ...]

    objective_en: str
    objective_ko: str

    entry_conditions: tuple[str, ...] = ()

    recommended_primitives: tuple[str, ...] = ()
    mandatory_primitives: tuple[str, ...] = ()

    dead_end_criteria: tuple[DeadEndCriterion, ...] = ()
    success_criteria: tuple[str, ...] = ()
    blocking_errors: tuple[str, ...] = ()

    strategic_advice_en: str = ""
    strategic_advice_ko: str = ""

    crown_hint_en: str = ""
    crown_hint_ko: str = ""

    max_duration_minutes: int = 30
    next_phase_hint: tuple[str, ...] = ()

    def to_mcp_dict(self) -> dict[str, Any]:
        """Serialize for MCP transport (excludes lambda `check` callables)."""
        result: dict[str, Any] = {}
        for f in dc.fields(self):
            if f.name == "dead_end_criteria":
                result[f.name] = [
                    {
                        "id": c.id,
                        "description_en": c.description_en,
                        "description_ko": c.description_ko,
                    }
                    for c in self.dead_end_criteria
                ]
            else:
                result[f.name] = getattr(self, f.name)
        return result
