"""Coverage matrix primitives for v3 scan completion gates."""

from __future__ import annotations

from vxis.agent.coverage.matrix import (
    CoverageCell,
    CoverageGateReport,
    CoverageMatrix,
    SurfaceUnitRef,
    VECTOR_CLASSES,
    evaluate_finish_gate,
    high_value_surfaces,
    is_high_value_surface,
)

__all__ = [
    "CoverageCell",
    "CoverageGateReport",
    "CoverageMatrix",
    "SurfaceUnitRef",
    "VECTOR_CLASSES",
    "evaluate_finish_gate",
    "high_value_surfaces",
    "is_high_value_surface",
]
