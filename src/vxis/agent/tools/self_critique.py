"""Self-critique BrainTool wrapper for deterministic v3 critique primitives."""

from __future__ import annotations

from typing import Any

from vxis.agent.critique.loop import SelfCritique
from vxis.agent.tool_registry import ToolResult


class SelfCritiqueTool:
    name = "self_critique"
    description = (
        "Run deterministic self-critique over DAG, coverage matrix, findings, and PTI "
        "summaries. Returns gaps and whether finish_scan should be allowed."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "dag": {"type": ["object", "array", "null"]},
            "matrix": {"type": ["object", "array", "null"]},
            "findings": {"type": ["array", "null"]},
            "pti": {"type": ["object", "null"]},
            "coverage_threshold": {"type": "number", "default": 80.0},
            "high_value_coverage_threshold": {"type": "number", "default": 80.0},
            "high_prior_threshold": {"type": "number", "default": 0.7},
        },
    }

    def __init__(self, state: Any | None = None) -> None:
        self._state = state

    def bind_state(self, state: Any) -> None:
        self._state = state

    async def run(self, **kwargs: Any) -> ToolResult:
        critique = SelfCritique(
            coverage_threshold=_coerce_float(kwargs.get("coverage_threshold"), 80.0),
            high_value_coverage_threshold=_coerce_float(
                kwargs.get("high_value_coverage_threshold"), 80.0
            ),
            high_prior_threshold=_coerce_float(kwargs.get("high_prior_threshold"), 0.7),
        )
        state = self._state
        report = critique.run(
            dag=kwargs.get("dag") or getattr(state, "hypothesis_dag", None),
            matrix=kwargs.get("matrix") or getattr(state, "coverage_matrix", None),
            findings=kwargs.get("findings") or getattr(state, "findings", None) or [],
            pti=kwargs.get("pti") or getattr(state, "pti", None),
        )
        status = "allowed" if report.finish_allowed else "blocked"
        return ToolResult(
            ok=True,
            data={"report": report.model_dump(mode="json")},
            summary=f"self_critique {status} finish_scan with {len(report.gaps)} gap(s)",
        )


def _coerce_float(value: Any, default: float) -> float:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
