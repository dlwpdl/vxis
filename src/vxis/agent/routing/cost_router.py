"""Cost-aware model routing for v3 Brain decisions."""

from __future__ import annotations

import math
from enum import StrEnum

from pydantic import BaseModel, Field


class DecisionClass(StrEnum):
    """Decision taxonomy used by the v3 Brain router."""

    RECON = "recon"
    TRIAGE = "triage"
    STRATEGY = "strategy"
    EXPLOIT = "exploit"
    VERIFY = "verify"
    CRITIQUE = "critique"


class CostUsage(BaseModel):
    """Cumulative usage for one decision class."""

    calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.tokens_in + self.tokens_out

    @property
    def average_cost_usd(self) -> float:
        if self.calls <= 0:
            return 0.0
        return self.cost_usd / self.calls


class CostReport(BaseModel):
    """Snapshot of router telemetry."""

    by_class: dict[DecisionClass, CostUsage] = Field(default_factory=dict)
    calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0

    def cost_per_finding(self, finding_count: int) -> float:
        """Return cost per confirmed finding, or 0 when there are none."""
        if finding_count <= 0:
            return 0.0
        return self.cost_usd / finding_count


def coerce_decision_class(value: DecisionClass | str) -> DecisionClass:
    """Normalize enum instances, enum names, and string values."""
    if isinstance(value, DecisionClass):
        return value
    text = str(value).strip()
    if not text:
        raise ValueError("decision class cannot be empty")
    normalized = text.lower().replace("_", "-")
    for decision_class in DecisionClass:
        if normalized in {
            decision_class.value,
            decision_class.name.lower().replace("_", "-"),
        }:
            return decision_class
    raise ValueError(f"unknown decision class: {value!r}")


def _non_negative_int(name: str, value: int) -> int:
    number = int(value)
    if number < 0:
        raise ValueError(f"{name} must be non-negative")
    return number


def _non_negative_float(name: str, value: float) -> float:
    number = float(value)
    if number < 0.0 or not math.isfinite(number):
        raise ValueError(f"{name} must be a finite non-negative number")
    return number


class BrainCostRouter:
    """Accumulates usage telemetry by decision class.

    Model selection lives in AgentBrain._model_role_for_decision_class ->
    hybrid_config. Keeping a second model table here caused config drift.
    """

    def __init__(self) -> None:
        self._usage: dict[DecisionClass, CostUsage] = {
            decision_class: CostUsage() for decision_class in DecisionClass
        }

    def record(
        self,
        decision_class: DecisionClass | str,
        tokens_in: int,
        tokens_out: int,
        cost_usd: float,
    ) -> None:
        decision = coerce_decision_class(decision_class)
        validated_tokens_in = _non_negative_int("tokens_in", tokens_in)
        validated_tokens_out = _non_negative_int("tokens_out", tokens_out)
        validated_cost_usd = _non_negative_float("cost_usd", cost_usd)
        usage = self._usage.setdefault(decision, CostUsage())
        usage.calls += 1
        usage.tokens_in += validated_tokens_in
        usage.tokens_out += validated_tokens_out
        usage.cost_usd += validated_cost_usd

    def report(self) -> CostReport:
        by_class = {
            decision_class: self._usage.get(decision_class, CostUsage()).model_copy(deep=True)
            for decision_class in DecisionClass
        }
        calls = sum(usage.calls for usage in by_class.values())
        tokens_in = sum(usage.tokens_in for usage in by_class.values())
        tokens_out = sum(usage.tokens_out for usage in by_class.values())
        cost_usd = sum(usage.cost_usd for usage in by_class.values())
        return CostReport(
            by_class=by_class,
            calls=calls,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            total_tokens=tokens_in + tokens_out,
            cost_usd=cost_usd,
        )

    def reset(self) -> None:
        self._usage = {decision_class: CostUsage() for decision_class in DecisionClass}


__all__ = [
    "BrainCostRouter",
    "CostReport",
    "CostUsage",
    "DecisionClass",
    "coerce_decision_class",
]
