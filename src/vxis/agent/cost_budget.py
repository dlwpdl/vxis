"""Mid-scan LLM cost/token budget (Strix-style --max-budget-usd): stop the scan
when accumulated spend reaches an operator cap.

Reuses llm_cost.summarize_usage — the SAME precise per-model estimator the TUI
status bar already shows — so the budget number always matches what the operator
sees on screen (not the coarse per-provider flat rate). Pure + dependency-light.
"""
from __future__ import annotations

import os
from typing import Any


def _pos_float(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if result > 0 else None


def _pos_int(value: Any) -> int | None:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return result if result > 0 else None


def resolve_cost_budget(env: dict | None = None) -> tuple[float | None, int | None]:
    """Return (max_usd, max_tokens) from the environment
    (VXIS_SCAN_MAX_USD / VXIS_SCAN_MAX_TOKENS); None for an unset/non-positive
    value. The CLI flags set these env vars before a scan starts."""
    env = os.environ if env is None else env
    return _pos_float(env.get("VXIS_SCAN_MAX_USD")), _pos_int(env.get("VXIS_SCAN_MAX_TOKENS"))


def budget_exceeded(
    rows: list[dict[str, Any]] | None,
    max_usd: float | None,
    max_tokens: int | None,
) -> bool:
    """True iff accumulated spend (summarize_usage over the usage rows) meets or
    exceeds a set cap. With no cap set the budget feature is off → always False."""
    if not max_usd and not max_tokens:
        return False
    from vxis.agent.llm_cost import summarize_usage

    summary = summarize_usage(list(rows or []))
    if max_usd and float(summary.get("total_cost_usd") or 0.0) >= max_usd:
        return True
    if max_tokens and int(summary.get("total_tokens") or 0) >= max_tokens:
        return True
    return False


__all__ = ["resolve_cost_budget", "budget_exceeded"]
