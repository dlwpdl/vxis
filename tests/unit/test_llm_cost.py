"""Tests for the pure per-model USD cost estimator + usage aggregator.

TDD: written before ``vxis.agent.llm_cost`` exists. These pin the public API
(``estimate_cost``, ``summarize_usage``, ``format_cost_line``) and the contract
that costs are ESTIMATES (``~$`` marker, ``cost_known`` / ``cost_estimated`` flags).
"""
from __future__ import annotations

import pytest

from vxis.agent.llm_cost import (
    MODEL_PRICES,
    estimate_cost,
    format_cost_line,
    summarize_usage,
)


def test_model_prices_has_realistic_known_models() -> None:
    # flash is exercised numerically below; just assert the table is populated.
    assert MODEL_PRICES["gemini-2.5-flash"] == (0.30, 2.50)
    assert "claude-opus-4-8" in MODEL_PRICES


def test_estimate_cost_flash_one_million_each() -> None:
    # 1M in * $0.30/1M + 1M out * $2.50/1M = 2.80, price is known.
    assert estimate_cost("gemini-2.5-flash", 1_000_000, 1_000_000) == (2.80, True)


def test_estimate_cost_rounds_to_six_dp() -> None:
    cost, known = estimate_cost("gemini-2.5-flash", 1, 1)
    assert known is True
    # 1 * 0.30/1e6 + 1 * 2.50/1e6 = 2.8e-6
    assert cost == 0.000003  # round(2.8e-6, 6)


def test_estimate_cost_unknown_model_is_zero_and_unknown() -> None:
    assert estimate_cost("totally-made-up-model", 1_000_000, 1_000_000) == (0.0, False)


def test_estimate_cost_local_provider_unknown() -> None:
    assert estimate_cost("local/llama-whatever", 5_000, 5_000) == (0.0, False)


def test_estimate_cost_prefix_match_on_colon() -> None:
    # "gemini-2.5-flash:thinking" should match the "gemini-2.5-flash" price.
    assert estimate_cost("gemini-2.5-flash:thinking", 1_000_000, 1_000_000) == (2.80, True)


def test_estimate_cost_prefix_match_on_slash() -> None:
    assert estimate_cost("gemini-2.5-pro/v2", 1_000_000, 0) == (1.25, True)


def test_estimate_cost_zero_tokens() -> None:
    assert estimate_cost("claude-opus-4-8", 0, 0) == (0.0, True)


def test_summarize_usage_aggregates_same_model_role() -> None:
    rows = [
        {"model": "gemini-2.5-flash", "role": "director", "input_tokens": 1_000_000, "output_tokens": 0},
        {"model": "gemini-2.5-flash", "role": "director", "input_tokens": 0, "output_tokens": 1_000_000},
    ]
    out = summarize_usage(rows)

    assert out["cost_estimated"] is True
    assert out["total_tokens"] == 2_000_000
    assert out["total_cost_usd"] == 2.80

    buckets = out["by_model_role"]
    assert len(buckets) == 1
    b = buckets[0]
    assert b["model"] == "gemini-2.5-flash"
    assert b["role"] == "director"
    assert b["calls"] == 2
    assert b["input_tokens"] == 1_000_000
    assert b["output_tokens"] == 1_000_000
    assert b["cost_usd"] == 2.80
    assert b["cost_known"] is True


def test_summarize_usage_sorted_by_cost_desc() -> None:
    rows = [
        {"model": "gemini-2.5-flash-lite", "role": "scout", "input_tokens": 1_000_000, "output_tokens": 0},
        {"model": "claude-opus-4-8", "role": "brain", "input_tokens": 1_000_000, "output_tokens": 0},
    ]
    out = summarize_usage(rows)
    costs = [b["cost_usd"] for b in out["by_model_role"]]
    assert costs == sorted(costs, reverse=True)
    assert out["by_model_role"][0]["model"] == "claude-opus-4-8"


def test_summarize_usage_unknown_model_flags_estimate_off() -> None:
    rows = [
        {"model": "mystery-model", "role": "x", "input_tokens": 10, "output_tokens": 10},
    ]
    out = summarize_usage(rows)
    assert out["total_cost_usd"] == 0.0
    assert out["cost_estimated"] is False
    assert out["by_model_role"][0]["cost_known"] is False


def test_summarize_usage_empty() -> None:
    out = summarize_usage([])
    assert out["by_model_role"] == []
    assert out["total_tokens"] == 0
    assert out["total_cost_usd"] == 0.0
    assert out["cost_estimated"] is False


def test_format_cost_line_known_price() -> None:
    line = format_cost_line("gemini-2.5-flash", "director", 12_000, 345)
    assert "gemini-2.5-flash" in line
    assert "director" in line
    assert "12,345" in line  # comma-grouped total tokens
    assert "~$" in line  # estimate marker


def test_format_cost_line_unknown_price() -> None:
    line = format_cost_line("mystery-model", "brain", 1_000, 0)
    assert "mystery-model" in line
    assert "brain" in line
    assert "1,000" in line
    assert "~$? (no price)" in line


@pytest.mark.parametrize("model", list(MODEL_PRICES))
def test_every_known_model_is_marked_known(model: str) -> None:
    _, known = estimate_cost(model, 100, 100)
    assert known is True
