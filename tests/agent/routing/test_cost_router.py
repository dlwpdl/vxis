from __future__ import annotations

import pytest

from vxis.agent.routing.cost_router import (
    BrainCostRouter,
    CostReport,
    DecisionClass,
)


def test_cost_report_tracks_usage_without_model_table() -> None:
    report = CostReport(by_class={}, calls=2, cost_usd=0.5)

    module = __import__("vxis.agent.routing.cost_router", fromlist=["x"])
    assert report.cost_per_finding(2) == 0.25
    assert not hasattr(module, "ROUTE_TABLE")
    assert not hasattr(BrainCostRouter(), "model_for")


def test_report_accumulates_class_telemetry() -> None:
    router = BrainCostRouter()

    router.record("recon", tokens_in=100, tokens_out=25, cost_usd=0.01)
    router.record(DecisionClass.RECON, tokens_in=50, tokens_out=10, cost_usd=0.002)
    router.record(DecisionClass.EXPLOIT, tokens_in=300, tokens_out=120, cost_usd=0.2)

    report = router.report()

    assert report.calls == 3
    assert report.tokens_in == 450
    assert report.tokens_out == 155
    assert report.total_tokens == 605
    assert report.cost_usd == pytest.approx(0.212)
    assert report.by_class[DecisionClass.RECON].calls == 2
    assert report.by_class[DecisionClass.RECON].total_tokens == 185
    assert report.by_class[DecisionClass.EXPLOIT].cost_usd == pytest.approx(0.2)
    assert report.by_class[DecisionClass.TRIAGE].calls == 0
    assert report.cost_per_finding(2) == pytest.approx(0.106)
    assert report.cost_per_finding(0) == 0.0


def test_record_rejects_negative_usage() -> None:
    router = BrainCostRouter()

    with pytest.raises(ValueError):
        router.record(DecisionClass.RECON, tokens_in=-1, tokens_out=0, cost_usd=0.0)

    with pytest.raises(ValueError):
        router.record(DecisionClass.RECON, tokens_in=0, tokens_out=0, cost_usd=-0.01)

    assert router.report().calls == 0
