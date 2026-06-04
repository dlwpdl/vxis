from __future__ import annotations

import pytest

from vxis.agent.tools.self_critique import SelfCritiqueTool


@pytest.mark.asyncio
async def test_self_critique_tool_returns_serialized_report() -> None:
    tool = SelfCritiqueTool()

    result = await tool.run(
        dag={"nodes": [{"claim": "Admin API IDOR", "prior": 0.9, "status": "pending"}]},
        matrix={"coverage_pct": 50, "high_value_surface_coverage": 50},
        findings=[],
        pti=None,
    )

    assert result.ok is True
    report = result.data["report"]
    assert report["finish_allowed"] is False
    assert report["untested_high_prior_hypotheses"] == ["Admin API IDOR"]
    assert "self_critique blocked finish_scan" in result.summary
