from __future__ import annotations

import asyncio

from vxis.agent.tools.finding_tools import (
    LinkChainTool,
    ReportFindingTool,
    _reset_for_tests,
    set_event_callback,
)


def test_finding_tools_emit_live_hit_and_chain_events() -> None:
    async def _run() -> list[tuple[str, dict]]:
        _reset_for_tests()
        events: list[tuple[str, dict]] = []
        set_event_callback(lambda event_type, data: events.append((event_type, data)))

        report = ReportFindingTool()
        chain = LinkChainTool()

        first = await report.run(
            title="SQL Injection on login",
            severity="critical",
            finding_type="sql_injection",
            affected_component="/login",
            description="Classic auth bypass",
            evidence="POST /login username=admin' --",
        )
        second = await report.run(
            title="Weak auth on admin",
            severity="high",
            finding_type="weak_auth",
            affected_component="/admin",
            description="Default credentials accepted",
            evidence="admin:admin",
        )
        await chain.run(
            finding_ids=[first.data["id"], second.data["id"]],
            rationale="Initial foothold escalates to admin access",
            crown_jewel="admin takeover",
        )
        set_event_callback(None)
        return events

    events = asyncio.run(_run())

    hit_events = [data for event_type, data in events if event_type == "hit"]
    chain_start_events = [data for event_type, data in events if event_type == "chain_start"]
    chain_step_events = [data for event_type, data in events if event_type == "chain_step"]

    assert len(hit_events) == 2
    assert hit_events[0]["vector_id"] == "sql_injection"
    assert hit_events[0]["level"] == 4
    assert hit_events[0]["severity"] == "critical"
    assert hit_events[0]["finding_id"].startswith("VXIS-")

    assert len(chain_start_events) == 1
    assert chain_start_events[0]["chain_id"].startswith("CHAIN-")
    assert chain_start_events[0]["finding_type"] == "sql_injection"

    assert len(chain_step_events) == 2
    assert chain_step_events[0]["vector_id"] == "sql_injection"
    assert chain_step_events[1]["vector_id"] == "weak_auth"
