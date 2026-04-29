from __future__ import annotations

import asyncio

import pytest

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.agent.tools.finding_tools import ReportFindingTool, _reset_for_tests


class _ShellTool:
    name = "shell_exec"
    description = "run shell command"
    input_schema = {"type": "object", "properties": {"command": {"type": "string"}}}

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, summary=f"ran {kwargs.get('command', '')}", data={"stdout": "ok"})


def test_scan_loop_emits_ui_events_for_regular_dispatch() -> None:
    async def _run() -> list[tuple[str, dict]]:
        reg = ToolRegistry()
        reg.register(_ShellTool())

        events: list[tuple[str, dict]] = []
        loop = ScanAgentLoop(
            target="http://example.test",
            registry=reg,
            max_iters=1,
            event_callback=lambda event_type, data: events.append((event_type, data)),
        )

        async def _fake_decide(state):
            return [("shell_exec", {"command": "curl -s http://example.test/login"})]

        loop._decide = _fake_decide  # type: ignore[assignment]
        await loop.run()
        return events

    events = asyncio.run(_run())
    brain_events = [data for event_type, data in events if event_type == "brain_thinking"]
    attack_events = [data for event_type, data in events if event_type == "attack"]
    control_events = [data for event_type, data in events if event_type == "control_plane"]

    assert brain_events, "scan loop must emit brain_thinking so the TUI does not look idle"
    assert any("Brain choosing next action" in e["vectors"][0]["reasoning"] for e in brain_events)

    assert attack_events, "scan loop must emit attack events before dispatching long-running tools"
    assert attack_events[0]["vector_id"] == "shell_exec"
    assert attack_events[0]["method"] == "EXEC"
    assert "curl -s http://example.test/login" in attack_events[0]["endpoint"]

    assert control_events, "scan loop must emit control-plane state for live TUI sync"
    assert control_events[0]["todos"], "control-plane state should include visible todos"
    assert control_events[0]["branches"], "control-plane state should include visible branches"


def test_scan_loop_spawns_followup_branches_from_finding() -> None:
    async def _run() -> dict:
        _reset_for_tests()
        reg = ToolRegistry()
        reg.register(ReportFindingTool())

        loop = ScanAgentLoop(
            target="http://example.test",
            registry=reg,
            max_iters=1,
        )

        async def _fake_decide(state):
            return [(
                "report_finding",
                {
                    "title": "Auth bypass on login",
                    "severity": "high",
                    "finding_type": "auth_bypass",
                    "affected_component": "http://example.test/login",
                    "description": "The login accepted a bypass payload.",
                    "evidence": "status 302 -> /admin",
                },
            )]

        loop._decide = _fake_decide  # type: ignore[assignment]
        return await loop.run()

    result = asyncio.run(_run())
    branches = result["branches"]
    branch_ids = {branch["id"] for branch in branches}

    assert "web:auth-bypass:post-auth-enum" in branch_ids
    assert "web:auth-bypass:admin-access-control" in branch_ids
