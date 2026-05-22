import pytest

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry
from vxis.agent.tools.finding_tools import (
    ReportFindingTool,
    _reset_for_tests as _reset_findings,
)
from vxis.interaction.surface import TargetKind


class RunSkillTool:
    name = "run_skill"
    description = "execute prebuilt skill"
    input_schema = {"type": "object"}


@pytest.fixture(autouse=True)
def _isolate_findings():
    _reset_findings()
    yield
    _reset_findings()


@pytest.mark.asyncio
async def test_chain_nudge_reinjects_when_findings_outpace_chains():
    registry = ToolRegistry()
    registry.register(ReportFindingTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=40)

    for title, finding_type, component in [
        ("SQL injection on search", "sql_injection", "/search"),
        ("Admin panel exposed", "broken_access_control", "/admin"),
        ("User export leaks data", "information_disclosure", "/api/export"),
    ]:
        result = await registry.dispatch("report_finding", {
            "title": title,
            "severity": "medium",
            "finding_type": finding_type,
            "affected_component": component,
            "description": title,
        })
        assert result.ok

    loop.state.iteration = 18
    loop._maybe_inject_chain_nudge()

    assert loop.state.messages
    nudge = loop.state.messages[-1]
    assert nudge["role"] == "user"
    assert "CHAIN ANALYSIS PHASE" in nudge["content"]
    assert "link_chain" in nudge["content"]
    assert "SQL injection on search" in nudge["content"]

    message_count = len(loop.state.messages)
    loop._maybe_inject_chain_nudge()
    assert len(loop.state.messages) == message_count

    loop.state.iteration = 23
    loop._maybe_inject_chain_nudge()
    assert len(loop.state.messages) == message_count


def test_skill_sweep_queues_untried_web_skills_with_surface_filter():
    registry = ToolRegistry()
    registry.register(RunSkillTool())
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=registry,
        max_iters=60,
        target_kind=TargetKind.WEB,
    )
    loop.state.iteration = 25
    queued: list[tuple[str, int, dict, str | None]] = []

    def queue_skill(
        skill: str,
        trigger_iter: int,
        params: dict,
        *,
        alias: str | None = None,
    ) -> bool:
        queued.append((skill, trigger_iter, dict(params), alias))
        return True

    loop._maybe_queue_skill_sweep(
        target_kind_cls=TargetKind,
        real_skills_completed=set(),
        auth_token="token-123",
        queue_skill=queue_skill,
    )

    assert queued
    assert all(trigger_iter == 26 for _, trigger_iter, _, _ in queued)
    assert all(alias and alias.endswith("__sweep25") for _, _, _, alias in queued)
    assert all(params.get("_skill_override") == skill for skill, _, params, _ in queued)
    assert "test_macos_entitlements" not in {skill for skill, _, _, _ in queued}
    assert loop.state.messages[-1]["role"] == "user"
    assert "SKILL SWEEP at iter 25" in loop.state.messages[-1]["content"]

    message_count = len(loop.state.messages)
    loop._maybe_queue_skill_sweep(
        target_kind_cls=TargetKind,
        real_skills_completed=set(),
        auth_token="token-123",
        queue_skill=queue_skill,
    )
    assert len(loop.state.messages) == message_count
