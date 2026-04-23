"""Phase Q — surface guard tests.

Brain LLM ignores the desktop preamble's "DO NOT call web skills" rule on
~30% of iters and dispatches `run_skill test_infra` etc. against file://
paths, producing false-positive cloud_metadata reports. The dispatch-level
guard at scan_loop.py L805 must:

1. Block the dispatch (no actual run_skill call).
2. Inject a tool result with `surface_guard_blocked=True`.
3. Inject a SYSTEM HINT so Brain re-plans toward a desktop skill.
4. Continue the loop (not crash).

Symmetric: web targets must NOT be blocked from running web skills.
"""
from __future__ import annotations

import pytest

from vxis.agent.scan_loop import ScanAgentLoop, _DESKTOP_SKILLS
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.interaction.surface import TargetKind


class _FinishTool:
    name = "finish_scan"
    description = "end scan"
    input_schema = {"type": "object"}

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, summary="finished", data={"final": True})


class _RunSkillSpy:
    """run_skill stub that records every dispatch — guard must prevent web
    skills from reaching here on desktop targets."""

    name = "run_skill"
    description = "fire payloads"
    input_schema = {
        "type": "object",
        "properties": {"skill": {"type": "string"}},
    }

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def run(self, **kwargs) -> ToolResult:
        self.calls.append(dict(kwargs))
        return ToolResult(
            ok=True,
            summary=f"ran {kwargs.get('skill')}",
            data={"findings": []},
        )


@pytest.mark.asyncio
async def test_surface_guard_blocks_web_skill_on_desktop_target() -> None:
    spy = _RunSkillSpy()
    reg = ToolRegistry()
    reg.register(spy)
    reg.register(_FinishTool())

    loop = ScanAgentLoop(
        target="/Applications/Calculator.app",
        registry=reg,
        max_iters=3,
        target_kind=TargetKind.DESKTOP,
    )

    decisions = iter([
        [("run_skill", {"skill": "test_infra", "target_url": "/Applications/Calculator.app"})],
        [("run_skill", {"skill": "test_csrf", "target_url": "/Applications/Calculator.app"})],
        [("finish_scan", {})],
    ])

    async def _fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop._decide = _fake_decide  # type: ignore[assignment]
    await loop.run()

    # Spy must have received ZERO calls — guard blocks before dispatch.
    assert spy.calls == [], f"web skills reached dispatch: {spy.calls}"

    # Tool messages must record the block.
    blocks = [
        m for m in loop.state.messages
        if m.get("role") == "tool"
        and isinstance(m.get("content"), dict)
        and (m["content"].get("result") or {}).get("data", {}).get("surface_guard_blocked")
    ]
    assert len(blocks) == 2, f"expected 2 blocks, got {len(blocks)}"
    assert blocks[0]["content"]["result"]["data"]["requested_skill"] == "test_infra"
    assert blocks[1]["content"]["result"]["data"]["requested_skill"] == "test_csrf"


@pytest.mark.asyncio
async def test_surface_guard_allows_desktop_skill_on_desktop_target() -> None:
    spy = _RunSkillSpy()
    reg = ToolRegistry()
    reg.register(spy)
    reg.register(_FinishTool())

    loop = ScanAgentLoop(
        target="/Applications/Calculator.app",
        registry=reg,
        max_iters=2,
        target_kind=TargetKind.DESKTOP,
    )

    decisions = iter([
        [("run_skill", {"skill": "test_signature_audit", "target_url": "/Applications/Calculator.app"})],
        [("finish_scan", {})],
    ])

    async def _fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop._decide = _fake_decide  # type: ignore[assignment]
    await loop.run()

    assert len(spy.calls) == 1
    assert spy.calls[0]["skill"] == "test_signature_audit"


@pytest.mark.asyncio
async def test_surface_guard_inert_on_web_target() -> None:
    """Web targets must keep their existing behaviour — guard only fires on
    desktop kind."""
    spy = _RunSkillSpy()
    reg = ToolRegistry()
    reg.register(spy)
    reg.register(_FinishTool())

    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=2,
        target_kind=TargetKind.WEB,
    )

    decisions = iter([
        [("run_skill", {"skill": "test_infra", "target_url": "http://localhost:3000"})],
        [("finish_scan", {})],
    ])

    async def _fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop._decide = _fake_decide  # type: ignore[assignment]
    await loop.run()

    assert len(spy.calls) == 1
    assert spy.calls[0]["skill"] == "test_infra"


def test_desktop_skills_set_is_frozen() -> None:
    assert isinstance(_DESKTOP_SKILLS, frozenset)
    assert "test_signature_audit" in _DESKTOP_SKILLS
    assert "test_infra" not in _DESKTOP_SKILLS
