import pytest
from unittest.mock import MagicMock, AsyncMock

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.agent.tools.finding_tools import (
    ReportFindingTool,
    _reset_for_tests as _reset_findings,
)


class EchoTool:
    name = "echo"
    description = "echo back"
    input_schema = {"type": "object"}

    async def run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, summary="echoed", data=kw)


class FinishTool:
    name = "finish_scan"
    description = "end scan"
    input_schema = {"type": "object"}

    async def run(self, **kw) -> ToolResult:
        return ToolResult(ok=True, summary="done")


@pytest.fixture(autouse=True)
def _isolate_findings():
    _reset_findings()
    yield
    _reset_findings()


@pytest.mark.asyncio
async def test_brain_drives_loop_via_think_in_loop():
    """Brain drives loop via think_in_loop; Q11 requires ≥1 finding before
    finish_scan can complete, and the min_iters guard requires iter ≥
    max_iters//2 (= 2 here). Sequence: echo → report_finding → finish_scan
    rejected (iter 3, but actually iter < min_iters? min=2, iter 3 ≥ 2 so
    passes min_iters; 1 finding so passes 0-finding gate; chains check
    skipped for <3 findings) → completes.
    """
    reg = ToolRegistry()
    reg.register(EchoTool())
    reg.register(FinishTool())
    reg.register(ReportFindingTool())

    fake_brain = MagicMock()
    fake_brain.think_in_loop = AsyncMock(side_effect=[
        [("echo", {"msg": "hello"})],
        [("report_finding", {
            "title": "stub", "severity": "low", "finding_type": "test_stub",
            "affected_component": "/x", "description": "fixture",
        })],
        [("finish_scan", {})],
    ])

    loop = ScanAgentLoop(target="http://x", registry=reg, max_iters=5, brain=fake_brain)
    result = await loop.run()

    assert result["completed"] is True
    assert fake_brain.think_in_loop.await_count == 3
    first_call_args = fake_brain.think_in_loop.await_args_list[0].args
    messages_arg = first_call_args[0]
    tools_arg = first_call_args[1]
    assert isinstance(messages_arg, list) and len(messages_arg) > 0
    assert any(t["name"] == "echo" for t in tools_arg)
    assert any(t["name"] == "finish_scan" for t in tools_arg)


@pytest.mark.asyncio
async def test_think_in_loop_returns_parsed_actions_from_real_brain(monkeypatch):
    from vxis.agent.brain import AgentBrain, get_brain_decision_count, reset_brain_decision_count

    reset_brain_decision_count()

    brain = AgentBrain()
    fake_llm_response = (
        '```json\n'
        '{"reasoning": "map first", "actions": [{"tool": "cpr_recon", "args": {"depth": 2}, '
        '"reasoning": "map attack surface", "priority": "high"}]}\n'
        '```'
    )
    monkeypatch.setattr(brain, "_call_llm_with_fallback", lambda s, u, **kw: fake_llm_response)

    messages = [
        {"role": "system", "content": "Scan started"},
        {"role": "user", "content": "Target: http://example.com"},
    ]
    tool_catalog = [
        {"name": "cpr_recon", "description": "map endpoints + subdomains", "input_schema": {"type": "object"}},
        {"name": "finish_scan", "description": "end scan", "input_schema": {"type": "object"}},
    ]

    actions = await brain.think_in_loop(messages, tool_catalog)

    assert len(actions) == 1
    assert actions[0] == ("cpr_recon", {"depth": 2})
    assert get_brain_decision_count() == 1


def test_think_in_loop_adapter_concatenation_no_brace_explosion():
    from vxis.agent.brain import LOOP_PROMPT_ADAPTER, AGENT_SYSTEM_PROMPT

    body = AGENT_SYSTEM_PROMPT.format(available_tools="  - test_tool: test description")
    full = LOOP_PROMPT_ADAPTER + "\n" + body

    # Phase B rewrote the adapter from a thin "ADAPTER INSTRUCTIONS / STRIX-STYLE
    # ADAPTER" header into a full HOW-TO-THINK guide. "STRIX-STYLE ADAPTER" no
    # longer appears; assert on the actual section header present instead.
    assert "HOW TO THINK" in full
    # Authorization preamble survives the rewrite.
    assert "Authorization confirmed" in full

    # No brace explosion — AGENT_SYSTEM_PROMPT.format() must not raise KeyError.
    # The adapter is a raw string so its JSON-example braces are literals, not
    # format placeholders.  Only check that the adapter itself has no {{ or }}
    # (which would indicate accidental double-escaping in the raw string).
    assert "{{" not in LOOP_PROMPT_ADAPTER
    # AGENT_SYSTEM_PROMPT has {available_tools} filled above — confirm no
    # unfilled placeholders remain in the body.
    assert "{available_tools}" not in body

    assert "Controller" in full
    # Phase B: adapter upgraded to prefer shell_exec (real sqlmap/nuclei/ffuf)
    # over the hypothetical cpr_recon tool that was never implemented.
    assert "shell_exec" in full
    # link_chain is surfaced via the adapter's FINDING REPORT FORMAT section.
    assert "link_chain" in full
