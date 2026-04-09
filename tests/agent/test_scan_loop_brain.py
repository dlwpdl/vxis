import pytest
from unittest.mock import MagicMock, AsyncMock

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult


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


@pytest.mark.asyncio
async def test_brain_drives_loop_via_think_in_loop():
    reg = ToolRegistry()
    reg.register(EchoTool())
    reg.register(FinishTool())

    fake_brain = MagicMock()
    fake_brain.think_in_loop = AsyncMock(side_effect=[
        [("echo", {"msg": "hello"})],
        [("finish_scan", {})],
    ])

    loop = ScanAgentLoop(target="http://x", registry=reg, max_iters=5, brain=fake_brain)
    result = await loop.run()

    assert result["completed"] is True
    assert fake_brain.think_in_loop.await_count == 2
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

    # Phase B: adapter header renamed from "ADAPTER INSTRUCTIONS" to "STRIX-STYLE ADAPTER"
    assert "STRIX-STYLE ADAPTER" in full
    assert "100% COVERAGE" in full  # body marker

    assert "{{" not in full
    assert "}}" not in full

    assert "Controller" in full
    # Phase B: adapter upgraded to prefer shell_exec (real sqlmap/nuclei/ffuf)
    # over the hypothetical cpr_recon tool that was never implemented
    assert "shell_exec" in full
    assert "http_request" in full
