from __future__ import annotations

import pytest

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult


class _ShellExecStub:
    name = "shell_exec"
    description = "sandbox shell"
    input_schema = {"type": "object"}

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, summary="shell ok", data={"stdout": ""})


@pytest.mark.asyncio
async def test_auto_ffuf_is_returned_as_sandbox_invocation() -> None:
    reg = ToolRegistry()
    reg.register(_ShellExecStub())

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=11)

    async def keep_exploring(state):
        return [("think", {"note": "continue"})]

    loop._decide = keep_exploring  # type: ignore[assignment]
    result = await loop.run()

    cmds = [inv.get("cmd", "") for inv in result["sandbox_invocations"]]
    assert any("ffuf" in cmd for cmd in cmds), cmds
