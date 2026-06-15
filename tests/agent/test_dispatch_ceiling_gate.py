"""NOW-2/2d — exploitation-ceiling gate wired into tool_registry.dispatch.

A 3rd fail-closed gate (after P1 + scope) refuses exploitation primitives
(shell_exec/python_exec) when an active ScanPolicy's exploitation ceiling is
below 'lateral'. Active-only: no ambient policy → legacy (no block).
"""
import pytest

from vxis.agent.policy.runtime_policy import clear_active_policy, set_active_policy
from vxis.agent.policy.scan_policy import PROFILE_POLICY_TABLE
from vxis.agent.tool_registry import ToolRegistry, ToolResult


class _StubShell:
    name = "shell_exec"
    description = "stub"
    input_schema = {"type": "object"}

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, summary="ran", data={})


class _StubHttp:
    name = "http_request"
    description = "stub"
    input_schema = {"type": "object"}

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, summary="fetched", data={})


def _reg():
    reg = ToolRegistry()
    reg.register(_StubShell())
    reg.register(_StubHttp())
    return reg


@pytest.mark.asyncio
async def test_dispatch_blocks_shell_under_readonly_ceiling():
    reg = _reg()
    tok = set_active_policy(PROFILE_POLICY_TABLE["standard"])  # read-only
    try:
        r = await reg.dispatch("shell_exec", {"command": "id"})
    finally:
        clear_active_policy(tok)
    assert r.ok is False
    assert r.error == "ceiling_blocked"


@pytest.mark.asyncio
async def test_dispatch_allows_shell_under_full_ceiling():
    reg = _reg()
    tok = set_active_policy(PROFILE_POLICY_TABLE["aggressive"])  # full
    try:
        r = await reg.dispatch("shell_exec", {"command": "id"})
    finally:
        clear_active_policy(tok)
    assert r.ok is True


@pytest.mark.asyncio
async def test_dispatch_allows_non_exploitation_tool_under_low_ceiling():
    reg = _reg()
    tok = set_active_policy(PROFILE_POLICY_TABLE["standard"])  # read-only
    try:
        r = await reg.dispatch("http_request", {"url": "http://t"})
    finally:
        clear_active_policy(tok)
    assert r.ok is True


@pytest.mark.asyncio
async def test_dispatch_allows_shell_when_no_active_policy():
    # legacy: ceiling off → shell not gated
    reg = _reg()
    r = await reg.dispatch("shell_exec", {"command": "id"})
    assert r.ok is True
