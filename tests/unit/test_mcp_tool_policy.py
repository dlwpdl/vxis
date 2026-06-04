from __future__ import annotations

import pytest

from vxis import mcp_server


@pytest.mark.asyncio
async def test_mcp_tools_list_respects_allowlist(monkeypatch) -> None:
    monkeypatch.setenv("VXIS_MCP_TOOL_ALLOWLIST", "sense_*")
    monkeypatch.delenv("VXIS_MCP_TOOL_DENYLIST", raising=False)

    response = await mcp_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        }
    )
    tools = response["result"]["tools"]

    assert tools
    assert all(tool["name"].startswith("sense_") for tool in tools)


@pytest.mark.asyncio
async def test_mcp_tool_call_blocks_disallowed_known_tool(monkeypatch) -> None:
    monkeypatch.setenv("VXIS_MCP_TOOL_ALLOWLIST", "sense_*")
    monkeypatch.delenv("VXIS_MCP_TOOL_DENYLIST", raising=False)

    response = await mcp_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "phase_list", "arguments": {}},
        }
    )

    assert response["result"]["isError"] is True
    assert "not allowed" in response["result"]["content"][0]["text"]


@pytest.mark.asyncio
async def test_mcp_denylist_takes_precedence(monkeypatch) -> None:
    monkeypatch.setenv("VXIS_MCP_TOOL_ALLOWLIST", "*")
    monkeypatch.setenv("VXIS_MCP_TOOL_DENYLIST", "pattern_extract_secrets")

    response = await mcp_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        }
    )
    names = {tool["name"] for tool in response["result"]["tools"]}

    assert "pattern_extract_secrets" not in names
