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
            "params": {
                "name": "pattern_detect_sql",
                "arguments": {"response_body": "", "status": 200},
            },
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


@pytest.mark.asyncio
async def test_mcp_does_not_expose_removed_phase_tools(monkeypatch) -> None:
    monkeypatch.setenv("VXIS_MCP_TOOL_ALLOWLIST", "*")
    monkeypatch.delenv("VXIS_MCP_TOOL_DENYLIST", raising=False)

    response = await mcp_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
        }
    )
    names = {tool["name"] for tool in response["result"]["tools"]}

    assert "phase_list" not in names
    assert "phase_get" not in names
    assert "phase_validate" not in names


@pytest.mark.asyncio
async def test_mcp_scope_tools_execute(monkeypatch) -> None:
    monkeypatch.setenv("VXIS_MCP_TOOL_ALLOWLIST", "scope_*")
    monkeypatch.delenv("VXIS_MCP_TOOL_DENYLIST", raising=False)

    url_response = await mcp_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "scope_check_url",
                "arguments": {"url": "http://localhost:3000/login"},
            },
        }
    )
    assert url_response["result"]["isError"] is False
    assert '"allowed": true' in url_response["result"]["content"][0]["text"]

    action_response = await mcp_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "scope_check_action",
                "arguments": {"method": "DELETE", "url": "http://localhost:3000/api/item/1"},
            },
        }
    )
    assert action_response["result"]["isError"] is False
    assert '"allowed": false' in action_response["result"]["content"][0]["text"]
