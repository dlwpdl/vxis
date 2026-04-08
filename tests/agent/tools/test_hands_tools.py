import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from vxis.agent.tool_registry import BrainTool, ToolResult
from vxis.agent.tools.hands_tools import (
    HttpRequestTool,
    BrowserRenderTool,
    InterceptProxyTool,
    _reset_for_tests,
)


@pytest.fixture(autouse=True)
def reset_tool_state():
    _reset_for_tests()
    yield
    _reset_for_tests()


# ── HttpRequestTool ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_http_request_tool_successful_get():
    """HttpRequestTool wraps SessionManager.get_session().request() and returns parsed ToolResult."""
    fake_response = MagicMock()
    fake_response.status = 200
    fake_response.body = "hello world"
    fake_response.body_length = 11
    fake_response.headers = {"content-type": "text/html"}
    fake_response.links = ["/about", "/login"]
    fake_response.forms = []

    fake_session = MagicMock()
    fake_session.request = AsyncMock(return_value=fake_response)

    fake_manager = MagicMock()
    fake_manager.get_session = AsyncMock(return_value=fake_session)

    tool = HttpRequestTool()
    assert isinstance(tool, BrainTool)

    with patch("vxis.agent.tools.hands_tools._get_session_manager", return_value=fake_manager):
        result = await tool.run(base_url="http://x", method="GET", path="/")

    assert result.ok is True
    assert result.data["status"] == 200
    assert "hello" in result.data["body_preview"]
    assert result.data["body_length"] == 11
    assert result.data["links"] == ["/about", "/login"]
    assert "200" in result.summary


@pytest.mark.asyncio
async def test_http_request_tool_missing_base_url():
    tool = HttpRequestTool()
    result = await tool.run(method="GET", path="/")
    assert result.ok is False
    assert "base_url" in result.summary


@pytest.mark.asyncio
async def test_http_request_tool_exception_returns_failing_result():
    fake_manager = MagicMock()
    fake_manager.get_session = AsyncMock(side_effect=RuntimeError("connection refused"))

    tool = HttpRequestTool()
    with patch("vxis.agent.tools.hands_tools._get_session_manager", return_value=fake_manager):
        result = await tool.run(base_url="http://x", method="GET", path="/")

    assert result.ok is False
    assert "connection refused" in result.summary
    assert result.error is not None


# ── BrowserRenderTool ────────────────────────────────────────

@pytest.mark.asyncio
async def test_browser_render_tool_missing_url():
    tool = BrowserRenderTool()
    assert isinstance(tool, BrainTool)
    result = await tool.run()
    assert result.ok is False
    assert "url" in result.summary


@pytest.mark.asyncio
async def test_browser_render_tool_stubbed_engine():
    """Verify the tool calls engine.start() → new_page() → navigate() → snapshot() → stop()."""
    fake_snapshot = MagicMock()
    fake_snapshot.title = "Example Domain"
    fake_snapshot.url = "http://example.com"
    fake_snapshot.html = "<html>...</html>"
    fake_snapshot.links = ["http://example.com/a"]
    fake_snapshot.forms = []

    fake_page = MagicMock()
    fake_page.navigate = AsyncMock()
    fake_page.snapshot = AsyncMock(return_value=fake_snapshot)

    fake_engine = MagicMock()
    fake_engine.start = AsyncMock()
    fake_engine.stop = AsyncMock()
    fake_engine.new_page = AsyncMock(return_value=fake_page)

    with patch("vxis.interaction.eyes.BrowserEngine", return_value=fake_engine):
        tool = BrowserRenderTool()
        result = await tool.run(url="http://example.com")

    assert result.ok is True
    assert result.data["title"] == "Example Domain"
    assert result.data["final_url"] == "http://example.com"
    fake_engine.start.assert_awaited_once()
    fake_engine.stop.assert_awaited_once()
    fake_page.navigate.assert_awaited_once_with("http://example.com")
    fake_page.snapshot.assert_awaited_once()


# ── InterceptProxyTool ───────────────────────────────────────

@pytest.mark.asyncio
async def test_intercept_proxy_unknown_action():
    tool = InterceptProxyTool()
    assert isinstance(tool, BrainTool)
    result = await tool.run(action="frobnicate")
    assert result.ok is False
    assert "unknown action" in result.summary.lower()


@pytest.mark.asyncio
async def test_intercept_proxy_stop_when_not_running():
    tool = InterceptProxyTool()
    result = await tool.run(action="stop")
    assert result.ok is True
    assert "stopped" in result.summary.lower()


@pytest.mark.asyncio
async def test_intercept_proxy_flows_when_not_running():
    tool = InterceptProxyTool()
    result = await tool.run(action="flows")
    assert result.ok is True
    assert result.data["count"] == 0


# ── Registry integration ────────────────────────────────────

def test_build_default_registry_now_has_six_tools():
    from vxis.agent.tools import build_default_registry
    reg = build_default_registry()
    names = reg.list_tools()
    assert "finish_scan" in names
    assert "think" in names
    assert "wait" in names
    assert "http_request" in names
    assert "browser_render" in names
    assert "intercept_proxy" in names
    assert len(names) == 6
