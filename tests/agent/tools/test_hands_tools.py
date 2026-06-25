import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from vxis.agent.tool_registry import BrainTool
from vxis.agent.tools.hands_tools import (
    HttpRequestTool,
    BrowserRenderTool,
    InterceptProxyTool,
    import_browser_cookies,
    _reset_for_tests,
)


@pytest.fixture(autouse=True)
def reset_tool_state():
    from vxis.ghost.layer import ghost_layer

    ghost_layer.deactivate()
    _reset_for_tests()
    yield
    _reset_for_tests()
    ghost_layer.deactivate()


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

    fake_manager.get_session.assert_awaited_once_with(
        "http://x",
        identity=None,
        proxy=None,
    )
    assert result.ok is True
    assert result.data["status"] == 200
    assert result.data["identity"] == "default"
    assert "hello" in result.data["body_preview"]
    assert result.data["body_length"] == 11
    assert result.data["links"] == ["/about", "/login"]
    assert "200" in result.summary


@pytest.mark.asyncio
async def test_http_request_tool_passes_identity_to_session_manager():
    fake_response = MagicMock()
    fake_response.status = 200
    fake_response.body = "alice profile"
    fake_response.body_length = 13
    fake_response.headers = {}
    fake_response.links = []
    fake_response.forms = []

    fake_session = MagicMock()
    fake_session.request = AsyncMock(return_value=fake_response)

    fake_manager = MagicMock()
    fake_manager.get_session = AsyncMock(return_value=fake_session)

    with patch("vxis.agent.tools.hands_tools._get_session_manager", return_value=fake_manager):
        result = await HttpRequestTool().run(
            base_url="http://x",
            method="GET",
            path="/me",
            identity="alice",
        )

    fake_manager.get_session.assert_awaited_once_with(
        "http://x",
        identity="alice",
        proxy=None,
    )
    assert result.ok is True
    assert result.data["identity"] == "alice"


@pytest.mark.asyncio
async def test_import_browser_cookies_uses_shared_origin_session():
    fake_manager = MagicMock()
    fake_manager.import_cookies = AsyncMock(return_value=1)

    with patch("vxis.agent.tools.hands_tools._get_session_manager", return_value=fake_manager):
        count = await import_browser_cookies(
            "http://x/login",
            [{"name": "sessionid", "value": "abc", "domain": "x", "path": "/"}],
        )

    assert count == 1
    fake_manager.import_cookies.assert_awaited_once_with(
        "http://x",
        [{"name": "sessionid", "value": "abc", "domain": "x", "path": "/"}],
        identity=None,
        proxy=None,
    )


@pytest.mark.asyncio
async def test_session_manager_import_cookies_updates_target_session():
    from vxis.interaction.hands import AuthState, SessionManager

    mgr = SessionManager()
    try:
        count = await mgr.import_cookies(
            "http://example.test",
            [{"name": "sessionid", "value": "abc", "domain": "example.test", "path": "/"}],
        )
        session = await mgr.get_session("http://example.test")
        assert count == 1
        assert session.cookies["sessionid"] == "abc"
        assert session.auth_state == AuthState.AUTHENTICATED
    finally:
        await mgr.close_all()


@pytest.mark.asyncio
async def test_http_request_tool_reports_ghost_transport_when_active():
    from vxis.ghost.layer import ghost_layer

    fake_response = MagicMock()
    fake_response.status = 204
    fake_response.body = ""
    fake_response.body_length = 0
    fake_response.headers = {}
    fake_response.links = []
    fake_response.forms = []

    fake_session = MagicMock()
    fake_session.request = AsyncMock(return_value=fake_response)

    fake_manager = MagicMock()
    fake_manager.get_session = AsyncMock(return_value=fake_session)
    ghost_layer.activate(["socks5://127.0.0.1:9050"])

    tool = HttpRequestTool()
    with patch("vxis.agent.tools.hands_tools._get_session_manager", return_value=fake_manager):
        result = await tool.run(base_url="http://x", method="GET", path="/")

    assert result.ok is True
    assert result.data["ghost"]["active"] is True
    assert result.data["ghost"]["component"] == "http_request"
    assert result.data["ghost"]["network_coverage"] == "ghost_transport"
    assert result.data["ghost"]["proxy_count"] == 1


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


@pytest.mark.asyncio
async def test_browser_render_tool_uses_ghost_route_when_active():
    from vxis.ghost.layer import ghost_layer

    fake_snapshot = MagicMock()
    fake_snapshot.title = "Example Domain"
    fake_snapshot.url = "http://example.com"
    fake_snapshot.html = "<html>...</html>"
    fake_snapshot.links = []
    fake_snapshot.forms = []

    fake_page = MagicMock()
    fake_page.navigate = AsyncMock()
    fake_page.snapshot = AsyncMock(return_value=fake_snapshot)

    fake_engine = MagicMock()
    fake_engine.start = AsyncMock()
    fake_engine.stop = AsyncMock()
    fake_engine.new_page = AsyncMock(return_value=fake_page)
    ghost_layer.activate(["socks5://127.0.0.1:9050"])

    with patch("vxis.interaction.eyes.BrowserEngine", return_value=fake_engine) as mock_engine:
        tool = BrowserRenderTool()
        result = await tool.run(url="http://example.com")

    assert result.ok is True
    assert mock_engine.call_args.kwargs["proxy"] == "socks5://127.0.0.1:9050"
    assert mock_engine.call_args.kwargs["user_agent"]
    assert result.data["ghost"]["active"] is True
    assert result.data["ghost"]["component"] == "browser_render"


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


def test_intercept_proxy_status_and_request_listing():
    fake_runtime = MagicMock()
    fake_runtime.status.return_value = {
        "backend": "xray",
        "running": True,
        "proxy_url": "http://localhost:8081",
        "flow_count": 2,
    }
    fake_runtime.list_requests = AsyncMock(
        return_value={
            "backend": "xray",
            "count": 2,
            "page": 1,
            "page_size": 20,
            "total_count": 2,
            "requests": [
                {"id": "mitm-0000", "method": "POST", "path": "/login", "status_code": 302},
                {"id": "mitm-0001", "method": "GET", "path": "/admin", "status_code": 200},
            ],
        }
    )

    tool = InterceptProxyTool()
    with patch("vxis.agent.tools.hands_tools.get_proxy_runtime", return_value=fake_runtime):
        status_result = asyncio.run(tool.run(action="status"))
        list_result = asyncio.run(tool.run(action="list_requests", filter="method:POST"))

    assert status_result.ok is True
    assert "running" in status_result.summary
    assert status_result.data["backend"] == "xray"

    assert list_result.ok is True
    assert list_result.data["count"] == 2
    fake_runtime.list_requests.assert_awaited_once()


def test_intercept_proxy_view_and_repeat_request():
    fake_runtime = MagicMock()
    fake_runtime.view_request = AsyncMock(
        return_value={
            "backend": "xray",
            "request_id": "mitm-0000",
            "part": "request",
            "method": "POST",
            "url": "https://example.test/login",
            "headers": {"content-type": "application/x-www-form-urlencoded"},
            "body": "username=admin&password=test",
            "body_preview": "username=admin&password=test",
        }
    )
    fake_runtime.repeat_request = AsyncMock(
        return_value={
            "ok": True,
            "request_id": "mitm-0000",
            "status_code": 200,
            "url": "https://example.test/login",
            "body_preview": "ok",
            "body_length": 2,
        }
    )

    tool = InterceptProxyTool()
    with patch("vxis.agent.tools.hands_tools.get_proxy_runtime", return_value=fake_runtime):
        view_result = asyncio.run(tool.run(action="view_request", request_id="mitm-0000"))
        repeat_result = asyncio.run(
            tool.run(
                action="repeat_request",
                request_id="mitm-0000",
                overrides={"body_replacements": {"test": "admin"}},
            )
        )

    assert view_result.ok is True
    assert view_result.data["method"] == "POST"
    assert repeat_result.ok is True
    assert repeat_result.data["status_code"] == 200


# ── Registry integration ────────────────────────────────────

def test_build_default_registry_contains_hands_eyes_xray_tools():
    from vxis.agent.tools import build_default_registry
    reg = build_default_registry()
    names = reg.list_tools()
    # Hands/Eyes/X-Ray primitives from Task 6
    assert "http_request" in names
    assert "browser_render" in names
    assert "intercept_proxy" in names
    # Control tools from Task 5 also present
    assert "finish_scan" in names
    assert "think" in names
    assert "wait" in names
    # Forward-compat: Tasks 7-8 add more tools; assert minimum only
    assert len(names) >= 6
