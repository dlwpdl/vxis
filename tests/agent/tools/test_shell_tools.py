import pytest
import re
from unittest.mock import AsyncMock, MagicMock, patch

from vxis.agent.tool_registry import BrainTool
from vxis.agent.tools.shell_tools import (
    ShellExecTool,
    _reset_for_tests,
    SANDBOX_IMAGE,
    resolve_sandbox_runtime,
)


@pytest.fixture(autouse=True)
def reset_state():
    from vxis.ghost.layer import ghost_layer

    ghost_layer.deactivate()
    _reset_for_tests()
    yield
    _reset_for_tests()
    ghost_layer.deactivate()


@pytest.mark.asyncio
async def test_shell_exec_tool_conforms_to_brain_tool():
    tool = ShellExecTool()
    assert isinstance(tool, BrainTool)
    assert tool.name == "shell_exec"


@pytest.mark.asyncio
async def test_shell_exec_tool_missing_command():
    tool = ShellExecTool()
    result = await tool.run()
    assert result.ok is False
    assert "command" in result.summary


@pytest.mark.asyncio
async def test_shell_exec_tool_docker_unavailable():
    with patch("vxis.agent.tools.shell_tools._docker_available", return_value=False):
        tool = ShellExecTool()
        result = await tool.run(command="echo hi")
    assert result.ok is False
    assert "docker" in result.summary.lower()


@pytest.mark.asyncio
async def test_shell_exec_tool_image_not_built():
    async def fake_image_exists(img):
        return False
    async def fake_container_running(name):
        return False

    with patch("vxis.agent.tools.shell_tools._docker_available", return_value=True), \
         patch("vxis.agent.tools.shell_tools._image_exists", side_effect=fake_image_exists), \
         patch("vxis.agent.tools.shell_tools._container_running", side_effect=fake_container_running):
        tool = ShellExecTool()
        result = await tool.run(command="echo hi")
    assert result.ok is False
    assert "not built" in result.summary.lower()
    assert SANDBOX_IMAGE in result.summary


@pytest.mark.asyncio
async def test_ensure_sandbox_running_uses_per_scan_container_and_workspace(tmp_path):
    from vxis.agent.tools import shell_tools

    calls: list[tuple[str, ...]] = []

    async def fake_run_docker(*args, timeout=30.0):
        calls.append(tuple(args))
        if args[:2] == ("image", "inspect"):
            return 0, "", ""
        if args[:1] == ("ps",):
            return 0, "", ""
        if args[:1] == ("run",):
            return 0, "container-id\n", ""
        return 0, "", ""

    with patch("vxis.agent.tools.shell_tools._docker_available", return_value=True), \
         patch("vxis.agent.tools.shell_tools._run_docker", side_effect=fake_run_docker):
        ok, msg = await shell_tools._ensure_sandbox_running(
            sandbox_key="SCAN/ABC 123",
            workspace_host=str(tmp_path),
        )

    runtime = resolve_sandbox_runtime("SCAN/ABC 123", workspace_host=str(tmp_path))
    assert ok is True
    assert msg == "sandbox started"
    run_call = next(call for call in calls if call[:1] == ("run",))
    assert runtime.container in run_call
    assert f"{tmp_path}:/workspace" in run_call
    assert "vxis.managed=true" in run_call
    assert "vxis.sandbox_key=scan-abc-123" in run_call


@pytest.mark.asyncio
async def test_shell_exec_tool_runs_command_via_docker_exec_when_sandbox_ready():
    """When tool server is unavailable, shell_exec falls back to docker exec."""
    async def fake_ensure(**kwargs):
        return True, "sandbox already running"

    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.communicate = AsyncMock(return_value=(b"hello world\n", b""))

    with patch("vxis.agent.tools.shell_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.shell_tools._execute_via_tool_server", AsyncMock(return_value=None)), \
         patch("asyncio.create_subprocess_exec", return_value=fake_proc) as mock_exec:
        tool = ShellExecTool(sandbox_key="scan-123")
        result = await tool.run(command="echo hello world")

    assert result.ok is True
    assert result.data["exit_code"] == 0
    assert "hello world" in result.data["stdout"]
    # Verify the docker exec invocation
    call_args = mock_exec.call_args.args
    runtime = resolve_sandbox_runtime("scan-123")
    assert call_args[0] == "docker"
    assert call_args[1] == "exec"
    assert call_args[2] == runtime.container
    assert call_args[3] == "sh"
    assert call_args[4] == "-c"
    assert call_args[5] == "echo hello world"
    assert result.data["container"] == runtime.container
    assert result.data["transport"] == "docker_exec"


@pytest.mark.asyncio
async def test_shell_exec_applies_ghost_proxy_env_without_leaking_in_command_data():
    from vxis.ghost.layer import ghost_layer

    async def fake_ensure(**kwargs):
        return True, "sandbox already running"

    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.communicate = AsyncMock(return_value=(b"ok\n", b""))
    ghost_layer.activate(["socks5://user:secret@127.0.0.1:9050"])

    with patch("vxis.agent.tools.shell_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.shell_tools._execute_via_tool_server", AsyncMock(return_value=None)), \
         patch("asyncio.create_subprocess_exec", return_value=fake_proc) as mock_exec:
        tool = ShellExecTool(sandbox_key="scan-123")
        result = await tool.run(command="curl https://example.com")

    effective_command = mock_exec.call_args.args[5]
    assert "export HTTP_PROXY=socks5://user:secret@127.0.0.1:9050" in effective_command
    assert effective_command.rstrip().endswith("curl https://example.com")
    assert result.data["command"] == "curl https://example.com"
    assert result.data["ghost"]["active"] is True
    assert result.data["ghost"]["component"] == "shell_exec"
    assert result.data["ghost"]["proxy"] == "socks5://****@127.0.0.1:9050"
    assert "secret" not in result.data["ghost"]["proxy"]


@pytest.mark.asyncio
async def test_shell_exec_tool_uses_tool_server_when_available():
    async def fake_ensure(**kwargs):
        return True, "sandbox already running"

    server_result = {
        "exit_code": 0,
        "stdout": "via server\n",
        "stderr": "",
        "timeout": False,
        "transport": "tool_server",
    }
    with patch("vxis.agent.tools.shell_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.shell_tools._execute_via_tool_server", AsyncMock(return_value=server_result)), \
         patch("asyncio.create_subprocess_exec") as mock_exec:
        tool = ShellExecTool(sandbox_key="scan-123")
        result = await tool.run(command="echo hello world")

    assert result.ok is True
    assert result.data["stdout"] == "via server\n"
    assert result.data["transport"] == "tool_server"
    mock_exec.assert_not_called()


@pytest.mark.asyncio
async def test_shell_exec_session_uses_tmux_and_returns_marked_output():
    async def fake_ensure(**kwargs):
        return True, "sandbox already running"

    sent_payload = ""

    async def fake_run_docker(*args, timeout=30.0):
        nonlocal sent_payload
        if args[-3:] == ("command -v tmux >/dev/null 2>&1",):
            return 0, "", ""
        if "has-session" in args:
            return 1, "", "missing"
        if "new-session" in args:
            return 0, "", ""
        if "send-keys" in args and "-l" in args:
            sent_payload = args[-1]
            return 0, "", ""
        if "capture-pane" in args:
            start = re.search(r"__VXIS_START_[0-9a-f]+__", sent_payload).group(0)
            end = re.search(r"__VXIS_DONE_[0-9a-f]+__", sent_payload).group(0)
            return 0, f"{start}\n/opt/app\n{end}:0\n", ""
        return 0, "", ""

    with patch("vxis.agent.tools.shell_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.shell_tools._run_docker", side_effect=fake_run_docker):
        tool = ShellExecTool(sandbox_key="scan-123")
        result = await tool.run(command="cd /opt/app && pwd", session="main")

    assert result.ok is True
    assert result.data["exit_code"] == 0
    assert result.data["session"] == "main"
    assert result.data["stdout"] == "/opt/app"
    assert "shell_exec[main]" in result.summary


@pytest.mark.asyncio
async def test_shell_exec_tool_captures_nonzero_exit_as_failing_result():
    async def fake_ensure(**kwargs):
        return True, "ok"

    fake_proc = MagicMock()
    fake_proc.returncode = 1
    fake_proc.communicate = AsyncMock(return_value=(b"", b"command not found\n"))

    with patch("vxis.agent.tools.shell_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.shell_tools._execute_via_tool_server", AsyncMock(return_value=None)), \
         patch("asyncio.create_subprocess_exec", return_value=fake_proc):
        tool = ShellExecTool()
        result = await tool.run(command="nonexistent_command")

    assert result.ok is False
    assert result.data["exit_code"] == 1
    assert "command not found" in result.data["stderr"]


@pytest.mark.asyncio
async def test_shell_exec_tool_timeout_handling():
    async def fake_ensure(**kwargs):
        return True, "ok"

    fake_proc = MagicMock()
    fake_proc.kill = MagicMock()
    fake_proc.wait = AsyncMock()

    async def hang(*a, **kw):
        import asyncio as _asyncio
        await _asyncio.sleep(10)
        return (b"", b"")

    fake_proc.communicate = hang  # type: ignore[method-assign]

    with patch("vxis.agent.tools.shell_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.shell_tools._execute_via_tool_server", AsyncMock(return_value=None)), \
         patch("asyncio.create_subprocess_exec", return_value=fake_proc):
        tool = ShellExecTool()
        result = await tool.run(command="sleep 100", timeout=0.1)

    assert result.ok is False
    assert "timed out" in result.summary.lower()
    assert result.error == "timeout"


def test_build_default_registry_now_has_seven_tools():
    from vxis.agent.tools import build_default_registry
    reg = build_default_registry()
    names = reg.list_tools()
    assert "shell_exec" in names
    assert len(names) >= 7
