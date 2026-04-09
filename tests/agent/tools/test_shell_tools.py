import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from vxis.agent.tool_registry import BrainTool, ToolResult
from vxis.agent.tools.shell_tools import (
    ShellExecTool,
    _reset_for_tests,
    SANDBOX_IMAGE,
    SANDBOX_CONTAINER,
)


@pytest.fixture(autouse=True)
def reset_state():
    _reset_for_tests()
    yield
    _reset_for_tests()


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
async def test_shell_exec_tool_runs_command_via_docker_exec_when_sandbox_ready():
    """When sandbox is ready, shell_exec invokes docker exec vxis-sandbox sh -c <cmd>."""
    async def fake_ensure(**kwargs):
        return True, "sandbox already running"

    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.communicate = AsyncMock(return_value=(b"hello world\n", b""))

    with patch("vxis.agent.tools.shell_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("asyncio.create_subprocess_exec", return_value=fake_proc) as mock_exec:
        tool = ShellExecTool()
        result = await tool.run(command="echo hello world")

    assert result.ok is True
    assert result.data["exit_code"] == 0
    assert "hello world" in result.data["stdout"]
    # Verify the docker exec invocation
    call_args = mock_exec.call_args.args
    assert call_args[0] == "docker"
    assert call_args[1] == "exec"
    assert call_args[2] == SANDBOX_CONTAINER
    assert call_args[3] == "sh"
    assert call_args[4] == "-c"
    assert call_args[5] == "echo hello world"


@pytest.mark.asyncio
async def test_shell_exec_tool_captures_nonzero_exit_as_failing_result():
    async def fake_ensure(**kwargs):
        return True, "ok"

    fake_proc = MagicMock()
    fake_proc.returncode = 1
    fake_proc.communicate = AsyncMock(return_value=(b"", b"command not found\n"))

    with patch("vxis.agent.tools.shell_tools._ensure_sandbox_running", side_effect=fake_ensure), \
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
