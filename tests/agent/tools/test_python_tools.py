import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from vxis.agent.tool_registry import BrainTool, ToolResult
from vxis.agent.tools.python_tools import PythonExecTool
from vxis.agent.tools.shell_tools import _reset_for_tests, SANDBOX_CONTAINER


@pytest.fixture(autouse=True)
def reset_state():
    _reset_for_tests()
    yield
    _reset_for_tests()


@pytest.mark.asyncio
async def test_python_exec_tool_conforms_to_brain_tool():
    tool = PythonExecTool()
    assert isinstance(tool, BrainTool)
    assert tool.name == "python_exec"


@pytest.mark.asyncio
async def test_python_exec_tool_missing_code():
    tool = PythonExecTool()
    result = await tool.run()
    assert result.ok is False
    assert "code" in result.summary


@pytest.mark.asyncio
async def test_python_exec_tool_sandbox_unavailable():
    async def fake_ensure(**kwargs):
        return False, "vxis-sandbox image not built"

    with patch("vxis.agent.tools.python_tools._ensure_sandbox_running", side_effect=fake_ensure):
        tool = PythonExecTool()
        result = await tool.run(code="print('hi')")

    assert result.ok is False
    assert "not built" in result.summary.lower()


@pytest.mark.asyncio
async def test_python_exec_tool_writes_script_and_dispatches_docker_exec(tmp_path):
    async def fake_ensure(**kwargs):
        return True, "ok"

    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.communicate = AsyncMock(return_value=(b"hello\n", b""))

    with patch("vxis.agent.tools.python_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.python_tools.SANDBOX_WORKSPACE_HOST", str(tmp_path)), \
         patch("asyncio.create_subprocess_exec", return_value=fake_proc) as mock_exec:
        tool = PythonExecTool()
        code = "import sys\nprint('hello')\nsys.exit(0)"
        result = await tool.run(code=code)

    assert result.ok is True
    assert result.data["exit_code"] == 0
    assert "hello" in result.data["stdout"]

    call_args = mock_exec.call_args.args
    assert call_args[0] == "docker"
    assert call_args[1] == "exec"
    assert call_args[2] == SANDBOX_CONTAINER
    assert call_args[3] == "python3"
    assert call_args[4].startswith("/workspace/_python_exec_")
    assert call_args[4].endswith(".py")


@pytest.mark.asyncio
async def test_python_exec_tool_cleanup_on_success(tmp_path):
    async def fake_ensure(**kwargs):
        return True, "ok"

    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.communicate = AsyncMock(return_value=(b"", b""))

    with patch("vxis.agent.tools.python_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.python_tools.SANDBOX_WORKSPACE_HOST", str(tmp_path)), \
         patch("asyncio.create_subprocess_exec", return_value=fake_proc):
        tool = PythonExecTool()
        await tool.run(code="print('hi')")

    leftovers = list(tmp_path.glob("_python_exec_*.py"))
    assert len(leftovers) == 0, f"Expected no leftover scripts, found: {leftovers}"


@pytest.mark.asyncio
async def test_python_exec_tool_cleanup_on_subprocess_error(tmp_path):
    async def fake_ensure(**kwargs):
        return True, "ok"

    async def raise_subprocess(*args, **kwargs):
        raise OSError("docker not found")

    with patch("vxis.agent.tools.python_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.python_tools.SANDBOX_WORKSPACE_HOST", str(tmp_path)), \
         patch("asyncio.create_subprocess_exec", side_effect=raise_subprocess):
        tool = PythonExecTool()
        result = await tool.run(code="print('hi')")

    assert result.ok is False
    assert "docker not found" in result.summary
    leftovers = list(tmp_path.glob("_python_exec_*.py"))
    assert len(leftovers) == 0


@pytest.mark.asyncio
async def test_python_exec_tool_captures_stderr_and_nonzero_exit(tmp_path):
    async def fake_ensure(**kwargs):
        return True, "ok"

    fake_proc = MagicMock()
    fake_proc.returncode = 1
    fake_proc.communicate = AsyncMock(return_value=(b"", b"Traceback:\nNameError: foo\n"))

    with patch("vxis.agent.tools.python_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.python_tools.SANDBOX_WORKSPACE_HOST", str(tmp_path)), \
         patch("asyncio.create_subprocess_exec", return_value=fake_proc):
        tool = PythonExecTool()
        result = await tool.run(code="print(undefined)")

    assert result.ok is False
    assert result.data["exit_code"] == 1
    assert "NameError" in result.data["stderr"]


def test_build_default_registry_now_has_eight_tools():
    from vxis.agent.tools import build_default_registry
    reg = build_default_registry()
    names = reg.list_tools()
    assert "python_exec" in names
    assert "shell_exec" in names
    assert len(names) == 8
