import pytest
import re
from unittest.mock import AsyncMock, patch

from vxis.agent.tool_registry import BrainTool
from vxis.agent.tools.python_tools import PythonExecTool
from vxis.agent.tools.shell_tools import _reset_for_tests, resolve_sandbox_runtime


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

    command_result = {
        "exit_code": 0,
        "stdout": "hello\n",
        "stderr": "",
        "timeout": False,
        "transport": "tool_server",
    }

    with patch("vxis.agent.tools.python_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.python_tools.run_sandbox_shell_command", AsyncMock(return_value=command_result)) as mock_run:
        tool = PythonExecTool(sandbox_key="scan-123", workspace_host=str(tmp_path))
        code = "import sys\nprint('hello')\nsys.exit(0)"
        result = await tool.run(code=code)

    assert result.ok is True
    assert result.data["exit_code"] == 0
    assert "hello" in result.data["stdout"]

    runtime = resolve_sandbox_runtime("scan-123", workspace_host=str(tmp_path))
    call_args = mock_run.await_args.args
    assert call_args[0] == runtime
    assert call_args[1].startswith("python3 /workspace/_python_exec_")
    assert call_args[1].endswith(".py")
    assert call_args[2] == 120.0
    assert result.data["container"] == runtime.container
    assert result.data["transport"] == "tool_server"


@pytest.mark.asyncio
async def test_python_exec_session_uses_tmux_repl_and_returns_marked_output(tmp_path):
    async def fake_ensure(**kwargs):
        return True, "ok"

    sent_payload = ""

    async def fake_run_docker(*args, timeout=30.0):
        nonlocal sent_payload
        if "has-session" in args:
            return 1, "", "missing"
        if "new-session" in args:
            assert args[-1] == "python3 -q -i"
            return 0, "", ""
        if "send-keys" in args and "-l" in args:
            sent_payload = args[-1]
            assert "answer = 41" in sent_payload
            return 0, "", ""
        if "capture-pane" in args:
            start = re.search(r"__VXIS_PY_START_[0-9a-f]+__", sent_payload).group(0)
            end = re.search(r"__VXIS_PY_DONE_[0-9a-f]+__", sent_payload).group(0)
            return 0, f"{start}\n42\n{end}:0\n", ""
        return 0, "", ""

    with patch("vxis.agent.tools.python_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.shell_tools._run_docker", side_effect=fake_run_docker):
        tool = PythonExecTool(sandbox_key="scan-123", workspace_host=str(tmp_path))
        result = await tool.run(code="answer = 41\nprint(answer + 1)", session="py")

    assert result.ok is True
    assert result.data["exit_code"] == 0
    assert result.data["session"] == "py"
    assert result.data["stdout"] == "42"
    assert "python_exec[py]" in result.summary


@pytest.mark.asyncio
async def test_python_exec_tool_cleanup_on_success(tmp_path):
    async def fake_ensure(**kwargs):
        return True, "ok"

    with patch("vxis.agent.tools.python_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.python_tools.run_sandbox_shell_command", AsyncMock(return_value={
             "exit_code": 0,
             "stdout": "",
             "stderr": "",
             "timeout": False,
             "transport": "tool_server",
         })):
        tool = PythonExecTool(workspace_host=str(tmp_path))
        await tool.run(code="print('hi')")

    leftovers = list(tmp_path.glob("_python_exec_*.py"))
    assert len(leftovers) == 0, f"Expected no leftover scripts, found: {leftovers}"


@pytest.mark.asyncio
async def test_python_exec_tool_cleanup_on_subprocess_error(tmp_path):
    async def fake_ensure(**kwargs):
        return True, "ok"

    with patch("vxis.agent.tools.python_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.python_tools.run_sandbox_shell_command", side_effect=OSError("docker not found")):
        tool = PythonExecTool(workspace_host=str(tmp_path))
        result = await tool.run(code="print('hi')")

    assert result.ok is False
    assert "docker not found" in result.summary
    leftovers = list(tmp_path.glob("_python_exec_*.py"))
    assert len(leftovers) == 0


@pytest.mark.asyncio
async def test_python_exec_tool_captures_stderr_and_nonzero_exit(tmp_path):
    async def fake_ensure(**kwargs):
        return True, "ok"

    with patch("vxis.agent.tools.python_tools._ensure_sandbox_running", side_effect=fake_ensure), \
         patch("vxis.agent.tools.python_tools.run_sandbox_shell_command", AsyncMock(return_value={
             "exit_code": 1,
             "stdout": "",
             "stderr": "Traceback:\nNameError: foo\n",
             "timeout": False,
             "transport": "tool_server",
         })):
        tool = PythonExecTool(workspace_host=str(tmp_path))
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
    assert len(names) >= 8
