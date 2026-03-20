"""Unit tests for vxis.core.scanner."""

from __future__ import annotations

import pytest

from vxis.core.scanner import ToolResult, run_tool


class TestRunTool:
    """Tests for the run_tool async function."""

    async def test_successful_command(self) -> None:
        """echo hello should exit 0 and contain 'hello' in stdout."""
        result = await run_tool(["echo", "hello"])

        assert isinstance(result, ToolResult)
        assert result.return_code == 0
        assert "hello" in result.stdout

    async def test_failed_command(self) -> None:
        """'false' should exit with a non-zero return code."""
        result = await run_tool(["false"])

        assert result.return_code != 0

    async def test_timeout_kills_process(self) -> None:
        """A process that exceeds its timeout should raise TimeoutError."""
        with pytest.raises(TimeoutError):
            await run_tool(["sleep", "10"], timeout=1)

    async def test_captures_stderr(self) -> None:
        """stderr output must be captured and available on the result."""
        result = await run_tool(
            ["bash", "-c", "echo error-output >&2; exit 1"],
            shell=False,
        )

        assert "error-output" in result.stderr

    async def test_result_has_elapsed_time(self) -> None:
        """ToolResult.elapsed_seconds must be a non-negative float."""
        result = await run_tool(["echo", "timing"])

        assert isinstance(result.elapsed_seconds, float)
        assert result.elapsed_seconds >= 0.0

    async def test_result_has_command(self) -> None:
        """ToolResult.command must record the executed command."""
        result = await run_tool(["echo", "cmd-label"])

        assert "echo" in result.command
        assert "cmd-label" in result.command
