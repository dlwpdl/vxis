"""Async subprocess runner for external security tools.

Supports two modes:
- Buffered (default): collects all output, returns when process exits
- Streaming: emits lines via callback as they arrive (for real-time TUI)
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

_BUFFER_LIMIT = 10 * 1024 * 1024  # 10 MB

# Callback type for streaming: receives (line: str, is_stderr: bool)
LineCallback = Callable[[str, bool], Awaitable[None]]


@dataclass
class ToolResult:
    """Result of a tool execution."""

    stdout: str
    stderr: str
    return_code: int
    command: str
    elapsed_seconds: float
    lines_emitted: int = 0  # Number of lines streamed (0 if buffered mode)


async def run_tool(
    command: list[str] | str,
    timeout: float = 600,
    shell: bool = False,
    output_file: str | Path | None = None,
    on_line: LineCallback | None = None,
) -> ToolResult:
    """Run an external tool asynchronously and return its result.

    Args:
        command: Command and arguments to execute. A list when shell=False,
                 a string when shell=True.
        timeout: Maximum execution time in seconds. Defaults to 600.
        shell: Whether to run through the shell. Defaults to False.
        output_file: Optional path to write stdout to after completion.
        on_line: Optional async callback invoked for each stdout/stderr line
                 as it arrives. Enables real-time progress display.
                 Signature: async (line: str, is_stderr: bool) -> None

    Returns:
        ToolResult containing stdout, stderr, return code, command string,
        and elapsed time.

    Raises:
        TimeoutError: When the process does not finish within *timeout* seconds.
    """
    if shell:
        cmd_str: str = command if isinstance(command, str) else " ".join(command)
        command_label = cmd_str
        process = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_BUFFER_LIMIT,
        )
    else:
        cmd_list: list[str] = command if isinstance(command, list) else command.split()
        command_label = " ".join(cmd_list)
        process = await asyncio.create_subprocess_exec(
            *cmd_list,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_BUFFER_LIMIT,
        )

    start = time.monotonic()

    if on_line is not None:
        # Streaming mode: read lines as they arrive
        stdout, stderr, lines_emitted = await _stream_output(
            process, timeout, command_label, on_line
        )
    else:
        # Buffered mode: original behavior
        lines_emitted = 0
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
            raise TimeoutError(
                f"Command '{command_label}' timed out after {timeout} second(s)."
            )
        stdout = stdout_bytes.decode(errors="replace")
        stderr = stderr_bytes.decode(errors="replace")

    elapsed = time.monotonic() - start

    if output_file is not None:
        Path(output_file).write_text(stdout, encoding="utf-8")

    return ToolResult(
        stdout=stdout,
        stderr=stderr,
        return_code=process.returncode,  # type: ignore[arg-type]
        command=command_label,
        elapsed_seconds=elapsed,
        lines_emitted=lines_emitted,
    )


async def _stream_output(
    process: asyncio.subprocess.Process,
    timeout: float,
    command_label: str,
    on_line: LineCallback,
) -> tuple[str, str, int]:
    """Read stdout/stderr line by line, invoking callback for each line.

    Returns (stdout_full, stderr_full, lines_emitted).
    """
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    lines_emitted = 0

    async def _read_stream(
        stream: asyncio.StreamReader | None,
        is_stderr: bool,
        accumulator: list[str],
    ) -> None:
        nonlocal lines_emitted
        if stream is None:
            return
        while True:
            try:
                line_bytes = await stream.readline()
            except Exception:
                break
            if not line_bytes:
                break
            line = line_bytes.decode(errors="replace").rstrip("\n\r")
            accumulator.append(line)
            lines_emitted += 1
            try:
                await on_line(line, is_stderr)
            except Exception:
                pass  # Never let callback errors kill the tool

    try:
        await asyncio.wait_for(
            asyncio.gather(
                _read_stream(process.stdout, False, stdout_lines),
                _read_stream(process.stderr, True, stderr_lines),
            ),
            timeout=timeout,
        )
        await process.wait()
    except asyncio.TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        raise TimeoutError(
            f"Command '{command_label}' timed out after {timeout} second(s)."
        )

    return "\n".join(stdout_lines), "\n".join(stderr_lines), lines_emitted
