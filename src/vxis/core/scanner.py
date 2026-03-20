"""Async subprocess runner for external security tools."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from pathlib import Path

_BUFFER_LIMIT = 10 * 1024 * 1024  # 10 MB


@dataclass
class ToolResult:
    """Result of a tool execution."""

    stdout: str
    stderr: str
    return_code: int
    command: str
    elapsed_seconds: float


async def run_tool(
    command: list[str] | str,
    timeout: float = 600,
    shell: bool = False,
    output_file: str | Path | None = None,
) -> ToolResult:
    """Run an external tool asynchronously and return its result.

    Args:
        command: Command and arguments to execute. A list when shell=False,
                 a string when shell=True.
        timeout: Maximum execution time in seconds. Defaults to 600.
        shell: Whether to run through the shell. Defaults to False.
        output_file: Optional path to write stdout to after completion.

    Returns:
        ToolResult containing stdout, stderr, return code, command string,
        and elapsed time.

    Raises:
        TimeoutError: When the process does not finish within *timeout* seconds.
    """
    if shell:
        # command must be a str for shell=True; accept list and join for convenience
        cmd_str: str = command if isinstance(command, str) else " ".join(command)
        command_label = cmd_str
        process = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_BUFFER_LIMIT,
        )
    else:
        # command must be a list for exec variant
        cmd_list: list[str] = command if isinstance(command, list) else command.split()
        command_label = " ".join(cmd_list)
        process = await asyncio.create_subprocess_exec(
            *cmd_list,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=_BUFFER_LIMIT,
        )

    start = time.monotonic()

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        # Ensure the process is terminated before re-raising.
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        raise TimeoutError(
            f"Command '{command_label}' timed out after {timeout} second(s)."
        )

    elapsed = time.monotonic() - start
    stdout = stdout_bytes.decode(errors="replace")
    stderr = stderr_bytes.decode(errors="replace")

    if output_file is not None:
        Path(output_file).write_text(stdout, encoding="utf-8")

    return ToolResult(
        stdout=stdout,
        stderr=stderr,
        return_code=process.returncode,  # type: ignore[arg-type]
        command=command_label,
        elapsed_seconds=elapsed,
    )
