"""Python execution tool — Strix python equivalent inside the vxis-sandbox Docker container.

Accepts raw Python source code, writes it to a temp file in the shared /workspace
volume (mounted at SANDBOX_WORKSPACE_HOST on the host), then runs:
    docker exec vxis-sandbox python3 /workspace/_python_exec_<uuid>.py

Use for:
- Multi-line scripts with nested quotes that are painful as shell -c one-liners
- asyncio/aiohttp payload sprays (hundreds of parallel requests)
- Custom PoC scripts that persist state between tool calls (write to /workspace/*.json)
- Post-exploitation automation that needs real Python control flow

The vxis-sandbox container is shared with shell_exec. Lifecycle is managed by
shell_tools._ensure_sandbox_running(). No separate container is started here.
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from pathlib import Path
from typing import Any

from vxis.agent.tool_registry import ToolResult
from vxis.agent.tools.shell_tools import (
    SANDBOX_CONTAINER,
    SANDBOX_WORKSPACE_HOST,
    SANDBOX_WORKSPACE_MOUNT,
    _ensure_sandbox_running,
)

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120.0
MAX_TIMEOUT = 600.0


class PythonExecTool:
    name = "python_exec"
    description = (
        "Execute a multi-line Python 3 script inside the isolated vxis-sandbox "
        "Docker container. Use for asyncio/aiohttp payload sprays, custom PoC "
        "scripts, or any Python work that's awkward as a shell one-liner. The "
        "script runs from /workspace/ with httpx/aiohttp/requests pre-installed. "
        "Write output to /workspace/*.json or similar to persist state across calls."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "code": {"type": "string", "description": "Python 3 source code to execute"},
            "timeout": {
                "type": "number",
                "minimum": 1,
                "maximum": MAX_TIMEOUT,
                "description": f"Timeout in seconds (default {int(DEFAULT_TIMEOUT)}, max {int(MAX_TIMEOUT)})",
            },
        },
        "required": ["code"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        code = kwargs.get("code", "")
        if not code:
            return ToolResult(ok=False, summary="python_exec: code is required", error="missing_code")

        try:
            timeout = float(kwargs.get("timeout", DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT
        timeout = max(1.0, min(MAX_TIMEOUT, timeout))

        ok, msg = await _ensure_sandbox_running()
        if not ok:
            return ToolResult(ok=False, summary=f"python_exec: {msg}", error="sandbox_unavailable")

        script_id = uuid.uuid4().hex[:12]
        host_script_path = Path(SANDBOX_WORKSPACE_HOST) / f"_python_exec_{script_id}.py"
        container_script_path = f"{SANDBOX_WORKSPACE_MOUNT}/_python_exec_{script_id}.py"

        try:
            os.makedirs(SANDBOX_WORKSPACE_HOST, exist_ok=True)
            host_script_path.write_text(code, encoding="utf-8")
        except OSError as e:
            return ToolResult(
                ok=False,
                summary=f"python_exec: failed to write script: {e}",
                error="script_write_failed",
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", SANDBOX_CONTAINER, "python3", container_script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return ToolResult(
                    ok=False,
                    data={"timeout": timeout, "script_id": script_id},
                    summary=f"python_exec timed out after {timeout}s",
                    error="timeout",
                )
        except Exception as e:
            return ToolResult(
                ok=False,
                summary=f"python_exec failed: {type(e).__name__}: {e}",
                error=str(e),
            )
        finally:
            try:
                host_script_path.unlink(missing_ok=True)
            except OSError:
                pass

        exit_code = proc.returncode or 0
        stdout = stdout_b.decode("utf-8", "replace")
        stderr = stderr_b.decode("utf-8", "replace")

        return ToolResult(
            ok=(exit_code == 0),
            data={
                "exit_code": exit_code,
                "stdout": stdout[:5000],
                "stderr": stderr[:2000],
                "script_id": script_id,
                "stdout_truncated": len(stdout) > 5000,
                "stderr_truncated": len(stderr) > 2000,
            },
            summary=f"python_exec: exit={exit_code}, stdout={len(stdout)}b, stderr={len(stderr)}b",
        )
