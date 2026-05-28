"""Python execution tool — Strix python equivalent inside the VXIS sandbox.

Accepts raw Python source code, writes it to a temp file in the shared /workspace
volume for this scan, then runs:
    docker exec <scan-container> python3 /workspace/_python_exec_<uuid>.py

Use for:
- Multi-line scripts with nested quotes that are painful as shell -c one-liners
- asyncio/aiohttp payload sprays (hundreds of parallel requests)
- Custom PoC scripts that persist state between tool calls (write to /workspace/*.json)
- Post-exploitation automation that needs real Python control flow

The vxis-sandbox container is shared with shell_exec. Lifecycle is managed by
shell_tools._ensure_sandbox_running(). No separate container is started here.
"""
from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path
from typing import Any

from vxis.agent.tool_registry import ToolResult
from vxis.agent.tools.shell_tools import (
    _ensure_sandbox_running,
    _ensure_tmux_session,
    cleanup_sandbox_runtime,
    run_sandbox_shell_command,
    resolve_sandbox_runtime,
    sanitize_session_name,
    send_tmux_payload_and_wait,
)
from vxis.ghost.routing import (
    build_ghost_identity,
    ghost_python_env_prelude,
    public_ghost_identity,
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
            "session": {
                "type": "string",
                "description": (
                    "Optional persistent Python REPL session name. Reusing the "
                    "same session preserves imports, variables, functions, and "
                    "client objects within this scan."
                ),
            },
            "timeout": {
                "type": "number",
                "minimum": 1,
                "maximum": MAX_TIMEOUT,
                "description": f"Timeout in seconds (default {int(DEFAULT_TIMEOUT)}, max {int(MAX_TIMEOUT)})",
            },
        },
        "required": ["code"],
    }

    def __init__(
        self,
        sandbox_key: str | None = None,
        workspace_host: str | None = None,
    ) -> None:
        self._sandbox_key = sandbox_key
        self._workspace_host = workspace_host

    async def run(self, **kwargs: Any) -> ToolResult:
        code = kwargs.get("code", "")
        if not code:
            return ToolResult(ok=False, summary="python_exec: code is required", error="missing_code")

        try:
            timeout = float(kwargs.get("timeout", DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT
        timeout = max(1.0, min(MAX_TIMEOUT, timeout))

        runtime = resolve_sandbox_runtime(self._sandbox_key, self._workspace_host)
        ok, msg = await _ensure_sandbox_running(
            sandbox_key=self._sandbox_key,
            workspace_host=self._workspace_host,
        )
        if not ok:
            return ToolResult(ok=False, summary=f"python_exec: {msg}", error="sandbox_unavailable")

        session = str(kwargs.get("session", "") or "").strip()
        if session:
            ghost_identity = build_ghost_identity(
                "python_exec",
                include_raw=True,
            )
            ghost_meta = public_ghost_identity(ghost_identity)
            try:
                exit_code, stdout, timed_out = await _run_python_session_code(
                    runtime,
                    session,
                    code,
                    timeout,
                    ghost_identity=ghost_identity,
                )
            except Exception as e:
                return ToolResult(
                    ok=False,
                    summary=f"python_exec session failed: {type(e).__name__}: {e}",
                    error=str(e),
                )
            if exit_code == -1 and not timed_out:
                return ToolResult(
                    ok=False,
                    data={
                        "session": session,
                        "container": runtime.container,
                        "workspace": runtime.workspace_host,
                        "stdout": stdout[:5000],
                        "ghost": ghost_meta,
                    },
                    summary=f"python_exec session: {stdout[:500]}",
                    error="session_unavailable",
                )
            if timed_out:
                return ToolResult(
                    ok=False,
                    data={
                        "timeout": timeout,
                        "session": session,
                        "container": runtime.container,
                        "workspace": runtime.workspace_host,
                        "stdout": stdout[:5000],
                        "ghost": ghost_meta,
                    },
                    summary=f"python_exec session timed out after {timeout}s",
                    error="timeout",
                )
            return ToolResult(
                ok=(exit_code == 0),
                data={
                    "exit_code": exit_code,
                    "stdout": stdout[:5000],
                    "stderr": "",
                    "session": session,
                    "container": runtime.container,
                    "workspace": runtime.workspace_host,
                    "stdout_truncated": len(stdout) > 5000,
                    "stderr_truncated": False,
                    "ghost": ghost_meta,
                },
                summary=f"python_exec[{session}]: exit={exit_code}, stdout={len(stdout)}b",
            )

        script_id = uuid.uuid4().hex[:12]
        host_script_path = Path(runtime.workspace_host) / f"_python_exec_{script_id}.py"
        container_script_path = f"{runtime.workspace_mount}/_python_exec_{script_id}.py"

        try:
            os.makedirs(runtime.workspace_host, exist_ok=True)
            host_script_path.write_text(code, encoding="utf-8")
        except OSError as e:
            return ToolResult(
                ok=False,
                summary=f"python_exec: failed to write script: {e}",
                error="script_write_failed",
            )

        try:
            command_result = await run_sandbox_shell_command(
                runtime,
                f"python3 {container_script_path}",
                timeout,
                component="python_exec",
            )
            if command_result.get("timeout"):
                return ToolResult(
                    ok=False,
                    data={
                        "timeout": timeout,
                        "script_id": script_id,
                        "container": runtime.container,
                        "workspace": runtime.workspace_host,
                        "transport": command_result.get("transport", ""),
                        "stdout": str(command_result.get("stdout", ""))[:5000],
                        "stderr": str(command_result.get("stderr", ""))[:2000],
                        "ghost": command_result.get("ghost") or {},
                    },
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

        exit_code = int(command_result.get("exit_code", 0))
        stdout = str(command_result.get("stdout", ""))
        stderr = str(command_result.get("stderr", ""))

        return ToolResult(
            ok=(exit_code == 0),
            data={
                "exit_code": exit_code,
                "stdout": stdout[:5000],
                "stderr": stderr[:2000],
                "script_id": script_id,
                "container": runtime.container,
                "workspace": runtime.workspace_host,
                "transport": command_result.get("transport", ""),
                "stdout_truncated": len(stdout) > 5000,
                "stderr_truncated": len(stderr) > 2000,
                "ghost": command_result.get("ghost") or {},
            },
            summary=f"python_exec: exit={exit_code}, stdout={len(stdout)}b, stderr={len(stderr)}b",
        )

    async def cleanup(self) -> None:
        await cleanup_sandbox_runtime(self._sandbox_key)


async def _run_python_session_code(
    runtime: Any,
    session: str,
    code: str,
    timeout: float,
    *,
    ghost_identity: dict[str, Any] | None = None,
) -> tuple[int, str, bool]:
    session_name = sanitize_session_name("py", session)
    ok, msg = await _ensure_tmux_session(runtime, session_name, command="python3 -q -i")
    if not ok:
        return -1, msg, False

    marker_id = uuid.uuid4().hex
    start_marker = f"__VXIS_PY_START_{marker_id}__"
    end_marker = f"__VXIS_PY_DONE_{marker_id}__"
    driver = (
        ghost_python_env_prelude(ghost_identity)
        + "import traceback as __vxis_tb\n"
        f"print({start_marker!r})\n"
        "try:\n"
        f"    exec({code!r}, globals())\n"
        "    __vxis_rc = 0\n"
        "except BaseException:\n"
        "    __vxis_tb.print_exc()\n"
        "    __vxis_rc = 1\n"
        f"print({end_marker!r} + ':' + str(__vxis_rc))\n"
    )
    payload = f"exec({driver!r}, globals())"
    return await send_tmux_payload_and_wait(
        runtime,
        session_name,
        payload,
        start_marker,
        end_marker,
        timeout,
    )
