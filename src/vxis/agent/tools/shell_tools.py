"""Shell execution tool — Strix terminal equivalent inside the vxis-sandbox Docker container.

Gives the Brain unrestricted shell access inside an isolated Debian environment
with pentest tools pre-installed (sqlmap, nuclei, ffuf, nikto, gobuster, wapiti,
curl, python3, httpx, etc.).

Lifecycle: the vxis-sandbox container is started lazily on first tool call and
reused across scans ("warm" per Strix convention). Each shell_exec invocation
becomes `docker exec vxis-sandbox sh -c '<command>'`.

Security note: this tool is UNRESTRICTED by design. It can bypass the
Hands-layer deferred mutation queue because tools like sqlmap make their own
HTTP requests. For Phase A (local Docker targets) this is intentional — see
the pivot note in the plan doc. For Phase C enterprise scans, a second-layer
sandbox egress filter will be added.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
from typing import Any

from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)

SANDBOX_IMAGE = "vxis/sandbox:latest"
SANDBOX_CONTAINER = "vxis-sandbox"
SANDBOX_WORKSPACE_HOST = "/tmp/vxis-workspace"
SANDBOX_WORKSPACE_MOUNT = "/workspace"
DEFAULT_TIMEOUT = 120.0

# Module-level state (idempotent lifecycle cache)
_sandbox_verified: bool = False


def _reset_for_tests() -> None:
    """Reset module-level state. Called from test fixtures, NOT from production."""
    global _sandbox_verified
    _sandbox_verified = False


def _docker_available() -> bool:
    """Check if the docker CLI is on PATH."""
    return shutil.which("docker") is not None


async def _run_docker(*args: str, timeout: float = 30.0) -> tuple[int, str, str]:
    """Run `docker <args>` and capture (exit_code, stdout, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        "docker", *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode or 0, stdout_b.decode("utf-8", "replace"), stderr_b.decode("utf-8", "replace")


async def _image_exists(image: str) -> bool:
    rc, out, _ = await _run_docker("image", "inspect", image)
    return rc == 0


async def _container_running(name: str) -> bool:
    rc, out, _ = await _run_docker("ps", "--filter", f"name=^{name}$", "--format", "{{.Names}}")
    return rc == 0 and name in out


async def _container_exists(name: str) -> bool:
    rc, out, _ = await _run_docker("ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}")
    return rc == 0 and name in out


async def _ensure_sandbox_running() -> tuple[bool, str]:
    """Idempotently ensure vxis-sandbox is built and running.

    Returns (ok, message). When ok=False, the message describes the problem in
    a way that's safe to surface back to the Brain as a tool error.
    """
    global _sandbox_verified

    if not _docker_available():
        return False, "docker CLI not found on host PATH"

    if _sandbox_verified:
        # Fast path — previously verified in this process. Still re-check the
        # container state in case it was stopped externally.
        if await _container_running(SANDBOX_CONTAINER):
            return True, "sandbox already running"
        # Fall through to the slow path to restart.
        _sandbox_verified = False

    if not await _image_exists(SANDBOX_IMAGE):
        return False, (
            f"vxis-sandbox image not built. Build it with: "
            f"docker build -t {SANDBOX_IMAGE} docker/sandbox/"
        )

    if await _container_running(SANDBOX_CONTAINER):
        _sandbox_verified = True
        return True, "sandbox already running"

    # Container may exist but be stopped; remove and recreate for a clean slate.
    if await _container_exists(SANDBOX_CONTAINER):
        await _run_docker("rm", "-f", SANDBOX_CONTAINER)

    # Ensure workspace dir exists on host
    import os
    os.makedirs(SANDBOX_WORKSPACE_HOST, exist_ok=True)

    rc, _out, err = await _run_docker(
        "run", "-d",
        "--name", SANDBOX_CONTAINER,
        "--network", "host",
        "-v", f"{SANDBOX_WORKSPACE_HOST}:{SANDBOX_WORKSPACE_MOUNT}",
        SANDBOX_IMAGE,
    )
    if rc != 0:
        return False, f"docker run failed (rc={rc}): {err[:500]}"

    _sandbox_verified = True
    return True, "sandbox started"


class ShellExecTool:
    name = "shell_exec"
    description = (
        "Execute an arbitrary shell command inside the isolated vxis-sandbox "
        "Docker container (Debian + pentest tools: sqlmap, nuclei, ffuf, nikto, "
        "gobuster, wapiti, curl, python3, httpx, etc.). UNRESTRICTED — use any "
        "shell syntax, redirect to files in /workspace for persistence across "
        "calls. Network: host mode, so targets at localhost are reachable."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "Shell command to execute"},
            "timeout": {"type": "number", "minimum": 1, "maximum": 600, "description": "Timeout in seconds (default 120, max 600)"},
        },
        "required": ["command"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        command = kwargs.get("command", "")
        if not command:
            return ToolResult(ok=False, summary="shell_exec: command is required", error="missing_command")

        try:
            timeout = float(kwargs.get("timeout", DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT
        timeout = max(1.0, min(600.0, timeout))

        ok, msg = await _ensure_sandbox_running()
        if not ok:
            return ToolResult(ok=False, summary=f"shell_exec: {msg}", error="sandbox_unavailable")

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", SANDBOX_CONTAINER, "sh", "-c", command,
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
                    data={"command": command[:200], "timeout": timeout},
                    summary=f"shell_exec timed out after {timeout}s",
                    error="timeout",
                )
        except Exception as e:
            return ToolResult(
                ok=False,
                summary=f"shell_exec failed: {type(e).__name__}: {e}",
                error=str(e),
            )

        exit_code = proc.returncode or 0
        stdout = stdout_b.decode("utf-8", "replace")
        stderr = stderr_b.decode("utf-8", "replace")

        return ToolResult(
            ok=(exit_code == 0),
            data={
                "exit_code": exit_code,
                "stdout": stdout[:5000],
                "stderr": stderr[:2000],
                "command": command[:200],
                "stdout_truncated": len(stdout) > 5000,
                "stderr_truncated": len(stderr) > 2000,
            },
            summary=f"shell_exec: exit={exit_code}, stdout={len(stdout)}b, stderr={len(stderr)}b",
        )
