"""Shell execution tool — Strix terminal equivalent inside a VXIS sandbox container.

Gives the Brain unrestricted shell access inside an isolated Debian environment
with pentest tools pre-installed (sqlmap, nuclei, ffuf, nikto, gobuster, wapiti,
curl, python3, httpx, etc.).

Lifecycle: a per-scan sandbox container is started lazily on first tool call.
Each shell_exec invocation becomes `docker exec <scan-container> sh -c '<command>'`.

Security note: this tool is UNRESTRICTED by design. It can bypass the
Hands-layer deferred mutation queue because tools like sqlmap make their own
HTTP requests. For Phase A (local Docker targets) this is intentional — see
the pivot note in the plan doc. For Phase C enterprise scans, a second-layer
sandbox egress filter will be added.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import secrets
import socket
import shutil
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

from vxis.agent.egress_policy import blocked_policy_data, evaluate_shell_egress
from vxis.agent.tool_registry import ToolResult
from vxis.ghost.routing import wrap_shell_command_for_ghost

logger = logging.getLogger(__name__)

SANDBOX_IMAGE = "vxis/sandbox:latest"
SANDBOX_CONTAINER = "vxis-sandbox"
SANDBOX_WORKSPACE_ROOT = "/tmp/vxis-workspaces"
SANDBOX_WORKSPACE_HOST = "/tmp/vxis-workspace"  # legacy single-sandbox path
SANDBOX_WORKSPACE_MOUNT = "/workspace"
DEFAULT_TIMEOUT = 300.0  # 5 min — nuclei scans against medium targets need ~4 min
TMUX_CAPTURE_LINES = "4000"

# Module-level state (idempotent lifecycle cache)
_sandbox_verified: set[str] = set()
_tool_servers: dict[str, "ToolServerState"] = {}
_tool_server_disabled: set[str] = set()


@dataclass(frozen=True)
class SandboxRuntime:
    key: str
    container: str
    workspace_host: str
    workspace_mount: str = SANDBOX_WORKSPACE_MOUNT


@dataclass
class ToolServerState:
    port: int
    token: str


def _reset_for_tests() -> None:
    """Reset module-level state. Called from test fixtures, NOT from production."""
    _sandbox_verified.clear()
    _tool_servers.clear()
    _tool_server_disabled.clear()


def _sanitize_sandbox_key(raw: str | None) -> str:
    text = str(raw or os.environ.get("VXIS_SCAN_ID") or "default").strip()
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", text).strip(".-").lower()
    return slug[:36] or "default"


def _sandbox_suffix(raw: str | None) -> str:
    return hashlib.sha1(str(raw or "default").encode("utf-8")).hexdigest()[:10]


def resolve_sandbox_runtime(
    sandbox_key: str | None = None,
    workspace_host: str | None = None,
) -> SandboxRuntime:
    """Resolve the per-scan Docker runtime names without touching Docker."""
    clean_key = _sanitize_sandbox_key(sandbox_key)
    suffix = _sandbox_suffix(sandbox_key or clean_key)
    container = f"{SANDBOX_CONTAINER}-{clean_key}-{suffix}"
    host_path = workspace_host
    if host_path is None:
        root = os.environ.get("VXIS_SANDBOX_WORKSPACE_ROOT", SANDBOX_WORKSPACE_ROOT)
        host_path = os.path.join(root, f"{clean_key}-{suffix}")
    return SandboxRuntime(
        key=clean_key,
        container=container,
        workspace_host=host_path,
    )


def sanitize_session_name(prefix: str, raw: str | None) -> str:
    """Build a tmux-safe session name from local-model input."""
    text = str(raw or "default").strip()
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", text).strip(".-").lower()
    return f"vxis-{prefix}-{(slug or 'default')[:40]}"


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


def _pick_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _tool_server_request(
    state: ToolServerState,
    path: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    body = None
    headers = {"Authorization": f"Bearer {state.token}"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urlrequest.Request(
        f"http://127.0.0.1:{state.port}{path}",
        data=body,
        headers=headers,
        method="POST" if payload is not None else "GET",
    )
    with urlrequest.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - localhost sandbox API
        data = resp.read().decode("utf-8", "replace")
    parsed = json.loads(data or "{}")
    return parsed if isinstance(parsed, dict) else {}


async def _tool_server_healthy(state: ToolServerState) -> bool:
    try:
        payload = await asyncio.to_thread(_tool_server_request, state, "/health", None, 2.0)
        return bool(payload.get("ok"))
    except Exception:
        return False


async def _ensure_tool_server(runtime: SandboxRuntime) -> ToolServerState | None:
    if os.environ.get("VXIS_SANDBOX_TOOL_SERVER_DISABLE") == "1":
        return None
    if runtime.container in _tool_server_disabled:
        return None

    cached = _tool_servers.get(runtime.container)
    if cached is not None and await _tool_server_healthy(cached):
        return cached

    state = ToolServerState(port=_pick_local_port(), token=secrets.token_urlsafe(24))
    rc, _out, err = await _run_docker(
        "exec", "-d",
        runtime.container,
        "python3",
        "/usr/local/bin/vxis-tool-server",
        "--host", "127.0.0.1",
        "--port", str(state.port),
        "--token", state.token,
    )
    if rc != 0:
        logger.info("sandbox tool server unavailable: %s", err[:300])
        _tool_server_disabled.add(runtime.container)
        return None

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if await _tool_server_healthy(state):
            _tool_servers[runtime.container] = state
            return state
        await asyncio.sleep(0.1)

    logger.info("sandbox tool server health check timed out on port %d", state.port)
    _tool_server_disabled.add(runtime.container)
    return None


async def _execute_via_tool_server(
    runtime: SandboxRuntime,
    command: str,
    timeout: float,
) -> dict[str, Any] | None:
    state = await _ensure_tool_server(runtime)
    if state is None:
        return None
    try:
        payload = await asyncio.to_thread(
            _tool_server_request,
            state,
            "/execute",
            {"command": command, "timeout": timeout, "cwd": runtime.workspace_mount},
            max(5.0, timeout + 5.0),
        )
    except (TimeoutError, urlerror.URLError, OSError, json.JSONDecodeError) as exc:
        logger.info("sandbox tool server execute failed; falling back to docker exec: %s", exc)
        return None
    payload["transport"] = "tool_server"
    return payload


async def _execute_via_docker_exec(
    runtime: SandboxRuntime,
    command: str,
    timeout: float,
) -> dict[str, Any]:
    proc = await asyncio.create_subprocess_exec(
        "docker", "exec", runtime.container, "sh", "-c", command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {
            "ok": False,
            "exit_code": 124,
            "stdout": "",
            "stderr": "",
            "timeout": True,
            "transport": "docker_exec",
        }
    stdout = stdout_b.decode("utf-8", "replace")
    stderr = stderr_b.decode("utf-8", "replace")
    exit_code = proc.returncode or 0
    return {
        "ok": exit_code == 0,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "timeout": False,
        "transport": "docker_exec",
    }


async def run_sandbox_shell_command(
    runtime: SandboxRuntime,
    command: str,
    timeout: float,
    *,
    component: str = "sandbox_shell",
) -> dict[str, Any]:
    effective_command, ghost_meta = wrap_shell_command_for_ghost(
        command,
        component=component,
    )
    result = await _execute_via_tool_server(runtime, effective_command, timeout)
    if result is not None:
        if ghost_meta.get("active"):
            result["ghost"] = ghost_meta
        return result
    result = await _execute_via_docker_exec(runtime, effective_command, timeout)
    if ghost_meta.get("active"):
        result["ghost"] = ghost_meta
    return result


async def _ensure_tmux_session(
    runtime: SandboxRuntime,
    session_name: str,
    command: str | None = None,
) -> tuple[bool, str]:
    rc, _out, err = await _run_docker(
        "exec", runtime.container, "sh", "-lc", "command -v tmux >/dev/null 2>&1",
    )
    if rc != 0:
        return False, (
            "tmux not installed in sandbox image. Rebuild with: "
            f"docker build -t {SANDBOX_IMAGE} docker/sandbox/"
            + (f" ({err[:200]})" if err else "")
        )

    rc, _out, _err = await _run_docker(
        "exec", runtime.container, "tmux", "has-session", "-t", session_name,
    )
    if rc == 0:
        return True, "session already running"

    args = [
        "exec", runtime.container,
        "tmux", "new-session", "-d",
        "-s", session_name,
        "-c", runtime.workspace_mount,
    ]
    if command:
        args.append(command)
    rc, _out, err = await _run_docker(*args)
    if rc != 0:
        return False, f"tmux new-session failed (rc={rc}): {err[:500]}"
    return True, "session started"


async def _capture_tmux_pane(runtime: SandboxRuntime, session_name: str) -> str:
    rc, out, err = await _run_docker(
        "exec", runtime.container,
        "tmux", "capture-pane", "-p",
        "-t", session_name,
        "-S", f"-{TMUX_CAPTURE_LINES}",
    )
    if rc != 0:
        raise RuntimeError(f"tmux capture-pane failed: {err[:300]}")
    return out


async def send_tmux_payload_and_wait(
    runtime: SandboxRuntime,
    session_name: str,
    payload: str,
    start_marker: str,
    end_marker: str,
    timeout: float,
) -> tuple[int, str, bool]:
    await _run_docker("exec", runtime.container, "tmux", "send-keys", "-l", "-t", session_name, payload)
    await _run_docker("exec", runtime.container, "tmux", "send-keys", "-t", session_name, "C-m")

    deadline = time.monotonic() + timeout
    pane = ""
    while time.monotonic() < deadline:
        pane = await _capture_tmux_pane(runtime, session_name)
        parsed = _extract_marked_output(pane, start_marker, end_marker)
        if parsed is not None:
            exit_code, output = parsed
            return exit_code, output, False
        await asyncio.sleep(0.1)

    await _run_docker("exec", runtime.container, "tmux", "send-keys", "-t", session_name, "C-c")
    pane = pane or await _capture_tmux_pane(runtime, session_name)
    parsed = _extract_marked_output(pane, start_marker, end_marker)
    if parsed is not None:
        exit_code, output = parsed
        return exit_code, output, True
    return -1, pane, True


def _extract_marked_output(
    pane: str,
    start_marker: str,
    end_marker: str,
) -> tuple[int, str] | None:
    start_idx = pane.rfind(start_marker)
    if start_idx < 0:
        return None
    end_match = re.search(rf"{re.escape(end_marker)}:(-?\d+)", pane[start_idx:])
    if not end_match:
        return None
    output_start = start_idx + len(start_marker)
    output_end = start_idx + end_match.start()
    output = pane[output_start:output_end].strip("\r\n")
    return int(end_match.group(1)), output


async def _run_shell_session_command(
    runtime: SandboxRuntime,
    session: str,
    command: str,
    timeout: float,
) -> tuple[int, str, str, bool]:
    session_name = sanitize_session_name("sh", session)
    ok, msg = await _ensure_tmux_session(runtime, session_name)
    if not ok:
        return -1, "", msg, False

    marker_id = uuid.uuid4().hex
    start_marker = f"__VXIS_START_{marker_id}__"
    end_marker = f"__VXIS_DONE_{marker_id}__"
    payload = (
        f"printf '\\n{start_marker}\\n'\n"
        f"{command}\n"
        "__vxis_rc=$?\n"
        f"printf '\\n{end_marker}:%s\\n' \"$__vxis_rc\""
    )
    exit_code, stdout, timed_out = await send_tmux_payload_and_wait(
        runtime,
        session_name,
        payload,
        start_marker,
        end_marker,
        timeout,
    )
    return exit_code, stdout, "", timed_out


async def _image_exists(image: str) -> bool:
    rc, out, _ = await _run_docker("image", "inspect", image)
    return rc == 0


async def _container_running(name: str) -> bool:
    rc, out, _ = await _run_docker("ps", "--filter", f"name=^{name}$", "--format", "{{.Names}}")
    return rc == 0 and name in out


async def _container_exists(name: str) -> bool:
    rc, out, _ = await _run_docker("ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}")
    return rc == 0 and name in out


async def _ensure_sandbox_running(
    sandbox_key: str | None = None,
    workspace_host: str | None = None,
) -> tuple[bool, str]:
    """Idempotently ensure the per-scan VXIS sandbox is built and running.

    Returns (ok, message). When ok=False, the message describes the problem in
    a way that's safe to surface back to the Brain as a tool error.
    """
    if not _docker_available():
        return False, "docker CLI not found on host PATH"

    runtime = resolve_sandbox_runtime(sandbox_key, workspace_host)

    if runtime.container in _sandbox_verified:
        # Fast path — previously verified in this process. Still re-check the
        # container state in case it was stopped externally.
        if await _container_running(runtime.container):
            return True, "sandbox already running"
        # Fall through to the slow path to restart.
        _sandbox_verified.discard(runtime.container)

    if not await _image_exists(SANDBOX_IMAGE):
        return False, (
            f"vxis-sandbox image not built. Build it with: "
            f"docker build -t {SANDBOX_IMAGE} docker/sandbox/"
        )

    if await _container_running(runtime.container):
        _sandbox_verified.add(runtime.container)
        return True, "sandbox already running"

    # Container may exist but be stopped; remove and recreate for a clean slate.
    if await _container_exists(runtime.container):
        await _run_docker("rm", "-f", runtime.container)

    # Ensure workspace dir exists on host
    os.makedirs(runtime.workspace_host, exist_ok=True)

    rc, _out, err = await _run_docker(
        "run", "-d",
        "--name", runtime.container,
        "--network", "host",
        "--label", "vxis.managed=true",
        "--label", f"vxis.sandbox_key={runtime.key}",
        "-v", f"{runtime.workspace_host}:{runtime.workspace_mount}",
        SANDBOX_IMAGE,
    )
    if rc != 0:
        return False, f"docker run failed (rc={rc}): {err[:500]}"

    _sandbox_verified.add(runtime.container)
    return True, "sandbox started"


async def cleanup_sandbox_runtime(sandbox_key: str | None = None) -> None:
    """Remove the per-scan sandbox container if it exists."""
    runtime = resolve_sandbox_runtime(sandbox_key)
    if not _docker_available():
        return
    if await _container_exists(runtime.container):
        await _run_docker("rm", "-f", runtime.container)
    _sandbox_verified.discard(runtime.container)
    _tool_servers.pop(runtime.container, None)
    _tool_server_disabled.discard(runtime.container)


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
            "session": {
                "type": "string",
                "description": (
                    "Optional persistent shell session name. Reusing the same "
                    "session preserves cwd, exported env vars, shell functions, "
                    "and background jobs within this scan."
                ),
            },
            "timeout": {"type": "number", "minimum": 1, "maximum": 600, "description": "Timeout in seconds (default 120, max 600)"},
        },
        "required": ["command"],
    }

    def __init__(
        self,
        sandbox_key: str | None = None,
        workspace_host: str | None = None,
    ) -> None:
        self._sandbox_key = sandbox_key
        self._workspace_host = workspace_host

    async def run(self, **kwargs: Any) -> ToolResult:
        command = kwargs.get("command", "")
        if not command:
            return ToolResult(ok=False, summary="shell_exec: command is required", error="missing_command")

        policy_decision = evaluate_shell_egress(str(command))
        if not policy_decision.allowed:
            return ToolResult(
                ok=False,
                data=blocked_policy_data(
                    tool_name="shell_exec",
                    decision=policy_decision,
                    command=str(command),
                ),
                summary=f"shell_exec BLOCKED by Ghost egress policy: {policy_decision.reason}",
                error="direct_egress_blocked",
            )

        try:
            timeout = float(kwargs.get("timeout", DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT
        timeout = max(1.0, min(600.0, timeout))

        runtime = resolve_sandbox_runtime(self._sandbox_key, self._workspace_host)
        session = str(kwargs.get("session", "") or "").strip()
        ok, msg = await _ensure_sandbox_running(
            sandbox_key=self._sandbox_key,
            workspace_host=self._workspace_host,
        )
        if not ok:
            return ToolResult(ok=False, summary=f"shell_exec: {msg}", error="sandbox_unavailable")

        if session:
            effective_command, ghost_meta = wrap_shell_command_for_ghost(
                command,
                component="shell_exec",
            )
            try:
                exit_code, stdout, stderr, timed_out = await _run_shell_session_command(
                    runtime,
                    session,
                    effective_command,
                    timeout,
                )
            except Exception as e:
                return ToolResult(
                    ok=False,
                    summary=f"shell_exec session failed: {type(e).__name__}: {e}",
                    error=str(e),
                )
            if exit_code == -1 and stderr:
                return ToolResult(
                    ok=False,
                    data={
                        "command": command[:200],
                        "session": session,
                        "container": runtime.container,
                        "workspace": runtime.workspace_host,
                        "ghost": ghost_meta,
                    },
                    summary=f"shell_exec session: {stderr}",
                    error="session_unavailable",
                )
            if timed_out:
                return ToolResult(
                    ok=False,
                    data={
                        "command": command[:200],
                        "timeout": timeout,
                        "session": session,
                        "container": runtime.container,
                        "workspace": runtime.workspace_host,
                        "stdout": stdout[:5000],
                        "ghost": ghost_meta,
                    },
                    summary=f"shell_exec session timed out after {timeout}s",
                    error="timeout",
                )
            return ToolResult(
                ok=(exit_code == 0),
                data={
                    "exit_code": exit_code,
                    "stdout": stdout[:5000],
                    "stderr": stderr[:2000],
                    "command": command[:200],
                    "session": session,
                    "container": runtime.container,
                    "workspace": runtime.workspace_host,
                    "stdout_truncated": len(stdout) > 5000,
                    "stderr_truncated": len(stderr) > 2000,
                    "ghost": ghost_meta,
                },
                summary=(
                    f"shell_exec[{session}]: exit={exit_code}, "
                    f"stdout={len(stdout)}b, stderr={len(stderr)}b"
                ),
            )

        try:
            command_result = await run_sandbox_shell_command(
                runtime,
                command,
                timeout,
                component="shell_exec",
            )
        except Exception as e:
            return ToolResult(
                ok=False,
                summary=f"shell_exec failed: {type(e).__name__}: {e}",
                error=str(e),
            )

        exit_code = int(command_result.get("exit_code", 0))
        stdout = str(command_result.get("stdout", ""))
        stderr = str(command_result.get("stderr", ""))
        if command_result.get("timeout"):
            return ToolResult(
                ok=False,
                data={
                    "command": command[:200],
                    "timeout": timeout,
                    "container": runtime.container,
                    "workspace": runtime.workspace_host,
                    "transport": command_result.get("transport", ""),
                    "stdout": stdout[:5000],
                    "stderr": stderr[:2000],
                    "ghost": command_result.get("ghost") or {},
                },
                summary=f"shell_exec timed out after {timeout}s",
                error="timeout",
            )

        return ToolResult(
            ok=(exit_code == 0),
            data={
                "exit_code": exit_code,
                "stdout": stdout[:5000],
                "stderr": stderr[:2000],
                "command": command[:200],
                "container": runtime.container,
                "workspace": runtime.workspace_host,
                "transport": command_result.get("transport", ""),
                "stdout_truncated": len(stdout) > 5000,
                "stderr_truncated": len(stderr) > 2000,
                "ghost": command_result.get("ghost") or {},
            },
            summary=f"shell_exec: exit={exit_code}, stdout={len(stdout)}b, stderr={len(stderr)}b",
        )

    async def cleanup(self) -> None:
        await cleanup_sandbox_runtime(self._sandbox_key)
