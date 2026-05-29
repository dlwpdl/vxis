from __future__ import annotations

import ast
import os
import re
from dataclasses import asdict, dataclass
from typing import Any

from vxis.ghost.layer import ghost_layer


_RAW_SHELL_RE = re.compile(
    r"(?:^|[;&|()\n]\s*)"
    r"(?:sudo\s+|command\s+|timeout\s+\S+\s+|env\s+(?:\S+=\S+\s+)*)?"
    r"(?P<tool>nmap|masscan|hping3?|nping|nc|netcat|ncat|socat|dig|nslookup|host|"
    r"ping|traceroute|tracepath|telnet)\b",
    re.IGNORECASE,
)
_RAW_PYTHON_IMPORT_ROOTS = {"socket", "subprocess", "scapy"}
_RAW_PYTHON_IMPORT_MODULES = {"asyncio.subprocess", "dns.resolver"}
_RAW_PYTHON_CALLS = {
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "socket.socket",
    "socket.create_connection",
    "socket.getaddrinfo",
    "socket.gethostbyname",
    "socket.gethostbyname_ex",
}


@dataclass(frozen=True)
class EgressPolicyDecision:
    allowed: bool
    reason: str = ""
    match: str = ""
    mode: str = ""
    override_env: str = "VXIS_ALLOW_DIRECT_EGRESS"
    alternative: str = ""

    def compact(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value not in ("", None)}


def direct_egress_allowed() -> bool:
    return _truthy_env("VXIS_ALLOW_DIRECT_EGRESS") or _truthy_env("VXIS_ALLOW_GHOST_DIRECT_EGRESS")


def enforce_direct_tool_policy(tool_name: str, *, mode: str, alternative: str) -> EgressPolicyDecision:
    if not ghost_layer.is_active() or direct_egress_allowed():
        return EgressPolicyDecision(allowed=True, mode=mode)
    return EgressPolicyDecision(
        allowed=False,
        reason=f"{tool_name} uses {mode}, which bypasses Ghost proxy routing",
        mode=mode,
        alternative=alternative,
    )


def evaluate_shell_egress(command: str) -> EgressPolicyDecision:
    if not ghost_layer.is_active() or direct_egress_allowed():
        return EgressPolicyDecision(allowed=True, mode="env_proxy")
    match = _RAW_SHELL_RE.search(command)
    if not match:
        return EgressPolicyDecision(allowed=True, mode="env_proxy")
    tool = match.group("tool")
    return EgressPolicyDecision(
        allowed=False,
        reason=f"shell_exec command invokes raw egress tool '{tool}' while Ghost is active",
        match=tool,
        mode="raw_shell_command",
        alternative="Use http_request/browser tools or proxy-aware curl/httpx/sqlmap; set VXIS_ALLOW_DIRECT_EGRESS=1 for explicit opt-in.",
    )


def evaluate_python_egress(code: str) -> EgressPolicyDecision:
    if not ghost_layer.is_active() or direct_egress_allowed():
        return EgressPolicyDecision(allowed=True, mode="env_proxy")
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return EgressPolicyDecision(allowed=True, mode="env_proxy")
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                root = name.split(".", 1)[0]
                if root in _RAW_PYTHON_IMPORT_ROOTS or name in _RAW_PYTHON_IMPORT_MODULES:
                    return _blocked_python(name, "raw_python_import")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            root = module.split(".", 1)[0]
            if root in _RAW_PYTHON_IMPORT_ROOTS or module in _RAW_PYTHON_IMPORT_MODULES:
                return _blocked_python(module, "raw_python_import")
        elif isinstance(node, ast.Call):
            dotted = _dotted_name(node.func)
            if dotted in _RAW_PYTHON_CALLS:
                return _blocked_python(dotted, "raw_python_call")
    return EgressPolicyDecision(allowed=True, mode="env_proxy")


def blocked_policy_data(
    *,
    tool_name: str,
    decision: EgressPolicyDecision,
    command: str = "",
) -> dict[str, Any]:
    return {
        "blocked": True,
        "tool": tool_name,
        "command": command[:240],
        "policy": decision.compact(),
        "ghost": {
            "active": ghost_layer.is_active(),
            "direct_egress_allowed": direct_egress_allowed(),
        },
    }


def _blocked_python(match: str, mode: str) -> EgressPolicyDecision:
    return EgressPolicyDecision(
        allowed=False,
        reason=f"python_exec code uses {match!r}, which can bypass Ghost proxy routing",
        match=match,
        mode=mode,
        alternative="Use httpx/requests/aiohttp through proxy env, or set VXIS_ALLOW_DIRECT_EGRESS=1 for explicit opt-in.",
    )


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""
