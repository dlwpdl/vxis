from __future__ import annotations

import asyncio
import os
import re
import shlex
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlparse

from vxis.agent.context_budget import trim_text_chars
from vxis.agent.tool_registry import ToolResult
from vxis.agent.tools.shell_tools import ShellExecTool

_TARGET_RE = re.compile(r"^[A-Za-z0-9._:-]+(?:/\d{1,3})?$")
_PORTS_RE = re.compile(r"^[0-9TU:,\-]+$")
_ALLOWED_SCRIPTS = {
    "default",
    "safe",
    "vuln",
    "ssl-enum-ciphers",
    "http-title",
    "http-headers",
    "http-server-header",
    "ssh2-enum-algos",
}
_NMAP_SEMAPHORES: dict[int, tuple[int, asyncio.Semaphore]] = {}


class NmapScanTool:
    name = "nmap_scan"
    description = (
        "Bounded nmap service discovery inside the VXIS sandbox. Use for port/service "
        "mapping before choosing exploit or crown-chain pivots. Returns compact parsed "
        "open ports and service metadata; prefer this over raw shell_exec for nmap."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Hostname, IP, CIDR, or URL; URLs are reduced to hostnames.",
            },
            "ports": {
                "type": "string",
                "description": "Port spec like 80,443, 1-1024, T:80,U:53, top-1000, or all.",
            },
            "scripts": {
                "type": "string",
                "description": "Comma list: default, safe, vuln, ssl-enum-ciphers, http-title, http-headers, http-server-header, ssh2-enum-algos.",
            },
            "udp": {"type": "boolean", "description": "Include UDP scan mode."},
            "timing": {"type": "integer", "minimum": 0, "maximum": 5},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 600},
        },
        "required": ["target"],
    }

    def __init__(self, shell_tool: Any | None = None, sandbox_key: str | None = None) -> None:
        self._shell_tool = shell_tool or ShellExecTool(sandbox_key=sandbox_key)

    async def run(self, **kwargs: Any) -> ToolResult:
        target = _normalize_target(kwargs.get("target"))
        if not target:
            return ToolResult(
                ok=False,
                summary="nmap_scan: target is required",
                error="missing_target",
            )
        if not _TARGET_RE.fullmatch(target):
            return ToolResult(
                ok=False,
                data={"target": target},
                summary="nmap_scan: target contains unsupported characters",
                error="invalid_target",
            )

        command = _build_nmap_command(
            target=target,
            ports=kwargs.get("ports"),
            scripts=kwargs.get("scripts"),
            udp=bool(kwargs.get("udp", False)),
            timing=kwargs.get("timing"),
        )
        timeout = _bounded_int(kwargs.get("timeout"), default=240, minimum=1, maximum=600)
        async with _nmap_semaphore():
            shell_result = await self._shell_tool.run(command=command, timeout=timeout)
        stdout = str((shell_result.data or {}).get("stdout") or "")
        stderr = str((shell_result.data or {}).get("stderr") or "")
        services, parse_error = _parse_nmap_xml(stdout)
        open_count = len(services)
        ok = shell_result.ok and not parse_error
        return ToolResult(
            ok=ok,
            data={
                "target": target,
                "command": command,
                "open_ports": services[:80],
                "open_count": open_count,
                "stdout_excerpt": trim_text_chars(stdout, 1600),
                "stderr_excerpt": trim_text_chars(stderr, 800),
                "parse_error": parse_error,
                "shell": shell_result.data,
            },
            summary=(
                f"nmap_scan: {open_count} open service(s) on {target}"
                if ok
                else f"nmap_scan failed for {target}: {parse_error or shell_result.summary}"
            ),
            error=parse_error or shell_result.error,
        )


def _normalize_target(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        return str(parsed.hostname or "").strip("[]")
    target = raw.split()[0].strip()
    if "/" in target and not re.search(r"/\d{1,3}$", target):
        target = target.split("/", 1)[0]
    return target.strip("[]")


def _build_nmap_command(
    *,
    target: str,
    ports: Any,
    scripts: Any,
    udp: bool,
    timing: Any,
) -> str:
    args = [
        "nmap",
        "-Pn",
        "-sV",
        "--open",
        "--reason",
        "-oX",
        "-",
        f"-T{_bounded_int(timing, default=3, minimum=0, maximum=5)}",
    ]
    if udp:
        args.append("-sU")
    args.extend(_port_args(ports))
    script_arg = _script_arg(scripts)
    if script_arg:
        args.extend(["--script", script_arg])
    args.append(target)
    return shlex.join(args)


def _port_args(value: Any) -> list[str]:
    raw = str(value or "top-1000").strip().lower()
    if raw in {"", "top", "top-1000"}:
        return ["--top-ports", "1000"]
    if raw == "top-100":
        return ["--top-ports", "100"]
    if raw == "top-20":
        return ["--top-ports", "20"]
    if raw in {"all", "-"}:
        return ["-p-"]
    port_spec = raw.upper()
    if not _PORTS_RE.fullmatch(port_spec):
        return ["--top-ports", "1000"]
    return ["-p", port_spec[:80]]


def _script_arg(value: Any) -> str:
    raw = str(value or "default").strip().lower()
    if raw in {"", "none", "off", "false"}:
        return ""
    selected: list[str] = []
    for item in re.split(r"[\s,]+", raw):
        if item in _ALLOWED_SCRIPTS and item not in selected:
            selected.append(item)
    return ",".join(selected[:3])


def _bounded_int(value: Any, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _nmap_semaphore() -> asyncio.Semaphore:
    raw_limit = os.environ.get("VXIS_NMAP_CONCURRENCY", "1").strip()
    try:
        limit = max(1, int(raw_limit))
    except ValueError:
        limit = 1
    loop_id = id(asyncio.get_running_loop())
    current = _NMAP_SEMAPHORES.get(loop_id)
    if current is None or current[0] != limit:
        current = (limit, asyncio.Semaphore(limit))
        _NMAP_SEMAPHORES[loop_id] = current
    return current[1]


def _parse_nmap_xml(raw_xml: str) -> tuple[list[dict[str, Any]], str | None]:
    if not raw_xml.strip():
        return [], "empty_nmap_output"
    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError:
        return [], "invalid_nmap_xml"

    services: list[dict[str, Any]] = []
    for host_elem in root.findall("host"):
        address_elem = host_elem.find("address[@addrtype='ipv4']")
        if address_elem is None:
            address_elem = host_elem.find("address")
        host = address_elem.attrib.get("addr", "") if address_elem is not None else ""
        hostname_elem = host_elem.find("hostnames/hostname")
        hostname = hostname_elem.attrib.get("name", "") if hostname_elem is not None else ""
        for port_elem in host_elem.findall("ports/port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.attrib.get("state") != "open":
                continue
            service_elem = port_elem.find("service")
            scripts = [
                {
                    "id": script.attrib.get("id", ""),
                    "output": trim_text_chars(script.attrib.get("output", ""), 300),
                }
                for script in port_elem.findall("script")
            ]
            services.append(
                {
                    "host": host,
                    "hostname": hostname,
                    "port": port_elem.attrib.get("portid", ""),
                    "protocol": port_elem.attrib.get("protocol", "tcp"),
                    "service": service_elem.attrib.get("name", "") if service_elem is not None else "",
                    "product": service_elem.attrib.get("product", "") if service_elem is not None else "",
                    "version": service_elem.attrib.get("version", "") if service_elem is not None else "",
                    "reason": state_elem.attrib.get("reason", ""),
                    "scripts": scripts[:8],
                }
            )
    return services, None
