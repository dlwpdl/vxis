from __future__ import annotations

import asyncio

import pytest

from vxis.agent.tool_registry import ToolResult
from vxis.agent.tools import build_default_registry
from vxis.agent.tools.nmap_tools import NmapScanTool


class FakeShellTool:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout
        self.calls: list[dict] = []
        self.active = 0
        self.max_active = 0

    async def run(self, **kwargs):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.calls.append(dict(kwargs))
        try:
            if kwargs.get("delay"):
                await asyncio.sleep(float(kwargs["delay"]))
            return ToolResult(
                ok=True,
                summary="shell ok",
                data={"stdout": self.stdout, "stderr": "", "exit_code": 0},
            )
        finally:
            self.active -= 1


_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.25"/>
        <script id="http-title" output="Welcome"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.mark.asyncio
async def test_nmap_scan_tool_builds_bounded_command_and_parses_services():
    shell = FakeShellTool(_NMAP_XML)
    tool = NmapScanTool(shell_tool=shell)

    result = await tool.run(
        target="http://localhost:3000/path",
        ports="80,443",
        scripts="default,http-title,unsafe-shell",
        timing=4,
    )

    assert result.ok is True
    assert result.data["target"] == "localhost"
    assert result.data["open_count"] == 1
    assert result.data["open_ports"][0]["service"] == "http"
    command = shell.calls[0]["command"]
    assert "nmap -Pn -sV --open --reason -oX - -T4 -p 80,443 --script default,http-title localhost" == command
    assert "unsafe-shell" not in command


@pytest.mark.asyncio
async def test_nmap_scan_tool_rejects_shellish_target():
    tool = NmapScanTool(shell_tool=FakeShellTool(_NMAP_XML))

    result = await tool.run(target="localhost;id")

    assert result.ok is False
    assert result.error == "invalid_target"


@pytest.mark.asyncio
async def test_nmap_scan_tool_respects_default_local_backpressure(monkeypatch):
    monkeypatch.setenv("VXIS_NMAP_CONCURRENCY", "1")

    class SlowShell(FakeShellTool):
        async def run(self, **kwargs):
            return await super().run(**{**kwargs, "delay": 0.02})

    shell = SlowShell(_NMAP_XML)
    tool = NmapScanTool(shell_tool=shell)

    results = await asyncio.gather(
        tool.run(target="localhost", ports="80"),
        tool.run(target="127.0.0.1", ports="443"),
    )

    assert all(result.ok for result in results)
    assert shell.max_active == 1
    assert len(shell.calls) == 2


def test_build_default_registry_contains_nmap_scan_tool():
    reg = build_default_registry()
    assert "nmap_scan" in reg.list_tools()
