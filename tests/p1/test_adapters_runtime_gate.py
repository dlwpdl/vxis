import pytest

from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.p1.adapters import CapabilityAdapter, run_capability
from vxis.p1.audit import AuditLog
from vxis.p1.lifecycle import activate
from vxis.p1.models import Engagement, Policy, Scope, Window
from vxis.p1.resolver import FakeResolver
from vxis.p1.store import EngagementStore


class FakeAdapter(CapabilityAdapter):
    def __init__(self):
        self.calls = []

    def execute(self, *, technique, target, options):
        self.calls.append((technique, target, options))
        return "ok"

    def teardown(self, engagement_id: str) -> None:
        return None


class EchoTool:
    name = "http_request"
    description = "echo"
    input_schema = {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}

    async def run(self, **kwargs):
        return ToolResult(ok=True, summary="ran", data=kwargs)


class ShellTool:
    name = "shell_exec"
    description = "shell"
    input_schema = {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}

    async def run(self, **kwargs):
        return ToolResult(ok=True, summary="ran", data=kwargs)


def _eng():
    return activate(
        Engagement(
            id="eng_acme",
            name="ACME",
            operator="BAC",
            scope=Scope(allow=["app.acme.com", "10.0.0.0/24"]),
            window=Window(start="2026-06-01", expiry="2099-01-01"),
            policy=Policy(techniques=["recon", "emulate"]),
            attested=True,
        )
    )


def test_capability_runs_only_after_enforce_allows(tmp_path):
    adapter = FakeAdapter()
    result = run_capability(
        _eng(),
        adapter,
        technique="recon",
        target="app.acme.com",
        resolver=FakeResolver({"app.acme.com": ["10.0.0.12"]}),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        now="2026-06-10T00:00:00Z",
    )
    assert result == "ok"
    assert adapter.calls == [("recon", "app.acme.com", {})]


@pytest.mark.asyncio
async def test_runtime_gate_blocks_out_of_scope_tool(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_P1_HOME", str(tmp_path))
    monkeypatch.setenv("VXIS_P1_ENGAGEMENT_ID", "eng_acme")
    store = EngagementStore()
    store.save(_eng())
    registry = ToolRegistry()
    registry.register(EchoTool())

    result = await registry.dispatch("http_request", {"url": "https://evil.com"})

    assert result.ok is False
    assert result.error == "p1_scope_blocked"
    assert "out of scope" in result.summary


@pytest.mark.asyncio
async def test_runtime_gate_blocks_shell_without_explicit_target(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_P1_HOME", str(tmp_path))
    monkeypatch.setenv("VXIS_P1_ENGAGEMENT_ID", "eng_acme")
    EngagementStore().save(_eng())
    registry = ToolRegistry()
    registry.register(ShellTool())

    result = await registry.dispatch("shell_exec", {"command": "whoami"})

    assert result.ok is False
    assert result.error == "p1_scope_blocked"
    assert "requires p1_target" in result.summary
