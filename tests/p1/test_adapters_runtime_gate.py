import pytest

from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.config.schema import resolve_scan_profile
from vxis.p1.adapters import CapabilityAdapter, DryRunAdapter, resolve_adapter, run_capability
from vxis.p1.audit import AuditLog
from vxis.p1.lifecycle import activate
from vxis.p1.models import Engagement, Policy, Scope, Window
from vxis.p1.resolver import FakeResolver
from vxis.p1.runtime_gate import enforce_plugin_invocation
from vxis.p1.store import EngagementStore


class FakeAdapter(CapabilityAdapter):
    def __init__(self):
        self.calls = []

    def execute(self, *, technique, target, options):
        self.calls.append((technique, target, options))
        return "ok"

    def teardown(self, engagement_id: str) -> None:
        return None


class BeaconAdapter(CapabilityAdapter):
    def execute(self, *, technique, target, options):
        return {"beacon_id": "b-42"}

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


class C2Tool:
    name = "c2_beacon"
    description = "c2"
    input_schema = {
        "type": "object",
        "properties": {"target": {"type": "string"}},
        "required": ["target"],
    }

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


def test_safe_profile_resolves_dry_run_adapter():
    assert isinstance(resolve_adapter(live=False, technique="c2"), DryRunAdapter)


def test_live_profile_without_registered_tool_refuses():
    adapter = resolve_adapter(live=True, technique="c2")
    with pytest.raises(NotImplementedError, match="no authorized live adapter"):
        adapter.execute(technique="c2", target="app.acme.com", options={})


def test_run_capability_registers_returned_beacon(tmp_path):
    store = EngagementStore(tmp_path / "engagements")
    engagement = _eng()
    store.save(engagement)

    run_capability(
        engagement,
        BeaconAdapter(),
        technique="recon",
        target="app.acme.com",
        resolver=FakeResolver({"app.acme.com": ["10.0.0.12"]}),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        now="2026-06-10T00:00:00Z",
        store=store,
    )

    assert store.load("eng_acme").beacons == ["b-42"]


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


@pytest.mark.asyncio
async def test_runtime_gate_maps_c2_tool_to_c2_technique(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_P1_HOME", str(tmp_path))
    monkeypatch.setenv("VXIS_P1_ENGAGEMENT_ID", "eng_acme")
    EngagementStore().save(_eng())
    registry = ToolRegistry()
    registry.register(C2Tool())

    result = await registry.dispatch("c2_beacon", {"target": "app.acme.com"})

    assert result.ok is False
    assert result.error == "p1_scope_blocked"
    assert "technique 'c2' not authorized" in result.summary


def test_plugin_gate_is_inactive_for_ungated_profiles(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_P1_HOME", str(tmp_path))
    monkeypatch.delenv("VXIS_P1_ENGAGEMENT_ID", raising=False)

    decision = enforce_plugin_invocation(
        "nuclei",
        "https://evil.com",
        profile=resolve_scan_profile("standard"),
    )

    assert decision is None


def test_plugin_gate_blocks_out_of_scope_for_p1_profile(monkeypatch, tmp_path):
    monkeypatch.setenv("VXIS_P1_HOME", str(tmp_path))
    monkeypatch.setenv("VXIS_P1_ENGAGEMENT_ID", "eng_acme")
    EngagementStore().save(_eng())

    decision = enforce_plugin_invocation(
        "nuclei",
        "https://evil.com",
        profile=resolve_scan_profile("p1"),
    )

    assert decision is not None
    assert decision.allowed is False
    assert "out of scope" in decision.reason
