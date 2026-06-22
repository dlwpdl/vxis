from __future__ import annotations

from vxis.agent.egress_contract import (
    VALID_GHOST_COVERAGE,
    VALID_TARGET_EGRESS_MODES,
    registry_target_egress_snapshot,
    validate_registry_target_egress,
)
from vxis.agent.tools import build_default_registry


def test_default_registry_tools_have_target_egress_contracts() -> None:
    reg = build_default_registry()

    assert validate_registry_target_egress(reg) == []

    catalog = reg.describe_all()
    by_name = {entry["name"]: entry for entry in catalog}
    assert set(by_name) == set(reg.list_tools())
    for entry in catalog:
        target_egress = entry["target_egress"]
        assert target_egress["mode"] in VALID_TARGET_EGRESS_MODES
        assert target_egress["ghost_coverage"] in VALID_GHOST_COVERAGE
        assert isinstance(target_egress["target_facing"], bool)


def test_registry_target_egress_snapshot_flags_partial_and_direct_tools(monkeypatch) -> None:
    # nmap is opt-in (VXIS_ENABLE_NMAP); enable it here to exercise the
    # direct_raw_socket egress flagging it represents.
    monkeypatch.setenv("VXIS_ENABLE_NMAP", "1")
    snapshot = registry_target_egress_snapshot(build_default_registry())
    tools = {item["name"]: item for item in snapshot["tools"]}

    assert snapshot["errors"] == []
    assert tools["http_request"]["mode"] == "ghost_transport"
    assert tools["browser_navigate"]["mode"] == "browser_proxy_or_ua"
    assert tools["shell_exec"]["ghost_coverage"] == "partial"
    assert tools["python_exec"]["ghost_coverage"] == "partial"
    assert tools["nmap_scan"]["mode"] == "direct_raw_socket"
    assert tools["nmap_scan"]["risk"] == "direct"
    assert any("nmap_scan" in warning for warning in snapshot["warnings"])
