from __future__ import annotations

import pytest

from vxis.agent.memory import ScanMemory
from vxis.agent.tools.memory_tools import QueryScanMemoryTool
from vxis.pti.memory_bridge import scan_memory_to_dossier_facts
from vxis.pti.store import PTIStore


@pytest.mark.asyncio
async def test_query_scan_memory_fresh_target_contract(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("VXIS_V3_MEMORY", "1")
    monkeypatch.setenv("VXIS_PTI_ROOT", str(tmp_path / "pti"))

    result = await QueryScanMemoryTool().run(url="http://fresh.example.com:80")

    assert result.ok is True
    assert result.data["target_known"] is False
    for key in (
        "scans",
        "known_findings",
        "aggregated_findings",
        "refuted_patterns",
        "successful_tactics",
        "branch_leads",
        "cross_target_findings",
    ):
        assert key in result.data


@pytest.mark.asyncio
async def test_query_scan_memory_pti_known_target_contract(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("VXIS_V3_MEMORY", "1")
    monkeypatch.setenv("VXIS_PTI_ROOT", str(tmp_path / "pti"))
    scan = ScanMemory(
        target="http://known.example.com:80",
        tech_stack=["nginx"],
        findings_summary=[{"severity": "high", "type": "sqli", "title": "login SQLi"}],
        effective_tools=["test_injection"],
        total_findings=1,
    )
    PTIStore(root=tmp_path / "pti").persist(scan_memory_to_dossier_facts(scan))

    result = await QueryScanMemoryTool().run(url="http://known.example.com:80")

    assert result.ok is True
    assert result.data["target_known"] is True
    assert result.data["known_findings"][0]["finding_type"] == "sqli"
    assert result.data["successful_tactics"][0]["tool"] == "test_injection"
