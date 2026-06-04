from __future__ import annotations

from vxis.agent.memory import AgentMemory, ScanMemory, format_memory_context
from vxis.pti.memory_bridge import recall_context_from_pti, scan_memory_to_dossier_facts
from vxis.pti.store import PTIStore


def test_pti_recall_matches_legacy_format(tmp_path) -> None:
    scan = ScanMemory(
        target="http://example.com:80",
        tech_stack=["nginx"],
        findings_summary=[{"severity": "high", "type": "sqli", "title": "x"}],
        effective_tools=["test_injection"],
        total_findings=1,
    )

    legacy = AgentMemory(db_path=str(tmp_path / "legacy.json"))
    legacy.remember_scan(scan)
    legacy_text = format_memory_context(legacy.recall_similar("http://example.com:80", ["nginx"]))

    PTIStore(root=tmp_path / "pti").persist(scan_memory_to_dossier_facts(scan))
    pti_text = recall_context_from_pti(
        "http://example.com:80",
        ["nginx"],
        root=tmp_path / "pti",
    )

    for needle in ("nginx", "sqli", "test_injection"):
        assert needle in legacy_text.lower()
        assert needle in pti_text.lower()
