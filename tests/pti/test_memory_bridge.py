from __future__ import annotations

from vxis.agent.memory import ScanMemory
from vxis.pti.memory_bridge import scan_memory_to_dossier_facts


def test_scan_memory_maps_to_dossier_facts() -> None:
    mem = ScanMemory(
        target="http://example.com:80",
        tech_stack=["nginx", "php"],
        findings_summary=[{"severity": "high", "type": "sqli", "title": "login SQLi"}],
        effective_tools=["test_injection"],
        ineffective_tools=["test_xss"],
        total_findings=1,
    )

    facts = scan_memory_to_dossier_facts(mem)

    assert facts.target_url == "http://example.com:80"
    assert {item.tech for item in facts.stack} == {"nginx", "php"}
    assert facts.findings_history[0].finding_type == "sqli"
    assert any(tool.name == "test_injection" for tool in facts.authored_tools)
    assert any(tool.name == "test_xss" and tool.fail_count == 1 for tool in facts.authored_tools)
