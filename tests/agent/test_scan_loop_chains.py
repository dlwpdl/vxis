import pytest

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry
from vxis.agent.tools.finding_tools import (
    LinkChainTool,
    ReportFindingTool,
    _get_chains,
    _get_findings,
    _reset_for_tests as _reset_findings,
)


@pytest.fixture(autouse=True)
def _isolate_findings():
    _reset_findings()
    yield
    _reset_findings()


@pytest.mark.asyncio
async def test_suggested_chain_candidate_can_be_auto_linked():
    reg = ToolRegistry()
    reg.register(ReportFindingTool())
    reg.register(LinkChainTool())

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=6)
    await reg.dispatch("report_finding", {
        "title": "debug leak",
        "severity": "medium",
        "finding_type": "information_disclosure",
        "affected_component": "/debug",
        "description": "debug endpoint exposed",
    })
    await reg.dispatch("report_finding", {
        "title": "weak auth",
        "severity": "medium",
        "finding_type": "weak_auth",
        "affected_component": "/login",
        "description": "weak authentication evidence",
    })

    candidates = loop._suggest_chain_candidates(limit=3)
    assert candidates
    linked = await loop._maybe_auto_link_suggested_chain()
    assert linked is not None
    assert linked["source_id"].startswith("VXIS-")
    assert linked["target_id"].startswith("VXIS-")
    assert await loop._maybe_auto_link_suggested_chain() is None


@pytest.mark.asyncio
async def test_chain_candidates_prioritize_auth_foothold_to_post_auth_data_access():
    reg = ToolRegistry()
    reg.register(ReportFindingTool())
    reg.register(LinkChainTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=6)

    first = await reg.dispatch("report_finding", {
        "title": "Authentication bypass via sqli_bypass",
        "severity": "medium",
        "finding_type": "sql_injection",
        "affected_component": "/rest/user/login",
        "description": "Authentication succeeded via SQLi.",
    })
    await reg.dispatch("report_finding", {
        "title": "Sensitive file exposed: /ftp/",
        "severity": "medium",
        "finding_type": "information_disclosure",
        "affected_component": "/ftp/",
        "description": "FTP directory exposed.",
    })
    third = await reg.dispatch("report_finding", {
        "title": "Sensitive user data exposed on 4 endpoint(s)",
        "severity": "medium",
        "finding_type": "broken_access_control",
        "affected_component": "http://localhost:3000",
        "description": "Authenticated functionality exposed sensitive user data.",
        "technical_analysis": "The post_auth_enum skill collected user-data-bearing endpoints after authentication.",
    })

    candidates = loop._suggest_chain_candidates(limit=3)
    assert candidates
    assert candidates[0]["source_id"] == first.data["id"]
    assert candidates[0]["target_id"] == third.data["id"]
    assert candidates[0]["crown_jewel"] == "authenticated data exfiltration"


@pytest.mark.asyncio
async def test_settle_branches_after_chain_closes_parent_and_child_lineage():
    reg = ToolRegistry()
    reg.register(ReportFindingTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=6)

    loop.state.ensure_branch(
        "web:auth-bypass",
        "web:auth-bypass",
        "Authentication surface",
        priority=95,
        role="exploit_worker",
    )
    loop.state.ensure_branch(
        "web:auth-bypass:post-auth-enum",
        "WEB-AUTH-PIVOT",
        "Expand authenticated route coverage",
        priority=96,
        role="post_exploit_worker",
        parent_branch_id="web:auth-bypass",
        source_finding_id="VXIS-0001",
    )

    first = await reg.dispatch("report_finding", {
        "title": "Authentication bypass via sqli_bypass",
        "severity": "medium",
        "finding_type": "sql_injection",
        "affected_component": "/rest/user/login",
        "description": "Authentication succeeded via SQLi.",
    })
    second = await reg.dispatch("report_finding", {
        "title": "Sensitive user data exposed on 4 endpoint(s)",
        "severity": "medium",
        "finding_type": "broken_access_control",
        "affected_component": "http://localhost:3000",
        "description": "Authenticated functionality exposed sensitive user data.",
    })

    loop._settle_branches_after_chain([first.data["id"], second.data["id"]])

    assert loop.state.branches["web:auth-bypass"].status == "proven"
    assert loop.state.branches["web:auth-bypass:post-auth-enum"].status == "proven"


@pytest.mark.asyncio
async def test_link_chain_dedups_similar_source_target_type_and_crown_jewel():
    reg = ToolRegistry()
    reg.register(ReportFindingTool())
    reg.register(LinkChainTool())

    await reg.dispatch("report_finding", {
        "title": "Authentication bypass via sqli_bypass",
        "severity": "medium",
        "finding_type": "sql_injection",
        "affected_component": "/rest/user/login",
        "description": "Authentication succeeded via SQLi.",
    })
    await reg.dispatch("report_finding", {
        "title": "Sensitive file exposed: /ftp/",
        "severity": "medium",
        "finding_type": "information_disclosure",
        "affected_component": "/ftp/",
        "description": "FTP directory exposed.",
    })
    await reg.dispatch("report_finding", {
        "title": "Sensitive file exposed: /support/logs",
        "severity": "medium",
        "finding_type": "information_disclosure",
        "affected_component": "/support/logs",
        "description": "Logs exposed.",
    })

    findings = _get_findings()
    first = findings[0]["id"]
    second = findings[1]["id"]
    third = findings[2]["id"]

    first_link = await reg.dispatch("link_chain", {
        "finding_ids": [first, second],
        "rationale": "Leaked content helps pivot.",
        "crown_jewel": "privileged data exfiltration",
    })
    second_link = await reg.dispatch("link_chain", {
        "finding_ids": [first, third],
        "rationale": "Leaked content helps pivot again.",
        "crown_jewel": "privileged data exfiltration",
    })

    assert first_link.ok is True
    assert second_link.ok is True
    assert second_link.data["dedup"] is True
    assert len(_get_chains()) == 1


@pytest.mark.asyncio
async def test_suggest_chain_candidates_keeps_best_source_per_target_and_crown():
    reg = ToolRegistry()
    reg.register(ReportFindingTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)

    first = await reg.dispatch("report_finding", {
        "title": "Sensitive file exposed: /support/logs",
        "severity": "critical",
        "finding_type": "information_disclosure",
        "affected_component": "/support/logs",
        "description": "leak",
        "impact": "leak",
        "technical_analysis": "leak",
        "poc_description": "GET logs",
        "poc_script_code": "GET /support/logs HTTP/1.1",
        "remediation_steps": "fix",
    })
    second = await reg.dispatch("report_finding", {
        "title": "Sensitive file exposed: /ftp",
        "severity": "critical",
        "finding_type": "information_disclosure",
        "affected_component": "/ftp",
        "description": "leak",
        "impact": "leak",
        "technical_analysis": "leak",
        "poc_description": "GET ftp",
        "poc_script_code": "GET /ftp HTTP/1.1",
        "remediation_steps": "fix",
    })
    target = await reg.dispatch("report_finding", {
        "title": "Sensitive user data exposed on 4 endpoint(s)",
        "severity": "high",
        "finding_type": "broken_access_control",
        "affected_component": "/api/profile",
        "description": "post-auth exposure",
        "impact": "impact",
        "technical_analysis": "tech",
        "poc_description": "poc",
        "poc_script_code": "GET /api/profile HTTP/1.1",
        "remediation_steps": "fix",
    })

    candidates = loop._suggest_chain_candidates(limit=5)
    target_matches = [
        c for c in candidates
        if c["target_id"] == target.data["id"]
        and c["crown_jewel"] == "sensitive record exposure"
    ]
    assert len(target_matches) == 1
    assert target_matches[0]["source_id"] in {first.data["id"], second.data["id"]}


@pytest.mark.asyncio
async def test_suggest_chain_candidates_collapses_same_target_family():
    reg = ToolRegistry()
    reg.register(ReportFindingTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)

    for path in ("/support/logs", "/ftp", "/encryptionkeys"):
        await reg.dispatch("report_finding", {
            "title": f"Sensitive file exposed: {path}",
            "severity": "critical",
            "finding_type": "information_disclosure",
            "affected_component": path,
            "description": "leak",
            "impact": "leak",
            "technical_analysis": "leak",
            "poc_description": "GET file",
            "poc_script_code": f"GET {path} HTTP/1.1",
            "remediation_steps": "fix",
        })
    await reg.dispatch("report_finding", {
        "title": "Sensitive user data exposed on 4 endpoint(s)",
        "severity": "high",
        "finding_type": "broken_access_control",
        "affected_component": "/api/profile",
        "description": "post-auth exposure",
        "impact": "impact",
        "technical_analysis": "tech",
        "poc_description": "poc",
        "poc_script_code": "GET /api/profile HTTP/1.1",
        "remediation_steps": "fix",
    })

    candidates = loop._suggest_chain_candidates(limit=10)
    family = [
        c for c in candidates
        if c["target_type"] == "broken_access_control"
        and c["crown_jewel"] == "sensitive record exposure"
    ]
    assert len(family) == 1
