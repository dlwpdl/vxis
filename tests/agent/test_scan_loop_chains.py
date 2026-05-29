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


def _chain_artifact(source_id: str, target_id: str, *, crown: str = "privileged data") -> dict:
    return {
        "source_finding_id": source_id,
        "target_finding_id": target_id,
        "source_output": "exposed config disclosed /support/logs and token abc",
        "pivot_action": "Reused token abc from the source finding against the target endpoint.",
        "observed_result": "HTTP/1.1 200 OK\n\n{\"data\":\"privileged record\",\"token\":\"abc\"}",
        "control_result": "HTTP/1.1 403 Forbidden\n\nbaseline denied without token abc",
        "crown_jewel_evidence": f"{crown} returned with token abc in the response.",
        "source_output_used_in_pivot": True,
        "hops": [
            {
                "source_finding_id": source_id,
                "target_finding_id": target_id,
                "source_output": "exposed config disclosed /support/logs and token abc",
                "pivot_action": "Reused token abc from the source finding against the target endpoint.",
                "observed_result": "HTTP/1.1 200 OK\n\n{\"data\":\"privileged record\",\"token\":\"abc\"}",
                "control_result": "HTTP/1.1 403 Forbidden\n\nbaseline denied without token abc",
                "source_output_used_in_pivot": True,
            }
        ],
    }


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
        "evidence": "GET /debug HTTP/1.1\n\nHTTP/1.1 200 OK\n\nlogin_path=/login token_hint=abc",
    })
    await reg.dispatch("report_finding", {
        "title": "weak auth",
        "severity": "medium",
        "finding_type": "weak_auth",
        "affected_component": "/login",
        "description": "weak authentication evidence",
        "evidence": (
            "POST /login HTTP/1.1\n\nusername=bad&password=bad\n\n"
            "HTTP/1.1 401 Unauthorized\n\n"
            "POST /login HTTP/1.1\n\nusername=admin&password=admin\n\n"
            "HTTP/1.1 200 OK\nSet-Cookie: session=admin"
        ),
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
    reg.register(LinkChainTool())
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
    linked = await reg.dispatch("link_chain", {
        "finding_ids": [first.data["id"], second.data["id"]],
        "rationale": "Authentication bypass session was reused to read sensitive user data.",
        "crown_jewel": "authenticated data exfiltration",
        "evidence_artifact": _chain_artifact(
            first.data["id"],
            second.data["id"],
            crown="authenticated user data",
        ),
    })
    assert linked.ok is True

    loop._settle_branches_after_chain([first.data["id"], second.data["id"]])

    assert loop.state.branches["web:auth-bypass"].status == "proven"
    assert loop.state.branches["web:auth-bypass:post-auth-enum"].status == "proven"


@pytest.mark.asyncio
async def test_unverified_narrative_chain_does_not_settle_branches():
    reg = ToolRegistry()
    reg.register(ReportFindingTool())
    reg.register(LinkChainTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=6)

    first = await reg.dispatch("report_finding", {
        "title": "Informational route hint",
        "severity": "low",
        "finding_type": "misc",
        "affected_component": "/hint",
        "description": "Route hint observed.",
    })
    second = await reg.dispatch("report_finding", {
        "title": "Benign header",
        "severity": "low",
        "finding_type": "misc",
        "affected_component": "/header",
        "description": "Header observed.",
    })
    branch = loop.state.ensure_branch(
        "manual:narrative",
        "MANUAL-NARRATIVE",
        "Narrative-only branch",
        role="post_exploit_worker",
        source_finding_id=first.data["id"],
    )

    linked = await reg.dispatch("link_chain", {
        "finding_ids": [first.data["id"], second.data["id"]],
        "rationale": "The two observations are related but no exploit chain was proven.",
    })
    assert linked.ok is True
    assert linked.data["verification_status"] == "narrative"

    loop._settle_branches_after_chain([first.data["id"], second.data["id"]])

    assert loop.state.branches[branch.id].status != "proven"


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
        "evidence_artifact": _chain_artifact(first, second),
    })
    second_link = await reg.dispatch("link_chain", {
        "finding_ids": [first, third],
        "rationale": "Leaked content helps pivot again.",
        "crown_jewel": "privileged data exfiltration",
        "evidence_artifact": _chain_artifact(first, third),
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
        "poc_script_code": "GET /support/logs HTTP/1.1\n\nHTTP/1.1 200 OK\n\nlog token=abc",
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
        "poc_script_code": "GET /ftp HTTP/1.1\n\nHTTP/1.1 200 OK\n\nbackup data",
        "remediation_steps": "fix",
    })
    target = await reg.dispatch("report_finding", {
        "title": "Sensitive user data exposed on 4 endpoint(s)",
        "severity": "high",
        "finding_type": "broken_access_control",
        "affected_component": "/api/profile",
        "description": "post-auth exposure",
        "impact": "impact",
        "technical_analysis": "Baseline without auth returned 403, authenticated request returned profile data.",
        "poc_description": "Replay unauthenticated control, then authenticated profile request and compare responses.",
        "poc_script_code": (
            "GET /api/profile HTTP/1.1\nCookie: session=\n\n"
            "HTTP/1.1 403 Forbidden\n\n"
            "GET /api/profile HTTP/1.1\nCookie: session=valid\n\n"
            "HTTP/1.1 200 OK\n\n{\"data\":\"sensitive profile\"}"
        ),
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
            "poc_script_code": f"GET {path} HTTP/1.1\n\nHTTP/1.1 200 OK\n\nsecret file content",
            "remediation_steps": "fix",
        })
    await reg.dispatch("report_finding", {
        "title": "Sensitive user data exposed on 4 endpoint(s)",
        "severity": "high",
        "finding_type": "broken_access_control",
        "affected_component": "/api/profile",
        "description": "post-auth exposure",
        "impact": "impact",
        "technical_analysis": "Baseline without auth returned 403, authenticated request returned profile data.",
        "poc_description": "Replay unauthenticated control, then authenticated profile request and compare responses.",
        "poc_script_code": (
            "GET /api/profile HTTP/1.1\nCookie: session=\n\n"
            "HTTP/1.1 403 Forbidden\n\n"
            "GET /api/profile HTTP/1.1\nCookie: session=valid\n\n"
            "HTTP/1.1 200 OK\n\n{\"data\":\"sensitive profile\"}"
        ),
        "remediation_steps": "fix",
    })

    candidates = loop._suggest_chain_candidates(limit=10)
    family = [
        c for c in candidates
        if c["target_type"] == "broken_access_control"
        and c["crown_jewel"] == "sensitive record exposure"
    ]
    assert len(family) == 1
