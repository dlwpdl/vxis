import pytest

from vxis.agent.tool_registry import BrainTool
from vxis.agent.tools.finding_tools import (
    ReportFindingTool,
    QueryFindingsTool,
    LinkChainTool,
    _reset_for_tests,
    _get_findings,
    _get_chains,
)


@pytest.fixture(autouse=True)
def reset_state():
    _reset_for_tests()
    yield
    _reset_for_tests()


# ── ReportFindingTool ────────────────────────────────────────

@pytest.mark.asyncio
async def test_report_finding_conforms_to_brain_tool():
    tool = ReportFindingTool()
    assert isinstance(tool, BrainTool)
    assert tool.name == "report_finding"


@pytest.mark.asyncio
async def test_report_finding_stores_and_returns_id():
    tool = ReportFindingTool()
    result = await tool.run(
        title="SQL Injection in login",
        severity="critical",
        finding_type="sql_injection",
        affected_component="/login",
        description="Classic ' OR 1=1-- bypass on the username field",
        evidence="POST /login user=admin'--",
    )
    assert result.ok is True
    assert result.data["id"] == "VXIS-0001"
    assert result.data["total_findings"] == 1
    assert len(_get_findings()) == 1
    assert _get_findings()[0]["title"] == "SQL Injection in login"


@pytest.mark.asyncio
async def test_report_finding_auto_increments_id():
    tool = ReportFindingTool()
    for i in range(3):
        await tool.run(
            title=f"Finding {i}",
            severity="high",
            finding_type="xss",
            affected_component=f"/path{i}",
            description="test",
        )
    ids = [f["id"] for f in _get_findings()]
    assert ids == ["VXIS-0001", "VXIS-0002", "VXIS-0003"]


@pytest.mark.asyncio
async def test_report_finding_rejects_invalid_severity():
    tool = ReportFindingTool()
    result = await tool.run(
        title="bad",
        severity="omg",
        finding_type="x",
        affected_component="/x",
        description="x",
    )
    assert result.ok is False
    assert "severity" in result.summary


@pytest.mark.asyncio
async def test_report_finding_rejects_missing_fields():
    tool = ReportFindingTool()
    result = await tool.run(
        title="no severity field set",
        severity="high",
        finding_type="",  # empty
        affected_component="/x",
        description="x",
    )
    assert result.ok is False
    assert "missing" in result.summary.lower()


# ── QueryFindingsTool ────────────────────────────────────────

@pytest.mark.asyncio
async def test_query_findings_conforms_to_brain_tool():
    tool = QueryFindingsTool()
    assert isinstance(tool, BrainTool)


@pytest.mark.asyncio
async def test_query_findings_empty_store():
    tool = QueryFindingsTool()
    result = await tool.run()
    assert result.ok is True
    assert result.data["count"] == 0
    assert result.data["findings"] == []


@pytest.mark.asyncio
async def test_query_findings_filters_by_severity_and_type():
    rep = ReportFindingTool()
    await rep.run(title="A", severity="critical", finding_type="sqli", affected_component="/a", description="da")
    await rep.run(title="B", severity="high",     finding_type="xss",  affected_component="/b", description="db")
    await rep.run(title="C", severity="critical", finding_type="xss",  affected_component="/c", description="dc")

    q = QueryFindingsTool()
    r1 = await q.run(severity="critical")
    assert r1.data["count"] == 2
    ids1 = {f["id"] for f in r1.data["findings"]}
    assert ids1 == {"VXIS-0001", "VXIS-0003"}

    r2 = await q.run(finding_type="xss")
    assert r2.data["count"] == 2

    r3 = await q.run(severity="critical", finding_type="xss")
    assert r3.data["count"] == 1
    assert r3.data["findings"][0]["id"] == "VXIS-0003"


@pytest.mark.asyncio
async def test_query_findings_text_contains_matches_title_or_description():
    rep = ReportFindingTool()
    await rep.run(title="Login bypass", severity="critical", finding_type="auth", affected_component="/login", description="jwt none alg")
    await rep.run(title="Open redirect", severity="low", finding_type="redirect", affected_component="/go", description="phishing vector")

    q = QueryFindingsTool()
    r1 = await q.run(text_contains="login")
    assert r1.data["count"] == 1
    r2 = await q.run(text_contains="phishing")
    assert r2.data["count"] == 1
    r3 = await q.run(text_contains="kubernetes")
    assert r3.data["count"] == 0


@pytest.mark.asyncio
async def test_query_findings_respects_limit():
    rep = ReportFindingTool()
    for i in range(10):
        await rep.run(title=f"F{i}", severity="low", finding_type="misc", affected_component="/x", description="y")
    q = QueryFindingsTool()
    r = await q.run(limit=3)
    assert r.data["count"] == 3


# ── LinkChainTool ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_link_chain_conforms_to_brain_tool():
    tool = LinkChainTool()
    assert isinstance(tool, BrainTool)


@pytest.mark.asyncio
async def test_link_chain_happy_path():
    rep = ReportFindingTool()
    await rep.run(title="Info leak", severity="low", finding_type="info_disclosure", affected_component="/debug", description="d")
    await rep.run(title="IDOR", severity="medium", finding_type="idor", affected_component="/api/user", description="d")
    await rep.run(title="Privesc", severity="high", finding_type="privesc", affected_component="/admin", description="d")

    link = LinkChainTool()
    result = await link.run(
        finding_ids=["VXIS-0001", "VXIS-0002", "VXIS-0003"],
        rationale="debug endpoint exposes internal IDs → enumerate users via IDOR → escalate to admin",
        crown_jewel="full admin account takeover",
    )
    assert result.ok is True
    assert result.data["id"] == "CHAIN-001"
    assert result.data["length"] == 3
    chains = _get_chains()
    assert len(chains) == 1
    assert chains[0]["crown_jewel"] == "full admin account takeover"


@pytest.mark.asyncio
async def test_link_chain_rejects_unknown_finding_ids():
    link = LinkChainTool()
    result = await link.run(
        finding_ids=["VXIS-9999", "VXIS-9998"],
        rationale="ghost chain",
    )
    assert result.ok is False
    assert "unknown" in result.summary.lower()


@pytest.mark.asyncio
async def test_link_chain_requires_at_least_two_findings():
    rep = ReportFindingTool()
    await rep.run(title="Solo", severity="high", finding_type="x", affected_component="/s", description="d")

    link = LinkChainTool()
    result = await link.run(finding_ids=["VXIS-0001"], rationale="alone")
    assert result.ok is False
    assert "at least 2" in result.summary.lower()


@pytest.mark.asyncio
async def test_link_chain_requires_rationale():
    rep = ReportFindingTool()
    await rep.run(title="A", severity="high", finding_type="x", affected_component="/a", description="d")
    await rep.run(title="B", severity="high", finding_type="x", affected_component="/b", description="d")

    link = LinkChainTool()
    result = await link.run(finding_ids=["VXIS-0001", "VXIS-0002"], rationale="")
    assert result.ok is False
    assert "rationale" in result.summary.lower()


# ── Registry integration ────────────────────────────────────

def test_build_default_registry_contains_finding_tools():
    from vxis.agent.tools import build_default_registry
    reg = build_default_registry()
    names = reg.list_tools()
    assert "report_finding" in names
    assert "query_findings" in names
    assert "link_chain" in names
    assert len(names) >= 11
