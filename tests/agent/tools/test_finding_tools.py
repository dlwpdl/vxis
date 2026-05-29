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


def _verified_chain_artifact(
    *,
    source_id: str = "VXIS-0001",
    target_id: str = "VXIS-0002",
    source_output: str = "debug leak exposed /api/user ids",
    pivot_action: str = "Reused exposed /api/user ids against the target endpoint.",
    observed_result: str = "HTTP/1.1 200 OK\n\n{\"role\":\"admin\",\"data\":\"secret\"}",
    control_result: str = "HTTP/1.1 403 Forbidden\n\nbaseline denied",
    crown_jewel_evidence: str = "Admin role and sensitive data returned in the target response.",
) -> dict:
    return {
        "source_finding_id": source_id,
        "target_finding_id": target_id,
        "source_output": source_output,
        "pivot_action": pivot_action,
        "observed_result": observed_result,
        "control_result": control_result,
        "crown_jewel_evidence": crown_jewel_evidence,
        "source_output_used_in_pivot": True,
        "hops": [
            {
                "source_finding_id": source_id,
                "target_finding_id": target_id,
                "source_output": source_output,
                "pivot_action": pivot_action,
                "observed_result": observed_result,
                "control_result": control_result,
                "source_output_used_in_pivot": True,
            }
        ],
    }


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
        impact="Authentication bypass leads to administrative access.",
        technical_analysis="Server accepted attacker-controlled quote payload and created an authenticated session.",
        poc_description="Submit a quote-based payload to the login endpoint and observe a valid session cookie.",
        poc_script_code=(
            "POST /login HTTP/1.1\n"
            "Host: app.local\n"
            "Content-Type: application/json\n\n"
            "{\"username\":\"admin'--\",\"password\":\"x\"}\n\n"
            "HTTP/1.1 200 OK\n"
            "Set-Cookie: session=abc\n\n"
            "{\"role\":\"admin\"}"
        ),
        remediation_steps="Parameterize the login query and reject malformed authentication input.",
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
            severity="medium",
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


@pytest.mark.asyncio
async def test_report_finding_rejects_high_without_real_poc():
    tool = ReportFindingTool()
    result = await tool.run(
        title="JWT bypass",
        severity="high",
        finding_type="broken_authentication",
        affected_component="/",
        description="looks exploitable",
        impact="Login boundary may be bypassed.",
    )
    assert result.ok is False
    assert result.error == "missing_report_fields"


@pytest.mark.asyncio
async def test_report_finding_rejects_high_with_weak_poc_transcript():
    tool = ReportFindingTool()
    result = await tool.run(
        title="Admin access control bypass",
        severity="high",
        finding_type="access_control",
        affected_component="/admin",
        description="Admin endpoint may be reachable.",
        impact="Admin data exposure.",
        technical_analysis="The endpoint looked different.",
        poc_description="Visit /admin.",
        poc_script_code="Admin page looked interesting",
        remediation_steps="Enforce authorization.",
    )

    assert result.ok is False
    assert result.error == "weak_poc"
    assert "exploit_attempt" in result.data["proof"]["missing"]
    assert "observed_result" in result.data["proof"]["missing"]
    assert "control_or_baseline" in result.data["proof"]["missing"]


@pytest.mark.asyncio
async def test_report_finding_normalizes_escaped_poc_transcript():
    tool = ReportFindingTool()
    result = await tool.run(
        title="Reflected XSS",
        severity="high",
        finding_type="xss_reflected",
        affected_component="/search",
        description="Payload is reflected into the response.",
        impact="Victim browser script execution.",
        technical_analysis="Baseline text response changed to active markup with the payload.",
        poc_description="Replay benign search, then replay payload search and compare response body.",
        poc_script_code=(
            "GET /search?q=test HTTP/1.1\\nHost: example\\n\\n"
            "HTTP/1.1 200 OK\\n\\nsearch:test\\n\\n"
            "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\\nHost: example\\n\\n"
            "HTTP/1.1 200 OK\\n\\nsearch:<script>alert(1)</script>"
        ),
        remediation_steps="Apply context-aware output encoding.",
    )

    assert result.ok is True
    findings = _get_findings()
    assert "\nHost: example" in findings[0]["poc_script_code"]
    assert result.data["proof"]["has_result"] is True


@pytest.mark.asyncio
async def test_report_finding_allows_medium_with_descriptive_evidence():
    tool = ReportFindingTool()
    result = await tool.run(
        title="Verbose error disclosure",
        severity="medium",
        finding_type="info_disclosure",
        affected_component="/search",
        description="Verbose stack trace observed",
        evidence="Stack trace included SQL exception details in browser response.",
    )
    assert result.ok is True
    assert _get_findings()[0]["poc_script_code"] == "Stack trace included SQL exception details in browser response."


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
    await rep.run(title="A", severity="critical", finding_type="sqli", affected_component="/a", description="da", impact="ia", technical_analysis="ta", poc_description="pa", poc_script_code="GET /a\nHTTP/1.1 500", remediation_steps="ra")
    await rep.run(title="B", severity="high",     finding_type="xss",  affected_component="/b", description="db", impact="ib", technical_analysis="tb", poc_description="pb", poc_script_code="GET /b?q=<script>alert(1)</script>\nHTTP/1.1 200 OK\n\n<script>alert(1)</script>", remediation_steps="rb")
    await rep.run(title="C", severity="critical", finding_type="xss",  affected_component="/c", description="dc", impact="ic", technical_analysis="tc", poc_description="pc", poc_script_code="GET /c\nHTTP/1.1 200", remediation_steps="rc")

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
    await rep.run(
        title="Login bypass",
        severity="critical",
        finding_type="auth",
        affected_component="/login",
        description="jwt none alg",
        impact="ia",
        technical_analysis="Control without auth returned 401, forged JWT returned 200.",
        poc_description="Replay baseline without token, then replay with forged JWT.",
        poc_script_code=(
            "GET /admin HTTP/1.1\nCookie: token=\n\n"
            "HTTP/1.1 401 Unauthorized\n\n"
            "GET /admin HTTP/1.1\nCookie: JWT=forged\n\n"
            "HTTP/1.1 200 OK\n\n{\"role\":\"admin\"}"
        ),
        remediation_steps="ra",
    )
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
    # Phase B: base-path dedup strips trailing numeric segments (/0, /1, ...) so
    # /path/0 through /path/9 all collapse to /path and merge into one finding.
    # Use alphabetic slugs so _base_path() produces 10 distinct paths and each
    # report_finding call creates a new VXIS-NNNN entry.
    slugs = [f"/page/item-{chr(ord('a') + i)}" for i in range(10)]
    for i, slug in enumerate(slugs):
        await rep.run(title=f"F{i}", severity="low", finding_type="misc", affected_component=slug, description="y")
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
    await rep.run(
        title="Privesc",
        severity="high",
        finding_type="privesc",
        affected_component="/admin",
        description="d",
        impact="Administrative role escalation succeeds.",
        technical_analysis="Server honored a low-privilege session during a promotion action.",
        poc_description="Replay the promotion request with a low-privilege cookie and observe a success response.",
        poc_script_code=(
            "POST /admin/promote HTTP/1.1\n"
            "Host: app.local\n"
            "Cookie: session=low\n\n"
            "{\"user\":\"attacker\",\"role\":\"admin\"}\n\n"
            "HTTP/1.1 200 OK\n\n"
            "{\"status\":\"promoted\"}"
        ),
        remediation_steps="Enforce server-side role checks on promotion endpoints.",
    )

    link = LinkChainTool()
    result = await link.run(
        finding_ids=["VXIS-0001", "VXIS-0002", "VXIS-0003"],
        rationale="debug endpoint exposes internal IDs → enumerate users via IDOR → escalate to admin",
        crown_jewel="full admin account takeover",
        evidence_artifact={
            "source_finding_id": "VXIS-0001",
            "target_finding_id": "VXIS-0003",
            "source_output": "debug endpoint exposes internal IDs and /api/user route",
            "pivot_action": "Reused /api/user ids to enumerate users, then replayed promotion request.",
            "observed_result": "HTTP/1.1 200 OK\n\n{\"status\":\"promoted\",\"role\":\"admin\"}",
            "control_result": "HTTP/1.1 403 Forbidden\n\nbaseline low privilege denied",
            "crown_jewel_evidence": "Admin role promotion succeeded and returned role=admin.",
            "source_output_used_in_pivot": True,
            "hops": [
                {
                    "source_finding_id": "VXIS-0001",
                    "target_finding_id": "VXIS-0002",
                    "source_output": "debug endpoint exposes internal IDs and /api/user route",
                    "pivot_action": "Reused exposed /api/user ids for IDOR enumeration.",
                    "observed_result": "HTTP/1.1 200 OK\n\n{\"data\":\"other user\"}",
                    "control_result": "HTTP/1.1 403 Forbidden\n\nbaseline denied",
                    "source_output_used_in_pivot": True,
                },
                {
                    "source_finding_id": "VXIS-0002",
                    "target_finding_id": "VXIS-0003",
                    "source_output": "IDOR returned attacker-controlled user id 1002",
                    "pivot_action": "Used enumerated user id 1002 in the admin promotion request.",
                    "observed_result": "HTTP/1.1 200 OK\n\n{\"status\":\"promoted\",\"role\":\"admin\"}",
                    "control_result": "HTTP/1.1 403 Forbidden\n\nbaseline low privilege denied",
                    "source_output_used_in_pivot": True,
                },
            ],
        },
    )
    assert result.ok is True
    assert result.data["id"] == "CHAIN-001"
    assert result.data["length"] == 3
    assert result.data["verification_status"] == "verified"
    chains = _get_chains()
    assert len(chains) == 1
    assert chains[0]["crown_jewel"] == "full admin account takeover"
    assert chains[0]["proof"]["verified"] is True


@pytest.mark.asyncio
async def test_link_chain_rejects_high_value_chain_without_verified_artifact():
    rep = ReportFindingTool()
    await rep.run(title="Info leak", severity="medium", finding_type="info_disclosure", affected_component="/debug", description="d")
    await rep.run(
        title="Default admin credentials",
        severity="high",
        finding_type="weak_auth",
        affected_component="/login",
        description="Default credentials work.",
        impact="Admin session takeover.",
        technical_analysis="Baseline invalid credentials returned 401, default credentials returned 200.",
        poc_description="Replay baseline and default credential requests.",
        poc_script_code=(
            "POST /login HTTP/1.1\n\nusername=bad&password=bad\n\n"
            "HTTP/1.1 401 Unauthorized\n\n"
            "POST /login HTTP/1.1\n\nusername=admin&password=admin\n\n"
            "HTTP/1.1 200 OK\nSet-Cookie: session=admin"
        ),
        remediation_steps="Disable default credentials.",
    )

    result = await LinkChainTool().run(
        finding_ids=["VXIS-0001", "VXIS-0002"],
        rationale="debug leak points to login, then default credentials work",
        crown_jewel="admin takeover",
    )

    assert result.ok is False
    assert result.error == "weak_chain_proof"
    assert "evidence_artifact" in result.data["proof"]["missing"]


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
    await rep.run(title="Solo", severity="high", finding_type="x", affected_component="/s", description="d", impact="i", technical_analysis="t", poc_description="p", poc_script_code="GET /s\nHTTP/1.1 200", remediation_steps="r")

    link = LinkChainTool()
    result = await link.run(finding_ids=["VXIS-0001"], rationale="alone")
    assert result.ok is False
    assert "at least 2" in result.summary.lower()


@pytest.mark.asyncio
async def test_link_chain_requires_rationale():
    rep = ReportFindingTool()
    await rep.run(title="A", severity="high", finding_type="x", affected_component="/a", description="d", impact="i", technical_analysis="t", poc_description="p", poc_script_code="GET /a\nHTTP/1.1 200", remediation_steps="r")
    await rep.run(title="B", severity="high", finding_type="x", affected_component="/b", description="d", impact="i", technical_analysis="t", poc_description="p", poc_script_code="GET /b\nHTTP/1.1 200", remediation_steps="r")

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


# ── Phase Q8: # discriminator preservation ───────────────────────────────


@pytest.mark.asyncio
async def test_hash_discriminator_keeps_findings_distinct() -> None:
    """Desktop promotion block appends '#<dylib>' to affected_component so 18
    DYL-002 findings on one binary stay distinct. urlparse used to drop
    everything after '#' as a URI fragment, so the dedup grouped them all."""
    tool = ReportFindingTool()

    binary = "/Applications/X.app/Contents/MacOS/X"
    dylibs = [
        "/usr/lib/libfoo.dylib",
        "/usr/lib/libbar.dylib",
        "/usr/lib/libbaz.dylib",
    ]

    ids: list[str] = []
    for dylib in dylibs:
        r = await tool.run(
            title="Missing dylib",
            severity="medium",
            finding_type="DESK-DYL-002",
            affected_component=f"{binary}#{dylib}",
            description=f"weak link to {dylib} missing",
            evidence=f"otool -l shows weak {dylib}",
        )
        ids.append(r.data["id"])

    assert len(set(ids)) == 3, (
        f"expected 3 distinct VXIS ids (one per dylib discriminator), "
        f"got {ids}"
    )


@pytest.mark.asyncio
async def test_no_hash_falls_back_to_existing_dedup() -> None:
    """When affected_component has no '#', behavior must be unchanged — same
    base path + same finding_type still groups under the first VXIS id."""
    tool = ReportFindingTool()

    base = "/api/Orders"
    r1 = await tool.run(
        title="IDOR",
        severity="medium",
        finding_type="idor",
        affected_component=f"{base}/1",
        description="...",
        evidence="GET /api/Orders/1 returns other user data",
    )
    r2 = await tool.run(
        title="IDOR",
        severity="medium",
        finding_type="idor",
        affected_component=f"{base}/2",
        description="...",
        evidence="GET /api/Orders/2 returns other user data",
    )
    assert r1.data["id"] == r2.data["id"], (
        "without '#' the existing base-path dedup must still merge IDs"
    )
