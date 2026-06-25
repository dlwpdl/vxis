import pytest
from unittest.mock import AsyncMock
from types import SimpleNamespace
from vxis.agent.scan_loop import ScanAgentLoop, VectorCandidate
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.agent.tools.finding_tools import (
    LinkChainTool,
    ReportFindingTool,
    _get_chains,
    _reset_for_tests as _reset_findings,
)

class FinishTool:
    name = "finish_scan"
    description = "end scan"
    input_schema = {"type": "object"}
    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, summary="finished", data={"final": True})


class VerifyTool:
    name = "verify_finding"
    description = "verify"
    input_schema = {"type": "object"}

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(
            ok=True,
            summary="verify_finding: UNCONFIRMED (medium) — control gap",
            data={
                "verdict": "UNCONFIRMED",
                "confidence": "medium",
                "reasoning": "The transcript shows a positive signal but lacks the expected control comparison.",
            },
        )


class ConfirmingVerifyTool:
    name = "verify_finding"
    description = "verify confirmed"
    input_schema = {"type": "object"}

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(
            ok=True,
            summary="verify_finding: CONFIRMED (high)",
            data={
                "verdict": "CONFIRMED",
                "confidence": "high",
                "reasoning": "Evidence is sufficient.",
            },
        )


class RunSkillTool:
    name = "run_skill"
    description = "execute prebuilt skill"
    input_schema = {"type": "object"}

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def run(self, **kwargs) -> ToolResult:
        self.calls.append(dict(kwargs))
        return ToolResult(ok=True, summary=f"ran skill {kwargs.get('skill', '?')}", data={})


class ReplayHttpTool:
    name = "http_request"
    description = "machine replay http"
    input_schema = {"type": "object", "properties": {"method": {"type": "string"}}, "required": ["method"]}

    async def run(self, **kwargs) -> ToolResult:
        path = str(kwargs.get("path") or kwargs.get("url") or "")
        body = (
            "search:<img src=x onerror=alert(1)>"
            if "%3Cimg" in path or "<img" in path
            else "search:test"
        )
        return ToolResult(ok=True, summary="HTTP 200", data={"status": 200, "body_preview": body})


@pytest.fixture(autouse=True)
def _isolate_findings():
    _reset_findings()
    yield
    _reset_findings()


def test_focus_branch_role_blocks_exploit_action_for_recon_worker():
    reg = ToolRegistry()
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    branch = loop.state.ensure_branch(
        "web:dir-bruteforce",
        "web:dir-bruteforce",
        "Hidden routes/directories",
        role="recon_worker",
        objective="Map non-authenticated surface",
    )
    assert (
        loop._action_advances_focus_branch(
            branch,
            "shell_exec",
            {"command": "sqlmap -u http://localhost:3000/rest/products/search?q=test"},
            [],
    )
        is False
    )


def test_status_from_tool_result_treats_skill_runner_block_as_blocked():
    result = ToolResult(
        ok=False,
        summary="run_skill BLOCKED — you've called 'attempt_auth' with IDENTICAL args 3 times.",
        data={"blocked": True, "hits": 3},
        error="stuck_loop",
    )
    assert ScanAgentLoop._status_from_tool_result(result) == "blocked"


def test_recent_blocked_skill_count_uses_explicit_skill_counter():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.record_blocked_skill("attempt_auth")
    loop.state.record_blocked_skill("attempt_auth")
    assert loop._recent_blocked_skill_count("attempt_auth") == 2


def test_platform_allowed_skills_for_desktop_excludes_web_skills():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="/Applications/Calculator.app", registry=reg, max_iters=3, target_kind="desktop")
    allowed = loop._platform_allowed_skills()
    assert "test_xss" not in allowed
    assert "test_signature_audit" in allowed


def test_pivoted_skill_name_moves_within_web_graph_after_blocked_retries():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    loop.state.record_blocked_skill("attempt_auth")
    loop.state.record_blocked_skill("attempt_auth")
    loop.state.record_blocked_skill("attempt_auth")
    assert loop._pivoted_skill_name("attempt_auth") == "post_auth_enum"


def test_reroute_blocked_skill_advances_to_next_web_pivot():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    for _ in range(3):
        loop.state.record_blocked_skill("attempt_auth")
    for _ in range(3):
        loop.state.record_blocked_skill("post_auth_enum")
    skill, params = loop._reroute_blocked_skill("attempt_auth", {})
    assert skill == "test_idor"
    assert params["base_url"] == "http://localhost:3000"


def test_mobile_forced_candidate_action_does_not_select_web_skill():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="/tmp/app.apk", registry=reg, max_iters=3, target_kind="mobile")
    candidate = VectorCandidate(
        id="mobile:auth",
        vector_id="mobile:auth",
        title="Authentication bypass or weak login",
        priority=95,
        evidence="login form exposed",
    )
    assert loop._forced_candidate_action(candidate) is None


def test_focus_discipline_profile_is_stricter_for_local_llm():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=24)
    loop.brain = SimpleNamespace(_provider="llamacpp")
    assert loop._llm_discipline_profile() == "local_strict"
    assert loop._focus_grace_iterations() < 5
    assert loop._focus_drift_block_threshold() == 2


def test_focus_discipline_profile_is_looser_for_cloud_llm():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=24)
    loop.brain = SimpleNamespace(_provider="together", _model="deepseek-ai/DeepSeek-V3.1")
    assert loop._llm_discipline_profile() == "cloud_balanced"
    assert loop._focus_grace_iterations() >= 4
    assert loop._focus_drift_block_threshold() == 3


def test_frontier_profile_is_most_permissive():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=24)
    loop.brain = SimpleNamespace(_provider="openai", _model="gpt-5.5")
    assert loop._llm_discipline_profile() == "frontier_loose"
    assert loop._focus_grace_iterations() > 5
    assert loop._focus_drift_block_threshold() == 4


def test_cloud_profiles_allow_uncovered_family_probe_more_readily_than_local():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=24)
    branch = loop.state.ensure_branch(
        "web:sqli:credential-pivot",
        "WEB-SQLI-PIVOT",
        "Turn SQL injection into authenticated foothold",
        priority=95,
        role="post_exploit_worker",
        phase="session_reuse",
        source_finding_id="VXIS-0001",
    )
    candidate = loop.state.ensure_vector_candidate(
        "web:dir-bruteforce",
        "web:dir-bruteforce",
        "Hidden routes/directories",
        priority=88,
        evidence="unexplored route family discovered",
    )
    loop.state.findings.append({
        "finding_type": "sql_injection",
        "title": "SQLi on q",
        "severity": "critical",
    })
    loop.brain = SimpleNamespace(_provider="llamacpp")
    local_allowed = loop._should_allow_off_branch_action(
        branch,
        "browser_render",
        {"url": "http://localhost:3000/#/administration"},
        [],
        [candidate.id],
    )
    loop.brain = SimpleNamespace(_provider="together", _model="deepseek-ai/DeepSeek-V3.1")
    balanced_allowed = loop._should_allow_off_branch_action(
        branch,
        "browser_render",
        {"url": "http://localhost:3000/#/administration"},
        [],
        [candidate.id],
    )
    loop.brain = SimpleNamespace(_provider="openai", _model="gpt-5.5")
    frontier_allowed = loop._should_allow_off_branch_action(
        branch,
        "browser_render",
        {"url": "http://localhost:3000/#/administration"},
        [],
        [candidate.id],
    )
    assert local_allowed is False
    assert balanced_allowed is True
    assert frontier_allowed is True


def test_local_strict_brain_tool_catalog_is_narrower_than_full_registry():
    reg = ToolRegistry()
    class _Tool:
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
        def __init__(self, name: str, description: str = "") -> None:
            self.name = name
            self.description = description or name

    for name in (
        "finish_scan", "think", "wait", "report_finding", "query_findings", "link_chain",
        "verify_finding", "run_skill", "fingerprint_target", "list_playbooks", "load_playbook",
        "http_request", "browser_render", "browser_navigate", "browser_analyze_dom",
        "browser_fill_form", "browser_get_cookies", "browser_eval_js", "shell_exec",
        "python_exec", "browser_click", "browser_screenshot", "intercept_proxy", "query_scan_memory",
        "agent_graph",
    ):
        reg.register(_Tool(name))
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=24)
    loop.brain = SimpleNamespace(_provider="llamacpp", _model="local-qwen")
    catalog = loop._brain_tool_catalog()
    names = {item["name"] for item in catalog}
    assert len(catalog) < len(reg.describe_all())
    assert "finish_scan" in names
    assert "run_skill" in names
    assert "agent_graph" in names
    assert "browser_click" not in names
    assert "browser_screenshot" not in names


def test_cloud_balanced_brain_tool_catalog_keeps_full_registry():
    reg = ToolRegistry()
    class _Tool:
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
        def __init__(self, name: str) -> None:
            self.name = name
            self.description = name

    for name in ("finish_scan", "think", "run_skill", "browser_click", "browser_screenshot"):
        reg.register(_Tool(name))
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=24)
    loop.brain = SimpleNamespace(_provider="openai", _model="gpt-5.5")
    assert len(loop._brain_tool_catalog()) == len(reg.describe_all())


def test_local_strict_scan_dashboard_is_compact():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=24)
    loop.brain = SimpleNamespace(_provider="llamacpp", _model="local-qwen")
    loop.state.iteration = 7
    for i in range(5):
        loop.state.findings.append({
            "id": f"VXIS-{i:04d}",
            "finding_type": "sql_injection",
            "severity": "high",
            "title": f"Finding {i}",
        })
    for i in range(6):
        loop.state.ensure_branch(
            f"branch-{i}",
            "WEB-SQLI-001",
            f"Branch {i}",
            priority=90 - i,
            role="post_exploit_worker",
            phase="session_reuse",
            source_finding_id=f"VXIS-{i:04d}",
        )
    dashboard = loop._build_scan_dashboard()
    assert "LOCAL SCAN DASHBOARD" in dashboard
    assert "═══ CHAIN INTELLIGENCE ═══" not in dashboard
    assert dashboard.count("Branch ") <= 4


def test_scan_dashboard_surfaces_crown_objective_distance():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=24)
    loop.state.ensure_branch(
        "web:sqli:db-impact",
        "WEB-SQLI-IMPACT",
        "DB impact",
        priority=102,
        role="post_exploit_worker",
        phase="data_access",
        objective="Extract meaningful backend data.",
        next_step="Dump users/auth tables.",
        crown_jewel="DB dump",
    )
    dashboard = loop._build_scan_dashboard()

    assert "crown: DB dump" in dashboard
    assert "Crown distance: prove a control/payload delta" in dashboard


@pytest.mark.asyncio
async def test_scan_dashboard_keeps_crown_distance_under_chain_pressure():
    await ReportFindingTool().run(
        title="Finding one",
        severity="low",
        finding_type="information_disclosure",
        affected_component="/one",
        description="one",
    )
    await ReportFindingTool().run(
        title="Finding two",
        severity="low",
        finding_type="information_disclosure",
        affected_component="/two",
        description="two",
    )
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=24)
    loop.state.ensure_branch(
        "web:sqli:db-impact",
        "WEB-SQLI-IMPACT",
        "DB impact",
        priority=102,
        role="post_exploit_worker",
        phase="data_access",
        objective="Extract meaningful backend data.",
        next_step="Dump users/auth tables.",
        crown_jewel="DB dump",
    )

    dashboard = loop._build_scan_dashboard()

    assert "Crown distance: prove a control/payload delta" in dashboard


def test_scan_dashboard_surfaces_auth_state_without_tokens():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=24)
    loop.state.record_auth_identities([
        {
            "name": "alice",
            "role": "admin",
            "token": "SECRET_TOKEN_123",
            "headers": {"Cookie": "session=SECRET_TOKEN_123"},
        }
    ])

    dashboard = loop._build_scan_dashboard()

    assert "Auth state: authenticated (alice/admin)" in dashboard
    assert "SECRET_TOKEN_123" not in dashboard


def test_open_crown_goal_keeps_post_exploit_branch_finish_blocking_until_depth():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=24)
    branch = loop.state.ensure_branch(
        "web:sqli:db-impact",
        "WEB-SQLI-IMPACT",
        "DB impact",
        priority=38,
        role="post_exploit_worker",
        phase="data_access",
        source_finding_id="VXIS-0002",
        objective="Extract meaningful backend data.",
        next_step="Dump users/auth tables.",
        crown_jewel="DB dump",
    )
    branch.attempts = 2

    assert loop._branch_expected_yield_score(branch) < 65
    assert loop._branch_has_finish_blocking_yield(branch) is True

    branch.attempts = 3
    assert loop._branch_has_finish_blocking_yield(branch) is False


def test_dag_finish_readds_active_crown_branch_outside_untested_nodes():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=24)
    branch = loop.state.ensure_branch(
        "web:sqli:db-impact",
        "WEB-SQLI-IMPACT",
        "DB impact",
        priority=38,
        role="post_exploit_worker",
        phase="data_access",
        source_finding_id="VXIS-0002",
        objective="Extract meaningful backend data.",
        next_step="Dump users/auth tables.",
        crown_jewel="DB dump",
    )
    branch.status = "active"
    branch.attempts = 1

    blockers = loop._dag_finish_blocking_branches()

    assert any(item.id == branch.id for item in blockers)


def test_local_strict_compacts_finding_payload_before_verifier():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=24)
    loop.brain = SimpleNamespace(_provider="llamacpp", _model="local-qwen")
    args = loop._compact_local_finding_payload({
        "description": "D" * 600,
        "impact": "I" * 600,
        "technical_analysis": "HTTP/1.1 500\n" + ("A" * 3000),
        "poc_description": "baseline/control\n" + ("B" * 2000),
        "poc_script_code": "GET /x HTTP/1.1\nHost: test\n\nHTTP/1.1 200\n" + ("C" * 3000),
        "evidence": "GET /x HTTP/1.1\nHost: test\n\nHTTP/1.1 200\n" + ("E" * 3000),
        "extra_evidence": [
            {"title": "artifact", "content": "payload\n" + ("X" * 2000)},
            {"title": "artifact2", "content": "payload\n" + ("Y" * 2000)},
            {"title": "artifact3", "content": "payload\n" + ("Z" * 2000)},
        ],
    })
    assert len(args["description"]) <= 220
    assert len(args["impact"]) <= 240
    assert len(args["technical_analysis"]) <= 520
    assert len(args["poc_description"]) <= 420
    assert len(args["poc_script_code"]) <= 1200
    assert len(args["evidence"]) <= 1200
    assert len(args["extra_evidence"]) == 2


def test_cloud_profile_keeps_finding_payload_uncompacted():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=24)
    loop.brain = SimpleNamespace(_provider="openai", _model="gpt-5.5")
    payload = {
        "description": "D" * 600,
        "poc_script_code": "GET /x HTTP/1.1\nHost: test\n\nHTTP/1.1 200\n" + ("C" * 3000),
    }
    out = loop._compact_local_finding_payload(payload)
    assert out["description"] == payload["description"]
    assert out["poc_script_code"] == payload["poc_script_code"]


def test_dag_finish_branches_exhausts_post_exploit_branch_when_pivot_graph_is_spent():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    loop.state.ensure_vector_candidate(
        "web:auth-bypass:post-auth-enum",
        "WEB-AUTH-PIVOT",
        "Expand authenticated route coverage",
        priority=95,
    )
    for skill in ("attempt_auth", "post_auth_enum", "test_idor", "test_api_security", "test_business_logic", "test_sensitive_files"):
        for _ in range(3):
            loop.state.record_blocked_skill(skill)
    branch = loop.state.ensure_branch(
        "web:auth-bypass:post-auth-enum",
        "WEB-AUTH-PIVOT",
        "Expand authenticated route coverage",
        priority=95,
        role="post_exploit_worker",
        phase="data_access",
        source_finding_id="VXIS-0001",
    )
    branch.attempts = 4
    blockers = loop._dag_finish_blocking_branches()
    assert all(item.id != branch.id for item in blockers)
    assert loop.state.branches[branch.id].status == "exhausted"


def test_dag_finish_branches_keeps_high_yield_post_exploit_branch():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    loop.state.ensure_vector_candidate(
        "web:auth-bypass:post-auth-enum",
        "WEB-AUTH-PIVOT",
        "Expand authenticated route coverage",
        priority=95,
    )
    branch = loop.state.ensure_branch(
        "web:auth-bypass:post-auth-enum",
        "WEB-AUTH-PIVOT",
        "Expand authenticated route coverage",
        priority=95,
        role="post_exploit_worker",
        phase="data_access",
        source_finding_id="VXIS-0001",
    )
    branch.attempts = 1
    blockers = loop._dag_finish_blocking_branches()
    assert any(item.id == branch.id for item in blockers)
    assert loop.state.branches[branch.id].status != "exhausted"


@pytest.mark.asyncio
async def test_budget_exhaustion_completion_accepts_when_no_meaningful_blockers_remain():
    reg = ToolRegistry()
    reg.register(ReportFindingTool())
    reg.register(LinkChainTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)

    first = await reg.dispatch("report_finding", {
        "title": "debug leak",
        "severity": "medium",
        "finding_type": "information_disclosure",
        "affected_component": "/debug",
        "description": "debug endpoint exposed",
    })
    second = await reg.dispatch("report_finding", {
        "title": "weak auth",
        "severity": "medium",
        "finding_type": "weak_auth",
        "affected_component": "/login",
        "description": "weak authentication evidence",
    })
    await reg.dispatch("link_chain", {
        "finding_ids": [first.data["id"], second.data["id"]],
        "rationale": "debug leak leads to auth foothold",
        "crown_jewel": "authenticated foothold",
        "evidence_artifact": {
            "source_finding_id": first.data["id"],
            "target_finding_id": second.data["id"],
            "source_output": "debug leak disclosed the /login path and default credential hint",
            "pivot_action": "Reused the default credential hint against /login.",
            "observed_result": "HTTP/1.1 200 OK\nSet-Cookie: session=admin",
            "control_result": "HTTP/1.1 401 Unauthorized\nbaseline invalid credentials denied",
            "crown_jewel_evidence": "Authenticated session cookie issued after credential reuse.",
            "repeat_count": 2,
            "negative_result": "HTTP/1.1 401 Unauthorized\nbaseline invalid credentials denied",
            "source_output_used_in_pivot": True,
            "hops": [
                {
                    "source_finding_id": first.data["id"],
                    "target_finding_id": second.data["id"],
                    "source_output": "debug leak disclosed the /login path and default credential hint",
                    "pivot_action": "Reused the default credential hint against /login.",
                    "observed_result": "HTTP/1.1 200 OK\nSet-Cookie: session=admin",
                    "control_result": "HTTP/1.1 401 Unauthorized\nbaseline invalid credentials denied",
                    "repeat_count": 2,
                    "negative_result": "HTTP/1.1 401 Unauthorized\nbaseline invalid credentials denied",
                    "source_output_used_in_pivot": True,
                }
            ],
        },
    })
    loop.state.record_review_item(
        "judge:unfinished_branches:http://localhost:3000",
        stage="judge",
        status="escalated",
        title="unfinished_branches",
        reason="branches remained",
        action_hint="keep going",
        affected_component="http://localhost:3000",
    )
    loop._dag_finish_blocking_branches = lambda: []  # type: ignore[method-assign]
    loop.state.open_vector_candidates = lambda: []  # type: ignore[method-assign]
    assert loop._maybe_finalize_budget_exhausted_scan() is True
    assert loop.state.completed is True
    assert loop.state.review_queue["judge:unfinished_branches:http://localhost:3000"].status == "closed"
    assert any(item.verdict == "ACCEPTED" for item in loop.state.review_history)


def test_candidate_finish_blocking_yield_drops_when_vector_family_already_covered():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    candidate = loop.state.ensure_vector_candidate(
        "web:auth-bypass",
        "WEB-AUTH-001",
        "Authentication bypass or weak login",
        priority=95,
        evidence="login form exposed",
    )
    findings = [{
        "finding_type": "sql_injection",
        "title": "Authentication bypass via sqli_bypass",
        "affected_component": "/rest/user/login",
    }]
    for _ in range(3):
        loop.state.record_blocked_skill("attempt_auth")
    assert loop._candidate_has_finish_blocking_yield(candidate, findings) is False


def test_memory_candidate_finish_blocking_yield_drops_when_family_is_already_covered():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    candidate = loop.state.ensure_vector_candidate(
        "memory:idor:http://localhost:3000/api/users/{id}",
        "web:idor",
        "Revalidate prior IDOR lead",
        priority=95,
        evidence="Previously observed IDOR on /api/users/{id}.",
    )
    findings = [{
        "finding_type": "idor",
        "title": "Unauthorized object retrieval",
        "affected_component": "/api/Users/1",
    }]
    for _ in range(3):
        loop.state.record_blocked_skill("test_idor")
    assert loop._candidate_has_finish_blocking_yield(candidate, findings) is False


def test_candidate_family_detects_disclosure_seed_variants():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    disclosure = loop.state.ensure_vector_candidate(
        "web:sensitive-files",
        "WEB-MISCONF-001",
        "Sensitive files or exposed config",
        priority=85,
        evidence="seeded from target surface",
    )
    brute = loop.state.ensure_vector_candidate(
        "web:dir-bruteforce",
        "WEB-INFRA-001",
        "Hidden routes/directories",
        priority=75,
        evidence="seeded from target surface",
    )
    assert loop._candidate_family(disclosure) == "disclosure"
    assert loop._candidate_family(brute) == "infra"


def test_memory_carry_branch_drops_finish_blocking_yield_when_family_is_already_covered():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    loop.state.findings.append({
        "finding_type": "broken_access_control",
        "title": "Authenticated data access via IDOR",
        "affected_component": "/api/Users/1",
    })
    for _ in range(3):
        loop.state.record_blocked_skill("test_idor")
    branch = loop.state.ensure_branch(
        "carry:web:idor:users",
        "web:idor",
        "Revisit user object access control",
        priority=92,
        owner="memory",
        role="post_exploit_worker",
        phase="data_access",
        objective="Revalidate prior IDOR lead and deepen access.",
        blocker="carry-over lead",
    )
    branch.attempts = 1
    blockers = loop._dag_finish_blocking_branches()
    assert all(item.id != branch.id for item in blockers)
    assert loop.state.branches[branch.id].status == "exhausted"


def test_blocked_root_branch_drops_finish_blocking_yield_when_family_is_already_covered():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    loop.state.findings.append({
        "finding_type": "sql_injection",
        "title": "Authentication bypass via sqli_bypass",
        "affected_component": "/rest/user/login",
    })
    for _ in range(3):
        loop.state.record_blocked_skill("attempt_auth")
    for _ in range(3):
        loop.state.record_blocked_skill("post_auth_enum")
    branch = loop.state.ensure_branch(
        "web:auth-bypass",
        "web:auth-bypass",
        "Authentication bypass or weak login",
        priority=95,
        role="recon_worker",
        objective="Gain an authenticated foothold.",
    )
    branch.status = "blocked"
    branch.last_tool = "run_skill"
    branch.last_summary = "run_skill BLOCKED — you've called 'attempt_auth' with IDENTICAL args 3 times."
    blockers = loop._dag_finish_blocking_branches()
    assert all(item.id != branch.id for item in blockers)
    assert loop.state.branches[branch.id].status == "blocked"


def test_best_skill_params_reuses_known_search_surface_for_xss_and_injection():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.add_message("tool", {
        "name": "run_skill",
        "args": {"skill": "enumerate_endpoints", "target_url": "http://localhost:3000"},
        "result": {
            "ok": True,
            "summary": "enumerated",
            "data": {
                "accessible": [
                    {"path": "/rest/products/search?q=test", "status": 200, "size": 1234},
                ],
            },
        },
    })
    assert loop._best_skill_params("test_xss")["url"].endswith("/rest/products/search?q=test")
    assert loop._best_skill_params("test_injection")["url"].endswith("/rest/products/search?q=test")


def test_best_skill_params_passes_seed_paths_to_infra():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.add_message("tool", {
        "name": "run_skill",
        "args": {"skill": "enumerate_endpoints", "target_url": "http://localhost:3000"},
        "result": {
            "ok": True,
            "summary": "enumerated",
            "data": {
                "accessible": [
                    {"path": "/ftp/acme.md", "status": 200, "size": 128},
                    {"path": "/support/logs", "status": 200, "size": 256},
                ],
            },
        },
    })
    params = loop._best_skill_params("test_infra")
    assert params["seed_paths"] == ["/ftp/acme.md", "/support/logs"]


def test_finish_scan_does_not_attach_family_candidates_from_report_text():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    ids = loop._candidate_ids_for_action("finish_scan", {
        "executive_summary": "xss and ssrf checked",
        "methodology": "exercise xss ssrf family",
        "technical_analysis": "search xss and redirect ssrf",
    })
    assert ids == []


def test_finish_scan_unattempted_candidate_gate_uses_high_yield_family_filter():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    findings = [{
        "finding_type": "idor",
        "title": "Unauthorized object retrieval",
        "affected_component": "/api/Users/1",
    }]
    candidate = loop.state.ensure_vector_candidate(
        "memory:idor:http://localhost:3000/api/users/{id}",
        "web:idor",
        "Revalidate prior IDOR lead",
        priority=95,
        evidence="Previously observed IDOR on /api/users/{id}.",
    )
    for _ in range(3):
        loop.state.record_blocked_skill("test_idor")
    filtered = loop._dag_remaining_high_yield_candidates(findings)
    assert candidate not in filtered


def test_fallback_branch_ids_for_candidates_maps_root_branch_without_watch_terms():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.ensure_vector_candidate(
        "web:dir-bruteforce",
        "web:dir-bruteforce",
        "Hidden routes/directories",
        priority=80,
        evidence="seeded from target surface",
    )
    loop.state.ensure_branch(
        "web:dir-bruteforce",
        "web:dir-bruteforce",
        "Hidden routes/directories",
        priority=80,
        role="recon_worker",
    )
    assert loop._branch_ids_for_action("run_skill", {"skill": "enumerate_endpoints"}) == []
    assert loop._fallback_branch_ids_for_candidates(["web:dir-bruteforce"]) == ["web:dir-bruteforce"]


def test_dag_finish_blocking_branches_exhausts_stale_root_recon_branch_after_candidate_failure():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    candidate = loop.state.ensure_vector_candidate(
        "web:dir-bruteforce",
        "web:dir-bruteforce",
        "Hidden routes/directories",
        priority=80,
        evidence="seeded from target surface",
    )
    candidate.status = "failed"
    branch = loop.state.ensure_branch(
        "web:dir-bruteforce",
        "web:dir-bruteforce",
        "Hidden routes/directories",
        priority=80,
        role="recon_worker",
    )
    branch.source_candidate_id = "web:dir-bruteforce"
    blockers = loop._dag_finish_blocking_branches()
    assert all(item.id != branch.id for item in blockers)
    assert loop.state.branches[branch.id].status == "exhausted"


def test_dag_finish_blocking_branches_drops_redundant_root_family_branch_when_child_post_exploit_exists():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    root = loop.state.ensure_branch(
        "web:sqli",
        "WEB-SQLI-001",
        "SQL injection toward DB/admin data",
        priority=95,
        role="exploit_worker",
    )
    root.attempts = 3
    child = loop.state.ensure_branch(
        "web:sqli:db-impact",
        "WEB-SQLI-IMPACT",
        "Expand SQLi toward full database impact",
        priority=102,
        role="post_exploit_worker",
        phase="data_access",
        parent_branch_id=root.id,
        source_candidate_id=root.id,
        source_finding_id="VXIS-0001",
    )
    child.status = "active"
    blockers = loop._dag_finish_blocking_branches()
    assert any(item.id == child.id for item in blockers)
    assert all(item.id != root.id for item in blockers)


def test_dag_finish_blocking_branches_drops_redundant_memory_branch_when_live_family_branch_exists():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    live = loop.state.ensure_branch(
        "web:sqli:credential-pivot",
        "WEB-SQLI-PIVOT",
        "Harvest credentials or tokens from SQLi impact",
        priority=106,
        role="post_exploit_worker",
        phase="session_reuse",
        source_finding_id="VXIS-0001",
    )
    live.attempts = 1
    memory = loop.state.ensure_branch(
        "memory:sql_injection:/rest/user/login",
        "WEB-SQLI-001",
        "Revalidate prior Authentication bypass via sqli_bypass",
        priority=92,
        role="exploit_worker",
        owner="memory",
    )
    blockers = loop._dag_finish_blocking_branches()
    assert any(item.id == live.id for item in blockers)
    assert all(item.id != memory.id for item in blockers)


def test_dag_finish_blocking_branches_drops_memory_revalidation_when_family_already_found_this_run():
    reg = ToolRegistry()
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    loop.state.findings.append({
        "finding_type": "sql_injection",
        "title": "SQLI on q",
        "affected_component": "http://localhost:3000/rest/products/search?q=",
    })
    memory = loop.state.ensure_branch(
        "memory:sql_injection:/rest/user/login",
        "WEB-SQLI-001",
        "Revalidate prior Authentication bypass via sqli_bypass",
        priority=92,
        role="exploit_worker",
    )
    blockers = loop._dag_finish_blocking_branches()
    assert all(item.id != memory.id for item in blockers)


def test_hydrate_verify_finding_args_backfills_from_latest_report():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.add_message("tool", {
        "name": "report_finding",
        "args": {
            "title": "SQLI on q",
            "severity": "critical",
            "finding_type": "sql_injection",
            "affected_component": "http://localhost:3000/rest/products/search?q=",
            "description": "Injection behavior was observed on parameter q.",
            "impact": "DB impact possible.",
            "technical_analysis": "Observed response-length delta.",
            "poc_description": "Send quote payload and compare responses.",
            "poc_script_code": "curl 'http://localhost:3000/rest/products/search?q='",
            "evidence": "GET /rest/products/search?q= ... HTTP/1.1 200 ...",
        },
        "result": {"ok": True, "summary": "reported"},
    })
    hydrated = loop._hydrate_verify_finding_args({
        "title": "SQLI on q",
        "severity": "critical",
        "finding_type": "sql_injection",
        "affected_component": "/rest/user/login",
    })
    assert hydrated["evidence"].startswith("GET /rest/products/search?q=")
    assert hydrated["technical_analysis"] == "Observed response-length delta."


def test_normalize_tool_args_maps_shell_exec_cmd_to_command():
    normalized = ScanAgentLoop._normalize_tool_args("shell_exec", {"cmd": "echo hi"})
    assert normalized["command"] == "echo hi"


def test_dag_finish_blocking_branches_exhausts_found_root_branch_when_family_is_already_confirmed():
    reg = ToolRegistry()
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    loop.state.findings.append({
        "finding_type": "sql_injection",
        "title": "SQLI on q",
        "affected_component": "http://localhost:3000/rest/products/search?q=",
    })
    candidate = loop.state.ensure_vector_candidate(
        "web:sqli",
        "WEB-SQLI-001",
        "SQL injection toward DB/admin data",
        priority=95,
    )
    candidate.status = "found"
    branch = loop.state.ensure_branch(
        "web:sqli",
        "WEB-SQLI-001",
        "SQL injection toward DB/admin data",
        priority=95,
        role="post_exploit_worker",
    )
    branch.attempts = 3
    blockers = loop._dag_finish_blocking_branches()
    assert all(item.id != branch.id for item in blockers)
    assert loop.state.branches[branch.id].status == "exhausted"


def test_branch_expected_yield_downgrades_disclosure_when_stronger_foothold_exists():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.findings.append({
        "finding_type": "weak_auth",
        "title": "Authentication bypass via sqli_bypass",
        "impact": "An authenticated foothold was obtained.",
        "technical_analysis": "Token acquired and session reused.",
    })
    branch = loop.state.ensure_branch(
        "web:sensitive-files:admin-surface",
        "WEB-ADMIN-PIVOT",
        "Use the disclosure to map privileged routes and internal surfaces",
        priority=96,
        role="post_exploit_worker",
        phase="privilege_probe",
        source_finding_id="VXIS-0009",
        crown_jewel="privileged route exposure",
    )
    score = loop._branch_expected_yield_score(branch)
    assert score < 65
    root = loop.state.ensure_branch(
        "web:sensitive-files",
        "WEB-MISCONF-001",
        "Sensitive files or exposed config",
        priority=85,
        role="recon_worker",
    )
    assert loop._branch_has_finish_blocking_yield(root) is False


def test_branch_expected_yield_downgrades_disclosure_when_only_binary_blob_reviews_exist():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.record_review_decision(
        stage="verifier",
        verdict="REFUTED",
        title="Sensitive file exposed: /encryptionkeys/",
        reason="The captured response is dominated by escaped binary/compressed blob data without readable secret material.",
        source_finding_type="information_disclosure",
    )
    loop.state.record_review_decision(
        stage="verifier",
        verdict="REFUTED",
        title="Sensitive file exposed: /ftp/",
        reason="The captured response is dominated by escaped binary/compressed blob data without readable secret material.",
        source_finding_type="information_disclosure",
    )
    branch = loop.state.ensure_branch(
        "web:sensitive-files:credential-reuse",
        "WEB-DISCLOSURE-PIVOT",
        "Turn disclosed material into authenticated access",
        priority=91,
        role="post_exploit_worker",
        phase="session_reuse",
        source_finding_id="VXIS-0004",
        crown_jewel="admin takeover",
    )
    score = loop._branch_expected_yield_score(branch)
    assert score < 65
    assert loop._branch_has_finish_blocking_yield(branch) is False


def test_branch_expected_yield_downgrades_db_impact_without_meaningful_db_evidence():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    branch = loop.state.ensure_branch(
        "web:sqli:db-impact",
        "WEB-SQLI-PIVOT",
        "Turn SQL injection into database dump or admin-impact evidence",
        priority=102,
        role="post_exploit_worker",
        phase="data_access",
        source_finding_id="VXIS-0010",
        objective="Extract meaningful backend data or prove administrative data impact.",
        next_step="Dump users/auth tables or prove row-level data extraction.",
        crown_jewel="DB dump",
    )
    branch.attempts = 3
    branch.last_summary = "shell_exec exit=2 with no rows and no useful output"
    score = loop._branch_expected_yield_score(branch)
    assert score < 65


def test_forced_branch_action_prefers_test_idor_for_idor_branch():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    branch = loop.state.ensure_branch(
        "web:idor",
        "WEB-AC-001",
        "IDOR or broken access control",
        priority=90,
        role="exploit_worker",
    )
    action = loop._forced_branch_action(branch)
    assert action is not None
    assert action[1]["skill"] == "test_idor"


def test_best_skill_params_for_idor_carries_latest_auth_token():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.add_message("tool", {
        "name": "run_skill",
        "args": {"skill": "attempt_auth"},
        "result": {"ok": True, "data": {"authenticated": True, "token": "abc123token"}},
    })
    loop.state.add_message("tool", {
        "name": "run_skill",
        "args": {"skill": "enumerate_endpoints"},
        "result": {
            "ok": True,
            "data": {"accessible": [{"path": "/api/users/2", "status": 200, "size": 120}]},
        },
    })
    params = loop._best_skill_params("test_idor")
    assert params["url_pattern"].endswith("/api/users/{id}")
    assert params["token"] == "abc123token"
    assert params["max_id"] == 30


def test_best_skill_params_carries_multi_identity_authz_context():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.record_auth_identities(
        [
            {"name": "alice", "token": "tok-alice", "owned_ids": [1], "role": "user"},
            {"name": "bob", "token": "tok-bob", "owned_ids": [2], "role": "user"},
        ]
    )
    loop.state.add_message("tool", {
        "name": "run_skill",
        "args": {"skill": "enumerate_endpoints"},
        "result": {
            "ok": True,
            "data": {"accessible": [{"path": "/api/users/2", "status": 200, "size": 120}]},
        },
    })

    idor_params = loop._best_skill_params("test_idor")
    chain_params = loop._best_skill_params("execute_chain")

    assert idor_params["token"] == "tok-alice"
    assert idor_params["identities"][1]["name"] == "bob"
    assert idor_params["owner_map"] == {"1": "alice", "2": "bob"}
    assert chain_params["identities"][0]["token"] == "tok-alice"
    assert chain_params["owner_map"]["2"] == "bob"


def test_best_skill_params_for_business_logic_carries_captured_flows():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.add_message("tool", {
        "name": "intercept_proxy",
        "args": {"action": "view_request", "request_id": "req-1"},
        "result": {
            "ok": True,
            "data": {
                "id": "req-1",
                "method": "POST",
                "path": "/api/orders",
                "body": '{"sku":"A1","quantity":1,"price":19.99}',
            },
        },
    })

    params = loop._best_skill_params("test_business_logic")

    assert params["captured_flows"][0]["id"] == "req-1"
    assert params["captured_flows"][0]["path"] == "/api/orders"


def test_spawn_followup_branches_reuses_same_vector_for_same_finding():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.ensure_branch("web:sqli", "WEB-SQLI-001", "SQL injection", priority=95)
    loop.state.ensure_branch("web:auth-bypass", "WEB-AUTH-001", "Auth bypass", priority=95)
    args = {
        "finding_type": "sql_injection",
        "title": "Authentication bypass via sqli_bypass",
        "affected_component": "/rest/user/login",
        "severity": "critical",
    }
    loop._spawn_followup_branches_from_finding("VXIS-0002", args)
    loop._spawn_followup_branches_from_finding("VXIS-0002", {
        **args,
        "finding_type": "weak_auth",
    })
    pivots = [
        b for b in loop.state.branches.values()
        if b.source_finding_id == "VXIS-0002" and b.vector_id == "WEB-SQLI-PIVOT"
    ]
    assert len(pivots) == 1


def test_forced_branch_action_uses_http_fallback_after_shell_exec_exit_on_post_exploit():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    branch = loop.state.ensure_branch(
        "web:sqli:credential-pivot",
        "WEB-SQLI-PIVOT",
        "Harvest credentials or tokens from SQLi impact",
        priority=106,
        role="post_exploit_worker",
        phase="session_reuse",
        objective="Turn the injection into usable credentials, session material, or privilege context.",
        next_step="Dump users/auth tables or config values, then attempt login/session reuse with anything exposed.",
        crown_jewel="admin takeover or DB dump",
    )
    branch.last_tool = "shell_exec"
    branch.last_summary = "shell_exec: exit=7, stdout=0b, stderr=0b"
    action = loop._forced_branch_action(branch)
    assert action is not None
    assert action[0] == "http_request"
    assert action[1]["url"].endswith("/rest/user/whoami")


def test_off_branch_action_allowed_for_same_campaign_branch():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    focus = loop.state.ensure_branch(
        "web:sqli:credential-pivot",
        "WEB-SQLI-PIVOT",
        "Harvest credentials or tokens from SQLi impact",
        priority=106,
        role="post_exploit_worker",
        phase="session_reuse",
        source_finding_id="VXIS-0002",
        source_candidate_id="web:sqli",
    )
    sibling = loop.state.ensure_branch(
        "web:sqli:admin-access-control",
        "WEB-AC-PIVOT",
        "Probe admin-only access controls with the new session",
        priority=105,
        role="post_exploit_worker",
        phase="session_reuse",
        source_finding_id="VXIS-0002",
        source_candidate_id="web:sqli",
    )
    allowed = loop._should_allow_off_branch_action(
        focus,
        "http_request",
        {"url": "http://localhost:3000/admin"},
        [sibling.id],
        [],
    )
    assert allowed is True


def test_off_branch_action_allowed_for_high_value_cross_campaign_after_sqli_foothold():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.findings.append({
        "finding_type": "sql_injection",
        "title": "Authentication bypass via sqli_bypass",
        "affected_component": "/rest/user/login",
        "impact": "Authenticated foothold obtained.",
    })
    focus = loop.state.ensure_branch(
        "web:sqli:credential-pivot",
        "WEB-SQLI-PIVOT",
        "Harvest credentials or tokens from SQLi impact",
        priority=106,
        role="post_exploit_worker",
        phase="session_reuse",
        source_finding_id="VXIS-0002",
        source_candidate_id="web:sqli",
    )
    idor = loop.state.ensure_vector_candidate(
        "web:idor",
        "WEB-AC-001",
        "IDOR or broken access control",
        priority=90,
    )
    allowed = loop._should_allow_off_branch_action(
        focus,
        "run_skill",
        {"skill": "test_idor", "params": {"url_pattern": "http://localhost:3000/api/users/{id}"}},
        [],
        [idor.id],
    )
    assert allowed is True


def test_high_value_cross_campaign_exception_ignores_low_value_unrelated_campaign():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.findings.append({
        "finding_type": "sql_injection",
        "title": "Authentication bypass via sqli_bypass",
        "affected_component": "/rest/user/login",
    })
    focus = loop.state.ensure_branch(
        "web:sqli:credential-pivot",
        "WEB-SQLI-PIVOT",
        "Harvest credentials or tokens from SQLi impact",
        priority=106,
        role="post_exploit_worker",
        phase="session_reuse",
        source_finding_id="VXIS-0002",
        source_candidate_id="web:sqli",
    )
    generic = loop.state.ensure_vector_candidate(
        "web:dir-bruteforce",
        "WEB-RECON-001",
        "Hidden routes/directories",
        priority=82,
    )
    allowed = loop._is_high_value_cross_campaign_exception(
        focus,
        matched_branch_ids=[],
        matched_candidate_ids=[generic.id],
        capability_score=14,
    )
    assert allowed is False


def test_dag_finish_blocking_branches_dedupes_same_source_finding_same_phase():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    a = loop.state.ensure_branch(
        "web:sqli:credential-pivot",
        "WEB-SQLI-PIVOT",
        "Harvest credentials",
        priority=106,
        role="post_exploit_worker",
        phase="session_reuse",
        source_finding_id="VXIS-0002",
    )
    b = loop.state.ensure_branch(
        "web:sqli:admin-access-control",
        "WEB-AC-PIVOT",
        "Admin access controls",
        priority=105,
        role="post_exploit_worker",
        phase="session_reuse",
        source_finding_id="VXIS-0002",
    )
    c = loop.state.ensure_branch(
        "web:sqli:db-impact",
        "WEB-SQLI-IMPACT",
        "DB impact",
        priority=102,
        role="post_exploit_worker",
        phase="data_access",
        source_finding_id="VXIS-0002",
    )
    blockers = loop._dedupe_blocking_campaign_branches([a, b, c])
    assert [item.id for item in blockers] == [a.id, c.id]


def test_campaign_groups_for_ui_rolls_up_same_finding_campaign():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.ensure_branch(
        "web:sqli:credential-pivot",
        "WEB-SQLI-PIVOT",
        "Harvest credentials",
        priority=106,
        role="post_exploit_worker",
        phase="session_reuse",
        source_finding_id="VXIS-0002",
        objective="Turn foothold into credential reuse.",
        next_step="Probe /rest/user/whoami then admin APIs.",
        crown_jewel="admin takeover",
    )
    loop.state.ensure_branch(
        "web:sqli:db-impact",
        "WEB-SQLI-IMPACT",
        "DB impact",
        priority=102,
        role="post_exploit_worker",
        phase="data_access",
        source_finding_id="VXIS-0002",
        objective="Extract meaningful backend data.",
        next_step="Dump users/auth tables.",
        crown_jewel="DB dump",
    )
    groups = loop._campaign_groups_for_ui()
    assert groups
    assert groups[0]["source_finding_id"] == "VXIS-0002"
    assert groups[0]["branch_count"] >= 1


def test_focus_campaign_for_ui_includes_related_findings_and_reviews():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.ensure_branch(
        "web:sqli:db-impact",
        "WEB-SQLI-IMPACT",
        "DB impact",
        priority=102,
        role="post_exploit_worker",
        phase="data_access",
        source_finding_id="VXIS-0002",
        objective="Extract meaningful backend data.",
        next_step="Dump users/auth tables.",
        crown_jewel="DB dump",
    )
    loop.state.findings.append({
        "id": "VXIS-0002",
        "finding_type": "sql_injection",
        "severity": "critical",
        "title": "SQLI on q",
        "affected_component": "/rest/products/search?q=",
        "impact": "DB impact possible.",
    })
    loop.state.record_review_item(
        "verify:sqli:/rest/products/search?q=",
        stage="verifier",
        status="open",
        title="SQLI on q",
        reason="Need stronger DB transcript.",
        action_hint="Gather stronger DB transcript.",
        affected_component="/rest/products/search?q=",
        source_finding_type="sql_injection",
    )
    detail = loop._focus_campaign_for_ui()
    assert detail is not None
    assert detail["family"] == "injection"
    assert detail["findings"]
    assert detail["reviews"]


def test_branch_is_redundant_family_root_when_same_family_post_exploit_branch_exists():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    root = loop.state.ensure_branch(
        "web:sqli",
        "WEB-SQLI-001",
        "SQL injection toward DB/admin data",
        priority=95,
        role="post_exploit_worker",
    )
    root.attempts = 1
    loop.state.ensure_branch(
        "web:sqli:db-impact",
        "WEB-SQLI-IMPACT",
        "DB impact",
        priority=102,
        role="post_exploit_worker",
        phase="data_access",
        source_finding_id="VXIS-0002",
        objective="Extract meaningful backend data.",
        next_step="Dump users/auth tables.",
        crown_jewel="DB dump",
    )
    assert loop._branch_is_redundant_family_root(root) is True


def test_best_skill_params_rotates_xss_surface_after_recent_attempt():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    loop.state.add_message("tool", {
        "name": "run_skill",
        "args": {"skill": "enumerate_endpoints", "target_url": "http://localhost:3000"},
        "result": {
            "ok": True,
            "summary": "enumerated",
            "data": {
                "accessible": [
                    {"path": "/search?q=test", "status": 200, "size": 123},
                    {"path": "/redirect?next=/profile", "status": 200, "size": 123},
                ],
            },
        },
    })
    loop.state.add_message("tool", {
        "name": "run_skill",
        "args": {
            "skill": "test_xss",
            "target_url": "http://localhost:3000",
            "params": {"url": "http://localhost:3000/search?q=test"},
        },
        "result": {"ok": True, "summary": "clean", "data": {"vulnerable": False}},
    })
    params = loop._best_skill_params("test_xss")
    assert params["url"].endswith("/redirect?next=/profile")


def test_reroute_blocked_skill_retries_same_xss_skill_on_fresh_surface_before_pivot():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    loop.state.add_message("tool", {
        "name": "run_skill",
        "args": {"skill": "enumerate_endpoints", "target_url": "http://localhost:3000"},
        "result": {
            "ok": True,
            "summary": "enumerated",
            "data": {
                "accessible": [
                    {"path": "/search?q=test", "status": 200, "size": 123},
                    {"path": "/redirect?next=/profile", "status": 200, "size": 123},
                ],
            },
        },
    })
    for _ in range(3):
        loop.state.record_blocked_skill("test_xss")
    skill, params = loop._reroute_blocked_skill(
        "test_xss",
        {"url": "http://localhost:3000/search?q=test"},
    )
    assert skill == "test_xss"
    assert params["url"].endswith("/redirect?next=/profile")


def test_mark_family_probe_retryable_revives_xss_candidate():
    loop = ScanAgentLoop(target="http://localhost:3000", registry=ToolRegistry(), max_iters=3)
    candidate = loop.state.ensure_vector_candidate(
        "web:xss",
        "WEB-XSS-001",
        "XSS toward session theft",
        priority=70,
        evidence="initial seed",
    )
    candidate.status = "clean"
    loop._mark_family_probe_retryable(
        "test_xss",
        url="http://localhost:3000/search?q=test",
        round_num=1,
        tested_params=["q"],
    )
    assert loop.state.vector_candidates["web:xss"].status == "retryable"
    branch = loop.state.branches["web:xss"]
    assert branch.status == "retryable"
    assert "inconclusive at round 1" in loop.state.vector_candidates["web:xss"].last_summary.lower()


@pytest.mark.asyncio
async def test_suggested_replan_uses_remaining_family_candidate_when_branch_cannot_advance():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    reg.register(ReportFindingTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    branch = loop.state.ensure_branch(
        "web:auth-bypass:post-auth-enum",
        "WEB-AUTH-PIVOT",
        "Expand authenticated route coverage",
        priority=95,
        role="post_exploit_worker",
        phase="data_access",
        source_finding_id="VXIS-0001",
    )
    branch.attempts = 4
    for skill in ("attempt_auth", "post_auth_enum", "test_idor", "test_api_security", "test_business_logic", "test_sensitive_files"):
        for _ in range(3):
            loop.state.record_blocked_skill(skill)
    await reg.dispatch("report_finding", {
        "title": "Authentication bypass via sqli_bypass",
        "severity": "medium",
        "finding_type": "sql_injection",
        "affected_component": "/rest/user/login",
        "description": "auth foothold",
    })
    forced = loop._suggested_replan_action("unfinished_branches")
    assert forced is not None
    assert forced[0] == "run_skill"
    assert forced[1]["skill"] in {"test_injection", "test_xss", "test_ssrf", "enumerate_endpoints", "test_infra"}


@pytest.mark.asyncio
async def test_suggested_replan_prioritizes_retryable_family_candidate():
    reg = ToolRegistry()
    class _RunSkill:
        name = "run_skill"
        description = "run skill"
        input_schema = {"type": "object"}
        async def run(self, **kwargs):  # pragma: no cover - not executed
            return ToolResult(ok=True, summary="ok")
    reg.register(_RunSkill())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    retryable = loop.state.ensure_vector_candidate(
        "web:xss",
        "WEB-XSS-001",
        "XSS toward session theft",
        priority=70,
        evidence="needs stronger round on reflected surface",
    )
    retryable.status = "retryable"
    retryable.attempts = 1
    retryable.last_summary = "test_xss remained inconclusive at round 1; retry with stronger payload variant"
    loop.state.add_message("tool", {
        "name": "run_skill",
        "args": {"skill": "enumerate_endpoints", "target_url": "http://localhost:3000"},
        "result": {
            "ok": True,
            "summary": "enumerated",
            "data": {"accessible": [{"path": "/search?q=test", "status": 200, "size": 123}]},
        },
    })
    forced = loop._suggested_replan_action("unattempted_candidates")
    assert forced is not None
    assert forced[0] == "run_skill"
    assert forced[1]["skill"] == "test_xss"
    assert forced[1]["params"]["round"] == 2


def test_spawned_child_branch_promotes_to_post_exploit_role():
    reg = ToolRegistry()
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    parent = loop.state.ensure_branch(
        "web:sqli",
        "web:sqli",
        "SQL injection toward DB/admin data",
        role="exploit_worker",
    )
    loop._spawn_followup_branches_from_finding(
        "VXIS-0001",
        {
            "source_branch_id": parent.id,
            "finding_type": "sql_injection",
            "title": "SQL injection confirmed on search",
            "severity": "critical",
            "affected_component": "/rest/products/search?q=",
        },
    )
    children = [b for b in loop.state.branches.values() if b.parent_branch_id == parent.id]
    assert children
    assert any(child.role == "post_exploit_worker" for child in children)


def test_post_exploit_session_reuse_phase_blocks_premature_db_dump_action():
    reg = ToolRegistry()
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    branch = loop.state.ensure_branch(
        "auth:post-auth-enum",
        "WEB-AUTH-PIVOT",
        "Expand authenticated route coverage",
        role="post_exploit_worker",
        phase="session_reuse",
        objective="Use the obtained session to map authenticated APIs.",
        next_step="Reuse the live session with browser_get_cookies, then browse /admin.",
    )
    assert (
        loop._action_advances_focus_branch(
            branch,
            "shell_exec",
            {"command": "sqlmap -u http://localhost:3000/rest/products/search?q=test --dump"},
            [],
        )
        is False
    )


def test_post_exploit_phase_advances_from_session_reuse_to_privilege_probe():
    reg = ToolRegistry()
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    branch = loop.state.ensure_branch(
        "auth:post-auth-enum",
        "WEB-AUTH-PIVOT",
        "Expand authenticated route coverage",
        role="post_exploit_worker",
        phase="session_reuse",
        objective="Use the obtained session to map authenticated APIs.",
        next_step="Reuse the live session with browser_get_cookies, then browse /admin.",
    )
    loop.state.record_branch_attempt(
        branch.id,
        "browser_navigate",
        {"url": "http://localhost:3000/#/admin"},
        status="attempted",
        summary="navigated to /admin with authenticated session",
    )
    assert loop.state.branches[branch.id].phase == "privilege_probe"


def test_scan_dashboard_surfaces_memory_directives():
    reg = ToolRegistry()
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    for branch in loop.state.branches.values():
        branch.status = "blocked"
    loop.state.add_shared_note("memory: 2 prior scan(s) for this target.")
    loop.state.add_shared_note("memory strategy: first revalidate the strongest prior lead, then spend at least one branch on unexplored surface.")
    loop.state.add_shared_note("memory refuted: suppress weak error_oracle on /api/foo")
    loop.state.add_shared_note("memory branch: reopen Dump product table as p90 post_exploit_worker/data_access")
    loop.state.ensure_branch(
        "carry:branch-1",
        "WEB-SQLI-001",
        "Dump product table",
        priority=90,
        role="post_exploit_worker",
        phase="data_access",
        owner="memory",
        objective="Extract rows",
        next_step="Run sqlmap --dump",
        blocker="carry-over lead",
    )
    dashboard = loop._build_scan_dashboard()
    assert "Memory directives:" in dashboard
    assert "memory strategy:" in dashboard
    assert "memory branch:" in dashboard


@pytest.mark.asyncio
async def test_memory_refuted_pattern_blocks_repeated_run_skill_probe():
    reg = ToolRegistry()
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=2)
    loop._target_memory_profile = {
        "target_known": True,
        "refuted_patterns": [
            {
                "finding_type": "xss_reflected",
                "affected_component": "http://localhost:3000/#/search?q=test",
                "title": "Reflected XSS on search",
                "reasoning": "Prior replay only reflected inert text without executable context.",
            }
        ],
    }

    async def fake_decide(state):
        return [("run_skill", {
            "skill": "test_xss",
            "target_url": "http://localhost:3000",
            "params": {"url": "http://localhost:3000/#/search?q=test"},
        })]

    loop._decide = fake_decide  # type: ignore
    result = await loop.run()

    assert result["completed"] is False
    assert any(
        item["stage"] == "memory"
        and item["verdict"] == "SUPPRESSED"
        and item["blocked_action"] == "run_skill"
        for item in result["review_history"]
    )


@pytest.mark.asyncio
async def test_memory_success_tactic_hint_injected_for_matching_action():
    reg = ToolRegistry()
    reg.register(FinishTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=2)
    loop._target_memory_profile = {
        "target_known": True,
        "successful_tactics": [
            {
                "finding_type": "sql_injection",
                "affected_component": "http://localhost:3000/rest/products/search?q=",
                "title": "SQL injection on q",
            }
        ],
    }

    async def fake_decide(state):
        return [("run_skill", {
            "skill": "test_injection",
            "target_url": "http://localhost:3000",
            "params": {"url": "http://localhost:3000/rest/products/search?q=test", "param_name": "q"},
        })]

    loop._decide = fake_decide  # type: ignore
    await loop.run()

    assert any(
        isinstance(m.get("content"), dict)
        and "MEMORY TACTIC HINT" in str((m["content"]).get("hint", ""))
        for m in loop.state.messages
        if m.get("role") == "system"
    )


@pytest.mark.asyncio
async def test_direct_injection_promotion_skips_medium_noise():
    reg = ToolRegistry()
    reg.register(ReportFindingTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=2)

    original_dispatch = reg.dispatch
    captured: list[dict] = []

    async def capture_dispatch(name, args):
        if name == "report_finding":
            captured.append(dict(args))
        return await original_dispatch(name, args)

    reg.dispatch = AsyncMock(side_effect=capture_dispatch)  # type: ignore[method-assign]

    await loop._promote_direct_run_skill_result(
        "test_injection",
        {
            "url": "http://localhost:3000/rest/products/search?q=test",
            "param": "q",
            "findings": [
                {
                    "type": "xss",
                    "severity": "medium",
                    "payload": "<script>alert(1)</script>",
                    "control": {"baseline_status": 200, "payload_status": 200, "repeat_count": 2},
                    "response_preview": "payload reflected as inert text",
                },
                {
                    "type": "sql_injection",
                    "severity": "critical",
                    "payload": "' OR 1=1--",
                    "control": {"baseline_status": 200, "payload_status": 200, "repeat_count": 2},
                    "response_preview": "database error and altered response",
                },
            ],
        },
    )

    assert len(captured) == 1
    assert captured[0]["finding_type"] == "sql_injection"


@pytest.mark.asyncio
async def test_direct_promotion_requires_confirmed_verifier_for_high_signal():
    reg = ToolRegistry()
    reg.register(ReportFindingTool())
    reg.register(VerifyTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=2)

    original_dispatch = reg.dispatch
    captured: list[dict] = []

    async def capture_dispatch(name, args):
        if name == "report_finding":
            captured.append(dict(args))
        return await original_dispatch(name, args)

    reg.dispatch = AsyncMock(side_effect=capture_dispatch)  # type: ignore[method-assign]

    await loop._promote_direct_run_skill_result(
        "test_injection",
        {
            "url": "http://localhost:3000/rest/products/search?q=test",
            "param": "q",
            "findings": [
                {
                    "type": "sql_injection",
                    "severity": "critical",
                    "payload": "' OR 1=1--",
                    "control": {"baseline_status": 200, "payload_status": 200, "repeat_count": 2},
                    "response_preview": "database error and altered response",
                },
            ],
        },
    )

    assert captured == []
    assert loop.state.verdict_counts["UNCONFIRMED"] == 1


@pytest.mark.asyncio
async def test_scan_loop_runs_to_finish(monkeypatch):
    """Brain reports a finding, then completes via finish_scan past min_iters.

    History: assertion was `call_count == 1` before the early-finish guard
    (commit d47fd36) added the `iter < min_iters` rejection, then the Q11
    `0 findings` rejection further raised the bar — finish_scan only
    succeeds when there is at least one finding in the store AND iter has
    cleared min_iters (= max_iters // 2).
    """
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())

    call_count = {"n": 0}

    async def fake_decide(state):
        call_count["n"] += 1
        # First decision drops a finding so Q11's 0-finding gate clears.
        if call_count["n"] == 1:
            return [("report_finding", {
                "title": "stub finding",
                "severity": "low",
                "finding_type": "test_stub",
                "affected_component": "/x",
                "description": "evidence of nothing — fixture only",
            })]
        return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost", registry=reg, max_iters=10)
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()
    assert result["completed"] is True
    assert call_count["n"] >= 5
    assert len(loop.state.messages) >= 2  # system + user + tool result


def test_retrieval_observation_sanitizes_binary_samples():
    reg = ToolRegistry()
    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=2)
    loop.state.record_retrieval_observation(
        finding_type="information_disclosure",
        component="/ftp/",
        retrieval_kind="sensitive_file",
        summary="binary sample",
        sample="\x00ABC\x01\x02",
    )
    sample = loop.state.retrieval_observations_as_dicts()[0]["sample"]
    assert "\x00" not in sample
    assert "\\x00ABC\\x01\\x02" in sample

@pytest.mark.asyncio
async def test_scan_loop_respects_max_iters():
    reg = ToolRegistry()
    loop = ScanAgentLoop(target="http://localhost", registry=reg, max_iters=3)
    async def never_finish(state):
        return [("nonexistent_tool", {})]
    loop._decide = never_finish  # type: ignore
    result = await loop.run()
    assert result["completed"] is False
    assert loop.state.iteration == 3


@pytest.mark.asyncio
async def test_finish_scan_rejected_when_two_findings_have_no_chain():
    """Two findings are enough to require at least one crown-jewel chain."""
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())

    decisions = iter([
        [("report_finding", {
            "title": "first finding",
            "severity": "medium",
            "finding_type": "information_disclosure",
            "affected_component": "/debug",
            "description": "debug endpoint exposed",
        })],
        [("report_finding", {
            "title": "second finding",
            "severity": "medium",
            "finding_type": "weak_auth",
            "affected_component": "/login",
            "description": "weak authentication evidence",
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            for branch in state.branches.values():
                branch.status = "blocked"
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost", registry=reg, max_iters=8)
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()

    chain_rejections = [
        m for m in loop.state.messages
        if m.get("role") == "tool"
        and isinstance(m.get("content"), dict)
        and (m["content"].get("result") or {}).get("data", {}).get("needs_chains")
    ]
    assert chain_rejections, "finish_scan must be rejected until the two findings are chained"
    assert any(
        item["stage"] == "judge" and item["title"] == "needs_chains"
        for item in result["review_queue"]
    )


@pytest.mark.asyncio
async def test_unconfirmed_verifier_result_is_kept_in_review_queue():
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())
    reg.register(VerifyTool())

    decisions = iter([
        [("report_finding", {
            "title": "Auth bypass on login",
            "severity": "high",
            "finding_type": "auth_bypass",
            "affected_component": "/login",
            "description": "Forged token accepted by login flow.",
            "impact": "Attacker gains authenticated access.",
            "technical_analysis": "The forged token was accepted and returned a session cookie, but the control pair is still missing.",
            "poc_description": "Send the forged token and observe the session response.",
            "poc_script_code": "POST /login HTTP/1.1\\nHost: example\\nAuthorization: Bearer forged\\n\\nHTTP/1.1 200 OK\\nSet-Cookie: session=abc",
            "remediation_steps": "Reject forged tokens and validate signatures.",
            "evidence": "HTTP/1.1 200 OK\\nSet-Cookie: session=abc",
        })],
        [("finish_scan", {})],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=5)
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()

    assert any(
        item["stage"] == "verifier"
        and item["status"] == "open"
        and item["title"] == "Auth bypass on login"
        for item in result["review_queue"]
    )
    assert any(
        item["stage"] == "verifier"
        and item["verdict"] == "UNCONFIRMED"
        and item["blocked_action"] == ""
        for item in result["review_history"]
    )


@pytest.mark.asyncio
async def test_short_smoke_can_finish_after_single_high_finding_once_branch_guard_expires():
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())
    reg.register(ReplayHttpTool())

    decisions = iter([
        [("report_finding", {
            "title": "reflected xss",
            "severity": "high",
            "finding_type": "xss_reflected",
            "affected_component": "/search?q=test",
            "description": "script payload reflected",
            "impact": "Attacker can execute script in the victim browser and act in their session context.",
            "technical_analysis": "Negative control baseline was not reflected as markup; payload reflection reproduced twice. repeat_count=2",
            "poc_description": "Replay a benign search, then inject an HTML payload twice and observe reflected execution content.",
            "poc_script_code": "GET /search?q=test HTTP/1.1\\nHost: example\\n\\nHTTP/1.1 200\\n\\nnegative control: search:test not reflected\\n\\nGET /search?q=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1\\nHost: example\\n\\nHTTP/1.1 200\\n\\nsearch:<img src=x onerror=alert(1)>\\n\\nrepeat_count=2\\nGET /search?q=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1\\nHost: example\\n\\nHTTP/1.1 200\\n\\nsearch:<img src=x onerror=alert(1)>",
            "response_or_effect": "search:<img src=x onerror=alert(1)>",
            "control_comparison": "GET /search?q=test HTTP/1.1\\nHost: example\\n\\nsearch:test",
            "request_or_payload": "GET /search?q=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1\\nHost: example",
            "remediation_steps": "Apply output encoding and context-aware templating.",
            "verifier_verdict": "CONFIRMED",
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=4)
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()

    assert result["completed"] is True


@pytest.mark.asyncio
async def test_finish_scan_rejected_when_high_finding_lacks_machine_replay_gate():
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())

    decisions = iter([
        [("report_finding", {
            "title": "reflected xss",
            "severity": "high",
            "finding_type": "xss_reflected",
            "affected_component": "/search?q=test",
            "description": "script payload reflected",
            "impact": "Attacker can execute script in the victim browser and act in their session context.",
            "technical_analysis": "Negative control baseline was not reflected as markup; payload reflection reproduced twice. repeat_count=2",
            "poc_description": "Replay a benign search, then inject an HTML payload twice and observe reflected execution content.",
            "poc_script_code": "GET /search?q=test HTTP/1.1\\nHost: example\\n\\nHTTP/1.1 200\\n\\nnegative control: search:test not reflected\\n\\nGET /search?q=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1\\nHost: example\\n\\nHTTP/1.1 200\\n\\nsearch:<img src=x onerror=alert(1)>\\n\\nrepeat_count=2\\nGET /search?q=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1\\nHost: example\\n\\nHTTP/1.1 200\\n\\nsearch:<img src=x onerror=alert(1)>",
            "remediation_steps": "Apply output encoding and context-aware templating.",
            "verifier_verdict": "CONFIRMED",
            "replay_gate": {"status": "passed", "method": "brain_attested"},
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=4)
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()

    assert result["completed"] is False
    assert any(
        item["stage"] == "judge" and item["title"] == "needs_replay_gate"
        for item in result["review_queue"]
    )


@pytest.mark.asyncio
async def test_non_web_high_finding_uses_verifier_replay_gate_not_http_replay():
    from vxis.agent.tools.finding_tools import _get_findings

    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())
    reg.register(ConfirmingVerifyTool())

    decisions = iter([
        [("report_finding", {
            "title": "Local secret exposed",
            "severity": "high",
            "finding_type": "information_disclosure",
            "affected_component": "/tmp/App.app/Contents/Resources/config.json",
            "description": "Bundled app config exposes a credential.",
            "impact": "Credential material can be extracted from the local app bundle.",
            "technical_analysis": "Control file has no secret; target config contains api_key=abc. repeat_count=2. Negative result: clean control has no api_key.",
            "poc_description": "Read the bundled config and compare it to a clean control file twice.",
            "poc_script_code": (
                "PAYLOAD: cat /tmp/App.app/Contents/Resources/config.json -> api_key=abc\n"
                "CONTROL: cat /tmp/clean-config.json -> no api_key\n"
                "repeat_count=2\n"
                "NEGATIVE_RESULT: clean control did not expose api_key"
            ),
            "request_or_payload": "cat /tmp/App.app/Contents/Resources/config.json",
            "response_or_effect": "response_excerpt: api_key=abc",
            "control_comparison": "control_result: /tmp/clean-config.json contains no api_key",
            "replay_command": "cat /tmp/App.app/Contents/Resources/config.json",
            "remediation_steps": "Remove secrets from bundled resources.",
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(
        target="/Applications/Fake.app",
        registry=reg,
        max_iters=4,
        target_kind="desktop",
    )
    loop._decide = fake_decide  # type: ignore
    loop._run_scheduled_skills = AsyncMock(return_value=None)  # type: ignore[method-assign]
    await loop.run()

    findings = _get_findings()
    assert findings
    assert findings[0]["acceptance_status"] == "accepted"
    assert findings[0]["replay_gate"]["method"] == "verifier_confirmed_non_web"


@pytest.mark.asyncio
async def test_auto_chain_links_information_disclosure_to_weak_auth():
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())
    reg.register(LinkChainTool())

    decisions = iter([
        [("report_finding", {
            "title": "debug config leak",
            "severity": "low",
            "finding_type": "information_disclosure",
            "affected_component": "/debug",
            "description": "debug endpoint exposed stack details and default credential hint admin@juice-sh.op/admin123",
            "evidence": "GET /debug -> default credential path /rest/user/login admin@juice-sh.op/admin123",
        })],
        [("report_finding", {
            "title": "default admin credentials",
            "severity": "high",
            "finding_type": "default_credentials",
            "affected_component": "/login",
            "description": "admin:admin works",
            "impact": "Attacker gains an authenticated foothold as a privileged user.",
            "technical_analysis": "Negative control invalid credentials returned 401; debug-disclosed admin@juice-sh.op/admin123 succeeded twice. repeat_count=2",
            "poc_description": "Attempt invalid credentials, then the documented default credentials twice and compare authentication responses.",
            "poc_script_code": "POST /rest/user/login HTTP/1.1\\nHost: example\\nContent-Type: application/json\\n\\n{\"email\":\"bad@example\",\"password\":\"bad\"}\\n\\nHTTP/1.1 401 Unauthorized\\n\\nnegative control\\n\\nPOST /rest/user/login HTTP/1.1\\nHost: example\\nContent-Type: application/json\\n\\n{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}\\n\\nHTTP/1.1 200\\n\\n{\"authentication\":{\"token\":\"...\"}}\\n\\nrepeat_count=2\\nPOST /rest/user/login HTTP/1.1\\nHost: example\\nContent-Type: application/json\\n\\n{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}\\n\\nHTTP/1.1 200\\n\\n{\"authentication\":{\"token\":\"...\"}}",
            "remediation_steps": "Disable default accounts and enforce unique bootstrap secrets.",
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=5)
    loop._decide = fake_decide  # type: ignore
    await loop.run()

    chains = _get_chains()
    assert any(c.get("finding_ids") == ["VXIS-0001", "VXIS-0002"] for c in chains)


@pytest.mark.asyncio
async def test_vector_candidates_record_attempt_outcomes_for_brain_tools():
    reg = ToolRegistry()
    reg.register(FinishTool())

    class ShellTool:
        name = "shell_exec"
        description = "shell"
        input_schema = {"type": "object"}

        async def run(self, **kwargs) -> ToolResult:
            return ToolResult(
                ok=True,
                summary="sqlmap confirmed SQL injection",
                data={"stdout": "parameter q is vulnerable"},
            )

    reg.register(ShellTool())

    decisions = iter([
        [("shell_exec", {"command": "sqlmap -u http://localhost:3000/rest/products/search?q=test --batch"})],
        [("finish_scan", {})],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=3)
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()

    outcomes = result["attempt_outcomes"]
    assert any(o["candidate_id"] == "web:sqli" and o["status"] == "found" for o in outcomes)
    candidates = {c["id"]: c for c in result["vector_candidates"]}
    assert candidates["web:sqli"]["attempts"] >= 1
    assert candidates["web:sqli"]["status"] == "found"


@pytest.mark.asyncio
async def test_execution_monitor_escalates_repeated_no_progress_action():
    reg = ToolRegistry()
    reg.register(FinishTool())

    class HttpRequestTool:
        name = "http_request"
        description = "http"
        input_schema = {"type": "object"}

        async def run(self, **kwargs) -> ToolResult:
            return ToolResult(ok=True, summary="HTTP 404 unchanged", data={"status": 404})

    reg.register(HttpRequestTool())

    decisions = iter([
        [("http_request", {"url": "http://localhost:3000/health"})],
        [("http_request", {"url": "http://localhost:3000/health"})],
        [("finish_scan", {})],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=3,
        brain=SimpleNamespace(_provider="ollama", _model="qwen-30b"),
    )
    loop._focus_branch = lambda: None  # type: ignore[method-assign]
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()

    assert any(
        item["stage"] == "monitor"
        and item["status"] == "escalated"
        and item["title"] == "repeated_action_no_progress"
        for item in result["review_queue"]
    )
    assert any("monitor: repeated http_request" in note for note in result["shared_notes"])
    assert any(
        isinstance(message.get("content"), dict)
        and "EXECUTION MONITOR" in str(message["content"].get("hint", ""))
        for message in loop.state.messages
    )


@pytest.mark.asyncio
async def test_execution_monitor_resets_after_progress():
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())

    class HttpRequestTool:
        name = "http_request"
        description = "http"
        input_schema = {"type": "object"}

        async def run(self, **kwargs) -> ToolResult:
            return ToolResult(ok=True, summary="HTTP 404 unchanged", data={"status": 404})

    reg.register(HttpRequestTool())

    decisions = iter([
        [("http_request", {"url": "http://localhost:3000/health"})],
        [("report_finding", {
            "title": "Debug endpoint exposes version",
            "severity": "medium",
            "finding_type": "information_disclosure",
            "affected_component": "/debug",
            "description": "Debug endpoint leaks build metadata.",
            "evidence": "GET /debug -> 200 OK build=dev",
        })],
        [("http_request", {"url": "http://localhost:3000/health"})],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=3,
        brain=SimpleNamespace(_provider="ollama", _model="qwen-30b"),
    )
    loop._focus_branch = lambda: None  # type: ignore[method-assign]
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()

    assert not any(item["stage"] == "monitor" for item in result["review_queue"])


@pytest.mark.asyncio
async def test_global_no_progress_halts_varied_low_value_actions():
    reg = ToolRegistry()
    reg.register(FinishTool())

    class HttpRequestTool:
        name = "http_request"
        description = "http"
        input_schema = {"type": "object"}

        async def run(self, **kwargs) -> ToolResult:
            return ToolResult(ok=True, summary="HTTP 404 unchanged", data={"status": 404})

    reg.register(HttpRequestTool())

    counter = {"n": 0}

    async def fake_decide(state):
        counter["n"] += 1
        return [("http_request", {"url": f"http://localhost:3000/noop-{counter['n']}"})]

    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=40,
        brain=SimpleNamespace(_provider="ollama", _model="qwen-30b"),
    )
    loop._focus_branch = lambda: None  # type: ignore[method-assign]
    loop._decide = fake_decide  # type: ignore
    loop._run_scheduled_skills = AsyncMock(return_value=None)  # type: ignore[method-assign]
    loop._run_auto_orchestration = AsyncMock(return_value=(False, False, False))  # type: ignore[method-assign]
    loop._maybe_execute_director_action = AsyncMock(return_value=None)  # type: ignore[method-assign]

    result = await loop.run()

    assert result["completed"] is False
    assert result["iterations"] < loop.state.max_iters
    assert any(
        item["stage"] == "monitor"
        and item["verdict"] == "HALTED"
        and item["title"] == "global_no_progress"
        for item in result["review_history"]
    )
    assert any(
        isinstance(message.get("content"), dict)
        and "GLOBAL NO-PROGRESS HALT" in str(message["content"].get("hint", ""))
        for message in loop.state.messages
    )


@pytest.mark.asyncio
async def test_authenticated_401_requeues_attempt_auth_once():
    reg = ToolRegistry()
    reg.register(FinishTool())
    run_skill = RunSkillTool()
    reg.register(run_skill)

    class HttpRequestTool:
        name = "http_request"
        description = "http"
        input_schema = {"type": "object"}

        async def run(self, **kwargs) -> ToolResult:
            return ToolResult(ok=True, summary="HTTP 401 login required", data={"status": 401})

    reg.register(HttpRequestTool())

    decisions = iter([
        [("http_request", {"url": "http://localhost:3000/api/me"})],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=4)
    loop.state.record_auth_identities([{"name": "alice", "token": "tok"}])
    loop._decide = fake_decide  # type: ignore
    loop._run_auto_orchestration = AsyncMock(return_value=(False, False, False))  # type: ignore[method-assign]
    loop._maybe_execute_director_action = AsyncMock(return_value=None)  # type: ignore[method-assign]

    await loop.run()

    assert any(call.get("skill") == "attempt_auth" for call in run_skill.calls)
    assert any(
        isinstance(message.get("content"), dict)
        and "AUTH SESSION CHECK" in str(message["content"].get("hint", ""))
        for message in loop.state.messages
    )


@pytest.mark.asyncio
async def test_finish_scan_rejected_when_high_priority_candidates_unattempted():
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())

    decisions = iter([
        [("report_finding", {
            "title": "one finding",
            "severity": "low",
            "finding_type": "information_disclosure",
            "affected_component": "/debug",
            "description": "debug endpoint exposed",
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=30)
    loop._decide = fake_decide  # type: ignore
    loop._dag_finish_blocking_branches = lambda: []  # type: ignore[method-assign]
    result = await loop.run()

    assert result["completed"] is False
    candidate_rejections = [
        m for m in loop.state.messages
        if m.get("role") == "tool"
        and isinstance(m.get("content"), dict)
        and (m["content"].get("result") or {}).get("data", {}).get("unresolved_vector_candidates")
    ]
    assert candidate_rejections
    assert any(
        item["stage"] == "judge"
        and item["verdict"] == "REJECTED"
        and item["blocked_action"] == "finish_scan"
        and item["title"] == "unattempted_candidates"
        for item in result["review_history"]
    )


@pytest.mark.asyncio
async def test_memory_refuted_pattern_suppresses_repeat_report_finding():
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())

    decisions = iter([
        [("report_finding", {
            "title": "HTTP 500 on /api/foo",
            "severity": "medium",
            "finding_type": "error_oracle",
            "affected_component": "/api/foo",
            "description": "generic 500 page",
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=2)
    loop._target_memory_profile = {
        "target_known": True,
        "refuted_patterns": [
            {
                "finding_type": "error_oracle",
                "affected_component": "/api/foo",
            }
        ],
    }
    loop._decide = fake_decide  # type: ignore
    result = await loop.run()

    assert any(
        item["stage"] == "memory"
        and item["verdict"] == "SUPPRESSED"
        and item["blocked_action"] == "report_finding"
        for item in result["review_history"]
    )


@pytest.mark.asyncio
async def test_repeated_finish_unattempted_candidates_suggests_brain_replan():
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())
    run_skill = RunSkillTool()
    reg.register(run_skill)

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=35)
    loop.state.vector_candidates["web:auth-bypass"] = VectorCandidate(
        id="web:auth-bypass",
        vector_id="web:auth-bypass",
        title="Authentication bypass or weak login",
        priority=95,
        evidence="login form exposed",
    )

    decisions = iter([
        [("report_finding", {
            "title": "seed finding",
            "severity": "low",
            "finding_type": "information_disclosure",
            "affected_component": "/debug",
            "description": "seed finding",
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop._decide = fake_decide  # type: ignore
    loop._dag_finish_blocking_branches = lambda: []  # type: ignore[method-assign]
    loop._run_scheduled_skills = AsyncMock(return_value=None)  # type: ignore[method-assign]
    result = await loop.run()

    assert not run_skill.calls
    assert result["completed"] is False
    assert result["iterations"] < loop.state.max_iters
    assert any(
        isinstance(m.get("content"), dict)
        and ((m["content"].get("result") or {}).get("data") or {}).get("suggested_action")
        for m in loop.state.messages
        if m.get("role") == "tool" and isinstance(m.get("content"), dict) and m["content"].get("name") == "finish_scan"
    )
    assert any(
        item["stage"] == "judge"
        and item["verdict"] == "HALTED"
        and item["title"] == "judge_replan_ignored"
        for item in result["review_history"]
    )
    assert any(
        isinstance(m.get("content"), dict)
        and ((m["content"].get("result") or {}).get("data") or {}).get("judge_replan_halt")
        for m in loop.state.messages
        if m.get("role") == "tool" and isinstance(m.get("content"), dict) and m["content"].get("name") == "finish_scan"
    )


@pytest.mark.asyncio
async def test_repeated_finish_unfinished_branches_suggests_post_auth_replan():
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())
    run_skill = RunSkillTool()
    reg.register(run_skill)

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=60)
    loop.state.ensure_branch(
        "web:auth-bypass:post-auth-enum",
        "WEB-AUTH-PIVOT",
        "Expand authenticated route coverage",
        priority=95,
        role="post_exploit_worker",
        phase="data_access",
        objective="Use the obtained session to enumerate authenticated data-bearing routes.",
        next_step="Probe /api/profile and admin routes with the authenticated session.",
        crown_jewel="authenticated data exfiltration",
    )

    decisions = iter([
        [("report_finding", {
            "title": "seed finding",
            "severity": "low",
            "finding_type": "information_disclosure",
            "affected_component": "/debug",
            "description": "seed finding",
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop._decide = fake_decide  # type: ignore
    loop._run_scheduled_skills = AsyncMock(return_value=None)  # type: ignore[method-assign]
    result = await loop.run()

    assert result["completed"] is False
    assert result["iterations"] < loop.state.max_iters
    assert not run_skill.calls
    assert any(
        item["stage"] == "judge"
        and item["blocked_action"] == "finish_scan"
        and item["title"] == "unfinished_branches"
        for item in result["review_history"]
    )
    assert any(
        isinstance(m.get("content"), dict)
        and ((m["content"].get("result") or {}).get("data") or {}).get("suggested_action")
        for m in loop.state.messages
        if m.get("role") == "tool" and isinstance(m.get("content"), dict) and m["content"].get("name") == "finish_scan"
    )
    assert any(
        item["stage"] == "judge"
        and item["verdict"] == "HALTED"
        and item["title"] == "judge_replan_ignored"
        for item in result["review_history"]
    )


@pytest.mark.asyncio
async def test_repeated_finish_alternating_rejections_halts_title_agnostic():
    class FailingFinishTool:
        name = "finish_scan"
        description = "finish"
        input_schema = {"type": "object"}

        async def run(self, **kwargs) -> ToolResult:
            return ToolResult(ok=False, summary="not finished")

    reg = ToolRegistry()
    reg.register(FailingFinishTool())
    reg.register(ReportFindingTool())

    decisions = iter([
        [("report_finding", {
            "title": "seed finding",
            "severity": "low",
            "finding_type": "information_disclosure",
            "affected_component": "/debug",
            "description": "seed finding",
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=8)
    loop.state.record_review_decision(
        stage="judge",
        verdict="REJECTED",
        title="needs_replay_gate",
        reason="seed",
        blocked_action="finish_scan",
    )
    loop.state.record_review_decision(
        stage="judge",
        verdict="REJECTED",
        title="unfinished_branches",
        reason="seed",
        blocked_action="finish_scan",
    )
    loop._decide = fake_decide  # type: ignore
    loop._dag_finish_blocking_branches = lambda: []  # type: ignore[method-assign]
    loop._run_scheduled_skills = AsyncMock(return_value=None)  # type: ignore[method-assign]

    result = await loop.run()

    assert result["completed"] is False
    assert result["iterations"] < loop.state.max_iters
    assert any(
        item["stage"] == "judge"
        and item["verdict"] == "HALTED"
        and item["title"] == "judge_replan_ignored"
        for item in result["review_history"]
    )
    assert any(
        isinstance(m.get("content"), dict)
        and ((m["content"].get("result") or {}).get("data") or {}).get(
            "finish_rejection_streak"
        )
        for m in loop.state.messages
        if m.get("role") == "tool"
        and isinstance(m.get("content"), dict)
        and m["content"].get("name") == "finish_scan"
    )


@pytest.mark.asyncio
async def test_finish_gate_exception_fails_closed():
    reg = ToolRegistry()
    reg.register(FinishTool())
    reg.register(ReportFindingTool())

    decisions = iter([
        [("report_finding", {
            "title": "seed finding",
            "severity": "low",
            "finding_type": "information_disclosure",
            "affected_component": "/debug",
            "description": "seed finding",
        })],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=4)
    loop._decide = fake_decide  # type: ignore
    loop._desired_chain_count = lambda _findings: (_ for _ in ()).throw(RuntimeError("boom"))  # type: ignore[method-assign]
    loop._run_scheduled_skills = AsyncMock(return_value=None)  # type: ignore[method-assign]

    result = await loop.run()

    assert result["completed"] is False
    assert any(
        item["stage"] == "judge"
        and item["blocked_action"] == "finish_scan"
        and item["title"] == "finish_gate_error"
        for item in result["review_history"]
    )


@pytest.mark.asyncio
async def test_memory_priority_hint_injected_when_early_action_ignores_prior_leads():
    reg = ToolRegistry()
    reg.register(FinishTool())

    class QueryTool:
        name = "query_findings"
        description = "query"
        input_schema = {"type": "object"}

        async def run(self, **kwargs) -> ToolResult:
            return ToolResult(ok=True, summary="query ok", data={})

    reg.register(QueryTool())

    decisions = iter([
        [("query_findings", {"text_contains": "random"})],
        [("finish_scan", {})],
    ])

    async def fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop = ScanAgentLoop(target="http://localhost:3000", registry=reg, max_iters=2)
    loop._target_memory_profile = {
        "target_known": True,
        "known_findings": [{"finding_type": "sql_injection", "affected_component": "/rest/products/search?q="}],
        "branch_leads": [{"id": "branch-1"}],
    }
    loop._decide = fake_decide  # type: ignore
    await loop.run()

    assert any(
        isinstance(m.get("content"), dict)
        and "MEMORY PRIORITY HINT" in str(m["content"].get("hint", ""))
        for m in loop.state.messages
    )
