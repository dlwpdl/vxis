import pytest

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry
from vxis.agent.tool_registry import ToolResult
from vxis.agent.tools.finding_tools import (
    ReportFindingTool,
    _get_findings,
    _reset_for_tests as _reset_findings,
)
from vxis.interaction.surface import TargetKind


class RunSkillTool:
    name = "run_skill"
    description = "execute prebuilt skill"
    input_schema = {"type": "object"}


class VerifyFindingToolStub:
    name = "verify_finding"
    description = "verify finding"
    input_schema = {"type": "object"}

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(
            ok=True,
            summary="verify_finding: CONFIRMED (high)",
            data={
                "verdict": "CONFIRMED",
                "confidence": "high",
                "reasoning": "stub reason",
            },
        )


@pytest.fixture(autouse=True)
def _isolate_findings():
    _reset_findings()
    yield
    _reset_findings()


@pytest.mark.asyncio
async def test_chain_nudge_reinjects_when_findings_outpace_chains():
    registry = ToolRegistry()
    registry.register(ReportFindingTool())
    loop = ScanAgentLoop(target="http://localhost:3000", registry=registry, max_iters=40)

    for title, finding_type, component in [
        ("SQL injection on search", "sql_injection", "/search"),
        ("Admin panel exposed", "broken_access_control", "/admin"),
        ("User export leaks data", "information_disclosure", "/api/export"),
    ]:
        result = await registry.dispatch(
            "report_finding",
            {
                "title": title,
                "severity": "medium",
                "finding_type": finding_type,
                "affected_component": component,
                "description": title,
            },
        )
        assert result.ok

    loop.state.iteration = 18
    loop._maybe_inject_chain_nudge()

    assert loop.state.messages
    nudge = loop.state.messages[-1]
    assert nudge["role"] == "user"
    assert "CHAIN ANALYSIS PHASE" in nudge["content"]
    assert "link_chain" in nudge["content"]
    assert "SQL injection on search" in nudge["content"]

    message_count = len(loop.state.messages)
    loop._maybe_inject_chain_nudge()
    assert len(loop.state.messages) == message_count

    loop.state.iteration = 23
    loop._maybe_inject_chain_nudge()
    assert len(loop.state.messages) == message_count


def test_skill_sweep_queues_untried_web_skills_with_surface_filter():
    registry = ToolRegistry()
    registry.register(RunSkillTool())
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=registry,
        max_iters=60,
        target_kind=TargetKind.WEB,
    )
    loop.state.iteration = 25
    queued: list[tuple[str, int, dict, str | None]] = []

    def queue_skill(
        skill: str,
        trigger_iter: int,
        params: dict,
        *,
        alias: str | None = None,
    ) -> bool:
        queued.append((skill, trigger_iter, dict(params), alias))
        return True

    loop._maybe_queue_skill_sweep(
        target_kind_cls=TargetKind,
        real_skills_completed=set(),
        auth_token="token-123",
        queue_skill=queue_skill,
    )

    assert queued
    assert all(trigger_iter == 26 for _, trigger_iter, _, _ in queued)
    assert all(alias and alias.endswith("__sweep25") for _, _, _, alias in queued)
    assert all(params.get("_skill_override") == skill for skill, _, params, _ in queued)
    assert "test_macos_entitlements" not in {skill for skill, _, _, _ in queued}
    assert [params["url"] for skill, _, params, _ in queued if skill == "test_ssrf"] == [
        "http://localhost:3000/proxy?url=http://example.com"
    ]
    assert loop.state.messages[-1]["role"] == "user"
    assert "SKILL SWEEP at iter 25" in loop.state.messages[-1]["content"]

    message_count = len(loop.state.messages)
    loop._maybe_queue_skill_sweep(
        target_kind_cls=TargetKind,
        real_skills_completed=set(),
        auth_token="token-123",
        queue_skill=queue_skill,
    )
    assert len(loop.state.messages) == message_count


@pytest.mark.asyncio
async def test_enumerate_endpoints_queues_multiple_query_surfaces():
    class _RunSkill:
        name = "run_skill"
        description = "execute prebuilt skill"
        input_schema = {"type": "object"}

        async def run(self, **kwargs):
            assert kwargs["skill"] == "enumerate_endpoints"
            return ToolResult(
                ok=True,
                summary="enumerated",
                data={
                    "accessible": [
                        {"path": "/rest/products/search?q=", "status": 200, "size": 111},
                        {"path": "/redirect?next=/profile", "status": 200, "size": 90},
                        {"path": "/rest/products/search?q=", "status": 200, "size": 111},
                        {"path": "/api/Users/1", "status": 200, "size": 70},
                        {"path": "/proxy?url=http://example.com", "status": 200, "size": 88},
                    ],
                    "errors": [],
                },
            )

    registry = ToolRegistry()
    registry.register(_RunSkill())
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=registry,
        max_iters=20,
        target_kind=TargetKind.WEB,
    )
    loop.state.iteration = 3
    queued: list[tuple[str, int, dict, str | None]] = []

    def queue_skill(
        skill: str,
        trigger_iter: int,
        params: dict,
        *,
        alias: str | None = None,
    ) -> bool:
        queued.append((skill, trigger_iter, dict(params), alias))
        return True

    await loop._run_scheduled_skills(
        target_kind_cls=TargetKind,
        skill_sequence=[("enumerate_endpoints", 3, {})],
        skills_completed=set(),
        real_skills_completed=set(),
        queue_skill=queue_skill,
        auth_token=None,
    )

    assert len(queued) == 10
    assert [params["url"] for skill, _, params, _ in queued if skill == "test_injection"] == [
        "http://localhost:3000/rest/products/search?q=",
        "http://localhost:3000/redirect?next=/profile",
        "http://localhost:3000/proxy?url=http://example.com",
    ]
    assert [alias for _, _, _, alias in queued] == [
        "test_injection__recon1",
        "test_xss__recon1",
        "test_ssrf__recon1",
        "test_injection__recon2",
        "test_xss__recon2",
        "test_ssrf__recon2",
        "test_injection__recon3",
        "test_xss__recon3",
        "test_ssrf__recon3",
        "test_idor_1",
    ]


@pytest.mark.asyncio
async def test_enumerate_endpoints_handoff_reports_only_actionable_errors():
    registry = ToolRegistry()
    registry.register(ReportFindingTool())
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=registry,
        max_iters=20,
        target_kind=TargetKind.WEB,
    )

    await loop._handle_enumerate_endpoints_handoff(
        {
            "accessible": [],
            "errors": [
                {
                    "path": "/redirect",
                    "status": 500,
                    "size": 120,
                    "error_kind": "actionable",
                    "error_preview": "TypeError: Cannot read properties of undefined",
                },
                {
                    "path": "/api/error",
                    "status": 500,
                    "size": 90,
                    "error_kind": "unknown",
                    "error_preview": "Internal Server Error",
                },
            ],
        },
        lambda *args, **kwargs: True,
    )

    findings = _get_findings()
    assert len(findings) == 1
    assert findings[0]["title"] == "HTTP 500 on /redirect"


@pytest.mark.asyncio
async def test_post_auth_enum_handoff_reports_same_data_without_auth():
    registry = ToolRegistry()
    registry.register(ReportFindingTool())
    registry.register(VerifyFindingToolStub())
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=registry,
        max_iters=20,
        target_kind=TargetKind.WEB,
    )

    await loop._handle_post_auth_enum_handoff(
        {
            "user_data_exposed": [],
            "control_evidence": {
                "same_data_without_auth": [
                    {
                        "path": "/rest/admin/application-configuration",
                        "status_auth": 200,
                        "status_noauth": 200,
                        "preview_auth": '{"config":{"server":{"port":3000}}}',
                        "preview_noauth": '{"config":{"server":{"port":3000}}}',
                    }
                ]
            },
        }
    )

    findings = _get_findings()
    assert len(findings) == 1
    assert findings[0]["title"] == "Missing authentication on 1 endpoint(s)"
    assert findings[0]["finding_type"] == "broken_access_control"
    assert "/rest/admin/application-configuration" in findings[0]["description"]


@pytest.mark.asyncio
async def test_execute_chain_handoff_preserves_evidence_artifact():
    registry = ToolRegistry()
    registry.register(ReportFindingTool())
    registry.register(VerifyFindingToolStub())
    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=registry,
        max_iters=20,
        target_kind=TargetKind.WEB,
    )

    await loop._handle_execute_chain_handoff(
        {
            "findings": [
                {
                    "title": "Validated post-auth crown replay on /api/users",
                    "severity": "medium",
                    "finding_type": "attack_chain",
                    "affected_component": "http://localhost:3000/api/users",
                    "description": "A foothold session was reused to create a privileged account.",
                    "impact": "An attacker can turn a low-privilege foothold into admin takeover.",
                    "technical_analysis": "mass assignment accepted role=admin during authenticated account creation.",
                    "poc_description": "Replay the account creation request with the privileged field.",
                    "remediation_steps": "Reject privileged fields from user-controlled account creation.",
                    "endpoint": "http://localhost:3000/api/users",
                    "method": "POST",
                    "verification_method": "live_chain_replay",
                    "evidence_artifact": {
                        "source_output": "Authenticated foothold token acquired.",
                        "pivot_action": "POST /api/users with role=admin using the foothold token.",
                        "observed_result": "201 Created with role=admin reflected in the new account.",
                        "control_result": "Baseline account creation should ignore or reject role=admin.",
                        "crown_jewel_evidence": "The new account persisted role=admin after login.",
                        "repeat_count": 2,
                        "negative_result": "Control account did not gain role=admin.",
                        "source_output_used_in_pivot": True,
                    },
                }
            ]
        }
    )

    findings = _get_findings()
    assert len(findings) == 1
    assert findings[0]["evidence_artifact"]["source_output_used_in_pivot"] is True
    assert "role=admin" in findings[0]["evidence_artifact"]["observed_result"]
