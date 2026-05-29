from __future__ import annotations

import asyncio

from vxis.agent.tools.finding_tools import (
    LinkChainTool,
    ReportFindingTool,
    _reset_for_tests,
    set_event_callback,
)


def test_finding_tools_emit_live_hit_and_chain_events() -> None:
    async def _run() -> list[tuple[str, dict]]:
        _reset_for_tests()
        events: list[tuple[str, dict]] = []
        set_event_callback(lambda event_type, data: events.append((event_type, data)))

        report = ReportFindingTool()
        chain = LinkChainTool()

        first = await report.run(
            title="SQL Injection on login",
            severity="critical",
            finding_type="sql_injection",
            affected_component="/login",
            description="Classic auth bypass",
            impact="Authentication bypass to privileged session.",
            technical_analysis="The login accepted a boolean-auth bypass payload and returned an authenticated response.",
            poc_description="Submit a crafted username payload to bypass authentication.",
            poc_script_code="POST /login HTTP/1.1\\n\\nusername=admin' --&password=x\\nHTTP/1.1 302 Found\\nLocation: /admin",
            remediation_steps="Parameterize the login query and add strict authentication controls.",
        )
        second = await report.run(
            title="Weak auth on admin",
            severity="high",
            finding_type="weak_auth",
            affected_component="/admin",
            description="Default credentials accepted",
            impact="Administrative access with default credentials.",
            technical_analysis="Baseline invalid credentials returned 401, default credentials returned 200 and an admin session.",
            poc_description="Replay invalid-credential control, then authenticate to the admin panel with default credentials.",
            poc_script_code=(
                "POST /admin/login HTTP/1.1\\n\\nusername=guest&password=wrong\\n\\n"
                "HTTP/1.1 401 Unauthorized\\n\\n"
                "POST /admin/login HTTP/1.1\\n\\nusername=admin&password=admin\\n\\n"
                "HTTP/1.1 200 OK\\nSet-Cookie: session=admin"
            ),
            remediation_steps="Disable default credentials and enforce rotation on first use.",
        )
        await chain.run(
            finding_ids=[first.data["id"], second.data["id"]],
            rationale="Initial foothold escalates to admin access",
            crown_jewel="admin takeover",
            evidence_artifact={
                "source_finding_id": first.data["id"],
                "target_finding_id": second.data["id"],
                "source_output": "SQL injection returned Location: /admin and an authenticated session hint.",
                "pivot_action": "Reused the authenticated session path against the admin login.",
                "observed_result": "HTTP/1.1 200 OK\nSet-Cookie: session=admin",
                "control_result": "HTTP/1.1 401 Unauthorized\nbaseline invalid credentials denied",
                "crown_jewel_evidence": "Admin session cookie issued by /admin/login.",
                "source_output_used_in_pivot": True,
            },
        )
        set_event_callback(None)
        return events

    events = asyncio.run(_run())

    hit_events = [data for event_type, data in events if event_type == "hit"]
    chain_start_events = [data for event_type, data in events if event_type == "chain_start"]
    chain_step_events = [data for event_type, data in events if event_type == "chain_step"]

    assert len(hit_events) == 2
    assert hit_events[0]["vector_id"] == "sql_injection"
    assert hit_events[0]["level"] == 4
    assert hit_events[0]["severity"] == "critical"
    assert hit_events[0]["finding_id"].startswith("VXIS-")

    assert len(chain_start_events) == 1
    assert chain_start_events[0]["chain_id"].startswith("CHAIN-")
    assert chain_start_events[0]["finding_type"] == "sql_injection"

    assert len(chain_step_events) == 2
    assert chain_step_events[0]["vector_id"] == "sql_injection"
    assert chain_step_events[1]["vector_id"] == "weak_auth"
