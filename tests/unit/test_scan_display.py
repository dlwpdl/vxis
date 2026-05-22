from __future__ import annotations

import io
from types import SimpleNamespace

from rich.console import Console

from vxis.cli.scan_display import ScanLiveDisplay


def test_scan_display_switches_to_single_loop_live_mode() -> None:
    console = Console(file=io.StringIO(), force_terminal=False, width=120)
    display = ScanLiveDisplay(
        console,
        target="https://example.test",
        profile="standard",
        brain="test-brain",
        ghost=False,
        version="0.0.0",
    )
    display.init_phases(
        [
            SimpleNamespace(id=0, name="Foundation"),
            SimpleNamespace(id=1, name="Director"),
        ]
    )

    display.handle_event("phase_start", {"phase": "scan_loop", "name": "ScanAgentLoop"})
    display.handle_event(
        "brain_thinking",
        {
            "phase": "scan_loop",
            "iteration": 8,
            "max_iters": 50,
            "vectors": [{"id": "web:sqli", "reasoning": "testing login surface"}],
        },
    )
    display.handle_event(
        "hit",
        {
            "vector_id": "sql_injection",
            "severity": "critical",
            "level": 4,
            "title": "SQL Injection on login",
        },
    )
    display.handle_event(
        "control_plane",
        {
            "iteration": 8,
            "max_iters": 50,
            "waiting_reason": "Executing: browser_fill_form /login",
            "todo_counts": {"pending": 2, "done": 1},
            "branch_counts": {"active": 1, "proven": 1},
            "todos": [
                {"id": "web:auth-bypass", "title": "Authentication bypass or weak login", "priority": 95, "status": "pending"},
            ],
            "branches": [
                {
                    "id": "web:auth-bypass",
                    "vector_id": "WEB-AUTH-001",
                    "role": "exploit_worker",
                    "phase": "session_reuse",
                    "status": "active",
                    "attempts": 1,
                    "last_tool": "browser_fill_form",
                    "objective": "Turn the auth foothold into post-auth data access",
                    "next_step": "Probe /admin and authenticated APIs with the new session",
                },
            ],
            "reviews": [
                {
                    "id": "review-1",
                    "stage": "judge",
                    "status": "open",
                    "title": "needs_chains",
                    "reason": "Link auth foothold to post-auth access before finish",
                },
            ],
            "chain_candidates": [
                {
                    "source_id": "VXIS-0001",
                    "target_id": "VXIS-0002",
                    "source_type": "weak_auth",
                    "target_type": "broken_access_control",
                    "rationale": "Auth foothold can unlock authenticated data retrieval.",
                    "crown_jewel": "authenticated data exfiltration",
                },
            ],
            "campaign_groups": [
                {
                    "campaign_id": "VXIS-0001",
                    "headline": "Authentication bypass via SQLi",
                    "source_finding_id": "VXIS-0001",
                    "crown_jewel": "authenticated data exfiltration",
                    "family": "auth",
                    "roles": ["post_exploit_worker"],
                    "phases": ["session_reuse", "data_access"],
                    "branch_count": 2,
                    "blocking_count": 1,
                    "max_priority": 106,
                    "objective": "Turn the auth foothold into post-auth data access",
                    "next_step": "Probe /admin and authenticated APIs with the new session",
                },
            ],
            "focus_campaign": {
                "campaign_id": "VXIS-0001",
                "headline": "Authentication bypass via SQLi",
                "source_finding_id": "VXIS-0001",
                "crown_jewel": "authenticated data exfiltration",
                "family": "auth",
                "roles": ["post_exploit_worker"],
                "phases": ["session_reuse", "data_access"],
                "branch_count": 2,
                "blocking_count": 1,
                "max_priority": 106,
                "objective": "Turn the auth foothold into post-auth data access",
                "next_step": "Probe /admin and authenticated APIs with the new session",
                "findings": [
                    {
                        "id": "VXIS-0001",
                        "title": "Authentication bypass via SQLi",
                        "finding_type": "weak_auth",
                        "severity": "critical",
                        "affected_component": "/login",
                    },
                ],
                "reviews": [
                    {
                        "stage": "judge",
                        "status": "open",
                        "title": "needs_chains",
                        "reason": "Link auth foothold to post-auth access before finish",
                    },
                ],
            },
            "memory_directives": [
                "memory strategy: first revalidate auth footholds, then explore unexplored surface",
            ],
            "focus_branch": {
                "id": "web:auth-bypass",
                "vector_id": "WEB-AUTH-001",
                "role": "exploit_worker",
                "phase": "session_reuse",
                "status": "active",
                "objective": "Turn the auth foothold into post-auth data access",
                "next_step": "Probe /admin and authenticated APIs with the new session",
                "crown_jewel": "authenticated data exfiltration",
            },
            "recent_attempts": [
                {
                    "candidate_id": "web:auth-bypass",
                    "vector_id": "WEB-AUTH-001",
                    "tool": "browser_fill_form",
                    "status": "found",
                    "summary": "authenticated session established",
                },
            ],
            "agents": [
                {
                    "id": "agent-0001",
                    "role": "exploit_worker",
                    "task": "Validate SQL injection on /api/search and collect control evidence",
                    "status": "waiting",
                    "skills": ["test_injection"],
                    "result": "",
                    "message_count": 2,
                    "execution_count": 1,
                    "messages": [
                        {
                            "id": "msg-0001",
                            "sender": "root",
                            "recipient": "agent-0001",
                            "body": "Validate SQL injection with baseline/control/payload comparison",
                        },
                        {
                            "id": "msg-0002",
                            "sender": "agent-0001",
                            "recipient": "root",
                            "body": "status delta observed on /api/search",
                        },
                    ],
                    "executions": [
                        {
                            "id": "exec-0001",
                            "tool": "run_skill",
                            "args": {"skill": "test_injection"},
                            "ok": True,
                            "summary": "status delta observed on /api/search",
                            "data": {},
                            "error": None,
                        },
                    ],
                    "skill_context": (
                        "### test_injection\n"
                        "action: run_skill(skill=\"test_injection\", target_url=<target>, params={...})"
                    ),
                },
                {
                    "id": "agent-0002",
                    "role": "review_worker",
                    "task": "Review clean route map",
                    "status": "finished",
                    "skills": ["enumerate_endpoints"],
                    "result": "No admin route before auth.",
                    "message_count": 1,
                    "execution_count": 0,
                },
            ],
            "telemetry": {
                "provider": "openai",
                "model": "gpt-5.4-mini",
                "discipline_profile": "frontier_loose",
                "base_url": "https://api.openai.test/v1",
                "llm_calls": 3,
                "brain_decisions": 4,
                "total_tokens": 12345,
                "tokens_estimated": True,
                "cost_usd": 0.0123,
                "cost_estimated": True,
                "memory_compression": {
                    "triggered": 2,
                    "total_tokens_saved": 1200,
                },
            },
            "proxy": {
                "backend": "xray",
                "running": True,
                "proxy_url": "http://localhost:8081",
                "flow_count": 7,
                "auth_flow_count": 2,
                "recent_requests": [
                    {"method": "POST", "path": "/login", "status_code": 302},
                    {"method": "GET", "path": "/admin", "status_code": 200},
                ],
            },
        },
    )
    display.handle_event(
        "chain_start",
        {
            "chain_id": "CHAIN-001",
            "finding_type": "weak_auth",
            "endpoint": "/login",
            "vector_id": "weak_auth",
            "finding_ids": ["VXIS-0001", "VXIS-0002"],
            "source_title": "Authentication bypass via SQLi",
            "rationale": "The foothold enables post-authenticated retrieval.",
            "crown_jewel": "authenticated data exfiltration",
        },
    )
    display.handle_event(
        "chain_step",
        {
            "chain_id": "CHAIN-001",
            "finding_id": "VXIS-0001",
            "vector_id": "weak_auth",
            "endpoint": "/login",
            "level": 4,
            "reasoning": "Authentication bypass via SQLi",
            "title": "Authentication bypass via SQLi",
            "severity": "critical",
        },
    )
    display.handle_event(
        "chain_step",
        {
            "chain_id": "CHAIN-001",
            "finding_id": "VXIS-0002",
            "vector_id": "broken_access_control",
            "endpoint": "/api/profile",
            "level": 3,
            "reasoning": "Sensitive user data exposed on 4 endpoint(s)",
            "title": "Sensitive user data exposed on 4 endpoint(s)",
            "severity": "high",
        },
    )

    assert display.loop_mode is True
    assert display.loop_iteration == 8
    assert display.loop_max_iters == 50
    assert display.total_findings == 1
    assert display.phases[0]["name"] == "Scan Loop"
    assert display.waiting_reason == "Executing: browser_fill_form /login"

    panel = display._render_phases()
    assert "Scan Loop" in str(panel.title)
    control_panel = display._render_control_plane()
    control_text = str(control_panel.renderable)
    assert "Control Plane" in str(control_panel.title)
    assert "gpt-5.4-mini" in control_text
    assert "frontier_loose" in control_text
    assert "compress 2x" in control_text
    assert "Authentication bypass or weak login" in control_text
    assert "Probe /admin" in control_text
    assert "xray running" in control_text
    assert "/login" in control_text

    assert "frontier_loose" in display._runtime_summary()

    header_panel = display._render_header()
    header_console = Console(file=io.StringIO(), force_terminal=False, width=120)
    header_console.print(header_panel)
    header_text = header_console.file.getvalue()
    assert "gpt-5.4-mini" in header_text
    assert "api.openai.test" in header_text

    brain_panel = display._render_brain_thinking()
    brain_text = str(brain_panel.renderable)
    assert "LLM Runtime:" in brain_text
    assert "gpt-5.4-mini" in brain_text

    agent_panel = display._render_agent_monitor()
    agent_text = str(agent_panel.renderable)
    assert "Agents" in str(agent_panel.title)
    assert "agent-0001" in agent_text
    assert "waiting" in agent_text
    assert "test_injection" in agent_text
    assert "finish agent-0001" in agent_text
    assert "status delta observed" in agent_text
    assert 'action: run_skill(skill="test_injection"' in agent_text

    chain_panel = display._render_chains()
    chain_text = str(chain_panel.renderable)
    assert "Chain Ops" in str(chain_panel.title)
    assert "Focus branch" in chain_text
    assert "Pending chain candidates" in chain_text
    assert "Active campaigns" in chain_text
    assert "Campaign detail" in chain_text
    assert "Linked chains" in chain_text
    assert "Recent branch activity" in chain_text
    assert "authenticated data exfiltration" in chain_text
