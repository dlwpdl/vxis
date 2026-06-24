import pytest

from vxis.agent.replay_gate import (
    blocking_replay_gate_findings,
    machine_replay_gate,
    parse_raw_http_requests,
    replay_gate_passed,
)
from vxis.agent.tool_registry import ToolResult


def test_replay_gate_blocks_unreplayed_high_findings() -> None:
    blockers = blocking_replay_gate_findings(
        [
            {
                "id": "VXIS-0001",
                "title": "admin auth bypass",
                "severity": "high",
                "verifier_verdict": "CONFIRMED",
            },
            {"id": "VXIS-0002", "title": "banner leak", "severity": "low"},
        ]
    )

    assert [item["id"] for item in blockers] == ["VXIS-0001"]


def test_replay_gate_accepts_confirmed_high_with_passed_replay() -> None:
    assert replay_gate_passed(
        {
            "id": "VXIS-0001",
            "severity": "critical",
            "verifier_verdict": "CONFIRMED",
            "replay_gate": {"status": "passed", "method": "raw_http"},
        }
    )


def test_parse_raw_http_requests_uses_scan_target_base_url() -> None:
    requests = parse_raw_http_requests(
        "GET /search?q=test HTTP/1.1\nHost: example\n\n",
        "http://localhost:3000/app",
    )
    assert requests == [
        {
            "method": "GET",
            "headers": {},
            "base_url": "http://localhost:3000",
            "path": "/search?q=test",
        }
    ]


@pytest.mark.asyncio
async def test_machine_replay_gate_passes_on_marker_delta() -> None:
    async def dispatch(name: str, args: dict) -> ToolResult:
        assert name == "http_request"
        path = str(args.get("path", ""))
        if "%3Cimg" in path:
            body = "search:<img src=x onerror=alert(1)>"
        else:
            body = "search:test"
        return ToolResult(ok=True, data={"status": 200, "body_preview": body})

    gate = await machine_replay_gate(
        finding={
            "severity": "high",
            "control_comparison": "GET /search?q=test HTTP/1.1\nHost: example\n\n",
            "request_or_payload": (
                "GET /search?q=%3Cimg%20src=x%20onerror=alert(1)%3E HTTP/1.1\n"
                "Host: example\n\n"
            ),
            "response_or_effect": "search:<img src=x onerror=alert(1)>",
        },
        target="http://localhost:3000",
        dispatch=dispatch,
    )

    assert gate["status"] == "passed"
    assert gate["matched_markers"] == ["search:<img src=x onerror=alert(1)>"]


@pytest.mark.asyncio
async def test_machine_replay_gate_accepts_specific_non_security_word_marker() -> None:
    async def dispatch(name: str, args: dict) -> ToolResult:
        body = "orderId=42" if "orderId" in str(args.get("path", "")) else "empty cart"
        return ToolResult(ok=True, data={"status": 200, "body_preview": body})

    gate = await machine_replay_gate(
        finding={
            "severity": "high",
            "control_comparison": "GET /cart HTTP/1.1\nHost: example\n\n",
            "request_or_payload": "GET /cart?show=orderId HTTP/1.1\nHost: example\n\n",
            "response_or_effect": "orderId=42",
        },
        target="http://localhost:3000",
        dispatch=dispatch,
    )

    assert gate["status"] == "passed"
    assert gate["matched_markers"] == ["orderId=42"]


@pytest.mark.asyncio
async def test_machine_replay_gate_turns_dispatch_exception_into_blocked_oracle() -> None:
    async def dispatch(name: str, args: dict) -> ToolResult:
        raise TimeoutError("network blip")

    gate = await machine_replay_gate(
        finding={
            "severity": "high",
            "control_comparison": "GET /cart HTTP/1.1\nHost: example\n\n",
            "request_or_payload": "GET /cart?show=orderId HTTP/1.1\nHost: example\n\n",
            "response_or_effect": "orderId=42",
        },
        target="http://localhost:3000",
        dispatch=dispatch,
    )

    assert gate["status"] == "blocked_oracle"
    assert gate["reason"] == "http replay failed: TimeoutError"


@pytest.mark.asyncio
async def test_machine_replay_gate_blocks_unsafe_methods(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("WARNING")
    gate = await machine_replay_gate(
        finding={
            "id": "VXIS-0007",
            "title": "POST login bypass",
            "severity": "critical",
            "control_comparison": "POST /login HTTP/1.1\nHost: example\n\n{}",
            "request_or_payload": "POST /login HTTP/1.1\nHost: example\n\n{}",
        },
        target="http://localhost:3000",
        dispatch=lambda *_args, **_kwargs: None,
    )

    assert gate["status"] == "blocked_policy"
    assert "VXIS-0007" in caplog.text
